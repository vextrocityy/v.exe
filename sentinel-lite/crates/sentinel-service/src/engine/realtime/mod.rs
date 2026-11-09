//! Real-time shields. Each shield runs on its own thread(s), takes a stop flag,
//! and reports whether it started. A shield that fails to start degrades the
//! dashboard to "At risk" rather than crashing the service.

pub mod decoy;
pub mod file_watch;
pub mod persistence;
pub mod privacy;
pub mod process;
pub mod tasks;

use super::Engine;
use sentinel_protocol::ShieldStatus;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

pub const PROCESS_GUARD: &str = "Process Guard";
pub const FILE_SHIELD: &str = "File Shield";
pub const PERSISTENCE_WATCH: &str = "Persistence Watch";
pub const BEHAVIOR_ENGINE: &str = "Behavior Engine";
pub const PRIVACY_MONITOR: &str = "Privacy Monitor";

pub struct ShieldHandle {
    pub name: &'static str,
    pub stop: Arc<AtomicBool>,
    pub threads: Vec<JoinHandle<()>>,
    /// Extra teardown (e.g. stopping an ETW session) run before joining.
    pub on_stop: Option<Box<dyn FnOnce() + Send>>,
    pub detail: Option<String>,
}

#[derive(Default)]
pub struct RealtimeManager {
    handles: Vec<ShieldHandle>,
}

/// Sleep in short slices so shields stop promptly. Returns true if asked to stop.
pub fn sleep_or_stop(stop: &AtomicBool, total: Duration) -> bool {
    let slice = Duration::from_millis(250);
    let mut left = total;
    while !left.is_zero() {
        if stop.load(Ordering::Relaxed) {
            return true;
        }
        let d = left.min(slice);
        std::thread::sleep(d);
        left -= d;
    }
    stop.load(Ordering::Relaxed)
}

type StartFn = fn(Arc<Engine>) -> Result<ShieldHandle, String>;

impl RealtimeManager {
    /// Start every enabled shield; returns their status for the dashboard.
    pub fn start(&mut self, engine: &Arc<Engine>) -> Vec<ShieldStatus> {
        self.stop();
        let s = engine.settings();
        let on = s.realtime_protection;
        let plan: [(&'static str, bool, StartFn); 4] = [
            (PROCESS_GUARD, on && s.process_monitor, process::start),
            (FILE_SHIELD, on && s.file_monitor, file_watch::start),
            (PERSISTENCE_WATCH, on && s.persistence_monitor, persistence::start),
            // Windows records camera / microphone use; there is nothing to watch elsewhere.
            (PRIVACY_MONITOR, on && s.privacy_monitor && cfg!(windows), privacy::start),
        ];

        let mut statuses = Vec::new();
        for (name, enabled, start) in plan {
            let mut status = ShieldStatus {
                name: name.into(),
                enabled,
                running: false,
                detail: None,
            };
            if enabled {
                match start(engine.clone()) {
                    Ok(h) => {
                        status.running = true;
                        status.detail = h.detail.clone();
                        self.handles.push(h);
                    }
                    Err(e) => {
                        tracing::error!(shield = name, error = %e, "shield failed to start");
                        status.detail = Some(e);
                    }
                }
            }
            statuses.push(status);
        }

        // The behaviour engine piggybacks on the process + file event streams.
        let feeds = statuses
            .iter()
            .filter(|st| st.running && (st.name == PROCESS_GUARD || st.name == FILE_SHIELD))
            .count();
        statuses.push(ShieldStatus {
            name: BEHAVIOR_ENGINE.into(),
            enabled: on && s.behavior_monitor,
            running: on && s.behavior_monitor && feeds > 0,
            detail: Some("Process lineage + mass file-modification detection".into()),
        });
        statuses
    }

    pub fn stop(&mut self) {
        for h in &self.handles {
            h.stop.store(true, Ordering::Relaxed);
        }
        for mut h in self.handles.drain(..) {
            if let Some(f) = h.on_stop.take() {
                f();
            }
            for t in h.threads.drain(..) {
                let _ = t.join();
            }
            tracing::info!(shield = h.name, "stopped");
        }
    }
}

impl Drop for RealtimeManager {
    fn drop(&mut self) {
        self.stop();
    }
}
