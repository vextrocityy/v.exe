//! Process Guard: reacts to every new process.
//!
//! Event source on Windows: an ETW real-time session on the
//! `Microsoft-Windows-Kernel-Process` provider (ProcessStart, event id 1).
//! If ETW cannot start (no privilege, session limit), we fall back to a 1 s
//! Toolhelp snapshot diff so protection degrades instead of disappearing.
//!
//! Note: user-mode notification happens *as* the process starts, not before.
//! True pre-execution blocking needs a kernel callback
//! (`PsSetCreateProcessNotifyRoutineEx`) in a signed driver; see docs/ROADMAP.md.

use super::{sleep_or_stop, ShieldHandle, PROCESS_GUARD};
use crate::engine::heuristics::{self, ProcessContext};
use crate::engine::Engine;
use crate::platform;
use sentinel_protocol::{EventKind, Severity};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ProcessStart {
    pub pid: u32,
    pub ppid: u32,
}

pub fn start(engine: Arc<Engine>) -> Result<ShieldHandle, String> {
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = sync_channel::<ProcessStart>(4096);
    let mut threads = Vec::new();

    let (detail, on_stop) = match etw::start(tx.clone()) {
        Ok(stopper) => ("ETW: Microsoft-Windows-Kernel-Process".to_string(), Some(stopper)),
        Err(e) => {
            tracing::warn!(error = %e, "ETW unavailable, using polling fallback");
            let stop2 = stop.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("proc-poll".into())
                    .spawn(move || poll_source(tx, stop2))
                    .map_err(|e| e.to_string())?,
            );
            (format!("Polling every 1 s (ETW unavailable: {e})"), None)
        }
    };

    let stop2 = stop.clone();
    threads.push(
        std::thread::Builder::new()
            .name("proc-analyzer".into())
            .spawn(move || analyzer(engine, rx, stop2))
            .map_err(|e| e.to_string())?,
    );

    Ok(ShieldHandle {
        name: PROCESS_GUARD,
        stop,
        threads,
        on_stop,
        detail: Some(detail),
    })
}

/// Fallback source: diff the process list once per second.
fn poll_source(tx: SyncSender<ProcessStart>, stop: Arc<AtomicBool>) {
    let mut known: HashSet<u32> = platform::list_processes().into_iter().map(|p| p.pid).collect();
    while !sleep_or_stop(&stop, Duration::from_secs(1)) {
        let now = platform::list_processes();
        for p in &now {
            if !known.contains(&p.pid) {
                let _ = tx.try_send(ProcessStart {
                    pid: p.pid,
                    ppid: p.ppid,
                });
            }
        }
        known = now.into_iter().map(|p| p.pid).collect();
    }
}

fn analyzer(engine: Arc<Engine>, rx: Receiver<ProcessStart>, stop: Arc<AtomicBool>) {
    // pid -> image, so we can name the parent even after it has exited.
    let mut images: HashMap<u32, PathBuf> = HashMap::new();
    for p in platform::list_processes() {
        if let Some(img) = platform::image_path(p.pid) {
            images.insert(p.pid, img);
        }
    }

    while !stop.load(Ordering::Relaxed) {
        let ev = match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(ev) => ev,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        if images.len() > 8192 {
            let live: HashSet<u32> = platform::list_processes().into_iter().map(|p| p.pid).collect();
            images.retain(|pid, _| live.contains(pid));
        }
        crate::util::contain("process event", || handle_start(&engine, &mut images, &ev));
    }
}

fn handle_start(engine: &Engine, images: &mut HashMap<u32, PathBuf>, ev: &ProcessStart) {
    let Some(image) = platform::image_path(ev.pid) else {
        return;
    }; // already exited
    images.insert(ev.pid, image.clone());
    if engine.is_excluded(&image) {
        return;
    }
    let settings = engine.settings();

    let parent = images.get(&ev.ppid).cloned().or_else(|| platform::image_path(ev.ppid));
    let mut image_sha: Option<String> = None;

    // 1) Signature check of the executable.
    match engine.check_file(&image, None) {
        Ok(verdict) => {
            image_sha = Some(verdict.sha256.clone());
            if let Some(hit) = &verdict.hit {
                if settings.auto_kill_malicious
                    && engine.may_remediate(&image, hit).is_ok()
                    && platform::terminate(ev.pid)
                {
                    engine.emit(
                        EventKind::ProcessBlocked,
                        Severity::Critical,
                        format!("Terminated malicious process ({})", hit.name),
                        None,
                        Some(&image),
                        Some(ev.pid),
                    );
                    // Give the OS a moment to release the image file before quarantining.
                    std::thread::sleep(Duration::from_millis(300));
                }
                engine.handle_detection(&image, &verdict, Some(ev.pid), "Process Guard");
                return;
            }
        }
        Err(reason) => tracing::debug!(image = %image.display(), ?reason, "could not hash process image"),
    }

    // 2) Attack-surface rule: documents must not launch shells or script hosts.
    if settings.block_office_children {
        if let Some(parent) = parent
            .as_deref()
            .filter(|p| heuristics::office_spawning_shell(&image, p))
        {
            if platform::terminate(ev.pid) {
                let name = |p: &std::path::Path| p.file_name().unwrap_or_default().to_string_lossy().into_owned();
                engine.emit(
                    EventKind::ProcessBlocked,
                    Severity::High,
                    format!("Blocked {} started by {}", name(&image), name(parent)),
                    Some(
                        "Office documents and PDF readers launching a shell or script host is a classic malware \
                         technique (malicious macros, exploits). Attack-surface rule."
                            .into(),
                    ),
                    Some(&image),
                    Some(ev.pid),
                );
                return;
            }
        }
    }

    // 3) Backups: ransomware deletes shadow copies / disables recovery before encrypting.
    //    (Our own snapshot pruning runs as a child of this service and is exempt.)
    if (settings.rollback_snapshots || settings.ransomware_suspend) && ev.ppid != std::process::id() {
        if let Some(what) = platform::command_line(ev.pid)
            .as_deref()
            .and_then(crate::engine::rollback::is_backup_deletion)
        {
            if platform::terminate(ev.pid) {
                engine.emit(
                    EventKind::ProcessBlocked,
                    Severity::Critical,
                    "Blocked an attempt to delete backups",
                    Some(format!(
                        "{what}. Ransomware does this before encrypting files so they cannot be recovered. \
                         The program that started it ({}) deserves a scan.",
                        parent
                            .as_deref()
                            .and_then(|p| p.file_name())
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "unknown".into())
                    )),
                    Some(&image),
                    Some(ev.pid),
                );
                return;
            }
        }
    }

    // 4) Execution Guard: unsigned programs from Downloads / Temp / AppData.
    if settings.block_untrusted_risky {
        if let Some(folder) = heuristics::risky_location(&image) {
            let trusted = image_sha
                .as_deref()
                .is_some_and(|h| engine.is_trusted_app(h) || engine.is_own_uninstaller(h));
            if !trusted && engine.may_suspend(ev.pid, &image) && platform::terminate(ev.pid) {
                engine.emit(
                    EventKind::ProcessBlocked,
                    Severity::High,
                    format!("Blocked unsigned program from {folder}"),
                    Some(format!(
                        "Execution Guard stops programs without a valid digital signature when they start from {folder}, \
                         where malware usually lands. If you trust it, choose Always allow."
                    )),
                    Some(&image),
                    Some(ev.pid),
                );
                return;
            }
        }
    }

    // 5) Behavioural assessment (alert only).
    if settings.behavior_monitor {
        let cmd = platform::command_line(ev.pid);
        let a = heuristics::assess_process(&ProcessContext {
            image: &image,
            command_line: cmd.as_deref(),
            parent_image: parent.as_deref(),
        });
        if a.score >= heuristics::ALERT_MEDIUM {
            let sev = if a.score >= heuristics::ALERT_HIGH {
                Severity::High
            } else {
                Severity::Medium
            };
            engine.emit(
                EventKind::BehaviorAlert,
                sev,
                "Suspicious process behaviour",
                Some(format!("score {}: {}", a.score, a.reasons.join("; "))),
                Some(&image),
                Some(ev.pid),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// ETW source
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod etw {
    use super::ProcessStart;
    use ferrisetw::parser::Parser;
    use ferrisetw::provider::Provider;
    use ferrisetw::schema_locator::SchemaLocator;
    use ferrisetw::trace::UserTrace;
    use ferrisetw::EventRecord;
    use std::sync::mpsc::SyncSender;
    use std::sync::Mutex;

    const KERNEL_PROCESS_GUID: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";
    const WINEVENT_KEYWORD_PROCESS: u64 = 0x10;
    const EVENT_PROCESS_START: u16 = 1;

    pub fn start(tx: SyncSender<ProcessStart>) -> Result<Box<dyn FnOnce() + Send>, String> {
        let callback = move |record: &EventRecord, locator: &SchemaLocator| {
            if record.event_id() != EVENT_PROCESS_START {
                return;
            }
            let Ok(schema) = locator.event_schema(record) else {
                return;
            };
            let parser = Parser::create(record, &schema);
            let pid: Option<u32> = parser.try_parse("ProcessID").ok();
            let ppid: u32 = parser.try_parse("ParentProcessID").unwrap_or(0);
            if let Some(pid) = pid {
                // Never block the ETW callback thread; drop on overload.
                let _ = tx.try_send(ProcessStart { pid, ppid });
            }
        };
        let provider = Provider::by_guid(KERNEL_PROCESS_GUID)
            .any(WINEVENT_KEYWORD_PROCESS)
            .add_callback(callback)
            .build();
        let trace = UserTrace::new()
            .named(format!("SentinelLite-Process-{}", std::process::id()))
            .enable(provider)
            .start_and_process()
            .map_err(|e| format!("{e:?}"))?;
        let slot = Mutex::new(Some(trace));
        Ok(Box::new(move || {
            if let Some(t) = slot.lock().ok().and_then(|mut s| s.take()) {
                let _ = t.stop();
            }
        }))
    }
}

#[cfg(not(windows))]
mod etw {
    use super::ProcessStart;
    use std::sync::mpsc::SyncSender;

    pub fn start(_tx: SyncSender<ProcessStart>) -> Result<Box<dyn FnOnce() + Send>, String> {
        Err("ETW is Windows-only".into())
    }
}
