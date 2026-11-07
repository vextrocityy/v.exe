//! Background schedule: periodic signature updates and quick scans.
//! Checks once a minute; all timestamps persist in SQLite so the schedule
//! survives restarts and reboots.

use super::realtime::sleep_or_stop;
use super::Engine;
use crate::database::now_unix;
use sentinel_protocol::ScanKind;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

/// Wait after service start before the first update / scan (do not compete with boot).
const STARTUP_GRACE: Duration = Duration::from_secs(120);
/// After a failed update, retry no sooner than this.
const UPDATE_RETRY_SECS: i64 = 30 * 60;
/// First scheduled scan on a fresh install runs this long after the first start.
const FIRST_SCAN_DELAY_SECS: i64 = 15 * 60;

/// Pure decision logic, unit-tested below.
pub fn update_due(now: i64, last_success: i64, last_attempt: i64, interval_hours: u64) -> bool {
    now - last_success >= interval_hours as i64 * 3600 && now - last_attempt >= UPDATE_RETRY_SECS
}

pub fn scan_due(now: i64, last_scan: i64, interval_hours: u64) -> bool {
    now - last_scan >= interval_hours as i64 * 3600
}

pub fn run(engine: Arc<Engine>, stop: Arc<AtomicBool>) {
    if sleep_or_stop(&stop, STARTUP_GRACE) {
        return;
    }
    if engine.db.counter("last_scheduled_scan") == 0 {
        // Fresh install: schedule the first scan shortly, not a full interval away.
        let hours = engine.settings().scheduled_scan_hours as i64;
        engine
            .db
            .set_counter("last_scheduled_scan", now_unix() - hours * 3600 + FIRST_SCAN_DELAY_SECS);
    }
    loop {
        crate::util::contain("scheduler tick", || tick(&engine));
        if sleep_or_stop(&stop, Duration::from_secs(60)) {
            return;
        }
    }
}

fn tick(engine: &Arc<Engine>) {
    let s = engine.settings();
    let now = now_unix();
    let counter = |n: &str| engine.db.counter(n) as i64;

    if s.auto_update
        && !engine.update_running()
        && update_due(
            now,
            counter("last_signature_update"),
            counter("last_update_attempt"),
            s.update_interval_hours,
        )
    {
        tracing::info!("scheduled signature update");
        if let Err(e) = engine.update_signatures() {
            tracing::warn!(error = %e, "scheduled update failed");
        }
    }
    if s.auto_update_app && now - counter("last_app_update_check") >= 6 * 3600 {
        match engine.check_app_update() {
            Ok(line) => tracing::info!("app update: {line}"),
            Err(e) => tracing::warn!(error = %e, "scheduled app update check failed"),
        }
    }

    if s.scheduled_scan
        && !engine.scan_state().is_running()
        && scan_due(now, counter("last_scheduled_scan"), s.scheduled_scan_hours)
    {
        engine.db.set_counter("last_scheduled_scan", now);
        match engine.start_scan(ScanKind::Quick, Vec::new()) {
            Ok(id) => tracing::info!(id, "scheduled quick scan started"),
            Err(e) => tracing::warn!(error = %e, "scheduled scan skipped"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_schedule_with_retry_backoff() {
        let h = 3600;
        assert!(update_due(10 * h, 0, 0, 6)); // never updated
        assert!(!update_due(10 * h, 9 * h, 9 * h, 6)); // updated an hour ago
                                                       // last success long ago, but we just failed 5 minutes ago -> wait
        assert!(!update_due(10 * h, 0, 10 * h - 300, 6));
        assert!(update_due(10 * h, 0, 10 * h - UPDATE_RETRY_SECS, 6));
    }

    #[test]
    fn scan_schedule() {
        assert!(scan_due(100 * 3600, 75 * 3600, 24));
        assert!(!scan_due(100 * 3600, 80 * 3600, 24));
    }
}
