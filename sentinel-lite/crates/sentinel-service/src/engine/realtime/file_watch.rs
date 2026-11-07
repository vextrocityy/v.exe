//! File Shield: scans files as they land in watched folders and feeds every
//! modification into the ransomware detector.
//!
//! User-mode source: `ReadDirectoryChangesW` (through `notify`). It reports
//! changes *after* they happen and without the writing PID; a file-system
//! minifilter is the Phase-2 replacement that can block writes inline.

use super::{ShieldHandle, FILE_SHIELD};
use crate::engine::heuristics::{FileActivity, RansomwareDetector};
use crate::engine::{targets, Engine};
use notify::event::{ModifyKind, RenameMode};
use notify::{EventKind as NEvent, RecursiveMode, Watcher};
use sentinel_protocol::{EventKind, Severity};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Wait until a file has been quiet this long before hashing it (downloads, copies).
const SETTLE: Duration = Duration::from_millis(1500);
const MAX_PENDING: usize = 10_000;

pub fn start(engine: Arc<Engine>) -> Result<ShieldHandle, String> {
    let roots = targets::watch_roots(&engine.settings().watch_paths);
    if roots.is_empty() {
        return Err("no folders to watch".into());
    }
    let (tx, rx) = sync_channel::<notify::Event>(8192);
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res {
            let _ = tx.try_send(ev); // never block the OS notification thread
        }
    })
    .map_err(|e| e.to_string())?;

    let mut watched = 0;
    for root in &roots {
        match watcher.watch(root, RecursiveMode::Recursive) {
            Ok(()) => watched += 1,
            Err(e) => tracing::warn!(dir = %root.display(), error = %e, "cannot watch folder"),
        }
    }
    if watched == 0 {
        return Err("could not watch any folder".into());
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let thread = std::thread::Builder::new()
        .name("file-shield".into())
        .spawn(move || {
            let _watcher = watcher; // dropped (unwatched) when the loop exits
            let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
            let mut rename_from: Option<PathBuf> = None;
            let mut ransomware = RansomwareDetector::default();

            while !stop2.load(Ordering::Relaxed) {
                match rx.recv_timeout(Duration::from_millis(250)) {
                    Ok(ev) => {
                        // Decoys first: any write, rename or delete touching one.
                        if !matches!(ev.kind, NEvent::Access(_)) {
                            for p in &ev.paths {
                                if engine.is_decoy(p) {
                                    engine.on_decoy_event(p.clone());
                                }
                            }
                        }
                        let behavior = engine.settings().behavior_monitor;
                        for (path, activity) in classify(&ev, &mut rename_from) {
                            if engine.is_excluded(&path) {
                                continue;
                            }
                            if behavior {
                                if let Some(activity) = activity {
                                    if let Some(alert) = ransomware.record(&path, activity) {
                                        raise_ransomware_alert(&engine, &alert);
                                    }
                                }
                            }
                            if pending.len() < MAX_PENDING {
                                pending.insert(path, Instant::now());
                            }
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => break,
                }
                let now = Instant::now();
                let ready: Vec<PathBuf> = pending
                    .iter()
                    .filter(|(_, t)| now.duration_since(**t) >= SETTLE)
                    .map(|(p, _)| p.clone())
                    .collect();
                for p in ready {
                    pending.remove(&p);
                    crate::util::contain("file shield scan", || scan_one(&engine, &p));
                }
            }
        })
        .map_err(|e| e.to_string())?;

    Ok(ShieldHandle {
        name: FILE_SHIELD,
        stop,
        threads: vec![thread],
        on_stop: None,
        detail: Some(format!("Watching {watched} folder(s)")),
    })
}

fn ext_of(p: &Path) -> Option<String> {
    p.extension().map(|e| e.to_string_lossy().to_ascii_lowercase())
}

/// Map a raw notification to (path to scan, activity for the ransomware detector).
fn classify(ev: &notify::Event, rename_from: &mut Option<PathBuf>) -> Vec<(PathBuf, Option<FileActivity>)> {
    match ev.kind {
        NEvent::Create(_) => ev.paths.iter().map(|p| (p.clone(), None)).collect(),
        NEvent::Modify(ModifyKind::Name(RenameMode::From)) => {
            *rename_from = ev.paths.first().cloned();
            Vec::new()
        }
        NEvent::Modify(ModifyKind::Name(RenameMode::To)) => {
            let from = rename_from.take();
            ev.paths
                .iter()
                .map(|to| (to.clone(), Some(rename_activity(from.as_deref(), to))))
                .collect()
        }
        NEvent::Modify(ModifyKind::Name(RenameMode::Both)) if ev.paths.len() == 2 => {
            let act = rename_activity(Some(&ev.paths[0]), &ev.paths[1]);
            vec![(ev.paths[1].clone(), Some(act))]
        }
        NEvent::Modify(ModifyKind::Name(_)) => Vec::new(),
        NEvent::Modify(_) => ev
            .paths
            .iter()
            .map(|p| (p.clone(), Some(FileActivity::Modified)))
            .collect(),
        _ => Vec::new(),
    }
}

fn rename_activity(from: Option<&Path>, to: &Path) -> FileActivity {
    match from {
        Some(f) if ext_of(f) != ext_of(to) => FileActivity::RenamedNewExtension,
        _ => FileActivity::Renamed,
    }
}

fn scan_one(engine: &Engine, path: &Path) {
    if !path.is_file() {
        return;
    }
    match engine.check_file(path, None) {
        Ok(v) if v.hit.is_some() => engine.handle_detection(path, &v, None, "File Shield"),
        Ok(_) => {}
        Err(reason) => tracing::debug!(path = %path.display(), ?reason, "file shield skip"),
    }
}

fn raise_ransomware_alert(engine: &Engine, alert: &crate::engine::heuristics::RansomwareAlert) {
    let samples: Vec<String> = alert.sample_paths.iter().map(|p| p.display().to_string()).collect();
    engine.emit(
        EventKind::BehaviorAlert,
        Severity::Critical,
        "Possible ransomware: mass file modification",
        Some(format!(
            "Activity weight {} across {} folders in 10 s. Recent: {}",
            alert.weight,
            alert.directories,
            samples.join(", ")
        )),
        alert.sample_paths.first().map(|p| p.as_path()),
        None,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{CreateKind, DataChange};

    #[test]
    fn classify_rename_pairs() {
        let mut from = None;
        let ev =
            notify::Event::new(NEvent::Modify(ModifyKind::Name(RenameMode::From))).add_path("C:\\a\\x.docx".into());
        assert!(classify(&ev, &mut from).is_empty());
        let ev =
            notify::Event::new(NEvent::Modify(ModifyKind::Name(RenameMode::To))).add_path("C:\\a\\x.docx.enc".into());
        let out = classify(&ev, &mut from);
        assert_eq!(out[0].1, Some(FileActivity::RenamedNewExtension));
    }

    #[test]
    fn classify_create_and_write() {
        let mut from = None;
        let ev = notify::Event::new(NEvent::Create(CreateKind::File)).add_path("/d/new.exe".into());
        assert_eq!(classify(&ev, &mut from)[0].1, None);
        let ev = notify::Event::new(NEvent::Modify(ModifyKind::Data(DataChange::Content))).add_path("/d/f".into());
        assert_eq!(classify(&ev, &mut from)[0].1, Some(FileActivity::Modified));
    }
}
