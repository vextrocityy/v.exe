//! On-demand scanner: one walker thread feeding a bounded queue drained by N
//! hashing workers. Bounded queue = bounded memory, regardless of disk size.

use super::hasher::SkipReason;
use super::Engine;
use crate::database::{now_unix, CacheEntry};
use sentinel_protocol::{EventKind, ScanKind, ScanProgress, Severity};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};

const QUEUE_DEPTH: usize = 2048;
const CACHE_FLUSH_EVERY: usize = 256;

#[derive(Default)]
pub struct ScanState {
    running: AtomicBool,
    id: AtomicU64,
    kind: Mutex<Option<ScanKind>>,
    files: AtomicU64,
    bytes: AtomicU64,
    threats: AtomicU64,
    skipped: AtomicU64,
    current: Mutex<Option<String>>,
    started_at: AtomicI64,
    finished_at: AtomicI64,
}

impl ScanState {
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    pub(super) fn begin(&self, kind: ScanKind) -> u64 {
        let id = self.id.fetch_add(1, Ordering::Relaxed) + 1;
        for c in [&self.files, &self.bytes, &self.threats, &self.skipped] {
            c.store(0, Ordering::Relaxed);
        }
        *self.kind.lock().unwrap_or_else(|e| e.into_inner()) = Some(kind);
        *self.current.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.started_at.store(now_unix(), Ordering::Relaxed);
        self.finished_at.store(0, Ordering::Relaxed);
        self.running.store(true, Ordering::Release);
        id
    }

    fn finish(&self) {
        self.finished_at.store(now_unix(), Ordering::Relaxed);
        *self.current.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.running.store(false, Ordering::Release);
    }

    fn set_current(&self, p: &Path) {
        *self.current.lock().unwrap_or_else(|e| e.into_inner()) = Some(p.to_string_lossy().into_owned());
    }

    pub fn snapshot(&self) -> ScanProgress {
        let ts = |a: &AtomicI64| Some(a.load(Ordering::Relaxed)).filter(|v| *v != 0);
        ScanProgress {
            scan_id: self.id.load(Ordering::Relaxed),
            running: self.is_running(),
            kind: *self.kind.lock().unwrap_or_else(|e| e.into_inner()),
            files_scanned: self.files.load(Ordering::Relaxed),
            bytes_scanned: self.bytes.load(Ordering::Relaxed),
            threats_found: self.threats.load(Ordering::Relaxed),
            files_skipped: self.skipped.load(Ordering::Relaxed),
            current_path: self.current.lock().unwrap_or_else(|e| e.into_inner()).clone(),
            started_at: ts(&self.started_at),
            finished_at: ts(&self.finished_at),
        }
    }
}

fn worker_count(configured: usize) -> usize {
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
    match configured {
        0 => (cpus / 2).max(1),
        n => n.clamp(1, cpus),
    }
}

/// Is this directory entry a symlink / junction / other reparse point?
/// Following those causes loops (e.g. `C:\Users\X\Application Data`) and double counting.
fn is_link(entry: &std::fs::DirEntry) -> bool {
    let Ok(ft) = entry.file_type() else { return true };
    if ft.is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if let Ok(m) = entry.metadata() {
            return m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        }
    }
    false
}

fn walk(engine: &Engine, roots: &[PathBuf], tx: &SyncSender<PathBuf>, cancel: &AtomicBool) {
    let state = engine.scan_state();
    let mut stack: Vec<PathBuf> = roots.to_vec();
    while let Some(dir) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        if dir.is_file() {
            // A custom scan may target a single file.
            if tx.send(dir).is_err() {
                return;
            }
            continue;
        }
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!(dir = %dir.display(), error = %e, "cannot list directory");
                state.skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };
        for entry in entries.flatten() {
            if is_link(&entry) {
                continue;
            }
            let path = entry.path();
            if engine.is_excluded(&path) {
                continue;
            }
            match entry.file_type() {
                Ok(ft) if ft.is_dir() => stack.push(path),
                Ok(ft) if ft.is_file() && tx.send(path).is_err() => return,
                _ => {}
            }
        }
    }
}

fn worker(engine: &Engine, rx: &Mutex<Receiver<PathBuf>>, cancel: &AtomicBool, low_priority: bool) {
    let _priority = crate::platform::BackgroundPriority::enter(low_priority);
    let state = engine.scan_state();
    let mut cache: Vec<CacheEntry> = Vec::with_capacity(CACHE_FLUSH_EVERY);
    let mut n = 0u64;
    loop {
        let next = rx.lock().unwrap_or_else(|e| e.into_inner()).recv();
        let Ok(path) = next else { break };
        if cancel.load(Ordering::Relaxed) {
            continue; // drain so the walker never blocks on a full queue
        }
        n += 1;
        if n % 64 == 1 {
            state.set_current(&path);
        }
        let outcome = crate::util::contain("scan file", || engine.check_file(&path, Some(&mut cache)));
        match outcome.unwrap_or(Err(SkipReason::Other)) {
            Ok(verdict) => {
                state.files.fetch_add(1, Ordering::Relaxed);
                state.bytes.fetch_add(verdict.size, Ordering::Relaxed);
                if verdict.hit.is_some() {
                    state.threats.fetch_add(1, Ordering::Relaxed);
                    engine.handle_detection(&path, &verdict, None, "on-demand scan");
                }
            }
            Err(reason) => {
                state.skipped.fetch_add(1, Ordering::Relaxed);
                if !matches!(reason, SkipReason::Gone | SkipReason::TooLarge | SkipReason::Other) {
                    tracing::debug!(path = %path.display(), ?reason, "skipped");
                }
            }
        }
        if cache.len() >= CACHE_FLUSH_EVERY {
            if let Err(e) = engine.db.store_cache_batch(&cache) {
                tracing::warn!(error = %e, "scan cache flush failed");
            }
            cache.clear();
        }
    }
    let _ = engine.db.store_cache_batch(&cache);
}

/// Blocking: run a complete scan on the calling thread (plus workers).
pub fn run(engine: Arc<Engine>, id: u64, kind: ScanKind, mut roots: Vec<PathBuf>, cancel: Arc<AtomicBool>) {
    let settings = engine.settings();
    if kind == ScanKind::Quick {
        // Also check what is executing right now.
        roots.extend(crate::platform::running_process_images());
    }
    let threads = worker_count(settings.max_scan_threads);
    engine.emit(
        EventKind::ScanStarted,
        Severity::Info,
        format!("{kind:?} scan started"),
        Some(format!("{} location(s), {threads} worker thread(s)", roots.len())),
        None,
        None,
    );

    let (tx, rx) = sync_channel::<PathBuf>(QUEUE_DEPTH);
    let rx = Mutex::new(rx);
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| worker(&engine, &rx, &cancel, settings.low_priority_scans));
        }
        {
            let _priority = crate::platform::BackgroundPriority::enter(settings.low_priority_scans);
            walk(&engine, &roots, &tx, &cancel);
        }
        drop(tx);
    });

    let snap = engine.scan_state().snapshot();
    engine.scan_state().finish();
    let cancelled = cancel.load(Ordering::Relaxed);
    engine.emit(
        EventKind::ScanFinished,
        if snap.threats_found > 0 {
            Severity::High
        } else {
            Severity::Info
        },
        format!(
            "{kind:?} scan {}: {} threat(s)",
            if cancelled { "cancelled" } else { "complete" },
            snap.threats_found
        ),
        Some(format!(
            "{} files scanned, {} skipped (locked, protected or too large), scan #{id}",
            snap.files_scanned, snap.files_skipped
        )),
        None,
        None,
    );
}
