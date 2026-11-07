//! The protection engine: owns the database, quarantine vault, settings,
//! real-time shields and on-demand scans, and publishes security events.

pub mod hasher;
pub mod heuristics;
pub mod quarantine;
pub mod realtime;
pub mod scanner;
pub mod scheduler;
pub mod targets;
pub mod update;

use crate::database::{now_unix, CacheEntry, Database, SignatureHit};
use crate::settings;
use anyhow::Result;
use hasher::SkipReason;
use quarantine::Quarantine;
use sentinel_protocol::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, UNIX_EPOCH};
use tokio::sync::broadcast;

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub data: PathBuf,
    pub database: PathBuf,
    pub quarantine: PathBuf,
    pub signatures: PathBuf,
    pub settings: PathBuf,
    pub logs: PathBuf,
}

impl AppPaths {
    pub fn new(data: PathBuf) -> Self {
        Self {
            database: data.join("sentinel.db"),
            quarantine: data.join("quarantine"),
            signatures: data.join("signatures"),
            settings: data.join("settings.json"),
            logs: data.join("logs"),
            data,
        }
    }

    pub fn create_all(&self) -> std::io::Result<()> {
        for d in [&self.data, &self.quarantine, &self.signatures, &self.logs] {
            std::fs::create_dir_all(d)?;
        }
        Ok(())
    }
}

/// Outcome of checking one file.
#[derive(Debug, Clone)]
pub struct FileVerdict {
    pub sha256: String,
    pub size: u64,
    pub hit: Option<SignatureHit>,
}

pub struct Engine {
    pub db: Database,
    pub quarantine: Quarantine,
    pub paths: AppPaths,
    settings: RwLock<Settings>,
    events: broadcast::Sender<SecurityEvent>,
    scan: Arc<scanner::ScanState>,
    scan_cancel: Mutex<Option<Arc<AtomicBool>>>,
    realtime: Mutex<realtime::RealtimeManager>,
    shields: RwLock<Vec<ShieldStatus>>,
    /// Detections that were not automatically quarantined.
    unresolved_threats: AtomicU64,
    update_running: AtomicBool,
    scheduler: Mutex<Option<(Arc<AtomicBool>, std::thread::JoinHandle<()>)>>,
    started: Instant,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Engine {
    pub fn new(paths: AppPaths, db: Database, settings: Settings) -> Result<Arc<Self>> {
        let quarantine = Quarantine::new(paths.quarantine.clone())?;
        let (events, _) = broadcast::channel(256);
        Ok(Arc::new(Self {
            db,
            quarantine,
            paths,
            settings: RwLock::new(settings),
            events,
            scan: Arc::new(scanner::ScanState::default()),
            scan_cancel: Mutex::new(None),
            realtime: Mutex::new(realtime::RealtimeManager::default()),
            shields: RwLock::new(Vec::new()),
            unresolved_threats: AtomicU64::new(0),
            update_running: AtomicBool::new(false),
            scheduler: Mutex::new(None),
            started: Instant::now(),
        }))
    }

    // ----- settings ------------------------------------------------------------

    pub fn settings(&self) -> Settings {
        self.settings.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Validate, persist and apply new settings (restarts the real-time shields).
    pub fn update_settings(self: &Arc<Self>, new: Settings) -> Result<Settings> {
        let new = settings::merge_secrets(&self.settings(), settings::sanitize(new));
        settings::save(&self.paths.settings, &new)?;
        *self.settings.write().unwrap_or_else(|e| e.into_inner()) = new.clone();
        self.emit(
            EventKind::SettingsChanged,
            Severity::Info,
            "Settings updated",
            None,
            None,
            None,
        );
        self.restart_realtime();
        Ok(new)
    }

    /// Exclusions are case-insensitive, component-aware prefix matches. The engine's own data
    /// directory (DB, quarantine vault) is always excluded.
    pub fn is_excluded(&self, path: &Path) -> bool {
        if path.starts_with(&self.paths.data) {
            return true;
        }
        let p = path.to_string_lossy();
        self.settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .exclusions
            .iter()
            .any(|ex| crate::util::path_within(&p, ex))
    }

    // ----- events ------------------------------------------------------------

    pub fn emit(
        &self,
        kind: EventKind,
        severity: Severity,
        title: impl Into<String>,
        detail: Option<String>,
        path: Option<&Path>,
        pid: Option<u32>,
    ) -> SecurityEvent {
        let ev = SecurityEvent {
            id: 0,
            timestamp: now_unix(),
            kind,
            severity,
            title: title.into(),
            detail,
            path: path.map(|p| p.to_string_lossy().into_owned()),
            pid,
        };
        let ev = match self.db.insert_event(ev.clone()) {
            Ok(stored) => stored,
            Err(e) => {
                tracing::error!(error = %e, "failed to persist event");
                ev
            }
        };
        match ev.severity {
            Severity::High | Severity::Critical => tracing::warn!(title = %ev.title, path = ?ev.path, "security event"),
            _ => tracing::info!(title = %ev.title, path = ?ev.path, "event"),
        }
        let _ = self.events.send(ev.clone()); // no subscribers is fine
        ev
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SecurityEvent> {
        self.events.subscribe()
    }

    // ----- detection ---------------------------------------------------------

    /// Hash `path` (using the scan cache) and look it up in the signature DB.
    /// `cache_sink` lets the scanner batch cache writes; `None` writes immediately.
    pub fn check_file(&self, path: &Path, cache_sink: Option<&mut Vec<CacheEntry>>) -> Result<FileVerdict, SkipReason> {
        let meta = std::fs::metadata(path).map_err(|e| hasher::classify(&e))?;
        if !meta.is_file() {
            return Err(SkipReason::Other);
        }
        let size = meta.len();
        let max = self.settings().max_file_size_mb.saturating_mul(1024 * 1024);
        if size > max {
            return Err(SkipReason::TooLarge);
        }
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let key = path.to_string_lossy();

        let sha256 = match self.db.cached_hash(&key, size, mtime) {
            Some(h) => h,
            None => {
                let (h, _) = hasher::sha256_file(path, max)?;
                let entry = CacheEntry {
                    path: key.into_owned(),
                    size,
                    mtime,
                    sha256: h.clone(),
                };
                match cache_sink {
                    Some(sink) => sink.push(entry),
                    None => {
                        let _ = self.db.store_cache_batch(std::slice::from_ref(&entry));
                    }
                }
                h
            }
        };
        let hit = self.db.lookup_hash(&sha256).unwrap_or_else(|e| {
            tracing::error!(error = %e, "signature lookup failed");
            None
        });
        Ok(FileVerdict { sha256, size, hit })
    }

    /// Safety gate before killing or quarantining. Hashes from vetted sources
    /// (bundled / signed official packs) always remediate. Unsigned community
    /// hashes do not touch Windows system files or validly code-signed binaries,
    /// so a bad feed entry can never break the OS or a legitimate application.
    pub fn may_remediate(&self, path: &Path, hit: &SignatureHit) -> Result<(), &'static str> {
        if !hit.is_community() {
            return Ok(());
        }
        if let Some(root) = std::env::var_os("SystemRoot") {
            if crate::util::path_within(&path.to_string_lossy(), &root.to_string_lossy()) {
                return Err("it is a Windows system file");
            }
        }
        if crate::platform::has_valid_signature(path) {
            return Err("it carries a valid code signature");
        }
        Ok(())
    }

    /// React to a signature match: record it and quarantine if configured.
    pub fn handle_detection(&self, path: &Path, verdict: &FileVerdict, pid: Option<u32>, source: &str) {
        let Some(hit) = &verdict.hit else { return };
        if let Err(reason) = self.may_remediate(path, hit) {
            self.unresolved_threats.fetch_add(1, Ordering::Relaxed);
            self.emit(
                EventKind::ThreatDetected,
                Severity::Medium,
                format!("{}: suspicious file left in place", hit.name),
                Some(format!(
                    "Found by {source}. It matches a community hash, but {reason}, so it was not quarantined automatically. \
                     Review it with your security team or submit it to your vendor. SHA-256 {}",
                    verdict.sha256
                )),
                Some(path),
                pid,
            );
            return;
        }
        self.db.incr_counter("threats_blocked");
        self.emit(
            EventKind::ThreatDetected,
            hit.severity,
            format!("{} detected", hit.name),
            Some(format!("Found by {source}. SHA-256 {}", verdict.sha256)),
            Some(path),
            pid,
        );
        if !self.settings().auto_quarantine {
            self.unresolved_threats.fetch_add(1, Ordering::Relaxed);
            return;
        }
        match self.quarantine.isolate(&self.db, path, &verdict.sha256, &hit.name) {
            Ok(item) => {
                self.emit(
                    EventKind::ThreatQuarantined,
                    Severity::Info,
                    format!("{} moved to quarantine", hit.name),
                    Some(format!("Quarantine id {}", item.id)),
                    Some(path),
                    pid,
                );
            }
            Err(e) => {
                self.unresolved_threats.fetch_add(1, Ordering::Relaxed);
                self.emit(
                    EventKind::ScanError,
                    Severity::High,
                    format!("Could not quarantine {}", hit.name),
                    Some(format!("{e:#}")),
                    Some(path),
                    pid,
                );
            }
        }
    }

    // ----- quarantine ----------------------------------------------------------

    pub fn restore_quarantine(&self, id: &str) -> Result<PathBuf> {
        let restored = self.quarantine.restore(&self.db, id)?;
        self.emit(
            EventKind::SettingsChanged,
            Severity::Medium,
            "File restored from quarantine",
            Some("Its hash was added to the allow-list.".into()),
            Some(&restored),
            None,
        );
        Ok(restored)
    }

    pub fn delete_quarantine(&self, id: &str) -> Result<()> {
        self.quarantine.delete(&self.db, id)?;
        self.emit(
            EventKind::ServiceInfo,
            Severity::Info,
            "Quarantined file permanently deleted",
            None,
            None,
            None,
        );
        Ok(())
    }

    /// The user reviewed the dashboard alert; clears the "threat detected" state.
    pub fn acknowledge_threats(&self) {
        self.unresolved_threats.store(0, Ordering::Relaxed);
    }

    // ----- scans -----------------------------------------------------------------

    pub fn start_scan(self: &Arc<Self>, kind: ScanKind, paths: Vec<String>) -> Result<u64, String> {
        let mut cancel_slot = lock(&self.scan_cancel);
        if self.scan.is_running() {
            return Err("a scan is already running".into());
        }
        let roots: Vec<PathBuf> = match kind {
            ScanKind::Quick => targets::quick_scan_roots(),
            ScanKind::Full => targets::full_scan_roots(),
            ScanKind::Custom => {
                let v: Vec<PathBuf> = paths.into_iter().map(PathBuf::from).filter(|p| p.exists()).collect();
                if v.is_empty() {
                    return Err("none of the requested paths exist".into());
                }
                v
            }
        };
        let cancel = Arc::new(AtomicBool::new(false));
        *cancel_slot = Some(cancel.clone());
        let id = self.scan.begin(kind);
        let engine = self.clone();
        std::thread::Builder::new()
            .name(format!("scan-{id}"))
            .spawn(move || scanner::run(engine, id, kind, roots, cancel))
            .map_err(|e| e.to_string())?;
        Ok(id)
    }

    pub fn cancel_scan(&self) -> bool {
        match lock(&self.scan_cancel).as_ref() {
            Some(flag) if self.scan.is_running() => {
                flag.store(true, Ordering::Relaxed);
                true
            }
            _ => false,
        }
    }

    pub(crate) fn scan_state(&self) -> &scanner::ScanState {
        &self.scan
    }

    // ----- signature updates -------------------------------------------------------

    pub fn update_running(&self) -> bool {
        self.update_running.load(Ordering::Acquire)
    }

    /// Blocking: run all enabled update channels now.
    pub fn update_signatures(&self) -> Result<usize, String> {
        if self.update_running.swap(true, Ordering::AcqRel) {
            return Err("an update is already running".into());
        }
        let settings = self.settings();
        let before = self.db.signature_count();
        let out = crate::util::contain("signature update", || {
            update::run(
                &self.db,
                &update::Sources::from_settings(&settings),
                &update::trusted_keys(),
            )
        })
        .unwrap_or_else(|| update::Outcome {
            errors: vec!["internal error during update".into()],
            ..Default::default()
        });
        self.update_running.store(false, Ordering::Release);

        let now = now_unix();
        self.db.set_counter("last_update_attempt", now);
        let succeeded = out.errors.is_empty() || out.imported > 0;
        if succeeded {
            self.db.set_counter("last_signature_update", now);
        }
        let error = (!out.errors.is_empty()).then(|| out.errors.join("; "));
        self.db.set_meta("update_error", error.as_deref());
        let added = self.db.signature_count().saturating_sub(before);
        self.emit(
            EventKind::SignaturesUpdated,
            if succeeded { Severity::Info } else { Severity::Medium },
            if succeeded {
                format!("Signatures updated: {added} new")
            } else {
                "Signature update failed".to_string()
            },
            Some(
                [out.notes.join("; "), error.clone().unwrap_or_default()]
                    .join(" ")
                    .trim()
                    .to_string(),
            ),
            None,
            None,
        );
        match error {
            Some(e) if !succeeded => Err(e),
            _ => Ok(added as usize),
        }
    }

    /// Non-blocking variant for IPC: runs the update on its own thread.
    pub fn start_update(self: &Arc<Self>) -> Result<(), String> {
        if self.update_running() {
            return Err("an update is already running".into());
        }
        let e = self.clone();
        std::thread::Builder::new()
            .name("sig-update".into())
            .spawn(move || {
                let _ = e.update_signatures();
            })
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn start_scheduler(self: &Arc<Self>) {
        let stop = Arc::new(AtomicBool::new(false));
        let (e, s) = (self.clone(), stop.clone());
        match std::thread::Builder::new()
            .name("scheduler".into())
            .spawn(move || scheduler::run(e, s))
        {
            Ok(handle) => *lock(&self.scheduler) = Some((stop, handle)),
            Err(err) => tracing::error!(error = %err, "could not start scheduler"),
        }
    }

    // ----- real-time ---------------------------------------------------------------

    pub fn start_realtime(self: &Arc<Self>) {
        let statuses = lock(&self.realtime).start(self);
        *self.shields.write().unwrap_or_else(|e| e.into_inner()) = statuses;
    }

    pub fn restart_realtime(self: &Arc<Self>) {
        self.stop_realtime();
        self.start_realtime();
    }

    pub fn stop_realtime(&self) {
        lock(&self.realtime).stop();
    }

    pub fn shutdown(&self) {
        if let Some((stop, handle)) = lock(&self.scheduler).take() {
            stop.store(true, Ordering::Relaxed);
            let _ = handle.join();
        }
        self.cancel_scan();
        self.stop_realtime();
    }

    // ----- status --------------------------------------------------------------------

    pub fn status(&self) -> EngineStatus {
        let settings = self.settings();
        let shields = self.shields.read().unwrap_or_else(|e| e.into_inner()).clone();
        let signature_count = self.db.signature_count();

        let mut reasons = Vec::new();
        if !settings.realtime_protection {
            reasons.push("Real-time protection is turned off".to_string());
        }
        for s in shields.iter().filter(|s| s.enabled && !s.running) {
            reasons.push(format!("{} is not running", s.name));
        }
        if signature_count == 0 {
            reasons.push("No threat signatures loaded".to_string());
        }
        let state = if self.unresolved_threats.load(Ordering::Relaxed) > 0 {
            ProtectionState::ThreatDetected
        } else if reasons.is_empty() {
            ProtectionState::Protected
        } else {
            ProtectionState::AtRisk { reasons }
        };

        EngineStatus {
            protocol_version: PROTOCOL_VERSION,
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            state,
            realtime_enabled: settings.realtime_protection,
            shields,
            signature_count,
            threats_blocked_total: self.db.counter("threats_blocked"),
            quarantine_count: self.db.quarantine_count(),
            scan: self.scan.snapshot(),
            uptime_secs: self.started.elapsed().as_secs(),
            memory_bytes: crate::platform::working_set_bytes(),
            last_signature_update: Some(self.db.counter("last_signature_update") as i64).filter(|t| *t > 0),
            signature_update_error: self.db.meta("update_error"),
            update_in_progress: self.update_running(),
        }
    }
}
