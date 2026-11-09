//! The protection engine: owns the database, quarantine vault, settings,
//! real-time shields and on-demand scans, and publishes security events.

pub mod appupdate;
pub mod archive;
pub mod hasher;
pub mod heuristics;
pub mod inspect;
pub mod netguard;
pub mod quarantine;
pub mod realtime;
pub mod rollback;
pub mod scanner;
pub mod scheduler;
pub mod targets;
pub mod update;
pub mod yara;

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
    pub yara: yara::YaraEngine,
    yara_reload: Mutex<()>,
    decoys: Mutex<realtime::decoy::Decoys>,
    /// Processes we suspended, awaiting the user's decision.
    suspended: Mutex<std::collections::HashMap<u32, PathBuf>>,
    last_decoy_response: Mutex<Option<Instant>>,
    firewall: Mutex<Option<netguard::Firewall>>,
    /// (sample time, CPU time used so far, last computed %).
    cpu_sample: Mutex<(Instant, Option<std::time::Duration>, Option<f32>)>,
    app_update_status: Mutex<Option<String>>,
    app_update_running: AtomicBool,
    devices_in_use: Mutex<Vec<DeviceUse>>,
    /// Rollback snapshots this app created.
    owned_snapshots: Mutex<rollback::Owned>,
    snapshot_error: Mutex<Option<String>>,
    snapshot_running: AtomicBool,
    /// A rollback restore is writing files: entropy alerts would be our own doing.
    restore_running: AtomicBool,
    started: Instant,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Engine {
    pub fn new(paths: AppPaths, db: Database, settings: Settings) -> Result<Arc<Self>> {
        let quarantine = Quarantine::new(paths.quarantine.clone())?;
        let decoys = realtime::decoy::Decoys::load(&db);
        let (events, _) = broadcast::channel(256);
        let owned_snapshots = rollback::Owned::load(&paths.data.join("snapshots.json"));
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
            yara: yara::YaraEngine::default(),
            yara_reload: Mutex::new(()),
            decoys: Mutex::new(decoys),
            suspended: Mutex::new(std::collections::HashMap::new()),
            last_decoy_response: Mutex::new(None),
            firewall: Mutex::new(None),
            // Baseline at start-up, so the first status request already has a reading.
            cpu_sample: Mutex::new((Instant::now(), crate::platform::own_cpu_time(), None)),
            app_update_status: Mutex::new(None),
            app_update_running: AtomicBool::new(false),
            devices_in_use: Mutex::new(Vec::new()),
            owned_snapshots: Mutex::new(owned_snapshots),
            snapshot_error: Mutex::new(None),
            snapshot_running: AtomicBool::new(false),
            restore_running: AtomicBool::new(false),
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
        let mut hit = self.db.lookup_hash(&sha256).unwrap_or_else(|e| {
            tracing::error!(error = %e, "signature lookup failed");
            None
        });
        if hit.is_none() {
            hit = self.yara_check(path, &sha256, size);
        }
        if hit.is_none() {
            hit = self.archive_check(path, &sha256, size);
        }
        Ok(FileVerdict { sha256, size, hit })
    }

    /// Look inside ZIP / ISO files. Clean results are cached per archive hash,
    /// rule-set version and signature count, so archives are not reopened on
    /// every scan; a match inside quarantines the whole archive.
    pub(crate) fn archive_check(&self, path: &Path, sha256: &str, size: u64) -> Option<SignatureHit> {
        let s = self.settings();
        let limits = archive::Limits::default();
        if !s.archive_scanning || size == 0 || size > limits.max_total {
            return None;
        }
        archive::kind_of_file(path)?;
        let rules = if s.yara_enabled { self.yara.rules() } else { None };
        let cache_key = format!(
            "arc:{}:{}",
            rules.as_ref().map(|r| r.version.as_str()).unwrap_or("none"),
            self.db.signature_count()
        );
        if let Some(None) = self.db.yara_cached(sha256, &cache_key) {
            return None; // known clean with today's signatures and rules
        }
        let yara_max = s.yara_max_file_mb.saturating_mul(1024 * 1024);
        let mut check = |name: &str, data: &[u8]| -> Option<SignatureHit> {
            let member_sha = hasher::sha256_bytes(data);
            if let Ok(Some(hit)) = self.db.lookup_hash(&member_sha) {
                return Some(hit);
            }
            let rules = rules.as_ref()?;
            if data.len() as u64 > yara_max || !yara::is_candidate_member(name, data) {
                return None;
            }
            let m = yara::scan_bytes(rules, data).ok()?;
            let top = yara::strongest(&m)?;
            Some(yara_hit(&top.namespace, &top.rule, top.score, top.description.clone()))
        };
        match archive::scan(path, limits, &mut check) {
            Ok((Some(found), _)) => {
                let mut hit = found.detail;
                hit.name = format!("{} (inside {})", hit.name, found.member);
                Some(hit)
            }
            Ok((None, stats)) => {
                tracing::debug!(path = %path.display(), members = stats.members_checked, skipped = stats.members_skipped, "archive clean");
                self.db.store_yara(sha256, &cache_key, &None);
                None
            }
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %format!("{e:#}"), "archive not inspected");
                None
            }
        }
    }

    /// YARA pass for files no hash matched. Verdicts are cached per content
    /// hash and rule-set version, so unchanged files are never rescanned.
    fn yara_check(&self, path: &Path, sha256: &str, size: u64) -> Option<SignatureHit> {
        let s = self.settings();
        if !s.yara_enabled || size > s.yara_max_file_mb.saturating_mul(1024 * 1024) || size == 0 {
            return None;
        }
        let rules = self.yara.rules()?;
        if !yara::is_candidate(path) {
            return None;
        }
        let verdict = match self.db.yara_cached(sha256, &rules.version) {
            Some(v) => v,
            None => match yara::scan_file(&rules, path) {
                Ok(matches) => {
                    let v = yara::strongest(&matches)
                        .map(|m| (format!("{}:{}", m.namespace, m.rule), m.score, m.description.clone()));
                    self.db.store_yara(sha256, &rules.version, &v);
                    v
                }
                Err(e) => {
                    // Timeouts / unreadable files are not cached, so they are retried later.
                    tracing::debug!(path = %path.display(), error = %format!("{e:#}"), "YARA scan failed");
                    return None;
                }
            },
        }?;
        let (id, score, description) = verdict;
        let (namespace, rule) = id.split_once(':').unwrap_or(("rules", id.as_str()));
        Some(yara_hit(namespace, rule, score, description))
    }

    /// Safety gate before killing or quarantining. Hashes from vetted sources
    /// (bundled / signed official packs) always remediate. Unsigned community
    /// hashes do not touch Windows system files or validly code-signed binaries,
    /// so a bad feed entry can never break the OS or a legitimate application.
    pub fn may_remediate(&self, path: &Path, hit: &SignatureHit) -> Result<(), String> {
        if hit.is_yara() {
            let min = self.settings().yara_min_remediate_score;
            let score = hit.score.unwrap_or(0);
            if score < min {
                return Err(format!(
                    "the rule's confidence score ({score}) is below the quarantine threshold ({min})"
                ));
            }
        } else if !hit.is_community() {
            return Ok(());
        }
        if let Some(root) = std::env::var_os("SystemRoot") {
            if crate::util::path_within(&path.to_string_lossy(), &root.to_string_lossy()) {
                return Err("it is a Windows system file".into());
            }
        }
        if crate::platform::has_valid_signature(path) {
            return Err("it carries a valid code signature".into());
        }
        Ok(())
    }

    fn match_description(hit: &SignatureHit, sha256: &str) -> String {
        if hit.is_yara() {
            let rule = hit
                .name
                .trim_start_matches("YARA.")
                .split(" (inside ")
                .next()
                .unwrap_or_default();
            let ns = hit.source.trim_start_matches(crate::database::YARA_PREFIX);
            let desc = hit
                .description
                .as_deref()
                .map(|d| format!(" ({d})"))
                .unwrap_or_default();
            format!(
                "YARA rule {ns}:{rule}{desc}, score {}. SHA-256 {sha256}",
                hit.score.unwrap_or(0)
            )
        } else if hit.is_community() {
            format!("community hash list. SHA-256 {sha256}")
        } else {
            format!("SHA-256 {sha256}")
        }
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
                    "Found by {source}: {}. Not quarantined automatically because {reason}. \
                     Review it, quarantine it with a manual scan if confirmed, or add an exclusion if it is safe.",
                    Self::match_description(hit, &verdict.sha256)
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
            Some(format!(
                "Found by {source}: {}",
                Self::match_description(hit, &verdict.sha256)
            )),
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
                if self.settings().startup_cleanup {
                    crate::util::contain("startup clean-up", || {
                        self.cleanup_startup(path, &item.id, &realtime::persistence::startup_folders())
                    });
                }
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

    /// Remove every autostart that launches `path` (now quarantined). Each
    /// removal is recorded against the quarantine item so a restore puts it back.
    pub fn cleanup_startup(&self, path: &Path, quarantine_id: &str, startup_folders: &[PathBuf]) -> usize {
        use realtime::persistence::{self as pers, Removed};
        let mut removed: Vec<(Removed, String)> = pers::remove_registry_references(path);
        for item in pers::startup_items_referencing(path, startup_folders) {
            let sha = hasher::sha256_file(&item, 16 * 1024 * 1024)
                .map(|(h, _)| h)
                .unwrap_or_default();
            let label = format!(
                "Startup item for {}",
                path.file_name().unwrap_or_default().to_string_lossy()
            );
            if let Ok(q) = self.quarantine.isolate(&self.db, &item, &sha, &label) {
                removed.push((Removed::StartupItem { quarantine_id: q.id }, item.display().to_string()));
            }
        }
        for (entry, desc) in &removed {
            if let Ok(json) = serde_json::to_string(entry) {
                self.db.add_removed_persistence(quarantine_id, &json, desc);
            }
            self.emit(
                EventKind::PersistenceChange,
                Severity::Info,
                "Removed startup entry for a quarantined file",
                Some(format!("{desc}. It will be put back if you restore the file.")),
                Some(path),
                None,
            );
        }
        removed.len()
    }

    pub fn restore_quarantine(&self, id: &str) -> Result<PathBuf> {
        let restored = self.quarantine.restore(&self.db, id)?;
        for (json, desc) in self.db.take_removed_persistence(id) {
            let Ok(entry) = serde_json::from_str::<realtime::persistence::Removed>(&json) else {
                continue;
            };
            let result = match &entry {
                realtime::persistence::Removed::StartupItem { quarantine_id } => {
                    self.quarantine.restore(&self.db, quarantine_id).map(|_| ())
                }
                other => realtime::persistence::restore_registry(other),
            };
            match result {
                Ok(()) => {
                    self.emit(
                        EventKind::PersistenceChange,
                        Severity::Info,
                        "Startup entry restored",
                        Some(desc),
                        Some(&restored),
                        None,
                    );
                }
                Err(e) => tracing::warn!(entry = %desc, error = %format!("{e:#}"), "could not restore startup entry"),
            }
        }
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

    /// Quarantine a file the user checked on the File Check page.
    pub fn quarantine_path(&self, path: &Path, threat_name: Option<String>) -> Result<String> {
        anyhow::ensure!(path.is_file(), "{} is not a file", path.display());
        let (sha256, size) =
            hasher::sha256_file(path, u64::MAX).map_err(|r| anyhow::anyhow!("cannot read the file: {r:?}"))?;
        let name = threat_name
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| "Manual.UserQuarantine".into());
        let item = self.quarantine.isolate(&self.db, path, &sha256, &name)?;
        let _ = size;
        self.emit(
            EventKind::ThreatQuarantined,
            Severity::Info,
            format!("{name} moved to quarantine by user"),
            Some(format!("From File Check. Quarantine id {}", item.id)),
            Some(path),
            None,
        );
        if self.settings().startup_cleanup {
            crate::util::contain("startup clean-up", || {
                self.cleanup_startup(path, &item.id, &realtime::persistence::startup_folders())
            });
        }
        Ok(item.id)
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
        let mut out = out;
        let mut yara_ok = false;
        if settings.network_guard && now_unix() - self.db.counter("last_drop_update") as i64 >= 86_400 {
            match netguard::update_drop(&self.paths.data) {
                Ok(n) => {
                    self.db.set_counter("last_drop_update", now_unix());
                    out.notes.push(format!("Spamhaus DROP: {n} ranges"));
                    self.refresh_network_guard();
                    yara_ok = true; // a channel succeeded
                }
                Err(e) => out.errors.push(format!("Spamhaus DROP: {e:#}")),
            }
        }
        if settings.yara_enabled && settings.yara_rules_feed {
            match crate::util::contain("YARA feed update", || self.update_yara_feed(update::YARA_FORGE_CORE)) {
                Some(Ok(note)) => {
                    yara_ok = true;
                    out.notes.push(note)
                }
                Some(Err(e)) => out.errors.push(format!("YARA rules: {e:#}")),
                None => out.errors.push("YARA rules: internal error".into()),
            }
        }
        self.update_running.store(false, Ordering::Release);

        let now = now_unix();
        self.db.set_counter("last_update_attempt", now);
        // Partial success (one channel working) still counts: protection got fresher.
        let succeeded = out.errors.is_empty() || out.imported > 0 || yara_ok;
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
        let mut statuses = lock(&self.realtime).start(self);
        statuses.push(self.apply_network_guard());
        *self.shields.write().unwrap_or_else(|e| e.into_inner()) = statuses;
        crate::util::contain("decoy sync", || self.sync_decoys());
    }

    /// (Re)install Network Guard's WFP filters from the current lists.
    fn apply_network_guard(&self) -> ShieldStatus {
        let s = self.settings();
        let enabled = s.realtime_protection && s.network_guard;
        let mut fw = lock(&self.firewall);
        *fw = None; // closing the old session removes its filters first
        let mut status = ShieldStatus {
            name: "Network Guard".into(),
            enabled,
            running: false,
            detail: None,
        };
        if !enabled {
            return status;
        }
        let ranges = netguard::load_ranges(&self.paths.data);
        match netguard::Firewall::install(&ranges) {
            Ok(f) => {
                status.running = true;
                status.detail = Some(if f.ranges == 0 {
                    "No block list yet: Spamhaus DROP downloads with the next update".into()
                } else {
                    format!("Blocking {} malicious IP ranges (Spamhaus DROP + your list)", f.ranges)
                });
                *fw = Some(f);
            }
            Err(e) => {
                tracing::error!(error = %format!("{e:#}"), "Network Guard could not install filters");
                status.detail = Some(format!("{e:#}"));
            }
        }
        status
    }

    fn refresh_network_guard(&self) {
        let status = self.apply_network_guard();
        let mut shields = self.shields.write().unwrap_or_else(|e| e.into_inner());
        shields.retain(|s| s.name != status.name);
        shields.push(status);
    }

    /// Trust a program for Execution Guard, pinned to its current content hash.
    pub fn trust_app(self: &Arc<Self>, path: &str) -> anyhow::Result<()> {
        let (sha256, _) =
            hasher::sha256_file(Path::new(path), u64::MAX).map_err(|r| anyhow::anyhow!("cannot read {path}: {r:?}"))?;
        let mut s = self.settings();
        let app = TrustedApp {
            path: path.to_string(),
            sha256,
        };
        if !s.trusted_apps.contains(&app) {
            s.trusted_apps.push(app);
        }
        self.update_settings(s)?;
        self.emit(
            EventKind::SettingsChanged,
            Severity::Medium,
            "Program trusted by user",
            None,
            Some(Path::new(path)),
            None,
        );
        Ok(())
    }

    pub fn is_trusted_app(&self, sha256: &str) -> bool {
        self.settings
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .trusted_apps
            .iter()
            .any(|t| t.sha256 == sha256)
    }

    /// Check for (and install) a newer Vigil release. Blocking.
    pub fn check_app_update(&self) -> Result<String, String> {
        if self.app_update_running.swap(true, Ordering::AcqRel) {
            return Err("an app update check is already running".into());
        }
        *lock(&self.app_update_status) = Some("Checking for app updates…".into());
        let result = crate::util::contain("app update", || appupdate::check_and_install(self))
            .unwrap_or_else(|| Err(anyhow::anyhow!("internal error")))
            .map_err(|e| format!("{e:#}"));
        self.app_update_running.store(false, Ordering::Release);
        self.db.set_counter("last_app_update_check", now_unix());
        *lock(&self.app_update_status) = Some(match &result {
            Ok(line) => line.clone(),
            Err(e) => format!("Update check failed: {e}"),
        });
        if let Err(e) = &result {
            tracing::warn!(error = %e, "app update check failed");
        }
        result
    }

    pub fn start_app_update(self: &Arc<Self>) -> Result<(), String> {
        if self.app_update_running.load(Ordering::Acquire) {
            return Err("an app update check is already running".into());
        }
        let e = self.clone();
        std::thread::Builder::new()
            .name("app-update".into())
            .spawn(move || {
                let _ = e.check_app_update();
            })
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn enable_hardening(&self, id: &str) -> anyhow::Result<String> {
        let msg = crate::platform::enable_hardening(id)?;
        self.emit(
            EventKind::SettingsChanged,
            Severity::Info,
            "Windows hardening changed",
            Some(msg.clone()),
            None,
            None,
        );
        Ok(msg)
    }

    /// Engine CPU % since the previous sample. Requests arriving sooner than
    /// 0.5 s after the last sample get the last value instead of resetting the
    /// baseline, so several clients polling at once never starve the reading.
    fn cpu_percent(&self) -> Option<f32> {
        let mut sample = lock(&self.cpu_sample);
        let (at, used, last) = *sample;
        let wall = at.elapsed().as_secs_f32();
        if wall < 0.5 {
            return last;
        }
        let now_used = crate::platform::own_cpu_time()?;
        let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1) as f32;
        let pct = used.map(|u| (now_used.saturating_sub(u).as_secs_f32() / wall / cpus * 100.0).min(100.0));
        *sample = (Instant::now(), Some(now_used), pct.or(last));
        pct.or(last)
    }

    // ----- ransomware decoys -------------------------------------------------------------

    /// Plant (or remove) decoys to match settings; report decoys that were
    /// tampered with while nobody was watching.
    pub fn sync_decoys(&self) {
        let s = self.settings();
        let mut decoys = lock(&self.decoys);
        if s.realtime_protection && s.file_monitor && s.ransomware_decoys {
            for (path, state) in decoys.tampered() {
                self.emit(
                    EventKind::BehaviorAlert,
                    Severity::High,
                    "Ransomware decoy changed while protection was off",
                    Some(format!("The decoy was {state:?}. Check recent files in this folder.").to_lowercase()),
                    Some(&path),
                    None,
                );
            }
            let n = decoys.plant(&self.db, &decoy_profiles());
            if n > 0 {
                tracing::info!(planted = n, "ransomware decoys in place");
            }
        } else {
            decoys.remove_all(&self.db);
        }
    }

    #[cfg(all(test, unix))]
    pub fn plant_decoys_for_test(&self, profiles: &[PathBuf]) -> usize {
        lock(&self.decoys).plant(&self.db, profiles)
    }

    pub fn is_decoy(&self, path: &Path) -> bool {
        lock(&self.decoys).is_decoy(path)
    }

    /// File Shield saw a change to a decoy. Respond on a separate thread
    /// (sampling takes a second) so the watcher keeps draining events.
    pub fn on_decoy_event(self: &Arc<Self>, path: PathBuf) {
        let e = self.clone();
        let _ = std::thread::Builder::new()
            .name("decoy-response".into())
            .spawn(move || crate::util::contain("decoy response", || e.respond_to_decoy(&path)));
    }

    /// Never suspend the OS, ourselves, excluded or validly code-signed programs.
    pub(crate) fn may_suspend(&self, pid: u32, image: &Path) -> bool {
        if pid <= 4 || pid == std::process::id() || self.is_excluded(image) {
            return false;
        }
        if let Some(root) = std::env::var_os("SystemRoot") {
            if crate::util::path_within(&image.to_string_lossy(), &root.to_string_lossy()) {
                return false;
            }
        }
        !crate::platform::has_valid_signature(image)
    }

    pub(crate) fn respond_to_decoy(&self, path: &Path) {
        let state = lock(&self.decoys).state(path);
        if !matches!(
            state,
            Some(realtime::decoy::State::Modified | realtime::decoy::State::Missing)
        ) {
            return; // metadata-only event or not ours: decoy content is unchanged
        }
        {
            let mut last = lock(&self.last_decoy_response);
            if last.is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(15)) {
                return; // one attack touches several decoys: respond once
            }
            *last = Some(Instant::now());
        }
        self.emit(
            EventKind::BehaviorAlert,
            Severity::Critical,
            "Ransomware behaviour: a decoy file was changed",
            Some(format!(
                "A hidden decoy file was {}. Legitimate programs never touch it.{}",
                if state == Some(realtime::decoy::State::Missing) {
                    "deleted or renamed"
                } else {
                    "modified"
                },
                self.rollback_hint()
            )),
            Some(path),
            None,
        );
        if self.settings().ransomware_suspend {
            self.suspend_heaviest_writer(path, "the decoy changed");
        }
        lock(&self.decoys).replant(&self.db);
    }

    /// Freeze the heaviest eligible writer right now (shared by the decoy and
    /// entropy detectors). Reversible: the user terminates or resumes it.
    fn suspend_heaviest_writer(&self, trigger: &Path, reason: &str) {
        let suspects = realtime::decoy::heaviest_writers(std::time::Duration::from_secs(1), 512 * 1024, |pid, img| {
            self.may_suspend(pid, img)
        });
        match suspects.first() {
            Some(s) if crate::platform::suspend(s.pid) => {
                lock(&self.suspended).insert(s.pid, s.image.clone());
                self.emit(
                    EventKind::ProcessSuspended,
                    Severity::Critical,
                    format!(
                        "Suspended {}",
                        s.image.file_name().unwrap_or_default().to_string_lossy()
                    ),
                    Some(format!(
                        "It wrote {:.1} MB in 1 second right after {reason}. It is frozen, not killed: \
                         choose Terminate (and quarantine it) or Resume in Activity.",
                        s.bytes_written as f64 / 1e6
                    )),
                    Some(&s.image),
                    Some(s.pid),
                );
            }
            Some(s) => tracing::warn!(pid = s.pid, "could not suspend ransomware suspect"),
            None => {
                self.emit(
                    EventKind::BehaviorAlert,
                    Severity::High,
                    "No process could be suspended",
                    Some(
                        "No unsigned, non-system program was writing heavily. Windows components and signed \
                         programs are never suspended automatically."
                            .into(),
                    ),
                    Some(trigger),
                    None,
                );
            }
        }
    }

    /// File Shield saw a burst of rewrites across folders and most of the
    /// sampled files now look encrypted (high entropy, not a compressed format).
    pub fn on_mass_encryption(self: &Arc<Self>, samples: Vec<PathBuf>, encrypted: usize) {
        if self.restore_running.load(Ordering::SeqCst) {
            return; // a rollback is rewriting files: that burst is ours
        }
        let e = self.clone();
        let _ = std::thread::Builder::new().name("entropy-response".into()).spawn(move || {
            crate::util::contain("entropy response", || {
                {
                    let mut last = lock(&e.last_decoy_response);
                    if last.is_some_and(|t| t.elapsed() < std::time::Duration::from_secs(15)) {
                        return;
                    }
                    *last = Some(Instant::now());
                }
                let first = samples.first().cloned().unwrap_or_default();
                e.emit(
                    EventKind::BehaviorAlert,
                    Severity::Critical,
                    "Ransomware behaviour: files are being encrypted",
                    Some(format!(
                        "Many files across several folders were rewritten in seconds, and {encrypted} of {} sampled now \
                         contain encrypted-looking data. Recent: {}.{}",
                        samples.len(),
                        samples.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "),
                        e.rollback_hint()
                    )),
                    Some(&first),
                    None,
                );
                if e.settings().ransomware_suspend {
                    e.suspend_heaviest_writer(&first, "the encryption burst");
                }
            });
        });
    }

    /// The user's decision on a suspended process.
    pub fn process_action(&self, pid: u32, action: ProcessActionKind) -> Result<String, String> {
        let image = lock(&self.suspended).remove(&pid);
        match action {
            ProcessActionKind::Resume => {
                if !crate::platform::resume(pid) {
                    return Err("could not resume the process (it may have exited)".into());
                }
                self.emit(
                    EventKind::ServiceInfo,
                    Severity::Medium,
                    "Process resumed by user",
                    None,
                    image.as_deref(),
                    Some(pid),
                );
                Ok("resumed".into())
            }
            ProcessActionKind::Terminate => {
                let image = image.or_else(|| crate::platform::image_path(pid));
                if !crate::platform::terminate(pid) {
                    return Err("could not terminate the process (it may have exited)".into());
                }
                self.emit(
                    EventKind::ProcessBlocked,
                    Severity::High,
                    "Process terminated by user",
                    None,
                    image.as_deref(),
                    Some(pid),
                );
                // Quarantine its executable too (reversible), unless it is a system or signed binary.
                if let Some(image) = image.filter(|img| self.may_suspend(pid, img)) {
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    if let Ok((sha256, size)) = hasher::sha256_file(&image, u64::MAX) {
                        let verdict = FileVerdict {
                            sha256,
                            size,
                            hit: Some(SignatureHit {
                                name: "Behavior.Ransomware.Decoy".into(),
                                severity: Severity::Critical,
                                source: "behavior:decoy".into(),
                                score: None,
                                description: Some("modified a ransomware decoy file".into()),
                            }),
                        };
                        self.handle_detection(&image, &verdict, Some(pid), "Ransomware decoys");
                    }
                }
                Ok("terminated".into())
            }
        }
    }

    pub fn restart_realtime(self: &Arc<Self>) {
        self.stop_realtime();
        self.start_realtime();
    }

    pub fn stop_realtime(&self) {
        lock(&self.realtime).stop();
    }

    // ----- YARA ------------------------------------------------------------------------

    /// (Re)load YARA rules: use the precompiled cache when it matches the
    /// sources, else compile in a child process. Blocking; call off the async runtime.
    pub fn reload_yara(&self) -> Result<String, String> {
        let _one_at_a_time = lock(&self.yara_reload);
        let dirs = yara::rule_dirs(&self.paths);
        let compiled = yara::compiled_path(&self.paths);
        let _ = std::fs::create_dir_all(yara::feeds_dir(&self.paths));
        let result = self
            .yara
            .load_or_compile(&dirs, &compiled, || compile_rules(&self.paths, None))
            .map_err(|e| format!("{e:#}"));
        match &result {
            Ok(_) => {
                if let Some(rules) = self.yara.rules() {
                    self.db.prune_yara_cache(&rules.version);
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "YARA rules could not be loaded");
                self.yara.set_error(format!("YARA rules failed to load: {e}"));
            }
        }
        result
    }

    /// Download a YARA rule package; install it only if it compiles.
    pub fn update_yara_feed(&self, url: &str) -> anyhow::Result<String> {
        let rules = update::fetch_yara_zip(url)?;
        let dir = yara::feeds_dir(&self.paths);
        std::fs::create_dir_all(&dir)?;
        let dest = dir.join("yara-forge-core.yar");
        if std::fs::read(&dest).map(|old| old == rules).unwrap_or(false) {
            return Ok("YARA rules already current".into());
        }
        let candidate = dir.join("yara-forge-core.yar.new");
        std::fs::write(&candidate, &rules)?;
        if let Err(e) = compile_rules(&self.paths, Some(&candidate)) {
            let _ = std::fs::remove_file(&candidate);
            anyhow::bail!("downloaded rules rejected: {e:#}");
        }
        std::fs::rename(&candidate, &dest)?;
        let line = self.reload_yara().map_err(anyhow::Error::msg)?;
        Ok(format!("YARA rules updated: {line}"))
    }

    // ----- ransomware rollback -------------------------------------------------------

    fn snapshots_file(&self) -> PathBuf {
        self.paths.data.join("snapshots.json")
    }

    pub fn last_snapshot(&self) -> Option<i64> {
        lock(&self.owned_snapshots).newest()
    }

    /// Take a snapshot of the system drive now and prune our older ones.
    pub fn create_snapshot(&self) -> Result<Snapshot, String> {
        if self.snapshot_running.swap(true, Ordering::SeqCst) {
            return Err("a snapshot is already being taken".into());
        }
        let result = self.create_snapshot_inner();
        self.snapshot_running.store(false, Ordering::SeqCst);
        *lock(&self.snapshot_error) = result.as_ref().err().cloned();
        result
    }

    fn create_snapshot_inner(&self) -> Result<Snapshot, String> {
        self.db.set_counter("last_snapshot_attempt", now_unix());
        let volume = rollback::system_volume();
        let id = rollback::create(&volume).map_err(|e| format!("Could not take a snapshot: {e:#}"))?;
        let taken = now_unix();
        let stale: Vec<String> = {
            let mut owned = lock(&self.owned_snapshots);
            owned.ids.push((id.clone(), taken));
            owned.ids.sort_by_key(|(_, t)| std::cmp::Reverse(*t));
            let keep = owned.ids.len().min(rollback::KEEP);
            let stale = owned.ids.split_off(keep);
            if let Err(e) = owned.save(&self.snapshots_file()) {
                tracing::warn!(error = %e, "could not record snapshot");
            }
            stale.into_iter().map(|(id, _)| id).collect()
        };
        for old in stale {
            if let Err(e) = rollback::delete(&old) {
                tracing::warn!(id = %old, error = %format!("{e:#}"), "could not delete old snapshot");
            }
        }
        self.emit(
            EventKind::Recovery,
            Severity::Info,
            "Rollback snapshot taken",
            Some(format!(
                "Files on {volume} can be rolled back to this point if ransomware strikes.                  The newest {} snapshots are kept.",
                rollback::KEEP
            )),
            None,
            None,
        );
        Ok(Snapshot {
            id,
            created_at: taken,
            volume,
            ours: true,
        })
    }

    /// All snapshots on the machine (ours flagged), newest first. Forgets our
    /// snapshots that Windows has since deleted (it prunes when space runs low).
    pub fn list_snapshots(&self) -> Result<Vec<rollback::ShadowCopy>, String> {
        let mut all = rollback::list().map_err(|e| format!("Could not list snapshots: {e:#}"))?;
        let mut owned = lock(&self.owned_snapshots);
        let live: std::collections::HashSet<String> = all.iter().map(|s| s.snapshot.id.clone()).collect();
        let before = owned.ids.len();
        owned.ids.retain(|(id, _)| live.contains(id));
        if owned.ids.len() != before {
            let _ = owned.save(&self.snapshots_file());
        }
        for s in &mut all {
            s.snapshot.ours = owned.ids.iter().any(|(id, _)| *id == s.snapshot.id);
        }
        all.sort_by_key(|s| std::cmp::Reverse(s.snapshot.created_at));
        Ok(all)
    }

    fn find_snapshot(&self, id: &str) -> Result<rollback::ShadowCopy, String> {
        if !rollback::valid_id(id) {
            return Err("invalid snapshot id".into());
        }
        self.list_snapshots()?
            .into_iter()
            .find(|s| s.snapshot.id == id)
            .ok_or_else(|| "That snapshot no longer exists (Windows may have removed it to free space).".into())
    }

    /// Files that differ from the snapshot (encrypted-looking first).
    pub fn rollback_preview(&self, id: &str, folders: Vec<String>) -> Result<(Vec<FileChange>, bool), String> {
        let shadow = self.find_snapshot(id)?;
        let profiles = targets::user_profiles();
        let folders: Vec<PathBuf> = if folders.is_empty() {
            rollback::default_folders(&profiles)
        } else {
            folders.into_iter().map(PathBuf::from).filter(|p| p.is_dir()).collect()
        };
        let skip = |p: &Path| {
            self.is_decoy(p) || p.to_string_lossy().contains(rollback::BACKUP_DIR_NAME)
        };
        let mut changes = Vec::new();
        for folder in folders {
            let Some(snap) = rollback::snapshot_path(&shadow.device, &shadow.snapshot.volume, &folder) else {
                continue; // on another drive
            };
            changes.extend(rollback::diff_folder(&folder, &snap, shadow.snapshot.created_at, &skip));
        }
        rollback::sort_changes(&mut changes);
        let truncated = changes.len() > rollback::MAX_CHANGES;
        changes.truncate(rollback::MAX_CHANGES);
        Ok((changes, truncated))
    }

    /// Put the snapshot's copies of `paths` back. Only files inside a user
    /// profile can be restored; the current copies go to a backup folder.
    pub fn rollback_restore(&self, id: &str, paths: Vec<String>) -> Result<(u32, Vec<String>, Option<String>), String> {
        let shadow = self.find_snapshot(id)?;
        let profiles = targets::user_profiles();
        let stamp = rollback::stamp(now_unix());
        self.restore_running.store(true, Ordering::SeqCst);
        let mut restored = 0u32;
        let mut failed = Vec::new();
        let mut backup_root: Option<PathBuf> = None;
        for p in paths {
            let live = PathBuf::from(&p);
            let outcome = (|| -> Result<(), String> {
                if !rollback::allowed(&live, &profiles) || self.is_decoy(&live) {
                    return Err("not in a user folder".into());
                }
                let snap = rollback::snapshot_path(&shadow.device, &shadow.snapshot.volume, &live)
                    .ok_or("not on the snapshot's drive")?;
                let backup = rollback::backup_path(&live, &profiles, &stamp);
                rollback::restore_file(&snap, &live, backup.as_deref()).map_err(|e| e.to_string())?;
                if live.exists() && backup_root.is_none() {
                    backup_root = backup.and_then(|b| {
                        profiles
                            .iter()
                            .find(|pr| b.starts_with(pr))
                            .map(|pr| pr.join(rollback::BACKUP_DIR_NAME).join(&stamp))
                    });
                }
                Ok(())
            })();
            match outcome {
                Ok(()) => restored += 1,
                Err(e) => failed.push(format!("{p}: {e}")),
            }
        }
        self.restore_running.store(false, Ordering::SeqCst);
        let backup_dir = backup_root.filter(|b| b.exists()).map(|b| b.display().to_string());
        self.emit(
            EventKind::Recovery,
            if failed.is_empty() { Severity::Info } else { Severity::Medium },
            format!("Restored {restored} file(s) from the snapshot of {}", rollback::stamp(shadow.snapshot.created_at)),
            Some(match (&backup_dir, failed.len()) {
                (Some(b), 0) => format!("The versions they replaced were moved to {b}."),
                (Some(b), n) => format!("{n} could not be restored. The versions that were replaced are in {b}."),
                (None, 0) => "Nothing was overwritten.".into(),
                (None, n) => format!("{n} could not be restored: {}", failed.join("; ")),
            }),
            None,
            None,
        );
        Ok((restored, failed, backup_dir))
    }

    /// One sentence for ransomware alerts: where the user can recover from.
    fn rollback_hint(&self) -> String {
        match self.last_snapshot() {
            Some(t) => format!(
                " Files changed since the snapshot of {} can be restored: open Recovery.",
                rollback::stamp(t)
            ),
            None => String::new(),
        }
    }

    /// Disable a scheduled task the user decided they do not want. Only names of
    /// tasks that actually exist are passed on to `schtasks`.
    pub fn disable_task(&self, name: &str) -> Result<(), String> {
        let mut map = std::collections::HashMap::new();
        realtime::tasks::collect(&realtime::tasks::tasks_dir(), &mut map);
        if !map.contains_key(&format!("{}{name}", realtime::tasks::KEY_PREFIX)) {
            return Err(format!("no scheduled task named {name}"));
        }
        realtime::tasks::set_enabled(name, false).map_err(|e| format!("{e:#}"))?;
        self.emit(
            EventKind::PersistenceChange,
            Severity::Info,
            "Scheduled task disabled",
            Some(format!(
                "{name} will no longer run. To undo, enable it again in Task Scheduler."
            )),
            None,
            None,
        );
        Ok(())
    }

    // ----- privacy ---------------------------------------------------------------

    pub fn set_devices_in_use(&self, v: Vec<DeviceUse>) {
        *lock(&self.devices_in_use) = v;
    }

    pub fn shutdown(&self) {
        if let Some((stop, handle)) = lock(&self.scheduler).take() {
            stop.store(true, Ordering::Relaxed);
            // The scheduler may be mid-way through a download or rule compile. Give it a
            // moment, but never let it hold up a service stop / uninstall: the update path
            // is atomic (temp file + rename, SQLite transactions), so abandoning it is safe.
            let deadline = Instant::now() + std::time::Duration::from_secs(3);
            while !handle.is_finished() && Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            if handle.is_finished() {
                let _ = handle.join();
            } else {
                tracing::warn!("scheduler busy at shutdown; not waiting for it");
            }
        }
        self.cancel_scan();
        self.stop_realtime();
    }

    // ----- status --------------------------------------------------------------------

    pub fn status(&self) -> EngineStatus {
        let settings = self.settings();
        let mut shields = self.shields.read().unwrap_or_else(|e| e.into_inner()).clone();
        let yara_rules = self.yara.rules();
        shields.push(ShieldStatus {
            name: "YARA Rules".into(),
            enabled: settings.yara_enabled,
            running: settings.yara_enabled && yara_rules.is_some(),
            detail: self.yara.status_line().or_else(|| Some("Loading rules…".into())),
        });
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
            yara_rule_count: yara_rules.map(|r| r.rule_count as u64).unwrap_or(0),
            cpu_percent: self.cpu_percent(),
            system_memory_percent: crate::platform::system_memory_percent(),
            network_blocked_ranges: lock(&self.firewall).as_ref().map(|f| f.ranges as u64).unwrap_or(0),
            hardening: crate::platform::hardening_checks(),
            build: appupdate::build(),
            app_update_status: lock(&self.app_update_status).clone(),
            devices_in_use: lock(&self.devices_in_use).clone(),
            last_snapshot: self.last_snapshot(),
            snapshot_error: lock(&self.snapshot_error).clone(),
        }
    }
}

/// Profiles that get decoys. Unit tests plant their own and never touch real profiles.
fn decoy_profiles() -> Vec<PathBuf> {
    if cfg!(test) {
        Vec::new()
    } else {
        targets::user_profiles()
    }
}

fn yara_hit(namespace: &str, rule: &str, score: u32, description: Option<String>) -> SignatureHit {
    SignatureHit {
        name: format!("YARA.{rule}"),
        severity: match score {
            90.. => Severity::Critical,
            75..=89 => Severity::High,
            _ => Severity::Medium,
        },
        source: format!("{}{namespace}", crate::database::YARA_PREFIX),
        score: Some(score),
        description,
    }
}

/// Compile YARA rules (or validate one candidate file) in a short-lived child
/// process: the compiler's memory peak and any crash stay out of the service.
/// Unit tests (whose executable is the test harness) compile in-process.
pub fn compile_rules(paths: &AppPaths, validate_only: Option<&Path>) -> anyhow::Result<String> {
    if cfg!(test) {
        return compile_rules_in_process(paths, validate_only);
    }
    let exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(exe);
    match validate_only {
        Some(file) => cmd.arg("yara-validate").arg(file),
        None => cmd.arg("yara-compile"),
    };
    cmd.env("SENTINEL_HOME", &paths.data)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;
        cmd.creation_flags(CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS);
    }
    let mut child = cmd.spawn()?;
    let deadline = Instant::now() + std::time::Duration::from_secs(300);
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            anyhow::bail!("YARA compiler timed out");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let out = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.status.success() {
        Ok(stdout.lines().last().unwrap_or_default().to_string())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!(
            "{}",
            stderr
                .lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("compiler failed")
        )
    }
}

/// The body of `sentinel-service yara-compile` / `yara-validate`.
pub fn compile_rules_in_process(paths: &AppPaths, validate_only: Option<&Path>) -> anyhow::Result<String> {
    if let Some(file) = validate_only {
        let n = yara::validate(&std::fs::read(file)?)?;
        return Ok(format!("{n} rules valid"));
    }
    let started = Instant::now();
    let (set, report) = yara::compile(&yara::rule_dirs(paths));
    let set = set.ok_or_else(|| anyhow::anyhow!("no YARA rules found"))?;
    std::fs::create_dir_all(paths.data.join("rules"))?;
    set.save(&yara::compiled_path(paths))?;
    let mut line = format!(
        "{} rules from {} file(s), compiled in {:.1} s",
        set.rule_count,
        report.loaded_files,
        started.elapsed().as_secs_f32()
    );
    if !report.errors.is_empty() {
        line.push_str(&format!("; skipped: {}", report.errors.join(" | ")));
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine_with_rules(rules: &str) -> (tempfile::TempDir, Arc<Engine>) {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(dir.path().join("data"));
        paths.create_all().unwrap();
        std::fs::create_dir_all(paths.data.join("rules")).unwrap();
        std::fs::write(paths.data.join("rules").join("local.yar"), rules).unwrap();
        let s = Settings {
            realtime_protection: false,
            ..Settings::default()
        };
        let engine = Engine::new(paths, Database::open_in_memory().unwrap(), s).unwrap();
        engine.reload_yara().unwrap();
        (dir, engine)
    }

    const RULES: &str = r#"
rule High_Confidence { meta: score = 90 description = "test family" strings: $a = "HIGH-CONFIDENCE-MARKER" condition: $a }
rule Low_Confidence  { meta: score = 60 strings: $a = "LOW-CONFIDENCE-MARKER" condition: $a }
"#;

    fn add_sig(engine: &Engine, data: &[u8], name: &str) {
        let h = hasher::sha256_bytes(data);
        engine
            .db
            .upsert_signatures("test@1", [(h.as_str(), name, Severity::High)])
            .unwrap();
    }

    #[test]
    fn archive_member_hash_match_quarantines_the_archive() {
        let (dir, engine) = engine_with_rules(RULES);
        let payload = b"MZ pretend trojan payload";
        add_sig(&engine, payload, "Trojan.Test");
        let zip = dir.path().join("invoice.zip");
        std::fs::write(
            &zip,
            archive::tests::make_zip(&[("readme.txt", b"hi"), ("invoice.pdf.exe", payload)]),
        )
        .unwrap();
        let v = engine.check_file(&zip, None).unwrap();
        let hit = v.hit.clone().expect("member should match");
        assert_eq!(hit.name, "Trojan.Test (inside invoice.zip/invoice.pdf.exe)");
        engine.handle_detection(&zip, &v, None, "test");
        assert!(!zip.exists());

        // A clean archive is cached as clean.
        let clean = dir.path().join("photos.zip");
        std::fs::write(&clean, archive::tests::make_zip(&[("a.jpg", b"jpeg bytes")])).unwrap();
        assert!(engine.check_file(&clean, None).unwrap().hit.is_none());
        *engine.settings.write().unwrap() = Settings {
            archive_scanning: false,
            ..engine.settings()
        };
        std::fs::write(&zip, archive::tests::make_zip(&[("x.exe", payload)])).unwrap();
        assert!(engine.check_file(&zip, None).unwrap().hit.is_none(), "disabled");
    }

    #[test]
    fn yara_match_inside_iso_is_reported_with_member_path() {
        let (dir, engine) = engine_with_rules(RULES);
        let iso = dir.path().join("delivery.iso");
        std::fs::write(
            &iso,
            archive::tests::make_iso(
                &[("Document.lnk", b"shortcut"), ("run.ps1", b"HIGH-CONFIDENCE-MARKER")],
                true,
            ),
        )
        .unwrap();
        let hit = engine.check_file(&iso, None).unwrap().hit.expect("YARA inside ISO");
        assert_eq!(hit.name, "YARA.High_Confidence (inside delivery.iso/run.ps1)");
        assert_eq!(hit.score, Some(90));
    }

    #[test]
    fn startup_entries_are_removed_with_the_file_and_restored_with_it() {
        let (dir, engine) = engine_with_rules(RULES);
        let startup = dir.path().join("Startup");
        std::fs::create_dir_all(&startup).unwrap();
        let malware = dir.path().join("updater.exe");
        let payload = b"MZ startup trojan";
        std::fs::write(&malware, payload).unwrap();
        add_sig(&engine, payload, "Trojan.Startup");
        let shortcut = startup.join("Updater.desktop");
        std::fs::write(&shortcut, format!("[Desktop Entry]\nExec={}\n", malware.display())).unwrap();
        let unrelated = startup.join("Other.desktop");
        std::fs::write(&unrelated, "Exec=/usr/bin/true").unwrap();

        let v = engine.check_file(&malware, None).unwrap();
        // handle_detection uses the real Startup folders; call the clean-up with ours.
        let item = engine
            .quarantine
            .isolate(&engine.db, &malware, &v.sha256, "Trojan.Startup")
            .unwrap();
        assert_eq!(
            engine.cleanup_startup(&malware, &item.id, std::slice::from_ref(&startup)),
            1
        );
        assert!(!shortcut.exists(), "shortcut quarantined");
        assert!(unrelated.exists());
        assert_eq!(engine.db.quarantine_count(), 2);

        engine.restore_quarantine(&item.id).unwrap();
        assert!(malware.exists());
        assert!(shortcut.exists(), "shortcut restored together with the file");
        assert_eq!(engine.db.quarantine_count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn encryption_burst_through_file_shield_suspends_the_writer() {
        let _serial = realtime::decoy::tests::WRITER_TESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let docs = dir.path().join("docs");
        let paths = AppPaths::new(dir.path().join("data"));
        paths.create_all().unwrap();
        let s = Settings {
            realtime_protection: true,
            process_monitor: false,
            persistence_monitor: false,
            network_guard: false,
            watch_paths: vec![docs.display().to_string()],
            ..Settings::default()
        };
        for i in 0..4 {
            std::fs::create_dir_all(docs.join(format!("folder{i}"))).unwrap();
        }
        let engine = Engine::new(paths, Database::open_in_memory().unwrap(), s).unwrap();
        engine.start_realtime();
        std::thread::sleep(std::time::Duration::from_millis(500));

        let fake = dir.path().join("locker");
        std::fs::copy("/bin/dd", &fake).unwrap();
        let mut child = std::process::Command::new(&fake)
            .args(["if=/dev/zero", "of=/dev/null", "bs=1M"])
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        // "Encrypt" 100 documents across 4 folders in a burst.
        for n in 0..100 {
            let mut data = vec![0u8; 8192];
            getrandom::fill(&mut data).unwrap();
            std::fs::write(
                docs.join(format!("folder{}", n % 4)).join(format!("report{n}.txt")),
                &data,
            )
            .unwrap();
        }
        let deadline = Instant::now() + std::time::Duration::from_secs(10);
        let mut suspended = false;
        while Instant::now() < deadline && !suspended {
            std::thread::sleep(std::time::Duration::from_millis(200));
            suspended = engine
                .db
                .recent_events(20, None)
                .unwrap()
                .iter()
                .any(|e| matches!(e.kind, EventKind::ProcessSuspended) && e.pid == Some(child.id()));
        }
        let titles: Vec<String> = engine
            .db
            .recent_events(20, None)
            .unwrap()
            .into_iter()
            .map(|e| e.title)
            .collect();
        let _ = engine.process_action(child.id(), ProcessActionKind::Resume);
        let _ = child.kill();
        let _ = child.wait();
        engine.shutdown();
        assert!(
            titles.iter().any(|t| t.contains("files are being encrypted")),
            "{titles:?}"
        );
        assert!(suspended, "{titles:?}");
    }

    #[cfg(unix)]
    #[test]
    fn decoy_change_suspends_the_heavy_writer_and_terminate_quarantines_it() {
        let _serial = realtime::decoy::tests::WRITER_TESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let (dir, engine) = engine_with_rules(RULES);
        let profile = dir.path().join("home").join("alice");
        std::fs::create_dir_all(profile.join("Documents")).unwrap();
        assert_eq!(engine.plant_decoys_for_test(std::slice::from_ref(&profile)), 2);
        let decoy = profile.join("Documents").join("!_Accounts_2026.xlsx");
        assert!(engine.is_decoy(&decoy));

        // "Ransomware": an unsigned copy of dd writing continuously.
        let fake = dir.path().join("encryptor");
        std::fs::copy("/bin/dd", &fake).unwrap();
        let mut child = std::process::Command::new(&fake)
            .args(["if=/dev/zero", "of=/dev/null", "bs=1M"])
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::fs::write(&decoy, b"encrypted!").unwrap();
        engine.respond_to_decoy(&decoy);

        let stat = std::fs::read_to_string(format!("/proc/{}/stat", child.id())).unwrap();
        let state = stat[stat.rfind(')').unwrap() + 2..].chars().next().unwrap();
        let events = engine.db.recent_events(10, None).unwrap();
        let suspended = events
            .iter()
            .any(|e| matches!(e.kind, EventKind::ProcessSuspended) && e.pid == Some(child.id()));
        if !suspended {
            let _ = child.kill();
            panic!(
                "not suspended; events: {:?}",
                events.iter().map(|e| &e.title).collect::<Vec<_>>()
            );
        }
        assert_eq!(state, 'T', "process is stopped");

        engine.process_action(child.id(), ProcessActionKind::Terminate).unwrap();
        let _ = child.wait();
        assert!(!fake.exists(), "its executable was quarantined");
        assert!(engine
            .db
            .list_quarantine()
            .unwrap()
            .iter()
            .any(|q| q.threat_name == "Behavior.Ransomware.Decoy"));
        // The decoy was re-planted intact.
        assert!(engine.is_decoy(&decoy));
        assert_ne!(std::fs::read(&decoy).unwrap(), b"encrypted!");
    }

    #[test]
    fn file_check_reports_verdicts_without_changing_files() {
        let (dir, engine) = engine_with_rules(RULES);
        let drop = dir.path().join("dropped");
        std::fs::create_dir_all(drop.join("sub")).unwrap();

        let known = drop.join("known.bin");
        std::fs::write(&known, b"MZ known trojan bytes").unwrap();
        add_sig(&engine, b"MZ known trojan bytes", "Trojan.Known");
        let high = drop.join("sub").join("dropper.ps1");
        std::fs::write(&high, b"HIGH-CONFIDENCE-MARKER").unwrap();
        let low = drop.join("tool.ps1");
        std::fs::write(&low, b"LOW-CONFIDENCE-MARKER").unwrap();
        let trick = drop.join("invoice.pdf.exe");
        std::fs::write(&trick, b"just some bytes").unwrap();
        let clean = drop.join("notes.txt");
        std::fs::write(&clean, b"shopping list").unwrap();

        let (reports, truncated) = inspect::inspect_paths(&engine, &[drop.display().to_string()]);
        assert!(!truncated);
        assert_eq!(reports.len(), 5, "folder expanded recursively");
        let by_name = |n: &str| reports.iter().find(|r| r.path.ends_with(n)).unwrap();
        assert_eq!(by_name("known.bin").verdict, Verdict::Malicious);
        assert_eq!(by_name("known.bin").detections[0].name, "Trojan.Known");
        assert_eq!(by_name("dropper.ps1").verdict, Verdict::Malicious);
        assert_eq!(by_name("dropper.ps1").detections[0].score, Some(90));
        assert_eq!(by_name("tool.ps1").verdict, Verdict::Suspicious);
        assert_eq!(by_name("invoice.pdf.exe").verdict, Verdict::Suspicious);
        assert!(by_name("invoice.pdf.exe").summary.contains("double extension"));
        assert_eq!(by_name("notes.txt").verdict, Verdict::NoThreats);
        assert!(by_name("notes.txt").sha256.is_some());
        // Checking changes nothing.
        for p in [&known, &high, &low, &trick, &clean] {
            assert!(p.exists());
        }
        assert_eq!(engine.db.quarantine_count(), 0);

        // Missing path -> error report, not a failure.
        let (r, _) = inspect::inspect_paths(&engine, &[dir.path().join("nope").display().to_string()]);
        assert_eq!(r[0].verdict, Verdict::Error);

        // The user can quarantine what they checked.
        engine.quarantine_path(&known, Some("Trojan.Known".into())).unwrap();
        assert!(!known.exists());
        assert_eq!(engine.db.quarantine_count(), 1);
    }

    #[test]
    fn cpu_reading_survives_rapid_polling() {
        let (_dir, engine) = engine_with_rules(RULES);
        std::thread::sleep(std::time::Duration::from_millis(600));
        let first = engine.cpu_percent();
        assert!(first.is_some(), "baseline taken at start-up");
        for _ in 0..20 {
            assert_eq!(engine.cpu_percent(), first, "rapid polls reuse the last value");
        }
    }

    #[test]
    fn yara_high_score_match_is_quarantined() {
        let (dir, engine) = engine_with_rules(RULES);
        assert!(engine.yara.rules().unwrap().rule_count >= 2);
        let f = dir.path().join("dropper.ps1");
        std::fs::write(&f, b"Write-Host x # HIGH-CONFIDENCE-MARKER").unwrap();

        let v = engine.check_file(&f, None).unwrap();
        let hit = v.hit.clone().expect("YARA should match");
        assert_eq!(hit.name, "YARA.High_Confidence");
        assert_eq!(hit.score, Some(90));
        assert!(hit.is_yara());
        engine.handle_detection(&f, &v, None, "test");
        assert!(!f.exists(), "score >= 75 is quarantined");
        assert_eq!(engine.db.quarantine_count(), 1);
    }

    #[test]
    fn yara_low_score_match_only_alerts() {
        let (dir, engine) = engine_with_rules(RULES);
        let f = dir.path().join("tool.ps1");
        std::fs::write(&f, b"LOW-CONFIDENCE-MARKER").unwrap();
        let v = engine.check_file(&f, None).unwrap();
        let hit = v.hit.clone().unwrap();
        assert!(engine
            .may_remediate(&f, &hit)
            .unwrap_err()
            .contains("below the quarantine threshold"));
        engine.handle_detection(&f, &v, None, "test");
        assert!(f.exists(), "low-confidence match must stay in place");
        assert!(matches!(engine.status().state, ProtectionState::ThreatDetected));
    }

    #[test]
    fn non_candidates_and_disabled_yara_are_skipped() {
        let (dir, engine) = engine_with_rules(RULES);
        let txt = dir.path().join("notes.txt");
        std::fs::write(&txt, b"HIGH-CONFIDENCE-MARKER").unwrap();
        assert!(
            engine.check_file(&txt, None).unwrap().hit.is_none(),
            "plain text is not YARA-scanned"
        );

        let ps = dir.path().join("x.ps1");
        std::fs::write(&ps, b"HIGH-CONFIDENCE-MARKER").unwrap();
        *engine.settings.write().unwrap() = Settings {
            yara_enabled: false,
            ..engine.settings()
        };
        assert!(engine.check_file(&ps, None).unwrap().hit.is_none());
    }

    #[test]
    fn verdicts_are_cached_and_invalidated_by_rule_changes() {
        let (dir, engine) = engine_with_rules(RULES);
        let f = dir.path().join("a.ps1");
        std::fs::write(&f, b"clean content").unwrap();
        let v = engine.check_file(&f, None).unwrap();
        let version = engine.yara.rules().unwrap().version.clone();
        assert_eq!(engine.db.yara_cached(&v.sha256, &version), Some(None));

        // New rule that matches the same content: cache must not hide it.
        std::fs::write(
            engine.paths.data.join("rules").join("new.yar"),
            "rule Clean_Now_Bad { meta: score = 80 strings: $a = \"clean content\" condition: $a }",
        )
        .unwrap();
        engine.reload_yara().unwrap();
        assert_ne!(engine.yara.rules().unwrap().version, version);
        assert!(engine.check_file(&f, None).unwrap().hit.is_some());
    }
}
