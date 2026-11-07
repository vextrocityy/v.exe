//! The protection engine: owns the database, quarantine vault, settings,
//! real-time shields and on-demand scans, and publishes security events.

pub mod archive;
pub mod hasher;
pub mod heuristics;
pub mod quarantine;
pub mod realtime;
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
    fn archive_check(&self, path: &Path, sha256: &str, size: u64) -> Option<SignatureHit> {
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
        let statuses = lock(&self.realtime).start(self);
        *self.shields.write().unwrap_or_else(|e| e.into_inner()) = statuses;
        crate::util::contain("decoy sync", || self.sync_decoys());
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
    fn may_suspend(&self, pid: u32, image: &Path) -> bool {
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
                "A hidden decoy file was {}. Legitimate programs never touch it.",
                if state == Some(realtime::decoy::State::Missing) {
                    "deleted or renamed"
                } else {
                    "modified"
                }
            )),
            Some(path),
            None,
        );
        if self.settings().ransomware_suspend {
            let suspects =
                realtime::decoy::heaviest_writers(std::time::Duration::from_secs(1), 512 * 1024, |pid, img| {
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
                            "It wrote {:.1} MB in 1 second right after the decoy changed. It is frozen, not killed: \
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
                        Some(path),
                        None,
                    );
                }
            }
        }
        lock(&self.decoys).replant(&self.db);
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
    fn decoy_change_suspends_the_heavy_writer_and_terminate_quarantines_it() {
        let _serial = realtime::decoy::tests::WRITER_TESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let (dir, engine) = engine_with_rules(RULES);
        let profile = dir.path().join("home").join("alice");
        std::fs::create_dir_all(profile.join("Documents")).unwrap();
        assert_eq!(engine.plant_decoys_for_test(std::slice::from_ref(&profile)), 2);
        let decoy = profile.join("Documents/!_Accounts_2026.xlsx");
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
