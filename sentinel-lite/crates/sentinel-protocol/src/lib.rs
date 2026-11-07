//! Sentinel-Lite IPC protocol.
//!
//! Transport: `\\.\pipe\sentinel_lite_ipc` (Windows) or a Unix socket in dev builds.
//! Framing:   4-byte little-endian length prefix followed by a UTF-8 JSON body.
//! Handshake: the first frame a client sends MUST be `Request::Auth`. Anything
//!            else, or a wrong token, closes the connection.

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

pub const PIPE_NAME: &str = r"\\.\pipe\sentinel_lite_ipc";
/// Hard upper bound on one frame; protects the service from memory exhaustion.
pub const MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;
/// Bumped on any incompatible change; the UI refuses to talk to a different version.
pub const PROTOCOL_VERSION: u32 = 5;
/// Placeholder sent instead of stored secrets; sending it back means "unchanged".
pub const SECRET_MASK: &str = "********";

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionState {
    /// All enabled shields running, signatures loaded.
    Protected,
    /// Real-time protection disabled by the user, or a shield failed to start.
    AtRisk { reasons: Vec<String> },
    /// Active, unresolved threat detected.
    ThreatDetected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanKind {
    Quick,
    Full,
    Custom,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: u64,
    pub running: bool,
    pub kind: Option<ScanKind>,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub threats_found: u64,
    /// Files skipped because they were locked, unreadable, too large, or excluded.
    pub files_skipped: u64,
    pub current_path: Option<String>,
    pub started_at: Option<i64>,
    pub finished_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldStatus {
    pub name: String,
    pub enabled: bool,
    pub running: bool,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStatus {
    pub protocol_version: u32,
    pub service_version: String,
    pub state: ProtectionState,
    pub realtime_enabled: bool,
    pub shields: Vec<ShieldStatus>,
    pub signature_count: u64,
    pub threats_blocked_total: u64,
    pub quarantine_count: u64,
    pub scan: ScanProgress,
    pub uptime_secs: u64,
    pub memory_bytes: Option<u64>,
    /// Unix time of the last successful signature update.
    #[serde(default)]
    pub last_signature_update: Option<i64>,
    #[serde(default)]
    pub signature_update_error: Option<String>,
    #[serde(default)]
    pub update_in_progress: bool,
    /// Compiled YARA rules currently active.
    #[serde(default)]
    pub yara_rule_count: u64,
    /// Engine CPU use since the previous status request, % of the whole machine.
    #[serde(default)]
    pub cpu_percent: Option<f32>,
    /// Machine-wide RAM in use, %.
    #[serde(default)]
    pub system_memory_percent: Option<f32>,
    /// IPv4 ranges currently blocked by Network Guard.
    #[serde(default)]
    pub network_blocked_ranges: u64,
    /// Windows security features Sentinel-Lite relies on (LSA protection, firewall, UAC).
    #[serde(default)]
    pub hardening: Vec<HardeningCheck>,
    /// CI build number of this installation (0 = local dev build).
    #[serde(default)]
    pub build: u64,
    /// Human-readable state of app self-updates.
    #[serde(default)]
    pub app_update_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardeningCheck {
    pub id: String,
    pub name: String,
    pub ok: bool,
    pub detail: String,
    /// The engine can switch this on (`Request::EnableHardening`).
    pub fixable: bool,
}

/// A program the user explicitly trusts, pinned by content hash so a
/// different file at the same path is not trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedApp {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ThreatDetected,
    ThreatQuarantined,
    ProcessBlocked,
    /// A process was suspended (reversible); the user decides to resume or terminate it.
    ProcessSuspended,
    PersistenceChange,
    BehaviorAlert,
    ScanStarted,
    ScanFinished,
    ScanError,
    SettingsChanged,
    SignaturesUpdated,
    ServiceInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: i64,
    pub timestamp: i64,
    pub kind: EventKind,
    pub severity: Severity,
    pub title: String,
    pub detail: Option<String>,
    pub path: Option<String>,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineItem {
    pub id: String,
    pub original_path: String,
    pub sha256: String,
    pub threat_name: String,
    pub size: u64,
    pub quarantined_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub realtime_protection: bool,
    pub process_monitor: bool,
    pub file_monitor: bool,
    pub persistence_monitor: bool,
    pub behavior_monitor: bool,
    /// Kill a process whose image hash matches a signature.
    pub auto_kill_malicious: bool,
    pub auto_quarantine: bool,
    pub exclusions: Vec<String>,
    /// Extra folders for the real-time file shield, on top of Downloads/Desktop/Temp.
    pub watch_paths: Vec<String>,
    pub max_file_size_mb: u64,
    /// Upper bound on scanner worker threads (0 = auto: half of the logical CPUs, min 1).
    pub max_scan_threads: usize,
    /// Run scan workers at background CPU + I/O priority.
    pub low_priority_scans: bool,
    pub persistence_poll_secs: u64,
    /// Download signature updates automatically.
    pub auto_update: bool,
    pub update_interval_hours: u64,
    /// Also import hashes from public community feeds (abuse.ch MalwareBazaar).
    /// These are unsigned, so validly code-signed files they match are reported, not quarantined.
    pub community_feeds: bool,
    /// abuse.ch Auth-Key (free, https://auth.abuse.ch/), required by MalwareBazaar exports.
    /// The service never sends the real value to clients: it is replaced by [`SECRET_MASK`].
    pub abusech_auth_key: Option<String>,
    /// Official, Ed25519-signed pack URL (`<url>` + `<url>.sig`). Ignored unless the
    /// build embeds a trusted public key.
    pub update_url: Option<String>,
    pub scheduled_scan: bool,
    pub scheduled_scan_hours: u64,
    /// Scan executables, scripts and documents with YARA rules (catches variants no hash list knows).
    pub yara_enabled: bool,
    /// Download the curated YARA Forge "core" rule package with signature updates.
    pub yara_rules_feed: bool,
    /// YARA matches at or above this rule score (0-100) may be quarantined; lower scores only alert.
    pub yara_min_remediate_score: u32,
    /// Larger files are not YARA-scanned (hash checks still apply).
    pub yara_max_file_mb: u64,
    /// Look inside ZIP (incl. Office documents) and ISO/IMG files.
    pub archive_scanning: bool,
    /// Plant hidden decoy files in Documents, Pictures and Desktop; touching one is treated as ransomware.
    pub ransomware_decoys: bool,
    /// When a decoy is modified, suspend the process that is writing the most (reversible).
    pub ransomware_suspend: bool,
    /// When a file is quarantined, also remove the startup entries that launch it (restored with the file).
    pub startup_cleanup: bool,
    /// Execution Guard: stop unsigned programs started from Downloads, Temp or AppData.
    pub block_untrusted_risky: bool,
    /// Attack-surface rule: stop shells/script hosts launched by Office or PDF readers.
    pub block_office_children: bool,
    /// Treat bursts of high-entropy (encrypted-looking) rewrites as ransomware.
    pub entropy_detection: bool,
    /// Network Guard: block connections to known-malicious IP ranges (Windows Filtering Platform).
    pub network_guard: bool,
    /// Programs allowed despite Execution Guard.
    pub trusted_apps: Vec<TrustedApp>,
    /// Install new Sentinel-Lite releases automatically (silently, by the service).
    pub auto_update_app: bool,
    /// Where releases are looked up. `None` = this project's GitHub releases.
    /// Only GitHub API URLs (or a loopback test server) are accepted.
    pub app_update_api: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            realtime_protection: true,
            process_monitor: true,
            file_monitor: true,
            persistence_monitor: true,
            behavior_monitor: true,
            auto_kill_malicious: true,
            auto_quarantine: true,
            exclusions: Vec::new(),
            watch_paths: Vec::new(),
            max_file_size_mb: 256,
            max_scan_threads: 0,
            low_priority_scans: true,
            persistence_poll_secs: 30,
            auto_update: true,
            update_interval_hours: 6,
            community_feeds: true,
            abusech_auth_key: None,
            update_url: None,
            scheduled_scan: true,
            scheduled_scan_hours: 24,
            yara_enabled: true,
            yara_rules_feed: true,
            yara_min_remediate_score: 75,
            yara_max_file_mb: 32,
            archive_scanning: true,
            ransomware_decoys: true,
            ransomware_suspend: true,
            startup_cleanup: true,
            block_untrusted_risky: true,
            block_office_children: true,
            entropy_detection: true,
            network_guard: true,
            trusted_apps: Vec::new(),
            auto_update_app: true,
            app_update_api: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Request {
    Auth {
        token: String,
        client: String,
    },
    GetStatus,
    StartScan {
        kind: ScanKind,
        paths: Vec<String>,
    },
    CancelScan,
    /// The user reviewed outstanding detections; clears the "threat detected" state.
    AcknowledgeThreats,
    /// Download signature updates now.
    UpdateSignatures,
    /// Resume or terminate a process the engine suspended.
    ProcessAction {
        pid: u32,
        action: ProcessActionKind,
    },
    /// Trust the program at `path` (hashed by the service) for Execution Guard.
    TrustApp {
        path: String,
    },
    /// Switch on a Windows hardening feature reported as fixable.
    EnableHardening {
        id: String,
    },
    /// Look for a newer Sentinel-Lite release now and install it if found.
    CheckAppUpdate,
    GetEvents {
        limit: u32,
        before_id: Option<i64>,
    },
    ListQuarantine,
    RestoreQuarantine {
        id: String,
    },
    DeleteQuarantine {
        id: String,
    },
    GetSettings,
    UpdateSettings {
        settings: Settings,
    },
    /// Turn the connection into a push stream of `Response::Event`.
    Subscribe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessActionKind {
    Resume,
    Terminate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Response {
    AuthOk { protocol_version: u32 },
    Status(EngineStatus),
    ScanStarted { scan_id: u64 },
    Events(Vec<SecurityEvent>),
    Quarantine(Vec<QuarantineItem>),
    Settings(Settings),
    Event(SecurityEvent),
    Ok,
    Error { code: ErrorCode, message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Unauthorized,
    /// The operation weakens protection; retry from an elevated (administrator) client.
    ElevationRequired,
    /// The connecting program is not a trusted Sentinel-Lite component.
    Forbidden,
    BadRequest,
    NotFound,
    Busy,
    Internal,
}

impl Response {
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Response::Error {
            code,
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Framing (sync helpers; async users can frame with the same layout)
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("frame of {0} bytes exceeds limit")]
    TooLarge(u32),
    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, FrameError> {
    let body = serde_json::to_vec(msg)?;
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge(u32::MAX))?;
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(len));
    }
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn write_frame<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<(), FrameError> {
    w.write_all(&encode(msg)?)?;
    w.flush()?;
    Ok(())
}

pub fn read_frame<R: Read, T: for<'de> Deserialize<'de>>(r: &mut R) -> Result<T, FrameError> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len);
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    Ok(serde_json::from_slice(&body)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let req = Request::StartScan {
            kind: ScanKind::Custom,
            paths: vec!["C:\\Users".into()],
        };
        let bytes = encode(&req).unwrap();
        let back: Request = read_frame(&mut &bytes[..]).unwrap();
        assert!(matches!(
            back,
            Request::StartScan {
                kind: ScanKind::Custom,
                ..
            }
        ));
    }

    #[test]
    fn rejects_oversized_frame() {
        let mut bytes = (MAX_FRAME_BYTES + 1).to_le_bytes().to_vec();
        bytes.extend_from_slice(b"{}");
        let err = read_frame::<_, Request>(&mut &bytes[..]).unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(_)));
    }

    #[test]
    fn settings_tolerate_missing_fields() {
        let s: Settings = serde_json::from_str(r#"{"realtime_protection": false}"#).unwrap();
        assert!(!s.realtime_protection);
        assert_eq!(s.max_file_size_mb, 256);
    }
}

// ---------------------------------------------------------------------------
// Well-known locations shared by the service and the UI
// ---------------------------------------------------------------------------

pub mod paths {
    use std::path::PathBuf;

    /// `%ProgramData%\SentinelLite` on Windows, `~/.sentinel-lite` elsewhere.
    /// `SENTINEL_HOME` overrides both (used by tests and dev builds).
    pub fn data_dir() -> PathBuf {
        if let Some(p) = std::env::var_os("SENTINEL_HOME") {
            return PathBuf::from(p);
        }
        #[cfg(windows)]
        {
            let base = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
            PathBuf::from(base).join("SentinelLite")
        }
        #[cfg(not(windows))]
        {
            let home = std::env::var_os("HOME").unwrap_or_else(|| ".".into());
            PathBuf::from(home).join(".sentinel-lite")
        }
    }

    /// File holding the per-boot IPC auth token, written by the service.
    pub fn token_file() -> PathBuf {
        data_dir().join("ipc.token")
    }

    /// Dev-only transport on non-Windows hosts.
    #[cfg(not(windows))]
    pub fn unix_socket() -> PathBuf {
        data_dir().join("sentinel.sock")
    }
}
