//! Behavioural heuristics.
//!
//! Two detectors, both designed around *combinations* of signals so that a
//! single weak indicator never raises an alert on its own:
//!
//! * [`assess_process`] scores a newly started process from its lineage and the
//!   *shape* of its command line.
//! * [`RansomwareDetector`] watches the rate and spread of file modifications.
//!
//! Heuristic hits raise alerts; only signature matches trigger automatic
//! kill / quarantine, to keep false-positive damage at zero.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Process heuristics
// ---------------------------------------------------------------------------

pub struct ProcessContext<'a> {
    pub image: &'a Path,
    pub command_line: Option<&'a str>,
    pub parent_image: Option<&'a Path>,
}

#[derive(Debug, Default, Clone)]
pub struct Assessment {
    pub score: u32,
    pub reasons: Vec<String>,
}

impl Assessment {
    fn add(&mut self, score: u32, reason: impl Into<String>) {
        self.score += score;
        self.reasons.push(reason.into());
    }
}

pub const ALERT_MEDIUM: u32 = 40;
pub const ALERT_HIGH: u32 = 70;

/// Interpreters that are frequently abused as a second stage.
const SCRIPT_HOSTS: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "cmd.exe",
];
/// Applications that have no ordinary reason to launch a script host.
const DOCUMENT_APPS: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "onenote.exe",
    "mspub.exe",
    "visio.exe",
    "acrord32.exe",
    "acrobat.exe",
    "foxitpdfreader.exe",
    "foxitreader.exe",
    "sumatrapdf.exe",
];

/// Final path component, lower-cased. Splits on both separators so Windows
/// paths are handled identically on every host (and in tests).
fn file_name_lower(p: &Path) -> String {
    let s = p.to_string_lossy();
    s.rsplit(['\\', '/']).next().unwrap_or_default().to_ascii_lowercase()
}

/// Longest run of base64-alphabet characters in `s`.
fn longest_base64_run(s: &str) -> usize {
    let mut best = 0;
    let mut cur = 0;
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=') {
            cur += 1;
            best = best.max(cur);
        } else {
            cur = 0;
        }
    }
    best
}

/// PowerShell accepts prefixes of `-EncodedCommand` (`-e`, `-enc`, ...) and the alias `-ec`.
fn has_encoded_command_flag(cmd: &str) -> bool {
    cmd.split_whitespace().any(|tok| {
        let t = tok.trim_start_matches(['-', '/']).to_ascii_lowercase();
        tok.len() > t.len() && !t.is_empty() && ("encodedcommand".starts_with(&t) || t == "ec")
    })
}

fn in_user_writable_location(p: &Path) -> bool {
    let s = p.to_string_lossy().to_ascii_lowercase().replace('/', "\\");
    [
        "\\appdata\\local\\temp\\",
        "\\downloads\\",
        "\\windows\\temp\\",
        "\\users\\public\\",
    ]
    .iter()
    .any(|frag| s.contains(frag))
}

/// Attack-surface rule: a document application starting a shell / script host.
pub fn office_spawning_shell(image: &Path, parent: &Path) -> bool {
    SCRIPT_HOSTS.contains(&file_name_lower(image).as_str()) && DOCUMENT_APPS.contains(&file_name_lower(parent).as_str())
}

/// Folders where downloaded or dropped malware typically starts from.
pub fn risky_location(p: &Path) -> Option<&'static str> {
    let s = p.to_string_lossy().to_ascii_lowercase().replace('/', "\\");
    [
        ("\\appdata\\local\\temp\\", "Temp"),
        ("\\windows\\temp\\", "Windows Temp"),
        ("\\downloads\\", "Downloads"),
        ("\\appdata\\roaming\\", "AppData\\Roaming"),
    ]
    .iter()
    .find(|(frag, _)| s.contains(frag))
    .map(|(_, name)| *name)
}

pub fn assess_process(ctx: &ProcessContext<'_>) -> Assessment {
    let mut a = Assessment::default();
    let image = file_name_lower(ctx.image);
    let is_script_host = SCRIPT_HOSTS.contains(&image.as_str());

    if is_script_host {
        if let Some(parent) = ctx.parent_image {
            let parent_name = file_name_lower(parent);
            if DOCUMENT_APPS.contains(&parent_name.as_str()) {
                a.add(50, format!("{image} launched by document application {parent_name}"));
            }
        }
    }

    if let Some(cmd) = ctx.command_line {
        let is_powershell = image == "powershell.exe" || image == "pwsh.exe";
        if is_powershell && has_encoded_command_flag(cmd) {
            a.add(30, "PowerShell started with an encoded command");
        }
        if is_script_host && longest_base64_run(cmd) >= 200 {
            a.add(25, "command line carries a large encoded blob");
        }
        if is_script_host && cmd.len() > 2000 {
            a.add(10, "unusually long command line");
        }
    }

    if in_user_writable_location(ctx.image) {
        a.add(10, "executable runs from a temporary / download folder");
    }
    a
}

// ---------------------------------------------------------------------------
// Entropy (encryption) check
// ---------------------------------------------------------------------------

/// Shannon entropy in bits per byte (0..=8). Encrypted or compressed data is ~8.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Formats that are compressed by design: high entropy there is normal.
fn naturally_high_entropy(path: &Path) -> bool {
    const EXT: &[&str] = &[
        "zip", "7z", "rar", "gz", "xz", "bz2", "zst", "cab", "jpg", "jpeg", "png", "gif", "webp", "heic", "mp3", "mp4",
        "m4a", "mkv", "avi", "mov", "webm", "flac", "ogg", "docx", "xlsx", "pptx", "odt", "pdf", "jar", "apk", "msi",
        "iso", "vhdx", "pack", "idx", "woff2",
    ];
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| EXT.contains(&e.to_ascii_lowercase().as_str()))
}

/// Does this recently modified file look encrypted? Reads at most 64 KiB.
pub fn looks_encrypted(path: &Path) -> bool {
    if naturally_high_entropy(path) {
        return false;
    }
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = vec![0u8; 64 * 1024];
    let n = std::io::Read::read(&mut f, &mut buf).unwrap_or(0);
    n >= 512 && shannon_entropy(&buf[..n]) > 7.5
}

// ---------------------------------------------------------------------------
// Ransomware-style mass modification detector
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileActivity {
    Modified,
    /// Renamed and the extension changed (a strong ransomware trait).
    RenamedNewExtension,
    Renamed,
}

#[derive(Debug, Clone)]
pub struct RansomwareAlert {
    pub weight: u32,
    pub directories: usize,
    pub sample_paths: Vec<PathBuf>,
}

pub struct RansomwareDetector {
    window: Duration,
    weight_threshold: u32,
    min_directories: usize,
    cooldown: Duration,
    events: VecDeque<(Instant, u32, PathBuf)>,
    last_alert: Option<Instant>,
}

impl Default for RansomwareDetector {
    fn default() -> Self {
        // ~60 weighted changes in 10 s spread over at least 4 folders.
        Self::new(Duration::from_secs(10), 60, 4)
    }
}

impl RansomwareDetector {
    pub fn new(window: Duration, weight_threshold: u32, min_directories: usize) -> Self {
        Self {
            window,
            weight_threshold,
            min_directories,
            cooldown: Duration::from_secs(60),
            events: VecDeque::new(),
            last_alert: None,
        }
    }

    pub fn record(&mut self, path: &Path, activity: FileActivity) -> Option<RansomwareAlert> {
        self.record_at(Instant::now(), path, activity)
    }

    pub fn record_at(&mut self, now: Instant, path: &Path, activity: FileActivity) -> Option<RansomwareAlert> {
        let weight = match activity {
            FileActivity::Modified => 1,
            FileActivity::Renamed => 2,
            FileActivity::RenamedNewExtension => 4,
        };
        self.events.push_back((now, weight, path.to_path_buf()));
        while let Some((t, _, _)) = self.events.front() {
            if now.duration_since(*t) > self.window {
                self.events.pop_front();
            } else {
                break;
            }
        }
        // Bound memory under a flood.
        while self.events.len() > 10_000 {
            self.events.pop_front();
        }

        if let Some(t) = self.last_alert {
            if now.duration_since(t) < self.cooldown {
                return None;
            }
        }
        let total: u32 = self.events.iter().map(|(_, w, _)| w).sum();
        if total < self.weight_threshold {
            return None;
        }
        let mut dirs: HashMap<&Path, ()> = HashMap::new();
        for (_, _, p) in &self.events {
            if let Some(parent) = p.parent() {
                dirs.insert(parent, ());
            }
        }
        if dirs.len() < self.min_directories {
            return None;
        }
        self.last_alert = Some(now);
        Some(RansomwareAlert {
            weight: total,
            directories: dirs.len(),
            sample_paths: self.events.iter().rev().take(5).map(|(_, _, p)| p.clone()).collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign_process_scores_low() {
        let a = assess_process(&ProcessContext {
            image: Path::new(r"C:\Windows\System32\notepad.exe"),
            command_line: Some("notepad.exe C:\\notes.txt"),
            parent_image: Some(Path::new(r"C:\Windows\explorer.exe")),
        });
        assert!(a.score < ALERT_MEDIUM, "{a:?}");
    }

    #[test]
    fn document_app_spawning_encoded_powershell_is_high() {
        let blob = "A".repeat(300);
        let cmd = format!("powershell.exe -NoProfile -enc {blob}");
        let a = assess_process(&ProcessContext {
            image: Path::new(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"),
            command_line: Some(&cmd),
            parent_image: Some(Path::new(
                r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            )),
        });
        assert!(a.score >= ALERT_HIGH, "{a:?}");
        assert_eq!(a.reasons.len(), 3);
    }

    #[test]
    fn asr_and_risky_location_rules() {
        assert!(office_spawning_shell(
            Path::new(r"C:\Windows\System32\cmd.exe"),
            Path::new(r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE")
        ));
        assert!(office_spawning_shell(
            Path::new(r"C:\Windows\System32\wscript.exe"),
            Path::new(r"C:\x\AcroRd32.exe")
        ));
        assert!(!office_spawning_shell(
            Path::new(r"C:\Windows\System32\cmd.exe"),
            Path::new(r"C:\Windows\explorer.exe")
        ));
        assert!(!office_spawning_shell(
            Path::new(r"C:\Windows\splwow64.exe"),
            Path::new(r"C:\x\WINWORD.EXE")
        ));

        assert_eq!(
            risky_location(Path::new(r"C:\Users\a\Downloads\setup.exe")),
            Some("Downloads")
        );
        assert_eq!(
            risky_location(Path::new(r"C:\Users\a\AppData\Local\Temp\x\y.exe")),
            Some("Temp")
        );
        assert_eq!(
            risky_location(Path::new(r"C:\Users\a\AppData\Roaming\z.exe")),
            Some("AppData\\Roaming")
        );
        assert_eq!(risky_location(Path::new(r"C:\Program Files\App\app.exe")), None);
        assert_eq!(
            risky_location(Path::new(r"C:\Users\a\AppData\Local\Programs\app.exe")),
            None
        );
    }

    #[test]
    fn encoded_flag_prefix_matching() {
        assert!(has_encoded_command_flag("powershell -EncodedCommand AAA"));
        assert!(has_encoded_command_flag("powershell -ec AAA"));
        assert!(!has_encoded_command_flag(
            "powershell -ExecutionPolicy Bypass -File x.ps1"
        ));
        assert!(has_encoded_command_flag("powershell -e AAA"));
    }

    #[test]
    fn ransomware_detector_needs_rate_and_spread() {
        let start = Instant::now();
        // Many changes in ONE folder (e.g. a build) => no alert.
        let mut d = RansomwareDetector::default();
        for i in 0..200 {
            let p = PathBuf::from(format!("/home/u/project/file{i}.o"));
            assert!(d.record_at(start, &p, FileActivity::Modified).is_none());
        }
        // Renames with new extensions across many folders => alert.
        let mut d = RansomwareDetector::default();
        let mut alert = None;
        for i in 0..40 {
            let p = PathBuf::from(format!("/home/u/Documents/dir{}/doc{i}.docx.locked", i % 8));
            alert = alert.or(d.record_at(start, &p, FileActivity::RenamedNewExtension));
        }
        let alert = alert.expect("should alert");
        assert!(alert.directories >= 4);
    }

    #[test]
    fn entropy_separates_text_from_encrypted_data() {
        assert!(shannon_entropy(b"aaaaaaaaaaaaaaaa") < 0.1);
        let text = "The quick brown fox jumps over the lazy dog. ".repeat(200);
        assert!(shannon_entropy(text.as_bytes()) < 5.0);
        let mut random = vec![0u8; 64 * 1024];
        getrandom::fill(&mut random).unwrap();
        assert!(shannon_entropy(&random) > 7.9);

        let dir = tempfile::tempdir().unwrap();
        let enc = dir.path().join("report.docx.locked");
        std::fs::write(&enc, &random).unwrap();
        assert!(looks_encrypted(&enc));
        let photo = dir.path().join("photo.jpg");
        std::fs::write(&photo, &random).unwrap();
        assert!(
            !looks_encrypted(&photo),
            "compressed formats are expected to be high-entropy"
        );
        let notes = dir.path().join("notes.txt");
        std::fs::write(&notes, text).unwrap();
        assert!(!looks_encrypted(&notes));
    }

    #[test]
    fn ransomware_window_expires() {
        let start = Instant::now();
        let mut d = RansomwareDetector::default();
        for i in 0..50u64 {
            let t = start + Duration::from_secs(i); // 1 event/sec: slow, normal editing
            let p = PathBuf::from(format!("/d{}/f{i}", i % 10));
            assert!(d.record_at(t, &p, FileActivity::Modified).is_none());
        }
    }
}
