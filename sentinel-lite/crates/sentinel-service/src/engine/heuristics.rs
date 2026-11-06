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
const SCRIPT_HOSTS: &[&str] = &["powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "cmd.exe"];
/// Applications that have no ordinary reason to launch a script host.
const DOCUMENT_APPS: &[&str] = &["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "acrord32.exe"];

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
    ["\\appdata\\local\\temp\\", "\\downloads\\", "\\windows\\temp\\", "\\users\\public\\"]
        .iter()
        .any(|frag| s.contains(frag))
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
            parent_image: Some(Path::new(r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE")),
        });
        assert!(a.score >= ALERT_HIGH, "{a:?}");
        assert_eq!(a.reasons.len(), 3);
    }

    #[test]
    fn encoded_flag_prefix_matching() {
        assert!(has_encoded_command_flag("powershell -EncodedCommand AAA"));
        assert!(has_encoded_command_flag("powershell -ec AAA"));
        assert!(!has_encoded_command_flag("powershell -ExecutionPolicy Bypass -File x.ps1"));
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
