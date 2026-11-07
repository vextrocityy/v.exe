//! Settings persistence (`<data_dir>/settings.json`), with atomic writes and
//! sanitisation so a hand-edited or hostile file cannot break the engine.

use anyhow::Result;
use sentinel_protocol::Settings;
use std::path::Path;

pub fn load(path: &Path) -> Settings {
    match std::fs::read(path) {
        Ok(raw) => match serde_json::from_slice::<Settings>(&raw) {
            Ok(s) => sanitize(s),
            Err(e) => {
                tracing::warn!(error = %e, "settings.json is invalid; using defaults");
                Settings::default()
            }
        },
        Err(_) => Settings::default(),
    }
}

pub fn save(path: &Path, s: &Settings) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(s)?)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn sanitize(mut s: Settings) -> Settings {
    let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
    s.max_scan_threads = s.max_scan_threads.min(cpus);
    s.max_file_size_mb = s.max_file_size_mb.clamp(1, 4096);
    s.persistence_poll_secs = s.persistence_poll_secs.clamp(5, 3600);
    let clean = |v: &mut Vec<String>| {
        v.iter_mut().for_each(|p| *p = p.trim().to_string());
        v.retain(|p| !p.is_empty());
        v.sort();
        v.dedup();
        v.truncate(256);
    };
    s.update_interval_hours = s.update_interval_hours.clamp(1, 168);
    s.scheduled_scan_hours = s.scheduled_scan_hours.clamp(1, 24 * 30);
    s.update_url = s
        .update_url
        .take()
        .map(|u| u.trim().to_string())
        .filter(|u| is_allowed_update_url(u));
    // abuse.ch keys are alphanumeric; anything else is dropped rather than put into a URL.
    s.abusech_auth_key = s.abusech_auth_key.take().map(|k| k.trim().to_string()).filter(|k| {
        k == sentinel_protocol::SECRET_MASK
            || (!k.is_empty() && k.len() <= 128 && k.chars().all(|c| c.is_ascii_alphanumeric()))
    });
    s.yara_min_remediate_score = s.yara_min_remediate_score.clamp(50, 101); // 101 = never quarantine
    s.yara_max_file_mb = s.yara_max_file_mb.clamp(1, 256);
    clean(&mut s.exclusions);
    clean(&mut s.watch_paths);
    // Excluding a whole drive root is almost certainly a mistake (or an attack).
    s.exclusions.retain(|p| {
        let t = p.trim_end_matches(['\\', '/']);
        !(t.is_empty() || (t.len() == 2 && t.ends_with(':')))
    });
    s
}

/// Copy of `s` safe to hand to a client: secrets replaced by the mask.
pub fn redacted(s: &Settings) -> Settings {
    let mut out = s.clone();
    if out.abusech_auth_key.is_some() {
        out.abusech_auth_key = Some(sentinel_protocol::SECRET_MASK.into());
    }
    out
}

/// A client echoing the mask back keeps the stored secret.
pub fn merge_secrets(old: &Settings, mut new: Settings) -> Settings {
    if new.abusech_auth_key.as_deref() == Some(sentinel_protocol::SECRET_MASK) {
        new.abusech_auth_key = old.abusech_auth_key.clone();
    }
    new
}

/// Updates must come over HTTPS (plain HTTP only for a local mirror / tests).
pub fn is_allowed_update_url(u: &str) -> bool {
    let lower = u.to_ascii_lowercase();
    lower.starts_with("https://") || lower.starts_with("http://127.0.0.1") || lower.starts_with("http://localhost")
}

/// Describe every way `new` reduces protection compared with `old`.
/// Empty = the change is neutral or strengthening and needs no elevation.
pub fn weakenings(old: &Settings, new: &Settings) -> Vec<String> {
    let mut out = Vec::new();
    let flags: [(&str, bool, bool); 15] = [
        ("real-time protection", old.realtime_protection, new.realtime_protection),
        ("Process Guard", old.process_monitor, new.process_monitor),
        ("File Shield", old.file_monitor, new.file_monitor),
        ("Persistence Watch", old.persistence_monitor, new.persistence_monitor),
        ("Behavior Engine", old.behavior_monitor, new.behavior_monitor),
        (
            "terminating malicious processes",
            old.auto_kill_malicious,
            new.auto_kill_malicious,
        ),
        ("automatic quarantine", old.auto_quarantine, new.auto_quarantine),
        ("automatic updates", old.auto_update, new.auto_update),
        ("community threat feeds", old.community_feeds, new.community_feeds),
        ("YARA scanning", old.yara_enabled, new.yara_enabled),
        ("the YARA rules feed", old.yara_rules_feed, new.yara_rules_feed),
        ("archive scanning", old.archive_scanning, new.archive_scanning),
        ("ransomware decoys", old.ransomware_decoys, new.ransomware_decoys),
        ("suspending ransomware", old.ransomware_suspend, new.ransomware_suspend),
        ("startup clean-up", old.startup_cleanup, new.startup_cleanup),
    ];
    for (name, before, after) in flags {
        if before && !after {
            out.push(format!("turns off {name}"));
        }
    }
    let added: Vec<&String> = new.exclusions.iter().filter(|e| !old.exclusions.contains(e)).collect();
    if !added.is_empty() {
        out.push(format!("adds {} exclusion(s)", added.len()));
    }
    if new.yara_min_remediate_score > old.yara_min_remediate_score {
        out.push("raises the YARA quarantine threshold".into());
    }
    if new.yara_max_file_mb < old.yara_max_file_mb {
        out.push("lowers the maximum YARA-scanned file size".into());
    }
    if new.max_file_size_mb < old.max_file_size_mb {
        out.push("lowers the maximum scanned file size".into());
    }
    if !new.scheduled_scan && old.scheduled_scan {
        out.push("turns off scheduled scans".into());
    }
    let removed_watch = old.watch_paths.iter().any(|w| !new.watch_paths.contains(w));
    if removed_watch {
        out.push("removes watched folders".into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_rejects_drive_root_exclusions_and_clamps() {
        let s = sanitize(Settings {
            exclusions: vec!["C:\\".into(), "  ".into(), "/".into(), r"D:\Games".into()],
            max_file_size_mb: 0,
            persistence_poll_secs: 1,
            ..Settings::default()
        });
        assert_eq!(s.exclusions, vec![r"D:\Games".to_string()]);
        assert_eq!(s.max_file_size_mb, 1);
        assert_eq!(s.persistence_poll_secs, 5);
    }

    #[test]
    fn weakenings_detects_reductions_only() {
        let base = Settings::default();
        assert!(weakenings(&base, &base).is_empty());

        // Turning something ON or removing an exclusion is never "weakening".
        let mut stronger = Settings {
            realtime_protection: false,
            exclusions: vec!["D:\\x".into()],
            ..base.clone()
        };
        let weaker = stronger.clone();
        stronger.realtime_protection = true;
        stronger.exclusions.clear();
        assert!(weakenings(&weaker, &stronger).is_empty());

        let w = weakenings(
            &base,
            &Settings {
                auto_quarantine: false,
                exclusions: vec!["D:\\a".into()],
                ..base.clone()
            },
        );
        assert_eq!(w.len(), 2, "{w:?}");
    }

    #[test]
    fn secrets_are_masked_and_preserved() {
        let stored = Settings {
            abusech_auth_key: Some("abc123".into()),
            ..Settings::default()
        };
        let shown = redacted(&stored);
        assert_eq!(shown.abusech_auth_key.as_deref(), Some(sentinel_protocol::SECRET_MASK));
        assert_eq!(
            merge_secrets(&stored, sanitize(shown)).abusech_auth_key.as_deref(),
            Some("abc123")
        );
        let cleared = merge_secrets(
            &stored,
            Settings {
                abusech_auth_key: None,
                ..Settings::default()
            },
        );
        assert_eq!(cleared.abusech_auth_key, None);
        let bad = sanitize(Settings {
            abusech_auth_key: Some("../evil?x=1".into()),
            ..Settings::default()
        });
        assert_eq!(bad.abusech_auth_key, None);
    }

    #[test]
    fn update_url_must_be_https() {
        let s = sanitize(Settings {
            update_url: Some("http://evil.example/pack.json".into()),
            ..Settings::default()
        });
        assert_eq!(s.update_url, None);
        let s = sanitize(Settings {
            update_url: Some(" https://updates.example/pack.json ".into()),
            ..Settings::default()
        });
        assert_eq!(s.update_url.as_deref(), Some("https://updates.example/pack.json"));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("settings.json");
        let s = Settings {
            auto_quarantine: false,
            ..Settings::default()
        };
        save(&p, &s).unwrap();
        assert_eq!(load(&p), s);
        std::fs::write(&p, b"{not json").unwrap();
        assert_eq!(load(&p), Settings::default());
    }
}
