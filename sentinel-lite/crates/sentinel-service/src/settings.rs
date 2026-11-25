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
    s.rollback_interval_hours = s.rollback_interval_hours.clamp(1, 168);
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
    s.trusted_apps
        .retain(|t| crate::database::signatures::is_sha256(&t.sha256));
    s.trusted_apps.dedup();
    s.app_update_api = s
        .app_update_api
        .take()
        .map(|u| u.trim().to_string())
        .filter(|u| crate::engine::appupdate::is_allowed_api_url(u));
    s.trusted_apps.truncate(512);
    s.gmail_client_id = s
        .gmail_client_id
        .take()
        .map(|c| c.trim().to_string())
        .filter(|c| crate::engine::mailwatch::valid_client_id(c));
    s.gmail_client_secret = s.gmail_client_secret.take().map(|c| c.trim().to_string()).filter(|c| {
        c == sentinel_protocol::SECRET_MASK
            || (!c.is_empty() && c.len() < 200 && c.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)))
    });
    s.pihole_url = s.pihole_url.take().and_then(|u| crate::engine::homenet::normalize_url(&u));
    s.pihole_password = s
        .pihole_password
        .take()
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty() && k.len() <= 256 && !k.chars().any(char::is_control));
    let test = s.dns_test_domain.trim().trim_end_matches('.').to_ascii_lowercase();
    s.dns_test_domain = if crate::engine::homenet::valid_domain(&test) && !crate::engine::homenet::is_local(&test) {
        test
    } else {
        Settings::default().dns_test_domain
    };
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
    if out.pihole_password.is_some() {
        out.pihole_password = Some(sentinel_protocol::SECRET_MASK.into());
    }
    if out.gmail_client_secret.is_some() {
        out.gmail_client_secret = Some(sentinel_protocol::SECRET_MASK.into());
    }
    out
}

/// A client echoing the mask back keeps the stored secret.
pub fn merge_secrets(old: &Settings, mut new: Settings) -> Settings {
    if new.abusech_auth_key.as_deref() == Some(sentinel_protocol::SECRET_MASK) {
        new.abusech_auth_key = old.abusech_auth_key.clone();
    }
    if new.pihole_password.as_deref() == Some(sentinel_protocol::SECRET_MASK) {
        new.pihole_password = old.pihole_password.clone();
    }
    if new.gmail_client_secret.as_deref() == Some(sentinel_protocol::SECRET_MASK) {
        new.gmail_client_secret = old.gmail_client_secret.clone();
    }
    new
}

/// Updates must come over HTTPS (plain HTTP only for a local mirror / tests).
pub fn is_allowed_update_url(u: &str) -> bool {
    let lower = u.to_ascii_lowercase();
    lower.starts_with("https://") || crate::util::is_loopback_url(&lower)
}

/// Describe every way `new` reduces protection compared with `old`.
/// Empty = the change is neutral or strengthening and needs no elevation.
pub fn weakenings(old: &Settings, new: &Settings) -> Vec<String> {
    let mut out = Vec::new();
    let flags: [(&str, bool, bool); 24] = [
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
        ("Execution Guard", old.block_untrusted_risky, new.block_untrusted_risky),
        (
            "the Office child-process rule",
            old.block_office_children,
            new.block_office_children,
        ),
        ("entropy detection", old.entropy_detection, new.entropy_detection),
        ("Network Guard", old.network_guard, new.network_guard),
        ("automatic app updates", old.auto_update_app, new.auto_update_app),
        ("camera / microphone alerts", old.privacy_monitor, new.privacy_monitor),
        ("rollback snapshots", old.rollback_snapshots, new.rollback_snapshots),
        ("the DNS tamper alarm", old.dns_guard, new.dns_guard),
        ("the email account watch", old.mail_watch, new.mail_watch),
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
    if new.app_update_api != old.app_update_api {
        out.push("changes where app updates come from".into());
    }
    if new.trusted_apps.iter().any(|t| !old.trusted_apps.contains(t)) {
        out.push("trusts additional programs".into());
    }
    if old.gmail_client_id.is_some()
        && (new.gmail_client_id != old.gmail_client_id || new.gmail_client_secret != old.gmail_client_secret)
    {
        out.push("changes the Google sign-in details the email watch depends on".into());
    }
    if old.pihole_url.is_some() && new.pihole_url != old.pihole_url {
        out.push("changes or removes the Pi-hole server".into());
    }
    if old.dns_guard && new.dns_test_domain != old.dns_test_domain {
        out.push("changes the DNS test domain".into());
    }
    if new.persistence_poll_secs > old.persistence_poll_secs.max(60) {
        out.push("makes the startup-change check much slower".into());
    }
    if new.update_interval_hours > old.update_interval_hours.max(24) {
        out.push("makes signature updates rarer".into());
    }
    if new.rollback_interval_hours > old.rollback_interval_hours.max(24) {
        out.push("makes rollback snapshots rarer".into());
    }
    if new.scheduled_scan_hours > old.scheduled_scan_hours.max(24 * 7) {
        out.push("makes scheduled scans rarer".into());
    }
    if new.update_url != old.update_url {
        out.push("changes where signature updates come from".into());
    }
    if old.abusech_auth_key.is_some() && new.abusech_auth_key != old.abusech_auth_key {
        out.push("replaces the community-feed key".into());
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
    fn pihole_settings_are_sanitised_masked_and_guarded() {
        let s = sanitize(Settings {
            pihole_url: Some("http://192.168.88.6/admin/".into()),
            pihole_password: Some("  app-pw  ".into()),
            dns_test_domain: "not a domain".into(),
            ..Settings::default()
        });
        assert_eq!(s.pihole_url.as_deref(), Some("http://192.168.88.6"));
        assert_eq!(s.pihole_password.as_deref(), Some("app-pw"));
        assert_eq!(s.dns_test_domain, "doubleclick.net");
        assert_eq!(sanitize(Settings { pihole_url: Some("http://1.2.3.4".into()), ..s.clone() }).pihole_url, None);

        let shown = redacted(&s);
        assert_eq!(shown.pihole_password.as_deref(), Some(sentinel_protocol::SECRET_MASK));
        assert_eq!(merge_secrets(&s, sanitize(shown)).pihole_password.as_deref(), Some("app-pw"));

        // Setting up Pi-hole is fine; pointing it elsewhere or silencing the alarm is not.
        assert!(weakenings(&Settings::default(), &s).is_empty());
        let moved = Settings { pihole_url: Some("http://192.168.88.7".into()), ..s.clone() };
        assert_eq!(weakenings(&s, &moved).len(), 1);
        let silent = Settings { dns_guard: false, ..s.clone() };
        assert_eq!(weakenings(&s, &silent), vec!["turns off the DNS tamper alarm".to_string()]);
        let canary = Settings { dns_test_domain: "nonexistent.example".into(), ..s.clone() };
        assert_eq!(weakenings(&s, &canary).len(), 1);
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
