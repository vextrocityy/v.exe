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
    clean(&mut s.exclusions);
    clean(&mut s.watch_paths);
    // Excluding a whole drive root is almost certainly a mistake (or an attack).
    s.exclusions.retain(|p| {
        let t = p.trim_end_matches(['\\', '/']);
        !(t.is_empty() || (t.len() == 2 && t.ends_with(':')))
    });
    s
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
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("settings.json");
        let s = Settings { auto_quarantine: false, ..Settings::default() };
        save(&p, &s).unwrap();
        assert_eq!(load(&p), s);
        std::fs::write(&p, b"{not json").unwrap();
        assert_eq!(load(&p), Settings::default());
    }
}
