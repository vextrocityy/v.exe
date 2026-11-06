//! Persistence Watch: diffs autostart locations against a stored baseline and
//! scans the binary behind every new or changed entry.
//!
//! Watched: Run/RunOnce (HKLM, WOW6432Node, every loaded user hive),
//! Winlogon Shell/Userinit, service ImagePaths, and Startup folders.
//! The baseline lives in SQLite, so changes made while the service was stopped
//! are reported at the next start.

use super::{sleep_or_stop, ShieldHandle, PERSISTENCE_WATCH};
use crate::engine::{targets, Engine};
use sentinel_protocol::{EventKind, Severity};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

pub fn start(engine: Arc<Engine>) -> Result<ShieldHandle, String> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let interval = Duration::from_secs(engine.settings().persistence_poll_secs.max(5));
    let thread = std::thread::Builder::new()
        .name("persistence".into())
        .spawn(move || run(engine, stop2, interval))
        .map_err(|e| e.to_string())?;
    Ok(ShieldHandle {
        name: PERSISTENCE_WATCH,
        stop,
        threads: vec![thread],
        on_stop: None,
        detail: Some(format!("Checking autostart locations every {} s", interval.as_secs())),
    })
}

fn run(engine: Arc<Engine>, stop: Arc<AtomicBool>, interval: Duration) {
    let mut baseline = engine.db.persistence_baseline().unwrap_or_default();
    let mut first_run = baseline.is_empty();
    loop {
        let current = collect();
        if !first_run {
            for (key, value) in &current {
                let change = match baseline.get(key) {
                    None => "New autostart entry",
                    Some(old) if old != value => "Autostart entry modified",
                    _ => continue,
                };
                engine.emit(
                    EventKind::PersistenceChange,
                    Severity::Medium,
                    change,
                    Some(format!("{key} = {value}")),
                    None,
                    None,
                );
                if let Some(target) = target_of(key, value) {
                    if let Ok(v) = engine.check_file(&target, None) {
                        if v.hit.is_some() {
                            engine.handle_detection(&target, &v, None, "Persistence Watch");
                        }
                    }
                }
            }
        }
        if current != baseline {
            if let Err(e) = engine.db.replace_persistence_baseline(&current) {
                tracing::warn!(error = %e, "could not store persistence baseline");
            }
            baseline = current;
        }
        first_run = false;
        if sleep_or_stop(&stop, interval) {
            break;
        }
    }
}

/// Which file does this entry launch?
fn target_of(key: &str, value: &str) -> Option<PathBuf> {
    if let Some(path) = key.strip_prefix("STARTUP|") {
        return Some(PathBuf::from(path));
    }
    let p = extract_executable(value)?;
    p.is_file().then_some(p)
}

/// Pull the executable out of a command string such as
/// `"C:\Program Files\App\app.exe" --tray` or `%SystemRoot%\system32\svchost.exe -k netsvcs`.
pub fn extract_executable(cmd: &str) -> Option<PathBuf> {
    let cmd = expand_env(cmd.trim());
    let cmd = cmd.strip_prefix(r"\??\").unwrap_or(&cmd).to_string();
    let path = if let Some(rest) = cmd.strip_prefix('"') {
        rest.split('"').next()?.to_string()
    } else if let Some(i) = cmd.to_ascii_lowercase().find(".exe") {
        cmd[..i + 4].to_string()
    } else {
        cmd.split_whitespace().next()?.to_string()
    };
    (!path.is_empty()).then(|| PathBuf::from(path))
}

fn expand_env(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match std::env::var(name) {
                    Ok(v) if !name.is_empty() => out.push_str(&v),
                    _ => {
                        out.push('%');
                        out.push_str(name);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    if let Some(tail) = out.strip_prefix(r"\SystemRoot\") {
        if let Ok(root) = std::env::var("SystemRoot") {
            return format!(r"{root}\{tail}");
        }
    }
    out
}

fn startup_folders() -> Vec<PathBuf> {
    let mut v = Vec::new();
    for profile in targets::user_profiles() {
        if cfg!(windows) {
            v.push(profile.join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"));
        } else {
            v.push(profile.join(".config/autostart"));
        }
    }
    #[cfg(windows)]
    if let Some(pd) = std::env::var_os("ProgramData") {
        v.push(PathBuf::from(pd).join(r"Microsoft\Windows\Start Menu\Programs\StartUp"));
    }
    #[cfg(not(windows))]
    v.push(PathBuf::from("/etc/xdg/autostart"));
    v
}

fn collect() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for dir in startup_folders() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let Ok(meta) = e.metadata() else { continue };
            if !meta.is_file() || e.file_name().eq_ignore_ascii_case("desktop.ini") {
                continue;
            }
            let mtime = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs());
            map.insert(format!("STARTUP|{}", e.path().display()), format!("size={} mtime={:?}", meta.len(), mtime));
        }
    }
    #[cfg(windows)]
    registry::collect(&mut map);
    map
}

#[cfg(windows)]
mod registry {
    use std::collections::HashMap;
    use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ};
    use winreg::RegKey;

    const RUN_KEYS: &[&str] = &[
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    fn values(root: &RegKey, root_name: &str, sub: &str, map: &mut HashMap<String, String>) {
        let Ok(key) = root.open_subkey_with_flags(sub, KEY_READ) else { return };
        for (name, value) in key.enum_values().flatten() {
            map.insert(format!(r"{root_name}\{sub}!{name}"), value.to_string());
        }
    }

    pub fn collect(map: &mut HashMap<String, String>) {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        for sub in RUN_KEYS {
            values(&hklm, "HKLM", sub, map);
        }
        if let Ok(wl) = hklm.open_subkey_with_flags(r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", KEY_READ) {
            for name in ["Shell", "Userinit"] {
                if let Ok(v) = wl.get_value::<String, _>(name) {
                    map.insert(format!(r"HKLM\...\Winlogon!{name}"), v);
                }
            }
        }
        if let Ok(services) = hklm.open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Services", KEY_READ) {
            for name in services.enum_keys().flatten() {
                if let Ok(svc) = services.open_subkey_with_flags(&name, KEY_READ) {
                    if let Ok(img) = svc.get_value::<String, _>("ImagePath") {
                        map.insert(format!(r"HKLM\...\Services\{name}!ImagePath"), img);
                    }
                }
            }
        }
        // Each logged-on user's hive (the service's own HKCU is LocalSystem's).
        let hku = RegKey::predef(HKEY_USERS);
        for sid in hku.enum_keys().flatten() {
            if !sid.starts_with("S-1-5-21-") || sid.ends_with("_Classes") {
                continue;
            }
            if let Ok(user) = hku.open_subkey_with_flags(&sid, KEY_READ) {
                for sub in &RUN_KEYS[..2] {
                    values(&user, &format!(r"HKU\{sid}"), sub, map);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_quoted_and_unquoted_paths() {
        assert_eq!(
            extract_executable(r#""C:\Program Files\App\app.exe" --tray"#),
            Some(PathBuf::from(r"C:\Program Files\App\app.exe"))
        );
        assert_eq!(
            extract_executable(r"C:\Program Files\App\app.exe /background"),
            Some(PathBuf::from(r"C:\Program Files\App\app.exe"))
        );
        assert_eq!(extract_executable(r"\??\C:\drivers\x.sys"), Some(PathBuf::from(r"C:\drivers\x.sys")));
    }

    #[test]
    fn expands_environment_variables() {
        std::env::set_var("SENTINEL_TEST_ROOT", "/opt/x");
        assert_eq!(expand_env("%SENTINEL_TEST_ROOT%/bin/a"), "/opt/x/bin/a");
        assert_eq!(expand_env("100% sure"), "100% sure");
        assert_eq!(expand_env("%UNSET_SENTINEL_VAR%/a"), "%UNSET_SENTINEL_VAR%/a");
    }
}
