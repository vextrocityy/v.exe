//! Persistence Watch: diffs autostart locations against a stored baseline and
//! scans the binary behind every new or changed entry.
//!
//! Watched: Run/RunOnce (HKLM, WOW6432Node, every loaded user hive),
//! Winlogon Shell/Userinit, service ImagePaths, Startup folders and Scheduled
//! Tasks (see [`super::tasks`]).
//! The baseline lives in SQLite, so changes made while the service was stopped
//! are reported at the next start.

use super::{sleep_or_stop, tasks, ShieldHandle, PERSISTENCE_WATCH};
use crate::engine::{targets, Engine};
use sentinel_protocol::{EventKind, Severity};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
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
        crate::util::contain("persistence poll", || poll(&engine, &mut baseline, &mut first_run));
        if sleep_or_stop(&stop, interval) {
            break;
        }
    }
}

/// Our own installer's autostart entries are expected, not suspicious.
fn is_own_entry(value: &str) -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_string_lossy().to_lowercase()))
        .is_some_and(|dir| dir.len() > 3 && value.to_lowercase().contains(&dir))
}

fn poll(engine: &Engine, baseline: &mut HashMap<String, String>, first_run: &mut bool) {
    {
        let current = collect();
        if !*first_run {
            for (key, value) in &current {
                if is_own_entry(value) || is_own_entry(key) {
                    continue;
                }
                let is_new = match baseline.get(key) {
                    None => true,
                    Some(old) if old != value => false,
                    _ => continue,
                };
                let targets = if let Some(task) = key.strip_prefix(tasks::KEY_PREFIX) {
                    if tasks::is_routine(task, value)
                        || task.trim_start_matches('\\') == crate::platform::UPDATE_WATCHDOG_TASK
                    {
                        continue;
                    }
                    report_task(engine, task, value, is_new);
                    tasks::targets(value)
                } else {
                    engine.emit(
                        EventKind::PersistenceChange,
                        Severity::Medium,
                        if is_new { "New autostart entry" } else { "Autostart entry modified" },
                        Some(format!("{key} = {value}")),
                        None,
                        None,
                    );
                    target_of(key, value).into_iter().collect()
                };
                for target in targets {
                    if let Ok(v) = engine.check_file(&target, None) {
                        if v.hit.is_some() {
                            engine.handle_detection(&target, &v, None, "Persistence Watch");
                        }
                    }
                }
            }
        }
        if current != *baseline {
            if let Err(e) = engine.db.replace_persistence_baseline(&current) {
                tracing::warn!(error = %e, "could not store persistence baseline");
            }
            *baseline = current;
        }
        *first_run = false;
    }
}

/// Alert for a new / changed scheduled task. The task name goes in `path`, so the
/// dashboard can offer "Disable task".
fn report_task(engine: &Engine, task: &str, value: &str, is_new: bool) {
    let flags: Vec<&str> = value.split(" ; ").flat_map(tasks::red_flags).collect();
    let severity = if flags.len() >= 2 {
        Severity::High
    } else {
        Severity::Medium
    };
    let mut detail = format!("Runs: {}", if value.is_empty() { "(no program)" } else { value });
    if !flags.is_empty() {
        let mut flags = flags;
        flags.dedup();
        detail.push_str(&format!(". Red flags: {}", flags.join("; ")));
    }
    detail.push_str(". If you did not install something that needs this, disable it.");
    engine.emit(
        EventKind::PersistenceChange,
        severity,
        if is_new { "New scheduled task" } else { "Scheduled task changed" },
        Some(detail),
        Some(Path::new(task)),
        None,
    );
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

/// A startup entry removed because it launched a quarantined file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub enum Removed {
    /// A Run/RunOnce value; `expand` = REG_EXPAND_SZ.
    RegistryValue {
        root: String,
        key: String,
        name: String,
        data: String,
        expand: bool,
    },
    /// A service whose ImagePath was the file: disabled (Start = 4), not deleted.
    ServiceDisabled { name: String, previous_start: u32 },
    /// A Startup-folder item (shortcut, .desktop file) moved to quarantine.
    StartupItem { quarantine_id: String },
    /// A scheduled task that launched the file: disabled, not deleted.
    TaskDisabled { name: String },
}

/// Does this command string launch `target`?
#[cfg_attr(not(windows), allow(dead_code))]
pub fn launches(command: &str, target: &Path) -> bool {
    let t = target.to_string_lossy().to_lowercase();
    if t.len() < 4 {
        return false;
    }
    let exe_matches = extract_executable(command).is_some_and(|p| p.to_string_lossy().to_lowercase() == t);
    exe_matches || command.to_lowercase().contains(&t)
}

/// Startup-folder files that point at `target`: the file itself, or a
/// shortcut whose bytes contain the path (ANSI or UTF-16LE, as .lnk stores it).
pub fn startup_items_referencing(target: &Path, folders: &[PathBuf]) -> Vec<PathBuf> {
    let t = target.to_string_lossy().to_lowercase();
    let utf16: Vec<u8> = t.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let mut out = Vec::new();
    for dir in folders {
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            if !p.is_file() || p.to_string_lossy().to_lowercase() == t {
                continue; // the target itself is quarantined by the caller
            }
            let Ok(bytes) = std::fs::read(&p) else { continue };
            if bytes.len() > 1024 * 1024 {
                continue;
            }
            let lower: Vec<u8> = bytes.iter().map(|b| b.to_ascii_lowercase()).collect();
            let hit_ansi = lower.windows(t.len()).any(|w| w == t.as_bytes());
            let hit_utf16 = lower.windows(utf16.len()).any(|w| w == utf16.as_slice());
            if hit_ansi || hit_utf16 {
                out.push(p);
            }
        }
    }
    out
}

/// Remove registry autostarts and disable scheduled tasks that launch `target`. Windows only.
pub fn remove_registry_references(target: &Path) -> Vec<(Removed, String)> {
    #[cfg(windows)]
    {
        let mut out = registry::remove_references(target);
        for name in tasks::tasks_launching(&tasks::tasks_dir(), target) {
            match tasks::set_enabled(&name, false) {
                Ok(()) => out.push((Removed::TaskDisabled { name: name.clone() }, format!("scheduled task {name} (disabled)"))),
                Err(e) => tracing::warn!(task = %name, error = %format!("{e:#}"), "could not disable scheduled task"),
            }
        }
        out
    }
    #[cfg(not(windows))]
    {
        let _ = target;
        Vec::new()
    }
}

/// Put a removed registry entry back (or re-enable a task).
pub fn restore_registry(entry: &Removed) -> anyhow::Result<()> {
    if let Removed::TaskDisabled { name } = entry {
        return tasks::set_enabled(name, true);
    }
    #[cfg(windows)]
    {
        registry::restore(entry)
    }
    #[cfg(not(windows))]
    {
        let _ = entry;
        anyhow::bail!("registry entries exist only on Windows")
    }
}

pub fn startup_folders() -> Vec<PathBuf> {
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
            let mtime = meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs());
            map.insert(
                format!("STARTUP|{}", e.path().display()),
                format!("size={} mtime={:?}", meta.len(), mtime),
            );
        }
    }
    #[cfg(windows)]
    {
        registry::collect(&mut map);
        tasks::collect(&tasks::tasks_dir(), &mut map);
    }
    map
}

#[cfg(windows)]
mod registry {
    use super::{launches, Removed};
    use std::collections::HashMap;
    use std::path::Path;
    use winreg::enums::{RegType, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_SET_VALUE};
    use winreg::{RegKey, RegValue};

    fn root(name: &str) -> RegKey {
        RegKey::predef(if name == "HKLM" { HKEY_LOCAL_MACHINE } else { HKEY_USERS })
    }

    /// (root name, full subkey path) of every Run/RunOnce key we monitor.
    fn run_keys() -> Vec<(&'static str, String)> {
        let mut v: Vec<(&'static str, String)> = RUN_KEYS.iter().map(|k| ("HKLM", k.to_string())).collect();
        for sid in RegKey::predef(HKEY_USERS).enum_keys().flatten() {
            if sid.starts_with("S-1-5-21-") && !sid.ends_with("_Classes") {
                for k in &RUN_KEYS[..2] {
                    v.push(("HKU", format!(r"{sid}\{k}")));
                }
            }
        }
        v
    }

    pub fn remove_references(target: &Path) -> Vec<(Removed, String)> {
        let mut out = Vec::new();
        for (root_name, path) in run_keys() {
            let Ok(key) = root(root_name).open_subkey_with_flags(&path, KEY_READ | KEY_SET_VALUE) else {
                continue;
            };
            let values: Vec<(String, RegValue)> = key.enum_values().flatten().collect();
            for (name, value) in values {
                let expand = value.vtype == RegType::REG_EXPAND_SZ;
                if !(expand || value.vtype == RegType::REG_SZ) {
                    continue;
                }
                let data = value.to_string();
                if launches(&data, target) && key.delete_value(&name).is_ok() {
                    let desc = format!(r"{root_name}\{path}!{name}");
                    out.push((
                        Removed::RegistryValue {
                            root: root_name.into(),
                            key: path.clone(),
                            name,
                            data,
                            expand,
                        },
                        desc,
                    ));
                }
            }
        }
        let services_path = r"SYSTEM\CurrentControlSet\Services";
        if let Ok(services) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(services_path, KEY_READ) {
            for name in services.enum_keys().flatten() {
                let Ok(svc) = services.open_subkey_with_flags(&name, KEY_READ | KEY_SET_VALUE) else {
                    continue;
                };
                let Ok(image) = svc.get_value::<String, _>("ImagePath") else {
                    continue;
                };
                if !launches(&image, target) {
                    continue;
                }
                let previous: u32 = svc.get_value("Start").unwrap_or(3);
                if previous != 4 && svc.set_value("Start", &4u32).is_ok() {
                    out.push((
                        Removed::ServiceDisabled {
                            name: name.clone(),
                            previous_start: previous,
                        },
                        format!("service {name} (disabled)"),
                    ));
                }
            }
        }
        out
    }

    pub fn restore(entry: &Removed) -> anyhow::Result<()> {
        match entry {
            Removed::RegistryValue {
                root: r,
                key,
                name,
                data,
                expand,
            } => {
                let (k, _) = root(r).create_subkey(key)?;
                if *expand {
                    let mut bytes: Vec<u8> = data
                        .encode_utf16()
                        .chain(Some(0))
                        .flat_map(|u| u.to_le_bytes())
                        .collect();
                    bytes.shrink_to_fit();
                    k.set_raw_value(
                        name,
                        &RegValue {
                            bytes,
                            vtype: RegType::REG_EXPAND_SZ,
                        },
                    )?;
                } else {
                    k.set_value(name, data)?;
                }
                Ok(())
            }
            Removed::ServiceDisabled { name, previous_start } => {
                let svc = RegKey::predef(HKEY_LOCAL_MACHINE)
                    .open_subkey_with_flags(format!(r"SYSTEM\CurrentControlSet\Services\{name}"), KEY_SET_VALUE)?;
                svc.set_value("Start", previous_start)?;
                Ok(())
            }
            Removed::StartupItem { .. } | Removed::TaskDisabled { .. } => Ok(()),
        }
    }

    const RUN_KEYS: &[&str] = &[
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    ];

    fn values(root: &RegKey, root_name: &str, sub: &str, map: &mut HashMap<String, String>) {
        let Ok(key) = root.open_subkey_with_flags(sub, KEY_READ) else {
            return;
        };
        for (name, value) in key.enum_values().flatten() {
            map.insert(format!(r"{root_name}\{sub}!{name}"), value.to_string());
        }
    }

    pub fn collect(map: &mut HashMap<String, String>) {
        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        for sub in RUN_KEYS {
            values(&hklm, "HKLM", sub, map);
        }
        if let Ok(wl) = hklm.open_subkey_with_flags(r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", KEY_READ)
        {
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
        assert_eq!(
            extract_executable(r"\??\C:\drivers\x.sys"),
            Some(PathBuf::from(r"C:\drivers\x.sys"))
        );
    }

    #[test]
    fn finds_startup_items_that_launch_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let startup = dir.path().join("Startup");
        std::fs::create_dir_all(&startup).unwrap();
        let target = PathBuf::from(r"C:\Users\bob\AppData\Roaming\evil\updater.exe");
        // .lnk files store the path as UTF-16LE; .desktop / .bat as plain text (any case).
        let utf16: Vec<u8> = target
            .to_string_lossy()
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        std::fs::write(
            startup.join("Updater.lnk"),
            [b"L\0\0\0junk".as_slice(), &utf16, b"more"].concat(),
        )
        .unwrap();
        std::fs::write(
            startup.join("run.bat"),
            b"start \"\" \"C:\\USERS\\BOB\\APPDATA\\ROAMING\\EVIL\\UPDATER.EXE\"",
        )
        .unwrap();
        std::fs::write(
            startup.join("OneDrive.lnk"),
            b"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
        )
        .unwrap();
        let mut found = startup_items_referencing(&target, std::slice::from_ref(&startup));
        found.sort();
        assert_eq!(found, vec![startup.join("Updater.lnk"), startup.join("run.bat")]);
    }

    #[test]
    fn launches_matches_command_lines() {
        let t = Path::new(r"C:\Users\bob\AppData\Roaming\evil\updater.exe");
        assert!(launches(
            r#""C:\Users\Bob\AppData\Roaming\evil\updater.exe" --silent"#,
            t
        ));
        assert!(launches(
            r"rundll32.exe C:\Users\bob\AppData\Roaming\evil\updater.exe,Run",
            t
        ));
        assert!(!launches(r"C:\Program Files\App\updater.exe", t));
    }

    #[test]
    fn expands_environment_variables() {
        std::env::set_var("SENTINEL_TEST_ROOT", "/opt/x");
        assert_eq!(expand_env("%SENTINEL_TEST_ROOT%/bin/a"), "/opt/x/bin/a");
        assert_eq!(expand_env("100% sure"), "100% sure");
        assert_eq!(expand_env("%UNSET_SENTINEL_VAR%/a"), "%UNSET_SENTINEL_VAR%/a");
    }
}
