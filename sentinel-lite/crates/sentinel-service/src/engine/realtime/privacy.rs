//! Privacy Monitor: notices when an app starts or stops using the camera or
//! microphone.
//!
//! Windows records every capture session per app under
//! `Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{webcam,microphone}`
//! (one subkey per Store app, `NonPackaged\<path with # for \>` for desktop apps),
//! with `LastUsedTimeStart` / `LastUsedTimeStop` FILETIMEs. A session is open
//! while Stop is 0. We read every loaded user hive plus HKLM every 2 s: a
//! handful of registry reads, no hooks, no driver.

use super::{sleep_or_stop, ShieldHandle, PRIVACY_MONITOR};
use crate::engine::{heuristics, Engine};
use sentinel_protocol::{Device, DeviceUse, EventKind, Severity};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

const POLL: Duration = Duration::from_secs(2);

pub fn start(engine: Arc<Engine>) -> Result<ShieldHandle, String> {
    if !cfg!(windows) {
        return Err("camera / microphone tracking is Windows-only".into());
    }
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let thread = std::thread::Builder::new()
        .name("privacy".into())
        .spawn(move || {
            let mut open: HashMap<Key, DeviceUse> = HashMap::new();
            let mut first = true;
            loop {
                crate::util::contain("privacy poll", || {
                    let now = read_all();
                    let (started, stopped) = diff(&open, &now);
                    if !first {
                        for u in started {
                            report(&engine, &u, true);
                        }
                        for u in stopped {
                            report(&engine, &u, false);
                        }
                    }
                    first = false;
                    open = now.into_iter().filter(|u| u.in_use).map(|u| (key(&u), u)).collect();
                    engine.set_devices_in_use(open.values().cloned().collect());
                });
                if sleep_or_stop(&stop2, POLL) {
                    break;
                }
            }
            engine.set_devices_in_use(Vec::new());
        })
        .map_err(|e| e.to_string())?;
    Ok(ShieldHandle {
        name: PRIVACY_MONITOR,
        stop,
        threads: vec![thread],
        on_stop: None,
        detail: Some("Notifies when an app turns on the camera or microphone".into()),
    })
}

type Key = (Device, Option<String>, String);

fn key(u: &DeviceUse) -> Key {
    (u.device, u.user.clone(), u.path.clone().unwrap_or_else(|| u.app.clone()))
}

/// Sessions that opened since `open` was taken, and ones that closed (with their stop time).
pub fn diff(open: &HashMap<Key, DeviceUse>, now: &[DeviceUse]) -> (Vec<DeviceUse>, Vec<DeviceUse>) {
    let current: HashMap<Key, &DeviceUse> = now.iter().map(|u| (key(u), u)).collect();
    let started = now
        .iter()
        .filter(|u| u.in_use)
        .filter(|u| match open.get(&key(u)) {
            None => true,
            // A new session of the same app (restarted capture).
            Some(prev) => prev.last_started != u.last_started,
        })
        .cloned()
        .collect();
    let stopped = open
        .iter()
        .filter(|(k, _)| !current.get(*k).is_some_and(|u| u.in_use))
        .map(|(k, prev)| {
            let mut u = current.get(k).map(|u| (*u).clone()).unwrap_or_else(|| prev.clone());
            u.in_use = false;
            u
        })
        .collect();
    (started, stopped)
}

fn device_name(d: Device) -> &'static str {
    match d {
        Device::Camera => "Camera",
        Device::Microphone => "Microphone",
    }
}

fn report(engine: &Engine, u: &DeviceUse, started: bool) {
    let what = device_name(u.device);
    let path = u.path.as_deref().map(Path::new);
    if started {
        let mut notes = Vec::new();
        let mut severity = Severity::Low;
        if let Some(p) = path {
            if let Some(folder) = heuristics::risky_location(p) {
                notes.push(format!("it runs from {folder}"));
                severity = Severity::Medium;
            }
            if p.is_file() && !crate::platform::has_valid_signature(p) {
                notes.push("it is not digitally signed".to_string());
                severity = Severity::Medium;
            }
        }
        let mut detail = format!("{} started using your {}.", u.app, what.to_lowercase());
        if !notes.is_empty() {
            detail.push_str(&format!(" Worth a look: {}.", notes.join(" and ")));
        }
        detail.push_str(" If you did not expect this, close the app (or turn off its access in Windows Settings → Privacy).");
        engine.emit(
            EventKind::DeviceAccess,
            severity,
            format!("{what} turned on by {}", u.app),
            Some(detail),
            path,
            None,
        );
    } else {
        let took = match (u.last_started, u.last_stopped) {
            (Some(a), Some(b)) if b >= a => format!(" after {}", human_duration(b - a)),
            _ => String::new(),
        };
        engine.emit(
            EventKind::DeviceAccess,
            Severity::Info,
            format!("{what} turned off by {}", u.app),
            Some(format!("{} stopped using your {}{took}.", u.app, what.to_lowercase())),
            path,
            None,
        );
    }
}

fn human_duration(secs: i64) -> String {
    match secs {
        s if s < 60 => format!("{s} s"),
        s if s < 3600 => format!("{} min", s / 60),
        s => format!("{} h {} min", s / 3600, (s % 3600) / 60),
    }
}

/// FILETIME (100 ns since 1601) to Unix seconds; 0 = never.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn filetime_to_unix(ft: u64) -> Option<i64> {
    (ft != 0).then(|| (ft / 10_000_000) as i64 - 11_644_473_600)
}

/// `C:#Program Files#App#app.exe` → `C:\Program Files\App\app.exe`.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn nonpackaged_path(key_name: &str) -> String {
    key_name.replace('#', "\\")
}

/// `Microsoft.WindowsCamera_8wekyb3d8bbwe` → `Microsoft.WindowsCamera`.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn package_name(key_name: &str) -> String {
    key_name.rsplit_once('_').map(|(n, _)| n).unwrap_or(key_name).to_string()
}

/// Every app Windows has recorded using the camera or microphone, newest first.
pub fn read_all() -> Vec<DeviceUse> {
    #[cfg(windows)]
    {
        let mut v = registry::read_all();
        v.sort_by_key(|u| std::cmp::Reverse(u.last_started));
        v
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

#[cfg(windows)]
mod registry {
    use super::{filetime_to_unix, nonpackaged_path, package_name};
    use sentinel_protocol::{Device, DeviceUse};
    use winreg::enums::{HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ};
    use winreg::RegKey;

    const STORE: &str = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore";

    fn entry(key: &RegKey, device: Device, app: String, path: Option<String>, user: Option<String>) -> Option<DeviceUse> {
        let start: u64 = key.get_value("LastUsedTimeStart").ok()?;
        let stop: u64 = key.get_value("LastUsedTimeStop").unwrap_or(0);
        let last_started = filetime_to_unix(start)?;
        Some(DeviceUse {
            device,
            app,
            path,
            user,
            in_use: stop == 0,
            last_started: Some(last_started),
            last_stopped: filetime_to_unix(stop),
        })
    }

    fn read_store(root: &RegKey, user: Option<String>, out: &mut Vec<DeviceUse>) {
        for (device, sub) in [(Device::Camera, "webcam"), (Device::Microphone, "microphone")] {
            let Ok(store) = root.open_subkey_with_flags(format!(r"{STORE}\{sub}"), KEY_READ) else {
                continue;
            };
            for name in store.enum_keys().flatten() {
                let Ok(k) = store.open_subkey_with_flags(&name, KEY_READ) else { continue };
                if name == "NonPackaged" {
                    for exe in k.enum_keys().flatten() {
                        let Ok(ek) = k.open_subkey_with_flags(&exe, KEY_READ) else { continue };
                        let path = nonpackaged_path(&exe);
                        let app = path.rsplit('\\').next().unwrap_or(&path).to_string();
                        out.extend(entry(&ek, device, app, Some(path), user.clone()));
                    }
                } else {
                    out.extend(entry(&k, device, package_name(&name), None, user.clone()));
                }
            }
        }
    }

    pub fn read_all() -> Vec<DeviceUse> {
        let mut out = Vec::new();
        let hku = RegKey::predef(HKEY_USERS);
        for sid in hku.enum_keys().flatten() {
            if !sid.starts_with("S-1-5-21-") || sid.ends_with("_Classes") {
                continue;
            }
            if let Ok(user) = hku.open_subkey_with_flags(&sid, KEY_READ) {
                read_store(&user, Some(sid), &mut out);
            }
        }
        read_store(&RegKey::predef(HKEY_LOCAL_MACHINE), None, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cam(app: &str, start: i64, stop: Option<i64>) -> DeviceUse {
        DeviceUse {
            device: Device::Camera,
            app: app.into(),
            path: Some(format!(r"C:\Apps\{app}")),
            user: Some("S-1-5-21-1".into()),
            in_use: stop.is_none(),
            last_started: Some(start),
            last_stopped: stop,
        }
    }

    #[test]
    fn converts_registry_formats() {
        // 2024-01-01T00:00:00Z
        assert_eq!(filetime_to_unix(133_485_408_000_000_000), Some(1_704_067_200));
        assert_eq!(filetime_to_unix(0), None);
        assert_eq!(
            nonpackaged_path("C:#Program Files#Zoom#bin#Zoom.exe"),
            r"C:\Program Files\Zoom\bin\Zoom.exe"
        );
        assert_eq!(package_name("Microsoft.WindowsCamera_8wekyb3d8bbwe"), "Microsoft.WindowsCamera");
    }

    #[test]
    fn diff_reports_sessions_opening_and_closing() {
        let mut open = HashMap::new();
        // Zoom starts using the camera.
        let now = vec![cam("zoom.exe", 100, None), cam("teams.exe", 50, Some(60))];
        let (started, stopped) = diff(&open, &now);
        assert_eq!(started.iter().map(|u| u.app.as_str()).collect::<Vec<_>>(), ["zoom.exe"]);
        assert!(stopped.is_empty());
        open.insert(key(&now[0]), now[0].clone());

        // Still in use: nothing new.
        let (started, stopped) = diff(&open, &now);
        assert!(started.is_empty() && stopped.is_empty());

        // Zoom stops: reported once, with its stop time.
        let now = vec![cam("zoom.exe", 100, Some(400))];
        let (started, stopped) = diff(&open, &now);
        assert!(started.is_empty());
        assert_eq!(stopped.len(), 1);
        assert_eq!(stopped[0].last_stopped, Some(400));
        assert!(!stopped[0].in_use);

        // A new session while we thought the old one was still open (missed the gap).
        let (started, _) = diff(&open, &[cam("zoom.exe", 500, None)]);
        assert_eq!(started.len(), 1);
    }

    #[test]
    fn durations_read_naturally() {
        assert_eq!(human_duration(42), "42 s");
        assert_eq!(human_duration(185), "3 min");
        assert_eq!(human_duration(3720), "1 h 2 min");
    }
}
