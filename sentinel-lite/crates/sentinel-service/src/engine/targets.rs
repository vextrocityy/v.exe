//! Where to look: quick-scan roots, full-scan roots and real-time watch folders.
//!
//! The service runs as LocalSystem, so "the user's Downloads" means every
//! profile under `C:\Users`, not the service account's own profile.

use std::path::PathBuf;

/// Real user profile directories (skips Default / All Users / junctions).
pub fn user_profiles() -> Vec<PathBuf> {
    #[cfg(windows)]
    let root = {
        let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        PathBuf::from(format!("{drive}\\Users"))
    };
    #[cfg(not(windows))]
    let root = PathBuf::from(if cfg!(target_os = "macos") { "/Users" } else { "/home" });

    let Ok(entries) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_ascii_lowercase();
            !matches!(n.as_str(), "default" | "default user" | "all users")
        })
        .map(|e| e.path())
        .collect()
}

fn existing(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = paths.into_iter().filter(|p| p.is_dir()).collect();
    out.sort();
    out.dedup();
    out
}

/// Folders where malware typically lands or persists.
pub fn hot_folders() -> Vec<PathBuf> {
    let mut v = Vec::new();
    for profile in user_profiles() {
        v.push(profile.join("Downloads"));
        v.push(profile.join("Desktop"));
        #[cfg(windows)]
        {
            v.push(profile.join(r"AppData\Local\Temp"));
            v.push(profile.join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"));
        }
    }
    #[cfg(windows)]
    {
        if let Some(pd) = std::env::var_os("ProgramData") {
            v.push(PathBuf::from(pd).join(r"Microsoft\Windows\Start Menu\Programs\StartUp"));
        }
        if let Some(root) = std::env::var_os("SystemRoot") {
            v.push(PathBuf::from(root).join("Temp"));
        }
    }
    #[cfg(not(windows))]
    v.push(PathBuf::from("/tmp"));
    existing(v)
}

/// Quick scan = hot folders + roaming/local app data (common drop locations).
pub fn quick_scan_roots() -> Vec<PathBuf> {
    #[allow(unused_mut)]
    let mut v = hot_folders();
    #[cfg(windows)]
    for profile in user_profiles() {
        v.push(profile.join(r"AppData\Roaming"));
        v.push(profile.join(r"AppData\Local"));
    }
    existing(v)
}

/// Full scan = every fixed drive root.
pub fn full_scan_roots() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        existing((b'A'..=b'Z').map(|d| PathBuf::from(format!("{}:\\", d as char))))
    }
    #[cfg(not(windows))]
    {
        vec![PathBuf::from("/")]
    }
}

/// Folders the real-time file shield watches: hot folders + Documents
/// (for the ransomware detector) + user-configured extras.
pub fn watch_roots(extra: &[String]) -> Vec<PathBuf> {
    let mut v = hot_folders();
    for profile in user_profiles() {
        v.push(profile.join("Documents"));
    }
    v.extend(extra.iter().map(PathBuf::from));
    existing(v)
}
