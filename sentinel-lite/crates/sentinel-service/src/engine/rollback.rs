//! Ransomware rollback.
//!
//! The service keeps a few recent Volume Shadow Copies ("snapshots") of the
//! system drive, taken on a schedule. After an attack, the user picks a
//! snapshot, sees which of their files differ from it (encrypted-looking ones
//! first) and puts the snapshot's copies back. Current copies are moved to a
//! backup folder first, so a restore never destroys anything.
//!
//! Snapshots are created and listed through WMI (`Win32_ShadowCopy`, via
//! PowerShell's CIM cmdlets; this works on client editions of Windows, unlike
//! `vssadmin create`). Files are read from the snapshot's device path,
//! `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\...`, which LocalSystem can
//! open like any directory. Process Guard blocks the usual ways ransomware
//! deletes snapshots (see [`is_backup_deletion`]).

use sentinel_protocol::{ChangeKind, FileChange, Snapshot};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// How many of our own snapshots to keep (older ones are deleted).
pub const KEEP: usize = 3;
/// Stop walking after this many files, and list at most this many changes.
const MAX_WALK: usize = 300_000;
pub const MAX_CHANGES: usize = 5_000;

/// A snapshot plus the device path its files are read from.
#[derive(Debug, Clone, PartialEq)]
pub struct ShadowCopy {
    pub snapshot: Snapshot,
    pub device: String,
}

/// Our snapshots (`snapshots.json` in the data folder): id and time taken.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Owned {
    pub ids: Vec<(String, i64)>,
}

impl Owned {
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(self).unwrap_or_default())?;
        std::fs::rename(tmp, path)
    }

    pub fn newest(&self) -> Option<i64> {
        self.ids.iter().map(|(_, t)| *t).max()
    }
}

/// Snapshot ids are GUIDs in braces; anything else is refused before it gets
/// near a PowerShell command line.
pub fn valid_id(id: &str) -> bool {
    let inner = id.strip_prefix('{').and_then(|s| s.strip_suffix('}'));
    inner.is_some_and(|g| {
        g.len() == 36
            && g.char_indices().all(|(i, c)| match i {
                8 | 13 | 18 | 23 => c == '-',
                _ => c.is_ascii_hexdigit(),
            })
    })
}

/// Map a live path to the same file inside a snapshot of `volume` (`C:\`).
pub fn snapshot_path(device: &str, volume: &str, live: &Path) -> Option<PathBuf> {
    let live_s = live.to_string_lossy();
    let vol = volume.trim_end_matches(['\\', '/']);
    if vol.is_empty() || live_s.len() <= vol.len() || !live_s[..vol.len()].eq_ignore_ascii_case(vol) {
        return None;
    }
    let rest = live_s[vol.len()..].trim_start_matches(['\\', '/']);
    let dev = device.trim_end_matches(['\\', '/']);
    let sep = if dev.contains('\\') { '\\' } else { '/' };
    Some(PathBuf::from(format!("{dev}{sep}{rest}")))
}

fn mtime(meta: &std::fs::Metadata) -> Option<i64> {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
}

fn head(path: &Path) -> Option<Vec<u8>> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut f = std::fs::File::open(path).ok()?;
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => return None,
        }
    }
    buf.truncate(n);
    Some(buf)
}

/// Did this change turn a normal file into an encrypted-looking one?
/// True when the current copy is near-random and either the snapshot copy was
/// not, or the snapshot copy had a recognisable header that is now gone
/// (catches encrypted .docx / .jpg, which are compressed and high-entropy anyway).
pub fn encrypted_change(then: &Path, now: &Path) -> bool {
    let (Some(a), Some(b)) = (head(then), head(now)) else {
        return false;
    };
    if b.len() < 256 {
        return false;
    }
    let now_e = super::heuristics::shannon_entropy(&b);
    if now_e < 7.5 {
        return false;
    }
    let then_e = super::heuristics::shannon_entropy(&a);
    let header_lost = a.len() >= 4 && b.len() >= 4 && a[..4] != b[..4] && has_magic(&a);
    then_e < 7.0 || header_lost
}

/// Common file signatures (the first bytes of a valid file of that type).
fn has_magic(b: &[u8]) -> bool {
    const MAGIC: &[&[u8]] = &[
        b"PK\x03\x04",        // zip, docx, xlsx, pptx, odt, jar
        b"%PDF",              //
        b"\xFF\xD8\xFF",      // jpeg
        b"\x89PNG",           //
        b"GIF8",              //
        b"\xD0\xCF\x11\xE0", // legacy Office
        b"7z\xBC\xAF",        //
        b"Rar!",              //
        b"RIFF",              // wav, avi, webp
        b"ID3",               // mp3
        b"fLaC",              //
        b"\x1F\x8B",          // gzip
        b"SQLite format 3",   //
    ];
    MAGIC.iter().any(|m| b.starts_with(m)) || (b.len() > 8 && &b[4..8] == b"ftyp") // mp4, heic, mov
}

/// Iterative directory walk; returns files (bounded by [`MAX_WALK`]).
fn walk(root: &Path, skip: &dyn Fn(&Path) -> bool) -> Vec<(PathBuf, std::fs::Metadata)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_symlink() || skip(&p) {
                continue; // junctions such as "My Music" loop back
            }
            if ft.is_dir() {
                stack.push(p);
            } else if let Ok(m) = e.metadata() {
                out.push((p, m));
                if out.len() >= MAX_WALK {
                    return out;
                }
            }
        }
    }
    out
}

/// Files in `live` that differ from their copy in `snap` (the same folder
/// inside the snapshot), plus files that only the snapshot still has.
/// `taken` is the snapshot time: files not modified since then are unchanged.
pub fn diff_folder(live: &Path, snap: &Path, taken: i64, skip: &dyn Fn(&Path) -> bool) -> Vec<FileChange> {
    let mut out = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    for (path, meta) in walk(live, skip) {
        let Ok(rel) = path.strip_prefix(live) else { continue };
        seen.insert(rel.to_path_buf());
        let modified = mtime(&meta);
        if modified.is_some_and(|m| m < taken) {
            continue;
        }
        let then_path = snap.join(rel);
        let Ok(then) = std::fs::metadata(&then_path) else { continue }; // new since the snapshot
        if !then.is_file() || (then.len() == meta.len() && mtime(&then) == modified) {
            continue;
        }
        out.push(FileChange {
            path: path.display().to_string(),
            change: ChangeKind::Modified,
            size_then: then.len(),
            size_now: Some(meta.len()),
            modified_at: modified,
            looks_encrypted: encrypted_change(&then_path, &path),
        });
    }
    for (path, meta) in walk(snap, &|_| false) {
        let Ok(rel) = path.strip_prefix(snap) else { continue };
        if seen.contains(rel) {
            continue;
        }
        let live_path = live.join(rel);
        if skip(&live_path) || live_path.exists() {
            continue;
        }
        out.push(FileChange {
            path: live_path.display().to_string(),
            change: ChangeKind::Deleted,
            size_then: meta.len(),
            size_now: None,
            modified_at: None,
            looks_encrypted: false,
        });
    }
    out
}

/// Encrypted-looking first, then deleted, then other changes (newest first).
pub fn sort_changes(v: &mut [FileChange]) {
    v.sort_by(|a, b| {
        let rank = |c: &FileChange| match (c.looks_encrypted, c.change) {
            (true, _) => 0,
            (false, ChangeKind::Deleted) => 1,
            _ => 2,
        };
        rank(a)
            .cmp(&rank(b))
            .then(b.modified_at.cmp(&a.modified_at))
            .then(a.path.cmp(&b.path))
    });
}

/// Folders a rollback looks at by default: each user's personal folders.
pub fn default_folders(profiles: &[PathBuf]) -> Vec<PathBuf> {
    const NAMES: &[&str] = &["Desktop", "Documents", "Pictures", "Music", "Videos", "Downloads"];
    profiles
        .iter()
        .flat_map(|p| NAMES.iter().map(move |n| p.join(n)))
        .filter(|p| p.is_dir())
        .collect()
}

pub const BACKUP_DIR_NAME: &str = "Vigil Restore Backup";

/// Where the current copy of `live` goes before it is replaced:
/// `<profile>\Vigil Restore Backup\<stamp>\<path inside the profile>`.
pub fn backup_path(live: &Path, profiles: &[PathBuf], stamp: &str) -> Option<PathBuf> {
    profiles.iter().find_map(|p| {
        let rel = live.strip_prefix(p).ok()?;
        Some(p.join(BACKUP_DIR_NAME).join(stamp).join(rel))
    })
}

/// Is `live` inside one of the allowed folders (and not a path trick)?
pub fn allowed(live: &Path, folders: &[PathBuf]) -> bool {
    let s = live.to_string_lossy();
    !s.contains("..") && folders.iter().any(|f| live.starts_with(f) && live != f)
}

/// Restore one file: move the current copy (if any) to `backup`, then copy the
/// snapshot's version into place (timestamps are kept by the copy).
pub fn restore_file(snap: &Path, live: &Path, backup: Option<&Path>) -> std::io::Result<()> {
    if !snap.is_file() {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "not in the snapshot"));
    }
    if live.exists() {
        let backup = backup.ok_or_else(|| std::io::Error::other("no backup location"))?;
        if let Some(dir) = backup.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::rename(live, backup).or_else(|_| {
            std::fs::copy(live, backup)?;
            std::fs::remove_file(live)
        })?;
    } else if let Some(dir) = live.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = live.with_extension("vigil-restoring");
    std::fs::copy(snap, &tmp)?;
    std::fs::rename(&tmp, live)
}

/// Command lines that destroy backups / recovery: the first thing most
/// ransomware does. Process Guard terminates these.
pub fn is_backup_deletion(cmd: &str) -> Option<&'static str> {
    let c = cmd.to_ascii_lowercase().replace(['"', '\''], "");
    let has = |s: &str| c.contains(s);
    if has("vssadmin") && (has("delete shadows") || has("resize shadowstorage")) {
        return Some("vssadmin deleting shadow copies");
    }
    if has("wmic") && has("shadowcopy") && has("delete") {
        return Some("WMIC deleting shadow copies");
    }
    if has("win32_shadowcopy") && (has("delete") || has("remove-")) {
        return Some("PowerShell deleting shadow copies");
    }
    if has("wbadmin") && (has("delete catalog") || has("delete systemstatebackup") || has("delete backup")) {
        return Some("wbadmin deleting backups");
    }
    if has("bcdedit") && (has("recoveryenabled no") || has("bootstatuspolicy ignoreallfailures")) {
        return Some("bcdedit disabling Windows recovery");
    }
    None
}

// ---------------------------------------------------------------------------
// Volume Shadow Copy service (Windows)
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn powershell(script: &str) -> anyhow::Result<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .output()?;
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let first = err.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("failed");
        anyhow::bail!("{first}");
    }
    Ok(stdout)
}

/// Take a snapshot of `volume` (e.g. `C:\`). Returns its id.
pub fn create(volume: &str) -> anyhow::Result<String> {
    if !(volume.len() == 3 && volume.as_bytes()[0].is_ascii_alphabetic() && volume.ends_with(":\\")) {
        anyhow::bail!("not a drive root: {volume}");
    }
    #[cfg(windows)]
    {
        let script = format!(
            "$r = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create \
             -Arguments @{{Volume='{volume}'; Context='ClientAccessible'}}; \
             if ($r.ReturnValue -ne 0) {{ throw \"Volume Shadow Copy error $($r.ReturnValue)\" }}; $r.ShadowID"
        );
        let id = powershell(&script)?;
        let id = id.lines().last().unwrap_or_default().trim().to_string();
        if !valid_id(&id) {
            anyhow::bail!("unexpected snapshot id: {id}");
        }
        Ok(id)
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("snapshots need Windows (Volume Shadow Copy)")
    }
}

/// Every shadow copy on the machine.
pub fn list() -> anyhow::Result<Vec<ShadowCopy>> {
    #[cfg(windows)]
    {
        #[derive(serde::Deserialize)]
        struct Row {
            id: String,
            device: String,
            created: i64,
            volume: Option<String>,
        }
        let script = "$v=@{}; Get-CimInstance Win32_Volume | ForEach-Object { $v[$_.DeviceID] = $_.DriveLetter }; \
             $rows = @(Get-CimInstance Win32_ShadowCopy | ForEach-Object { [pscustomobject]@{ \
               id = $_.ID; device = $_.DeviceObject; \
               created = [DateTimeOffset]::new($_.InstallDate).ToUnixTimeSeconds(); \
               volume = $v[$_.VolumeName] } }); \
             ConvertTo-Json -InputObject $rows -Compress";
        let out = powershell(script)?;
        let rows: Vec<Row> = if out.is_empty() { Vec::new() } else { serde_json::from_str(&out)? };
        Ok(rows
            .into_iter()
            .filter(|r| valid_id(&r.id))
            .map(|r| ShadowCopy {
                snapshot: Snapshot {
                    id: r.id,
                    created_at: r.created,
                    volume: r.volume.map(|v| format!("{}\\", v.trim_end_matches('\\'))).unwrap_or_default(),
                    ours: false,
                },
                device: r.device,
            })
            .collect())
    }
    #[cfg(not(windows))]
    {
        Ok(Vec::new())
    }
}

pub fn delete(id: &str) -> anyhow::Result<()> {
    if !valid_id(id) {
        anyhow::bail!("invalid snapshot id");
    }
    #[cfg(windows)]
    {
        powershell(&format!(
            "Get-CimInstance Win32_ShadowCopy | Where-Object {{ $_.ID -eq '{id}' }} | Remove-CimInstance"
        ))?;
        Ok(())
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("snapshots need Windows")
    }
}

/// `2026-11-09 1432` (UTC) for backup folder names.
pub fn stamp(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}{:02} UTC", secs / 3600, (secs % 3600) / 60)
}

/// The system drive, `C:\` on almost every PC.
pub fn system_volume() -> String {
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    format!("{}\\", drive.trim_end_matches('\\'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn stamps_read_as_dates() {
        assert_eq!(stamp(1_704_067_200), "2024-01-01 0000 UTC");
        assert_eq!(stamp(1_762_660_440), "2025-11-09 0354 UTC");
    }

    #[test]
    fn snapshot_ids_must_be_guids() {
        assert!(valid_id("{3F2504E0-4F89-11D3-9A0C-0305E82C3301}"));
        assert!(!valid_id("3F2504E0-4F89-11D3-9A0C-0305E82C3301"));
        assert!(!valid_id("{3F2504E0-4F89-11D3-9A0C-0305E82C330'}"));
        assert!(!valid_id("{x'; Remove-Item C:\\ -Recurse; '}"));
    }

    #[test]
    fn maps_live_paths_into_the_snapshot() {
        let dev = r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7";
        assert_eq!(
            snapshot_path(dev, "C:\\", Path::new(r"c:\Users\bob\Documents\a.docx")),
            Some(PathBuf::from(format!(r"{dev}\Users\bob\Documents\a.docx")))
        );
        assert_eq!(snapshot_path(dev, "C:\\", Path::new(r"D:\data\a.txt")), None);
        assert_eq!(
            snapshot_path("/snap", "/live", Path::new("/live/docs/a.txt")),
            Some(PathBuf::from("/snap/docs/a.txt"))
        );
    }

    #[test]
    fn spots_files_that_were_encrypted() {
        let dir = tempfile::tempdir().unwrap();
        let random: Vec<u8> = (0..65536u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        let write = |n: &str, b: &[u8]| {
            let p = dir.path().join(n);
            std::fs::write(&p, b).unwrap();
            p
        };
        let text = write("then.txt", &b"quarterly figures ".repeat(4000));
        let enc = write("now.bin", &random);
        assert!(encrypted_change(&text, &enc));
        // A compressed original (high entropy anyway) still counts once its header is gone.
        let zip = write("then.docx", &[b"PK\x03\x04".as_slice(), &random[4..]].concat());
        assert!(encrypted_change(&zip, &enc));
        // Editing a text file is not encryption.
        let edited = write("edited.txt", &b"quarterly figures, revised ".repeat(3000));
        assert!(!encrypted_change(&text, &edited));
    }

    #[test]
    fn finds_changed_and_deleted_files_and_restores_them() {
        let root = tempfile::tempdir().unwrap();
        let profile = root.path().join("Users/bob");
        let live = profile.join("Documents");
        let snap = root.path().join("snapshot/Users/bob/Documents");
        for d in [&live, &snap, &live.join("sub"), &snap.join("sub")] {
            std::fs::create_dir_all(d).unwrap();
        }
        let both = |rel: &str, body: &[u8]| {
            std::fs::write(snap.join(rel), body).unwrap();
            std::fs::write(live.join(rel), body).unwrap();
        };
        both("same.txt", b"unchanged");
        both("sub/report.txt", b"original report");
        both("gone.txt", b"deleted by ransomware");
        std::fs::remove_file(live.join("gone.txt")).unwrap();
        // Old file times on the unchanged copies: older than the snapshot.
        let old = SystemTime::now() - Duration::from_secs(3600);
        for p in [live.join("same.txt"), snap.join("same.txt")] {
            std::fs::File::options().write(true).open(&p).unwrap().set_modified(old).unwrap();
        }
        let taken = (SystemTime::now() - Duration::from_secs(60))
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        std::fs::write(live.join("sub/report.txt"), b"ENCRYPTED!!").unwrap();
        std::fs::write(live.join("new.txt"), b"ransom note").unwrap();

        let mut changes = diff_folder(&live, &snap, taken, &|_| false);
        sort_changes(&mut changes);
        let got: Vec<(String, ChangeKind)> = changes
            .iter()
            .map(|c| {
                let rel = Path::new(&c.path).strip_prefix(&live).unwrap();
                (rel.to_string_lossy().replace('\\', "/"), c.change)
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("gone.txt".to_string(), ChangeKind::Deleted),
                ("sub/report.txt".to_string(), ChangeKind::Modified)
            ]
        );

        // Restore: the encrypted copy goes to the backup folder, the original comes back.
        let profiles = vec![profile.clone()];
        let target = live.join("sub/report.txt");
        let backup = backup_path(&target, &profiles, "2026-11-09 1200").unwrap();
        assert!(backup.starts_with(profile.join(BACKUP_DIR_NAME)));
        restore_file(&snap.join("sub/report.txt"), &target, Some(&backup)).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"original report");
        assert_eq!(std::fs::read(&backup).unwrap(), b"ENCRYPTED!!");
        restore_file(&snap.join("gone.txt"), &live.join("gone.txt"), None).unwrap();
        assert_eq!(std::fs::read(live.join("gone.txt")).unwrap(), b"deleted by ransomware");

        assert!(allowed(&target, std::slice::from_ref(&live)));
        assert!(!allowed(&live, std::slice::from_ref(&live)));
        assert!(!allowed(&root.path().join("etc/passwd"), std::slice::from_ref(&live)));
        assert!(!allowed(&live.join("../../x"), &[live]));
    }

    #[test]
    fn recognises_backup_destruction() {
        assert!(is_backup_deletion("vssadmin.exe Delete Shadows /All /Quiet").is_some());
        assert!(is_backup_deletion(r#"cmd /c "wmic shadowcopy delete""#).is_some());
        assert!(is_backup_deletion("powershell Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete()}").is_some());
        assert!(is_backup_deletion("bcdedit /set {default} recoveryenabled No").is_some());
        assert!(is_backup_deletion("wbadmin DELETE CATALOG -quiet").is_some());
        assert!(is_backup_deletion("vssadmin list shadows").is_none());
        assert!(is_backup_deletion("powershell Get-CimInstance Win32_ShadowCopy").is_none());
    }
}
