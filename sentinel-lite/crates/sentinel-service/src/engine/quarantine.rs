//! Quarantine vault.
//!
//! A quarantined file is stream-encoded (XOR with a random per-item key) into
//! `<data_dir>/quarantine/<id>.qtn`, so it can no longer be executed or picked
//! up by other scanners, then the original is deleted. Metadata lives in SQLite.
//!
//! File layout: `b"SLQ1"` | 16-byte key | encoded payload.

use crate::database::{now_unix, Database};
use anyhow::{bail, Context, Result};
use sentinel_protocol::QuarantineItem;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 4] = b"SLQ1";
const KEY_LEN: usize = 16;

pub struct Quarantine {
    dir: PathBuf,
}

fn xor_stream(src: &mut impl Read, dst: &mut impl Write, key: &[u8; KEY_LEN]) -> std::io::Result<u64> {
    let mut buf = [0u8; 64 * 1024];
    let mut pos = 0usize;
    let mut total = 0u64;
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        for b in &mut buf[..n] {
            *b ^= key[pos % KEY_LEN];
            pos = pos.wrapping_add(1);
        }
        dst.write_all(&buf[..n])?;
        total += n as u64;
    }
    Ok(total)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    // getrandom only fails if the OS RNG is unavailable; fall back to time-based
    // bytes so quarantine still works (the key is obfuscation, not secrecy).
    if getrandom::fill(&mut b).is_err() {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        for (i, x) in b.iter_mut().enumerate() {
            *x = (t >> ((i % 16) * 8)) as u8;
        }
    }
    b
}

/// Clear the read-only attribute so the delete below can succeed.
fn make_writable(path: &Path) {
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        let _ = fs::set_permissions(path, perms);
    }
}

#[cfg(windows)]
fn delete_on_reboot(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    unsafe { MoveFileExW(wide.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) != 0 }
}

#[cfg(not(windows))]
fn delete_on_reboot(_path: &Path) -> bool {
    false
}

impl Quarantine {
    pub fn new(dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
        Ok(Self { dir })
    }

    fn vault_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.qtn"))
    }

    /// Move `path` into the vault. Returns the new record.
    pub fn isolate(&self, db: &Database, path: &Path, sha256: &str, threat: &str) -> Result<QuarantineItem> {
        let id = crate::engine::hasher::to_hex(&random_bytes::<12>());
        let key: [u8; KEY_LEN] = random_bytes();
        let dest = self.vault_path(&id);
        let tmp = dest.with_extension("tmp");

        let size = {
            let mut src = BufReader::new(File::open(path).with_context(|| format!("opening {}", path.display()))?);
            let mut out = BufWriter::new(OpenOptions::new().write(true).create_new(true).open(&tmp)?);
            out.write_all(MAGIC)?;
            out.write_all(&key)?;
            let n = xor_stream(&mut src, &mut out, &key)?;
            out.into_inner().map_err(|e| e.into_error())?.sync_all()?;
            n
        };
        fs::rename(&tmp, &dest)?;

        make_writable(path);
        if let Err(e) = fs::remove_file(path) {
            if delete_on_reboot(path) {
                tracing::warn!(path = %path.display(), error = %e, "file locked; scheduled deletion at reboot");
            } else {
                // Could not remove the original: undo so we never report a false "quarantined".
                let _ = fs::remove_file(&dest);
                return Err(e).with_context(|| format!("removing {}", path.display()));
            }
        }

        let item = QuarantineItem {
            id,
            original_path: path.to_string_lossy().into_owned(),
            sha256: sha256.to_owned(),
            threat_name: threat.to_owned(),
            size,
            quarantined_at: now_unix(),
        };
        db.insert_quarantine(&item)?;
        Ok(item)
    }

    /// Decode back to the original location (or `<name>.restored` if occupied).
    /// The hash is allow-listed so real-time protection does not re-quarantine it.
    pub fn restore(&self, db: &Database, id: &str) -> Result<PathBuf> {
        let item = db.get_quarantine(id)?.context("no such quarantine item")?;
        let vault = self.vault_path(id);
        let mut src = BufReader::new(File::open(&vault).context("opening vault file")?);
        let mut magic = [0u8; 4];
        let mut key = [0u8; KEY_LEN];
        src.read_exact(&mut magic)?;
        if &magic != MAGIC {
            bail!("vault file is corrupt");
        }
        src.read_exact(&mut key)?;

        let mut target = PathBuf::from(&item.original_path);
        if target.exists() {
            let mut name = target.file_name().unwrap_or_default().to_os_string();
            name.push(".restored");
            target.set_file_name(name);
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        db.allow_hash(&item.sha256, "restored from quarantine by user")?;
        {
            let mut out = BufWriter::new(OpenOptions::new().write(true).create_new(true).open(&target)?);
            xor_stream(&mut src, &mut out, &key)?;
            out.flush()?;
        }
        fs::remove_file(&vault)?;
        db.remove_quarantine(id)?;
        Ok(target)
    }

    pub fn delete(&self, db: &Database, id: &str) -> Result<()> {
        if db.get_quarantine(id)?.is_none() {
            bail!("no such quarantine item");
        }
        match fs::remove_file(self.vault_path(id)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        db.remove_quarantine(id)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolate_restore_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open_in_memory().unwrap();
        let q = Quarantine::new(tmp.path().join("vault")).unwrap();
        let victim = tmp.path().join("bad.exe");
        fs::write(&victim, b"MZ pretend payload").unwrap();

        let item = q.isolate(&db, &victim, &"b".repeat(64), "Test.Threat").unwrap();
        assert!(!victim.exists());
        let stored = fs::read(q.vault_path(&item.id)).unwrap();
        assert!(!stored.windows(2).any(|w| w == b"MZ"), "payload must not be stored in clear");
        assert_eq!(db.list_quarantine().unwrap().len(), 1);

        let back = q.restore(&db, &item.id).unwrap();
        assert_eq!(fs::read(back).unwrap(), b"MZ pretend payload");
        assert!(db.list_quarantine().unwrap().is_empty());
        assert!(db.lookup_hash(&"b".repeat(64)).unwrap().is_none());
    }

    #[test]
    fn delete_removes_vault_file() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Database::open_in_memory().unwrap();
        let q = Quarantine::new(tmp.path().join("vault")).unwrap();
        let victim = tmp.path().join("bad.bin");
        fs::write(&victim, b"x").unwrap();
        let item = q.isolate(&db, &victim, &"c".repeat(64), "T").unwrap();
        q.delete(&db, &item.id).unwrap();
        assert!(!q.vault_path(&item.id).exists());
        assert!(q.delete(&db, &item.id).is_err());
    }
}
