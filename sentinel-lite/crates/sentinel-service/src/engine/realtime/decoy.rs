//! Ransomware decoys ("canary files").
//!
//! Hidden files with ordinary-looking names are planted in every profile's
//! Documents, Pictures and Desktop. Nobody has a reason to modify them;
//! ransomware walking those folders encrypts or renames them early, since
//! the names sort first ("!") and last ("~"). File Shield reports any change
//! to a decoy; the engine then confirms it by re-hashing (so harmless
//! metadata events never trigger) and responds.
//!
//! The response is deliberately reversible: the process that is writing the
//! most at that moment is *suspended*, not killed, and the user chooses
//! Terminate or Resume. Windows system processes and validly code-signed
//! programs are never suspended.

use crate::database::Database;
use crate::engine::hasher;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const META_KEY: &str = "ransomware_decoys";

/// (sub-folder, file name). Extensions are ones ransomware always targets.
const PLAN: &[(&str, &str)] = &[
    ("Documents", "!_Accounts_2026.xlsx"),
    ("Documents", "~_Scanned_Contracts.docx"),
    ("Pictures", "!_IMG_0001.jpg"),
    ("Pictures", "~_Family_Archive.png"),
    ("Desktop", "!_Notes.docx"),
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Decoy {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Intact,
    Modified,
    Missing,
}

#[derive(Default)]
pub struct Decoys {
    by_path: HashMap<String, Decoy>,
}

/// Comparison key: case-insensitive and separator-agnostic (Windows accepts both
/// `\` and `/`, and file-system notifications always report `\`).
fn key(p: &Path) -> String {
    let s = p.to_string_lossy().to_lowercase();
    if cfg!(windows) {
        s.replace('/', "\\")
    } else {
        s
    }
}

/// Content: an explanatory header plus random bytes (so it looks like real
/// data and cannot be compressed away).
fn content() -> Vec<u8> {
    let mut data =
        b"This hidden file is a Sentinel-Lite ransomware decoy. Please do not edit, move or delete it.\n".to_vec();
    let mut noise = vec![0u8; 48 * 1024];
    let _ = getrandom::fill(&mut noise);
    data.extend_from_slice(&noise);
    data
}

impl Decoys {
    pub fn load(db: &Database) -> Self {
        let list: Vec<Decoy> = db
            .meta(META_KEY)
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or_default();
        Self {
            by_path: list.into_iter().map(|d| (key(&d.path), d)).collect(),
        }
    }

    fn save(&self, db: &Database) {
        let list: Vec<&Decoy> = self.by_path.values().collect();
        db.set_meta(META_KEY, serde_json::to_string(&list).ok().as_deref());
    }

    pub fn is_decoy(&self, path: &Path) -> bool {
        self.by_path.contains_key(&key(path))
    }

    #[cfg(test)]
    pub fn paths(&self) -> Vec<PathBuf> {
        self.by_path.values().map(|d| d.path.clone()).collect()
    }

    pub fn state(&self, path: &Path) -> Option<State> {
        let d = self.by_path.get(&key(path))?;
        Some(match std::fs::read(&d.path) {
            Ok(bytes) if hasher::sha256_bytes(&bytes) == d.sha256 => State::Intact,
            Ok(_) => State::Modified,
            Err(_) => State::Missing,
        })
    }

    /// Decoys that were changed or removed (e.g. while the service was stopped).
    pub fn tampered(&self) -> Vec<(PathBuf, State)> {
        self.by_path
            .values()
            .filter_map(|d| match self.state(&d.path) {
                Some(State::Intact) | None => None,
                Some(s) => Some((d.path.clone(), s)),
            })
            .collect()
    }

    /// Ensure a fresh decoy exists at every planned location under `profiles`.
    /// Never overwrites a file that is not one of ours.
    pub fn plant(&mut self, db: &Database, profiles: &[PathBuf]) -> usize {
        let mut planted = 0;
        for profile in profiles {
            for (sub, name) in PLAN {
                let dir = profile.join(sub);
                if !dir.is_dir() {
                    continue;
                }
                let path = dir.join(name);
                let ours = self.is_decoy(&path);
                if path.exists() && !ours {
                    continue; // a real user file with this name: leave it alone
                }
                if ours && self.state(&path) == Some(State::Intact) {
                    continue;
                }
                crate::platform::unhide_file(&path);
                let data = content();
                match std::fs::write(&path, &data) {
                    Ok(()) => {
                        crate::platform::hide_file(&path);
                        self.by_path.insert(
                            key(&path),
                            Decoy {
                                path,
                                sha256: hasher::sha256_bytes(&data),
                            },
                        );
                        planted += 1;
                    }
                    Err(e) => tracing::debug!(path = %path.display(), error = %e, "cannot plant decoy"),
                }
            }
        }
        self.save(db);
        planted
    }

    /// Rewrite decoys that were changed or deleted, at their known locations.
    pub fn replant(&mut self, db: &Database) -> usize {
        let damaged: Vec<PathBuf> = self.tampered().into_iter().map(|(p, _)| p).collect();
        let mut n = 0;
        for path in damaged {
            if !path.parent().is_some_and(|d| d.is_dir()) {
                continue;
            }
            crate::platform::unhide_file(&path);
            let data = content();
            if std::fs::write(&path, &data).is_ok() {
                crate::platform::hide_file(&path);
                self.by_path.insert(
                    key(&path),
                    Decoy {
                        path,
                        sha256: hasher::sha256_bytes(&data),
                    },
                );
                n += 1;
            }
        }
        self.save(db);
        n
    }

    /// Remove every decoy we planted (feature turned off).
    pub fn remove_all(&mut self, db: &Database) {
        for d in self.by_path.values() {
            if self.state(&d.path) == Some(State::Intact) {
                crate::platform::unhide_file(&d.path);
                let _ = std::fs::remove_file(&d.path);
            }
        }
        self.by_path.clear();
        self.save(db);
    }
}

/// A process that wrote heavily during the sampling window.
#[derive(Debug, Clone)]
pub struct Suspect {
    pub pid: u32,
    pub image: PathBuf,
    pub bytes_written: u64,
}

/// Sample every process's write counter twice, `window` apart, and return
/// the heaviest writers that are eligible for suspension, best first.
pub fn heaviest_writers(
    window: std::time::Duration,
    min_bytes: u64,
    eligible: impl Fn(u32, &Path) -> bool,
) -> Vec<Suspect> {
    use crate::platform;
    let before: HashMap<u32, u64> = platform::list_processes()
        .into_iter()
        .filter_map(|p| platform::write_bytes(p.pid).map(|w| (p.pid, w)))
        .collect();
    std::thread::sleep(window);
    let mut out: Vec<Suspect> = platform::list_processes()
        .into_iter()
        .filter_map(|p| {
            let delta = platform::write_bytes(p.pid)?.saturating_sub(*before.get(&p.pid)?);
            (delta >= min_bytes).then_some((p.pid, delta))
        })
        .filter_map(|(pid, bytes_written)| {
            let image = platform::image_path(pid)?;
            eligible(pid, &image).then_some(Suspect {
                pid,
                image,
                bytes_written,
            })
        })
        .collect();
    out.sort_by_key(|s| std::cmp::Reverse(s.bytes_written));
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Tests that start heavy-writer processes must not run concurrently:
    /// each would see (and might suspend) the other's writer.
    #[cfg(unix)]
    pub(crate) static WRITER_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn plant_detect_and_remove() {
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("alice");
        for sub in ["Documents", "Pictures"] {
            std::fs::create_dir_all(profile.join(sub)).unwrap();
        }
        // A real user file with a planned name must never be touched.
        std::fs::write(profile.join("Pictures").join("!_IMG_0001.jpg"), b"real photo").unwrap();

        let db = Database::open_in_memory().unwrap();
        let mut d = Decoys::default();
        assert_eq!(d.plant(&db, std::slice::from_ref(&profile)), 3); // 2 Documents + 1 Pictures (no Desktop)
        assert_eq!(
            std::fs::read(profile.join("Pictures").join("!_IMG_0001.jpg")).unwrap(),
            b"real photo"
        );
        assert!(d.tampered().is_empty());

        // Persisted: a reload knows the same decoys.
        let reloaded = Decoys::load(&db);
        let doc = profile.join("Documents").join("!_Accounts_2026.xlsx");
        assert!(reloaded.is_decoy(&doc));
        assert!(!reloaded.is_decoy(&profile.join("Pictures").join("!_IMG_0001.jpg")));

        // "Encrypt" one decoy, delete another. (Windows will not truncate a
        // hidden+system file with a plain create; real ransomware clears it too.)
        crate::platform::unhide_file(&doc);
        std::fs::write(&doc, b"ENCRYPTED GARBAGE").unwrap();
        std::fs::remove_file(profile.join("Documents").join("~_Scanned_Contracts.docx")).unwrap();
        let t = reloaded.tampered();
        assert_eq!(t.len(), 2);
        assert!(t.iter().any(|(_, s)| *s == State::Modified));
        assert!(t.iter().any(|(_, s)| *s == State::Missing));

        // Re-planting restores them; removal cleans up only our files.
        let mut d = reloaded;
        assert_eq!(d.plant(&db, std::slice::from_ref(&profile)), 2);
        assert!(d.tampered().is_empty());
        d.remove_all(&db);
        assert!(!doc.exists());
        assert!(profile.join("Pictures").join("!_IMG_0001.jpg").exists());
        assert!(Decoys::load(&db).paths().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn finds_the_process_that_is_writing() {
        let _serial = WRITER_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        // `dd` writing to /dev/null: counted as written bytes, costs no disk.
        let mut child = std::process::Command::new("dd")
            .args(["if=/dev/zero", "of=/dev/null", "bs=1M"])
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let me = std::process::id();
        let suspects = heaviest_writers(std::time::Duration::from_millis(500), 1024 * 1024, |pid, _| pid != me);
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(suspects.first().map(|s| s.pid), Some(child.id()), "{suspects:?}");
        assert!(suspects[0].bytes_written >= 1024 * 1024);
    }
}
