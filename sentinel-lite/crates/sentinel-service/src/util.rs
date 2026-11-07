//! Small robustness helpers used across the service.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

/// Run `f`, converting a panic into a logged error. Used around every unit of
/// work in long-lived threads (one file, one process event, one poll cycle) so
/// a single bad input can never take a shield, or the service, down.
pub fn contain<T>(what: &str, f: impl FnOnce() -> T) -> Option<T> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(v) => Some(v),
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".into());
            tracing::error!(task = what, panic = %msg, "recovered from panic");
            None
        }
    }
}

/// Route panics through tracing so they land in the service log file
/// (a service has no console to print them to).
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_default();
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_default();
        let thread = std::thread::current().name().unwrap_or("unnamed").to_string();
        tracing::error!(%location, %thread, "panic: {msg}");
    }));
}

/// Size-capped log file: rotates to `.1`, `.2`, … `.{keep}` when it grows past `max_bytes`.
pub struct RotatingFile {
    path: PathBuf,
    max_bytes: u64,
    keep: u32,
    file: File,
    written: u64,
}

impl RotatingFile {
    pub fn open(path: &Path, max_bytes: u64, keep: u32) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path: path.to_path_buf(),
            max_bytes,
            keep: keep.max(1),
            file,
            written,
        })
    }

    fn rotated(&self, n: u32) -> PathBuf {
        let mut s = self.path.clone().into_os_string();
        s.push(format!(".{n}"));
        PathBuf::from(s)
    }

    fn rotate(&mut self) -> io::Result<()> {
        let _ = std::fs::remove_file(self.rotated(self.keep));
        for n in (1..self.keep).rev() {
            let _ = std::fs::rename(self.rotated(n), self.rotated(n + 1));
        }
        self.file.flush()?;
        std::fs::rename(&self.path, self.rotated(1))?;
        self.file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        self.written = 0;
        Ok(())
    }
}

impl Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written + buf.len() as u64 > self.max_bytes {
            // Rotation failure must never stop logging; keep appending instead.
            let _ = self.rotate();
        }
        let n = self.file.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Normalise a path for prefix comparison: lower-case, `\` separators, no trailing separator.
fn norm(p: &str) -> String {
    let mut s = p.trim().replace('/', "\\").to_lowercase();
    while s.len() > 1 && s.ends_with('\\') {
        s.pop();
    }
    s
}

/// True if `path` is `prefix` itself or lies inside it, respecting component
/// boundaries: `C:\Games` covers `C:\Games\x.exe` but not `C:\GamesFolder\x.exe`.
pub fn path_within(path: &str, prefix: &str) -> bool {
    let (p, pre) = (norm(path), norm(prefix));
    if pre.is_empty() {
        return false;
    }
    p == pre || (p.starts_with(&pre) && p.as_bytes().get(pre.len()) == Some(&b'\\'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contain_recovers_from_panic() {
        assert_eq!(contain("ok", || 5), Some(5));
        assert_eq!(contain::<()>("boom", || panic!("bad input")), None);
    }

    #[test]
    fn path_within_respects_component_boundaries() {
        assert!(path_within(r"C:\Games\x.exe", r"C:\Games"));
        assert!(path_within(r"c:\games\x.exe", r"C:\Games\"));
        assert!(path_within(r"C:\Games", r"C:\Games"));
        assert!(!path_within(r"C:\GamesFolder\x.exe", r"C:\Games"));
        assert!(path_within("/home/u/build/a.o", "/home/u/build"));
        assert!(!path_within(r"C:\x", ""));
    }

    #[test]
    fn rotating_file_rotates_and_caps() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("svc.log");
        let mut f = RotatingFile::open(&p, 100, 2).unwrap();
        for _ in 0..10 {
            f.write_all(&[b'x'; 40]).unwrap();
        }
        assert!(std::fs::metadata(&p).unwrap().len() <= 100);
        assert!(dir.path().join("svc.log.1").exists());
        assert!(dir.path().join("svc.log.2").exists());
        assert!(!dir.path().join("svc.log.3").exists());
    }
}
