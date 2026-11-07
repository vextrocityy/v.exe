//! Streaming SHA-256 with graceful classification of I/O failures.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Why a file was not scanned. None of these are fatal to the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Locked by another process (sharing / lock violation).
    Locked,
    PermissionDenied,
    /// Deleted between enumeration and open.
    Gone,
    TooLarge,
    Other,
}

pub fn classify(e: &io::Error) -> SkipReason {
    // ERROR_SHARING_VIOLATION (32) / ERROR_LOCK_VIOLATION (33) on Windows.
    if matches!(e.raw_os_error(), Some(32) | Some(33)) {
        return SkipReason::Locked;
    }
    match e.kind() {
        io::ErrorKind::PermissionDenied => SkipReason::PermissionDenied,
        io::ErrorKind::NotFound => SkipReason::Gone,
        _ => SkipReason::Other,
    }
}

/// Hash a file, refusing anything larger than `max_bytes`.
/// Uses a 64 KiB stack buffer: constant memory regardless of file size.
pub fn sha256_file(path: &Path, max_bytes: u64) -> Result<(String, u64), SkipReason> {
    let mut f = File::open(path).map_err(|e| classify(&e))?;
    let len = f.metadata().map(|m| m.len()).map_err(|e| classify(&e))?;
    if len > max_bytes {
        return Err(SkipReason::TooLarge);
    }
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(classify(&e)),
        };
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((to_hex(&hasher.finalize()), total))
}

pub fn sha256_bytes(data: &[u8]) -> String {
    to_hex(&Sha256::digest(data))
}

pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_known_content() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.txt");
        std::fs::write(&p, b"abc").unwrap();
        let (h, n) = sha256_file(&p, 1024).unwrap();
        assert_eq!(n, 3);
        assert_eq!(h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    #[test]
    fn missing_and_oversized_are_skips_not_errors() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(sha256_file(&dir.path().join("nope"), 10), Err(SkipReason::Gone));
        let p = dir.path().join("big");
        std::fs::write(&p, vec![0u8; 100]).unwrap();
        assert_eq!(sha256_file(&p, 10), Err(SkipReason::TooLarge));
    }
}
