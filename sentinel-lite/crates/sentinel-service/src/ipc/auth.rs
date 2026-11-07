//! Per-start IPC token.
//!
//! The service generates 32 random bytes at startup and writes them (hex) to
//! `%ProgramData%\SentinelLite\ipc.token`. A client must present the token in
//! its first frame. Together with the pipe DACL (see `transport.rs`) this means
//! only local, interactive users who can read the token file can talk to the
//! engine. Remote clients are rejected at the pipe level.

use std::io;
use std::path::Path;

pub struct AuthToken(String);

impl AuthToken {
    pub fn generate() -> io::Result<Self> {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).map_err(|e| io::Error::other(e.to_string()))?;
        Ok(Self(crate::engine::hasher::to_hex(&b)))
    }

    #[cfg(all(test, unix))]
    pub fn from_string(s: &str) -> Self {
        Self(s.to_string())
    }

    pub fn write_to(&self, path: &Path) -> io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &self.0)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, path)
    }

    /// Constant-time comparison: no early exit that leaks how many bytes matched.
    pub fn verify(&self, candidate: &str) -> bool {
        let a = self.0.as_bytes();
        let b = candidate.trim().as_bytes();
        if a.len() != b.len() {
            return false;
        }
        a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_token() {
        let t = AuthToken::generate().unwrap();
        assert_eq!(t.0.len(), 64);
        assert!(t.verify(&t.0.clone()));
        assert!(!t.verify("nope"));
        assert!(!t.verify(&"0".repeat(64)));
    }
}
