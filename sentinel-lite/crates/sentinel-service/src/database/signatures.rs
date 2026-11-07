//! Loading the modular signature database from JSON packs.
//!
//! Every `*.json` file in `<data_dir>/signatures/` (plus the packs bundled next
//! to the executable) is a pack:
//!
//! ```json
//! { "name": "core", "version": "2026.11.06",
//!   "signatures": [ { "sha256": "…", "name": "Trojan.Example", "severity": "high" } ] }
//! ```
//!
//! Packs are imported into SQLite on startup and when they change, so lookups
//! stay O(log n) on disk instead of holding the whole set in RAM.

use super::Database;
use anyhow::{Context, Result};
use sentinel_protocol::Severity;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct SignaturePack {
    pub name: String,
    #[serde(default)]
    pub version: String,
    pub signatures: Vec<SignatureRecord>,
}

#[derive(Debug, Deserialize)]
pub struct SignatureRecord {
    pub sha256: String,
    pub name: String,
    #[serde(default = "default_severity")]
    pub severity: Severity,
}

fn default_severity() -> Severity {
    Severity::High
}

pub fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn import_pack(db: &Database, path: &Path) -> Result<usize> {
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    import_pack_bytes(db, &raw, None).with_context(|| format!("importing {}", path.display()))
}

pub fn parse_pack(raw: &[u8]) -> Result<SignaturePack> {
    let pack: SignaturePack = serde_json::from_slice(raw).context("parsing signature pack")?;
    anyhow::ensure!(!pack.name.is_empty(), "pack has no name");
    // Packs may never claim the community namespace (it disables safety checks' trust).
    anyhow::ensure!(!pack.name.starts_with(super::COMMUNITY_PREFIX), "reserved pack name");
    Ok(pack)
}

/// Import a pack; `source_override` replaces the `name@version` provenance label.
pub fn import_pack_bytes(db: &Database, raw: &[u8], source_override: Option<&str>) -> Result<usize> {
    let pack = parse_pack(raw)?;
    let valid = pack.signatures.iter().filter(|s| is_sha256(&s.sha256));
    let source = source_override
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{}@{}", pack.name, pack.version));
    db.upsert_signatures(&source, valid.map(|s| (s.sha256.as_str(), s.name.as_str(), s.severity)))
}

/// Import every pack found in `dirs`. Bad packs are logged and skipped.
pub fn import_all(db: &Database, dirs: &[&Path]) -> usize {
    let mut total = 0;
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            match import_pack(db, &p) {
                Ok(n) => {
                    tracing::info!(pack = %p.display(), count = n, "imported signature pack");
                    total += n;
                }
                Err(e) => tracing::warn!(pack = %p.display(), error = %e, "skipping signature pack"),
            }
        }
    }
    total
}
