//! SQLite-backed storage: signatures, scan cache, event journal, quarantine index.
//!
//! One connection guarded by a mutex. SQLite in WAL mode handles our write rate
//! (bursty scan-cache batches, sparse events) comfortably, and a single connection
//! keeps the memory footprint predictable (page cache capped below).

pub mod signatures;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use sentinel_protocol::{EventKind, QuarantineItem, SecurityEvent, Severity};
use std::path::Path;
use std::sync::Mutex;

pub struct Database {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct SignatureHit {
    pub name: String,
    pub severity: Severity,
    /// Where the hash came from, e.g. `core@2026.11.06`, `official@…`, `community:malwarebazaar`.
    pub source: String,
}

impl SignatureHit {
    /// Hashes from unsigned third-party feeds get extra safety checks before remediation.
    pub fn is_community(&self) -> bool {
        self.source.starts_with(COMMUNITY_PREFIX)
    }
}

pub const COMMUNITY_PREFIX: &str = "community:";

/// Cache key for "have we already hashed this exact file version?"
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub path: String,
    pub size: u64,
    pub mtime: i64,
    pub sha256: String,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS signatures (
    sha256   TEXT PRIMARY KEY,
    name     TEXT NOT NULL,
    severity TEXT NOT NULL,
    source   TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS allowlist (
    sha256   TEXT PRIMARY KEY,
    reason   TEXT,
    added_at INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS scan_cache (
    path   TEXT PRIMARY KEY,
    size   INTEGER NOT NULL,
    mtime  INTEGER NOT NULL,
    sha256 TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    kind      TEXT NOT NULL,
    severity  TEXT NOT NULL,
    title     TEXT NOT NULL,
    detail    TEXT,
    path      TEXT,
    pid       INTEGER
);
CREATE TABLE IF NOT EXISTS quarantine (
    id             TEXT PRIMARY KEY,
    original_path  TEXT NOT NULL,
    sha256         TEXT NOT NULL,
    threat_name    TEXT NOT NULL,
    size           INTEGER NOT NULL,
    quarantined_at INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS persistence_baseline (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS counters (
    name  TEXT PRIMARY KEY,
    value INTEGER NOT NULL
) WITHOUT ROWID;
"#;

/// Ordered schema migrations; `PRAGMA user_version` records how many have run.
/// Never edit a shipped migration, only append new ones.
const MIGRATIONS: &[&str] = &[
    // 1: initial schema
    SCHEMA,
    // 2: signature age (for pruning stale community hashes) + key/value metadata
    "ALTER TABLE signatures ADD COLUMN added_at INTEGER NOT NULL DEFAULT 0;
     CREATE INDEX IF NOT EXISTS signatures_source ON signatures(source);
     CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;",
];

/// Keep the journal bounded so the DB does not grow forever.
const MAX_EVENTS: i64 = 20_000;

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn enum_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn enum_from<T: for<'de> serde::Deserialize<'de>>(s: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(s.to_owned())).ok()
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        Self::init(conn)
    }

    /// Open the database; if it is unreadable or fails an integrity check, move
    /// it aside (`*.corrupt-<unix time>`) and start a fresh one. Returns whether
    /// a rebuild happened so the caller can tell the user.
    pub fn open_or_recover(path: &Path) -> Result<(Self, bool)> {
        let healthy = Self::open(path).and_then(|db| {
            let ok: String = db.conn().query_row("PRAGMA quick_check", [], |r| r.get(0))?;
            anyhow::ensure!(ok == "ok", "integrity check failed: {ok}");
            Ok(db)
        });
        match healthy {
            Ok(db) => Ok((db, false)),
            Err(e) => {
                tracing::error!(error = %format!("{e:#}"), "database unusable, rebuilding");
                let stamp = now_unix();
                for suffix in ["", "-wal", "-shm"] {
                    let mut from = path.as_os_str().to_owned();
                    from.push(suffix);
                    let mut to = from.clone();
                    to.push(format!(".corrupt-{stamp}"));
                    let _ = std::fs::rename(&from, &to);
                }
                Ok((Self::open(path)?, true))
            }
        }
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA cache_size=-8000;   -- ~8 MB page cache cap
             PRAGMA temp_store=MEMORY;",
        )?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let mut version: usize = conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))? as usize;
        // Databases created before versioning existed already have the v1 tables.
        if version == 0 {
            let has_tables: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE name = 'signatures'",
                [],
                |r| r.get(0),
            )?;
            if has_tables > 0 {
                conn.execute_batch(SCHEMA)?; // idempotent; fills in anything missing
                version = 1;
                conn.pragma_update(None, "user_version", 1)?;
            }
        }
        if version > MIGRATIONS.len() {
            anyhow::bail!(
                "database schema v{version} is newer than this build (v{})",
                MIGRATIONS.len()
            );
        }
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(version) {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(sql)
                .with_context(|| format!("applying migration {}", i + 1))?;
            tx.pragma_update(None, "user_version", (i + 1) as i64)?;
            tx.commit()?;
        }
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A panic while holding the lock must not take the whole service down.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ----- signatures ------------------------------------------------------

    pub fn lookup_hash(&self, sha256: &str) -> Result<Option<SignatureHit>> {
        let c = self.conn();
        let allowed: Option<i64> = c
            .query_row("SELECT 1 FROM allowlist WHERE sha256 = ?1", [sha256], |r| r.get(0))
            .optional()?;
        if allowed.is_some() {
            return Ok(None);
        }
        let hit = c
            .query_row(
                "SELECT name, severity, source FROM signatures WHERE sha256 = ?1",
                [sha256],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)),
            )
            .optional()?;
        Ok(hit.map(|(name, sev, source)| SignatureHit {
            name,
            severity: enum_from(&sev).unwrap_or(Severity::High),
            source,
        }))
    }

    pub fn upsert_signatures<'a>(
        &self,
        source: &str,
        rows: impl IntoIterator<Item = (&'a str, &'a str, Severity)>,
    ) -> Result<usize> {
        let mut c = self.conn();
        let tx = c.transaction()?;
        let mut n = 0;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO signatures (sha256, name, severity, source, added_at) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(sha256) DO UPDATE SET
                   name = excluded.name, severity = excluded.severity, added_at = excluded.added_at,
                   -- a vetted source always wins over a community feed for the same hash
                   source = CASE WHEN signatures.source NOT LIKE 'community:%' AND excluded.source LIKE 'community:%'
                                 THEN signatures.source ELSE excluded.source END",
            )?;
            let now = now_unix();
            for (hash, name, sev) in rows {
                stmt.execute(params![hash.to_ascii_lowercase(), name, enum_str(&sev), source, now])?;
                n += 1;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    pub fn signature_count(&self) -> u64 {
        self.conn()
            .query_row("SELECT COUNT(*) FROM signatures", [], |r| r.get::<_, i64>(0))
            .map(|n| n as u64)
            .unwrap_or(0)
    }

    /// Drop community hashes not seen in any feed for `max_age_secs`.
    pub fn prune_community(&self, max_age_secs: i64) -> Result<usize> {
        Ok(self.conn().execute(
            "DELETE FROM signatures WHERE source LIKE 'community:%' AND added_at < ?1",
            [now_unix() - max_age_secs],
        )?)
    }

    pub fn allow_hash(&self, sha256: &str, reason: &str) -> Result<()> {
        self.conn().execute(
            "INSERT OR REPLACE INTO allowlist (sha256, reason, added_at) VALUES (?1, ?2, ?3)",
            params![sha256, reason, now_unix()],
        )?;
        Ok(())
    }

    // ----- scan cache ------------------------------------------------------

    pub fn cached_hash(&self, path: &str, size: u64, mtime: i64) -> Option<String> {
        self.conn()
            .query_row(
                "SELECT sha256 FROM scan_cache WHERE path = ?1 AND size = ?2 AND mtime = ?3",
                params![path, size as i64, mtime],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    pub fn store_cache_batch(&self, entries: &[CacheEntry]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut c = self.conn();
        let tx = c.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT OR REPLACE INTO scan_cache (path, size, mtime, sha256) VALUES (?1, ?2, ?3, ?4)",
            )?;
            for e in entries {
                stmt.execute(params![e.path, e.size as i64, e.mtime, e.sha256])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    // ----- events ------------------------------------------------------------

    pub fn insert_event(&self, mut ev: SecurityEvent) -> Result<SecurityEvent> {
        let c = self.conn();
        c.execute(
            "INSERT INTO events (timestamp, kind, severity, title, detail, path, pid)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                ev.timestamp,
                enum_str(&ev.kind),
                enum_str(&ev.severity),
                ev.title,
                ev.detail,
                ev.path,
                ev.pid
            ],
        )?;
        ev.id = c.last_insert_rowid();
        if ev.id % 500 == 0 {
            c.execute("DELETE FROM events WHERE id <= ?1", [ev.id - MAX_EVENTS])?;
        }
        Ok(ev)
    }

    pub fn recent_events(&self, limit: u32, before_id: Option<i64>) -> Result<Vec<SecurityEvent>> {
        let c = self.conn();
        let mut stmt = c.prepare_cached(
            "SELECT id, timestamp, kind, severity, title, detail, path, pid FROM events
             WHERE id < ?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![before_id.unwrap_or(i64::MAX), limit.min(1000)], |r| {
            Ok(SecurityEvent {
                id: r.get(0)?,
                timestamp: r.get(1)?,
                kind: enum_from(&r.get::<_, String>(2)?).unwrap_or(EventKind::ServiceInfo),
                severity: enum_from(&r.get::<_, String>(3)?).unwrap_or(Severity::Info),
                title: r.get(4)?,
                detail: r.get(5)?,
                path: r.get(6)?,
                pid: r.get(7)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    // ----- quarantine index -----------------------------------------------

    pub fn insert_quarantine(&self, q: &QuarantineItem) -> Result<()> {
        self.conn().execute(
            "INSERT INTO quarantine (id, original_path, sha256, threat_name, size, quarantined_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                q.id,
                q.original_path,
                q.sha256,
                q.threat_name,
                q.size as i64,
                q.quarantined_at
            ],
        )?;
        Ok(())
    }

    pub fn get_quarantine(&self, id: &str) -> Result<Option<QuarantineItem>> {
        Ok(self
            .conn()
            .query_row(
                "SELECT id, original_path, sha256, threat_name, size, quarantined_at FROM quarantine WHERE id = ?1",
                [id],
                row_to_quarantine,
            )
            .optional()?)
    }

    pub fn list_quarantine(&self) -> Result<Vec<QuarantineItem>> {
        let c = self.conn();
        let mut stmt = c.prepare_cached(
            "SELECT id, original_path, sha256, threat_name, size, quarantined_at FROM quarantine
             ORDER BY quarantined_at DESC",
        )?;
        let rows = stmt.query_map([], row_to_quarantine)?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn remove_quarantine(&self, id: &str) -> Result<bool> {
        Ok(self.conn().execute("DELETE FROM quarantine WHERE id = ?1", [id])? > 0)
    }

    pub fn quarantine_count(&self) -> u64 {
        self.conn()
            .query_row("SELECT COUNT(*) FROM quarantine", [], |r| r.get::<_, i64>(0))
            .map(|n| n as u64)
            .unwrap_or(0)
    }

    // ----- persistence baseline ------------------------------------------

    pub fn persistence_baseline(&self) -> Result<std::collections::HashMap<String, String>> {
        let c = self.conn();
        let mut stmt = c.prepare_cached("SELECT key, value FROM persistence_baseline")?;
        let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn replace_persistence_baseline(&self, entries: &std::collections::HashMap<String, String>) -> Result<()> {
        let mut c = self.conn();
        let tx = c.transaction()?;
        tx.execute("DELETE FROM persistence_baseline", [])?;
        {
            let mut stmt = tx.prepare_cached("INSERT INTO persistence_baseline (key, value) VALUES (?1, ?2)")?;
            for (k, v) in entries {
                stmt.execute(params![k, v])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    // ----- counters ------------------------------------------------------------

    pub fn incr_counter(&self, name: &str) -> u64 {
        let c = self.conn();
        let _ = c.execute(
            "INSERT INTO counters (name, value) VALUES (?1, 1)
             ON CONFLICT(name) DO UPDATE SET value = value + 1",
            [name],
        );
        drop(c);
        self.counter(name)
    }

    pub fn set_counter(&self, name: &str, value: i64) {
        let _ = self.conn().execute(
            "INSERT INTO counters (name, value) VALUES (?1, ?2)
             ON CONFLICT(name) DO UPDATE SET value = excluded.value",
            params![name, value],
        );
    }

    pub fn meta(&self, key: &str) -> Option<String> {
        self.conn()
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
    }

    pub fn set_meta(&self, key: &str, value: Option<&str>) {
        let c = self.conn();
        let _ = match value {
            Some(v) => c.execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, v],
            ),
            None => c.execute("DELETE FROM meta WHERE key = ?1", [key]),
        };
    }

    pub fn counter(&self, name: &str) -> u64 {
        self.conn()
            .query_row("SELECT value FROM counters WHERE name = ?1", [name], |r| {
                r.get::<_, i64>(0)
            })
            .map(|n| n as u64)
            .unwrap_or(0)
    }
}

fn row_to_quarantine(r: &rusqlite::Row<'_>) -> rusqlite::Result<QuarantineItem> {
    Ok(QuarantineItem {
        id: r.get(0)?,
        original_path: r.get(1)?,
        sha256: r.get(2)?,
        threat_name: r.get(3)?,
        size: r.get::<_, i64>(4)? as u64,
        quarantined_at: r.get(5)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_and_allowlist() {
        let db = Database::open_in_memory().unwrap();
        let h = "a".repeat(64);
        db.upsert_signatures("test", [(h.as_str(), "Test.Threat", Severity::Critical)])
            .unwrap();
        let hit = db.lookup_hash(&h).unwrap().unwrap();
        assert_eq!(hit.name, "Test.Threat");
        assert_eq!(hit.severity, Severity::Critical);
        db.allow_hash(&h, "user restored").unwrap();
        assert!(db.lookup_hash(&h).unwrap().is_none());
    }

    #[test]
    fn vetted_source_is_not_downgraded_by_community_feed() {
        let db = Database::open_in_memory().unwrap();
        let h = "d".repeat(64);
        db.upsert_signatures("official@1", [(h.as_str(), "Trojan.X", Severity::High)])
            .unwrap();
        db.upsert_signatures("community:feed", [(h.as_str(), "Malware.Feed", Severity::High)])
            .unwrap();
        let hit = db.lookup_hash(&h).unwrap().unwrap();
        assert_eq!(hit.source, "official@1");
        assert!(!hit.is_community());
    }

    #[test]
    fn migrates_pre_versioning_database_and_recovers_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s.db");
        // A v1-era database with no user_version set.
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(SCHEMA).unwrap();
            c.execute("INSERT INTO signatures VALUES ('aa', 'n', 'high', 'core')", [])
                .unwrap();
        }
        let db = Database::open(&p).unwrap();
        assert_eq!(db.signature_count(), 1);
        db.set_meta("k", Some("v"));
        assert_eq!(db.meta("k").as_deref(), Some("v"));
        drop(db);

        std::fs::write(&p, b"this is not a sqlite database at all, just garbage bytes......").unwrap();
        let _ = std::fs::remove_file(dir.path().join("s.db-wal"));
        let (db, rebuilt) = Database::open_or_recover(&p).unwrap();
        assert!(rebuilt);
        assert_eq!(db.signature_count(), 0);
    }

    #[test]
    fn cache_requires_matching_size_and_mtime() {
        let db = Database::open_in_memory().unwrap();
        db.store_cache_batch(&[CacheEntry {
            path: "C:\\a.exe".into(),
            size: 10,
            mtime: 5,
            sha256: "x".into(),
        }])
        .unwrap();
        assert_eq!(db.cached_hash("C:\\a.exe", 10, 5).as_deref(), Some("x"));
        assert!(db.cached_hash("C:\\a.exe", 11, 5).is_none());
    }
}
