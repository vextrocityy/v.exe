//! Signature updates.
//!
//! Two channels:
//!
//! * **Official** (`settings.update_url`): a JSON pack at `<url>` plus a detached
//!   Ed25519 signature (hex) at `<url>.sig`. The pack is rejected unless it
//!   verifies against a public key compiled into this build
//!   (`SENTINEL_UPDATE_PUBKEYS`, comma-separated hex) and its version is not
//!   older than the last applied one (rollback protection).
//! * **Community** (`settings.community_feeds`): abuse.ch MalwareBazaar's export
//!   of recently submitted samples (CSV) over HTTPS. Since October 2026 abuse.ch
//!   requires a free Auth-Key, placed in the URL path; the key is redacted from
//!   every error and log line. Unsigned, so detections from it pass extra
//!   safety checks before any remediation (see `Engine::may_remediate`).
//!
//! Hashes accumulate across updates; community hashes not seen for 180 days are pruned.

use crate::database::{signatures, Database, COMMUNITY_PREFIX};
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sentinel_protocol::{Settings, Severity};
use std::io::Read;
use std::time::Duration;

/// `{key}` is replaced by the abuse.ch Auth-Key. abuse.ch refreshes this export
/// every 5 minutes; we fetch at most hourly (`update_interval_hours` >= 1).
pub const MALWAREBAZAAR_RECENT: &str = "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv";
const MAX_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024;
const MAX_COMMUNITY_HASHES: usize = 500_000;
const COMMUNITY_MAX_AGE_SECS: i64 = 180 * 86_400;
const META_OFFICIAL_VERSION: &str = "official_pack_version";

#[derive(Debug, Default)]
pub struct Outcome {
    pub imported: usize,
    pub notes: Vec<String>,
    pub errors: Vec<String>,
}

/// Community channel configuration.
pub enum Community {
    Off,
    /// Enabled, but no Auth-Key configured yet.
    MissingKey,
    /// URL to fetch, plus the secret to redact from errors.
    Url {
        url: String,
        secret: Option<String>,
    },
}

/// Where each channel fetches from (overridable in tests).
pub struct Sources<'a> {
    pub official_url: Option<&'a str>,
    pub community: Community,
}

impl<'a> Sources<'a> {
    pub fn from_settings(s: &'a Settings) -> Self {
        let community = match (s.community_feeds, s.abusech_auth_key.as_deref()) {
            (false, _) => Community::Off,
            (true, None) => Community::MissingKey,
            (true, Some(key)) => Community::Url {
                url: MALWAREBAZAAR_RECENT.replace("{key}", key),
                secret: Some(key.to_string()),
            },
        };
        Self {
            official_url: s.update_url.as_deref(),
            community,
        }
    }
}

fn redact(msg: String, secret: Option<&str>) -> String {
    match secret {
        Some(sec) if !sec.is_empty() => msg.replace(sec, "<auth-key>"),
        _ => msg,
    }
}

/// Public keys baked in at build time. Empty in dev builds = official channel off.
pub fn trusted_keys() -> Vec<VerifyingKey> {
    option_env!("SENTINEL_UPDATE_PUBKEYS")
        .unwrap_or("")
        .split(',')
        .filter_map(|k| parse_key(k.trim()))
        .collect()
}

use crate::util::from_hex;

pub fn parse_key(hex: &str) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = from_hex(hex)?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// Generate a signing keypair: (secret hex, public hex). Keep the secret offline.
pub fn keygen() -> Result<(String, String)> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("rng: {e}"))?;
    let sk = SigningKey::from_bytes(&seed);
    Ok((
        super::hasher::to_hex(&seed),
        super::hasher::to_hex(sk.verifying_key().as_bytes()),
    ))
}

pub fn sign(secret_hex: &str, payload: &[u8]) -> Result<String> {
    let seed: [u8; 32] = from_hex(secret_hex)
        .and_then(|b| b.try_into().ok())
        .context("secret key must be 64 hex chars")?;
    let sig = SigningKey::from_bytes(&seed).sign(payload);
    Ok(super::hasher::to_hex(&sig.to_bytes()))
}

pub fn verify(payload: &[u8], sig_hex: &str, keys: &[VerifyingKey]) -> Result<()> {
    let bytes: [u8; 64] = from_hex(sig_hex)
        .and_then(|b| b.try_into().ok())
        .context("malformed signature")?;
    let sig = Signature::from_bytes(&bytes);
    if keys.iter().any(|k| k.verify(payload, &sig).is_ok()) {
        Ok(())
    } else {
        bail!("signature does not match any trusted key")
    }
}

fn is_loopback(url: &str) -> bool {
    let rest = url.split("://").nth(1).unwrap_or("");
    let host = rest.split(['/', ':']).next().unwrap_or("");
    host == "127.0.0.1" || host.eq_ignore_ascii_case("localhost")
}

fn agent(url: &str) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(15))
        .timeout(Duration::from_secs(180))
        .user_agent(concat!("Sentinel-Lite/", env!("CARGO_PKG_VERSION")))
        // Honour HTTPS_PROXY for corporate networks, but never proxy a local mirror.
        .try_proxy_from_env(!is_loopback(url))
        .build()
}

pub fn fetch(url: &str) -> Result<Vec<u8>> {
    anyhow::ensure!(
        crate::settings::is_allowed_update_url(url),
        "refusing non-HTTPS update URL"
    );
    let resp = agent(url).get(url).call().with_context(|| format!("GET {url}"))?;
    let mut buf = Vec::new();
    resp.into_reader().take(MAX_DOWNLOAD_BYTES + 1).read_to_end(&mut buf)?;
    anyhow::ensure!(
        buf.len() as u64 <= MAX_DOWNLOAD_BYTES,
        "download exceeds {MAX_DOWNLOAD_BYTES} bytes"
    );
    Ok(buf)
}

/// Extract SHA-256 values from a plain list or a CSV export (first SHA-256
/// field per row; `#` comment lines and headers ignored).
pub fn parse_hash_list(text: &str) -> Vec<String> {
    text.lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter_map(|l| {
            l.split(',')
                .map(|f| f.trim().trim_matches('"').trim().to_ascii_lowercase())
                .find(|f| signatures::is_sha256(f))
        })
        .take(MAX_COMMUNITY_HASHES)
        .collect()
}

/// Compare dotted numeric versions ("2026.11.07.2"); non-numeric parts compare as text.
fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |s: &str| {
        s.split('.')
            .map(|p| (p.parse::<u64>().ok(), p.to_string()))
            .collect::<Vec<_>>()
    };
    parts(a).cmp(&parts(b))
}

fn apply_official(db: &Database, url: &str, keys: &[VerifyingKey]) -> Result<Option<usize>> {
    if keys.is_empty() {
        bail!("this build has no trusted update key; official channel disabled");
    }
    let pack = fetch(url)?;
    let sig = String::from_utf8(fetch(&format!("{url}.sig"))?).context("signature is not text")?;
    verify(&pack, &sig, keys)?;
    let parsed = signatures::parse_pack(&pack)?;
    if let Some(current) = db.meta(META_OFFICIAL_VERSION) {
        match version_cmp(&parsed.version, &current) {
            std::cmp::Ordering::Less => bail!(
                "pack {} is older than installed {current} (rollback refused)",
                parsed.version
            ),
            std::cmp::Ordering::Equal => return Ok(None),
            std::cmp::Ordering::Greater => {}
        }
    }
    let n = signatures::import_pack_bytes(db, &pack, Some(&format!("official@{}", parsed.version)))?;
    db.set_meta(META_OFFICIAL_VERSION, Some(&parsed.version));
    Ok(Some(n))
}

fn apply_community(db: &Database, url: &str) -> Result<usize> {
    let body = fetch(url)?;
    let hashes = parse_hash_list(&String::from_utf8_lossy(&body));
    anyhow::ensure!(!hashes.is_empty(), "feed returned no hashes");
    let source = format!("{COMMUNITY_PREFIX}malwarebazaar");
    let n = db.upsert_signatures(
        &source,
        hashes
            .iter()
            .map(|h| (h.as_str(), "Malware.MalwareBazaar", Severity::High)),
    )?;
    let pruned = db.prune_community(COMMUNITY_MAX_AGE_SECS)?;
    if pruned > 0 {
        tracing::info!(pruned, "pruned stale community hashes");
    }
    Ok(n)
}

/// Run every enabled channel. A failure in one does not stop the other.
pub fn run(db: &Database, sources: &Sources<'_>, keys: &[VerifyingKey]) -> Outcome {
    let mut out = Outcome::default();
    if let Some(url) = sources.official_url {
        match apply_official(db, url, keys) {
            Ok(Some(n)) => {
                out.imported += n;
                out.notes.push(format!("official pack: {n} signatures"));
            }
            Ok(None) => out.notes.push("official pack already current".into()),
            Err(e) => out.errors.push(format!("official: {e:#}")),
        }
    }
    match &sources.community {
        Community::Off => {}
        Community::MissingKey => out.errors.push(
            "MalwareBazaar: add your free abuse.ch Auth-Key in Settings > Updates to enable the community feed".into(),
        ),
        Community::Url { url, secret } => match apply_community(db, url) {
            Ok(n) => {
                out.imported += n;
                out.notes.push(format!("MalwareBazaar: {n} hashes"));
            }
            Err(e) => out
                .errors
                .push(redact(format!("MalwareBazaar: {e:#}"), secret.as_deref())),
        },
    }
    if sources.official_url.is_none() && matches!(sources.community, Community::Off) {
        out.notes.push("no update sources enabled".into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// Minimal HTTP server: serves `routes` (path -> body) for `n` requests.
    fn serve(routes: Vec<(&'static str, Vec<u8>)>, n: usize) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(n) {
                let mut s = stream.unwrap();
                let mut req = [0u8; 2048];
                let len = s.read(&mut req).unwrap();
                let line = String::from_utf8_lossy(&req[..len]);
                let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
                match routes.iter().find(|(p, _)| *p == path) {
                    Some((_, body)) => {
                        write!(
                            s,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .unwrap();
                        s.write_all(body).unwrap();
                    }
                    None => write!(
                        s,
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .unwrap(),
                }
            }
        });
        format!("http://127.0.0.1:{}", addr.port())
    }

    fn pack(version: &str, hash: &str) -> Vec<u8> {
        format!(r#"{{"name":"official","version":"{version}","signatures":[{{"sha256":"{hash}","name":"Trojan.Test","severity":"critical"}}]}}"#).into_bytes()
    }

    #[test]
    fn signed_pack_is_applied_and_rollback_refused() {
        let (secret, public) = keygen().unwrap();
        let keys = vec![parse_key(&public).unwrap()];
        let db = Database::open_in_memory().unwrap();
        let h = "e".repeat(64);

        let v2 = pack("2026.11.07.2", &h);
        let base = serve(
            vec![
                ("/p.json", v2.clone()),
                ("/p.json.sig", sign(&secret, &v2).unwrap().into_bytes()),
            ],
            2,
        );
        let out = run(
            &db,
            &Sources {
                official_url: Some(&format!("{base}/p.json")),
                community: Community::Off,
            },
            &keys,
        );
        assert!(out.errors.is_empty(), "{:?}", out.errors);
        let hit = db.lookup_hash(&h).unwrap().unwrap();
        assert_eq!(hit.source, "official@2026.11.07.2");
        assert_eq!(hit.severity, Severity::Critical);

        let v1 = pack("2026.11.07.1", &"f".repeat(64));
        let base = serve(
            vec![
                ("/p.json", v1.clone()),
                ("/p.json.sig", sign(&secret, &v1).unwrap().into_bytes()),
            ],
            2,
        );
        let out = run(
            &db,
            &Sources {
                official_url: Some(&format!("{base}/p.json")),
                community: Community::Off,
            },
            &keys,
        );
        assert!(out.errors[0].contains("rollback"), "{:?}", out.errors);
        assert!(db.lookup_hash(&"f".repeat(64)).unwrap().is_none());
    }

    #[test]
    fn tampered_or_unsigned_pack_is_rejected() {
        let (secret, public) = keygen().unwrap();
        let (_, other_public) = keygen().unwrap();
        let db = Database::open_in_memory().unwrap();
        let body = pack("1", &"a".repeat(64));
        let mut tampered = body.clone();
        tampered[10] ^= 1;

        let base = serve(
            vec![
                ("/p.json", tampered),
                ("/p.json.sig", sign(&secret, &body).unwrap().into_bytes()),
            ],
            2,
        );
        let out = run(
            &db,
            &Sources {
                official_url: Some(&format!("{base}/p.json")),
                community: Community::Off,
            },
            &[parse_key(&public).unwrap()],
        );
        assert_eq!(out.errors.len(), 1);

        let base = serve(
            vec![
                ("/p.json", body.clone()),
                ("/p.json.sig", sign(&secret, &body).unwrap().into_bytes()),
            ],
            2,
        );
        let out = run(
            &db,
            &Sources {
                official_url: Some(&format!("{base}/p.json")),
                community: Community::Off,
            },
            &[parse_key(&other_public).unwrap()],
        );
        assert!(out.errors[0].contains("trusted key"), "{:?}", out.errors);

        let out = run(
            &db,
            &Sources {
                official_url: Some("http://127.0.0.1:9/p.json"),
                community: Community::Off,
            },
            &[],
        );
        assert!(out.errors[0].contains("no trusted update key"));
        assert_eq!(db.signature_count(), 0);
    }

    #[test]
    fn community_feed_parses_abusech_csv_export() {
        let db = Database::open_in_memory().unwrap();
        // Shape of the abuse.ch v2 CSV export.
        let feed = format!(
            "################\n# MalwareBazaar recent additions\n################\n\
             # \"first_seen_utc\",\"sha256_hash\",\"md5_hash\",\"sha1_hash\"\n\
             \"2026-11-07 00:01:02\", \"{}\", \"{}\", \"aa\"\n\
             \"2026-11-07 00:01:03\", \"{}\", \"{}\", \"bb\"\nnot,a,hash\n",
            "1".repeat(64),
            "c".repeat(32),
            "2".repeat(64),
            "d".repeat(32)
        );
        let base = serve(vec![("/v2/files/exports/KEY123/recent.csv", feed.into_bytes())], 1);
        let community = Community::Url {
            url: format!("{base}/v2/files/exports/KEY123/recent.csv"),
            secret: Some("KEY123".into()),
        };
        let out = run(
            &db,
            &Sources {
                official_url: None,
                community,
            },
            &[],
        );
        assert_eq!(out.imported, 2, "{out:?}");
        assert!(db.lookup_hash(&"1".repeat(64)).unwrap().unwrap().is_community());
        assert!(db.lookup_hash(&"c".repeat(64)).unwrap().is_none());
    }

    #[test]
    fn failing_channel_does_not_block_the_other() {
        let db = Database::open_in_memory().unwrap();
        let base = serve(vec![("/recent/", "3".repeat(64).into_bytes())], 1);
        let community = Community::Url {
            url: format!("{base}/recent/"),
            secret: None,
        };
        let out = run(
            &db,
            &Sources {
                official_url: Some("https://127.0.0.1:1/never"),
                community,
            },
            &[],
        );
        assert_eq!(out.errors.len(), 1);
        assert_eq!(out.imported, 1);
    }

    #[test]
    fn missing_key_is_reported_and_key_never_leaks_into_errors() {
        let db = Database::open_in_memory().unwrap();
        let s = Settings {
            community_feeds: true,
            abusech_auth_key: None,
            ..Settings::default()
        };
        let out = run(&db, &Sources::from_settings(&s), &[]);
        assert!(out.errors[0].contains("Auth-Key"), "{:?}", out.errors);

        // Unreachable host: the error quotes the URL, which contains the key.
        let community = Community::Url {
            url: "http://127.0.0.1:1/v2/files/exports/SECRETKEY9/recent.csv".into(),
            secret: Some("SECRETKEY9".into()),
        };
        let out = run(
            &db,
            &Sources {
                official_url: None,
                community,
            },
            &[],
        );
        assert_eq!(out.errors.len(), 1);
        assert!(!out.errors[0].contains("SECRETKEY9"), "{}", out.errors[0]);
        assert!(out.errors[0].contains("<auth-key>"));
    }

    #[test]
    fn version_ordering_is_numeric() {
        use std::cmp::Ordering::*;
        assert_eq!(version_cmp("2026.11.10", "2026.11.9"), Greater);
        assert_eq!(version_cmp("2026.11.07.1", "2026.11.07"), Greater);
        assert_eq!(version_cmp("1.0", "1.0"), Equal);
    }

    #[test]
    fn refuses_plain_http_to_remote_hosts() {
        assert!(fetch("http://example.com/pack.json").is_err());
    }
}
