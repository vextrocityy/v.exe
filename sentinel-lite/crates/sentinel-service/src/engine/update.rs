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
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// `{key}` is replaced by the abuse.ch Auth-Key. abuse.ch refreshes this export
/// every 5 minutes; we fetch at most hourly (`update_interval_hours` >= 1).
pub const MALWAREBAZAAR_RECENT: &str = "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv";
/// Curated YARA rule package (YARA Forge "core": quality- and score-filtered,
/// performance-tested). Rules carry their own licenses (CC BY-SA 4.0, DRL 1.1, …).
pub const YARA_FORGE_CORE: &str =
    "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip";
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

/// TLS settings for every download. Certificates are checked by the operating
/// system (Windows CryptoAPI): unlike reading the root store directly, Windows
/// fetches missing root certificates on demand (the store on a normal PC is
/// only partly populated), checks revocation, and trusts roots installed by
/// security software or IT. Falls back to Mozilla's root list if the platform
/// verifier cannot start.
fn tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let builder = || {
                rustls::ClientConfig::builder_with_provider(provider.clone())
                    .with_safe_default_protocol_versions()
                    .expect("ring supports the default TLS versions")
            };
            let config = match rustls_platform_verifier::Verifier::new(provider.clone()) {
                Ok(verifier) => {
                    builder().dangerous().with_custom_certificate_verifier(Arc::new(verifier)).with_no_client_auth()
                }
                Err(e) => {
                    tracing::warn!(error = %e, "OS certificate verifier unavailable; using bundled Mozilla roots");
                    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
                    builder().with_root_certificates(roots).with_no_client_auth()
                }
            };
            Arc::new(config)
        })
        .clone()
}

fn agent(url: &str) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .tls_config(tls_config())
        .timeout_connect(Duration::from_secs(15))
        .timeout(Duration::from_secs(180))
        .user_agent(concat!("Vigil/", env!("CARGO_PKG_VERSION")))
        // Honour HTTPS_PROXY for corporate networks, but never proxy a local mirror.
        .try_proxy_from_env(!is_loopback(url))
        .build()
}

/// GitHub's release downloads (and other CDNs) answer 502/503/504 now and then
/// for a few seconds. Retry those and connection failures a few times with a
/// growing pause; anything else (404, 403, TLS errors) fails at once.
fn get_with_retry(url: &str, accept: Option<&str>) -> Result<ureq::Response> {
    let pauses: &[u64] = if cfg!(test) { &[0, 0] } else { &[2, 6, 15] };
    let mut attempt = 0;
    loop {
        let mut req = agent(url).get(url);
        if let Some(a) = accept {
            req = req.set("Accept", a);
        }
        match req.call() {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                let transient = match &e {
                    ureq::Error::Status(code, _) => matches!(code, 429 | 500 | 502 | 503 | 504),
                    ureq::Error::Transport(t) => matches!(
                        t.kind(),
                        ureq::ErrorKind::ConnectionFailed | ureq::ErrorKind::Io | ureq::ErrorKind::Dns
                    ),
                };
                match pauses.get(attempt) {
                    Some(secs) if transient => {
                        tracing::info!(url, error = %e, retry_in_secs = secs, "transient download error, retrying");
                        std::thread::sleep(std::time::Duration::from_secs(*secs));
                        attempt += 1;
                    }
                    _ => return Err(anyhow::Error::new(e).context(format!("GET {url}"))),
                }
            }
        }
    }
}

pub fn fetch(url: &str) -> Result<Vec<u8>> {
    match fetch_with(url, None) {
        Ok(b) => Ok(b),
        Err(e) => match github_api_asset(url) {
            // github.com/<o>/<r>/releases/.../download/<file> can be down (504) while the
            // same file is served fine through the API: try that before giving up.
            Some(api) => {
                tracing::info!(url, "release download failed; trying the GitHub API asset endpoint");
                fetch_release_asset_via_api(&api.0, &api.1).map_err(|api_err| e.context(format!("API fallback: {api_err:#}")))
            }
            None => Err(e),
        },
    }
}

/// For a GitHub release download URL, the API release lookup and the asset name:
/// `https://github.com/o/r/releases/download/<tag>/<name>` → (`…/repos/o/r/releases/tags/<tag>`, name);
/// `https://github.com/o/r/releases/latest/download/<name>` → (`…/repos/o/r/releases/latest`, name).
pub fn github_api_asset(url: &str) -> Option<(String, String)> {
    let rest = url.strip_prefix("https://github.com/")?;
    let parts: Vec<&str> = rest.split('/').collect();
    let ok = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    match parts.as_slice() {
        [o, r, "releases", "latest", "download", name] if ok(o) && ok(r) && ok(name) => {
            Some((format!("https://api.github.com/repos/{o}/{r}/releases/latest"), name.to_string()))
        }
        [o, r, "releases", "download", tag, name] if ok(o) && ok(r) && ok(tag) && ok(name) => {
            Some((format!("https://api.github.com/repos/{o}/{r}/releases/tags/{tag}"), name.to_string()))
        }
        _ => None,
    }
}

fn fetch_release_asset_via_api(release_api: &str, name: &str) -> Result<Vec<u8>> {
    #[derive(serde::Deserialize)]
    struct Asset {
        name: String,
        url: String,
    }
    #[derive(serde::Deserialize)]
    struct Rel {
        assets: Vec<Asset>,
    }
    let rel: Rel = serde_json::from_slice(&fetch_with(release_api, None)?).context("unexpected release JSON")?;
    let asset = rel
        .assets
        .into_iter()
        .find(|a| a.name == name)
        .with_context(|| format!("release has no asset {name}"))?;
    anyhow::ensure!(
        asset.url.starts_with("https://api.github.com/repos/"),
        "unexpected asset URL {}",
        asset.url
    );
    fetch_with(&asset.url, Some("application/octet-stream"))
}

fn fetch_with(url: &str, accept: Option<&str>) -> Result<Vec<u8>> {
    anyhow::ensure!(
        crate::settings::is_allowed_update_url(url),
        "refusing non-HTTPS update URL"
    );
    let resp = get_with_retry(url, accept)?;
    let mut buf = Vec::new();
    resp.into_reader().take(MAX_DOWNLOAD_BYTES + 1).read_to_end(&mut buf)?;
    anyhow::ensure!(
        buf.len() as u64 <= MAX_DOWNLOAD_BYTES,
        "download exceeds {MAX_DOWNLOAD_BYTES} bytes"
    );
    Ok(buf)
}

/// Download a rule package zip and return the contents of its `.yar` file.
/// Entry names are never used as paths (no extraction to disk), and the
/// uncompressed size is capped (zip-bomb protection).
pub fn fetch_yara_zip(url: &str) -> Result<Vec<u8>> {
    let zip_bytes = fetch(url)?;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).context("rule package is not a zip")?;
    for i in 0..archive.len() {
        let entry = archive.by_index(i)?;
        let name = entry.name().to_ascii_lowercase();
        if entry.is_file() && (name.ends_with(".yar") || name.ends_with(".yara")) {
            let mut out = Vec::new();
            entry.take(MAX_DOWNLOAD_BYTES + 1).read_to_end(&mut out)?;
            anyhow::ensure!(out.len() as u64 <= MAX_DOWNLOAD_BYTES, "rule file too large");
            return Ok(out);
        }
    }
    bail!("no .yar file in rule package")
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

    /// Serve the given raw HTTP responses, one per connection, on a loopback port.
    fn serve_raw(responses: Vec<&'static str>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for r in responses {
                let (mut sock, _) = listener.accept().unwrap();
                let mut buf = [0u8; 2048];
                let _ = std::io::Read::read(&mut sock, &mut buf);
                let _ = std::io::Write::write_all(&mut sock, r.as_bytes());
            }
        });
        format!("http://127.0.0.1:{}/file", addr.port())
    }

    #[test]
    fn release_downloads_map_to_the_api() {
        assert_eq!(
            github_api_asset("https://github.com/vextrocityy/v.exe/releases/download/sentinel-lite-build-18/Vigil_0.1.0_x64-setup.exe"),
            Some((
                "https://api.github.com/repos/vextrocityy/v.exe/releases/tags/sentinel-lite-build-18".into(),
                "Vigil_0.1.0_x64-setup.exe".into()
            ))
        );
        assert_eq!(
            github_api_asset("https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"),
            Some((
                "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest".into(),
                "yara-forge-rules-core.zip".into()
            ))
        );
        assert_eq!(github_api_asset("https://www.spamhaus.org/drop/drop_v4.json"), None);
        assert_eq!(github_api_asset("https://github.com/o/r/releases/download/t/../../x"), None);
    }

    #[test]
    fn transient_server_errors_are_retried_but_not_found_is_not() {
        let gw = "HTTP/1.1 504 Gateway Time-out\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let ok = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
        let url = serve_raw(vec![gw, gw, ok]);
        assert_eq!(fetch(&url).unwrap(), b"hello");

        let nf = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let url = serve_raw(vec![nf, ok]);
        let err = format!("{:#}", fetch(&url).unwrap_err());
        assert!(err.contains("404"), "{err}");
    }
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
    fn yara_zip_is_unpacked_in_memory() {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut z = zip::ZipWriter::new(&mut buf);
            let opts = zip::write::SimpleFileOptions::default();
            z.add_directory("packages/core/", opts).unwrap();
            z.start_file("../../evil/packages/core/rules.yar", opts).unwrap(); // hostile name is harmless
            z.write_all(b"rule a { condition: true }").unwrap();
            z.finish().unwrap();
        }
        let base = serve(vec![("/core.zip", buf.into_inner())], 1);
        let rules = fetch_yara_zip(&format!("{base}/core.zip")).unwrap();
        assert_eq!(rules, b"rule a { condition: true }");

        let base = serve(vec![("/core.zip", b"not a zip".to_vec())], 1);
        assert!(fetch_yara_zip(&format!("{base}/core.zip")).is_err());
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
