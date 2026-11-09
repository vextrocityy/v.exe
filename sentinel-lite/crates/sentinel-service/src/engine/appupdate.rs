//! Self-update: the service installs new Vigil releases silently.
//!
//! Flow: look up the latest GitHub release of this project; if its build
//! number is higher than ours, download the NSIS installer and the release's
//! `SHA256SUMS.txt`, verify the hash, record a marker, and run the installer
//! with `/S`. The installer stops this service, replaces the files and starts
//! the new service, which reads the marker, reports the result and puts the
//! dashboard back in the user's tray if it was running.
//!
//! Trust: HTTPS to github.com, only this repository's releases, and a SHA-256
//! check against the release's checksum file; the same trust as downloading
//! from the Releases page by hand. Dev builds (build number 0) never update.

use super::Engine;
use crate::database::now_unix;
use anyhow::{bail, Context, Result};
use sentinel_protocol::{EventKind, Severity};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const REPO: &str = match option_env!("SENTINEL_UPDATE_REPO") {
    Some(r) => r,
    None => "vextrocityy/v.exe",
};
const TAG_PREFIX: &str = "sentinel-lite-build-";

/// CI run number baked in at build time (`SENTINEL_BUILD`); 0 for local builds.
pub fn build() -> u64 {
    option_env!("SENTINEL_BUILD")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

pub fn default_api() -> String {
    format!("https://api.github.com/repos/{REPO}/releases/latest")
}

fn is_loopback(url: &str) -> bool {
    let rest = url.split("://").nth(1).unwrap_or("");
    let host = rest.split(['/', ':']).next().unwrap_or("");
    url.starts_with("http://") && (host == "127.0.0.1" || host.eq_ignore_ascii_case("localhost"))
}

/// Release lookups may only go to GitHub's API (or a loopback test server).
pub fn is_allowed_api_url(url: &str) -> bool {
    (url.starts_with("https://api.github.com/repos/") && url.ends_with("/releases/latest")) || is_loopback(url)
}

/// Downloads may only come from GitHub release assets (or the same loopback server).
fn is_allowed_asset_url(url: &str, api: &str) -> bool {
    url.starts_with("https://github.com/") && url.contains("/releases/download/")
        || (is_loopback(api) && is_loopback(url))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Release {
    pub build: u64,
    pub tag: String,
    pub installer_url: String,
    pub installer_name: String,
    pub sums_url: String,
}

#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    assets: Vec<ApiAsset>,
}

#[derive(Deserialize)]
struct ApiAsset {
    name: String,
    browser_download_url: String,
}

pub fn parse_release(json: &[u8], api: &str) -> Result<Release> {
    let r: ApiRelease = serde_json::from_slice(json).context("unexpected release JSON")?;
    if r.draft || r.prerelease {
        bail!("latest release is a draft or pre-release");
    }
    let build: u64 = r
        .tag_name
        .strip_prefix(TAG_PREFIX)
        .and_then(|n| n.parse().ok())
        .with_context(|| format!("release tag {} is not a Vigil build", r.tag_name))?;
    let installer = r
        .assets
        .iter()
        .find(|a| a.name.to_ascii_lowercase().ends_with("-setup.exe"))
        .context("release has no installer")?;
    let sums = r
        .assets
        .iter()
        .find(|a| a.name == "SHA256SUMS.txt")
        .context("release has no SHA256SUMS.txt")?;
    for url in [&installer.browser_download_url, &sums.browser_download_url] {
        if !is_allowed_asset_url(url, api) {
            bail!("refusing download from {url}");
        }
    }
    Ok(Release {
        build,
        tag: r.tag_name.clone(),
        installer_url: installer.browser_download_url.clone(),
        installer_name: installer.name.clone(),
        sums_url: sums.browser_download_url.clone(),
    })
}

pub fn fetch_latest(api: &str) -> Result<Release> {
    anyhow::ensure!(is_allowed_api_url(api), "refusing release lookup at {api}");
    match super::update::fetch(api).and_then(|json| parse_release(&json, api)) {
        Ok(r) => Ok(r),
        // GitHub's API allows 60 anonymous requests per hour per IP address (403/429
        // when used up, common behind shared connections). The website needs no quota.
        Err(api_err) if api == default_api() => fetch_latest_web().map_err(|web_err| {
            anyhow::anyhow!("GitHub API: {api_err:#}; GitHub website: {web_err:#}")
        }),
        Err(e) => Err(e),
    }
}

/// Find the latest release without the API: `/releases/latest` redirects to
/// `/releases/tag/<tag>`, and the release's SHA256SUMS.txt names the installer.
fn fetch_latest_web() -> Result<Release> {
    let landed = super::update::final_url(&format!("https://github.com/{REPO}/releases/latest"))?;
    let tag = tag_from_release_url(&landed).with_context(|| format!("unexpected release page {landed}"))?;
    let base = format!("https://github.com/{REPO}/releases/download/{tag}");
    let sums_url = format!("{base}/SHA256SUMS.txt");
    let sums = String::from_utf8_lossy(&super::update::fetch(&sums_url)?).into_owned();
    let installer_name = installer_in_sums(&sums).context("SHA256SUMS.txt lists no installer")?;
    let build: u64 = tag
        .strip_prefix(TAG_PREFIX)
        .and_then(|n| n.parse().ok())
        .with_context(|| format!("release tag {tag} is not a Vigil build"))?;
    Ok(Release {
        build,
        installer_url: format!("{base}/{installer_name}"),
        installer_name,
        sums_url,
        tag,
    })
}

/// `https://github.com/o/r/releases/tag/<tag>` → `<tag>` (letters, digits, `-_.` only).
fn tag_from_release_url(url: &str) -> Option<String> {
    let tag = url.split_once("/releases/tag/")?.1.trim_end_matches('/');
    let ok = !tag.is_empty() && tag.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    ok.then(|| tag.to_string())
}

/// The `*-setup.exe` file named in a sha256sum-format list.
fn installer_in_sums(sums: &str) -> Option<String> {
    sums.lines().find_map(|l| {
        let name = l.split_whitespace().nth(1)?.trim_start_matches('*');
        let safe = name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
        (safe && name.to_ascii_lowercase().ends_with("-setup.exe")).then(|| name.to_string())
    })
}

/// `sha256  filename` lines (sha256sum format).
fn expected_hash(sums: &str, file: &str) -> Option<String> {
    sums.lines().find_map(|l| {
        let mut it = l.split_whitespace();
        let hash = it.next()?;
        let name = it.next()?.trim_start_matches('*');
        (name == file && crate::database::signatures::is_sha256(hash)).then(|| hash.to_ascii_lowercase())
    })
}

/// Download the installer into `dir` and verify it against the release checksums.
pub fn download_verified(rel: &Release, dir: &Path) -> Result<PathBuf> {
    let sums = String::from_utf8_lossy(&super::update::fetch(&rel.sums_url)?).into_owned();
    let want = expected_hash(&sums, &rel.installer_name).context("installer is not listed in SHA256SUMS.txt")?;
    let bytes = super::update::fetch(&rel.installer_url)?;
    let got = super::hasher::sha256_bytes(&bytes);
    if got != want {
        bail!("installer checksum mismatch (expected {want}, got {got})");
    }
    std::fs::create_dir_all(dir)?;
    let dest = dir.join(&rel.installer_name);
    let tmp = dest.with_extension("part");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, &dest)?;
    Ok(dest)
}

/// Written before running the installer; read by the new service on start.
#[derive(Debug, Serialize, Deserialize)]
struct Pending {
    from_build: u64,
    to_build: u64,
    relaunch_dashboard: bool,
    started_at: i64,
}

pub fn updates_dir(engine: &Engine) -> PathBuf {
    engine.paths.data.join("updates")
}

fn marker(engine: &Engine) -> PathBuf {
    updates_dir(engine).join("pending.json")
}

/// Look for a newer release and install it. Returns a status line.
pub fn check_and_install(engine: &Engine) -> Result<String> {
    let s = engine.settings();
    let api = s.app_update_api.clone().unwrap_or_else(default_api);
    let ours = build();
    if ours == 0 && !is_loopback(&api) {
        return Ok("Development build: automatic app updates are off".into());
    }
    let rel = fetch_latest(&api)?;
    if rel.build <= ours {
        return Ok(format!("Up to date (build {ours})"));
    }
    let installer = download_verified(&rel, &updates_dir(engine))?;
    let pending = Pending {
        from_build: ours,
        to_build: rel.build,
        relaunch_dashboard: crate::platform::dashboard_running(),
        started_at: now_unix(),
    };
    std::fs::write(marker(engine), serde_json::to_vec(&pending)?)?;
    engine.emit(
        EventKind::ServiceInfo,
        Severity::Info,
        format!("Installing Vigil build {}", rel.build),
        Some(format!(
            "Downloaded and verified {} (SHA-256). Protection restarts in a few seconds.",
            rel.installer_name
        )),
        Some(&installer),
        None,
    );
    if let Err(e) = crate::platform::run_installer_detached(&installer) {
        let _ = std::fs::remove_file(marker(engine));
        return Err(e);
    }
    Ok(format!("Installing build {}…", rel.build))
}

/// On service start: report the outcome of an update and restore the dashboard.
pub fn finish_pending(engine: &Engine) {
    let path = marker(engine);
    let Ok(raw) = std::fs::read(&path) else { return };
    let _ = std::fs::remove_file(&path);
    let Ok(p) = serde_json::from_slice::<Pending>(&raw) else {
        return;
    };
    let ours = build();
    if ours >= p.to_build {
        engine.emit(
            EventKind::ServiceInfo,
            Severity::Info,
            format!("Updated to build {ours}"),
            Some(format!("Vigil updated itself from build {}.", p.from_build)),
            None,
            None,
        );
    } else {
        engine.emit(
            EventKind::ServiceInfo,
            Severity::Medium,
            format!("Update to build {} did not complete", p.to_build),
            Some(format!(
                "Still running build {ours}. It will be retried at the next check."
            )),
            None,
            None,
        );
    }
    if p.relaunch_dashboard {
        if let Some(dir) = crate::platform::install_dir() {
            let ok = crate::platform::launch_in_user_session(&dir.join("vigil.exe"), "--minimized");
            tracing::info!(ok, "dashboard relaunch after update");
        }
    }
    // Old installers are not needed any more.
    if let Ok(entries) = std::fs::read_dir(updates_dir(engine)) {
        for e in entries.flatten() {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_latest_release_from_the_website() {
        assert_eq!(
            tag_from_release_url("https://github.com/vextrocityy/v.exe/releases/tag/sentinel-lite-build-23").as_deref(),
            Some("sentinel-lite-build-23")
        );
        assert_eq!(tag_from_release_url("https://github.com/vextrocityy/v.exe/releases"), None);
        assert_eq!(tag_from_release_url("https://github.com/o/r/releases/tag/../../x"), None);
        let sums = "0f00  SHA256SUMS.txt\nab12cd  Vigil_0.1.0_x64-setup.exe\n";
        assert_eq!(installer_in_sums(sums).as_deref(), Some("Vigil_0.1.0_x64-setup.exe"));
        assert_eq!(installer_in_sums("ab  ../../evil-setup.exe\n"), None);
    }

    fn release_json(tag: &str, base: &str) -> String {
        format!(
            r#"{{"tag_name":"{tag}","draft":false,"prerelease":false,"assets":[
              {{"name":"Vigil_0.1.0_x64-setup.exe","browser_download_url":"{base}/Vigil_0.1.0_x64-setup.exe"}},
              {{"name":"SHA256SUMS.txt","browser_download_url":"{base}/SHA256SUMS.txt"}}]}}"#
        )
    }

    #[test]
    fn parses_github_release_and_rejects_foreign_assets() {
        let api = default_api();
        let base = "https://github.com/vextrocityy/v.exe/releases/download/sentinel-lite-build-42";
        let r = parse_release(release_json("sentinel-lite-build-42", base).as_bytes(), &api).unwrap();
        assert_eq!(r.build, 42);
        assert!(r.installer_url.ends_with("-setup.exe"));

        let evil = release_json("sentinel-lite-build-43", "https://evil.example/files");
        assert!(parse_release(evil.as_bytes(), &api)
            .unwrap_err()
            .to_string()
            .contains("refusing"));
        assert!(parse_release(release_json("v1.0", base).as_bytes(), &api).is_err());
    }

    #[test]
    fn api_url_allow_list() {
        assert!(is_allowed_api_url(
            "https://api.github.com/repos/vextrocityy/v.exe/releases/latest"
        ));
        assert!(is_allowed_api_url("http://127.0.0.1:8765/latest"));
        assert!(!is_allowed_api_url("https://evil.example/repos/x/releases/latest"));
        assert!(!is_allowed_api_url("http://api.github.com/repos/x/y/releases/latest"));
    }

    #[test]
    fn checksum_lines() {
        let sums = format!(
            "{}  Vigil_0.1.0_x64-setup.exe\n{} *other.txt\n",
            "a".repeat(64),
            "b".repeat(64)
        );
        assert_eq!(
            expected_hash(&sums, "Vigil_0.1.0_x64-setup.exe"),
            Some("a".repeat(64))
        );
        assert_eq!(expected_hash(&sums, "other.txt"), Some("b".repeat(64)));
        assert_eq!(expected_hash(&sums, "missing.exe"), None);
    }

    #[test]
    fn download_is_verified_against_checksums() {
        use std::io::{Read, Write};
        let installer = b"MZ fake installer bytes".to_vec();
        let good = format!(
            "{}  Vigil_0.1.0_x64-setup.exe\n",
            super::super::hasher::sha256_bytes(&installer)
        );
        let bad = format!("{}  Vigil_0.1.0_x64-setup.exe\n", "0".repeat(64));
        for (sums, ok) in [(good, true), (bad, false)] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            let (inst, sums_b) = (installer.clone(), sums.into_bytes());
            std::thread::spawn(move || {
                for stream in listener.incoming().take(2) {
                    let mut s = stream.unwrap();
                    let mut req = [0u8; 1024];
                    let n = s.read(&mut req).unwrap();
                    let body = if String::from_utf8_lossy(&req[..n]).contains("SHA256SUMS") {
                        &sums_b
                    } else {
                        &inst
                    };
                    write!(
                        s,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .unwrap();
                    s.write_all(body).unwrap();
                }
            });
            let rel = parse_release(
                release_json("sentinel-lite-build-7", &base).as_bytes(),
                &format!("{base}/latest"),
            )
            .unwrap();
            let dir = tempfile::tempdir().unwrap();
            let result = download_verified(&rel, dir.path());
            assert_eq!(result.is_ok(), ok, "{result:?}");
            if ok {
                assert_eq!(std::fs::read(result.unwrap()).unwrap(), installer);
            }
        }
    }
}
