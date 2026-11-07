//! sentinel-service
//!
//!   sentinel-service              (no args) started by the Windows SCM
//!   sentinel-service run          run the engine in the foreground (console)
//!   sentinel-service install      register + start the Windows service (admin)
//!   sentinel-service uninstall    stop + remove the Windows service (admin)
//!   sentinel-service scan <path>  one-shot scan to stdout, no IPC
//!   sentinel-service update       one-shot signature update, no IPC
//!   sentinel-service status       print the running service's status (JSON)
//!   sentinel-service events [n]   print the last n security events (JSON)
//!   sentinel-service settings     print the active settings (JSON)
//!   sentinel-service keygen       create an Ed25519 update-signing keypair
//!   sentinel-service sign-pack <pack.json> <secret-key-file>   writes <pack.json>.sig
//!   sentinel-service elevated-request <hex>   (internal) run one privileged request
//!                                 for the dashboard after a UAC prompt

mod app;
mod database;
mod engine;
mod ipc;
mod platform;
#[cfg(windows)]
mod service;
mod settings;
mod util;

use anyhow::{bail, Result};
use engine::AppPaths;
use sentinel_protocol::ScanKind;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let paths = AppPaths::new(sentinel_protocol::paths::data_dir());

    match args.first().map(String::as_str) {
        None => {
            #[cfg(windows)]
            return service::dispatch();
            #[cfg(not(windows))]
            bail!("usage: sentinel-service run | scan <path>");
        }
        Some("run") => {
            app::init_logging(&paths, true);
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()?;
            rt.block_on(app::run(paths, async {
                let _ = tokio::signal::ctrl_c().await;
            }))
        }
        Some("scan") => {
            app::init_logging(&paths, true);
            let targets: Vec<String> = args[1..].to_vec();
            if targets.is_empty() {
                bail!("usage: sentinel-service scan <path> [path...]");
            }
            one_shot_scan(paths, targets)
        }
        Some("update") => {
            app::init_logging(&paths, true);
            let engine = app::build_engine(paths)?;
            let n = engine.update_signatures().map_err(anyhow::Error::msg)?;
            println!("{n} new signatures; {} total", engine.db.signature_count());
            Ok(())
        }
        Some("events") => {
            let limit = args.get(1).and_then(|n| n.parse().ok()).unwrap_or(50);
            let resp = ipc::client::request(&sentinel_protocol::Request::GetEvents { limit, before_id: None })?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
            Ok(())
        }
        Some("settings") => {
            let resp = ipc::client::request(&sentinel_protocol::Request::GetSettings)?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
            Ok(())
        }
        Some("status") => {
            let resp = ipc::client::request(&sentinel_protocol::Request::GetStatus)?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
            Ok(())
        }
        Some("keygen") => {
            let (secret, public) = engine::update::keygen()?;
            println!("secret (keep OFFLINE, never commit): {secret}");
            println!("public (build with SENTINEL_UPDATE_PUBKEYS={public})");
            Ok(())
        }
        Some("sign-pack") => {
            let (Some(pack), Some(key)) = (args.get(1), args.get(2)) else {
                bail!("usage: sentinel-service sign-pack <pack.json> <secret-key-file>");
            };
            let body = std::fs::read(pack)?;
            database::signatures::parse_pack(&body)?; // refuse to sign something we cannot load
            let sig = engine::update::sign(std::fs::read_to_string(key)?.trim(), &body)?;
            std::fs::write(format!("{pack}.sig"), &sig)?;
            println!("wrote {pack}.sig");
            Ok(())
        }
        Some("elevated-request") => elevated_request(args.get(1).map(String::as_str).unwrap_or("")),
        #[cfg(windows)]
        Some("install") => service::install(),
        #[cfg(windows)]
        Some("uninstall") => service::uninstall(),
        #[cfg(windows)]
        Some("start") => service::start(),
        #[cfg(windows)]
        Some("stop") => service::stop(),
        Some(other) => bail!("unknown command: {other}"),
    }
}

/// Run on behalf of the dashboard after the user approved a UAC prompt: this
/// process is elevated and lives in the install directory, so the service
/// accepts protection-weakening requests from it. Only those requests are allowed.
fn elevated_request(hex: &str) -> Result<()> {
    use sentinel_protocol::{Request, Response};
    let raw = util::from_hex(hex)
        .filter(|b| b.len() <= 64 * 1024)
        .ok_or_else(|| anyhow::anyhow!("bad request encoding"))?;
    let req: Request = serde_json::from_slice(&raw)?;
    if !matches!(req, Request::UpdateSettings { .. } | Request::RestoreQuarantine { .. }) {
        bail!("request type not allowed");
    }
    match ipc::client::request(&req)? {
        Response::Error { message, .. } => bail!("{message}"),
        _ => Ok(()),
    }
}

fn one_shot_scan(paths: AppPaths, targets: Vec<String>) -> Result<()> {
    let engine = app::build_engine(paths)?;
    let mut events = engine.subscribe();
    let id = engine
        .start_scan(ScanKind::Custom, targets)
        .map_err(anyhow::Error::msg)?;
    loop {
        match events.blocking_recv() {
            Ok(ev) => {
                println!(
                    "[{:?}] {}{}",
                    ev.severity,
                    ev.title,
                    ev.path.map(|p| format!(" - {p}")).unwrap_or_default()
                );
                if matches!(ev.kind, sentinel_protocol::EventKind::ScanFinished) {
                    if let Some(d) = ev.detail {
                        println!("{d}");
                    }
                    break;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(_) => break,
        }
    }
    let _ = id;
    Ok(())
}
