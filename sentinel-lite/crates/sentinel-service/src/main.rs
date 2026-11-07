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
//!   sentinel-service yara-check <rules-dir> [path]   compile rules, optionally scan (support/QA)
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
            if engine.settings().yara_enabled {
                let _ = engine.reload_yara();
            }
            let result = engine.update_signatures();
            if let Some(ev) = engine.db.recent_events(1, None)?.into_iter().next() {
                println!("{}: {}", ev.title, ev.detail.unwrap_or_default());
            }
            let n = result.map_err(anyhow::Error::msg)?;
            println!(
                "{n} new signatures; {} total; {} YARA rules",
                engine.db.signature_count(),
                engine.yara.rules().map(|r| r.rule_count).unwrap_or(0)
            );
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
        Some("yara-check") => {
            // Support tool: compile a rules directory and optionally scan a file/folder with it.
            let Some(dir) = args.get(1) else {
                bail!("usage: sentinel-service yara-check <rules-dir> [path]")
            };
            if dir == "--load" {
                let set = engine::yara::RuleSet::load(std::path::Path::new(&args[2]))?;
                println!(
                    "loaded {} precompiled rules; resident memory {} MB",
                    set.rule_count,
                    platform::working_set_bytes().unwrap_or(0) / (1024 * 1024)
                );
                return Ok(());
            }
            let t = std::time::Instant::now();
            let (set, report) = engine::yara::compile(&[std::path::PathBuf::from(dir)]);
            for e in &report.errors {
                eprintln!("skipped: {e}");
            }
            let set = set.ok_or_else(|| anyhow::anyhow!("no rules compiled"))?;
            if let Ok(out) = std::env::var("SENTINEL_YARA_SAVE") {
                set.save(std::path::Path::new(&out))?;
            }
            println!(
                "{} rules compiled in {:.2} s; resident memory {} MB",
                set.rule_count,
                t.elapsed().as_secs_f32(),
                platform::working_set_bytes().unwrap_or(0) / (1024 * 1024)
            );
            if let Some(target) = args.get(2) {
                let mut stack = vec![std::path::PathBuf::from(target)];
                let (mut files, mut bytes, mut hits) = (0u64, 0u64, 0u64);
                let t = std::time::Instant::now();
                while let Some(p) = stack.pop() {
                    if p.is_dir() {
                        if let Ok(rd) = std::fs::read_dir(&p) {
                            stack.extend(rd.flatten().map(|e| e.path()));
                        }
                    } else if p.is_file() && engine::yara::is_candidate(&p) {
                        files += 1;
                        bytes += p.metadata().map(|m| m.len()).unwrap_or(0);
                        if let Ok(m) = engine::yara::scan_file(&set, &p) {
                            if let Some(top) = engine::yara::strongest(&m) {
                                hits += 1;
                                println!(
                                    "MATCH {} -> {}:{} (score {})",
                                    p.display(),
                                    top.namespace,
                                    top.rule,
                                    top.score
                                );
                            }
                        }
                    }
                }
                let secs = t.elapsed().as_secs_f32().max(0.001);
                println!(
                    "scanned {files} candidate files ({:.1} MB) in {secs:.2} s = {:.1} MB/s, {hits} match(es); resident memory {} MB",
                    bytes as f32 / 1e6,
                    bytes as f32 / 1e6 / secs,
                    platform::working_set_bytes().unwrap_or(0) / (1024 * 1024)
                );
            }
            Ok(())
        }
        // Internal: run by the service to keep the compiler out of its own process.
        Some("yara-compile") => {
            println!("{}", engine::compile_rules_in_process(&paths, None)?);
            Ok(())
        }
        Some("yara-validate") => {
            let file = args
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("usage: yara-validate <file>"))?;
            println!(
                "{}",
                engine::compile_rules_in_process(&paths, Some(std::path::Path::new(file)))?
            );
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
    if engine.settings().yara_enabled {
        if let Err(e) = engine.reload_yara() {
            eprintln!("YARA unavailable: {e}");
        }
    }
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
