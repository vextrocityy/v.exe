//! sentinel-service
//!
//!   sentinel-service              (no args) started by the Windows SCM
//!   sentinel-service run          run the engine in the foreground (console)
//!   sentinel-service install      register + start the Windows service (admin)
//!   sentinel-service uninstall    stop + remove the Windows service (admin)
//!   sentinel-service scan <path>  one-shot scan to stdout, no IPC

mod app;
mod database;
mod engine;
mod ipc;
mod platform;
#[cfg(windows)]
mod service;
mod settings;

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
            let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?;
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
        #[cfg(windows)]
        Some("install") => service::install(),
        #[cfg(windows)]
        Some("uninstall") => service::uninstall(),
        Some(other) => bail!("unknown command: {other}"),
    }
}

fn one_shot_scan(paths: AppPaths, targets: Vec<String>) -> Result<()> {
    let engine = app::build_engine(paths)?;
    let mut events = engine.subscribe();
    let id = engine.start_scan(ScanKind::Custom, targets).map_err(anyhow::Error::msg)?;
    loop {
        match events.blocking_recv() {
            Ok(ev) => {
                println!("[{:?}] {}{}", ev.severity, ev.title, ev.path.map(|p| format!(" - {p}")).unwrap_or_default());
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
