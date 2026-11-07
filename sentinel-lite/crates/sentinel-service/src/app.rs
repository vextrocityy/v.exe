//! Service bootstrap shared by console mode and Windows-service mode.

use crate::database::{signatures, Database};
use crate::engine::{AppPaths, Engine};
use crate::ipc::{self, auth::AuthToken};
use crate::settings;
use anyhow::{Context, Result};
use sentinel_protocol::{EventKind, Severity};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;

pub fn init_logging(paths: &AppPaths, to_console: bool) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("SENTINEL_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    crate::util::install_panic_hook();
    let builder = tracing_subscriber::fmt().with_env_filter(filter).with_target(false);
    if to_console {
        let _ = builder.try_init();
        return;
    }
    let _ = std::fs::create_dir_all(&paths.logs);
    // 4 x 10 MB cap on disk, rotated while running.
    match crate::util::RotatingFile::open(&paths.logs.join("service.log"), 10 * 1024 * 1024, 3) {
        Ok(file) => {
            let _ = builder
                .with_ansi(false)
                .with_writer(std::sync::Mutex::new(file))
                .try_init();
        }
        Err(_) => {
            let _ = builder.try_init();
        }
    }
}

/// Signature packs shipped next to the executable, plus user/feed packs.
fn signature_dirs(paths: &AppPaths) -> Vec<PathBuf> {
    let mut dirs = vec![paths.signatures.clone()];
    if let Some(exe_dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
    {
        dirs.push(exe_dir.join("signatures"));
    }
    if let Some(extra) = std::env::var_os("SENTINEL_SIGNATURES") {
        dirs.push(PathBuf::from(extra));
    }
    // Dev convenience: `cargo run` from the workspace.
    dirs.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../signatures"));
    dirs
}

pub fn build_engine(paths: AppPaths) -> Result<Arc<Engine>> {
    paths.create_all().context("creating data directories")?;
    if let Err(e) = crate::platform::harden_data_dir(&paths.data) {
        tracing::warn!(error = %e, "could not restrict data directory permissions");
    }
    let (db, rebuilt) = Database::open_or_recover(&paths.database)?;
    if rebuilt {
        tracing::warn!("database was corrupt and has been rebuilt; scan cache and history were reset");
    }
    let dirs = signature_dirs(&paths);
    let refs: Vec<&std::path::Path> = dirs.iter().map(|d| d.as_path()).collect();
    let imported = signatures::import_all(&db, &refs);
    tracing::info!(imported, total = db.signature_count(), "signature database ready");
    let settings = settings::load(&paths.settings);
    Engine::new(paths, db, settings)
}

/// Run until `shutdown` resolves.
pub async fn run(paths: AppPaths, shutdown: impl std::future::Future<Output = ()>) -> Result<()> {
    let engine = build_engine(paths)?;
    let token = Arc::new(AuthToken::generate()?);
    let token_path = sentinel_protocol::paths::token_file();
    token.write_to(&token_path).context("writing IPC token")?;
    if let Err(e) = crate::platform::harden_token_file(&token_path) {
        tracing::warn!(error = %e, "could not set IPC token permissions");
    }
    match crate::platform::install_dir() {
        Some(dir) if crate::platform::is_protected_dir(&dir) => {
            tracing::info!(dir = %dir.display(), "IPC clients restricted to the install directory")
        }
        _ => tracing::warn!("running outside Program Files: IPC client verification is DISABLED (dev mode)"),
    }

    {
        let e = engine.clone();
        tokio::task::spawn_blocking(move || e.start_realtime()).await?;
    }
    crate::util::contain("finish app update", || {
        crate::engine::appupdate::finish_pending(&engine)
    });
    engine.start_scheduler();
    {
        // Compile/load YARA rules off the startup path; shields work meanwhile with hashes.
        let e = engine.clone();
        std::thread::Builder::new().name("yara-load".into()).spawn(move || {
            if e.settings().yara_enabled {
                let _ = e.reload_yara();
            }
        })?;
    }
    engine.emit(
        EventKind::ServiceInfo,
        Severity::Info,
        "Sentinel-Lite engine started",
        Some(format!("{} signatures loaded", engine.db.signature_count())),
        None,
        None,
    );

    let (stop_tx, stop_rx) = watch::channel(false);
    let server = tokio::spawn(ipc::serve(engine.clone(), token, stop_rx));
    tokio::pin!(server);

    tokio::select! {
        _ = shutdown => tracing::info!("shutdown requested"),
        res = &mut server => match res {
            Ok(Err(e)) => tracing::error!(error = %e, "IPC server failed"),
            _ => tracing::error!("IPC server exited unexpectedly"),
        },
    }
    let _ = stop_tx.send(true);
    let e = engine.clone();
    tokio::task::spawn_blocking(move || e.shutdown()).await?;
    let _ = std::fs::remove_file(sentinel_protocol::paths::token_file());
    tracing::info!("engine stopped");
    Ok(())
}
