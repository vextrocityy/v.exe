//! Dashboard backend: typed Tauri commands over the service protocol, a tray
//! icon that keeps the app resident, and desktop notifications for threats.

mod client;
mod elevate;

use client::ClientError;
use sentinel_protocol::*;
use std::time::Duration;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, WindowEvent};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_opener::OpenerExt;

/// Run blocking pipe I/O off the async runtime.
async fn call(req: Request) -> Result<Response, ClientError> {
    tauri::async_runtime::spawn_blocking(move || client::request(req))
        .await
        .map_err(|e| ClientError {
            code: None,
            message: e.to_string(),
        })?
}

/// Like `call`, but if the service demands elevation, re-issue the request
/// through a UAC-approved helper and report success.
async fn call_privileged(req: Request) -> Result<Option<Response>, String> {
    match call(req.clone()).await {
        Ok(r) => Ok(Some(r)),
        Err(ClientError {
            code: Some(ErrorCode::ElevationRequired),
            ..
        }) => {
            tauri::async_runtime::spawn_blocking(move || elevate::run(&req))
                .await
                .map_err(|e| e.to_string())??;
            Ok(None)
        }
        Err(e) => Err(e.message),
    }
}

fn unexpected(r: Response) -> String {
    format!("unexpected response from service: {r:?}")
}

#[tauri::command]
async fn get_status() -> Result<EngineStatus, String> {
    match call(Request::GetStatus).await? {
        Response::Status(s) => Ok(s),
        r => Err(unexpected(r)),
    }
}

#[tauri::command]
async fn start_scan(kind: ScanKind, paths: Option<Vec<String>>) -> Result<u64, String> {
    match call(Request::StartScan {
        kind,
        paths: paths.unwrap_or_default(),
    })
    .await?
    {
        Response::ScanStarted { scan_id } => Ok(scan_id),
        r => Err(unexpected(r)),
    }
}

#[tauri::command]
async fn cancel_scan() -> Result<(), String> {
    call(Request::CancelScan).await.map(|_| ()).map_err(Into::into)
}

#[tauri::command]
async fn acknowledge_threats() -> Result<(), String> {
    call(Request::AcknowledgeThreats).await.map(|_| ()).map_err(Into::into)
}

#[tauri::command]
async fn update_signatures() -> Result<(), String> {
    call(Request::UpdateSignatures).await.map(|_| ()).map_err(Into::into)
}

#[tauri::command]
async fn process_action(pid: u32, action: ProcessActionKind) -> Result<(), String> {
    // Resume weakens protection: the service asks for elevation, handled via UAC.
    call_privileged(Request::ProcessAction { pid, action })
        .await
        .map(|_| ())
}

#[tauri::command]
async fn trust_app(path: String) -> Result<(), String> {
    call_privileged(Request::TrustApp { path }).await.map(|_| ())
}

#[tauri::command]
async fn enable_hardening(id: String) -> Result<(), String> {
    // Writes HKLM via the SYSTEM service; ask for elevation if the service wants it.
    call_privileged(Request::EnableHardening { id }).await.map(|_| ())
}

#[tauri::command]
async fn check_app_update() -> Result<(), String> {
    call(Request::CheckAppUpdate).await.map(|_| ()).map_err(Into::into)
}

#[derive(serde::Serialize)]
struct Inspection {
    reports: Vec<FileReport>,
    truncated: bool,
}

/// File Check: detailed, read-only report for dropped or picked files/folders.
#[tauri::command]
async fn inspect_paths(paths: Vec<String>) -> Result<Inspection, String> {
    match call(Request::InspectPaths { paths }).await? {
        Response::Inspection { reports, truncated } => Ok(Inspection { reports, truncated }),
        r => Err(unexpected(r)),
    }
}

#[tauri::command]
async fn quarantine_path(path: String, threat_name: Option<String>) -> Result<(), String> {
    call_privileged(Request::QuarantinePath { path, threat_name }).await.map(|_| ())
}

/// Native "Choose files" dialog (runs in Rust, so the webview needs no file-system permission).
#[tauri::command]
async fn pick_files(app: AppHandle) -> Result<Vec<String>, String> {
    let picked = tauri::async_runtime::spawn_blocking(move || app.dialog().file().blocking_pick_files())
        .await
        .map_err(|e| e.to_string())?;
    Ok(picked
        .unwrap_or_default()
        .into_iter()
        .filter_map(|p| p.into_path().ok())
        .map(|p| p.display().to_string())
        .collect())
}

/// Open the VirusTotal report for a hash in the browser. Only the hash is
/// in the URL; the file itself is never uploaded.
#[tauri::command]
fn open_virustotal(app: AppHandle, sha256: String) -> Result<(), String> {
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("not a SHA-256".into());
    }
    app.opener()
        .open_url(format!("https://www.virustotal.com/gui/file/{sha256}"), None::<&str>)
        .map_err(|e| e.to_string())
}

/// Open File Explorer at a file, selected. If it no longer exists (quarantined,
/// deleted), open the closest folder that does.
#[tauri::command]
fn reveal_path(app: AppHandle, path: String) -> Result<(), String> {
    let p = std::path::PathBuf::from(&path);
    if !p.is_absolute() {
        return Err("not a file path".into());
    }
    if p.exists() {
        return app.opener().reveal_item_in_dir(&p).map_err(|e| e.to_string());
    }
    let dir = p
        .ancestors()
        .skip(1)
        .find(|d| d.is_dir())
        .ok_or("the file and its folder no longer exist")?;
    app.opener()
        .open_path(dir.to_string_lossy(), None::<&str>)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn disable_task(name: String) -> Result<(), String> {
    call_privileged(Request::DisableTask { name }).await.map(|_| ())
}

#[tauri::command]
async fn get_device_usage() -> Result<Vec<DeviceUse>, String> {
    match call(Request::GetDeviceUsage).await? {
        Response::DeviceUsage(v) => Ok(v),
        r => Err(unexpected(r)),
    }
}

#[tauri::command]
async fn list_snapshots() -> Result<Vec<Snapshot>, String> {
    match call(Request::ListSnapshots).await? {
        Response::Snapshots(v) => Ok(v),
        r => Err(unexpected(r)),
    }
}

#[tauri::command]
async fn create_snapshot() -> Result<(), String> {
    call(Request::CreateSnapshot).await.map(|_| ()).map_err(Into::into)
}

#[derive(serde::Serialize)]
struct Preview {
    changes: Vec<FileChange>,
    truncated: bool,
}

#[tauri::command]
async fn rollback_preview(snapshot_id: String, folders: Option<Vec<String>>) -> Result<Preview, String> {
    match call(Request::RollbackPreview {
        snapshot_id,
        folders: folders.unwrap_or_default(),
    })
    .await?
    {
        Response::RollbackPreview { changes, truncated } => Ok(Preview { changes, truncated }),
        r => Err(unexpected(r)),
    }
}

/// Writes user files from a snapshot: always needs administrator approval.
/// The result (files restored, backup folder) arrives as a Recovery event.
#[tauri::command]
async fn rollback_restore(snapshot_id: String, paths: Vec<String>) -> Result<(), String> {
    call_privileged(Request::RollbackRestore { snapshot_id, paths })
        .await
        .map(|_| ())
}

#[tauri::command]
async fn get_events(limit: Option<u32>, before_id: Option<i64>) -> Result<Vec<SecurityEvent>, String> {
    match call(Request::GetEvents {
        limit: limit.unwrap_or(100),
        before_id,
    })
    .await?
    {
        Response::Events(v) => Ok(v),
        r => Err(unexpected(r)),
    }
}

#[tauri::command]
async fn list_quarantine() -> Result<Vec<QuarantineItem>, String> {
    match call(Request::ListQuarantine).await? {
        Response::Quarantine(v) => Ok(v),
        r => Err(unexpected(r)),
    }
}

#[tauri::command]
async fn restore_quarantine(id: String) -> Result<(), String> {
    call_privileged(Request::RestoreQuarantine { id }).await.map(|_| ())
}

#[tauri::command]
async fn delete_quarantine(id: String) -> Result<(), String> {
    call(Request::DeleteQuarantine { id })
        .await
        .map(|_| ())
        .map_err(Into::into)
}

#[tauri::command]
async fn get_settings() -> Result<Settings, String> {
    match call(Request::GetSettings).await? {
        Response::Settings(s) => Ok(s),
        r => Err(unexpected(r)),
    }
}

#[tauri::command]
async fn update_settings(settings: Settings) -> Result<Settings, String> {
    match call_privileged(Request::UpdateSettings { settings }).await? {
        Some(Response::Settings(s)) => Ok(s),
        Some(r) => Err(unexpected(r)),
        // Applied by the elevated helper: read back what the service actually stored.
        None => get_settings().await,
    }
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

/// Desktop notification for events the user must know about even with the window closed.
fn maybe_notify(app: &AppHandle, ev: &SecurityEvent) {
    let important = match ev.kind {
        EventKind::ThreatDetected | EventKind::ProcessBlocked | EventKind::ProcessSuspended => true,
        EventKind::BehaviorAlert => ev.severity >= Severity::High,
        // Camera / microphone switched on (switching off is Info: no toast).
        EventKind::DeviceAccess => ev.severity >= Severity::Low,
        EventKind::PersistenceChange => ev.severity >= Severity::High,
        _ => false,
    };
    if !important {
        return;
    }
    let body = ev
        .path
        .as_deref()
        .map(|p| format!("{p}\n{}", ev.detail.as_deref().unwrap_or("")))
        .or_else(|| ev.detail.clone())
        .unwrap_or_default();
    let _ = app
        .notification()
        .builder()
        .title(format!("Vigil: {}", ev.title))
        .body(body.trim())
        .show();
}

/// Keep a subscription open and forward pushed events to the webview as
/// `sentinel://event`; reconnect forever if the service restarts.
fn spawn_event_bridge(app: AppHandle) {
    std::thread::Builder::new()
        .name("sentinel-events".into())
        .spawn(move || loop {
            let result = (|| -> Result<(), String> {
                let mut conn = client::connect()?;
                write_frame(&mut conn, &Request::Subscribe).map_err(|e| e.to_string())?;
                let _ack: Response = read_frame(&mut conn).map_err(|e| e.to_string())?;
                let _ = app.emit("sentinel://connection", true);
                loop {
                    match read_frame::<_, Response>(&mut conn) {
                        Ok(Response::Event(ev)) => {
                            maybe_notify(&app, &ev);
                            let _ = app.emit("sentinel://event", ev);
                        }
                        Ok(_) => {}
                        Err(FrameError::Io(e))
                            if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                        Err(e) => return Err(e.to_string()),
                    }
                }
            })();
            if let Err(e) = result {
                let _ = app.emit("sentinel://connection", false);
                eprintln!("event bridge: {e}");
            }
            std::thread::sleep(Duration::from_secs(3));
        })
        .expect("spawn event bridge");
}

fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open Vigil", true, None::<&str>)?;
    let scan = MenuItem::with_id(app, "scan", "Run quick scan", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Close dashboard (protection stays on)", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &scan, &quit])?;
    let mut tray = TrayIconBuilder::with_id("main")
        .tooltip("Vigil: protection is handled by the background service")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => show_main(app),
            "scan" => {
                tauri::async_runtime::spawn(async {
                    let _ = call(Request::StartScan {
                        kind: ScanKind::Quick,
                        paths: vec![],
                    })
                    .await;
                });
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

pub fn run() {
    tauri::Builder::default()
        // Must be first: a second launch focuses the running dashboard instead.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| show_main(app)))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            build_tray(app)?;
            // Started at login by the installer with --minimized: stay in the tray.
            let minimized = std::env::args().any(|a| a == "--minimized");
            if !minimized {
                show_main(app.handle());
            }
            spawn_event_bridge(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window hides it to the tray; "Close dashboard" in the tray exits.
            if let WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            start_scan,
            cancel_scan,
            acknowledge_threats,
            update_signatures,
            process_action,
            trust_app,
            check_app_update,
            inspect_paths,
            quarantine_path,
            pick_files,
            open_virustotal,
            reveal_path,
            enable_hardening,
            disable_task,
            get_device_usage,
            list_snapshots,
            create_snapshot,
            rollback_preview,
            rollback_restore,
            get_events,
            list_quarantine,
            restore_quarantine,
            delete_quarantine,
            get_settings,
            update_settings,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Vigil dashboard");
}
