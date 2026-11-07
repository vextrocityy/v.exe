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
use tauri_plugin_notification::NotificationExt;

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
        .title(format!("Sentinel-Lite: {}", ev.title))
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
    let open = MenuItem::with_id(app, "open", "Open Sentinel-Lite", true, None::<&str>)?;
    let scan = MenuItem::with_id(app, "scan", "Run quick scan", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Close dashboard (protection stays on)", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &scan, &quit])?;
    let mut tray = TrayIconBuilder::with_id("main")
        .tooltip("Sentinel-Lite: protection is handled by the background service")
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
            get_events,
            list_quarantine,
            restore_quarantine,
            delete_quarantine,
            get_settings,
            update_settings,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Sentinel-Lite dashboard");
}
