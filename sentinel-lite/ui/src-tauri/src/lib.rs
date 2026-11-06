//! Tauri commands: thin, typed wrappers over the service protocol.

mod client;

use sentinel_protocol::*;
use std::time::Duration;
use tauri::{AppHandle, Emitter};

/// Run blocking pipe I/O off the async runtime.
async fn call(req: Request) -> Result<Response, String> {
    tauri::async_runtime::spawn_blocking(move || client::request(req)).await.map_err(|e| e.to_string())?
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
    match call(Request::StartScan { kind, paths: paths.unwrap_or_default() }).await? {
        Response::ScanStarted { scan_id } => Ok(scan_id),
        r => Err(unexpected(r)),
    }
}

#[tauri::command]
async fn cancel_scan() -> Result<(), String> {
    call(Request::CancelScan).await.map(|_| ())
}

#[tauri::command]
async fn acknowledge_threats() -> Result<(), String> {
    call(Request::AcknowledgeThreats).await.map(|_| ())
}

#[tauri::command]
async fn get_events(limit: Option<u32>, before_id: Option<i64>) -> Result<Vec<SecurityEvent>, String> {
    match call(Request::GetEvents { limit: limit.unwrap_or(100), before_id }).await? {
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
    call(Request::RestoreQuarantine { id }).await.map(|_| ())
}

#[tauri::command]
async fn delete_quarantine(id: String) -> Result<(), String> {
    call(Request::DeleteQuarantine { id }).await.map(|_| ())
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
    match call(Request::UpdateSettings { settings }).await? {
        Response::Settings(s) => Ok(s),
        r => Err(unexpected(r)),
    }
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
                            let _ = app.emit("sentinel://event", ev);
                        }
                        Ok(_) => {}
                        Err(FrameError::Io(e)) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {}
                        Err(e) => return Err(e.to_string()),
                    }
                }
            })();
            if let Err(e) = result {
                let _ = app.emit("sentinel://connection", false);
                eprintln!("event bridge: {e}");
            }
            std::thread::sleep(Duration::from_secs(2));
        })
        .expect("spawn event bridge");
}

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            spawn_event_bridge(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            start_scan,
            cancel_scan,
            acknowledge_threats,
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
