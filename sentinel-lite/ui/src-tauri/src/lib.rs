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
            let outcome = tauri::async_runtime::spawn_blocking(move || elevate::run(&req))
                .await
                .map_err(|e| e.to_string())?;
            match outcome {
                Ok(()) => Ok(None),
                // The helper runs behind the UAC prompt and cannot pass its error
                // text back; the engine recorded the reason as an event. Use it.
                Err(generic) => Err(approved_change_error().await.unwrap_or(generic)),
            }
        }
        Err(e) => Err(e.message),
    }
}

/// The engine's reason for refusing the request the user just approved, if it
/// recorded one in the last minute.
async fn approved_change_error() -> Option<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    match call(Request::GetEvents {
        limit: 10,
        before_id: None,
    })
    .await
    .ok()?
    {
        Response::Events(events) => events
            .into_iter()
            .find(|e| e.title == APPROVED_CHANGE_FAILED && now - e.timestamp <= 60)
            .and_then(|e| e.detail),
        _ => None,
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

/// The engine is not running (e.g. an update stopped it and failed): start it.
#[tauri::command]
async fn start_service() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(elevate::start_service)
        .await
        .map_err(|e| e.to_string())?
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
    // Each snapshot replaces the oldest one, so the service asks for approval.
    call_privileged(Request::CreateSnapshot).await.map(|_| ())
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

#[derive(serde::Serialize)]
struct Suggestions {
    domains: Vec<DomainSuggestion>,
    from: i64,
    until: i64,
}

/// Domains this PC looked up around a detection, from the home network's Pi-hole.
#[tauri::command]
async fn home_network_suggestions(around: i64) -> Result<Suggestions, String> {
    match call(Request::HomeNetworkSuggestions { around }).await? {
        Response::DomainSuggestions { domains, from, until } => Ok(Suggestions { domains, from, until }),
        r => Err(unexpected(r)),
    }
}

#[derive(serde::Serialize)]
struct Blocked {
    added: Vec<String>,
    failed: Vec<String>,
}

/// Block domains for every device on the home network (Pi-hole deny list).
#[tauri::command]
async fn home_network_block(domains: Vec<String>, reason: Option<String>) -> Result<Blocked, String> {
    match call(Request::HomeNetworkBlock { domains, reason }).await? {
        Response::DomainsBlocked { added, failed } => Ok(Blocked { added, failed }),
        r => Err(unexpected(r)),
    }
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
    call_privileged(Request::DeleteQuarantine { id }).await.map(|_| ())
}

/// `%41+b` → `A b` (query-string decoding).
fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() && s.is_char_boundary(i + 1) && s.is_char_boundary(i + 3) => {
                match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    Ok(v) => {
                        out.push(v);
                        i += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `GET /?code=..&state=.. HTTP/1.1` → the query's values for `code`, `state`, `error`.
fn parse_callback(request_line: &str) -> (Option<String>, Option<String>, Option<String>) {
    let target = request_line.split_whitespace().nth(1).unwrap_or("");
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
    let get = |key: &str| {
        query
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| url_decode(v))
    };
    (get("code"), get("state"), get("error"))
}

/// Wait (up to 5 minutes) for Google to send the browser back to our one-shot
/// loopback listener, answer the browser, and return (code, state).
fn wait_for_google(listener: std::net::TcpListener) -> Result<(String, String), String> {
    use std::io::{BufRead, BufReader, Write};
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let deadline = std::time::Instant::now() + Duration::from_secs(300);
    while std::time::Instant::now() < deadline {
        let (mut stream, _) = match listener.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(150));
                continue;
            }
            Err(e) => return Err(e.to_string()),
        };
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut line = String::new();
        if BufReader::new(&stream).read_line(&mut line).is_err() {
            continue;
        }
        let (code, state, error) = parse_callback(&line);
        let page = |title: &str, text: &str| {
            let body = format!(
                "<!doctype html><meta charset=utf-8><title>Vigil</title><body style=\"font-family:Segoe UI,sans-serif;background:#020617;color:#e2e8f0;padding:3rem\"><h2>{title}</h2><p>{text}</p></body>"
            );
            format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        };
        match (code, state, error) {
            (Some(code), Some(state), _) => {
                let _ = stream.write_all(page("Almost done", "Go back to Vigil and approve the administrator prompt. You can close this tab.").as_bytes());
                return Ok((code, state));
            }
            (_, _, Some(_)) => {
                let _ = stream.write_all(page("Not connected", "Google sign-in was cancelled. You can close this tab.").as_bytes());
                return Err("Google sign-in was cancelled.".into());
            }
            // Anything else (a favicon request, a port scan): not our answer, keep waiting.
            _ => {
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
        }
    }
    Err("Timed out waiting for the Google sign-in. Press Connect Gmail to try again.".into())
}

/// Email account watch: connect a Gmail mailbox (read-only). Opens Google's
/// consent page in the browser and waits for it to come back to this PC.
#[tauri::command]
async fn gmail_connect(app: AppHandle) -> Result<(), String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let url = match call(Request::GmailBegin {
        redirect_uri: format!("http://127.0.0.1:{port}"),
    })
    .await?
    {
        Response::GmailAuth { url } => url,
        r => return Err(unexpected(r)),
    };
    app.opener().open_url(url, None::<&str>).map_err(|e| e.to_string())?;
    let (code, state) = tauri::async_runtime::spawn_blocking(move || wait_for_google(listener))
        .await
        .map_err(|e| e.to_string())??;
    call_privileged(Request::GmailFinish { code, state }).await.map(|_| ())
}

#[tauri::command]
async fn gmail_disconnect() -> Result<(), String> {
    call_privileged(Request::GmailDisconnect).await.map(|_| ())
}

/// Open items that wait for the user's decision.
#[tauri::command]
async fn get_attention() -> Result<Vec<SecurityEvent>, String> {
    match call(Request::GetAttention).await? {
        Response::Events(v) => Ok(v),
        r => Err(unexpected(r)),
    }
}

#[tauri::command]
async fn resolve_event(id: i64) -> Result<(), String> {
    call(Request::ResolveEvent { id }).await.map(|_| ()).map_err(Into::into)
}

/// "This file is safe": never report it again (administrator approval).
#[tauri::command]
async fn allow_file(path: String) -> Result<(), String> {
    call_privileged(Request::AllowFile { path }).await.map(|_| ())
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
        // Info = a weak match on a program Windows vouches for: history only.
        EventKind::ThreatDetected => ev.severity >= Severity::Low,
        EventKind::ProcessBlocked | EventKind::ProcessSuspended => true,
        EventKind::BehaviorAlert => ev.severity >= Severity::High,
        // A threat that could not be quarantined is still on the PC.
        EventKind::ScanError => ev.severity >= Severity::High,
        // Camera / microphone switched on (switching off is Info: no toast).
        EventKind::DeviceAccess => ev.severity >= Severity::Low,
        EventKind::PersistenceChange => ev.severity >= Severity::High,
        // DNS stopped going through Pi-hole.
        EventKind::NetworkAlert => ev.severity >= Severity::High,
        // New sign-ins, resets and mailbox tampering; routine sign-in codes (Low) stay quiet.
        EventKind::AccountAlert => ev.severity >= Severity::Medium,
        _ => false,
    };
    if !important {
        return;
    }
    // A scan of a folder full of detections must not raise hundreds of toasts:
    // at most 4 in 30 s, then one summary; and never the same title twice in a row.
    {
        static STATE: std::sync::Mutex<Option<(std::time::Instant, u32, String)>> = std::sync::Mutex::new(None);
        let mut st = STATE.lock().unwrap_or_else(|e| e.into_inner());
        let now = std::time::Instant::now();
        let (start, count, last) = st.get_or_insert_with(|| (now, 0, String::new()));
        if now.duration_since(*start) > Duration::from_secs(30) {
            *start = now;
            *count = 0;
            last.clear();
        }
        if *last == ev.title {
            return;
        }
        *last = ev.title.clone();
        *count += 1;
        if *count == 5 {
            let _ = app
                .notification()
                .builder()
                .title("Vigil: more alerts")
                .body("Several things happened at once. Open Vigil to see what needs your attention.")
                .show();
        }
        if *count >= 5 {
            return;
        }
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
const TRAY_OK: &str = "Vigil: protection is on";
const TRAY_OFF: &str = "Vigil: PROTECTION IS OFF (the engine is not running). Open Vigil to start it.";

fn set_tray_tooltip(app: &AppHandle, text: &str) {
    if let Some(tray) = app.tray_by_id("main") {
        let _ = tray.set_tooltip(Some(text));
    }
}

fn spawn_event_bridge(app: AppHandle) {
    std::thread::Builder::new()
        .name("sentinel-events".into())
        .spawn(move || {
          // The dashboard is the only thing that can tell the user the engine has
          // stopped: after 45 s without it, say so once (toast + tray), even when
          // the window is hidden in the tray.
          let mut down_since: Option<std::time::Instant> = None;
          let mut told = false;
          loop {
            let connected_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flag = connected_flag.clone();
            let app_ok = app.clone();
            let result = (|| -> Result<(), String> {
                let mut conn = client::connect()?;
                write_frame(&mut conn, &Request::Subscribe).map_err(|e| e.to_string())?;
                let _ack: Response = read_frame(&mut conn).map_err(|e| e.to_string())?;
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                set_tray_tooltip(&app_ok, TRAY_OK);
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
            if connected_flag.load(std::sync::atomic::Ordering::SeqCst) {
                // We were connected and lost it just now: start the clock afresh.
                down_since = Some(std::time::Instant::now());
                told = false;
            }
            let since = *down_since.get_or_insert_with(std::time::Instant::now);
            if !told && since.elapsed() > Duration::from_secs(45) {
                told = true;
                set_tray_tooltip(&app, TRAY_OFF);
                let _ = app
                    .notification()
                    .builder()
                    .title("Vigil: protection is off")
                    .body("The protection engine is not running. Open Vigil and choose Start protection.")
                    .show();
            }
            // Retry quickly at first, then every 15 s: no busy loop while it is down for days.
            let pause = if since.elapsed() > Duration::from_secs(120) { 15 } else { 3 };
            std::thread::sleep(Duration::from_secs(pause));
          }
        })
        .expect("spawn event bridge");
}

fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open Vigil", true, None::<&str>)?;
    let scan = MenuItem::with_id(app, "scan", "Run quick scan", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Close dashboard (protection stays on)", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &scan, &quit])?;
    let mut tray = TrayIconBuilder::with_id("main")
        .tooltip("Vigil")
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
            home_network_suggestions,
            home_network_block,
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
            start_service,
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
            gmail_connect,
            gmail_disconnect,
            get_attention,
            resolve_event,
            allow_file,
            get_settings,
            update_settings,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Vigil dashboard");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_google_callback() {
        let (code, state, error) = parse_callback("GET /?state=abc123&code=4%2F0Ab_cd-ef&scope=x HTTP/1.1");
        assert_eq!((code.as_deref(), state.as_deref(), error), (Some("4/0Ab_cd-ef"), Some("abc123"), None));
        assert_eq!(parse_callback("GET /?error=access_denied&state=s HTTP/1.1").2.as_deref(), Some("access_denied"));
        assert_eq!(parse_callback("GET /favicon.ico HTTP/1.1"), (None, None, None));
        assert_eq!(url_decode("a%20b+c%zz%4"), "a b c%zz%4");
    }
}
