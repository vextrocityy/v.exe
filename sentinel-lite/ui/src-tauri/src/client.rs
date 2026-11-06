//! Blocking IPC client for the Sentinel-Lite service.
//! One short-lived connection per request keeps the UI stateless; the
//! subscription stream uses its own long-lived connection.

use sentinel_protocol::{paths, read_frame, write_frame, Request, Response};
use std::io::{Read, Write};
use std::time::Duration;

pub trait Conn: Read + Write + Send {}
impl<T: Read + Write + Send> Conn for T {}

#[cfg(windows)]
fn open_transport() -> std::io::Result<Box<dyn Conn>> {
    const ERROR_PIPE_BUSY: i32 = 231;
    let mut last = None;
    for _ in 0..20 {
        match std::fs::OpenOptions::new().read(true).write(true).open(sentinel_protocol::PIPE_NAME) {
            Ok(f) => return Ok(Box::new(f)),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e),
        }
    }
    Err(last.unwrap_or_else(|| std::io::Error::other("pipe busy")))
}

#[cfg(not(windows))]
fn open_transport() -> std::io::Result<Box<dyn Conn>> {
    let s = std::os::unix::net::UnixStream::connect(paths::unix_socket())?;
    s.set_read_timeout(Some(Duration::from_secs(30)))?;
    Ok(Box::new(s))
}

/// Connect and authenticate.
pub fn connect() -> Result<Box<dyn Conn>, String> {
    let token = std::fs::read_to_string(paths::token_file())
        .map_err(|e| format!("Sentinel-Lite service is not running (token unavailable: {e})"))?;
    let mut conn = open_transport().map_err(|e| format!("cannot reach the Sentinel-Lite service: {e}"))?;
    write_frame(&mut conn, &Request::Auth { token: token.trim().to_string(), client: "sentinel-ui".into() })
        .map_err(|e| e.to_string())?;
    match read_frame::<_, Response>(&mut conn).map_err(|e| e.to_string())? {
        Response::AuthOk { .. } => Ok(conn),
        Response::Error { message, .. } => Err(message),
        other => Err(format!("unexpected handshake reply: {other:?}")),
    }
}

pub fn request(req: Request) -> Result<Response, String> {
    let mut conn = connect()?;
    write_frame(&mut conn, &req).map_err(|e| e.to_string())?;
    match read_frame::<_, Response>(&mut conn).map_err(|e| e.to_string())? {
        Response::Error { message, .. } => Err(message),
        ok => Ok(ok),
    }
}
