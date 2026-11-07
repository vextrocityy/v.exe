//! Blocking IPC client for the Sentinel-Lite service.
//! One short-lived connection per request keeps the UI stateless; the
//! subscription stream uses its own long-lived connection.

use sentinel_protocol::{paths, read_frame, write_frame, ErrorCode, Request, Response, PROTOCOL_VERSION};
use std::io::{Read, Write};
use std::time::Duration;

pub trait Conn: Read + Write + Send {}
impl<T: Read + Write + Send> Conn for T {}

#[derive(Debug)]
pub struct ClientError {
    pub code: Option<ErrorCode>,
    pub message: String,
}

impl ClientError {
    fn msg(m: impl Into<String>) -> Self {
        Self {
            code: None,
            message: m.into(),
        }
    }
}

impl From<ClientError> for String {
    fn from(e: ClientError) -> String {
        e.message
    }
}

impl From<sentinel_protocol::FrameError> for ClientError {
    fn from(e: sentinel_protocol::FrameError) -> Self {
        Self::msg(format!("connection to the service failed: {e}"))
    }
}

#[cfg(windows)]
fn open_transport() -> std::io::Result<Box<dyn Conn>> {
    const ERROR_PIPE_BUSY: i32 = 231;
    let mut last = None;
    for _ in 0..20 {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(sentinel_protocol::PIPE_NAME)
        {
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
pub fn connect() -> Result<Box<dyn Conn>, ClientError> {
    let token = std::fs::read_to_string(paths::token_file())
        .map_err(|_| ClientError::msg("The Sentinel-Lite protection service is not running."))?;
    let mut conn =
        open_transport().map_err(|e| ClientError::msg(format!("Cannot reach the Sentinel-Lite service: {e}")))?;
    write_frame(
        &mut conn,
        &Request::Auth {
            token: token.trim().to_string(),
            client: "sentinel-ui".into(),
        },
    )?;
    match read_frame::<_, Response>(&mut conn)? {
        Response::AuthOk { protocol_version } if protocol_version == PROTOCOL_VERSION => Ok(conn),
        Response::AuthOk { protocol_version } => Err(ClientError::msg(format!(
            "This dashboard (protocol v{PROTOCOL_VERSION}) does not match the installed service (v{protocol_version}). Reinstall Sentinel-Lite."
        ))),
        Response::Error { code, message } => Err(ClientError { code: Some(code), message }),
        other => Err(ClientError::msg(format!("unexpected handshake reply: {other:?}"))),
    }
}

pub fn request(req: Request) -> Result<Response, ClientError> {
    let mut conn = connect()?;
    write_frame(&mut conn, &req)?;
    match read_frame::<_, Response>(&mut conn)? {
        Response::Error { code, message } => Err(ClientError {
            code: Some(code),
            message,
        }),
        ok => Ok(ok),
    }
}
