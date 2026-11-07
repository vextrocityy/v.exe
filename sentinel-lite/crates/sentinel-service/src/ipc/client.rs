//! Synchronous pipe client used by the CLI (`status`, `elevated-request`).

use anyhow::{bail, Context, Result};
use sentinel_protocol::{paths, read_frame, write_frame, Request, Response};
use std::io::{Read, Write};

trait Conn: Read + Write {}
impl<T: Read + Write> Conn for T {}

#[cfg(windows)]
fn open() -> std::io::Result<Box<dyn Conn>> {
    const ERROR_PIPE_BUSY: i32 = 231;
    for _ in 0..50 {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(sentinel_protocol::PIPE_NAME)
        {
            Ok(f) => return Ok(Box::new(f)),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                std::thread::sleep(std::time::Duration::from_millis(100))
            }
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other("pipe busy"))
}

#[cfg(not(windows))]
fn open() -> std::io::Result<Box<dyn Conn>> {
    Ok(Box::new(std::os::unix::net::UnixStream::connect(paths::unix_socket())?))
}

pub fn request(req: &Request) -> Result<Response> {
    let token = std::fs::read_to_string(paths::token_file()).context("service is not running (no IPC token)")?;
    let mut conn = open().context("cannot connect to the service")?;
    write_frame(
        &mut conn,
        &Request::Auth {
            token: token.trim().into(),
            client: "sentinel-cli".into(),
        },
    )?;
    match read_frame::<_, Response>(&mut conn)? {
        Response::AuthOk { .. } => {}
        Response::Error { message, .. } => bail!("authentication failed: {message}"),
        other => bail!("unexpected handshake: {other:?}"),
    }
    write_frame(&mut conn, req)?;
    Ok(read_frame(&mut conn)?)
}
