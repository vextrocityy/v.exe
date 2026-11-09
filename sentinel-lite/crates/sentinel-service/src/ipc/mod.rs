//! IPC server: authenticates clients and maps protocol requests onto the engine.

pub mod auth;
pub mod client;
pub mod transport;

use crate::engine::Engine;
use anyhow::Result;
use auth::AuthToken;
use sentinel_protocol::{ErrorCode, ProcessActionKind, Request, Response, MAX_FRAME_BYTES, PROTOCOL_VERSION};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{broadcast, watch};
use transport::{Peer, Stream};

const AUTH_TIMEOUT: Duration = Duration::from_secs(5);

enum ReadError {
    Closed,
    Malformed(String),
}

async fn read_msg<R: AsyncRead + Unpin>(r: &mut R) -> Result<Request, ReadError> {
    let len = r.read_u32_le().await.map_err(|_| ReadError::Closed)?;
    if len > MAX_FRAME_BYTES {
        return Err(ReadError::Closed); // cannot resync after a bogus length
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await.map_err(|_| ReadError::Closed)?;
    serde_json::from_slice(&body).map_err(|e| ReadError::Malformed(e.to_string()))
}

async fn write_msg<W: AsyncWrite + Unpin>(w: &mut W, resp: &Response) -> std::io::Result<()> {
    let bytes = sentinel_protocol::encode(resp).map_err(|e| std::io::Error::other(e.to_string()))?;
    w.write_all(&bytes).await?;
    w.flush().await
}

/// Accept loop. Runs until `shutdown` flips to true.
pub async fn serve(engine: Arc<Engine>, token: Arc<AuthToken>, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let mut listener = transport::Listener::bind()?;
    tracing::info!("IPC listening");
    loop {
        tokio::select! {
            res = listener.accept() => match res {
                Ok((stream, peer)) => {
                    let (engine, token) = (engine.clone(), token.clone());
                    tokio::spawn(async move {
                        if let Err(e) = handle(engine, token, stream, peer).await {
                            tracing::debug!(error = %e, "client session ended with error");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            },
            _ = shutdown.changed() => break,
        }
    }
    Ok(())
}

async fn handle<S: Stream>(engine: Arc<Engine>, token: Arc<AuthToken>, mut s: S, peer: Peer) -> Result<()> {
    // --- handshake --------------------------------------------------------------
    match tokio::time::timeout(AUTH_TIMEOUT, read_msg(&mut s)).await {
        Ok(Ok(Request::Auth { token: t, .. })) if token.verify(&t) && !peer.trusted => {
            tracing::warn!(pid = ?peer.pid, image = ?peer.image, "rejected IPC client outside the install directory");
            let _ = write_msg(
                &mut s,
                &Response::error(ErrorCode::Forbidden, "not a trusted Vigil component"),
            )
            .await;
            return Ok(());
        }
        Ok(Ok(Request::Auth { token: t, client })) if token.verify(&t) => {
            tracing::info!(client, pid = ?peer.pid, image = ?peer.image, elevated = peer.elevated, "client authenticated");
            write_msg(
                &mut s,
                &Response::AuthOk {
                    protocol_version: PROTOCOL_VERSION,
                },
            )
            .await?;
        }
        _ => {
            tracing::warn!(pid = ?peer.pid, image = ?peer.image, "rejected unauthenticated IPC client");
            let _ = write_msg(
                &mut s,
                &Response::error(ErrorCode::Unauthorized, "authentication required"),
            )
            .await;
            return Ok(());
        }
    }

    // --- request loop -------------------------------------------------------------
    loop {
        let req = match read_msg(&mut s).await {
            Ok(r) => r,
            Err(ReadError::Closed) => return Ok(()),
            Err(ReadError::Malformed(m)) => {
                write_msg(&mut s, &Response::error(ErrorCode::BadRequest, m)).await?;
                continue;
            }
        };
        if let Request::Subscribe = req {
            write_msg(&mut s, &Response::Ok).await?;
            return stream_events(engine.subscribe(), s).await;
        }
        let resp = dispatch(&engine, req, &peer).await;
        write_msg(&mut s, &resp).await?;
    }
}

/// Push events until the client hangs up.
async fn stream_events<S: Stream>(mut rx: broadcast::Receiver<sentinel_protocol::SecurityEvent>, s: S) -> Result<()> {
    let (mut rd, mut wr) = tokio::io::split(s);
    let mut probe = [0u8; 1];
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Ok(ev) => write_msg(&mut wr, &Response::Event(ev)).await?,
                Err(broadcast::error::RecvError::Lagged(n)) => tracing::debug!(n, "subscriber lagged"),
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            },
            // A read returning 0 bytes / error means the client disconnected.
            r = rd.read(&mut probe) => if matches!(r, Ok(0) | Err(_)) { return Ok(()) },
        }
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Box<Response>> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Box::new(Response::error(ErrorCode::Internal, e.to_string())))
}

fn elevation_required(what: &str) -> Response {
    Response::error(
        ErrorCode::ElevationRequired,
        format!("Administrator approval is required because this {what}."),
    )
}

async fn dispatch(engine: &Arc<Engine>, req: Request, peer: &Peer) -> Response {
    // Authorisation: anything that weakens protection needs an elevated client.
    match &req {
        Request::RestoreQuarantine { .. } if !peer.elevated => {
            return elevation_required("releases a detected threat");
        }
        Request::QuarantinePath { .. } if !peer.elevated => {
            return elevation_required("moves a file of your choice into quarantine");
        }
        Request::DisableTask { .. } if !peer.elevated => {
            return elevation_required("turns off a scheduled task, which can be one Windows needs");
        }
        Request::RollbackRestore { .. } if !peer.elevated => {
            return elevation_required("overwrites files with older copies from a snapshot");
        }
        Request::TrustApp { .. } if !peer.elevated => {
            return elevation_required("lets an unsigned program run from a risky folder");
        }
        Request::ProcessAction {
            action: ProcessActionKind::Resume,
            ..
        } if !peer.elevated => {
            return elevation_required("resumes a process suspended as ransomware");
        }
        Request::UpdateSettings { settings } if !peer.elevated => {
            let current = engine.settings();
            let proposed = crate::settings::merge_secrets(&current, crate::settings::sanitize(settings.clone()));
            let reasons = crate::settings::weakenings(&current, &proposed);
            if !reasons.is_empty() {
                return elevation_required(&format!("change {}", reasons.join(", ")));
            }
        }
        _ => {}
    }
    if matches!(req, Request::RestoreQuarantine { .. } | Request::UpdateSettings { .. }) {
        tracing::info!(pid = ?peer.pid, image = ?peer.image, elevated = peer.elevated, "privileged request: {:?}", std::mem::discriminant(&req));
    }
    let e = engine.clone();
    let result = match req {
        Request::DisableTask { name } => {
            blocking(move || match e.disable_task(&name) {
                Ok(()) => Response::Ok,
                Err(m) => Response::error(ErrorCode::BadRequest, m),
            })
            .await
        }
        Request::GetDeviceUsage => {
            blocking(|| Response::DeviceUsage(crate::engine::realtime::privacy::read_all())).await
        }
        Request::ListSnapshots => {
            blocking(move || match e.list_snapshots() {
                Ok(v) => Response::Snapshots(v.into_iter().map(|s| s.snapshot).collect()),
                Err(m) => Response::error(ErrorCode::Internal, m),
            })
            .await
        }
        Request::CreateSnapshot => {
            blocking(move || match e.create_snapshot() {
                Ok(_) => Response::Ok,
                Err(m) => Response::error(ErrorCode::Busy, m),
            })
            .await
        }
        Request::RollbackPreview { snapshot_id, folders } => {
            blocking(move || match e.rollback_preview(&snapshot_id, folders) {
                Ok((changes, truncated)) => Response::RollbackPreview { changes, truncated },
                Err(m) => Response::error(ErrorCode::BadRequest, m),
            })
            .await
        }
        Request::RollbackRestore { snapshot_id, paths } => {
            blocking(move || match e.rollback_restore(&snapshot_id, paths) {
                Ok((restored, failed, backup_dir)) => Response::RollbackDone {
                    restored,
                    failed,
                    backup_dir,
                },
                Err(m) => Response::error(ErrorCode::BadRequest, m),
            })
            .await
        }
        Request::Auth { .. } => Ok(Response::error(ErrorCode::BadRequest, "already authenticated")),
        Request::Subscribe => unreachable!("handled by caller"),
        Request::GetStatus => blocking(move || Response::Status(e.status())).await,
        Request::StartScan { kind, paths } => match e.start_scan(kind, paths) {
            Ok(scan_id) => Ok(Response::ScanStarted { scan_id }),
            Err(m) => Ok(Response::error(ErrorCode::Busy, m)),
        },
        Request::CancelScan => Ok(if e.cancel_scan() {
            Response::Ok
        } else {
            Response::error(ErrorCode::NotFound, "no scan running")
        }),
        Request::AcknowledgeThreats => {
            e.acknowledge_threats();
            Ok(Response::Ok)
        }
        Request::ProcessAction { pid, action } => {
            blocking(move || match e.process_action(pid, action) {
                Ok(_) => Response::Ok,
                Err(m) => Response::error(ErrorCode::NotFound, m),
            })
            .await
        }
        Request::TrustApp { path } => {
            blocking(move || match e.trust_app(&path) {
                Ok(()) => Response::Ok,
                Err(err) => Response::error(ErrorCode::BadRequest, format!("{err:#}")),
            })
            .await
        }
        Request::EnableHardening { id } => {
            blocking(move || match e.enable_hardening(&id) {
                Ok(_) => Response::Ok,
                Err(err) => Response::error(ErrorCode::BadRequest, format!("{err:#}")),
            })
            .await
        }
        Request::InspectPaths { paths } => {
            blocking(move || {
                let (reports, truncated) = crate::engine::inspect::inspect_paths(&e, &paths);
                Response::Inspection { reports, truncated }
            })
            .await
        }
        Request::QuarantinePath { path, threat_name } => {
            blocking(
                move || match e.quarantine_path(std::path::Path::new(&path), threat_name) {
                    Ok(_) => Response::Ok,
                    Err(err) => Response::error(ErrorCode::BadRequest, format!("{err:#}")),
                },
            )
            .await
        }
        Request::CheckAppUpdate => Ok(match e.start_app_update() {
            Ok(()) => Response::Ok,
            Err(m) => Response::error(ErrorCode::Busy, m),
        }),
        Request::UpdateSignatures => Ok(match e.start_update() {
            Ok(()) => Response::Ok,
            Err(m) => Response::error(ErrorCode::Busy, m),
        }),
        Request::GetEvents { limit, before_id } => {
            blocking(move || match e.db.recent_events(limit, before_id) {
                Ok(v) => Response::Events(v),
                Err(err) => Response::error(ErrorCode::Internal, err.to_string()),
            })
            .await
        }
        Request::ListQuarantine => {
            blocking(move || match e.db.list_quarantine() {
                Ok(v) => Response::Quarantine(v),
                Err(err) => Response::error(ErrorCode::Internal, err.to_string()),
            })
            .await
        }
        Request::RestoreQuarantine { id } => {
            blocking(move || match e.restore_quarantine(&id) {
                Ok(_) => Response::Ok,
                Err(err) => Response::error(ErrorCode::NotFound, format!("{err:#}")),
            })
            .await
        }
        Request::DeleteQuarantine { id } => {
            blocking(move || match e.delete_quarantine(&id) {
                Ok(()) => Response::Ok,
                Err(err) => Response::error(ErrorCode::NotFound, format!("{err:#}")),
            })
            .await
        }
        Request::GetSettings => Ok(Response::Settings(crate::settings::redacted(&e.settings()))),
        Request::UpdateSettings { settings } => {
            blocking(move || match e.update_settings(settings) {
                Ok(s) => Response::Settings(crate::settings::redacted(&s)),
                Err(err) => Response::error(ErrorCode::Internal, format!("{err:#}")),
            })
            .await
        }
    };
    result.unwrap_or_else(|r| *r)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::database::Database;
    use crate::engine::AppPaths;
    use sentinel_protocol::Settings;

    async fn roundtrip(s: &mut tokio::io::DuplexStream, req: &Request) -> Response {
        let bytes = sentinel_protocol::encode(req).unwrap();
        s.write_all(&bytes).await.unwrap();
        let len = s.read_u32_le().await.unwrap();
        let mut body = vec![0u8; len as usize];
        s.read_exact(&mut body).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn peer(elevated: bool) -> Peer {
        Peer {
            trusted: true,
            elevated,
            ..Peer::default()
        }
    }

    async fn session(engine: &Arc<Engine>, token: &Arc<AuthToken>, p: Peer) -> tokio::io::DuplexStream {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(handle(engine.clone(), token.clone(), server, p));
        let r = roundtrip(
            &mut client,
            &Request::Auth {
                token: "secret".into(),
                client: "t".into(),
            },
        )
        .await;
        assert!(matches!(r, Response::AuthOk { .. }), "{r:?}");
        client
    }

    fn engine() -> (tempfile::TempDir, Arc<Engine>) {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::new(dir.path().to_path_buf());
        paths.create_all().unwrap();
        let s = Settings {
            realtime_protection: false,
            ..Settings::default()
        };
        (dir, Engine::new(paths, Database::open_in_memory().unwrap(), s).unwrap())
    }

    #[tokio::test]
    async fn rejects_bad_token_and_serves_good_one() {
        let (_dir, engine) = engine();
        let token = Arc::new(AuthToken::from_string("secret"));

        let (mut client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(handle(engine.clone(), token.clone(), server, peer(false)));
        let r = roundtrip(
            &mut client,
            &Request::Auth {
                token: "wrong".into(),
                client: "t".into(),
            },
        )
        .await;
        assert!(matches!(
            r,
            Response::Error {
                code: ErrorCode::Unauthorized,
                ..
            }
        ));

        let mut client = session(&engine, &token, peer(false)).await;
        match roundtrip(&mut client, &Request::GetStatus).await {
            Response::Status(st) => assert!(!st.realtime_enabled),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn untrusted_client_is_forbidden_even_with_token() {
        let (_dir, engine) = engine();
        let token = Arc::new(AuthToken::from_string("secret"));
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(handle(
            engine,
            token,
            server,
            Peer {
                trusted: false,
                elevated: true,
                ..Peer::default()
            },
        ));
        let r = roundtrip(
            &mut client,
            &Request::Auth {
                token: "secret".into(),
                client: "t".into(),
            },
        )
        .await;
        assert!(
            matches!(
                r,
                Response::Error {
                    code: ErrorCode::Forbidden,
                    ..
                }
            ),
            "{r:?}"
        );
    }

    #[tokio::test]
    async fn weakening_needs_elevation_strengthening_does_not() {
        let (_dir, engine) = engine();
        let token = Arc::new(AuthToken::from_string("secret"));
        let current = engine.settings();

        let mut user = session(&engine, &token, peer(false)).await;
        let weaker = Settings {
            exclusions: vec!["/srv/data".into()],
            ..current.clone()
        };
        let r = roundtrip(
            &mut user,
            &Request::UpdateSettings {
                settings: weaker.clone(),
            },
        )
        .await;
        assert!(
            matches!(
                r,
                Response::Error {
                    code: ErrorCode::ElevationRequired,
                    ..
                }
            ),
            "{r:?}"
        );
        let r = roundtrip(&mut user, &Request::RestoreQuarantine { id: "x".into() }).await;
        assert!(
            matches!(
                r,
                Response::Error {
                    code: ErrorCode::ElevationRequired,
                    ..
                }
            ),
            "{r:?}"
        );
        // Checking files is open to everyone; quarantining an arbitrary path is not.
        let r = roundtrip(
            &mut user,
            &Request::InspectPaths {
                paths: vec!["/nonexistent".into()],
            },
        )
        .await;
        assert!(matches!(r, Response::Inspection { .. }), "{r:?}");
        let r = roundtrip(
            &mut user,
            &Request::QuarantinePath {
                path: "/etc/hostname".into(),
                threat_name: None,
            },
        )
        .await;
        assert!(
            matches!(
                r,
                Response::Error {
                    code: ErrorCode::ElevationRequired,
                    ..
                }
            ),
            "{r:?}"
        );

        // A neutral / strengthening change is fine for a standard user.
        let r = roundtrip(
            &mut user,
            &Request::UpdateSettings {
                settings: Settings {
                    max_file_size_mb: 512,
                    ..current
                },
            },
        )
        .await;
        assert!(matches!(r, Response::Settings(_)), "{r:?}");

        let mut admin = session(&engine, &token, peer(true)).await;
        let r = roundtrip(&mut admin, &Request::UpdateSettings { settings: weaker }).await;
        match r {
            Response::Settings(s) => assert_eq!(s.exclusions, vec!["/srv/data".to_string()]),
            other => panic!("{other:?}"),
        }
    }
}
