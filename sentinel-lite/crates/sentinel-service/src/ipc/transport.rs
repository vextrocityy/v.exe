//! Listener: a Windows named pipe in production, a Unix socket for dev hosts.

use tokio::io::{AsyncRead, AsyncWrite};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Stream for T {}

/// Who connected, and what they may do.
#[derive(Debug, Default, Clone)]
pub struct Peer {
    pub pid: Option<u32>,
    pub image: Option<String>,
    /// Running elevated (administrator) or as SYSTEM: may weaken protection.
    pub elevated: bool,
    /// A Vigil executable from the protected install directory.
    pub trusted: bool,
}

impl Peer {
    pub fn from_pid(pid: Option<u32>) -> Self {
        let image = pid.and_then(crate::platform::image_path);
        Self {
            pid,
            trusted: crate::platform::is_trusted_client(image.as_deref()),
            elevated: pid.is_some_and(crate::platform::is_process_elevated),
            image: image.map(|p| p.display().to_string()),
        }
    }
}

#[cfg(windows)]
pub use win::Listener;

#[cfg(windows)]
mod win {
    use super::Peer;
    use sentinel_protocol::PIPE_NAME;
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::{LocalFree, HLOCAL};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

    /// Protected DACL:
    ///   SYSTEM, Administrators     -> full control
    ///   Interactive users (IU)     -> read/write only (cannot create pipe instances,
    ///                                 so a user process cannot squat the pipe name)
    /// Network logons are not in IU, and remote clients are rejected explicitly.
    const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

    struct SecurityAttributes {
        sd: PSECURITY_DESCRIPTOR,
        attrs: SECURITY_ATTRIBUTES,
    }

    impl SecurityAttributes {
        fn from_sddl(sddl: &str) -> io::Result<Self> {
            let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                sd,
                attrs: SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: sd,
                    bInheritHandle: 0,
                },
            })
        }
    }

    impl Drop for SecurityAttributes {
        fn drop(&mut self) {
            unsafe { LocalFree(self.sd as HLOCAL) };
        }
    }

    pub struct Listener {
        next: NamedPipeServer,
    }

    fn create(first: bool) -> io::Result<NamedPipeServer> {
        let mut sa = SecurityAttributes::from_sddl(PIPE_SDDL)?;
        let mut opts = ServerOptions::new();
        opts.first_pipe_instance(first) // fail if someone already owns the name
            .reject_remote_clients(true)
            .max_instances(16)
            .in_buffer_size(64 * 1024)
            .out_buffer_size(64 * 1024);
        unsafe { opts.create_with_security_attributes_raw(PIPE_NAME, &mut sa.attrs as *mut _ as *mut c_void) }
    }

    impl Listener {
        pub fn bind() -> io::Result<Self> {
            Ok(Self { next: create(true)? })
        }

        pub async fn accept(&mut self) -> io::Result<(NamedPipeServer, Peer)> {
            self.next.connect().await?;
            // Create the next instance before handing this one off, so there is
            // always a listening instance.
            let connected = std::mem::replace(&mut self.next, create(false)?);
            let mut pid = 0u32;
            let ok = unsafe { GetNamedPipeClientProcessId(connected.as_raw_handle() as _, &mut pid) } != 0;
            Ok((connected, Peer::from_pid(ok.then_some(pid))))
        }
    }
}

#[cfg(not(windows))]
pub use unix::Listener;

#[cfg(not(windows))]
mod unix {
    use super::Peer;
    use std::io;
    use tokio::net::{UnixListener, UnixStream};

    pub struct Listener {
        inner: UnixListener,
    }

    impl Listener {
        pub fn bind() -> io::Result<Self> {
            let path = sentinel_protocol::paths::unix_socket();
            let _ = std::fs::remove_file(&path);
            let inner = UnixListener::bind(&path)?;
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            Ok(Self { inner })
        }

        pub async fn accept(&mut self) -> io::Result<(UnixStream, Peer)> {
            let (s, _) = self.inner.accept().await?;
            let pid = s.peer_cred().ok().and_then(|c| c.pid()).map(|p| p as u32);
            Ok((s, Peer::from_pid(pid)))
        }
    }
}
