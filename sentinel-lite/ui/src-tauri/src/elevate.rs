//! Privileged actions (anything that weakens protection) need an elevated
//! client. Rather than running the whole dashboard as administrator, we hand
//! that single request to `sentinel-service.exe elevated-request <hex>`
//! through a UAC prompt, the same pattern Windows Security uses.

use sentinel_protocol::Request;
use std::path::PathBuf;

fn service_exe() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os("SENTINEL_SERVICE_EXE") {
        return Ok(PathBuf::from(p)); // dev builds
    }
    let exe_name = if cfg!(windows) {
        "sentinel-service.exe"
    } else {
        "sentinel-service"
    };
    let p = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .with_file_name(exe_name);
    if p.exists() {
        Ok(p)
    } else {
        Err(format!("{} not found next to the dashboard", p.display()))
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Run `req` elevated. Blocks until the user answers the UAC prompt and the request completes.
pub fn run(req: &Request) -> Result<(), String> {
    let payload = to_hex(&serde_json::to_vec(req).map_err(|e| e.to_string())?);
    if payload.len() > 30_000 {
        return Err("request too large to elevate".into());
    }
    platform::run_elevated(&service_exe()?, &format!("elevated-request {payload}"))
}

#[cfg(windows)]
mod platform {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_CANCELLED};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    pub fn run_elevated(exe: &Path, args: &str) -> Result<(), String> {
        let verb = wide("runas".as_ref());
        let file = wide(exe.as_os_str());
        let params = wide(args.as_ref());
        unsafe {
            let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
            info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOCLOSEPROCESS;
            info.lpVerb = verb.as_ptr();
            info.lpFile = file.as_ptr();
            info.lpParameters = params.as_ptr();
            info.nShow = SW_HIDE;
            if ShellExecuteExW(&mut info) == 0 {
                return Err(if GetLastError() == ERROR_CANCELLED {
                    "Administrator approval was declined.".into()
                } else {
                    format!("Could not request administrator approval (error {}).", GetLastError())
                });
            }
            if info.hProcess.is_null() {
                return Err("elevated helper did not start".into());
            }
            WaitForSingleObject(info.hProcess, 120_000);
            let mut code = 1u32;
            GetExitCodeProcess(info.hProcess, &mut code);
            CloseHandle(info.hProcess);
            if code == 0 {
                Ok(())
            } else {
                Err("The protected change was rejected by the service.".into())
            }
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use std::path::Path;

    /// Dev hosts: the service treats same-user clients as elevated, so this is never needed.
    pub fn run_elevated(_exe: &Path, _args: &str) -> Result<(), String> {
        Err("elevation is only supported on Windows".into())
    }
}
