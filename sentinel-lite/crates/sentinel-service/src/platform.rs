//! Thin OS abstraction. Windows uses Win32 directly (windows-sys, no wrappers);
//! the non-Windows implementations exist so the engine can be developed and
//! tested on Linux/macOS CI.

use std::path::PathBuf;

#[derive(Debug, Clone, Copy)]
pub struct ProcessEntry {
    pub pid: u32,
    pub ppid: u32,
}

pub use imp::*;

/// Executables of all running processes (deduplicated), for quick scans.
pub fn running_process_images() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = list_processes().into_iter().filter_map(|p| image_path(p.pid)).collect();
    v.sort();
    v.dedup();
    v
}

// ===========================================================================
#[cfg(windows)]
mod imp {
    use super::ProcessEntry;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::ffi::OsStringExt;
    use std::path::Path;
    use std::path::PathBuf;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
        WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
        WTD_UI_NONE,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, GetTokenInformation, TokenElevation, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, OpenProcess, QueryFullProcessImageNameW, SetThreadPriority,
        TerminateProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
        THREAD_MODE_BACKGROUND_BEGIN, THREAD_MODE_BACKGROUND_END,
    };

    /// RAII process handle.
    struct Handle(HANDLE);
    impl Handle {
        fn open(access: u32, pid: u32) -> Option<Self> {
            let h = unsafe { OpenProcess(access, 0, pid) };
            (!h.is_null()).then_some(Self(h))
        }
    }
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    pub fn list_processes() -> Vec<ProcessEntry> {
        let mut out = Vec::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return out;
            }
            let mut e: PROCESSENTRY32W = std::mem::zeroed();
            e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snap, &mut e) != 0 {
                loop {
                    out.push(ProcessEntry {
                        pid: e.th32ProcessID,
                        ppid: e.th32ParentProcessID,
                    });
                    if Process32NextW(snap, &mut e) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
        }
        out
    }

    pub fn image_path(pid: u32) -> Option<PathBuf> {
        if pid <= 4 {
            return None; // Idle / System
        }
        let h = Handle::open(PROCESS_QUERY_LIMITED_INFORMATION, pid)?;
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = unsafe { QueryFullProcessImageNameW(h.0, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) };
        (ok != 0).then(|| PathBuf::from(std::ffi::OsString::from_wide(&buf[..len as usize])))
    }

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *const u16,
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtQueryInformationProcess(h: HANDLE, class: u32, info: *mut c_void, len: u32, ret_len: *mut u32) -> i32;
    }
    const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;

    /// Command line of another process (Windows 8.1+), via ProcessCommandLineInformation.
    pub fn command_line(pid: u32) -> Option<String> {
        let h = Handle::open(PROCESS_QUERY_LIMITED_INFORMATION, pid)?;
        let mut needed = 0u32;
        unsafe {
            NtQueryInformationProcess(
                h.0,
                PROCESS_COMMAND_LINE_INFORMATION,
                std::ptr::null_mut(),
                0,
                &mut needed,
            )
        };
        if needed == 0 || needed > 64 * 1024 {
            return None;
        }
        // u64 backing store keeps the UNICODE_STRING header correctly aligned.
        let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
        let status = unsafe {
            NtQueryInformationProcess(
                h.0,
                PROCESS_COMMAND_LINE_INFORMATION,
                buf.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        if status < 0 {
            return None;
        }
        let us = unsafe { &*(buf.as_ptr() as *const UnicodeString) };
        if us.buffer.is_null() || us.length == 0 {
            return None;
        }
        let chars = unsafe { std::slice::from_raw_parts(us.buffer, us.length as usize / 2) };
        Some(String::from_utf16_lossy(chars))
    }

    pub fn terminate(pid: u32) -> bool {
        match Handle::open(PROCESS_TERMINATE, pid) {
            Some(h) => unsafe { TerminateProcess(h.0, 1) != 0 },
            None => false,
        }
    }

    pub fn working_set_bytes() -> Option<u64> {
        unsafe {
            let mut c: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
            c.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            (GetProcessMemoryInfo(GetCurrentProcess(), &mut c, c.cb) != 0).then_some(c.WorkingSetSize as u64)
        }
    }

    fn wide(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    /// Embedded Authenticode signature that chains to a trusted root.
    /// Revocation is not checked online (fast, works offline). Catalog-signed
    /// system files report false here; callers treat %SystemRoot% separately.
    pub fn has_valid_signature(path: &Path) -> bool {
        let file = wide(path);
        unsafe {
            let mut info: WINTRUST_FILE_INFO = std::mem::zeroed();
            info.cbStruct = std::mem::size_of::<WINTRUST_FILE_INFO>() as u32;
            info.pcwszFilePath = file.as_ptr();
            let mut data: WINTRUST_DATA = std::mem::zeroed();
            data.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
            data.dwUIChoice = WTD_UI_NONE;
            data.fdwRevocationChecks = WTD_REVOKE_NONE;
            data.dwUnionChoice = WTD_CHOICE_FILE;
            data.Anonymous.pFile = &mut info;
            data.dwStateAction = WTD_STATEACTION_VERIFY;
            data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
            let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            let status = WinVerifyTrust(std::ptr::null_mut(), &mut action, &mut data as *mut _ as *mut c_void);
            data.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(std::ptr::null_mut(), &mut action, &mut data as *mut _ as *mut c_void);
            status == 0
        }
    }

    /// Is `pid` running with an elevated (administrator) or SYSTEM token?
    pub fn is_process_elevated(pid: u32) -> bool {
        let Some(h) = Handle::open(PROCESS_QUERY_LIMITED_INFORMATION, pid) else {
            return false;
        };
        unsafe {
            let mut token: HANDLE = std::ptr::null_mut();
            if OpenProcessToken(h.0, TOKEN_QUERY, &mut token) == 0 {
                return false;
            }
            let token = Handle(token);
            let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
            let mut len = 0u32;
            let ok = GetTokenInformation(
                token.0,
                TokenElevation,
                &mut elevation as *mut _ as *mut c_void,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut len,
            );
            ok != 0 && elevation.TokenIsElevated != 0
        }
    }

    /// Replace the DACL on `path` with the one described by `sddl` (protected:
    /// no inheritance from the parent; inheritable ACEs flow to children).
    pub fn set_dacl(path: &Path, sddl: &str) -> std::io::Result<()> {
        let sddl_w: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let target = wide(path);
        unsafe {
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_w.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let (mut present, mut defaulted) = (0i32, 0i32);
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let got = GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted);
            let rc = if got != 0 && present != 0 {
                SetNamedSecurityInfoW(
                    target.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    dacl,
                    std::ptr::null_mut(),
                )
            } else {
                1 // ERROR_INVALID_FUNCTION
            };
            LocalFree(sd as HLOCAL);
            if rc == 0 {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(rc as i32))
            }
        }
    }

    /// Data directory (DB, quarantine vault, logs): SYSTEM + Administrators only.
    pub fn harden_data_dir(dir: &Path) -> std::io::Result<()> {
        set_dacl(dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
    }

    /// IPC token: additionally readable by interactive users so the dashboard can connect.
    pub fn harden_token_file(path: &Path) -> std::io::Result<()> {
        set_dacl(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;IU)")
    }

    /// CPU time (user + kernel) consumed by this process so far.
    pub fn own_cpu_time() -> Option<std::time::Duration> {
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::Threading::GetProcessTimes;
        unsafe {
            let (mut c, mut e, mut k, mut u): (FILETIME, FILETIME, FILETIME, FILETIME) = std::mem::zeroed();
            if GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) == 0 {
                return None;
            }
            let t = |f: FILETIME| ((f.dwHighDateTime as u64) << 32) | f.dwLowDateTime as u64;
            Some(std::time::Duration::from_nanos((t(k) + t(u)) * 100))
        }
    }

    pub fn system_memory_percent() -> Option<f32> {
        use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
        unsafe {
            let mut m: MEMORYSTATUSEX = std::mem::zeroed();
            m.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
            (GlobalMemoryStatusEx(&mut m) != 0).then_some(m.dwMemoryLoad as f32)
        }
    }

    fn reg_dword(path: &str, name: &str) -> Option<u32> {
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
        winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
            .open_subkey_with_flags(path, KEY_READ)
            .ok()?
            .get_value(name)
            .ok()
    }

    /// Windows features that cover what a user-mode engine cannot: LSASS
    /// memory protection, the firewall, and UAC.
    pub fn hardening_checks() -> Vec<sentinel_protocol::HardeningCheck> {
        use sentinel_protocol::HardeningCheck;
        let lsa = reg_dword(r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL").unwrap_or(0);
        let fw: Vec<bool> = ["DomainProfile", "StandardProfile", "PublicProfile"]
            .iter()
            .map(|p| {
                reg_dword(
                    &format!(r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{p}"),
                    "EnableFirewall",
                )
                .unwrap_or(1)
                    == 1
            })
            .collect();
        let uac = reg_dword(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA",
        )
        .unwrap_or(1);
        vec![
            HardeningCheck {
                id: "lsa_protection".into(),
                name: "LSA protection (credential theft)".into(),
                ok: lsa == 1 || lsa == 2,
                detail: if lsa == 1 || lsa == 2 {
                    "LSASS runs as a protected process: credential-dumping tools cannot read its memory.".into()
                } else {
                    "Off. Turning it on stops tools like Mimikatz from reading passwords out of LSASS memory. Takes effect after a restart.".into()
                },
                fixable: !(lsa == 1 || lsa == 2),
            },
            HardeningCheck {
                id: "firewall".into(),
                name: "Windows Firewall".into(),
                ok: fw.iter().all(|x| *x),
                detail: if fw.iter().all(|x| *x) {
                    "On for all network profiles.".into()
                } else {
                    "Off for at least one network profile (Windows Security → Firewall).".into()
                },
                fixable: false,
            },
            HardeningCheck {
                id: "uac".into(),
                name: "User Account Control".into(),
                ok: uac == 1,
                detail: if uac == 1 {
                    "On: programs need approval to get administrator rights.".into()
                } else {
                    "Off: every program runs with full rights.".into()
                },
                fixable: false,
            },
        ]
    }

    /// Switch on a fixable hardening feature (requires SYSTEM / admin).
    pub fn enable_hardening(id: &str) -> anyhow::Result<String> {
        use winreg::enums::HKEY_LOCAL_MACHINE;
        match id {
            "lsa_protection" => {
                let (key, _) = winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
                    .create_subkey(r"SYSTEM\CurrentControlSet\Control\Lsa")?;
                key.set_value("RunAsPPL", &1u32)?;
                Ok("LSA protection enabled. Restart Windows to apply it.".into())
            }
            other => anyhow::bail!("{other} cannot be changed automatically"),
        }
    }

    /// Total bytes written by `pid` since it started.
    pub fn write_bytes(pid: u32) -> Option<u64> {
        use windows_sys::Win32::System::Threading::{GetProcessIoCounters, IO_COUNTERS};
        let h = Handle::open(PROCESS_QUERY_LIMITED_INFORMATION, pid)?;
        let mut c: IO_COUNTERS = unsafe { std::mem::zeroed() };
        (unsafe { GetProcessIoCounters(h.0, &mut c) } != 0).then_some(c.WriteTransferCount)
    }

    #[link(name = "ntdll")]
    extern "system" {
        fn NtSuspendProcess(h: HANDLE) -> i32;
        fn NtResumeProcess(h: HANDLE) -> i32;
    }

    /// Freeze every thread of `pid` (reversible with `resume`).
    pub fn suspend(pid: u32) -> bool {
        use windows_sys::Win32::System::Threading::PROCESS_SUSPEND_RESUME;
        match Handle::open(PROCESS_SUSPEND_RESUME, pid) {
            Some(h) => unsafe { NtSuspendProcess(h.0) >= 0 },
            None => false,
        }
    }

    pub fn resume(pid: u32) -> bool {
        use windows_sys::Win32::System::Threading::PROCESS_SUSPEND_RESUME;
        match Handle::open(PROCESS_SUSPEND_RESUME, pid) {
            Some(h) => unsafe { NtResumeProcess(h.0) >= 0 },
            None => false,
        }
    }

    /// Hidden + system: invisible in Explorer by default (decoy files).
    pub fn hide_file(path: &Path) {
        use windows_sys::Win32::Storage::FileSystem::{
            SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM,
        };
        let w = wide(path);
        unsafe { SetFileAttributesW(w.as_ptr(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) };
    }

    pub fn unhide_file(path: &Path) {
        use windows_sys::Win32::Storage::FileSystem::{SetFileAttributesW, FILE_ATTRIBUTE_NORMAL};
        let w = wide(path);
        unsafe { SetFileAttributesW(w.as_ptr(), FILE_ATTRIBUTE_NORMAL) };
    }

    /// Background mode lowers CPU *and* I/O priority for the current thread,
    /// so scans yield to the user's foreground work.
    pub struct BackgroundPriority(bool);
    impl BackgroundPriority {
        pub fn enter(enabled: bool) -> Self {
            let on = enabled && unsafe { SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN) } != 0;
            Self(on)
        }
    }
    impl Drop for BackgroundPriority {
        fn drop(&mut self) {
            if self.0 {
                unsafe { SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_END) };
            }
        }
    }
}

/// Is `client` a trusted Sentinel-Lite component? When the service runs from a
/// protected install location (Program Files, writable only by administrators),
/// clients must be executables from that same directory. Dev builds running from
/// anywhere else skip the check (and log that they do).
pub fn is_trusted_client(client_image: Option<&std::path::Path>) -> bool {
    let Some(install_dir) = install_dir().filter(|d| is_protected_dir(d)) else {
        return true;
    };
    client_image
        .and_then(|p| p.parent())
        .is_some_and(|d| d.to_string_lossy().eq_ignore_ascii_case(&install_dir.to_string_lossy()))
}

/// Directory containing the service executable.
pub fn install_dir() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(|p| p.to_path_buf())
}

/// Under Program Files (Windows). Never true elsewhere.
pub fn is_protected_dir(dir: &std::path::Path) -> bool {
    if !cfg!(windows) {
        return false;
    }
    let d = dir.to_string_lossy();
    ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]
        .iter()
        .filter_map(|v| std::env::var(v).ok())
        .any(|pf| crate::util::path_within(&d, &pf))
}

// ===========================================================================
#[cfg(not(windows))]
mod imp {
    use super::ProcessEntry;
    use std::path::PathBuf;

    pub fn list_processes() -> Vec<ProcessEntry> {
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        dir.flatten()
            .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
            .filter_map(|pid| {
                let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
                // Field 4 (ppid) comes after the parenthesised command name.
                let rest = &stat[stat.rfind(')')? + 2..];
                let ppid = rest.split_whitespace().nth(1)?.parse().ok()?;
                Some(ProcessEntry { pid, ppid })
            })
            .collect()
    }

    pub fn image_path(pid: u32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }

    pub fn command_line(pid: u32) -> Option<String> {
        let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        Some(String::from_utf8_lossy(&raw).replace('\0', " ").trim().to_string())
    }

    pub fn terminate(pid: u32) -> bool {
        std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    pub fn working_set_bytes() -> Option<u64> {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some(pages * 4096)
    }

    pub fn has_valid_signature(_path: &std::path::Path) -> bool {
        false
    }

    pub fn own_cpu_time() -> Option<std::time::Duration> {
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        let rest = &stat[stat.rfind(')')? + 2..];
        let f: Vec<&str> = rest.split_whitespace().collect();
        let ticks: u64 = f.get(11)?.parse::<u64>().ok()? + f.get(12)?.parse::<u64>().ok()?;
        Some(std::time::Duration::from_millis(ticks * 10)) // USER_HZ = 100
    }

    pub fn system_memory_percent() -> Option<f32> {
        let info = std::fs::read_to_string("/proc/meminfo").ok()?;
        let get = |k: &str| {
            info.lines()
                .find(|l| l.starts_with(k))?
                .split_whitespace()
                .nth(1)?
                .parse::<f32>()
                .ok()
        };
        let (total, avail) = (get("MemTotal:")?, get("MemAvailable:")?);
        Some((1.0 - avail / total) * 100.0)
    }

    pub fn hardening_checks() -> Vec<sentinel_protocol::HardeningCheck> {
        Vec::new()
    }

    pub fn enable_hardening(id: &str) -> anyhow::Result<String> {
        anyhow::bail!("{id}: hardening changes are Windows-only")
    }

    pub fn write_bytes(pid: u32) -> Option<u64> {
        let io = std::fs::read_to_string(format!("/proc/{pid}/io")).ok()?;
        // `wchar` counts bytes passed to write(), including page-cache writes.
        io.lines()
            .find_map(|l| l.strip_prefix("wchar:"))
            .and_then(|v| v.trim().parse().ok())
    }

    fn signal(pid: u32, sig: &str) -> bool {
        std::process::Command::new("kill")
            .args([sig, &pid.to_string()])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    pub fn suspend(pid: u32) -> bool {
        signal(pid, "-STOP")
    }

    pub fn resume(pid: u32) -> bool {
        signal(pid, "-CONT")
    }

    pub fn hide_file(_path: &std::path::Path) {}

    pub fn unhide_file(_path: &std::path::Path) {}

    /// Dev hosts: root, or the same user the service runs as.
    pub fn is_process_elevated(pid: u32) -> bool {
        use std::os::unix::fs::MetadataExt;
        let uid_of = |p: &str| std::fs::metadata(p).map(|m| m.uid()).ok();
        match (uid_of(&format!("/proc/{pid}")), uid_of("/proc/self")) {
            (Some(client), Some(me)) => client == 0 || client == me,
            _ => false,
        }
    }

    pub fn harden_data_dir(dir: &std::path::Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
    }

    pub fn harden_token_file(path: &std::path::Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
    }

    pub struct BackgroundPriority;
    impl BackgroundPriority {
        pub fn enter(_enabled: bool) -> Self {
            Self
        }
    }
}
