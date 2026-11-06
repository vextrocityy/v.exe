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
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
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
                    out.push(ProcessEntry { pid: e.th32ProcessID, ppid: e.th32ParentProcessID });
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
        unsafe { NtQueryInformationProcess(h.0, PROCESS_COMMAND_LINE_INFORMATION, std::ptr::null_mut(), 0, &mut needed) };
        if needed == 0 || needed > 64 * 1024 {
            return None;
        }
        // u64 backing store keeps the UNICODE_STRING header correctly aligned.
        let mut buf = vec![0u64; (needed as usize).div_ceil(8)];
        let status = unsafe {
            NtQueryInformationProcess(h.0, PROCESS_COMMAND_LINE_INFORMATION, buf.as_mut_ptr().cast(), needed, &mut needed)
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

// ===========================================================================
#[cfg(not(windows))]
mod imp {
    use super::ProcessEntry;
    use std::path::PathBuf;

    pub fn list_processes() -> Vec<ProcessEntry> {
        let Ok(dir) = std::fs::read_dir("/proc") else { return Vec::new() };
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
        std::process::Command::new("kill").args(["-9", &pid.to_string()]).status().map(|s| s.success()).unwrap_or(false)
    }

    pub fn working_set_bytes() -> Option<u64> {
        let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
        let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
        Some(pages * 4096)
    }

    pub struct BackgroundPriority;
    impl BackgroundPriority {
        pub fn enter(_enabled: bool) -> Self {
            Self
        }
    }
}
