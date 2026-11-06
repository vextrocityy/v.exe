# Sentinel-Lite

A lightweight Windows endpoint-protection agent: a native Rust **service** that does
all detection, and a **Tauri + React** dashboard that only talks to it over a secured
named pipe. Close the dashboard and protection keeps running.

| Budget | Target | Measured (Phase 1 engine, idle, release build) |
|---|---|---|
| CPU at idle | < 1 % | ~0.2 % on Linux with the 1-second *polling* fallback; ETW on Windows is event-driven and should be lower |
| RAM | < 150 MB | ~7 MB resident engine. The WebView2 dashboard is extra and only runs while open |
| Engine binary | – | 3.7 MB (`x86_64-pc-windows-gnu`, LTO, stripped) |

## Layout

```
sentinel-lite/
├─ Cargo.toml                    workspace (engine crates build by default)
├─ signatures/core.json          bundled signature pack (EICAR test hashes)
├─ crates/
│  ├─ sentinel-protocol/         IPC message types + framing, shared by service & UI
│  └─ sentinel-service/src/
│     ├─ main.rs                 CLI: run | install | uninstall | scan <path>
│     ├─ service.rs              Windows SCM integration (auto-start, restart-on-crash)
│     ├─ app.rs                  bootstrap: logging, DB, signatures, shields, IPC
│     ├─ settings.rs             settings.json load/save + sanitisation
│     ├─ platform.rs             Win32 process/memory/priority helpers (+ Linux dev impl)
│     ├─ database/               SQLite: signatures, scan cache, events, quarantine index
│     ├─ engine/
│     │  ├─ mod.rs               Engine: detection pipeline, status, event bus
│     │  ├─ scanner.rs           multi-threaded walker + bounded hashing queue
│     │  ├─ hasher.rs            streaming SHA-256, graceful lock/permission handling
│     │  ├─ quarantine.rs        encoded vault, restore (allow-lists hash) / delete
│     │  ├─ heuristics.rs        process-lineage scoring, ransomware rate detector
│     │  ├─ targets.rs           quick / full / watch locations across all profiles
│     │  └─ realtime/            Process Guard (ETW), File Shield, Persistence Watch
│     └─ ipc/                    named-pipe server, DACL, token auth, dispatch
└─ ui/
   ├─ src/                       React + TypeScript + Tailwind 4 dashboard
   │  ├─ pages/                  Dashboard, Activity, Quarantine, Settings
   │  ├─ components/             ShieldHero, ScanPanel, ActivityLog, StatCard, …
   │  ├─ hooks/useEngine.ts      adaptive status polling + pushed events
   │  └─ lib/                    typed API, protocol types, browser mock engine
   └─ src-tauri/                 Tauri 2 shell: commands → pipe client
```

## Build & run

Prerequisites: Rust ≥ 1.80, Node ≥ 20, and on Windows the WebView2 runtime (preinstalled on Windows 11).

```powershell
# Engine
cargo build --release -p sentinel-service
cargo test  -p sentinel-service -p sentinel-protocol

# Foreground (console) mode: easiest for development; run from an elevated
# prompt so ETW and all-profile scanning work.
.\target\release\sentinel-service.exe run

# Or install as a real auto-start service (elevated):
.\target\release\sentinel-service.exe install
.\target\release\sentinel-service.exe uninstall

# One-shot scan without the service:
.\target\release\sentinel-service.exe scan C:\Users\me\Downloads

# Dashboard
cd ui
npm install
npm run tauri dev      # desktop app talking to the running service
npm run dev            # browser preview with a mock engine (no service needed)
npm run tauri build    # NSIS/MSI installer
```

**Try a detection:** save the [EICAR test string](https://www.eicar.org/download-anti-malware-testfile/)
into a file in your Downloads folder. File Shield detects and quarantines it within about 2 seconds,
and it then appears in the Quarantine page. The EICAR file is harmless by design.

Data lives in `%ProgramData%\SentinelLite\` (`sentinel.db`, `quarantine\`, `signatures\`,
`settings.json`, `logs\`). Set `SENTINEL_HOME` to override; `SENTINEL_LOG=debug` for verbose logs.

## How detection works (Phase 1)

1. **Signatures.** SHA-256 of a file → SQLite lookup (allow-list checked first). JSON packs
   in `signatures/` are imported at start-up. A `(path, size, mtime) → hash` cache makes
   re-scans of unchanged files nearly free.
2. **Process Guard.** ETW `Microsoft-Windows-Kernel-Process` ProcessStart → hash the image →
   on a match, `TerminateProcess` + quarantine. Falls back to 1 s Toolhelp polling if ETW
   cannot start, and the dashboard says so.
3. **File Shield.** `ReadDirectoryChangesW` on Downloads / Desktop / Documents / Temp / Startup
   for every profile. Files are scanned once they have been quiet for 1.5 s.
4. **Persistence Watch.** Run/RunOnce (HKLM, WOW64, every user hive), Winlogon, service
   ImagePaths and Startup folders are diffed against a baseline stored in SQLite, so changes
   made while the service was stopped are reported too. New targets are scanned.
5. **Behaviour Engine** (alerts only, never auto-kills):
   * process lineage and command-line shape (e.g. an Office app launching a script host,
     encoded PowerShell, large encoded blobs);
   * mass modification: weighted rename/modify rate across ≥ 4 folders in 10 s.

Errors are contained: locked or protected files are counted as *skipped*, a shield that
fails to start turns the status to **At Risk** instead of crashing, and the SCM restarts
the service on failure.

## Security model of the IPC channel

* Pipe `\\.\pipe\sentinel_lite_ipc` with a protected DACL: SYSTEM and Administrators get full
  control, **interactive** users read/write only. Remote clients are rejected, and users
  cannot create pipe instances, which blocks pipe-name squatting.
* First frame must carry the per-start random token from `%ProgramData%\SentinelLite\ipc.token`
  (constant-time compare, 5 s handshake timeout, 4 MB frame cap).
* The client PID and image path are logged for every connection.

Read [`docs/ROADMAP.md`](docs/ROADMAP.md) before relying on this: it lists what Phase 1 does
**not** do yet. In short, keep Microsoft Defender enabled alongside it.
