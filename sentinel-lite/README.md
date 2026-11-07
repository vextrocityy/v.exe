# Sentinel-Lite

A lightweight Windows endpoint-protection agent: a native Rust **service** that does
all detection, and a **Tauri + React** dashboard that only talks to it over a secured
named pipe. Close the dashboard and protection keeps running.

| Budget | Target | Measured (Phase 1 engine, idle, release build) |
|---|---|---|
| CPU at idle | < 1 % | ~0.2 % on Linux with the 1-second *polling* fallback; the Windows CI smoke test enforces < 1 % with ETW |
| RAM | < 150 MB | ~7 MB resident engine on Linux; the Windows CI smoke test enforces the 150 MB budget. The WebView2 dashboard is extra |
| Engine binary | – | about 4 MB (LTO, stripped) |

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
npm run dev            # browser preview with a mock engine (no service needed)
npm run tauri dev      # (set SENTINEL_SERVICE_EXE to your built engine for UAC actions)

# Full installer with the engine bundled (Windows, PowerShell):
.\scripts\build-release.ps1
```

**Try a detection:** save the [EICAR test string](https://www.eicar.org/download-anti-malware-testfile/)
into a file in your Downloads folder. File Shield detects and quarantines it within about 2 seconds,
and it then appears in the Quarantine page. The EICAR file is harmless by design.

Data lives in `%ProgramData%\SentinelLite\` (`sentinel.db`, `quarantine\`, `signatures\`,
`settings.json`, `logs\`). Set `SENTINEL_HOME` to override; `SENTINEL_LOG=debug` for verbose logs.

## How detection works

1. **Signatures.** SHA-256 of a file → SQLite lookup (allow-list checked first). Sources:
   the bundled pack, the **official signed channel** (Ed25519-verified, rollback-protected),
   and the **community feed** (abuse.ch MalwareBazaar). Updates run every 6 h by default.
   A `(path, size, mtime) → hash` cache makes re-scans of unchanged files nearly free.
2. **Process Guard.** ETW `Microsoft-Windows-Kernel-Process` ProcessStart → hash the image →
   on a match, `TerminateProcess` + quarantine. Falls back to 1 s Toolhelp polling if ETW
   cannot start, and the dashboard says so.
3. **File Shield.** `ReadDirectoryChangesW` on Downloads / Desktop / Documents / Temp / Startup
   for every profile. Files are scanned once they have been quiet for 1.5 s.
4. **Persistence Watch.** Run/RunOnce (HKLM, WOW64, every user hive), Winlogon, service
   ImagePaths and Startup folders are diffed against a baseline stored in SQLite.
5. **Behaviour Engine** (alerts only, never auto-kills): process lineage / command-line shape,
   and ransomware-style mass modification across folders.
6. **Scheduled quick scan** every 24 h at background CPU/IO priority.

### False-positive safety

Only exact hash matches ever kill or quarantine. Hashes from the **unsigned community feed**
additionally never remediate a file under `%SystemRoot%` or one with a valid Authenticode
signature: those are reported for review instead. A restored file's hash is allow-listed.

## Security model

| Control | Implementation |
|---|---|
| Who can reach the engine | Named pipe with protected DACL (SYSTEM, Administrators, *interactive* users), remote clients rejected, users cannot create pipe instances (no squatting) |
| Which programs | When installed under Program Files, only executables **from the install directory** are accepted (a copied client elsewhere is refused) |
| Authentication | Per-start 256-bit token, constant-time compare, 5 s handshake timeout, 4 MB frame cap |
| Weakening protection | Turning shields off, adding exclusions, lowering limits, or restoring from quarantine requires an **elevated** client. The dashboard gets that through a UAC prompt that runs a single request via `sentinel-service elevated-request` |
| Data at rest | `%ProgramData%\SentinelLite` DACL: SYSTEM + Administrators only; token file additionally readable by interactive users; quarantined files XOR-encoded |
| Update integrity | Official packs must carry an Ed25519 signature from a key compiled into the build; older versions are refused |
| Resilience | Per-event panic containment, SCM restart on failure (5 s / 30 s / 120 s), corrupt DB auto-rebuilt, schema migrations, rotating logs (4 × 10 MB) |

## Operating it

```powershell
sentinel-service status            # JSON status of the running service
sentinel-service events 50         # recent security events
sentinel-service settings          # active settings
sentinel-service update            # one-off signature update
sentinel-service start | stop      # service control (admin)
```

The NSIS installer (`scripts/build-release.ps1`) installs the dashboard and service into
`C:\Program Files\Sentinel-Lite`, registers and starts the service, and starts the dashboard
in the tray at login. Uninstall removes both and keeps `%ProgramData%\SentinelLite`
(quarantine vault, logs). See [`docs/RELEASING.md`](docs/RELEASING.md) for signing keys,
publishing signature packs and code signing.

Read [`docs/ROADMAP.md`](docs/ROADMAP.md) for what is **not** covered yet. In short, this is
a user-mode product without kernel components; keep Microsoft Defender enabled alongside it.
