# Limitations & roadmap

Phase 1 is a solid, user-mode foundation. It is **not yet** at the level of Defender or
Malwarebytes, and this document is explicit about the gaps so nobody relies on it beyond
what it does.

## Known limitations (Phase 1)

| Area | Today | Why it matters |
|---|---|---|
| Signature coverage | Only the bundled EICAR pack; no update feed | Hash signatures detect nothing until a real feed is wired in (Phase 2). |
| Pre-execution blocking | Processes are checked *as* they start (ETW), then killed | Malware gets milliseconds of execution. True blocking needs a kernel callback. |
| File writes | Seen after the fact (`ReadDirectoryChangesW`), no writer PID | Ransomware alerts cannot name or stop the process yet. |
| Tamper protection | Service can be stopped by an administrator; files are not protected | Malware running as admin can disable it. |
| IPC authorisation | Any interactive user who can read the token can change settings | Settings changes should require elevation. |
| Detection breadth | Hashes + a few behavioural rules | No YARA/static analysis, no script (AMSI) inspection, no cloud reputation. |
| Quarantine vault ACL | Inherits `%ProgramData%` defaults | Should be SYSTEM/Admins only. |

## Phase 2: hardening (user mode)

- [ ] **Signature updates**: signed pack downloads (e.g. abuse.ch MalwareBazaar exports),
      verified with an embedded Ed25519 public key before import.
- [ ] **YARA scanning** of new executables via `yara-x` (pure Rust), with rule packs signed like signatures.
- [ ] **AMSI provider** DLL so PowerShell/VBScript/JScript content is inspected *after* de-obfuscation.
- [ ] **ETW file I/O + network** providers to attribute mass-modification to a PID and suspend it.
- [ ] **Authenticode** checks (`WinVerifyTrust`): trust signed binaries from known publishers and
      require the dashboard to be signed by us before the pipe accepts it.
- [ ] Settings changes that **weaken** protection require an elevated client (check the client token).
- [ ] Explicit DACLs on `%ProgramData%\SentinelLite` (vault + DB SYSTEM-only, token readable by IU).
- [ ] Canary (decoy) files in Documents for high-confidence ransomware detection.
- [ ] `RegNotifyChangeKeyValue` instead of polling for Persistence Watch.
- [ ] Scheduled Tasks and WMI event subscriptions as persistence sources.

## Phase 3: kernel components (needs EV certificate + Microsoft attestation signing)

- [ ] **File-system minifilter**: scan on `IRP_MJ_CREATE` for execute access, block writes inline.
- [ ] `PsSetCreateProcessNotifyRoutineEx`: deny process creation before the first instruction runs.
- [ ] `ObRegisterCallbacks`: strip terminate rights on our service process (self-protection).
- [ ] ELAM driver so the service can launch as a **Protected Process Light** (anti-malware).

## Performance guardrails to keep

- Bounded queues everywhere (scan queue 2 048 paths, event channel 4 096, pending-file map 10 000).
- SQLite page cache capped at ~8 MB; event journal trimmed to 20 000 rows.
- Scan workers run in `THREAD_MODE_BACKGROUND_BEGIN` (low CPU *and* I/O priority).
- The dashboard polls every 3 s at idle and every 0.5 s only while a scan runs.
