# Limitations & roadmap

Phase 1 is a solid, user-mode foundation. It is **not yet** at the level of Defender or
Malwarebytes, and this document is explicit about the gaps so nobody relies on it beyond
what it does.

## Done in the hardening pass

- [x] Signature updates: Ed25519-signed official packs with rollback protection + MalwareBazaar community feed, every 6 h
- [x] False-positive safety: community hashes never remediate system or validly code-signed files
- [x] Elevation (UAC) required for any change that weakens protection, and for quarantine restore
- [x] IPC clients restricted to the install directory; data directory DACL SYSTEM/Administrators only
- [x] Scheduled quick scans; per-event panic containment; SCM restart on failure
- [x] Corrupt-database recovery, schema migrations, rotating logs
- [x] Installer (NSIS, per-machine) that installs, upgrades and removes the service; tray app with notifications
- [x] YARA scanning (YARA-X) with the YARA Forge core package, score-based remediation, verdict cache, child-process compilation
- [x] Windows CI: real service install + ETW/File Shield/Process Guard/elevation smoke test + installer install/uninstall

## Known limitations

| Area | Today | Why it matters |
|---|---|---|
| Pre-execution blocking | Processes are checked *as* they start (ETW), then killed | Malware gets milliseconds of execution. True blocking needs a kernel callback. |
| File writes | Seen after the fact (`ReadDirectoryChangesW`), no writer PID | Ransomware alerts cannot name or stop the process yet. |
| Tamper protection | An administrator (or malware running as one) can stop the service | Needs a protected process (ELAM + PPL). |
| Detection breadth | Hashes + YARA rules + behavioural rules | Variants of known families are caught; genuinely novel malware that no rule describes, fileless/in-memory attacks and obfuscated scripts (no AMSI yet) are not. No cloud reputation. |
| Official signature content | The channel and signing exist, but there is no threat-research team producing packs | The community feed is the only real-world source out of the box. |
| Catalog-signed files | Authenticode check reads embedded signatures only | Mitigated by the `%SystemRoot%` rule for community hashes. |
| Code signing | Not configured (needs your certificate) | See docs/RELEASING.md. |

## Phase 2: next user-mode steps

- [ ] Signed official YARA rule packs (same Ed25519 channel as hash packs).
- [ ] YARA scanning of process memory for running processes (catches packed / fileless payloads).
- [ ] **AMSI provider** DLL so PowerShell/VBScript/JScript content is inspected after de-obfuscation.
- [ ] **ETW file I/O + network** providers to attribute mass modification to a PID and suspend it.
- [ ] Signed allow-list packs (retract false positives centrally).
- [ ] Canary (decoy) files in Documents for high-confidence ransomware detection.
- [ ] `RegNotifyChangeKeyValue` instead of polling; Scheduled Tasks + WMI subscriptions as persistence sources.
- [ ] Dashboard auto-update (Tauri updater) for the UI and engine.

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
