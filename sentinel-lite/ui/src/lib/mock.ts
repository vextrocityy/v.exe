// Browser-only stand-in for the engine. Never used inside the Tauri app.

import type { EngineStatus, QuarantineItem, ScanKind, SecurityEvent, Settings } from "./types";

const now = () => Math.floor(Date.now() / 1000);
let nextId = 100;
const listeners = new Set<(e: SecurityEvent) => void>();

const settings: Settings = {
  realtime_protection: true,
  process_monitor: true,
  file_monitor: true,
  persistence_monitor: true,
  behavior_monitor: true,
  auto_kill_malicious: true,
  auto_quarantine: true,
  exclusions: ["D:\\Games\\SteamLibrary"],
  watch_paths: [],
  max_file_size_mb: 256,
  max_scan_threads: 0,
  low_priority_scans: true,
  persistence_poll_secs: 30,
  auto_update: true,
  update_interval_hours: 6,
  community_feeds: true,
  abusech_auth_key: null,
  update_url: null,
  scheduled_scan: true,
  scheduled_scan_hours: 24,
  yara_enabled: true,
  yara_rules_feed: true,
  yara_min_remediate_score: 75,
  yara_max_file_mb: 32,
  archive_scanning: true,
  ransomware_decoys: true,
  ransomware_suspend: true,
  startup_cleanup: true,
  block_untrusted_risky: true,
  block_office_children: true,
  entropy_detection: true,
  network_guard: true,
  trusted_apps: [{ path: "C:\\Users\\alex\\Downloads\\tools\\putty.exe", sha256: "9f".repeat(32) }],
};
let lsaOn = false;
let lastUpdate = now() - 3 * 3600;
let updating = false;

let quarantine: QuarantineItem[] = [
  {
    id: "4f1c9a0b7e2d",
    original_path: "C:\\Users\\alex\\Downloads\\invoice_2026.pdf.exe",
    sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    threat_name: "EICAR-Test-File",
    size: 68,
    quarantined_at: now() - 5400,
  },
];

const events: SecurityEvent[] = [
  { id: 6, timestamp: now() - 300, kind: "process_blocked", severity: "high", title: "Blocked unsigned program from Downloads", detail: "Execution Guard stops programs without a valid digital signature when they start from Downloads, where malware usually lands. If you trust it, choose Always allow.", path: "C:\\Users\\alex\\Downloads\\cool-tool.exe", pid: 9120 },
  { id: 5, timestamp: now() - 600, kind: "process_suspended", severity: "critical", title: "Suspended encryptor.exe", detail: "It wrote 48.2 MB in 1 second right after the decoy changed. It is frozen, not killed: choose Terminate (and quarantine it) or Resume in Activity.", path: "C:\\Users\\alex\\AppData\\Local\\Temp\\encryptor.exe", pid: 7344 },
  { id: 4, timestamp: now() - 601, kind: "behavior_alert", severity: "critical", title: "Ransomware behaviour: a decoy file was changed", detail: "A hidden decoy file was modified. Legitimate programs never touch it.", path: "C:\\Users\\alex\\Documents\\!_Accounts_2026.xlsx", pid: null },
  { id: 3, timestamp: now() - 5400, kind: "threat_quarantined", severity: "info", title: "EICAR-Test-File moved to quarantine", detail: null, path: quarantine[0].original_path, pid: null },
  { id: 2, timestamp: now() - 5401, kind: "threat_detected", severity: "high", title: "EICAR-Test-File detected", detail: "Found by File Shield", path: quarantine[0].original_path, pid: null },
  { id: 1, timestamp: now() - 7200, kind: "service_info", severity: "info", title: "Sentinel-Lite engine started", detail: "2 signatures loaded", path: null, pid: null },
];

const scan = {
  scan_id: 0, running: false, kind: null as ScanKind | null, files_scanned: 0, bytes_scanned: 0,
  threats_found: 0, files_skipped: 0, current_path: null as string | null, started_at: null as number | null, finished_at: null as number | null,
};
let timer: ReturnType<typeof setInterval> | undefined;

function push(e: Omit<SecurityEvent, "id" | "timestamp">) {
  const ev = { ...e, id: nextId++, timestamp: now() };
  events.unshift(ev);
  listeners.forEach((l) => l(ev));
}

function status(): EngineStatus {
  return {
    protocol_version: 1,
    service_version: "0.1.0-mock",
    state: settings.realtime_protection ? "protected" : { at_risk: { reasons: ["Real-time protection is turned off"] } },
    realtime_enabled: settings.realtime_protection,
    shields: [
      { name: "Process Guard", enabled: settings.process_monitor, running: settings.realtime_protection && settings.process_monitor, detail: "ETW: Microsoft-Windows-Kernel-Process" },
      { name: "File Shield", enabled: settings.file_monitor, running: settings.realtime_protection && settings.file_monitor, detail: "Watching 9 folder(s)" },
      { name: "Persistence Watch", enabled: settings.persistence_monitor, running: settings.realtime_protection && settings.persistence_monitor, detail: "Checking autostart locations every 30 s" },
      { name: "Behavior Engine", enabled: settings.behavior_monitor, running: settings.realtime_protection && settings.behavior_monitor, detail: "Process lineage + mass file-modification detection" },
      { name: "YARA Rules", enabled: settings.yara_enabled, running: settings.yara_enabled, detail: "5134 rules (precompiled)" },
      { name: "Network Guard", enabled: settings.network_guard, running: settings.realtime_protection && settings.network_guard, detail: "Blocking 1489 malicious IP ranges (Spamhaus DROP + your list)" },
    ],
    signature_count: 48213,
    threats_blocked_total: 3,
    quarantine_count: quarantine.length,
    scan: { ...scan },
    uptime_secs: 7260,
    memory_bytes: 9 * 1024 * 1024,
    last_signature_update: lastUpdate,
    signature_update_error: null,
    update_in_progress: updating,
    yara_rule_count: settings.yara_enabled ? 5134 : 0,
    cpu_percent: 0.1 + Math.random() * 0.3,
    system_memory_percent: 41 + Math.random() * 2,
    network_blocked_ranges: settings.network_guard ? 1489 : 0,
    hardening: [
      { id: "lsa_protection", name: "LSA protection (credential theft)", ok: lsaOn, detail: lsaOn ? "LSASS runs as a protected process." : "Off. Turning it on stops tools like Mimikatz from reading passwords out of LSASS memory. Takes effect after a restart.", fixable: !lsaOn },
      { id: "firewall", name: "Windows Firewall", ok: true, detail: "On for all network profiles.", fixable: false },
      { id: "uac", name: "User Account Control", ok: true, detail: "On: programs need approval to get administrator rights.", fixable: false },
    ],
  };
}

function startScan(kind: ScanKind) {
  if (scan.running) throw new Error("a scan is already running");
  Object.assign(scan, { scan_id: scan.scan_id + 1, running: true, kind, files_scanned: 0, bytes_scanned: 0, threats_found: 0, files_skipped: 0, started_at: now(), finished_at: null });
  push({ kind: "scan_started", severity: "info", title: `${kind[0].toUpperCase()}${kind.slice(1)} scan started`, detail: null, path: null, pid: null });
  const total = kind === "full" ? 60000 : 9000;
  timer = setInterval(() => {
    scan.files_scanned += 450 + Math.floor(Math.random() * 300);
    scan.bytes_scanned += 40_000_000;
    scan.files_skipped += Math.random() < 0.3 ? 1 : 0;
    scan.current_path = `C:\\Users\\alex\\AppData\\Local\\Package${Math.floor(Math.random() * 999)}\\cache.bin`;
    if (scan.files_scanned >= total) finishScan(false);
  }, 200);
  return scan.scan_id;
}

function finishScan(cancelled: boolean) {
  clearInterval(timer);
  Object.assign(scan, { running: false, finished_at: now(), current_path: null });
  push({ kind: "scan_finished", severity: "info", title: `Scan ${cancelled ? "cancelled" : "complete"}: 0 threat(s)`, detail: `${scan.files_scanned} files scanned, ${scan.files_skipped} skipped`, path: null, pid: null });
}

export const mock = {
  async invoke<T>(cmd: string, args: Record<string, unknown> = {}): Promise<T> {
    await new Promise((r) => setTimeout(r, 60));
    const r = ((): unknown => {
      switch (cmd) {
        case "get_status": return status();
        case "start_scan": return startScan(args.kind as ScanKind);
        case "cancel_scan": return scan.running ? finishScan(true) : undefined;
        case "acknowledge_threats": return undefined;
        case "trust_app":
          settings.trusted_apps = [...settings.trusted_apps, { path: args.path as string, sha256: "ab".repeat(32) }];
          return undefined;
        case "enable_hardening":
          lsaOn = true;
          return undefined;
        case "process_action":
          push({ kind: args.action === "terminate" ? "process_blocked" : "service_info", severity: "high", title: args.action === "terminate" ? "Process terminated by user" : "Process resumed by user", detail: null, path: null, pid: args.pid as number });
          return undefined;
        case "update_signatures":
          updating = true;
          setTimeout(() => {
            updating = false;
            lastUpdate = now();
            push({ kind: "signatures_updated", severity: "info", title: "Signatures updated: 412 new", detail: "MalwareBazaar: 412 hashes", path: null, pid: null });
          }, 1500);
          return undefined;
        case "get_events": return events.slice(0, (args.limit as number) ?? 100);
        case "list_quarantine": return quarantine;
        case "restore_quarantine":
        case "delete_quarantine":
          quarantine = quarantine.filter((q) => q.id !== args.id);
          push({ kind: "service_info", severity: cmd === "restore_quarantine" ? "medium" : "info", title: cmd === "restore_quarantine" ? "File restored from quarantine" : "Quarantined file permanently deleted", detail: null, path: null, pid: null });
          return undefined;
        case "get_settings": return { ...settings };
        case "update_settings": Object.assign(settings, args.settings); return { ...settings };
        default: throw new Error(`mock: unknown command ${cmd}`);
      }
    })();
    return r as T;
  },
  subscribe(fn: (e: SecurityEvent) => void): () => void {
    listeners.add(fn);
    return () => listeners.delete(fn);
  },
};
