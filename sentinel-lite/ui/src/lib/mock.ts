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
  update_url: null,
  scheduled_scan: true,
  scheduled_scan_hours: 24,
};
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
