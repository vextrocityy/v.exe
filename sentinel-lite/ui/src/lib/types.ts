// Mirrors crates/sentinel-protocol (serde snake_case). Keep in sync.

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type ScanKind = "quick" | "full" | "custom";

export type ProtectionState =
  | "protected"
  | "threat_detected"
  | { at_risk: { reasons: string[] } };

export interface ScanProgress {
  scan_id: number;
  running: boolean;
  kind: ScanKind | null;
  files_scanned: number;
  bytes_scanned: number;
  threats_found: number;
  files_skipped: number;
  current_path: string | null;
  started_at: number | null;
  finished_at: number | null;
}

export interface ShieldStatus {
  name: string;
  enabled: boolean;
  running: boolean;
  detail: string | null;
}

export interface EngineStatus {
  protocol_version: number;
  service_version: string;
  state: ProtectionState;
  realtime_enabled: boolean;
  shields: ShieldStatus[];
  signature_count: number;
  threats_blocked_total: number;
  quarantine_count: number;
  scan: ScanProgress;
  uptime_secs: number;
  memory_bytes: number | null;
  last_signature_update: number | null;
  signature_update_error: string | null;
  update_in_progress: boolean;
  yara_rule_count: number;
  cpu_percent: number | null;
  system_memory_percent: number | null;
  network_blocked_ranges: number;
  hardening: HardeningCheck[];
}

export interface HardeningCheck {
  id: string;
  name: string;
  ok: boolean;
  detail: string;
  fixable: boolean;
}

export interface TrustedApp {
  path: string;
  sha256: string;
}

export type EventKind =
  | "threat_detected"
  | "threat_quarantined"
  | "process_blocked"
  | "process_suspended"
  | "persistence_change"
  | "behavior_alert"
  | "scan_started"
  | "scan_finished"
  | "scan_error"
  | "settings_changed"
  | "signatures_updated"
  | "service_info";

export interface SecurityEvent {
  id: number;
  timestamp: number;
  kind: EventKind;
  severity: Severity;
  title: string;
  detail: string | null;
  path: string | null;
  pid: number | null;
}

export interface QuarantineItem {
  id: string;
  original_path: string;
  sha256: string;
  threat_name: string;
  size: number;
  quarantined_at: number;
}

export interface Settings {
  realtime_protection: boolean;
  process_monitor: boolean;
  file_monitor: boolean;
  persistence_monitor: boolean;
  behavior_monitor: boolean;
  auto_kill_malicious: boolean;
  auto_quarantine: boolean;
  exclusions: string[];
  watch_paths: string[];
  max_file_size_mb: number;
  max_scan_threads: number;
  low_priority_scans: boolean;
  persistence_poll_secs: number;
  auto_update: boolean;
  update_interval_hours: number;
  community_feeds: boolean;
  /** Masked as "********" by the service; send it back unchanged to keep the stored key. */
  abusech_auth_key: string | null;
  update_url: string | null;
  scheduled_scan: boolean;
  scheduled_scan_hours: number;
  yara_enabled: boolean;
  yara_rules_feed: boolean;
  yara_min_remediate_score: number;
  yara_max_file_mb: number;
  archive_scanning: boolean;
  ransomware_decoys: boolean;
  ransomware_suspend: boolean;
  startup_cleanup: boolean;
  block_untrusted_risky: boolean;
  block_office_children: boolean;
  entropy_detection: boolean;
  network_guard: boolean;
  trusted_apps: TrustedApp[];
}

export type ProcessAction = "resume" | "terminate";

export type StateTone = "safe" | "warn" | "danger";

export function toneOf(state: ProtectionState | undefined): StateTone {
  if (!state) return "warn";
  if (state === "protected") return "safe";
  if (state === "threat_detected") return "danger";
  return "warn";
}
