// Typed bridge to the Tauri commands in src-tauri/src/lib.rs.
// Outside Tauri (plain `npm run dev` in a browser) it falls back to an
// in-memory mock engine so the UI can be developed without the service.

import type { DeviceUse, EngineStatus, Inspection, ProcessAction, QuarantineItem, RollbackPreview, ScanKind, SecurityEvent, Settings, Snapshot } from "./types";
import { mock } from "./mock";

export const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri) return mock.invoke<T>(cmd, args);
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

export const api = {
  getStatus: () => invoke<EngineStatus>("get_status"),
  startScan: (kind: ScanKind, paths?: string[]) => invoke<number>("start_scan", { kind, paths }),
  cancelScan: () => invoke<void>("cancel_scan"),
  acknowledgeThreats: () => invoke<void>("acknowledge_threats"),
  updateSignatures: () => invoke<void>("update_signatures"),
  processAction: (pid: number, action: ProcessAction) => invoke<void>("process_action", { pid, action }),
  trustApp: (path: string) => invoke<void>("trust_app", { path }),
  checkAppUpdate: () => invoke<void>("check_app_update"),
  inspectPaths: (paths: string[]) => invoke<Inspection>("inspect_paths", { paths }),
  quarantinePath: (path: string, threatName?: string) => invoke<void>("quarantine_path", { path, threatName }),
  pickFiles: () => invoke<string[]>("pick_files"),
  openVirusTotal: (sha256: string) => invoke<void>("open_virustotal", { sha256 }),
  /** File Explorer with the file selected (or its folder, if the file is gone). */
  revealPath: (path: string) => invoke<void>("reveal_path", { path }),
  /** Start the protection service (administrator approval). */
  startService: () => invoke<void>("start_service"),
  enableHardening: (id: string) => invoke<void>("enable_hardening", { id }),
  disableTask: (name: string) => invoke<void>("disable_task", { name }),
  getDeviceUsage: () => invoke<DeviceUse[]>("get_device_usage"),
  listSnapshots: () => invoke<Snapshot[]>("list_snapshots"),
  createSnapshot: () => invoke<void>("create_snapshot"),
  rollbackPreview: (snapshotId: string, folders: string[] = []) => invoke<RollbackPreview>("rollback_preview", { snapshotId, folders }),
  /** Needs administrator approval; the outcome is reported as a "recovery" event. */
  rollbackRestore: (snapshotId: string, paths: string[]) => invoke<void>("rollback_restore", { snapshotId, paths }),
  getEvents: (limit = 100, beforeId?: number) => invoke<SecurityEvent[]>("get_events", { limit, beforeId }),
  listQuarantine: () => invoke<QuarantineItem[]>("list_quarantine"),
  restoreQuarantine: (id: string) => invoke<void>("restore_quarantine", { id }),
  deleteQuarantine: (id: string) => invoke<void>("delete_quarantine", { id }),
  getSettings: () => invoke<Settings>("get_settings"),
  updateSettings: (settings: Settings) => invoke<Settings>("update_settings", { settings }),
};

/** Native file drag-and-drop (Tauri delivers real paths). Returns an unsubscribe function. */
export async function onFileDrop(handlers: { hover: (on: boolean) => void; drop: (paths: string[]) => void }): Promise<() => void> {
  if (!isTauri) return () => {};
  const { getCurrentWebview } = await import("@tauri-apps/api/webview");
  return getCurrentWebview().onDragDropEvent((e) => {
    const p = e.payload;
    if (p.type === "enter" || p.type === "over") handlers.hover(true);
    else if (p.type === "leave") handlers.hover(false);
    else if (p.type === "drop") {
      handlers.hover(false);
      if (p.paths.length) handlers.drop(p.paths);
    }
  });
}

/** Subscribe to pushed engine events. Returns an unsubscribe function. */
export async function onEngineEvent(
  onEvent: (e: SecurityEvent) => void,
  onConnection: (connected: boolean) => void,
): Promise<() => void> {
  if (!isTauri) return mock.subscribe(onEvent);
  const { listen } = await import("@tauri-apps/api/event");
  const offEvent = await listen<SecurityEvent>("sentinel://event", (e) => onEvent(e.payload));
  const offConn = await listen<boolean>("sentinel://connection", (e) => onConnection(e.payload));
  return () => {
    offEvent();
    offConn();
  };
}
