// Typed bridge to the Tauri commands in src-tauri/src/lib.rs.
// Outside Tauri (plain `npm run dev` in a browser) it falls back to an
// in-memory mock engine so the UI can be developed without the service.

import type { EngineStatus, QuarantineItem, ScanKind, SecurityEvent, Settings } from "./types";
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
  getEvents: (limit = 100, beforeId?: number) => invoke<SecurityEvent[]>("get_events", { limit, beforeId }),
  listQuarantine: () => invoke<QuarantineItem[]>("list_quarantine"),
  restoreQuarantine: (id: string) => invoke<void>("restore_quarantine", { id }),
  deleteQuarantine: (id: string) => invoke<void>("delete_quarantine", { id }),
  getSettings: () => invoke<Settings>("get_settings"),
  updateSettings: (settings: Settings) => invoke<Settings>("update_settings", { settings }),
};

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
