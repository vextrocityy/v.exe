import { useMemo, useState } from "react";
import { ActivityLog } from "../components/ActivityLog";
import { Panel } from "../components/Panel";
import type { SecurityEvent } from "../lib/types";

const FILTERS = {
  all: () => true,
  threats: (e: SecurityEvent) => ["threat_detected", "threat_quarantined", "process_blocked", "process_suspended", "behavior_alert"].includes(e.kind),
  system: (e: SecurityEvent) => ["persistence_change", "settings_changed", "signatures_updated", "service_info", "recovery"].includes(e.kind),
  privacy: (e: SecurityEvent) => e.kind === "device_access",
  scans: (e: SecurityEvent) => e.kind.startsWith("scan_"),
} as const;

export function ActivityPage({ events }: { events: SecurityEvent[] }) {
  const [filter, setFilter] = useState<keyof typeof FILTERS>("all");
  const rows = useMemo(() => events.filter(FILTERS[filter]), [events, filter]);
  return (
    <Panel
      title="Activity log"
      action={
        <div className="flex gap-1">
          {(Object.keys(FILTERS) as (keyof typeof FILTERS)[]).map((f) => (
            <button key={f} onClick={() => setFilter(f)} className={`rounded-md px-2.5 py-1 text-xs capitalize ${filter === f ? "bg-cyan-400/15 text-cyan-300" : "text-slate-400 hover:text-slate-200"}`}>
              {f}
            </button>
          ))}
        </div>
      }
    >
      <ActivityLog events={rows} />
    </Panel>
  );
}
