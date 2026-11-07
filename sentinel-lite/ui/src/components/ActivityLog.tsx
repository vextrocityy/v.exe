import { Activity, AlertOctagon, Ban, Bug, DownloadCloud, FileWarning, Info, KeyRound, Lock, ScanLine, Settings2 } from "lucide-react";
import type { EventKind, SecurityEvent, Severity } from "../lib/types";
import { shortPath, timeAgo } from "../lib/format";

const KIND_ICON: Record<EventKind, typeof Info> = {
  threat_detected: Bug,
  threat_quarantined: Lock,
  process_blocked: Ban,
  persistence_change: KeyRound,
  behavior_alert: AlertOctagon,
  scan_started: ScanLine,
  scan_finished: ScanLine,
  scan_error: FileWarning,
  settings_changed: Settings2,
  signatures_updated: DownloadCloud,
  service_info: Activity,
};

const SEVERITY: Record<Severity, string> = {
  info: "text-slate-400 bg-slate-400/10",
  low: "text-cyan-300 bg-cyan-400/10",
  medium: "text-amber-300 bg-amber-400/10",
  high: "text-rose-300 bg-rose-400/10",
  critical: "text-rose-200 bg-rose-500/25 ring-1 ring-rose-500/40",
};

export function ActivityLog({ events, limit, compact }: { events: SecurityEvent[]; limit?: number; compact?: boolean }) {
  const rows = limit ? events.slice(0, limit) : events;
  if (rows.length === 0) {
    return <p className="px-5 py-10 text-center text-sm text-slate-500">No activity yet.</p>;
  }
  return (
    <ul className="divide-y divide-slate-800/70">
      {rows.map((e) => {
        const Icon = KIND_ICON[e.kind] ?? Info;
        return (
          <li key={e.id} className="flex items-start gap-3 px-5 py-3 hover:bg-slate-800/30">
            <span className={`mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-md ${SEVERITY[e.severity]}`}>
              <Icon className="h-3.5 w-3.5" />
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline justify-between gap-3">
                <p className="truncate text-sm text-slate-200">{e.title}</p>
                <time className="shrink-0 text-xs text-slate-500">{timeAgo(e.timestamp)}</time>
              </div>
              {e.path && <p className="truncate font-mono text-xs text-slate-500" title={e.path}>{shortPath(e.path, compact ? 56 : 96)}</p>}
              {!compact && e.detail && <p className="mt-0.5 text-xs text-slate-400">{e.detail}</p>}
            </div>
          </li>
        );
      })}
    </ul>
  );
}
