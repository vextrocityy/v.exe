import { memo, useState } from "react";
import { Activity, AlertOctagon, Ban, Bug, Camera, Check, Copy, DownloadCloud, FileWarning, FolderOpen, History, Info, KeyRound, Lock, Mic, Network, PauseCircle, ScanLine, Settings2 } from "lucide-react";
import { api } from "../lib/api";
import type { EventKind, SecurityEvent, Severity } from "../lib/types";
import { shortPath, timeAgo } from "../lib/format";
import { EventActions, isFilePath } from "./EventActions";
import { NetworkBlock } from "./NetworkBlock";

export const KIND_ICON: Record<EventKind, typeof Info> = {
  threat_detected: Bug,
  threat_quarantined: Lock,
  process_blocked: Ban,
  process_suspended: PauseCircle,
  persistence_change: KeyRound,
  device_access: Camera,
  recovery: History,
  behavior_alert: AlertOctagon,
  scan_started: ScanLine,
  scan_finished: ScanLine,
  scan_error: FileWarning,
  settings_changed: Settings2,
  signatures_updated: DownloadCloud,
  service_info: Activity,
  network_alert: Network,
};

export const SEVERITY: Record<Severity, string> = {
  info: "text-slate-400 bg-slate-400/10",
  low: "text-cyan-300 bg-cyan-400/10",
  medium: "text-amber-300 bg-amber-400/10",
  high: "text-rose-300 bg-rose-400/10",
  critical: "text-rose-200 bg-rose-500/25 ring-1 ring-rose-500/40",
};

export function iconFor(e: SecurityEvent) {
  return e.kind === "device_access" && e.title.startsWith("Microphone") ? Mic : KIND_ICON[e.kind] ?? Info;
}

interface Props {
  events: SecurityEvent[];
  limit?: number;
  compact?: boolean;
  /** Ids of items still waiting for a decision: only those show action buttons. */
  openIds?: Set<number>;
  onChanged?: () => void;
  /** Pi-hole is connected, so detections offer network-wide blocking. */
  networkBlock?: boolean;
}

export function ActivityLog({ events, limit, compact, openIds, onChanged, networkBlock }: Props) {
  const rows = limit ? events.slice(0, limit) : events;
  if (rows.length === 0) {
    return <p className="px-5 py-10 text-center text-sm text-slate-500">No activity yet.</p>;
  }
  return (
    <ul className="divide-y divide-slate-800/70">
      {rows.map((e) => (
        <Row key={e.id} e={e} compact={!!compact} open={!compact && !!openIds?.has(e.id)} onChanged={onChanged} networkBlock={!compact && !!networkBlock} />
      ))}
    </ul>
  );
}

const Row = memo(function Row({ e, compact, open, onChanged, networkBlock }: { e: SecurityEvent; compact: boolean; open: boolean; onChanged?: () => void; networkBlock: boolean }) {
  const Icon = iconFor(e);
  return (
    <li className="flex items-start gap-3 px-5 py-3 hover:bg-slate-800/30">
      <span className={`mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-md ${SEVERITY[e.severity]}`} title={`Severity: ${e.severity}`}>
        <Icon className="h-3.5 w-3.5" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline justify-between gap-3">
          <p className="truncate text-sm text-slate-200">
            {e.title}
            {open && <span className="ml-2 rounded bg-amber-400/15 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-amber-300">needs a decision</span>}
          </p>
          <time className="shrink-0 text-xs text-slate-500">{timeAgo(e.timestamp)}</time>
        </div>
        {e.path && (compact ? <p className="truncate font-mono text-xs text-slate-500" title={e.path}>{shortPath(e.path, 56)}</p> : <PathLine path={e.path} />)}
        {!compact && e.detail && <p className="mt-0.5 text-xs text-slate-400">{e.detail}</p>}
        {open && <EventActions event={e} onChanged={onChanged ?? (() => {})} />}
        {networkBlock && e.severity !== "info" && (e.kind === "threat_detected" || e.kind === "behavior_alert") && <NetworkBlock around={e.timestamp} threat={e.title} />}
      </div>
    </li>
  );
});

async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const t = document.createElement("textarea");
    t.value = text;
    document.body.appendChild(t);
    t.select();
    document.execCommand("copy");
    t.remove();
  }
}

/** Full path, selectable, with Copy and Show in folder. */
export function PathLine({ path }: { path: string }) {
  const [copied, setCopied] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const file = isFilePath(path);
  const copy = async () => {
    await copyText(path).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  const reveal = async () => {
    setErr(null);
    try {
      await api.revealPath(path);
    } catch (e) {
      setErr(String(e));
    }
  };
  return (
    <div className="group flex items-start gap-2">
      <p className="min-w-0 select-text break-all font-mono text-xs text-slate-500">{path}</p>
      <div className="flex shrink-0 items-center gap-0.5 opacity-60 transition group-hover:opacity-100">
        <button onClick={copy} title="Copy path" aria-label="Copy path" className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-cyan-300">
          {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
        </button>
        {file && (
          <button onClick={reveal} title="Show in folder" aria-label="Show in folder" className="rounded p-1 text-slate-400 hover:bg-slate-800 hover:text-cyan-300">
            <FolderOpen className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
      {err && <span className="text-xs text-rose-400">{err}</span>}
    </div>
  );
}
