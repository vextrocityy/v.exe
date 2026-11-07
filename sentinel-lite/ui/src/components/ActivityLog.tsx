import { useState } from "react";
import { Activity, AlertOctagon, Ban, Bug, DownloadCloud, FileWarning, Info, KeyRound, Lock, PauseCircle, Play, ScanLine, Settings2, Skull } from "lucide-react";
import { api } from "../lib/api";
import type { EventKind, SecurityEvent, Severity } from "../lib/types";
import { shortPath, timeAgo } from "../lib/format";

const KIND_ICON: Record<EventKind, typeof Info> = {
  threat_detected: Bug,
  threat_quarantined: Lock,
  process_blocked: Ban,
  process_suspended: PauseCircle,
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
              {e.kind === "process_suspended" && e.pid != null && <SuspendedActions pid={e.pid} />}
              {e.kind === "process_blocked" && e.title.startsWith("Blocked unsigned program") && e.path && <AllowButton path={e.path} />}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

/** Decision buttons for a process the engine froze after a decoy was touched. */
function SuspendedActions({ pid }: { pid: number }) {
  const [state, setState] = useState<"idle" | "busy" | "done">("idle");
  const [msg, setMsg] = useState<string | null>(null);
  const act = async (action: "terminate" | "resume") => {
    setState("busy");
    setMsg(null);
    try {
      await api.processAction(pid, action);
      setState("done");
      setMsg(action === "terminate" ? "Terminated and quarantined." : "Resumed.");
    } catch (err) {
      setState("idle");
      setMsg(String(err));
    }
  };
  if (state === "done") return <p className="mt-2 text-xs text-emerald-400">{msg}</p>;
  return (
    <div className="mt-2 flex flex-wrap items-center gap-2">
      <button disabled={state === "busy"} onClick={() => act("terminate")} className="flex items-center gap-1 rounded-md bg-rose-500/90 px-2.5 py-1 text-xs font-medium text-white hover:bg-rose-500 disabled:opacity-50">
        <Skull className="h-3.5 w-3.5" /> Terminate &amp; quarantine
      </button>
      <button disabled={state === "busy"} onClick={() => act("resume")} title="Requires administrator approval" className="flex items-center gap-1 rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:border-amber-400/50 hover:text-amber-300 disabled:opacity-50">
        <Play className="h-3.5 w-3.5" /> Resume (it's safe)
      </button>
      {msg && <span className="text-xs text-rose-400">{msg}</span>}
    </div>
  );
}

/** Execution Guard blocked an unsigned program; let the user trust this exact file. */
function AllowButton({ path }: { path: string }) {
  const [state, setState] = useState<"idle" | "busy" | "done">("idle");
  const [err, setErr] = useState<string | null>(null);
  const allow = async () => {
    setState("busy");
    setErr(null);
    try {
      await api.trustApp(path);
      setState("done");
    } catch (e) {
      setState("idle");
      setErr(String(e));
    }
  };
  if (state === "done") return <p className="mt-2 text-xs text-emerald-400">Trusted. Start it again; it will be allowed from now on.</p>;
  return (
    <div className="mt-2 flex items-center gap-2">
      <button disabled={state === "busy"} onClick={allow} title="Requires administrator approval" className="rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:border-emerald-400/50 hover:text-emerald-300 disabled:opacity-50">
        Always allow this program
      </button>
      {err && <span className="text-xs text-rose-400">{err}</span>}
    </div>
  );
}
