import { useState, type ReactNode } from "react";
import { Ban, Check, History, Lock, Play, ShieldCheck, Skull, X } from "lucide-react";
import { api } from "../lib/api";
import type { SecurityEvent } from "../lib/types";

type Tone = "danger" | "neutral" | "safe";
const TONE: Record<Tone, string> = {
  danger: "bg-rose-500/90 text-white hover:bg-rose-500 border-transparent",
  neutral: "border-slate-700 text-slate-300 hover:border-cyan-400/50 hover:text-cyan-300",
  safe: "border-slate-700 text-slate-300 hover:border-emerald-400/50 hover:text-emerald-300",
};

interface Action {
  label: string;
  icon: ReactNode;
  tone: Tone;
  /** Shown as a tooltip; "admin" adds the approval note. */
  hint?: string;
  admin?: boolean;
  run: () => Promise<void>;
  /** Text shown once it worked. */
  done: string;
}

/** A real file path (drive or UNC), as opposed to a scheduled-task name. */
export function isFilePath(p: string): boolean {
  return /^[A-Za-z]:[\\/]|^\\\\/.test(p);
}

/** What the user can do about an open item. The last one is always "Dismiss". */
function actionsFor(e: SecurityEvent, onNavigate?: (page: "recovery") => void): Action[] {
  const a: Action[] = [];
  const path = e.path;
  const quarantine = (threat: string): Action => ({
    label: "Quarantine it",
    icon: <Lock className="h-3.5 w-3.5" />,
    tone: "danger",
    admin: true,
    run: () => api.quarantinePath(path!, threat),
    done: "Moved to quarantine. You can restore it from Quarantine.",
  });
  const safe: Action = {
    label: "It's safe",
    icon: <ShieldCheck className="h-3.5 w-3.5" />,
    tone: "safe",
    admin: true,
    hint: "Never report this exact file again",
    run: () => api.allowFile(path!),
    done: "Marked as safe. This exact file will not be reported again.",
  };
  if (e.kind === "process_suspended" && e.pid != null) {
    a.push({ label: "Terminate & quarantine", icon: <Skull className="h-3.5 w-3.5" />, tone: "danger", run: () => api.processAction(e.pid!, "terminate"), done: "Terminated and quarantined." });
    a.push({ label: "Resume (it's safe)", icon: <Play className="h-3.5 w-3.5" />, tone: "neutral", admin: true, run: () => api.processAction(e.pid!, "resume"), done: "Resumed." });
    return a; // a frozen process needs one of the two; no plain dismiss
  }
  if (e.kind === "threat_detected" && path && isFilePath(path)) {
    a.push(quarantine(e.title.replace(/( detected|: suspicious file left in place)$/, "")));
    a.push(safe);
  } else if (e.kind === "scan_error" && path && isFilePath(path)) {
    a.push({ ...quarantine(e.title.replace(/^Could not quarantine /, "")), label: "Try again" });
  } else if (e.kind === "process_blocked" && path && isFilePath(path)) {
    a.push({ label: "Always allow this program", icon: <Check className="h-3.5 w-3.5" />, tone: "safe", admin: true, run: () => api.trustApp(path), done: "Trusted. Start it again; it will be allowed from now on." });
  } else if (e.kind === "persistence_change" && path && !isFilePath(path)) {
    a.push({ label: "Disable this task", icon: <Ban className="h-3.5 w-3.5" />, tone: "danger", admin: true, run: () => api.disableTask(path), done: "Disabled. Re-enable it in Task Scheduler if you need it." });
  } else if (e.kind === "behavior_alert" && onNavigate) {
    a.push({ label: "Check my files in Recovery", icon: <History className="h-3.5 w-3.5" />, tone: "neutral", run: async () => onNavigate("recovery"), done: "" });
  }
  a.push({
    label: a.length ? "Dismiss" : "OK, got it",
    icon: <X className="h-3.5 w-3.5" />,
    tone: "neutral",
    hint: "Remove from this list; it stays in Activity",
    run: () => api.resolveEvent(e.id),
    done: "Dismissed.",
  });
  return a;
}

/** Decision buttons for an open item. `onChanged` re-reads the engine state. */
export function EventActions({ event, onChanged, onNavigate }: { event: SecurityEvent; onChanged: () => void; onNavigate?: (page: "recovery") => void }) {
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  if (done) return <p className="mt-2 text-xs text-emerald-400">{done}</p>;
  const run = async (a: Action) => {
    setBusy(true);
    setErr(null);
    try {
      await a.run();
      if (a.done) setDone(a.done);
      onChanged();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="mt-2 flex flex-wrap items-center gap-2">
      {actionsFor(event, onNavigate).map((a) => (
        <button
          key={a.label}
          disabled={busy}
          onClick={() => run(a)}
          title={[a.hint, a.admin ? "Requires administrator approval" : null].filter(Boolean).join(" · ") || undefined}
          className={`flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs font-medium disabled:opacity-50 ${TONE[a.tone]}`}
        >
          {a.icon} {a.label}
        </button>
      ))}
      {err && <span className="text-xs text-rose-400">{err}</span>}
    </div>
  );
}
