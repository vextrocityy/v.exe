import { useState } from "react";
import { CheckCircle2, ShieldAlert } from "lucide-react";
import { Panel } from "./Panel";
import { api } from "../lib/api";
import type { HardeningCheck } from "../lib/types";

/** Windows features that cover what a user-mode engine cannot (e.g. LSASS credential theft). */
export function HardeningPanel({ checks, onChanged }: { checks: HardeningCheck[]; onChanged: () => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  if (checks.length === 0) return null;
  const fix = async (id: string) => {
    setBusy(id);
    setMsg(null);
    try {
      await api.enableHardening(id);
      setMsg("Enabled. Restart Windows to apply it.");
      onChanged();
    } catch (e) {
      setMsg(String(e));
    } finally {
      setBusy(null);
    }
  };
  return (
    <Panel title="Windows hardening">
      <ul className="divide-y divide-slate-800/70">
        {checks.map((c) => (
          <li key={c.id} className="flex items-start gap-3 px-5 py-3">
            {c.ok ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" /> : <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />}
            <div className="min-w-0 flex-1">
              <p className="text-sm text-slate-200">{c.name}</p>
              <p className="text-xs text-slate-500">{c.detail}</p>
            </div>
            {c.fixable && (
              <button onClick={() => fix(c.id)} disabled={busy === c.id} className="shrink-0 rounded-md bg-cyan-500 px-2.5 py-1 text-xs font-medium text-slate-950 hover:bg-cyan-400 disabled:opacity-50">
                Enable
              </button>
            )}
          </li>
        ))}
      </ul>
      {msg && <p className="border-t border-slate-800 px-5 py-2 text-xs text-slate-400">{msg}</p>}
    </Panel>
  );
}
