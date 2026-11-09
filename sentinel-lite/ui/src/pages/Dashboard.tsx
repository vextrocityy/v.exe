import { useState } from "react";
import { Database, Lock, RefreshCw, ShieldOff } from "lucide-react";
import { HardeningPanel } from "../components/HardeningPanel";
import { ResourceCard } from "../components/ResourceCard";
import { ActivityLog } from "../components/ActivityLog";
import { Panel } from "../components/Panel";
import { ScanPanel } from "../components/ScanPanel";
import { ShieldHero } from "../components/ShieldHero";
import { DevicesInUse } from "./Privacy";
import { StatCard } from "../components/StatCard";
import { api } from "../lib/api";
import { formatNumber, timeAgo } from "../lib/format";
import type { EngineStatus, SecurityEvent } from "../lib/types";

function signatureHint(status: EngineStatus | null): { text: string; warn: boolean } {
  if (!status) return { text: "Local database", warn: false };
  if (status.update_in_progress) return { text: "Updating…", warn: false };
  if (status.signature_update_error && !status.last_signature_update) return { text: "Update failed: " + status.signature_update_error, warn: true };
  if (!status.last_signature_update) return { text: "Never updated", warn: true };
  const stale = Date.now() / 1000 - status.last_signature_update > 3 * 86400;
  const yara = status.yara_rule_count ? ` · ${formatNumber(status.yara_rule_count)} YARA rules` : "";
  return { text: `Updated ${timeAgo(status.last_signature_update)}${yara}`, warn: stale };
}

export function Dashboard({ status, events, refresh, onSeeAll }: { status: EngineStatus | null; events: SecurityEvent[]; refresh: () => Promise<void>; onSeeAll: () => void }) {
  const [updateError, setUpdateError] = useState<string | null>(null);
  const sig = signatureHint(status);
  const updating = !!status?.update_in_progress;
  const runUpdate = async () => {
    setUpdateError(null);
    try {
      await api.updateSignatures();
      await refresh();
    } catch (e) {
      setUpdateError(String(e));
    }
  };
  return (
    <div className="space-y-6">
      <DevicesInUse devices={status?.devices_in_use ?? []} compact />
      <div className="grid grid-cols-[1fr_340px] gap-6">
        <Panel className="flex items-center px-8 py-8">
          <ShieldHero status={status} onAcknowledge={async () => { await api.acknowledgeThreats(); await refresh(); }} />
        </Panel>
        <Panel title="Scan">
          <ScanPanel
            scan={status?.scan}
            onStart={async (k) => { await api.startScan(k); await refresh(); }}
            onCancel={async () => { await api.cancelScan(); await refresh(); }}
          />
        </Panel>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <StatCard icon={ShieldOff} accent="rose" label="Threats blocked" value={formatNumber(status?.threats_blocked_total ?? 0)} hint="All time" />
        <StatCard icon={Lock} accent="violet" label="Quarantined" value={formatNumber(status?.quarantine_count ?? 0)} hint="Isolated files" />
        <StatCard
          icon={Database}
          accent="cyan"
          label="Signatures"
          value={formatNumber(status?.signature_count ?? 0)}
          hint={updateError ?? sig.text}
          hintTone={updateError || sig.warn ? "warn" : undefined}
          action={
            <button onClick={runUpdate} disabled={updating || !status} title="Check for signature updates now" aria-label="Update signatures" className="rounded-md p-1 text-slate-400 hover:bg-slate-800 hover:text-cyan-300 disabled:opacity-40">
              <RefreshCw className={`h-4 w-4 ${updating ? "animate-spin" : ""}`} />
            </button>
          }
        />
        <ResourceCard status={status} />
      </div>

      <div className="grid grid-cols-[1fr_340px] gap-6">
        <Panel title="Recent activity" action={<button onClick={onSeeAll} className="text-xs text-cyan-400 hover:text-cyan-300">View all</button>}>
          <ActivityLog events={events} limit={7} compact />
        </Panel>
        <Panel title="Real-time shields">
          <ul className="divide-y divide-slate-800/70">
            {(status?.shields ?? []).map((s) => (
              <li key={s.name} className="flex items-center gap-3 px-5 py-3">
                <span className={`h-2 w-2 shrink-0 rounded-full ${s.running ? "bg-emerald-400 shadow-[0_0_8px_#34d399]" : s.enabled ? "bg-amber-400" : "bg-slate-600"}`} />
                <div className="min-w-0">
                  <p className="text-sm text-slate-200">{s.name}</p>
                  <p className="truncate text-xs text-slate-500" title={s.detail ?? ""}>{s.running ? s.detail : s.enabled ? `Failed: ${s.detail ?? "unknown"}` : "Disabled"}</p>
                </div>
              </li>
            ))}
          </ul>
        </Panel>
      </div>
      <HardeningPanel checks={status?.hardening ?? []} onChanged={refresh} />
    </div>
  );
}
