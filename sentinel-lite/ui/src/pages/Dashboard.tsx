import { Cpu, Database, Lock, ShieldOff } from "lucide-react";
import { ActivityLog } from "../components/ActivityLog";
import { Panel } from "../components/Panel";
import { ScanPanel } from "../components/ScanPanel";
import { ShieldHero } from "../components/ShieldHero";
import { StatCard } from "../components/StatCard";
import { api } from "../lib/api";
import { formatBytes, formatNumber, formatUptime } from "../lib/format";
import type { EngineStatus, SecurityEvent } from "../lib/types";

export function Dashboard({ status, events, refresh, onSeeAll }: { status: EngineStatus | null; events: SecurityEvent[]; refresh: () => Promise<void>; onSeeAll: () => void }) {
  return (
    <div className="space-y-6">
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
        <StatCard icon={Database} accent="cyan" label="Signatures" value={formatNumber(status?.signature_count ?? 0)} hint="Local database" />
        <StatCard icon={Cpu} accent="emerald" label="Engine memory" value={formatBytes(status?.memory_bytes)} hint={status ? `Up ${formatUptime(status.uptime_secs)}` : undefined} />
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
    </div>
  );
}
