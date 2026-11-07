import { Cpu } from "lucide-react";
import type { EngineStatus } from "../lib/types";
import { formatBytes, formatUptime } from "../lib/format";

function Bar({ label, value, max, text }: { label: string; value: number; max: number; text: string }) {
  // Bars are relative to the budget (CPU 1 %, RAM 150 MB) or to 100 % for the PC.
  const pct = Math.min(100, (value / max) * 100);
  const color = pct > 80 ? "bg-rose-400" : pct > 50 ? "bg-amber-400" : "bg-emerald-400";
  return (
    <div>
      <div className="flex justify-between text-[11px] text-slate-500">
        <span>{label}</span>
        <span className="font-mono text-slate-300">{text}</span>
      </div>
      <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-slate-800">
        <div className={`h-full rounded-full ${color} transition-all duration-700`} style={{ width: `${Math.max(pct, 2)}%` }} />
      </div>
    </div>
  );
}

/** Live resource meter: the engine's own budget (CPU < 1 %, RAM < 150 MB) and machine RAM. */
export function ResourceCard({ status }: { status: EngineStatus | null }) {
  const cpu = status?.cpu_percent ?? 0;
  const mem = status?.memory_bytes ?? 0;
  const sys = status?.system_memory_percent ?? 0;
  return (
    <div className="rounded-2xl border border-slate-800/80 bg-slate-900/60 p-4" title="Bars: engine CPU vs its 1 % budget, engine RAM vs its 150 MB budget, and the whole PC's memory use">
      <div className="flex items-center gap-3">
        <span className="grid h-9 w-9 place-items-center rounded-lg bg-emerald-400/10 text-emerald-400">
          <Cpu className="h-4.5 w-4.5" />
        </span>
        <span className="flex-1 text-xs font-medium uppercase tracking-wider text-slate-500">Resources</span>
        {status && <span className="whitespace-nowrap text-[11px] text-slate-500" title="Engine uptime">{formatUptime(status.uptime_secs)}</span>}
      </div>
      <div className="mt-3 space-y-2">
        <Bar label="Engine CPU" value={cpu} max={1} text={status?.cpu_percent == null ? "–" : `${cpu.toFixed(2)} %`} />
        <Bar label="Engine RAM" value={mem} max={150 * 1024 * 1024} text={formatBytes(mem)} />
        <Bar label="PC memory" value={sys} max={100} text={status?.system_memory_percent == null ? "–" : `${sys.toFixed(0)} %`} />
      </div>
    </div>
  );
}
