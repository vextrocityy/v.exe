import { ShieldAlert, ShieldCheck, ShieldOff, ShieldX } from "lucide-react";
import type { EngineStatus } from "../lib/types";
import { toneOf } from "../lib/types";

const TONES = {
  safe: { label: "Protected", color: "text-emerald-400", ring: "border-emerald-400/50", glow: "#10b981", Icon: ShieldCheck },
  warn: { label: "At Risk", color: "text-amber-400", ring: "border-amber-400/50", glow: "#f59e0b", Icon: ShieldAlert },
  danger: { label: "Threat Detected", color: "text-rose-400", ring: "border-rose-400/60", glow: "#f43f5e", Icon: ShieldX },
  off: { label: "Protection is off", color: "text-rose-400", ring: "border-rose-400/60", glow: "#f43f5e", Icon: ShieldOff },
  connecting: { label: "Connecting…", color: "text-slate-400", ring: "border-slate-500/40", glow: "#64748b", Icon: ShieldAlert },
} as const;

interface Props {
  status: EngineStatus | null;
  /** The engine could not be reached (as opposed to: not asked yet). */
  offline: boolean;
  attention: number;
  onShowAttention: () => void;
}

export function ShieldHero({ status, offline, attention, onShowAttention }: Props) {
  const key = !status ? (offline ? "off" : "connecting") : toneOf(status.state);
  const t = TONES[key];
  const reasons = status && typeof status.state === "object" ? status.state.at_risk.reasons : [];
  const scanning = status?.scan.running;
  const sub =
    key === "off"
      ? "The protection engine is not running, so nothing is being watched. Use Start protection above."
      : key === "connecting"
        ? "Waiting for the Vigil service."
        : key === "warn"
          ? reasons.join(" · ")
          : key === "danger"
            ? `${attention === 1 ? "One thing needs" : `${attention} things need`} your decision.`
            : attention > 0
              ? `Real-time protection is on. ${attention === 1 ? "One item is" : `${attention} items are`} waiting for a decision.`
              : "All shields are active. Your PC is being monitored in real time.";

  return (
    <div className="flex items-center gap-10">
      <div className="relative grid h-44 w-44 shrink-0 place-items-center" style={{ ["--glow" as string]: t.glow }}>
        {/* expanding pulse rings */}
        <span className={`absolute inset-6 rounded-full border-2 ${t.ring} animate-shield-pulse`} />
        <span className={`absolute inset-6 rounded-full border-2 ${t.ring} animate-shield-pulse [animation-delay:1.5s]`} />
        {/* rotating radar sweep while scanning */}
        {scanning && (
          <span className="absolute inset-2 animate-scan-sweep rounded-full bg-[conic-gradient(from_0deg,transparent_0deg,#22d3ee55_60deg,transparent_90deg)]" />
        )}
        <span className="absolute inset-8 rounded-full bg-slate-900 shadow-inner ring-1 ring-slate-700/60" />
        <t.Icon className={`relative h-20 w-20 ${t.color} animate-glow`} strokeWidth={1.4} />
      </div>

      <div className="min-w-0">
        <p className="text-xs font-semibold uppercase tracking-[0.25em] text-slate-500">System Status</p>
        <h1 className={`mt-1 text-4xl font-semibold tracking-tight ${t.color}`}>{t.label}</h1>
        <p className="mt-2 max-w-md text-sm text-slate-400">{sub}</p>
        {status && attention > 0 && (
          <button onClick={onShowAttention} className={`mt-4 rounded-lg border px-3 py-1.5 text-sm ${key === "danger" ? "border-rose-400/40 text-rose-300 hover:bg-rose-500/10" : "border-amber-400/40 text-amber-300 hover:bg-amber-500/10"}`}>
            Show me
          </button>
        )}
      </div>
    </div>
  );
}
