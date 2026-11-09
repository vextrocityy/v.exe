import { ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import type { EngineStatus } from "../lib/types";
import { toneOf } from "../lib/types";

const TONES = {
  safe: { label: "Protected", color: "text-emerald-400", ring: "border-emerald-400/50", glow: "#10b981", Icon: ShieldCheck, sub: "All shields are active. Your PC is being monitored in real time." },
  warn: { label: "At Risk", color: "text-amber-400", ring: "border-amber-400/50", glow: "#f59e0b", Icon: ShieldAlert, sub: "" },
  danger: { label: "Threat Detected", color: "text-rose-400", ring: "border-rose-400/60", glow: "#f43f5e", Icon: ShieldX, sub: "A threat needs your attention. Review the activity log." },
} as const;

export function ShieldHero({ status, onAcknowledge }: { status: EngineStatus | null; onAcknowledge: () => void }) {
  const tone = toneOf(status?.state);
  const t = TONES[tone];
  const reasons = status && typeof status.state === "object" ? status.state.at_risk.reasons : [];
  const scanning = status?.scan.running;

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
        <h1 className={`mt-1 text-4xl font-semibold tracking-tight ${t.color}`}>{status ? t.label : "Connecting…"}</h1>
        <p className="mt-2 max-w-md text-sm text-slate-400">
          {!status ? "Waiting for the Vigil service." : tone === "warn" ? reasons.join(" · ") : t.sub}
        </p>
        {tone === "danger" && (
          <button onClick={onAcknowledge} className="mt-4 rounded-lg border border-rose-400/40 px-3 py-1.5 text-sm text-rose-300 hover:bg-rose-500/10">
            Mark as reviewed
          </button>
        )}
      </div>
    </div>
  );
}
