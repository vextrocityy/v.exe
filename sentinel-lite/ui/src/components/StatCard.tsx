import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";

export function StatCard({ icon: Icon, label, value, accent = "cyan", hint, action, hintTone }: { icon: LucideIcon; label: string; value: string; accent?: "cyan" | "emerald" | "rose" | "violet"; hint?: string; action?: ReactNode; hintTone?: "warn" }) {
  const color = { cyan: "text-cyan-400 bg-cyan-400/10", emerald: "text-emerald-400 bg-emerald-400/10", rose: "text-rose-400 bg-rose-400/10", violet: "text-violet-400 bg-violet-400/10" }[accent];
  return (
    <div className="rounded-2xl border border-slate-800/80 bg-slate-900/60 p-4">
      <div className="flex items-center gap-3">
        <span className={`grid h-9 w-9 place-items-center rounded-lg ${color}`}>
          <Icon className="h-4.5 w-4.5" />
        </span>
        <span className="flex-1 text-xs font-medium uppercase tracking-wider text-slate-500">{label}</span>
        {action}
      </div>
      <p className="mt-3 font-mono text-2xl font-semibold tabular-nums text-slate-100">{value}</p>
      {hint && <p className={`mt-0.5 truncate text-xs ${hintTone === "warn" ? "text-amber-400" : "text-slate-500"}`} title={hint}>{hint}</p>}
    </div>
  );
}
