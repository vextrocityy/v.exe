import { Activity, LayoutDashboard, Lock, Settings, Shield } from "lucide-react";
import type { EngineStatus } from "../lib/types";
import { toneOf } from "../lib/types";
import { formatBytes } from "../lib/format";

export type Page = "dashboard" | "activity" | "quarantine" | "settings";

const NAV: { id: Page; label: string; icon: typeof Shield }[] = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "activity", label: "Activity", icon: Activity },
  { id: "quarantine", label: "Quarantine", icon: Lock },
  { id: "settings", label: "Settings", icon: Settings },
];

export function Sidebar({ page, onNavigate, status, connected }: { page: Page; onNavigate: (p: Page) => void; status: EngineStatus | null; connected: boolean }) {
  const tone = toneOf(status?.state);
  const dot = !connected ? "bg-slate-500" : tone === "safe" ? "bg-emerald-400 shadow-[0_0_8px_#34d399]" : tone === "danger" ? "bg-rose-400 shadow-[0_0_8px_#fb7185]" : "bg-amber-400 shadow-[0_0_8px_#fbbf24]";

  return (
    <aside className="flex w-60 shrink-0 flex-col border-r border-slate-800/80 bg-slate-950/70">
      <div className="flex items-center gap-2.5 px-5 py-6">
        <Shield className="h-7 w-7 text-cyan-400 drop-shadow-[0_0_8px_#22d3ee]" />
        <div>
          <p className="text-base font-semibold tracking-tight text-slate-100">Sentinel-Lite</p>
          <p className="text-[10px] uppercase tracking-[0.2em] text-slate-500">Endpoint Protection</p>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-3">
        {NAV.map(({ id, label, icon: Icon }) => {
          const active = page === id;
          const badge = id === "quarantine" && status?.quarantine_count ? status.quarantine_count : null;
          return (
            <button
              key={id}
              onClick={() => onNavigate(id)}
              className={`flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-sm transition ${
                active ? "bg-cyan-400/10 text-cyan-300 shadow-[inset_2px_0_0_#22d3ee]" : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200"
              }`}
            >
              <Icon className="h-4 w-4" />
              <span className="flex-1 text-left">{label}</span>
              {badge && <span className="rounded-full bg-rose-500/20 px-2 text-xs text-rose-300">{badge}</span>}
            </button>
          );
        })}
      </nav>

      <div className="space-y-1.5 border-t border-slate-800/80 px-5 py-4 text-xs text-slate-500">
        <div className="flex items-center gap-2">
          <span className={`h-2 w-2 rounded-full ${dot}`} />
          <span>{connected ? "Engine connected" : "Engine offline"}</span>
        </div>
        {status && (
          <p className="font-mono">
            v{status.service_version}{status.build ? ` build ${status.build}` : " dev"} · {formatBytes(status.memory_bytes)} RAM
          </p>
        )}
      </div>
    </aside>
  );
}
