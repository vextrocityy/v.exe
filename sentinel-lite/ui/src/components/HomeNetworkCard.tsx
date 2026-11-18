import { Router, ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import { Panel } from "./Panel";
import { formatNumber, timeAgo } from "../lib/format";
import type { HomeNetworkStatus } from "../lib/types";

/** Pi-hole stats and whether this PC's DNS actually goes through it. */
export function HomeNetworkCard({ home, onSetUp }: { home: HomeNetworkStatus | undefined; onSetUp: () => void }) {
  if (!home?.configured) {
    return (
      <Panel title="Home network">
        <div className="flex items-center justify-between gap-4 px-5 py-4">
          <p className="text-sm text-slate-400">Connect your Pi-hole to see network-wide blocking and get an alert if this PC's DNS is tampered with.</p>
          <button onClick={onSetUp} className="shrink-0 rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 hover:border-cyan-400/50 hover:text-cyan-300">
            Set up
          </button>
        </div>
      </Panel>
    );
  }
  const dns =
    home.dns_filtered === true
      ? { icon: ShieldCheck, tone: "text-emerald-400", label: "This PC's DNS goes through Pi-hole" }
      : home.dns_filtered === false
        ? { icon: ShieldAlert, tone: "text-rose-400", label: "DNS is bypassing Pi-hole" }
        : { icon: ShieldQuestion, tone: "text-slate-400", label: "DNS check not available" };
  const DnsIcon = dns.icon;
  return (
    <Panel title="Home network" action={home.last_check ? <span className="text-xs text-slate-500">Checked {timeAgo(home.last_check)}</span> : undefined}>
      <div className="grid grid-cols-[1.4fr_1fr_1fr_1fr] divide-x divide-slate-800/70">
        <div className="flex items-start gap-3 px-5 py-4">
          <DnsIcon className={`mt-0.5 h-5 w-5 shrink-0 ${dns.tone}`} />
          <div className="min-w-0">
            <p className={`text-sm ${home.dns_filtered === false ? "text-rose-300" : "text-slate-200"}`}>{dns.label}</p>
            {home.dns_detail && <p className="text-xs text-slate-500" title={home.dns_detail}>{home.dns_detail}</p>}
          </div>
        </div>
        {home.reachable ? (
          <>
            <Stat label="Queries today" value={home.queries_today} />
            <Stat label="Blocked today" value={home.blocked_today} hint={home.percent_blocked != null ? `${home.percent_blocked.toFixed(1)}% of all lookups` : undefined} />
            <Stat label="Domains on lists" value={home.domains_on_lists} />
          </>
        ) : (
          <div className="col-span-3 flex items-center gap-3 px-5 py-4">
            <Router className="h-5 w-5 shrink-0 text-amber-400" />
            <p className="text-sm text-amber-300">{home.error ?? "Pi-hole did not answer."}</p>
          </div>
        )}
      </div>
    </Panel>
  );
}

function Stat({ label, value, hint }: { label: string; value: number | null; hint?: string }) {
  return (
    <div className="px-5 py-4">
      <p className="text-xs font-medium uppercase tracking-wider text-slate-500">{label}</p>
      <p className="mt-1 font-mono text-xl font-semibold tabular-nums text-slate-100">{value != null ? formatNumber(value) : "–"}</p>
      {hint && <p className="text-xs text-slate-500">{hint}</p>}
    </div>
  );
}
