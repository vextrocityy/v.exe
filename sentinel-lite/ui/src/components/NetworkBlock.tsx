import { useState } from "react";
import { Ban, Network } from "lucide-react";
import { api } from "../lib/api";
import type { DomainSuggestion } from "../lib/types";

function clock(t: number): string {
  return new Date(t * 1000).toLocaleTimeString([], { hour: "numeric", minute: "2-digit", second: "2-digit" });
}

/**
 * After a detection: list the domains this PC looked up around that time
 * (from Pi-hole) and block the chosen ones for every device in the house.
 * Unknown domains are preselected; big services and household favourites are not.
 */
export function NetworkBlock({ around, threat }: { around: number; threat: string }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [items, setItems] = useState<DomainSuggestion[] | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);

  const load = async () => {
    setOpen(true);
    setBusy(true);
    setMsg(null);
    try {
      const r = await api.homeNetworkSuggestions(around);
      setItems(r.domains);
      setPicked(new Set(r.domains.filter((d) => !d.note && !d.already_blocked).map((d) => d.domain)));
    } catch (e) {
      setMsg({ text: String(e), ok: false });
    } finally {
      setBusy(false);
    }
  };

  const block = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const r = await api.homeNetworkBlock([...picked], threat);
      const parts = [];
      if (r.added.length) parts.push(`Blocked ${r.added.length} domain(s) for every device on your network.`);
      if (r.failed.length) parts.push(`Not blocked: ${r.failed.join("; ")}`);
      setMsg({ text: parts.join(" "), ok: r.failed.length === 0 });
      if (r.added.length) {
        setItems((prev) => prev?.map((d) => (r.added.includes(d.domain) ? { ...d, already_blocked: true } : d)) ?? null);
        setPicked(new Set());
      }
    } catch (e) {
      setMsg({ text: String(e), ok: false });
    } finally {
      setBusy(false);
    }
  };

  const toggle = (d: string) => {
    const next = new Set(picked);
    if (next.has(d)) next.delete(d);
    else next.add(d);
    setPicked(next);
  };

  if (!open) {
    return (
      <button onClick={load} className="mt-2 flex items-center gap-1 rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:border-cyan-400/50 hover:text-cyan-300">
        <Network className="h-3.5 w-3.5" /> Block where it connected…
      </button>
    );
  }

  return (
    <div className="mt-2 rounded-lg border border-slate-800 bg-slate-950/60 p-3">
      <p className="text-xs text-slate-400">
        Websites this PC looked up from 15 minutes before to 5 minutes after the detection. Blocking stops every device on your network from reaching them.
      </p>
      {busy && !items && <p className="mt-2 text-xs text-slate-500">Asking Pi-hole…</p>}
      {items && items.length === 0 && <p className="mt-2 text-xs text-slate-500">Pi-hole has no lookups from this PC in that window.</p>}
      {items && items.length > 0 && (
        <ul className="mt-2 max-h-64 space-y-1 overflow-y-auto">
          {items.map((d) => (
            <li key={d.domain}>
              <label className={`flex items-start gap-2 rounded-md px-2 py-1.5 ${d.already_blocked ? "opacity-60" : "hover:bg-slate-800/40"}`}>
                <input type="checkbox" className="mt-0.5 accent-cyan-500" disabled={d.already_blocked || busy} checked={picked.has(d.domain)} onChange={() => toggle(d.domain)} />
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-mono text-xs text-slate-200" title={d.domain}>{d.domain}</span>
                  <span className="block text-[11px] text-slate-500">
                    {d.queries}× · {clock(d.first_seen)}
                    {d.already_blocked ? " · already blocked by Pi-hole" : d.note ? ` · ${d.note}` : ""}
                  </span>
                </span>
              </label>
            </li>
          ))}
        </ul>
      )}
      <div className="mt-2 flex flex-wrap items-center gap-2">
        {items && items.length > 0 && (
          <button disabled={busy || picked.size === 0} onClick={block} className="flex items-center gap-1 rounded-md bg-rose-500/90 px-2.5 py-1 text-xs font-medium text-white hover:bg-rose-500 disabled:opacity-40">
            <Ban className="h-3.5 w-3.5" /> Block {picked.size || ""} on home network
          </button>
        )}
        <button onClick={() => setOpen(false)} className="rounded-md px-2.5 py-1 text-xs text-slate-400 hover:text-slate-200">Close</button>
        {msg && <span className={`text-xs ${msg.ok ? "text-emerald-400" : "text-rose-400"}`}>{msg.text}</span>}
      </div>
    </div>
  );
}
