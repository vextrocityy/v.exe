import { useCallback, useEffect, useState } from "react";
import { RotateCcw, ShieldCheck, Trash2 } from "lucide-react";
import { Panel } from "../components/Panel";
import { api } from "../lib/api";
import { formatBytes, shortPath, timeAgo } from "../lib/format";
import type { QuarantineItem } from "../lib/types";

export function QuarantinePage({ onChanged }: { onChanged: () => void }) {
  const [items, setItems] = useState<QuarantineItem[]>([]);
  const [confirm, setConfirm] = useState<{ item: QuarantineItem; action: "restore" | "delete" } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => api.listQuarantine().then(setItems).catch((e) => setError(String(e))), []);
  useEffect(() => { load(); }, [load]);

  const act = async () => {
    if (!confirm) return;
    try {
      if (confirm.action === "restore") await api.restoreQuarantine(confirm.item.id);
      else await api.deleteQuarantine(confirm.item.id);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
    setConfirm(null);
    await load();
    onChanged();
  };

  return (
    <>
      <Panel title={`Quarantine · ${items.length} item(s)`}>
        {error && <p className="border-b border-slate-800 px-5 py-2 text-sm text-rose-400">{error}</p>}
        {items.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-16 text-slate-500">
            <ShieldCheck className="h-10 w-10 text-emerald-500/60" />
            <p className="text-sm">The vault is empty. No isolated threats.</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-5 py-3 font-medium">Threat</th>
                <th className="py-3 font-medium">Original location</th>
                <th className="py-3 font-medium">Size</th>
                <th className="py-3 font-medium">Isolated</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {items.map((q) => (
                <tr key={q.id} className="hover:bg-slate-800/30">
                  <td className="px-5 py-3">
                    <p className="font-medium text-rose-300">{q.threat_name}</p>
                    <p className="font-mono text-[11px] text-slate-500" title={q.sha256}>{q.sha256.slice(0, 16)}…</p>
                  </td>
                  <td className="max-w-0 py-3 pr-4"><p className="truncate font-mono text-xs text-slate-400" title={q.original_path}>{shortPath(q.original_path, 70)}</p></td>
                  <td className="py-3 text-slate-400">{formatBytes(q.size)}</td>
                  <td className="py-3 text-slate-400">{timeAgo(q.quarantined_at)}</td>
                  <td className="px-5 py-3">
                    <div className="flex justify-end gap-2">
                      <button onClick={() => setConfirm({ item: q, action: "restore" })} className="flex items-center gap-1 rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:border-amber-400/50 hover:text-amber-300">
                        <RotateCcw className="h-3.5 w-3.5" /> Restore
                      </button>
                      <button onClick={() => setConfirm({ item: q, action: "delete" })} className="flex items-center gap-1 rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:border-rose-400/50 hover:text-rose-300">
                        <Trash2 className="h-3.5 w-3.5" /> Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {confirm && (
        <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/70 backdrop-blur-sm" onClick={() => setConfirm(null)}>
          <div className="w-[440px] rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-lg font-semibold text-slate-100">{confirm.action === "restore" ? "Restore this file?" : "Delete permanently?"}</h3>
            <p className="mt-2 text-sm text-slate-400">
              {confirm.action === "restore"
                ? `"${confirm.item.threat_name}" will be returned to its original location and its hash allow-listed, so Vigil will stop blocking it. Windows will ask for administrator approval. Only do this if you are sure it is a false positive.`
                : `"${confirm.item.threat_name}" will be destroyed. This cannot be undone.`}
            </p>
            <div className="mt-6 flex justify-end gap-2">
              <button onClick={() => setConfirm(null)} className="rounded-lg px-4 py-2 text-sm text-slate-300 hover:bg-slate-800">Cancel</button>
              <button onClick={act} className={`rounded-lg px-4 py-2 text-sm font-medium ${confirm.action === "restore" ? "bg-amber-500 text-slate-950" : "bg-rose-500 text-white"}`}>
                {confirm.action === "restore" ? "Restore" : "Delete"}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
