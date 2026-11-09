import { useCallback, useEffect, useMemo, useState } from "react";
import { Camera, FileWarning, History, Loader2, RotateCcw, ShieldAlert } from "lucide-react";
import { Panel } from "../components/Panel";
import { api } from "../lib/api";
import { formatBytes, shortPath, timeAgo } from "../lib/format";
import type { EngineStatus, FileChange, SecurityEvent, Snapshot } from "../lib/types";

const when = (t: number) => new Date(t * 1000).toLocaleString();

export function RecoveryPage({ status, events, refresh }: { status: EngineStatus | null; events: SecurityEvent[]; refresh: () => Promise<void> }) {
  const [snapshots, setSnapshots] = useState<Snapshot[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [taking, setTaking] = useState(false);
  const [chosen, setChosen] = useState<Snapshot | null>(null);

  const load = useCallback(() => api.listSnapshots().then((s) => { setSnapshots(s); setError(null); }).catch((e) => setError(String(e))), []);
  useEffect(() => { load(); }, [load]);

  const take = async () => {
    setTaking(true);
    setError(null);
    try {
      await api.createSnapshot();
      await load();
      await refresh();
    } catch (e) {
      setError(String(e));
    } finally {
      setTaking(false);
    }
  };

  return (
    <div className="space-y-6">
      <Panel>
        <div className="flex items-center justify-between gap-6 px-6 py-5">
          <div className="flex items-start gap-4">
            <History className="mt-0.5 h-8 w-8 shrink-0 text-cyan-400" />
            <div>
              <p className="text-base font-medium text-slate-100">Ransomware rollback</p>
              <p className="max-w-2xl text-sm text-slate-400">
                Snapshots of your system drive are taken automatically, so files that ransomware encrypts or deletes can be put back.
                Pick a snapshot from before the attack to see what changed since then.
              </p>
              <p className="mt-1 text-xs text-slate-500">
                {status?.last_snapshot ? `Newest automatic snapshot: ${timeAgo(status.last_snapshot)}` : "No automatic snapshot yet."}
                {status?.snapshot_error && <span className="text-amber-400"> · Last attempt failed: {status.snapshot_error}</span>}
              </p>
            </div>
          </div>
          <button onClick={take} disabled={taking} className="flex shrink-0 items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:border-cyan-400/50 hover:text-cyan-300 disabled:opacity-50">
            {taking ? <Loader2 className="h-4 w-4 animate-spin" /> : <Camera className="h-4 w-4" />}
            {taking ? "Taking snapshot…" : "Take snapshot now"}
          </button>
        </div>
      </Panel>

      {error && <p className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-300">{error}</p>}

      <Panel title="Snapshots">
        {!snapshots && !error && <p className="px-5 py-6 text-sm text-slate-500">Loading snapshots…</p>}
        {snapshots && snapshots.length === 0 && <p className="px-5 py-10 text-center text-sm text-slate-500">No snapshots yet. Take one now, or wait for the automatic one.</p>}
        <ul className="divide-y divide-slate-800/70">
          {snapshots?.map((s) => (
            <li key={s.id} className={`flex items-center justify-between gap-4 px-5 py-3 ${chosen?.id === s.id ? "bg-cyan-400/5" : ""}`}>
              <div>
                <p className="text-sm text-slate-200">{when(s.created_at)} <span className="text-xs text-slate-500">({timeAgo(s.created_at)})</span></p>
                <p className="text-xs text-slate-500">{s.volume || "Unknown drive"} · {s.ours ? "Automatic rollback snapshot" : "Windows restore point / backup"}</p>
              </div>
              <button onClick={() => setChosen(s)} className="shrink-0 rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 hover:border-cyan-400/50 hover:text-cyan-300">
                Find changed files
              </button>
            </li>
          ))}
        </ul>
      </Panel>

      {chosen && <ChangesPanel key={chosen.id} snapshot={chosen} events={events} />}
    </div>
  );
}

function ChangesPanel({ snapshot, events }: { snapshot: Snapshot; events: SecurityEvent[] }) {
  const [changes, setChanges] = useState<FileChange[] | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [onlySuspicious, setOnlySuspicious] = useState(true);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [restoredAt, setRestoredAt] = useState<number | null>(null);

  const scan = useCallback(async () => {
    setChanges(null);
    setMsg(null);
    try {
      const r = await api.rollbackPreview(snapshot.id);
      setChanges(r.changes);
      setTruncated(r.truncated);
      // Pre-select what ransomware typically leaves behind.
      setSelected(new Set(r.changes.filter((c) => c.looks_encrypted || c.change === "deleted").map((c) => c.path)));
      setOnlySuspicious(r.changes.some((c) => c.looks_encrypted || c.change === "deleted"));
    } catch (e) {
      setChanges([]);
      setMsg(String(e));
    }
  }, [snapshot.id]);
  useEffect(() => { scan(); }, [scan]);

  const shown = useMemo(
    () => (changes ?? []).filter((c) => !onlySuspicious || c.looks_encrypted || c.change === "deleted"),
    [changes, onlySuspicious],
  );
  const encrypted = (changes ?? []).filter((c) => c.looks_encrypted).length;
  const deleted = (changes ?? []).filter((c) => c.change === "deleted").length;
  const outcome = restoredAt ? events.find((e) => e.kind === "recovery" && e.title.startsWith("Restored") && e.timestamp >= restoredAt) : undefined;

  const toggle = (p: string) => {
    const next = new Set(selected);
    if (next.has(p)) next.delete(p);
    else next.add(p);
    setSelected(next);
  };
  const allShown = shown.length > 0 && shown.every((c) => selected.has(c.path));
  const toggleAll = () => {
    const next = new Set(selected);
    shown.forEach((c) => (allShown ? next.delete(c.path) : next.add(c.path)));
    setSelected(next);
  };

  const restore = async () => {
    setBusy(true);
    setMsg(null);
    const started = Math.floor(Date.now() / 1000) - 1;
    try {
      await api.rollbackRestore(snapshot.id, [...selected]);
      setRestoredAt(started);
      await scan();
    } catch (e) {
      setMsg(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel
      title={`Changed since ${when(snapshot.created_at)}`}
      action={
        changes && changes.length > 0 ? (
          <label className="flex items-center gap-2 text-xs text-slate-400">
            <input type="checkbox" checked={onlySuspicious} onChange={(e) => setOnlySuspicious(e.target.checked)} className="accent-cyan-500" />
            Only encrypted-looking &amp; deleted
          </label>
        ) : undefined
      }
    >
      {outcome && (
        <p className="border-b border-slate-800/70 bg-emerald-500/5 px-5 py-3 text-sm text-emerald-300">
          {outcome.title}. {outcome.detail}
        </p>
      )}
      {msg && <p className="border-b border-slate-800/70 px-5 py-3 text-sm text-rose-400">{msg}</p>}
      {!changes && (
        <p className="flex items-center gap-2 px-5 py-6 text-sm text-slate-500">
          <Loader2 className="h-4 w-4 animate-spin" /> Comparing Desktop, Documents, Pictures, Music, Videos and Downloads with the snapshot…
        </p>
      )}
      {changes && changes.length === 0 && !msg && <p className="px-5 py-10 text-center text-sm text-slate-500">Nothing in your personal folders has changed since this snapshot.</p>}
      {changes && changes.length > 0 && (
        <>
          <div className="flex items-center gap-4 border-b border-slate-800/70 px-5 py-3 text-xs text-slate-400">
            {encrypted > 0 && <span className="flex items-center gap-1 text-rose-300"><ShieldAlert className="h-3.5 w-3.5" />{encrypted} look encrypted</span>}
            {deleted > 0 && <span className="flex items-center gap-1 text-amber-300"><FileWarning className="h-3.5 w-3.5" />{deleted} deleted</span>}
            <span>{changes.length} changed in total{truncated ? " (showing the first 5,000)" : ""}</span>
          </div>
          <div className="max-h-[420px] overflow-y-auto">
            <table className="w-full table-fixed text-sm">
              <thead className="sticky top-0 bg-slate-900 text-left text-xs uppercase tracking-wider text-slate-500">
                <tr>
                  <th className="w-14 px-5 py-2"><input type="checkbox" aria-label="Select all shown" checked={allShown} onChange={toggleAll} className="accent-cyan-500" /></th>
                  <th className="py-2 font-medium">File</th>
                  <th className="w-40 py-2 font-medium">Change</th>
                  <th className="w-48 px-5 py-2 text-right font-medium">Size then → now</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {shown.map((c) => (
                  <tr key={c.path} className="hover:bg-slate-800/30">
                    <td className="px-5 py-2"><input type="checkbox" aria-label={`Restore ${c.path}`} checked={selected.has(c.path)} onChange={() => toggle(c.path)} className="accent-cyan-500" /></td>
                    <td className="py-2 pr-4"><p className="truncate font-mono text-xs text-slate-300" title={c.path}>{shortPath(c.path, 110)}</p></td>
                    <td className="py-2 text-xs">
                      {c.looks_encrypted ? <span className="text-rose-300">Looks encrypted</span> : c.change === "deleted" ? <span className="text-amber-300">Deleted</span> : <span className="text-slate-400">Modified {c.modified_at ? timeAgo(c.modified_at) : ""}</span>}
                    </td>
                    <td className="px-5 py-2 text-right font-mono text-xs text-slate-500">{formatBytes(c.size_then)} → {c.size_now == null ? "gone" : formatBytes(c.size_now)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="flex items-center justify-between gap-4 px-5 py-4">
            <p className="text-xs text-slate-500">Current versions are moved to a "Vigil Restore Backup" folder in your user folder first, so nothing is lost. Needs administrator approval.</p>
            <button onClick={restore} disabled={busy || selected.size === 0} className="flex shrink-0 items-center gap-2 rounded-lg bg-cyan-500 px-4 py-2 text-sm font-medium text-slate-950 hover:bg-cyan-400 disabled:opacity-40">
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <RotateCcw className="h-4 w-4" />}
              Restore {selected.size} file{selected.size === 1 ? "" : "s"}
            </button>
          </div>
        </>
      )}
    </Panel>
  );
}
