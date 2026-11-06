import { useState } from "react";
import { HardDrive, Loader2, Square, Zap } from "lucide-react";
import type { ScanKind, ScanProgress } from "../lib/types";
import { formatBytes, formatNumber, shortPath } from "../lib/format";

export function ScanPanel({ scan, onStart, onCancel }: { scan: ScanProgress | undefined; onStart: (k: ScanKind) => Promise<void>; onCancel: () => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const running = !!scan?.running;

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    setErr(null);
    try {
      await fn();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  };

  if (running && scan) {
    return (
      <div className="space-y-4 p-5">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-cyan-300">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span className="text-sm font-medium capitalize">{scan.kind} scan in progress</span>
          </div>
          <button onClick={() => run(onCancel)} disabled={busy} className="flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 hover:border-rose-400/50 hover:text-rose-300">
            <Square className="h-3.5 w-3.5" /> Stop
          </button>
        </div>
        {/* indeterminate bar: total file count is unknown up front */}
        <div className="relative h-1.5 overflow-hidden rounded-full bg-slate-800">
          <div className="absolute inset-y-0 w-1/3 animate-scan-bar rounded-full bg-gradient-to-r from-cyan-500 to-emerald-400" />
        </div>
        <dl className="grid grid-cols-3 gap-3 text-center">
          <Metric label="Files" value={formatNumber(scan.files_scanned)} />
          <Metric label="Data" value={formatBytes(scan.bytes_scanned)} />
          <Metric label="Threats" value={String(scan.threats_found)} danger={scan.threats_found > 0} />
        </dl>
        <p className="truncate font-mono text-xs text-slate-500" title={scan.current_path ?? ""}>
          {scan.current_path ? shortPath(scan.current_path, 80) : "Enumerating…"}
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3 p-5">
      <button
        onClick={() => run(() => onStart("quick"))}
        disabled={busy}
        className="group flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-emerald-500 px-5 py-3.5 text-base font-semibold text-slate-950 shadow-[0_0_24px_#06b6d455] transition hover:shadow-[0_0_36px_#06b6d488] disabled:opacity-60"
      >
        <Zap className="h-5 w-5 transition group-hover:scale-110" /> Quick Scan
      </button>
      <button
        onClick={() => run(() => onStart("full"))}
        disabled={busy}
        className="flex w-full items-center justify-center gap-2 rounded-xl border border-slate-700 px-5 py-2.5 text-sm text-slate-300 hover:border-cyan-400/50 hover:text-cyan-300"
      >
        <HardDrive className="h-4 w-4" /> Full System Scan
      </button>
      {scan?.finished_at && (
        <p className="text-center text-xs text-slate-500">
          Last scan: {formatNumber(scan.files_scanned)} files, {scan.threats_found} threat(s), {scan.files_skipped} skipped
        </p>
      )}
      {err && <p className="text-center text-xs text-rose-400">{err}</p>}
    </div>
  );
}

function Metric({ label, value, danger }: { label: string; value: string; danger?: boolean }) {
  return (
    <div className="rounded-lg bg-slate-800/50 py-2">
      <dt className="text-[10px] uppercase tracking-wider text-slate-500">{label}</dt>
      <dd className={`font-mono text-lg tabular-nums ${danger ? "text-rose-400" : "text-slate-100"}`}>{value}</dd>
    </div>
  );
}
