import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, Copy, ExternalLink, FileSearch, FolderOpen, Globe, Loader2, Lock, ShieldAlert, ShieldCheck, XCircle } from "lucide-react";
import { Panel } from "../components/Panel";
import { api, isTauri, onFileDrop } from "../lib/api";
import { formatBytes } from "../lib/format";
import type { FileReport, Verdict } from "../lib/types";

const VERDICT: Record<Verdict, { label: string; className: string; Icon: typeof ShieldCheck }> = {
  malicious: { label: "Malicious", className: "bg-rose-500/15 text-rose-300 ring-1 ring-rose-500/40", Icon: XCircle },
  suspicious: { label: "Suspicious", className: "bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30", Icon: AlertTriangle },
  no_threats: { label: "No threats found", className: "bg-emerald-500/10 text-emerald-300 ring-1 ring-emerald-500/25", Icon: CheckCircle2 },
  error: { label: "Could not check", className: "bg-slate-700/40 text-slate-300 ring-1 ring-slate-600", Icon: AlertTriangle },
};

const ORDER: Record<Verdict, number> = { malicious: 0, suspicious: 1, error: 2, no_threats: 3 };

export function FileCheckPage() {
  const [hover, setHover] = useState(false);
  const [busy, setBusy] = useState(false);
  const [reports, setReports] = useState<FileReport[]>([]);
  const [truncated, setTruncated] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const check = async (paths: string[]) => {
    if (paths.length === 0) return;
    setBusy(true);
    setError(null);
    try {
      const r = await api.inspectPaths(paths);
      setReports([...r.reports].sort((a, b) => ORDER[a.verdict] - ORDER[b.verdict]));
      setTruncated(r.truncated);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => {
    let off: (() => void) | undefined;
    onFileDrop({ hover: setHover, drop: check }).then((f) => (off = f));
    return () => off?.();
  }, []);

  // Browser preview: HTML drag-and-drop only knows file names.
  const htmlDrop = (e: React.DragEvent) => {
    if (isTauri) return;
    e.preventDefault();
    setHover(false);
    check(Array.from(e.dataTransfer.files).map((f) => `C:\\Users\\alex\\Downloads\\${f.name}`));
  };

  const counts = reports.reduce((acc, r) => ({ ...acc, [r.verdict]: (acc[r.verdict] ?? 0) + 1 }), {} as Record<Verdict, number>);

  return (
    <div className="space-y-6">
      <div
        onDragOver={(e) => { if (!isTauri) { e.preventDefault(); setHover(true); } }}
        onDragLeave={() => !isTauri && setHover(false)}
        onDrop={htmlDrop}
        className={`flex flex-col items-center justify-center gap-3 rounded-2xl border-2 border-dashed px-6 py-12 text-center transition ${
          hover ? "border-cyan-400 bg-cyan-400/5 shadow-[0_0_40px_#22d3ee22]" : "border-slate-700 bg-slate-900/40"
        }`}
      >
        {busy ? <Loader2 className="h-10 w-10 animate-spin text-cyan-400" /> : <FileSearch className={`h-10 w-10 ${hover ? "text-cyan-300" : "text-slate-500"}`} />}
        <p className="text-lg font-medium text-slate-200">{busy ? "Checking…" : hover ? "Drop to check" : "Drop files or folders here to check them"}</p>
        <p className="max-w-lg text-sm text-slate-500">
          Checked against known-malware hashes, {">"}5,000 YARA rules and inside archives, plus signature and download-origin checks.
          Nothing is moved, changed or uploaded.
        </p>
        <button onClick={async () => check(await api.pickFiles())} disabled={busy} className="mt-1 flex items-center gap-2 rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 hover:border-cyan-400/50 hover:text-cyan-300 disabled:opacity-50">
          <FolderOpen className="h-4 w-4" /> Choose files…
        </button>
      </div>

      {error && <p className="rounded-xl border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">{error}</p>}

      {reports.length > 0 && (
        <Panel
          title={`Results · ${reports.length} file(s)`}
          action={
            <div className="flex gap-3 text-xs">
              {counts.malicious ? <span className="text-rose-300">{counts.malicious} malicious</span> : null}
              {counts.suspicious ? <span className="text-amber-300">{counts.suspicious} suspicious</span> : null}
              {counts.no_threats ? <span className="text-emerald-300">{counts.no_threats} clean</span> : null}
            </div>
          }
        >
          {truncated && <p className="border-b border-slate-800 px-5 py-2 text-xs text-amber-300">Only the first 500 files were checked. Drop a smaller folder to check the rest.</p>}
          <ul className="divide-y divide-slate-800/70">
            {reports.map((r) => (
              <ReportRow key={r.path} r={r} onQuarantined={(p) => setReports((rs) => rs.filter((x) => x.path !== p))} />
            ))}
          </ul>
        </Panel>
      )}
    </div>
  );
}

function ReportRow({ r, onQuarantined }: { r: FileReport; onQuarantined: (path: string) => void }) {
  const v = VERDICT[r.verdict];
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const name = r.path.split(/[\\/]/).pop() ?? r.path;

  const quarantine = async () => {
    setBusy(true);
    setMsg(null);
    try {
      await api.quarantinePath(r.path, r.detections[0]?.name);
      onQuarantined(r.path);
    } catch (e) {
      setMsg(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <li className="px-5 py-4">
      <div className="flex items-start gap-3">
        <span className={`mt-0.5 flex shrink-0 items-center gap-1.5 rounded-md px-2 py-1 text-xs font-medium ${v.className}`}>
          <v.Icon className="h-3.5 w-3.5" /> {v.label}
        </span>
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-slate-100" title={r.path}>{name}</p>
          <p className="truncate font-mono text-[11px] text-slate-500" title={r.path}>{r.path} · {formatBytes(r.size)}</p>
          <p className="mt-1 text-sm text-slate-300">{r.summary}</p>

          {r.detections.length > 0 && (
            <ul className="mt-2 space-y-1">
              {r.detections.map((d, i) => (
                <li key={i} className="text-xs text-slate-400">
                  <span className="font-mono text-rose-300">{d.name}</span>
                  {d.score != null && <span className="ml-1 text-slate-500">(score {d.score})</span>}
                  <span className="text-slate-500"> · {d.source}</span>
                  {d.description && <span className="text-slate-500"> · {d.description}</span>}
                </li>
              ))}
            </ul>
          )}

          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500">
            {r.signed === true && <span className="flex items-center gap-1 text-emerald-400"><ShieldCheck className="h-3.5 w-3.5" /> Validly signed</span>}
            {r.signed === false && <span className="flex items-center gap-1 text-amber-400"><ShieldAlert className="h-3.5 w-3.5" /> Not signed</span>}
            {r.downloaded_from && (
              <span className="flex min-w-0 items-center gap-1" title={r.downloaded_from}>
                <Globe className="h-3.5 w-3.5 shrink-0" /> <span className="truncate">Downloaded from {r.downloaded_from}</span>
              </span>
            )}
          </div>
          {r.indicators.length > 0 && (
            <ul className="mt-1.5 space-y-0.5">
              {r.indicators.map((i) => (
                <li key={i} className="flex items-start gap-1.5 text-xs text-amber-300/90"><AlertTriangle className="mt-0.5 h-3 w-3 shrink-0" /> {i}</li>
              ))}
            </ul>
          )}

          <div className="mt-3 flex flex-wrap items-center gap-2">
            {(r.verdict === "malicious" || r.verdict === "suspicious") && (
              <button onClick={quarantine} disabled={busy} title="Requires administrator approval" className="flex items-center gap-1 rounded-md bg-rose-500/90 px-2.5 py-1 text-xs font-medium text-white hover:bg-rose-500 disabled:opacity-50">
                <Lock className="h-3.5 w-3.5" /> Quarantine
              </button>
            )}
            {r.sha256 && (
              <>
                <button onClick={() => api.openVirusTotal(r.sha256!)} title="Opens VirusTotal's page for this hash. The file is not uploaded." className="flex items-center gap-1 rounded-md border border-slate-700 px-2.5 py-1 text-xs text-slate-300 hover:border-cyan-400/50 hover:text-cyan-300">
                  <ExternalLink className="h-3.5 w-3.5" /> Look up on VirusTotal
                </button>
                <button onClick={() => navigator.clipboard?.writeText(r.sha256!)} title={r.sha256} className="flex items-center gap-1 rounded-md px-2 py-1 font-mono text-[11px] text-slate-500 hover:text-slate-300">
                  <Copy className="h-3 w-3" /> {r.sha256.slice(0, 16)}…
                </button>
              </>
            )}
            {msg && <span className="text-xs text-rose-400">{msg}</span>}
          </div>
        </div>
      </div>
    </li>
  );
}
