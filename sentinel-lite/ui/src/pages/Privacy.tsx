import { useCallback, useEffect, useState } from "react";
import { Camera, Mic, ShieldCheck } from "lucide-react";
import { Panel } from "../components/Panel";
import { api } from "../lib/api";
import { shortPath, timeAgo } from "../lib/format";
import type { DeviceUse, EngineStatus } from "../lib/types";

const ICON = { camera: Camera, microphone: Mic };
const LABEL = { camera: "Camera", microphone: "Microphone" };

function duration(u: DeviceUse): string | null {
  if (!u.last_started || !u.last_stopped || u.last_stopped < u.last_started) return null;
  const s = u.last_stopped - u.last_started;
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min`;
  return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`;
}

/** Live "in use" banner, shared with the dashboard. */
export function DevicesInUse({ devices, compact }: { devices: DeviceUse[]; compact?: boolean }) {
  if (devices.length === 0) return null;
  return (
    <div className={`flex flex-wrap items-center gap-2 rounded-xl border border-amber-400/30 bg-amber-400/10 ${compact ? "px-4 py-2.5" : "px-5 py-4"}`}>
      <span className="relative mr-1 flex h-2.5 w-2.5">
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-amber-400 opacity-60" />
        <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-amber-400" />
      </span>
      {devices.map((d) => {
        const Icon = ICON[d.device];
        return (
          <span key={`${d.device}-${d.path ?? d.app}`} className="flex items-center gap-1.5 text-sm text-amber-100" title={d.path ?? d.app}>
            <Icon className="h-4 w-4 text-amber-300" />
            {LABEL[d.device]} in use by <strong className="font-medium">{d.app}</strong>
            {d.last_started && <span className="text-xs text-amber-200/70">since {timeAgo(d.last_started)}</span>}
          </span>
        );
      })}
    </div>
  );
}

export function PrivacyPage({ status }: { status: EngineStatus | null }) {
  const [history, setHistory] = useState<DeviceUse[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(() => api.getDeviceUsage().then((h) => { setHistory(h); setError(null); }).catch((e) => setError(String(e))), []);
  const live = status?.devices_in_use ?? [];
  const liveKey = live.map((d) => d.app).join("|");
  // Reload when something starts or stops.
  useEffect(() => { load(); }, [load, liveKey]);

  return (
    <div className="space-y-6">
      {live.length > 0 ? (
        <DevicesInUse devices={live} />
      ) : (
        <div className="flex items-center gap-3 rounded-xl border border-emerald-500/20 bg-emerald-500/5 px-5 py-4 text-sm text-emerald-200">
          <ShieldCheck className="h-5 w-5 text-emerald-400" />
          Nothing is using your camera or microphone right now.
        </div>
      )}
      <Panel title="Camera & microphone history">
        <p className="border-b border-slate-800/70 px-5 py-3 text-xs text-slate-500">
          Every app Windows has recorded using the camera or microphone, newest first. You get a notification the moment one switches on.
          To block an app for good, turn off its access in Windows Settings → Privacy &amp; security.
        </p>
        {error && <p className="px-5 py-3 text-sm text-rose-400">{error}</p>}
        {history && history.length === 0 && <p className="px-5 py-10 text-center text-sm text-slate-500">No camera or microphone use recorded yet.</p>}
        {history && history.length > 0 && (
          <table className="w-full table-fixed text-sm">
            <thead className="text-left text-xs uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-5 py-3 font-medium">App</th>
                <th className="w-40 py-3 font-medium">Device</th>
                <th className="w-40 py-3 font-medium">Last used</th>
                <th className="w-32 px-5 py-3 font-medium">For</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {history.map((u) => {
                const Icon = ICON[u.device];
                return (
                  <tr key={`${u.device}-${u.user}-${u.path ?? u.app}`} className="hover:bg-slate-800/30">
                    <td className="px-5 py-3">
                      <p className="truncate text-slate-200">{u.app}</p>
                      {u.path && <p className="truncate font-mono text-[11px] text-slate-500" title={u.path}>{shortPath(u.path, 72)}</p>}
                    </td>
                    <td className="py-3 text-slate-400"><span className="flex items-center gap-1.5"><Icon className="h-4 w-4" />{LABEL[u.device]}</span></td>
                    <td className="py-3 text-slate-400">
                      {u.in_use ? <span className="rounded-md bg-amber-400/15 px-2 py-0.5 text-xs text-amber-300">In use now</span> : u.last_started ? timeAgo(u.last_started) : "–"}
                    </td>
                    <td className="px-5 py-3 text-slate-400">{u.in_use ? "–" : duration(u) ?? "–"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
