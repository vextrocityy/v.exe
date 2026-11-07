import { useEffect, useState } from "react";
import { Plus, ShieldAlert, X } from "lucide-react";
import { Panel } from "../components/Panel";
import { Toggle } from "../components/Toggle";
import { api } from "../lib/api";
import type { Settings } from "../lib/types";

type BoolKey = { [K in keyof Settings]: Settings[K] extends boolean ? K : never }[keyof Settings];

const SHIELDS: { key: BoolKey; label: string; hint: string }[] = [
  { key: "process_monitor", label: "Process Guard", hint: "Check every new process against signatures as it starts." },
  { key: "file_monitor", label: "File Shield", hint: "Scan files as they land in Downloads, Desktop, Temp and Startup." },
  { key: "persistence_monitor", label: "Persistence Watch", hint: "Alert on new Run keys, services and Startup items." },
  { key: "behavior_monitor", label: "Behavior Engine", hint: "Detect ransomware-like mass modification and suspicious process chains." },
];

const RESPONSE: { key: BoolKey; label: string; hint: string }[] = [
  { key: "auto_quarantine", label: "Quarantine automatically", hint: "Move confirmed threats to the vault without asking." },
  { key: "auto_kill_malicious", label: "Terminate malicious processes", hint: "Kill processes whose executable matches a signature." },
  { key: "low_priority_scans", label: "Low-priority scanning", hint: "Run scans at background CPU and disk priority." },
];

function AppUpdateRow({ s, set }: { s: Settings; set: <K extends keyof Settings>(k: K, v: Settings[K]) => void }) {
  const [status, setStatus] = useState<string | null>(null);
  const [build, setBuild] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const refresh = () =>
    api.getStatus().then((st) => {
      setStatus(st.app_update_status);
      setBuild(st.build);
    }).catch(() => {});
  useEffect(() => {
    refresh();
  }, []);
  const check = async () => {
    setBusy(true);
    try {
      await api.checkAppUpdate();
      for (let i = 0; i < 20; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        const st = await api.getStatus();
        setStatus(st.app_update_status);
        if (st.app_update_status && !st.app_update_status.startsWith("Checking")) break;
      }
    } catch (e) {
      setStatus(String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Row label="Install app updates automatically" hint="New Sentinel-Lite releases are downloaded from this project's GitHub Releases, checked against their SHA-256 checksums and installed silently. The dashboard reopens in the tray afterwards.">
        <Toggle label="Install app updates automatically" checked={s.auto_update_app} onChange={(v) => set("auto_update_app", v)} />
      </Row>
      <div className="flex items-center justify-between gap-6 border-b border-slate-800/70 px-5 py-4">
        <div>
          <p className="text-sm text-slate-200">App version</p>
          <p className="text-xs text-slate-500">
            {build ? `Build ${build}` : "Development build"}
            {status ? ` · ${status}` : ""}
          </p>
        </div>
        <button onClick={check} disabled={busy} className="shrink-0 rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 hover:border-cyan-400/50 hover:text-cyan-300 disabled:opacity-50">
          {busy ? "Checking…" : "Check now"}
        </button>
      </div>
    </>
  );
}

export function SettingsPage() {
  const [s, setS] = useState<Settings | null>(null);
  const [saved, setSaved] = useState<Settings | null>(null);
  const [newExclusion, setNewExclusion] = useState("");
  const [status, setStatus] = useState<string | null>(null);

  useEffect(() => {
    api.getSettings().then((v) => { setS(v); setSaved(v); }).catch((e) => setStatus(String(e)));
  }, []);

  if (!s) return <Panel><p className="p-6 text-sm text-slate-500">{status ?? "Loading settings…"}</p></Panel>;

  const dirty = JSON.stringify(s) !== JSON.stringify(saved);
  const set = <K extends keyof Settings>(k: K, v: Settings[K]) => setS({ ...s, [k]: v });

  const save = async () => {
    try {
      const applied = await api.updateSettings(s);
      setS(applied);
      setSaved(applied);
      setStatus("Settings saved and applied.");
    } catch (e) {
      setStatus(`Could not save: ${e}`);
    }
  };

  const addExclusion = () => {
    const v = newExclusion.trim();
    if (v && !s.exclusions.includes(v)) set("exclusions", [...s.exclusions, v]);
    setNewExclusion("");
  };

  return (
    <div className="space-y-6 pb-20">
      <p className="flex items-center gap-2 text-xs text-slate-500">
        <ShieldAlert className="h-4 w-4 text-amber-400/80" />
        Changes that reduce protection (turning shields off, adding exclusions) ask for administrator approval.
      </p>
      <Panel>
        <Row label="Real-time protection" hint="Master switch for every shield below." strong>
          <Toggle label="Real-time protection" checked={s.realtime_protection} onChange={(v) => set("realtime_protection", v)} />
        </Row>
      </Panel>

      <div className="grid grid-cols-2 gap-6">
        <Panel title="Shields">
          {SHIELDS.map((o) => (
            <Row key={o.key} label={o.label} hint={o.hint}>
              <Toggle label={o.label} checked={s[o.key]} disabled={!s.realtime_protection} onChange={(v) => set(o.key, v)} />
            </Row>
          ))}
        </Panel>
        <Panel title="Response & performance">
          {RESPONSE.map((o) => (
            <Row key={o.key} label={o.label} hint={o.hint}>
              <Toggle label={o.label} checked={s[o.key]} onChange={(v) => set(o.key, v)} />
            </Row>
          ))}
          <Row label="Scan threads" hint="0 = automatic (half of your CPU cores).">
            <NumberInput value={s.max_scan_threads} min={0} max={64} onChange={(v) => set("max_scan_threads", v)} />
          </Row>
          <Row label="Max file size (MB)" hint="Larger files are skipped.">
            <NumberInput value={s.max_file_size_mb} min={1} max={4096} onChange={(v) => set("max_file_size_mb", v)} />
          </Row>
        </Panel>
      </div>

      <Panel title="Updates & schedule">
        <AppUpdateRow s={s} set={set} />
        <Row label="Automatic signature updates" hint="Download new threat signatures in the background.">
          <Toggle label="Automatic signature updates" checked={s.auto_update} onChange={(v) => set("auto_update", v)} />
        </Row>
        <Row label="Update interval (hours)" hint="How often to check for new signatures.">
          <NumberInput value={s.update_interval_hours} min={1} max={168} onChange={(v) => set("update_interval_hours", v)} />
        </Row>
        <Row label="Community threat feed" hint="Add hashes of recently submitted malware from abuse.ch MalwareBazaar. Code-signed and Windows files matched only by this feed are reported, never quarantined.">
          <Toggle label="Community threat feed" checked={s.community_feeds} onChange={(v) => set("community_feeds", v)} />
        </Row>
        <div className="border-b border-slate-800/70 px-5 py-4">
          <label htmlFor="abusech-key" className="text-sm text-slate-200">abuse.ch Auth-Key</label>
          <p className="text-xs text-slate-500">
            Required by the community feed. Get a free key at auth.abuse.ch. Check abuse.ch's terms before commercial use. Stored by the service and never shown again.
          </p>
          <input
            id="abusech-key"
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={s.abusech_auth_key ?? ""}
            onChange={(e) => set("abusech_auth_key", e.target.value.trim() === "" ? null : e.target.value.trim())}
            placeholder={s.community_feeds ? "Paste your key to enable the community feed" : "Community feed is off"}
            className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
          />
        </div>
        <Row label="Scheduled quick scan" hint="Run a low-priority quick scan in the background.">
          <Toggle label="Scheduled quick scan" checked={s.scheduled_scan} onChange={(v) => set("scheduled_scan", v)} />
        </Row>
        <Row label="Scan every (hours)" hint="Interval between scheduled quick scans.">
          <NumberInput value={s.scheduled_scan_hours} min={1} max={720} onChange={(v) => set("scheduled_scan_hours", v)} />
        </Row>
      </Panel>

      <Panel title="Execution & network">
        <Row label="Execution Guard" hint="Stop programs without a valid digital signature when they start from Downloads, Temp or AppData. Allow trusted ones from Activity.">
          <Toggle label="Execution Guard" checked={s.block_untrusted_risky} disabled={!s.realtime_protection} onChange={(v) => set("block_untrusted_risky", v)} />
        </Row>
        <Row label="Block Office/PDF launching shells" hint="Stop cmd, PowerShell, wscript and mshta when started by Word, Excel, Outlook, PowerPoint or a PDF reader (macro and exploit attacks).">
          <Toggle label="Block Office/PDF launching shells" checked={s.block_office_children} disabled={!s.realtime_protection} onChange={(v) => set("block_office_children", v)} />
        </Row>
        <Row label="Encryption detection" hint="A burst of rewrites across folders whose new content looks encrypted (high entropy) freezes the writing program.">
          <Toggle label="Encryption detection" checked={s.entropy_detection} onChange={(v) => set("entropy_detection", v)} />
        </Row>
        <Row label="Network Guard" hint="Block connections to known-criminal networks (Spamhaus DROP, updated daily) plus your own list, via Windows Filtering Platform.">
          <Toggle label="Network Guard" checked={s.network_guard} disabled={!s.realtime_protection} onChange={(v) => set("network_guard", v)} />
        </Row>
        <div className="px-5 py-4">
          <p className="text-sm text-slate-200">Trusted programs</p>
          <p className="text-xs text-slate-500">Allowed despite Execution Guard. Trust is tied to the exact file: an updated version asks again.</p>
          {s.trusted_apps.length === 0 ? (
            <p className="mt-2 text-xs text-slate-600">None yet.</p>
          ) : (
            <ul className="mt-2 space-y-1.5">
              {s.trusted_apps.map((t) => (
                <li key={t.sha256} className="flex items-center justify-between rounded-lg bg-slate-800/40 px-3 py-2">
                  <span className="truncate font-mono text-xs text-slate-300" title={`SHA-256 ${t.sha256}`}>{t.path}</span>
                  <button aria-label={`Stop trusting ${t.path}`} onClick={() => set("trusted_apps", s.trusted_apps.filter((x) => x.sha256 !== t.sha256))} className="text-slate-500 hover:text-rose-400">
                    <X className="h-4 w-4" />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      </Panel>

      <Panel title="Ransomware, archives & clean-up">
        <Row label="Scan inside archives" hint="Look inside ZIP files (including Office documents) and ISO/IMG disk images. A malicious file inside quarantines the whole archive.">
          <Toggle label="Scan inside archives" checked={s.archive_scanning} onChange={(v) => set("archive_scanning", v)} />
        </Row>
        <Row label="Ransomware decoys" hint="Hidden decoy files in Documents, Pictures and Desktop. Nothing legitimate touches them, so a change means ransomware.">
          <Toggle label="Ransomware decoys" checked={s.ransomware_decoys} disabled={!s.realtime_protection || !s.file_monitor} onChange={(v) => set("ransomware_decoys", v)} />
        </Row>
        <Row label="Suspend the culprit" hint="When a decoy changes, freeze the program writing the most (never Windows or signed programs). You choose Terminate or Resume.">
          <Toggle label="Suspend the culprit" checked={s.ransomware_suspend} disabled={!s.ransomware_decoys} onChange={(v) => set("ransomware_suspend", v)} />
        </Row>
        <Row label="Startup clean-up" hint="When a file is quarantined, also remove the Run keys, Startup shortcuts and services that launch it. Restoring the file puts them back.">
          <Toggle label="Startup clean-up" checked={s.startup_cleanup} onChange={(v) => set("startup_cleanup", v)} />
        </Row>
      </Panel>

      <Panel title="YARA rules">
        <Row label="YARA scanning" hint="Scan executables, scripts, shortcuts and documents with rules that recognise malware families and their new variants.">
          <Toggle label="YARA scanning" checked={s.yara_enabled} onChange={(v) => set("yara_enabled", v)} />
        </Row>
        <Row label="YARA Forge rule feed" hint="Download the curated YARA Forge core package (about 5,000 rules) with each update.">
          <Toggle label="YARA Forge rule feed" checked={s.yara_rules_feed} disabled={!s.yara_enabled} onChange={(v) => set("yara_rules_feed", v)} />
        </Row>
        <Row label="Quarantine threshold" hint="Rule score (0-100) needed to quarantine automatically. Lower-scoring matches are reported for review. 101 = never quarantine.">
          <NumberInput value={s.yara_min_remediate_score} min={50} max={101} onChange={(v) => set("yara_min_remediate_score", v)} />
        </Row>
        <Row label="Max YARA file size (MB)" hint="Larger files are still hash-checked, but not YARA-scanned.">
          <NumberInput value={s.yara_max_file_mb} min={1} max={256} onChange={(v) => set("yara_max_file_mb", v)} />
        </Row>
      </Panel>

      <Panel title="Exclusions">
        <div className="space-y-3 p-5">
          <p className="text-xs text-slate-500">Files and folders whose path starts with one of these are never scanned. Whole drives cannot be excluded.</p>
          <div className="flex gap-2">
            <input
              value={newExclusion}
              onChange={(e) => setNewExclusion(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && addExclusion()}
              placeholder="D:\Projects\build-output"
              className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
            />
            <button onClick={addExclusion} className="flex items-center gap-1 rounded-lg border border-slate-700 px-3 text-sm text-slate-300 hover:border-cyan-400/50 hover:text-cyan-300">
              <Plus className="h-4 w-4" /> Add
            </button>
          </div>
          <ul className="space-y-1.5">
            {s.exclusions.map((p) => (
              <li key={p} className="flex items-center justify-between rounded-lg bg-slate-800/40 px-3 py-2">
                <span className="truncate font-mono text-xs text-slate-300">{p}</span>
                <button aria-label={`Remove ${p}`} onClick={() => set("exclusions", s.exclusions.filter((x) => x !== p))} className="text-slate-500 hover:text-rose-400">
                  <X className="h-4 w-4" />
                </button>
              </li>
            ))}
          </ul>
        </div>
      </Panel>

      {(dirty || status) && (
        <div className="fixed bottom-6 right-8 flex items-center gap-3 rounded-xl border border-slate-700 bg-slate-900/95 px-4 py-3 shadow-2xl">
          <span className="text-sm text-slate-400">{dirty ? "You have unsaved changes." : status}</span>
          {dirty && (
            <>
              <button onClick={() => setS(saved)} className="rounded-lg px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-800">Discard</button>
              <button onClick={save} className="rounded-lg bg-cyan-500 px-3 py-1.5 text-sm font-medium text-slate-950 hover:bg-cyan-400">Save</button>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function Row({ label, hint, children, strong }: { label: string; hint: string; children: React.ReactNode; strong?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-6 border-b border-slate-800/70 px-5 py-4 last:border-0">
      <div>
        <p className={strong ? "text-base font-medium text-slate-100" : "text-sm text-slate-200"}>{label}</p>
        <p className="text-xs text-slate-500">{hint}</p>
      </div>
      {children}
    </div>
  );
}

function NumberInput({ value, min, max, onChange }: { value: number; min: number; max: number; onChange: (v: number) => void }) {
  return (
    <input
      type="number"
      value={value}
      min={min}
      max={max}
      onChange={(e) => onChange(Math.min(max, Math.max(min, Number(e.target.value) || 0)))}
      className="w-20 rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-right font-mono text-sm text-slate-200 focus:border-cyan-500 focus:outline-none"
    />
  );
}
