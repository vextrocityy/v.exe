import { useEffect, useState, type ReactNode } from "react";
import { ChevronDown, Plus, ShieldAlert, X } from "lucide-react";
import { Panel } from "../components/Panel";
import { Toggle } from "../components/Toggle";
import { api } from "../lib/api";
import type { EngineStatus, Settings } from "../lib/types";

type BoolKey = { [K in keyof Settings]: Settings[K] extends boolean ? K : never }[keyof Settings];
type Setter = <K extends keyof Settings>(k: K, v: Settings[K]) => void;

function AppUpdateRow({ s, set, status }: { s: Settings; set: Setter; status: EngineStatus | null }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const line = status?.app_update_status ?? null;
  // "Check now" is finished when the engine reports something other than "Checking…".
  useEffect(() => {
    if (busy && line && !line.startsWith("Checking")) setBusy(false);
  }, [busy, line]);
  const check = async () => {
    setBusy(true);
    setErr(null);
    try {
      await api.checkAppUpdate();
      setTimeout(() => setBusy(false), 30000); // never leave the button stuck
    } catch (e) {
      setErr(String(e));
      setBusy(false);
    }
  };
  return (
    <>
      <Row label="Install app updates automatically" hint="New Vigil releases are downloaded from this project's GitHub Releases, checked against their SHA-256 checksums and installed silently.">
        <Toggle label="Install app updates automatically" checked={s.auto_update_app} onChange={(v) => set("auto_update_app", v)} />
      </Row>
      <div className="flex items-center justify-between gap-6 border-b border-slate-800/70 px-5 py-4">
        <div>
          <p className="text-sm text-slate-200">App version</p>
          <p className="text-xs text-slate-500">
            {!status ? "Unknown (engine not running)" : status.build ? `Build ${status.build}` : "Development build"}
            {err ? ` · ${err}` : line ? ` · ${line}` : ""}
          </p>
        </div>
        <button onClick={check} disabled={busy || !status} className="shrink-0 rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-300 hover:border-cyan-400/50 hover:text-cyan-300 disabled:opacity-50">
          {busy ? "Checking…" : "Check now"}
        </button>
      </div>
    </>
  );
}

export function SettingsPage({ status }: { status: EngineStatus | null }) {
  const [s, setS] = useState<Settings | null>(null);
  const [saved, setSaved] = useState<Settings | null>(null);
  const [newExclusion, setNewExclusion] = useState("");
  const [note, setNote] = useState<string | null>(null);
  const connected = !!status;

  // Load once the engine is reachable (and again if it comes back after being down).
  useEffect(() => {
    if (!connected || s) return;
    api.getSettings().then((v) => { setS(v); setSaved(v); setNote(null); }).catch((e) => setNote(String(e)));
  }, [connected, s]);

  // The "saved" note is a confirmation, not a fixture.
  useEffect(() => {
    if (!note) return;
    const t = setTimeout(() => setNote(null), 4000);
    return () => clearTimeout(t);
  }, [note]);

  if (!s) return <Panel><p className="p-6 text-sm text-slate-500">{note ?? (connected ? "Loading settings…" : "Settings are available when the protection engine is running.")}</p></Panel>;

  const dirty = JSON.stringify(s) !== JSON.stringify(saved);
  const set: Setter = (k, v) => setS({ ...s, [k]: v });
  const toggle = (key: BoolKey, label: string, hint: string, disabled = false) => (
    <Row key={key} label={label} hint={hint}>
      <Toggle label={label} checked={s[key]} disabled={disabled} onChange={(v) => set(key, v)} />
    </Row>
  );
  const off = !s.realtime_protection;

  const save = async () => {
    try {
      const applied = await api.updateSettings(s);
      setS(applied);
      setSaved(applied);
      setNote("Settings saved and applied.");
    } catch (e) {
      setNote(`Could not save: ${e}`);
    }
  };

  const addExclusion = () => {
    const v = newExclusion.trim();
    if (v && !s.exclusions.includes(v)) set("exclusions", [...s.exclusions, v]);
    setNewExclusion("");
  };
  const pickExclusion = async () => {
    try {
      const picked = await api.pickFiles();
      const add = picked.filter((p) => !s.exclusions.includes(p));
      if (add.length) set("exclusions", [...s.exclusions, ...add]);
    } catch (e) {
      setNote(String(e));
    }
  };

  return (
    <div className="space-y-6 pb-20">
      <p className="flex items-center gap-2 text-xs text-slate-500">
        <ShieldAlert className="h-4 w-4 text-amber-400/80" />
        Changes that reduce protection (turning things off, adding exceptions) ask for administrator approval.
      </p>

      <Panel>
        <Row label="Real-time protection" hint="Master switch. Turn it off only to troubleshoot." strong>
          <Toggle label="Real-time protection" checked={s.realtime_protection} onChange={(v) => set("realtime_protection", v)} />
        </Row>
      </Panel>

      <Panel title="Everyday">
        {toggle("auto_quarantine", "Quarantine threats automatically", "Move confirmed threats to the vault without asking. You can restore anything from Quarantine.")}
        {toggle("privacy_monitor", "Camera & microphone alerts", "Notify the moment any app turns on your camera or microphone.", off)}
        {toggle("rollback_snapshots", "Ransomware rollback snapshots", "Keep the 3 newest snapshots of your system drive, so files hit by ransomware can be restored from Recovery.")}
        {toggle("scheduled_scan", "Scheduled quick scan", "Run a low-priority quick scan in the background.")}
        <Row label="Scan every (hours)" hint="Time between scheduled quick scans.">
          <NumberInput value={s.scheduled_scan_hours} min={1} max={720} onChange={(v) => set("scheduled_scan_hours", v)} />
        </Row>
        <AppUpdateRow s={s} set={set} status={status} />
        {toggle("auto_update", "Update threat definitions automatically", "Download new signatures and detection rules in the background.")}
      </Panel>

      <Panel title="Exceptions">
        <div className="border-b border-slate-800/70 px-5 py-4">
          <p className="text-sm text-slate-200">Trusted programs</p>
          <p className="text-xs text-slate-500">Unsigned programs you allowed to run from Downloads, Temp or AppData. Trust is tied to the exact file: an updated version asks again.</p>
          {s.trusted_apps.length === 0 ? (
            <p className="mt-2 text-xs text-slate-500">None. Allow one from its alert when it gets blocked.</p>
          ) : (
            <ul className="mt-2 space-y-1.5">
              {s.trusted_apps.map((t) => (
                <li key={`${t.sha256}|${t.path}`} className="flex items-center justify-between rounded-lg bg-slate-800/40 px-3 py-2">
                  <span className="truncate font-mono text-xs text-slate-300" title={`SHA-256 ${t.sha256}`}>{t.path}</span>
                  <button aria-label={`Stop trusting ${t.path}`} onClick={() => set("trusted_apps", s.trusted_apps.filter((x) => !(x.sha256 === t.sha256 && x.path === t.path)))} className="text-slate-500 hover:text-rose-400">
                    <X className="h-4 w-4" />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="space-y-3 px-5 py-4">
          <div>
            <p className="text-sm text-slate-200">Excluded files and folders</p>
            <p className="text-xs text-slate-500">Never scanned, whatever is in them. Prefer "It's safe" on an alert, which excuses one exact file. Whole drives cannot be excluded.</p>
          </div>
          <div className="flex gap-2">
            <input
              value={newExclusion}
              onChange={(e) => setNewExclusion(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && addExclusion()}
              placeholder="D:\Projects\build-output"
              aria-label="Folder or file to exclude"
              className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
            />
            <button onClick={addExclusion} className="flex items-center gap-1 rounded-lg border border-slate-700 px-3 text-sm text-slate-300 hover:border-cyan-400/50 hover:text-cyan-300">
              <Plus className="h-4 w-4" /> Add
            </button>
            <button onClick={pickExclusion} className="rounded-lg border border-slate-700 px-3 text-sm text-slate-300 hover:border-cyan-400/50 hover:text-cyan-300">
              Choose files…
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

      <Panel title="Home network (Pi-hole)">
        <div className="border-b border-slate-800/70 px-5 py-4">
          <label htmlFor="pihole-url" className="text-sm text-slate-200">Pi-hole address</label>
          <p className="text-xs text-slate-500">The address you open Pi-hole's dashboard at, without /admin. Only home-network and Tailscale addresses are accepted.</p>
          <input
            id="pihole-url"
            spellCheck={false}
            value={s.pihole_url ?? ""}
            onChange={(e) => set("pihole_url", e.target.value.trim() === "" ? null : e.target.value.trim())}
            placeholder="http://192.168.1.10"
            className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
          />
        </div>
        <div className="border-b border-slate-800/70 px-5 py-4">
          <label htmlFor="pihole-password" className="text-sm text-slate-200">Pi-hole app password</label>
          <p className="text-xs text-slate-500">
            In Pi-hole: Settings, switch to Expert, Web interface / API, Configure app password. An app password is safer than your login password. Stored by the engine and never shown again.
          </p>
          <input
            id="pihole-password"
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={s.pihole_password ?? ""}
            onFocus={(e) => e.target.select()}
            onChange={(e) => {
              const v = e.target.value.replace(/\*{8}/g, "").trim();
              set("pihole_password", v === "" ? null : v);
            }}
            placeholder={s.pihole_url ? "Paste the app password" : "Set the address first"}
            className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
          />
        </div>
        <Row label="DNS tamper alarm" hint={`Every 5 minutes, check that ${s.dns_test_domain} (blocked by Pi-hole) is blocked for this PC. If it resolves, something is sending DNS around Pi-hole: malware often changes DNS settings to dodge blocking.`}>
          <Toggle label="DNS tamper alarm" checked={s.dns_guard} disabled={!s.pihole_url} onChange={(v) => set("dns_guard", v)} />
        </Row>
      </Panel>

      <details className="group">
        <summary className="flex cursor-pointer list-none items-center gap-2 rounded-xl border border-slate-800/80 bg-slate-900/60 px-5 py-3 text-sm text-slate-300 hover:text-slate-100">
          <ChevronDown className="h-4 w-4 transition group-open:rotate-180" />
          Advanced settings
          <span className="text-xs text-slate-500">· individual shields, ransomware response, scanning limits, detection rules. The defaults are the recommended values.</span>
        </summary>
        <div className="mt-6 space-y-6">
          <div className="grid grid-cols-2 gap-6">
            <Panel title="Ransomware">
              {toggle("ransomware_decoys", "Decoy files", "Hidden decoy files in Documents, Pictures and Desktop. Nothing legitimate touches them, so a change means ransomware.", off || !s.file_monitor)}
              {toggle("ransomware_suspend", "Freeze the culprit", "When a decoy changes, freeze the program writing the most (never Windows or signed programs). You choose Terminate or Resume.", !s.ransomware_decoys)}
              {toggle("entropy_detection", "Encryption detection", "A burst of rewrites whose new content looks encrypted freezes the writing program.")}
              <Row label="Snapshot every (hours)" hint="More often = less lost work after an attack.">
                <NumberInput value={s.rollback_interval_hours} min={1} max={168} onChange={(v) => set("rollback_interval_hours", v)} />
              </Row>
            </Panel>
            <Panel title="Programs & downloads">
              {toggle("block_untrusted_risky", "Execution Guard", "Stop programs without a valid digital signature when they start from Downloads, Temp or AppData.", off)}
              {toggle("block_office_children", "Block Office/PDF launching shells", "Stop cmd, PowerShell and script hosts started by Word, Excel, Outlook or a PDF reader.", off)}
              {toggle("auto_kill_malicious", "Terminate malicious processes", "End a running program whose file matches a known threat.")}
              {toggle("archive_scanning", "Scan inside archives", "Look inside ZIP files (including Office documents) and ISO/IMG disk images.")}
              {toggle("startup_cleanup", "Startup clean-up", "When a file is quarantined, also remove the startup entries and scheduled tasks that launch it. Restoring the file puts them back.")}
            </Panel>
          </div>
          <div className="grid grid-cols-2 gap-6">
            <Panel title="Shields">
              {toggle("process_monitor", "Process Guard", "Check every program as it starts.", off)}
              {toggle("file_monitor", "File Shield", "Scan files as they land in Downloads, Desktop, Documents and Temp.", off)}
              {toggle("persistence_monitor", "Startup changes", "Alert on new startup entries, services and scheduled tasks.", off)}
              {toggle("behavior_monitor", "Behaviour engine", "Detect ransomware-like mass changes and suspicious process chains.", off)}
              {toggle("network_guard", "Network Guard", "Block connections to known-criminal networks (Spamhaus DROP, updated daily).", off)}
            </Panel>
            <Panel title="Scanning & performance">
              {toggle("low_priority_scans", "Low-priority scanning", "Run scans at background CPU and disk priority.")}
              <Row label="Scan threads" hint="0 = automatic (half of your CPU cores).">
                <NumberInput value={s.max_scan_threads} min={0} max={64} onChange={(v) => set("max_scan_threads", v)} />
              </Row>
              <Row label="Max file size (MB)" hint="Larger files are skipped.">
                <NumberInput value={s.max_file_size_mb} min={1} max={4096} onChange={(v) => set("max_file_size_mb", v)} />
              </Row>
            </Panel>
          </div>
          <div className="grid grid-cols-2 gap-6">
            <Panel title="Detection rules (YARA)">
              {toggle("yara_enabled", "Rule-based detection", "Scan programs, scripts and documents with rules that recognise malware families and their new variants.")}
              {toggle("yara_rules_feed", "Download the rule pack", "Fetch the curated YARA Forge core package (about 5,000 rules) with each update.", !s.yara_enabled)}
              <Row label="Quarantine threshold" hint="Rule confidence (50-100) needed to quarantine automatically. Weaker matches are reported for your decision. 101 = never quarantine.">
                <NumberInput value={s.yara_min_remediate_score} min={50} max={101} onChange={(v) => set("yara_min_remediate_score", v)} />
              </Row>
              <Row label="Max rule-scanned file size (MB)" hint="Larger files are still checked against hash lists.">
                <NumberInput value={s.yara_max_file_mb} min={1} max={256} onChange={(v) => set("yara_max_file_mb", v)} />
              </Row>
            </Panel>
            <Panel title="Threat definitions">
              <Row label="Update interval (hours)" hint="How often to check for new signatures.">
                <NumberInput value={s.update_interval_hours} min={1} max={168} onChange={(v) => set("update_interval_hours", v)} />
              </Row>
              {toggle("community_feeds", "Community threat feed", "Add hashes of recently submitted malware from abuse.ch MalwareBazaar. Signed and Windows files matched only by this feed are reported, never quarantined.")}
              <div className="px-5 py-4">
                <label htmlFor="abusech-key" className="text-sm text-slate-200">abuse.ch Auth-Key</label>
                <p className="text-xs text-slate-500">Required by the community feed. Free at auth.abuse.ch. Stored by the engine and never shown again.</p>
                <input
                  id="abusech-key"
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  value={s.abusech_auth_key ?? ""}
                  // The stored key is shown as a mask: typing replaces it instead of appending to it.
                  onFocus={(e) => e.target.select()}
                  onChange={(e) => {
                    const v = e.target.value.replace(/\*{8}/g, "").trim();
                    set("abusech_auth_key", v === "" ? null : v);
                  }}
                  placeholder={s.community_feeds ? "Paste your key to enable the community feed" : "Community feed is off"}
                  className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-sm text-slate-200 placeholder:text-slate-600 focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </Panel>
          </div>
        </div>
      </details>

      {(dirty || note) && (
        <div className="fixed bottom-6 right-8 flex items-center gap-3 rounded-xl border border-slate-700 bg-slate-900/95 px-4 py-3 shadow-2xl">
          <span className="text-sm text-slate-400">{dirty ? note ?? "You have unsaved changes." : note}</span>
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

function Row({ label, hint, children, strong }: { label: string; hint: string; children: ReactNode; strong?: boolean }) {
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

/** Free typing; the value is clamped when the field loses focus or Enter is pressed. */
function NumberInput({ value, min, max, onChange }: { value: number; min: number; max: number; onChange: (v: number) => void }) {
  const [text, setText] = useState(String(value));
  useEffect(() => setText(String(value)), [value]);
  const commit = () => {
    const n = Math.round(Number(text));
    const v = Number.isFinite(n) && text.trim() !== "" ? Math.min(max, Math.max(min, n)) : value;
    setText(String(v));
    if (v !== value) onChange(v);
  };
  return (
    <input
      type="number"
      value={text}
      min={min}
      max={max}
      onChange={(e) => setText(e.target.value)}
      onBlur={commit}
      onKeyDown={(e) => e.key === "Enter" && commit()}
      className="w-20 rounded-lg border border-slate-700 bg-slate-950 px-2 py-1.5 text-right font-mono text-sm text-slate-200 focus:border-cyan-500 focus:outline-none"
    />
  );
}
