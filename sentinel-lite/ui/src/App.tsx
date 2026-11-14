import { useState } from "react";
import { Sidebar, type Page } from "./components/Sidebar";
import { useEngine } from "./hooks/useEngine";
import { api, isTauri } from "./lib/api";
import { ActivityPage } from "./pages/Activity";
import { Dashboard } from "./pages/Dashboard";
import { FileCheckPage } from "./pages/FileCheck";
import { PrivacyPage } from "./pages/Privacy";
import { RecoveryPage } from "./pages/Recovery";
import { QuarantinePage } from "./pages/Quarantine";
import { SettingsPage } from "./pages/Settings";

const TITLES: Record<Page, string> = {
  dashboard: "Overview",
  filecheck: "File Check",
  activity: "Activity",
  privacy: "Privacy",
  recovery: "Recovery",
  quarantine: "Quarantine",
  settings: "Settings",
};

export default function App() {
  const [page, setPage] = useState<Page>("dashboard");
  const { status, events, error, refresh } = useEngine();
  const connected = !!status && !error;

  return (
    <div className="flex h-full">
      <Sidebar page={page} onNavigate={setPage} status={status} connected={connected} />
      <main className="flex-1 overflow-y-auto">
        <header className="flex items-center justify-between px-8 pt-7 pb-5">
          <h1 className="text-xl font-semibold tracking-tight text-slate-100">{TITLES[page]}</h1>
          {!isTauri && <span className="rounded-md bg-amber-400/10 px-2 py-1 text-xs text-amber-300">Browser preview · mock engine</span>}
        </header>
        {error && <ServiceError error={error} onStarted={refresh} />}
        <div className="px-8 pb-8">
          {page === "dashboard" && <Dashboard status={status} events={events} refresh={refresh} onSeeAll={() => setPage("activity")} />}
          {page === "filecheck" && <FileCheckPage />}
          {page === "activity" && <ActivityPage events={events} />}
          {page === "privacy" && <PrivacyPage status={status} />}
          {page === "recovery" && <RecoveryPage status={status} events={events} refresh={refresh} />}
          {page === "quarantine" && <QuarantinePage onChanged={refresh} />}
          {page === "settings" && <SettingsPage />}
        </div>
      </main>
    </div>
  );
}

/** Engine unreachable: say so, and offer to start it when it is simply not running. */
function ServiceError({ error, onStarted }: { error: string; onStarted: () => Promise<void> }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const stopped = /not running|cannot reach/i.test(error);
  const start = async () => {
    setBusy(true);
    setMsg(null);
    try {
      await api.startService();
      await onStarted();
    } catch (e) {
      setMsg(String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="mx-8 mb-5 flex items-center justify-between gap-4 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
      <div>
        <p>{error}</p>
        {stopped && <p className="text-xs text-amber-200/70">Your PC is not protected until the service runs again.</p>}
        {msg && <p className="text-xs text-rose-300">{msg}</p>}
      </div>
      {stopped && (
        <button onClick={start} disabled={busy} title="Requires administrator approval" className="shrink-0 rounded-lg bg-amber-400 px-3 py-1.5 text-sm font-medium text-slate-950 hover:bg-amber-300 disabled:opacity-50">
          {busy ? "Starting…" : "Start protection"}
        </button>
      )}
    </div>
  );
}
