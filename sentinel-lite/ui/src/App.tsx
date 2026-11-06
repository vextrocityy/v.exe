import { useState } from "react";
import { Sidebar, type Page } from "./components/Sidebar";
import { useEngine } from "./hooks/useEngine";
import { isTauri } from "./lib/api";
import { ActivityPage } from "./pages/Activity";
import { Dashboard } from "./pages/Dashboard";
import { QuarantinePage } from "./pages/Quarantine";
import { SettingsPage } from "./pages/Settings";

const TITLES: Record<Page, string> = {
  dashboard: "Overview",
  activity: "Activity",
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
        {error && (
          <div className="mx-8 mb-5 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-3 text-sm text-amber-200">
            {error}
          </div>
        )}
        <div className="px-8 pb-8">
          {page === "dashboard" && <Dashboard status={status} events={events} refresh={refresh} onSeeAll={() => setPage("activity")} />}
          {page === "activity" && <ActivityPage events={events} />}
          {page === "quarantine" && <QuarantinePage onChanged={refresh} />}
          {page === "settings" && <SettingsPage />}
        </div>
      </main>
    </div>
  );
}
