import { ShieldCheck } from "lucide-react";
import type { SecurityEvent } from "../lib/types";
import { timeAgo } from "../lib/format";
import { iconFor, PathLine, SEVERITY } from "./ActivityLog";
import { EventActions } from "./EventActions";
import { Panel } from "./Panel";

/**
 * Everything that waits for the user's decision, each with its buttons.
 * Activity is the history; this is the to-do list.
 */
export function AttentionList({ items, onChanged, onNavigate }: { items: SecurityEvent[]; onChanged: () => void; onNavigate: (page: "recovery") => void }) {
  if (items.length === 0) {
    return (
      <div className="flex items-center gap-3 rounded-2xl border border-emerald-500/20 bg-emerald-500/5 px-5 py-3.5 text-sm text-emerald-200">
        <ShieldCheck className="h-5 w-5 shrink-0 text-emerald-400" />
        Nothing needs your attention.
      </div>
    );
  }
  return (
    <div id="attention">
      <Panel title={`Needs your attention · ${items.length}`} className="border-amber-400/30">
        <ul className="divide-y divide-slate-800/70">
          {items.map((e) => {
            const Icon = iconFor(e);
            return (
              <li key={e.id} className="flex items-start gap-3 px-5 py-4">
                <span className={`mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-md ${SEVERITY[e.severity]}`}>
                  <Icon className="h-4 w-4" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline justify-between gap-3">
                    <p className="text-sm font-medium text-slate-100">{e.title}</p>
                    <time className="shrink-0 text-xs text-slate-500">{timeAgo(e.timestamp)}</time>
                  </div>
                  {e.path && <PathLine path={e.path} />}
                  {e.detail && <p className="mt-1 text-xs text-slate-400">{e.detail}</p>}
                  <EventActions event={e} onChanged={onChanged} onNavigate={onNavigate} />
                </div>
              </li>
            );
          })}
        </ul>
      </Panel>
    </div>
  );
}
