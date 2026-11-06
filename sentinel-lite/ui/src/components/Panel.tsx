import type { ReactNode } from "react";

export function Panel({ title, action, children, className = "" }: { title?: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-2xl border border-slate-800/80 bg-slate-900/60 shadow-[0_0_0_1px_#0f172a] backdrop-blur ${className}`}>
      {title && (
        <header className="flex items-center justify-between border-b border-slate-800/80 px-5 py-3">
          <h2 className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">{title}</h2>
          {action}
        </header>
      )}
      {children}
    </section>
  );
}
