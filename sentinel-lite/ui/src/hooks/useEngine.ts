import { useCallback, useEffect, useRef, useState } from "react";
import { api, onEngineEvent } from "../lib/api";
import type { EngineStatus, SecurityEvent } from "../lib/types";

/** Newest first, one row per id (the initial fetch and the push stream can overlap). */
function mergeEvents(a: SecurityEvent[], b: SecurityEvent[]): SecurityEvent[] {
  const seen = new Set<number>();
  return [...a, ...b]
    .filter((e) => (seen.has(e.id) ? false : (seen.add(e.id), true)))
    .sort((x, y) => y.id - x.id)
    .slice(0, 500);
}

/**
 * Live engine state: status is polled (fast while scanning, slow at idle, and
 * not at all while the window is hidden); events arrive by push. `attention` is
 * the list of open items that wait for the user's decision.
 */
export function useEngine() {
  const [status, setStatus] = useState<EngineStatus | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [attention, setAttention] = useState<SecurityEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const scanning = useRef(false);
  const failures = useRef(0);

  const refreshAttention = useCallback(async () => {
    try {
      setAttention(await api.getAttention());
    } catch {
      /* the status poll reports connection problems */
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const s = await api.getStatus();
      scanning.current = s.scan.running;
      failures.current = 0;
      setStatus(s);
      setError(null);
    } catch (e) {
      failures.current += 1;
      // A stale "Protected" must never stay on screen while the engine is down.
      setStatus(null);
      setError(String(e));
    }
  }, []);

  const refreshAll = useCallback(async () => {
    await Promise.all([refresh(), refreshAttention()]);
  }, [refresh, refreshAttention]);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      // Hidden in the tray: nothing to draw, so do not poll (events still arrive by push).
      if (!document.hidden) await refresh();
      if (cancelled) return;
      const down = failures.current;
      const delay = scanning.current ? 500 : down > 20 ? 15000 : 3000;
      timer = setTimeout(tick, delay);
    };
    tick();
    const onVisible = () => {
      if (!document.hidden) refreshAll();
    };
    document.addEventListener("visibilitychange", onVisible);
    api.getEvents(200).then((v) => setEvents((prev) => mergeEvents(prev, v))).catch(() => {});
    refreshAttention();

    let unsubscribe: (() => void) | undefined;
    let debounce: ReturnType<typeof setTimeout> | undefined;
    onEngineEvent(
      (ev) => {
        setEvents((prev) => mergeEvents([ev], prev));
        // A burst of events (a scan with many detections) needs one refresh, not hundreds.
        clearTimeout(debounce);
        debounce = setTimeout(refreshAll, 250);
      },
      (connected) => {
        if (connected) {
          refreshAll();
          api.getEvents(200).then((v) => setEvents((prev) => mergeEvents(prev, v))).catch(() => {});
        }
      },
    ).then((off) => (unsubscribe = off));

    return () => {
      cancelled = true;
      clearTimeout(timer);
      clearTimeout(debounce);
      document.removeEventListener("visibilitychange", onVisible);
      unsubscribe?.();
    };
  }, [refresh, refreshAll, refreshAttention]);

  // The count changed without an event we saw (e.g. dismissed elsewhere): re-read the list.
  const count = status?.attention_count;
  useEffect(() => {
    if (count !== undefined) refreshAttention();
  }, [count, refreshAttention]);

  return { status, events, attention, error, refresh: refreshAll };
}
