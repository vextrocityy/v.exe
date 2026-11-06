import { useCallback, useEffect, useRef, useState } from "react";
import { api, onEngineEvent } from "../lib/api";
import type { EngineStatus, SecurityEvent } from "../lib/types";

/**
 * Live engine state: status is polled (fast while scanning, slow at idle, to
 * keep the UI's own footprint small); events arrive by push.
 */
export function useEngine() {
  const [status, setStatus] = useState<EngineStatus | null>(null);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const scanning = useRef(false);

  const refresh = useCallback(async () => {
    try {
      const s = await api.getStatus();
      scanning.current = s.scan.running;
      setStatus(s);
      setError(null);
    } catch (e) {
      setError(String(e));
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      await refresh();
      if (!cancelled) timer = setTimeout(tick, scanning.current ? 500 : 3000);
    };
    tick();
    api.getEvents(200).then(setEvents).catch(() => {});

    let unsubscribe: (() => void) | undefined;
    onEngineEvent(
      (ev) => {
        setEvents((prev) => [ev, ...prev].slice(0, 500));
        refresh();
      },
      (connected) => {
        if (connected) {
          refresh();
          api.getEvents(200).then(setEvents).catch(() => {});
        }
      },
    ).then((off) => (unsubscribe = off));

    return () => {
      cancelled = true;
      clearTimeout(timer);
      unsubscribe?.();
    };
  }, [refresh]);

  return { status, events, error, refresh };
}
