"""Central logging + detection event journal."""

from __future__ import annotations

import json
import logging
import time
from logging.handlers import RotatingFileHandler

from . import config

_configured = False
_listeners: list = []


def get_logger(name: str = "vguard") -> logging.Logger:
    global _configured
    if not _configured:
        config.ensure_dirs()
        root = logging.getLogger("vguard")
        root.setLevel(logging.INFO)
        fh = RotatingFileHandler(config.LOG_DIR / "vguard.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        root.addHandler(fh)
        _configured = True
    return logging.getLogger(name)


def add_listener(fn) -> None:
    """Register fn(event_dict) to receive every security event (used by the GUI)."""
    _listeners.append(fn)


def event(kind: str, severity: str, message: str, **details) -> dict:
    """Record a security event to events.jsonl and notify listeners."""
    rec = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "kind": kind, "severity": severity,
           "message": message, **details}
    get_logger().warning("%s | %s | %s", kind, severity, message)
    try:
        with open(config.LOG_DIR / "events.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
    except OSError:
        pass
    for fn in list(_listeners):
        try:
            fn(rec)
        except Exception:  # listener must never break protection
            pass
    return rec


def recent_events(limit: int = 200) -> list[dict]:
    try:
        lines = (config.LOG_DIR / "events.jsonl").read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
