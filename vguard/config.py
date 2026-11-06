"""Paths and settings for VGuard."""

from __future__ import annotations

import json
import os
import platform
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"


def _default_data_dir() -> Path:
    override = os.environ.get("VGUARD_HOME")
    if override:
        return Path(override)
    if IS_WINDOWS:
        base = os.environ.get("PROGRAMDATA") or os.environ.get("LOCALAPPDATA") or str(Path.home())
        return Path(base) / "VGuard"
    return Path.home() / ".vguard"


DATA_DIR = _default_data_dir()
QUARANTINE_DIR = DATA_DIR / "quarantine"
SIGNATURE_DIR = DATA_DIR / "signatures"
LOG_DIR = DATA_DIR / "logs"
CONFIG_FILE = DATA_DIR / "config.json"

# Signatures that ship with the program (EICAR test, etc.)
if getattr(sys, "frozen", False):  # PyInstaller bundle
    BUNDLED_DATA = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent)) / "vguard" / "data"
else:
    BUNDLED_DATA = Path(__file__).resolve().parent / "data"


def user_hot_folders() -> list[Path]:
    """Folders where malware usually lands first; watched by real-time protection."""
    home = Path.home()
    folders = [home / "Downloads", home / "Desktop", home / "Documents"]
    if IS_WINDOWS:
        appdata = os.environ.get("APPDATA")
        local = os.environ.get("LOCALAPPDATA")
        temp = os.environ.get("TEMP")
        if appdata:
            folders.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup")
        if local:
            folders.append(Path(local) / "Temp")
        if temp:
            folders.append(Path(temp))
        programdata = os.environ.get("PROGRAMDATA")
        if programdata:
            folders.append(Path(programdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp")
    else:
        folders += [Path("/tmp"), home / ".config" / "autostart"]
    seen, out = set(), []
    for f in folders:
        key = str(f).lower()
        if key not in seen and f.exists():
            seen.add(key)
            out.append(f)
    return out


def quick_scan_targets() -> list[Path]:
    targets = user_hot_folders()
    if IS_WINDOWS:
        for env in ("APPDATA", "LOCALAPPDATA"):
            v = os.environ.get(env)
            if v and Path(v).exists():
                targets.append(Path(v))
    return list(dict.fromkeys(targets))


def full_scan_targets() -> list[Path]:
    if IS_WINDOWS:
        import string
        return [Path(f"{d}:\\") for d in string.ascii_uppercase if Path(f"{d}:\\").exists()]
    return [Path("/")]


@dataclass
class Settings:
    max_file_size_mb: int = 100
    heuristic_threshold: int = 60          # score >= threshold -> flagged
    auto_quarantine: bool = True           # real-time: quarantine detections automatically
    kill_malicious_processes: bool = True  # process guard: terminate processes whose image is known-bad
    scan_archives: bool = True
    extra_watch_paths: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    signature_feeds: list[str] = field(default_factory=lambda: [
        # abuse.ch MalwareBazaar: SHA256 of samples seen in the last 48h (free, no key)
        "https://bazaar.abuse.ch/export/txt/sha256/recent/",
    ])
    ip_blocklist_feeds: list[str] = field(default_factory=lambda: [
        # abuse.ch Feodo Tracker: active botnet C2 servers
        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    ])
    domain_blocklist_feeds: list[str] = field(default_factory=lambda: [
        # abuse.ch URLhaus: hosts serving malware (hosts-file format)
        "https://urlhaus.abuse.ch/downloads/hostfile/",
    ])

    @classmethod
    def load(cls) -> "Settings":
        try:
            raw = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            known = {k: v for k, v in raw.items() if k in cls.__dataclass_fields__}
            return cls(**known)
        except (OSError, ValueError, TypeError):
            return cls()

    def save(self) -> None:
        ensure_dirs()
        CONFIG_FILE.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    def is_excluded(self, path: Path) -> bool:
        p = str(path).lower()
        return any(p.startswith(e.lower()) for e in self.exclusions)


def ensure_dirs() -> None:
    for d in (DATA_DIR, QUARANTINE_DIR, SIGNATURE_DIR, LOG_DIR):
        d.mkdir(parents=True, exist_ok=True)
