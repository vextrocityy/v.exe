"""Hash-signature database and threat-intel feeds (malware hashes, bad IPs, bad domains)."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import threading
import time
import urllib.request
from pathlib import Path

from . import config
from .logger import get_logger

log = get_logger("vguard.signatures")
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
USER_AGENT = "VGuard/1.0 (+signature-update)"


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _parse_hash_lines(text: str, default_name: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        h = parts[0].strip('"').lower()
        if _SHA256_RE.match(h):
            out[h] = parts[1].strip() if len(parts) > 1 else default_name
    return out


class SignatureDB:
    """In-memory sets of known-bad file hashes, IPs and domains."""

    def __init__(self) -> None:
        self.hashes: dict[str, str] = {}
        self.bad_ips: set[str] = set()
        self.bad_networks: list = []
        self.bad_domains: set[str] = set()
        self._lock = threading.Lock()
        self.load()

    # ---------- loading ----------
    def load(self) -> None:
        config.ensure_dirs()
        hashes: dict[str, str] = {}
        bundled = config.BUNDLED_DATA / "signatures.txt"
        if bundled.exists():
            hashes.update(_parse_hash_lines(bundled.read_text(encoding="utf-8"), "Malware.Generic"))
        for f in sorted(config.SIGNATURE_DIR.glob("*.txt")):
            if f.name.startswith(("ip_", "domain_")):
                continue
            try:
                hashes.update(_parse_hash_lines(f.read_text(encoding="utf-8", errors="ignore"), "Malware.Feed"))
            except OSError as e:
                log.error("Could not read %s: %s", f, e)
        ips, nets, domains = set(), [], set()
        for f in config.SIGNATURE_DIR.glob("ip_*.txt"):
            for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    if "/" in line:
                        nets.append(ipaddress.ip_network(line, strict=False))
                    else:
                        ips.add(str(ipaddress.ip_address(line)))
                except ValueError:
                    continue
        for f in config.SIGNATURE_DIR.glob("domain_*.txt"):
            for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    domains.add(line)
        with self._lock:
            self.hashes, self.bad_ips, self.bad_networks, self.bad_domains = hashes, ips, nets, domains
        log.info("Loaded %d hash signatures, %d bad IPs, %d bad domains", len(hashes), len(ips), len(domains))

    # ---------- lookups ----------
    def lookup_hash(self, sha256: str) -> str | None:
        return self.hashes.get(sha256.lower())

    def is_bad_ip(self, ip: str) -> bool:
        if ip in self.bad_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self.bad_networks)

    def add_custom_hash(self, sha256: str, name: str = "User.Blocked") -> None:
        if not _SHA256_RE.match(sha256):
            raise ValueError("Not a SHA-256 hash")
        with open(config.SIGNATURE_DIR / "custom.txt", "a", encoding="utf-8") as f:
            f.write(f"{sha256.lower()} {name}\n")
        self.hashes[sha256.lower()] = name

    @property
    def last_update(self) -> float | None:
        stamp = config.SIGNATURE_DIR / ".last_update"
        try:
            return float(stamp.read_text())
        except (OSError, ValueError):
            return None

    # ---------- updating ----------
    @staticmethod
    def _fetch(url: str, timeout: int = 60) -> str:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore")

    def update(self, settings: config.Settings | None = None, progress=print) -> dict:
        """Download threat-intel feeds. Returns counts per category."""
        settings = settings or config.Settings.load()
        config.ensure_dirs()
        result = {"hashes": 0, "ips": 0, "domains": 0, "errors": []}

        for i, url in enumerate(settings.signature_feeds):
            try:
                progress(f"Downloading malware hashes: {url}")
                parsed = _parse_hash_lines(self._fetch(url), "Malware.MalwareBazaar")
                if parsed:
                    # Merge with what we already had so the DB grows over time.
                    target = config.SIGNATURE_DIR / f"feed_{i}.txt"
                    existing = _parse_hash_lines(target.read_text(encoding="utf-8"), "Malware.Feed") if target.exists() else {}
                    existing.update(parsed)
                    target.write_text("\n".join(f"{h} {n}" for h, n in existing.items()) + "\n", encoding="utf-8")
                    result["hashes"] += len(parsed)
            except Exception as e:
                result["errors"].append(f"{url}: {e}")

        for i, url in enumerate(settings.ip_blocklist_feeds):
            try:
                progress(f"Downloading IP blocklist: {url}")
                lines = [l.strip() for l in self._fetch(url).splitlines() if l.strip() and not l.startswith("#")]
                (config.SIGNATURE_DIR / f"ip_{i}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
                result["ips"] += len(lines)
            except Exception as e:
                result["errors"].append(f"{url}: {e}")

        for i, url in enumerate(settings.domain_blocklist_feeds):
            try:
                progress(f"Downloading domain blocklist: {url}")
                domains = []
                for line in self._fetch(url).splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    d = parts[1] if len(parts) > 1 and parts[0] in ("127.0.0.1", "0.0.0.0") else parts[0]
                    domains.append(d.lower())
                (config.SIGNATURE_DIR / f"domain_{i}.txt").write_text("\n".join(domains) + "\n", encoding="utf-8")
                result["domains"] += len(domains)
            except Exception as e:
                result["errors"].append(f"{url}: {e}")

        (config.SIGNATURE_DIR / ".last_update").write_text(str(time.time()))
        self.load()
        return result


_db: SignatureDB | None = None


def get_db() -> SignatureDB:
    global _db
    if _db is None:
        _db = SignatureDB()
    return _db
