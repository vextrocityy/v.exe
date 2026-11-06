"""Minimal, dependency-free Windows PE parser (headers, sections, imports)."""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int
    entropy: float = 0.0

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)


@dataclass
class PEInfo:
    is_64: bool
    is_dll: bool
    entry_point: int
    timestamp: int
    sections: list[Section] = field(default_factory=list)
    imports: dict[str, list[str]] = field(default_factory=dict)
    overlay_size: int = 0

    @property
    def imported_functions(self) -> set[str]:
        return {f for fns in self.imports.values() for f in fns}

    def entry_section(self) -> Section | None:
        for s in self.sections:
            if s.virtual_address <= self.entry_point < s.virtual_address + max(s.virtual_size, s.raw_size):
                return s
        return None


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def parse(data: bytes) -> PEInfo | None:
    """Parse PE bytes. Returns None if not a (valid) PE file."""
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return None
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            return None
        fh = e_lfanew + 4
        _machine, nsec, timestamp, _, _, opt_size, characteristics = struct.unpack_from("<HHIIIHH", data, fh)
        opt = fh + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        is_64 = magic == 0x20B
        entry = struct.unpack_from("<I", data, opt + 16)[0]
        dd_off = opt + (112 if is_64 else 96)
        num_dd = struct.unpack_from("<I", data, dd_off - 4)[0]
        import_rva = import_size = 0
        if num_dd > 1:
            import_rva, import_size = struct.unpack_from("<II", data, dd_off + 8)

        info = PEInfo(is_64=is_64, is_dll=bool(characteristics & 0x2000), entry_point=entry, timestamp=timestamp)
        sec_off = opt + opt_size
        end_of_raw = 0
        for i in range(min(nsec, 96)):
            o = sec_off + i * 40
            if o + 40 > len(data):
                break
            name = data[o:o + 8].rstrip(b"\0").decode("latin-1", "replace")
            vsize, va, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
            chars = struct.unpack_from("<I", data, o + 36)[0]
            s = Section(name, va, vsize, roff, rsize, chars)
            s.entropy = entropy(data[roff:roff + min(rsize, 4 << 20)])
            info.sections.append(s)
            end_of_raw = max(end_of_raw, roff + rsize)
        info.overlay_size = max(0, len(data) - end_of_raw) if end_of_raw else 0

        def rva_to_off(rva: int) -> int | None:
            for s in info.sections:
                if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
                    return rva - s.virtual_address + s.raw_offset
            return None

        def cstr(off: int, limit: int = 256) -> str:
            end = data.find(b"\0", off, off + limit)
            return data[off:end if end != -1 else off + limit].decode("latin-1", "replace")

        if import_rva:
            off = rva_to_off(import_rva)
            count = 0
            while off is not None and off + 20 <= len(data) and count < 512:
                oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, off)
                if not (oft or name_rva or ft):
                    break
                noff = rva_to_off(name_rva)
                dll = cstr(noff).lower() if noff is not None else "?"
                fns: list[str] = []
                toff = rva_to_off(oft or ft)
                tsize = 8 if is_64 else 4
                flag = 1 << 63 if is_64 else 1 << 31
                n = 0
                while toff is not None and toff + tsize <= len(data) and n < 4096:
                    val = struct.unpack_from("<Q" if is_64 else "<I", data, toff)[0]
                    if not val:
                        break
                    if not val & flag:
                        hoff = rva_to_off(val & 0x7FFFFFFF)
                        if hoff is not None:
                            fns.append(cstr(hoff + 2))
                    toff += tsize
                    n += 1
                info.imports[dll] = fns
                off += 20
                count += 1
        return info
    except (struct.error, IndexError):
        return None
