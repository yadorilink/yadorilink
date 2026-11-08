#!/usr/bin/env python3
"""Fail if a Windows PE file imports the Visual C++ runtime DLLs.

The Store (and any clean Windows) has no VC++ redistributable, so a shipped binary that imports
VCRUNTIME140*.dll / MSVCP140*.dll / the VC concurrency DLLs fails at launch with a "not found" dialog.
Rust binaries must be built with the static CRT (.cargo/config.toml: +crt-static).

usage: check-pe-imports.py FILE_OR_DIR...   (a directory is scanned recursively for .exe/.dll)
exit 1 and list every offending import; --list prints the imports of every file instead.
Reads both the normal and the delay-load import tables. No third-party dependencies.
"""
import re
import struct
import sys
from pathlib import Path

FORBIDDEN = re.compile(r"^(vcruntime140(_1|_threads)?|msvcp140(_\d+|_atomic_wait|_codecvt_ids)?|concrt140|vcomp140|vccorlib140)\.dll$", re.I)


def _sections(data, nsec, off):
    # section header: name[8], vsize, va, rawsize, rawptr, ...
    return [struct.unpack_from("<IIII", data, off + 40 * i + 8) for i in range(nsec)]


def _rva(secs, rva):
    for vsize, va, rawsize, rawptr in secs:
        if va <= rva < va + max(vsize, rawsize):
            return rawptr + rva - va
    return None


def _cstr(data, off):
    end = data.index(b"\0", off)
    return data[off:end].decode("ascii", "replace")


def import_names(data):
    """The DLL names a PE image imports (normal and delay-load), or None if `data` is not a PE image."""
    if data[:2] != b"MZ":
        return None
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        return None
    nsec, = struct.unpack_from("<H", data, pe + 6)
    optsize, = struct.unpack_from("<H", data, pe + 20)
    opt = pe + 24
    magic, = struct.unpack_from("<H", data, opt)
    dd = opt + (112 if magic == 0x20B else 96)
    secs = _sections(data, nsec, opt + optsize)
    names = []
    # data directory 1 = import, 13 = delay import
    for idx, desc_size, name_field in ((1, 20, 12), (13, 32, 4)):
        rva, size = struct.unpack_from("<II", data, dd + 8 * idx)
        if not rva:
            continue
        off = _rva(secs, rva)
        while off is not None:
            desc = data[off:off + desc_size]
            if len(desc) < desc_size or not any(desc):
                break
            nrva, = struct.unpack_from("<I", desc, name_field)
            noff = _rva(secs, nrva)
            if noff is not None:
                names.append(_cstr(data, noff))
            off += desc_size
    return names


def main(argv):
    list_mode = "--list" in argv
    paths = [Path(a) for a in argv if a != "--list"]
    if not paths:
        print(__doc__)
        return 2
    files = []
    for p in paths:
        files += sorted(f for f in p.rglob("*") if f.is_file() and f.suffix.lower() in (".exe", ".dll", ".pyd")) if p.is_dir() else [p]
    bad = 0
    for f in files:
        names = import_names(f.read_bytes())
        if names is None:
            continue
        if list_mode:
            print(f"{f}: {', '.join(sorted(set(n.lower() for n in names)))}")
            continue
        hits = sorted({n for n in names if FORBIDDEN.match(n)})
        if hits:
            bad += 1
            print(f"FAIL  {f} imports {', '.join(hits)}")
    if not list_mode:
        print(f"{'FAIL' if bad else 'ok'}    {len(files)} file(s) checked, {bad} import the VC++ runtime")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
