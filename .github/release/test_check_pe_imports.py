#!/usr/bin/env python3
"""Tests for check-pe-imports.py. Run: python3 .github/release/test_check_pe_imports.py"""

from __future__ import annotations

import importlib.util
import struct
import unittest
from pathlib import Path

_spec = importlib.util.spec_from_file_location("check_pe_imports", Path(__file__).with_name("check-pe-imports.py"))
pe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pe)


def fake_pe(dlls, delay=()):
    """A minimal PE32+ image with one .idata section holding a normal and a delay-load import table."""
    va, raw = 0x1000, 0x200
    blob = bytearray()
    names_at = {}

    def name_rva(n):
        if n not in names_at:
            names_at[n] = len(blob)
            blob.extend(n.encode() + b"\0")
        return names_at[n]

    # names first (offset within section), then descriptor tables after them
    for n in (*dlls, *delay):
        name_rva(n)
    while len(blob) % 8:
        blob.append(0)
    imp_off = len(blob)
    for n in dlls:
        blob.extend(struct.pack("<IIIII", 0, 0, 0, va + names_at[n], 0))
    blob.extend(b"\0" * 20)
    dly_off = len(blob)
    for n in delay:
        blob.extend(struct.pack("<IIIIIIII", 1, va + names_at[n], 0, 0, 0, 0, 0, 0))
    blob.extend(b"\0" * 32)
    opt = bytearray(240)
    struct.pack_into("<H", opt, 0, 0x20B)
    dd = 112
    struct.pack_into("<II", opt, dd + 8 * 1, va + imp_off, 20 * (len(dlls) + 1))
    if delay:
        struct.pack_into("<II", opt, dd + 8 * 13, va + dly_off, 32 * (len(delay) + 1))
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, len(opt), 0x22)
    sec = struct.pack("<8sIIIIIIHHI", b".idata", len(blob), va, len(blob), raw, 0, 0, 0, 0, 0)
    head = bytearray(b"MZ" + b"\0" * 58) + struct.pack("<I", 64)
    head = head + b"PE\0\0" + coff + opt + sec
    return bytes(head.ljust(raw, b"\0")) + bytes(blob)


class CheckPeImports(unittest.TestCase):
    def test_reads_normal_and_delay_imports(self):
        names = pe.import_names(fake_pe(["KERNEL32.dll", "VCRUNTIME140.dll"], ["msvcp140.dll"]))
        self.assertEqual(sorted(n.lower() for n in names), ["kernel32.dll", "msvcp140.dll", "vcruntime140.dll"])

    def test_forbidden_names(self):
        for n in ("VCRUNTIME140.dll", "vcruntime140_1.dll", "MSVCP140.dll", "msvcp140_1.dll", "CONCRT140.dll"):
            self.assertTrue(pe.FORBIDDEN.match(n), n)
        for n in ("kernel32.dll", "api-ms-win-crt-runtime-l1-1-0.dll", "ucrtbase.dll"):
            self.assertFalse(pe.FORBIDDEN.match(n), n)

    def test_not_a_pe(self):
        self.assertIsNone(pe.import_names(b"not a pe file"))


if __name__ == "__main__":
    unittest.main()
