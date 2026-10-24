#!/usr/bin/env python3
"""Build the verifier twice from two different source paths and require identical bytes.

Usage: check-verifier-reproducible.py <target-name> <out-dir>

Copies the verifier crate and the build script to two scratch trees at different paths, runs
build-verifier.sh in each, refuses unless both binaries are byte-identical, and leaves the
binary and its .sha256 sidecar in <out-dir> after the built program passes the RFC 8032
known-answer vector and rejects a corrupted signature. A path, a clock or a cargo home leaking into the
binary shows up as a difference here.
"""

from __future__ import annotations

import filecmp
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FILES = ("crates/yadorilink-verify", ".github/release/build-verifier.sh")


def build(tree: Path, target: str, out: Path) -> Path:
    for rel in FILES:
        src, dst = ROOT / rel, tree / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns("target"))
        else:
            shutil.copy2(src, dst)
    subprocess.run([str(tree / ".github/release/build-verifier.sh"), target, str(out)], check=True)
    return out / f"yadorilink-verify-{target}"


# RFC 8032 section 7.1 test vector 2: public key, message, signature.
KAT_PUB = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
KAT_MSG = bytes.fromhex("72")
KAT_SIG = bytes.fromhex(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
    "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
)


def known_answer(binary: Path) -> list[str]:
    """Run the built program on the vector (must verify) and a corrupted copy (must not)."""
    problems = []
    with tempfile.TemporaryDirectory(prefix="verifier-kat-") as d:
        msg, good, bad = Path(d) / "msg", Path(d) / "good", Path(d) / "bad"
        msg.write_bytes(KAT_MSG)
        good.write_bytes(KAT_SIG)
        bad.write_bytes(KAT_SIG[:-1] + bytes([KAT_SIG[-1] ^ 1]))
        ok = subprocess.run([str(binary), KAT_PUB, str(msg), str(good)], capture_output=True)
        no = subprocess.run([str(binary), KAT_PUB, str(msg), str(bad)], capture_output=True)
        if ok.returncode != 0:
            problems.append("the built verifier rejects the RFC 8032 vector")
        if no.returncode == 0:
            problems.append("the built verifier accepts a corrupted signature")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    target, out_dir = argv[0], Path(argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="verifier-a-") as a, tempfile.TemporaryDirectory(
        prefix="verifier-longer-path-b-"
    ) as b:
        first = build(Path(a), target, Path(a) / "out")
        second = build(Path(b), target, Path(b) / "out")
        if not filecmp.cmp(first, second, shallow=False):
            print("error: the two builds differ; the verifier is not reproducible", file=sys.stderr)
            return 1
        problems = known_answer(first)
        if problems:
            for p in problems:
                print(f"error: {p}", file=sys.stderr)
            return 1
        out_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(first, out_dir / first.name)
        shutil.copy2(first.with_name(first.name + ".sha256"), out_dir / (first.name + ".sha256"))
    print(f"reproducible: {(out_dir / (first.name + '.sha256')).read_text(encoding="utf-8").strip()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
