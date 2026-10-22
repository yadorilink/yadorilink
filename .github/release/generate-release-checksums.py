#!/usr/bin/env python3
"""Generate/verify SHA-256 checksums for release artifacts.

Every downloadable release
artifact (installer, source tarball, etc.) must have a
published checksum. This script is the single, cross-platform (Python,
already required by the CI check scripts) source of truth for
that: it can write a combined manifest (SHA256SUMS-style, one line per
file) and/or per-file `<name>.sha256` sidecars (the sidecar format the
installer build scripts in the product repositories also produce), and it can verify either form.

Usage:
    # Write release/SHA256SUMS covering the given artifacts.
    generate-release-checksums.py --out release/SHA256SUMS FILE [FILE ...]

    # Also/instead write a FILE.sha256 sidecar next to each artifact.
    generate-release-checksums.py --sidecars FILE [FILE ...]

    # Verify artifacts against a previously generated manifest.
    generate-release-checksums.py --verify release/SHA256SUMS

    # Verify a single artifact against its own sidecar.
    generate-release-checksums.py --verify-sidecar FILE

Exits non-zero (release-blocking — a missing/mismatched checksum is
treated as release-blocking) if any input file is
missing or any checksum fails to verify.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(paths: list[Path], out: Path) -> None:
    lines = []
    for path in paths:
        if not path.exists():
            raise SystemExit(f"error: artifact not found: {path}")
        lines.append(f"{sha256_of(path)}  {path.name}")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(paths)} artifact(s))")


def write_sidecars(paths: list[Path]) -> None:
    for path in paths:
        if not path.exists():
            raise SystemExit(f"error: artifact not found: {path}")
        sidecar = path.with_name(path.name + ".sha256")
        sidecar.write_text(f"{sha256_of(path)}  {path.name}", encoding="utf-8")
        print(f"wrote {sidecar}")


def verify_manifest(manifest: Path) -> int:
    if not manifest.exists():
        print(f"error: manifest not found: {manifest}", file=sys.stderr)
        return 1
    base_dir = manifest.parent
    failures = 0
    entries = 0
    for line in manifest.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        expected, _, name = line.partition("  ")
        if not name:
            # Tolerate a single-space separator too.
            expected, _, name = line.partition(" ")
        entries += 1
        artifact = base_dir / name
        if not artifact.exists():
            print(f"MISSING: {name}", file=sys.stderr)
            failures += 1
            continue
        actual = sha256_of(artifact)
        if actual.lower() != expected.strip().lower():
            print(f"MISMATCH: {name} (expected {expected}, got {actual})", file=sys.stderr)
            failures += 1
        else:
            print(f"OK: {name}")
    if entries == 0:
        print(f"error: manifest {manifest} contains no entries", file=sys.stderr)
        return 1
    if failures:
        print(f"{failures}/{entries} checksum(s) failed", file=sys.stderr)
        return 1
    print(f"all {entries} checksum(s) verified")
    return 0


def verify_sidecar(artifact: Path) -> int:
    sidecar = artifact.with_name(artifact.name + ".sha256")
    if not artifact.exists():
        print(f"error: artifact not found: {artifact}", file=sys.stderr)
        return 1
    if not sidecar.exists():
        print(f"error: missing checksum sidecar for {artifact}", file=sys.stderr)
        return 1
    expected = sidecar.read_text(encoding="utf-8").split()[0].strip().lower()
    actual = sha256_of(artifact)
    if actual != expected:
        print(f"MISMATCH: {artifact.name} (expected {expected}, got {actual})", file=sys.stderr)
        return 1
    print(f"OK: {artifact.name}")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("artifacts", nargs="*", type=Path, help="artifact files to checksum")
    parser.add_argument("--out", type=Path, help="write a combined SHA256SUMS-style manifest here")
    parser.add_argument("--sidecars", action="store_true", help="write a <name>.sha256 sidecar next to each artifact")
    parser.add_argument("--verify", type=Path, help="verify artifacts next to this manifest file")
    parser.add_argument("--verify-sidecar", type=Path, help="verify a single artifact against its .sha256 sidecar")
    args = parser.parse_args(argv)

    if args.verify is not None:
        return verify_manifest(args.verify)
    if args.verify_sidecar is not None:
        return verify_sidecar(args.verify_sidecar)

    if not args.artifacts:
        parser.error("no artifacts given (and neither --verify nor --verify-sidecar was used)")

    if args.out is None and not args.sidecars:
        parser.error("nothing to do: pass --out, --sidecars, or a --verify* mode")

    if args.out is not None:
        write_manifest(args.artifacts, args.out)
    if args.sidecars:
        write_sidecars(args.artifacts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
