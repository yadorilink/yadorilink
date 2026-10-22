#!/usr/bin/env python3
"""Copy a build's provenance sidecar next to the artifact that is released.

The package builders write `<artifact>.provenance.json` recording the artifact
sha256 and the commit it was built from. Release jobs copy (and sometimes
rename) the artifact; this copies the sidecar to `<final artifact>.provenance.json`
and fails unless the sidecar's artifact_sha256 equals the sha256 of the final
file, so a released artifact never ships with provenance for different bytes.

  collect-provenance.py BUILT_ARTIFACT FINAL_ARTIFACT
"""

import hashlib
import json
import pathlib
import re
import shutil
import sys

SCHEMA = "yadorilink-release-provenance/1"


def collect(built: pathlib.Path, final: pathlib.Path) -> str:
    """Return an error message, or "" after copying the sidecar."""
    src = pathlib.Path(str(built) + ".provenance.json")
    try:
        doc = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return f"{src}: missing or unreadable: {e}"
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        return f"{src}: schema must be {SCHEMA}"
    if not re.fullmatch(r"[0-9a-f]{40}", str(doc.get("product_sha", ""))):
        return f"{src}: product_sha must be a 40-hex commit sha"
    try:
        digest = hashlib.sha256(final.read_bytes()).hexdigest()
    except OSError as e:
        return f"{final}: cannot read: {e}"
    if str(doc.get("artifact_sha256", "")).lower() != digest:
        return f"{src}: artifact_sha256 does not match {final}"
    dest = pathlib.Path(str(final) + ".provenance.json")
    if dest.resolve() != src.resolve():
        shutil.copyfile(src, dest)
    return ""


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    err = collect(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
