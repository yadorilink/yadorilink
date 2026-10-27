#!/usr/bin/env python3
"""Compare this repository's channel list (.github/release/channels.json) with the landing
repository's (the CHANNELS set in its src/dl.mjs).

Usage: check-landing-channels.py [LANDING_REPO_PATH]

The two lists must name the same channels. Exit 0 when equal or when the landing path is absent
or not given (the check is skipped); 1 on a mismatch; 2 when the landing file cannot be parsed.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_channels  # noqa: E402

DL_FILE = Path("src") / "dl.mjs"
CHANNELS_RE = re.compile(r"\bconst\s+CHANNELS\s*=\s*new\s+Set\(\s*\[([^\]]*)\]\s*\)")


def landing_channels(text: str) -> set[str] | None:
    m = CHANNELS_RE.search(text)
    if not m:
        return None
    return set(re.findall(r"""["']([^"']+)["']""", m.group(1)))


def main(argv: list[str]) -> int:
    if not argv:
        print("landing repository path not given; skipped")
        return 0
    dl = Path(argv[0]) / DL_FILE
    if not dl.is_file():
        print(f"{dl} not found; skipped")
        return 0
    theirs = landing_channels(dl.read_text(encoding="utf-8"))
    if theirs is None:
        print(f"{dl}: cannot find the CHANNELS set", file=sys.stderr)
        return 2
    ours = set(release_channels.CHANNELS)
    if ours != theirs:
        print(f"channel lists differ: core {sorted(ours)}, landing {sorted(theirs)}", file=sys.stderr)
        return 1
    print(f"channel lists match: {sorted(ours)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
