#!/usr/bin/env python3
"""Summarize a `cargo test` log: failing tests, panic messages, build errors.

Writes a markdown summary to $GITHUB_STEP_SUMMARY (when set) and prints one
`::error` annotation per failing test, so a failed job is readable on the run
page without opening the raw log.
"""

import os
import re
import sys
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")
TS = re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]+Z\s")
MAX_ANNOTATIONS = 20


def parse(lines):
    failed, panics, binaries, results, build_errors = [], {}, [], [], []
    for i, line in enumerate(lines):
        if m := re.match(r"test (\S+) \.\.\. FAILED", line):
            failed.append(m.group(1))
        elif m := re.match(r"thread '([^']+)'.* panicked at (\S+?):?$", line):
            msg = []
            for nxt in lines[i + 1 : i + 6]:
                if not nxt.strip() or nxt.startswith("note:") or nxt.startswith("thread "):
                    break
                msg.append(nxt.strip())
            panics[m.group(1)] = (m.group(2), " ".join(msg)[:400])
        elif m := re.match(r"error: test failed, to rerun pass `(.*)`", line):
            binaries.append(m.group(1))
        elif line.startswith("test result: FAILED"):
            results.append(line.strip())
        elif re.match(r"error(\[E\d+\])?: ", line) and "aborting" not in line:
            if not line.startswith("error: test failed") and "targets failed" not in line:
                build_errors.append(line.strip()[:240])
    return failed, panics, binaries, results, build_errors


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("test-output.log")
    if not path.exists():
        print(f"no log at {path}")
        return 0
    lines = [TS.sub("", ANSI.sub("", l.rstrip("\n"))) for l in path.read_text(errors="replace").splitlines()]
    failed, panics, binaries, results, build_errors = parse(lines)
    if not (failed or binaries or build_errors):
        print("no failing tests in the log")
        return 0
    out = ["### Failed tests", ""]
    if build_errors and not failed:
        out += ["Build errors:", ""] + [f"- `{e}`" for e in dict.fromkeys(build_errors)][:15] + [""]
    if failed:
        out += ["| test | location | message |", "|---|---|---|"]
        for name in failed:
            short = name.split("::")[-1]
            loc, msg = panics.get(name, panics.get(short, ("", "")))
            cell = msg.replace("|", "\\|")
            out.append(f"| `{name}` | `{loc}` | {cell} |")
        out.append("")
    if binaries:
        out += ["Rerun locally:", ""] + [f"- `cargo test {b}`" for b in dict.fromkeys(binaries)] + [""]
    if results:
        out += ["```", *results[:20], "```"]
    text = "\n".join(out)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    for name in failed[:MAX_ANNOTATIONS]:
        loc, msg = panics.get(name, panics.get(name.split("::")[-1], ("", "")))
        print(f"::error title=Test failed::{name} {loc} {msg}".replace("\n", " ")[:600])
    return 0


if __name__ == "__main__":
    sys.exit(main())
