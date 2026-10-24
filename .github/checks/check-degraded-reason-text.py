#!/usr/bin/env python3
"""Fail when production code decides anything from a degraded reason's text.

A degraded folder carries one typed cause (`LinkStatus.degraded_cause`, the
daemon's `DegradedCause`); `degraded_reason` is human detail for a tooltip or
a status line and nothing else. Matching its text (an equality, `starts_with`,
`contains`) makes a rewording silently change what a shell shows, which is
how an ownership-lost folder was told apart from a not-joined one. This guard
scans production Rust code (the scanner, and what counts as test code, are
those of `check-materialization-semantic-boundary.py`) and the bundled web UI
for a comparison involving `degraded_reason` or one of the reason-text
constants.

Run with no arguments to check the tree and `--self-test` to exercise the
check against synthetic fixtures.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location(
    "materialization_semantic_boundary",
    Path(__file__).resolve().parent / "check-materialization-semantic-boundary.py",
)
_boundary = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_boundary)

TEXT = r"(?:degraded_reason|(?:OWNERSHIP_LOST|NOT_JOINED|WAITING_FOR_DISK_SPACE\w*)_REASON)"
COMPARE = r"(?:==|!=|\.starts_with\(|\.ends_with\(|\.contains\(|\.eq\(|\.eq_ignore_ascii_case\()"
# Group 1 is the matched comparison, for the message.
PATTERN = re.compile(
    rf"(\b{TEXT}\b[^;{{}}]*?{COMPARE}|{COMPARE}[^;{{}}]*?\b{TEXT}\b)"
)
# The webui is JavaScript: any use of the field other than printing it.
WEBUI_PATTERN = re.compile(r"degraded_reason\s*(?:===?|!==?|\.startsWith|\.includes|\.indexOf|\.match)")


def scan(root: Path) -> list[str]:
    errors = []
    for rel, number, _, expr in _boundary.scan(root, PATTERN):
        errors.append(f"{rel}:{number}: `{expr.strip()}` compares a degraded reason's text")
    web = root / "crates/yadorilink-http-api/webui"
    if web.is_dir():
        for path in sorted(web.rglob("*.html")) + sorted(web.rglob("*.js")):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if WEBUI_PATTERN.search(line):
                    errors.append(f"{path.relative_to(root)}:{number}: compares a degraded reason's text")
    return errors


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        src = root / "crates/demo/src"
        src.mkdir(parents=True)
        (src / "lib.rs").write_text(
            "fn a(l: &L) -> bool { l.degraded && l.degraded_reason == OWNERSHIP_LOST_REASON }\n"
            "fn b(l: &L) -> bool { l.degraded_reason.starts_with(\"Waiting\") }\n"
            "fn c(l: &L) -> bool { \"x\" == l.degraded_reason }\n"
            "fn d(l: &L) -> String { format!(\"degraded ({})\", l.degraded_reason) }\n"
            "fn e(l: &mut L) { l.degraded_reason = String::new(); }\n"
            "fn f(h: &H) -> bool { h.reason == \"held\" }\n"
            "// l.degraded_reason == \"in a comment\"\n"
            "#[cfg(test)]\n"
            "mod tests {\n"
            "    fn t(l: &L) -> bool { l.degraded_reason == \"x\" }\n"
            "}\n",
            encoding="utf-8",
        )
        web = root / "crates/yadorilink-http-api/webui"
        web.mkdir(parents=True)
        (web / "index.html").write_text(
            "<script>if (l.degraded_reason === 'x') {}\nel.title = l.degraded_reason;</script>\n",
            encoding="utf-8",
        )
        errors = scan(root)
        lines = sorted(e.split(": ")[0] for e in errors)
        assert lines == [
            "crates/demo/src/lib.rs:1",
            "crates/demo/src/lib.rs:2",
            "crates/demo/src/lib.rs:3",
            "crates/yadorilink-http-api/webui/index.html:1",
        ], errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("degraded-reason text guard self-test passed")
        return 0
    errors = scan(ROOT)
    if errors:
        print("a degraded reason is human detail; decide from `degraded_cause`:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print("degraded-reason text guard: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
