#!/usr/bin/env python3
"""Release scripts write their text files with LF on every OS.

Path.write_text (and open in text mode) turns "\\n" into CRLF on Windows, and
the engine bundle is built on a Windows runner. A checksum sidecar with a
carriage return after the file name fails `sha256sum -c` everywhere else, and
any other written file would differ from the same file built on Linux. Every
text write in a release script therefore passes newline="\\n" (or writes
bytes).

Run with --self-test to prove the check flags what it should.
"""
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RELEASE = ROOT / ".github" / "release"

# Signing helpers that only run on the Linux signing runner; their files are
# never built on Windows.
EXEMPT = {"sign_request.py", "announce_trust_chain.py"}


def problems(source: str, name: str) -> list[str]:
    out = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        kws = {k.arg for k in node.keywords}
        if isinstance(func, ast.Attribute) and func.attr == "write_text":
            bad = "newline" not in kws
        elif (isinstance(func, ast.Name) and func.id == "open") or (
            isinstance(func, ast.Attribute) and func.attr == "open"
        ):
            first = 1 if isinstance(func, ast.Name) else 0
            mode = None
            if len(node.args) > first and isinstance(node.args[first], ast.Constant):
                mode = node.args[first].value
            for k in node.keywords:
                if k.arg == "mode" and isinstance(k.value, ast.Constant):
                    mode = k.value.value
            bad = (
                isinstance(mode, str)
                and ("w" in mode or "a" in mode or "x" in mode)
                and "b" not in mode
                and "newline" not in kws
            )
        else:
            continue
        if bad:
            out.append(f'{name}:{node.lineno}: text write without newline="\\n"')
    return out


def main() -> int:
    if "--self-test" in sys.argv:
        assert problems('p.write_text("x")', "t")
        assert problems('open(p, "w")', "t")
        assert problems('p.open("w")', "t")
        assert not problems('p.write_text("x", newline="\\n")', "t")
        assert not problems('open(p, "w", newline="\\n")', "t")
        assert not problems('open(p, "rb")', "t")
        assert not problems("p.write_bytes(b'x')", "t")
        print("check-release-lf-writes self-test passed")
        return 0
    found = []
    for path in sorted(RELEASE.glob("*.py")):
        if path.name.startswith("test_") or path.name in EXEMPT:
            continue
        found += problems(path.read_text(encoding="utf-8"), path.relative_to(ROOT).as_posix())
    for line in found:
        print(line, file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
