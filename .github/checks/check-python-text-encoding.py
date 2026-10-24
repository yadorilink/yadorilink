#!/usr/bin/env python3
"""Require an explicit encoding on every text-mode file or subprocess call.

Python text I/O defaults to the locale encoding. On a Windows host with a
non-UTF-8 code page (cp932, cp1252) a guard that reads a UTF-8 file with a
bare `read_text()` fails with `UnicodeDecodeError`, or silently mis-decodes.
Stating `encoding="utf-8"` at every site removes the dependence on the host.

This guard parses every tracked `.py` file and fails on:
  * `open(...)` in text mode (no `b` in the mode) without `encoding=`,
  * `.read_text(...)` / `.write_text(...)` without `encoding=`,
  * `path.open()` / `path.open("r"|"w"...)` in text mode without `encoding=`,
  * `subprocess.run/Popen/call/check_call/check_output` with `text=True`
    (or `universal_newlines=True`) and no `encoding=`.
A call that forwards `**kwargs` is not judged.

Run with no arguments to check the tree, and `--self-test` to exercise the
check against synthetic sources.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

SUBPROCESS_FUNCS = {"run", "Popen", "call", "check_call", "check_output"}
NOT_A_PATH = {"webbrowser", "os", "tarfile", "zipfile", "io", "codecs", "Image"}


def _kw(call: ast.Call, name: str):
    for k in call.keywords:
        if k.arg == name:
            return k
    return None


def _text_mode(call: ast.Call, index: int, no_mode_is_text: bool) -> bool:
    """True when the call opens in text mode: a literal mode without 'b', or
    no mode at all when `no_mode_is_text`."""
    if len(call.args) > index:
        mode = call.args[index]
    elif (k := _kw(call, "mode")) is not None:
        mode = k.value
    else:
        return no_mode_is_text
    return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and "b" not in mode.value


def violations(source: str, name: str = "<src>"):
    """Yield (call node, description) for each offending call."""
    for node in ast.walk(ast.parse(source, filename=name)):
        if not isinstance(node, ast.Call) or any(k.arg is None for k in node.keywords):
            continue
        f = node.func
        has_enc = _kw(node, "encoding") is not None
        what = None
        if isinstance(f, ast.Name) and f.id == "open":
            # open(file, mode, buffering, encoding): 4th positional is encoding.
            if len(node.args) < 4 and not has_enc and _text_mode(node, 1, True):
                what = "open() in text mode"
        elif isinstance(f, ast.Attribute):
            if f.attr == "read_text":
                if not has_enc and not node.args:
                    what = "read_text()"
            elif f.attr == "write_text":
                if not has_enc and len(node.args) < 2:
                    what = "write_text()"
            elif f.attr == "open":
                is_path = not (isinstance(f.value, ast.Name) and f.value.id in NOT_A_PATH)
                # Path.open(mode): a bare .open("name") is some other API.
                path_shape = not node.args or (
                    isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    and len(node.args[0].value) <= 3
                    and set(node.args[0].value) <= set("rwxabt+")
                )
                if is_path and path_shape and not has_enc and _text_mode(node, 0, True):
                    what = ".open() in text mode"
            elif (
                f.attr in SUBPROCESS_FUNCS
                and isinstance(f.value, ast.Name)
                and f.value.id == "subprocess"
            ):
                t = _kw(node, "text") or _kw(node, "universal_newlines")
                if t is not None and isinstance(t.value, ast.Constant) and t.value.value and not has_enc:
                    what = f"subprocess.{f.attr}(text=True)"
        if what:
            yield node, what


def findings(source: str, name: str = "<src>"):
    return [f"{name}:{n.lineno}: {w} without encoding=" for n, w in violations(source, name)]


def tracked_python(root: Path):
    try:
        r = subprocess.run(
            ["git", "ls-files", "*.py"], cwd=root, capture_output=True,
            text=True, encoding="utf-8", check=True,
        )
        return [root / p for p in r.stdout.splitlines() if p]
    except (OSError, subprocess.CalledProcessError):
        return sorted(root.rglob("*.py"))


def check_tree(root: Path) -> int:
    bad = []
    for p in tracked_python(root):
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        try:
            bad += findings(p.read_text(encoding="utf-8"), rel)
        except SyntaxError as e:
            bad.append(f"{rel}: cannot parse: {e}")
    for line in bad:
        print(line)
    if bad:
        print(f"FAIL: {len(bad)} text-mode site(s) without an explicit encoding")
        return 1
    print("ok: every text-mode open/read_text/write_text/subprocess call states its encoding")
    return 0


def self_test() -> int:
    good = [
        'open("f", encoding="utf-8")',
        'open("f", "rb")',
        'open("f", mode="wb")',
        'open("f", "r", -1, "utf-8")',
        'p.read_text(encoding="utf-8")',
        'p.write_text("x", encoding="utf-8")',
        'p.write_text("x", "utf-8")',
        'p.open("rb")',
        'p.open(encoding="utf-8")',
        'zipfile.open("a")',
        'z.open("member.txt")',
        'subprocess.run(["x"], capture_output=True)',
        'subprocess.run(["x"], text=True, encoding="utf-8")',
        "open(*a, **k)",
    ]
    bad = [
        'open("f")',
        'open("f", "w")',
        'open("f", mode="r")',
        "p.read_text()",
        'p.write_text("x")',
        "p.open()",
        'p.open("w")',
        'subprocess.run(["x"], text=True)',
        'subprocess.check_output(["x"], universal_newlines=True)',
        'subprocess.Popen(["x"], text=True)',
    ]
    fails = [f"false positive: {s}" for s in good if findings(s)]
    fails += [f"missed: {s}" for s in bad if not findings(s)]
    # Mutation: removing the encoding from a clean source must be caught.
    clean = 'x = Path("a").read_text(encoding="utf-8")\n'
    mutated = clean.replace('encoding="utf-8"', "")
    if findings(clean) or not findings(mutated):
        fails.append("mutation (drop encoding) not caught")
    for f in fails:
        print("self-test FAIL:", f)
    if fails:
        return 1
    print("self-test ok")
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()
    return check_tree(Path(__file__).resolve().parents[2])


if __name__ == "__main__":
    sys.exit(main())
