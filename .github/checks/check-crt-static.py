#!/usr/bin/env python3
"""Fail unless .cargo/config.toml links the C runtime statically for the Windows MSVC target.

A Windows binary built with the dynamic CRT imports VCRUNTIME140.dll, which a clean Windows (and the
Microsoft Store reviewers' machine) does not have, so it does not start. Run from the repository root:
python3 .github/checks/check-crt-static.py [--self-test]
"""
import sys
import tomllib
from pathlib import Path

TARGET = "x86_64-pc-windows-msvc"
WANT = ["-C", "target-feature=+crt-static"]


def problem(text):
    """None when the config enables crt-static for TARGET, else a short description."""
    try:
        flags = tomllib.loads(text).get("target", {}).get(TARGET, {}).get("rustflags", [])
    except tomllib.TOMLDecodeError as e:
        return f"not valid TOML ({e})"
    if isinstance(flags, str):
        flags = flags.split()
    joined = " ".join(flags).replace("-Ctarget-feature", "-C target-feature")
    if "target-feature=+crt-static" not in joined:
        return f"[target.{TARGET}] rustflags lack {' '.join(WANT)}"
    return None


def self_test():
    assert problem(f'[target.{TARGET}]\nrustflags = ["-C", "target-feature=+crt-static"]\n') is None
    assert problem(f'[target.{TARGET}]\nrustflags = ["-Ctarget-feature=+crt-static"]\n') is None
    assert problem("") is not None
    assert problem(f'[target.{TARGET}]\nrustflags = ["-C", "target-cpu=native"]\n') is not None
    assert problem(f'[target.{TARGET}]\nrustflags = ["-C", "target-feature=-crt-static"]\n') is not None
    assert problem("[alias]\nx = 'y'\n") is not None
    assert problem("= broken") is not None


def main(argv):
    if "--self-test" in argv:
        self_test()
        return 0
    path = Path(".cargo/config.toml")
    if not path.is_file():
        print(f"error: {path} is missing: Windows binaries would use the dynamic CRT")
        return 1
    why = problem(path.read_text(encoding="utf-8"))
    if why:
        print(f"error: {path}: {why}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
