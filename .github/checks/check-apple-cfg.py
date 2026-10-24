#!/usr/bin/env python3
"""Fail on an unclassified `target_os = "macos"` / `target_os = "ios"` in crates/.

`target_os = "macos"` reads as "any Apple platform" but is false on iOS, so code
gated on it silently takes the generic branch there (wrong flush call, no
durable rename, wrong default paths). Each use must be a deliberate decision:

  * Apple-wide behaviour is written `target_vendor = "apple"` (never matched here);
  * a use that really is macOS-only (or an iOS-only arm) carries a classification marker in the same file:
        // apple-cfg-file: macos-only <reason>      (whole file)
        // apple-cfg: macos-only <reason>           (the same line or up to
                                                     six lines above the use)
    `#` comments work the same way in Cargo.toml.

Categories: macos-only, ios-explicit (an iOS-only arm, e.g. skipping a test the
platform cannot run). Run with --self-test to check the guard itself.
"""
import re
import sys
from pathlib import Path

USE = re.compile(r'target_os\s*=\s*"(?:macos|ios)"')
MARK = re.compile(r'apple-cfg:\s*(macos-only|ios-explicit)\s+\S')
FILE_MARK = re.compile(r'apple-cfg-file:\s*(macos-only|ios-explicit)\s+\S')
WINDOW = 6


def unclassified(text):
    if FILE_MARK.search(text):
        return []
    lines = text.splitlines()
    bad = []
    for i, line in enumerate(lines):
        if not USE.search(line):
            continue
        near = lines[max(0, i - WINDOW) : i + 1]
        if not any(MARK.search(n) for n in near):
            bad.append(i + 1)
    return bad


def scan(root):
    failures = []
    for path in sorted(list(root.glob("crates/**/*.rs")) + list(root.glob("crates/*/Cargo.toml"))):
        if "target" in path.parts:
            continue
        for n in unclassified(path.read_text(encoding="utf-8")):
            failures.append(f"{path.relative_to(root)}:{n}")
    return failures


def self_test():
    assert unclassified('#[cfg(target_os = "macos")]\nfn f() {}\n') == [1]
    assert unclassified('cfg!(target_os="ios")') == [1]
    assert unclassified('#[cfg(target_vendor = "apple")]\n') == []
    assert unclassified('// apple-cfg: macos-only ioreg\n#[cfg(target_os = "macos")]\n') == []
    assert unclassified('// apple-cfg-file: macos-only backend\ncfg!(target_os = "macos")') == []
    assert unclassified('// apple-cfg: macos-only x\n' + '\n' * 8 + 'cfg!(target_os = "macos")') == [10]
    assert unclassified('// apple-cfg: ios-explicit x\ncfg_attr(target_os = "ios", ignore)') == []
    assert unclassified('// apple-cfg: other x\ncfg!(target_os = "macos")') == [2]
    print("check-apple-cfg self-test: ok")


def main():
    if "--self-test" in sys.argv:
        self_test()
        return 0
    root = Path(__file__).resolve().parents[2]
    failures = scan(root)
    if failures:
        print('target_os = "macos"/"ios" without an apple-cfg classification (see the header of this script):')
        for f in failures:
            print("  " + f)
        return 1
    print("check-apple-cfg: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
