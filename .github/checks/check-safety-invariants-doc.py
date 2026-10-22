#!/usr/bin/env python3
"""Fail when SAFETY_INVARIANTS.md names a file or a test that does not exist.

The document maps each data-safety rule to the code, checks and tests that
enforce it. A rename that leaves the document pointing at nothing makes the
mapping untrue, so every reference is resolved:

  * a backticked token that contains a `/` and ends in a known file suffix is
    a path and must exist (relative to the repository root);
  * a backticked token that is a bare `*.rs` or `*.py` file name must exist
    somewhere under `crates/` or `.github/`;
  * a backticked snake_case identifier of three or more words is a test or
    function name and must appear as `fn <name>` in some Rust source under
    `crates/`.

The scan reads the document from the repository root (the published layout) or
from `oss-public/` (the layout the published tree is generated from). Run with
`--self-test` to exercise the resolver on synthetic input.
"""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[2]
DOC_NAMES = ("docs/SAFETY_INVARIANTS.md",)
DOC_DIRS = (ROOT, ROOT / "oss-public")
PATH_SUFFIXES = (".rs", ".py", ".md", ".toml", ".yml", ".yaml", ".sh")
TOKEN = re.compile(r"`([^`\n]+)`")
IDENT = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+){2,}$")


def find_doc():
    for directory in DOC_DIRS:
        for name in DOC_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def rust_function_names(root):
    names = set()
    pattern = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")
    for path in (root / "crates").rglob("*.rs"):
        if "target" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        names.update(pattern.findall(text))
    return names


def file_basenames(root):
    names = set()
    for sub in ("crates", ".github"):
        base = root / sub
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if path.is_file() and "target" not in path.parts:
                names.add(path.name)
    return names


def path_exists(root, token):
    """A path in the document may be spelled for the published tree."""
    if (root / token).exists():
        return True
    return (root / "oss-public" / token).exists()


def check_text(text, root, functions, basenames):
    problems = []
    seen = set()
    for number, line in enumerate(text.splitlines(), start=1):
        for token in TOKEN.findall(line):
            token = token.strip()
            if token in seen:
                continue
            if "/" in token and token.endswith(PATH_SUFFIXES) and " " not in token:
                seen.add(token)
                if not path_exists(root, token):
                    problems.append(f"line {number}: no such path: {token}")
            elif token.endswith((".rs", ".py")) and "/" not in token and " " not in token:
                seen.add(token)
                if token not in basenames:
                    problems.append(f"line {number}: no such file: {token}")
            elif IDENT.match(token):
                seen.add(token)
                if token not in functions:
                    problems.append(f"line {number}: no function named: {token}")
    return problems


def self_test():
    functions = {"a_named_test_function"}
    basenames = {"present.rs"}
    root = ROOT
    good = "`a_named_test_function` and `present.rs` and `.github/checks/check-safety-invariants-doc.py`"
    assert check_text(good, root, functions, basenames) == []
    bad = "`a_missing_test_function` `gone.rs` `crates/nothing/src/lib.rs`"
    found = check_text(bad, root, functions, basenames)
    assert len(found) == 3, found
    print("self-test passed")


def main():
    if "--self-test" in sys.argv[1:]:
        self_test()
        return 0
    doc = find_doc()
    if doc is None:
        print("SAFETY_INVARIANTS.md not found", file=sys.stderr)
        return 1
    problems = check_text(
        doc.read_text(encoding="utf-8"),
        ROOT,
        rust_function_names(ROOT),
        file_basenames(ROOT),
    )
    if problems:
        print("SAFETY_INVARIANTS.md has references that do not resolve:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print("SAFETY_INVARIANTS.md: every named path, file and test resolves")
    return 0


if __name__ == "__main__":
    sys.exit(main())
