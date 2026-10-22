#!/usr/bin/env python3
"""Enforce Phase 3's `LinkRuntime`/`LinkRuntimeController` ownership
invariants, the same way `check-daemon-composition-root.py` enforces
Phase 2's:

1. `link_manager` must never reappear anywhere in this crate (source or
   its own integration tests) -- the whole module was deleted in Commit
   4+6; every caller now goes through `LinkRuntimeController`. A
   resurrected `link_manager::` reference is either a stale doc comment
   that regressed, or a real caller that bypassed the controller.
2. The `link_runtime` module tree (`link_runtime.rs` and everything under
   `link_runtime/`) must stay free of real `DaemonState` code references
   -- specifically, the literal `crate::daemon_state` substring the
   dependency-graph generator (`gen-daemon-production-graph.py`) itself
   treats as a real edge. A bare `DaemonState` mention in prose (this
   module tree's own established convention for explaining why something
   is excluded, e.g. "needs `DaemonState` directly") is fine and NOT
   flagged -- only the `crate::`-prefixed form is, matching exactly what
   the graph generator's own `crate::`-prefixed regex would pick up as a
   phantom edge. `root_commit_authority.rs` is a deliberate, documented
   exception -- it lives OUTSIDE this module tree specifically because it
   needs `DaemonState` directly (see that file's own module doc) -- so it
   is not scanned here.
3. `LinkRuntimeController::new(` -- the one non-trivial construction this
   gate cares about -- is only called from an allowlisted set of files
   (the composition points: `adapters/mod.rs`, `maintenance_coordinator.rs`,
   `app.rs`) or from inside a `#[cfg(test)]` span anywhere (every test
   fixture across this crate and its relocated `link_runtime_controller.rs`/
   `link_runtime/startup.rs`/`link_runtime/operations/capture_local_change.rs`
   test modules constructs its own controller/dependencies directly).

This is a substring/brace-matching scan, not a real Rust parser -- same
class of tool, and the same false-positive/evasion tradeoffs, as
`check-architecture.py`/`check-daemon-composition-root.py`.
Check 2's "real code, not a comment" distinction is a plain per-line
`.strip().startswith("//")` heuristic (this repo's own style never puts
a real `use`/type reference on the same line as a `//` comment opener),
not `#[cfg(test)]`-aware brace matching -- deliberately simpler than
`check-daemon-composition-root.py`'s span detection, since this crate's
own established convention (Phase 2E-1 onward) is to never write a
literal `crate::daemon_state`/bare `DaemonState` token in a doc comment
inside this module tree at all, describing the target in prose instead
("the daemon's own X module") -- so any real match here, comment or not,
is itself the thing worth flagging and fixing.
"""

from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DAEMON_SRC = ROOT / "crates/yadorilink-daemon/src"
DAEMON_TESTS = ROOT / "crates/yadorilink-daemon/tests"

LINK_RUNTIME_ROOT_FILE = "link_runtime.rs"
LINK_RUNTIME_SUBDIR = "link_runtime"
DAEMONSTATE_TOKENS = ("crate::daemon_state",)

CONTROLLER_NEW_TOKEN = "LinkRuntimeController::new("
ALLOWED_CONTROLLER_CALLERS = {
    "mod.rs",  # adapters/mod.rs -- the composition point for every adapter
    "maintenance_coordinator.rs",
    "app.rs",
}

CFG_TEST_ATTR = re.compile(r"#\[cfg\(\s*test\s*\)\]")


def cfg_test_line_ranges(text: str) -> list[tuple[int, int]]:
    """Same brace-matching technique as `check-daemon-composition-root.py`
    (itself borrowed from `gen-daemon-production-graph.py`'s
    `strip_cfg_test_blocks`): every `#[cfg(test)] <item> { ... }` span, as
    (start_line, end_line) 1-indexed inclusive line numbers.
    """
    # A file that opens with the inner attribute is a test module living in
    # its own file: its parent declares it `#[cfg(test)] mod x;`, which this
    # per-file scanner cannot see. The whole file is one test span.
    if text.lstrip().startswith("#![cfg(test)]"):
        return [(1, text.count("\n") + 1)]
    ranges: list[tuple[int, int]] = []
    i = 0
    n = len(text)
    while i < n:
        m = CFG_TEST_ATTR.search(text, i)
        if not m:
            break
        brace_start = text.find("{", m.end())
        if brace_start == -1:
            i = m.end()
            continue
        depth = 0
        j = brace_start
        while j < n:
            c = text[j]
            if c == '"':
                j += 1
                while j < n and text[j] != '"':
                    if text[j] == "\\":
                        j += 1
                    j += 1
                j += 1
                continue
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        start_line = text.count("\n", 0, m.start()) + 1
        end_line = text.count("\n", 0, j) + 1
        ranges.append((start_line, end_line))
        i = j
    return ranges


def is_link_runtime_module_tree(rel: str) -> bool:
    return rel == LINK_RUNTIME_ROOT_FILE or rel.startswith(LINK_RUNTIME_SUBDIR + "/")


def violations(src_dir: Path, tests_dir: Path | None) -> list[str]:
    failures: list[str] = []

    all_files = sorted(src_dir.rglob("*.rs"))
    if tests_dir is not None and tests_dir.is_dir():
        all_files += sorted(tests_dir.rglob("*.rs"))

    for path in all_files:
        under_tests = tests_dir is not None and tests_dir in path.parents
        base_dir = tests_dir if under_tests else src_dir
        rel = path.relative_to(base_dir).as_posix()
        rel_name = path.name
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()

        # Check 1: link_manager must never reappear, anywhere.
        for i, line in enumerate(lines, start=1):
            if "link_manager" in line:
                failures.append(f"{path}:{i} references the deleted link_manager module")

        if under_tests:
            continue

        # Check 2: the link_runtime module tree stays DaemonState-free,
        # real code or comment alike.
        if is_link_runtime_module_tree(rel):
            for i, line in enumerate(lines, start=1):
                for token in DAEMONSTATE_TOKENS:
                    if token in line:
                        failures.append(
                            f"{path}:{i} mentions {token} inside the link_runtime module tree "
                            "(should stay DaemonState-free; describe the target in prose "
                            "instead of naming the type/path literally)"
                        )

        # Check 3: LinkRuntimeController::new( only from the allowlist or
        # a #[cfg(test)] span.
        if CONTROLLER_NEW_TOKEN in text:
            test_ranges = cfg_test_line_ranges(text)

            def in_test_span(line_no: int, _ranges=test_ranges) -> bool:
                return any(start <= line_no <= end for start, end in _ranges)

            for i, line in enumerate(lines, start=1):
                if CONTROLLER_NEW_TOKEN not in line:
                    continue
                if rel_name in ALLOWED_CONTROLLER_CALLERS:
                    continue
                if in_test_span(i):
                    continue
                failures.append(
                    f"{path}:{i} constructs LinkRuntimeController::new outside the "
                    "allowlist and outside a #[cfg(test)] span"
                )

    return failures


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        src_dir = Path(directory)

        # Check 1: link_manager anywhere is flagged.
        stale = src_dir / "some_module.rs"
        stale.write_text("// see link_manager::start_link_watch's old doc\n", encoding="utf-8")
        found = violations(src_dir, None)
        assert any("link_manager" in f for f in found), "a link_manager mention must be flagged"
        stale.unlink()
        assert not violations(src_dir, None)

        # Check 2: a real `crate::daemon_state` use is flagged; bare
        # "DaemonState" prose (this module tree's own established
        # convention) is NOT -- matching the graph generator's own
        # crate::-prefixed regex exactly.
        (src_dir / LINK_RUNTIME_SUBDIR).mkdir()
        lr_root = src_dir / LINK_RUNTIME_ROOT_FILE
        lr_root.write_text("use crate::daemon_state::DaemonState;\n", encoding="utf-8")
        found = violations(src_dir, None)
        assert any(LINK_RUNTIME_ROOT_FILE in f for f in found), "real DaemonState use must be flagged"
        lr_root.write_text("//! reaches into `DaemonState` directly\n", encoding="utf-8")
        assert not violations(src_dir, None), "bare DaemonState prose must pass, only crate::daemon_state is flagged"

        # A file outside the link_runtime tree naming DaemonState is fine
        # (that's every other module in the crate).
        outside = src_dir / "root_commit_authority.rs"
        outside.write_text("use crate::daemon_state::DaemonState;\n", encoding="utf-8")
        assert not violations(src_dir, None), "DaemonState outside link_runtime/ must not be flagged"
        outside.unlink()
        lr_root.unlink()
        (src_dir / LINK_RUNTIME_SUBDIR).rmdir()

        # Check 3: LinkRuntimeController::new allowlist.
        allowed = src_dir / "mod.rs"
        allowed.write_text(
            "let controller = LinkRuntimeController::new(state.clone());\n", encoding="utf-8"
        )
        assert not violations(src_dir, None), "adapters/mod.rs (mod.rs) must be allowed"
        allowed.unlink()

        disallowed = src_dir / "some_handler.rs"
        disallowed.write_text(
            "let controller = LinkRuntimeController::new(state.clone());\n", encoding="utf-8"
        )
        found = violations(src_dir, None)
        assert any(
            "some_handler.rs" in f for f in found
        ), "a non-allowlisted, non-test construction must be flagged"

        test_gated = src_dir / "some_handler.rs"
        test_gated.write_text(
            "#[cfg(test)]\nmod tests {\n"
            "    fn helper() {\n"
            "        let controller = LinkRuntimeController::new(state.clone());\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        assert not violations(src_dir, None), "a #[cfg(test)]-gated construction must pass"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("link-runtime ownership self-test passed")
        return 0

    failures = violations(DAEMON_SRC, DAEMON_TESTS)
    if failures:
        print("link-runtime ownership violations:")
        for failure in failures:
            print(f"- {failure.replace(str(ROOT) + '/', '')}")
        return 1

    print("link-runtime ownership check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
