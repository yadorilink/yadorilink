#!/usr/bin/env python3
"""Enforce that `yadorilink-daemon`'s composition-root functions
(`adapters::build_application_services`, `adapters::build_query_services`,
`maintenance_coordinator::start`) are only ever CALLED from an allowed set
of files -- the production composition root (`app.rs`),
`maintenance_coordinator.rs` (which builds the services its recovery job
holds, once -- see `ALLOWED_BUILD_CALLERS` below), the
test-construction helper (`control_context.rs`'s `ControlContext::
from_state`, a normal `pub fn` used by both this crate's own unit tests
and the external integration-test binaries under `tests/`, so never
`#[cfg(test)]`-gated itself), and `#[cfg(test)]`-gated call sites in
`control_socket.rs`/`diagnostics_ipc.rs` -- including their test-only child
module files (e.g. `control_socket/migration_safety_tests.rs`), which the
parent declares `#[cfg(test)] mod name;` or which open with `#![cfg(test)]`.

This stays a separate script rather than an `.config/architecture.toml` rule
because what it enforces is not a boundary between crates or paths but a
three-tier per-file call allowlist with `#[cfg(test)]` span awareness,
specific to one crate's startup sequence.

This is a substring/brace-matching scan, not a real Rust parser -- same
class of tool as `.github/checks/check-architecture.py`, with the same
false-positive/evasion tradeoffs documented there. `#[cfg(test)]` span
detection reuses `gen-daemon-production-graph.py`'s own brace-matching
approach (see that script's `strip_cfg_test_blocks` for the same
technique, doc comment included).

This gate exists specifically to keep "build the whole application/query
layer fresh on every single request/tick" from quietly reappearing at a
new call site: constructing those services is expensive and is meant to
happen once, at startup. New violations must be treated as real
regressions, not adjusted into the allowlist without a documented reason.
"""

from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DAEMON_SRC = ROOT / "crates/yadorilink-daemon/src"

CALL_TOKENS = {
    "build_application_services(": "build_application_services",
    "build_query_services(": "build_query_services",
}
MAINTENANCE_START_TOKEN = "maintenance_coordinator::start("

DEFINITION_FILE = "adapters/mod.rs"

# Files allowed to call the composition-root builders, relative to
# DAEMON_SRC. `maintenance_coordinator.rs` builds the one `ApplicationServices`
# instance its `RecoveryJob` holds, once at start (maintenance starts before
# `app.rs` builds the control socket's instance; the services are stateless
# over `DaemonState`, so the two instances are interchangeable).
# `daemon_state.rs` is deliberately NOT allowed: the state owner must never
# drive an application workflow itself.
ALLOWED_BUILD_CALLERS = {
    "app.rs",
    "control_context.rs",
    "maintenance_coordinator.rs",
}

# `control_socket.rs`/`diagnostics_ipc.rs` may call the builders ONLY from
# inside a `#[cfg(test)]` span.
TEST_GATED_ONLY_CALLERS = {
    "control_socket.rs",
    "diagnostics_ipc.rs",
}

# A file-level cfg(test): `#![cfg(test)]` as the first attribute of the file.
INNER_CFG_TEST = re.compile(r"\A(?:\s*//[^\n]*\n)*\s*#!\[cfg\(\s*test\s*\)\]")


def is_test_only_child(src_dir: Path, path: Path) -> bool:
    """True when `path` is a child module of a TEST_GATED_ONLY_CALLERS file
    (`control_socket/x.rs` under `control_socket.rs`) and is compiled only
    under `cfg(test)`: the file opens with `#![cfg(test)]`, or its parent
    declares it `#[cfg(test)] mod x;`. Such a file is one whole test span.
    """
    parent_dir = path.parent
    parent = parent_dir.with_suffix(".rs")
    if parent.name not in TEST_GATED_ONLY_CALLERS or parent.parent != src_dir:
        return False
    if INNER_CFG_TEST.match(path.read_text(encoding="utf-8")):
        return True
    if not parent.is_file():
        return False
    declaration = re.compile(
        r"#\[cfg\(\s*test\s*\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+"
        + re.escape(path.stem)
        + r"\s*;"
    )
    return bool(declaration.search(parent.read_text(encoding="utf-8")))


# `maintenance_coordinator::start` -- production's `app.rs` and the
# `DaemonState::new` compatibility wrapper are the only two
# legitimate callers; nothing else should ever start the maintenance
# background-task set a second time.
ALLOWED_MAINTENANCE_START_CALLERS = {
    "app.rs",
    "daemon_state.rs",
}

CFG_TEST_ATTR = re.compile(r"#\[cfg\(\s*test\s*\)\]")


def cfg_test_line_ranges(text: str) -> list[tuple[int, int]]:
    """Every `#[cfg(test)] <item> { ... }` span, as (start_line, end_line)
    1-indexed inclusive line numbers -- brace-matched from the `{` after
    the attribute, same technique as `gen-daemon-production-graph.py`'s
    `strip_cfg_test_blocks`.
    """
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


def violations(src_dir: Path) -> list[str]:
    failures: list[str] = []

    for path in sorted(src_dir.rglob("*.rs")):
        rel = path.relative_to(src_dir).as_posix()
        rel_name = path.name
        if rel == DEFINITION_FILE:
            continue
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        test_ranges = cfg_test_line_ranges(text)
        if is_test_only_child(src_dir, path):
            test_ranges = [(1, len(lines))]

        def in_test_span(line_no: int) -> bool:
            return any(start <= line_no <= end for start, end in test_ranges)

        for i, line in enumerate(lines, start=1):
            for token, label in CALL_TOKENS.items():
                if token not in line:
                    continue
                if in_test_span(i) and (
                    rel_name in TEST_GATED_ONLY_CALLERS or is_test_only_child(src_dir, path)
                ):
                    continue
                if rel_name in TEST_GATED_ONLY_CALLERS:
                    if not in_test_span(i):
                        failures.append(
                            f"{path}:{i} calls {label} outside a #[cfg(test)] span in a "
                            "test-only-allowed file"
                        )
                elif rel_name not in ALLOWED_BUILD_CALLERS:
                    failures.append(
                        f"{path}:{i} calls {label} from a file not in the composition-root "
                        "allowlist"
                    )

            if MAINTENANCE_START_TOKEN in line and rel_name not in ALLOWED_MAINTENANCE_START_CALLERS:
                failures.append(
                    f"{path}:{i} calls maintenance_coordinator::start from a file not in "
                    "its allowlist"
                )

    return failures


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        src_dir = Path(directory)

        allowed = src_dir / "app.rs"
        allowed.write_text(
            "crate::adapters::build_application_services(state.clone());\n", encoding="utf-8"
        )
        assert not violations(src_dir), "app.rs must be allowed to call the builder"
        allowed.unlink()

        disallowed = src_dir / "some_handler.rs"
        disallowed.write_text(
            "crate::adapters::build_application_services(state.clone());\n", encoding="utf-8"
        )
        found = violations(src_dir)
        assert any("some_handler.rs" in f for f in found), "non-allowlisted caller must be flagged"
        disallowed.unlink()

        start_disallowed = src_dir / "some_handler.rs"
        start_disallowed.write_text(
            "maintenance_coordinator::start(&state, rx);\n", encoding="utf-8"
        )
        found = violations(src_dir)
        assert any(
            "maintenance_coordinator::start" in f for f in found
        ), "non-allowlisted maintenance_coordinator::start caller must be flagged"
        start_disallowed.unlink()

        test_gated_ok = src_dir / "control_socket.rs"
        test_gated_ok.write_text(
            "#[cfg(test)]\nmod tests {\n"
            "    fn helper() {\n"
            "        crate::adapters::build_application_services(state.clone());\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        assert not violations(src_dir), "a #[cfg(test)]-gated call in control_socket.rs must pass"

        test_gated_ok.write_text(
            "crate::adapters::build_application_services(state.clone());\n"
            "#[cfg(test)]\nmod tests {}\n",
            encoding="utf-8",
        )
        found = violations(src_dir)
        assert any(
            "control_socket.rs" in f for f in found
        ), "an UN-gated call in control_socket.rs must be flagged"
        test_gated_ok.unlink()

        child_dir = src_dir / "control_socket"
        child_dir.mkdir()
        (src_dir / "control_socket.rs").write_text(
            "#[cfg(test)]\nmod declared_tests;\nmod production_child;\n", encoding="utf-8"
        )
        call = "crate::adapters::build_application_services(state.clone());\n"
        (child_dir / "declared_tests.rs").write_text(call, encoding="utf-8")
        (child_dir / "inner_gated_tests.rs").write_text("#![cfg(test)]\n" + call, encoding="utf-8")
        assert not violations(src_dir), "a cfg(test) child module of control_socket.rs must pass"

        (child_dir / "production_child.rs").write_text(call, encoding="utf-8")
        found = violations(src_dir)
        assert any(
            "production_child.rs" in f for f in found
        ), "a production child module of control_socket.rs must be flagged"
        (child_dir / "production_child.rs").unlink()

        other_dir = src_dir / "some_handler"
        other_dir.mkdir()
        (other_dir / "tests.rs").write_text("#![cfg(test)]\n" + call, encoding="utf-8")
        found = violations(src_dir)
        assert any(
            "some_handler/tests.rs" in f for f in found
        ), "a test file outside the test-gated callers must still be flagged"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("daemon composition-root self-test passed")
        return 0

    failures = violations(DAEMON_SRC)
    if failures:
        print("daemon composition-root violations:")
        for failure in failures:
            print(f"- {failure.replace(str(ROOT) + '/', '')}")
        return 1

    print("daemon composition-root check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
