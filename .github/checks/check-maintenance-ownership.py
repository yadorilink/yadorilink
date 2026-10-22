#!/usr/bin/env python3
"""Enforce Phase 4's maintenance-job ownership invariant, the same way
`check-daemon-composition-root.py`/`check-link-runtime-ownership.py`
enforce their own phase's: every `crate::maintenance::*` job type (and
`reporting_retry::ReportingRetryJob`, which stayed in `reporting_retry.rs`
rather than moving under `crate::maintenance` -- see that module's own
doc comment) is constructed ONLY from its composition point
(`maintenance_coordinator.rs`, or `reporting_retry.rs`'s own
`spawn_periodic` for `ReportingRetryJob`) or from a `#[cfg(test)]` span
anywhere.

`maintenance_coordinator::start`'s own call-site allowlist (who may call
it at all) is already enforced by `check-daemon-composition-root.py`'s
`ALLOWED_MAINTENANCE_START_CALLERS` -- this gate does not duplicate that,
it enforces the complementary invariant one level down: once `start` is
running, nothing else in this crate should be independently constructing
one of its jobs and spawning a second, competing periodic loop for the
same maintenance concern.

Same substring/brace-matching tradeoffs as this repo's other gate
scripts in this family -- not a real Rust parser.
"""

from __future__ import annotations

import argparse
import re
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DAEMON_SRC = ROOT / "crates/yadorilink-daemon/src"

# job type name -> the `::new(` construction token to search for.
JOB_TYPES = (
    "UpdateCheckJob",
    "MaterializationRepairJob",
    "DegradedLinkRecheckJob",
    "RetentionExpiryJob",
    "RecoveryJob",
    "DiskReconcileBackstopJob",
    "GcIdleJob",
    "ReportingRetryJob",
)

ALLOWED_CALLERS = {
    "maintenance_coordinator.rs": set(JOB_TYPES) - {"ReportingRetryJob"},
    "reporting_retry.rs": {"ReportingRetryJob"},
}

CFG_TEST_ATTR = re.compile(r"#\[cfg\(\s*test\s*\)\]")


def cfg_test_line_ranges(text: str) -> list[tuple[int, int]]:
    """Same brace-matching technique as this repo's other Phase 2-4 gate
    scripts (originally `gen-daemon-production-graph.py`'s
    `strip_cfg_test_blocks`)."""
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
        rel_name = path.name
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        test_ranges = cfg_test_line_ranges(text)

        def in_test_span(line_no: int, _ranges=test_ranges) -> bool:
            return any(start <= line_no <= end for start, end in _ranges)

        allowed_here = ALLOWED_CALLERS.get(rel_name, set())

        for i, line in enumerate(lines, start=1):
            for job in JOB_TYPES:
                token = f"{job}::new("
                if token not in line:
                    continue
                # The type's own `impl` block (`fn new(...) -> Self`
                # inside `impl JobName { ... }`) is not a construction
                # call site -- skip lines that are plainly the
                # definition itself (`pub(crate) fn new(`), not a
                # `Type::new(` call.
                if re.search(rf"\bfn\s+new\s*\(", line) and job not in line.split("fn new")[0]:
                    continue
                if job in allowed_here:
                    continue
                if in_test_span(i):
                    continue
                failures.append(
                    f"{path}:{i} constructs {job}::new outside its composition point "
                    "and outside a #[cfg(test)] span"
                )

    return failures


def self_test() -> None:
    with tempfile.TemporaryDirectory() as directory:
        src_dir = Path(directory)

        allowed = src_dir / "maintenance_coordinator.rs"
        allowed.write_text(
            "let job = GcIdleJob::new(state.clone());\n", encoding="utf-8"
        )
        assert not violations(src_dir), "maintenance_coordinator.rs must be allowed"
        allowed.unlink()

        disallowed = src_dir / "some_handler.rs"
        disallowed.write_text(
            "let job = GcIdleJob::new(state.clone());\n", encoding="utf-8"
        )
        found = violations(src_dir)
        assert any(
            "some_handler.rs" in f for f in found
        ), "a non-allowlisted, non-test construction must be flagged"
        disallowed.unlink()

        test_gated = src_dir / "some_handler.rs"
        test_gated.write_text(
            "#[cfg(test)]\nmod tests {\n"
            "    fn helper() {\n"
            "        let job = GcIdleJob::new(state.clone());\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        assert not violations(src_dir), "a #[cfg(test)]-gated construction must pass"
        test_gated.unlink()

        reporting_allowed = src_dir / "reporting_retry.rs"
        reporting_allowed.write_text(
            "let job = ReportingRetryJob::new(state, client);\n", encoding="utf-8"
        )
        assert not violations(src_dir), "reporting_retry.rs must be allowed for ReportingRetryJob"
        reporting_allowed.unlink()

        reporting_disallowed = src_dir / "maintenance_coordinator.rs"
        reporting_disallowed.write_text(
            "let job = ReportingRetryJob::new(state, client);\n", encoding="utf-8"
        )
        found = violations(src_dir)
        assert any(
            "maintenance_coordinator.rs" in f for f in found
        ), "ReportingRetryJob is not in maintenance_coordinator.rs's own allowlist"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        print("maintenance ownership self-test passed")
        return 0

    failures = violations(DAEMON_SRC)
    if failures:
        print("maintenance ownership violations:")
        for failure in failures:
            print(f"- {failure.replace(str(ROOT) + '/', '')}")
        return 1

    print("maintenance ownership check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
