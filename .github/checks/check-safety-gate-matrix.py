#!/usr/bin/env python3
"""Fail when a safety gate, a failpoint or a refusal has no fault-injection row.

`crates/yadorilink-daemon/tests/safety_gate_fault_matrix.table` is the index of
the table-driven fault-injection harness (`safety_gate_fault_matrix.rs`). This
guard keeps the index complete:

  * every `### 2.N` rule and the `## 3` durability model of
    `SAFETY_INVARIANTS.md` has a `case` or `delegate` row, or an `exempt` row
    that says why it cannot be driven;
  * every variant of a watched failpoint or refusal enum (the explicit list
    below, plus any enum named `*Failpoint` / `*CommitPoint` anywhere under
    `crates/*/src`) is covered by a row's `covers` list or exempted with a reason;
  * every test-injection seam (a non-test function named `arm_*`, `inject_*`,
    `set_*` or `fail_*` function whose name says fail, fault, crash, inject,
    race hook or refusal) is covered as `seam:<name>` or exempted with a reason;
  * a `delegate` row names a test function that still exists;
  * a row that names a section, variant or seam that no longer exists is stale.

Row syntax (`#` starts a comment, fields are separated by `|`):

  case     | <id> | <section> | <covers,...> | <the invariant the case asserts>
  delegate | <section> | <covers,...> | <path>::<test function>
  exempt   | <section, Enum::Variant or seam:name> | <reason>

Run with `--self-test` to exercise the parsers on synthetic input.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TABLE = ROOT / "crates/yadorilink-daemon/tests/safety_gate_fault_matrix.table"
DOC_CANDIDATES = (
    ROOT / "docs/SAFETY_INVARIANTS.md",
    ROOT / "oss-public/docs/SAFETY_INVARIANTS.md",
)

# Refusal enums whose every variant is a distinct typed way a gate says no.
WATCHED_ENUMS = (
    ("crates/yadorilink-fs-platform/src/durable_dir.rs", "UnavailableReason"),
    ("crates/yadorilink-fs-platform/src/volume_identity.rs", "VolumeMatch"),
    ("crates/yadorilink-daemon/src/install_witness.rs", "Restored"),
    ("crates/yadorilink-daemon/src/update/manifest.rs", "VersionRefusal"),
)
AUTO_ENUM = re.compile(r"\bpub enum (\w*(?:Failpoint|CommitPoint))\b")
SEAM_FN = re.compile(r"\bpub(?:\(crate\))? fn ((?:arm|inject|set|fail)_\w*)\s*[(<]")
SEAM_WORDS = {"fail", "failpoint", "failures", "fault", "crash", "inject", "race", "refusal"}


def seams_in(text: str) -> list[str]:
    return [n for n in SEAM_FN.findall(text) if SEAM_WORDS & set(n.split("_"))]


MIN_REASON = 20


def is_test_path(path: Path) -> bool:
    parts = path.relative_to(ROOT).parts
    return "tests" in parts or path.name in ("tests.rs", "test_support.rs") or "target" in parts


def enum_variants(text: str, name: str) -> list[str]:
    """Variant names of `enum name { ... }` (identifiers at brace depth 1)."""
    match = re.search(rf"\benum {re.escape(name)}\b[^{{;]*{{", text)
    if not match:
        return []
    depth, index = 1, match.end()
    while index < len(text) and depth > 0:
        depth += {"{": 1, "}": -1}.get(text[index], 0)
        index += 1
    out, nested = [], 0
    for raw in text[match.end() : index - 1].splitlines():
        line = raw.strip()
        if nested == 0 and line and not line.startswith(("//", "#", "/*", "*")):
            ident = re.match(r"([A-Z]\w*)", line)
            if ident:
                out.append(ident.group(1))
        nested += sum(raw.count(c) for c in "{([") - sum(raw.count(c) for c in "})]")
    return out


def parse_table(text: str) -> tuple[list[dict], list[str]]:
    rows, problems = [], []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip() if raw.lstrip().startswith("#") else raw.strip()
        if not line:
            continue
        fields = [f.strip() for f in line.split("|")]
        kind = fields[0]
        where = f"table line {number}"
        if kind == "case" and len(fields) >= 5:
            rows.append({"kind": kind, "id": fields[1], "section": fields[2],
                         "covers": [c for c in fields[3].split(",") if c.strip()],
                         "text": "|".join(fields[4:]), "where": where})
        elif kind == "delegate" and len(fields) == 4:
            rows.append({"kind": kind, "section": fields[1],
                         "covers": [c.strip() for c in fields[2].split(",") if c.strip()],
                         "ref": fields[3], "where": where})
        elif kind == "exempt" and len(fields) >= 3:
            rows.append({"kind": kind, "key": fields[1], "reason": "|".join(fields[2:]),
                         "where": where})
        else:
            problems.append(f"{where}: unrecognised row: {raw.strip()}")
    return rows, problems


def doc_sections(text: str) -> set[str]:
    sections = set(re.findall(r"^### (2\.\d+)\b", text, flags=re.M))
    if re.search(r"^## 3\.", text, flags=re.M):
        sections.add("3")
    return sections


def check(rows, problems, sections, required_tokens, rust_fn_exists):
    problems = list(problems)
    covered_sections, covered_tokens = set(), set()
    seen_ids = set()
    for row in rows:
        if row["kind"] == "exempt":
            if len(row["reason"]) < MIN_REASON:
                problems.append(f"{row['where']}: an exempt row needs a real reason")
            key = row["key"]
            (covered_sections if re.fullmatch(r"\d(\.\d+)?", key) else covered_tokens).add(key)
            continue
        covered_sections.add(row["section"])
        covered_tokens.update(c.strip() for c in row["covers"])
        if row["kind"] == "case":
            if row["id"] in seen_ids:
                problems.append(f"{row['where']}: duplicate case id {row['id']}")
            seen_ids.add(row["id"])
        else:
            path, _, name = row["ref"].partition("::")
            if not rust_fn_exists(path, name):
                problems.append(f"{row['where']}: delegated test {row['ref']} does not exist")
    for section in sorted(sections - covered_sections):
        problems.append(f"SAFETY_INVARIANTS section {section} has no case, delegate or exempt row")
    for section in sorted(covered_sections - sections):
        problems.append(f"the table names section {section}, which SAFETY_INVARIANTS no longer has")
    for token in sorted(required_tokens - covered_tokens):
        problems.append(f"{token} has no row: add a case/delegate with it in `covers`, or an exempt row")
    for token in sorted(covered_tokens - required_tokens):
        problems.append(f"the table names {token}, which does not exist (renamed or removed)")
    return problems


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def discover_tokens() -> set[str]:
    tokens: set[str] = set()
    enums = list(WATCHED_ENUMS)
    sources = [p for p in (ROOT / "crates").glob("*/src/**/*.rs") if not is_test_path(p)]
    for path in sources:
        text = read(path)
        for name in AUTO_ENUM.findall(text):
            enums.append((path.relative_to(ROOT).as_posix(), name))
        for name in seams_in(text):
            tokens.add(f"seam:{name}")
    for rel, name in enums:
        for variant in enum_variants(read(ROOT / rel), name):
            tokens.add(f"{name}::{variant}")
    return tokens


def fn_exists(path: str, name: str) -> bool:
    file = ROOT / path
    return file.is_file() and re.search(rf"\bfn {re.escape(name)}\b", read(file)) is not None


def main() -> int:
    doc = next((p for p in DOC_CANDIDATES if p.is_file()), None)
    if doc is None:
        print("SAFETY_INVARIANTS.md not found", file=sys.stderr)
        return 1
    rows, problems = parse_table(read(TABLE))
    problems = check(rows, problems, doc_sections(read(doc)), discover_tokens(), fn_exists)
    if problems:
        print("safety gate fault matrix is out of date:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    print(f"safety gate fault matrix: {len(rows)} rows cover every gate, failpoint and seam")
    return 0


def self_test() -> int:
    enum = "pub enum Demo {\n    /// doc\n    A,\n    B(usize),\n    C { x: u8 },\n}\n"
    assert enum_variants(enum, "Demo") == ["A", "B", "C"], enum_variants(enum, "Demo")
    assert seams_in("pub fn arm_failpoint(x: u8) {}\npub fn plain() {}") == ["arm_failpoint"]
    assert seams_in("pub fn set_fail_after_rename_for_test(a: bool) {}") == [
        "set_fail_after_rename_for_test"
    ]
    assert not seams_in("pub fn arm(x: u8) {}\npub fn set_default_interval_for_tests() {}")
    rows, problems = parse_table(
        "case | a.b | 2.1 | Demo::A | text\n"
        "delegate | 2.2 | Demo::B | x.rs::t\n"
        "exempt | 2.3 | too short\n"
        "exempt | seam:s | a reason that is long enough to count\n"
        "nonsense\n"
    )
    assert len(problems) == 1 and len(rows) == 4
    result = check(rows, problems, {"2.1", "2.2", "2.3", "2.4"},
                   {"Demo::A", "Demo::B", "Demo::C", "seam:s"}, lambda p, n: False)
    wanted = ["unrecognised row", "needs a real reason", "does not exist", "section 2.4",
              "Demo::C"]
    for fragment in wanted:
        assert any(fragment in p for p in result), (fragment, result)
    assert not check(
        parse_table("case | a | 2.1 | Demo::A | t\n")[0], [], {"2.1"}, {"Demo::A"},
        lambda p, n: True)
    print("check-safety-gate-matrix self-test ok")
    return 0


if __name__ == "__main__":
    sys.exit(self_test() if "--self-test" in sys.argv[1:] else main())
