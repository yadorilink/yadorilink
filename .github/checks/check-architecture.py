#!/usr/bin/env python3
"""Check the workspace against `.config/architecture.toml`.

One checker, one manifest. `.config/architecture.toml` states the intended
structure -- ordered layers, exact dependency allowlists for the crates
whose isolation carries weight, and the forbidden packages, symbols,
patterns, confinements and call-site allowlists that the layer order alone
is too coarse to express. This script resolves the real crate graph with
`cargo metadata`, scans the sources each rule names, and reports every
divergence.

The graph comes from `cargo metadata --no-deps`, so renamed dependencies,
target-conditional tables and dependency kinds are read the way Cargo
resolves them rather than guessed from manifest text. Source rules are
substring and regex matches, not a Rust parser: whole-line comments are
skipped, `#[cfg(test)]` items are skipped where a rule asks for it, and a
deliberate `use tokio as t;` rename evades a symbol rule. Reviewer judgment
remains the backstop, as it does for every lint.

Structural staleness is itself a failure. Every individual path pattern a
rule names must match at least one file -- per pattern, not per rule, so a
rule listing several files cannot half-rot when one of them is renamed --
and every crate named in the manifest must exist in the workspace. A rule
cannot quietly stop guarding anything when the code it was written for is
renamed or removed.

Run with no arguments to check the tree; `--self-test` exercises every rule
kind against synthetic fixtures.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / ".config" / "architecture.toml"

COMMENT_LINE = re.compile(r"^\s*//")
CFG_TEST_ATTR = re.compile(r"#\[cfg\(\s*test\s*\)\]")

# Cargo reports a normal dependency's kind as null.
KIND_NORMAL = "normal"
KIND_BUILD = "build"

# The kinds that make up a crate's production graph. A dev dependency is
# deliberately excluded: several engine crates carry a dev-only back edge
# onto the daemon so their integration fixtures can drive a real process,
# and that is not a production cycle. A build dependency is included --
# a build script that reaches upward is compiled into the real build.
PRODUCTION_KINDS = (KIND_NORMAL, KIND_BUILD)


# --------------------------------------------------------------------------
# Workspace graph
# --------------------------------------------------------------------------


def workspace_graph(root: Path) -> dict[str, dict[str, set[str]]]:
    """`{package: {kind: {dependency names}}}` for every workspace member.

    Both the real package name and any `package = "..."` rename are recorded,
    so a rule naming either form matches.
    """
    raw = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return parse_metadata(json.loads(raw))


def parse_metadata(metadata: dict) -> dict[str, dict[str, set[str]]]:
    graph: dict[str, dict[str, set[str]]] = {}
    for package in metadata.get("packages", []):
        kinds: dict[str, set[str]] = {}
        for dependency in package.get("dependencies", []):
            kind = dependency.get("kind") or KIND_NORMAL
            names = kinds.setdefault(kind, set())
            names.add(dependency["name"])
            if dependency.get("rename"):
                names.add(dependency["rename"])
        graph[package["name"]] = kinds
    return graph


def dependencies_of(
    graph: dict[str, dict[str, set[str]]], package: str, kinds: tuple[str, ...]
) -> set[str]:
    entry = graph.get(package, {})
    found: set[str] = set()
    for kind in kinds:
        found |= entry.get(kind, set())
    return found


# --------------------------------------------------------------------------
# Source scanning
# --------------------------------------------------------------------------


def cfg_test_spans(text: str) -> list[tuple[int, int]]:
    """Line ranges (1-indexed, inclusive) covered by `#[cfg(test)]` items.

    Brace-matched from the `{` that opens the attributed item, skipping over
    string literals so a brace inside one does not unbalance the count. An
    attribute followed by a `;` before any `{` (a `#[cfg(test)] use ...;`)
    covers only its own statement.
    """
    return item_spans(text, CFG_TEST_ATTR)


def item_spans(
    text: str, start: re.Pattern[str], statements: bool = True
) -> list[tuple[int, int]]:
    """Line ranges covered by every item that `start` introduces.

    `start` is an attribute or an item header (`fn name`); the span runs to
    the brace that closes the item it introduces, as `cfg_test_spans`
    describes. `statements` is false for a function header, whose signature
    may hold a `;` (`[u8; 32]`) that does not end it.
    """
    spans: list[tuple[int, int]] = []
    i = 0
    n = len(text)
    while i < n:
        match = start.search(text, i)
        if not match:
            break
        brace = text.find("{", match.end())
        semicolon = text.find(";", match.end())
        if brace == -1 or (statements and semicolon != -1 and semicolon < brace):
            end = semicolon if semicolon != -1 else match.end()
            spans.append(
                (text.count("\n", 0, match.start()) + 1, text.count("\n", 0, end) + 1)
            )
            i = end + 1
            continue
        depth = 0
        j = brace
        while j < n:
            char = text[j]
            if char == '"':
                j += 1
                while j < n and text[j] != '"':
                    if text[j] == "\\":
                        j += 1
                    j += 1
                j += 1
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        spans.append(
            (text.count("\n", 0, match.start()) + 1, text.count("\n", 0, j) + 1)
        )
        i = j
    return spans


def _parent_module_files(path: Path) -> list[Path]:
    """Files that may declare `path` as a submodule (`mod <stem>;`)."""
    directory = path.parent
    if path.name == "mod.rs":
        directory = directory.parent
    return [
        directory.with_suffix(".rs"),
        directory / "mod.rs",
        directory / "lib.rs",
        directory / "main.rs",
    ]


def is_cfg_test_module_file(path: Path) -> bool:
    """True when `path` is a module file compiled only under `cfg(test)`.

    An inline `#[cfg(test)] mod tests { ... }` is excluded by its brace span;
    the same module moved to its own file (`#[cfg(test)] mod tests;` in the
    parent) must be excluded as a whole, or moving a test module out of line
    would change what a rule sees. A file nested under such a module is a
    test file too.
    """
    stem = path.parent.name if path.name == "mod.rs" else path.stem
    declaration = re.compile(
        r"#\[cfg\(\s*test\s*\)\]\s*(?:#\[[^\]]*\]\s*)*"
        r"(?:pub(?:\([^)]*\))?\s+)?mod\s+" + re.escape(stem) + r"\s*;"
    )
    for parent in _parent_module_files(path):
        if parent == path or not parent.is_file():
            continue
        text = parent.read_text(encoding="utf-8")
        if not re.search(r"\bmod\s+" + re.escape(stem) + r"\s*;", text):
            continue
        if declaration.search(text):
            return True
        return is_cfg_test_module_file(parent)
    return False


def scannable_lines(
    text: str, exclude_test_spans: bool, path: Path | None = None
) -> list[tuple[int, str]]:
    """`(line number, line)` for every line a source rule may look at."""
    if exclude_test_spans and path is not None and is_cfg_test_module_file(path):
        return []
    spans = cfg_test_spans(text) if exclude_test_spans else []

    def in_test(line_no: int) -> bool:
        return any(start <= line_no <= end for start, end in spans)

    out: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if COMMENT_LINE.match(line):
            continue
        if exclude_test_spans and in_test(number):
            continue
        out.append((number, line))
    return out


def resolve(root: Path, patterns: list[str]) -> list[Path]:
    found: set[Path] = set()
    for pattern in patterns:
        found.update(p for p in root.glob(pattern) if p.is_file())
    return sorted(found)


def relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def stale_patterns(
    root: Path, kind: str, name: str, field: str, patterns: list[str]
) -> list[str]:
    """One failure for every pattern in `patterns` that matches no file.

    Per pattern, deliberately, not per rule. A rule that names several
    literal files stops guarding one of them the moment that file is
    renamed, and the surviving entries would otherwise keep the rule
    resolving to a non-empty set and the check green -- the exact silent
    degradation the anti-rot guarantee exists to prevent.
    """
    if not patterns:
        return [f"{kind} {name!r}: {field} list is empty -- it guards nothing"]
    return [
        f"{kind} {name!r}: {field} {pattern!r} matches no file -- it no longer "
        "guards anything"
        for pattern in patterns
        if not any(p.is_file() for p in root.glob(pattern))
    ]


# --------------------------------------------------------------------------
# Rule kinds
# --------------------------------------------------------------------------


def check_layers(
    manifest: dict, graph: dict[str, dict[str, set[str]]], members: set[str]
) -> list[str]:
    failures: list[str] = []
    order: list[str] = manifest["layers"]["order"]
    exempt = set(manifest["layers"].get("exempt", []))

    rank: dict[str, int] = {}
    for index, layer in enumerate(order):
        if layer not in manifest.get("layer", {}):
            failures.append(f"layers.order names {layer!r}, which has no [layer.{layer}] table")
            continue
        for crate in manifest["layer"][layer]["crates"]:
            if crate in rank:
                failures.append(f"{crate} is assigned to more than one layer")
            rank[crate] = index

    for crate in sorted(rank):
        if crate not in members:
            failures.append(
                f"[layer.*] assigns {crate!r}, which is not a workspace member -- "
                "this rule no longer guards anything"
            )

    for crate in sorted(members - exempt):
        if crate not in rank:
            failures.append(
                f"workspace member {crate!r} is in no layer -- every crate must be "
                "placed in .config/architecture.toml before it can be depended on"
            )

    for crate in sorted(rank):
        if crate not in members:
            continue
        for dependency in sorted(dependencies_of(graph, crate, PRODUCTION_KINDS)):
            if dependency not in rank:
                continue
            if rank[dependency] > rank[crate]:
                failures.append(
                    f"{crate} ({order[rank[crate]]}) depends on {dependency} "
                    f"({order[rank[dependency]]}) -- a crate may only depend on its own "
                    "layer or a lower one"
                )
    return failures


def check_crate_allowlists(
    manifest: dict, graph: dict[str, dict[str, set[str]]], members: set[str]
) -> list[str]:
    failures: list[str] = []
    for crate, rule in manifest.get("crate", {}).items():
        if crate not in members:
            failures.append(
                f'[crate."{crate}"] names a crate that is not a workspace member -- '
                "this rule no longer guards anything"
            )
            continue
        if "workspace_dependencies" not in rule:
            continue
        allowed = set(rule["workspace_dependencies"])
        actual = dependencies_of(graph, crate, (KIND_NORMAL,)) & members
        for extra in sorted(actual - allowed):
            failures.append(
                f"{crate} depends on {extra}, which is not in its "
                "workspace_dependencies allowlist"
            )
        for stale in sorted(allowed - actual):
            failures.append(
                f"{crate}'s workspace_dependencies allows {stale}, which it no longer "
                "depends on -- narrow the allowlist so it keeps describing reality"
            )
    return failures


def check_forbidden_dependencies(
    manifest: dict, graph: dict[str, dict[str, set[str]]], members: set[str]
) -> list[str]:
    failures: list[str] = []
    for rule in manifest.get("forbidden_dependency", []):
        kinds = tuple(rule.get("kinds", [KIND_NORMAL]))
        for crate in rule["crates"]:
            if crate not in members:
                failures.append(
                    f"forbidden_dependency {rule['name']!r} names {crate!r}, which is not "
                    "a workspace member -- this rule no longer guards anything"
                )
                continue
            present = dependencies_of(graph, crate, kinds)
            for package in rule["packages"]:
                if package in present:
                    failures.append(
                        f"[{rule['name']}] {crate} depends on forbidden package {package!r}"
                    )
    return failures


def check_forbidden_symbols(root: Path, manifest: dict) -> list[str]:
    failures: list[str] = []
    for rule in manifest.get("forbidden_symbol", []):
        failures += stale_patterns(
            root, "forbidden_symbol", rule["name"], "path", rule["paths"]
        )
        paths = resolve(root, rule["paths"])
        exclude = rule.get("test_spans") == "exclude"
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for number, line in scannable_lines(text, exclude, path):
                for symbol in rule["symbols"]:
                    if symbol in line:
                        failures.append(
                            f"[{rule['name']}] {relative(root, path)}:{number} "
                            f"references forbidden {symbol!r}"
                        )
    return failures


def check_forbidden_patterns(root: Path, manifest: dict) -> list[str]:
    failures: list[str] = []
    for rule in manifest.get("forbidden_pattern", []):
        failures += stale_patterns(
            root, "forbidden_pattern", rule["name"], "path", rule["paths"]
        )
        paths = resolve(root, rule["paths"])
        exclude = rule.get("test_spans") == "exclude"
        compiled = [re.compile(p) for p in rule["patterns"]]
        skip_containing = rule.get("skip_lines_containing", [])
        require_containing = rule.get("require_lines_containing", [])
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for number, line in scannable_lines(text, exclude, path):
                if any(token in line for token in skip_containing):
                    continue
                if require_containing and not any(t in line for t in require_containing):
                    continue
                for pattern in compiled:
                    if pattern.search(line):
                        failures.append(
                            f"[{rule['name']}] {relative(root, path)}:{number} "
                            f"matches forbidden pattern {pattern.pattern!r}: {line.strip()}"
                        )
    return failures


def mentions_symbol(line: str, symbol: str) -> bool:
    """Whole-identifier match: `probe_direct` is not `probe_directory_durability`."""
    left = r"(?<![A-Za-z0-9_])" if re.match(r"\w", symbol[0]) else ""
    right = r"(?![A-Za-z0-9_])" if re.match(r"\w", symbol[-1]) else ""
    return re.search(left + re.escape(symbol) + right, line) is not None


def check_confined_symbols(root: Path, manifest: dict) -> list[str]:
    failures: list[str] = []
    for rule in manifest.get("confined_symbol", []):
        failures += stale_patterns(
            root, "confined_symbol", rule["name"], "path", rule["paths"]
        )
        failures += stale_patterns(
            root,
            "confined_symbol",
            rule["name"],
            "allowed_paths entry",
            rule["allowed_paths"],
        )
        paths = resolve(root, rule["paths"])
        allowed = set(resolve(root, rule["allowed_paths"]))
        if not allowed:
            # Every allowed path is already reported stale above. Scanning
            # on would report the confined symbol's legitimate home as a
            # violation too, which buries the one failure worth reading.
            continue
        exclude = rule.get("test_spans") == "exclude"
        for path in paths:
            if path in allowed:
                continue
            text = path.read_text(encoding="utf-8")
            for number, line in scannable_lines(text, exclude, path):
                for symbol in rule["symbols"]:
                    if mentions_symbol(line, symbol):
                        failures.append(
                            f"[{rule['name']}] {relative(root, path)}:{number} "
                            f"references {symbol!r} outside its confinement"
                        )
    return failures


def check_call_sites(root: Path, manifest: dict) -> list[str]:
    failures: list[str] = []
    for rule in manifest.get("call_site", []):
        failures += stale_patterns(
            root, "call_site", rule["name"], "path", rule["paths"]
        )
        if "allowed_paths" in rule:
            failures += stale_patterns(
                root,
                "call_site",
                rule["name"],
                "allowed_paths entry",
                rule["allowed_paths"],
            )
        paths = resolve(root, rule["paths"])
        allowed = set(resolve(root, rule.get("allowed_paths", [])))
        item_failures, allowed_spans = allowed_item_spans(root, rule)
        failures += item_failures
        compiled = [re.compile(p) for p in rule["patterns"]]
        skip_test_paths = rule.get("skip_test_paths", False)
        exclude = rule.get("test_spans") == "exclude"
        matched_anywhere = False
        for path in paths:
            if skip_test_paths and is_test_path(path):
                continue
            text = path.read_text(encoding="utf-8")
            if not any(pattern.search(text) for pattern in compiled):
                continue
            matched_anywhere = True
            if path in allowed:
                continue
            spans = allowed_spans.get(path, [])
            for number, line in scannable_lines(text, exclude, path):
                if not any(pattern.search(line) for pattern in compiled):
                    continue
                if any(first <= number <= last for first, last in spans):
                    continue
                failures.append(
                    f"[{rule['name']}] {relative(root, path)}:{number} is not an "
                    f"allowed call site: {line.strip()}"
                )
        if not matched_anywhere:
            failures.append(
                f"call_site {rule['name']!r} found no call anywhere -- the symbol it "
                "guards no longer exists"
            )
    return failures


def allowed_item_spans(
    root: Path, rule: dict
) -> tuple[list[str], dict[Path, list[tuple[int, int]]]]:
    """The spans of a call-site rule's `allowed_items`, one function each.

    An allowed item names a single function in a single file, with the
    reason it may call what the rule otherwise confines -- narrower than
    allowing its whole file. A named file or function that no longer exists
    is a failure, like any other stale allowance.
    """
    failures: list[str] = []
    spans: dict[Path, list[tuple[int, int]]] = {}
    for item in rule.get("allowed_items", []):
        if not item.get("reason", "").strip():
            failures.append(
                f"call_site {rule['name']!r} allowed item {item['fn']!r} in "
                f"{item['path']} gives no reason"
            )
        path = root / item["path"]
        found = (
            item_spans(
                path.read_text(encoding="utf-8"),
                re.compile(r"\bfn\s+" + re.escape(item["fn"]) + r"\b"),
                statements=False,
            )
            if path.is_file()
            else []
        )
        if not found:
            failures.append(
                f"call_site {rule['name']!r} allowed item: no fn {item['fn']!r} in "
                f"{item['path']}"
            )
        spans.setdefault(path, []).extend(found)
    return failures, spans


def is_test_path(path: Path) -> bool:
    return (
        "tests" in path.parts
        or path.name.endswith("_test.rs")
        or "test_support" in path.name
    )


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------


def run_all(
    root: Path,
    manifest: dict,
    graph: dict[str, dict[str, set[str]]],
    members: set[str],
) -> list[str]:
    return (
        check_layers(manifest, graph, members)
        + check_crate_allowlists(manifest, graph, members)
        + check_forbidden_dependencies(manifest, graph, members)
        + check_forbidden_symbols(root, manifest)
        + check_forbidden_patterns(root, manifest)
        + check_confined_symbols(root, manifest)
        + check_call_sites(root, manifest)
    )


def workspace_members(root: Path) -> set[str]:
    raw = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    metadata = json.loads(raw)
    by_id = {p["id"]: p["name"] for p in metadata["packages"]}
    return {by_id[i] for i in metadata["workspace_members"] if i in by_id}


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------


def self_test() -> None:
    _self_test_cfg_test_spans()
    _self_test_layers()
    _self_test_crate_allowlists()
    _self_test_forbidden_dependencies()
    _self_test_source_rules()
    _self_test_staleness()


def _fake_graph(spec: dict[str, dict[str, list[str]]]) -> dict[str, dict[str, set[str]]]:
    return {name: {k: set(v) for k, v in kinds.items()} for name, kinds in spec.items()}


def _self_test_cfg_test_spans() -> None:
    text = (
        "fn production() {}\n"
        "#[cfg(test)]\n"
        "mod tests {\n"
        '    fn helper() { let s = "}"; }\n'
        "}\n"
        "fn after() {}\n"
    )
    spans = cfg_test_spans(text)
    assert spans == [(2, 5)], spans
    kept = [n for n, _ in scannable_lines(text, True)]
    assert kept == [1, 6], kept

    statement = "#[cfg(test)]\nuse foo::bar;\nfn after() {}\n"
    assert cfg_test_spans(statement) == [(1, 2)], cfg_test_spans(statement)

    assert [n for n, _ in scannable_lines("// comment\ncode();\n", False)] == [2]


def _self_test_layers() -> None:
    manifest = {
        "layers": {"order": ["low", "high"], "exempt": ["tool"]},
        "layer": {"low": {"crates": ["a"]}, "high": {"crates": ["b"]}},
    }
    members = {"a", "b", "tool"}

    ok = _fake_graph({"a": {}, "b": {KIND_NORMAL: ["a"]}, "tool": {}})
    assert not check_layers(manifest, ok, members), check_layers(manifest, ok, members)

    upward = _fake_graph({"a": {KIND_NORMAL: ["b"]}, "b": {}, "tool": {}})
    found = check_layers(manifest, upward, members)
    assert any("may only depend on its own layer or a lower one" in f for f in found), found

    # A build script reaching upward is compiled into the real build, so the
    # build kind is part of the production graph the layer order governs.
    build_upward = _fake_graph({"a": {KIND_BUILD: ["b"]}, "b": {}, "tool": {}})
    found = check_layers(manifest, build_upward, members)
    assert any("may only depend on its own layer or a lower one" in f for f in found), found

    # A dev-only back edge is not; several engine crates rely on one.
    dev_upward = _fake_graph({"a": {"dev": ["b"]}, "b": {}, "tool": {}})
    assert not check_layers(manifest, dev_upward, members)

    found = check_layers(manifest, ok, members | {"stray"})
    assert any("is in no layer" in f for f in found), found

    found = check_layers(manifest, ok, {"a", "tool"})
    assert any("not a workspace member" in f for f in found), found


def _self_test_crate_allowlists() -> None:
    manifest = {"crate": {"a": {"workspace_dependencies": ["b"]}}}
    members = {"a", "b", "c"}

    ok = _fake_graph({"a": {KIND_NORMAL: ["b", "serde"]}, "b": {}, "c": {}})
    assert not check_crate_allowlists(manifest, ok, members)

    extra = _fake_graph({"a": {KIND_NORMAL: ["b", "c"]}, "b": {}, "c": {}})
    found = check_crate_allowlists(manifest, extra, members)
    assert any("not in its workspace_dependencies allowlist" in f for f in found), found

    # A dev-only back edge is not a production dependency.
    dev_only = _fake_graph({"a": {KIND_NORMAL: ["b"], "dev": ["c"]}, "b": {}, "c": {}})
    assert not check_crate_allowlists(manifest, dev_only, members)

    stale = _fake_graph({"a": {}, "b": {}, "c": {}})
    found = check_crate_allowlists(manifest, stale, members)
    assert any("keeps describing reality" in f for f in found), found

    found = check_crate_allowlists(manifest, ok, {"b", "c"})
    assert any("not a workspace member" in f for f in found), found


def _self_test_forbidden_dependencies() -> None:
    manifest = {
        "forbidden_dependency": [
            {"name": "r", "crates": ["a"], "kinds": ["normal"], "packages": ["tokio"]},
            {
                "name": "r_all",
                "crates": ["b"],
                "kinds": ["normal", "dev"],
                "packages": ["tokio"],
            },
        ]
    }
    members = {"a", "b"}

    graph = _fake_graph({"a": {"dev": ["tokio"]}, "b": {}})
    assert not check_forbidden_dependencies(manifest, graph, members)

    graph = _fake_graph({"a": {KIND_NORMAL: ["tokio"]}, "b": {}})
    found = check_forbidden_dependencies(manifest, graph, members)
    assert any("forbidden package 'tokio'" in f for f in found), found

    # A dev-only use is a violation for the rule that covers the dev kind.
    graph = _fake_graph({"a": {}, "b": {"dev": ["tokio"]}})
    found = check_forbidden_dependencies(manifest, graph, members)
    assert any("[r_all]" in f for f in found), found

    # A renamed dependency is caught under its real package name.
    graph = _fake_graph({"a": {KIND_NORMAL: ["madsim-tokio", "tokio"]}, "b": {}})
    found = check_forbidden_dependencies(manifest, graph, members)
    assert found, "a renamed dependency must still be matched"

    found = check_forbidden_dependencies(manifest, _fake_graph({"b": {}}), {"b"})
    assert any("no longer guards anything" in f for f in found), found


def _self_test_source_rules() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        src = root / "crates" / "pure" / "src"
        src.mkdir(parents=True)
        (src / "lib.rs").write_text("pub struct Change;\n", encoding="utf-8")
        codec = root / "crates" / "wire" / "src"
        codec.mkdir(parents=True)
        (codec / "lib.rs").write_text("pub struct Frame;\n", encoding="utf-8")
        (codec / "protobuf.rs").write_text("use prost::Message;\n", encoding="utf-8")
        app = root / "crates" / "app" / "src"
        app.mkdir(parents=True)
        (app / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

        symbol_rule = {
            "forbidden_symbol": [
                {
                    "name": "pure",
                    "paths": ["crates/pure/src/**/*.rs"],
                    "symbols": ["tokio::", "std::fs"],
                }
            ]
        }
        assert not check_forbidden_symbols(root, symbol_rule)

        (src / "lib.rs").write_text("fn f() { tokio::spawn(g()); }\n", encoding="utf-8")
        found = check_forbidden_symbols(root, symbol_rule)
        assert any("references forbidden 'tokio::'" in f for f in found), found

        # A whole-line comment is documentation, not a dependency.
        (src / "lib.rs").write_text("/// see tokio::spawn\npub struct Change;\n", encoding="utf-8")
        assert not check_forbidden_symbols(root, symbol_rule)

        # ... but a trailing comment on a code line is still scanned.
        (src / "lib.rs").write_text("fn f() {} // tokio::spawn\n", encoding="utf-8")
        assert check_forbidden_symbols(root, symbol_rule)

        # test_spans = "exclude" drops cfg(test) items, and only those.
        (src / "lib.rs").write_text(
            "pub struct Change;\n#[cfg(test)]\nmod tests {\n    fn f() { tokio::spawn(g()); }\n}\n",
            encoding="utf-8",
        )
        assert check_forbidden_symbols(root, symbol_rule), "included by default"
        excluding = {
            "forbidden_symbol": [
                dict(symbol_rule["forbidden_symbol"][0], test_spans="exclude")
            ]
        }
        assert not check_forbidden_symbols(root, excluding)
        (src / "lib.rs").write_text("fn f() { tokio::spawn(g()); }\n", encoding="utf-8")
        assert check_forbidden_symbols(root, excluding), "production code is still scanned"
        # ... and so does a cfg(test) module moved into its own file, along
        # with anything nested under it -- but not a plain out-of-line module.
        (src / "lib.rs").write_text(
            "pub struct Change;\nmod prod;\n#[cfg(test)]\nmod tests;\n", encoding="utf-8"
        )
        (src / "prod.rs").write_text("pub struct P;\n", encoding="utf-8")
        (src / "tests.rs").write_text(
            "mod helpers;\nfn f() { tokio::spawn(g()); }\n", encoding="utf-8"
        )
        (src / "tests").mkdir()
        (src / "tests" / "helpers.rs").write_text("fn h() { tokio::spawn(g()); }\n", encoding="utf-8")
        assert not check_forbidden_symbols(root, excluding)
        assert check_forbidden_symbols(root, symbol_rule), "included by default"
        (src / "prod.rs").write_text("fn f() { tokio::spawn(g()); }\n", encoding="utf-8")
        assert check_forbidden_symbols(root, excluding), "out-of-line production module"
        (src / "prod.rs").unlink()
        (src / "tests.rs").unlink()
        (src / "tests" / "helpers.rs").unlink()
        (src / "tests").rmdir()
        (src / "lib.rs").write_text("fn f() { tokio::spawn(g()); }\n", encoding="utf-8")
        (src / "lib.rs").write_text("pub struct Change;\n", encoding="utf-8")

        pattern_rule = {
            "forbidden_pattern": [
                {
                    "name": "no_hand_rolled_framing",
                    "paths": ["crates/app/src/**/*.rs"],
                    "patterns": [r"\bfn\s+(encode|decode)\s*\("],
                }
            ]
        }
        assert not check_forbidden_patterns(root, pattern_rule)
        (app / "main.rs").write_text("fn encode(buf: &mut Vec<u8>) {}\n", encoding="utf-8")
        found = check_forbidden_patterns(root, pattern_rule)
        assert any("no_hand_rolled_framing" in f for f in found), found
        (app / "main.rs").write_text("fn decode(bytes: &[u8]) {}\n", encoding="utf-8")
        assert check_forbidden_patterns(root, pattern_rule)

        guarded = {
            "forbidden_pattern": [
                {
                    "name": "public_transaction",
                    "paths": ["crates/app/src/**/*.rs"],
                    "patterns": [r"rusqlite::Transaction"],
                    "require_lines_containing": ["pub fn"],
                }
            ]
        }
        (app / "main.rs").write_text(
            "fn private(t: &rusqlite::Transaction) {}\n", encoding="utf-8"
        )
        assert not check_forbidden_patterns(root, guarded), "private signatures are fine"
        (app / "main.rs").write_text(
            "pub fn leaked(t: &rusqlite::Transaction) {}\n", encoding="utf-8"
        )
        assert check_forbidden_patterns(root, guarded)

        skipping = {
            "forbidden_pattern": [
                {
                    "name": "no_open",
                    "paths": ["crates/app/src/**/*.rs"],
                    "patterns": [r"fn open\s*\("],
                    "skip_lines_containing": ["SqliteConnectionManager"],
                }
            ]
        }
        (app / "main.rs").write_text(
            "fn open(m: SqliteConnectionManager) {}\n", encoding="utf-8"
        )
        assert not check_forbidden_patterns(root, skipping)
        (app / "main.rs").write_text("fn open(path: &Path) {}\n", encoding="utf-8")
        assert check_forbidden_patterns(root, skipping)
        (app / "main.rs").write_text("fn main() {}\n", encoding="utf-8")

        confinement = {
            "confined_symbol": [
                {
                    "name": "protobuf_in_codec_only",
                    "paths": ["crates/wire/src/**/*.rs"],
                    "allowed_paths": ["crates/wire/src/protobuf.rs"],
                    "symbols": ["prost::"],
                }
            ]
        }
        assert not check_confined_symbols(root, confinement)
        (codec / "lib.rs").write_text("use prost::Message;\n", encoding="utf-8")
        found = check_confined_symbols(root, confinement)
        assert any("outside its confinement" in f for f in found), found
        (codec / "lib.rs").write_text("pub struct Frame;\n", encoding="utf-8")

        call_rule = {
            "call_site": [
                {
                    "name": "one_composition_root",
                    "paths": ["crates/**/*.rs"],
                    "patterns": [r"Session::(new|new_with_deps)\s*\("],
                    "allowed_paths": ["crates/app/src/**/*.rs"],
                    "skip_test_paths": True,
                    "test_spans": "exclude",
                }
            ]
        }
        (app / "main.rs").write_text("fn boot() { Session::new(a); }\n", encoding="utf-8")
        assert not check_call_sites(root, call_rule)

        (src / "lib.rs").write_text("fn rogue() { Session::new_with_deps(a); }\n", encoding="utf-8")
        found = check_call_sites(root, call_rule)
        assert any("not an allowed call site" in f for f in found), found

        # Inside a cfg(test) item, and under tests/, the call is exempt.
        (src / "lib.rs").write_text(
            "pub struct X;\n#[cfg(test)]\nmod t { fn f() { Session::new(a); } }\n",
            encoding="utf-8",
        )
        assert not check_call_sites(root, call_rule)

        # ... but production code that merely SITS AFTER a cfg(test) item is
        # not exempt: the exemption is the item's brace-matched span, not
        # everything past the first attribute in the file.
        (src / "lib.rs").write_text(
            "pub struct X;\n"
            "#[cfg(test)]\n"
            "mod t { fn f() { Session::new(a); } }\n"
            "fn rogue() { Session::new_with_deps(a); }\n",
            encoding="utf-8",
        )
        found = check_call_sites(root, call_rule)
        assert any(":4 is not an allowed call site" in f for f in found), found
        assert not any(":3 is not an allowed call site" in f for f in found), found
        (src / "lib.rs").write_text("pub struct X;\n", encoding="utf-8")
        tests_dir = root / "crates" / "pure" / "tests"
        tests_dir.mkdir(parents=True, exist_ok=True)
        (tests_dir / "it.rs").write_text("fn f() { Session::new(a); }\n", encoding="utf-8")
        assert not check_call_sites(root, call_rule)
        (tests_dir / "it.rs").unlink()

        # An allowed item exempts that one function, not its file.
        item_rule = {
            "call_site": [
                dict(
                    call_rule["call_site"][0],
                    allowed_items=[
                        {"path": "crates/pure/src/lib.rs", "fn": "seam", "reason": "sim"}
                    ],
                )
            ]
        }
        (src / "lib.rs").write_text(
            "fn seam(k: [u8; 32]) {\n    Session::new(a);\n}\n"
            "fn rogue() { Session::new(a); }\n",
            encoding="utf-8",
        )
        found = check_call_sites(root, item_rule)
        assert any(":4 is not an allowed call site" in f for f in found), found
        assert not any(":2 is not an allowed call site" in f for f in found), found
        (src / "lib.rs").write_text("fn other() {}\n", encoding="utf-8")
        found = check_call_sites(root, item_rule)
        assert any("no fn 'seam'" in f for f in found), found
        item_rule["call_site"][0]["allowed_items"][0]["reason"] = " "
        (src / "lib.rs").write_text("fn seam() {}\n", encoding="utf-8")
        found = check_call_sites(root, item_rule)
        assert any("gives no reason" in f for f in found), found
        (src / "lib.rs").write_text("pub struct X;\n", encoding="utf-8")

        # A guard whose symbol has vanished must fail, not pass quietly.
        (app / "main.rs").write_text("fn boot() {}\n", encoding="utf-8")
        found = check_call_sites(root, call_rule)
        assert any("no longer exists" in f for f in found), found


def _self_test_staleness() -> None:
    kinds = (
        ("forbidden_symbol", check_forbidden_symbols),
        ("forbidden_pattern", check_forbidden_patterns),
        ("confined_symbol", check_confined_symbols),
        ("call_site", check_call_sites),
    )

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "crates").mkdir()
        for kind, checker in kinds:
            rule = {
                "name": "gone",
                "paths": ["crates/removed/src/**/*.rs"],
                "symbols": ["tokio::"],
                "patterns": ["tokio::"],
                "allowed_paths": ["crates/removed/src/lib.rs"],
            }
            found = checker(root, {kind: [rule]})
            assert any("no longer guards anything" in f for f in found), (kind, found)

            empty = dict(rule, paths=[])
            found = checker(root, {kind: [empty]})
            assert any("list is empty" in f for f in found), (kind, found)

    # A rule that names SEVERAL literal files must fail when ONE of them is
    # renamed away, not only when every last one is gone. The surviving
    # entries keep the rule resolving to a non-empty file set, so a per-rule
    # check would pass here while the renamed file silently stops being
    # guarded.
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        src = root / "crates" / "cli" / "src"
        src.mkdir(parents=True)
        (src / "kept.rs").write_text("pub struct A;\n", encoding="utf-8")
        (src / "also_kept.rs").write_text("pub struct B;\n", encoding="utf-8")

        for kind, checker in kinds:
            rule = {
                "name": "half_rotted",
                "paths": [
                    "crates/cli/src/kept.rs",
                    "crates/cli/src/renamed_away.rs",
                    "crates/cli/src/also_kept.rs",
                ],
                "symbols": ["tokio::"],
                "patterns": ["tokio::"],
                "allowed_paths": ["crates/cli/src/kept.rs"],
            }
            found = checker(root, {kind: [rule]})
            assert any(
                "'crates/cli/src/renamed_away.rs' matches no file" in f for f in found
            ), (kind, found)
            assert not any("kept.rs' matches no file" in f for f in found), (kind, found)

        # The same guarantee on the allowed_paths side of a confinement and
        # of a call-site allowlist: a confinement target that is renamed away
        # stops confining anything.
        allowed_rule = {
            "name": "target_renamed",
            "paths": ["crates/cli/src/*.rs"],
            "symbols": ["tokio::"],
            "patterns": ["tokio::"],
            "allowed_paths": [
                "crates/cli/src/kept.rs",
                "crates/cli/src/renamed_away.rs",
            ],
        }
        for kind, checker in (
            ("confined_symbol", check_confined_symbols),
            ("call_site", check_call_sites),
        ):
            found = checker(root, {kind: [allowed_rule]})
            assert any(
                "allowed_paths entry 'crates/cli/src/renamed_away.rs' matches no file" in f
                for f in found
            ), (kind, found)


# --------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("architecture checker self-test passed")
        return 0

    manifest = tomllib.loads(args.manifest.read_text(encoding="utf-8"))
    graph = workspace_graph(ROOT)
    members = workspace_members(ROOT)

    failures = run_all(ROOT, manifest, graph, members)
    if failures:
        print("architecture violations:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        print(
            f"\n{len(failures)} violation(s). See .config/architecture.toml for the rule each "
            "one names and the reason it exists.",
            file=sys.stderr,
        )
        return 1

    layers = len(manifest["layers"]["order"])
    exempt = set(manifest["layers"].get("exempt", []))
    layered = len(members - exempt)
    rules = sum(
        len(manifest.get(kind, []))
        for kind in (
            "forbidden_dependency",
            "forbidden_symbol",
            "forbidden_pattern",
            "confined_symbol",
            "call_site",
        )
    ) + len(manifest.get("crate", {}))
    print(
        f"architecture check passed: the layer model over {layered} crates in "
        f"{layers} layers ({len(members & exempt)} exempt), plus {rules} further rules"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
