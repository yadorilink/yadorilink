#!/usr/bin/env python3
"""Keep the engine free of the process environment.

An embedded host (the iOS app) runs one or more engines inside its own process. A
process-global environment read is wrong there: two engines would share it and the host has no
reason to own the variables a desktop daemon reads. So every setting the engine honours is
handed to it explicitly (`EngineConfig`, `EngineTuning`, `CredentialConfig`,
`CredentialSettings`), and the desktop maps its `YADORILINK_*` variables onto those once, at the
command line or the daemon binary's composition root.

This guard scans every library source under `crates/*/src` for a runtime environment read
(`env::var`, `env::var_os`, `env::vars`, `Env::from_process`, libc `getenv`) and fails when one appears in a
file that is not in `ALLOWED` with a reason. Binary entry points (`src/main.rs`, `src/bin/`), code under
`#[cfg(test)]`, modules a parent declares `#[cfg(test)] mod x;`, integration tests, benches and
examples are not scanned. Every reading function of `std::env` counts (`var`, `var_os`, `vars`,
`vars_os`, `args`, `args_os`, `current_dir`, `current_exe`, `temp_dir`, `home_dir`), as do aliased
imports (`use std::env as e`, `use std::env::{self as e}`, `use std::{env as e}`), name imports
(`use std::env::var`) and glob imports (`use std::env::*`).
Compile-time `option_env!` is not a process read and is not matched.

An `ALLOWED` entry that no longer reads the environment fails too, so the list only shrinks.
A new read belongs in an entry-point file; if it truly cannot be moved there, add the file with
the reason it is not engine behaviour.

The host crates (`yadorilink-embedded-host`, `yadorilink-mobile-ffi`) may not even name the
environment mappings (`from_env`, `from_process`, `process_dir`, ...): they are given settings.

This is a text scan with brace matching, not a Rust parser (same class of tool as
`check-architecture.py`). Known limits, out of scope: `std::env` re-exported or wrapped by another
crate (a dependency's own environment reads are not seen), macro-generated reads, and reads inside
`cfg(test)` / `cfg(feature = "test-support")` regions, which are blanked on purpose.
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

READ_NAMES = (
    "var|var_os|vars|vars_os|args|args_os|current_dir|current_exe|temp_dir|home_dir"
)
# `getenv` (libc, or a `extern "C"` declaration) reads the C environment directly.
ENV_READ = re.compile(
    rf"\benv::(?:{READ_NAMES})\b|\bEnv::from_process\b|\b(?:secure_)?getenv\b"
)
# `use std::env as e;`, `use std::{env as e}` and `use std::env::{self as e}` make `e::var(..)` a
# read; importing a reading function by name hides the `env::` prefix, so the import itself is
# reported, as is a glob import of `std::env`.
ENV_ALIAS = re.compile(
    r"\buse\s+(?:::)?std::(?:[^;]*?\{[^;]*?)?\benv\s+as\s+(\w+)"
    r"|\buse\s+(?:::)?std::env::\{[^};]*?\bself\s+as\s+(\w+)"
    r"|\buse\s+(?:::)?std::\{[^;]*?\benv::\{[^};]*?\bself\s+as\s+(\w+)"
)
ENV_NAME_IMPORT = re.compile(
    rf"\buse\s+(?:::)?std::env::(?:(?:{READ_NAMES})\b|\*"
    rf"|\{{[^}}]*(?:\b(?:{READ_NAMES})\b|\*)[^}}]*\}})"
    r"|\buse\s+(?:::)?std::\{[^;]*?\benv::(?:\*|\{[^};]*\*[^};]*\})"
    rf"|\buse\s+(?:::)?std::\{{[^;]*?\benv::\{{[^}};]*\b(?:{READ_NAMES})\b"
)

# Whole crates whose process environment is their configuration: binaries and desktop-only
# components that the embedded host does not link.
ALLOWED_CRATES = {
    "yadorilink-cli": "the command line binary: its process environment is its configuration",
    "yadorilink-shell-ext-windows": "Windows shell extension and cfapi host: Windows-only desktop processes",
    "yadorilink-windows-provider-policy": "Windows provider host: Windows-only desktop component",
}

# Whole files that may read the environment, with the reason.
ALLOWED = {
    "crates/yadorilink-daemon/src/app.rs": (
        "the daemon's composition root: maps the YADORILINK_* variables once into DaemonConfig "
        "and EngineTuning, and arms the process diagnostics"
    ),
    "crates/yadorilink-fs-platform/src/state_dir.rs": (
        "the placement resolver (Env::from_process); engines take their directories explicitly "
        "(check-embedded-host-surface.py keeps daemon code off it)"
    ),
}

# Single functions that may read the environment: entry-point mappings and desktop-only
# operations living in a library file that also holds engine-reachable code.
ALLOWED_FUNCTIONS = {
    "crates/yadorilink-fapi-client/src/store/mod.rs": {
        "from_env": "Backend::from_env, the environment mapping of the entry points; an engine is given a Backend",
    },
    "crates/yadorilink-daemon/src/update/install_source.rs": {
        "running_exe": (
            "the desktop daemon's own install location (process-model: identity and updater); "
            "the embedded host does not run these"
        ),
    },
    "crates/yadorilink-transport/src/key_secret_store.rs": {
        "from_env": "KeyMirror::from_env, the environment mapping of the entry points; an engine is given a KeyMirror",
    },
    "crates/yadorilink-client-core/src/coordination/credential_store.rs": {
        "from_env": (
            "CredentialSettings::from_env, the one environment mapping of the client layer; the "
            "embedded host builds CredentialSettings itself"
        ),
    },
    "crates/yadorilink-client-core/src/coordination/device_config.rs": {
        "control_socket_path": "the desktop process's control socket path (CLI and desktop UI)",
    },
    "crates/yadorilink-client-core/src/facade.rs": {
        "desktop_device_name": "desktop UI: prefill of the device name; an embedded host gives host_name",
    },
    "crates/yadorilink-client-core/src/facade/folders.rs": {
        "default_folder": "desktop UI: the default folder under HOME",
    },
    "crates/yadorilink-client-core/src/daemon/control.rs": {
        "local_descriptor": "desktop CLI: the running program's own path (current_exe) for `doctor`",
    },
    "crates/yadorilink-client-core/src/ops/daemon.rs": {
        "launch_steps": "desktop daemon service control (Windows SystemRoot)",
        "start_daemon_with": "desktop CLI: the CLI's own path (current_exe) decides the launch owner",
        "daemon_binary_path": "desktop CLI: the daemon binary beside the CLI (current_exe)",
    },
    "crates/yadorilink-client-core/src/ops/handoff.rs": {
        "running_from_cli_install": "desktop install handoff: the running program's own path (current_exe)",
        "home": "desktop install handoff: the user's home",
        "context": "desktop install handoff: the process placement environment and SystemRoot",
    },
    "crates/yadorilink-client-core/src/ops/links.rs": {
        "run_link_preflight": "desktop command-line preflight: the user's home directory",
    },
}

# The host crates may not reach the environment mappings at all.
HOST_CRATES = ["yadorilink-embedded-host", "yadorilink-mobile-ffi"]
HOST_FORBIDDEN = re.compile(
    r"\b(?:from_env|from_process|process_dir|process_override|credential_settings_from_env)\b"
    r"|\bstate_dir::(?:state_dir|resolve)\b|\bdevice_config::config_dir\b"
)

CFG_TEST_ATTR = re.compile(
    r"#\[cfg\(\s*(?:test|any\(\s*test\s*,\s*feature\s*=\s*\"test-support\"\s*\))\s*\)\]"
)
CHAR_LITERAL = re.compile(r"'(?:\\[^']+|[^\\'])'")
INNER_CFG_TEST = re.compile(r"\A(?:\s*//[^\n]*\n)*\s*#!\[cfg\(\s*test\s*\)\]")


def skip_string_or_comment(text: str, j: int) -> int:
    """Index just past a string literal or comment starting at `j`, else `j`."""
    n = len(text)
    if text.startswith("//", j):
        end = text.find("\n", j)
        return n if end == -1 else end
    if text.startswith("/*", j):
        end = text.find("*/", j + 2)
        return n if end == -1 else end + 2
    if text[j] == "'":
        m = CHAR_LITERAL.match(text, j)
        return m.end() if m else j
    if text[j] == '"':
        j += 1
        while j < n and text[j] != '"':
            j += 2 if text[j] == "\\" else 1
        return min(j + 1, n)
    return j


def cfg_test_spans(text: str) -> list[tuple[int, int]]:
    """Character spans of every `#[cfg(test)] <item> { ... }` (brace matched)."""
    spans: list[tuple[int, int]] = []
    i = 0
    while True:
        m = CFG_TEST_ATTR.search(text, i)
        if not m:
            return spans
        # The item the attribute is on: up to its `{` block or its `;`.
        j = m.end()
        n = len(text)
        while j < n and text[j] not in "{;":
            nxt = skip_string_or_comment(text, j)
            j = nxt if nxt != j else j + 1
        if j >= n:
            return spans
        if text[j] == ";":
            spans.append((m.start(), j + 1))
            i = j + 1
            continue
        depth = 0
        while j < n:
            nxt = skip_string_or_comment(text, j)
            if nxt != j:
                j = nxt
                continue
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        spans.append((m.start(), min(j, n)))
        i = j


def runtime_text(text: str) -> str:
    """`text` with every cfg(test) span and every comment blanked, line structure kept."""
    chars = list(text)
    for start, end in cfg_test_spans(text):
        for k in range(start, end):
            if chars[k] != "\n":
                chars[k] = " "
    out = "".join(chars)
    return re.sub(r"//[^\n]*", lambda m: " " * len(m.group(0)), out)


FN_ITEM = re.compile(r"\bfn\s+(\w+)")


def fn_spans(text: str) -> list[tuple[str, int, int]]:
    """(name, start, end) character spans of every `fn` item that has a body (brace matched)."""
    spans: list[tuple[str, int, int]] = []
    n = len(text)
    for m in FN_ITEM.finditer(text):
        j = m.end()
        while j < n and text[j] not in "{;":
            nxt = skip_string_or_comment(text, j)
            j = nxt if nxt != j else j + 1
        if j >= n or text[j] == ";":
            continue
        start, depth = j, 0
        while j < n:
            nxt = skip_string_or_comment(text, j)
            if nxt != j:
                j = nxt
                continue
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        spans.append((m.group(1), start, min(j, n)))
    return spans


def read_sites(text: str) -> list[tuple[int, int, str | None]]:
    """(line, offset, innermost enclosing fn name) of every environment read in `text`."""
    patterns = [ENV_READ]
    for groups in ENV_ALIAS.findall(text):
        for alias in filter(None, groups):
            patterns.append(re.compile(rf"\b{re.escape(alias)}::(?:{READ_NAMES})\b"))
    spans = fn_spans(text)
    positions = set()
    for pattern in [*patterns, ENV_NAME_IMPORT]:
        positions.update(m.start() for m in pattern.finditer(text))
    sites: list[tuple[int, int, str | None]] = []
    seen_lines: set = set()
    for pos in sorted(positions):
        number = text.count("\n", 0, pos) + 1
        inner = [sp for sp in spans if sp[1] <= pos < sp[2]]
        name = min(inner, key=lambda sp: sp[2] - sp[1])[0] if inner else None
        if (number, name) in seen_lines:
            continue
        seen_lines.add((number, name))
        sites.append((number, pos, name))
    return sites


def test_only_files(src: Path) -> set[Path]:
    """Files compiled only under cfg(test): `#![cfg(test)]` files and `#[cfg(test)] mod x;`."""
    found: set[Path] = set()
    for path in src.rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        if INNER_CFG_TEST.match(text):
            found.add(path)
        base = path.parent if path.name in ("lib.rs", "main.rs", "mod.rs") else path.with_suffix("")
        for m in re.finditer(
            r"#\[cfg\(\s*test\s*\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;",
            text,
        ):
            for candidate in (base / f"{m.group(1)}.rs", base / m.group(1) / "mod.rs"):
                if candidate.is_file():
                    found.add(candidate)
                    # A test-only module's children are test-only too.
                    found.update((candidate.with_suffix("")).rglob("*.rs"))
    return found


def library_files(root: Path):
    for src in sorted((root / "crates").glob("*/src")):
        crate = src.parent.name
        excluded = test_only_cache(src)
        for path in sorted(src.rglob("*.rs")):
            if path in excluded or path.name.endswith(("tests.rs", "_tests.rs", "test_support.rs")):
                continue
            inside = path.relative_to(src).as_posix()
            if inside == "main.rs" or inside.startswith("bin/"):
                continue  # a binary's entry point: its process environment is its configuration
            yield crate, path


_cache: dict[Path, set[Path]] = {}


def test_only_cache(src: Path) -> set[Path]:
    if src not in _cache:
        _cache[src] = test_only_files(src)
    return _cache[src]


def check_tree(root: Path, allowed=None, allowed_functions=None, allowed_crates=None) -> list[str]:
    allowed = ALLOWED if allowed is None else allowed
    allowed_functions = ALLOWED_FUNCTIONS if allowed_functions is None else allowed_functions
    allowed_crates = ALLOWED_CRATES if allowed_crates is None else allowed_crates
    _cache.clear()
    errors: list[str] = []
    reading: set[str] = set()
    reading_fns: set[tuple[str, str]] = set()
    for crate, path in library_files(root):
        rel = path.relative_to(root).as_posix()
        text = runtime_text(path.read_text(encoding="utf-8"))
        sites = read_sites(text)
        if sites:
            reading.add(rel)
        for number, _offset, name in sites:
            if name is not None:
                reading_fns.add((rel, name))
            if rel in allowed or crate in allowed_crates or name in allowed_functions.get(rel, {}):
                continue
            errors.append(
                f"{rel}:{number}: reads the process environment in library code"
                f"{f' (fn {name})' if name else ''}; an embedded host must not depend on it. "
                "Take the value as an explicit setting (EngineTuning, EngineConfig, "
                "CredentialSettings) and map the variable at the entry point, or add the file or "
                "function to ALLOWED/ALLOWED_FUNCTIONS in check-engine-env-reads.py with the reason"
            )
        if crate in HOST_CRATES:
            for n, line in enumerate(text.splitlines(), 1):
                if HOST_FORBIDDEN.search(line):
                    errors.append(
                        f"{rel}:{n}: the host crate reaches an environment mapping; it is given "
                        "its settings by the host"
                    )
    for rel in sorted(allowed):
        if not (root / rel).is_file():
            errors.append(f"ALLOWED names {rel}, which does not exist; remove the entry")
        elif rel not in reading:
            errors.append(f"ALLOWED names {rel}, which no longer reads the environment; remove the entry")
    for rel, functions in sorted(allowed_functions.items()):
        if not (root / rel).is_file():
            errors.append(f"ALLOWED_FUNCTIONS names {rel}, which does not exist; remove the entry")
            continue
        for name in sorted(functions):
            if (rel, name) not in reading_fns:
                errors.append(
                    f"ALLOWED_FUNCTIONS names {rel} fn {name}, which no longer reads the "
                    "environment; remove the entry"
                )
    for crate in sorted(allowed_crates):
        if not (root / "crates" / crate / "src").is_dir():
            errors.append(f"ALLOWED_CRATES names {crate}, which does not exist; remove the entry")
    return errors


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def self_test() -> int:
    errors = check_tree(ROOT)
    if errors:
        print("self-test needs a clean tree:", *errors, sep="\n  ")
        return 1

    def expect(label, tree, wanted, files=None, functions=None, crates=None) -> bool:
        found = check_tree(tree, files or {}, functions or {}, crates or {})
        ok = (wanted is None and not found) or (wanted is not None and any(wanted in e for e in found))
        if not ok:
            print(f"self-test: {label}: expected {wanted!r}, got {found}")
        return ok

    reads = 'pub fn f() -> Option<String> { std::env::var("X").ok() }\n'
    rel = "crates/yadorilink-fake/src/lib.rs"
    with tempfile.TemporaryDirectory() as tmp:
        t = Path(tmp)
        lib = t / rel
        good = True
        write(lib, reads)
        good &= expect("a new read", t, "lib.rs:1")
        # Every spelling of a read is reported.
        for label, body in [
            ("var_os", 'pub fn f() { let _ = std::env::var_os("X"); }'),
            ("vars", "pub fn f() { for _ in std::env::vars() {} }"),
            ("vars_os", "pub fn f() { for _ in std::env::vars_os() {} }"),
            ("args", "pub fn f() { let _ = std::env::args(); }"),
            ("temp_dir", "pub fn f() { let _ = std::env::temp_dir(); }"),
            ("from_process", "pub fn f() { let _ = Env::from_process(); }"),
            ("aliased module", "use std::env as e;\npub fn f() { let _ = e::var(\"X\"); }"),
            ("name import", "use std::env::var;\npub fn f() { let _ = var(\"X\"); }"),
            ("grouped name import", "use std::env::{var_os, current_dir};\npub fn f() {}"),
            ("args_os", "pub fn f() { let _ = std::env::args_os(); }"),
            ("current_dir", "pub fn f() { let _ = std::env::current_dir(); }"),
            ("current_exe", "pub fn f() { let _ = std::env::current_exe(); }"),
            ("home_dir", "pub fn f() { let _ = std::env::home_dir(); }"),
            ("current_dir name import", "use std::env::current_dir;\npub fn f() {}"),
            ("brace self alias", "use std::env::{self as e};\npub fn f() { let _ = e::var(\"X\"); }"),
            (
                "brace self alias with others",
                "use std::env::{self as e, temp_dir_x};\npub fn f() { let _ = e::current_dir(); }",
            ),
            ("nested alias", "use std::{env as e, fs};\npub fn f() { let _ = e::vars(); }"),
            ("glob import", "use std::env::*;\npub fn f() { let _ = var(\"X\"); }"),
            ("brace glob import", "use std::env::{self, *};\npub fn f() {}"),
            ("nested glob import", "use std::{env::*, fs};\npub fn f() {}"),
            ("nested name import", "use std::{env::var, fs};\npub fn f() {}"),
            (
                "nested brace self alias",
                "use std::{env::{self as e}, fs};\npub fn f() { let _ = e::var(\"X\"); }",
            ),
            (
                "multi-line nested brace self alias",
                "use std::{\n    env::{\n        self as e,\n    },\n    fs,\n};\npub fn f() { let _ = e::vars(); }",
            ),
            ("nested brace name import", "use std::{env::{var, args}, fs};\npub fn f() {}"),
            ("libc getenv", "pub fn f() { unsafe { libc::getenv(std::ptr::null()); } }"),
            ("bare getenv", "extern \"C\" { fn getenv(k: *const u8) -> *const u8; }"),
        ]:
            write(lib, body + "\n")
            good &= expect(label, t, "reads the process environment")
        # Allow-listed with a reason, it passes; a stale or missing entry fails.
        write(lib, reads)
        good &= expect("allow-listed file", t, None, files={rel: "an entry point"})
        good &= expect("allow-listed function", t, None, functions={rel: {"f": "an entry point"}})
        write(lib, reads + 'pub fn g() { let _ = std::env::var("Y"); }\n')
        good &= expect("another function in an allowed file", t, "(fn g)", functions={rel: {"f": "x"}})
        write(lib, "pub fn f() {}\n")
        good &= expect("stale file entry", t, "no longer reads", files={rel: "x"})
        good &= expect("stale function entry", t, "fn f, which no longer reads", functions={rel: {"f": "x"}})
        good &= expect("a missing file", t, "does not exist", files={"crates/yadorilink-fake/src/gone.rs": "x"})
        # Test code, comments and compile-time reads are not reads.
        write(
            lib,
            "// std::env::var(\"X\")\n"
            "pub const A: Option<&str> = option_env!(\"X\");\n"
            "#[cfg(test)]\nmod tests { fn t() { let _ = std::env::var(\"X\"); } }\n"
            "pub fn f() {\n    #[cfg(any(test, feature = \"test-support\"))]\n"
            "    let _ = { std::env::var(\"X\").ok() };\n}\n",
        )
        good &= expect("test-only and comments", t, None)
        # A module the parent declares cfg(test) is test code.
        write(lib, "#[cfg(test)]\nmod harness;\n")
        write(t / "crates/yadorilink-fake/src/harness.rs", reads)
        good &= expect("cfg(test) module file", t, None)
        (t / "crates/yadorilink-fake/src/harness.rs").unlink()
        # Binary entry points are not library code.
        write(t / "crates/yadorilink-fake/src/main.rs", reads)
        write(t / "crates/yadorilink-fake/src/bin/tool.rs", reads)
        good &= expect("entry points", t, None)
        # A whole allowed crate may read.
        write(t / "crates/yadorilink-bin/src/lib.rs", reads)
        write(lib, "pub fn f() {}\n")
        good &= expect("crate not allowed", t, "yadorilink-bin/src/lib.rs:1")
        good &= expect("crate allowed", t, None, crates={"yadorilink-bin": "a binary"})
        (t / "crates/yadorilink-bin/src/lib.rs").unlink()
        # The host crates may not reach the environment mappings.
        write(
            t / "crates/yadorilink-embedded-host/src/lib.rs",
            "pub fn f() { let _ = CredentialSettings::from_env(dir); }\n",
        )
        good &= expect("host mapping", t, "host crate reaches an environment mapping")
        if not good:
            return 1
    print("self-test ok")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    if parser.parse_args().self_test:
        return self_test()
    errors = check_tree(ROOT)
    for e in errors:
        print(f"engine env reads: {e}")
    if errors:
        return 1
    print("engine env reads ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
