#!/usr/bin/env python3
"""Require a cutover note whenever a protocol-generation constant changes.

Devices of one account must run matching versions, so changing any of the
constants below is a coordinated cutover, not a routine edit. CUTOVER.md keeps
one line per generation:

    - NAME = VALUE: what changed and what users must do

The check reads each constant's current value from source and fails unless
CUTOVER.md has an entry for exactly that value. A bump therefore cannot merge
without the author writing the note.

CONTROL_PROTOCOL_VERSION is exempt from the per-value line before 1.0: it is
the local app<->daemon contract, the two ship in one package, so a bump is never
a cross-device cutover. It is still read from source (a removed or duplicated
constant fails) and CUTOVER.md must carry the standing line `- CONTROL_PROTOCOL_VERSION: local app<->daemon only; not a cutover before 1.0`
instead. Drop the exemption at 1.0, or earlier if the control socket ever
becomes reachable across devices. Run with no arguments to check the tree,
or `--self-test` to exercise the check against synthetic fixtures.

It also fails on a repo-relative markdown link in CUTOVER.md, docs/ or oss-public/
that does not resolve. Published files (CUTOVER.md and everything under oss-public/)
are judged in the projected public layout, built from .public-tree.toml: the
overlay copies `oss-public/` onto the root, and the snapshot exclusions apply to the
rest, so a link to an excluded file fails. docs/ is not published and is judged in
the source tree. Links in code (inline, fenced, indented) are ignored; reference
definitions, nested brackets, `<angle>` and percent-encoded targets, queries, a leading
`/` (repo root) and escapes are handled; matching is case-sensitive and a target
that leaves the repository fails.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
import tomllib
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NOTES = "docs/CUTOVER.md"

# constant name -> source file (relative to the repo root)
GATES = {
    "PROTOCOL_VERSION": "crates/yadorilink-sync-protocol/src/wire.rs",
    "RPC_VERSION": "crates/yadorilink-peer-session/src/service_rpc.rs",
    "CONTROL_PROTOCOL_VERSION": "crates/yadorilink-ipc-proto/src/lib.rs",
    "SCHEMA_VERSION": "crates/yadorilink-sqlite-runtime/src/schema.rs",
}

# Gates whose value is read from source but needs no per-value note.
EXEMPT = {"CONTROL_PROTOCOL_VERSION"}
STANDING_LINE = "- CONTROL_PROTOCOL_VERSION: local app<->daemon only; not a cutover before 1.0"

NOTE_LINE = re.compile(r"^\s*[-*]\s+([A-Z_]+)\s*=\s*(\d+)\s*:\s*(\S.*)$")


def current_value(root: Path, name: str, rel: str) -> int:
    pattern = re.compile(rf"\bconst\s+{name}\s*:\s*[a-z0-9]+\s*=\s*(\d+)\s*;")
    matches = pattern.findall((root / rel).read_text(encoding="utf-8"))
    if len(matches) != 1:
        raise ValueError(f"{rel}: expected exactly one `const {name}`, found {len(matches)}")
    return int(matches[0])


def noted(root: Path) -> set[tuple[str, int]]:
    path = root / NOTES
    if not path.is_file():
        return set()
    found = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        m = NOTE_LINE.match(line)
        if m:
            found.add((m.group(1), int(m.group(2))))
    return found


def standing_present(root: Path) -> bool:
    path = root / NOTES
    if not path.is_file():
        return False
    return any(line.strip() == STANDING_LINE for line in path.read_text(encoding="utf-8").splitlines())


OVERLAY = "oss-public"
PROJECTION_CONFIG = ".public-tree.toml"
EXTERNAL = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|#|//)")
FENCE_OPEN = re.compile(r"^( *)(`{3,}|~{3,})(.*)$")
LIST_MARKER = re.compile(r"^ {0,3}(?:[-*+]|\d{1,9}[.)])(?:\s|$)")
REF_DEFINITION = re.compile(
    r"^ {0,3}\[((?:[^\]\\\n]|\\.)+)\]:[ \t]*\n?[ \t]*(<(?:[^<>\n\\]|\\.)*>|[^\s<]\S*)",
    re.MULTILINE,
)


def link_files(root: Path) -> list[Path]:
    """Markdown files whose links are checked."""
    files = []  # docs/ scan includes the published cutover note
    for directory in ("docs", OVERLAY):
        base = root / directory
        if base.is_dir():
            files += sorted(base.rglob("*.md"))
    return files


def mask_code_blocks(text: str) -> str:
    """Blank out fenced and indented code blocks, keeping the line count."""
    out = []
    fence: tuple[str, int, int] | None = None
    previous_blank = True
    in_list = False
    in_indented = False
    for line in text.splitlines():
        if fence is not None:
            stripped = line.strip()
            if (
                (len(line) - len(line.lstrip(" ")) <= 3 or fence[2] >= 4)
                and stripped
                and set(stripped) == {fence[0]}
                and len(stripped) >= fence[1]
            ):
                fence = None
            out.append("")
            continue
        opened = FENCE_OPEN.match(line)
        indent = len(opened.group(1)) if opened else 0
        # Four or more spaces is a fence only inside a list item; elsewhere it is indented code.
        if (
            opened
            and (indent <= 3 or in_list)
            and not (opened.group(2)[0] == "`" and "`" in opened.group(3))
        ):
            fence = (opened.group(2)[0], len(opened.group(2)), indent)
            out.append("")
            previous_blank = False
            continue
        blank = not line.strip()
        indented = line.startswith("    ") or line.startswith("\t")
        if indented and not blank and (previous_blank or in_indented) and not in_list:
            in_indented = True
            out.append("")
            previous_blank = False
            continue
        if not blank:
            in_indented = False
            if LIST_MARKER.match(line):
                in_list = True
            elif not indented and previous_blank:
                in_list = False
        out.append(line)
        previous_blank = blank
    return "\n".join(out)


def mask_inline_code(paragraph: str) -> str:
    """Replace inline code spans with spaces; a backslash escapes a backtick outside a span."""
    chars = list(paragraph)
    i = 0
    n = len(chars)
    while i < n:
        c = chars[i]
        if c == "\\":
            i += 2
            continue
        if c != "`":
            i += 1
            continue
        j = i
        while j < n and chars[j] == "`":
            j += 1
        width = j - i
        k = j
        close = -1
        while k < n:
            if chars[k] != "`":
                k += 1
                continue
            m = k
            while m < n and chars[m] == "`":
                m += 1
            if m - k == width:
                close = m
                break
            k = m
        if close < 0:
            i = j
            continue
        for p in range(i, close):
            if chars[p] != "\n":
                chars[p] = " "
        i = close
    return "".join(chars)


def unescape(target: str) -> str:
    return re.sub(r"\\([!-/:-@\[-`{-~])", r"\1", target)


def parse_destination(text: str, start: int) -> tuple[str, int] | None:
    """Parse an inline link destination and the closing `)` after `(` at start-1."""
    n = len(text)
    i = start
    while i < n and text[i] in " \t\n":
        i += 1
    if i < n and text[i] == "<":
        j = i + 1
        while j < n and text[j] not in ">\n":
            j += 2 if text[j] == "\\" else 1
        if j >= n or text[j] != ">":
            return None
        destination = text[i + 1 : j]
        i = j + 1
    else:
        depth = 0
        j = i
        while j < n:
            c = text[j]
            if c == "\\":
                j += 2
                continue
            if c in " \t\n":
                break
            if c == "(":
                depth += 1
            elif c == ")":
                if depth == 0:
                    break
                depth -= 1
            j += 1
        destination = text[i:j]
        i = j
    while i < n and text[i] in " \t\n":
        i += 1
    if i < n and text[i] in "\"'(":
        closer = ")" if text[i] == "(" else text[i]
        j = i + 1
        while j < n and text[j] != closer:
            j += 2 if text[j] == "\\" else 1
        if j >= n:
            return None
        i = j + 1
        while i < n and text[i] in " \t\n":
            i += 1
    if i >= n or text[i] != ")":
        return None
    return unescape(destination), i + 1


def inline_targets(paragraph: str) -> list[tuple[int, str]]:
    """(offset, destination) of every non-image inline link; nested brackets and escapes handled."""
    found = []
    opened: list[tuple[int, bool]] = []
    i = 0
    n = len(paragraph)
    while i < n:
        c = paragraph[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            opened.append((i, i > 0 and paragraph[i - 1] == "!"))
        elif c == "]" and opened:
            start, is_image = opened.pop()
            if i + 1 < n and paragraph[i + 1] == "(":
                parsed = parse_destination(paragraph, i + 2)
                if parsed is not None:
                    if not is_image:
                        found.append((start, parsed[0]))
                    i = parsed[1]  # the destination is not markdown
                    continue
        i += 1
    return found


def extract_links(text: str) -> list[tuple[int, str]]:
    """(1-based line, destination) of every link in a markdown text, outside code."""
    masked = mask_code_blocks(text)
    links = []
    offset = 0
    for block in re.split(r"(\n[ \t]*\n)", masked):
        cleaned = mask_inline_code(block)
        base_line = masked.count("\n", 0, offset) + 1
        for position, target in inline_targets(cleaned):
            links.append((base_line + cleaned.count("\n", 0, position), target))
        for match in REF_DEFINITION.finditer(cleaned):
            if match.group(1).startswith("^"):
                continue
            destination = match.group(2)
            if destination.startswith("<"):
                destination = destination[1:-1]
            links.append(
                (base_line + cleaned.count("\n", 0, match.start()), unescape(destination))
            )
        offset += len(block)
    return links


def exists_exact(base: Path, parts: tuple[str, ...]) -> bool:
    """Case-sensitive existence, so a macOS checkout agrees with the Linux runner."""
    current = base
    for part in parts:
        try:
            if part not in os.listdir(current):
                return False
        except OSError:
            return False
        current = current / part
    return True


class Projection:
    """The public layout: the overlay copied onto the root of the source tree minus exclusions."""

    def __init__(self, root: Path) -> None:
        self.root = root
        config: dict = {}
        path = root / PROJECTION_CONFIG
        if path.is_file():
            config = tomllib.loads(path.read_text(encoding="utf-8"))
        snapshot = config.get("snapshot", {})
        self.dirs_root = set(snapshot.get("exclude_dirs_root", []))
        self.dirs_any = set(snapshot.get("exclude_dirs_any_depth", []))
        self.paths = [p.rstrip("/") for p in snapshot.get("exclude_paths", [])]
        self.includes = [p.rstrip("/") for p in snapshot.get("include_paths", [])]

    @staticmethod
    def _under(joined: str, prefix: str) -> bool:
        return joined == prefix or joined.startswith(prefix + "/")

    def projected_from_root(self, parts: tuple[str, ...]) -> bool:
        if not parts or parts[0] == OVERLAY:
            return not parts
        joined = "/".join(parts)
        if joined == PROJECTION_CONFIG:
            return False  # the projector always removes its own configuration
        if any(self._under(joined, inc) or self._under(inc, joined) for inc in self.includes):
            return True
        if parts[0] in self.dirs_root or any(p in self.dirs_any for p in parts):
            return False
        return not any(self._under(joined, excluded) for excluded in self.paths)

    def exists(self, parts: tuple[str, ...]) -> bool:
        if not parts:
            return True
        if exists_exact(self.root / OVERLAY, parts):
            return True
        return self.projected_from_root(parts) and exists_exact(self.root, parts)


def clean_target(target: str) -> str:
    """The path part of a link destination: no fragment, no query, percent-decoded."""
    path = target.split("#", 1)[0].split("?", 1)[0]
    return urllib.parse.unquote(path)


def link_resolves(root: Path, projection: Projection, source: Path, target: str) -> bool:
    relative = source.relative_to(root)
    in_overlay = relative.parts[0] == OVERLAY
    # A published file is judged in the public layout, where the overlay has no prefix.
    public_dir = relative.parts[1:-1] if in_overlay else relative.parts[:-1]
    published = in_overlay or projection.projected_from_root(relative.parts)
    if target.startswith("/"):
        stack: list[str] = []
        raw = target.lstrip("/")
    else:
        stack = list(public_dir if published else relative.parts[:-1])
        raw = target
    for part in raw.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                return False  # leaves the repository
            stack.pop()
        else:
            stack.append(part)
    parts = tuple(stack)
    if published:
        return projection.exists(parts)
    return exists_exact(root, parts)


def check_links(root: Path) -> list[str]:
    errors = []
    projection = Projection(root)
    for source in link_files(root):
        text = source.read_text(encoding="utf-8")
        for number, target in extract_links(text):
            if EXTERNAL.match(target):
                continue
            path = clean_target(target)
            if not path:
                continue
            if not link_resolves(root, projection, source, path):
                errors.append(f"{source.relative_to(root)}:{number}: broken link to `{target}`")
    return errors


def check(root: Path) -> list[str]:
    errors = check_links(root)
    have = noted(root)
    standing = standing_present(root)
    for name, rel in GATES.items():
        try:
            value = current_value(root, name, rel)
        except (OSError, ValueError) as exc:
            errors.append(str(exc))
            continue
        if name in EXEMPT:
            if not standing:
                errors.append(
                    f"{NOTES} is missing the standing line `{STANDING_LINE}` for {name}"
                )
            continue
        if (name, value) not in have:
            errors.append(
                f"{name} is {value} in {rel} but {NOTES} has no `- {name} = {value}: <note>` line; "
                "a protocol-generation change is a coordinated cutover and needs a note"
            )
    return errors


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name, rel in GATES.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(f"pub const {name}: u32 = 7;\n", encoding="utf-8")
        assert len(check(root)) == len(GATES), "missing CUTOVER.md must fail every gate"
        full = "".join(f"- {n} = 7: baseline\n" for n in GATES if n not in EXEMPT) + STANDING_LINE + "\n"
        (root / NOTES).parent.mkdir(parents=True, exist_ok=True)
        (root / NOTES).write_text(full, encoding="utf-8")
        assert check(root) == [], check(root)
        # A bump without a note fails, and only that gate.
        rel = GATES["RPC_VERSION"]
        (root / rel).write_text("const RPC_VERSION: u8 = 8;\n", encoding="utf-8")
        errs = check(root)
        assert len(errs) == 1 and "RPC_VERSION is 8" in errs[0], errs
        # An old note for a different value does not satisfy it; the new one does.
        (root / NOTES).write_text(full + "- RPC_VERSION = 8: renamed frame\n", encoding="utf-8")
        assert check(root) == []
        # A note without text, or in prose, does not count.
        (root / NOTES).write_text(full + "- RPC_VERSION = 8:\n", encoding="utf-8")
        assert len(check(root)) == 1
        (root / rel).write_text("const RPC_VERSION: u8 = 7;\n", encoding="utf-8")
        (root / NOTES).parent.mkdir(parents=True, exist_ok=True)
        (root / NOTES).write_text(full, encoding="utf-8")
        assert check(root) == [], check(root)
        # An exempt bump passes without a new line; a non-exempt bump still fails.
        crel = GATES["CONTROL_PROTOCOL_VERSION"]
        (root / crel).write_text("pub const CONTROL_PROTOCOL_VERSION: u32 = 8;\n", encoding="utf-8")
        assert check(root) == [], check(root)
        (root / crel).write_text("pub const CONTROL_PROTOCOL_VERSION: u32 = 7;\n", encoding="utf-8")
        # Removing the standing line fails, and a per-value line does not replace it.
        (root / NOTES).write_text(
            "".join(f"- {n} = 7: baseline\n" for n in GATES if n not in EXEMPT)
            + "- CONTROL_PROTOCOL_VERSION = 7: baseline\n",
            encoding="utf-8",
        )
        errs = check(root)
        assert len(errs) == 1 and "standing line" in errs[0], errs
        # A near-miss standing line (wrong text) does not count.
        (root / NOTES).write_text(full.replace("not a cutover", "a cutover"), encoding="utf-8")
        assert len(check(root)) == 1
        (root / NOTES).parent.mkdir(parents=True, exist_ok=True)
        (root / NOTES).write_text(full, encoding="utf-8")
        # An exempt constant is still read from source: missing or duplicated fails.
        (root / crel).write_text("// nothing here\n", encoding="utf-8")
        assert any("expected exactly one" in e for e in check(root))
        (root / crel).write_text(
            "pub const CONTROL_PROTOCOL_VERSION: u32 = 7;\npub const CONTROL_PROTOCOL_VERSION: u32 = 7;\n",
            encoding="utf-8",
        )
        assert any("expected exactly one" in e for e in check(root))
        (root / crel).write_text("pub const CONTROL_PROTOCOL_VERSION: u32 = 7;\n", encoding="utf-8")
        # A duplicated or missing constant is an error, not a silent pass.
        (root / rel).write_text("// nothing here\n", encoding="utf-8")
        assert any("expected exactly one" in e for e in check(root))


def link_self_test() -> None:
    def broken(files: dict[str, str], config: str = "") -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, content in files.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text(content, encoding="utf-8")
            if config:
                (root / PROJECTION_CONFIG).write_text(config, encoding="utf-8")
            return check_links(root)

    def notes(text: str) -> list[str]:
        return broken({NOTES: text})

    def count(errors: list[str], expected: int) -> None:
        assert len(errors) == expected, errors

    # A missing target fails; the overlay copy satisfies a root-level link.
    errs = notes("[policy](COMPATIBILITY.md)\n")
    assert len(errs) == 1 and "COMPATIBILITY.md" in errs[0], errs
    count(broken({NOTES: "[policy](COMPATIBILITY.md)\n", "oss-public/docs/COMPATIBILITY.md": "x"}), 0)
    # External links, anchors and images are ignored.
    count(notes("[a](https://x.example/y) [b](#top) [c](//x.example/z) ![i](missing.png)\n"), 0)
    # docs/ links resolve relative to the file and get no overlay fallback.
    errs = broken(
        {
            "docs/a.md": "[ok](b.md#s) [bad](COMPATIBILITY.md)\n",
            "docs/b.md": "x\n",
            "oss-public/docs/COMPATIBILITY.md": "x\n",
        },
        '[snapshot]\nexclude_dirs_root = ["docs"]\n',
    )
    assert len(errs) == 1 and "docs/a.md:1" in errs[0], errs

    # oss-public/ files are judged in the projected layout.
    layout = {"oss-public/README.md": "[l](LICENSE) [p](packaging/) [o](docs/COMPATIBILITY.md)\n"}
    count(broken(layout), 3)
    count(
        broken(
            {**layout, "LICENSE": "x", "packaging/a": "x", "oss-public/docs/COMPATIBILITY.md": "x"}
        ),
        0,
    )
    # A link to a file the snapshot excludes is broken publicly even though it exists privately.
    config = '[snapshot]\nexclude_dirs_root = ["docs"]\nexclude_paths = ["private.md"]\n'
    files = {
        "oss-public/README.md": "[d](docs/a.md) [p](private.md) [ok](LICENSE)\n",
        "docs/a.md": "x\n",
        "private.md": "x\n",
        "LICENSE": "x\n",
    }
    count(broken(files, config), 2)
    count(broken({"oss-public/README.md": "[c](.public-tree.toml)\n", ".public-tree.toml": "[snapshot]\n"}), 1)
    # An include re-opens an excluded directory; the overlay's own dotdirs resolve.
    config = '[snapshot]\nexclude_dirs_root = [".github"]\ninclude_paths = [".github/checks"]\n'
    files = {
        "oss-public/README.md": "[c](.github/checks/x.py) [s](.github/SECURITY.md) [w](.github/w.md)\n",
        ".github/checks/x.py": "x",
        ".github/w.md": "x",
        "oss-public/.github/SECURITY.md": "x",
    }
    errs = broken(files, config)
    assert len(errs) == 1 and "w.md" in errs[0], errs
    # The overlay directory has no name in the public layout, and matching is exact-case there too.
    count(broken({"oss-public/README.md": "[o](oss-public/README.md) [c](readme.md)\n"}), 2)
    # An overlay document cannot link out of the repository, even to a file that exists there.
    with tempfile.TemporaryDirectory() as tmp:
        outer = Path(tmp)
        (outer / "outside.md").write_text("x\n", encoding="utf-8")
        root = outer / "repo"
        (root / "oss-public" / ".github").mkdir(parents=True)
        (root / "oss-public" / ".github" / "A.md").write_text(
            "[a](../../outside.md) [b](../../../outside.md) [c](../README.md)\n", encoding="utf-8"
        )
        (root / "oss-public" / "README.md").write_text("x\n", encoding="utf-8")
        errs = check_links(root)
        assert len(errs) == 2 and all("outside.md" in e for e in errs), errs
    # Nested overlay documents resolve relative to their public location.
    count(
        broken(
            {
                "oss-public/.github/CONTRIBUTING.md": "[c](../README.md) [d](legal/CLA.md)\n",
                "oss-public/README.md": "x",
                "oss-public/.github/legal/CLA.md": "x",
            }
        ),
        0,
    )

    # A fenced example nested in a list item, even with blank lines inside it.
    count(notes("- item\n\n    ```\n    [x](nope.md)\n\n    [y](nope.md)\n    ```\n\n  [z](nope.md)\n"), 1)
    count(notes("text\n\n    ```\n\n[x](nope.md)\n"), 1)  # indented code outside a list, no fence
    count(notes("[x](https://example.com/[a](nope.md)) ![i](https://e.example/[b](nope.md))\n"), 0)
    # False positives: code, escapes and target forms that are valid.
    count(notes("`[x](nope.md)` and ``[x](nope.md)`` and ` a `` [x](nope.md) b ` end\n"), 0)
    count(notes("~~~\n[x](nope.md)\n~~~\n"), 0)
    count(notes("text\n\n    [x](nope.md)\n\nmore\n"), 0)
    count(notes("```\n[x](nope.md)\n```\n~~~~\n```\n[y](nope.md)\n~~~~\n"), 0)
    count(notes("- item\n\n    [x](b.md) continued in the item\n"), 1)
    count(broken({NOTES: "[x](<b.md>) [y](b.md \"title\")\n", "docs/b.md": "x"}), 0)
    count(broken({NOTES: "[x](b%20c.md) [y](b.md?x=1) [z](b.md?x=1#f)\n", "docs/b c.md": "x", "docs/b.md": "x"}), 0)
    count(broken({NOTES: "[x](/b.md)\n", "b.md": "x"}), 0)
    count(broken({"docs/a.md": "[x](/b.md) [y](/missing.md)\n", "b.md": "x"}), 1)
    count(notes("\\[x](nope.md) and [y\\](nope.md)\n"), 0)
    count(notes("[x]: <nope.md\n"), 0)
    # Footnote definitions and undefined references are not links.
    count(notes("[^1]: note [text][undefined]\n"), 0)

    # False negatives: all of these are broken links and must be reported.
    count(notes("[x][r]\n\n[r]: nope.md\n"), 1)
    count(notes("[r]\n\n[r]: <nope file.md>\n"), 1)
    count(broken({NOTES: "[r]\n\n[r]: b.md\n", "docs/b.md": "x"}), 0)
    count(notes("[a [b] c](nope.md)\n"), 1)
    count(notes("[![i](i.png)](nope.md)\n"), 1)
    count(broken({NOTES: "[![i](i.png)](b.md)\n", "docs/b.md": "x"}), 0)
    count(notes("````\n```\n````\n[x](nope.md)\n"), 1)
    count(notes("````\n```\n[x](nope.md)\n"), 0)
    count(notes("[x](<no pe.md>)\n"), 1)
    count(broken({NOTES: "[x](<b c.md>)\n", "docs/b c.md": "x"}), 0)
    count(broken({NOTES: "[x](f(1).md)\n", "docs/f(1).md": "x"}), 0)
    count(notes("[x](f(1).md)\n"), 1)
    count(broken({NOTES: "[x](B.md)\n", "docs/b.md": "x"}), 1)  # exact case, as on the Linux runner
    with tempfile.TemporaryDirectory() as tmp:
        outer = Path(tmp)
        (outer / "outside.md").write_text("x\n", encoding="utf-8")
        root = outer / "repo"
        (root / "docs").mkdir(parents=True)
        (root / "docs" / "a.md").write_text("[x](../../outside.md)\n", encoding="utf-8")
        count(check_links(root), 1)
    # Line numbers point at the link, also after a code block and inside a paragraph.
    errs = notes("a\n\n```\nx\n```\n\nline\n[x](nope.md)\n")
    assert len(errs) == 1 and f"{NOTES}:8:" in errs[0], errs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        link_self_test()
        print("cutover note guard self-test passed")
        return 0
    errors = check(ROOT)
    if errors:
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(f"cutover note guard: ok ({len(GATES) - len(EXEMPT)} generation constants noted, {len(EXEMPT)} exempt)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
