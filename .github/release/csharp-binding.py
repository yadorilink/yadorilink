#!/usr/bin/env python3
"""Drift guard and notes for the generated C# binding of the client facade.

  csharp-binding.py pin-check [--pin FILE] [--lock Cargo.lock]
  csharp-binding.py check GENERATED_DIR [--snapshot FILE] [--update]
  csharp-binding.py notice GENERATED_DIR [--pin FILE]
  csharp-binding.py notes GENERATED_DIR --out FILE [--pin FILE] [--lock Cargo.lock]
  csharp-binding.py --self-test

`generate-csharp-binding.sh` runs these around the generator. The binding is
generated at bundle build time and not checked in; what is checked in is its
API surface (`csharp-api-surface.txt`): every public declaration the Windows
app can call, plus the UniFFI API checksums the generated code compares with
the native library at load time. A change to the facade that alters that
surface fails `check` until the snapshot is regenerated on purpose
(`--update`), so a Rust change cannot reach the Windows app unnoticed.

Doc comments and layout do not count: they are dropped before comparing, so
rewording a comment in the facade does not touch the snapshot.

`notice` prepends the generator's licence notice to every generated file: the
generator (uniffi-bindgen-cs) is MPL-2.0 and its templates are copied into the
output, but the templates' own MPL headers are template comments and do not
reach it. The notice states the MPL-2.0 terms, the generator version and where
the templates' source is. It is a comment, so the API surface is unchanged.

`pin-check` ties the generator to the workspace: `csharp-bindgen.pin` names
the UniFFI release the generator was built for, and it must equal the `uniffi`
version in Cargo.lock (major.minor; UniFFI changes its metadata format between
minors, and the generator cannot read a library built with another one).
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_PIN = HERE / "csharp-bindgen.pin"
DEFAULT_SNAPSHOT = HERE / "csharp-api-surface.txt"
DEFAULT_LOCK = ROOT / "Cargo.lock"

SNAPSHOT_HEADER = (
    "# API surface of the generated C# binding (see csharp-binding.py).\n"
    "# Regenerate on purpose with: .github/release/generate-csharp-binding.sh --out DIR --update-snapshot\n"
)
# Serialization plumbing: public in the generated code, but not part of what the
# app calls. Its shape follows from the types it converts.
PLUMBING = re.compile(r"FfiConverter|BigEndianStream|AllocationSize|\bINSTANCE\b|\bRead\(|\bWrite\(|RustBuffer|_Uniffi|UniffiRust")
# The generated library loader compares these with the native library:
#   var checksum = _UniFFILib.uniffi_<lib>_checksum_<item>();
#   if (checksum != 4242) { ...
CHECKSUM = re.compile(r"(uniffi_\w+_checksum_\w+)\(\);\s*if \(checksum != (\d+)\)")
CONTRACT = re.compile(r"if \((\d+) != scaffolding_contract_version\)")


def read_kv(path: Path) -> dict[str, str]:
    out = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            key, sep, value = line.partition("=")
            if not sep:
                raise SystemExit(f"error: {path}: not KEY=VALUE: {line!r}")
            out[key.strip()] = value.strip()
    return out


def lock_version(lock: Path, package: str) -> str:
    text = lock.read_text(encoding="utf-8")
    found = re.findall(rf'\[\[package\]\]\nname = "{re.escape(package)}"\nversion = "([^"]+)"', text)
    if len(found) != 1:
        raise SystemExit(f"error: expected exactly one {package} in {lock}, found {len(found)}")
    return found[0]


def pin_problems(pin: Path, lock: Path) -> list[str]:
    values = read_kv(pin)
    problems = [f"{pin.name} lacks {k}" for k in ("repository", "rev", "version", "uniffi_rs") if k not in values]
    if problems:
        return problems
    if not re.fullmatch(r"[0-9a-f]{40}", values["rev"]):
        problems.append("pin rev must be a full 40-hex commit")
    if not values["repository"].startswith("https://"):
        problems.append("pin repository must be an https URL")
    have = ".".join(lock_version(lock, "uniffi").split(".")[:2])
    if values["uniffi_rs"] != have:
        problems.append(
            f"generator is pinned for uniffi {values['uniffi_rs']} but Cargo.lock has uniffi {have}; "
            "update csharp-bindgen.pin together with the workspace uniffi"
        )
    if f"v{values['uniffi_rs']}." not in values["version"]:
        problems.append(f"pin version {values['version']} does not name uniffi {values['uniffi_rs']}")
    return problems


def significant_lines(text: str) -> list[str]:
    """Code lines without comments, doc comments or indentation."""
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("//"):
            lines.append(line)
    return lines


def surface_of(text: str) -> list[str]:
    """Checksums, then the public declarations: type headers and their direct
    members (record fields, enum variants, interface and class members), not
    method bodies and not the serialization plumbing."""
    out = [f"checksum {name} {value}" for name, value in CHECKSUM.findall(text)]
    out += [f"contract_version {value}" for value in CONTRACT.findall(text)]
    depth = 0
    parens = 0
    in_public = False
    skipping = False
    for line in significant_lines(text):
        # `#if X ... #else ... #endif` declares the same item twice; read the first.
        if line.startswith("#else") or line.startswith("#elif"):
            skipping = True
        if line.startswith("#endif"):
            skipping = False
        if skipping or line.startswith("#"):
            continue
        if depth == 0 and line.startswith("namespace "):
            out.append(line.rstrip(";{ "))
        if depth == 0 and parens == 0 and not line.startswith(("[", "}", ")")):
            in_public = line.startswith("public ")
        if in_public and depth <= 1 and not line.startswith(("[", "}")) and not PLUMBING.search(line):
            # Drop an inline body or initializer; the declaration is what matters.
            decl = re.sub(r"\s*(\{.*|=>.*|=\s*new .*)$", "", line).rstrip()
            if decl and decl not in (")", ");"):
                out.append(decl)
        code = re.sub(r'"(\\.|[^"\\])*"', '""', line)
        depth += code.count("{") - code.count("}")
        if depth <= 1:
            parens = max(0, parens + code.count("(") - code.count(")"))
    if depth != 0 or parens != 0:
        raise SystemExit("error: unbalanced braces in the generated C#; the surface parser needs updating")
    return out


def surface(generated: Path) -> str:
    files = sorted(generated.glob("*.cs"))
    if not files:
        raise SystemExit(f"error: no .cs files in {generated}")
    body = []
    for f in files:
        body.append(f"## {f.name}")
        lines = surface_of(f.read_text(encoding="utf-8"))
        # Checksums sorted, then declarations in source order.
        head = [l for l in lines if l.startswith(("checksum ", "contract_version "))]
        body += sorted(head)
        body += [l for l in lines if l not in head]
    return SNAPSHOT_HEADER + "\n".join(body) + "\n"


def surface_digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def check(generated: Path, snapshot: Path, update: bool) -> int:
    current = surface(generated)
    if update:
        snapshot.write_text(current, encoding="utf-8", newline="\n")
        print(f"api surface snapshot written: {snapshot} (sha256 {surface_digest(current)})")
        return 0
    if not snapshot.is_file():
        print(f"error: {snapshot} is missing; create it with --update-snapshot", file=sys.stderr)
        return 1
    recorded = snapshot.read_text(encoding="utf-8")
    if recorded == current:
        print(f"C# api surface matches {snapshot.name} (sha256 {surface_digest(current)})")
        return 0
    import difflib

    diff = list(difflib.unified_diff(recorded.splitlines(), current.splitlines(), "snapshot", "generated", lineterm="", n=0))
    print("error: the generated C# API surface differs from the checked-in snapshot:", file=sys.stderr)
    for line in diff[:80]:
        print(line, file=sys.stderr)
    if len(diff) > 80:
        print(f"... {len(diff) - 80} more lines", file=sys.stderr)
    print(
        "The Windows app calls this surface. If the change is intended, run\n"
        "  .github/release/generate-csharp-binding.sh --out DIR --update-snapshot\n"
        "and commit the snapshot with the facade change.",
        file=sys.stderr,
    )
    return 1


NOTICE_MARK = "uniffi-bindgen-cs is licensed under the Mozilla Public License"


def notice_text(values: dict[str, str]) -> str:
    return (
        f"// This file was generated by uniffi-bindgen-cs {values['version']} and contains text from\n"
        "// that generator's templates. " + NOTICE_MARK + ", v. 2.0.\n"
        "// If a copy of the MPL was not distributed with this file, You can obtain one at\n"
        "// http://mozilla.org/MPL/2.0/. The source of the generator and of those templates is\n"
        f"// {values['repository']}/tree/{values['rev']}\n"
    )


def add_notice(generated: Path, pin: Path) -> int:
    header = notice_text(read_kv(pin))
    files = sorted(generated.glob("*.cs"))
    if not files:
        raise SystemExit(f"error: no .cs files in {generated}")
    for f in files:
        text = f.read_text(encoding="utf-8")
        if NOTICE_MARK not in text:
            f.write_text(header + text, encoding="utf-8", newline="\n")
    return 0


def notes(generated: Path, out: Path, pin: Path, lock: Path) -> int:
    values = read_kv(pin)
    digest = surface_digest(surface(generated))
    files = "\n".join(f"- `Generated/{f.name}`" for f in sorted(generated.glob("*.cs")))
    out.write_text(
        f"""# C# binding of the YadoriLink client facade

Generated by `.github/release/generate-csharp-binding.sh` from the native
library in this bundle. Do not edit; do not mix files from different bundles.

| | |
| --- | --- |
| Generator | uniffi-bindgen-cs {values['version']}, pinned to commit {values['rev']} |
| Generator source | {values['repository']}/tree/{values['rev']} |
| Generator licence | Mozilla Public License 2.0 (https://mozilla.org/MPL/2.0/); the text is in `THIRD-PARTY-LICENSES` |
| UniFFI (workspace) | {lock_version(lock, 'uniffi')} |
| API surface sha256 | {digest} |
| Native library | `yadorilink_client_ffi.dll`, loaded by the name `yadorilink_client_ffi` |
| Namespaces | `YadoriLink.Native` (facade), `YadoriLink.Native.Core` (product types) |

Files:

{files}

Generator licence notice: the generator is free software under the MPL-2.0
and its templates are copied into the generated files, so each `Generated/*.cs`
starts with the MPL-2.0 notice naming the generator, its version and where its
source is. The generated files are not otherwise modified by the bundle; they
are used and redistributed under the same terms as the rest of the bundle
(`LICENSE`), plus that notice.

Using it:

- Compile both files into one assembly (net8.0 or later, `AllowUnsafeBlocks`
  true). They are plain C# with no package dependencies. The types are public.
- Ship `yadorilink_client_ffi.dll` next to the executable. The generated code
  compares API checksums with the library when it first loads and throws if
  they differ, so a binding and a library from different builds cannot be
  mixed.
- Entry points: `ClientCore` (the facade), `LoginSession` (sign-in flow) and
  `StatusWatch` (status polling). Facade calls are `Task`-returning methods that
  run on one long-lived Rust runtime. Product types are in
  `YadoriLink.Native.Core`, the facade in `YadoriLink.Native`.
- All safety, authorization and durability decisions are made in Rust; the
  binding only carries requests and answers.
""",
        encoding="utf-8",
     newline="\n")
    return 0


SAMPLE = """// <auto-generated>
namespace YadoriLink.Native;
/// <summary>doc</summary>
public record Folder (
    string @name
) {}
public interface IClientCore {
    Task<Folder> FolderDetail(string @id);
}
internal class Hidden {
    public int Nope() { return 1; }
}
public class Impl : IClientCore {
    public async Task<Folder> FolderDetail(string @id) {
        var s = $"{id}";
        return default!;
    }
}
public class FfiConverterTypeFolder {
    public static int AllocationSize(Folder v) { return 1; }
}
static void check() {
    var scaffolding_contract_version = _UniFFILib.ffi_x_uniffi_contract_version();
    if (30 != scaffolding_contract_version) { throw new Exception(); }
    {
        var checksum = _UniFFILib.uniffi_yadorilink_client_ffi_checksum_method_clientcore_folder_detail();
        if (checksum != 4242) { throw new Exception(); }
    }
}
"""


def self_test() -> int:
    import contextlib
    import io

    # The negative cases print their diagnostics; keep the test output quiet.
    with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
        _self_test()
    print("ok")
    return 0


def _self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        gen = tmp / "Generated"
        gen.mkdir()
        (gen / "a.cs").write_text(SAMPLE, encoding="utf-8", newline="\n")
        snap = tmp / "snap.txt"
        assert check(gen, snap, update=True) == 0
        text = snap.read_text(encoding="utf-8")
        assert "public record Folder (" in text, text
        assert "FolderDetail(string @id);" in text, text
        assert "checksum uniffi_yadorilink_client_ffi_checksum_method_clientcore_folder_detail 4242" in text, text
        assert "contract_version 30" in text, text
        assert "FfiConverter" not in text and "AllocationSize" not in text, text
        assert check(gen, snap, update=False) == 0
        # Comments and layout do not drift the snapshot.
        (gen / "a.cs").write_text(SAMPLE.replace("/// <summary>doc</summary>", "/// reworded").replace("    Task", "        Task"), encoding="utf-8", newline="\n")
        assert check(gen, snap, update=False) == 0
        # A new method, a changed checksum, a new field and a new file each do.
        for mutate in (
            lambda s: s.replace("FolderDetail(string @id);", "FolderDetail(string @id);\n    Task Pause();"),
            lambda s: s.replace("4242", "4243"),
            lambda s: s.replace("(30 !=", "(31 !=").replace("30 !=", "31 !="),
            lambda s: s.replace("string @name\n", "string @name,\n    string @extra\n"),
            lambda s: s.replace("string @id", "long @id"),
        ):
            (gen / "a.cs").write_text(mutate(SAMPLE), encoding="utf-8", newline="\n")
            assert check(gen, snap, update=False) == 1, mutate
        (gen / "a.cs").write_text(SAMPLE, encoding="utf-8", newline="\n")
        (gen / "b.cs").write_text(SAMPLE, encoding="utf-8", newline="\n")
        assert check(gen, snap, update=False) == 1
        (gen / "b.cs").unlink()
        assert check(gen, tmp / "missing.txt", update=False) == 1

        lock = tmp / "Cargo.lock"
        lock.write_text('[[package]]\nname = "uniffi"\nversion = "0.32.2"\n', encoding="utf-8", newline="\n")
        pin = tmp / "pin"
        good = (
            "repository=https://example.invalid/x\nrev=" + "a" * 40 + "\nversion=0.12.0+v0.32.0\nuniffi_rs=0.32\n"
        )
        pin.write_text(good, encoding="utf-8", newline="\n")
        assert pin_problems(pin, lock) == []
        lock.write_text('[[package]]\nname = "uniffi"\nversion = "0.33.0"\n', encoding="utf-8", newline="\n")
        assert pin_problems(pin, lock), "a uniffi minor bump must fail the pin check"
        lock.write_text('[[package]]\nname = "uniffi"\nversion = "0.32.2"\n', encoding="utf-8", newline="\n")
        pin.write_text(good.replace("a" * 40, "main"), encoding="utf-8", newline="\n")
        assert pin_problems(pin, lock), "a moving ref must be rejected"
        pin.write_text(good, encoding="utf-8", newline="\n")
        assert notes(gen, tmp / "n.md", pin, lock) == 0
        note = (tmp / "n.md").read_text(encoding="utf-8")
        assert "0.32.2" in note and "Mozilla Public License 2.0" in note and "a" * 40 in note
        # The licence notice is added once, as comments only.
        before = surface(gen)
        assert add_notice(gen, pin) == 0 and add_notice(gen, pin) == 0
        text = (gen / "a.cs").read_text(encoding="utf-8")
        assert text.count(NOTICE_MARK) == 1 and text.startswith("// This file was generated by uniffi-bindgen-cs 0.12.0+v0.32.0")
        assert surface(gen) == before, "the notice must not change the API surface"


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("pin-check", "notes"):
        s = sub.add_parser(name)
        s.add_argument("--pin", default=str(DEFAULT_PIN))
        s.add_argument("--lock", default=str(DEFAULT_LOCK))
        if name == "notes":
            s.add_argument("generated")
            s.add_argument("--out", required=True)
    nt = sub.add_parser("notice")
    nt.add_argument("generated")
    nt.add_argument("--pin", default=str(DEFAULT_PIN))
    c = sub.add_parser("check")
    c.add_argument("generated")
    c.add_argument("--snapshot", default=str(DEFAULT_SNAPSHOT))
    c.add_argument("--update", action="store_true")
    args = p.parse_args(argv)
    if args.cmd == "pin-check":
        found = pin_problems(Path(args.pin), Path(args.lock))
        for line in found:
            print(f"csharp bindgen pin: {line}", file=sys.stderr)
        return 1 if found else 0
    if args.cmd == "check":
        return check(Path(args.generated), Path(args.snapshot), args.update)
    if args.cmd == "notice":
        return add_notice(Path(args.generated), Path(args.pin))
    return notes(Path(args.generated), Path(args.out), Path(args.pin), Path(args.lock))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
