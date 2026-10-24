#!/usr/bin/env python3
"""Render the THIRD-PARTY-LICENSES notice from cargo-about JSON output.

  third-party-licenses.py render --out FILE JSON [JSON ...]
  third-party-licenses.py --self-test

`generate-third-party-licenses.sh` runs `cargo about generate --format json`
once per shipped package and hands the results here. Crates from several
packages are merged (a crate is listed once), first-party crates (path
sources) are left out, and the plain-text notice is deterministic: licence
texts are grouped by identical text (so each copyright line is kept), crates
are sorted by name and version.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

RULE = "=" * 78


def merge(documents: list[dict]) -> list[tuple[str, str, list[tuple[str, str, str]]]]:
    """[(licence name, text, [(crate, version, repository)])], sorted."""
    groups: dict[tuple[str, str], dict[tuple[str, str], str]] = {}
    for doc in documents:
        for lic in doc["licenses"]:
            for used in lic["used_by"]:
                crate = used["crate"]
                if crate.get("source") is None:
                    continue  # first-party (path) crate
                key = (lic["name"], lic["text"].strip())
                groups.setdefault(key, {})[(crate["name"], crate["version"])] = crate.get("repository") or ""
    out = []
    for (name, text), crates in sorted(groups.items()):
        out.append((name, text, [(n, v, crates[(n, v)]) for n, v in sorted(crates)]))
    return out


def render(documents: list[dict]) -> str:
    groups = merge(documents)
    if not groups:
        raise SystemExit("error: no third-party crates found; refusing to write an empty notice")
    count = len({(n, v) for _, _, crates in groups for n, v, _ in crates})
    lines = [
        "Third-party licenses",
        "",
        f"The programs in this bundle include {count} third-party Rust crates.",
        "Each is distributed under the licence text shown below it; the crates that",
        "text applies to are listed above the text.",
        "",
    ]
    for name, text, crates in groups:
        lines += [RULE, name, RULE, "", "Used by:"]
        lines += [f"  {n} {v}" + (f" ({repo})" if repo else "") for n, v, repo in crates]
        lines += ["", text, ""]
    return "\n".join(lines)


def self_test() -> int:
    def crate(name, version, source="registry+x"):
        return {"crate": {"name": name, "version": version, "source": source, "repository": ""}}

    a = {"licenses": [
        {"name": "MIT License", "text": "MIT text A\n", "used_by": [crate("b", "1.0.0"), crate("firstparty", "0.1.0", None)]},
        {"name": "MIT License", "text": "MIT text B", "used_by": [crate("a", "2.0.0")]},
    ]}
    b = {"licenses": [{"name": "MIT License", "text": "MIT text A", "used_by": [crate("b", "1.0.0"), crate("c", "0.3.0")]}]}
    one, two = render([a, b]), render([b, a])
    assert one == two, "the notice depends on input order"
    assert "firstparty" not in one, "first-party crates must be left out"
    assert one.count("MIT text A") == 1 and "MIT text B" in one
    assert one.count("  b 1.0.0") == 1, "a merged crate is listed once"
    assert "3 third-party" in one
    try:
        render([{"licenses": [{"name": "x", "text": "t", "used_by": [crate("firstparty", "1", None)]}]}])
    except SystemExit:
        pass
    else:
        raise AssertionError("an empty notice must be refused")
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "a.json"
        f.write_text(json.dumps(a), encoding="utf-8", newline="\n")
        out = Path(tmp) / "out"
        assert main(["render", "--out", str(out), str(f)]) == 0 and "MIT text A" in out.read_text(encoding="utf-8")
    print("ok")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if len(argv) < 4 or argv[0] != "render" or argv[1] != "--out":
        print(__doc__, file=sys.stderr)
        return 2
    documents = [json.loads(Path(p).read_text(encoding="utf-8")) for p in argv[3:]]
    Path(argv[2]).write_text(render(documents), encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
