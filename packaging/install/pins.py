#!/usr/bin/env python3
"""Render, read and check the pin block of the installers.

Usage: pins.py show
       pins.py check [--allow-dev-key] [--require-verifier] [--require-floor]
       pins.py set [--trust-set "id:hex id2:hex"] [--verifier-sha TARGET=HEX]...
                   [--verifier-base URL] [--min-generated-at TS]
       pins.py --self-test

install.sh and install.ps1 each carry one block between `>>> PINS >>>` and `<<< PINS <<<`.
Release CI (installer-sync) writes it with `set`; nothing edits it by hand. The block holds
exactly what a client must trust without fetching it: the manifest signing keys (current key
first, next key during a rotation), the verifier program's hash per platform, where the
verifier is released, and the oldest manifest time a first install accepts.

`check` fails unless every block is well formed, both installers pin the same trust set and
replay floor, and no pinned key is the public development key (unless --allow-dev-key).
--require-verifier additionally fails while any platform's verifier hash is still empty; release
CI passes it for a tagged release, so an engine tag cannot ship installers that pin no verifier.
--require-floor likewise fails while the manifest floor is empty: installers keep no state, so
an unset floor lets any manifest ever signed (an old one, with an unexpired window or not
yet expired) pass a first install. Set it to the `generated_at` of the first manifest that
carries `expires_at` (`set --min-generated-at`), and roll it forward when a release needs to.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SH, PS1 = HERE / "install.sh", HERE / "install.ps1"
DEV_KEY = "00e033f866c263139ff4afd165e75bae3cfca67eb32399dddd6e33a3251af1e3"
TARGETS = ("macos-aarch64", "linux-x86_64")
KEY_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")
HEX_RE = re.compile(r"\A[0-9a-f]{64}\Z")
TS_RE = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
BASE_RE = re.compile(r"\Ahttps://github\.com/yadorilink/yadorilink/releases/download/verifier-[1-9][0-9]*\Z")
BEGIN, END = ">>> PINS >>>", "<<< PINS <<<"


class PinError(Exception):
    pass


def _block(text: str, name: str) -> tuple[int, int]:
    """Character range of the lines strictly between the two markers."""
    lines = text.splitlines(keepends=True)
    b = [i for i, l in enumerate(lines) if l.strip() == f"# {BEGIN}"]
    e = [i for i, l in enumerate(lines) if l.strip() == f"# {END}"]
    if len(b) != 1 or len(e) != 1 or b[0] >= e[0]:
        raise PinError(f"{name}: needs exactly one `# {BEGIN}` ... `# {END}` block")
    start = sum(len(l) for l in lines[: b[0] + 1])
    stop = sum(len(l) for l in lines[: e[0]])
    return start, stop


def parse_sh(text: str) -> dict:
    s, e = _block(text, "install.sh")
    body = text[s:e].strip().splitlines()
    want = ["TRUST_SET", "VERIFIER_SHA_macos_aarch64", "VERIFIER_SHA_linux_x86_64", "VERIFIER_BASE",
            "MIN_MANIFEST_GENERATED_AT"]
    got = {}
    names = []
    for line in body:
        m = re.fullmatch(r'([A-Z_a-z0-9]+)="([^"$`\\]*)"', line)
        if not m:
            raise PinError(f"install.sh: unexpected line in the pin block: {line!r}")
        names.append(m.group(1))
        got[m.group(1)] = m.group(2)
    if names != want:
        raise PinError(f"install.sh: the pin block must define exactly {want} in order, got {names}")
    return {
        "trust_set": got["TRUST_SET"].split(),
        "verifier_sha": {"macos-aarch64": got["VERIFIER_SHA_macos_aarch64"],
                         "linux-x86_64": got["VERIFIER_SHA_linux_x86_64"]},
        "verifier_base": got["VERIFIER_BASE"],
        "min_generated_at": got["MIN_MANIFEST_GENERATED_AT"],
    }


def parse_ps1(text: str) -> dict:
    s, e = _block(text, "install.ps1")
    body = text[s:e].strip().splitlines()
    if len(body) != 2:
        raise PinError("install.ps1: the pin block must hold exactly the trust set and the floor")
    m1 = re.fullmatch(r"\$script:TrustSet = @\(([^)]*)\)", body[0])
    m2 = re.fullmatch(r"\$script:MinManifestGeneratedAt = '([^'$`\\]*)'", body[1])
    if not (m1 and m2):
        raise PinError(f"install.ps1: unexpected pin block lines {body!r}")
    entries = re.findall(r"'([^']*)'", m1.group(1))
    if re.sub(r"\s*'[^']*'\s*,?", "", m1.group(1)).strip():
        raise PinError("install.ps1: the trust set must be a list of single-quoted entries")
    return {"trust_set": entries, "min_generated_at": m2.group(1)}


def validate(pins: dict, where: str, allow_dev: bool) -> list[str]:
    out = []
    if not pins["trust_set"]:
        out.append(f"{where}: the trust set is empty")
    ids = []
    for entry in pins["trust_set"]:
        kid, _, hexkey = entry.partition(":")
        ids.append(kid)
        if not KEY_ID_RE.fullmatch(kid) or not HEX_RE.fullmatch(hexkey):
            out.append(f"{where}: trust entry {entry!r} must be <key_id>:<64 lowercase hex>")
        elif hexkey == DEV_KEY and not allow_dev:
            out.append(f"{where}: trust entry {kid!r} is the public development key")
    if len(set(ids)) != len(ids) or len({e.partition(':')[2] for e in pins['trust_set']}) != len(ids):
        out.append(f"{where}: a key id or key is pinned twice")
    if pins["min_generated_at"] and not TS_RE.fullmatch(pins["min_generated_at"]):
        out.append(f"{where}: MIN_MANIFEST_GENERATED_AT must be YYYY-MM-DDTHH:MM:SSZ or empty")
    for t, sha in pins.get("verifier_sha", {}).items():
        if sha and not HEX_RE.fullmatch(sha):
            out.append(f"{where}: verifier hash for {t} must be 64 lowercase hex or empty")
    if "verifier_base" in pins and not BASE_RE.fullmatch(pins["verifier_base"]):
        out.append(f"{where}: verifier base must be a yadorilink verifier-N release download URL")
    return out


def check(sh_text: str, ps1_text: str, allow_dev: bool = False, require_verifier: bool = False,
          require_floor: bool = False) -> list[str]:
    out = []
    try:
        sh = parse_sh(sh_text)
        ps = parse_ps1(ps1_text)
    except PinError as ex:
        return [str(ex)]
    out += validate(sh, "install.sh", allow_dev) + validate(ps, "install.ps1", allow_dev)
    if require_verifier:
        for t in TARGETS:
            if not sh.get("verifier_sha", {}).get(t):
                out.append(f"install.sh pins no verifier hash for {t} (publish verifier-N and `pins.py set --verifier-sha` first)")
    if require_floor:
        for name, pins in (("install.sh", sh), ("install.ps1", ps)):
            if not pins["min_generated_at"]:
                out.append(f"{name} pins no manifest floor (`pins.py set --min-generated-at` the generated_at of the first manifest with expires_at first)")
    if sh["trust_set"] != ps["trust_set"]:
        out.append("install.sh and install.ps1 pin different trust sets")
    if sh["min_generated_at"] != ps["min_generated_at"]:
        out.append("install.sh and install.ps1 pin different manifest floors")
    return out


def render_sh(pins: dict) -> str:
    return "\n".join([
        f'TRUST_SET="{" ".join(pins["trust_set"])}"',
        f'VERIFIER_SHA_macos_aarch64="{pins["verifier_sha"]["macos-aarch64"]}"',
        f'VERIFIER_SHA_linux_x86_64="{pins["verifier_sha"]["linux-x86_64"]}"',
        f'VERIFIER_BASE="{pins["verifier_base"]}"',
        f'MIN_MANIFEST_GENERATED_AT="{pins["min_generated_at"]}"',
    ]) + "\n"


def render_ps1(pins: dict) -> str:
    entries = ", ".join(f"'{e}'" for e in pins["trust_set"])
    return f"$script:TrustSet = @({entries})\n$script:MinManifestGeneratedAt = '{pins['min_generated_at']}'\n"


def replace_block(text: str, new_body: str, name: str) -> str:
    s, e = _block(text, name)
    return text[:s] + new_body + text[e:]


def apply(sh_text: str, ps1_text: str, updates: dict, allow_dev: bool = False) -> tuple[str, str]:
    sh = parse_sh(sh_text)
    ps = parse_ps1(ps1_text)
    sh = {**sh, **{k: v for k, v in updates.items() if k in ("trust_set", "verifier_base", "min_generated_at")}}
    if "verifier_sha" in updates:
        sh["verifier_sha"] = {**sh["verifier_sha"], **updates["verifier_sha"]}
    problems = validate(sh, "install.sh", allow_dev)
    if problems:
        raise PinError("; ".join(problems))
    ps = {"trust_set": sh["trust_set"], "min_generated_at": sh["min_generated_at"]}
    return replace_block(sh_text, render_sh(sh), "install.sh"), replace_block(ps1_text, render_ps1(ps), "install.ps1")


def self_test() -> int:
    sh_text, ps_text = SH.read_text(encoding="utf-8"), PS1.read_text(encoding="utf-8")
    problems = check(sh_text, ps_text)
    if problems:
        print("self-test: the real installers fail:", *problems, sep="\n  ")
        return 1
    ok = "k1:" + "a" * 64
    other = "k2:" + "b" * 64
    cases = []
    # set then check round-trips, and rendering is idempotent
    new_sh, new_ps = apply(sh_text, ps_text, {
        "trust_set": [ok, other], "verifier_sha": {"linux-x86_64": "c" * 64},
        "min_generated_at": "2026-10-19T00:00:00Z"})
    assert check(new_sh, new_ps) == [], check(new_sh, new_ps)
    # --require-verifier: an empty verifier pin fails, a fully pinned set passes
    empty_sh, empty_ps = apply(sh_text, ps_text, {"verifier_sha": {"linux-x86_64": "c" * 64, "macos-aarch64": ""}})
    assert check(empty_sh, empty_ps, require_verifier=True), "one empty verifier hash must fail --require-verifier"
    full_sh, full_ps = apply(sh_text, ps_text, {"verifier_sha": {"linux-x86_64": "c" * 64, "macos-aarch64": "d" * 64}})
    assert check(full_sh, full_ps, require_verifier=True) == [], check(full_sh, full_ps, require_verifier=True)
    # --require-floor: an empty floor fails in either installer, a set one passes
    assert check(sh_text, ps_text, require_floor=True), "an empty floor must fail --require-floor"
    floored_sh, floored_ps = apply(sh_text, ps_text, {"min_generated_at": "2026-10-19T00:00:00Z"})
    assert check(floored_sh, floored_ps, require_floor=True) == [], check(floored_sh, floored_ps, require_floor=True)
    assert check(floored_sh, floored_ps.replace("MinManifestGeneratedAt = '2026-10-19T00:00:00Z'", "MinManifestGeneratedAt = ''"), require_floor=True)
    assert apply(new_sh, new_ps, {})[0] == new_sh
    assert parse_sh(new_sh)["trust_set"] == [ok, other] and parse_ps1(new_ps)["trust_set"] == [ok, other]
    assert new_sh.replace(render_sh(parse_sh(new_sh)), "") != new_sh
    # only the block changes
    s, e = _block(sh_text, "x")
    assert new_sh[:s] == sh_text[:s] and new_sh[s:].endswith(sh_text[e:])
    mutants = {
        "dev key pinned": lambda a, b: (a.replace(re.search(r'TRUST_SET="[^"]*"', a).group(0), f'TRUST_SET="dev:{DEV_KEY}"'), b),
        "trust sets differ": lambda a, b: (new_sh, b),
        "floor differs": lambda a, b: (a.replace('MIN_MANIFEST_GENERATED_AT=""', 'MIN_MANIFEST_GENERATED_AT="2026-01-01T00:00:00Z"'), b),
        "bad floor format": lambda a, b: (a.replace('MIN_MANIFEST_GENERATED_AT=""', 'MIN_MANIFEST_GENERATED_AT="yesterday"'), b.replace("MinManifestGeneratedAt = ''", "MinManifestGeneratedAt = 'yesterday'")),
        "short key": lambda a, b: (re.sub(r'TRUST_SET="([^:]*):[0-9a-f]+', r'TRUST_SET="\1:abcd', a, count=1), b),
        "uppercase key": lambda a, b: (re.sub(r'(TRUST_SET="[^:]*:)([0-9a-f])', lambda m: m.group(1) + m.group(2).upper(), a, count=1), b),
        "extra line in block": lambda a, b: (a.replace("# <<< PINS <<<", 'EVIL="x"\n# <<< PINS <<<'), b),
        "command substitution": lambda a, b: (re.sub(r'VERIFIER_SHA_linux_x86_64="[^"]*"', 'VERIFIER_SHA_linux_x86_64="$(id)"', a), b),
        "missing end marker": lambda a, b: (a.replace("# <<< PINS <<<", "# end"), b),
        "two blocks": lambda a, b: (a + "\n# >>> PINS >>>\n# <<< PINS <<<\n", b),
        "wrong verifier base": lambda a, b: (a.replace("releases/download/verifier-1", "releases/download/evil"), b),
        "ps1 extra statement": lambda a, b: (a, b.replace("# <<< PINS <<<", "iex 'x'\n# <<< PINS <<<")),
        "ps1 empty trust set": lambda a, b: (a, re.sub(r"\$script:TrustSet = @\([^)]*\)", "$script:TrustSet = @()", b)),
        "duplicate key id": lambda a, b: (a.replace('TRUST_SET="', f'TRUST_SET="x:{"c" * 64} x:{"d" * 64} ', 1), b),
    }
    failed = 0
    for name, mutate in mutants.items():
        a, b = mutate(sh_text, ps_text)
        if not check(a, b):
            print(f"self-test FAILED: mutation '{name}' was not caught")
            failed += 1
    try:
        apply(sh_text, ps_text, {"trust_set": ["x:" + DEV_KEY]})
        print("self-test FAILED: set accepted the development key")
        failed += 1
    except PinError:
        pass
    print(f"pins self-test: {len(mutants) + 1 - failed}/{len(mutants) + 1} checks caught")
    return 1 if failed else 0


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    if not argv or argv[0] not in ("show", "check", "set"):
        print(__doc__, file=sys.stderr)
        return 2
    sh_text, ps_text = SH.read_text(encoding="utf-8"), PS1.read_text(encoding="utf-8")
    cmd, rest = argv[0], argv[1:]
    if cmd == "show":
        print(render_sh(parse_sh(sh_text)), end="")
        print(render_ps1(parse_ps1(ps_text)), end="")
        return 0
    if cmd == "check":
        problems = check(sh_text, ps_text, allow_dev="--allow-dev-key" in rest,
                         require_verifier="--require-verifier" in rest,
                         require_floor="--require-floor" in rest)
        for p in problems:
            print(f"error: {p}", file=sys.stderr)
        print("pins: ok" if not problems else "pins: FAILED")
        return 1 if problems else 0
    updates: dict = {"verifier_sha": {}}
    it = iter(rest)
    for flag in it:
        value = next(it, None)
        if value is None:
            print(f"{flag} needs a value", file=sys.stderr)
            return 2
        if flag == "--trust-set":
            updates["trust_set"] = value.split()
        elif flag == "--verifier-sha":
            target, _, sha = value.partition("=")
            if target not in TARGETS:
                print(f"unknown verifier target {target!r}", file=sys.stderr)
                return 2
            updates["verifier_sha"][target] = sha
        elif flag == "--verifier-base":
            updates["verifier_base"] = value
        elif flag == "--min-generated-at":
            updates["min_generated_at"] = value
        else:
            print(f"unknown option {flag}", file=sys.stderr)
            return 2
    try:
        new_sh, new_ps = apply(sh_text, ps_text, updates)
    except PinError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 1
    SH.write_text(new_sh, encoding="utf-8")
    PS1.write_text(new_ps, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
