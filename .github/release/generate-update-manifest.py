#!/usr/bin/env python3
"""Generate, validate, and sign the per-channel update manifest that
`automatic-updates` clients consume.

The manifest schema is defined by the daemon client, not here — see
`crates/yadorilink-daemon/src/update/manifest.rs` (`UpdateManifest` /
`ReleaseEntry` / `SignedManifestEnvelope`). Signing reuses the maintainer
tool `yadorilink-sign-manifest` (same crate) so the signed bytes are exactly
what the client's `verify_and_parse` accepts: an Ed25519 signature over the
literal manifest body bytes, carried in an envelope alongside the key id.

Subcommands:

  generate  Build a fresh channel manifest from an artifacts spec (used by the
            release/nightly pipeline once artifacts are built + signed).

  resign    Take an already-published signed manifest, change ONLY the
            operator-controlled fields (rollout percentage, kill-switch,
            minimum supported version) on its entries, and re-sign — leaving
            the referenced artifacts untouched. This is the
            rollout/kill-switch/min-version operator path: no artifact rebuild.

  assemble  Build the UNSIGNED manifest body and appcast body data as a pure function of a
            channel ledger, its release records, trust-chain.json and --generated-at (see
            channel_ledger.py). Never signs and never reads a key.

  floor     Print the first release of the current protocol generation (from
            docs/CUTOVER.md). `generate` and `resign` refuse a minimum_supported_version
            below it, and refuse to run at all when the current generation has no
            recorded first release: that is how a protocol-generation bump release
            is forced to publish the cutover marker.

Signing is gated on the key being present: with MANIFEST_SIGNING_KEY set the
output is a signed envelope; without it the tool writes the unsigned body and
exits non-zero for `generate --require-signature` (release), or warns and
writes the body for local/dry runs.

Artifacts spec (generate --artifacts FILE), JSON:
  [
    {"platform":"macos","arch":"aarch64","install_source":"standalone",
     "artifact_url":"https://.../yadorilink-macos.pkg",
     "artifact_sha256":"<64 hex>", "artifact_size":<bytes>, "artifact_publisher_identity":"Developer ID Installer: ..."},
    ...
  ]
The shared fields (channel, version, minimum_supported_version,
rollout_percentage, kill_switch, mandatory, release_notes_url) are applied to
every entry.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import channel_ledger  # noqa: E402
import release_channels  # noqa: E402

MANIFEST_SCHEMA_VERSION = 2
CHANNELS = release_channels.CHANNELS
SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")

# Fields the client requires with no serde default — must always be present.
REQUIRED_ENTRY_FIELDS = (
    "channel",
    "platform",
    "arch",
    "install_source",
    "version",
    "minimum_supported_version",
    "artifact_url",
    "artifact_sha256",
    "artifact_size",
)


def parse_semver(raw: str) -> tuple[int, int, int, str]:
    """Match the client's tolerant-of-leading-v strict semver parse
    (crates/.../manifest.rs parse_semver). Returns a comparable tuple; the
    prerelease string is compared lexically only for equal core versions,
    which is enough for the min<=version validation we do here."""
    s = raw[1:] if raw.startswith("v") else raw
    m = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+].*)?", s)
    if not m:
        raise ValueError(f"not strict semver: {raw!r}")
    pre = s[m.end(3):]
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), pre)


def version_le(a: str, b: str) -> bool:
    """a <= b on the semver core (prerelease ignored for the min-version
    gate, which only needs 'minimum not above published core version')."""
    ca = parse_semver(a)[:3]
    cb = parse_semver(b)[:3]
    return ca <= cb


# The peer-facing protocol generation is the pair (PROTOCOL_VERSION, RPC_VERSION). The signed
# manifest's `minimum_supported_version` is the single marker of a cutover: a release of a
# generation must publish a minimum at or above that generation's first release, so older builds
# are told an update is required. docs/CUTOVER.md records the first release of each generation:
#
#     - Generation PROTOCOL_VERSION = 4, RPC_VERSION = 2: first release 0.0.0
GENERATION_LINE = re.compile(
    r"^\s*[-*]\s+Generation\s+PROTOCOL_VERSION\s*=\s*(\d+)\s*,\s*RPC_VERSION\s*=\s*(\d+)\s*:"
    r"\s*first release\s+(\d+\.\d+\.\d+)\b"
)


class FloorError(Exception):
    """The current protocol generation has no recorded first release."""


def _cutover_guard():
    spec = importlib.util.spec_from_file_location(
        "check_cutover_note", Path(__file__).resolve().parents[1] / "checks" / "check-cutover-note.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def generation_floor(root: Path) -> str:
    """The first release of the protocol generation `root` is at, from docs/CUTOVER.md.

    Fails closed: if the current (PROTOCOL_VERSION, RPC_VERSION) pair has no recorded first
    release, no release of it can be published, because nothing says which clients it cuts off."""
    guard = _cutover_guard()
    try:
        current = tuple(
            guard.current_value(root, name, guard.GATES[name])
            for name in ("PROTOCOL_VERSION", "RPC_VERSION")
        )
    except (OSError, ValueError) as ex:
        raise FloorError(str(ex)) from ex
    notes = root / "docs/CUTOVER.md"
    if not notes.is_file():
        raise FloorError("docs/CUTOVER.md is missing; it records each generation's first release")
    for line in notes.read_text(encoding="utf-8").splitlines():
        m = GENERATION_LINE.match(line)
        if m and (int(m.group(1)), int(m.group(2))) == current:
            return m.group(3)
    raise FloorError(
        f"docs/CUTOVER.md has no `- Generation PROTOCOL_VERSION = {current[0]}, RPC_VERSION = "
        f"{current[1]}: first release <version>` line; record the first release of this protocol "
        "generation (the release that carries it) before publishing"
    )


def build_manifest(shared: dict, artifacts: list[dict], generated_at: str) -> dict:
    releases = []
    for a in artifacts:
        entry = {
            "channel": shared["channel"],
            "platform": a["platform"],
            "arch": a["arch"],
            "install_source": a["install_source"],
            "version": shared["version"],
            "minimum_supported_version": shared["minimum_supported_version"],
            "rollout_percentage": int(shared["rollout_percentage"]),
            "kill_switch": bool(shared["kill_switch"]),
            "mandatory": bool(shared["mandatory"]),
            "artifact_url": a["artifact_url"],
            "artifact_sha256": a["artifact_sha256"].lower(),
            "artifact_size": int(a["artifact_size"]),
            "artifact_publisher_identity": a.get("artifact_publisher_identity", ""),
            "release_notes_url": shared.get("release_notes_url", ""),
        }
        # The engine's declared state database range, when the artifact record carries it.
        for key in ("state_schema_version", "state_schema_min_readable", "sparkle_build"):
            if key in a:
                entry[key] = int(a[key])
        releases.append(entry)
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generated_at": generated_at,
        "expires_at": channel_ledger.expires_at_for(generated_at),
        "releases": releases,
    }


def validate_manifest(manifest: dict, check_urls: bool, floor: str | None = None,
                      snapshot: bool = False, require_sparkle_build: bool = False) -> list[str]:
    """Field/consistency validation that must pass BEFORE signing
    (spec: 'Manifest is validated before signing'). Returns a list of
    problems; empty means valid. With `floor` (the first release of the protocol generation
    being published) every entry's minimum_supported_version must be at least the floor.
    The live channel manifest must carry a valid expires_at; with `snapshot` (a per-version
    manifest, published once and kept, never expired) it is accepted with or without one."""
    problems: list[str] = []
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        problems.append(
            f"schema_version must be {MANIFEST_SCHEMA_VERSION}, got {manifest.get('schema_version')!r}"
        )
    generated_at = manifest.get("generated_at")
    expires_at = manifest.get("expires_at")
    stamp = channel_ledger.GENERATED_AT_RE
    if not (isinstance(generated_at, str) and stamp.fullmatch(generated_at)):
        problems.append(f"generated_at {generated_at!r} must be YYYY-MM-DDTHH:MM:SSZ")
    elif snapshot:
        pass
    elif not (isinstance(expires_at, str) and stamp.fullmatch(expires_at)):
        problems.append(f"expires_at {expires_at!r} is required and must be YYYY-MM-DDTHH:MM:SSZ")
    elif expires_at <= generated_at:
        problems.append(f"expires_at {expires_at} must be after generated_at {generated_at}")
    releases = manifest.get("releases")
    if not isinstance(releases, list) or not releases:
        problems.append("releases must be a non-empty array")
        return problems

    for i, e in enumerate(releases):
        where = f"releases[{i}]"
        for f in REQUIRED_ENTRY_FIELDS:
            if not e.get(f):
                problems.append(f"{where}.{f} is required and non-empty")
        build = e.get("sparkle_build")
        if e.get("install_source") == "app_bundle":
            valid = isinstance(build, int) and not isinstance(build, bool) and build > 0
            if build is None and not require_sparkle_build:
                pass
            elif not valid:
                problems.append(f"{where}.sparkle_build must be a positive integer for app_bundle")
        elif build is not None:
            problems.append(f"{where}.sparkle_build is only carried by app_bundle entries")
        ch = e.get("channel")
        if ch not in CHANNELS:
            problems.append(f"{where}.channel {ch!r} is not one of {CHANNELS}")
        roll = e.get("rollout_percentage", 0)
        if not isinstance(roll, int) or not (0 <= roll <= 100):
            problems.append(f"{where}.rollout_percentage {roll!r} must be an int in 0..100")
        size = e.get("artifact_size")
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            problems.append(f"{where}.artifact_size must be a positive integer byte count")
        sha = e.get("artifact_sha256", "")
        if not SHA256_RE.fullmatch(sha):
            problems.append(f"{where}.artifact_sha256 must be 64 lowercase hex chars")
        ver = e.get("version", "")
        minv = e.get("minimum_supported_version", "")
        try:
            if ver and minv and not version_le(minv, ver):
                problems.append(
                    f"{where}.minimum_supported_version {minv} exceeds version {ver}"
                )
            if floor is not None:
                if minv and not version_le(floor, minv):
                    problems.append(
                        f"{where}.minimum_supported_version {minv} is below {floor}, the first "
                        "release of this protocol generation; older builds must be told an update "
                        "is required"
                    )
                if ver and not version_le(floor, ver):
                    problems.append(
                        f"{where}.version {ver} is older than {floor}, the first release of the "
                        "protocol generation this tree carries"
                    )
        except ValueError as ex:
            problems.append(f"{where}: {ex}")
        if check_urls:
            url = e.get("artifact_url", "")
            if not _url_resolves(url, sha):
                problems.append(f"{where}.artifact_url does not resolve (or checksum sidecar missing): {url}")
    return problems


def _url_resolves(url: str, sha256: str) -> bool:
    """Best-effort reachability + checksum-sidecar check. Only run under
    --check-urls (network); kept out of the default path so the tool is
    testable offline."""
    import urllib.request

    def head_ok(u: str) -> bool:
        try:
            req = urllib.request.Request(u, method="HEAD")
            with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310
                return 200 <= r.status < 400
        except Exception:
            return False

    if not head_ok(url):
        return False
    # The repo's release convention publishes a `<artifact>.sha256` sidecar;
    # confirm it exists and matches when reachable.
    try:
        with urllib.request.urlopen(url + ".sha256", timeout=20) as r:  # noqa: S310
            sidecar = r.read().decode().split()[0].strip().lower()
            if SHA256_RE.fullmatch(sidecar):
                return sidecar == sha256.lower()
    except Exception:
        pass
    return True  # sidecar unavailable is not fatal; HEAD already passed


def sign_or_write(manifest: dict, out_path: Path, *, require_signature: bool,
                  sign_tool: str, key_id: str, trust_chain: str) -> int:
    """Write the manifest body and, if MANIFEST_SIGNING_KEY is set, sign it
    into a `SignedManifestEnvelope` via `yadorilink-sign-manifest`. The signer
    reads the body bytes verbatim, so the signature covers exactly what the
    client re-reads."""
    body_json = channel_ledger.render_body(manifest)

    key = os.environ.get("MANIFEST_SIGNING_KEY", "").strip()
    if not key:
        msg = "MANIFEST_SIGNING_KEY is not set; cannot sign the manifest."
        if require_signature:
            print(f"error: {msg}", file=sys.stderr)
            return 3
        print(f"warning: {msg} Writing UNSIGNED body to {out_path}.", file=sys.stderr)
        out_path.write_text(body_json, encoding="utf-8", newline="\n")
        return 0

    with tempfile.TemporaryDirectory() as td:
        body_file = Path(td) / "manifest-body.json"
        body_file.write_text(body_json, encoding="utf-8", newline="\n")
        cmd = [
            sign_tool, "sign",
            "--key-hex", key,
            "--key-id", key_id,
            "--manifest", str(body_file),
            "--out", str(out_path),
            # Published on the envelope; clients verify every record.
            "--trust-chain", trust_chain,
        ]
        # Never echo the key. Pass it as an argv element (already avoided in
        # logs by not printing cmd verbatim).
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
        except FileNotFoundError:
            print(
                f"error: signer not found: {sign_tool}. Build it first, e.g.\n"
                f"  cargo build --release -p yadorilink-daemon --bin yadorilink-sign-manifest",
                file=sys.stderr,
            )
            return 4
        except subprocess.CalledProcessError as ex:
            print(f"error: yadorilink-sign-manifest failed (exit {ex.returncode})", file=sys.stderr)
            return ex.returncode
    print(f"wrote signed manifest envelope to {out_path} (key_id={key_id})")
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    artifacts = json.loads(Path(args.artifacts).read_text(encoding="utf-8"))
    if not isinstance(artifacts, list) or not artifacts:
        print("error: --artifacts must be a non-empty JSON array", file=sys.stderr)
        return 2
    if args.channel not in CHANNELS:
        print(f"error: --channel must be one of {CHANNELS}", file=sys.stderr)
        return 2

    generated_at = args.generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    shared = {
        "channel": args.channel,
        "version": args.version,
        "minimum_supported_version": args.min_version,
        "rollout_percentage": args.rollout_percentage,
        "kill_switch": args.kill_switch,
        "mandatory": args.mandatory,
        "release_notes_url": args.release_notes_url,
    }
    manifest = build_manifest(shared, artifacts, generated_at)

    try:
        floor = generation_floor(Path(args.repo_root))
    except FloorError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 6
    problems = validate_manifest(manifest, check_urls=args.check_urls, floor=floor)
    if problems:
        print("manifest validation failed:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 5

    return sign_or_write(
        manifest, Path(args.out),
        require_signature=args.require_signature,
        sign_tool=args.sign_tool, key_id=args.key_id, trust_chain=args.trust_chain,
    )


def cmd_assemble(args: argparse.Namespace) -> int:
    """Unsigned manifest body + appcast body data from the ledger. Pure: no clock, no key."""
    ledger_path = Path(args.ledger)
    try:
        floor = generation_floor(Path(args.repo_root))
        ledger = channel_ledger.load_json(ledger_path.read_text(encoding="utf-8"), str(ledger_path))
        previous = None
        if args.previous_ledger:
            previous = channel_ledger.load_json(
                Path(args.previous_ledger).read_text(encoding="utf-8"), args.previous_ledger)
        source = None
        source_path = args.promotion_source_ledger
        if not source_path and (source_channel := release_channels.PROMOTES_FROM.get(ledger_path.stem)):
            # A channel that promotes always reads its source from the sibling ledger, as the
            # publisher does (plan.load_inputs): no caller can forget the argument.
            source_path = str(ledger_path.with_name(f"{source_channel}.json"))
        if source_path and (args.promotion_source_ledger or Path(source_path).is_file()):
            source = channel_ledger.load_json(Path(source_path).read_text(encoding="utf-8"), source_path)
        records = channel_ledger.load_records(Path(args.records_dir))
        chain_text = Path(args.trust_chain).read_text(encoding="utf-8")
        plan = channel_ledger.assemble(
            ledger, records, chain_text, args.generated_at, floor=floor, previous_ledger=previous,
            served_appcast_version=args.served_appcast_version, ledger_stem=ledger_path.stem,
            promotion_source=source,
        )
        # Belt and braces: the body must also pass the generic manifest validation.
        problems = validate_manifest(
            json.loads(plan["manifest_body"]), check_urls=False, floor=floor,
            require_sparkle_build=True)
        if problems:
            raise channel_ledger.LedgerError(problems)
    except FloorError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 6
    except channel_ledger.LedgerError as ex:
        print("ledger validation failed:", file=sys.stderr)
        for p in ex.problems:
            print(f"  - {p}", file=sys.stderr)
        return 5
    except OSError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 2
    Path(args.out_body).write_text(plan["manifest_body"], encoding="utf-8", newline="\n")
    if args.out_appcast:
        Path(args.out_appcast).write_text(
            json.dumps(plan["appcast"], indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(f"manifest_body_sha256={plan['manifest_body_sha256']}")
    print(f"trust_chain_sha256={plan['trust_chain_sha256']}")
    return 0


def cmd_check_records_immutable(args: argparse.Namespace) -> int:
    """Refuse an edit or deletion of a release record that already exists at --base-ref."""
    def git(*a: str) -> bytes:
        return subprocess.run(["git", "-C", args.repo_root, *a], check=True, capture_output=True).stdout

    rel = ".github/channels/releases"
    names = [n for n in git("ls-tree", "--name-only", args.base_ref, f"{rel}/").decode().split("\n")
             if n.endswith(".json")]
    base = {Path(n).name: git("show", f"{args.base_ref}:{n}") for n in names}
    head_dir = Path(args.repo_root) / rel
    head = {p.name: p.read_bytes() for p in head_dir.glob("*.json")} if head_dir.is_dir() else {}
    problems = channel_ledger.check_records_immutable(base, head)
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    return 5 if problems else 0


def cmd_floor(args: argparse.Namespace) -> int:
    """Print the first release of the current protocol generation: the lowest
    minimum_supported_version a release of it may publish."""
    try:
        print(generation_floor(Path(args.repo_root)))
    except FloorError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 6
    return 0


def cmd_resign(args: argparse.Namespace) -> int:
    """Operator control path: mutate rollout / kill-switch / min-version on an
    existing published manifest and re-sign, preserving artifact refs."""
    envelope_or_body = json.loads(Path(args.input).read_text(encoding="utf-8"))
    # Accept either a signed envelope (has manifest_json) or a raw body.
    if isinstance(envelope_or_body, dict) and "manifest_json" in envelope_or_body:
        manifest = json.loads(envelope_or_body["manifest_json"])
    else:
        manifest = envelope_or_body

    for e in manifest.get("releases", []):
        if args.rollout_percentage is not None:
            e["rollout_percentage"] = int(args.rollout_percentage)
        if args.kill_switch is not None:
            e["kill_switch"] = bool(args.kill_switch)
        if args.min_version is not None:
            e["minimum_supported_version"] = args.min_version
    # Refresh the generation timestamp so consumers can see the change.
    manifest["generated_at"] = args.generated_at or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    manifest["expires_at"] = channel_ledger.expires_at_for(manifest["generated_at"])

    try:
        floor = generation_floor(Path(args.repo_root))
    except FloorError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 6
    problems = validate_manifest(manifest, check_urls=False, floor=floor)
    if problems:
        print("re-signed manifest validation failed:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 5

    return sign_or_write(
        manifest, Path(args.out),
        require_signature=args.require_signature,
        sign_tool=args.sign_tool, key_id=args.key_id, trust_chain=args.trust_chain,
    )


def _add_common_signing_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--out", required=True, help="output path for the signed envelope")
    p.add_argument("--sign-tool", default=os.environ.get("YADORILINK_SIGN_MANIFEST", "yadorilink-sign-manifest"),
                   help="path to the yadorilink-sign-manifest binary")
    p.add_argument("--key-id", default=os.environ.get("MANIFEST_SIGNING_KEY_ID", "yadorilink-beta-dev-2026"),
                   help="signing key id; MUST be in the clients' trust set (the compiled-in key "
                        "extended by the trust chain)")
    p.add_argument("--trust-chain", default=str(Path(__file__).with_name("trust-chain.json")),
                   help="trust chain (rotation/revocation records) to publish on the envelope")
    p.add_argument("--require-signature", action="store_true",
                   help="fail (non-zero) instead of writing an unsigned body when the key is absent")
    p.add_argument("--generated-at", default=None, help="RFC3339 timestamp; defaults to now (UTC)")
    p.add_argument("--repo-root", default=str(ROOT),
                   help="tree whose docs/CUTOVER.md and protocol constants define the generation floor")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="build + validate + sign a fresh channel manifest")
    g.add_argument("--channel", required=True, choices=CHANNELS)
    g.add_argument("--version", required=True)
    g.add_argument("--min-version", required=True, dest="min_version")
    g.add_argument("--artifacts", required=True, help="JSON file of per-platform artifact entries")
    g.add_argument("--rollout-percentage", type=int, default=100)
    g.add_argument("--kill-switch", action="store_true")
    g.add_argument("--mandatory", action="store_true")
    g.add_argument("--release-notes-url", default="")
    g.add_argument("--check-urls", action="store_true", help="HEAD each artifact_url (+ .sha256) before signing")
    _add_common_signing_args(g)
    g.set_defaults(func=cmd_generate)

    r = sub.add_parser("resign", help="operator: change rollout/kill-switch/min-version and re-sign")
    r.add_argument("--input", required=True, help="existing signed envelope or manifest body")
    r.add_argument("--rollout-percentage", type=int, default=None)
    kill = r.add_mutually_exclusive_group()
    kill.add_argument("--kill-switch", dest="kill_switch", action="store_const", const=True, default=None)
    kill.add_argument("--clear-kill-switch", dest="kill_switch", action="store_const", const=False)
    r.add_argument("--min-version", default=None, dest="min_version")
    _add_common_signing_args(r)
    r.set_defaults(func=cmd_resign)

    a = sub.add_parser("assemble", help="unsigned manifest body + appcast data from the channel ledger")
    a.add_argument("--ledger", required=True, help=".github/channels/<channel>.json")
    a.add_argument("--records-dir", required=True, help=".github/channels/releases")
    a.add_argument("--previous-ledger", default=None,
                   help="the ledger this one replaces (e.g. from the base branch); enables the "
                        "promotion, yank and live-minimum rules")
    a.add_argument("--promotion-source-ledger", default=None,
                   help="the ledger of the channel this one promotes from (default: the sibling <source>.json "
                        "of a channel that promotes; a missing one is refused by the ledger rules)")
    a.add_argument("--served-appcast-version", default=None,
                   help="app_bundle version currently in the served appcast")
    a.add_argument("--trust-chain", default=str(Path(__file__).with_name("trust-chain.json")))
    a.add_argument("--generated-at", required=True, help="YYYY-MM-DDTHH:MM:SSZ (never defaulted)")
    a.add_argument("--out-body", required=True)
    a.add_argument("--out-appcast", default=None)
    a.add_argument("--repo-root", default=str(ROOT))
    a.set_defaults(func=cmd_assemble)

    c = sub.add_parser("check-records-immutable", help="refuse edits to merged release records")
    c.add_argument("--base-ref", required=True)
    c.add_argument("--repo-root", default=str(ROOT))
    c.set_defaults(func=cmd_check_records_immutable)

    f = sub.add_parser("floor", help="print the first release of the current protocol generation")
    f.add_argument("--repo-root", default=str(ROOT))
    f.set_defaults(func=cmd_floor)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
