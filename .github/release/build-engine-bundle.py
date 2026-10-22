#!/usr/bin/env python3
"""Build and verify the per-channel engine bundle published on GitHub Releases.

  build-engine-bundle.py release-id --channel CH --target T --public-commit-sha SHA
        [--build-config KEY=VALUE ...]
  build-engine-bundle.py build  --channel CH --target T --expect-release-id ID
        --root KEY=DIR [--root KEY=DIR ...] --public-commit-sha SHA
        --repository OWNER/NAME --release-tag TAG --out-dir DIR [options]
  build-engine-bundle.py provenance ZIP --public-commit-sha SHA --repository OWNER/NAME
        --attestation-json FILE --out-dir DIR [--target T] [--expect-zip-sha256 HEX] [--gate NAME ...] [--sign-cmd CMD]
        [--release]
  build-engine-bundle.py lock ZIP --target T --public-commit-sha SHA --out-dir DIR [--expect-zip-sha256 HEX]
        [--release]
  build-engine-bundle.py verify ZIP [--target T] [--expect-zip-sha256 HEX]
        [--lock engine.lock] [--release]
  build-engine-bundle.py --self-test

--target names one of the platform layouts in LAYOUTS (documented in
.github/release/engine-bundle-layout.md); each layout maps bundle paths to
files under named source roots given with --root. The bundle holds exactly the
layout's files plus LICENSE, SOURCE.txt, THIRD-PARTY-LICENSES, SHA256SUMS and
engine-identity.json. SHA256SUMS
lists every file except itself and engine-identity.json; the identity's
`bundle_sha256` is the SHA-256 of SHA256SUMS and its `artifact_sha256` is the
daemon's SHA-256. Identity schema: .github/checks/engine-identity.schema.json.

`release-id` prints `<public_commit_sha>:<build_config_digest>`, which the release build exports as
YADORILINK_RELEASE_ID (and the channel as YADORILINK_CHANNEL) before compiling, so every program
names its own build. `build --expect-release-id` refuses settings that give another id and any
program of the layout (LAYOUTS "programs") that does not contain the id.

`build` runs in an unprivileged job (no secrets) and writes the zip and its
`.sha256`. `provenance ZIP` runs in the protected release job: it first
verifies the zip (hashes only), then writes `<zip>.provenance.json`, a
statement binding the public commit, the CI run, the gates that passed, the
zip's SHA-256 and the identity of its GitHub build-provenance attestation. That
attestation is checked first by `gh attestation verify` (pinned to this
repository, its release workflow and the commit); `--attestation-json` is that
command's JSON output, and provenance refuses it unless a result has a subject
digest equal to the zip's SHA-256, a signer workflow that is this repository's
release.yml and a source commit equal to --public-commit-sha. It proves where
the bytes came from, not that the generators that built them were harmless. Signing is optional: --sign-cmd names a command that is run with
the statement's path and must write `<statement>.sig`; no key material is
handled here.

`verify` only hashes and compares; it never executes anything from the bundle.
`verify --release` (release and production paths) also refuses a development
bundle. The identity's `kind` follows the channel: channel dev is kind dev, any
other channel is kind release. A kind release bundle must be built with the
release trust root enforced.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CHECKS = ROOT / ".github" / "checks"
PROVENANCE_SCHEMA = "yadorilink-engine-provenance/1"
EXCLUDED_FROM_SUMS = ("SHA256SUMS", "engine-identity.json")
API_RE = re.compile(r"pub const PROVIDER_HOST_API_VERSION: u32 = (\d+);")
ZIP_DATE = (2020, 1, 1, 0, 0, 0)

# One layout per platform. `programs`: the files built from the engine sources, each of which must
# embed the release identity (YADORILINK_RELEASE_ID). `files`: (bundle path, source root, path under the
# root, executable). `globs`: (bundle directory, source root, directory under
# the root, file suffix); at least one match is required. Roots:
#   bin        cargo release output directory (executables, static library)
#   shell      Windows shell extension release output directory
#   generated  generated Swift binding directory
#   csharp     generated C# binding directory (generate-csharp-binding.sh --out)
#   ipc        the ipc-proto crate directory
_BIN = [("yadorilink", "bin"), ("yadorilink-daemon", "bin")]
LAYOUTS = {
    "linux-x86_64": {
        "daemon": "yadorilink-daemon",
        "programs": ["yadorilink", "yadorilink-daemon"],
        "files": [(n, r, n, True) for n, r in _BIN],
        "globs": [],
    },
    "windows-x86_64": {
        "daemon": "yadorilink-daemon.exe",
        "programs": ["yadorilink.exe", "yadorilink-daemon.exe", "yadorilink_client_ffi.dll"],
        "files": [
            ("yadorilink.exe", "bin", "yadorilink.exe", True),
            ("yadorilink-daemon.exe", "bin", "yadorilink-daemon.exe", True),
            ("yadorilink_shell_ext.dll", "shell", "yadorilink_shell_ext.dll", True),
            ("yadorilink-cfapi-host.exe", "shell", "yadorilink-cfapi-host.exe", True),
            # The client facade library, built under this name by cargo, and
            # the C# generated from it.
            ("yadorilink_client_ffi.dll", "bin", "yadorilink_client_ffi.dll", True),
            ("csharp/BINDING-NOTES.md", "csharp", "BINDING-NOTES.md", False),
        ],
        "globs": [("csharp/Generated", "csharp", "Generated", ".cs")],
    },
    "macos-aarch64": {
        "daemon": "bin/yadorilink-daemon",
        "programs": ["bin/yadorilink", "bin/yadorilink-daemon", "lib/libyadorilink_client_ffi.a"],
        "files": [
            ("bin/yadorilink", "bin", "yadorilink", True),
            ("bin/yadorilink-daemon", "bin", "yadorilink-daemon", True),
            ("lib/libyadorilink_client_ffi.a", "bin", "libyadorilink_client_ffi.a", False),
            ("swift/Generated/YadoriLinkCore.swift", "generated", "YadoriLinkCore.swift", False),
            ("swift/Generated/YadoriLinkFFI.swift", "generated", "YadoriLinkFFI.swift", False),
            ("swift/Generated/include/module.modulemap", "generated", "include/module.modulemap", False),
            ("ipc-proto/proto/shellipc.proto", "ipc", "proto/shellipc.proto", False),
            ("ipc-proto/src/framing.rs", "ipc", "src/framing.rs", False),
        ],
        "globs": [("swift/Generated/include", "generated", "include", ".h")],
    },
}
# Present in every bundle whatever the platform: the licence of the binaries,
# the pointer to their corresponding source, the third-party licence notice
# for the crates compiled into them, and the checksums and identity.
NOTICE_FILES = ("LICENSE", "SOURCE.txt", "THIRD-PARTY-LICENSES")
RESERVED = (*NOTICE_FILES, "SHA256SUMS", "engine-identity.json")
# The client facade library was named yadorilink_apple_ffi until the ABI
# rename. Its symbols and API checksums differ from the current library's, so
# a bundle carrying anything of that name is a stale or mixed build.
RETIRED_LIBRARY_NAME = "yadorilink_apple_ffi"


def safe_path(name: str) -> bool:
    parts = name.split("/")
    return all(p and p not in (".", "..") and not p.startswith(".") and "\\" not in p and ":" not in p for p in parts)


def layout_files(layout: dict, roots: dict[str, Path]) -> dict[str, tuple[bytes, bool]]:
    """Collect the layout's files as {bundle path: (bytes, executable)}."""
    found: dict[str, tuple[bytes, bool]] = {}

    def take(dest: str, root: str, rel: str, executable: bool):
        if root not in roots:
            raise SystemExit(f"error: missing --root {root}=DIR")
        path = roots[root] / rel
        if not path.is_file():
            raise SystemExit(f"error: missing {path}")
        found[dest] = (path.read_bytes(), executable)

    for dest, root, rel, executable in layout["files"]:
        take(dest, root, rel, executable)
    for dest_dir, root, rel_dir, suffix in layout["globs"]:
        if root not in roots:
            raise SystemExit(f"error: missing --root {root}=DIR")
        matches = sorted(p.name for p in (roots[root] / rel_dir).glob(f"*{suffix}") if p.is_file())
        if not matches:
            raise SystemExit(f"error: no *{suffix} files in {roots[root] / rel_dir}")
        for name in matches:
            take(f"{dest_dir}/{name}", root, f"{rel_dir}/{name}", False)
    return found


def layout_problems(layout: dict, names: set[str]) -> list[str]:
    """Names (minus the reserved files) must be exactly what the layout lists."""
    fixed = {f[0] for f in layout["files"]}
    problems = [f"bundle is missing {n}" for n in sorted(fixed - names)]
    allowed = set(fixed)
    for dest_dir, _, _, suffix in layout["globs"]:
        matched = {n for n in names if n.startswith(dest_dir + "/") and n.endswith(suffix) and "/" not in n[len(dest_dir) + 1:]}
        if not matched:
            problems.append(f"bundle has no {dest_dir}/*{suffix}")
        allowed |= matched
    retired = {n for n in names if RETIRED_LIBRARY_NAME in n}
    problems += [f"{n} is a retired {RETIRED_LIBRARY_NAME} artifact (stale or mixed build)" for n in sorted(retired)]
    problems += [f"{n} is not part of the layout" for n in sorted(names - allowed - retired)]
    return problems


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), CHECKS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


validator = _load("validate-engine-identity")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def host_api_version(source: Path) -> int:
    match = API_RE.search(source.read_text(encoding="utf-8"))
    if not match:
        raise SystemExit(f"error: PROVIDER_HOST_API_VERSION not found in {source}")
    return int(match.group(1))


def source_notice(repository: str, release_tag: str, public_commit_sha: str, config: dict, config_digest: str, kind: str = "release") -> bytes:
    """SOURCE.txt: where the exact source of this bundle's binaries is. Deterministic."""
    url = f"https://github.com/{repository}"
    lines = [
        "YadoriLink engine bundle: corresponding source",
        "",
        "The programs in this bundle are free software, licensed under the GNU Affero",
        "General Public License, version 3 only (AGPL-3.0-only; the text shipped in",
        "LICENSE). The official applications are distributed under their own terms; see",
        "LICENSING.md in the repository below. The complete corresponding source,",
        "including the scripts that build and package this bundle, is the following",
        "commit of the public repository:",
        "",
        f"  Repository:   {url}",
        f"  Commit:       {public_commit_sha}",
        f"  Source tree:  {url}/tree/{public_commit_sha}",
        f"  Archive:      {url}/archive/{public_commit_sha}.tar.gz",
        f"  Release tag:  {release_tag}",
        "",
        "To obtain it, run:",
        "",
        f"  git clone {url} && git -C {url.rsplit('/', 1)[1]} checkout {public_commit_sha}",
        "",
        "or download the archive above. If the repository is unavailable, ask the",
        "publisher of this bundle for a copy of the source; the request is honoured for",
        "as long as this bundle is offered.",
    ]
    if kind == "dev":
        lines += [
            "",
            "DEVELOPMENT BUNDLE (kind dev): built for development and testing only. It",
            "is not a release, is not signed or notarized, must not be distributed and",
            "is refused by every release and production build path. The repository above",
            "may not be public.",
        ]
    lines += [
        "",
        "How this bundle was built",
        "",
        "  Layout:        .github/release/engine-bundle-layout.md in that commit",
        f"  Build config:  sha256 {config_digest}",
        "                 (build_config_digest in engine-identity.json: the SHA-256 of the",
        "                 canonical JSON of the settings below)",
    ]
    lines += [f"                   {k} = {config[k]}" for k in sorted(config)]
    lines += [
        "",
        "Third-party code",
        "",
        "THIRD-PARTY-LICENSES lists the third-party crates compiled into the programs",
        "of this bundle with the licence text of each. A Windows bundle also carries",
        "csharp/Generated, produced by the uniffi-bindgen-cs generator (MPL-2.0); its",
        "version, source and licence are stated in csharp/BINDING-NOTES.md.",
        "",
    ]
    return "\n".join(lines).encode()


def build_identity(args):
    """(kind, config, config_digest) of a build, known before any binary is built."""
    config = dict(item.split("=", 1) for item in args.build_config)
    kind = "dev" if args.channel == "dev" else "release"
    enforced = "enforce-release-trust-root" in config.get("features", "")
    if kind == "release" and not enforced:
        raise SystemExit("error: a release bundle must be built with the enforce-release-trust-root feature (--build-config features=...)")
    config.update({"channel": args.channel, "target": args.target})
    return kind, config, sha256(canonical(config))


def release_id(args) -> int:
    """Prints the release_id (<public_commit_sha>:<build_config_digest>) the binaries must embed.

    The release build exports it as YADORILINK_RELEASE_ID (with YADORILINK_CHANNEL) before
    compiling, so every program names its own build instead of inferring it from where it is
    installed. `build --expect-release-id` then refuses a bundle whose settings differ.
    """
    if not re.fullmatch(r"[0-9a-f]{40}", args.public_commit_sha):
        raise SystemExit("error: --public-commit-sha must be a 40-hex commit")
    if args.target not in LAYOUTS:
        raise SystemExit(f"error: unknown --target {args.target!r}; layouts: {', '.join(sorted(LAYOUTS))}")
    print(f"{args.public_commit_sha}:{build_identity(args)[2]}")
    return 0


def embeds(binary: bytes, release_id: str) -> bool:
    return release_id.encode() in binary


def build(args) -> int:
    if not re.fullmatch(r"[0-9a-f]{40}", args.public_commit_sha):
        raise SystemExit("error: --public-commit-sha must be a 40-hex commit")
    if args.target not in LAYOUTS:
        raise SystemExit(f"error: unknown --target {args.target!r}; layouts: {', '.join(sorted(LAYOUTS))}")
    layout = LAYOUTS[args.target]
    roots = {}
    for item in args.root:
        key, sep, value = item.partition("=")
        if not sep or not key or key in roots:
            raise SystemExit(f"error: bad or repeated --root {item!r}")
        roots[key] = Path(value)
    collected = layout_files(layout, roots)
    executable = {n for n, (_, x) in collected.items() if x}
    files = {n: data for n, (data, _) in collected.items()}
    daemon = layout["daemon"]
    files["LICENSE"] = Path(args.license).read_bytes()
    notices = Path(args.third_party_licenses).read_bytes()
    if not notices.strip():
        raise SystemExit("error: --third-party-licenses file is empty")
    files["THIRD-PARTY-LICENSES"] = notices

    kind, config, config_digest = build_identity(args)
    expected_id = f"{args.public_commit_sha}:{config_digest}"
    if args.expect_release_id != expected_id:
        raise SystemExit(f"error: the binaries were built to embed {args.expect_release_id} but these settings give {expected_id}")
    for name in layout["programs"]:
        if not embeds(files[name], expected_id):
            raise SystemExit(f"error: {name} does not embed the release identity {expected_id}")
    files["SOURCE.txt"] = source_notice(args.repository, args.release_tag, args.public_commit_sha, config, config_digest, kind)

    sums = "".join(f"{sha256(files[n])}  {n}\n" for n in sorted(files)).encode()
    asset = args.asset_name or f"yadorilink-engine-{args.channel}-{args.target}.zip"
    identity = {
        "public_commit_sha": args.public_commit_sha,
        "engine_api_version": host_api_version(Path(args.api_version_source)),
        "artifact_sha256": sha256(files[daemon]),
        "channel": args.channel,
        "kind": kind,
        "build_config_digest": config_digest,
        "bundle_sha256": sha256(sums),
        "source": {"repository": args.repository, "release_tag": args.release_tag, "asset_name": asset},
    }
    problems = validator.validate(identity, require_source=True)
    if problems:
        raise SystemExit("error: invalid engine identity: " + "; ".join(problems))
    identity_bytes = (json.dumps(identity, indent=2, sort_keys=True) + "\n").encode()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    zip_path = out / asset
    entries = {**files, "SHA256SUMS": sums, "engine-identity.json": identity_bytes}
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, ZIP_DATE)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if name in executable else 0o644) << 16
            z.writestr(info, entries[name])
    zip_sha = sha256(zip_path.read_bytes())

    (out / f"{asset}.sha256").write_text(f"{zip_sha}  {asset}\n")
    print(zip_path)
    return 0


def attestation_identity(path: Path, zip_sha256: str, repository: str, public_sha: str) -> dict:
    """The verified attestation's identity, or SystemExit if none matches.

    `path` is the JSON from `gh attestation verify --format json`. Fails closed:
    the output must hold a result whose subject digest is the zip's SHA-256,
    signed by this repository's release workflow, built from `public_sha`.
    """
    try:
        results = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise SystemExit(f"error: unreadable attestation {path}: {e}")
    if not isinstance(results, list) or not results:
        raise SystemExit("error: no attestation for the bundle")
    signer_prefix = f"https://github.com/{repository}/.github/workflows/release.yml@"
    why = []
    for item in results:
        try:
            result = item["verificationResult"]
            digests = {d.get("digest", {}).get("sha256") for d in result["statement"]["subject"]}
            cert = result["signature"]["certificate"]
            signer, source_sha = cert["buildSignerURI"], cert["sourceRepositoryDigest"]
            source_uri, source_ref = cert["sourceRepositoryURI"], cert["sourceRepositoryRef"]
        except (KeyError, TypeError, AttributeError):
            why.append("malformed result")
            continue
        if zip_sha256 not in digests:
            why.append("subject digest differs from the zip")
        elif not signer.startswith(signer_prefix):
            why.append(f"signer workflow {signer} is not {signer_prefix}*")
        elif source_sha != public_sha:
            why.append("source commit differs from --public-commit-sha")
        elif source_uri != f"https://github.com/{repository}":
            why.append(f"source repository {source_uri} differs")
        else:
            return {
                "signer_workflow": signer,
                "source_repository": source_uri,
                "source_commit": source_sha,
                "source_ref": source_ref,
                "subject_sha256": zip_sha256,
            }
    raise SystemExit("error: no acceptable attestation: " + "; ".join(why))


def provenance(args) -> int:
    """Verify a built zip (hashes only), then write and optionally sign its provenance.

    Runs in the protected release job: the zip is an input from an unprivileged
    job, so it is verified before any statement binds its hash, and nothing
    from it is executed.
    """
    zip_path = Path(args.zip)
    found = verify_zip(zip_path, args.expect_zip_sha256, None, args.target, args.release)
    if found:
        raise SystemExit("error: refusing to attest an unverified bundle: " + "; ".join(found))
    data = zip_path.read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        identity_bytes = z.read("engine-identity.json")
    identity = json.loads(identity_bytes)
    if identity["source"]["asset_name"] != zip_path.name:
        raise SystemExit("error: zip name != identity asset_name")
    if identity["public_commit_sha"] != args.public_commit_sha:
        raise SystemExit("error: identity public_commit_sha != --public-commit-sha")
    zip_sha = sha256(data)
    attestation = attestation_identity(Path(args.attestation_json), zip_sha, args.repository, args.public_commit_sha)
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    asset = zip_path.name
    statement = {
        "attestation": attestation,
        "schema": PROVENANCE_SCHEMA,
        "public_commit_sha": args.public_commit_sha,
        "source": identity["source"],
        "artifact": {"name": asset, "sha256": zip_sha},
        "bundle_sha256": identity["bundle_sha256"],
        "engine_identity_sha256": sha256(identity_bytes),
        "ci": {
            "repository": os.environ.get("GITHUB_REPOSITORY", ""),
            "workflow": os.environ.get("GITHUB_WORKFLOW", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "ref": os.environ.get("GITHUB_REF", ""),
        },
        "gates_passed": sorted(args.gate),
    }
    statement_path = out / f"{asset}.provenance.json"
    statement_path.write_text(json.dumps(statement, indent=2, sort_keys=True) + "\n")
    if args.sign_cmd:
        subprocess.run([*shlex.split(args.sign_cmd), str(statement_path)], check=True)
        if not Path(f"{statement_path}.sig").is_file():
            raise SystemExit("error: --sign-cmd did not write the .sig file")
    print(statement_path)
    return 0


def write_lock(args) -> int:
    """Write the engine.lock a consumer pins for a verified bundle.

    The lock is the bundle's own engine-identity.json (kind release on a tagged
    release, source{repository,release_tag,asset_name} filled in, identity =
    the public commit SHA the tag points at), released next to the zip as
    `engine.lock.<target>.json`, the same name and bytes `dev-engine.py lock`
    uses for the dev flow. Nothing is run; the zip is hash-verified first.
    """
    zip_path = Path(args.zip)
    found = verify_zip(zip_path, args.expect_zip_sha256, None, args.target, args.release)
    if found:
        raise SystemExit("error: refusing to write a lock for an unverified bundle: " + "; ".join(found))
    with zipfile.ZipFile(zip_path) as z:
        identity = json.loads(z.read("engine-identity.json"))
    if identity["public_commit_sha"] != args.public_commit_sha:
        raise SystemExit("error: identity public_commit_sha != --public-commit-sha")
    if identity["source"]["asset_name"] != zip_path.name:
        raise SystemExit("error: zip name != identity asset_name")
    problems = validator.validate(identity, require_source=True, release=args.release)
    if problems:
        raise SystemExit("error: identity is not a pinnable lock: " + "; ".join(problems))
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"engine.lock.{args.target}.json"
    path.write_text(json.dumps(identity, indent=2, sort_keys=True) + "\n")
    print(path)
    return 0


def verify_zip(zip_path: Path, expect_zip_sha256: str | None = None, lock: dict | None = None, target: str | None = None, release: bool = False) -> list[str]:
    """Hash-only verification. Returns problems; executes nothing."""
    data = zip_path.read_bytes()
    problems = []
    if expect_zip_sha256 and sha256(data) != expect_zip_sha256:
        return [f"zip sha256 {sha256(data)} != expected {expect_zip_sha256}"]
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as e:
        return [f"not a zip: {e}"]
    names = [i.filename for i in z.infolist() if not i.is_dir()]
    for n in names:
        if not safe_path(n):
            return [f"unsafe entry name {n!r}"]
    if len(set(names)) != len(names):
        return ["duplicate zip entries"]
    entries = {n: z.read(n) for n in names}
    for need in RESERVED:
        if need not in entries:
            return [f"bundle is missing {need}"]
    try:
        identity = json.loads(entries["engine-identity.json"])
    except ValueError:
        return ["engine-identity.json is not JSON"]
    problems += validator.validate(identity, release=release)
    if target is not None:
        if target not in LAYOUTS:
            return [f"unknown layout {target!r}"]
        problems += layout_problems(LAYOUTS[target], {n for n in entries if n not in RESERVED})
    if problems:
        return problems
    if identity["public_commit_sha"] not in entries["SOURCE.txt"].decode(errors="replace"):
        problems.append("SOURCE.txt does not name the identity's public_commit_sha")
    if identity["build_config_digest"] not in entries["SOURCE.txt"].decode(errors="replace"):
        problems.append("SOURCE.txt does not name the identity's build_config_digest")
    if not entries["THIRD-PARTY-LICENSES"].strip():
        problems.append("THIRD-PARTY-LICENSES is empty")
    listed = {}
    for line in entries["SHA256SUMS"].decode().splitlines():
        digest, _, name = line.partition("  ")
        listed[name] = digest
    present = {n for n in entries if n not in EXCLUDED_FROM_SUMS}
    problems += [f"SHA256SUMS does not list {n}" for n in sorted(present - set(listed))]
    problems += [f"SHA256SUMS lists {n}, which is absent" for n in sorted(set(listed) - present)]
    problems += [f"{n} does not match SHA256SUMS" for n in sorted(present & set(listed)) if sha256(entries[n]) != listed[n]]
    if sha256(entries["SHA256SUMS"]) != identity["bundle_sha256"]:
        problems.append("SHA256SUMS digest != identity bundle_sha256")
    if identity["artifact_sha256"] not in listed.values():
        problems.append("identity artifact_sha256 matches no bundle file")
    if target is not None and listed.get(LAYOUTS[target]["daemon"]) != identity["artifact_sha256"]:
        problems.append("identity artifact_sha256 is not the layout's daemon")
    if lock is not None:
        problems += validator.validate(lock, require_source=True, release=release)
        for key in ("public_commit_sha", "engine_api_version", "artifact_sha256", "channel", "kind", "build_config_digest", "bundle_sha256"):
            if identity[key] != lock.get(key):
                problems.append(f"identity {key} != lock {key}")
        if "source" in identity and identity["source"] != lock.get("source"):
            problems.append("identity source != lock source")
        if lock.get("source", {}).get("asset_name") not in (None, zip_path.name):
            problems.append(f"zip name {zip_path.name} != lock asset_name")
    return problems


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        lic = tmp / "LICENSE"
        lic.write_text("license\n")
        tpl = tmp / "THIRD-PARTY-LICENSES"
        tpl.write_text("third party\n")
        api = tmp / "lib.rs"
        api.write_text("pub const PROVIDER_HOST_API_VERSION: u32 = 7;\n")
        sha = "a" * 40

        # Fake source roots holding every file any layout can ask for.
        roots = {k: tmp / "roots" / k for k in ("bin", "shell", "generated", "ipc", "csharp")}
        for target, layout in LAYOUTS.items():
            for dest, root, rel, _ in layout["files"]:
                path = roots[root] / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(f"{target}:{dest}".encode())
        for layout in LAYOUTS.values():
            for _, root, rel_dir, suffix in layout["globs"]:
                (roots[root] / rel_dir).mkdir(parents=True, exist_ok=True)
                for name in ("A", "B"):
                    (roots[root] / rel_dir / f"{name}{suffix}").write_bytes(f"{name}{suffix}".encode())
                (roots[root] / rel_dir / "ignored.txt").write_bytes(b"not part of the layout")

        def run_build(target: str, out: Path, channel: str = "beta", features: str | None = None, embed: bool = True, expect: str | None = None, **extra):
            if features is None:
                features = "" if channel == "dev" else "yadorilink-daemon/enforce-release-trust-root"
            ident = ["--channel", channel, "--target", target, "--build-config", f"features={features}", "--public-commit-sha", sha]
            rid = f"{sha}:{build_identity(parse(['release-id', *ident]))[2]}"
            for name in LAYOUTS[target]["programs"]:
                for layout_name, root, rel, _ in LAYOUTS[target]["files"]:
                    if layout_name == name:
                        (roots[root] / rel).write_bytes(f"{target}:{name}:{rid if embed else 'none'}".encode())
            argv = [
                "build", *ident, "--expect-release-id", expect or rid, "--repository", "o/r", "--release-tag", "v1.0.0",
                "--license", str(lic), "--third-party-licenses", str(tpl), "--api-version-source", str(api), "--out-dir", str(out),
            ]
            for key, path in roots.items():
                argv += ["--root", f"{key}={path}"]
            for k, v in extra.items():
                argv += [f"--{k.replace('_', '-')}", v]
            return build(parse(argv))

        def fake_attestation(zip_path: Path, **over) -> Path:
            cert = {
                "buildSignerURI": "https://github.com/o/r/.github/workflows/release.yml@refs/heads/main",
                "sourceRepositoryDigest": sha,
                "sourceRepositoryURI": "https://github.com/o/r",
                "sourceRepositoryRef": "refs/heads/main",
                **over.pop("cert", {}),
            }
            subject = over.pop("subject", sha256(zip_path.read_bytes()))
            doc = [{"verificationResult": {"statement": {"subject": [{"name": zip_path.name, "digest": {"sha256": subject}}]}, "signature": {"certificate": cert}}}]
            path = tmp / f"att-{abs(hash((zip_path.name, subject, json.dumps(cert, sort_keys=True))))}.json"
            path.write_text(json.dumps(over.get("doc", doc)))
            return path

        def run_provenance(zip_path: Path, out: Path, attestation: Path | None = None, **extra):
            attestation = attestation or fake_attestation(zip_path)
            argv = ["provenance", str(zip_path), "--public-commit-sha", sha, "--repository", "o/r", "--attestation-json", str(attestation),
                    "--gate", "release-gates", "--out-dir", str(out)]
            for k, v in extra.items():
                argv += [f"--{k.replace('_', '-')}", v]
            return provenance(parse(argv))

        def entries_of(zip_path: Path) -> dict[str, bytes]:
            z = zipfile.ZipFile(zip_path)
            return {n: z.read(n) for n in z.namelist()}

        def rewrite(zip_path: Path, entries: dict[str, bytes], name: str = "t.zip") -> Path:
            path = tmp / name
            with zipfile.ZipFile(path, "w") as z:
                for n, v in entries.items():
                    z.writestr(n, v)
            return path

        expected_names = {
            "linux-x86_64": {"yadorilink", "yadorilink-daemon"},
            "windows-x86_64": {
                "yadorilink.exe", "yadorilink-daemon.exe",
                "yadorilink_shell_ext.dll", "yadorilink-cfapi-host.exe",
                "yadorilink_client_ffi.dll", "csharp/BINDING-NOTES.md",
                "csharp/Generated/A.cs", "csharp/Generated/B.cs",
            },
            "macos-aarch64": {
                "bin/yadorilink", "bin/yadorilink-daemon", "lib/libyadorilink_client_ffi.a",
                "swift/Generated/YadoriLinkCore.swift", "swift/Generated/YadoriLinkFFI.swift",
                "swift/Generated/include/module.modulemap", "swift/Generated/include/A.h",
                "swift/Generated/include/B.h", "ipc-proto/proto/shellipc.proto", "ipc-proto/src/framing.rs",
            },
        }
        for target, names in expected_names.items():
            out1, out2 = tmp / f"{target}-1", tmp / f"{target}-2"
            run_build(target, out1)
            run_build(target, out2)
            z1 = out1 / f"yadorilink-engine-beta-{target}.zip"
            assert z1.read_bytes() == (out2 / z1.name).read_bytes(), "bundle is not deterministic"
            entries = entries_of(z1)
            assert set(entries) == names | set(RESERVED), (target, sorted(entries))
            assert verify_zip(z1) == [] and verify_zip(z1, target=target) == [], verify_zip(z1, target=target)
            sums = entries["SHA256SUMS"].decode()
            assert all(f"  {n}\n" in sums for n in names | set(NOTICE_FILES)), "SHA256SUMS misses a file"
            source = entries["SOURCE.txt"].decode()
            assert f"https://github.com/o/r/tree/{sha}" in source and "LICENSE" in source
            assert json.loads(entries["engine-identity.json"])["build_config_digest"] in source
            assert entries["THIRD-PARTY-LICENSES"] == b"third party\n"
            assert "engine-identity.json" not in sums
            identity = json.loads(entries["engine-identity.json"])
            daemon = LAYOUTS[target]["daemon"]
            assert identity["artifact_sha256"] == sha256(entries[daemon])
            assert identity["engine_api_version"] == 7 and identity["source"]["asset_name"] == z1.name
            for info in zipfile.ZipFile(z1).infolist():
                want = 0o755 if info.filename in {f[0] for f in LAYOUTS[target]["files"] if f[3]} else 0o644
                assert info.external_attr >> 16 == want, info.filename
            assert identity["bundle_sha256"] == sha256(entries["SHA256SUMS"])
            # The bundle must verify as its own platform only.
            for wrong in set(LAYOUTS) - {target}:
                assert verify_zip(z1, target=wrong), f"{target} bundle accepted as {wrong}"
            lock = dict(identity)
            assert verify_zip(z1, sha256(z1.read_bytes()), lock, target) == []
            assert verify_zip(z1, "0" * 64)
            assert verify_zip(z1, None, {**lock, "bundle_sha256": "0" * 64})
            assert verify_zip(z1, None, {k: v for k, v in lock.items() if k != "source"})
            assert not (out1 / f"{z1.name}.provenance.json").exists(), "build must not write provenance"
            run_provenance(z1, out1 / "prov", target=target, expect_zip_sha256=sha256(z1.read_bytes()))
            prov = json.loads((out1 / "prov" / f"{z1.name}.provenance.json").read_text())
            assert prov["artifact"]["sha256"] == sha256(z1.read_bytes())
            assert prov["public_commit_sha"] == sha and prov["gates_passed"] == ["release-gates"]
            assert prov["bundle_sha256"] == identity["bundle_sha256"]
            assert prov["attestation"]["signer_workflow"].endswith("/.github/workflows/release.yml@refs/heads/main")
            assert prov["attestation"]["source_commit"] == sha and prov["attestation"]["subject_sha256"] == prov["artifact"]["sha256"]

            # Tampering: altered, added, unlisted, escaping, missing and unexpected files.
            first = sorted(names)[0]
            assert verify_zip(rewrite(z1, {**entries, first: b"evil"}), target=target)
            assert verify_zip(rewrite(z1, {**entries, "extra": b"x"}), target=target)
            assert verify_zip(rewrite(z1, {**entries, "SHA256SUMS": b"x\n"}), target=target)
            assert verify_zip(rewrite(z1, {**entries, "../escape": b"x"}))
            assert verify_zip(rewrite(z1, {**entries, "/abs": b"x"}))
            assert verify_zip(rewrite(z1, {**entries, "a\\b": b"x"}))
            for notice in NOTICE_FILES:
                assert verify_zip(rewrite(z1, {n: v for n, v in entries.items() if n != notice}), target=target), notice
            assert verify_zip(rewrite(z1, {**entries, "SOURCE.txt": b"elsewhere\n", "SHA256SUMS": entries["SHA256SUMS"]}), target=target)
            assert verify_zip(rewrite(z1, {n: v for n, v in entries.items() if n != first}), target=target)
            # A file outside the layout is rejected even when SHA256SUMS lists it.
            extra_sums = entries["SHA256SUMS"] + f"{sha256(b'x')}  stray/file\n".encode()
            assert verify_zip(rewrite(z1, {**entries, "stray/file": b"x", "SHA256SUMS": extra_sums}), target=target)

        # A retired-name library is rejected even when SHA256SUMS lists it and
        # even when the current library is present too.
        for target, retired_name in [
            ("macos-aarch64", "lib/libyadorilink_apple_ffi.a"),
            ("windows-x86_64", "yadorilink_apple_ffi.dll"),
        ]:
            z1 = tmp / f"{target}-1" / f"yadorilink-engine-beta-{target}.zip"
            ents = entries_of(z1)
            sums_with = ents["SHA256SUMS"] + f"{sha256(b'old')}  {retired_name}\n".encode()
            stale = rewrite(z1, {**ents, retired_name: b"old", "SHA256SUMS": sums_with}, f"{target}-stale.zip")
            found = verify_zip(stale, target=target)
            assert any("retired" in f for f in found), (target, found)
            # The old library standing in for the new one: missing and retired.
            current = next(n for n in ents if n.endswith(("libyadorilink_client_ffi.a", "yadorilink_client_ffi.dll")))
            swapped = {n: v for n, v in ents.items() if n != current}
            swapped[retired_name] = b"old"
            found = verify_zip(rewrite(z1, swapped, f"{target}-swapped.zip"), target=target)
            assert any("retired" in f for f in found) and any(current in f for f in found), (target, found)

        # A dev bundle: kind dev, built without the release trust root, accepted
        # as a bundle but refused by every release path; the two never swap.
        dev_out = tmp / "dev"
        run_build("macos-aarch64", dev_out, channel="dev")
        dev_zip = dev_out / "yadorilink-engine-dev-macos-aarch64.zip"
        dev_id = json.loads(entries_of(dev_zip)["engine-identity.json"])
        assert dev_id["kind"] == "dev" and dev_id["channel"] == "dev"
        assert "DEVELOPMENT BUNDLE" in entries_of(dev_zip)["SOURCE.txt"].decode()
        assert verify_zip(dev_zip, target="macos-aarch64") == []
        assert verify_zip(dev_zip, target="macos-aarch64", release=True), "a release path accepted a dev bundle"
        assert verify_zip(dev_zip, None, dev_id, "macos-aarch64") == []
        assert verify_zip(dev_zip, None, {**dev_id, "kind": "release"}, "macos-aarch64")
        beta_zip = tmp / "macos-aarch64-1" / "yadorilink-engine-beta-macos-aarch64.zip"
        assert verify_zip(beta_zip, target="macos-aarch64", release=True) == []
        assert json.loads(entries_of(beta_zip)["engine-identity.json"])["kind"] == "release"
        for label, kwargs in [
            ("a release bundle without the release trust root", {"channel": "beta", "features": ""}),
            ("programs that do not embed the release identity", {"embed": False}),
            ("programs built for another release identity", {"expect": "a" * 40 + ":" + "0" * 64}),
        ]:
            try:
                run_build("macos-aarch64", tmp / "bad-kind", **kwargs)
            except SystemExit:
                pass
            else:
                raise AssertionError(f"built {label}")

        # Provenance, the release path, refuses a development bundle when asked to.
        try:
            provenance(parse(
                ["provenance", str(dev_zip), "--public-commit-sha", sha, "--repository", "o/r", "--attestation-json", str(fake_attestation(dev_zip)),
                 "--out-dir", str(tmp / "pdev"), "--release"]))
        except SystemExit:
            pass
        else:
            raise AssertionError("release provenance accepted a dev bundle")

        # A missing layout file refuses the build.
        (roots["ipc"] / "src" / "framing.rs").unlink()
        try:
            run_build("macos-aarch64", tmp / "bad2")
        except SystemExit:
            pass
        else:
            raise AssertionError("a bundle with a missing layout file was built")

        # Provenance refuses an unverified or tampered bundle.
        z = tmp / "linux-x86_64-1" / "yadorilink-engine-beta-linux-x86_64.zip"
        bad = rewrite(z, {**entries_of(z), "yadorilink": b"evil"}, "yadorilink-engine-beta-linux-x86_64.zip.bad")
        for label, args_ in [
            ("tampered", (bad, {})),
            ("wrong digest", (z, {"expect_zip_sha256": "0" * 64})),
            ("wrong layout", (z, {"target": "windows-x86_64"})),
        ]:
            try:
                run_provenance(args_[0], tmp / "pbad", **args_[1])
            except SystemExit:
                pass
            else:
                raise AssertionError(f"provenance accepted a {label} bundle")

        # The attestation must exist and match: digest, signer workflow, commit, repository.
        for label, att in [
            ("missing", tmp / "no-such.json"),
            ("empty", fake_attestation(z, doc=[])),
            ("other digest", fake_attestation(z, subject="0" * 64)),
            ("other signer workflow", fake_attestation(z, cert={"buildSignerURI": "https://github.com/o/r/.github/workflows/evil.yml@refs/heads/main"})),
            ("other signer repository", fake_attestation(z, cert={"buildSignerURI": "https://github.com/x/r/.github/workflows/release.yml@refs/heads/main"})),
            ("other source commit", fake_attestation(z, cert={"sourceRepositoryDigest": "f" * 40})),
            ("other source repository", fake_attestation(z, cert={"sourceRepositoryURI": "https://github.com/x/r"})),
            ("malformed", fake_attestation(z, doc=[{"verificationResult": {}}])),
        ]:
            try:
                run_provenance(z, tmp / "pbad2", attestation=att)
            except SystemExit:
                pass
            else:
                raise AssertionError(f"provenance accepted a {label} attestation")

        # The release lock asset: the verified bundle's identity, named per target.
        lock_out = tmp / "locks"
        lock_argv = ["lock", str(z), "--target", "linux-x86_64", "--public-commit-sha", sha, "--out-dir", str(lock_out)]
        write_lock(parse(lock_argv))
        lock_file = lock_out / "engine.lock.linux-x86_64.json"
        lock_doc = json.loads(lock_file.read_text())
        assert lock_doc == json.loads(zipfile.ZipFile(z).read("engine-identity.json"))
        assert lock_doc["public_commit_sha"] == sha and lock_doc["source"]["asset_name"] == z.name
        assert not verify_zip(z, None, lock_doc, "linux-x86_64"), "the lock must verify against its own bundle"
        for label, argv_ in [
            ("another commit", ["lock", str(z), "--target", "linux-x86_64", "--public-commit-sha", "f" * 40, "--out-dir", str(tmp / "l2")]),
            ("another layout", ["lock", str(z), "--target", "windows-x86_64", "--public-commit-sha", sha, "--out-dir", str(tmp / "l3")]),
            ("a wrong digest", [*lock_argv[:-1], str(tmp / "l4"), "--expect-zip-sha256", "0" * 64]),
            ("a tampered bundle", ["lock", str(bad), "--target", "linux-x86_64", "--public-commit-sha", sha, "--out-dir", str(tmp / "l5")]),
        ]:
            try:
                write_lock(parse(argv_))
            except SystemExit:
                pass
            else:
                raise AssertionError(f"lock accepted {label}")
        try:
            write_lock(parse(["lock", str(dev_zip), "--target", "macos-aarch64", "--public-commit-sha", sha, "--out-dir", str(tmp / "l6"), "--release"]))
        except SystemExit:
            pass
        else:
            raise AssertionError("release lock accepted a dev bundle")

        # Signing hook: a command that writes the .sig, and one that does not.
        signer = tmp / "sign.sh"
        signer.write_text('#!/bin/sh\necho sig > "$1.sig"\n')
        signer.chmod(0o755)
        run_provenance(z, tmp / "o3", sign_cmd=str(signer))
        assert (tmp / "o3" / "yadorilink-engine-beta-linux-x86_64.zip.provenance.json.sig").is_file()
        try:
            run_provenance(z, tmp / "o4", sign_cmd="true")
        except SystemExit:
            pass
        else:
            raise AssertionError("a signer that writes no .sig was accepted")
    print("ok")
    return 0


def parse(argv):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    ident = argparse.ArgumentParser(add_help=False)
    ident.add_argument("--channel", required=True, choices=["stable", "beta", "dev"])
    ident.add_argument("--target", required=True, choices=sorted(LAYOUTS), help="platform layout, also used in the asset name")
    ident.add_argument("--public-commit-sha", required=True)
    ident.add_argument("--build-config", action="append", default=[], metavar="KEY=VALUE")
    sub.add_parser("release-id", parents=[ident], help="print the release_id the binaries must embed")
    b = sub.add_parser("build", parents=[ident])
    b.add_argument("--expect-release-id", required=True, metavar="ID", help="the release_id the binaries were built to embed (from release-id); the build refuses a mismatch or a program that lacks it")
    b.add_argument("--root", action="append", default=[], metavar="KEY=DIR", help="source root named by the layout")
    b.add_argument("--license", default=str(ROOT / "LICENSE"))
    b.add_argument("--third-party-licenses", required=True, metavar="FILE", help="notice for the crates in this bundle (generate-third-party-licenses.sh)")
    b.add_argument("--repository", required=True)
    b.add_argument("--release-tag", required=True)
    b.add_argument("--asset-name")
    b.add_argument("--api-version-source", default=str(ROOT / "crates/yadorilink-ipc-proto/src/lib.rs"))
    b.add_argument("--out-dir", required=True)
    pv = sub.add_parser("provenance")
    pv.add_argument("zip")
    pv.add_argument("--target", choices=sorted(LAYOUTS))
    pv.add_argument("--expect-zip-sha256")
    pv.add_argument("--public-commit-sha", required=True)
    pv.add_argument("--repository", required=True)
    pv.add_argument("--attestation-json", required=True, metavar="FILE", help="output of gh attestation verify --format json")
    pv.add_argument("--gate", action="append", default=[], help="name of a required gate that passed")
    pv.add_argument("--sign-cmd")
    pv.add_argument("--release", action="store_true", help="release path: refuse a development bundle")
    pv.add_argument("--out-dir", required=True)
    lk = sub.add_parser("lock", help="write engine.lock.<target>.json for a verified bundle")
    lk.add_argument("zip")
    lk.add_argument("--target", required=True, choices=sorted(LAYOUTS))
    lk.add_argument("--expect-zip-sha256")
    lk.add_argument("--public-commit-sha", required=True)
    lk.add_argument("--release", action="store_true", help="release path: refuse a development bundle")
    lk.add_argument("--out-dir", required=True)
    v = sub.add_parser("verify")
    v.add_argument("zip")
    v.add_argument("--target", choices=sorted(LAYOUTS), help="also require exactly this platform layout")
    v.add_argument("--expect-zip-sha256")
    v.add_argument("--lock")
    v.add_argument("--release", action="store_true", help="release or production path: refuse a development bundle")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    args = parse(argv)
    if args.cmd == "release-id":
        return release_id(args)
    if args.cmd == "build":
        return build(args)
    if args.cmd == "provenance":
        return provenance(args)
    if args.cmd == "lock":
        return write_lock(args)
    lock = json.loads(Path(args.lock).read_text()) if args.lock else None
    found = verify_zip(Path(args.zip), args.expect_zip_sha256, lock, args.target, args.release)
    for line in found:
        print(f"engine bundle verification failed: {line}", file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
