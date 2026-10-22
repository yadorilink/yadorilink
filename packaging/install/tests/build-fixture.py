#!/usr/bin/env python3
"""Build a local fixture release for the installer tests.

Writes, under OUT:
  <channel>/manifest.json                      signed channel manifest envelope
  <version>/manifest.json                      signed per-version manifest envelope
  files/<version>/yadorilink-engine-<channel>-<target>.zip   real zips in the
                                               documented engine-bundle layout
  pubkey.hex, key_id                           the TEST public key (throw-away)

The manifest is signed with a TEST Ed25519 key derived from --seed (default:
a fixed test seed) using the RFC 8032 reference algorithm below, so no external
tool is needed and the installer's verifiers are checked against an independent
implementation. Binaries are fake: scripts that print a version (or, for
Windows, a prebuilt console exe given with --exe).

This never touches the network and signs only with the test seed.
"""

import argparse
import base64
import hashlib
import io
import json
import shutil
import sys
import zipfile
from pathlib import Path

# ---- RFC 8032 Ed25519 (reference, signing + public key) -----------------
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)


def inv(x):
    return pow(x, P - 2, P)


def add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = p[3] * 2 * D * q[3] % P
    d = p[2] * 2 * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def mul(s, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = add(q, p)
        p = add(p, p)
        s >>= 1
    return q


def recover_x(y, sign):
    x2 = (y * y - 1) * inv(D * y * y + 1) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P:
        x = x * I % P
    if x & 1 != sign:
        x = P - x
    return x


GY = 4 * inv(5) % P
G = (recover_x(GY, 0), GY, 1, recover_x(GY, 0) * GY % P)


def compress(p):
    zi = inv(p[2])
    x, y = p[0] * zi % P, p[1] * zi % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def sha512_int(b):
    return int.from_bytes(hashlib.sha512(b).digest(), "little")


def keypair(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:], compress(mul(a, G))


def sign(seed, msg):
    a, prefix, pub = keypair(seed)
    r = sha512_int(prefix + msg) % L
    rs = compress(mul(r, G))
    k = sha512_int(rs + pub + msg) % L
    return rs + int.to_bytes((r + k * a) % L, 32, "little")


# ---- bundle layout (build-engine-bundle.py LAYOUTS) ---------------------
LAYOUTS = {
    "linux-x86_64": {"bins": ["yadorilink", "yadorilink-daemon"], "daemon": "yadorilink-daemon", "extra": []},
    "macos-aarch64": {
        "bins": ["bin/yadorilink", "bin/yadorilink-daemon"],
        "daemon": "bin/yadorilink-daemon",
        "extra": ["lib/libyadorilink_client_ffi.a", "swift/Generated/YadoriLinkCore.swift"],
    },
    "windows-x86_64": {
        "bins": ["yadorilink.exe", "yadorilink-daemon.exe"],
        "daemon": "yadorilink-daemon.exe",
        "extra": [
            "yadorilink_shell_ext.dll",
            "yadorilink-cfapi-host.exe",
            "yadorilink_client_ffi.dll",
            "csharp/BINDING-NOTES.md",
            "csharp/Generated/Binding.cs",
        ],
    },
}
SOURCE_SHA = "0123456789abcdef0123456789abcdef01234567"
IDENTITY_CHANNEL = {"beta": "beta", "nightly": "dev"}


def sha(b):
    return hashlib.sha256(b).hexdigest()


def build_zip(args, target, channel, version):
    layout = LAYOUTS[target]
    files = {}
    for b in layout["bins"]:
        if args.bin_dir and b in ("yadorilink", "yadorilink-daemon", "yadorilink.exe", "yadorilink-daemon.exe", "bin/yadorilink", "bin/yadorilink-daemon"):
            # Real, prebuilt programs (acceptance harness): the bundle holds the repo's own
            # yadorilink and yadorilink-daemon instead of version-printing stand-ins.
            content = (Path(args.bin_dir) / Path(b).name).read_bytes()
        elif target.startswith("windows"):
            content = Path(args.exe).read_bytes() if args.exe else b"MZ fake " + b.encode()
            if b == "yadorilink-daemon.exe":
                content += b"\0daemon"  # different bytes, same behaviour
        else:
            body = f'#!/bin/sh\necho "yadorilink fake {version} {b}"\n'
            if args.broken_bin:
                body = "#!/bin/sh\necho broken >&2\nexit 7\n"
            content = body.encode()
        files[b] = content
    for e in layout["extra"]:
        files[e] = f"placeholder {e}\n".encode()
    files["LICENSE"] = b"fixture license\n"
    files["THIRD-PARTY-LICENSES"] = b"fixture third-party notice\n"
    files["SOURCE.txt"] = f"commit {SOURCE_SHA}\n".encode()
    sums = "".join(f"{sha(v)}  {k}\n" for k, v in sorted(files.items())).encode()
    if args.corrupt_sums:
        files[layout["bins"][0]] += b"tampered-after-sums"
    asset = f"yadorilink-engine-{IDENTITY_CHANNEL[channel]}-{target}.zip"
    identity = {
        "public_commit_sha": SOURCE_SHA,
        "engine_api_version": args.engine_api_version,
        "artifact_sha256": sha(files[layout["daemon"]] if not args.corrupt_sums or layout["daemon"] != layout["bins"][0] else files[layout["daemon"]]),
        "channel": args.identity_channel or IDENTITY_CHANNEL[channel],
        "build_config_digest": "b" * 64,
        "bundle_sha256": sha(sums),
        "source": {"repository": "o/r", "release_tag": f"v{version}", "asset_name": args.asset_name or asset},
    }
    entries = {**files, "SHA256SUMS": sums, "engine-identity.json": (json.dumps(identity, indent=2, sort_keys=True) + "\n").encode()}
    if args.extra_file:
        entries["unlisted.txt"] = b"not in SHA256SUMS\n"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            exe = name in layout["bins"] and not target.startswith("windows")
            info.external_attr = (0o755 if exe else 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, entries[name])
    return asset, buf.getvalue()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--base-url", required=True, help="where files/ is served, no trailing slash")
    ap.add_argument("--channel", default="beta", choices=sorted(IDENTITY_CHANNEL))
    ap.add_argument("--version", default="0.2.0")
    ap.add_argument("--targets", default=",".join(LAYOUTS))
    ap.add_argument("--seed", default="74657374" * 8, help="TEST key seed, 64 hex")
    ap.add_argument("--key-id", default="yadorilink-test-key")
    ap.add_argument("--exe", help="prebuilt console exe used as the Windows binaries")
    ap.add_argument("--bin-dir", help="directory with prebuilt yadorilink and yadorilink-daemon (non-Windows targets)")
    ap.add_argument("--engine-api-version", type=int, default=7, help="engine_api_version in engine-identity.json (real programs check it)")
    ap.add_argument("--kill-switch", action="store_true")
    ap.add_argument("--broken-bin", action="store_true", help="binaries fail --version")
    ap.add_argument("--corrupt-sums", action="store_true", help="a bundle file differs from SHA256SUMS")
    ap.add_argument("--extra-file", action="store_true", help="bundle holds a file SHA256SUMS does not list")
    ap.add_argument("--identity-channel")
    ap.add_argument("--asset-name")
    ap.add_argument("--min-version", default="0.1.0")
    ap.add_argument("--generated-at", default="2026-10-18T00:00:00Z")
    ap.add_argument("--withdrawn", default="", help="comma-separated withdrawn_versions of the channel manifest")
    ap.add_argument("--extra-version", action="append", default=[],
                    help="also build this version's zips and signed per-version manifest")
    args = ap.parse_args()

    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    (out / "files").mkdir(parents=True)
    (out / args.channel).mkdir()
    seed = bytes.fromhex(args.seed)
    pub = keypair(seed)[2]
    (out / "pubkey.hex").write_text(pub.hex())
    (out / "key_id").write_text(args.key_id)

    def envelope_for(body_obj):
        body = json.dumps(body_obj, indent=2).encode()
        return {
            "key_id": args.key_id,
            "manifest_json": body.decode(),
            "signature_base64": base64.b64encode(sign(seed, body)).decode(),
        }

    def entries_for(version, kill):
        entries = []
        for target in args.targets.split(","):
            asset, data = build_zip(args, target, args.channel, version)
            (out / "files" / version).mkdir(exist_ok=True)
            (out / "files" / version / asset).write_bytes(data)
            platform, arch = target.split("-")
            entries.append({
                "channel": args.channel, "platform": platform, "arch": arch, "install_source": "script",
                "version": version, "minimum_supported_version": args.min_version,
                "rollout_percentage": 100, "kill_switch": kill, "mandatory": False,
                "artifact_url": f"{args.base_url}/files/{version}/{asset}",
                "artifact_sha256": sha(data), "artifact_size": len(data),
                "artifact_publisher_identity": "", "release_notes_url": f"https://example.invalid/notes/{version}",
            })
        return entries

    channel_body = {"schema_version": 2, "generated_at": args.generated_at,
                    "releases": entries_for(args.version, args.kill_switch)}
    if args.withdrawn:
        channel_body["withdrawn_versions"] = args.withdrawn.split(",")
    (out / args.channel / "manifest.json").write_text(json.dumps(envelope_for(channel_body)))
    # The signed per-version manifest of every version this fixture carries: that version's
    # script entries only, never kill-switched (it cannot carry a later withdrawal).
    for version in [args.version, *args.extra_version]:
        (out / version).mkdir(exist_ok=True)
        snap = {"schema_version": 2, "generated_at": "2026-10-01T00:00:00Z",
                "releases": entries_for(version, False)}
        (out / version / "manifest.json").write_text(json.dumps(envelope_for(snap)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
