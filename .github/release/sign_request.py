#!/usr/bin/env python3
"""The one place a production manifest is signed: turns a signing request into a signed
bundle, inside the dedicated signing workflow (`sign-manifest.yml`).

Usage: sign_request.py sign --request FILE --channel nightly|beta --signing-digest HEX
                            --target production
                            --sign-tool PATH --root-key-id ID --root-public-key-hex HEX
                            --release-dir DIR --out FILE [--key-env NAME] [--key-id-env NAME]
       sign_request.py decode --b64gz TEXT --out FILE
       sign_request.py --self-test

The request is what the channel planner emitted (`publish.py plan --out-request`): the
exact manifest body, the exact per-version snapshot bodies and the appcast. The approver of the
signing Environment compares `--signing-digest` (a dispatch input) with the digest the planner
printed; this tool refuses unless the request's whole signing set (the manifest body, every
per-version snapshot body and the appcast) hashes to it, so nothing the key signs is outside
what the reviewer approved. The bundle it writes has the
shape the publisher verifies (`verify_bundle.py`): the publisher independently re-derives
the body from its own ledger and refuses any difference, so this tool is a signer, never an
authority on content.

Checks before the key is touched, each fatal:
  * the request is strict (known fields, types, channel, target) and bounded;
  * the request is for the channel the run was started for and the target this job signs for
    (production; a request for any other target never gets a production signature);
  * the signing set's digest equals the one the approver was shown (and the body hashes to
    its own digest), every body is JSON, and every body's generated_at equals the request's;
  * the request's trust chain digest equals this checkout's trust-chain.json (a stale tree fails);
  * the signing key id is in the trust set derived from the production root plus the production
    chain, and the key really is the private half of that trust-set entry;
  * a production signature is never made with the development key.
The key is read from the environment, passed to the signing tool and never printed.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import release_channels  # noqa: E402
import trust_chain as tc  # noqa: E402

REQUEST_SCHEMA_VERSION = 1
# The production trust chain; the signer consults no other chain.
CHAIN_FILES = {"production": "trust-chain.json"}
BUNDLE_SCHEMA_VERSION = 1  # must equal the bundle verifier's schema version (a test pins it)
CHANNELS = release_channels.CHANNELS
TARGETS = ("production",)
REQUEST_FIELDS = {
    "schema_version", "channel", "target", "generated_at", "ledger_sha256", "manifest_body_sha256",
    "signing_digest",
    "trust_chain_sha256", "manifest_body", "version_manifests", "appcast_xml",
}
MAX_COMPRESSED = 65_535  # GitHub caps the whole workflow_dispatch inputs payload at this size
MAX_REQUEST = 4_000_000
HEX64 = re.compile(r"[0-9a-f]{64}")


class SignError(Exception):
    pass


def sha256_hex(data: str | bytes) -> str:
    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


def decode_b64gz(text: str) -> str:
    """The dispatch input is base64(gzip(request json)): bounded both ways."""
    text = text.strip()
    if not text or len(text) > MAX_COMPRESSED:
        raise SignError("the request input is empty or larger than the allowed size")
    try:
        raw = base64.b64decode(text, validate=True)
        with gzip.GzipFile(fileobj=__import__("io").BytesIO(raw)) as gz:
            out = gz.read(MAX_REQUEST + 1)
    except (binascii.Error, OSError, EOFError, ValueError):
        raise SignError("the request input is not base64 of gzip data") from None
    if len(out) > MAX_REQUEST:
        raise SignError("the decompressed request is larger than the allowed size")
    try:
        return out.decode("utf-8")
    except UnicodeDecodeError:
        raise SignError("the request is not UTF-8") from None


def signing_digest(manifest_body: str, version_manifests: dict, appcast_xml: str | None) -> str:
    """The digest of everything the key will sign or the bundle will carry, in a canonical form.
    The planner prints it; the reviewer approves it; the signer recomputes it."""
    canonical = json.dumps({"manifest_body": manifest_body, "version_manifests": version_manifests,
                            "appcast_xml": appcast_xml}, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    return sha256_hex(canonical)


def parse_request(text: str) -> dict:
    try:
        req = json.loads(text)
    except json.JSONDecodeError as ex:
        raise SignError(f"the request is not JSON: {ex}") from None
    if not isinstance(req, dict) or set(req) != REQUEST_FIELDS:
        raise SignError("the request has missing or unknown fields")
    if req["schema_version"] != REQUEST_SCHEMA_VERSION:
        raise SignError("unsupported request schema version")
    if req["channel"] not in CHANNELS:
        raise SignError(f"channel must be one of {list(CHANNELS)}")
    if req["target"] not in TARGETS:
        raise SignError(f"target must be one of {list(TARGETS)}")
    for f in ("generated_at", "manifest_body"):
        if not isinstance(req[f], str) or not req[f]:
            raise SignError(f"{f} must be a non-empty string")
    for f in ("ledger_sha256", "manifest_body_sha256", "signing_digest", "trust_chain_sha256"):
        if not (isinstance(req[f], str) and HEX64.fullmatch(req[f])):
            raise SignError(f"{f} must be 64 lowercase hex characters")
    vm = req["version_manifests"]
    if not isinstance(vm, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in vm.items()):
        raise SignError("version_manifests must map version to body text")
    if req["appcast_xml"] is not None and not isinstance(req["appcast_xml"], str):
        raise SignError("appcast_xml must be text or null")
    return req


def check_request(req: dict, *, expected_digest: str, target: str, channel: str, chain_text: str) -> None:
    if req["target"] != target:
        raise SignError(f"the request is for {req['target']}, this job signs for {target}")
    if req["channel"] != channel:
        raise SignError(f"the request is for channel {req['channel']}, the run was started for {channel}")
    if not HEX64.fullmatch(expected_digest or ""):
        raise SignError("the approved signing digest must be 64 lowercase hex characters")
    if sha256_hex(req["manifest_body"]) != req["manifest_body_sha256"]:
        raise SignError("the request's body does not hash to its own manifest_body_sha256")
    actual = signing_digest(req["manifest_body"], req["version_manifests"], req["appcast_xml"])
    if actual != req["signing_digest"]:
        raise SignError("the request's signing set does not hash to its own signing_digest")
    if actual != expected_digest:
        raise SignError("the signing set is not the one the approver was shown; nothing was signed")
    if sha256_hex(chain_text) != req["trust_chain_sha256"]:
        raise SignError("the request was planned against a different trust chain than this checkout")
    for name, body in [("manifest_body", req["manifest_body"]), *req["version_manifests"].items()]:
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            raise SignError(f"{name} is not JSON") from None
        if not isinstance(parsed, dict) or parsed.get("generated_at") != req["generated_at"]:
            raise SignError(f"{name} does not carry the request's generated_at")


def derive_public_hex(key_hex: str) -> str:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415

    try:
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex)).public_key().public_bytes_raw().hex()
    except ValueError:
        raise SignError("the signing key is not a 32-byte hex Ed25519 seed") from None


def check_signer(*, key_hex: str, key_id: str, root_key_id: str, root_public_key_hex: str,
                 chain_text: str, target: str) -> None:
    if not (key_hex and key_id and root_key_id and root_public_key_hex):
        raise SignError("the signing key, its id and the release root key variables must all be set")
    try:
        state = tc.replay({root_key_id: root_public_key_hex.strip().lower()}, json.loads(chain_text))
        trusted_pub = state.lookup(key_id)
    except (ValueError, tc.TrustChainError) as ex:
        raise SignError(f"signing key id {key_id!r} is not in the trust set: {ex}") from None
    if target == "production" and tc.DEV_KEY in (trusted_pub, root_public_key_hex.strip().lower()):
        raise SignError("the development key never signs for production")
    pub = derive_public_hex(key_hex)
    if pub != trusted_pub:
        raise SignError(f"the signing key is not the private half of trust-set key {key_id!r}")


def sign_request(request_text: str, *, expected_digest: str, target: str, channel: str, sign_tool: str,
                 root_key_id: str, root_public_key_hex: str, chain_text: str, key_hex: str,
                 key_id: str) -> str:
    """The bundle text (what the publisher verifies), or SignError. Writes nothing on failure."""
    req = parse_request(request_text)
    check_request(req, expected_digest=expected_digest, target=target, channel=channel,
                  chain_text=chain_text)
    check_signer(key_hex=key_hex, key_id=key_id, root_key_id=root_key_id,
                 root_public_key_hex=root_public_key_hex, chain_text=chain_text, target=target)

    def sign(body: str, where: Path) -> str:
        body_file, env_file, chain_file = where / "body.json", where / "envelope.json", where / "chain.json"
        body_file.write_text(body, encoding="utf-8")
        chain_file.write_text(chain_text, encoding="utf-8")
        cmd = [sign_tool, "sign", "--key-hex", key_hex, "--key-id", key_id, "--manifest", str(body_file),
               "--out", str(env_file), "--trust-chain", str(chain_file)]
        try:
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL)
        except FileNotFoundError:
            raise SignError(f"signing tool not found: {sign_tool}") from None
        except subprocess.CalledProcessError as ex:
            raise SignError(f"the signing tool failed (exit {ex.returncode})") from None
        return env_file.read_text(encoding="utf-8")

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        envelope = sign(req["manifest_body"], td)
        versions = {}
        for v, body in sorted(req["version_manifests"].items()):
            sub = td / f"v-{len(versions)}"
            sub.mkdir()
            versions[v] = sign(body, sub)
    bundle = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "channel": req["channel"],
        "body_sha256": req["manifest_body_sha256"],
        "envelope_text": envelope,
        "version_manifests": versions,
        "appcast_xml": req["appcast_xml"],
    }
    return json.dumps(bundle, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    import argparse  # noqa: PLC0415

    if argv == ["--self-test"]:
        import test_sign_request  # noqa: PLC0415

        return test_sign_request.run()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("decode")
    d.add_argument("--b64gz-env", required=True, help="name of the environment variable holding the input")
    d.add_argument("--out", required=True)
    s = sub.add_parser("sign")
    s.add_argument("--request", required=True)
    s.add_argument("--signing-digest", required=True)
    s.add_argument("--target", choices=TARGETS, required=True)
    s.add_argument("--channel", choices=CHANNELS, required=True)
    s.add_argument("--sign-tool", required=True)
    s.add_argument("--root-key-id", required=True)
    s.add_argument("--root-public-key-hex", required=True, help="the release trust root")
    s.add_argument("--release-dir", required=True, help="directory holding the per-target trust chain files")
    s.add_argument("--out", required=True)
    s.add_argument("--key-env", default="MANIFEST_SIGNING_KEY")
    s.add_argument("--key-id-env", default="MANIFEST_SIGNING_KEY_ID")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "decode":
            Path(a.out).write_text(decode_b64gz(os.environ.get(a.b64gz_env, "")), encoding="utf-8")
            return 0
        root_id, root_hex = a.root_key_id, a.root_public_key_hex.strip().lower()
        bundle = sign_request(
            Path(a.request).read_text(encoding="utf-8"), expected_digest=a.signing_digest.strip(),
            target=a.target, channel=a.channel, sign_tool=a.sign_tool, root_key_id=root_id,
            root_public_key_hex=root_hex,
            chain_text=(Path(a.release_dir) / CHAIN_FILES[a.target]).read_text(encoding="utf-8"),
            key_hex=os.environ.get(a.key_env, "").strip(), key_id=os.environ.get(a.key_id_env, "").strip())
    except SignError as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 1
    Path(a.out).write_text(bundle, encoding="utf-8")
    print(f"wrote {a.out} (signing digest {a.signing_digest.strip()})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
