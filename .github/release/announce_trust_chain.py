#!/usr/bin/env python3
"""Checks around the announce-trust-chain workflow: announcing a new manifest-signing public key
in the trust chain without anyone holding the current signing seed.

Usage: announce_trust_chain.py check  --chain FILE
       announce_trust_chain.py verify --old FILE --new FILE
       announce_trust_chain.py --self-test

The workflow runs the signer's `trust-set` in the approval-gated signing Environment. This script
holds no key and never reads one; it runs in steps that have no secret:

  check   before the seed is used: the announced id and public key are well formed, are not the
          development key, are not the root, and are not (and never were) in the chain; the existing
          chain verifies against the root.
  verify  after `trust-set`: an independent re-check with the Python mirror of the client's rules
          (`trust_chain.py`), separate from the signing tool's own check. The new chain keeps every
          old record byte for byte, adds exactly one record, which adds exactly the announced key
          and revokes nothing, and the trust set grows by exactly that key. Prints a Markdown summary.

Inputs come from the environment: ROOT_KEY_ID, ROOT_PUBLIC_KEY_HEX (the client root), NEW_KEY_ID,
NEW_PUBLIC_KEY_HEX (the announcement); verify also reads the run facts the summary lists
(SIGNER_SHA256, SOURCE_COMMIT, RUN_URL, ACTOR). Requires the `cryptography` package.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import trust_chain as TC  # noqa: E402

KEY_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}")
HEX_RE = re.compile(r"[0-9a-f]{64}")


class Refused(Exception):
    pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_chain(path: Path) -> tuple[bytes, list]:
    raw = path.read_bytes()
    try:
        chain = json.loads(raw)
    except json.JSONDecodeError as e:
        raise Refused(f"{path} is not JSON: {e}") from None
    if not isinstance(chain, list):
        raise Refused(f"{path} is not a JSON array")
    return raw, chain


def announcement(env: dict[str, str]) -> tuple[str, str, dict[str, str]]:
    """The announced key and the root, validated for shape only."""
    new_id, new_hex = env.get("NEW_KEY_ID", ""), env.get("NEW_PUBLIC_KEY_HEX", "")
    root_id, root_hex = env.get("ROOT_KEY_ID", ""), env.get("ROOT_PUBLIC_KEY_HEX", "").strip().lower()
    if not KEY_ID_RE.fullmatch(new_id):
        raise Refused("the key id must be 3-64 characters of a-z, 0-9, '.', '_' or '-', starting with a letter or digit")
    if not HEX_RE.fullmatch(new_hex):
        raise Refused("the public key must be exactly 64 lowercase hex characters")
    if not root_id or not HEX_RE.fullmatch(root_hex):
        raise Refused("the client root (RELEASE_MANIFEST_KEY_ID / RELEASE_MANIFEST_PUBLIC_KEY_HEX) is not configured")
    if new_hex == TC.DEV_KEY:
        raise Refused("the development key can never be announced")
    try:
        TC._public_key(new_hex)
    except ValueError:
        raise Refused("the public key is not a valid Ed25519 public key") from None
    return new_id, new_hex, {root_id: root_hex}


def check(chain_path: Path, env: dict[str, str]) -> dict[str, str]:
    new_id, new_hex, anchor = announcement(env)
    _, chain = load_chain(chain_path)
    try:
        state = TC.replay(anchor, chain)
    except TC.TrustChainError as e:
        raise Refused(f"the existing chain does not verify against the root: {e}") from None
    known = {**state.active, **state.revoked}
    if new_id in known or new_id in anchor:
        raise Refused(f"key id {new_id!r} is or was already in the trust set")
    if new_hex in known.values() or new_hex in anchor.values():
        raise Refused("that public key is or was already in the trust set (under this or another id)")
    return {"serial": str(state.serial), "active": ", ".join(sorted(state.active))}


def verify(old_path: Path, new_path: Path, env: dict[str, str]) -> str:
    new_id, new_hex, anchor = announcement(env)
    old_raw, old = load_chain(old_path)
    new_raw, new = load_chain(new_path)
    try:
        old_state = TC.replay(anchor, old)
        new_state = TC.replay(anchor, new)
    except TC.TrustChainError as e:
        raise Refused(f"chain does not verify with the client rules: {e}") from None
    if len(new) != len(old) + 1 or new[: len(old)] != old:
        raise Refused("the new chain must be the old chain plus exactly one record")
    record = json.loads(new[-1]["record_json"])
    if record.get("add") != [{"key_id": new_id, "public_key_hex": new_hex}] or record.get("revoke", []) != []:
        raise Refused("the new record must add exactly the announced key and revoke nothing")
    if new_state.serial != old_state.serial + 1:
        raise Refused("the serial did not advance by one")
    if new_state.active != {**old_state.active, new_id: new_hex} or new_state.revoked != old_state.revoked:
        raise Refused("the trust set must grow by exactly the announced key")
    fingerprint = sha256_hex(bytes.fromhex(new_hex))
    run = lambda k: env.get(k, "") or "(unset)"  # noqa: E731
    return "\n".join([
        "### Trust chain announcement",
        "",
        "| Fact | Value |",
        "|---|---|",
        f"| Announced key id | `{new_id}` |",
        f"| Announced public key | `{new_hex}` |",
        f"| Public-key fingerprint (SHA-256 of the raw key) | `{fingerprint}` |",
        f"| Signed by key id (in the trust set) | `{new[-1]['key_id']}` |",
        f"| Chain serial | {old_state.serial} -> {new_state.serial} |",
        f"| Trusted key ids after | {', '.join(sorted(new_state.active))} |",
        f"| Previous chain SHA-256 | `{sha256_hex(old_raw)}` |",
        f"| New chain SHA-256 | `{sha256_hex(new_raw)}` |",
        f"| Signer binary SHA-256 | `{run('SIGNER_SHA256')}` |",
        f"| Source commit | `{run('SOURCE_COMMIT')}` |",
        f"| Run | {run('RUN_URL')} |",
        f"| Started by | {run('ACTOR')} |",
        "",
        "Both the signing tool and the independent check (client rules, Python mirror) accepted the chain. "
        "Download the `trust-chain` artifact (public data), compare its SHA-256 with the line above and commit it "
        "as `.github/release/trust-chain.json` in a reviewed change.",
        "",
    ])


# ---------------------------------------------------------------------------------------------
# Self-test (throwaway keys only)

def _keypair(byte: int):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    sk = Ed25519PrivateKey.from_private_bytes(bytes([byte]) * 32)
    return sk, sk.public_key().public_bytes_raw().hex()


def _record(sk, signer_id: str, serial: int, add=(), revoke=()) -> dict:
    import base64
    body = json.dumps({"schema_version": 1, "serial": serial,
                       "add": [{"key_id": i, "public_key_hex": h} for i, h in add], "revoke": list(revoke)},
                      separators=(",", ":"))
    sig = sk.sign(TC.DOMAIN + body.encode())
    return {"key_id": signer_id, "record_json": body, "signature_base64": base64.b64encode(sig).decode()}


class SelfTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.sk, self.pub = _keypair(1)
        _, self.spare = _keypair(2)
        self.env = {"ROOT_KEY_ID": "root-1", "ROOT_PUBLIC_KEY_HEX": self.pub,
                    "NEW_KEY_ID": "spare-1", "NEW_PUBLIC_KEY_HEX": self.spare}

    def write(self, name: str, chain) -> Path:
        p = self.tmp / name
        p.write_text(json.dumps(chain, indent=2) + "\n", encoding="utf-8")
        return p

    def refused(self, fn, *a, text=""):
        with self.assertRaises(Refused) as cm:
            fn(*a)
        self.assertIn(text, str(cm.exception))

    def test_check_accepts_a_fresh_key(self):
        self.assertEqual(check(self.write("c.json", []), self.env)["serial"], "0")

    def test_check_refusals(self):
        empty = self.write("c.json", [])
        for name, over, text in (
            ("bad hex", {"NEW_PUBLIC_KEY_HEX": "zz" * 32}, "64 lowercase hex"),
            ("upper hex", {"NEW_PUBLIC_KEY_HEX": self.spare.upper()}, "64 lowercase hex"),
            ("short hex", {"NEW_PUBLIC_KEY_HEX": self.spare[:-2]}, "64 lowercase hex"),
            ("bad id", {"NEW_KEY_ID": "Bad Id"}, "key id"),
            ("empty id", {"NEW_KEY_ID": ""}, "key id"),
            ("dev key", {"NEW_PUBLIC_KEY_HEX": TC.DEV_KEY}, "development key"),
            ("root id", {"NEW_KEY_ID": "root-1"}, "already"),
            ("root key", {"NEW_PUBLIC_KEY_HEX": self.pub}, "already"),
            ("no root", {"ROOT_KEY_ID": ""}, "root"),
        ):
            with self.subTest(name):
                self.refused(check, empty, {**self.env, **over}, text=text)

    def test_check_refuses_duplicates_and_broken_chains(self):
        chain = [_record(self.sk, "root-1", 1, add=[("spare-1", self.spare)])]
        p = self.write("c.json", chain)
        self.refused(check, p, self.env, text="already")
        self.refused(check, p, {**self.env, "NEW_KEY_ID": "other-1"}, text="another id")
        broken = [{**chain[0], "signature_base64": "AAAA"}]
        self.refused(check, self.write("b.json", broken), self.env, text="does not verify")

    def test_check_refuses_a_revoked_key_returning(self):
        sk2, pub2 = _keypair(3)
        chain = [_record(self.sk, "root-1", 1, add=[("k2", pub2)]),
                 _record(sk2, "k2", 2, revoke=["root-1"])]
        self.refused(check, self.write("c.json", chain), {**self.env, "NEW_KEY_ID": "n-1", "NEW_PUBLIC_KEY_HEX": self.pub},
                     text="already")

    def test_verify_accepts_one_added_record(self):
        old = self.write("old.json", [])
        new = self.write("new.json", [_record(self.sk, "root-1", 1, add=[("spare-1", self.spare)])])
        out = verify(old, new, {**self.env, "SIGNER_SHA256": "ab" * 32})
        self.assertIn(sha256_hex(bytes.fromhex(self.spare)), out)
        self.assertIn("`spare-1`", out)

    def test_verify_refusals(self):
        old = self.write("old.json", [])
        good = _record(self.sk, "root-1", 1, add=[("spare-1", self.spare)])
        _, other = _keypair(4)
        sk2, pub2 = _keypair(5)
        cases = {
            "unchanged chain": ([], "exactly one record"),
            "two records": ([good, _record(self.sk, "root-1", 2, add=[("x-2", other)])], "exactly one record"),
            "other key added": ([_record(self.sk, "root-1", 1, add=[("spare-1", other)])], "exactly the announced"),
            "extra key": ([_record(self.sk, "root-1", 1, add=[("spare-1", self.spare), ("x-2", other)])], "exactly the announced"),
            "revocation": ([_record(self.sk, "root-1", 1, add=[("spare-1", self.spare)], revoke=["root-1"])], "revoke"),
            "forged signature": ([_record(sk2, "root-1", 1, add=[("spare-1", self.spare)])], "does not verify"),
            "unknown signer": ([_record(self.sk, "nobody-1", 1, add=[("spare-1", self.spare)])], "does not verify"),
        }
        for name, (chain, text) in cases.items():
            with self.subTest(name):
                self.refused(verify, old, self.write("n.json", chain), self.env, text=text)

    def test_verify_requires_old_chain_as_prefix(self):
        _, pub2 = _keypair(6)
        base = [_record(self.sk, "root-1", 1, add=[("k2", pub2)])]
        old = self.write("old.json", base)
        rewritten = [_record(self.sk, "root-1", 1, add=[("k2", pub2)]), _record(self.sk, "root-1", 2, add=[("spare-1", self.spare)])]
        rewritten[0]["signature_base64"] = rewritten[0]["signature_base64"][:-2] + "AA"  # tamper with record 1
        self.refused(verify, old, self.write("n.json", rewritten), self.env, text="does not verify")
        ok = base + [_record(self.sk, "root-1", 2, add=[("spare-1", self.spare)])]
        self.assertIn("1 -> 2", verify(old, self.write("n2.json", ok), self.env))


def self_test() -> int:
    result = unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(SelfTest))
    return 0 if result.wasSuccessful() else 1


def main(argv: list[str]) -> int:
    if argv == ["--self-test"]:
        return self_test()
    try:
        if len(argv) == 3 and argv[0] == "check" and argv[1] == "--chain":
            facts = check(Path(argv[2]), dict(os.environ))
            print(f"announce check: ok (chain serial {facts['serial']}; trusted: {facts['active']})")
            return 0
        if len(argv) == 5 and argv[0] == "verify" and argv[1] == "--old" and argv[3] == "--new":
            print(verify(Path(argv[2]), Path(argv[4]), dict(os.environ)))
            return 0
    except (Refused, OSError) as e:
        print(f"announce refused: {e}", file=sys.stderr)
        return 1
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
