"""Verify the update trust chain: the signed records that extend the
compiled-in manifest-signing key through rotation and revocation.

Python mirror of crates/yadorilink-daemon/src/update/trust.rs; the Rust tests
and the release gate tests (check-release-gates.py --self-test) pin both to the
same rules. Requires the `cryptography` package.

A chain is a JSON array of records {key_id, record_json, signature_base64}.
Record n is signed (over DOMAIN + record_json) by a key trusted at that point,
carries serial n, and adds keys and/or revokes key ids. A revoked key, or its
public key under another id, never returns; a record cannot revoke its own
signer; the set can never become empty; the development key cannot be added.
"""

from __future__ import annotations

import base64
import json

DOMAIN = b"yadorilink-trust-record-v1\n"
SCHEMA_VERSION = 1
MAX_CHAIN_LEN = 64
DEV_KEY = "00e033f866c263139ff4afd165e75bae3cfca67eb32399dddd6e33a3251af1e3"
RECORD_FIELDS = {"schema_version", "serial", "add", "revoke"}


class TrustChainError(Exception):
    pass


class State:
    def __init__(self, anchor: dict[str, str]):
        self.serial = 0
        self.active = {k: v.strip().lower() for k, v in anchor.items()}
        self.revoked: dict[str, str] = {}

    def lookup(self, key_id: str) -> str:
        """Public key hex for an active signer; raises for revoked/unknown."""
        if key_id in self.active:
            return self.active[key_id]
        if key_id in self.revoked:
            raise TrustChainError(f"signing key id {key_id!r} is revoked")
        raise TrustChainError(f"unknown signing key id: {key_id!r} (not in the trust set)")


def _public_key(hex_str: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if len(hex_str) != 64:
        raise ValueError("public key must be 64 hex characters")
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))


def apply(state: State, rec: object) -> None:
    from cryptography.exceptions import InvalidSignature

    n = state.serial + 1
    if n > MAX_CHAIN_LEN:
        raise TrustChainError(f"trust chain is longer than {MAX_CHAIN_LEN} records")
    if not (isinstance(rec, dict) and set(rec) == {"key_id", "record_json", "signature_base64"}
            and all(isinstance(v, str) for v in rec.values())):
        raise TrustChainError(f"record {n}: malformed envelope")
    signer = state.lookup(rec["key_id"])
    try:
        _public_key(signer).verify(base64.b64decode(rec["signature_base64"], validate=True),
                                   DOMAIN + rec["record_json"].encode("utf-8"))
    except (InvalidSignature, ValueError):
        raise TrustChainError(f"record {n}: signature is invalid") from None
    try:
        body = json.loads(rec["record_json"])
    except json.JSONDecodeError as e:
        raise TrustChainError(f"record {n}: body is not JSON: {e}") from None
    if not isinstance(body, dict) or not {"schema_version", "serial"} <= set(body) or set(body) - RECORD_FIELDS:
        raise TrustChainError(f"record {n}: unexpected fields")
    if body["schema_version"] != SCHEMA_VERSION:
        raise TrustChainError(f"record {n}: unsupported schema version")
    if body["serial"] != n:
        raise TrustChainError(f"record {n}: serial {body['serial']!r} is out of sequence")
    add, revoke = body.get("add", []), body.get("revoke", [])
    if not isinstance(add, list) or not isinstance(revoke, list) or not (add or revoke):
        raise TrustChainError(f"record {n}: must add or revoke at least one key")
    if rec["key_id"] in revoke:
        raise TrustChainError(f"record {n}: revokes its own signer")
    active, revoked = dict(state.active), dict(state.revoked)
    for entry in add:
        if not (isinstance(entry, dict) and set(entry) == {"key_id", "public_key_hex"}
                and all(isinstance(v, str) for v in entry.values())):
            raise TrustChainError(f"record {n}: malformed key entry")
        kid, hex_str = entry["key_id"], entry["public_key_hex"].strip().lower()
        try:
            _public_key(hex_str)
        except ValueError:
            raise TrustChainError(f"record {n}: key {kid!r} is not a valid Ed25519 public key") from None
        if not kid or kid != kid.strip() or hex_str == DEV_KEY:
            raise TrustChainError(f"record {n}: key {kid!r} is not acceptable (blank id or development key)")
        if kid in active or kid in revoked or hex_str in active.values() or hex_str in revoked.values():
            raise TrustChainError(f"record {n}: key {kid!r} is or was already in the trust set")
        active[kid] = hex_str
    for kid in revoke:
        if not isinstance(kid, str) or kid not in active:
            raise TrustChainError(f"record {n}: cannot revoke {kid!r}, not an active key")
        revoked[kid] = active.pop(kid)
    if not active:
        raise TrustChainError(f"record {n}: would leave no active key")
    state.serial, state.active, state.revoked = n, active, revoked


def replay(anchor: dict[str, str], chain: object) -> State:
    if not isinstance(chain, list):
        raise TrustChainError("trust chain must be a JSON array")
    if len(chain) > MAX_CHAIN_LEN:
        raise TrustChainError(f"trust chain is longer than {MAX_CHAIN_LEN} records")
    state = State(anchor)
    for rec in chain:
        apply(state, rec)
    return state
