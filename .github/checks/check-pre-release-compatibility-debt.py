#!/usr/bin/env python3
"""Reject compatibility fallbacks that are invalid before the first release.

The check guards exact-generation decisions without banning crash recovery,
retry, journals, audits, retention, or integrity repair.

RESOLVED, and worth reading before touching the schema gate below.
    `resource_lock.rs` used to carry a startup gate
    (`CURRENT_SYNC_SCHEMA_VERSION` / `reject_retired_payloads`) that counted
    rows holding retired version-vector payloads and retired v1
    re-bootstrap snapshots and refused to start. It was removed during a
    larger consolidation, so it is fair to ask whether that was an accidental
    regression rather than a completed replacement.

    It is not a regression. `yadorilink-sqlite-runtime`'s
    `check_schema_version_supported`
    refuses `on_disk_version > SCHEMA_VERSION` AND
    `on_disk_version != 0 && on_disk_version < SCHEMA_VERSION` -- an exact
    match, with only an unstamped (brand new) database allowed through. That
    subsumes the row-level checks, but only because of TWO decisions
    together: the exact match, and this codebase carrying no cross-version
    data migrations. A database old enough to hold a retired payload
    necessarily carries a stamped version below the current one and is
    refused at open; a database at the current version was created by a
    build that never wrote those payloads, and nothing migrates one into the
    other.

    So the property is still enforced, by a different mechanism, and this
    guard now checks THAT mechanism. If either decision is ever revisited --
    an inexact version check, or a real migration path -- the row-level
    checks stop being redundant and must come back. That is what the entry
    below is watching for.

RESOLVED, and worth reading before touching the ALPN gate below.
    `peer_session_public.rs` (a facade since removed) used to carry its own
    exact-generation preflight: a `PROTOCOL_VERSION` constant plus capability
    bits, checked against the peer's first frame after the handshake. That
    was deleted, and so was the custom QUIC transport that followed it.

    The property now lives in the ALPN strings of the iroh router in
    `yadorilink-sync-substrate`. Each protocol is accepted only under its own
    versioned ALPN, so a peer advertising a different generation is refused
    during the TLS handshake itself, strictly before any application frame.
    The generation is in the ALPN string, not a separate field, so there is
    nothing left for an app-level equality check to add.

    So the property is still enforced, by a different (and watched)
    mechanism. If ALPN is ever no longer generation-specific, or a peer of
    another generation could otherwise reach a running session, an
    app-level check must come back. That is what the entry below is
    watching for.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[2]

FORBIDDEN = {
    "crates/yadorilink-daemon/src/device_config.rs": (
        "#[serde(default)]\npub struct DeviceConfig",
        "relay_addr",
    ),
    "crates/yadorilink-ipc-proto/src/lib.rs": (
        "legacy_index_shaped_field",
        "legacy_full_index_and_index_update_bytes_decode_as_an_unset_payload",
    ),
    # The plane sends these on every netmap push, empty arrays included, so
    # `#[serde(default)]` here would let a truncated or corrupted message
    # apply as "nothing changed" instead of failing the push closed.
    "crates/yadorilink-daemon/src/peer_orchestrator/ws_netmap.rs": (
        '#[serde(default, rename = "groupPolicyLogs")]',
        '#[serde(default, rename = "policyInvalidGroupIds")]',
    ),
    # Post-construction dependency setters, retired when the session's
    # dependencies moved into `PeerSyncSessionDeps` -- see REQUIRED below.
    "crates/yadorilink-peer-session/src/peer_session.rs": (
        "pub fn set_block_serve_engine",
        "pub fn set_headroom_override_bytes",
        "pub fn set_headroom_enforced",
        "pub fn set_maintenance_reconcile_interval",
        "pub fn new_with_dependencies",
        "pub fn new_with_forwarding",
    ),
}

# Files a completed migration retired outright. Their compatibility fallback
# was "this file no longer exists"; regressing that is exactly what this
# script exists to catch, so their reappearance is itself the forbidden
# marker rather than any string inside them.
RETIRED_FILES_MUST_NOT_EXIST = (
    "crates/yadorilink-sync-core",
    "crates/yadorilink-sync-core/src/version_vector.rs",
    # The signed-change re-bootstrap snapshot (version-vector counters, the
    # `YLNKsnp` domain tag) was removed with the signed-change model; its
    # reappearance is the forbidden marker, not any string inside it.
    "crates/yadorilink-replica-engine/src/rebootstrap_snapshot.rs",
    # The facade that wrapped `PeerSyncSession` and forwarded to it. Its
    # dependency setters are what let a session be reconfigured after
    # construction.
    "crates/yadorilink-peer-session/src/peer_session_public.rs",
)

REQUIRED = {
    # A session's dependencies are fixed when it is constructed, not
    # installed by setters afterwards. This used to be a runtime assertion
    # ("dependencies are immutable after run() starts") in a facade over
    # `PeerSyncSession`; the facade is gone and the property is structural
    # now: one `PeerSyncSessionDeps`, taken by the one constructor. The
    # setters it retired are pinned as FORBIDDEN in `peer_session.rs`.
    "crates/yadorilink-peer-session/src/peer_session/deps.rs": (
        "pub struct PeerSyncSessionDeps",
    ),
    "crates/yadorilink-peer-session/src/peer_session.rs": (
        "pub fn over_substrate(",
        "deps: PeerSyncSessionDeps,",
    ),
    # The exact-generation preflight that `peer_session_public.rs` used to
    # perform after the handshake now happens *during* it, via the versioned
    # ALPN the router accepts -- see the `RESOLVED` note above. The version in
    # each literal is expected to move: it is pinned so that bumping an ALPN
    # forces a deliberate edit here, rather than letting it quietly stop being
    # generation-specific. Whoever bumps one updates this line in the same
    # change.
    "crates/yadorilink-sync-substrate/src/node.rs": (
        'pub const YADORI_SYNC_ALPN: &[u8] = b"yadorilink/sync/v',
        "YADORI_SYNC_ALPN,\n            YadoriProtocolHandler {",
    ),
    "crates/yadorilink-sync-substrate/src/native_replication_transport.rs": (
        'pub const YADORI_NATIVE_REPLICATION_ALPN: &[u8] = b"yadorilink/native-replication/v',
    ),
    "crates/yadorilink-replica-domain/src/file.rs": (
        "pub struct FileRecord",
    ),
    # The retired-payload rejection that `resource_lock.rs` used to perform
    # row by row now follows from `check_schema_version_supported` refusing
    # any stamped version that is not exactly the current one -- see the
    # module doc. Watch the mechanism that actually delivers it: both halves
    # of the exact match must stay, because dropping the `<` half alone would
    # silently readmit every database old enough to hold a retired payload.
    # Both halves of the exact match must stay. The `!= 0` term is NOT the
    # guarded property -- it is a wart: `user_version == 0` is also what a
    # brand-new file reports, so this function cannot tell one from a
    # database written before stamping existed. `check_replica_schema_
    # generation` is what draws that line, and the replica index opens
    # through it; watch that it keeps doing so.
    "crates/yadorilink-sqlite-runtime/src/schema.rs": (
        "if on_disk_version > SCHEMA_VERSION {",
        "if on_disk_version != 0 && on_disk_version < SCHEMA_VERSION {",
        "pub fn check_replica_schema_generation",
        "if tables > 0 {",
    ),
    "crates/yadorilink-sync-sqlite/src/replica_schema.rs": (
        "check_replica_schema_generation(conn)?;",
    ),
    # Present AND without `default` -- see the FORBIDDEN entry above.
    "crates/yadorilink-daemon/src/peer_orchestrator/ws_netmap.rs": (
        '#[serde(rename = "groupPolicyLogs")]',
        '#[serde(rename = "policyInvalidGroupIds")]',
    ),
}


# Identifiers a completed retirement removed from EVERY source file. Unlike
# `FORBIDDEN`, these are not tied to one path: the point is that no file
# reintroduces them, including one that does not exist yet.
#
# `wg_public_key` and its wire/config spellings named the WireGuard transport
# key. A device has one key -- its Ed25519 signing key -- and the CLI used to
# send that same key a second time under the retired name purely because the
# coordination plane's column was `NOT NULL`.
#
# `relay_capable` was a per-device flag on a relay-selection path that no
# longer exists; it survived as a column nothing read or wrote.
FORBIDDEN_TREE_WIDE = (
    "wg_public_key",
    "wgPublicKey",
    "wireguard_public_key",
    "wireguardPublicKeyBase64",
    "relay_capable",
    "relayCapable",
    "ChangeBatchFrame",
    "ChangeRequestFrame",
)

TREE_WIDE_ROOTS = ("crates",)
TREE_WIDE_SUFFIXES = (".rs", ".ts", ".sql", ".proto")


def check_forbidden_tree_wide() -> list[str]:
    """Scan every source file for identifiers a retirement removed outright.

    Skips `target/` and `node_modules/`, and this script itself -- which
    necessarily contains every one of these strings.
    """
    failures: list[str] = []
    for root in TREE_WIDE_ROOTS:
        base = ROOT / root
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or path.suffix not in TREE_WIDE_SUFFIXES:
                continue
            parts = path.parts
            if "target" in parts or "node_modules" in parts:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            for needle in FORBIDDEN_TREE_WIDE:
                if needle in text:
                    rel = path.relative_to(ROOT)
                    failures.append(
                        f"{rel}: retired identifier reintroduced: {needle!r}"
                    )
    return failures


def main() -> int:
    failures: list[str] = []

    for relative_path, needles in FORBIDDEN.items():
        path = ROOT / relative_path
        if not path.exists():
            failures.append(f"missing guarded file: {relative_path}")
            continue
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle in text:
                failures.append(
                    f"{relative_path}: forbidden compatibility fallback marker: {needle!r}"
                )

    for relative_path, needles in REQUIRED.items():
        path = ROOT / relative_path
        if not path.exists():
            failures.append(f"missing required exact-generation file: {relative_path}")
            continue
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                failures.append(
                    f"{relative_path}: missing exact-generation marker: {needle!r}"
                )

    failures.extend(check_forbidden_tree_wide())

    for relative_path in RETIRED_FILES_MUST_NOT_EXIST:
        if (ROOT / relative_path).exists():
            failures.append(f"retired file still exists: {relative_path}")

    if failures:
        print("pre-release compatibility debt check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("pre-release compatibility debt check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
