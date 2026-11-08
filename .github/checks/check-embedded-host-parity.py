#!/usr/bin/env python3
"""Every command the daemon serves is accounted for in the embedded host.

The desktop daemon answers the requests of `DaemonControlRequest`. The embedded host (the iOS
and Windows engine) serves the same operations as typed `Command`s with the same DTOs. This guard
makes the two surfaces move together: each request payload must be listed here as

* `HOST`: the host command that serves it (the variant must exist in the host's `Command`),
* `DESKTOP_ONLY`: a process or operating-system concern the host does not have, with the reason, or
* `GAPS`: served by the daemon, not yet by the host. The list only shrinks.

A new daemon request fails the check until it is classified; a stale entry (a payload that no
longer exists, a host variant that was renamed, a gap that is now served) fails too.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROTO = ROOT / "crates/yadorilink-ipc-proto/proto/daemon_control.proto"
HOST = ROOT / "crates/yadorilink-embedded-host/src/commands.rs"

HOST_COMMANDS = {
    "link": "LinkFolder",
    "unlink": "Unlink",
    "list_links": "ListFolders",
    "pause": "PauseLink",
    "resume": "ResumeLink",
    "status": "Status",
    "restore_version": "RestoreVersion",
    "list_versions": "ListItemVersions",
    "list_trash": "ListDeletedItems",
    "list_preserved": "ListPreserved",
    "restore_preserved": "RestorePreserved",
    "discard_preserved": "DiscardPreserved",
    "get_space_management": "SpaceManagement",
    "set_space_management": "SetSpaceManagement",
    "get_network_policy": "NetworkPolicy",
    "set_sync_on_metered": "SetSyncOnMetered",
    "report_network_cost": "ReportNetworkCost",
    "list_activity": "ListActivity",
    "create_send_link": "CreateSendLink",
    "redeem_send_link": "RedeemSendLink",
    "cancel_send_link": "CancelSendLink",
    "send_link_status": "SendLinkStatus",
    "preview_send_link": "PreviewSendLink",
    "send_file": "SendToLink",
    "list_inbox": "ListInbox",
    "receive_transfer": "ReceiveTransfer",
    "list_sent_transfers": "ListSentTransfers",
    "cancel_transfer": "CancelTransfer",
    "create_and_link_command": "CreateShare",
    "join_and_link_command": "JoinGroup",
    "accept_invite_command": "JoinShare",
    "readopt_volume": "ReadoptMarkedFolder",
    "set_retention_rule": "SetRetentionRule",
    "evict": "EvictItem",
    "materialization_status": "ItemRetention",
    "preview_space_reclaim": "PreviewSpaceReclaim",
    "list_conflicts": "ListConflicts",
    "resolve_conflict": "ResolveConflict",
    "list_provider_pending": "ListProviderPending",
    "retry_preserved": "RetryPreserved",
    "mint_invite_command": "MintInvite",
    "retry_transfer": "RetryTransfer",
    "restore_trash_operation": "RestoreDeletedOperation",
    # One deleted file or folder comes back as an ordinary write that names the version.
    "restore_trash": "ApplyChange",
    "revoke_device_command": "RevokeMember",
}

DESKTOP_ONLY = {
    "ignore_rules_get": "a folder's ignore rules are edited by the desktop hosts through the client facade",
    "ignore_rules_set": "a folder's ignore rules are edited by the desktop hosts through the client facade",
    "shutdown": "the host owns the engine's lifetime (start/stop)",
    "health": "a liveness probe of a separate process",
    "identify": "tells a client which daemon build answers on a socket",
    "request_safe_stop": "service-manager stop coordination",
    "reporting_status": "usage and error reporting of the desktop product",
    "generate_usage_report": "usage and error reporting of the desktop product",
    "generate_last_error_report": "usage and error reporting of the desktop product",
    "submit_report": "usage and error reporting of the desktop product",
    "update_consent": "usage and error reporting of the desktop product",
    "list_queue_items": "the desktop report queue",
    "show_queue_item": "the desktop report queue",
    "delete_queue_item": "the desktop report queue",
    "flush_queue": "the desktop report queue",
    "update_status": "self-update of an installed desktop build; the app store updates the host",
    "update_check": "self-update of an installed desktop build; the app store updates the host",
    "update_install": "self-update of an installed desktop build; the app store updates the host",
    "update_config": "self-update of an installed desktop build; the app store updates the host",
    "update_version_check": "self-update of an installed desktop build; the app store updates the host",
    "update_verified_entry": "self-update of an installed desktop build; the app store updates the host",
    "list_connection_traces": "desktop diagnostics over the socket; the host reads them in process",
    "connectivity_doctor": "desktop diagnostics over the socket; the host reads them in process",
    "diagnostics_preview": "desktop diagnostics bundle",
    "diagnostics_export": "desktop diagnostics bundle",
    "open_nas_admin": "opens a NAS admin page from the desktop app",
    "resolve_folder": "resolves a path the desktop CLI was given",
    "list_account_devices": "the local web dashboard's device names; the apps read the account list themselves",
    "list_share_edges": "the local web dashboard's folder members; the apps read the account's shares themselves",
    "hydrate": "the operating system downloads a provider folder's item when it is opened; the daemon refuses an explicit download there too",
    "check_full_replica_handoff_ready": "the CLI's multi-step orchestration; the host runs enrollment in process",
    "check_full_replica_handoff_ready_excluding": "the CLI's multi-step orchestration; the host runs enrollment in process",
    "latch_group_durability_unknown": "the CLI's multi-step orchestration; the host runs enrollment in process",
    "remove_pending_enrollment": "the CLI's multi-step orchestration; the host runs enrollment in process",
    "request_handoff_lease": "the CLI's multi-step orchestration; the host runs enrollment in process",
    "obtain_handoff_ticket": "the CLI's multi-step orchestration; the host runs enrollment in process",
    "release_handoff_ticket": "the CLI's multi-step orchestration; the host runs enrollment in process",
}

GAPS = {
    "delete_group_command",
    "remove_device_command",
    "revoke_edge_command",
    "list_retained_originals",
    "release_retained_originals",
    "list_recovery_operations",
    "show_recovery_operation",
    "rewind_preview",
    "rewind_execute",
    "rewind_status",
    "set_storage_mode",
    "mark_link_not_rejoined",
    "link_preflight",
    "gc",
    "limits_set",
    "limits_show",
}


def payloads(proto: str) -> list[str]:
    body = re.search(r"message DaemonControlRequest \{(.*?)\n\}", proto, re.S)
    if not body:
        raise SystemExit("DaemonControlRequest not found")
    return [
        name
        for ty, name in re.findall(r"(\w+)\s+(\w+)\s*=\s*\d+;", body.group(1))
        if ty != "uint32" and name != "protocol_version"
    ]


def enum_variants(source: str, enum: str) -> set[str]:
    m = re.search(rf"pub enum {enum}\b[^{{]*\{{", source)
    if not m:
        raise SystemExit(f"enum {enum} not found")
    depth, i, start = 1, m.end(), m.end()
    while depth:
        depth += {"{": 1, "}": -1}.get(source[i], 0)
        i += 1
    body = source[start : i - 1]
    # top-level variants only: indentation of exactly four spaces
    return set(re.findall(r"^    ([A-Z]\w*)", body, re.M))


def problems(names: list[str], variants: set[str]) -> list[str]:
    out = []
    known = set(HOST_COMMANDS) | set(DESKTOP_ONLY) | GAPS
    classes = [set(HOST_COMMANDS), set(DESKTOP_ONLY), GAPS]
    for name in names:
        if name not in known:
            out.append(f"daemon request `{name}` is not classified (HOST, DESKTOP_ONLY or GAPS)")
    for name in sorted(known - set(names)):
        out.append(f"`{name}` is classified but the daemon no longer serves it")
    for i, a in enumerate(classes):
        for b in classes[i + 1 :]:
            for name in sorted(a & b):
                out.append(f"`{name}` is in more than one class")
    for name, variant in HOST_COMMANDS.items():
        if variant not in variants:
            out.append(f"`{name}` maps to host command `{variant}`, which does not exist")
    return out


def main() -> int:
    if "--self-test" in sys.argv:
        bad = problems(["link", "brand_new"], {"LinkFolder"})
        assert any("brand_new" in p and "not classified" in p for p in bad), bad
        assert any("`pause`" in p and "no longer serves" in p for p in bad), bad
        assert any("`Unlink`" in p for p in bad), bad
        print("check-embedded-host-parity self-test ok")
        return 0
    variants = enum_variants(HOST.read_text(encoding="utf-8"), "Command")
    found = problems(payloads(PROTO.read_text(encoding="utf-8")), variants)
    for p in found:
        print(f"embedded-host parity: {p}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
