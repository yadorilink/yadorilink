//! HTTP handlers and the JSON shapes they produce. Every handler is a thin
//! translation: build a `DaemonControlRequest` payload from the HTTP
//! request, send it over `ControlClient`, translate the
//! `DaemonControlResponse` payload into JSON. No handler here computes
//! anything the daemon didn't already compute.
//!
//! Enum fields (`PeerStatus.reachability`, `LinkStatus.durability_status`,
//! ...) are serialized using prost's generated `as_str_name()` -- the exact
//! `SCREAMING_SNAKE_CASE` identifier from `daemon_control.proto` (e.g.
//! `"PEER_REACHABILITY_CONNECTED"`) -- rather than a hand-picked friendlier
//! vocabulary, so the JSON never drifts from the wire protocol it mirrors.
//! `MaterializationState` is the one exception: it reuses the lowercase
//! words `yadorilink-cli`'s own `commands/materialization.rs` already
//! established for this exact enum (`"hydrated"`, `"placeholder"`,
//! `"hydrating"`, `"evicting"`, `"unknown"`), since that vocabulary is
//! already user-facing prior art this adapter should match rather than
//! duplicate differently.

pub mod events;
pub mod linking;
pub mod reads;
pub mod writes;

use serde_json::{json, Value};
use yadorilink_ipc_proto::daemonctl::{LinkStatus, LocalState, PeerStatus};

pub fn link_status_json(l: &LinkStatus) -> Value {
    let mut value = json!({
        "local_path": l.local_path,
        "group_id": l.group_id,
        "paused": l.paused,
        "conflict_count": l.conflict_count,
        "materialization_policy": l.materialization_policy,
        "hydrated_count": l.hydrated_count,
        "placeholder_count": l.placeholder_count,
        "hydrating_count": l.hydrating_count,
        "held_file_count": l.held_file_count,
        "held_files": l.held_files.iter().map(|h| json!({
            "path": h.path,
            "reason": h.reason,
            "held_since_unix_nanos": h.held_since_unix_nanos,
        })).collect::<Vec<_>>(),
        "skipped_symlink_count": l.skipped_symlink_count,
        "degraded": l.degraded,
        "degraded_reason": l.degraded_reason,
        "has_active_transfer": l.has_active_transfer,
        "transfer_bytes_done": l.transfer_bytes_done,
        "transfer_bytes_total": l.transfer_bytes_total,
        "transfer_blocks_done": l.transfer_blocks_done,
        "transfer_blocks_total": l.transfer_blocks_total,
        "transfer_eta_seconds": l.transfer_eta_seconds,
        "durability_status": l.durability_status().as_str_name(),
        "policy_stale": l.policy_stale,
        "ambiguous": l.ambiguous,
        "ambiguous_local_paths": l.ambiguous_local_paths,
        "local_storage_state": l.local_storage_state().as_str_name(),
        "fetch_availability": l.fetch_availability().as_str_name(),
        "full_replica_device_ids": l.full_replica_device_ids,
        "durability_evidence": l.durability_evidence().as_str_name(),
        "durability_check_pending": l.durability_check_pending,
        "conflicts_pending": l.conflicts_pending,
        "conflict_note": l.conflict_note,
        "capture_volume_changed": l.capture_volume_changed,
        "capture_volume_unconfirmed": l.capture_volume_unconfirmed,
        "stranded_directory_count": l.stranded_directory_count,
        "requested_content_count": l.requested_content_count,
        // The two product dimensions exactly as the daemon derived them; the
        // page never recomputes them from the fields above.
        "availability": l.availability().as_str_name(),
        "availability_reachable_device_ids": l.availability_reachable_device_ids,
        "availability_offline_device_ids": l.availability_offline_device_ids,
        "availability_update_required_device_ids": l.availability_update_required_device_ids,
        "protection": l.protection().as_str_name(),
        "protection_device_ids": l.protection_device_ids,
        "paused_until_unix": l.paused_until_unix,
    });
    // Added apart from the literal above, which is at the macro's recursion limit.
    value["unreadable_file_count"] = json!(l.unreadable_file_count);
    value["pending_approvals"] = json!(l.pending_approvals);
    value["reclaimable_bytes"] = json!(l.reclaimable_bytes);
    value["unreadable_files"] = l
        .unreadable_files
        .iter()
        .map(|f| json!({ "path": f.path, "reason": f.reason }))
        .collect::<Vec<_>>()
        .into();
    value
}

pub fn peer_status_json(p: &PeerStatus) -> Value {
    json!({
        "device_id": p.device_id,
        "reachability": p.reachability().as_str_name(),
        "unreachable_category": p.unreachable_category().as_str_name(),
        "route_kind": p.route_kind().as_str_name(),
    })
}

/// A path's local state as JSON: the two independent facts, the transition
/// and the one derived word (see `local_state_word`).
pub fn local_state_json(s: Option<&LocalState>) -> Value {
    json!({
        "local_object_present": s.is_some_and(|s| s.local_object_present),
        // Never true unless the daemon said so.
        "current_content_present": s.is_some_and(|s| s.current_content_present),
        "word": yadorilink_ipc_proto::daemonctl::local_state_word(s),
    })
}
