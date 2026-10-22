//! The canonical translation from a local `membership_operations` journal
//! row to the exact request shape the coordination plane's own lookup
//! (`GET /devices/membership-operations/:operationId`) reports back as
//! `record.request` -- shared by every caller that needs to compare a
//! journal row's identity against a remote record: the existing
//! reconcilers in `replica_membership_service.rs`, and the
//! evidence-identity qualification (the recovery-diagnosis module). A single
//! shared implementation means both stay in agreement by construction --
//! two independently-maintained canonicalizations could silently drift
//! apart, making one caller settle an operation the other would have
//! flagged as a mismatch.

use yadorilink_replica_domain::session_state::{MembershipCommitMode, MembershipOperation};

use super::model::{MembershipRemoteRequest, MembershipRemoteRequestGroup};

/// The local journal row's own request, in the SAME shape a Worker lookup's
/// `record.request` comes back as. `group_ids`/`target_device_ids`/
/// `lease_ids` are sorted by `group_id` to match
/// the coordination service's own
/// `canonicalRequest` ordering (fingerprinting/storage order-independent by
/// construction) -- comparing the RAW, unsorted local arrays against the
/// Worker's canonical order would report a false mismatch for a
/// request whose groups were simply presented in a different order.
pub(crate) fn expected_membership_remote_request(
    row: &MembershipOperation,
) -> MembershipRemoteRequest {
    let mut groups: Vec<MembershipRemoteRequestGroup> = row
        .group_ids
        .iter()
        .enumerate()
        .map(|(index, group_id)| MembershipRemoteRequestGroup {
            group_id: group_id.clone(),
            target_device_id: row.target_device_ids.get(index).cloned(),
            lease_id: row.lease_ids.get(index).cloned().flatten(),
        })
        .collect();
    groups.sort_by(|left, right| left.group_id.cmp(&right.group_id));
    MembershipRemoteRequest {
        action: row.action.as_db_str().to_string(),
        removed_device_id: row.removed_device_id.clone(),
        mode: membership_wire_mode(row.commit_mode).to_string(),
        groups,
    }
}

/// Translates the daemon's own 4-way `MembershipCommitMode` into the
/// coordination plane's coarser `MembershipOperationMode` wire vocabulary
/// (the coordination service) -- the Worker tracks
/// `mode: "guarded"` for every revoke (plain OR ticket-bound: see
/// `revokeAccess`/`commitHandoffRoleLoss` in `shares/service.ts`) and for a
/// ticket-bound device removal (`removeDeviceWithHandoffLeases`), and only
/// `mode: "plain"` for an UNticketed device removal (`removeDevice`). This
/// is NOT the same split as `PlainRevoke`/`GuardedRevoke` -- mapping
/// `commit_mode.as_db_str()` directly here would report a false mismatch
/// for every real production row.
pub(crate) fn membership_wire_mode(commit_mode: MembershipCommitMode) -> &'static str {
    match commit_mode {
        MembershipCommitMode::PlainRevoke
        | MembershipCommitMode::GuardedRevoke
        | MembershipCommitMode::HandoffRemoveDevice => "guarded",
        MembershipCommitMode::PlainRemoveDevice => "plain",
    }
}
