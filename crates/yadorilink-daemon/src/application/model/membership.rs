//! Membership's protocol-independent request/result types -- owned by
//! `application` so `ReplicaMembershipService`'s business logic never needs
//! to import the coordination-client module directly. That module
//! re-exports these same definitions (rather than keeping a second,
//! independently-drifting copy) so every OTHER existing caller of these
//! types (`recovery_diagnosis`, `control_socket`) keeps compiling against
//! the identical type, unchanged.

use yadorilink_replica_domain::session_state::{
    MembershipCommitMode, MembershipDurabilityScope, MembershipOperation, MembershipOperationAction,
};

/// The result of a successful role-loss commit -- this is entirely the
/// coordination-plane's own view: it carries no root-digest/content field,
/// since the Worker only ever adjudicates membership/eligibility, never file
/// paths, block hashes, or version content. Kept as a plain struct (rather
/// than the proto type) so neither `application` nor `coordination_client`
/// need a dependency on `yadorilink-ipc-proto` to carry this value around.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffCommitResult {
    pub target_device_id: String,
    pub membership_generation: i64,
    pub lease_id: Option<String>,
}

/// Terminal outcome of reverting a role loss on the coordination plane:
/// the source device's full-replica role was restored, or the coordination
/// plane reports the operation superseded. Both settle the local journal
/// row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleLossCompensationOutcome {
    Restored,
    Superseded,
}

/// Outcome of a role-loss commit, preserving whether it is safe to discard
/// the source-side Prepared journal row. Only an explicit 4xx response is a
/// protocol-level guarantee that the Worker rejected the transaction before
/// committing it. Transport failures, 5xx responses, and malformed 2xx
/// responses are ambiguous because the Worker may already have committed.
/// Shared by `ReplicaMembershipService`'s ticket-bound guarded revoke and
/// `ReplicaRoleService`'s demote/unlink role-loss commits -- both go through
/// the same coordination-plane handoff-commit endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleLossCommitOutcome {
    Committed(HandoffCommitResult),
    /// The Worker definitively refused this request without committing it.
    /// A different operation may be attempted under a fresh operation_id.
    DefinitelyRejected(String),
    /// This operation_id already belongs to a differently-shaped request
    /// (HTTP 409). Never release tickets/leases or fall through to
    /// `--force` automatically on this outcome.
    Conflict(String),
    /// The Worker may already have committed the request.
    Ambiguous(String),
}

/// A membership operation's terminal outcome, as recorded durably by the
/// coordination plane's `membership_operations` table. Deliberately not an
/// `Option<T>` -- see `MembershipOperationLookup`'s own doc comment for why
/// "definitely rejected" and "never heard of it" must stay distinguishable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipRemoteStatus {
    Committed,
    DefinitelyRejected,
}

/// The mode-specific payload a `Committed` operation may carry. Every field
/// is optional because the four membership-mutation endpoints populate
/// different subsets (a plain/ticket-bound device removal reports
/// `affected_group_ids`; a revoke reports `target_device_id`/
/// `membership_generation`/`lease_id`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MembershipRemoteResult {
    /// `None` means the field was absent from the response. `Some(vec![])`
    /// means the Worker explicitly confirmed no groups were affected. A
    /// caller latching a committed removal's real scope must keep these two
    /// cases distinguishable -- collapsing an absent field to an empty
    /// `Vec` reads a malformed or unexpected response as "confirmed zero
    /// groups", which would silently clear an unknown-scope marker without
    /// ever latching the groups it was protecting.
    pub affected_group_ids: Option<Vec<String>>,
    pub target_device_id: Option<String>,
    pub membership_generation: Option<i64>,
    pub lease_id: Option<String>,
}

/// One group's identity within a [`MembershipRemoteRequest`] -- index-free,
/// unlike the local journal row's parallel `group_ids`/`target_device_ids`/
/// `lease_ids` arrays, since the Worker returns groups pre-zipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipRemoteRequestGroup {
    pub group_id: String,
    pub target_device_id: Option<String>,
    pub lease_id: Option<String>,
}

/// The exact canonical request the coordination plane fingerprinted
/// `operation_id` against -- read back alongside the operation's outcome so
/// a caller can confirm this record actually describes what its OWN local
/// journal thinks it does before trusting `status`/`result`. Comparing only
/// `action`/`removed_device_id` is not enough: two different requests can
/// share both while differing in `mode` or which groups/targets/leases are
/// involved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipRemoteRequest {
    pub action: String,
    pub removed_device_id: String,
    pub mode: String,
    pub groups: Vec<MembershipRemoteRequestGroup>,
}

/// A membership operation record read back from the coordination plane,
/// scoped by this device's own account (never by device ownership).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipOperationRecord {
    pub status: MembershipRemoteStatus,
    pub action: String,
    pub removed_device_id: String,
    pub request_fingerprint: String,
    pub request: MembershipRemoteRequest,
    pub result: Option<MembershipRemoteResult>,
    pub rejection_code: Option<String>,
    pub rejection_detail: Option<String>,
}

/// The result of looking up a membership operation by id. Kept as an
/// explicit two-variant enum rather than `Option<MembershipOperationRecord>`
/// so a caller cannot mistake "definitely rejected" (a real, terminal,
/// recorded outcome inside `Found`) for "the coordination plane has never
/// heard of this operation_id" (`NotFound` -- e.g. the request never even
/// reached the Worker).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipOperationLookup {
    Found(Box<MembershipOperationRecord>),
    NotFound,
}

/// The 3-way outcome shared by every membership-mutation commit path (plain
/// revoke/remove, ticket-bound guarded revoke, ticket-bound multi-group
/// removal), so `ReplicaMembershipService` can handle all of them
/// identically. An `Ambiguous` result means the coordination plane may
/// already have committed -- it must never be treated the same as
/// `DefinitelyRejected`.
#[derive(Debug, Clone)]
pub(crate) enum MembershipCommitOutcome {
    Committed(MembershipCommitResult),
    DefinitelyRejected(String),
    Ambiguous(String),
    /// HTTP 409: this operation_id already names a different request. See
    /// `crate::application::ReplicaMembershipError::OperationConflict`'s own
    /// doc comment.
    Conflict(String),
}

/// Structured payload of a `Committed` outcome. `handoff` is only ever
/// `Some` for a single-group guarded revoke (the one mode whose Worker
/// response carries a real `membershipGeneration`); every other mode's
/// response body has nothing worth preserving.
#[derive(Debug, Clone)]
pub(crate) struct MembershipCommitResult {
    pub(crate) handoff: Option<HandoffCommitResult>,
}

impl MembershipCommitResult {
    pub(crate) const NONE: Self = Self { handoff: None };
}

/// A remote membership mutation, fully described in one shape regardless of
/// which of the four Worker endpoints ultimately carries it -- what
/// `ReplicaMembershipService::execute_membership_operation` journals and,
/// together with `commit_mode`, dispatches. `group_ids`/`target_device_ids`/
/// `lease_ids` are index-parallel; empty for `PlainRevoke`
/// (`target_device_ids`/`lease_ids` only -- `group_ids` still names the one
/// group) and `PlainRemoveDevice` (all three empty -- a plain removal names
/// no groups at all, matching the coordination plane's own fingerprint
/// contract for that endpoint).
#[derive(Debug, Clone)]
pub(crate) struct MembershipRemoteCommand {
    pub(crate) action: MembershipOperationAction,
    pub(crate) commit_mode: MembershipCommitMode,
    pub(crate) removed_device_id: String,
    pub(crate) group_ids: Vec<String>,
    pub(crate) target_device_ids: Vec<String>,
    pub(crate) lease_ids: Vec<Option<String>>,
    /// Whether the set of folder groups this operation puts at risk is
    /// known. `Unknown` for a `--force` removal whose eager-group
    /// enumeration failed; `Known` otherwise (including every ticket-bound
    /// mutation, which verified durability up front by construction).
    pub(crate) durability_scope: MembershipDurabilityScope,
    /// Folder groups to latch `DurabilityUnknown` once (and only once) this
    /// operation's remote mutation is CONFIRMED committed. Empty unless this
    /// command is a `--force` plain revoke/remove past a KNOWN but unready
    /// set of groups.
    pub(crate) latch_group_ids: Vec<String>,
}

impl MembershipRemoteCommand {
    /// Reconstructs the exact command a durable journal `row` describes --
    /// used to re-send a stuck row's original mutation, unchanged, under its
    /// own already-recorded `operation_id`.
    pub(crate) fn from_row(row: &MembershipOperation) -> Self {
        Self {
            action: row.action,
            commit_mode: row.commit_mode,
            removed_device_id: row.removed_device_id.clone(),
            group_ids: row.group_ids.clone(),
            target_device_ids: row.target_device_ids.clone(),
            lease_ids: row.lease_ids.clone(),
            durability_scope: row.durability_scope,
            latch_group_ids: row.latch_group_ids.clone(),
        }
    }
}
