//! Membership's own ports -- what `ReplicaMembershipService` needs from
//! durable storage, the coordination plane, an established peer session, and
//! another replica's own readiness, expressed as `dyn`-safe traits so a real
//! adapter (backed by `SyncState`/`DaemonState`/`reqwest`) and a fake (backed
//! by in-memory state, for unit tests) can both satisfy them. Split into four
//! narrow ports rather than one wide one -- each has an independent reason to
//! vary (a fake ticket port for ticket-lifecycle tests never needs a fake
//! journal too, and vice versa).

use crate::sync_error::SyncError;
use yadorilink_replica_domain::session_state::{FolderLink, MembershipOperationScan};

use super::common::BoxFuture;
use crate::application::model::{
    MembershipCommitOutcome, MembershipOperationLookup, MembershipRemoteCommand,
};

/// The durable membership-journal reads/writes `ReplicaMembershipService`
/// needs. Deliberately narrow: only the specific atomic transitions the
/// membership-mutation sagas actually perform, never a generic SQL/
/// transaction escape hatch a caller could use to reach outside this
/// contract.
pub(crate) trait MembershipRepository: Send + Sync {
    /// Opens a fresh `membership_operations` journal row. `Ok(false)` means
    /// `operation_id` already names a row (the caller retries under a new
    /// id); an existing row is never overwritten.
    #[allow(clippy::too_many_arguments)]
    fn try_insert_operation(
        &self,
        operation_id: &str,
        action: yadorilink_replica_domain::session_state::MembershipOperationAction,
        commit_mode: yadorilink_replica_domain::session_state::MembershipCommitMode,
        removed_device_id: &str,
        group_ids: &[String],
        target_device_ids: &[String],
        lease_ids: &[Option<String>],
        durability_scope: yadorilink_replica_domain::session_state::MembershipDurabilityScope,
        latch_group_ids: &[String],
    ) -> Result<bool, String>;

    /// Deletes a settled (`Completed`/`DefinitelyRejected`) row.
    fn settle_operation(&self, operation_id: &str);

    fn mark_ambiguous(&self, operation_id: &str, detail: &str);

    fn mark_recovery_blocked(&self, operation_id: &str, detail: &str);

    fn mark_local_settlement_pending(&self, operation_id: &str, detail: &str);

    /// Deletes a row whose scope became known (an unknown-scope marker
    /// converted to per-group latches).
    fn discard_operation(&self, operation_id: &str);

    /// Every NOT-terminal-or-blocked `membership_operations` row -- the
    /// recovery sweep's own work list.
    fn scan_open_operations(&self) -> Result<MembershipOperationScan, SyncError>;

    fn list_links(&self) -> Result<Vec<FolderLink>, SyncError>;

    fn latch_group_durability_unknown(&self, group_id: &str) -> Result<(), SyncError>;
}

/// The coordination-plane HTTP calls a membership mutation needs: dispatch
/// (whichever of the four Worker endpoints `command.commit_mode` names),
/// eager-group enumeration, operation lookup, edge resolution, and the
/// best-effort force-override audit trail.
pub(crate) trait MembershipCoordination: Send + Sync {
    /// Whether this device currently has a coordination-plane address/
    /// access token recorded. Checked BEFORE the membership journal is even
    /// opened -- refusing early keeps a coordination outage from ever
    /// producing a journal row for an attempt that was never made.
    fn is_configured(&self) -> bool;

    fn fetch_eager_groups<'a>(
        &'a self,
        device_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<String>, String>>;

    /// Sends `command` to whichever Worker endpoint `command.commit_mode`
    /// names, under `operation_id`. Pure remote dispatch with no journal
    /// side effects of its own.
    fn dispatch<'a>(
        &'a self,
        command: &'a MembershipRemoteCommand,
        operation_id: &'a str,
    ) -> BoxFuture<'a, MembershipCommitOutcome>;

    fn query_operation<'a>(
        &'a self,
        operation_id: &'a str,
    ) -> BoxFuture<'a, Result<MembershipOperationLookup, String>>;

    /// Resolves a share-edge id to its `(group_id, device_id)`.
    fn resolve_edge<'a>(
        &'a self,
        edge_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<(String, String)>, String>>;

    /// The coordination plane's membership state for one (group, device)
    /// edge -- `"active"` for a live member, or one of the not-yet-admitted
    /// states for an edge that has never been granted anything.
    ///
    /// `Ok(None)` means the answer is genuinely unknown (no such edge in
    /// this account's listing, or a coordination plane that does not report
    /// edge state at all), NOT "not active"; `Err` means the question could
    /// not be asked. Callers must treat both as "assume active" -- this
    /// exists to let a targeted revoke skip a guard that provably cannot
    /// apply, so only a POSITIVE non-active answer may relax anything.
    fn fetch_edge_state<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>, String>>;

    /// Best-effort audit record for a `--force` override. Never fails the
    /// caller -- a timeout/error here is logged by the adapter, not
    /// propagated.
    fn record_force_override_audit<'a>(
        &'a self,
        local_device_id: &'a str,
        target_device_id: &'a str,
        group_ids: &'a [String],
    ) -> BoxFuture<'a, ()>;
}

/// The one dependency a ticket-bound removal cannot exercise against a mock
/// HTTP server: a lease-bound removal's ticket is obtained/released over an
/// established peer-to-peer session, not the coordination plane's own HTTP
/// API.
pub(crate) trait HandoffTicketPort: Send + Sync {
    fn obtain_ticket<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, Option<yadorilink_peer_session::peer_session::PeerHandoffTicketGrant>>;

    /// `Err` means the release could not be confirmed (no active session,
    /// or the peer-side release call itself failed) -- the coordination
    /// plane's own lease TTL remains the final backstop either way, so
    /// callers only need to log this, never block a settlement on it.
    fn release_ticket<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
        target_device_id: &'a str,
        lease_id: &'a str,
    ) -> BoxFuture<'a, Result<(), String>>;
}

/// Whether another full replica of a folder group is ready to take over
/// sync duty, excluding one candidate device -- the guard a same-device
/// (self-)removal checks before letting a group become unprotected.
pub(crate) trait ReplicaReadinessPort: Send + Sync {
    fn another_full_replica_is_ready_excluding<'a>(
        &'a self,
        group_id: &'a str,
        excluded_device_id: &'a str,
    ) -> BoxFuture<'a, bool>;

    /// Whether this device's OWN verified group policy positively shows
    /// `device_id` is not a member of `group_id`.
    ///
    /// `false` for every uncertain case -- no verified policy loaded, a
    /// policy marked untrusted, or a device the verified chain does list --
    /// so a caller may relax a safety gate only on a positive answer from
    /// evidence this device checked itself, never on a coordination-plane
    /// statement alone.
    fn verified_policy_shows_non_member<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, bool>;

    /// The subset of `candidate_group_ids` this device's OWN evidence shows
    /// `device_id` holding as an eager (full) replica: the netmap role it is
    /// recorded with, plus -- when a live session exists -- the peer's own
    /// answer to a direct durability-summary question.
    ///
    /// Evidence can only ADD groups to a removal's at-risk set, never remove
    /// one: an unreachable peer or a refusal contributes nothing, and the
    /// coordination plane's list is never narrowed by it.
    fn peer_eager_replica_groups<'a>(
        &'a self,
        device_id: &'a str,
        candidate_group_ids: &'a [String],
    ) -> BoxFuture<'a, Vec<String>>;

    /// Every group this device's netmap shows `device_id` sharing with this
    /// account (any role). Read from the live netmap view only -- no peer
    /// round trip -- so it is answerable even when the coordination plane is
    /// not.
    fn groups_shared_with_peer<'a>(&'a self, device_id: &'a str) -> BoxFuture<'a, Vec<String>>;
}
