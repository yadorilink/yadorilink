//! `ListLinks`/`Status`'s shared per-link read model -- the first vertical
//! slice of the control-socket query boundary: a plain, non-protobuf view
//! (`LinkStatusView`) behind a narrow port (`LinkStatusReadPort`), backed
//! today by an adapter (`DaemonLinkStatusReader`) that still holds
//! `Arc<DaemonState>` -- seeing every field this view
//! aggregates already lives on `DaemonState`/its owned components, that's
//! a deliberate strangler step, not a shortcut: the port is the real
//! boundary, and the control socket handler now depends on it, not on
//! `DaemonState`.

use std::sync::Arc;

use crate::durability_service::{DurabilityEvidence, GroupDurabilityStatus};

/// This link's TRUTHFUL current local storage state -- distinct
/// from `materialization_policy` (the CONFIGURED target, "eager" |
/// "ondemand"), which only says what this device is trying to become, not
/// what it currently holds. Deliberately NOT derived from policy alone:
/// an eager link that hasn't finished catching up must report
/// `PartiallyMaterialized`, never `FullCopy`, until every current file is
/// recorded hydrated.
///
/// Trust boundary: `FullCopy`
/// reflects the `files.materialization_state` DB column's bookkeeping, not
/// a live disk verification (existence/size/block-content check) -- a row
/// left `Present` after its on-disk file is externally deleted or
/// corrupted would still report `FullCopy` until the separate
/// materialization-repair backstop reconciles it. Actually verifying disk
/// state on every `status` call would make every invocation stat every
/// file, a cost out of proportion to this read-only query; the repair
/// backstop is the real fix for that drift, out of this pass's scope. The
/// variant name and doc wording are deliberately scoped to what this
/// derivation actually proves ("recorded hydrated"), not a stronger claim
/// disk verification alone would justify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalStorageState {
    /// Materialization policy is eager AND every current file is recorded
    /// hydrated (see this enum's own doc comment for the DB-bookkeeping
    /// vs. live-disk-verification distinction).
    FullCopy,
    /// Materialization policy is eager, but at least one current file is
    /// still a placeholder or hydrating -- this device intends to become a
    /// full copy but is not one yet.
    PartiallyMaterialized,
    /// Materialization policy is on-demand -- placeholders for
    /// not-yet-opened files are this link's normal steady state, not a
    /// transient "catching up" condition.
    OnDemand,
}

/// Whether this link's required current-version content can
/// actually be obtained right now, locally or through a valid serving
/// path. Deliberately NOT an alias for `PeerReachability` -- a reachable
/// peer that isn't a full-replica writer for this group proves nothing
/// about fetchability, and content already hydrated locally is available
/// regardless of any peer's reachability at all. See
/// `DaemonLinkStatusReader::fetch_availability`'s own doc comment for the
/// exact derivation and its link-level aggregation rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FetchAvailability {
    /// Every current file's content is either already hydrated locally, or
    /// this device knows of a currently-reachable full-replica peer that
    /// can serve what isn't.
    AvailableNow,
    /// At least one current file is neither hydrated locally nor
    /// obtainable from any currently-reachable full-replica peer.
    UnavailableNow,
    /// This daemon cannot currently vouch for either answer (the same
    /// daemon-wide "cannot currently confirm" condition that gates
    /// `durability_status` to `Unknown` -- see
    /// `DaemonState::daemon_wide_evidence_uncertain`).
    Unknown,
}

/// One held (pinned, undeletable-on-demand) file within a link, as
/// reported by `SyncState::get_held_state`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldFileView {
    pub(crate) path: String,
    pub(crate) reason: String,
    pub(crate) held_since_unix_nanos: i64,
}

/// A link's Degraded (disk-pressure) state, if any -- see
/// `DegradedLinkInfo`'s own doc comment for what
/// this tracks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DegradedLinkView {
    pub(crate) reason: String,
}

/// A link's active-transfer rollup, if any transfer is currently in
/// flight for it -- see `crate::transfer_progress::LinkProgressRollup`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkTransferView {
    pub(crate) bytes_done: u64,
    pub(crate) bytes_total: u64,
    pub(crate) blocks_done: u64,
    pub(crate) blocks_total: u64,
    pub(crate) eta_seconds: Option<u64>,
}

/// One linked folder's full status, as `ListLinks`/`Status` report it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinkStatusView {
    /// The link's identity key; for a provider folder (`provider` is `Some`) NOT a path.
    pub(crate) local_path: String,
    /// `(root_id, display_name)` of a provider-backed folder.
    pub(crate) provider: Option<(String, String)>,
    pub(crate) group_id: String,
    pub(crate) paused: bool,
    /// Unix time a timed pause ends; 0 when not paused or paused until resumed.
    pub(crate) paused_until_unix: i64,
    pub(crate) conflict_count: u64,
    /// Paths contested in the replicated state, not yet resolved by their fork.
    pub(crate) conflicts_pending: u64,
    /// Why a resolved conflict has not reached the local files yet, when it has not.
    pub(crate) conflict_note: String,
    /// `MaterializationPolicy::as_db_str()`'s own stable string, not
    /// re-derived as a separate enum here -- see that method's own doc.
    pub(crate) materialization_policy: String,
    pub(crate) hydrated_count: u64,
    pub(crate) placeholder_count: u64,
    pub(crate) hydrating_count: u64,
    /// Content fetches requested and not finished (see `LinkStatus.requested_content_count`).
    pub(crate) requested_content_count: u64,
    pub(crate) held_files: Vec<HeldFileView>,
    pub(crate) skipped_symlink_count: u64,
    /// Directories a removal moved aside and could not put back; each still
    /// stands, with its contents, under a reserved name beside its old place.
    pub(crate) stranded_directory_count: u64,
    /// Files a scan could not read that need the person (sorted by path, all of them).
    pub(crate) unreadable_files: Vec<yadorilink_local_capture::unreadable::UnreadableFile>,
    /// Invite acceptances waiting on this account's approval to join the group.
    pub(crate) pending_approvals: u32,
    pub(crate) degraded: Option<DegradedLinkView>,
    pub(crate) transfer: Option<LinkTransferView>,
    pub(crate) durability_status: GroupDurabilityStatus,
    /// What kind of evidence `durability_status` is currently standing on.
    ///
    /// A separate axis on purpose. `Protected` used to mean exactly one
    /// thing -- a peer had recently read back and re-checksummed every byte
    /// of every durability root -- and no longer does, because establishing
    /// that cost one round-trip and one whole-file re-read per root, every
    /// ninety seconds. This field is where that is said out loud rather than
    /// left for a reader to discover.
    pub(crate) durability_evidence: DurabilityEvidence,
    /// `durability_status` is `Unknown` only because the first custody check
    /// for this group has not run yet.
    pub(crate) durability_check_pending: bool,
    pub(crate) policy_stale: bool,
    /// See `LocalStorageState`'s own doc comment.
    pub(crate) local_storage_state: LocalStorageState,
    /// See `FetchAvailability`'s own doc comment.
    pub(crate) fetch_availability: FetchAvailability,
    /// Every live folder registered for this link's group; more than one
    /// entry means the group is linked twice and refusing to sync -- the
    /// invariant this reports on.
    pub(crate) ambiguous_local_paths: Vec<String>,
    /// The folder's root is no longer on the volume its index was built from.
    pub(crate) capture_volume_changed: bool,
    /// The folder's root is on a volume only the user can confirm as its own
    /// (one with no stable identity, after a remount): nothing syncs until the
    /// user re-adopts it.
    pub(crate) capture_volume_unconfirmed: bool,
    /// Device ids of every OTHER device currently recorded
    /// (netmap-derived, content-blind) as an authorized-writer full
    /// replica for this group -- feeds the user-facing "Complete copies"
    /// per-device list. Cross-reference against `StatusResponse.peers`'s
    /// own `reachability` for each device's current availability; this
    /// list alone says nothing about whether any of them are online.
    pub(crate) full_replica_device_ids: Vec<String>,
    /// The device whose answer to the background custody check currently
    /// backs a `Protected` status; empty when none is on record (not
    /// protected, or the group has nothing to corroborate).
    pub(crate) custody_confirmed_by: Vec<String>,
}

pub(crate) trait LinkStatusReadPort: Send + Sync {
    fn list_links(&self) -> Result<Vec<LinkStatusView>, crate::sync_error::SyncError>;
}

pub(crate) struct LinkStatusQueryService {
    reader: Arc<dyn LinkStatusReadPort>,
}

impl LinkStatusQueryService {
    pub(crate) fn new(reader: Arc<dyn LinkStatusReadPort>) -> Self {
        Self { reader }
    }

    pub(crate) fn list_links(&self) -> Result<Vec<LinkStatusView>, crate::sync_error::SyncError> {
        self.reader.list_links()
    }
}
