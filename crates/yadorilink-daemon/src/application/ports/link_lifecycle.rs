//! What `LinkLifecycleService` needs to atomically register a link. Split
//! into two ports matching the two concerns the daemon's original
//! `link` handler body bundled: `LinkRepositoryPort` for the durable `SyncState`
//! reads/writes (each method here is one atomic `SyncState` operation,
//! never decomposed further -- a transactional commit/rollback stays one
//! port call, never split across two so a caller could interleave other
//! work in between), and `LinkWatcherPort` for the in-memory watcher/
//! on-demand-materialization setup that runs after the commit.
//!
//! This is the single local-link commit path both the plain `yadorilink
//! link` command and `EnrollmentService::create_and_link`/`join_and_link`
//! (via `EnrollmentLinkPort`) converge on -- there is no second,
//! independent way to create a link row in this daemon.

use crate::sync_error::SyncError;
use yadorilink_replica_domain::session_state::LinkRowWrite;

use super::common::BoxFuture;
use crate::application::EnrollmentKind;
use crate::error::DaemonError;

pub(crate) struct PendingEnrollmentLinkCommand {
    pub(crate) operation_id: String,
    pub(crate) kind: EnrollmentKind,
    pub(crate) device_id: String,
}

/// What a successful [`LinkLifecycleService::link`] did.
///
/// [`LinkLifecycleService::link`]: crate::application::LinkLifecycleService::link
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkOutcome {
    /// The link was committed and its runtime started.
    Linked,
    /// The folder was already linked to this group with a running runtime;
    /// nothing was written, and no pending-enrollment marker was recorded.
    AlreadyLinked,
}

/// A provider-backed link has no directory: it names a display name and whether the owner created
/// an empty group. The link key is a synthetic locator derived from the request token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderLinkTarget {
    /// The OS adapter that serves the root (macOS File Provider or Windows CfAPI).
    pub(crate) kind: yadorilink_replica_domain::session_state::ProviderKind,
    pub(crate) display_name: String,
    pub(crate) empty_owner: bool,
    /// The folder is created in on-demand mode (the OS fetches content on first access).
    pub(crate) on_demand: bool,
    /// Digest of the creation request (display name, group, policy) bound to the token.
    pub(crate) creation_digest: String,
}

pub(crate) struct LinkCommand {
    pub(crate) local_path: String,
    pub(crate) group_id: String,
    pub(crate) on_demand: bool,
    /// `None` for a plain `yadorilink link` -- no pending-enrollment
    /// marker is written. `Some` for a `share create`/`share
    /// join` link, coupling the link row and the marker in one
    /// transaction.
    pub(crate) pending_enrollment: Option<PendingEnrollmentLinkCommand>,
    /// `Some` for a provider-backed link: the local_path is then its locator, never a directory.
    pub(crate) provider: Option<ProviderLinkTarget>,
}

pub(crate) trait LinkRepositoryPort: Send + Sync {
    /// Every currently-live local path linked to `group_id` on this
    /// device -- used for the duplicate-group refusal (a folder group can
    /// only be linked to one folder on a device).
    fn live_link_paths_for_group(&self, group_id: &str) -> Result<Vec<String>, SyncError>;

    /// Every currently-linked `(local path, group)` on this device -- used
    /// for the unsupported-topology refusal (nested links, one folder linked
    /// to two groups).
    /// The `links` keys (paths for folder links, locators for provider links) of the group's live
    /// links: identity strings, never to be opened.
    fn live_link_keys_for_group(&self, group_id: &str) -> Result<Vec<String>, SyncError>;

    fn list_link_paths_and_groups(&self) -> Result<Vec<(String, String)>, SyncError>;

    /// The headroom reserve the preflight's free-space reading is measured against; `None` is the
    /// default `default headroom`.
    fn preflight_headroom_override_bytes(&self) -> Option<u64>;

    /// The user's home directory, which the preflight flags as a risky place to link; `None` for
    /// a host with no home directory.
    fn preflight_home_dir(&self) -> Option<std::path::PathBuf> {
        None
    }

    /// The state directory the recovery areas live under, which no linked folder may overlap.
    fn state_dir(&self) -> std::path::PathBuf;

    /// Commits the link row. Reports what that did to the row (inserted, or
    /// updated a row that already existed for the same path and group) so a
    /// failed setup can undo exactly that.
    fn commit_plain_link(
        &self,
        local_path: &str,
        group_id: &str,
    ) -> Result<LinkRowWrite, SyncError>;

    /// Atomically inserts the link row of a provider folder and declares its root, with no
    /// pending-enrollment marker or journal row (the invite-acceptance shape). Reports what it did
    /// to the link row, like [`Self::commit_plain_link`].
    fn commit_provider_link_plain(
        &self,
        local_path: &str,
        group_id: &str,
        provider: &ProviderLinkTarget,
    ) -> Result<LinkRowWrite, SyncError>;

    /// Atomically inserts the link row AND the pending-enrollment marker,
    /// advancing the matching `enrollment_operations` row from `Prepared`
    /// to `LocalSetupPending` in the same transaction. Reports what it did
    /// to the link row, like [`Self::commit_plain_link`].
    fn commit_link_with_pending_enrollment(
        &self,
        local_path: &str,
        group_id: &str,
        marker: &PendingEnrollmentLinkCommand,
        provider: Option<&ProviderLinkTarget>,
    ) -> Result<LinkRowWrite, SyncError>;

    /// Undoes a [`Self::commit_plain_link`] whose setup failed: deletes a row
    /// it inserted, or restores a row it updated. Never deletes a row the
    /// commit did not create. Returns what it did, for the caller's log.
    fn undo_plain_link(
        &self,
        local_path: &str,
        group_id: &str,
        write: &LinkRowWrite,
    ) -> Result<&'static str, SyncError>;

    /// Atomically undoes the link-row write (as [`Self::undo_plain_link`]),
    /// drops the pending marker, and rolls the matching
    /// `enrollment_operations` row back from `LocalSetupPending` to
    /// `CancelPending`, recording `detail` as the failure reason.
    fn rollback_local_setup_to_cancel_pending(
        &self,
        local_path: &str,
        group_id: &str,
        write: &LinkRowWrite,
        operation_id: &str,
        detail: &str,
    ) -> Result<&'static str, SyncError>;

    /// Advances the `enrollment_operations` row from `LocalSetupPending`
    /// to `ActivationPending` -- `Ok(false)` means the row was no longer
    /// advanceable (e.g. a concurrent recovery sweep already rolled it
    /// back), distinct from a read/write failure.
    fn mark_enrollment_activation_pending(&self, operation_id: &str) -> Result<bool, SyncError>;

    /// Records that the link no longer takes part in sync (`orphaned`), keeping its row and files.
    /// An error when `local_path` is not a linked folder.
    fn mark_link_orphaned(&self, local_path: &str) -> Result<(), SyncError>;
}

pub(crate) trait LinkWatcherPort: Send + Sync {
    /// True only after the path's watcher/runtime has completed startup.
    /// A `Starting` reservation is deliberately false so a concurrent retry
    /// cannot report success before the first attempt's fallible work lands.
    fn is_ready(&self, local_path: &str) -> bool;

    /// True while ANY runtime holds the path, `Starting` or `Ready`. A
    /// second start for such a path is refused, so a link call must not
    /// commit anything for it: its own failure rollback would then be
    /// undoing state the running (or starting) link depends on.
    fn is_registered(&self, local_path: &str) -> bool;

    /// The fallible steps that run after the link (and marker) row(s) are
    /// already committed: on-demand materialization policy/size-cap
    /// configuration, then starting the OS watcher. Bundled as one port
    /// call (mirroring the original `finish_link_setup`) since both must
    /// succeed or neither counts as done -- `LinkLifecycleService` rolls
    /// back the repository commit on any failure here.
    fn start<'a>(
        &'a self,
        local_path: &'a str,
        group_id: &'a str,
        on_demand: bool,
    ) -> BoxFuture<'a, Result<(), DaemonError>>;

    fn stop<'a>(&'a self, local_path: &'a str) -> BoxFuture<'a, ()>;
}
