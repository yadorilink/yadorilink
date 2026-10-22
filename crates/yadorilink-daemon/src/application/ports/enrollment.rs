//! Enrollment's own ports -- what `EnrollmentService` needs from durable
//! storage, the coordination plane, and the local link commit, expressed as
//! `dyn`-safe traits so a real adapter (backed by `SyncState`/`reqwest`/
//! the control-socket module's own `link` function) and a fake (backed by
//! in-memory state, for unit tests) can both satisfy them.

use crate::sync_error::SyncError;
use yadorilink_replica_domain::session_state::{
    EnrollmentOperation, EnrollmentOperationScan, EnrollmentOperationState, FolderLink,
    PendingEnrollment, PendingEnrollmentScan,
};

use super::common::BoxFuture;
use crate::application::model::{
    EnrollmentActivationResult, EnrollmentCancellationResult, EnrollmentPrepareResult,
};

/// The durable enrollment-journal reads/writes `EnrollmentService` needs.
/// Deliberately narrow: only the specific atomic transitions the create/
/// join sagas actually perform, never a generic SQL/transaction escape
/// hatch a caller could use to reach outside this contract.
pub(crate) trait EnrollmentRepository: Send + Sync {
    fn try_insert_operation(&self, operation: &EnrollmentOperation) -> Result<bool, SyncError>;

    fn delete_operation(&self, operation_id: &str) -> Result<(), SyncError>;

    fn mark_prepared(
        &self,
        operation_id: &str,
        group_id: &str,
        now_unix: i64,
    ) -> Result<bool, SyncError>;

    fn mark_state(
        &self,
        operation_id: &str,
        state: EnrollmentOperationState,
        error: Option<&str>,
        now_unix: i64,
    ) -> Result<bool, SyncError>;

    fn list_links(&self) -> Result<Vec<FolderLink>, SyncError>;

    /// The creation digest recorded with a provider link (the token-bound request).
    fn creation_digest(&self, locator: &str) -> Result<Option<String>, SyncError>;

    fn scan_pending(&self) -> Result<PendingEnrollmentScan, SyncError>;

    /// Removes the `pending_enrollments` marker once activation is
    /// confirmed -- the operation's own responsibility has moved to the
    /// (already-committed) link itself.
    fn settle_activated(&self, operation_id: &str) -> Result<(), SyncError>;

    fn operation(&self, operation_id: &str) -> Result<Option<EnrollmentOperation>, SyncError>;

    // ===== EnrollmentRecoveryService only =====

    /// Every `enrollment_operations` row not already `RecoveryBlocked` --
    /// the recovery sweep's own work list.
    fn scan_open_operations(&self) -> Result<EnrollmentOperationScan, SyncError>;

    /// Atomically deletes BOTH the `pending_enrollments` marker AND the
    /// `ActivationPending` journal row -- distinct from `settle_activated`
    /// (marker only), which is what `EnrollmentService`'s own synchronous
    /// activation path uses, leaving the journal row's own cleanup to a
    /// LATER recovery sweep. The recovery sweep, discovering success
    /// directly, settles both right away instead of deferring to itself
    /// again next sweep.
    fn settle_activated_and_close(&self, operation_id: &str) -> Result<(), SyncError>;

    fn move_marker_to_cancel_operation(
        &self,
        marker: &PendingEnrollment,
        now_unix: i64,
    ) -> Result<(), SyncError>;

    fn increment_attempts(&self, operation_id: &str, now_unix: i64) -> Result<i64, SyncError>;

    /// Rolls an incomplete `LocalSetupPending` row (the daemon crashed
    /// mid-setup) back to `CancelPending`, atomically with undoing the
    /// link-row write its commit recorded (deleting a row it inserted,
    /// restoring one it updated) and dropping its marker -- never left
    /// half-confirmed. `Ok(false)`: the row has no recorded link write, so
    /// nothing was touched; it must not be rolled back by guessing.
    fn rollback_local_setup_to_cancel_pending(
        &self,
        local_path: &str,
        operation_id: &str,
        detail: &str,
        now_unix: i64,
    ) -> Result<bool, SyncError>;
}

/// The in-memory (never persisted) retry-visibility counter for a marker
/// stuck on repeated `TransientFailure` activate outcomes -- see
/// `DaemonState::note_pending_enrollment_transient_attempt`'s own doc
/// comment for why this is deliberately NOT part of the durable journal.
pub(crate) trait EnrollmentAttemptTracker: Send + Sync {
    fn note_transient_attempt(&self, operation_id: &str) -> u32;
    fn clear_transient_attempts(&self, operation_id: &str);
}

/// The coordination-plane create/join prepare, activate, and cancel calls.
/// `Arc<dyn EnrollmentRepository>`'s counterpart on the remote side.
pub(crate) trait EnrollmentCoordination: Send + Sync {
    /// Whether this device currently has a coordination-plane address/
    /// access token recorded. Checked BEFORE the enrollment journal is
    /// even opened -- see `EnrollmentService::create_and_link`'s own doc
    /// comment for why: refusing early keeps a coordination outage from
    /// ever producing a journal row for an attempt that was never made.
    fn is_configured(&self) -> bool;

    fn prepare_create<'a>(
        &'a self,
        operation_id: &'a str,
        group_name: &'a str,
        device_id: &'a str,
        storage_mode: &'a str,
    ) -> BoxFuture<'a, EnrollmentPrepareResult>;

    fn prepare_join<'a>(
        &'a self,
        operation_id: &'a str,
        group_id: &'a str,
        device_id: &'a str,
        storage_mode: &'a str,
    ) -> BoxFuture<'a, EnrollmentPrepareResult>;

    fn activate_create<'a>(
        &'a self,
        group_id: &'a str,
        operation_id: &'a str,
    ) -> BoxFuture<'a, EnrollmentActivationResult>;

    fn activate_join<'a>(
        &'a self,
        group_id: &'a str,
        operation_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, EnrollmentActivationResult>;

    fn cancel_create<'a>(
        &'a self,
        group_id: &'a str,
        operation_id: &'a str,
    ) -> BoxFuture<'a, EnrollmentCancellationResult>;

    fn cancel_join<'a>(
        &'a self,
        group_id: &'a str,
        operation_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, EnrollmentCancellationResult>;

    /// Cross-account invite-accept PREPARE. Unlike `prepare_join`, the
    /// group id is not supplied -- only the invite `code` names it -- and a
    /// successful `EnrollmentPrepareResult::Prepared` carries whatever
    /// group id the coordination plane resolved the code to.
    fn prepare_invite_accept<'a>(
        &'a self,
        operation_id: &'a str,
        code: &'a str,
        device_id: &'a str,
        storage_mode: &'a str,
    ) -> BoxFuture<'a, EnrollmentPrepareResult>;

    fn activate_invite_accept<'a>(
        &'a self,
        group_id: &'a str,
        operation_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, EnrollmentActivationResult>;

    fn cancel_invite_accept<'a>(
        &'a self,
        group_id: &'a str,
        operation_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, EnrollmentCancellationResult>;

    /// Mints a one-use, expiring cross-account invite for `group_id`.
    /// Stateless on this device -- no journal row, no local link -- so a
    /// plain `Result` is enough; see `coordination_client::mint_invite`'s
    /// own doc comment for why this doesn't need the same classified-
    /// outcome treatment as prepare/activate/cancel.
    fn mint_invite<'a>(
        &'a self,
        group_id: &'a str,
        role: Option<&'a str>,
        ttl_secs: Option<u64>,
        requires_approval: bool,
    ) -> BoxFuture<'a, Result<crate::application::model::MintedInvite, String>>;
}

/// A local link/marker/watcher commit request -- what the current `LinkFn`
/// closure parameter to `EnrollmentService::create_and_link`/`join_and_link`
/// carries, made a first-class port instead of a callback so `application`
/// no longer calls back INTO `control_socket`.
pub(crate) struct EnrollmentLinkRequest {
    pub(crate) operation_id: String,
    pub(crate) kind: crate::application::EnrollmentKind,
    pub(crate) device_id: String,
    pub(crate) group_id: String,
    pub(crate) absolute_path: std::path::PathBuf,
    pub(crate) on_demand: bool,
    /// `Some` for a provider-backed link (`absolute_path` is then its locator).
    pub(crate) provider: Option<super::ProviderLinkTarget>,
}

pub(crate) trait EnrollmentLinkPort: Send + Sync {
    /// Commits the link and its pending-enrollment marker, then starts it.
    /// `Ok(LinkOutcome::AlreadyLinked)` means the folder was already linked
    /// to this group and running: nothing was written, no marker exists for
    /// this operation, and the operation's journal row is still `Prepared`.
    fn commit<'a>(
        &'a self,
        request: EnrollmentLinkRequest,
    ) -> BoxFuture<
        'a,
        Result<crate::application::LinkOutcome, crate::application::EnrollmentLinkError>,
    >;

    /// Undoes a link commit for a CONFIRMED-rejected activation (the
    /// coordination plane has nothing left to activate): orphans the link,
    /// drops its pending-enrollment marker, and stops the now-pointless
    /// watcher. `Err` means the rollback itself failed -- the caller must
    /// leave the link/marker in place for the next reconciliation attempt,
    /// never treat a failed rollback as done.
    fn rollback<'a>(
        &'a self,
        local_path: &'a str,
        operation_id: &'a str,
    ) -> BoxFuture<'a, Result<(), String>>;

    /// The same underlying local-link commit as `commit`, but with no
    /// `pending_enrollment` marker -- the plain `yadorilink link` shape,
    /// used by the invite-accept saga instead of `commit`. Returns the SAME
    /// two-variant `EnrollmentLinkError` `commit` does: `link()`'s `Err`
    /// does NOT always mean nothing was committed (its own doc comment
    /// documents a rollback-failure path where the link may still be live)
    /// -- there is no `enrollment_operations` journal row to classify
    /// against here (unlike `commit`'s `classify_link_failure`), so an
    /// implementation must classify some other way (e.g. reading back
    /// current local link state directly). Re-committing the SAME
    /// (group_id, path) this already linked is an idempotent no-op, which
    /// is what makes a retried invite-accept command (same code, same
    /// deterministic operation id) safe to run again after a crash between
    /// this call and the matching activate call -- see
    /// `EnrollmentService::accept_invite_and_link`'s own doc comment for
    /// the full retry story this depends on.
    fn commit_plain<'a>(
        &'a self,
        group_id: &'a str,
        absolute_path: &'a std::path::Path,
        on_demand: bool,
    ) -> BoxFuture<'a, Result<(), crate::application::EnrollmentLinkError>>;
}
