//! Crash-safety reconciliation for the create/join pending-enrollment
//! sagas -- the recovery counterpart to `EnrollmentService`'s own
//! synchronous create/join flow. Two distinct sweeps, run together every
//! call to [`EnrollmentRecoveryService::reconcile_once`]:
//!
//! - **Marker reconciliation** (`reconcile_markers`): a durable local
//!   marker records a local link whose local commit landed but whose
//!   matching coordination-plane activation was never confirmed -- the
//!   crash-safety net for a process killed in that exact window. See the
//!   coordination plane's own explicit Pending -> Active enrollment
//!   protocol this reconciles against: a create/join authorizes a Pending
//!   group/membership there BEFORE the local link is known to exist, and
//!   only `activate` turns it into a real, counted enrollment.
//! - **Journal reconciliation** (`reconcile_operations`): retries every
//!   other stuck `enrollment_operations` state (`PreparePending`,
//!   `Prepared`, `LocalSetupPending`, `CancelPending`) that has no other
//!   durable backstop.
//!
//! `app.rs` owns WHEN this runs (startup + a fixed interval); this service
//! owns WHAT recovery actually does.

use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_replica_domain::session_state::EnrollmentKind as WireEnrollmentKind;
use yadorilink_replica_domain::session_state::{
    EnrollmentOperation, EnrollmentOperationState as OpState,
};

use super::model::{
    EnrollmentActivationResult, EnrollmentCancellationResult, EnrollmentPrepareResult,
};
use super::ports::{
    EnrollmentAttemptTracker, EnrollmentCoordination, EnrollmentLinkPort, EnrollmentRepository,
};

/// How many CONSECUTIVE `TransientFailure` activate outcomes a single
/// marker can accumulate across reconcile sweeps before it is escalated (a
/// `tracing::error!` line, not just the ordinary per-sweep trace) -- purely
/// a visibility bound, never a rollback trigger; see
/// `EnrollmentAttemptTracker`'s own doc comment.
const TRANSIENT_ESCALATION_THRESHOLD: u32 = 20;

/// Age-gate for journal reconciliation: skip a row whose last transition
/// happened too recently, to avoid racing a still-in-flight command's own
/// writes to that exact row -- matches
/// `MEMBERSHIP_OPERATION_RECONCILE_MIN_AGE_SECS`'s own reasoning.
const RECONCILE_MIN_AGE_SECS: i64 = 30;

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) struct EnrollmentRecoveryService {
    repository: Arc<dyn EnrollmentRepository>,
    coordination: Arc<dyn EnrollmentCoordination>,
    links: Arc<dyn EnrollmentLinkPort>,
    attempts: Arc<dyn EnrollmentAttemptTracker>,
}

impl EnrollmentRecoveryService {
    pub(crate) fn new(
        repository: Arc<dyn EnrollmentRepository>,
        coordination: Arc<dyn EnrollmentCoordination>,
        links: Arc<dyn EnrollmentLinkPort>,
        attempts: Arc<dyn EnrollmentAttemptTracker>,
    ) -> Self {
        Self { repository, coordination, links, attempts }
    }

    pub(crate) async fn reconcile_once(&self) {
        self.reconcile_markers().await;
        self.reconcile_operations().await;
    }

    /// Drops a `pending_enrollments` marker once `share create`/`share
    /// join` has confirmed its own activate call directly -- an
    /// optimization over waiting for the next `reconcile_once` sweep to
    /// notice the same thing. Always succeeds: a marker that's already
    /// gone (this device's own sweep beat the caller to it) is a no-op,
    /// matching `settle_activated`'s own idempotent-delete contract.
    pub(crate) fn acknowledge_activation(&self, operation_id: &str) -> Result<(), SyncError> {
        self.repository.settle_activated(operation_id)
    }

    fn block_operation(&self, operation_id: &str, detail: &str) {
        tracing::error!(
            operation_id,
            detail,
            "enrollment recovery refused; operator attention required"
        );
        if let Err(e) = self.repository.mark_state(
            operation_id,
            OpState::RecoveryBlocked,
            Some(detail),
            now_unix(),
        ) {
            tracing::warn!(error = %e, operation_id, "failed to block an enrollment operation");
        }
    }

    // ===== Marker reconciliation =====

    /// The local link's presence is checked by `local_path` (`links`' own
    /// primary key) rather than `group_id` -- nothing in the schema
    /// guarantees at most one link per group, so matching by `group_id`
    /// alone could resolve a marker against an unrelated link that happens
    /// to share one, wrongly activating, orphaning, or dropping it.
    /// `group_id` is still cross-checked once a `local_path` match is
    /// found, as a second guard: a path relinked to a different group
    /// since the marker was written no longer describes what the marker
    /// was written for, so it is treated the same as "link absent" below.
    #[allow(
        clippy::too_many_lines,
        reason = "one fail-closed reconcile sweep: the links and markers snapshots \
                  are read once up front precisely so every marker decision \
                  (activate, cancel, orphan, leave pending) is taken against the \
                  same consistent view. Splitting the per-marker arms into helpers \
                  would either re-read the DB per marker or hand each helper the \
                  full snapshot, losing the read-once invariant the doc comment \
                  above depends on."
    )]
    async fn reconcile_markers(&self) {
        // Fail closed on a DB read error rather than defaulting to an empty
        // view. A defaulted-empty link list would make every marker's link
        // lookup miss, spuriously CANCELLING valid enrollments; a
        // defaulted-empty marker list would silently no-op the sweep.
        let local_links = match self.repository.list_links() {
            Ok(links) => links,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to read local links; skipping this pending-enrollment reconcile sweep \
                     rather than risking cancelling valid enrollments on an empty default"
                );
                return;
            }
        };
        let scan = match self.repository.scan_pending() {
            Ok(scan) => scan,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "failed to read pending-enrollment markers; skipping this reconcile sweep \
                     rather than silently no-opping it on an empty default"
                );
                return;
            }
        };
        for invalid in scan.invalid {
            tracing::error!(
                operation_id = %invalid.operation_id,
                detail = %invalid.detail,
                "pending-enrollment marker is malformed; refusing automatic activation/cancellation"
            );
            self.block_operation(
                &invalid.operation_id,
                &format!("pending-enrollment marker is malformed: {}", invalid.detail),
            );
        }
        for marker in scan.valid {
            let local_link = local_links
                .iter()
                .find(|l| l.key() == marker.local_path && l.group_id == marker.group_id);
            match local_link {
                Some(link) => {
                    // Gate remote activation on the durable journal row
                    // itself being `ActivationPending` -- NOT merely on a
                    // matching link/marker existing. Activating off
                    // link+marker alone would let this reconciler activate
                    // a remote authorization for a link whose post-commit
                    // local setup (watcher registration, on-demand config)
                    // was never confirmed to have finished, racing a crash
                    // between the atomic commit and setup completing.
                    let operation = match self.repository.operation(&marker.operation_id) {
                        Ok(Some(operation)) => operation,
                        Ok(None) => {
                            tracing::error!(
                                operation_id = %marker.operation_id,
                                "pending-enrollment marker has no matching enrollment operation; \
                                 refusing activation"
                            );
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                operation_id = %marker.operation_id,
                                "failed to read the enrollment operation for a pending-enrollment \
                                 marker; refusing activation"
                            );
                            continue;
                        }
                    };
                    if operation.state != OpState::ActivationPending {
                        // In particular, `LocalSetupPending` must never
                        // activate. Leave the marker for the next sweep;
                        // `reconcile_operations` owns advancing (or rolling
                        // back) a stuck row.
                        continue;
                    }
                    if operation.kind != marker.kind
                        || operation.group_id.as_deref() != Some(marker.group_id.as_str())
                        || operation.device_id != marker.device_id
                        || operation.local_path != marker.local_path
                    {
                        self.block_operation(
                            &operation.operation_id,
                            "pending-enrollment marker does not match its enrollment operation's \
                             identity",
                        );
                        continue;
                    }
                    let outcome = match marker.kind {
                        WireEnrollmentKind::Create => {
                            self.coordination
                                .activate_create(&marker.group_id, &marker.operation_id)
                                .await
                        }
                        WireEnrollmentKind::Join => {
                            self.coordination
                                .activate_join(
                                    &marker.group_id,
                                    &marker.operation_id,
                                    &marker.device_id,
                                )
                                .await
                        }
                    };
                    match outcome {
                        EnrollmentActivationResult::Activated
                        | EnrollmentActivationResult::AlreadyActive
                        // Unreachable from here: this sweep only ever
                        // activates the CREATE and JOIN markers the match
                        // above produces, and neither has an approval step
                        // (only cross-account invite acceptance does, and
                        // that path writes no marker for this sweep to
                        // find -- see `accept_invite_and_link`'s own doc
                        // comment). Grouped with the settled outcomes
                        // anyway rather than left to a catch-all: the
                        // remote side committed a state transition, so the
                        // one thing that must never happen is treating it
                        // as a rollback trigger.
                        | EnrollmentActivationResult::AwaitingApproval => {
                            self.attempts.clear_transient_attempts(&marker.operation_id);
                            // Deletes the marker AND the `ActivationPending`
                            // journal row atomically.
                            if let Err(e) =
                                self.repository.settle_activated_and_close(&marker.operation_id)
                            {
                                tracing::warn!(
                                    error = %e,
                                    operation_id = %marker.operation_id,
                                    "failed to settle a confirmed-activated enrollment; leaving the \
                                     marker and journal row in place for the next sweep"
                                );
                            }
                        }
                        EnrollmentActivationResult::Deleted => {
                            // Marking the link orphaned and dropping the
                            // marker commit together -- see
                            // `EnrollmentLinkPort::rollback`'s own doc
                            // comment.
                            match self.links.rollback(link.key(), &marker.operation_id).await
                            {
                                Ok(()) => {
                                    tracing::info!(
                                        operation_id = %marker.operation_id,
                                        group_id = %marker.group_id,
                                        local_path = %link.key(),
                                        "coordination-side authorization for this link is gone; \
                                         marked orphaned (on-disk files left untouched)"
                                    );
                                }
                                Err(e) => tracing::warn!(
                                    error = %e,
                                    operation_id = %marker.operation_id,
                                    local_path = %link.key(),
                                    "failed to mark link orphaned; leaving the pending-enrollment \
                                     marker in place for the next sweep to retry"
                                ),
                            }
                        }
                        EnrollmentActivationResult::TransientFailure { .. } => {
                            // Ambiguous: the coordination plane may already
                            // have committed this activation and only the
                            // RESPONSE was lost. Never a rollback trigger --
                            // only a confirmed `Deleted` is. The marker
                            // survives for the next sweep either way; this
                            // only decides how loudly that fact is logged.
                            let attempts =
                                self.attempts.note_transient_attempt(&marker.operation_id);
                            if attempts >= TRANSIENT_ESCALATION_THRESHOLD {
                                tracing::error!(
                                    operation_id = %marker.operation_id,
                                    group_id = %marker.group_id,
                                    attempts,
                                    "pending enrollment has been unconfirmable for {attempts} \
                                     consecutive reconcile sweeps -- the coordination plane may be \
                                     down for an extended period; the local link and its marker are \
                                     still retained (never rolled back on a mere retry count), but \
                                     this now needs operator attention"
                                );
                            } else {
                                tracing::info!(
                                    operation_id = %marker.operation_id,
                                    group_id = %marker.group_id,
                                    attempts,
                                    "pending enrollment still unresolved after reconciliation; will \
                                     retry on the next sweep"
                                );
                            }
                        }
                    }
                }
                None => {
                    // Transfer the marker into the durable
                    // `enrollment_operations` `CancelPending` journal
                    // BEFORE ever attempting the remote cancel -- see
                    // `EnrollmentRepository::move_marker_to_cancel_operation`'s
                    // own doc comment.
                    if let Err(e) =
                        self.repository.move_marker_to_cancel_operation(&marker, now_unix())
                    {
                        tracing::warn!(
                            error = %e,
                            operation_id = %marker.operation_id,
                            "failed to transfer an absent-link enrollment marker into durable \
                             cancellation recovery; leaving the marker in place for the next sweep"
                        );
                        continue;
                    }
                    self.attempts.clear_transient_attempts(&marker.operation_id);
                    // Best-effort immediate cancel attempt in the SAME
                    // sweep -- `reconcile_operations` retries durably
                    // either way, so this is purely a latency optimization,
                    // not a requirement for correctness.
                    let cancelled = matches!(
                        match marker.kind {
                            WireEnrollmentKind::Create => {
                                self.coordination
                                    .cancel_create(&marker.group_id, &marker.operation_id)
                                    .await
                            }
                            WireEnrollmentKind::Join => {
                                self.coordination
                                    .cancel_join(
                                        &marker.group_id,
                                        &marker.operation_id,
                                        &marker.device_id,
                                    )
                                    .await
                            }
                        },
                        EnrollmentCancellationResult::Confirmed
                    );
                    if cancelled {
                        if let Err(e) = self.repository.delete_operation(&marker.operation_id) {
                            tracing::warn!(
                                error = %e,
                                operation_id = %marker.operation_id,
                                "failed to delete a confirmed-cancelled enrollment journal row; the \
                                 next sweep will retry the (already-confirmed) cancel and delete it \
                                 then"
                            );
                        }
                    }
                }
            }
        }
    }

    // ===== Journal reconciliation =====

    async fn reconcile_operations(&self) {
        let scan = match self.repository.scan_open_operations() {
            Ok(scan) => scan,
            Err(e) => {
                tracing::warn!(error = %e, "failed to scan the enrollment operation journal; skipping this sweep");
                return;
            }
        };
        for invalid in scan.invalid {
            tracing::error!(
                operation_id = %invalid.operation_id,
                detail = %invalid.detail,
                "enrollment recovery journal row is malformed; refusing automatic recovery"
            );
            self.block_operation(&invalid.operation_id, &invalid.detail);
        }
        for operation in scan.valid {
            if now_unix() - operation.updated_at_unix < RECONCILE_MIN_AGE_SECS {
                continue;
            }
            self.reconcile_one_operation(operation).await;
        }
    }

    /// Settles a `Join` left `Prepared` beside a live link for its group and
    /// path with no marker -- a re-join of an already-linked, running folder
    /// that was interrupted while it activated (see
    /// `EnrollmentService::settle_rejoin_of_linked_folder`, whose outcomes
    /// this mirrors). Activation resolves a join by (group, device), so an
    /// Active membership answers `AlreadyActive` and a Pending one this
    /// prepare created becomes Active; either way only the journal row is
    /// closed. The link is never touched: it is the earlier link, which this
    /// operation never created, so neither outcome may orphan or remove it.
    async fn settle_interrupted_rejoin(&self, operation: &EnrollmentOperation, group_id: &str) {
        let activation = self
            .coordination
            .activate_join(group_id, &operation.operation_id, &operation.device_id)
            .await;
        match activation {
            EnrollmentActivationResult::Activated
            | EnrollmentActivationResult::AlreadyActive
            | EnrollmentActivationResult::AwaitingApproval => {
                if let Err(e) = self.repository.delete_operation(&operation.operation_id) {
                    tracing::warn!(error = %e, operation_id = %operation.operation_id, "failed to close a settled re-join's journal row; the next sweep will settle it again");
                }
            }
            EnrollmentActivationResult::Deleted => {
                tracing::warn!(
                    operation_id = %operation.operation_id,
                    group_id,
                    local_path = %operation.local_path,
                    "an interrupted re-join found no membership to activate; closing its journal \
                     row and leaving the existing link as it is"
                );
                if let Err(e) = self.repository.delete_operation(&operation.operation_id) {
                    tracing::warn!(error = %e, operation_id = %operation.operation_id, "failed to close an interrupted re-join's journal row");
                }
            }
            EnrollmentActivationResult::TransientFailure { detail } => {
                tracing::debug!(operation_id = %operation.operation_id, detail, "interrupted re-join activation still unresolved; will retry");
            }
        }
    }

    /// An operation still `LocalSetupPending` past the age gate.
    fn roll_back_stranded_local_setup(&self, operation: &EnrollmentOperation) {
        // This state should be purely transient -- setup runs
        // synchronously inside the same commit that just committed
        // the link/marker/LocalSetupPending transition, and does no
        // network I/O. A row still found here well past the
        // age-gate means the daemon crashed (or otherwise never
        // finished) mid-setup: rolled back rather than risk
        // activating a remote authorization for a link this device
        // never finished registering. The rollback undoes exactly
        // the link-row write the commit recorded -- a re-join of a
        // folder whose row already existed restores that row, root
        // token and all, instead of deleting it.
        match self.repository.rollback_local_setup_to_cancel_pending(
            &operation.local_path,
            &operation.operation_id,
            "local setup did not complete before recovery",
            now_unix(),
        ) {
            Ok(true) => {
                tracing::warn!(
                    operation_id = %operation.operation_id,
                    local_path = %operation.local_path,
                    "rolled back an enrollment whose local setup did not complete"
                );
            }
            Ok(false) => self.block_operation(
                &operation.operation_id,
                "local setup did not complete, and the operation has no recorded link \
                 write to undo",
            ),
            Err(e) => {
                tracing::warn!(error = %e, operation_id = %operation.operation_id, "could not roll back an incomplete local setup");
            }
        }
    }

    async fn reconcile_one_operation(&self, operation: EnrollmentOperation) {
        match operation.state {
            OpState::PreparePending => {
                let outcome = match operation.kind {
                    WireEnrollmentKind::Create => {
                        let Some(group_name) = operation.group_name.as_deref() else {
                            self.block_operation(
                                &operation.operation_id,
                                "create PreparePending has no group_name",
                            );
                            return;
                        };
                        self.coordination
                            .prepare_create(
                                &operation.operation_id,
                                group_name,
                                &operation.device_id,
                                &operation.storage_mode,
                            )
                            .await
                    }
                    WireEnrollmentKind::Join => {
                        let Some(group_id) = operation.group_id.as_deref() else {
                            self.block_operation(
                                &operation.operation_id,
                                "join PreparePending has no group_id",
                            );
                            return;
                        };
                        self.coordination
                            .prepare_join(
                                &operation.operation_id,
                                group_id,
                                &operation.device_id,
                                &operation.storage_mode,
                            )
                            .await
                    }
                };
                match outcome {
                    EnrollmentPrepareResult::Prepared { group_id } => {
                        let _ = self.repository.mark_prepared(
                            &operation.operation_id,
                            &group_id,
                            now_unix(),
                        );
                        // Recovery never creates a new local link -- if one
                        // doesn't already exist for this operation, the
                        // only safe next step is cancellation, handled by
                        // the NEXT sweep's `Prepared` branch below.
                    }
                    EnrollmentPrepareResult::DefinitelyRejected { .. }
                    | EnrollmentPrepareResult::InviteRefused { .. } => {
                        let _ = self.repository.delete_operation(&operation.operation_id);
                    }
                    EnrollmentPrepareResult::Conflict { detail } => {
                        self.block_operation(&operation.operation_id, &detail);
                    }
                    EnrollmentPrepareResult::Ambiguous { detail } => {
                        tracing::debug!(operation_id = %operation.operation_id, detail, "enrollment prepare still unresolved; will retry");
                    }
                }
            }
            OpState::Prepared => {
                let Some(group_id) = operation.group_id.clone() else {
                    self.block_operation(
                        &operation.operation_id,
                        "Prepared enrollment has no group_id",
                    );
                    return;
                };
                // A DB read failure here must never be treated as "no
                // matching link" -- that would route to CancelPending +
                // remote cancel even though the link might genuinely
                // exist. Leave the row untouched for the next sweep.
                let links = match self.repository.list_links() {
                    Ok(links) => links,
                    Err(e) => {
                        tracing::warn!(error = %e, operation_id = %operation.operation_id, "failed to list links while reconciling a Prepared enrollment; leaving unchanged");
                        return;
                    }
                };
                let markers = match self.repository.scan_pending() {
                    Ok(scan) => scan.valid,
                    Err(e) => {
                        tracing::warn!(error = %e, operation_id = %operation.operation_id, "failed to list pending enrollments while reconciling a Prepared enrollment; leaving unchanged");
                        return;
                    }
                };
                let matching_link = links
                    .into_iter()
                    .find(|link| link.key() == operation.local_path && link.group_id == group_id);
                // Full-identity match -- path+group alone isn't enough,
                // since an unrelated pre-existing link could coincidentally
                // share both.
                let matching_marker = markers.into_iter().find(|marker| {
                    marker.operation_id == operation.operation_id
                        && marker.kind == operation.kind
                        && marker.group_id == group_id
                        && marker.device_id == operation.device_id
                        && marker.local_path == operation.local_path
                });
                match (matching_link, matching_marker) {
                    (None, None) => {
                        let _ = self.repository.mark_state(
                            &operation.operation_id,
                            OpState::CancelPending,
                            Some("no matching local link exists after prepare"),
                            now_unix(),
                        );
                    }
                    (Some(_), Some(_)) => {
                        // Full identity confirmed on both sides -- the
                        // `LocalSetupPending` transition must have been
                        // lost (e.g. a crash right after the commit).
                        // Recovery never creates a new link and never
                        // cancels one that already exists -- advance it to
                        // `LocalSetupPending`, NOT `ActivationPending`:
                        // this path has no way to confirm local setup
                        // actually finished, so it must not skip the
                        // setup-confirmation gate. (With no recorded link
                        // write, that state's rollback blocks the row
                        // rather than guess at the link.)
                        let _ = self.repository.mark_state(
                            &operation.operation_id,
                            OpState::LocalSetupPending,
                            None,
                            now_unix(),
                        );
                    }
                    // A join beside a LIVE link for its group and path,
                    // with no marker: the shape a re-join of a folder
                    // already linked and running leaves for the whole of
                    // its activation round trip, because its link call
                    // commits nothing. A daemon that died in that window
                    // did nothing wrong; finish what the join was doing.
                    (Some(link), None)
                        if operation.kind == WireEnrollmentKind::Join && !link.orphaned =>
                    {
                        self.settle_interrupted_rejoin(&operation, &group_id).await;
                    }
                    (Some(_), None) => {
                        self.block_operation(
                            &operation.operation_id,
                            "matching link exists but its pending-enrollment marker is missing",
                        );
                    }
                    (None, Some(marker)) => {
                        if let Err(e) =
                            self.repository.move_marker_to_cancel_operation(&marker, now_unix())
                        {
                            tracing::warn!(error = %e, operation_id = %operation.operation_id, "failed to transfer an absent-link marker to CancelPending");
                        }
                    }
                }
            }
            OpState::LocalSetupPending => self.roll_back_stranded_local_setup(&operation),
            OpState::ActivationPending => {
                // The link + pending_enrollments marker + local setup are
                // all confirmed, so this row's own job is usually done and
                // `pending_enrollments` owns recovery for the activation
                // step from here -- still, confirm which case this is by
                // reading back the marker and link before touching the
                // row.
                let markers = match self.repository.scan_pending() {
                    Ok(scan) => scan.valid,
                    Err(e) => {
                        tracing::warn!(error = %e, operation_id = %operation.operation_id, "failed to list pending enrollments while reconciling an ActivationPending enrollment; leaving unchanged");
                        return;
                    }
                };
                if markers.iter().any(|marker| marker.operation_id == operation.operation_id) {
                    // Activation is still outstanding -- do NOT delete it.
                    return;
                }
                let links = match self.repository.list_links() {
                    Ok(links) => links,
                    Err(_) => return,
                };
                let has_matching_link = links.iter().any(|link| {
                    link.key() == operation.local_path
                        && Some(link.group_id.as_str()) == operation.group_id.as_deref()
                });
                if has_matching_link {
                    // Confirmed post-activation cleanup.
                    if let Err(e) = self.repository.delete_operation(&operation.operation_id) {
                        tracing::warn!(error = %e, operation_id = %operation.operation_id, "failed to clean up an activation-pending enrollment operation");
                    }
                    return;
                }
                // Neither a marker nor a matching link exists -- a remote
                // Pending authorization may still exist and must be
                // confirmed-cancelled before this row can be safely
                // discarded.
                let _ = self.repository.mark_state(
                    &operation.operation_id,
                    OpState::CancelPending,
                    Some("transferred enrollment lost its local link before activation completed"),
                    now_unix(),
                );
            }
            OpState::CancelPending => {
                let Some(group_id) = operation.group_id.clone() else {
                    self.block_operation(
                        &operation.operation_id,
                        "CancelPending enrollment has no group_id",
                    );
                    return;
                };
                let outcome = match operation.kind {
                    WireEnrollmentKind::Create => {
                        self.coordination.cancel_create(&group_id, &operation.operation_id).await
                    }
                    WireEnrollmentKind::Join => {
                        self.coordination
                            .cancel_join(&group_id, &operation.operation_id, &operation.device_id)
                            .await
                    }
                };
                match outcome {
                    EnrollmentCancellationResult::Confirmed => {
                        let _ = self.repository.delete_operation(&operation.operation_id);
                    }
                    EnrollmentCancellationResult::Conflict { detail } => {
                        self.block_operation(&operation.operation_id, &detail);
                    }
                    EnrollmentCancellationResult::Ambiguous { detail } => {
                        let _ =
                            self.repository.increment_attempts(&operation.operation_id, now_unix());
                        tracing::debug!(operation_id = %operation.operation_id, detail, "enrollment cancel still unresolved; will retry");
                    }
                }
            }
            OpState::RecoveryBlocked => {
                // Excluded by `scan_open_operations`'s own query --
                // unreachable in practice, kept only for match
                // exhaustiveness.
            }
        }
    }
}

#[cfg(test)]
mod tests;
