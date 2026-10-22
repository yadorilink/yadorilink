//! [`EnrollmentLinkPort`] backed by `LinkLifecycleService` (the same
//! atomic local-link commit the plain `yadorilink link` command uses) plus
//! post-failure journal classification -- see `commit`'s own doc comment
//! for why reading the journal row back is the ONLY safe way to tell a
//! definitely-rolled-back failure apart from one that may still be
//! committed.

use std::sync::Arc;

use yadorilink_replica_domain::session_state::EnrollmentOperationState;

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use crate::application::ports::{BoxFuture, EnrollmentLinkPort, EnrollmentLinkRequest};
use crate::application::{
    EnrollmentLinkError, LinkCommand, LinkLifecycleService, LinkOutcome,
    PendingEnrollmentLinkCommand,
};
use crate::daemon_state::DaemonState;

pub(crate) struct DaemonEnrollmentLinkAdapter {
    state: Arc<DaemonState>,
    link_lifecycle: Arc<LinkLifecycleService>,
    controller: Arc<LinkRuntimeController>,
}

impl DaemonEnrollmentLinkAdapter {
    pub(crate) fn new(
        state: Arc<DaemonState>,
        link_lifecycle: Arc<LinkLifecycleService>,
        controller: Arc<LinkRuntimeController>,
    ) -> Self {
        Self { state, link_lifecycle, controller }
    }
}

impl EnrollmentLinkPort for DaemonEnrollmentLinkAdapter {
    fn commit<'a>(
        &'a self,
        request: EnrollmentLinkRequest,
    ) -> BoxFuture<'a, Result<LinkOutcome, EnrollmentLinkError>> {
        Box::pin(classify_link_failure(&self.state, &self.link_lifecycle, request))
    }

    /// This is a pending-enrollment compensation, never a normal role loss:
    /// the link never became an Active/eager full replica, so it must NOT
    /// go through `ReplicaRoleService::unlink`'s full-replica-handoff gate
    /// (that gate exists to protect an already-durable eager replica, which
    /// this never was). Orphan the link and drop the marker atomically,
    /// matching exactly what the reconciliation sweep's own `Deleted`
    /// handling does for a marker left over from a crash
    /// (`pending_enrollment::reconcile`) -- see
    /// `SyncState::orphan_link_and_remove_pending_enrollment`'s doc
    /// comment. On-disk files are left untouched, same as there.
    fn rollback<'a>(
        &'a self,
        local_path: &'a str,
        operation_id: &'a str,
    ) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.state
                .replica_coordinator
                .enrollment_repository()
                .orphan_link_and_remove_pending_enrollment(local_path, operation_id)
                .map_err(|e| e.to_string())?;
            self.controller.stop(local_path).await;
            self.state.clear_pending_enrollment_transient_attempts(operation_id);
            Ok(())
        })
    }

    fn commit_plain<'a>(
        &'a self,
        group_id: &'a str,
        absolute_path: &'a std::path::Path,
        on_demand: bool,
    ) -> BoxFuture<'a, Result<(), EnrollmentLinkError>> {
        Box::pin(async move {
            let local_path = absolute_path.to_string_lossy().to_string();
            let link_error = match self
                .link_lifecycle
                .link(LinkCommand {
                    local_path: local_path.clone(),
                    group_id: group_id.to_string(),
                    on_demand,
                    pending_enrollment: None,
                    provider: None,
                })
                .await
            {
                // Already linked and running is as good as linked here: the
                // invite-accept path activates its membership either way.
                Ok(LinkOutcome::Linked | LinkOutcome::AlreadyLinked) => return Ok(()),
                Err(link_error) => link_error,
            };
            let detail = link_error.to_string();
            let refusal = link_error.link_refusal();
            // No `enrollment_operations` journal row exists for a plain
            // link -- classify by reading CURRENT local link state back
            // directly instead (`LinkLifecycleService::is_linked`), the
            // same authoritative source `link()`'s own duplicate-group
            // check reads. See `commit_plain`'s own doc comment (port
            // trait) for why `link()`'s `Err` alone is not enough here.
            match self.link_lifecycle.is_linked(group_id, &local_path) {
                Ok(true) => Err(EnrollmentLinkError::CommitUncertain {
                    detail: format!(
                        "{detail}; the local link may still be committed even though this call \
                         is reporting failure, so remote cancellation was not attempted"
                    ),
                }),
                Ok(false) => Err(EnrollmentLinkError::NotCommitted { detail, refusal }),
                Err(read_err) => {
                    // Can't even confirm which -- fail closed the same way
                    // `classify_link_failure`'s own unreachable/unknown-
                    // state branch does: assume it may still be committed.
                    tracing::error!(
                        error = %read_err,
                        group_id,
                        local_path = %local_path,
                        "commit_plain: link() failed and the local link state re-check ALSO \
                         failed -- cannot confirm whether the link is actually committed"
                    );
                    Err(EnrollmentLinkError::CommitUncertain {
                        detail: format!(
                            "{detail}; could not confirm local link state after the failure \
                             ({read_err}), so remote cancellation was not attempted"
                        ),
                    })
                }
            }
        })
    }
}

fn enrollment_link_to_command(link: EnrollmentLinkRequest) -> LinkCommand {
    LinkCommand {
        local_path: link.absolute_path.to_string_lossy().to_string(),
        group_id: link.group_id.clone(),
        on_demand: link.on_demand,
        pending_enrollment: Some(PendingEnrollmentLinkCommand {
            operation_id: link.operation_id,
            kind: link.kind,
            device_id: link.device_id,
        }),
        provider: link.provider,
    }
}

async fn classify_link_failure(
    state: &Arc<DaemonState>,
    link_lifecycle: &Arc<LinkLifecycleService>,
    spec: EnrollmentLinkRequest,
) -> Result<LinkOutcome, EnrollmentLinkError> {
    let operation_id = spec.operation_id.clone();
    let link_error = match link_lifecycle.link(enrollment_link_to_command(spec)).await {
        Ok(outcome) => return Ok(outcome),
        Err(link_error) => link_error,
    };
    let detail = link_error.to_string();
    let refusal = link_error.link_refusal();
    match state.replica_coordinator.enrollment_repository().get_enrollment_operation(&operation_id)
    {
        // The link/marker/LocalSetupPending commit was never reached (a
        // preflight check failed) or was already rolled back to
        // CancelPending by `link()` itself -- safe to compensate now.
        Ok(Some(operation))
            if matches!(
                operation.state,
                EnrollmentOperationState::Prepared | EnrollmentOperationState::CancelPending
            ) =>
        {
            Err(EnrollmentLinkError::NotCommitted { detail, refusal })
        }
        // The row is still `LocalSetupPending` -- the commit landed and
        // either the post-commit setup failure's own rollback never ran, or
        // it ran and failed. The link (and its pending-enrollment marker)
        // may still be fully committed; remote cancellation must never be
        // attempted against a link that might still exist.
        //
        // `ActivationPending` is included in the same fail-closed bucket
        // below even though `link()` returning `Err` should never actually
        // leave a row there (a successful `mark_enrollment_activation_pending`
        // is exactly what makes `link()` return `Ok`) -- if it is ever
        // observed, treating it as "definitely not committed" would be the
        // one classification capable of orphaning a fully live, already
        // activation-eligible link's remote authorization.
        Ok(Some(operation)) if operation.state == EnrollmentOperationState::LocalSetupPending => {
            Err(EnrollmentLinkError::CommitUncertain { detail })
        }
        // Any other state (ActivationPending, RecoveryBlocked), a missing
        // row, or a read failure -- all fail closed on the side of "may
        // still be committed" rather than risk a remote cancel against a
        // link that exists.
        Ok(_) | Err(_) => Err(EnrollmentLinkError::CommitUncertain { detail }),
    }
}

#[cfg(test)]
mod tests;
