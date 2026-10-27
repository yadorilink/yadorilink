use std::sync::Arc;

use yadorilink_replica_domain::session_state::{MaterializationPolicy, RoleLossOperationState};

use super::model::{HandoffCommitResult, RoleLossCommitOutcome};
use crate::sync_error::SyncError;

use super::ports::{
    CustodyLeaseHandoffPort, HandoffReadinessPort, LinkRuntimePort, OnDemandCapabilityPort,
    ReplicaRoleRepository, RoleLossCoordination, RoleLossJournal, StorageModeWriteError,
};

/// Past this many compensation attempts for the same role-loss operation,
/// a failed attempt is logged at `error` instead of `warn` -- a visibility
/// aid only. The row itself is never abandoned or deleted regardless of how
/// many attempts it has accrued.
const ROLE_LOSS_COMPENSATION_ESCALATION_ATTEMPTS: i64 = 5;

/// Why a storage-mode change was refused.
#[derive(Debug)]
pub(crate) enum StorageModeError {
    /// On-demand was asked for a root that is not a ready provider root.
    OnDemandUnavailable,
    Failed(String),
    /// Refused for now; the front end words the step that retries it.
    Advised {
        message: String,
        step: crate::error::NextStep,
    },
    /// The account has not accepted the current Terms (`403 terms_consent_required`). Nothing was
    /// committed; signing in again clears it.
    TermsConsentRequired,
}

impl From<String> for StorageModeError {
    fn from(message: String) -> Self {
        Self::Failed(message)
    }
}

impl StorageModeError {
    fn retry(message: impl Into<String>) -> Self {
        Self::Advised {
            message: message.into(),
            step: crate::error::NextStep::RetryStorageModeChange,
        }
    }
}

impl std::fmt::Display for StorageModeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OnDemandUnavailable => f.write_str(crate::provider_gate::ON_DEMAND_REFUSAL),
            Self::Failed(message) | Self::Advised { message, .. } => f.write_str(message),
            Self::TermsConsentRequired => f.write_str(TERMS_CONSENT_REQUIRED_MESSAGE),
        }
    }
}

/// The text of a refusal because the Terms were not accepted; the typed code carries the meaning.
const TERMS_CONSENT_REQUIRED_MESSAGE: &str =
    "the Terms must be accepted to continue; sign in again to review and accept them";

pub(crate) fn demotion_handoff_lease_failure_message() -> String {
    "refusing to drop complete-copy status: confirmed a ready replica but could not obtain the \
     required handoff lease (peer unreachable, not caught up, or coordination unavailable)"
        .to_string()
}

/// Why an unlink was refused. `NotProtected` is the durability gate: the
/// group's data would no longer be held by a confirmed complete copy
/// elsewhere, and `--force` overrides it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnlinkError {
    NotProtected(String),
    /// The account has not accepted the current Terms (`403 terms_consent_required`). Nothing was
    /// changed; signing in again clears it.
    TermsConsentRequired,
    /// The link at the path belongs to a different group than the caller expected. Nothing
    /// was changed.
    GroupMismatch(String),
    Other(String),
}

impl std::fmt::Display for UnlinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UnlinkError::NotProtected(message)
            | UnlinkError::GroupMismatch(message)
            | UnlinkError::Other(message) => f.write_str(message),
            UnlinkError::TermsConsentRequired => f.write_str(TERMS_CONSENT_REQUIRED_MESSAGE),
        }
    }
}

impl From<String> for UnlinkError {
    fn from(message: String) -> Self {
        UnlinkError::Other(message)
    }
}

fn group_mismatch(local_path: &str) -> UnlinkError {
    UnlinkError::GroupMismatch(local_path.to_string())
}

pub(crate) fn unlink_handoff_lease_failure_message(local_path: &str) -> String {
    format!(
        "refusing to unlink {local_path}: confirmed a ready replica but could not obtain the \
         required handoff lease (peer unreachable, not caught up, or coordination unavailable). \
         Re-run unlink to retry."
    )
}

/// Owns storage-mode changes and unlink -- the two operations that can flip
/// or drop this device's full-replica status for a folder group. Every
/// dependency is a port -- no `DaemonState`, no `coordination_client`, no
/// the daemon's own `LinkRuntimeController` -- see the composition root for
/// what backs each one in production.
pub(crate) struct ReplicaRoleService {
    device_id: String,
    repository: Arc<dyn ReplicaRoleRepository>,
    role_loss: Arc<dyn RoleLossJournal>,
    readiness: Arc<dyn HandoffReadinessPort>,
    coordination: Arc<dyn RoleLossCoordination>,
    runtime: Arc<dyn LinkRuntimePort>,
    on_demand_capability: Arc<dyn OnDemandCapabilityPort>,
    custody_leases: Arc<dyn CustodyLeaseHandoffPort>,
}

#[derive(Debug)]
struct AmbiguityRecovery {
    group_id: String,
    survivors: Vec<String>,
}

/// Which link-row removal step the unlink dispatcher still owes after the
/// durability gate (`ensure_unlink_keeps_a_full_replica`) returns.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UnlinkCommit {
    /// The eager ready path already removed the link row atomically with its
    /// digest re-check; the caller must not remove it again. Carries the
    /// coordination-plane handoff-commit result, paired with this device's
    /// own locally-computed root digest (never sent to or read back from
    /// the coordination service), when that path actually ran one (`Some`).
    AlreadyRemoved(Option<(HandoffCommitResult, [u8; 32])>),
    /// No atomic removal happened (on-demand cache, no link row, or a forced
    /// bypass); the caller performs the plain `remove_link`.
    RemoveNormally,
}

/// Protocol-agnostic result of a coordination-plane role-loss handoff commit
/// -- `control_socket` maps this to the IPC `HandoffResult` proto type;
/// nothing in this module depends on the wire format.
pub(crate) struct HandoffOutcome {
    pub(crate) target_device_id: String,
    pub(crate) root_digest: [u8; 32],
    pub(crate) membership_generation: i64,
    pub(crate) lease_id: Option<String>,
}

pub(crate) struct UnlinkOutcome {
    pub(crate) handoff: Option<HandoffOutcome>,
}

impl ReplicaRoleService {
    #[allow(
        clippy::too_many_arguments,
        reason = "one port per independent reason to vary; the composition root is the only caller"
    )]
    pub(crate) fn new(
        device_id: String,
        repository: Arc<dyn ReplicaRoleRepository>,
        role_loss: Arc<dyn RoleLossJournal>,
        readiness: Arc<dyn HandoffReadinessPort>,
        coordination: Arc<dyn RoleLossCoordination>,
        runtime: Arc<dyn LinkRuntimePort>,
        on_demand_capability: Arc<dyn OnDemandCapabilityPort>,
        custody_leases: Arc<dyn CustodyLeaseHandoffPort>,
    ) -> Self {
        Self {
            device_id,
            repository,
            role_loss,
            readiness,
            coordination,
            runtime,
            on_demand_capability,
            custody_leases,
        }
    }

    /// The local link's path for `group_id`, if this device has one -- the
    /// reverse of every other lookup in this file (which resolve a
    /// `local_path` forward to a `group_id`), needed here because a
    /// storage-mode request carries only the group id (like the Worker's
    /// own storage-mode route), while the materialization-policy write is
    /// keyed by `local_path`.
    fn local_path_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<String>, crate::sync_error::SyncError> {
        self.repository.live_link_key_for_group(group_id)
    }

    fn prepare_ambiguity_recovery(
        &self,
        local_path: &str,
        checked_group: &str,
    ) -> Result<Option<AmbiguityRecovery>, crate::sync_error::SyncError> {
        let links = self.repository.list_links()?;
        let Some(target) = links.iter().find(|l| l.key() == local_path) else {
            return Ok(None);
        };
        if target.group_id != checked_group {
            return Err(SyncError::GroupMismatch(local_path.to_string()));
        }
        let group_id = target.group_id.clone();
        let live_paths: Vec<String> = links
            .iter()
            .filter(|l| l.group_id == group_id && !l.orphaned)
            .map(|l| l.key().to_string())
            .collect();
        if live_paths.len() < 2 {
            return Ok(None);
        }

        let survivors: Vec<String> =
            live_paths.into_iter().filter(|path| path != local_path).collect();

        self.repository.arm_duplicate_recovery_paths(&group_id)?;
        for survivor in &survivors {
            self.repository.set_suppress_tombstones(survivor, true)?;
        }

        Ok(Some(AmbiguityRecovery { group_id, survivors }))
    }

    /// Changes the group's storage mode. An on-demand request on a root that cannot hold
    /// dataless items is the typed [`StorageModeError::OnDemandUnavailable`], so the front end
    /// words the next step for itself.
    pub(crate) async fn set_storage_mode(
        &self,
        group_id: &str,
        on_demand: bool,
    ) -> Result<Option<(HandoffCommitResult, [u8; 32])>, StorageModeError> {
        if on_demand && !self.on_demand_capability.allows_on_demand(group_id) {
            return Err(StorageModeError::OnDemandUnavailable);
        }
        self.set_storage_mode_checked(group_id, on_demand).await
    }

    /// Orchestrates `yadorilink share set-storage-mode`: the SOLE place that
    /// commits BOTH the coordination-plane record of this device's storage mode
    /// for `group_id` AND the local materialization-policy flip between eager
    /// (full replica) and on-demand (cache) -- the CLI only asks for the
    /// change and prints this function's result; it makes no coordination-plane
    /// call of its own and has nothing to compensate.
    ///
    /// Demoting FROM eager (`on_demand = true`) is refused, fail-closed, unless
    /// the handoff-readiness port confirms some other full replica durably
    /// holds the current version of every file in the group -- without central
    /// storage, a full replica is the only durable copy, so giving one up
    /// before a confirmed handoff risks permanent data loss. This re-checks
    /// readiness itself rather than trusting any earlier check the caller may
    /// have already done, since that is the only check in this whole path
    /// that is actually authoritative at the moment local policy commits.
    ///
    /// Promoting TO eager (`on_demand = false`) has no such hazard -- gaining a
    /// durable copy is always safe -- and is applied unconditionally; this
    /// direction is intentionally minimal (no readiness preflight, no backfill
    /// orchestration) since the corrected custody/hydration paths already bring
    /// an eager link's placeholders down over time.
    ///
    /// Ordering, and why it is crash-safe either way. For a DEMOTION, when a real
    /// confirming peer is named and this device has coordination-plane config
    /// recorded (production, a logged-in registered device), a live lease is now
    /// MANDATORY: this device asks the confirmed peer directly, over the
    /// authenticated peer channel, to verify and pin its own durability-root set
    /// and hand back a lease naming it, refusing outright if no live lease can
    /// be obtained (peer unreachable, refused, or its attested root digest
    /// doesn't match this device's own). Only once a lease is in hand does the
    /// coordination-plane role-loss commit happen, BEFORE the local policy
    /// flip, mirroring `ensure_unlink_keeps_a_full_replica`'s identical wiring.
    /// Unlike unlink, there is no `--force` here, so a refused or unreachable
    /// coordination-plane commit -- or a lease that could not be obtained at
    /// all -- fails the demotion closed with no local-only fallback and this
    /// device stays locally eager -- a crash between the two commits still
    /// leaves both sides agreeing this device is eager, which a re-run of the
    /// command reconciles. Committing local-only first would be the unsafe
    /// order: it would let this device release its only durable copy (and, on
    /// a crash before the coordination-plane commit, start reclaiming blocks)
    /// before the handoff is ever recorded coordination-side. For a PROMOTION,
    /// the coordination-plane storage-mode write also happens BEFORE the local
    /// flip, and its failure aborts before the flip runs -- but a promotion
    /// only ever ADDS a durable copy, so the reverse failure direction (Worker
    /// updated, local flip not yet run) is always safe and self-heals on a
    /// re-run; there is no data-loss hazard symmetric to the demotion case.
    ///
    /// Behavior when no coordination-plane config is recorded differs by
    /// direction. A DEMOTION with no config falls through to a local-only flip
    /// (it can only get there when there was no confirming peer to name, i.e. a
    /// plane-disconnected daemon, which the readiness gate above already handles
    /// fail-closed for a real full replica). A PROMOTION instead FAILS CLOSED:
    /// it has no peer gate, so a silently-skipped Worker write would leave the
    /// plane on-demand while local goes eager, and -- because a re-run no-ops
    /// once local already matches the target -- that split would not
    /// self-heal.
    ///
    /// The readiness confirmation above is itself a network round trip, so
    /// there is a real window between it returning and the local policy flip
    /// below actually committing during which this device's own
    /// durability-root set could change (a local edit lands). To close that
    /// TOCTOU, the digest the peer was confirmed against is re-checked and the
    /// policy flip is committed together, in one write transaction, so a
    /// concurrent watcher index write cannot interleave between the re-check
    /// and the commit; a mismatch fails closed exactly like an unconfirmed
    /// peer would -- there is no `--force` for demote, so the caller simply
    /// has to retry.
    ///
    /// Note this atomic re-check guards the coordination-plane ROLE flip
    /// (eager -> on-demand), not block deletion. Actually reclaiming any
    /// specific version's blocks stays separately gated, per file, by the
    /// on-demand eviction custody check, which is the real backstop against
    /// dropping the last copy of a version.
    #[allow(
        clippy::too_many_lines,
        clippy::excessive_nesting,
        reason = "one demotion fix-saga: readiness gate, mandatory peer lease, durable role-loss \
                  journal open, the coordination service commit, and the digest-recheck local policy \
                  flip must stay in a single function because every early return is a compensation \
                  decision that depends on how far the saga got (role_loss_operation_id / \
                  lease_acquisition_failed); the nesting is the RoleLossCommitOutcome match inside \
                  the lease-acquired arm, and splitting it would move the commit and its rollback \
                  into different scopes"
    )]
    async fn set_storage_mode_checked(
        &self,
        group_id: &str,
        on_demand: bool,
    ) -> Result<Option<(HandoffCommitResult, [u8; 32])>, StorageModeError> {
        let Some(local_path) = self.local_path_for_group(group_id).map_err(|e| e.to_string())?
        else {
            return Err(format!("no link registered for folder group {group_id}").into());
        };
        if on_demand && self.readiness.is_local_full_replica(group_id) {
            let Some(proof) = self.readiness.full_replica_handoff_proof(group_id).await else {
                // Deliberately no consultation of cached background custody
                // evidence on this path, now or ever: this is the moment
                // this device gives up its own durable copy, and the only
                // admissible answer is one taken just now against a peer
                // that read every block back.
                return Err(
                    "refusing to drop complete-copy status: no other complete copy is confirmed to \
                 hold every file in this group yet"
                        .to_string()
                        .into(),
                );
            };
            let digest_at_check = proof.root_digest();
            let ready_peer_device_id = proof.into_peer_device_id();
            // Custody leases this device holds for on-demand devices are the
            // only copy of versions those devices have dropped. They move to
            // another full replica before the role can go, and the group takes
            // no new one until this call returns.
            let _custody_closed = self.custody_leases.hand_off_leases(group_id).await?;
            // Same role-loss shape as `ensure_unlink_keeps_a_full_replica`'s
            // unlink path (this device giving up its own eager status) --
            // reuse its exact wiring: a real confirmed peer means a
            // non-empty root set, so a live, peer-attested lease is now
            // MANDATORY (asked of the confirmed target directly, not merely
            // looked up best-effort), and its absence refuses the whole
            // commit -- see that function's own doc comment for the full
            // rationale; only duplicated here because the two call sites
            // commit two different local side effects (link removal vs.
            // materialization-policy flip) on top of the same
            // coordination-plane commit.
            // Fix-saga: filled in inside the `Some(lease_id)` arm below,
            // right before the coordination service commit, and consulted
            // after the local recheck below to close out (success) or
            // compensate (failure) the journal row it names.
            let mut role_loss_operation_id: Option<String> = None;
            let mut lease_acquisition_failed = false;
            let mut terms_consent_required = false;
            let coordination_result = match (
                &ready_peer_device_id,
                self.coordination.is_configured(),
            ) {
                (Some(target_device_id), true) => {
                    match self
                        .readiness
                        .obtain_handoff_lease_from_peer(group_id, target_device_id, digest_at_check)
                        .await
                    {
                        Some(lease_id) => {
                            // Fix-saga: persist the durable Prepared journal row
                            // FIRST, and fail closed if that write itself fails --
                            // committing the role loss on the Worker without a
                            // durable recovery record would reopen the exact
                            // split-state hole the journal exists to close.
                            // Nothing has been committed on either side yet, so
                            // aborting here leaves no split (routed through the
                            // same `Err(())` fail-closed tail as an unconfirmed
                            // peer -- for demote there is no `--force`, so it just
                            // refuses).
                            match self.role_loss.open_operation(
                                group_id,
                                target_device_id,
                                &lease_id,
                                yadorilink_replica_domain::session_state::RoleLossAction::Demote,
                                &local_path,
                            ) {
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        group_id,
                                        target_device_id = %target_device_id,
                                        "refusing the demotion: could not persist the durable \
                                         role-loss rollback journal, so the role loss must not be \
                                         committed on the coordination plane"
                                    );
                                    Err(())
                                }
                                Ok(operation_id) => {
                                    match self
                                        .coordination
                                        .commit_handoff_role_loss(
                                            group_id,
                                            &self.device_id,
                                            target_device_id,
                                            Some(lease_id.as_str()),
                                            "demote",
                                            &operation_id,
                                        )
                                        .await
                                    {
                                        RoleLossCommitOutcome::Committed(result) => {
                                            self.role_loss.mark_worker_committed(
                                                &operation_id,
                                                result.membership_generation,
                                            );
                                            role_loss_operation_id = Some(operation_id);
                                            Ok(Some((result, digest_at_check)))
                                        }
                                        RoleLossCommitOutcome::DefinitelyRejected(e) => {
                                            self.role_loss.discard_operation(&operation_id);
                                            tracing::warn!(
                                                error = %e,
                                                group_id,
                                                target_device_id = %target_device_id,
                                                "coordination-plane handoff role-loss commit failed; \
                                                 set-storage-mode readiness gate treats this the same \
                                                 as an unconfirmed peer"
                                            );
                                            Err(())
                                        }
                                        RoleLossCommitOutcome::TermsConsentRequired(e) => {
                                            // Nothing was committed: the journal row is terminal.
                                            self.role_loss.discard_operation(&operation_id);
                                            tracing::warn!(
                                                error = %e,
                                                group_id,
                                                "coordination plane refused the role-loss commit \
                                                 until the Terms are accepted"
                                            );
                                            terms_consent_required = true;
                                            Err(())
                                        }
                                        RoleLossCommitOutcome::Ambiguous(e) => {
                                            tracing::error!(
                                                error = %e,
                                                group_id,
                                                target_device_id = %target_device_id,
                                                operation_id,
                                                "handoff role-loss commit outcome is ambiguous; retaining the \
                                                 Prepared journal and compensating Worker state back to eager"
                                            );
                                            if let Err(compensation_error) = self
                                                .compensate_role_loss_operation(&operation_id)
                                                .await
                                            {
                                                tracing::error!(
                                                    error = %compensation_error,
                                                    operation_id,
                                                    "immediate ambiguous role-loss compensation failed; the \
                                                     periodic reconciler will retry"
                                                );
                                            }
                                            Err(())
                                        }
                                        RoleLossCommitOutcome::Conflict(e) => {
                                            // Should never happen for a freshly generated operation_id;
                                            // leave the Prepared row untouched for operator attention
                                            // rather than discarding or retrying blindly.
                                            tracing::error!(
                                                error = %e,
                                                group_id,
                                                target_device_id = %target_device_id,
                                                operation_id,
                                                "handoff role-loss commit's operation_id conflicts with a \
                                                 differently-shaped request already recorded -- operator \
                                                 attention required"
                                            );
                                            Err(())
                                        }
                                    }
                                }
                            }
                        }
                        None => {
                            lease_acquisition_failed = true;
                            tracing::warn!(
                                group_id,
                                target_device_id = %target_device_id,
                                "could not obtain a live handoff lease from the confirmed target \
                                 peer (unreachable, refused, or its attested durability-root digest \
                                 did not match this device's own); a lease is mandatory for a \
                                 non-empty root set, so refusing to relinquish complete-copy status"
                            );
                            Err(())
                        }
                    }
                }
                // A confirmed handoff target with no coordination-plane config
                // recorded. A named target means a NON-EMPTY root set, which now
                // mandates a live lease -- and with no config there is no way to
                // obtain or commit one. Fail closed rather than relinquish the
                // role lease-less: the mandatory-lease guarantee is encoded here,
                // not left resting on the (implicit, unencoded) assumption that a
                // confirmed peer cannot exist without config.
                (Some(target_device_id), false) => {
                    lease_acquisition_failed = true;
                    tracing::warn!(
                        group_id,
                        target_device_id = %target_device_id,
                        "confirmed a ready replica but cannot obtain the mandatory handoff lease: \
                         coordination-plane configuration is unavailable"
                    );
                    Err(())
                }
                // Empty root set (vacuously ready -- no confirmed peer to name, no
                // lease required).
                _ => Ok(None),
            };
            let Ok(handoff_result) = coordination_result else {
                if terms_consent_required {
                    return Err(StorageModeError::TermsConsentRequired);
                }
                if lease_acquisition_failed {
                    return Err(StorageModeError::retry(demotion_handoff_lease_failure_message()));
                }
                return Err(StorageModeError::retry(
                    "refusing to drop complete-copy status: the coordination plane could not \
                 confirm the target device is still an active eager complete copy for this \
                 group",
                ));
            };
            // Atomic: re-enumerate the root set and, only if its digest still
            // equals the one the peer confirmed against, flip the policy --
            // both in one transaction, so no watcher write can slip in
            // between.
            //
            // Fix-saga: when `role_loss_operation_id` is `Some`, the
            // the coordination service role-loss commit above already succeeded, so a
            // failure here (digest mismatch OR a storage error -- both handled
            // identically) must not just return an error and leave the Worker
            // and this device disagreeing about full-replica status. Compensate
            // by reverting the Worker back to `eager` instead of erroring bare.
            // When `role_loss_operation_id` is `None`, no Worker commit
            // happened (an empty root set, or no coordination-plane config), so
            // this is exactly the pre-existing local-only failure path,
            // unchanged.
            let recheck_result = self.repository.recheck_digest_then_set_materialization_policy(
                group_id,
                &local_path,
                MaterializationPolicy::OnDemand,
                digest_at_check,
            );
            let local_failure_reason = match &recheck_result {
                Ok(true) => None,
                Ok(false) => Some(
                    "this group's durable file/version set changed between the readiness check and \
                     the commit, so the earlier confirmation no longer covers it"
                        .to_string(),
                ),
                Err(e) => Some(e.to_string()),
            };
            let Some(local_failure_reason) = local_failure_reason else {
                if let Some(operation_id) = &role_loss_operation_id {
                    self.role_loss.settle_success(operation_id);
                }
                return Ok(handoff_result);
            };
            let Some(operation_id) = role_loss_operation_id else {
                return Err(StorageModeError::retry(format!(
                    "refusing to drop complete-copy status: {local_failure_reason}"
                )));
            };
            return Err(match self.compensate_role_loss_operation(&operation_id).await {
                Ok(()) => StorageModeError::retry(format!(
                "demotion was committed on the coordination plane but the matching local change \
                 failed ({local_failure_reason}); the operation was SAFELY ROLLED BACK -- this \
                 device's complete-copy status was restored on the coordination plane"
            )),
                Err(compensation_err) => StorageModeError::Failed(format!(
                "demotion was committed on the coordination plane but the matching local change \
                 failed ({local_failure_reason}); the automatic rollback could not complete \
                 ({compensation_err}) and will be retried automatically until it succeeds -- \
                 this device may briefly appear demoted on the coordination plane even though \
                 it is still storing this group eagerly locally."
            )),
            });
        }
        // Reached for a PROMOTION (`on_demand = false`), and for a redundant
        // on-demand request from a device that is not currently an eager full
        // replica (nothing to hand off, so the demotion branch above never
        // applies). Only the promotion direction needs a coordination-plane
        // write here: a demotion's write is the role-loss commit above,
        // already done by the time execution reaches this point. Written
        // BEFORE the local flip below, and its failure aborts before the flip
        // runs (via `?`), mirroring the demotion branch's own ordering.
        //
        // Unlike a demotion, a promotion has no ready-peer gate that would
        // independently fail closed when this daemon is disconnected from the
        // coordination plane. So if the mode write is silently skipped when no
        // config is recorded, a promotion would flip local policy to eager while
        // the coordination plane stays on-demand -- and it would NOT self-heal,
        // since re-running the command sees the local mode already at the target
        // and no-ops. Fail closed instead: a missing config means
        // the daemon is not connected to the coordination plane (started before
        // login, or a token was lost and it was not restarted), so refuse rather
        // than diverge. The local flip below is never reached in that case.
        if !on_demand {
            if !self.coordination.is_configured() {
                return Err(
                "not connected to the coordination plane; cannot change storage mode (ensure the \
                 daemon is logged in; restart it if you logged in after it started)"
                    .to_string()
                    .into(),
            );
            };
            self.coordination.set_storage_mode(group_id, &self.device_id, "eager").await.map_err(
                |e| match e {
                    StorageModeWriteError::TermsConsentRequired(_) => {
                        StorageModeError::TermsConsentRequired
                    }
                    StorageModeWriteError::Failed(m) => m.into(),
                },
            )?;
        }
        let policy =
            if on_demand { MaterializationPolicy::OnDemand } else { MaterializationPolicy::Eager };
        self.repository
            .set_materialization_policy(&local_path, policy)
            .map_err(|e| e.to_string())?;
        Ok(None)
    }

    /// Refuses to unlink an eager (full-replica) folder on this device unless
    /// the handoff-readiness port confirms some OTHER full replica is, right
    /// now, durably holding the current version of every file in the group.
    /// Because there is no central storage, a full replica is a group's only
    /// durable copy, so unlinking the last one before a confirmed handoff
    /// risks permanent data loss -- merely having another device's row
    /// recorded as "also a full replica" is not enough, since that device
    /// could be offline, behind, or missing blocks (this is the same gap
    /// `set_storage_mode`'s demotion gate closes; unlink is the same hazard
    /// by a different name). Unlinking an on-demand link (this device is a
    /// cache, not a durable holder) is always allowed regardless. A missing
    /// or unreadable link list defers to `remove_link` for the real outcome
    /// rather than blocking.
    ///
    /// `force` bypasses the gate for a genuinely dead sole replica that would
    /// otherwise have no way to ever unlink -- every forced override is
    /// logged here as an audit trail (`tracing::warn!`), since bypassing this
    /// gate can permanently lose the only copy of the group's data.
    ///
    /// The readiness confirmation is itself a peer round trip, so there is a
    /// real window between it succeeding and the unlink actually committing
    /// during which this device's own durability-root set could change (a
    /// local edit lands). To close that TOCTOU, the digest the peer was
    /// confirmed against is re-checked and the link row removed together, in
    /// one write transaction, so a concurrent watcher index write cannot
    /// interleave between the re-check and the removal; a digest that no
    /// longer matches is treated exactly like an unconfirmed peer -- refused
    /// unless `--force`. See `set_storage_mode`'s matching comment for the
    /// demote side of the same pattern.
    ///
    /// Note this atomic re-check guards only the coordination-plane ROLE flip
    /// (removing this device's eager link), not block deletion. Actually
    /// reclaiming any version's blocks stays separately gated, per file, by
    /// the on-demand eviction custody check, which is the real backstop
    /// against dropping the last copy of a version.
    ///
    /// Returns which removal step the caller still owes: the eager ready path
    /// removes the link atomically here (`AlreadyRemoved`); every other path
    /// leaves the plain removal to the caller (`RemoveNormally`).
    #[allow(
        clippy::too_many_lines,
        clippy::excessive_nesting,
        reason = "the unlink side of the same demotion fix-saga as `set_storage_mode`: the \
                  policy/force pre-checks, the mandatory lease, the journal row, the \
                  coordination-plane role-loss commit and the atomic digest-recheck link removal \
                  share the saga state that decides between refusing, compensating, and settling; \
                  the depth comes from the per-outcome RoleLossCommitOutcome arms nested in the \
                  lease-acquired branch, and keeping them here holds the commit next to its \
                  compensation"
    )]
    pub(crate) async fn ensure_unlink_keeps_a_full_replica(
        &self,
        local_path: &str,
        force: bool,
        checked_group: &str,
    ) -> Result<UnlinkCommit, UnlinkError> {
        let Some(link) = self
            .repository
            .list_links()
            .map_err(|e| {
                format!("refusing to unlink because the local link table could not be read: {e}")
            })?
            .into_iter()
            .find(|l| l.key() == local_path)
        else {
            return Ok(UnlinkCommit::RemoveNormally);
        };
        // Nothing below (lease, role-loss commit, removal) may run for a group the caller
        // did not check: the path was linked again since.
        if link.group_id != checked_group {
            return Err(group_mismatch(local_path));
        }
        if link.materialization_policy != MaterializationPolicy::Eager {
            return Ok(UnlinkCommit::RemoveNormally);
        }
        // A confirmed whole-group handoff yields the exact root-set digest it
        // was made against (and, when a real peer confirmed it, that peer's
        // device id); the atomic method below re-enumerates and removes the
        // link in one transaction only if that digest still holds.
        let mut lease_acquisition_failed = false;
        let mut terms_consent_required = false;
        if let Some(proof) = self.readiness.full_replica_handoff_proof(&link.group_id).await {
            let digest_at_check = proof.root_digest();
            let ready_peer_device_id = proof.into_peer_device_id();
            // This device giving up its own eager status is exactly the
            // role-loss shape the coordination service's handoff-commit endpoint
            // guards: confirm the named target is currently Active+eager and
            // commit the role loss (`storage_mode` narrows to on-demand)
            // atomically, coordination-side, before this device also removes
            // its own local link. Only attempted when both a real confirming
            // peer was named (not the vacuously-ready empty-group case,
            // which has no peer to target) and this device actually has
            // coordination-plane config recorded -- otherwise this falls
            // back to exactly the pre-existing purely-local gate, unchanged.
            // `Ok(None)`: no coordination-plane commit was attempted (falls
            // back to the pre-existing purely-local gate) or attempted and
            // refused (fail closed, same as an unconfirmed peer). `Ok(Some(result))`:
            // a commit was attempted and succeeded, to be threaded into the
            // eventual `UnlinkResponse`.
            //
            // Fix-saga: filled in inside the `Some(lease_id)` arm below,
            // right before the coordination service commit, and consulted
            // after the local recheck further down to close out (success)
            // or compensate (failure) the journal row it names.
            let mut role_loss_operation_id: Option<String> = None;
            let coordination_result = match (
                &ready_peer_device_id,
                self.coordination.is_configured(),
            ) {
                (Some(target_device_id), true) => {
                    // A real confirming peer was named, i.e. a non-empty
                    // root set -- a live, peer-attested lease is now
                    // MANDATORY, not merely looked up best-effort: ask
                    // the confirmed target directly, over the
                    // authenticated peer channel, to verify and pin its
                    // own durability-root set and hand back a lease
                    // naming it, and refuse the whole commit if none can
                    // be obtained (unreachable, refused, or a digest
                    // mismatch -- the target isn't actually caught up to
                    // this device's exact set). The `--force` override
                    // below still lets a forced unlink proceed with no
                    // lease at all; this gate only governs the
                    // non-forced path.
                    match self
                        .readiness
                        .obtain_handoff_lease_from_peer(
                            &link.group_id,
                            target_device_id,
                            digest_at_check,
                        )
                        .await
                    {
                        None => {
                            lease_acquisition_failed = true;
                            tracing::warn!(
                                group_id = %link.group_id,
                                local_path,
                                target_device_id = %target_device_id,
                                "could not obtain a live handoff lease from the confirmed target \
                                 peer; a lease is mandatory for a non-empty root set -- unlink \
                                 readiness gate treats this the same as an unconfirmed peer (use \
                                 --force to override)"
                            );
                            Err(())
                        }
                        Some(lease_id) => {
                            // Fix-saga: persist the durable Prepared journal row
                            // FIRST and fail closed if it can't be written -- see
                            // `set_storage_mode`'s matching Fix-saga comment. A
                            // failed Prepared write routes to the same `Err(())`
                            // the no-lease case uses, so the force-or-refuse tail
                            // below still governs (a `--force` unlink can still
                            // proceed, latching `DurabilityUnknown`; a non-forced
                            // one is refused) -- but the Worker role-loss commit is
                            // never reached without a durable rollback record.
                            match self.role_loss.open_operation(
                                &link.group_id,
                                target_device_id,
                                &lease_id,
                                yadorilink_replica_domain::session_state::RoleLossAction::Unlink,
                                local_path,
                            ) {
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        group_id = %link.group_id,
                                        local_path,
                                        target_device_id = %target_device_id,
                                        "refusing the online unlink handoff: could not persist the \
                                         durable role-loss rollback journal, so the role loss must \
                                         not be committed on the coordination plane"
                                    );
                                    Err(())
                                }
                                Ok(operation_id) => {
                                    match self
                                        .coordination
                                        .commit_handoff_role_loss(
                                            &link.group_id,
                                            &self.device_id,
                                            target_device_id,
                                            Some(lease_id.as_str()),
                                            "demote",
                                            &operation_id,
                                        )
                                        .await
                                    {
                                        // `digest_at_check` is this
                                        // device's own local
                                        // durability-root digest, paired
                                        // here purely for the caller's
                                        // `HandoffResult.root_digest`
                                        // output -- never itself sent to
                                        // the coordination service.
                                        RoleLossCommitOutcome::Committed(result) => {
                                            self.role_loss.mark_worker_committed(
                                                &operation_id,
                                                result.membership_generation,
                                            );
                                            role_loss_operation_id = Some(operation_id);
                                            Ok(Some((result, digest_at_check)))
                                        }
                                        RoleLossCommitOutcome::DefinitelyRejected(e) => {
                                            self.role_loss.discard_operation(&operation_id);
                                            tracing::warn!(
                                                error = %e,
                                                group_id = %link.group_id,
                                                local_path,
                                                target_device_id = %target_device_id,
                                                "coordination-plane handoff role-loss commit failed; \
                                                 unlink readiness gate treats this the same as an \
                                                 unconfirmed peer"
                                            );
                                            Err(())
                                        }
                                        RoleLossCommitOutcome::TermsConsentRequired(e) => {
                                            // Nothing was committed: the journal row is terminal.
                                            self.role_loss.discard_operation(&operation_id);
                                            tracing::warn!(
                                                error = %e,
                                                group_id = %link.group_id,
                                                local_path,
                                                "coordination plane refused the role-loss commit \
                                                 until the Terms are accepted"
                                            );
                                            terms_consent_required = true;
                                            Err(())
                                        }
                                        RoleLossCommitOutcome::Ambiguous(e) => {
                                            tracing::error!(
                                                error = %e,
                                                group_id = %link.group_id,
                                                local_path,
                                                target_device_id = %target_device_id,
                                                operation_id,
                                                "unlink role-loss commit outcome is ambiguous; retaining the \
                                                 Prepared journal and compensating Worker state back to eager"
                                            );
                                            if let Err(compensation_error) = self
                                                .compensate_role_loss_operation(&operation_id)
                                                .await
                                            {
                                                tracing::error!(
                                                    error = %compensation_error,
                                                    operation_id,
                                                    "immediate ambiguous unlink compensation failed; the periodic \
                                                     reconciler will retry"
                                                );
                                            }
                                            Err(())
                                        }
                                        RoleLossCommitOutcome::Conflict(e) => {
                                            tracing::error!(
                                                error = %e,
                                                group_id = %link.group_id,
                                                local_path,
                                                target_device_id = %target_device_id,
                                                operation_id,
                                                "unlink role-loss commit's operation_id conflicts with a \
                                                 differently-shaped request already recorded -- operator \
                                                 attention required"
                                            );
                                            Err(())
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // A confirmed handoff target with no coordination-plane
                // config recorded -- a NON-EMPTY root set that now
                // mandates a live lease, with no way to obtain one. Fail
                // closed exactly like the no-lease-obtainable case above
                // (`Err(())`), which the tail below routes to the
                // existing force-or-refuse handling -- so `--force`
                // still proceeds (latching `DurabilityUnknown`), a
                // non-forced unlink is refused, and the mandatory-lease
                // guarantee is encoded rather than resting on the
                // implicit assumption that a confirmed peer cannot exist
                // without config.
                (Some(target_device_id), false) => {
                    lease_acquisition_failed = true;
                    tracing::warn!(
                        group_id = %link.group_id,
                        local_path,
                        target_device_id = %target_device_id,
                        "confirmed a ready replica but cannot obtain the mandatory handoff lease: \
                         coordination-plane configuration is unavailable"
                    );
                    Err(())
                }
                // Empty root set (vacuously ready -- no confirmed peer to
                // name, no lease required).
                _ => Ok(None),
            };
            if let Ok(handoff_result) = coordination_result {
                let recheck_result = self.repository.recheck_digest_then_remove_link(
                    &link.group_id,
                    local_path,
                    digest_at_check,
                );
                match recheck_result {
                    Ok(true) => {
                        if let Some(operation_id) = &role_loss_operation_id {
                            self.role_loss.settle_success(operation_id);
                        }
                        return Ok(UnlinkCommit::AlreadyRemoved(handoff_result));
                    }
                    Ok(false) | Err(_) if role_loss_operation_id.is_some() => {
                        // Fix-saga: the Worker commit above already succeeded, so a
                        // local failure here (digest mismatch OR a storage error --
                        // both handled identically) must not silently fall through to
                        // `--force` completing an unlink whose digest was never
                        // re-verified against the peer confirmation, nor leave a bare
                        // split state on the non-forced path. Compensate by reverting
                        // the Worker back to `eager` instead -- see
                        // `set_storage_mode`'s matching Fix-saga comment for the full
                        // rationale (revert, never force-complete, once the Worker
                        // has already committed).
                        let operation_id = role_loss_operation_id
                            .clone()
                            .expect("guarded by role_loss_operation_id.is_some() above");
                        let local_failure_reason = match &recheck_result {
                            Ok(false) => {
                                "this group's durable file/version set changed between the \
                                          readiness check and the commit, so the earlier \
                                          confirmation no longer covers it"
                                    .to_string()
                            }
                            Err(e) => e.to_string(),
                            Ok(true) => unreachable!("Ok(true) handled by the arm above"),
                        };
                        return Err(UnlinkError::Other(match self
                            .compensate_role_loss_operation(&operation_id)
                            .await
                        {
                            Ok(()) => format!(
                                "unlink was committed on the coordination plane but the matching \
                                 local removal failed ({local_failure_reason}); the operation was \
                                 SAFELY ROLLED BACK -- this device's complete-copy status was \
                                 restored on the coordination plane. Re-run unlink to try again."
                            ),
                            Err(compensation_err) => format!(
                                "unlink was committed on the coordination plane but the matching \
                                 local removal failed ({local_failure_reason}); the automatic \
                                 rollback could not complete ({compensation_err}) and will be \
                                 retried automatically until it succeeds -- this device may briefly \
                                 appear demoted on the coordination plane even though it is still \
                                 storing this group eagerly locally."
                            ),
                        }));
                    }
                    // No coordination service commit happened (empty root set,
                    // or no coordination-plane config) -- exactly the
                    // pre-existing behavior: the root set moved between the
                    // peer confirmation and the atomic re-check, so fall
                    // through to the same force-or-refuse handling as an
                    // unconfirmed peer.
                    Ok(false) => {}
                    Err(e) => return Err(e.to_string().into()),
                }
            }
        }
        if force {
            tracing::warn!(
                group_id = %link.group_id,
                local_path,
                "forced unlink of an eager complete copy with no other complete copy confirmed \
                 ready -- proceeding anyway; this may have permanently lost the only complete \
                 copy of this folder's data"
            );
            // This override is exactly the case the local durability-status
            // latch exists for: the group's remaining local replica (if any)
            // must not be able to report `Healthy`/"synced" again until a real
            // whole-group handoff re-check says so, even though nothing else
            // about its own files just changed.
            self.repository
                .latch_group_durability_unknown(&link.group_id)
                .map_err(|e| e.to_string())?;
            return Ok(UnlinkCommit::RemoveNormally);
        }
        if terms_consent_required {
            return Err(UnlinkError::TermsConsentRequired);
        }
        if lease_acquisition_failed {
            return Err(UnlinkError::NotProtected(unlink_handoff_lease_failure_message(
                local_path,
            )));
        }
        Err(UnlinkError::NotProtected(format!(
            "refusing to unlink {local_path}: no other complete copy is confirmed ready to durably \
             hold every file in this group yet, so unlinking it may permanently lose the only \
             complete copy of this folder's data. Wait for another complete copy to finish syncing."
        )))
    }

    /// Moves the custody leases off an eager link that is about to be
    /// unlinked. `None` for a link that is not eager (it holds none) or is not
    /// there.
    async fn hand_off_custody_leases_for_unlink(
        &self,
        local_path: &str,
        checked_group: &str,
    ) -> Result<Option<Box<dyn Send>>, UnlinkError> {
        let links = self
            .repository
            .list_links()
            .map_err(|e| format!("could not read the local link table: {e}"))?;
        let Some(link) = links.iter().find(|l| l.key() == local_path) else {
            return Ok(None);
        };
        if link.group_id != checked_group {
            return Err(group_mismatch(local_path));
        }
        if link.materialization_policy != MaterializationPolicy::Eager {
            return Ok(None);
        }
        self.custody_leases
            .hand_off_leases(&link.group_id)
            .await
            .map(Some)
            .map_err(UnlinkError::NotProtected)
    }

    /// Durability gate, atomic link removal (or normal removal), and the
    /// legacy duplicate-root recovery restart of a surviving link -- the
    /// exact sequence `control_socket`'s `Unlink` handler used to run
    /// inline.
    #[allow(
        clippy::excessive_nesting,
        reason = "the nesting is the ordered crash-safety sequence for duplicate-root recovery: \
                  the survivor's watch may only be restarted after the removal actually \
                  succeeded and only when exactly one survivor remains, so the guards must stay \
                  nested inside the successful-removal branch rather than become independent \
                  early returns"
    )]
    pub(crate) async fn unlink(
        &self,
        local_path: &str,
        force: bool,
        expected_group: Option<&str>,
    ) -> Result<UnlinkOutcome, UnlinkError> {
        // Links are keyed by their exact recorded path; a path that matches no
        // link must not report success while the real link stays live.
        let links = self.repository.list_links().map_err(|e| {
            format!("refusing to unlink because the local link table could not be read: {e}")
        })?;
        let Some(link) = links.iter().find(|l| l.key() == local_path) else {
            return Err(format!("no folder is linked at {local_path}").into());
        };
        // With an expected group the folder is removed only if it is still that group's:
        // refused here before anything changes, and again by the removal itself below.
        if expected_group.is_some_and(|expected| expected != link.group_id) {
            return Err(group_mismatch(local_path));
        }
        // The group this unlink is about. The steps below that look the link up by path again
        // (custody hand-off, durability gate) refuse if they find another group, and the
        // removal itself only deletes a link of this group.
        let checked_group = link.group_id.clone();
        let checked_group = checked_group.as_str();
        // If this is recovery from a legacy two-live-roots state, persist the
        // survivor's additive-scan protection BEFORE anything can remove the
        // departing link. A crash after the unlink commit must therefore
        // never leave a seemingly healthy one-link group whose first scan
        // tombstones files that only existed under the departed root.
        let ambiguity_recovery =
            self.prepare_ambiguity_recovery(local_path, checked_group).map_err(|e| match e {
                SyncError::GroupMismatch(_) => group_mismatch(local_path),
                other => UnlinkError::Other(other.to_string()),
            })?;
        // An eager link's custody leases (the only copy of versions on-demand
        // devices dropped) move to another full replica before the link can
        // go; a forced unlink goes ahead without them and says so.
        let _custody_closed = match self
            .hand_off_custody_leases_for_unlink(local_path, checked_group)
            .await
        {
            Ok(closed) => closed,
            Err(message) if force => {
                tracing::warn!(
                    local_path,
                    %message,
                    "forced unlink proceeding without handing off the custody leases this device holds"
                );
                None
            }
            Err(message) => return Err(message),
        };
        match self.ensure_unlink_keeps_a_full_replica(local_path, force, checked_group).await {
            Ok(commit) => {
                self.runtime.stop_link_watch(local_path).await;
                let (removed, handoff_result) = match commit {
                    UnlinkCommit::AlreadyRemoved(handoff_result) => (Ok(()), handoff_result),
                    UnlinkCommit::RemoveNormally => (
                        self.repository.remove_link_expecting_group(local_path, checked_group),
                        None,
                    ),
                };
                if let Err(SyncError::GroupMismatch(_)) = &removed {
                    // The link was replaced after the check above and is still there: its
                    // watch was stopped with the one that was meant to go, so start it again.
                    self.restart_watch_of_remaining_link(local_path);
                    return Err(group_mismatch(local_path));
                }
                if removed.is_ok() {
                    if let Some(recovery) = ambiguity_recovery {
                        if recovery.survivors.len() == 1 {
                            let survivor = recovery.survivors[0].clone();
                            self.runtime.stop_link_watch(&survivor).await;
                            if let Err(e) = self
                                .runtime
                                .start_link_watch(survivor.clone(), recovery.group_id.clone())
                            {
                                tracing::error!(
                                    group_id = %recovery.group_id,
                                    local_path = %survivor,
                                    error = %e,
                                    "duplicate-root recovery removed the extra link but could not restart the survivor; the group remains fail-closed until a relink or daemon restart"
                                );
                            }
                        }
                    }
                }
                removed.map_err(|e| UnlinkError::Other(e.to_string())).map(|()| UnlinkOutcome {
                    handoff: handoff_result.map(|(hr, root_digest)| HandoffOutcome {
                        target_device_id: hr.target_device_id,
                        root_digest,
                        membership_generation: hr.membership_generation,
                        lease_id: hr.lease_id,
                    }),
                })
            }
            // The atomic removal of the eager path also declines when the link at the path is
            // no longer the one confirmed; say so rather than blaming the durability gate.
            Err(UnlinkError::NotProtected(_))
                if expected_group.is_some_and(|expected| {
                    self.repository.list_links().is_ok_and(|links| {
                        !links.iter().any(|l| l.key() == local_path && l.group_id == expected)
                    })
                }) =>
            {
                Err(group_mismatch(local_path))
            }
            Err(e) => Err(e),
        }
    }

    /// Starts the watch of the link now recorded at `local_path`, if any; best effort, as
    /// nothing else is left to do once an unlink was refused.
    fn restart_watch_of_remaining_link(&self, local_path: &str) {
        let Ok(links) = self.repository.list_links() else { return };
        let Some(link) = links.into_iter().find(|l| l.key() == local_path) else { return };
        if let Err(error) = self.runtime.start_link_watch(local_path.to_string(), link.group_id) {
            tracing::error!(local_path, %error, "could not restart the watch of a link left in place by a refused unlink");
        }
    }

    /// Compensates a role-loss operation whose coordination service commit
    /// succeeded (or may have succeeded) but whose matching local change
    /// never completed: a digest mismatch or storage error in the local
    /// recheck-then-commit, or a crash before that local step ran. The SAFE
    /// recovery direction is to REVERT the Worker back to `eager` for the
    /// source device, not to force-complete the local demotion: the handoff
    /// target's lease/pin may have lapsed by the time this runs, so
    /// completing the demotion could release the only durable copy of the
    /// group's data. The Worker-side effect of every role-loss commit this
    /// journal wraps (demote and unlink alike) is a `storage_mode`
    /// narrowing, so reverting it is exactly one idempotent call.
    ///
    /// On success, advances the row to `Completed` and deletes it. On
    /// failure (coordination plane unconfigured, unreachable or refusing),
    /// leaves the row at `Compensating`, bumps its attempt counter
    /// (escalating the log level past
    /// `ROLE_LOSS_COMPENSATION_ESCALATION_ATTEMPTS`) and returns `Err`. The
    /// row is NEVER deleted on a failed attempt -- [`Self::reconcile_role_loss`]
    /// retries it indefinitely until a revert is confirmed.
    ///
    /// A missing journal row (already reconciled by a concurrent attempt, or
    /// never written because the Prepared write itself failed) is treated as
    /// already compensated: there is nothing left to do.
    pub(crate) async fn compensate_role_loss_operation(
        &self,
        operation_id: &str,
    ) -> Result<(), String> {
        let Some(op) = self.role_loss.get_operation(operation_id)? else {
            return Ok(());
        };
        if op.state != RoleLossOperationState::Compensating {
            if let Err(e) =
                self.role_loss.advance_operation(operation_id, RoleLossOperationState::Compensating)
            {
                tracing::warn!(
                    error = %e,
                    operation_id,
                    "failed to advance a role-loss operation journal row to Compensating"
                );
            }
        }
        if !self.coordination.is_configured() {
            let attempts =
                self.role_loss.increment_attempts(operation_id).unwrap_or(op.attempts + 1);
            tracing::warn!(
                operation_id,
                group_id = %op.group_id,
                attempts,
                "role-loss compensation could not run: no coordination-plane config recorded; \
                 will retry once this device is connected"
            );
            return Err(
                "not connected to the coordination plane; the rollback will be retried once \
                 connectivity is restored"
                    .to_string(),
            );
        }
        match self
            .coordination
            .compensate_handoff_role_loss(
                &op.group_id,
                &op.source_device_id,
                &op.target_device_id,
                &op.lease_id,
                op.worker_membership_generation,
            )
            .await
        {
            Ok(outcome) => {
                tracing::info!(
                    operation_id,
                    ?outcome,
                    "role-loss compensation reached a terminal outcome"
                );
                if let Err(e) = self
                    .role_loss
                    .advance_operation(operation_id, RoleLossOperationState::Completed)
                {
                    tracing::warn!(
                        error = %e,
                        operation_id,
                        "failed to advance a role-loss operation journal row to Completed"
                    );
                }
                if let Err(e) = self.role_loss.delete_operation(operation_id) {
                    tracing::warn!(
                        error = %e,
                        operation_id,
                        "failed to delete a Completed role-loss operation journal row; it will \
                         be cleaned up by the next reconciliation sweep"
                    );
                }
                Ok(())
            }
            Err(e) => {
                let attempts =
                    self.role_loss.increment_attempts(operation_id).unwrap_or(op.attempts + 1);
                if attempts >= ROLE_LOSS_COMPENSATION_ESCALATION_ATTEMPTS {
                    tracing::error!(
                        error = %e,
                        operation_id,
                        group_id = %op.group_id,
                        attempts,
                        "role-loss compensation has failed repeatedly; this device's \
                         complete-copy status for this group may still be inconsistent with the \
                         coordination plane"
                    );
                } else {
                    tracing::warn!(
                        error = %e,
                        operation_id,
                        group_id = %op.group_id,
                        attempts,
                        "role-loss compensation attempt failed; will retry"
                    );
                }
                Err(e)
            }
        }
    }

    /// Startup + periodic reconciliation of every role-loss journal row,
    /// whichever group it names:
    /// - `LocalCommitted`/`Completed` (terminal): the operation's real
    ///   outcome was already reached; only the follow-up delete never ran (a
    ///   crash in that narrow window). Just finishes the delete.
    /// - `Prepared`/`WorkerCommitted`/`Compensating`: handed to
    ///   [`Self::compensate_role_loss_operation`], which reverts the source
    ///   device back to `eager` on the coordination plane -- the safe
    ///   direction either way, since a `Prepared` row cannot tell "the
    ///   commit never reached the Worker" from "it committed but the reply
    ///   was lost". A row that cannot be compensated this pass simply
    ///   survives to the next sweep; errors are logged by the compensation
    ///   itself and otherwise swallowed here.
    pub(crate) async fn reconcile_role_loss(&self) {
        let rows = match self.role_loss.list_operations_in_states(&[
            RoleLossOperationState::Prepared,
            RoleLossOperationState::WorkerCommitted,
            RoleLossOperationState::LocalCommitted,
            RoleLossOperationState::Compensating,
            RoleLossOperationState::Completed,
        ]) {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(error = %e, "role-loss reconciliation sweep failed to list journal rows");
                return;
            }
        };
        for op in rows {
            match op.state {
                RoleLossOperationState::LocalCommitted | RoleLossOperationState::Completed => {
                    if let Err(e) = self.role_loss.delete_operation(&op.operation_id) {
                        tracing::warn!(
                            error = %e,
                            operation_id = %op.operation_id,
                            "role-loss reconciliation sweep failed to delete a settled journal row"
                        );
                    }
                }
                RoleLossOperationState::Prepared
                | RoleLossOperationState::WorkerCommitted
                | RoleLossOperationState::Compensating => {
                    if self.compensate_role_loss_operation(&op.operation_id).await.is_ok() {
                        tracing::info!(
                            operation_id = %op.operation_id,
                            group_id = %op.group_id,
                            "role-loss reconciliation sweep compensated an in-flight operation"
                        );
                    }
                    // On `Err` the compensation already logged; the row stays
                    // `Compensating` for the next sweep to retry.
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
