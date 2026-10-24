use std::path::PathBuf;
use std::sync::Arc;

use uuid::Uuid;
use yadorilink_replica_domain::session_state::{EnrollmentOperation, EnrollmentOperationState};

use super::model::{
    EnrollmentActivationResult, EnrollmentCancellationResult, EnrollmentPrepareResult,
    InviteRefusal, LinkRefusal, MintedInvite,
};
use super::ports::{
    EnrollmentCoordination, EnrollmentLinkPort, EnrollmentLinkRequest, EnrollmentRepository,
    LinkOutcome,
};

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Owns the create/join pending-enrollment sagas, cross-account invite
/// acceptance (a related but deliberately simpler saga -- see
/// `accept_invite_and_link`'s own doc comment for how and why it differs),
/// and invite minting (no saga at all -- see `mint_invite`'s own doc
/// comment). Every dependency is a port -- no `DaemonState`, no `reqwest`,
/// no IPC proto -- see the composition root for what backs each one in
/// production.
pub(crate) struct EnrollmentService {
    /// Serializes provider-folder creations, so two requests with one token cannot both pass the
    /// retry check.
    provider_creation: tokio::sync::Mutex<()>,
    /// The provider adapter this host serves; `None` refuses every provider link.
    provider_kind: Option<yadorilink_replica_domain::session_state::ProviderKind>,
    device_id: String,
    repository: Arc<dyn EnrollmentRepository>,
    coordination: Arc<dyn EnrollmentCoordination>,
    links: Arc<dyn EnrollmentLinkPort>,
}

/// High-level create-and-link command.
///
/// Coordination credentials come from the daemon's configured identity and
/// are intentionally absent from this command.
pub(crate) struct CreateAndLinkCommand {
    pub(crate) group_name: String,
    pub(crate) absolute_path: PathBuf,
    pub(crate) on_demand: bool,
    /// `Some` for a provider-backed folder: `absolute_path` is ignored and the folder is keyed by
    /// the request token.
    pub(crate) provider: Option<ProviderCreation>,
}

/// A provider-backed folder to create: a display name and the client's retry identity.
#[derive(Debug, Clone)]
pub(crate) struct ProviderCreation {
    pub(crate) display_name: String,
    pub(crate) request_token: String,
}

impl ProviderCreation {
    /// The synthetic link key. Never a path.
    fn locator(&self) -> String {
        format!("provider://{}", self.request_token)
    }
}

/// A stable operation id for a provider creation, derived like invite acceptance: a retry of the
/// same token reaches the same journal row and the same (idempotent) remote prepare.
fn provider_operation_id(token: &str, digest: &str, device_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"provider-link\0");
    hasher.update(token.as_bytes());
    hasher.update(b"\0");
    hasher.update(digest.as_bytes());
    hasher.update(b"\0");
    hasher.update(device_id.as_bytes());
    hex::encode(hasher.finalize())
}

/// The digest a token is bound to: the same token with a different request is refused.
fn creation_digest(
    creation: &ProviderCreation,
    group: &str,
    on_demand: bool,
    kind: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for part in
        [creation.display_name.as_str(), group, kind, if on_demand { "on-demand" } else { "eager" }]
    {
        hasher.update(part.as_bytes());
        hasher.update(b"\0");
    }
    hex::encode(hasher.finalize())
}

/// High-level join-and-link command.
pub(crate) struct JoinAndLinkCommand {
    pub(crate) group_id: String,
    pub(crate) group_name: String,
    pub(crate) absolute_path: PathBuf,
    pub(crate) on_demand: bool,
    pub(crate) provider: Option<ProviderCreation>,
}

/// High-level cross-account invite-accept command. `code` is the plaintext
/// invite credential; the group it names is learned from the coordination
/// plane's accept/prepare response, not supplied here.
pub(crate) struct AcceptInviteCommand {
    pub(crate) code: String,
    pub(crate) absolute_path: PathBuf,
    pub(crate) on_demand: bool,
    /// `Some` joins the invited group as a provider-backed folder: `absolute_path` is ignored and
    /// the folder is keyed by the request token, the client's retry identity.
    pub(crate) provider: Option<ProviderCreation>,
}

/// A stable operation id derived from `(code, device_id)` rather than a
/// fresh random UUID -- see `EnrollmentService::accept_invite_and_link`'s
/// own doc comment for why: without a durable cross-restart journal for
/// this saga, retry-safety depends on a repeated command (same code, same
/// device) presenting the SAME operation_id, so the coordination plane's
/// own idempotent-redemption check recognizes it. Not a secret and not
/// sent anywhere the code itself isn't already going, so a plain SHA-256
/// hex digest (not a MAC) is enough -- collision resistance is the only
/// property this needs.
fn invite_accept_operation_id(code: &str, device_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(code.as_bytes());
    hasher.update(b"\0");
    hasher.update(device_id.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnrollmentOutcome {
    pub(crate) operation_id: String,
    pub(crate) group_id: String,
    pub(crate) local_path: PathBuf,
    /// Set only by `accept_invite_and_link`, and only when the redeemed
    /// invite required the group owner's approval: this device finished its
    /// own half, but the membership is parked awaiting that decision and
    /// grants nothing until it is made. Always false for create/join,
    /// neither of which has an approval step.
    ///
    /// Carried on the outcome rather than being flattened into "success"
    /// because the two are materially different for the person who ran the
    /// command: one means the folder is syncing, the other means it will
    /// not sync until someone else acts.
    pub(crate) awaiting_approval: bool,
    /// The folder was already linked to this group and running, so this
    /// command changed nothing locally: a repeated `share join` is a no-op,
    /// reported as such rather than as a fresh join. Set only by the join
    /// path (`settle_rejoin_of_linked_folder`); always false for create and
    /// for invite-accept, whose `commit_plain` folds an already-linked
    /// folder into plain success.
    pub(crate) already_linked: bool,
}

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub(crate) enum EnrollmentError {
    #[error("local device identity is unavailable")]
    LocalIdentityUnavailable,
    #[error(
        "could not persist enrollment recovery journal for operation {operation_id}: {detail}"
    )]
    RecoveryJournalUnavailable { operation_id: String, detail: String },
    #[error("enrollment preparation was rejected: {detail}")]
    PreparationRejected { detail: String },
    /// The invite cannot be redeemed (expired, or already used or cancelled).
    #[error("{detail}")]
    InviteRefused { reason: InviteRefusal, detail: String },
    /// The folder cannot be linked here, refused before anything was
    /// changed remotely.
    #[error("{detail}")]
    LinkRefused { refusal: LinkRefusal, detail: String },
    #[error("enrollment preparation result is ambiguous for operation {operation_id}: {detail}")]
    PreparationAmbiguous { operation_id: String, detail: String },
    #[error("local link commit failed: {detail}")]
    LocalLinkFailed { detail: String, refusal: Option<LinkRefusal> },
    #[error("local link outcome is ambiguous for operation {operation_id}: {detail}")]
    LocalLinkAmbiguous { operation_id: String, detail: String },
    #[error("enrollment activation was rejected: {detail}")]
    ActivationRejected { detail: String },
    #[error("enrollment activation result is ambiguous for operation {operation_id}: {detail}")]
    ActivationAmbiguous { operation_id: String, detail: String },
    #[error("enrollment compensation is pending for operation {operation_id}: {detail}")]
    CompensationPending { operation_id: String, detail: String },
    #[error("enrollment operation {operation_id} conflicts with another request: {detail}")]
    OperationConflict { operation_id: String, detail: String },
    #[error("coordination transport failed: {detail}")]
    CoordinationTransport { detail: String },
    #[error("local persistence failed: {0}")]
    Persistence(#[from] crate::sync_error::SyncError),
}

/// The classified result of a `link()` failure -- distinct from a plain
/// `Result<(), String>` so a caller can tell "definitely never committed"
/// (safe to compensate: mark CancelPending, retry remote cancel) apart from
/// "may still be committed" (the link/marker/Transferred row might be fully
/// live locally; remote cancellation must never be attempted, since that
/// would delete the authorization for a link that still exists).
#[derive(Debug, thiserror::Error)]
pub(crate) enum EnrollmentLinkError {
    #[error("{detail}")]
    NotCommitted { detail: String, refusal: Option<LinkRefusal> },
    #[error("{detail}")]
    CommitUncertain { detail: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnrollmentKind {
    Create,
    Join,
}

impl From<EnrollmentKind> for yadorilink_replica_domain::session_state::EnrollmentKind {
    fn from(kind: EnrollmentKind) -> Self {
        match kind {
            EnrollmentKind::Create => {
                yadorilink_replica_domain::session_state::EnrollmentKind::Create
            }
            EnrollmentKind::Join => yadorilink_replica_domain::session_state::EnrollmentKind::Join,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActivationDisposition {
    Finalize,
    RollBack,
    LeaveForReconciliation,
}

fn activation_disposition(outcome: &EnrollmentActivationResult) -> ActivationDisposition {
    match outcome {
        EnrollmentActivationResult::Activated
        | EnrollmentActivationResult::AlreadyActive
        // Only the CROSS-ACCOUNT invite path can produce this, and that
        // path does not go through `finish_activation` at all -- neither
        // create nor join has an approval step, so this arm is
        // unreachable from the two callers of this function. Finalize
        // anyway rather than roll back: the remote side did commit a
        // state transition, and treating a committed transition as
        // "never happened" is the one answer that could destroy local
        // state. Never `RollBack`, never left dangling.
        | EnrollmentActivationResult::AwaitingApproval => ActivationDisposition::Finalize,
        EnrollmentActivationResult::Deleted => ActivationDisposition::RollBack,
        EnrollmentActivationResult::TransientFailure { .. } => {
            ActivationDisposition::LeaveForReconciliation
        }
    }
}

impl EnrollmentService {
    pub(crate) fn new(
        device_id: String,
        repository: Arc<dyn EnrollmentRepository>,
        coordination: Arc<dyn EnrollmentCoordination>,
        links: Arc<dyn EnrollmentLinkPort>,
    ) -> Self {
        Self {
            provider_creation: tokio::sync::Mutex::new(()),
            provider_kind:
                yadorilink_replica_domain::session_state::ProviderKind::for_host_platform(),
            device_id,
            repository,
            coordination,
            links,
        }
    }

    /// The provider adapter for a provider link, or a refusal on a platform that has none. Checked
    /// before the first journal write or remote call.
    fn require_provider_kind(
        &self,
    ) -> Result<yadorilink_replica_domain::session_state::ProviderKind, EnrollmentError> {
        self.provider_kind.ok_or_else(|| EnrollmentError::PreparationRejected {
            detail: "provider folders are not available on this operating system".to_string(),
        })
    }

    /// Test seam: the adapter kind this service serves, independent of the host OS.
    #[cfg(test)]
    pub(crate) fn with_provider_kind(
        mut self,
        kind: Option<yadorilink_replica_domain::session_state::ProviderKind>,
    ) -> Self {
        self.provider_kind = kind;
        self
    }

    pub(crate) async fn create_and_link(
        &self,
        command: CreateAndLinkCommand,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        if !self.coordination.is_configured() {
            return Err(EnrollmentError::LocalIdentityUnavailable);
        }
        let storage_mode = if command.on_demand { "on-demand" } else { "eager" };
        let mut command = command;
        let _provider_guard = match &command.provider {
            Some(_) => Some(self.provider_creation.lock().await),
            None => None,
        };
        let provider_target = match &command.provider {
            Some(creation) => {
                let digest =
                    creation_digest(creation, &command.group_name, command.on_demand, "create");
                if let Some(existing) = self.provider_retry(creation, &digest)? {
                    return Ok(existing);
                }
                command.absolute_path = PathBuf::from(creation.locator());
                Some(crate::application::ports::ProviderLinkTarget {
                    kind: self.require_provider_kind()?,
                    display_name: creation.display_name.clone(),
                    empty_owner: true,
                    on_demand: command.on_demand,
                    creation_digest: digest,
                })
            }
            None => None,
        };
        let fixed_id = match (&command.provider, &provider_target) {
            (Some(c), Some(target)) => {
                let id = provider_operation_id(
                    &c.request_token,
                    &target.creation_digest,
                    &self.device_id,
                );
                self.refuse_foreign_provider_operation(&c.locator(), &id)?;
                Some(id)
            }
            _ => None,
        };

        // 1. Journal ALWAYS opens before the first remote prepare call --
        // if this write itself fails, nothing is ever sent to the
        // coordination plane (fail closed).
        let (operation_id, resumed_prepared) = self.open_enrollment_operation(
            yadorilink_replica_domain::session_state::EnrollmentKind::Create,
            None,
            Some(command.group_name.clone()),
            &command.absolute_path,
            storage_mode,
            fixed_id,
        )?;

        // 2. Prepare, under the SAME operation_id.
        let group_id = match self
            .coordination
            .prepare_create(&operation_id, &command.group_name, &self.device_id, storage_mode)
            .await
        {
            EnrollmentPrepareResult::Prepared { group_id } => group_id,
            EnrollmentPrepareResult::DefinitelyRejected { detail }
            | EnrollmentPrepareResult::InviteRefused { detail, .. } => {
                self.repository.delete_operation(&operation_id)?;
                return Err(EnrollmentError::PreparationRejected { detail });
            }
            EnrollmentPrepareResult::Conflict { detail } => {
                self.mark_recovery_blocked(&operation_id, &detail);
                return Err(EnrollmentError::OperationConflict { operation_id, detail });
            }
            EnrollmentPrepareResult::Ambiguous { detail } => {
                // The row stays `PreparePending`; the next reconciliation
                // sweep resends the exact same prepare request under this
                // same operation_id.
                return Err(EnrollmentError::PreparationAmbiguous { operation_id, detail });
            }
        };

        // 3. Prepare confirmed remotely -- record it locally. A failure
        // here leaves the row `PreparePending`; the next sweep resends the
        // same prepare (idempotent by operation_id) and recovers the same
        // group_id.
        if !resumed_prepared
            && !self.repository.mark_prepared(&operation_id, &group_id, now_unix())?
        {
            return Err(EnrollmentError::PreparationAmbiguous {
                operation_id,
                detail: "remote prepare succeeded but local Prepared transition could not be \
                         confirmed"
                    .to_string(),
            });
        }

        let local_path = command.absolute_path.clone();
        let link_request = EnrollmentLinkRequest {
            operation_id: operation_id.clone(),
            kind: EnrollmentKind::Create,
            device_id: self.device_id.clone(),
            group_id: group_id.clone(),
            absolute_path: command.absolute_path,
            on_demand: command.on_demand,
            provider: provider_target,
        };

        // 4. `link()` commits the local link + pending_enrollments marker +
        // this journal row's Transferred transition atomically. Its own
        // best-effort rollback on a post-commit setup failure is itself
        // fallible, so a plain `Err` here does not by itself mean nothing
        // was committed -- the port classifies the failure by reading back
        // the journal row's actual state.
        match self.links.commit(link_request).await {
            Ok(LinkOutcome::Linked) => {}
            // A group this call just prepared cannot already be linked here;
            // if it somehow is, nothing was committed for this operation, so
            // it is cancelled like any other link that never happened.
            Ok(LinkOutcome::AlreadyLinked) => {
                return self
                    .compensate_failed_create_link(
                        &operation_id,
                        &group_id,
                        "the newly created folder group is unexpectedly already linked here"
                            .to_string(),
                        None,
                    )
                    .await;
            }
            Err(EnrollmentLinkError::NotCommitted { detail, refusal }) => {
                return self
                    .compensate_failed_create_link(&operation_id, &group_id, detail, refusal)
                    .await;
            }
            Err(EnrollmentLinkError::CommitUncertain { detail }) => {
                return Err(EnrollmentError::LocalLinkAmbiguous {
                    operation_id,
                    detail: format!(
                        "{detail}; the local link or its activation marker may still be \
                         committed, so remote cancellation was not attempted"
                    ),
                });
            }
        }

        self.finish_activation(
            EnrollmentKind::Create,
            &group_id,
            &operation_id,
            &self.device_id.clone(),
            local_path,
        )
        .await
    }

    pub(crate) async fn join_and_link(
        &self,
        command: JoinAndLinkCommand,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        // Measurement only: the join-to-first-file timeline covers eager,
        // non-provider joins (the ones that end in a committed file) and is
        // dropped again as soon as the attempt turns out not to sync.
        let group_id = command.group_id.clone();
        let tracked = !command.on_demand && command.provider.is_none();
        let attempt = tracked
            .then(|| yadorilink_fs_platform::join_timeline::begin(&self.device_id, &group_id));
        let result = self.join_and_link_inner(command).await;
        if let Some(attempt) = attempt {
            if !matches!(&result, Ok(o) if !o.awaiting_approval && !o.already_linked) {
                yadorilink_fs_platform::join_timeline::abandon(&self.device_id, &group_id, attempt);
            }
        }
        result
    }

    async fn join_and_link_inner(
        &self,
        command: JoinAndLinkCommand,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        if !self.coordination.is_configured() {
            return Err(EnrollmentError::LocalIdentityUnavailable);
        }
        tracing::debug!(group_name = %command.group_name, group_id = %command.group_id, "starting join-and-link enrollment");
        let storage_mode = if command.on_demand { "on-demand" } else { "eager" };
        let mut command = command;
        let _provider_guard = match &command.provider {
            Some(_) => Some(self.provider_creation.lock().await),
            None => None,
        };
        let provider_target = match &command.provider {
            Some(creation) => {
                let digest =
                    creation_digest(creation, &command.group_id, command.on_demand, "join");
                if let Some(existing) = self.provider_retry(creation, &digest)? {
                    return Ok(existing);
                }
                command.absolute_path = PathBuf::from(creation.locator());
                Some(crate::application::ports::ProviderLinkTarget {
                    kind: self.require_provider_kind()?,
                    display_name: creation.display_name.clone(),
                    empty_owner: false,
                    on_demand: command.on_demand,
                    creation_digest: digest,
                })
            }
            None => None,
        };
        let fixed_id = match (&command.provider, &provider_target) {
            (Some(c), Some(target)) => {
                let id = provider_operation_id(
                    &c.request_token,
                    &target.creation_digest,
                    &self.device_id,
                );
                self.refuse_foreign_provider_operation(&c.locator(), &id)?;
                Some(id)
            }
            _ => None,
        };

        let (operation_id, resumed_prepared) = self.open_enrollment_operation(
            yadorilink_replica_domain::session_state::EnrollmentKind::Join,
            Some(command.group_id.clone()),
            None,
            &command.absolute_path,
            storage_mode,
            fixed_id,
        )?;

        match self
            .coordination
            .prepare_join(&operation_id, &command.group_id, &self.device_id, storage_mode)
            .await
        {
            EnrollmentPrepareResult::Prepared { .. } => {}
            EnrollmentPrepareResult::DefinitelyRejected { detail }
            | EnrollmentPrepareResult::InviteRefused { detail, .. } => {
                self.repository.delete_operation(&operation_id)?;
                return Err(EnrollmentError::PreparationRejected { detail });
            }
            EnrollmentPrepareResult::Conflict { detail } => {
                self.mark_recovery_blocked(&operation_id, &detail);
                return Err(EnrollmentError::OperationConflict { operation_id, detail });
            }
            EnrollmentPrepareResult::Ambiguous { detail } => {
                return Err(EnrollmentError::PreparationAmbiguous { operation_id, detail });
            }
        };

        if !resumed_prepared
            && !self.repository.mark_prepared(&operation_id, &command.group_id, now_unix())?
        {
            return Err(EnrollmentError::PreparationAmbiguous {
                operation_id,
                detail: "remote prepare succeeded but local Prepared transition could not be \
                         confirmed"
                    .to_string(),
            });
        }

        let local_path = command.absolute_path.clone();
        let link_request = EnrollmentLinkRequest {
            operation_id: operation_id.clone(),
            kind: EnrollmentKind::Join,
            device_id: self.device_id.clone(),
            group_id: command.group_id.clone(),
            absolute_path: command.absolute_path,
            on_demand: command.on_demand,
            provider: provider_target,
        };
        match self.links.commit(link_request).await {
            Ok(LinkOutcome::Linked) => {}
            Ok(LinkOutcome::AlreadyLinked) => {
                return self
                    .settle_rejoin_of_linked_folder(&operation_id, &command.group_id, local_path)
                    .await;
            }
            Err(EnrollmentLinkError::NotCommitted { detail, refusal }) => {
                return self
                    .compensate_failed_join_link(&operation_id, &command.group_id, detail, refusal)
                    .await;
            }
            Err(EnrollmentLinkError::CommitUncertain { detail }) => {
                return Err(EnrollmentError::LocalLinkAmbiguous {
                    operation_id,
                    detail: format!(
                        "{detail}; the local link or its activation marker may still be \
                         committed, so remote cancellation was not attempted"
                    ),
                });
            }
        }

        self.finish_activation(
            EnrollmentKind::Join,
            &command.group_id,
            &operation_id,
            &self.device_id.clone(),
            local_path,
        )
        .await
    }

    /// Cross-account invite acceptance: redeems an invite credential and
    /// links it locally in one crash-safe enrollment, mirroring
    /// `join_and_link`'s Pending -> Active shape at the coordination-plane
    /// level.
    ///
    /// Deliberately does NOT use `open_enrollment_operation`/the durable
    /// `enrollment_operations` journal `create_and_link`/`join_and_link`
    /// use for cross-*daemon-restart* crash recovery -- doing so would mean
    /// giving `EnrollmentKind` (and every exhaustive match over it in the
    /// recovery/diagnosis subsystem) a third variant, a change with a much
    /// larger blast radius than this feature needs yet. Instead:
    ///
    /// - `operation_id` is DERIVED deterministically from `(code,
    ///   device_id)` (a SHA-256 hex digest), not a random UUID. Re-running
    ///   this exact command (same invite code, same device) after a crash
    ///   or a transient/ambiguous error therefore always presents the SAME
    ///   operation_id, which is what makes it a safe retry rather than a
    ///   rejected "invite already used": the coordination plane's own
    ///   accept/prepare recognizes a repeated (device, operation_id) pair
    ///   as this device's own earlier redemption (see that route's own
    ///   doc comment), and `commit_plain`'s underlying `LinkLifecycleService`
    ///   allows re-linking the identical (group_id, path) pair as an
    ///   idempotent no-op.
    /// - The local link commits via `commit_plain` (the plain `yadorilink
    ///   link` shape, no `pending_enrollment` marker) rather than `commit`.
    ///   There is therefore no local crash-recovery marker for a daemon
    ///   restart to reconcile: if this process dies between a successful
    ///   local link and the matching activate call, the coordination-plane
    ///   edge is left Pending, and this device's own next restart does
    ///   NOT automatically retry it -- either the user re-runs `share
    ///   accept <code>` (safe, per the retry story above), or the
    ///   coordination plane's own pending-enrollment TTL sweep eventually
    ///   deletes the abandoned Pending row, leaving a local link that no
    ///   longer syncs rather than a silently-orphaned coordination-plane
    ///   authorization. This is a real, bounded gap relative to
    ///   create/join's full cross-restart recovery, accepted for now
    ///   rather than silently pretended away.
    /// - `commit_plain`'s failure still gets classified (`NotCommitted` vs
    ///   `CommitUncertain`), same two-variant shape `commit` uses for
    ///   create/join -- a local link that may still be live must never be
    ///   silently cancelled on the coordination plane just because this
    ///   call is reporting failure. There is no `enrollment_operations`
    ///   journal row to classify against here, so the classification reads
    ///   current local link state back directly instead (see
    ///   `commit_plain`'s own doc comment).
    pub(crate) async fn accept_invite_and_link(
        &self,
        command: AcceptInviteCommand,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        // Measurement only: see `join_and_link`. The group id is known once
        // the invite is prepared, so the inner call reports it back.
        let tracked = !command.on_demand && command.provider.is_none();
        let mut begun = None;
        let result = self.accept_invite_and_link_inner(command, tracked, &mut begun).await;
        if let Some((group_id, attempt)) = begun {
            if !matches!(&result, Ok(o) if !o.awaiting_approval) {
                yadorilink_fs_platform::join_timeline::abandon(&self.device_id, &group_id, attempt);
            }
        }
        result
    }

    async fn accept_invite_and_link_inner(
        &self,
        command: AcceptInviteCommand,
        tracked: bool,
        begun: &mut Option<(String, u64)>,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        if !self.coordination.is_configured() {
            return Err(EnrollmentError::LocalIdentityUnavailable);
        }
        let storage_mode = if command.on_demand { "on-demand" } else { "eager" };
        let operation_id = invite_accept_operation_id(&command.code, &self.device_id);
        let mut command = command;
        // One provider creation at a time, like create and join: the display-name check below and
        // the link commit must not interleave with another creation.
        let _provider_guard = match &command.provider {
            Some(_) => Some(self.provider_creation.lock().await),
            None => None,
        };
        let provider_kind = match &command.provider {
            Some(_) => Some(self.require_provider_kind()?),
            None => None,
        };
        if let Some(creation) = &command.provider {
            // Everything that can be known without the redemption is checked before the one-use
            // invite is redeemed: a redeemed invite is not given back.
            // The name must be one a provider root can have (the rule of the root declaration).
            if creation.display_name.trim().is_empty() {
                return Err(EnrollmentError::PreparationRejected {
                    detail: "a provider folder needs a name".to_string(),
                });
            }
            let locator = creation.locator();
            let links = self.repository.list_links()?;
            // The token's earlier link binds it to its request: this very request (the group
            // that link is of) must match what was recorded, or the token is another request's.
            let earlier = links.iter().find(|l| l.key() == locator);
            if let Some(link) = earlier {
                let digest = creation_digest(creation, &link.group_id, command.on_demand, "invite");
                if self.repository.creation_digest(&locator)?.as_deref() != Some(&digest) {
                    return Err(EnrollmentError::PreparationRejected {
                        detail: "this request token was already used for a different request"
                            .to_string(),
                    });
                }
            }
            // A retry of this very request finds its own earlier link, whose name is not a clash.
            if earlier.is_none()
                && self.repository.provider_display_name_taken(&creation.display_name)?
            {
                return Err(EnrollmentError::PreparationRejected {
                    detail: format!(
                        "a provider folder named '{}' already exists on this device",
                        creation.display_name
                    ),
                });
            }
            command.absolute_path = PathBuf::from(creation.locator());
        }

        let group_id = match self
            .coordination
            .prepare_invite_accept(&operation_id, &command.code, &self.device_id, storage_mode)
            .await
        {
            EnrollmentPrepareResult::Prepared { group_id } => group_id,
            EnrollmentPrepareResult::DefinitelyRejected { detail } => {
                return Err(EnrollmentError::PreparationRejected { detail });
            }
            EnrollmentPrepareResult::InviteRefused { reason, detail } => {
                return Err(EnrollmentError::InviteRefused { reason, detail });
            }
            EnrollmentPrepareResult::Conflict { detail } => {
                return Err(EnrollmentError::OperationConflict { operation_id, detail });
            }
            EnrollmentPrepareResult::Ambiguous { detail } => {
                return Err(EnrollmentError::PreparationAmbiguous { operation_id, detail });
            }
        };
        if tracked {
            let attempt = yadorilink_fs_platform::join_timeline::begin(&self.device_id, &group_id);
            *begun = Some((group_id.clone(), attempt));
        }

        let local_path = command.absolute_path.clone();
        // What can only be known with the group the invite named. A refusal here leaves the
        // acceptance redeemed and pending remotely with nothing committed locally, so it is
        // cancelled, exactly like a link that failed to commit. Cancelling is safe: another
        // group than the token's earlier link means another invite code, hence another operation.
        let provider_target = match self.provider_target(&command, provider_kind, &group_id) {
            Ok(target) => target,
            Err(error) => {
                let _ = self
                    .coordination
                    .cancel_invite_accept(&group_id, &operation_id, &self.device_id)
                    .await;
                return Err(error);
            }
        };
        match self
            .links
            .commit_plain(&group_id, &command.absolute_path, command.on_demand, provider_target)
            .await
        {
            Ok(()) => {}
            Err(EnrollmentLinkError::NotCommitted { detail, refusal }) => {
                // Confirmed nothing was committed locally -- safe to
                // compensate. Best-effort: if the cancel call also fails,
                // the coordination plane's own pending-enrollment TTL sweep
                // is the eventual backstop, same as every other best-effort
                // cancel call in this file.
                let _ = self
                    .coordination
                    .cancel_invite_accept(&group_id, &operation_id, &self.device_id)
                    .await;
                return Err(EnrollmentError::LocalLinkFailed { detail, refusal });
            }
            Err(EnrollmentLinkError::CommitUncertain { detail }) => {
                // The local link may still be live even though this call
                // is reporting failure -- cancelling here would delete the
                // coordination-plane authorization for a group this device
                // may actually be actively linked to (see `commit_plain`'s
                // own doc comment, and `classify_link_failure`'s identical
                // reasoning for the same-account `commit` path this
                // mirrors). Leave the Pending edge in place instead: a
                // retry of this exact command is always safe (same
                // deterministic operation id), and re-commits idempotently
                // once local state is confirmed one way or the other.
                return Err(EnrollmentError::LocalLinkAmbiguous {
                    operation_id,
                    detail: format!(
                        "{detail}; the local link may still be committed, so remote \
                         cancellation was not attempted"
                    ),
                });
            }
        }

        match self
            .coordination
            .activate_invite_accept(&group_id, &operation_id, &self.device_id)
            .await
        {
            EnrollmentActivationResult::Activated | EnrollmentActivationResult::AlreadyActive => {
                Ok(EnrollmentOutcome {
                    operation_id,
                    group_id,
                    local_path,
                    awaiting_approval: false,
                    already_linked: false,
                })
            }
            // The invite required the group owner's approval, so this
            // device's own half is complete and correct but the membership
            // is not live yet. Reported as a success, not an error: nothing
            // failed and there is nothing here to retry -- the local link
            // committed above stays, and the coordination plane's edge
            // stays, both waiting on a human. The local runtime this
            // enrollment started is running but idle; with no policy-log
            // grant it withholds every local change rather than syncing or
            // losing one, and it starts working the moment the owner
            // approves, with no further action here. The FLAG is what
            // keeps this from being reported as a completed join.
            EnrollmentActivationResult::AwaitingApproval => Ok(EnrollmentOutcome {
                operation_id,
                group_id,
                local_path,
                awaiting_approval: true,
                already_linked: false,
            }),
            EnrollmentActivationResult::Deleted => {
                // Confirmed terminal: the Pending row this operation_id
                // named is permanently gone (most likely the TTL sweep won
                // a race against a very slow local link commit). Unlike
                // `finish_activation`'s marker-based rollback, the local
                // link just committed above has no marker to remove -- it
                // is left in place, orphaned from this now-gone
                // authorization, for the user to `yadorilink unlink` if
                // they don't retry with a fresh invite.
                Err(EnrollmentError::ActivationRejected {
                    detail: format!(
                        "invite-accept authorization for operation {operation_id} is gone \
                         (expired or already superseded); the local folder was linked but is \
                         not authorized -- unlink it, or request a new invite and retry"
                    ),
                })
            }
            EnrollmentActivationResult::TransientFailure { detail } => {
                Err(EnrollmentError::ActivationAmbiguous { operation_id, detail })
            }
        }
    }

    /// The provider target of an invite accepted as a provider folder, `None` for a plain folder.
    /// The request is bound to its token and the group the invite named: the same token with
    /// another request is refused, never silently linked as the earlier one.
    fn provider_target(
        &self,
        command: &AcceptInviteCommand,
        kind: Option<yadorilink_replica_domain::session_state::ProviderKind>,
        group_id: &str,
    ) -> Result<Option<crate::application::ports::ProviderLinkTarget>, EnrollmentError> {
        let (Some(creation), Some(kind)) = (&command.provider, kind) else {
            return Ok(None);
        };
        let digest = creation_digest(creation, group_id, command.on_demand, "invite");
        let locator = creation.locator();
        if self.repository.list_links()?.iter().any(|l| l.key() == locator)
            && self.repository.creation_digest(&locator)?.as_deref() != Some(&digest)
        {
            return Err(EnrollmentError::PreparationRejected {
                detail: "this request token was already used for a different request".to_string(),
            });
        }
        Ok(Some(crate::application::ports::ProviderLinkTarget {
            kind,
            display_name: creation.display_name.clone(),
            empty_owner: false,
            on_demand: command.on_demand,
            creation_digest: digest,
        }))
    }

    /// Mints a one-use, expiring cross-account invite for `group_id`,
    /// naming this device as the minting device -- the CLI never needs to
    /// know or supply its own device id (unlike `grant`, which names some
    /// OTHER device explicitly). No local state, no journal row: a single
    /// stateless coordination-plane call.
    pub(crate) async fn mint_invite(
        &self,
        group_id: &str,
        role: Option<&str>,
        ttl_secs: Option<u64>,
        requires_approval: bool,
    ) -> Result<MintedInvite, String> {
        if !self.coordination.is_configured() {
            return Err(
                "coordination-plane address/access token not configured on this device".to_string()
            );
        }
        self.coordination.mint_invite(group_id, role, ttl_secs, requires_approval).await
    }

    /// Opens a fresh `enrollment_operations` journal row, retrying under a
    /// NEW `operation_id` on a (should be astronomically rare) UUID
    /// collision -- mirrors `replica_membership_service.rs`'s
    /// `open_membership_operation`. Fails closed (no coordination call
    /// ever attempted) if the durable write itself keeps failing.
    /// A retry of an already-completed provider creation: the same token and request answer with
    /// the existing link; the same token with a different request is refused.
    fn provider_retry(
        &self,
        creation: &ProviderCreation,
        digest: &str,
    ) -> Result<Option<EnrollmentOutcome>, EnrollmentError> {
        let locator = creation.locator();
        let Some(link) = self.repository.list_links()?.into_iter().find(|l| l.key() == locator)
        else {
            return Ok(None);
        };
        if self.repository.creation_digest(&locator)?.as_deref() != Some(digest) {
            return Err(EnrollmentError::PreparationRejected {
                detail: "this request token was already used for a different request".to_string(),
            });
        }
        Ok(Some(EnrollmentOutcome {
            operation_id: provider_operation_id(&creation.request_token, digest, &self.device_id),
            group_id: link.group_id,
            local_path: PathBuf::from(locator),
            awaiting_approval: false,
            already_linked: true,
        }))
    }

    /// The operation id binds the token to its request (display name, group, policy), so a resume
    /// reaches only a row of the SAME request. A journal row already open on this token's link key
    /// under a different id is a different request on a used token: refused, never resumed.
    fn refuse_foreign_provider_operation(
        &self,
        locator: &str,
        expected_id: &str,
    ) -> Result<(), EnrollmentError> {
        let open = self.repository.scan_open_operations()?;
        if open.valid.iter().any(|op| op.local_path == locator && op.operation_id != expected_id) {
            return Err(EnrollmentError::PreparationRejected {
                detail: "this request token is already in use by a different, unfinished request"
                    .to_string(),
            });
        }
        Ok(())
    }

    fn open_enrollment_operation(
        &self,
        kind: yadorilink_replica_domain::session_state::EnrollmentKind,
        group_id: Option<String>,
        group_name: Option<String>,
        local_path: &std::path::Path,
        storage_mode: &str,
        fixed_id: Option<String>,
    ) -> Result<(String, bool), EnrollmentError> {
        const MAX_ID_ATTEMPTS: usize = 4;
        let mut last_operation_id = String::new();
        // A request without a token-derived id is still the same request when its journal row is
        // still in its prepare phase for the same kind, group, device, path and mode. A fresh id would collide with
        // the coordination plane's pending edge of the earlier (ambiguous) attempt -- "already has a
        // pending join operation" -- and never finish, so the earlier row's id is reused.
        let fixed_id = match fixed_id {
            Some(id) => Some(id),
            None => self
                .repository
                .scan_open_operations()?
                .valid
                .into_iter()
                .filter(|op| {
                    matches!(
                        op.state,
                        EnrollmentOperationState::PreparePending
                            | EnrollmentOperationState::Prepared
                    ) && op.kind == kind
                        && op.group_id == group_id
                        && op.group_name == group_name
                        && op.device_id == self.device_id
                        && op.local_path == local_path.to_string_lossy()
                        && op.storage_mode == storage_mode
                })
                .min_by(|x, y| {
                    (x.created_at_unix, &x.operation_id).cmp(&(y.created_at_unix, &y.operation_id))
                })
                .map(|op| op.operation_id),
        };
        for _ in 0..MAX_ID_ATTEMPTS {
            let operation_id = fixed_id.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
            last_operation_id.clone_from(&operation_id);
            let now = now_unix();
            let operation = EnrollmentOperation {
                operation_id: operation_id.clone(),
                kind,
                group_id: group_id.clone(),
                group_name: group_name.clone(),
                device_id: self.device_id.clone(),
                local_path: local_path.to_string_lossy().to_string(),
                storage_mode: storage_mode.to_string(),
                state: EnrollmentOperationState::PreparePending,
                last_error: None,
                attempts: 0,
                created_at_unix: now,
                updated_at_unix: now,
            };
            match self.repository.try_insert_operation(&operation) {
                Ok(true) => return Ok((operation_id, false)),
                // A request-derived id names a row: a retry of the same request. Resume it only
                // while its prepare is still in flight; anything further along is the recovery
                // sweep's to settle.
                Ok(false) if fixed_id.is_some() => {
                    return match self.repository.operation(&operation_id)? {
                        Some(row) if row.state == EnrollmentOperationState::PreparePending => {
                            Ok((operation_id, false))
                        }
                        Some(row) if row.state == EnrollmentOperationState::Prepared => {
                            Ok((operation_id, true))
                        }
                        _ => Err(EnrollmentError::PreparationAmbiguous {
                            operation_id,
                            detail: "an earlier attempt with this request token is still being \
                                     recovered; retry shortly"
                                .to_string(),
                        }),
                    };
                }
                // A fresh UUID already names a row -- retry under another
                // one; the existing row is untouched.
                Ok(false) => continue,
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        operation_id,
                        "refusing the enrollment: could not persist the durable recovery journal, so \
                         coordination prepare must not be attempted"
                    );
                    return Err(EnrollmentError::RecoveryJournalUnavailable {
                        operation_id,
                        detail: error.to_string(),
                    });
                }
            }
        }
        Err(EnrollmentError::RecoveryJournalUnavailable {
            operation_id: last_operation_id,
            detail: "could not allocate a unique enrollment operation id after repeated \
                      collisions"
                .to_string(),
        })
    }

    fn mark_recovery_blocked(&self, operation_id: &str, detail: &str) {
        if let Err(error) = self.repository.mark_state(
            operation_id,
            EnrollmentOperationState::RecoveryBlocked,
            Some(detail),
            now_unix(),
        ) {
            tracing::warn!(
                %error,
                operation_id,
                "failed to advance an enrollment operation journal row to RecoveryBlocked"
            );
        }
    }

    fn mark_cancel_pending(&self, operation_id: &str, detail: &str) {
        if let Err(error) = self.repository.mark_state(
            operation_id,
            EnrollmentOperationState::CancelPending,
            Some(detail),
            now_unix(),
        ) {
            tracing::warn!(
                %error,
                operation_id,
                "failed to advance an enrollment operation journal row to CancelPending"
            );
        }
    }

    async fn compensate_failed_create_link(
        &self,
        operation_id: &str,
        group_id: &str,
        link_error: String,
        refusal: Option<LinkRefusal>,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        self.mark_cancel_pending(operation_id, &link_error);
        for _ in 0..3 {
            match self.coordination.cancel_create(group_id, operation_id).await {
                EnrollmentCancellationResult::Confirmed => {
                    self.repository.delete_operation(operation_id)?;
                    return Err(EnrollmentError::LocalLinkFailed { detail: link_error, refusal });
                }
                EnrollmentCancellationResult::Conflict { detail } => {
                    self.mark_recovery_blocked(operation_id, &detail);
                    return Err(EnrollmentError::OperationConflict {
                        operation_id: operation_id.to_string(),
                        detail,
                    });
                }
                EnrollmentCancellationResult::Ambiguous { detail } => {
                    self.mark_cancel_pending(operation_id, &detail);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
        Err(EnrollmentError::CompensationPending {
            operation_id: operation_id.to_string(),
            detail: format!(
                "local link failed ({link_error}); cancellation remains durably journaled"
            ),
        })
    }

    async fn compensate_failed_join_link(
        &self,
        operation_id: &str,
        group_id: &str,
        link_error: String,
        refusal: Option<LinkRefusal>,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        self.mark_cancel_pending(operation_id, &link_error);
        for _ in 0..3 {
            match self.coordination.cancel_join(group_id, operation_id, &self.device_id).await {
                EnrollmentCancellationResult::Confirmed => {
                    self.repository.delete_operation(operation_id)?;
                    return Err(EnrollmentError::LocalLinkFailed { detail: link_error, refusal });
                }
                EnrollmentCancellationResult::Conflict { detail } => {
                    self.mark_recovery_blocked(operation_id, &detail);
                    return Err(EnrollmentError::OperationConflict {
                        operation_id: operation_id.to_string(),
                        detail,
                    });
                }
                EnrollmentCancellationResult::Ambiguous { detail } => {
                    self.mark_cancel_pending(operation_id, &detail);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
        Err(EnrollmentError::CompensationPending {
            operation_id: operation_id.to_string(),
            detail: format!(
                "local link failed ({link_error}); cancellation remains durably journaled"
            ),
        })
    }

    /// A join for a folder that is already linked to the group and running:
    /// nothing was committed locally, so this operation's journal row is
    /// still `Prepared` and there is no pending marker. Activating settles
    /// the coordination side -- the plane resolves a join by (group,
    /// device), so an already-Active membership answers `AlreadyActive`,
    /// and a membership this prepare just created (a folder linked without
    /// ever joining) becomes Active. Then only the journal row is closed.
    ///
    /// Never goes through [`Self::finish_activation`]: its `Deleted` branch
    /// orphans the local link, which here is the earlier, still-running
    /// link this command never created.
    async fn settle_rejoin_of_linked_folder(
        &self,
        operation_id: &str,
        group_id: &str,
        local_path: PathBuf,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        let activation =
            self.coordination.activate_join(group_id, operation_id, &self.device_id).await;
        match activation {
            // `AwaitingApproval` is here only so the match is exhaustive:
            // the join route answers `activated`, `already_active` or
            // `not_found`, never an approval state (only invite-accept
            // has an approval step), so `awaiting_approval: false` below
            // is accurate for every result this arm can see.
            EnrollmentActivationResult::Activated
            | EnrollmentActivationResult::AlreadyActive
            | EnrollmentActivationResult::AwaitingApproval => {
                self.repository.delete_operation(operation_id)?;
                Ok(EnrollmentOutcome {
                    operation_id: operation_id.to_string(),
                    group_id: group_id.to_string(),
                    local_path,
                    awaiting_approval: false,
                    already_linked: true,
                })
            }
            EnrollmentActivationResult::Deleted => {
                self.repository.delete_operation(operation_id)?;
                Err(EnrollmentError::ActivationRejected {
                    detail: format!(
                        "the folder is already linked to group {group_id}, but the coordination \
                         plane has no membership to activate for operation {operation_id}; the \
                         existing local link was left as it is"
                    ),
                })
            }
            EnrollmentActivationResult::TransientFailure { detail } => {
                // Cancel rather than leave it `Prepared` for recovery to
                // activate later: the caller is told this join did not
                // complete, so it must not quietly complete afterwards.
                // Cancelling this operation only ever removes a Pending
                // membership it created, never an Active one.
                self.mark_cancel_pending(operation_id, &detail);
                Err(EnrollmentError::ActivationAmbiguous {
                    operation_id: operation_id.to_string(),
                    detail: format!(
                        "the folder is already linked to group {group_id} and was left as it \
                         is; confirming its membership failed ({detail})"
                    ),
                })
            }
        }
    }

    async fn finish_activation(
        &self,
        kind: EnrollmentKind,
        group_id: &str,
        operation_id: &str,
        device_id: &str,
        local_path: PathBuf,
    ) -> Result<EnrollmentOutcome, EnrollmentError> {
        let activation = match kind {
            EnrollmentKind::Create => {
                self.coordination.activate_create(group_id, operation_id).await
            }
            EnrollmentKind::Join => {
                self.coordination.activate_join(group_id, operation_id, device_id).await
            }
        };
        match activation_disposition(&activation) {
            ActivationDisposition::Finalize => {
                self.repository.settle_activated(operation_id)?;
                Ok(EnrollmentOutcome {
                    operation_id: operation_id.to_string(),
                    group_id: group_id.to_string(),
                    local_path,
                    // Create and join have no approval step at all.
                    awaiting_approval: false,
                    already_linked: false,
                })
            }
            ActivationDisposition::RollBack => {
                // `Deleted` is a CONFIRMED terminal answer -- see
                // `EnrollmentLinkPort::rollback`'s own doc comment for the
                // full rollback sequence and why it must not go through
                // `ReplicaRoleService::unlink`'s full-replica-handoff gate.
                let local_path_str = local_path.to_string_lossy().to_string();
                if let Err(e) = self.links.rollback(&local_path_str, operation_id).await {
                    // Leave the link and marker in place; the next
                    // reconciliation sweep retries the same orphan-and-
                    // remove compensation (it will see `Deleted` again and
                    // take this same path).
                    return Err(EnrollmentError::CompensationPending {
                        operation_id: operation_id.to_string(),
                        detail: format!(
                            "activation was rejected but the local rollback failed: {e}"
                        ),
                    });
                }
                Err(EnrollmentError::ActivationRejected {
                    detail: format!("operation {operation_id} no longer exists"),
                })
            }
            ActivationDisposition::LeaveForReconciliation => {
                Err(EnrollmentError::ActivationAmbiguous {
                    operation_id: operation_id.to_string(),
                    detail: "the local link and pending marker were kept for daemon \
                             reconciliation"
                        .to_string(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests;
