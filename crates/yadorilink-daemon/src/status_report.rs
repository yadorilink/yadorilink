//! The status the engine reports, assembled once for every front end: the control socket's
//! `Status` reply and the embedded host's status command both come from here, so the rollup
//! (`overall_status`) and every per-link field can never differ between them.
//!
//! Nothing here reads the process environment: the state directory the replacement records
//! live in is passed in by the caller.

use yadorilink_ipc_proto::daemonctl::{
    ActiveTransferProgress, DegradedCause, FetchAvailability, GroupDurabilityStatus, HeldFile,
    LinkStatus, LocalStorageState, PeerStatus, RecentSyncError, StatusResponse, VolumeFreeSpace,
};

/// Maps the daemon's internal reachability into the control-socket wire
/// enums (`PeerStatus.reachability` / `unreachable_category`). The category
/// is `Unspecified` whenever the peer is not unreachable.
///
/// The third element is this connection's `RouteKind` (only meaningful,
/// i.e. non-`Unspecified`, when the reachability itself is `Connected`).
pub(crate) fn reachability_to_proto(
    reachability: crate::peer_registry::PeerReachability,
) -> (
    yadorilink_ipc_proto::daemonctl::PeerReachability,
    yadorilink_ipc_proto::daemonctl::UnreachableCategory,
    yadorilink_ipc_proto::daemonctl::RouteKind,
) {
    use crate::peer_registry::{PeerReachability as Daemon, UnreachableCategory as DaemonCat};
    use yadorilink_ipc_proto::daemonctl::{
        PeerReachability as Wire, RouteKind as WireRoute, UnreachableCategory as WireCat,
    };
    match reachability {
        Daemon::Connecting => (Wire::Connecting, WireCat::Unspecified, WireRoute::Unspecified),
        Daemon::Connected(route) => {
            let wire_route = match route {
                crate::route::RouteKind::Direct => WireRoute::Direct,
                crate::route::RouteKind::Relay => WireRoute::Relay,
            };
            (Wire::Connected, WireCat::Unspecified, wire_route)
        }
        Daemon::Unreachable(category) => {
            let wire_category = match category {
                DaemonCat::NoCandidates => WireCat::NoCandidates,
                DaemonCat::NoResponse => WireCat::NoResponse,
                DaemonCat::UdpBlocked => WireCat::UdpBlocked,
                DaemonCat::HandshakeRefused => WireCat::HandshakeRefused,
                DaemonCat::DeviceReplaced => WireCat::DeviceReplaced,
            };
            (Wire::Unreachable, wire_category, WireRoute::Unspecified)
        }
    }
}

/// Maps the daemon's internal per-group durability status into the
/// control-socket wire enum (`LinkStatus.durability_status`).
pub(crate) fn durability_status_to_proto(
    status: crate::durability_service::GroupDurabilityStatus,
) -> GroupDurabilityStatus {
    use crate::durability_service::GroupDurabilityStatus as Daemon;
    match status {
        Daemon::Protected => GroupDurabilityStatus::Protected,
        Daemon::Protecting => GroupDurabilityStatus::Protecting,
        Daemon::Unknown => GroupDurabilityStatus::Unknown,
        Daemon::AtRisk => GroupDurabilityStatus::AtRisk,
    }
}

/// Projects the evidence axis onto the wire enum. See
/// `DurabilityEvidence`'s own doc comment for why it is an axis rather than
/// more values of the status it accompanies.
pub(crate) fn durability_evidence_to_proto(
    evidence: crate::durability_service::DurabilityEvidence,
) -> yadorilink_ipc_proto::daemonctl::DurabilityEvidence {
    use crate::durability_service::DurabilityEvidence as Domain;
    use yadorilink_ipc_proto::daemonctl::DurabilityEvidence as Wire;
    match evidence {
        Domain::None => Wire::None,
        Domain::CorroboratedIndex => Wire::CorroboratedIndex,
        Domain::VerifiedPayload => Wire::VerifiedPayload,
    }
}

pub(crate) fn local_storage_state_to_proto(
    state: crate::queries::link_status::LocalStorageState,
) -> LocalStorageState {
    use crate::queries::link_status::LocalStorageState as Domain;
    match state {
        Domain::FullCopy => LocalStorageState::FullCopy,
        Domain::PartiallyMaterialized => LocalStorageState::PartiallyMaterialized,
        Domain::OnDemand => LocalStorageState::OnDemand,
    }
}

pub(crate) fn fetch_availability_to_proto(
    availability: crate::queries::link_status::FetchAvailability,
) -> FetchAvailability {
    use crate::queries::link_status::FetchAvailability as Domain;
    match availability {
        Domain::AvailableNow => FetchAvailability::AvailableNow,
        Domain::UnavailableNow => FetchAvailability::UnavailableNow,
        Domain::Unknown => FetchAvailability::Unknown,
    }
}

/// Attributes what freeing up space would give back to every volume it frees: the block store's
/// physical volume, however many entries (the store itself, linked folders) sit on it. Space
/// management evicts the daemon's own copies, so it cannot relieve any other volume, and a
/// low-disk item about another volume must not offer the action.
pub(crate) fn attribute_reclaimable(
    volumes: &mut [VolumeFreeSpace],
    reclaimable_by_group: &std::collections::HashMap<String, u64>,
    shares_block_store_volume: impl Fn(&str) -> bool,
) {
    let total = reclaimable_by_group.values().fold(0u64, |sum, b| sum.saturating_add(*b));
    for volume in volumes {
        if shares_block_store_volume(&volume.path) {
            volume.reclaimable_bytes = total;
        }
    }
}

/// `RuntimeStatusView` (`crate::queries::runtime_status`, DaemonState-
/// independent) -> the IPC wire type. `overall_state`/`attention_reasons`
/// are left at their zero values -- `overall_status` fills them in from
/// this same response immediately after, so they can never disagree with
/// the rest of the message they summarize.
pub(crate) fn encode_runtime_status(
    view: crate::queries::runtime_status::RuntimeStatusView,
) -> StatusResponse {
    let links = view.links.into_iter().map(encode_link_status).collect();
    let peers = view
        .peers
        .into_iter()
        .map(|peer| {
            let (reachability, category, route_kind) = reachability_to_proto(peer.reachability);
            PeerStatus {
                device_id: peer.device_id,
                reachability: reachability as i32,
                unreachable_category: category as i32,
                route_kind: route_kind as i32,
                version_incompatible: peer.version_incompatible,
                replaced_by_device_id: peer.replaced_by_device_id.unwrap_or_default(),
            }
        })
        .collect();
    let volumes = view
        .volumes
        .into_iter()
        .map(|v| VolumeFreeSpace {
            path: v.path,
            state: v.state,
            available_bytes: v.available_bytes,
            headroom_bytes: v.headroom_bytes,
            total_bytes: v.total_bytes,
            reclaimable_bytes: 0,
        })
        .collect();
    // A host that updates itself reports its update state; an embedded host is updated by its
    // store, and reports none.
    #[cfg(feature = "process-model")]
    let update = crate::update_ipc::encode_update_status(view.update);
    #[cfg(not(feature = "process-model"))]
    let update = yadorilink_ipc_proto::daemonctl::UpdateStatusResponse::default();
    let active_transfers = view
        .active_transfers
        .into_iter()
        .map(|t| ActiveTransferProgress {
            group_id: t.group_id,
            path: t.path,
            bytes_done: t.bytes_done,
            bytes_total: t.bytes_total,
            blocks_done: t.blocks_done,
            blocks_total: t.blocks_total,
            source_peer: t.source_peer,
            started_at_unix: t.started_at_unix,
        })
        .collect();
    let recent_errors = view
        .recent_errors
        .into_iter()
        .map(|e| RecentSyncError {
            category: e.category,
            timestamp_unix: e.timestamp_unix,
            coarse_context: e.coarse_context,
        })
        .collect();
    StatusResponse {
        links,
        peers,
        upload_limit_bytes_per_sec: view.upload_limit_bytes_per_sec,
        download_limit_bytes_per_sec: view.download_limit_bytes_per_sec,
        update_state: update.state,
        update_available_version: update.available_version,
        update_mandatory: update.mandatory,
        update_required: update.update_required,
        update_last_error_category: update.last_error_category,
        update_channel: update.channel,
        update_install_source: update.install_source,
        update_holdback_reason: update.holdback_reason,
        current_upload_bytes_per_sec: view.current_upload_bytes_per_sec,
        current_download_bytes_per_sec: view.current_download_bytes_per_sec,
        volumes,
        block_store_total_bytes: view.block_store.total_bytes,
        block_store_block_count: view.block_store.block_count,
        last_gc_unix: view.last_gc_unix,
        gc_reclaimable_estimate_bytes: view.gc_reclaimable_estimate_bytes,
        active_transfers,
        recent_errors,
        overall_state: String::new(),
        attention_reasons: Vec::new(),
        preserved: None,
        rebootstrapping_groups: Vec::new(),
        undecided_uploads: 0,
        undecided_uploads_oldest_ms: 0,
        provider_roots: Vec::new(),
        provider_removals: Vec::new(),
        orphan_domains: Vec::new(),
        host_api_version: yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION,
        provider_registry_restored: false,
    }
}

/// `LinkStatusView` (`crate::queries::link_status`, DaemonState-independent)
/// -> the IPC wire type -- the one place this crate is allowed to know
/// both sides.
pub(crate) fn encode_link_status(view: crate::queries::link_status::LinkStatusView) -> LinkStatus {
    let held_files: Vec<HeldFile> = view
        .held_files
        .into_iter()
        .map(|held| HeldFile {
            path: held.path,
            reason: held.reason,
            held_since_unix_nanos: held.held_since_unix_nanos,
        })
        .collect();
    let held_file_count = held_files.len() as u64;
    let durability_status = durability_status_to_proto(view.durability_status);
    let durability_evidence = durability_evidence_to_proto(view.durability_evidence);
    let (provider_root_id, provider_display_name) = view.provider.unwrap_or_default();
    LinkStatus {
        provider_root_id,
        provider_display_name,
        local_path: view.local_path,
        group_id: view.group_id,
        paused: view.paused,
        conflict_count: view.conflict_count,
        conflicts_pending: view.conflicts_pending,
        conflict_note: view.conflict_note,
        materialization_policy: view.materialization_policy,
        hydrated_count: view.hydrated_count,
        placeholder_count: view.placeholder_count,
        hydrating_count: view.hydrating_count,
        requested_content_count: view.requested_content_count,
        held_file_count,
        held_files,
        stranded_directory_count: view.stranded_directory_count,
        unreadable_file_count: view.unreadable_files.len() as u64,
        pending_approvals: view.pending_approvals,
        // Filled by the status read, which alone has the space-management cache.
        reclaimable_bytes: 0,
        unreadable_files: view
            .unreadable_files
            .into_iter()
            .take(UNREADABLE_FILES_LISTED)
            .map(|f| yadorilink_ipc_proto::daemonctl::UnreadableFile {
                path: f.path,
                reason: f.reason.code().to_owned(),
            })
            .collect(),
        skipped_symlink_count: view.skipped_symlink_count,
        degraded: view.degraded.is_some(),
        waiting_for_disk_space: view
            .degraded
            .as_ref()
            .is_some_and(|d| d.cause == crate::link_registry::DegradedCause::WaitingForDiskSpace),
        degraded_cause: view
            .degraded
            .as_ref()
            .map_or(DegradedCause::Unspecified, |d| d.cause.to_wire())
            .into(),
        degraded_reason: view.degraded.map(|d| d.reason).unwrap_or_default(),
        // This link's active-transfer rollup -- absent (all zero,
        // `has_active_transfer = false`) when nothing is currently
        // in flight for this link.
        has_active_transfer: view.transfer.is_some(),
        transfer_bytes_done: view.transfer.as_ref().map(|t| t.bytes_done).unwrap_or(0),
        transfer_bytes_total: view.transfer.as_ref().map(|t| t.bytes_total).unwrap_or(0),
        transfer_blocks_done: view.transfer.as_ref().map(|t| t.blocks_done).unwrap_or(0),
        transfer_blocks_total: view.transfer.as_ref().map(|t| t.blocks_total).unwrap_or(0),
        transfer_eta_seconds: view.transfer.and_then(|t| t.eta_seconds).unwrap_or(0),
        durability_status: durability_status as i32,
        durability_evidence: durability_evidence as i32,
        durability_check_pending: view.durability_check_pending,
        policy_stale: view.policy_stale,
        // A folder group linked at more than one folder refuses to sync
        // entirely (each folder's scan would delete the other's files on
        // every device). The refusal is otherwise only a log line, which is
        // loud in the code and silent in the UI -- this is what makes it
        // visible where the user actually looks, and names every folder
        // involved so the remedy (unlink all but one) is actionable.
        ambiguous: view.ambiguous_local_paths.len() > 1,
        ambiguous_local_paths: view.ambiguous_local_paths,
        capture_volume_changed: view.capture_volume_changed,
        capture_volume_unconfirmed: view.capture_volume_unconfirmed,
        local_storage_state: local_storage_state_to_proto(view.local_storage_state) as i32,
        fetch_availability: fetch_availability_to_proto(view.fetch_availability) as i32,
        full_replica_device_ids: view.full_replica_device_ids,
        // Filled in with the peer list at status assembly, which this per-link
        // conversion does not see.
        availability: 0,
        availability_reachable_device_ids: Vec::new(),
        availability_offline_device_ids: Vec::new(),
        availability_update_required_device_ids: Vec::new(),
        protection: 0,
        // Input to the dimension fill: who confirmed the custody, if anyone.
        protection_device_ids: view.custody_confirmed_by,
        paused_until_unix: view.paused_until_unix,
    }
}

/// `StatusResponse.overall_state`'s three values, kept as a small internal
/// enum (rather than juggling raw strings below) purely so the precedence
/// rules below read clearly; the wire format is still the plain lowercase
/// string this converts to via `as_str`, matching every other
/// string-typed status enum in this message
/// (`LinkStatus.materialization_policy`, `VolumeFreeSpace.state`,...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OverallState {
    Healthy,
    Attention,
    Degraded,
}

impl OverallState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            OverallState::Healthy => "healthy",
            OverallState::Attention => "attention",
            OverallState::Degraded => "degraded",
        }
    }
}

/// The coordination service refuses this device although its credential is intact: the account
/// has not accepted the current Terms, or the session cannot be renewed. Local sync state is
/// untouched; the person signs in again. Status is never healthy meanwhile.
pub(crate) fn apply_coordination_block(
    block: Option<&yadorilink_fapi_client::CoordinationBlock>,
    overall_state: &mut OverallState,
    attention_reasons: &mut Vec<String>,
) {
    use yadorilink_fapi_client::CoordinationBlock;
    let Some(block) = block else { return };
    attention_reasons.insert(
        0,
        match block {
            CoordinationBlock::TermsConsentRequired { .. } => "terms_consent_required",
            CoordinationBlock::SignInRequired => "sign_in_required",
        }
        .to_owned(),
    );
    if *overall_state == OverallState::Healthy {
        *overall_state = OverallState::Attention;
    }
}

/// This device's own account is scheduled for deletion: the person may want to cancel it. Status
/// is never healthy meanwhile. The reason is appended after the others; `urgent` (the
/// departing-account durability guard is blocking finalization) is its own key so it can rank
/// higher.
pub(crate) fn apply_account_deletion(
    state: crate::daemon_state::AccountDeletionState,
    overall_state: &mut OverallState,
    attention_reasons: &mut Vec<String>,
) {
    use crate::daemon_state::AccountDeletionState;
    let reason = match state {
        AccountDeletionState::None => return,
        AccountDeletionState::Pending => "account_deletion_pending",
        AccountDeletionState::Urgent => "account_deletion_urgent",
    };
    attention_reasons.push(reason.to_owned());
    if *overall_state == OverallState::Healthy {
        *overall_state = OverallState::Attention;
    }
}

/// The device that was replaced may have held the only complete replica of a group, and the new
/// device's state is not confirmed yet: status is never healthy meanwhile. The reason is appended
/// after the others.
pub(crate) fn apply_replacement_unconfirmed(
    pending: bool,
    overall_state: &mut OverallState,
    attention_reasons: &mut Vec<String>,
) {
    if !pending {
        return;
    }
    attention_reasons
        .push(yadorilink_local_storage::replacement_unconfirmed::ATTENTION_REASON.to_owned());
    if *overall_state == OverallState::Healthy {
        *overall_state = OverallState::Attention;
    }
}

/// The confirmation of the replacement was refused for lack of a valid sign-in: the person has to
/// sign in again. Appended after every other reason (the state is already attention, because the
/// replacement is unconfirmed).
pub(crate) fn apply_replacement_sign_in(required: bool, attention_reasons: &mut Vec<String>) {
    if required {
        attention_reasons.push(
            yadorilink_local_storage::replacement_unconfirmed::SIGN_IN_ATTENTION_REASON.to_owned(),
        );
    }
}

/// The person has not yet acknowledged that changes made after the backup may be missing, which
/// the confirm of the replacement waits for. Appended after every other reason (the state is
/// already attention, because the replacement is unconfirmed).
pub(crate) fn apply_replacement_acknowledgement(
    required: bool,
    attention_reasons: &mut Vec<String>,
) {
    if required {
        attention_reasons.push(
            yadorilink_local_storage::replacement_unconfirmed::ACKNOWLEDGEMENT_ATTENTION_REASON
                .to_owned(),
        );
    }
}

/// Why the confirmation of the replacement is still waiting, as the daemon's last pass recorded
/// it. Appended after every other reason as `code:reason`, so the wait can be told from a stall.
pub(crate) fn apply_replacement_waiting(
    reason: Option<String>,
    attention_reasons: &mut Vec<String>,
) {
    if let Some(reason) = reason {
        attention_reasons.push(format!(
            "{}:{reason}",
            yadorilink_local_storage::replacement_unconfirmed::WAITING_ATTENTION_REASON
        ));
    }
}

pub(crate) fn replacement_waiting_reason(dir: Option<&std::path::Path>) -> Option<String> {
    yadorilink_local_storage::replacement_unconfirmed::waiting_reason(dir?)
}

pub(crate) fn replacement_acknowledgement_required(dir: Option<&std::path::Path>) -> bool {
    dir.is_some_and(yadorilink_local_storage::replacement_unconfirmed::acknowledgement_required)
}

pub(crate) fn replacement_sign_in_required(dir: Option<&std::path::Path>) -> bool {
    dir.is_some_and(yadorilink_local_storage::replacement_unconfirmed::sign_in_required)
}

/// Whether a start over left a replacement the service has not confirmed (see
/// `yadorilink_local_storage::replacement_unconfirmed`). A state directory that cannot be resolved
/// has no such record.
pub(crate) fn replacement_unconfirmed_pending(dir: Option<&std::path::Path>) -> bool {
    dir.is_some_and(yadorilink_local_storage::replacement_unconfirmed::pending)
}

/// The whole status of the engine behind `context`, as the wire type: the runtime view, the
/// provider roots, space that could be reclaimed, the preserved-items summary and the
/// attention rollup. `state_dir` is where the replacement records live (`None`: there is none).
///
/// # Errors
/// The message of the failure to read the runtime view.
pub(crate) fn build_status(
    context: &crate::control_context::ControlContext,
    state_dir: Option<&std::path::Path>,
) -> Result<StatusResponse, String> {
    let view = context.queries.runtime_status.snapshot().map_err(|e| e.to_string())?;
    let database_restored = view.database_restored;
    let author_unavailable = view.author_unavailable;
    let coordination_block = view.coordination_block.clone();
    let account_deletion = view.account_deletion;
    let mut response = encode_runtime_status(view);
    response.provider_roots = context.provider_status.snapshot();
    (response.provider_removals, response.orphan_domains) = context.provider_status.extras();
    response.provider_registry_restored =
        crate::windows_sync_roots::registry_restored(&context.config_dir);
    crate::status_dimensions::fill_link_dimensions(&mut response);
    let reclaimable = context.auto_reclaim.reclaimable_by_group();
    for link in &mut response.links {
        link.reclaimable_bytes = reclaimable.get(&link.group_id).copied().unwrap_or(0);
    }
    attribute_reclaimable(&mut response.volumes, &reclaimable, |path| {
        context.queries.runtime_status.shares_block_store_volume(path)
    });
    let (mut overall_state, mut attention_reasons) = overall_status(&response);
    if let Some(category) = database_restored {
        // Sync as this device is refused until it is registered again.
        attention_reasons.insert(0, format!("database_restored:{category}"));
        if overall_state == OverallState::Healthy {
            overall_state = OverallState::Attention;
        }
    }
    if author_unavailable {
        // Nothing this device edits can be signed, so nothing syncs from it.
        attention_reasons.insert(0, "author_unavailable".to_owned());
        if overall_state == OverallState::Healthy {
            overall_state = OverallState::Attention;
        }
    }
    apply_coordination_block(
        coordination_block.as_ref(),
        &mut overall_state,
        &mut attention_reasons,
    );
    apply_account_deletion(account_deletion, &mut overall_state, &mut attention_reasons);
    apply_replacement_unconfirmed(
        replacement_unconfirmed_pending(state_dir),
        &mut overall_state,
        &mut attention_reasons,
    );
    apply_replacement_sign_in(replacement_sign_in_required(state_dir), &mut attention_reasons);
    apply_replacement_acknowledgement(
        replacement_acknowledgement_required(state_dir),
        &mut attention_reasons,
    );
    apply_replacement_waiting(replacement_waiting_reason(state_dir), &mut attention_reasons);
    response.overall_state = overall_state.as_str().to_string();
    response.attention_reasons = attention_reasons;
    let preserved = context.application.preserved.summary();
    response.preserved = Some(yadorilink_ipc_proto::daemonctl::PreservedSummary {
        total: preserved.total,
        content_unavailable: preserved.content_unavailable,
        record_unavailable: preserved.record_unavailable,
        bytes: preserved.bytes,
        unreplayed_own_units: preserved.unreplayed_own_units,
        warn_bytes: preserved.warn_bytes,
        warn: preserved.warn,
        retained_originals: preserved.retained_originals,
    });
    response.rebootstrapping_groups = context.application.preserved.rebootstrapping_groups();
    (response.undecided_uploads, response.undecided_uploads_oldest_ms) =
        context.application.preserved.undecided_uploads();
    Ok(response)
}

/// Rolls up every already-populated field on `response` into one
/// glanceable `(state, reasons)` pair (spec's "Aggregate Sync Status"/
/// "Sync needs attention" scenarios), computed daemon-side so a UI client
/// (or the CLI) never has to re-derive "is anything wrong?" itself and
/// risk drifting from this definition. Deliberately takes the
/// already-built `StatusResponse` rather than the raw `DaemonState` — this
/// keeps it a pure function over data the caller already has, directly
/// unit-testable with plain struct literals (this file's/`status.rs`'s
/// established discipline), and guarantees the rollup can never disagree
/// with the detail fields sitting right next to it in the same message.
///
/// Precedence (highest first): any link `degraded`, any link whose
/// `durability_status` is `AT_RISK` (a positively-known "no durable copy
/// exists anywhere" fact -- the durability axis's own most severe
/// state), or any volume `state == "critical"` -> `Degraded` (spec: a
/// low-disk condition on a linked folder needs attention; a *critical*
/// one is actively blocking sync, same severity split
/// `VolumeFreeSpace.state`'s own `"low"` vs `"critical"` already draws).
/// Otherwise any conflict, held file, a `"low"` volume, a disconnected
/// peer, a link whose `durability_status` cannot currently be confirmed
/// (`UNKNOWN`/`UNSPECIFIED`) or whose `fetch_availability` is
/// `UNAVAILABLE_NOW`/`UNKNOWN`/`UNSPECIFIED` (an unconfirmed fetch
/// availability must never silently read as `AVAILABLE_NOW` any more than
/// an unconfirmed durability status may silently read as `PROTECTED` --
/// same fail-safe discipline, applied to both axes uniformly), a
/// non-empty recent-error feed, or a recorded update failure ->
/// `Attention`. A merely-`paused` link is *not* by itself
/// attention-worthy (spec's "Sync is healthy" scenario: "caught up or idle
/// *without errors*" says nothing about pause being an error state --
/// pausing is a deliberate user action, matching `status.rs`'s own
/// `held_summary_suffix`-style "only surface what's actionable"
/// discipline). Otherwise `Healthy`, with no reasons.
///
/// Folding in `durability_status`/`fetch_availability` here is required by
/// this function's own doc comment above: it claims the rollup "can never
/// disagree with the detail fields sitting right next to it in the same
/// message," and an earlier version of this function never read those
/// two fields at all -- a group with zero durable copies anywhere
/// (`AtRisk`) could read `Overall: healthy`.
#[cfg(test)]
pub(crate) fn attention_reasons_for_tests(response: &StatusResponse) -> Vec<String> {
    overall_status(response).1
}

/// Most unreadable files a status reply names; the count carries the rest.
pub(crate) const UNREADABLE_FILES_LISTED: usize = 50;

pub(crate) fn overall_status(response: &StatusResponse) -> (OverallState, Vec<String>) {
    use yadorilink_ipc_proto::daemonctl::{FetchAvailability, GroupDurabilityStatus};

    let mut degraded_reasons = Vec::new();
    let mut attention_reasons = Vec::new();

    for link in &response.links {
        if link.degraded {
            // Keyed on the typed cause, never on `degraded_reason` text.
            let group = &link.group_id;
            match link.degraded_cause() {
                // A wait for room on the disk, not a stopped folder: it clears by itself.
                DegradedCause::WaitingForDiskSpace => {
                    attention_reasons.push(format!("waiting_for_disk_space:{group}"));
                }
                DegradedCause::FileWatchLimit => {
                    degraded_reasons.push(format!("file_watch_limit:{group}"));
                }
                DegradedCause::OwnershipLost => {
                    degraded_reasons.push(format!("ownership_lost:{group}"));
                }
                DegradedCause::NotJoined => degraded_reasons.push(format!("not_joined:{group}")),
                DegradedCause::Unspecified => degraded_reasons.push(format!("degraded:{group}")),
            }
        }
        // A group linked at several folders syncs nothing at all, which is not
        // something a rollup may call healthy next to the `NOT SYNCING` detail.
        if link.ambiguous {
            degraded_reasons.push(format!("ambiguous:{}", link.group_id));
        }
        if link.capture_volume_changed {
            attention_reasons.push(format!("volume_changed:{}", link.group_id));
        }
        if link.capture_volume_unconfirmed {
            attention_reasons.push(format!("volume_unconfirmed:{}", link.group_id));
        }
        match link.durability_status() {
            GroupDurabilityStatus::AtRisk => {
                degraded_reasons.push(format!("durability_at_risk:{}", link.group_id));
            }
            // Not asked yet is "checking" (see `LinkStatus.durability_check_pending`):
            // transient, and nothing a user could act on.
            GroupDurabilityStatus::Unknown if link.durability_check_pending => {}
            GroupDurabilityStatus::Unknown | GroupDurabilityStatus::Unspecified => {
                attention_reasons.push(format!("durability_unknown:{}", link.group_id));
            }
            GroupDurabilityStatus::Protected | GroupDurabilityStatus::Protecting => {}
        }
        let wants_content = link.requested_content_count > 0;
        // Fetch availability matters only while content is wanted; an idle On-Demand folder's
        // remote placeholders are its normal steady state (the same predicate as the product
        // summary's `wants_content`; the rollup/summary agreement test pins the two together).
        match link.fetch_availability() {
            _ if !wants_content => {}
            FetchAvailability::UnavailableNow => {
                attention_reasons.push(format!("fetch_unavailable:{}", link.group_id));
            }
            FetchAvailability::Unknown | FetchAvailability::Unspecified => {
                attention_reasons.push(format!("fetch_availability_unknown:{}", link.group_id));
            }
            FetchAvailability::AvailableNow => {}
        }
        if link.conflict_count > 0 {
            attention_reasons.push(format!("conflict:{}", link.group_id));
        }
        if link.conflicts_pending > 0 {
            attention_reasons.push(format!("conflict_pending:{}", link.group_id));
        }
        if link.held_file_count > 0 {
            attention_reasons.push(format!("held:{}", link.group_id));
        }
        if link.unreadable_file_count > 0 {
            attention_reasons.push(format!("unreadable_files:{}", link.group_id));
        }
        if link.stranded_directory_count > 0 {
            attention_reasons.push(format!("stranded_directory:{}", link.group_id));
        }
        if link.pending_approvals > 0 {
            attention_reasons.push(format!("approval_pending:{}", link.group_id));
        }
    }
    for root in &response.provider_roots {
        // A provider folder the user can act on: not ready (enable File Provider, an error), files
        // that keep failing to download, edits kept beside a file waiting to be merged.
        if root.readiness != "ready" && root.readiness != "preparing the folder" {
            attention_reasons.push(format!("provider_not_ready:{}", root.root_id));
        }
        if !root.stuck.is_empty() {
            attention_reasons.push(format!("provider_stuck:{}", root.root_id));
        }
        if root.kept_edits > 0 {
            attention_reasons.push(format!("kept_edits:{}", root.root_id));
        }
    }
    if response.provider_removals.iter().any(|r| r.unreadable) {
        // The list could not be read, so nothing is known about removals: not "no removals".
        // "removals" cannot be a root id (those are hex digits).
        attention_reasons.push("provider_not_ready:removals".to_owned());
    }
    if response.provider_registry_restored {
        attention_reasons.push("provider_registry_restored:older_generation".to_owned());
    }
    for orphan in &response.orphan_domains {
        attention_reasons.push(format!("provider_orphan_domain:{orphan}"));
    }
    for volume in &response.volumes {
        match volume.state.as_str() {
            "critical" => degraded_reasons.push(format!("low_disk_critical:{}", volume.path)),
            "low" => attention_reasons.push(format!("low_disk:{}", volume.path)),
            _ => {}
        }
    }
    for peer in &response.peers {
        // A peer still racing candidates ("connecting") is transient and
        // not yet attention; only one that genuinely cannot be connected is.
        if peer.version_incompatible {
            // Online but on another version: the user updates, nothing is waiting to come back.
            attention_reasons.push(format!("peer_update_required:{}", peer.device_id));
        } else if peer.reachability()
            == yadorilink_ipc_proto::daemonctl::PeerReachability::Unreachable
            // A replaced device is gone for good and has its own reason; nothing to reconnect.
            && peer.unreachable_category()
                != yadorilink_ipc_proto::daemonctl::UnreachableCategory::DeviceReplaced
        {
            attention_reasons.push(format!("peer_disconnected:{}", peer.device_id));
        }
    }
    for error in &response.recent_errors {
        attention_reasons.push(format!("recent_error:{}", error.category));
    }
    if response.update_required {
        // This device is below the signed minimum supported version: it cannot sync with
        // current-generation devices until it updates.
        attention_reasons.push("update_required".to_owned());
    }
    if !response.update_last_error_category.is_empty() {
        attention_reasons.push(format!("update_failed:{}", response.update_last_error_category));
    }

    if !degraded_reasons.is_empty() {
        degraded_reasons.extend(attention_reasons);
        return (OverallState::Degraded, degraded_reasons);
    }
    if !attention_reasons.is_empty() {
        return (OverallState::Attention, attention_reasons);
    }
    (OverallState::Healthy, Vec::new())
}

#[cfg(test)]
mod overall_status_tests;
