//! The status the engine reports, assembled once for every front end: the control socket's
//! `Status` reply and the embedded host's status command both come from here, so the rollup
//! (`overall_status`) and every per-link field can never differ between them.
//!
//! Nothing here reads the process environment: the state directory the replacement records
//! live in is passed in by the caller.

use crate::folder_state::FolderBlocker;
use yadorilink_ipc_proto::daemonctl::{
    ActiveTransferProgress, DegradedCause, FetchAvailability, GroupDurabilityStatus, HeldFile,
    LinkStatus, LocalStorageState, PeerStatus, RecentSyncError, RetentionApplyState,
    StatusResponse, VersionSkew, VolumeFreeSpace,
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
                version_skew: match peer.version_skew {
                    Some(crate::peer_connectivity_runtime::VersionSkew::PeerNewer) => {
                        VersionSkew::PeerNewer as i32
                    }
                    Some(crate::peer_connectivity_runtime::VersionSkew::PeerOlder) => {
                        VersionSkew::PeerOlder as i32
                    }
                    None => VersionSkew::Unspecified as i32,
                },
                replaced_by_device_id: peer.replaced_by_device_id.unwrap_or_default(),
                last_connected_unix: peer.last_connected_unix,
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
        snapshot_age_ms: 0,
        update_last_error_category: update.last_error_category,
        update_channel: update.channel,
        update_install_source: update.install_source,
        update_holdback_reason: update.holdback_reason,
        // Filled by `compose_status`, which holds the network policy.
        paused_on_metered: false,
        network_cost_known: false,
        current_upload_bytes_per_sec: view.current_upload_bytes_per_sec,
        current_download_bytes_per_sec: view.current_download_bytes_per_sec,
        volumes,
        block_store_total_bytes: view.block_store.total_bytes,
        block_store_block_count: view.block_store.block_count,
        kept_history_bytes: view.kept_history.map(|k| k.bytes),
        kept_history_budget_bytes: view.kept_history.map(|k| k.budget_bytes),
        unpublished_edits_service_unreachable: view.unpublished_edits_service_unreachable,
        unpublished_edits_not_authorized: view.unpublished_edits_not_authorized,
        unpublished_edits_rejected: view.unpublished_edits_rejected,
        last_gc_unix: view.last_gc_unix,
        gc_reclaimable_estimate_bytes: view.gc_reclaimable_estimate_bytes,
        active_transfers,
        recent_errors,
        overall_state: String::new(),
        attention_reasons: Vec::new(),
        product: None,
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
    // The folder's gates come from its snapshot (`crate::folder_state`), not from separate flags.
    let blocked = |blocker: FolderBlocker| view.folder_blockers.contains(&blocker);
    let degraded_cause = view.folder_blockers.iter().find_map(|b| match b {
        FolderBlocker::Degraded(cause) => Some(*cause),
        _ => None,
    });
    let durability_status = durability_status_to_proto(view.durability_status);
    let durability_evidence = durability_evidence_to_proto(view.durability_evidence);
    // A provider-backed root is not a plain folder the daemon writes itself.
    let (provider_root_id, provider_display_name) = view.provider.unwrap_or_default();
    LinkStatus {
        root_access_warning: view.root_access_warning,
        index_damaged_path: view.index_damaged_path,
        rebuild_needed: blocked(FolderBlocker::RebuildNeeded),
        product: None,
        history_skipped_last_day: view.history_skipped_last_day,
        history_skipped_last_30_days: view.history_skipped_last_30_days,
        provider_root_id,
        provider_display_name,
        local_path: view.local_path,
        group_id: view.group_id,
        paused: view.paused,
        conflict_count: view.conflict_count,
        conflicts_pending: view.conflicts_pending,
        pending_local_changes: view.pending_local_changes,
        last_change_origin_device_id: view.last_change_origin_device_id.unwrap_or_default(),
        conflict_note: view.conflict_note,
        materialization_policy: view.materialization_policy,
        hydrated_count: view.hydrated_count,
        placeholder_count: view.placeholder_count,
        hydrating_count: view.hydrating_count,
        total_bytes: Some(view.total_bytes),
        online_only_bytes: Some(view.online_only_bytes),
        requested_content_count: view.requested_content_count,
        pinned_pending_count: view.pinned_pending_count,
        pinned_pending_error: view.pinned_pending_error,
        pinned_pending_retry_secs: view.pinned_pending_retry_secs,
        retention_rule_count: view.retention.rule_count,
        retention_apply_state: if view.retention.online_only_count == 0 {
            RetentionApplyState::None
        } else if view.retention.pending_count > 0 {
            RetentionApplyState::Pending
        } else {
            RetentionApplyState::Done
        } as i32,
        retention_done_count: u64::from(view.retention.counts.done),
        retention_skipped_count: u64::from(view.retention.counts.skipped),
        retention_retryable_count: u64::from(view.retention.counts.retryable),
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
        degraded: degraded_cause.is_some(),
        waiting_for_disk_space: degraded_cause
            == Some(crate::link_registry::DegradedCause::WaitingForDiskSpace),
        degraded_cause: degraded_cause.map_or(DegradedCause::Unspecified, |c| c.to_wire()).into(),
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
        policy_stale: blocked(FolderBlocker::PolicyStale),
        // A folder group linked at more than one folder refuses to sync
        // entirely (each folder's scan would delete the other's files on
        // every device). The refusal is otherwise only a log line, which is
        // loud in the code and silent in the UI -- this is what makes it
        // visible where the user actually looks, and names every folder
        // involved so the remedy (unlink all but one) is actionable.
        ambiguous: blocked(FolderBlocker::AmbiguousLink),
        ambiguous_local_paths: view.ambiguous_local_paths,
        capture_volume_changed: blocked(FolderBlocker::CaptureVolumeChanged),
        capture_volume_unconfirmed: blocked(FolderBlocker::CaptureVolumeUnconfirmed),
        local_storage_state: local_storage_state_to_proto(view.local_storage_state) as i32,
        fetch_availability: fetch_availability_to_proto(view.fetch_availability) as i32,
        full_replica_device_ids: view.full_replica_device_ids,
        // Filled in with the peer list at status assembly, which this per-link
        // conversion does not see.
        availability: 0,
        availability_reachable_device_ids: Vec::new(),
        availability_offline_device_ids: Vec::new(),
        availability_update_required_device_ids: Vec::new(),
        availability_newer_peer_device_ids: Vec::new(),
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
///
/// `Healthy` does not say the data is safely stored: a folder whose copy is not confirmed yet
/// still reads healthy here, and only the product view's protection line ("Not confirmed yet")
/// says so. A consumer that wants "safely stored" reads `StatusResponse.product` (protection),
/// not this value.
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
        AccountDeletionState::Requested => "account_deletion_requested",
        AccountDeletionState::Pending => "account_deletion_pending",
        AccountDeletionState::Urgent => "account_deletion_urgent",
    };
    attention_reasons.push(reason.to_owned());
    if *overall_state == OverallState::Healthy {
        *overall_state = OverallState::Attention;
    }
}

/// The device that was replaced may have held the only complete replica of a group, and the new
/// device's state is not confirmed yet: status is never healthy meanwhile. One reason is appended
/// after the others, `replacement_unconfirmed` with the step the person or the daemon is at: what
/// is asked of the person comes before a wait, a wait (`:waiting:<why>`, so it can be told from a
/// stall) before the plain "not confirmed yet".
pub(crate) fn apply_replacement_unconfirmed(
    pending: bool,
    sign_in_required: bool,
    acknowledgement_required: bool,
    waiting: Option<String>,
    overall_state: &mut OverallState,
    attention_reasons: &mut Vec<String>,
) {
    use yadorilink_local_storage::replacement_unconfirmed as record;
    if !pending {
        return;
    }
    attention_reasons.push(if acknowledgement_required {
        record::ACKNOWLEDGEMENT_ATTENTION_REASON.to_owned()
    } else if sign_in_required {
        record::SIGN_IN_ATTENTION_REASON.to_owned()
    } else if let Some(why) = waiting {
        format!("{}:{why}", record::WAITING_ATTENTION_REASON)
    } else {
        record::ATTENTION_REASON.to_owned()
    });
    if *overall_state == OverallState::Healthy {
        *overall_state = OverallState::Attention;
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

/// The parts of the control context a status reads, as shared handles: the status builder holds
/// them, so a status can be collected without the control context itself.
pub(crate) struct StatusSources {
    pub(crate) queries: std::sync::Arc<crate::queries::QueryServices>,
    pub(crate) application: std::sync::Arc<crate::application::ApplicationServices>,
    pub(crate) provider_status: std::sync::Arc<crate::provider_status::ProviderStatusSource>,
    pub(crate) auto_reclaim: std::sync::Arc<crate::provider_auto_reclaim::AutoReclaimSlot>,
    /// Where the replacement records live.
    pub(crate) config_dir: std::path::PathBuf,
    pub(crate) network_policy: std::sync::Arc<crate::network_policy::NetworkPolicy>,
    /// When each folder, and the device, was last seen up to date.
    pub(crate) last_synced: LastSynced,
}

/// When each scope (a folder by local path, the device by the empty key) was last found up to
/// date by a status read. In memory: a restart starts empty and the field is then absent until
/// the scope is next found up to date; it is never read as "never synced".
#[derive(Default)]
pub(crate) struct LastSynced {
    seen: std::sync::Mutex<std::collections::HashMap<String, i64>>,
}

impl LastSynced {
    /// Stamps `last_synced_unix` on the device and every folder of a finished reply. A scope that
    /// is up to date is stamped `now_unix` and remembered, unless `stale` (a reply that makes no
    /// positive claim); others get their remembered time. Folders no longer listed are forgotten.
    pub(crate) fn stamp(&self, response: &mut StatusResponse, now_unix: i64, stale: bool) {
        use yadorilink_ipc_proto::daemonctl::product_status::State;
        let mut seen = self.seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let live: std::collections::HashSet<&str> =
            response.links.iter().map(|l| l.local_path.as_str()).collect();
        seen.retain(|key, _| key.is_empty() || live.contains(key.as_str()));
        let mut one =
            |key: &str, product: &mut Option<yadorilink_ipc_proto::daemonctl::ProductStatus>| {
                let Some(product) = product else { return };
                if !stale && product.state() == State::UpToDate {
                    seen.insert(key.to_owned(), now_unix);
                }
                product.last_synced_unix = seen.get(key).copied();
            };
        for link in &mut response.links {
            one(&link.local_path.clone(), &mut link.product);
        }
        one("", &mut response.product);
    }
}

/// What a status reads from the ledger, the block index, the filesystem and shell-installed
/// closures, collected in one pass off the request path.
pub(crate) struct CollectedStatus {
    pub(crate) runtime: crate::queries::runtime_status::RuntimeFacts,
    provider_roots: Vec<yadorilink_ipc_proto::daemonctl::ProviderRootStatus>,
    provider_removals: Vec<yadorilink_ipc_proto::daemonctl::ProviderRemovalStatus>,
    orphan_domains: Vec<String>,
    provider_registry_restored: bool,
    /// What the host last reported the OS holds, per provider folder group.
    pub(crate) os_file_counts:
        std::collections::HashMap<String, crate::provider_status::OsFileCounts>,
    reclaimable: std::collections::HashMap<String, u64>,
    /// The volume entries that share the block store's physical volume.
    shares_block_store_volume: std::collections::HashSet<String>,
    replacement_pending: bool,
    replacement_sign_in: bool,
    replacement_acknowledgement: bool,
    replacement_waiting: Option<String>,
    preserved: crate::preserved_items::PreservedSummary,
    rebootstrapping_groups: Vec<String>,
    undecided_uploads: (u64, u64),
}

/// Reads everything a status needs that is not in memory.
///
/// # Errors
/// The message of the failure to read the runtime view.
pub(crate) fn collect_status(sources: &StatusSources) -> Result<CollectedStatus, String> {
    let runtime = sources.queries.runtime_status.collect().map_err(|e| e.to_string())?;
    let dir = Some(sources.config_dir.as_path());
    let (provider_removals, orphan_domains) = sources.provider_status.extras();
    let reclaimable = sources.auto_reclaim.reclaimable_by_group();
    let shares_block_store_volume = runtime
        .volume_paths()
        .filter(|path| sources.queries.runtime_status.shares_block_store_volume(path))
        .map(str::to_owned)
        .collect();
    Ok(CollectedStatus {
        runtime,
        provider_roots: sources.provider_status.snapshot(),
        os_file_counts: sources.provider_status.os_file_counts(),
        provider_removals,
        orphan_domains,
        provider_registry_restored: crate::windows_sync_roots::registry_restored(
            &sources.config_dir,
        ),
        reclaimable,
        shares_block_store_volume,
        replacement_pending: replacement_unconfirmed_pending(dir),
        replacement_sign_in: replacement_sign_in_required(dir),
        replacement_acknowledgement: replacement_acknowledgement_required(dir),
        replacement_waiting: replacement_waiting_reason(dir),
        preserved: sources.application.preserved.summary(),
        rebootstrapping_groups: sources.application.preserved.rebootstrapping_groups(),
        undecided_uploads: sources.application.preserved.undecided_uploads(),
    })
}

/// Collects and composes in place: for a caller that decides something from the answer, or has
/// no builder; a status request is answered from the builder's facts (`crate::status_facts`).
///
/// # Errors
/// The message of the failure to read the runtime view.
pub(crate) fn build_status(sources: &StatusSources) -> Result<StatusResponse, String> {
    Ok(compose_status(sources, &collect_status(sources)?, false))
}

/// A provider folder's three file counts, from what its table says (whose total is the folder's file
/// count) and what the host reported the OS holds.
pub(crate) fn provider_counts_of(
    hydrated: u64,
    placeholder: u64,
    hydrating: u64,
    os: crate::provider_status::OsFileCounts,
) -> (u64, u64, u64) {
    crate::provider_status::provider_file_counts(hydrated + placeholder + hydrating, os)
}

/// The whole status of the engine, as the wire type: the runtime view, the provider roots,
/// space that could be reclaimed, the preserved-items summary and the attention rollup, from
/// collected facts and what the daemon holds in memory now. Reads no ledger, file or block
/// index. `stale` withholds every positive claim (see `RuntimeStatusQueryService::snapshot_from`).
pub(crate) fn compose_status(
    sources: &StatusSources,
    collected: &CollectedStatus,
    stale: bool,
) -> StatusResponse {
    let view = sources.queries.runtime_status.snapshot_from(&collected.runtime, stale);
    let database_restored = view.database_restored;
    let author_unavailable = view.author_unavailable;
    let coordination_block = view.coordination_block.clone();
    let account_deletion = view.account_deletion;
    let mut response = encode_runtime_status(view);
    response.provider_roots = collected.provider_roots.clone();
    response.provider_removals = collected.provider_removals.clone();
    response.orphan_domains = collected.orphan_domains.clone();
    response.provider_registry_restored = collected.provider_registry_restored;
    let policy = sources.network_policy.current();
    response.paused_on_metered = policy.paused_on_metered();
    response.network_cost_known = policy.cost_known;
    crate::status_dimensions::fill_link_dimensions(&mut response);
    for link in &mut response.links {
        link.reclaimable_bytes = collected.reclaimable.get(&link.group_id).copied().unwrap_or(0);
        if !link.provider_root_id.is_empty() {
            if let Some(os) = collected.os_file_counts.get(&link.group_id) {
                (link.hydrated_count, link.placeholder_count, link.hydrating_count) =
                    provider_counts_of(
                        link.hydrated_count,
                        link.placeholder_count,
                        link.hydrating_count,
                        *os,
                    );
            }
        }
    }
    attribute_reclaimable(&mut response.volumes, &collected.reclaimable, |path| {
        collected.shares_block_store_volume.contains(path)
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
        collected.replacement_pending,
        collected.replacement_sign_in,
        collected.replacement_acknowledgement,
        collected.replacement_waiting.clone(),
        &mut overall_state,
        &mut attention_reasons,
    );
    response.overall_state = overall_state.as_str().to_string();
    response.attention_reasons = attention_reasons;
    yadorilink_product_view::wire::fill_product_status(&mut response);
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    sources.last_synced.stamp(&mut response, now_unix, stale);
    let preserved = &collected.preserved;
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
    response.rebootstrapping_groups = collected.rebootstrapping_groups.clone();
    (response.undecided_uploads, response.undecided_uploads_oldest_ms) =
        collected.undecided_uploads;
    response
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
/// Otherwise any conflict, held file, a `"low"` volume, a disconnected peer,
/// a peer on another version, a link whose `durability_status` cannot currently be confirmed
/// (`UNKNOWN`/`UNSPECIFIED`), a non-empty recent-error feed, or a recorded
/// update failure -> `Attention`. Content that cannot be fetched now is not a
/// reason (availability; the product state is Waiting while content is
/// wanted), and a folder only this device holds is a configuration
/// (protection says so), not a fault. A merely-`paused` link is *not* by itself
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
    use yadorilink_ipc_proto::daemonctl::GroupDurabilityStatus;

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
                    degraded_reasons.push(format!("folder_needs_relink:{group}"));
                }
                DegradedCause::NotJoined => {
                    degraded_reasons.push(format!("folder_needs_relink:{group}"));
                }
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
        if link.rebuild_needed {
            attention_reasons.push(format!("rebuild_needed:{}", link.group_id));
        }
        if !link.index_damaged_path.is_empty() {
            attention_reasons.push(format!("index_damaged:{}", link.group_id));
        }
        match link.durability_status() {
            // One device holding the folder is a standing configuration, not a fault (the protection
            // dimension says "only on this device"); nothing the person must do is wrong.
            // (The same predicate as the product view's `is_single_copy`; a test pins them.)
            GroupDurabilityStatus::AtRisk if link.full_replica_device_ids.is_empty() => {}
            GroupDurabilityStatus::AtRisk => {
                degraded_reasons.push(format!("durability_at_risk:{}", link.group_id));
            }
            // A copy that is not confirmed yet is the protection dimension ("Not confirmed
            // yet", or "Checking" before the first round), never a reason: there is nothing the
            // person can do about it, and a first sync passes through it.
            GroupDurabilityStatus::Unknown
            | GroupDurabilityStatus::Unspecified
            | GroupDurabilityStatus::Protected
            | GroupDurabilityStatus::Protecting => {}
        }
        // Fetch availability is a wait, not a problem: it is reported as the folder's availability
        // (and the product state Waiting while content is wanted), never as a reason here.
        // Conflicts in the folder and conflicts still being resolved are one reason.
        if link.conflict_count > 0 || link.conflicts_pending > 0 {
            attention_reasons.push(format!("conflict:{}", link.group_id));
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
        // Waiting for the app to finish setting up is a wait, not a fault.
        if root.readiness != "ready"
            && root.readiness != "preparing the folder"
            && root.readiness != crate::provider_status::HANDOFF_ROOT_WAIT_TEXT
        {
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
        // Only a device on another version is a reason (the person updates it). A device that is
        // away or still connecting is availability, shown with when it was last seen, at any
        // duration; a device whose own history cannot catch up says so itself (`rebuild_needed`).
        // The reason names the side to update: that device when it is older, this one when it is
        // newer.
        match peer.version_skew() {
            VersionSkew::Unspecified => {}
            VersionSkew::PeerNewer => {
                attention_reasons.push(format!("peer_newer:{}", peer.device_id));
            }
            _ => attention_reasons.push(format!("peer_update_required:{}", peer.device_id)),
        }
    }
    for error in &response.recent_errors {
        // A failure another reason already explains is not a second item.
        let explained = |codes: &[&str]| {
            degraded_reasons.iter().chain(attention_reasons.iter()).any(|reason| {
                let code = reason.split_once(':').map_or(reason.as_str(), |(code, _)| code);
                codes.contains(&code)
            })
        };
        // Only disk pressure is explained this way: the other categories carry no folder, so
        // another folder's reason cannot be shown to explain them.
        let covered = error.category == "disk_pressure"
            && explained(&["waiting_for_disk_space", "low_disk", "low_disk_critical"]);
        if !covered {
            attention_reasons.push(format!("recent_error:{}", error.category));
        }
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
