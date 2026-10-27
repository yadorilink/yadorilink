//! Pure conversions from the daemon's control-protocol messages and the
//! coordination plane's listings into the product types. Nothing here does
//! I/O; every rule is covered by the unit tests next to this module.
//!
//! Two rules hold throughout: an unset wire value (`0`, an empty string) is
//! `None`, never a real-looking value; and a derivation that already exists
//! (folder state and mode in `yadorilink-product-view`, the conflict-copy
//! name parse, the invite URL) is called, not repeated.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use yadorilink_ipc_proto::daemonctl::EntryKind as WireEntryKind;
use yadorilink_ipc_proto::daemonctl::{
    self as wire, ConflictedFileInfo, FileVersionInfo, GcResponse, HandoffResult, InboxTransfer,
    LinkStatus, MaterializationStatusResponse, MintedInviteInfo, PeerStatus,
    ReceiveTransferResponse, ReplicaMembershipCommandOutcome, RestoreTrashOperationResponse,
    SendFileResponse, StatusResponse, TrashedFileInfo, UpdateConfigResponse, UpdateInstallResponse,
    UpdateStatusResponse, UpdateVerifiedEntryResponse, VolumeFreeSpace,
};
use yadorilink_local_storage::free_space::FreeSpaceState as LocalFreeSpace;
use yadorilink_local_storage::link_preflight::{self, LinkPreflightReport, RiskyLocation};
use yadorilink_product_view as view;

use super::*;
use crate::ops::account::DeletionStatus;
use crate::ops::shares::{GroupMemberInfo, PendingApproval, PendingInviteInfo, ShareEdgeInfo};

// ---- small rules ----------------------------------------------------------

fn text(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

fn unix_secs(secs: i64) -> Option<SystemTime> {
    u64::try_from(secs).ok().filter(|s| *s > 0).map(|s| UNIX_EPOCH + Duration::from_secs(s))
}

fn unix_nanos(nanos: i64) -> Option<SystemTime> {
    u64::try_from(nanos).ok().filter(|n| *n > 0).map(|n| UNIX_EPOCH + Duration::from_nanos(n))
}

fn size(bytes: i64) -> u64 {
    u64::try_from(bytes).unwrap_or(0)
}

fn limit(bytes_per_sec: u64) -> Option<u64> {
    (bytes_per_sec > 0).then_some(bytes_per_sec)
}

fn share_role(raw: &str) -> ShareRole {
    match raw {
        "owner" => ShareRole::Owner,
        "editor" => ShareRole::Editor,
        "viewer" => ShareRole::Viewer,
        other => ShareRole::Other { raw: other.to_owned() },
    }
}

fn free_space_state(raw: &str) -> FreeSpaceState {
    match raw {
        "ok" => FreeSpaceState::Ok,
        "low" => FreeSpaceState::Low,
        "critical" => FreeSpaceState::Critical,
        _ => FreeSpaceState::Unknown,
    }
}

fn update_state(raw: &str) -> UpdateState {
    match raw {
        "idle" => UpdateState::Idle,
        "checking" => UpdateState::Checking,
        "available" => UpdateState::Available,
        "held_back" => UpdateState::HeldBack,
        "kill_switched" => UpdateState::KillSwitched,
        "downloading" => UpdateState::Downloading,
        "downloaded" => UpdateState::Downloaded,
        "verified" => UpdateState::Verified,
        "installing" => UpdateState::Installing,
        "failed" => UpdateState::Failed,
        "deferred" => UpdateState::Deferred,
        "up_to_date" => UpdateState::UpToDate,
        other => UpdateState::Unknown { raw: other.to_owned() },
    }
}

fn reachability(peer: Option<&PeerStatus>) -> PeerReachability {
    match peer.map(PeerStatus::reachability) {
        Some(wire::PeerReachability::Connecting) => PeerReachability::Connecting,
        Some(wire::PeerReachability::Connected) => PeerReachability::Connected,
        Some(wire::PeerReachability::Unreachable) => PeerReachability::Unreachable,
        Some(wire::PeerReachability::Unspecified) | None => PeerReachability::Unknown,
    }
}

fn route(peer: Option<&PeerStatus>) -> RouteKind {
    match peer.map(PeerStatus::route_kind) {
        Some(wire::RouteKind::Direct) => RouteKind::Direct,
        Some(wire::RouteKind::Relay) => RouteKind::Relay,
        Some(wire::RouteKind::Unspecified) | None => RouteKind::Unknown,
    }
}

fn folder_path_of<'a>(links: &'a [LinkStatus], group_id: &str) -> Option<&'a str> {
    links.iter().find(|l| l.group_id == group_id).map(|l| l.local_path.as_str())
}

// ---- status ---------------------------------------------------------------

/// The daemon's whole status as the product snapshot, stamped with the time
/// it was captured.
pub fn status_snapshot(
    response: &StatusResponse,
    account: AccountStatus,
    captured_at: SystemTime,
) -> StatusSnapshot {
    let links = &response.links;
    let product = view::ProductStatusSummary::global(links);
    StatusSnapshot {
        captured_at,
        overall: match response.overall_state.as_str() {
            "healthy" => OverallState::Healthy,
            "attention" => OverallState::Attention,
            "degraded" => OverallState::Degraded,
            _ => OverallState::Unknown,
        },
        attention_reasons: response
            .attention_reasons
            .iter()
            .map(|raw| attention_reason(raw, links, &response.volumes))
            .collect(),
        this_device_id: account.this_device_id.clone(),
        account,
        engine_api_version: (response.host_api_version != 0).then_some(response.host_api_version),
        folders: links
            .iter()
            .map(|l| folder_summary(l, &response.volumes, &response.provider_roots))
            .collect(),
        product: product_summary(&product),
        availability: availability_summary(product.availability),
        protection: protection_summary(product.protection),
        peers: response.peers.iter().map(peer_summary).collect(),
        transfers: response
            .active_transfers
            .iter()
            .map(|t| TransferSummary {
                group_id: t.group_id.clone(),
                folder_local_path: folder_path_of(links, &t.group_id).map(str::to_owned),
                path: t.path.clone(),
                bytes_done: t.bytes_done,
                bytes_total: t.bytes_total,
                blocks_done: t.blocks_done,
                blocks_total: t.blocks_total,
                source_device_id: t.source_peer.clone(),
                started_at: unix_secs(t.started_at_unix),
            })
            .collect(),
        bandwidth: BandwidthStatus {
            limits: BandwidthLimits {
                upload_bytes_per_sec: limit(response.upload_limit_bytes_per_sec),
                download_bytes_per_sec: limit(response.download_limit_bytes_per_sec),
            },
            current_upload_bytes_per_sec: response.current_upload_bytes_per_sec,
            current_download_bytes_per_sec: response.current_download_bytes_per_sec,
        },
        volumes: response.volumes.iter().map(volume_summary).collect(),
        storage: StorageSummary {
            block_store_total_bytes: response.block_store_total_bytes,
            block_count: response.block_store_block_count,
            last_gc_at: unix_secs(response.last_gc_unix),
            reclaimable_estimate_bytes: response.gc_reclaimable_estimate_bytes,
        },
        update: update_badge(response),
        recent_errors: response
            .recent_errors
            .iter()
            .map(|e| RecentError {
                category: e.category.clone(),
                at: unix_secs(e.timestamp_unix),
                context: e.coarse_context.clone(),
            })
            .collect(),
    }
}

fn update_badge(response: &StatusResponse) -> UpdateBadge {
    UpdateBadge {
        state: update_state(&response.update_state),
        available_version: text(&response.update_available_version),
        mandatory: response.update_mandatory,
        last_error_category: text(&response.update_last_error_category),
        channel: response.update_channel.clone(),
        install_source: response.update_install_source.clone(),
        holdback_reason: text(&response.update_holdback_reason),
    }
}

fn volume_summary(volume: &VolumeFreeSpace) -> VolumeSummary {
    VolumeSummary {
        path: volume.path.clone(),
        state: free_space_state(&volume.state),
        available_bytes: volume.available_bytes,
        headroom_bytes: volume.headroom_bytes,
        reclaimable_bytes: volume.reclaimable_bytes,
    }
}

fn peer_summary(peer: &PeerStatus) -> PeerSummary {
    PeerSummary {
        device_id: peer.device_id.clone(),
        reachability: reachability(Some(peer)),
        unreachable_category: match peer.unreachable_category() {
            wire::UnreachableCategory::NoCandidates => Some(UnreachableCategory::NoCandidates),
            wire::UnreachableCategory::NoResponse => Some(UnreachableCategory::NoResponse),
            wire::UnreachableCategory::UdpBlocked => Some(UnreachableCategory::UdpBlocked),
            wire::UnreachableCategory::HandshakeRefused => {
                Some(UnreachableCategory::HandshakeRefused)
            }
            wire::UnreachableCategory::DeviceReplaced => Some(UnreachableCategory::DeviceReplaced),
            wire::UnreachableCategory::Unspecified => None,
        },
        route: route(Some(peer)),
    }
}

/// One `category:subject` reason from the daemon's overall-status rollup.
/// Only the first colon splits, so a subject may contain one. A reason about
/// a folder group names the folder linked to it here.
pub fn attention_reason(
    raw: &str,
    links: &[LinkStatus],
    volumes: &[VolumeFreeSpace],
) -> AttentionReason {
    let attention = view::Attention::from_reason(raw);
    let category = attention_category(attention.item);
    let arg_name = attention.scope.arg_name();
    let about_volume = matches!(attention.scope, view::AttentionScope::Volume(_));
    let (subject, folder_scoped) = match attention.scope {
        view::AttentionScope::Folder(id) => (id, true),
        view::AttentionScope::ProviderFolder(id)
        | view::AttentionScope::Device(id)
        | view::AttentionScope::Volume(id) => (id, false),
        view::AttentionScope::General => {
            (raw.split_once(':').map_or_else(String::new, |(_, s)| s.to_owned()), false)
        }
    };
    let folder_local_path =
        if folder_scoped { folder_path_of(links, &subject).map(str::to_owned) } else { None };
    // What the sentence is about: the subject by its kind, and the folder's place when linked here.
    // A code this build does not know has no subject worth naming.
    let mut args = Vec::new();
    if attention.item != view::AttentionItem::Unrecognized && !subject.is_empty() {
        args.push(AttentionArg { name: arg_name.to_owned(), value: subject.clone() });
    }
    if let Some(path) = &folder_local_path {
        args.push(AttentionArg { name: "folder_path".to_owned(), value: path.clone() });
    }
    let identity = format!("{}:{subject}", attention.item.key());
    let reclaim_available =
        about_volume && volumes.iter().any(|v| v.path == subject && v.reclaimable_bytes > 0);
    AttentionReason {
        category,
        folder_local_path,
        subject,
        raw: raw.to_owned(),
        kind: match attention.item.kind() {
            view::AttentionKind::Waiting => AttentionKind::Waiting,
            view::AttentionKind::Retryable => AttentionKind::Retryable,
            view::AttentionKind::Permanent => AttentionKind::Permanent,
        },
        // Free up space only where the volume the item is about can get space back now.
        primary_action: product_action(attention.item.offered_action(reclaim_available)),
        secondary_action: attention.item.secondary_action().map(product_action),
        key: attention.item.key().to_owned(),
        args,
        severity: match attention.item.severity() {
            view::AttentionSeverity::Info => AttentionSeverity::Info,
            view::AttentionSeverity::Warning => AttentionSeverity::Warning,
            view::AttentionSeverity::Critical => AttentionSeverity::Critical,
        },
        identity,
    }
}

/// The product state, counts and next action, as the shells receive them.
fn product_summary(summary: &view::ProductStatusSummary) -> ProductSummary {
    ProductSummary {
        state: match summary.state {
            view::ProductState::UpToDate => ProductState::UpToDate,
            view::ProductState::Syncing => ProductState::Syncing,
            view::ProductState::Waiting => ProductState::Waiting,
            view::ProductState::NeedsAttention => ProductState::NeedsAttention,
            view::ProductState::Paused => ProductState::Paused,
        },
        attention_count: summary.attention_count,
        paused_count: summary.paused_count,
        syncing_count: summary.syncing_count,
        waiting_count: summary.waiting_count,
        bytes_remaining: summary.bytes_remaining,
        next_action: summary.next_action.map(product_action),
    }
}

fn product_action(action: view::ProductAction) -> ProductAction {
    match action {
        view::ProductAction::Retry => ProductAction::Retry,
        view::ProductAction::ReviewConflict => ProductAction::ReviewConflict,
        view::ProductAction::FreeUpSpace => ProductAction::FreeUpSpace,
        view::ProductAction::RevealPath => ProductAction::RevealPath,
        view::ProductAction::OpenSettings => ProductAction::OpenSettings,
        view::ProductAction::DownloadUpdate => ProductAction::DownloadUpdate,
        view::ProductAction::ViewDetails => ProductAction::ViewDetails,
        view::ProductAction::ReviewApproval => ProductAction::ReviewApproval,
        view::ProductAction::ConfirmDisk => ProductAction::ConfirmDisk,
        view::ProductAction::Resume => ProductAction::Resume,
        view::ProductAction::StartOverAsNewDevice => ProductAction::StartOverAsNewDevice,
        view::ProductAction::SignIn => ProductAction::SignIn,
    }
}

/// The progress of a start over as a new device, as the product type.
pub fn start_over_progress(
    progress: crate::ops::start_over::StartOverProgress,
) -> StartOverProgress {
    use crate::ops::start_over as op;
    match progress {
        op::StartOverProgress::SignInRequired { retired_device_id } => {
            StartOverProgress::SignInRequired { retired_device_id }
        }
        op::StartOverProgress::Finished(report) => StartOverProgress::Finished {
            report: StartOverReport {
                retired_device_id: report.retired_device_id,
                new_device_id: report.new_device_id,
                rejoined: report.rejoined,
                not_rejoined: report
                    .not_rejoined
                    .into_iter()
                    .map(|f| NotRejoined {
                        local_path: f.local_path,
                        group_id: f.group_id,
                        message: f.message,
                    })
                    .collect(),
                complete: report.complete,
            },
        },
    }
}

/// The reporting category a shell knows for an item; held-file reasons have none.
fn attention_category(item: view::AttentionItem) -> AttentionCategory {
    use view::AttentionItem as I;
    match item {
        I::FolderStopped => AttentionCategory::Degraded,
        I::NoSafeCopy => AttentionCategory::DurabilityAtRisk,
        I::SafeCopyUnconfirmed => AttentionCategory::DurabilityUnknown,
        I::ContentUnavailable => AttentionCategory::FetchUnavailable,
        I::ContentAvailabilityUnknown => AttentionCategory::FetchAvailabilityUnknown,
        I::ConflictNeedsReview => AttentionCategory::Conflict,
        I::FileHeld => AttentionCategory::Held,
        I::StrandedDirectory => AttentionCategory::StrandedDirectory,
        I::DiskFull => AttentionCategory::LowDiskCritical,
        I::DiskLow => AttentionCategory::LowDisk,
        I::PeerUnavailable => AttentionCategory::PeerDisconnected,
        I::RetryableFailure => AttentionCategory::RecentError,
        I::UpdateFailed => AttentionCategory::UpdateFailed,
        I::UpdateRequired => AttentionCategory::UpdateRequired,
        I::LinkedTwice => AttentionCategory::Ambiguous,
        I::OwnershipLost => AttentionCategory::OwnershipLost,
        I::VolumeChanged => AttentionCategory::VolumeChanged,
        I::VolumeUnconfirmed => AttentionCategory::VolumeUnconfirmed,
        I::ProviderNotReady => AttentionCategory::ProviderNotReady,
        I::ProviderFilesFailing => AttentionCategory::ProviderStuck,
        I::EditsKeptBeside => AttentionCategory::KeptEdits,
        I::ProviderOrphan => AttentionCategory::ProviderOrphanDomain,
        // Held-file reasons never arrive through the rollup, so no shell category exists for them.
        // Keyed-only items: no shell category; the key, severity and args carry them (status-model.md).
        I::ProviderRegistryRestored
        | I::ApprovalPending
        | I::DatabaseRestored
        | I::AuthorUnavailable
        | I::WaitingForDiskSpace
        | I::ReplacementUnconfirmed
        | I::ReplacementWaiting
        | I::ReplacementSignInRequired
        | I::TermsConsentRequired
        | I::SignInRequired
        | I::AccountDeletionPending
        | I::AccountDeletionUrgent
        | I::NotJoined
        | I::FileWatchLimit
        | I::UnreadableFiles
        | I::UnsupportedFilename
        | I::FileNotReadable
        | I::Unrecognized => AttentionCategory::Unrecognized,
    }
}

fn degraded_cause(cause: view::DegradedCause) -> DegradedCause {
    match cause {
        view::DegradedCause::Stopped => DegradedCause::Stopped,
        view::DegradedCause::WaitingForDiskSpace => DegradedCause::WaitingForDiskSpace,
        view::DegradedCause::FileWatchLimit => DegradedCause::FileWatchLimit,
        view::DegradedCause::OwnershipLost => DegradedCause::OwnershipLost,
        view::DegradedCause::NotJoined => DegradedCause::NotJoined,
    }
}

/// One linked folder. State, mode and name come from the shared
/// `yadorilink-product-view` derivation; this only changes their shape.
pub fn folder_summary(
    link: &LinkStatus,
    volumes: &[VolumeFreeSpace],
    provider_roots: &[wire::ProviderRootStatus],
) -> FolderSummary {
    let derived = view::FolderSummary::from(link);
    let (unreadable_files, unreadable_files_more) = unreadable_files(link);
    FolderSummary {
        local_path: derived.local_path,
        group_id: derived.group_id,
        name: derived.name,
        mode: match derived.mode {
            view::FolderMode::Synced => FolderMode::KeepAll,
            view::FolderMode::Selective => FolderMode::OnDemand,
        },
        state: match derived.state {
            view::FolderState::UpToDate => FolderState::UpToDate,
            view::FolderState::Syncing => FolderState::Syncing,
            view::FolderState::Paused => FolderState::Paused,
            view::FolderState::Blocked => FolderState::Blocked,
            view::FolderState::Attention => FolderState::Attention,
        },
        paused: derived.paused,
        paused_until: if derived.paused { unix_secs(link.paused_until_unix) } else { None },
        conflict_count: derived.conflict_count,
        hydrated_file_count: derived.files_hydrated,
        placeholder_file_count: derived.files_placeholder,
        hydrating_file_count: derived.files_hydrating,
        held_file_count: derived.held_file_count,
        skipped_symlink_count: derived.skipped_symlink_count,
        transfer: derived.transfer.map(|t| FolderTransferProgress {
            bytes_done: t.bytes_done,
            bytes_total: t.bytes_total,
            blocks_done: t.blocks_done,
            blocks_total: t.blocks_total,
            eta: (t.eta_seconds > 0).then(|| Duration::from_secs(t.eta_seconds)),
        }),
        durability: match derived.durability_status {
            view::folder::DurabilityStatus::Protected => DurabilityStatus::Protected,
            view::folder::DurabilityStatus::Protecting => DurabilityStatus::Protecting,
            view::folder::DurabilityStatus::AtRisk => DurabilityStatus::AtRisk,
            view::folder::DurabilityStatus::Unknown
            | view::folder::DurabilityStatus::Unspecified => DurabilityStatus::Unknown,
        },
        durability_evidence: match link.durability_evidence() {
            wire::DurabilityEvidence::None => DurabilityEvidence::None,
            wire::DurabilityEvidence::CorroboratedIndex => DurabilityEvidence::CorroboratedIndex,
            wire::DurabilityEvidence::VerifiedPayload => DurabilityEvidence::VerifiedPayload,
            wire::DurabilityEvidence::Unspecified => DurabilityEvidence::Unknown,
        },
        local_storage: match derived.local_storage_state {
            wire::LocalStorageState::FullCopy => LocalStorageState::FullCopy,
            wire::LocalStorageState::PartiallyMaterialized => {
                LocalStorageState::PartiallyMaterialized
            }
            wire::LocalStorageState::OnDemand => LocalStorageState::OnDemand,
            wire::LocalStorageState::Unspecified => LocalStorageState::Unknown,
        },
        fetch_availability: match derived.fetch_availability {
            wire::FetchAvailability::AvailableNow => FetchAvailability::AvailableNow,
            wire::FetchAvailability::UnavailableNow => FetchAvailability::UnavailableNow,
            wire::FetchAvailability::Unknown | wire::FetchAvailability::Unspecified => {
                FetchAvailability::Unknown
            }
        },
        availability: availability_summary(view::AvailabilitySummary::from_link(link)),
        protection: protection_summary(view::ProtectionSummary::from_link(link)),
        product: product_summary(&view::ProductStatusSummary::for_folder(link)),
        full_replica_device_ids: derived.full_replica_device_ids,
        policy_stale: derived.policy_stale,
        ambiguous: derived.ambiguous,
        ambiguous_local_paths: derived.ambiguous_local_paths,
        degraded: derived.degraded,
        degraded_reason: text(&derived.degraded_reason),
        degraded_cause: derived.degraded_cause.map(degraded_cause),
        volume: volumes.iter().find(|v| v.path == link.local_path).map(volume_summary),
        provider: !link.provider_display_name.is_empty(),
        provider_status: provider_status(link, provider_roots),
        pending_approvals: link.pending_approvals,
        reclaimable_bytes: link.reclaimable_bytes,
        unreadable_files,
        unreadable_files_more,
    }
}

/// The folder's unreadable files, safe for a shell to show: at most [`MAX_UNREADABLE_FILES`], each
/// path relative to the folder. An entry that is empty, absolute, or climbs out of the folder is
/// not shown but still counted in the second value (the folder stays in attention; the count is
/// never lowered). `unreadable_file_count` is the daemon's full count; a daemon that sent a list
/// longer than its count is trusted for the list.
fn unreadable_files(link: &LinkStatus) -> (Vec<UnreadableFile>, u64) {
    let shown: Vec<UnreadableFile> = link
        .unreadable_files
        .iter()
        .filter(|f| is_folder_relative(&f.path))
        .take(MAX_UNREADABLE_FILES)
        .map(|f| {
            let reason = unreadable_reason(&f.reason);
            UnreadableFile {
                path: f.path.clone(),
                reason,
                advice_key: reason.advice_key().to_owned(),
            }
        })
        .collect();
    let total = link.unreadable_file_count.max(link.unreadable_files.len() as u64);
    let more = total - shown.len() as u64;
    (shown, more)
}

fn unreadable_reason(code: &str) -> UnreadableFileReason {
    match code {
        "permission_denied" => UnreadableFileReason::PermissionDenied,
        "not_a_regular_file" => UnreadableFileReason::NotARegularFile,
        "read_failed" => UnreadableFileReason::ReadFailed,
        _ => UnreadableFileReason::Unknown,
    }
}

fn is_folder_relative(path: &str) -> bool {
    let drive_letter = path.as_bytes().get(1) == Some(&b':')
        && path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic);
    !path.is_empty()
        && !path.starts_with('/')
        && !drive_letter
        && !path.split('/').any(|p| p == "..")
}

/// The status line of the provider root this link belongs to. The link carries the root's full id,
/// the line only its first 8 digits.
fn provider_status(
    link: &LinkStatus,
    roots: &[wire::ProviderRootStatus],
) -> Option<ProviderRootStatus> {
    if link.provider_root_id.is_empty() {
        return None;
    }
    let root = roots
        .iter()
        .find(|r| !r.root_id.is_empty() && link.provider_root_id.starts_with(&r.root_id))?;
    let count = |count: u64, oldest_ms: u64| ProviderCount {
        count,
        oldest: (count > 0).then(|| Duration::from_millis(oldest_ms)),
    };
    Some(ProviderRootStatus {
        root_id: root.root_id.clone(),
        display_name: root.display_name.clone(),
        readiness: root.readiness.clone(),
        sync_root_path: (!root.sync_root_path.is_empty()).then(|| root.sync_root_path.clone()),
        counters: (!root.counters_unreadable).then(|| ProviderCounters {
            eager: root.eager.then(|| ProviderEagerProgress {
                state: root.eager_state.clone(),
                remote: root.eager_remote,
                hydrating: root.eager_hydrating,
                current: root.eager_current,
            }),
            stuck: root
                .stuck
                .iter()
                .map(|s| ProviderStuckFile { path: s.path.clone(), failures: s.failures })
                .collect(),
            kept_edits: count(root.kept_edits, root.kept_edits_oldest_ms),
            pending_publications: count(root.pending_publications, root.pending_oldest_ms),
            unconfirmed_publications: count(
                root.unconfirmed_publications,
                root.unconfirmed_oldest_ms,
            ),
        }),
    })
}

/// The folders' availability, protection and never-downloaded file count and the overall answer
/// as JSON, for `status --json`.
/// States are the stable snake_case names `yadorilink-product-view` documents; device ids are for
/// lookup, never display.
pub fn status_dimensions_json(response: &StatusResponse) -> serde_json::Value {
    fn availability(summary: &view::AvailabilitySummary) -> serde_json::Value {
        serde_json::json!({
            "state": summary.availability.as_str(),
            "reachable_device_ids": summary.reachable_device_ids,
            "offline_device_ids": summary.offline_device_ids,
            "update_required_device_ids": summary.update_required_device_ids,
        })
    }
    fn protection(summary: &view::ProtectionSummary) -> serde_json::Value {
        serde_json::json!({
            "state": summary.protection.as_str(),
            "device_ids": summary.device_ids,
        })
    }

    let overall = view::ProductStatusSummary::global(&response.links);
    let folders: Vec<_> = response
        .links
        .iter()
        .map(|link| {
            serde_json::json!({
                "local_path": link.local_path,
                "group_id": link.group_id,
                "on_demand": link.materialization_policy == "ondemand",
                // Files whose content is not on this computer; an uninstaller warns about them.
                "placeholder_count": link.placeholder_count,
                "availability": availability(&view::AvailabilitySummary::from_link(link)),
                "protection": protection(&view::ProtectionSummary::from_link(link)),
                // Why the folder is degraded, as the attention code the rollup reports for it
                // (`waiting_for_disk_space`, `file_watch_limit`, ...); null when it is not.
                "degraded_cause": view::DegradedCause::of(link).map(|c| c.item().key()),
            })
        })
        .collect();
    serde_json::json!({
        "overall_state": response.overall_state,
        "availability": availability(&overall.availability),
        "protection": protection(&overall.protection),
        "folders": folders,
    })
}

fn availability_summary(summary: view::AvailabilitySummary) -> AvailabilitySummary {
    AvailabilitySummary {
        availability: match summary.availability {
            view::Availability::Available => Availability::Available,
            view::Availability::UpdateRequired => Availability::UpdateRequired,
            view::Availability::WaitingForPeer => Availability::WaitingForPeer,
            view::Availability::WaitingForExactContent => Availability::WaitingForExactContent,
            view::Availability::Unknown => Availability::Unknown,
        },
        reachable_device_ids: summary.reachable_device_ids,
        offline_device_ids: summary.offline_device_ids,
        update_required_device_ids: summary.update_required_device_ids,
    }
}

fn protection_summary(summary: view::ProtectionSummary) -> ProtectionSummary {
    ProtectionSummary {
        protection: match summary.protection {
            view::Protection::Protected => Protection::Protected,
            view::Protection::AtRisk => Protection::AtRisk,
            view::Protection::Pending => Protection::Pending,
            view::Protection::Unknown => Protection::Unknown,
        },
        device_ids: summary.device_ids,
    }
}

/// The detail view of the folder linked at `local_path`, or `None` when no
/// folder is linked there. Every complete copy is listed with this device's
/// current connection to it; a device the daemon reports nothing about reads
/// as unknown, not offline.
pub fn folder_detail(response: &StatusResponse, local_path: &str) -> Option<FolderDetail> {
    let link = response.links.iter().find(|l| l.local_path == local_path)?;
    Some(FolderDetail {
        summary: folder_summary(link, &response.volumes, &response.provider_roots),
        held_files: link
            .held_files
            .iter()
            .map(|h| HeldFile {
                path: h.path.clone(),
                reason: h.reason.clone(),
                held_since: unix_nanos(h.held_since_unix_nanos),
            })
            .collect(),
        complete_copies: link
            .full_replica_device_ids
            .iter()
            .map(|device_id| {
                let peer = response.peers.iter().find(|p| &p.device_id == device_id);
                ReplicaCopy {
                    device_id: device_id.clone(),
                    reachability: reachability(peer),
                    route: route(peer),
                }
            })
            .collect(),
    })
}

// ---- files ----------------------------------------------------------------

pub fn conflict_summary(file: &ConflictedFileInfo) -> ConflictSummary {
    let detail = view::conflict_detail(file);
    ConflictSummary {
        local_path: file.local_path.clone(),
        path: file.path.clone(),
        size: size(file.size),
        modified_at: unix_nanos(file.mtime_unix_nanos),
        current_path: detail.current_path,
        loser_device_id: detail.loser_device_id,
        conflict_timestamp: detail.timestamp,
        kind: entry_kind(file.kind()),
        reason: match detail.reason {
            view::ConflictReason::ConcurrentEdit => ConflictReason::ConcurrentEdit,
            view::ConflictReason::FolderAtPath => ConflictReason::FolderAtPath,
        },
        can_resolve: file.resolvable,
        origin_device_id: text(&file.origin_device_id),
        identity: conflict_identity(&file.local_path, &file.path),
    }
}

/// The identity of one conflict: a copy is identified by its own path under its folder's root (its
/// name carries the conflict's timestamp, so a later conflict of the same file is another one).
/// The root's length keeps two different splits of the same text apart.
fn conflict_identity(local_path: &str, path: &str) -> String {
    format!("conflict_needs_review:{}:{local_path}:{path}", local_path.len())
}

/// An unset kind is a sender that never classified the record, and every
/// such record is a file.
fn entry_kind(kind: WireEntryKind) -> EntryKind {
    match kind {
        WireEntryKind::Unspecified | WireEntryKind::File => EntryKind::File,
        WireEntryKind::Directory => EntryKind::Directory,
        WireEntryKind::Symlink => EntryKind::Symlink,
    }
}

pub fn trashed_file(file: &TrashedFileInfo) -> TrashedFile {
    TrashedFile {
        local_path: file.local_path.clone(),
        path: file.path.clone(),
        version_seq: file.version_seq,
        last_known_size: size(file.last_known_size),
        origin_device_id: text(&file.origin_device_id),
        deleted_at: unix_nanos(file.deleted_at_unix_nanos),
        kind: entry_kind(file.kind()),
        deleted_by_operation: text(&file.deleted_by_operation),
    }
}

pub fn folder_restore_outcome(outcome: &RestoreTrashOperationResponse) -> FolderRestoreOutcome {
    FolderRestoreOutcome {
        restored_paths: outcome.restored_paths.clone(),
        failed: outcome
            .failed
            .iter()
            .map(|failure| FolderRestoreFailure {
                path: failure.path.clone(),
                error: failure.error.clone(),
            })
            .collect(),
        partial: outcome.partial,
    }
}

pub fn file_version(version: &FileVersionInfo, is_current: bool) -> FileVersion {
    FileVersion {
        version_seq: version.version_seq,
        size: size(version.size),
        modified_at: unix_nanos(version.mtime_unix_nanos),
        state: version.state.clone(),
        origin_device_id: text(&version.origin_device_id),
        unix_mode: version.unix_mode,
        is_current,
        kind: entry_kind(version.kind()),
    }
}

/// Every retained version, in the daemon's order, with the highest
/// `version_seq` marked current.
pub fn file_versions(versions: &[FileVersionInfo]) -> Vec<FileVersion> {
    let current = versions.iter().map(|v| v.version_seq).max();
    versions.iter().map(|v| file_version(v, Some(v.version_seq) == current)).collect()
}

pub fn file_availability(status: &MaterializationStatusResponse) -> FileAvailability {
    FileAvailability {
        tracked: status.known,
        // The UI vocabulary has one word for "the current content is on this
        // device" and one for "it is not" (an older object that stands is not
        // current content, so it is offered for download like a remote file).
        state: match status.local_state.as_ref() {
            None => MaterializationState::Unknown,
            Some(local) => match local.transition() {
                wire::LocalTransition::Hydrating => MaterializationState::Hydrating,
                wire::LocalTransition::Evicting => MaterializationState::Evicting,
                wire::LocalTransition::None if local.current_content_present => {
                    MaterializationState::Hydrated
                }
                wire::LocalTransition::None => MaterializationState::Placeholder,
            },
        },
        // The daemon's own list. A value this build does not know is dropped, so an action it
        // cannot present is never offered.
        actions: status
            .available_actions
            .iter()
            .filter_map(|a| match wire::FileAction::try_from(*a) {
                Ok(wire::FileAction::Download) => Some(FileAction::Download),
                Ok(wire::FileAction::FreeUpSpace) => Some(FileAction::FreeUpSpace),
                Ok(wire::FileAction::KeepOnDevice) => Some(FileAction::KeepOnDevice),
                Ok(wire::FileAction::StopKeeping) => Some(FileAction::StopKeeping),
                Ok(wire::FileAction::Unspecified) | Err(_) => None,
            })
            .collect(),
    }
}

/// The retention policy a status reply carries. A reply without one (nothing says the path is
/// kept) reads as reclaimable.
pub fn file_retention(retention: Option<&wire::RetentionState>) -> FileRetention {
    match retention {
        Some(state) if state.policy() == wire::RetentionPolicy::Pinned => {
            FileRetention { policy: RetentionPolicy::Pinned, inherited: !state.explicit }
        }
        _ => FileRetention { policy: RetentionPolicy::Reclaimable, inherited: false },
    }
}

pub fn pin_outcome(response: &wire::PinItemResponse) -> PinOutcome {
    PinOutcome {
        retention: file_retention(response.retention.as_ref()),
        download_error: Some(response.download_error.clone()).filter(|e| !e.is_empty()),
    }
}

// ---- membership and shares ---------------------------------------------------

pub fn handoff_summary(handoff: &HandoffResult) -> HandoffSummary {
    HandoffSummary {
        target_device_id: handoff.target_device_id.clone(),
        membership_generation: handoff.membership_generation,
        lease_id: text(&handoff.lease_id),
    }
}

pub fn membership_outcome(outcome: &ReplicaMembershipCommandOutcome) -> MembershipOutcome {
    MembershipOutcome {
        handoffs: outcome
            .handoffs
            .iter()
            .map(|h| MembershipHandoff {
                group_id: h.group_id.clone(),
                target_device_id: h.target_device_id.clone(),
                lease_id: h.lease_id.clone(),
                membership_generation: h.membership_generation,
            })
            .collect(),
        forced_group_ids: outcome.forced_group_ids.clone(),
        unknown_scope_operation_id: text(&outcome.unknown_scope_operation_id),
    }
}

/// One member of a folder group, relative to whoever is looking: the same
/// rules as the command line's member listing.
pub fn member_summary(member: &GroupMemberInfo, own_device_id: Option<&str>) -> MemberSummary {
    let relationship = if own_device_id == Some(member.device_id.as_str()) {
        MemberRelationship::You
    } else if member.is_caller_account {
        MemberRelationship::YourOtherDevice
    } else if member.is_same_account {
        MemberRelationship::OwnersDevice
    } else {
        MemberRelationship::Invited
    };
    MemberSummary {
        device_id: member.device_id.clone(),
        device_name: member.device_name.clone(),
        role: share_role(&member.role),
        relationship,
        // Only "eager" is a full copy; an unrecognized mode understates.
        storage: if member.storage_mode == "eager" {
            MemberStorage::FullCopy
        } else {
            MemberStorage::OnDemand
        },
        online: member.online,
        last_seen: unix_secs(member.last_seen_unix),
    }
}

pub fn pending_approval_summary(pending: &PendingApproval) -> PendingApprovalSummary {
    PendingApprovalSummary {
        group_id: pending.group_id.clone(),
        group_name: pending.group_name.clone(),
        device_id: pending.device_id.clone(),
        requested_role: pending.role.as_deref().map(share_role),
    }
}

pub fn share_summary(edge: &ShareEdgeInfo) -> ShareSummary {
    ShareSummary {
        edge_id: edge.edge_id.clone(),
        group_id: edge.group_id.clone(),
        group_name: edge.group_name.clone(),
        device_id: edge.device_id.clone(),
        state: match edge.state.as_str() {
            "active" => ShareEdgeState::Active,
            crate::ops::shares::STATE_PENDING_APPROVAL => ShareEdgeState::PendingApproval,
            other => ShareEdgeState::Other { raw: other.to_owned() },
        },
        role: edge.role.as_deref().map(share_role),
    }
}

pub fn invite_summary(invite: &MintedInviteInfo) -> InviteSummary {
    InviteSummary {
        invite_id: invite.invite_id.clone(),
        code: invite.code.clone(),
        url: crate::wording::invite_url(&invite.code),
        group_id: invite.group_id.clone(),
        role: share_role(&invite.role),
        expires_at: unix_secs(invite.expires_at_unix).unwrap_or(UNIX_EPOCH),
        requires_approval: invite.requires_approval,
    }
}

pub fn pending_invite_summary(invite: &PendingInviteInfo) -> PendingInviteSummary {
    PendingInviteSummary {
        invite_id: invite.invite_id.clone(),
        group_id: invite.group_id.clone(),
        group_name: invite.group_name.clone(),
        role: share_role(&invite.role),
        expires_at: unix_secs(invite.expires_at_unix).unwrap_or(UNIX_EPOCH),
        status: match invite.status.as_str() {
            "pending" => InviteStatus::Pending,
            other => InviteStatus::Other { raw: other.to_owned() },
        },
    }
}

// ---- linking ----------------------------------------------------------------

/// The preflight report as typed issues, in the same order as the report's
/// own warning lines, so a front end can show them one to one.
pub fn preflight_result(resolved_path: &Path, report: &LinkPreflightReport) -> PreflightResult {
    PreflightResult {
        resolved_path: resolved_path.to_string_lossy().into_owned(),
        path_exists: report.path_exists,
        is_directory: report.is_directory,
        entry_count: report.entry_count,
        ignored_entry_count: report.ignored_entry_count,
        total_size_bytes: report.total_size_bytes,
        scan_truncated: report.scan_truncated,
        free_space: report.free_space.map(|space| FreeSpace {
            available_bytes: space.available_bytes,
            total_bytes: space.total_bytes,
            headroom_bytes: space.headroom_bytes,
            state: match space.classify() {
                LocalFreeSpace::Ok => FreeSpaceState::Ok,
                LocalFreeSpace::Low => FreeSpaceState::Low,
                LocalFreeSpace::Critical => FreeSpaceState::Critical,
            },
        }),
        issues: preflight_issues(report),
        requires_acknowledgement: report.is_risky(),
    }
}

fn preflight_issues(report: &LinkPreflightReport) -> Vec<PreflightIssue> {
    if !report.path_exists {
        return vec![PreflightIssue::PathMissing];
    }
    let mut issues = Vec::new();
    if report.ignore_rules_unreadable {
        issues.push(PreflightIssue::IgnoreRulesUnreadable);
    }
    if !report.is_empty_folder() {
        issues.push(PreflightIssue::NotEmpty {
            entry_count: report.entry_count,
            scan_truncated: report.scan_truncated,
        });
    }
    if let Some(space) = report.free_space {
        let (available_bytes, headroom_bytes) = (space.available_bytes, space.headroom_bytes);
        match space.classify() {
            LocalFreeSpace::Critical => {
                issues.push(PreflightIssue::CriticalFreeSpace { available_bytes, headroom_bytes });
            }
            LocalFreeSpace::Low => {
                issues.push(PreflightIssue::LowFreeSpace { available_bytes, headroom_bytes });
            }
            LocalFreeSpace::Ok => {}
        }
    }
    for conflict in &report.nested_conflicts {
        issues.push(PreflightIssue::NestedLink {
            other_path: conflict.other_path.clone(),
            relation: match conflict.relation {
                link_preflight::NestedLinkRelation::Ancestor => NestedLinkRelation::Ancestor,
                link_preflight::NestedLinkRelation::Descendant => NestedLinkRelation::Descendant,
                link_preflight::NestedLinkRelation::Same => NestedLinkRelation::Same,
            },
        });
    }
    match &report.risky_location {
        Some(RiskyLocation::CloudProviderFolder(provider)) => {
            issues.push(PreflightIssue::CloudProviderFolder { provider: (*provider).to_owned() });
        }
        Some(RiskyLocation::FilesystemRoot) => issues.push(PreflightIssue::FilesystemRoot),
        Some(RiskyLocation::HomeDirectory) => issues.push(PreflightIssue::HomeDirectory),
        None => {}
    }
    for path in &report.reserved_namespace_blocked_paths {
        issues.push(PreflightIssue::ReservedName { path: path.clone() });
    }
    issues
}

// ---- transfers, storage, updates, account --------------------------------------

pub fn sent_transfer(sent: SendFileResponse) -> SentTransfer {
    SentTransfer {
        transfer_id: sent.transfer_id,
        files_offered: sent.files_offered,
        total_size: sent.total_size,
    }
}

pub fn incoming_transfer(transfer: &InboxTransfer) -> IncomingTransfer {
    IncomingTransfer {
        transfer_id: transfer.transfer_id.clone(),
        sender_device_id: transfer.sender_device_id.clone(),
        files: transfer
            .files
            .iter()
            .map(|f| IncomingFile { relative_path: f.relative_path.clone(), size: f.size })
            .collect(),
        total_size: transfer.total_size,
        offered_at: unix_nanos(transfer.offered_at_unix_nanos),
        status: match transfer.status.as_str() {
            "pending" => IncomingTransferStatus::Pending,
            "in_progress" => IncomingTransferStatus::InProgress,
            "completed" => IncomingTransferStatus::Completed,
            "failed" => IncomingTransferStatus::Failed,
            "canceled" => IncomingTransferStatus::Canceled,
            other => IncomingTransferStatus::Other { raw: other.to_owned() },
        },
        failure: transfer_failure(&transfer.failure),
        can_retry: matches!(transfer.status.as_str(), "failed" | "canceled"),
    }
}

fn transfer_failure(code: &str) -> Option<TransferFailure> {
    Some(match code {
        "" => return None,
        "unreachable" => TransferFailure::Unreachable,
        "declined" => TransferFailure::Declined,
        "sender_canceled" => TransferFailure::SenderCanceled,
        "not_accepted" => TransferFailure::NotAccepted,
        "rejected" => TransferFailure::Rejected,
        "verification_failed" => TransferFailure::VerificationFailed,
        "local_storage" => TransferFailure::LocalStorage,
        "stalled" => TransferFailure::Stalled,
        "interrupted" => TransferFailure::Interrupted,
        other => TransferFailure::Other { raw: other.to_owned() },
    })
}

pub fn outgoing_transfer(
    transfer: &yadorilink_ipc_proto::daemonctl::SentTransferEntry,
) -> OutgoingTransfer {
    OutgoingTransfer {
        transfer_id: transfer.transfer_id.clone(),
        target_device_id: transfer.target_device_id.clone(),
        files: transfer
            .files
            .iter()
            .map(|f| IncomingFile { relative_path: f.relative_path.clone(), size: f.size })
            .collect(),
        total_size: transfer.total_size,
        created_at: unix_nanos(transfer.created_at_unix_nanos),
        status: match transfer.status.as_str() {
            "offered" => OutgoingTransferStatus::Offered,
            "accepted" => OutgoingTransferStatus::Accepted,
            "completed" => OutgoingTransferStatus::Completed,
            "declined" => OutgoingTransferStatus::Declined,
            "canceled" => OutgoingTransferStatus::Canceled,
            other => OutgoingTransferStatus::Other { raw: other.to_owned() },
        },
        failure: transfer_failure(&transfer.failure),
        can_retry: transfer.can_retry,
    }
}

pub fn retained_original(
    item: &yadorilink_ipc_proto::daemonctl::RetainedOriginal,
) -> RetainedOriginal {
    RetainedOriginal {
        group_id: item.group_id.clone(),
        path: item.path.clone(),
        size: item.size,
        reachable: item.reachable,
        group_removed: item.group_removed,
    }
}

pub fn retained_release(
    done: &yadorilink_ipc_proto::daemonctl::RetainedRelease,
) -> RetainedRelease {
    RetainedRelease {
        path: done.path.clone(),
        outcome: match done.outcome.as_str() {
            "removed" => RetainedReleaseOutcome::Removed,
            "gone" => RetainedReleaseOutcome::Gone,
            "still_retained" => RetainedReleaseOutcome::StillRetained,
            "saved_then_removed" => RetainedReleaseOutcome::SavedThenRemoved,
            "saved_still_retained" => RetainedReleaseOutcome::SavedStillRetained,
            "left" => RetainedReleaseOutcome::Left,
            _ => RetainedReleaseOutcome::Unknown,
        },
        detail: done.detail.clone(),
    }
}

pub fn space_management(
    settings: Option<&yadorilink_ipc_proto::daemonctl::SpaceManagementSettings>,
) -> SpaceManagement {
    // An answer without settings is Off, never On.
    settings.map_or(SpaceManagement { enabled: false }, |s| SpaceManagement { enabled: s.enabled })
}

pub fn space_reclaim_preview(
    response: &yadorilink_ipc_proto::daemonctl::PreviewSpaceReclaimResponse,
) -> SpaceReclaimPreview {
    use yadorilink_ipc_proto::daemonctl::SpaceReclaimVerdict as Wire;
    SpaceReclaimPreview {
        items: response
            .items
            .iter()
            .map(|item| SpaceReclaimPreviewItem {
                group_id: item.group_id.clone(),
                path: item.path.clone(),
                verdict: match item.verdict() {
                    Wire::Eligible => SpaceReclaimVerdict::Eligible,
                    Wire::Pinned => SpaceReclaimVerdict::Pinned,
                    Wire::UnsupportedRoot => SpaceReclaimVerdict::UnsupportedRoot,
                    Wire::CustodyUnavailable => SpaceReclaimVerdict::CustodyUnavailable,
                    Wire::Busy => SpaceReclaimVerdict::Busy,
                    Wire::Changed => SpaceReclaimVerdict::Changed,
                    // An unset or unknown verdict never reads as eligible.
                    Wire::SafetyBlocked | Wire::Unspecified => SpaceReclaimVerdict::SafetyBlocked,
                },
            })
            .collect(),
        unreadable_roots: response.unreadable_roots,
    }
}

pub fn received_transfer(received: ReceiveTransferResponse) -> ReceivedTransfer {
    ReceivedTransfer {
        destination_dir: received.destination_dir,
        files_received: received.files_received,
        bytes_received: received.bytes_received,
    }
}

pub fn gc_report(dry_run: bool, report: &GcResponse) -> GcReport {
    GcReport {
        dry_run,
        blocks_deleted: report.blocks_deleted,
        bytes_reclaimed: report.bytes_reclaimed,
    }
}

pub fn safe_stop_outcome(answer: &wire::RequestSafeStopResponse) -> SafeStopOutcome {
    use wire::request_safe_stop_response::Outcome;
    match &answer.outcome {
        Some(Outcome::Stopping(s)) => {
            SafeStopOutcome::Stopping { already_in_progress: s.already_in_progress }
        }
        Some(Outcome::Busy(busy)) => SafeStopOutcome::Busy {
            reason: match wire::SafeStopBusyReason::try_from(busy.reason) {
                Ok(wire::SafeStopBusyReason::CheckpointFailed) => {
                    SafeStopBusyReason::CheckpointFailed
                }
                Ok(wire::SafeStopBusyReason::AnotherRequestInProgress) => {
                    SafeStopBusyReason::AnotherRequestInProgress
                }
                // Writes in progress, and a reason this build does not know: both mean "not now".
                _ => SafeStopBusyReason::WritesInProgress,
            },
            retry_after_secs: busy.retry_after_secs.max(1),
            detail: busy.detail.clone(),
        },
        // An answer with no outcome is not a stop: treat it as busy rather than as success.
        None => SafeStopOutcome::Busy {
            reason: SafeStopBusyReason::WritesInProgress,
            retry_after_secs: 5,
            detail: "the daemon gave no outcome".into(),
        },
    }
}

fn daemon_owner(raw: &str) -> DaemonOwner {
    // Only the app distributions are `gui`; anything else is the headless one.
    if raw == "gui" {
        DaemonOwner::Gui
    } else {
        DaemonOwner::Cli
    }
}

pub fn daemon_identity(identity: &wire::IdentifyResponse) -> DaemonIdentity {
    let ownership = match wire::OwnershipRecordStatus::try_from(identity.ownership_status) {
        Ok(wire::OwnershipRecordStatus::Recorded) => match &identity.ownership_record {
            Some(r) => DataAreaOwnership::Recorded {
                record: OwnershipRecordSummary {
                    owner: daemon_owner(&r.owner),
                    install_source: r.install_source.clone(),
                    install_root: r.install_root.clone(),
                    release_id: text(&r.release_id),
                    written_at: unix_secs(r.written_at_unix as i64),
                },
            },
            None => DataAreaOwnership::Unreadable { detail: "the record is missing".into() },
        },
        Ok(wire::OwnershipRecordStatus::Missing) => DataAreaOwnership::NotRecorded,
        // Unreadable, and a status this build does not know: the owner cannot be told.
        _ => DataAreaOwnership::Unreadable { detail: identity.ownership_detail.clone() },
    };
    DaemonIdentity {
        version: identity.version.clone(),
        engine_api_version: identity.engine_api_version,
        release_id: text(&identity.release_id),
        install_source: identity.install_source.clone(),
        install_root: identity.install_root.clone(),
        owner: daemon_owner(&identity.owner),
        ownership,
        pid: identity.pid,
        started_at: unix_secs(identity.started_at_unix as i64),
    }
}

pub fn update_status(status: &UpdateStatusResponse) -> UpdateStatus {
    UpdateStatus {
        current_version: status.current_version.clone(),
        channel: status.channel.clone(),
        install_source: status.install_source.clone(),
        last_checked_at: unix_secs(status.last_check_unix),
        last_successful_check_at: unix_secs(status.last_success_unix),
        manifest_expires_at: text(&status.manifest_expires_at),
        manifest_expired: status.manifest_expired,
        state: update_state(&status.state),
        available_version: text(&status.available_version),
        release_notes_url: text(&status.release_notes_url),
        mandatory: status.mandatory,
        holdback_reason: text(&status.holdback_reason),
        last_error_category: text(&status.last_error_category),
        last_error_message: text(&status.last_error_message),
        package_managed: crate::ops::updates::is_package_managed(&status.install_source),
        config: UpdateConfig { automatic_checks: status.automatic_checks_enabled },
    }
}

pub fn appcast_item_check(resp: &UpdateVerifiedEntryResponse) -> AppcastItemCheck {
    use AppcastItemReason as R;
    let outcome = match resp.outcome.as_str() {
        "allowed" => AppcastItemOutcome::Allowed,
        "refused" => AppcastItemOutcome::Refused,
        "cannot_confirm" => AppcastItemOutcome::CannotConfirm,
        other => AppcastItemOutcome::Unknown { raw: other.to_owned() },
    };
    let reason = (!resp.reason_code.is_empty()).then(|| match resp.reason_code.as_str() {
        "not_checked" => R::NotChecked,
        "stale" => R::Stale,
        "manifest_expired" => R::ManifestExpired,
        "no_manifest" => R::NoManifest,
        "invalid_version" => R::InvalidVersion,
        "withdrawn" => R::Withdrawn,
        "kill_switched" => R::KillSwitched,
        "below_minimum" => R::BelowMinimum,
        "not_offered" => R::NotOffered,
        "version_mismatch" => R::VersionMismatch,
        "held_back" => R::HeldBack,
        "state_incompatible" => R::StateIncompatible,
        "channel_mismatch" => R::ChannelMismatch,
        "build_missing" => R::BuildMissing,
        "build_not_declared" => R::BuildNotDeclared,
        "build_mismatch" => R::BuildMismatch,
        "url_missing" => R::UrlMissing,
        "url_mismatch" => R::UrlMismatch,
        "length_missing" => R::LengthMissing,
        "length_mismatch" => R::LengthMismatch,
        "sha256_missing" => R::Sha256Missing,
        "sha256_mismatch" => R::Sha256Mismatch,
        other => R::Unknown { raw: other.to_owned() },
    });
    AppcastItemCheck {
        outcome,
        reason,
        message: text(&resp.reason),
        entry: resp.entry.as_ref().map(|e| VerifiedAppEntry {
            channel: e.channel.clone(),
            version: e.version.clone(),
            sparkle_build: (e.sparkle_build != 0).then_some(e.sparkle_build),
            minimum_supported_version: e.minimum_supported_version.clone(),
            file: e.file.clone(),
            sha256: e.sha256.clone(),
            size: e.size,
            kill_switch: e.kill_switch,
            rollout_percentage: e.rollout_percentage,
            generated_at: e.generated_at.clone(),
            expires_at: e.expires_at.clone(),
            update_required: e.update_required,
        }),
    }
}

pub fn update_config(config: &UpdateConfigResponse) -> UpdateConfig {
    UpdateConfig { automatic_checks: config.automatic_checks_enabled }
}

/// The checked download reply (see [`crate::ops::updates::check_download_reply`]).
///
/// # Errors
/// The reason the reply is refused.
pub fn update_download_guidance(
    response: &UpdateInstallResponse,
) -> Result<UpdateDownloadGuidance, String> {
    let (guidance, url) = crate::ops::updates::check_download_reply(response)?;
    Ok(UpdateDownloadGuidance { guidance, url })
}

pub fn account_deletion_impact(
    impact: &crate::ops::account::DeletionImpact,
) -> AccountDeletionImpact {
    let groups = |list: &[crate::ops::account::ImpactGroup]| {
        list.iter()
            .map(|g| AccountDeletionImpactGroup {
                group_id: g.group_id.clone(),
                name: g.name.clone(),
                guest_devices: g.guest_devices,
            })
            .collect()
    };
    AccountDeletionImpact {
        foreign_groups_at_risk: groups(&impact.foreign_groups_at_risk),
        owned_groups_with_guests: groups(&impact.owned_groups_with_guests),
    }
}

pub fn account_deletion_status(status: &DeletionStatus) -> AccountDeletionStatus {
    AccountDeletionStatus {
        state: match status.state.as_str() {
            "active" => AccountDeletionState::Active,
            "requested" => AccountDeletionState::Requested,
            "grace" => AccountDeletionState::Grace,
            other => AccountDeletionState::Other { raw: other.to_owned() },
        },
        grace_expires_at: status.grace_expires_at_unix.and_then(unix_secs),
        remaining: status
            .remaining_secs
            .and_then(|s| u64::try_from(s).ok())
            .map(Duration::from_secs),
    }
}

// ---- folder rewind ------------------------------------------------------

pub fn rewind_preview(plan: &wire::RewindPreviewResponse) -> RewindPreview {
    let counts = plan.counts.unwrap_or_default();
    RewindPreview {
        target_unix_nanos: plan.target_unix_nanos,
        restore_count: counts.create.saturating_add(counts.replace),
        remove_count: counts.delete,
        unavailable_count: counts.unavailable,
        unavailable_message: plan.unavailable_message.clone(),
        plan_id: plan.plan_id.clone(),
    }
}

fn rewind_refusal(reason: i32) -> RewindRefusal {
    use wire::RewindRefusalReason as Wire;
    match Wire::try_from(reason) {
        Ok(Wire::UnavailablePaths) => RewindRefusal::UnavailableFiles,
        Ok(Wire::RunActive) => RewindRefusal::RunActive,
        Ok(Wire::NotAuthorized) => RewindRefusal::NotAuthorized,
        Ok(Wire::GroupFrozen) => RewindRefusal::FolderFrozen,
        Ok(Wire::UnknownGroup) => RewindRefusal::UnknownFolder,
        Ok(Wire::InsufficientSpace) => RewindRefusal::InsufficientSpace,
        Ok(Wire::FolderSettling) => RewindRefusal::FolderSettling,
        Ok(Wire::Unspecified) | Err(_) => RewindRefusal::Other,
    }
}

pub fn rewind_start(start: crate::ops::rewind::RewindStart) -> RewindStartOutcome {
    use crate::ops::rewind::RewindStart;
    match start {
        RewindStart::Started { run_id } => RewindStartOutcome::Started { run_id },
        RewindStart::PlanStale { message, .. } => RewindStartOutcome::FolderChanged { message },
        RewindStart::Refused(refused) => RewindStartOutcome::Refused {
            reason: rewind_refusal(refused.reason),
            message: refused.message,
        },
    }
}

/// What a person is told when the rewind they started can no longer be
/// followed: the folder's latest rewind is not the one they started.
pub const RUN_MISSING_MESSAGE: &str =
    "This rewind can no longer be followed; check the folder and preview again.";

/// The answer for a run that can no longer be followed.
pub fn rewind_run_missing(run_id: String) -> RewindRun {
    RewindRun {
        run_id,
        state: RewindRunState::Failed,
        failure: Some(RewindFailure::Interrupted),
        steps_total: 0,
        steps_done: 0,
        restored: 0,
        removed: 0,
        message: RUN_MISSING_MESSAGE.to_owned(),
    }
}

pub fn rewind_run(run: &wire::RewindRun) -> RewindRun {
    use wire::RewindFailureKind as Kind;
    use wire::RewindRunState as State;
    let state = match State::try_from(run.state) {
        Ok(State::Planned) => RewindRunState::Gathering,
        Ok(State::Prefetched | State::Committing) => RewindRunState::Rewinding,
        Ok(State::Done) => RewindRunState::Done,
        Ok(State::NeedsReplan) => RewindRunState::Interrupted,
        // A state this build does not know is shown as stopped, with the
        // daemon's own message.
        Ok(State::Failed | State::Unspecified) | Err(_) => RewindRunState::Failed,
    };
    let failure =
        (state == RewindRunState::Failed).then(|| match Kind::try_from(run.failure_kind) {
            Ok(Kind::ContentUnavailable) => RewindFailure::ContentUnavailable,
            Ok(Kind::Transient) => RewindFailure::DevicesOffline,
            Ok(Kind::FolderChanged) => RewindFailure::FolderChanged,
            Ok(Kind::CommitRefused) => RewindFailure::CannotChangeFolder,
            Ok(Kind::Interrupted | Kind::Unspecified) | Err(_) => RewindFailure::Interrupted,
        });
    RewindRun {
        run_id: run.run_id.clone(),
        state,
        failure,
        steps_total: run.chunks_total,
        steps_done: run.chunks_done,
        restored: run.restored,
        removed: run.deleted,
        message: run.message.clone(),
    }
}
