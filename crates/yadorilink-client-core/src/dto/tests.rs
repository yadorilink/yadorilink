use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use yadorilink_ipc_proto::daemonctl::{
    ActiveTransferProgress, ConflictedFileInfo, FetchAvailability as WireFetch, FileVersionInfo,
    GroupDurabilityStatus, HandoffResult, HeldFile as WireHeldFile, InboxFileSummary,
    InboxTransfer, LinkStatus, LocalState as WireLocalState, LocalStorageState as WireLocal,
    LocalTransition as WireTransition, MaterializationStatusResponse, MembershipHandoffResult,
    MintedInviteInfo, PeerReachability as WireReach, PeerStatus, RecentSyncError,
    ReplicaMembershipCommandOutcome, RetentionPolicy as WireRetention,
    RetentionState as WireRetentionState, RouteKind as WireRoute, SetRetentionRuleResponse,
    StatusResponse, TrashedFileInfo, UnreachableCategory as WireUnreach, UpdateConfigResponse,
    UpdateInstallResponse, UpdateStatusResponse, VolumeFreeSpace,
};
use yadorilink_ipc_proto::daemonctl::{
    ProviderRootStatus as WireProviderRoot, StuckFile as WireStuck,
};
use yadorilink_local_storage::free_space::VolumeFreeSpace as Space;
use yadorilink_local_storage::link_preflight::{
    LinkPreflightReport, NestedLinkConflict, NestedLinkRelation as WireNested, RiskyLocation,
};

use yadorilink_ipc_proto::daemonctl::FileAction as WireFileAction;

use super::*;
use crate::ops::account::DeletionStatus;
use crate::ops::shares::{GroupMemberInfo, PendingApproval, PendingInviteInfo, ShareEdgeInfo};

/// A reply as the daemon sends it: with the product status computed and stored.
fn computed(mut response: StatusResponse) -> StatusResponse {
    yadorilink_product_view::wire::fill_product_status(&mut response);
    response
}

fn secs(n: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(n)
}

fn link(path: &str, group: &str) -> LinkStatus {
    LinkStatus {
        local_path: path.into(),
        group_id: group.into(),
        durability_status: GroupDurabilityStatus::Protected as i32,
        fetch_availability: WireFetch::AvailableNow as i32,
        local_storage_state: WireLocal::FullCopy as i32,
        ..Default::default()
    }
}

fn account(device_id: Option<&str>) -> AccountStatus {
    AccountStatus {
        sign_in: SignInState::SignedIn,
        client_id: Some("client".into()),
        this_device_id: device_id.map(str::to_owned),
        device_registered: device_id.is_some(),
        default_device_name: "box".into(),
        has_linked_folders: Some(true),
        start_over_pending: false,
        email: None,
        sign_in_provider: None,
        display_name: None,
    }
}

fn peer(id: &str, reach: WireReach, route: WireRoute) -> PeerStatus {
    PeerStatus {
        device_id: id.into(),
        reachability: reach as i32,
        route_kind: route as i32,
        ..Default::default()
    }
}

#[test]
fn attention_reason_is_split_into_category_and_subject() {
    let links = [link("/Users/a/Docs", "g1")];
    let reason = attention_reason("conflict:g1", &links, &[]);
    assert_eq!(
        reason,
        AttentionReason {
            category: AttentionCategory::Conflict,
            subject: "g1".into(),
            folder_local_path: Some("/Users/a/Docs".into()),
            raw: "conflict:g1".into(),
            kind: AttentionKind::Permanent,
            primary_action: ProductAction::ReviewConflict,
            secondary_action: None,
            key: "conflict_needs_review".into(),
            args: vec![arg("folder", "g1"), arg("folder_path", "/Users/a/Docs")],
            severity: AttentionSeverity::Warning,
            identity: "conflict_needs_review:g1".into(),
        }
    );
    // Only the first colon splits: a subject may itself contain one.
    let disk = attention_reason("low_disk:C:\\data", &links, &[]);
    assert_eq!(disk.category, AttentionCategory::LowDisk);
    assert_eq!(disk.subject, "C:\\data");
    assert_eq!(disk.folder_local_path, None);
    // A device-scoped reason never resolves to a folder, even when an id
    // happens to equal a group id.
    let peer = attention_reason("peer_disconnected:g1", &links, &[]);
    assert_eq!(peer.category, AttentionCategory::PeerDisconnected);
    assert_eq!(peer.folder_local_path, None);
}

#[test]
fn every_rollup_category_is_recognized_and_an_unknown_one_is_kept_raw() {
    let expected = [
        ("degraded", AttentionCategory::Degraded),
        ("durability_at_risk", AttentionCategory::DurabilityAtRisk),
        ("fetch_unavailable", AttentionCategory::FetchUnavailable),
        ("fetch_availability_unknown", AttentionCategory::FetchAvailabilityUnknown),
        ("conflict", AttentionCategory::Conflict),
        ("held", AttentionCategory::Held),
        ("stranded_directory", AttentionCategory::StrandedDirectory),
        ("low_disk_critical", AttentionCategory::LowDiskCritical),
        ("low_disk", AttentionCategory::LowDisk),
        ("peer_disconnected", AttentionCategory::PeerDisconnected),
        ("recent_error", AttentionCategory::RecentError),
        ("update_failed", AttentionCategory::UpdateFailed),
        ("peer_update_required", AttentionCategory::UpdateRequired),
        ("peer_newer", AttentionCategory::UpdateRequired),
        ("update_required", AttentionCategory::UpdateRequired),
        ("ambiguous", AttentionCategory::Ambiguous),
        ("folder_needs_relink", AttentionCategory::OwnershipLost),
        ("volume_changed", AttentionCategory::VolumeChanged),
        ("volume_unconfirmed", AttentionCategory::VolumeUnconfirmed),
        ("provider_not_ready", AttentionCategory::ProviderNotReady),
        ("provider_stuck", AttentionCategory::ProviderStuck),
        ("kept_edits", AttentionCategory::KeptEdits),
        ("provider_orphan_domain", AttentionCategory::ProviderOrphanDomain),
    ];
    for (name, category) in expected {
        assert_eq!(attention_reason(&format!("{name}:x"), &[], &[]).category, category, "{name}");
    }
    let odd = attention_reason("something_new", &[], &[]);
    assert_eq!(odd.category, AttentionCategory::Unrecognized);
    assert_eq!(odd.subject, "");
    assert_eq!(odd.raw, "something_new");
}

#[test]
fn a_restored_provider_registry_reaches_shells_by_key_and_severity() {
    let reason = attention_reason("provider_registry_restored:older_generation", &[], &[]);
    assert_eq!(reason.key, "provider_registry_restored");
    assert_eq!(reason.severity, AttentionSeverity::Warning);
    assert_eq!(
        reason.args,
        vec![AttentionArg { name: "category".into(), value: "older_generation".into() }]
    );
}

/// The start-over follow-up is one key; the step (and a wait's reason) are its arguments, and the
/// identity differs per step so a new step notifies again.
#[test]
fn the_replacement_follow_up_carries_its_step_as_an_argument() {
    let arg = |name: &str, value: &str| AttentionArg { name: name.into(), value: value.into() };
    let confirming = attention_reason("replacement_unconfirmed", &[], &[]);
    assert_eq!(confirming.key, "replacement_unconfirmed");
    assert_eq!(confirming.args, vec![arg("step", "confirming")]);
    let waiting = attention_reason("replacement_unconfirmed:waiting:g1: startup", &[], &[]);
    assert_eq!(waiting.key, "replacement_unconfirmed");
    assert_eq!(waiting.args, vec![arg("step", "waiting"), arg("reason", "g1: startup")]);
    let sign_in = attention_reason("replacement_unconfirmed:sign_in", &[], &[]);
    assert_eq!(sign_in.args, vec![arg("step", "sign_in")]);
    assert_ne!(sign_in.identity, waiting.identity);
}

#[test]
fn keyed_only_items_reach_shells_as_unrecognized_with_their_own_key() {
    for (raw, key) in [
        ("provider_registry_restored:older_generation", "provider_registry_restored"),
        ("database_restored:older_generation", "database_restored"),
        ("author_unavailable:x", "author_unavailable"),
        ("unreadable_files:g1", "unreadable_files"),
        ("approval_pending:g1", "approval_pending"),
        ("waiting_for_disk_space:g1", "waiting_for_disk_space"),
        ("file_watch_limit:g1", "file_watch_limit"),
    ] {
        let reason = attention_reason(raw, &[], &[]);
        assert_eq!(reason.category, AttentionCategory::Unrecognized, "{raw}");
        assert_eq!(reason.key, key, "{raw}");
        assert!(!reason.key.is_empty(), "{raw}");
    }
}

#[test]
fn folder_summary_wraps_the_shared_derivation_and_turns_unset_values_into_none() {
    let mut on_demand = link("/f/Photos", "g2");
    on_demand.materialization_policy = "ondemand".into();
    on_demand.conflict_count = 2;
    on_demand.has_active_transfer = true;
    on_demand.transfer_bytes_done = 5;
    on_demand.transfer_bytes_total = 10;
    on_demand.transfer_eta_seconds = 0;
    on_demand.durability_status = GroupDurabilityStatus::Unspecified as i32;
    on_demand.local_storage_state = WireLocal::OnDemand as i32;
    on_demand.fetch_availability = WireFetch::Unspecified as i32;
    let volumes = [VolumeFreeSpace {
        path: "/f/Photos".into(),
        state: "low".into(),
        available_bytes: 7,
        headroom_bytes: 3,
        total_bytes: 0,
        reclaimable_bytes: 0,
    }];
    let summary = folder_summary(&on_demand, &volumes, &[]);
    assert_eq!(summary.name, "Photos");
    assert_eq!(summary.mode, FolderMode::OnDemand);
    assert_eq!(summary.state, FolderState::Attention);
    assert_eq!(summary.durability, DurabilityStatus::Unknown);
    assert_eq!(summary.durability_evidence, DurabilityEvidence::Unknown);
    assert_eq!(summary.local_storage, LocalStorageState::OnDemand);
    assert_eq!(summary.fetch_availability, FetchAvailability::Unknown);
    assert_eq!(summary.degraded_reason, None);
    assert_eq!(
        summary.transfer,
        Some(FolderTransferProgress {
            bytes_done: 5,
            bytes_total: 10,
            blocks_done: 0,
            blocks_total: 0,
            eta: None
        })
    );
    assert_eq!(
        summary.volume,
        Some(VolumeSummary {
            path: "/f/Photos".into(),
            state: FreeSpaceState::Low,
            available_bytes: 7,
            headroom_bytes: 3,
            reclaimable_bytes: 0
        })
    );

    let mut eager = link("/f/Docs", "g1");
    eager.ambiguous = true;
    eager.paused = true;
    eager.degraded_reason = "disk full".into();
    let summary = folder_summary(&eager, &volumes, &[]);
    assert_eq!(summary.mode, FolderMode::KeepAll);
    assert_eq!(summary.state, FolderState::Blocked);
    assert_eq!(summary.durability, DurabilityStatus::Protected);
    assert_eq!(summary.degraded_reason.as_deref(), Some("disk full"));
    assert_eq!(summary.volume, None);
    assert_eq!(summary.transfer, None);
    assert_eq!(summary.degraded_cause, None);

    // The wait is the typed flag, whatever the detail text says.
    let mut waiting = link("/f/Docs", "g1");
    waiting.degraded = true;
    waiting.set_degraded_cause(yadorilink_ipc_proto::daemonctl::DegradedCause::WaitingForDiskSpace);
    waiting.degraded_reason = "anything".into();
    assert_eq!(
        folder_summary(&waiting, &volumes, &[]).degraded_cause,
        Some(DegradedCause::WaitingForDiskSpace)
    );
    let mut lookalike = link("/f/Docs", "g1");
    lookalike.degraded = true;
    lookalike.degraded_reason = "Waiting for disk space on /v".into();
    assert_eq!(
        folder_summary(&lookalike, &volumes, &[]).degraded_cause,
        Some(DegradedCause::Stopped)
    );
}

fn status_response() -> StatusResponse {
    let mut docs = link("/f/Docs", "g1");
    docs.full_replica_device_ids = vec!["dev-a".into(), "dev-b".into(), "dev-c".into()];
    docs.held_files = vec![WireHeldFile {
        path: "a.txt".into(),
        reason: "locked".into(),
        held_since_unix_nanos: 2_000_000_000,
    }];
    StatusResponse {
        links: vec![docs],
        peers: vec![
            peer("dev-a", WireReach::Connected, WireRoute::Relay),
            PeerStatus {
                unreachable_category: WireUnreach::UdpBlocked as i32,
                last_connected_unix: 500,
                ..peer("dev-b", WireReach::Unreachable, WireRoute::Unspecified)
            },
        ],
        upload_limit_bytes_per_sec: 0,
        download_limit_bytes_per_sec: 500,
        current_upload_bytes_per_sec: 1,
        current_download_bytes_per_sec: 2,
        volumes: vec![VolumeFreeSpace {
            path: "/store".into(),
            state: "surprising".into(),
            available_bytes: 1,
            headroom_bytes: 1,
            total_bytes: 0,
            reclaimable_bytes: 0,
        }],
        update_state: "held_back".into(),
        update_channel: "beta".into(),
        update_install_source: "pkg".into(),
        block_store_total_bytes: 9,
        block_store_block_count: 3,
        last_gc_unix: 0,
        gc_reclaimable_estimate_bytes: 4,
        active_transfers: vec![ActiveTransferProgress {
            group_id: "g1".into(),
            path: "big.bin".into(),
            bytes_done: 1,
            bytes_total: 2,
            blocks_done: 3,
            blocks_total: 4,
            source_peer: "dev-a".into(),
            started_at_unix: 100,
        }],
        recent_errors: vec![RecentSyncError {
            category: "io".into(),
            timestamp_unix: 50,
            coarse_context: "write".into(),
        }],
        overall_state: "attention".into(),
        attention_reasons: vec!["conflict:g1".into()],
        ..Default::default()
    }
}

#[test]
fn status_snapshot_maps_every_section_of_the_daemon_status() {
    let snapshot = status_snapshot(&status_response(), account(Some("me")), secs(1_000));
    assert_eq!(
        snapshot.account,
        account(Some("me")),
        "the account state travels with the snapshot"
    );
    assert_eq!(snapshot.captured_at, secs(1_000));
    assert_eq!(snapshot.overall, OverallState::Attention);
    assert_eq!(snapshot.this_device_id.as_deref(), Some("me"));
    assert_eq!(snapshot.attention_reasons[0].folder_local_path.as_deref(), Some("/f/Docs"));
    assert_eq!(snapshot.folders.len(), 1);
    assert_eq!(
        snapshot.peers,
        vec![
            PeerSummary {
                device_id: "dev-a".into(),
                reachability: PeerReachability::Connected,
                unreachable_category: None,
                route: RouteKind::Relay,
                last_connected: None,
            },
            PeerSummary {
                device_id: "dev-b".into(),
                reachability: PeerReachability::Unreachable,
                unreachable_category: Some(UnreachableCategory::UdpBlocked),
                route: RouteKind::Unknown,
                last_connected: Some(secs(500)),
            },
        ]
    );
    assert_eq!(
        snapshot.transfers,
        vec![TransferSummary {
            group_id: "g1".into(),
            folder_local_path: Some("/f/Docs".into()),
            path: "big.bin".into(),
            bytes_done: 1,
            bytes_total: 2,
            blocks_done: 3,
            blocks_total: 4,
            source_device_id: "dev-a".into(),
            started_at: Some(secs(100)),
        }]
    );
    assert_eq!(
        snapshot.bandwidth,
        BandwidthStatus {
            limits: BandwidthLimits {
                upload_bytes_per_sec: None,
                download_bytes_per_sec: Some(500)
            },
            current_upload_bytes_per_sec: 1,
            current_download_bytes_per_sec: 2,
        }
    );
    assert_eq!(snapshot.volumes[0].state, FreeSpaceState::Unknown);
    assert_eq!(
        snapshot.storage,
        StorageSummary {
            block_store_total_bytes: 9,
            block_count: 3,
            last_gc_at: None,
            reclaimable_estimate_bytes: 4
        }
    );
    assert_eq!(
        snapshot.update,
        UpdateBadge {
            state: UpdateState::HeldBack,
            available_version: None,
            mandatory: false,
            last_error_category: None,
            channel: "beta".into(),
            install_source: "pkg".into(),
            holdback_reason: None,
        }
    );
    assert_eq!(
        snapshot.recent_errors,
        vec![RecentError { category: "io".into(), at: Some(secs(50)), context: "write".into() }]
    );
}

#[test]
fn an_empty_or_unknown_overall_state_reads_as_unknown_never_healthy() {
    for raw in ["", "fine", "HEALTHY"] {
        let response = StatusResponse { overall_state: raw.into(), ..Default::default() };
        assert_eq!(
            status_snapshot(&response, account(None), secs(0)).overall,
            OverallState::Unknown
        );
    }
    for (raw, state) in [
        ("healthy", OverallState::Healthy),
        ("attention", OverallState::Attention),
        ("degraded", OverallState::Degraded),
    ] {
        let response = StatusResponse { overall_state: raw.into(), ..Default::default() };
        assert_eq!(status_snapshot(&response, account(None), secs(0)).overall, state);
    }
}

#[test]
fn folder_detail_lists_every_complete_copy_with_this_devices_connection_to_it() {
    let detail = folder_detail(&status_response(), "/f/Docs").expect("linked folder");
    assert_eq!(detail.summary.local_path, "/f/Docs");
    assert_eq!(
        detail.held_files,
        vec![HeldFile { path: "a.txt".into(), reason: "locked".into(), held_since: Some(secs(2)) }]
    );
    assert_eq!(
        detail.complete_copies,
        vec![
            ReplicaCopy {
                device_id: "dev-a".into(),
                reachability: PeerReachability::Connected,
                route: RouteKind::Relay
            },
            ReplicaCopy {
                device_id: "dev-b".into(),
                reachability: PeerReachability::Unreachable,
                route: RouteKind::Unknown
            },
            ReplicaCopy {
                device_id: "dev-c".into(),
                reachability: PeerReachability::Unknown,
                route: RouteKind::Unknown
            },
        ]
    );
    assert_eq!(folder_detail(&status_response(), "/elsewhere"), None);
}

#[test]
fn conflict_summary_names_the_file_it_conflicts_with() {
    let summary = conflict_summary(&ConflictedFileInfo {
        local_path: "/f/Docs".into(),
        path: "notes.txt".into(),
        size: -1,
        mtime_unix_nanos: 0,
        kind: 0,
        reason: 0,
        resolvable: false,
        origin_device_id: String::new(),
    });
    assert_eq!(summary.current_path, "notes.txt");
    assert_eq!(summary.reason, ConflictReason::ConcurrentEdit);
    assert_eq!(summary.size, 0);
    assert_eq!(summary.modified_at, None);
    assert_eq!(summary.loser_device_id, None);
    assert!(!summary.can_resolve);
    assert_eq!(summary.origin_device_id, None);
}

#[test]
fn conflict_summary_takes_resolvability_and_origin_from_the_daemon() {
    let summary = conflict_summary(&ConflictedFileInfo {
        path: "notes (conflicted copy, 2026-01-01-000000, device-b).txt".into(),
        resolvable: true,
        origin_device_id: "device-b".into(),
        ..Default::default()
    });
    assert!(summary.can_resolve);
    assert_eq!(summary.origin_device_id.as_deref(), Some("device-b"));
    // The same name, but the daemon says no: the facade does not second-guess it.
    let refused = conflict_summary(&ConflictedFileInfo {
        path: "notes (conflicted copy, 2026-01-01-000000, device-b).txt".into(),
        resolvable: false,
        ..Default::default()
    });
    assert!(!refused.can_resolve);
}

/// Two conflicts in one folder have different identities (the folder-level attention identity is
/// shared), the identity of one is the same on every list and ignores everything that merely
/// describes the copy, and the same copy name in another folder is another conflict.
#[test]
fn a_conflict_identity_is_stable_per_copy_and_distinct_between_copies() {
    let copy = |root: &str, path: &str, size: i64, resolvable: bool| {
        conflict_summary(&ConflictedFileInfo {
            local_path: root.into(),
            path: path.into(),
            size,
            resolvable,
            ..Default::default()
        })
        .identity
    };
    let a = "a (conflicted copy, 2026-01-01-000000, dev-b).txt";
    let b = "b (conflicted copy, 2026-01-01-000000, dev-b).txt";
    let first = copy("/f/Docs", a, 1, false);
    assert_eq!(first, copy("/f/Docs", a, 99, true));
    assert_ne!(first, copy("/f/Docs", b, 1, false));
    assert_ne!(first, copy("/f/Other", a, 1, false));
    // A different split of the same text is not the same conflict.
    assert_ne!(copy("/f/D", "ocs/x", 1, false), copy("/f/Docs", "/x", 1, false));
    // One folder-level attention identity for both, which is why the per-copy one exists.
    let links = [link("/f/Docs", "g1")];
    assert_eq!(attention_reason("conflict:g1", &links, &[]).identity, "conflict_needs_review:g1");
}

#[test]
fn only_the_highest_version_is_current() {
    let versions = file_versions(&[
        FileVersionInfo { version_seq: 3, size: 1, ..Default::default() },
        FileVersionInfo {
            version_seq: 7,
            size: 2,
            mtime_unix_nanos: 3_000_000_000,
            origin_device_id: "dev-a".into(),
            exec: true,
            state: "live".into(),
            kind: 0,
            ..Default::default()
        },
        FileVersionInfo { version_seq: 5, size: 3, ..Default::default() },
    ]);
    assert_eq!(versions.iter().map(|v| v.is_current).collect::<Vec<_>>(), [false, true, false]);
    assert_eq!(versions[1].modified_at, Some(secs(3)));
    assert_eq!(versions[1].origin_device_id.as_deref(), Some("dev-a"));
    assert!(versions[1].exec);
    assert_eq!(versions[0].origin_device_id, None);
}

#[test]
fn a_version_says_whether_this_device_still_holds_its_bytes() {
    use yadorilink_ipc_proto::daemonctl::VersionContent as Wire;
    let content = |wire: Wire| {
        file_version(&FileVersionInfo { content: wire as i32, ..Default::default() }, false).content
    };
    assert_eq!(content(Wire::NotApplicable), VersionContent::NotApplicable);
    assert_eq!(content(Wire::Kept), VersionContent::Kept);
    assert_eq!(content(Wire::NotKept), VersionContent::NotKept);
    // A daemon that does not send the field (an older one) reads as "not a statement about bytes", never as "kept".
    assert_eq!(
        file_version(&FileVersionInfo::default(), false).content,
        VersionContent::NotApplicable
    );
}

#[test]
fn trash_file_and_materialization_turn_unset_values_into_none() {
    let trashed = trashed_file(&TrashedFileInfo {
        local_path: "/f".into(),
        path: "x".into(),
        version_seq: 4,
        last_known_size: 10,
        origin_device_id: String::new(),
        deleted_at_unix_nanos: 1_000_000_000,
        kind: 0,
        deleted_by_operation: String::new(),
    });
    assert_eq!(trashed.origin_device_id, None);
    assert_eq!(trashed.deleted_at, Some(secs(1)));
    assert_eq!(trashed.deleted_by_operation, None);
    let in_folder = trashed_file(&TrashedFileInfo {
        deleted_by_operation: "device-a:0a0b".into(),
        ..Default::default()
    });
    assert_eq!(in_folder.deleted_by_operation.as_deref(), Some("device-a:0a0b"));

    let unknown = file_availability(&MaterializationStatusResponse {
        known: false,
        local_state: None,
        retention: None,
        available_actions: Vec::new(),
    });
    assert_eq!(
        unknown,
        FileAvailability {
            tracked: false,
            state: MaterializationState::Unknown,
            actions: Vec::new()
        }
    );
    let hydrating = file_availability(&MaterializationStatusResponse {
        known: true,
        local_state: Some(WireLocalState {
            local_object_present: false,
            current_content_present: false,
            transition: WireTransition::Hydrating as i32,
        }),
        retention: None,
        available_actions: Vec::new(),
    });
    assert_eq!(
        hydrating,
        FileAvailability {
            tracked: true,
            state: MaterializationState::Hydrating,
            actions: Vec::new()
        }
    );
    // An older object that stands is not current content.
    let stale = file_availability(&MaterializationStatusResponse {
        known: true,
        local_state: Some(WireLocalState {
            local_object_present: true,
            current_content_present: false,
            transition: WireTransition::None as i32,
        }),
        retention: None,
        available_actions: Vec::new(),
    });
    assert_eq!(stale.state, MaterializationState::Placeholder);
    let current = file_availability(&MaterializationStatusResponse {
        known: true,
        local_state: Some(WireLocalState {
            local_object_present: true,
            current_content_present: true,
            transition: WireTransition::None as i32,
        }),
        retention: None,
        available_actions: Vec::new(),
    });
    assert_eq!(current.state, MaterializationState::Hydrated);

    // The engine's action list is passed through in its order, and an action this build does not
    // know is dropped rather than guessed.
    let offered = file_availability(&MaterializationStatusResponse {
        known: true,
        local_state: None,
        retention: None,
        available_actions: vec![
            WireFileAction::FreeUpSpace as i32,
            99,
            WireFileAction::Unspecified as i32,
            WireFileAction::KeepOnDevice as i32,
        ],
    });
    assert_eq!(offered.actions, vec![FileAction::FreeUpSpace, FileAction::KeepOnDevice]);
}

#[test]
fn membership_outcome_keeps_forced_groups_and_the_unknown_scope_operation() {
    let outcome = membership_outcome(&ReplicaMembershipCommandOutcome {
        handoffs: vec![MembershipHandoffResult {
            group_id: "g".into(),
            target_device_id: "t".into(),
            lease_id: "l".into(),
            membership_generation: 9,
        }],
        forced_group_ids: vec!["g2".into()],
        unknown_scope_operation_id: String::new(),
    });
    assert_eq!(outcome.forced_group_ids, ["g2".to_string()]);
    assert_eq!(outcome.unknown_scope_operation_id, None);
    assert_eq!(outcome.handoffs[0].membership_generation, 9);

    let unknown = membership_outcome(&ReplicaMembershipCommandOutcome {
        unknown_scope_operation_id: "op".into(),
        ..Default::default()
    });
    assert_eq!(unknown.unknown_scope_operation_id.as_deref(), Some("op"));

    let handoff = handoff_summary(&HandoffResult {
        target_device_id: "t".into(),
        membership_generation: 3,
        lease_id: String::new(),
        ..Default::default()
    });
    assert_eq!(handoff.lease_id, None);
}

fn member(id: &str, caller: bool, same: bool) -> GroupMemberInfo {
    GroupMemberInfo {
        device_id: id.into(),
        device_name: "Laptop".into(),
        role: "editor".into(),
        is_same_account: same,
        is_caller_account: caller,
        storage_mode: "eager".into(),
        online: true,
        last_seen_unix: 0,
    }
}

#[test]
fn member_relationship_is_caller_relative() {
    assert_eq!(
        member_summary(&member("me", true, true), Some("me")).relationship,
        MemberRelationship::You
    );
    assert_eq!(
        member_summary(&member("other", true, false), Some("me")).relationship,
        MemberRelationship::YourOtherDevice
    );
    assert_eq!(
        member_summary(&member("other", false, true), Some("me")).relationship,
        MemberRelationship::OwnersDevice
    );
    assert_eq!(
        member_summary(&member("other", false, false), None).relationship,
        MemberRelationship::Invited
    );
    let summary = member_summary(&member("me", true, true), None);
    assert_eq!(summary.role, ShareRole::Editor);
    assert_eq!(summary.storage, MemberStorage::FullCopy);
    assert_eq!(summary.last_seen, None);
    let mut odd = member("x", false, false);
    odd.role = "unknown".into();
    odd.storage_mode = "future".into();
    odd.last_seen_unix = 60;
    let summary = member_summary(&odd, None);
    assert_eq!(summary.role, ShareRole::Other { raw: "unknown".into() });
    assert_eq!(summary.storage, MemberStorage::OnDemand);
    assert_eq!(summary.last_seen, Some(secs(60)));
}

#[test]
fn shares_invites_and_approvals_keep_unrecognized_values() {
    let edge = |state: &str, role: Option<&str>| ShareEdgeInfo {
        edge_id: "e".into(),
        group_id: "g".into(),
        group_name: "G".into(),
        device_id: "d".into(),
        state: state.into(),
        role: role.map(Into::into),
    };
    assert_eq!(share_summary(&edge("active", Some("owner"))).state, ShareEdgeState::Active);
    assert_eq!(share_summary(&edge("active", Some("owner"))).role, Some(ShareRole::Owner));
    assert_eq!(
        share_summary(&edge("pending_approval", None)).state,
        ShareEdgeState::PendingApproval
    );
    assert_eq!(
        share_summary(&edge("revoked", None)).state,
        ShareEdgeState::Other { raw: "revoked".into() }
    );

    let pending = pending_approval_summary(&PendingApproval {
        group_id: "g".into(),
        group_name: "G".into(),
        device_id: "d".into(),
        role: Some("viewer".into()),
    });
    assert_eq!(pending.requested_role, Some(ShareRole::Viewer));

    let invite = invite_summary(&MintedInviteInfo {
        code: "abc".into(),
        invite_id: "i".into(),
        group_id: "g".into(),
        role: "viewer".into(),
        expires_at_unix: 70,
        requires_approval: true,
    });
    assert_eq!(invite.url, "yadorilink://invite/abc");
    assert_eq!(invite.url, crate::wording::invite_url("abc"));
    assert_eq!(invite.expires_at, secs(70));
    assert_eq!(invite.role, ShareRole::Viewer);

    let listed = pending_invite_summary(&PendingInviteInfo {
        invite_id: "i".into(),
        group_id: "g".into(),
        group_name: "G".into(),
        role: "editor".into(),
        expires_at_unix: 80,
        status: "expired".into(),
    });
    assert_eq!(listed.status, InviteStatus::Other { raw: "expired".into() });
    assert_eq!(listed.expires_at, secs(80));
}

#[test]
fn preflight_issues_follow_the_reports_own_order() {
    let report = LinkPreflightReport {
        path_exists: true,
        is_directory: true,
        entry_count: 3,
        scan_truncated: true,
        free_space: Some(Space { available_bytes: 5, total_bytes: 100, headroom_bytes: 10 }),
        nested_conflicts: vec![NestedLinkConflict {
            other_path: "/a".into(),
            relation: WireNested::Ancestor,
        }],
        risky_location: Some(RiskyLocation::CloudProviderFolder("Dropbox")),
        reserved_namespace_blocked_paths: vec![".yadorilink-x".into()],
        ..Default::default()
    };
    let result = preflight_result(&PathBuf::from("/a/b"), &report);
    assert_eq!(result.resolved_path, "/a/b");
    assert!(result.requires_acknowledgement);
    assert_eq!(
        result.free_space,
        Some(FreeSpace {
            available_bytes: 5,
            total_bytes: 100,
            headroom_bytes: 10,
            state: FreeSpaceState::Critical
        })
    );
    assert_eq!(
        result.issues,
        vec![
            PreflightIssue::NotEmpty { entry_count: 3, scan_truncated: true },
            PreflightIssue::CriticalFreeSpace { available_bytes: 5, headroom_bytes: 10 },
            PreflightIssue::NestedLink {
                other_path: "/a".into(),
                relation: NestedLinkRelation::Ancestor
            },
            PreflightIssue::CloudProviderFolder { provider: "Dropbox".into() },
            PreflightIssue::ReservedName { path: ".yadorilink-x".into() },
        ]
    );
    // A nested link is listed as an issue but is a prohibition, not a warning.
    assert_eq!(
        result.issues.len(),
        report.warnings().len() + report.structural_prohibitions().len()
    );

    let missing = preflight_result(&PathBuf::from("/gone"), &LinkPreflightReport::default());
    assert_eq!(missing.issues, vec![PreflightIssue::PathMissing]);
    assert!(missing.requires_acknowledgement);

    let clean = LinkPreflightReport {
        path_exists: true,
        is_directory: true,
        free_space: Some(Space { available_bytes: 100, total_bytes: 100, headroom_bytes: 10 }),
        ..Default::default()
    };
    let clean = preflight_result(&PathBuf::from("/ok"), &clean);
    assert!(clean.issues.is_empty());
    assert!(!clean.requires_acknowledgement);
}

#[test]
fn updates_map_states_modes_and_outcomes() {
    let status = update_status(&UpdateStatusResponse {
        current_version: "1.0".into(),
        state: "kill_switched".into(),
        last_check_unix: 20,
        last_success_unix: 10,
        manifest_expires_at: "2026-12-18T00:00:00Z".into(),
        manifest_expired: true,
        automatic_checks_enabled: true,
        ..Default::default()
    });
    assert_eq!(status.state, UpdateState::KillSwitched);
    assert_eq!(status.last_checked_at, Some(secs(20)));
    assert_eq!(status.last_successful_check_at, Some(secs(10)));
    assert_eq!(status.manifest_expires_at.as_deref(), Some("2026-12-18T00:00:00Z"));
    assert!(status.manifest_expired);
    assert_eq!(status.available_version, None);
    assert_eq!(status.config, UpdateConfig { automatic_checks: true });
    assert_eq!(
        update_config(&UpdateConfigResponse { automatic_checks_enabled: false }),
        UpdateConfig { automatic_checks: false }
    );
    let states = [
        ("idle", UpdateState::Idle),
        ("checking", UpdateState::Checking),
        ("available", UpdateState::Available),
        ("held_back", UpdateState::HeldBack),
        ("state_incompatible", UpdateState::StateIncompatible),
        ("kill_switched", UpdateState::KillSwitched),
        ("downloading", UpdateState::Downloading),
        ("downloaded", UpdateState::Downloaded),
        ("verified", UpdateState::Verified),
        ("installing", UpdateState::Installing),
        ("failed", UpdateState::Failed),
        ("deferred", UpdateState::Deferred),
        ("up_to_date", UpdateState::UpToDate),
        ("", UpdateState::Unknown { raw: String::new() }),
    ];
    for (raw, state) in states {
        let status =
            update_status(&UpdateStatusResponse { state: raw.into(), ..Default::default() });
        assert_eq!(status.state, state, "{raw}");
    }
    let reply = |o: &str, g: &str, u: &str| UpdateInstallResponse {
        outcome: o.into(),
        guidance: g.into(),
        download_url: u.into(),
    };
    // A page to open comes only from the structured field, never from the sentence.
    assert_eq!(
        update_download_guidance(&reply(
            "manual_download",
            "Download the new version from https://github.com/yadorilink/yadorilink/releases",
            "https://github.com/yadorilink/yadorilink/releases",
        )),
        Ok(UpdateDownloadGuidance {
            guidance:
                "Download the new version from https://github.com/yadorilink/yadorilink/releases"
                    .into(),
            url: Some("https://github.com/yadorilink/yadorilink/releases".into()),
        })
    );
    // Steps for a package-managed install: a URL inside the sentence is not trusted.
    assert_eq!(
        update_download_guidance(&reply(
            "manual_download",
            "Run `brew upgrade` (see https://evil.test/x)",
            ""
        )),
        Ok(UpdateDownloadGuidance {
            guidance: "Run `brew upgrade` (see https://evil.test/x)".into(),
            url: None,
        })
    );
    for outcome in ["installing", "deferred", "store_managed", "later", ""] {
        assert!(update_download_guidance(&reply(outcome, "x", "")).is_err(), "{outcome}");
    }
    assert!(update_download_guidance(&reply("manual_download", "", "")).is_err());
}

#[test]
fn only_the_official_release_page_is_ever_offered_to_open() {
    let ok = |url: &str| {
        update_download_guidance(&UpdateInstallResponse {
            outcome: "manual_download".into(),
            guidance: "g".into(),
            download_url: url.into(),
        })
    };
    assert!(ok("https://github.com/yadorilink/yadorilink/releases/tag/v0.4.3").is_ok());
    for bad in [
        "http://github.com/yadorilink/yadorilink/releases",
        "https://evil.test/yadorilink/yadorilink/releases",
        "https://github.com/yadorilink/yadorilink/releases.evil.test",
        "https://github.com/yadorilink/yadorilink/releasesx",
        "https://github.com/yadorilink/yadorilink/releases ",
        "https://github.com/yadorilink/yadorilink/releases https://evil.test",
        "https://github.com/yadorilink/yadorilink/releases.",
        "https://github.com/yadorilink/yadorilink/releases?next=https://evil.test",
        "https://github.com/yadorilink/yadorilink/releases/../../evil",
        "file:///etc/passwd",
    ] {
        assert!(ok(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn package_managed_installs_are_recognised_by_install_source() {
    use crate::ops::updates::is_package_managed;
    for managed in ["homebrew", "apt", "winget", "microsoft_store"] {
        assert!(is_package_managed(managed), "{managed}");
    }
    for other in ["standalone", "", "pkg", "unknown"] {
        assert!(!is_package_managed(other), "{other}");
    }
    let status = update_status(&UpdateStatusResponse {
        install_source: "homebrew".into(),
        ..Default::default()
    });
    assert!(status.package_managed);
}

#[test]
fn account_deletion_and_transfers_parse_their_states() {
    let grace = account_deletion_status(&DeletionStatus {
        state: "grace".into(),
        grace_expires_at_unix: Some(90),
        remaining_secs: Some(30),
    });
    assert_eq!(
        grace,
        AccountDeletionStatus {
            state: AccountDeletionState::Grace,
            grace_expires_at: Some(secs(90)),
            remaining: Some(Duration::from_secs(30)),
        }
    );
    let odd = account_deletion_status(&DeletionStatus {
        state: "purged".into(),
        grace_expires_at_unix: None,
        remaining_secs: Some(-5),
    });
    assert_eq!(odd.state, AccountDeletionState::Other { raw: "purged".into() });
    assert_eq!(odd.remaining, None);

    let inbox = incoming_transfer(&InboxTransfer {
        transfer_id: "t".into(),
        sender_device_id: "s".into(),
        files: vec![InboxFileSummary { relative_path: "a".into(), size: 1 }],
        total_size: 1,
        offered_at_unix_nanos: 4_000_000_000,
        status: "in_progress".into(),
        failure: String::new(),
        files_done: 0,
        files_total: 1,
        ..Default::default()
    });
    assert_eq!(inbox.status, IncomingTransferStatus::InProgress);
    assert_eq!((inbox.files_done, inbox.files_total), (0, 1));
    assert_eq!(inbox.offered_at, Some(secs(4)));
    assert_eq!(inbox.files, vec![IncomingFile { relative_path: "a".into(), size: 1 }]);
    assert_eq!((inbox.failure.clone(), inbox.can_retry), (None, false));
    for (raw, status) in [
        ("pending", IncomingTransferStatus::Pending),
        ("completed", IncomingTransferStatus::Completed),
        ("failed", IncomingTransferStatus::Failed),
        ("canceled", IncomingTransferStatus::Canceled),
        ("paused", IncomingTransferStatus::Other { raw: "paused".into() }),
    ] {
        let t = incoming_transfer(&InboxTransfer { status: raw.into(), ..Default::default() });
        assert_eq!(t.status, status);
    }
}

/// Each record's kind reaches the product types. An unset wire kind is a
/// sender that never classified the record, which only ever meant a file.
#[test]
fn versions_trash_and_conflicts_carry_their_entry_kind() {
    use yadorilink_ipc_proto::daemonctl::EntryKind as Wire;
    for (wire, kind) in [
        (Wire::Unspecified, EntryKind::File),
        (Wire::File, EntryKind::File),
        (Wire::Directory, EntryKind::Directory),
        (Wire::Symlink, EntryKind::Symlink),
    ] {
        let version =
            file_version(&FileVersionInfo { kind: wire as i32, ..Default::default() }, true);
        assert_eq!(version.kind, kind, "{wire:?}");
        let trashed = trashed_file(&TrashedFileInfo { kind: wire as i32, ..Default::default() });
        assert_eq!(trashed.kind, kind, "{wire:?}");
        let conflict = conflict_summary(&ConflictedFileInfo {
            path: "a (conflicted copy, 2026-01-01-000000, dev-b)".into(),
            kind: wire as i32,
            ..Default::default()
        });
        assert_eq!(conflict.kind, kind, "{wire:?}");
    }
}

#[test]
fn folder_restore_outcome_carries_every_part() {
    use yadorilink_ipc_proto::daemonctl::{
        RestoreTrashOperationFailure, RestoreTrashOperationResponse,
    };
    let outcome = folder_restore_outcome(&RestoreTrashOperationResponse {
        restored_paths: vec!["album".into(), "album/a.jpg".into()],
        failed: vec![RestoreTrashOperationFailure {
            path: "album/b.jpg".into(),
            error: "content unavailable".into(),
        }],
        partial: true,
    });
    assert_eq!(
        outcome,
        FolderRestoreOutcome {
            restored_paths: vec!["album".into(), "album/a.jpg".into()],
            failed: vec![FolderRestoreFailure {
                path: "album/b.jpg".into(),
                error: "content unavailable".into(),
            }],
            partial: true,
        }
    );
}

#[test]
fn conflict_summary_says_when_a_folder_took_the_name() {
    let summary = conflict_summary(&ConflictedFileInfo {
        local_path: "/f/Docs".into(),
        path: "album (conflicted copy, 2026-01-01-000000, device-b)".into(),
        reason: yadorilink_ipc_proto::daemonctl::ConflictReason::FolderAtPath as i32,
        ..Default::default()
    });
    assert_eq!(summary.current_path, "album");
    assert_eq!(summary.reason, ConflictReason::FolderAtPath);
}

#[test]
fn retention_is_reported_apart_from_the_materialization_state() {
    // Nothing says the path is kept.
    assert_eq!(
        file_retention(None),
        FileRetention { policy: RetentionPolicy::Reclaimable, inherited: false }
    );
    let explicit = WireRetentionState { policy: WireRetention::Pinned as i32, explicit: true };
    assert_eq!(
        file_retention(Some(&explicit)),
        FileRetention { policy: RetentionPolicy::Pinned, inherited: false }
    );
    let inherited = WireRetentionState { policy: WireRetention::Pinned as i32, explicit: false };
    assert_eq!(
        file_retention(Some(&inherited)),
        FileRetention { policy: RetentionPolicy::Pinned, inherited: true }
    );
    // An online-only rule is its own policy, and inherited when a folder above sets it.
    let online_only =
        WireRetentionState { policy: WireRetention::OnlineOnly as i32, explicit: false };
    assert_eq!(
        file_retention(Some(&online_only)),
        FileRetention { policy: RetentionPolicy::OnlineOnly, inherited: true }
    );
    // An unreadable value is not "kept".
    let unknown = WireRetentionState { policy: 99, explicit: true };
    assert_eq!(file_retention(Some(&unknown)).policy, RetentionPolicy::Reclaimable);
}

#[test]
fn a_pin_outcome_carries_the_download_failure_without_dropping_the_pin() {
    let kept = WireRetentionState { policy: WireRetention::Pinned as i32, explicit: true };
    let failed = pin_outcome(&SetRetentionRuleResponse {
        retention: Some(kept),
        download_error: "no peer has the content".into(),
        ..Default::default()
    });
    assert_eq!(failed.retention.policy, RetentionPolicy::Pinned);
    assert_eq!(failed.download_error.as_deref(), Some("no peer has the content"));
    let done =
        pin_outcome(&SetRetentionRuleResponse { retention: Some(kept), ..Default::default() });
    assert_eq!(done.download_error, None, "an empty wire string is no error");
    assert_eq!(done.history_not_kept_reason, None, "an empty wire string is no reason");
}

/// A pin that stands while a file beneath it is not yet held in the store carries the reason to the
/// desktop client, instead of reading as a plain success.
#[test]
fn a_pin_outcome_carries_the_history_not_kept_reason() {
    let kept = WireRetentionState { policy: WireRetention::Pinned as i32, explicit: true };
    let pending = pin_outcome(&SetRetentionRuleResponse {
        retention: Some(kept),
        history_not_kept_reason: "changing_retry".into(),
        ..Default::default()
    });
    assert_eq!(pending.retention.policy, RetentionPolicy::Pinned);
    assert_eq!(pending.history_not_kept_reason.as_deref(), Some("changing_retry"));
    assert_eq!(pending.download_error, None);
}

#[test]
fn the_two_dimensions_reach_the_folder_and_the_snapshot_and_unset_reads_unknown() {
    use yadorilink_ipc_proto::daemonctl::{DataProtection, ProductAvailability};

    let waiting = LinkStatus {
        availability: ProductAvailability::WaitingForPeer as i32,
        availability_offline_device_ids: vec!["mini".into()],
        protection: DataProtection::Protected as i32,
        protection_device_ids: vec!["mini".into()],
        ..link("/f/Docs", "g1")
    };
    let folder = folder_summary(&waiting, &[], &[]);
    assert_eq!(folder.availability.availability, Availability::WaitingForPeer);
    assert_eq!(folder.availability.offline_device_ids, ["mini"]);
    assert_eq!(folder.protection.protection, Protection::Protected);

    let unset = link("/f/Other", "g2");
    let response = StatusResponse { links: vec![waiting, unset], ..Default::default() };
    let snapshot = status_snapshot(&computed(response.clone()), account(None), secs(1));
    assert_eq!(snapshot.folders[1].availability.availability, Availability::Unknown);
    assert_eq!(snapshot.availability.availability, Availability::WaitingForPeer);
    assert_eq!(snapshot.protection.protection, Protection::Unknown);
}

#[test]
fn dimensions_json_carries_both_dimensions_per_folder_and_overall() {
    use yadorilink_ipc_proto::daemonctl::{DataProtection, ProductAvailability};

    let status = StatusResponse {
        overall_state: "healthy".into(),
        links: vec![
            LinkStatus {
                availability: ProductAvailability::WaitingForPeer as i32,
                availability_offline_device_ids: vec!["dev-b".into()],
                protection: DataProtection::Protected as i32,
                protection_device_ids: vec!["dev-b".into()],
                materialization_policy: "ondemand".into(),
                placeholder_count: 7,
                ..link("/tmp/photos", "group-1")
            },
            LinkStatus {
                local_path: "/tmp/docs".into(),
                group_id: "group-2".into(),
                protection: DataProtection::AtRisk as i32,
                availability: ProductAvailability::Available as i32,
                ..link("/tmp/photos", "group-1")
            },
        ],
        ..Default::default()
    };
    let json = status_dimensions_json(&computed(status));
    assert_eq!(json["paused_on_metered"], false);
    assert_eq!(json["network_cost_known"], false);
    assert_eq!(json["overall_state"], "healthy");
    assert_eq!(json["availability"]["state"], "waiting_for_peer");
    assert_eq!(json["availability"]["offline_device_ids"][0], "dev-b");
    assert_eq!(json["protection"]["state"], "at_risk");
    let folders = json["folders"].as_array().unwrap();
    assert_eq!(folders.len(), 2);
    assert_eq!(folders[0]["local_path"], "/tmp/photos");
    assert_eq!(folders[0]["availability"]["state"], "waiting_for_peer");
    assert_eq!(folders[0]["protection"]["state"], "protected");
    assert_eq!(folders[0]["protection"]["device_ids"][0], "dev-b");
    assert_eq!(folders[1]["protection"]["state"], "at_risk");
    assert_eq!(folders[0]["on_demand"], true);
    assert_eq!(folders[0]["placeholder_count"], 7);
    assert_eq!(folders[1]["on_demand"], false);
    assert_eq!(folders[1]["placeholder_count"], 0);
}

#[test]
fn dimensions_json_of_an_older_daemon_reads_unknown_never_protected() {
    let status = StatusResponse { links: vec![LinkStatus::default()], ..Default::default() };
    let json = status_dimensions_json(&status);
    assert_eq!(json["folders"][0]["protection"]["state"], "unknown");
    assert_eq!(json["folders"][0]["availability"]["state"], "unknown");
}

#[test]
fn a_pending_conflict_reads_as_a_conflict_in_its_folder() {
    let reason = attention_reason("conflict_pending:g1", &[], &[]);
    assert_eq!(reason.category, AttentionCategory::Conflict);
    assert_eq!(reason.subject, "g1");
}

#[test]
fn attention_reason_carries_kind_and_actions_from_the_shared_item() {
    let waiting = attention_reason("peer_disconnected:dev", &[], &[]);
    assert_eq!(waiting.kind, AttentionKind::Waiting);
    let reclaimable =
        [VolumeFreeSpace { path: "/v".into(), reclaimable_bytes: 1, ..Default::default() }];
    let disk = attention_reason("low_disk_critical:/v", &[], &reclaimable);
    assert_eq!(disk.primary_action, ProductAction::FreeUpSpace);
    let retry = attention_reason("update_failed:net", &[], &[]);
    assert_eq!(retry.kind, AttentionKind::Retryable);
    assert_eq!(retry.primary_action, ProductAction::Retry);
    assert_eq!(retry.secondary_action, Some(ProductAction::ViewDetails));
    let disk = attention_reason("volume_unconfirmed:g1", &[], &[]);
    assert_eq!(disk.kind, AttentionKind::Permanent);
    assert_eq!(disk.primary_action, ProductAction::ConfirmDisk);
    assert_eq!(disk.secondary_action, Some(ProductAction::ViewDetails));
}

#[test]
fn a_timed_pause_deadline_is_shown_only_while_paused() {
    let timed = LinkStatus { paused: true, paused_until_unix: 5_000, ..link("/f/A", "g") };
    assert_eq!(folder_summary(&timed, &[], &[]).paused_until, Some(secs(5_000)));
    let until_resumed = LinkStatus { paused: true, ..link("/f/A", "g") };
    assert_eq!(folder_summary(&until_resumed, &[], &[]).paused_until, None);
    let stale = LinkStatus { paused_until_unix: 5_000, ..link("/f/A", "g") };
    assert_eq!(folder_summary(&stale, &[], &[]).paused_until, None);
}

#[test]
fn space_management_and_its_preview_never_read_unknown_as_on_or_eligible() {
    use yadorilink_ipc_proto::daemonctl::{
        PreviewSpaceReclaimResponse, SpaceManagementSettings, SpaceReclaimPreviewItem,
        SpaceReclaimVerdict as Wire,
    };

    assert_eq!(space_management(None), SpaceManagement { enabled: false });
    assert_eq!(
        space_management(Some(&SpaceManagementSettings { enabled: true })),
        SpaceManagement { enabled: true }
    );
    let item = |verdict: Wire| SpaceReclaimPreviewItem {
        group_id: "g".into(),
        path: "a.bin".into(),
        verdict: verdict as i32,
    };
    let preview = space_reclaim_preview(&PreviewSpaceReclaimResponse {
        items: vec![item(Wire::Eligible), item(Wire::Pinned), item(Wire::Unspecified)],
        unreadable_roots: 1,
    });
    assert_eq!(preview.unreadable_roots, 1);
    let verdicts: Vec<_> = preview.items.iter().map(|i| i.verdict).collect();
    assert_eq!(
        verdicts,
        [
            SpaceReclaimVerdict::Eligible,
            SpaceReclaimVerdict::Pinned,
            SpaceReclaimVerdict::SafetyBlocked
        ]
    );
}

#[test]
fn retained_originals_and_releases_keep_their_meaning_and_unknown_outcomes_stay_unknown() {
    use yadorilink_ipc_proto::daemonctl::{RetainedOriginal as Wire, RetainedRelease as Rel};
    let item = retained_original(&Wire {
        group_id: "g".into(),
        path: "a.txt".into(),
        size: 9,
        reachable: true,
        group_removed: false,
        ..Default::default()
    });
    assert_eq!((item.size, item.reachable, item.group_removed), (9, true, false));
    for (raw, outcome) in [
        ("removed", RetainedReleaseOutcome::Removed),
        ("left", RetainedReleaseOutcome::Left),
        ("saved_still_retained", RetainedReleaseOutcome::SavedStillRetained),
        ("something_new", RetainedReleaseOutcome::Unknown),
    ] {
        let done =
            retained_release(&Rel { path: "a".into(), outcome: raw.into(), detail: "why".into() });
        assert_eq!((done.outcome, done.detail.as_str()), (outcome, "why"));
    }
}

#[test]
fn a_rewind_preview_counts_restores_and_removals_and_hides_the_unchanged() {
    use yadorilink_ipc_proto::daemonctl::{RewindActionCounts, RewindPreviewResponse};
    let plan = RewindPreviewResponse {
        target_unix_nanos: 7,
        counts: Some(RewindActionCounts {
            create: 2,
            delete: 3,
            replace: 4,
            unchanged: 100,
            unavailable: 1,
        }),
        unavailable_message: "1 files unavailable; rewind cannot start".into(),
        plan_id: vec![9; 32],
        ..Default::default()
    };
    assert_eq!(
        rewind_preview(&plan),
        RewindPreview {
            target_unix_nanos: 7,
            restore_count: 6,
            remove_count: 3,
            unavailable_count: 1,
            unavailable_message: "1 files unavailable; rewind cannot start".into(),
            plan_id: vec![9; 32],
        }
    );
}

#[test]
fn a_rewind_run_maps_each_state_and_failure_and_keeps_the_daemons_words() {
    use yadorilink_ipc_proto::daemonctl::{
        RewindFailureKind as Kind, RewindRun as Wire, RewindRunState as State,
    };
    let run = |state: State, kind: Kind| {
        rewind_run(&Wire {
            run_id: "r".into(),
            state: state as i32,
            failure_kind: kind as i32,
            chunks_total: 5,
            chunks_done: 2,
            restored: 8,
            deleted: 1,
            message: "words".into(),
            ..Default::default()
        })
    };
    let state = |s: State| run(s, Kind::Unspecified);
    assert_eq!(state(State::Planned).state, RewindRunState::Gathering);
    assert_eq!(state(State::Prefetched).state, RewindRunState::Rewinding);
    assert_eq!(state(State::Committing).state, RewindRunState::Rewinding);
    assert_eq!(state(State::Done).state, RewindRunState::Done);
    assert_eq!(state(State::NeedsReplan).state, RewindRunState::Interrupted);
    assert_eq!(state(State::NeedsReplan).failure, None);
    let done = state(State::Done);
    assert_eq!((done.steps_total, done.steps_done, done.restored, done.removed), (5, 2, 8, 1));
    assert_eq!(done.message, "words");
    for (kind, failure) in [
        (Kind::ContentUnavailable, RewindFailure::ContentUnavailable),
        (Kind::Transient, RewindFailure::DevicesOffline),
        (Kind::FolderChanged, RewindFailure::FolderChanged),
        (Kind::CommitRefused, RewindFailure::CannotChangeFolder),
        (Kind::Interrupted, RewindFailure::Interrupted),
    ] {
        let failed = run(State::Failed, kind);
        assert_eq!((failed.state, failed.failure), (RewindRunState::Failed, Some(failure)));
    }
}

#[test]
fn a_rewind_start_answer_keeps_the_stale_and_refusal_wording() {
    use crate::ops::rewind::RewindStart;
    use yadorilink_ipc_proto::daemonctl::{RewindRefusalReason, RewindRefused};
    assert_eq!(
        rewind_start(RewindStart::Started { run_id: "r".into() }),
        RewindStartOutcome::Started { run_id: "r".into() }
    );
    assert_eq!(
        rewind_start(RewindStart::PlanStale {
            message: "m".into(),
            current_plan_id: vec![],
            current_counts: Default::default()
        }),
        RewindStartOutcome::FolderChanged { message: "m".into() }
    );
    assert_eq!(
        rewind_start(RewindStart::Refused(RewindRefused {
            reason: RewindRefusalReason::FolderSettling as i32,
            count: 0,
            message: "wait".into()
        })),
        RewindStartOutcome::Refused {
            reason: RewindRefusal::FolderSettling,
            message: "wait".into()
        }
    );
}

#[test]
fn a_run_that_cannot_be_followed_is_a_stopped_run_with_the_shared_words() {
    let run = rewind_run_missing("r".into());
    assert_eq!(
        (run.state, run.failure),
        (RewindRunState::Failed, Some(RewindFailure::Interrupted))
    );
    assert_eq!(run.message, RUN_MISSING_MESSAGE);
}

fn arg(name: &str, value: &str) -> AttentionArg {
    AttentionArg { name: name.into(), value: value.into() }
}

/// A shell renders a reason from its stable key and named arguments, orders it by severity and
/// offers its action; it never parses the daemon's code.
#[test]
fn attention_reason_carries_a_presentation_key_arguments_and_severity() {
    let disk = attention_reason("low_disk_critical:/v", &[], &[]);
    assert_eq!(disk.key, "disk_full");
    assert_eq!(disk.args, vec![arg("volume", "/v")]);
    assert_eq!(disk.severity, AttentionSeverity::Critical);

    let peer = attention_reason("peer_disconnected:dev", &[], &[]);
    assert_eq!((peer.key.as_str(), peer.severity), ("peer_unavailable", AttentionSeverity::Info));
    assert_eq!(peer.args, vec![arg("device", "dev")]);

    let error = attention_reason("recent_error:net", &[], &[]);
    assert_eq!(error.args, vec![arg("category", "net")]);

    let unknown = attention_reason("brand_new", &[], &[]);
    assert_eq!(unknown.key, "unrecognized");
    assert!(unknown.args.is_empty(), "{:?}", unknown.args);
}

/// The snapshot and every folder carry the product state with the one action to offer, so no
/// shell recomputes the precedence.
#[test]
fn the_snapshot_carries_the_product_state_and_next_action() {
    let paused = LinkStatus { paused: true, ..link("/f/Docs", "g1") };
    let conflicted = LinkStatus { conflict_count: 1, ..link("/f/Pics", "g2") };
    let response = StatusResponse { links: vec![paused, conflicted], ..Default::default() };
    let snapshot = status_snapshot(&computed(response.clone()), account(None), secs(1));
    assert_eq!(snapshot.product.state, ProductState::NeedsAttention);
    assert_eq!(snapshot.product.next_action, Some(ProductAction::ReviewConflict));
    assert_eq!((snapshot.product.attention_count, snapshot.product.paused_count), (1, 1));
    assert_eq!(snapshot.folders[0].product.state, ProductState::Paused);
    assert_eq!(snapshot.folders[0].product.next_action, Some(ProductAction::Resume));
    assert_eq!(snapshot.folders[1].product.state, ProductState::NeedsAttention);

    let idle = status_snapshot(&computed(StatusResponse::default()), account(None), secs(1));
    assert_eq!(idle.product.state, ProductState::UpToDate);
    assert_eq!(idle.product.next_action, None);
    assert_eq!(idle.product.bytes_remaining, None);
}

/// A request waiting on the owner reaches the folder as a count and as an attention item whose
/// one action is the review, scoped to the folder; the snapshot's next action is the same.
#[test]
fn a_waiting_approval_request_is_a_count_and_an_item_with_the_review_action() {
    let waiting = LinkStatus { pending_approvals: 2, ..link("/f/Shared", "g1") };
    let response = StatusResponse {
        links: vec![waiting, link("/f/Other", "g2")],
        attention_reasons: vec!["approval_pending:g1".into()],
        ..Default::default()
    };
    let snapshot = status_snapshot(&computed(response.clone()), account(None), secs(1));
    assert_eq!(snapshot.folders[0].pending_approvals, 2);
    assert_eq!(snapshot.folders[1].pending_approvals, 0);
    assert_eq!(snapshot.product.next_action, Some(ProductAction::ReviewApproval));
    assert_eq!(snapshot.folders[0].product.next_action, Some(ProductAction::ReviewApproval));
    let reason = &snapshot.attention_reasons[0];
    assert_eq!(reason.key, "approval_pending");
    assert_eq!(reason.primary_action, ProductAction::ReviewApproval);
    assert_eq!(reason.severity, AttentionSeverity::Warning);
    assert_eq!(reason.args, vec![arg("folder", "g1"), arg("folder_path", "/f/Shared")]);
}

/// Free up space is offered for a low-disk item only when the volume the item is about can get
/// space back; space a folder could give back on another volume does not count, and neither does
/// a volume the status does not list. Otherwise the item points at its details instead of a
/// button that cannot succeed.
#[test]
fn free_up_space_is_offered_only_for_the_volume_that_can_give_space_back() {
    let volume = |path: &str, reclaimable_bytes: u64| VolumeFreeSpace {
        path: path.into(),
        state: "low".into(),
        reclaimable_bytes,
        ..Default::default()
    };
    // Some folder can give space back, but the volume under pressure is another one.
    let other_volume_only = [volume("<block store>", 4096), volume("/mnt/photos", 0)];
    let on_it = [volume("<block store>", 4096), volume("/mnt/photos", 0)];
    let nothing = [volume("<block store>", 0)];
    let some = [link("/f/A", "g1"), LinkStatus { reclaimable_bytes: 4096, ..link("/f/B", "g2") }];
    for kind in ["low_disk", "low_disk_critical"] {
        let on = |subject: &str, volumes: &[VolumeFreeSpace]| {
            attention_reason(&format!("{kind}:{subject}"), &some, volumes).primary_action
        };
        assert_eq!(on("<block store>", &on_it), ProductAction::FreeUpSpace, "{kind}");
        // Negative controls: another volume, the same volume with nothing to give, an unlisted one.
        assert_eq!(on("/mnt/photos", &other_volume_only), ProductAction::ViewDetails, "{kind}");
        assert_eq!(on("<block store>", &nothing), ProductAction::ViewDetails, "{kind}");
        assert_eq!(on("/mnt/unlisted", &on_it), ProductAction::ViewDetails, "{kind}");
        assert_eq!(on("<block store>", &[]), ProductAction::ViewDetails, "{kind}");
    }
    // The snapshot reads the volumes from its own status and keeps the folder number as before.
    let snapshot = status_snapshot(
        &StatusResponse {
            links: some.to_vec(),
            volumes: on_it.to_vec(),
            attention_reasons: vec!["low_disk:<block store>".into(), "low_disk:/mnt/photos".into()],
            ..Default::default()
        },
        account(None),
        secs(1),
    );
    assert_eq!(snapshot.attention_reasons[0].primary_action, ProductAction::FreeUpSpace);
    assert_eq!(snapshot.attention_reasons[1].primary_action, ProductAction::ViewDetails);
    assert_eq!(snapshot.volumes[0].reclaimable_bytes, 4096);
    assert_eq!(snapshot.folders[1].reclaimable_bytes, 4096);
    assert_eq!(snapshot.folders[0].reclaimable_bytes, 0);
}

fn provider_link(root_id: &str) -> LinkStatus {
    LinkStatus {
        provider_root_id: root_id.into(),
        provider_display_name: "Photos".into(),
        ..link("provider:Photos", "g1")
    }
}

#[test]
fn provider_folder_carries_its_root_status_matched_by_id_prefix() {
    let roots = [
        WireProviderRoot {
            root_id: "deadbeef".into(),
            readiness: "ready".into(),
            ..Default::default()
        },
        WireProviderRoot {
            root_id: "01234567".into(),
            display_name: "Photos".into(),
            readiness: "ready".into(),
            eager: true,
            eager_state: "running".into(),
            eager_remote: 3,
            eager_hydrating: 2,
            eager_current: 5,
            stuck: vec![WireStuck { path: "a.txt".into(), failures: 4 }],
            kept_edits: 1,
            kept_edits_oldest_ms: 1500,
            pending_publications: 2,
            pending_oldest_ms: 900,
            unconfirmed_publications: 6,
            unconfirmed_oldest_ms: 100,
            ..Default::default()
        },
    ];
    // The link carries the root's full id; the status line only its first 8 digits.
    let summary = folder_summary(&provider_link("0123456789abcdef"), &[], &roots);
    let status = summary.provider_status.expect("matched by prefix");
    assert_eq!(status.readiness, "ready");
    let counters = status.counters.expect("readable");
    assert_eq!(
        counters.eager,
        Some(ProviderEagerProgress {
            state: "running".into(),
            remote: 3,
            hydrating: 2,
            current: 5
        })
    );
    assert_eq!(counters.stuck, vec![ProviderStuckFile { path: "a.txt".into(), failures: 4 }]);
    assert_eq!(
        counters.kept_edits,
        ProviderCount { count: 1, oldest: Some(Duration::from_millis(1500)) }
    );
    assert_eq!(
        counters.pending_publications,
        ProviderCount { count: 2, oldest: Some(Duration::from_millis(900)) }
    );
    assert_eq!(
        counters.unconfirmed_publications,
        ProviderCount { count: 6, oldest: Some(Duration::from_millis(100)) }
    );
}

/// The folder the system shows a provider root in is carried as it came, and is `None` (not an
/// empty path) while the host has not registered the root.
#[test]
fn a_provider_root_carries_the_folder_the_system_shows_it_in() {
    let registered = [WireProviderRoot {
        root_id: "01234567".into(),
        sync_root_path: r"C:\Users\a\YadoriLink\Photos".into(),
        ..Default::default()
    }];
    let status = folder_summary(&provider_link("0123456789abcdef"), &[], &registered)
        .provider_status
        .unwrap();
    assert_eq!(status.sync_root_path.as_deref(), Some(r"C:\Users\a\YadoriLink\Photos"));
    let waiting = [WireProviderRoot { root_id: "01234567".into(), ..Default::default() }];
    let status =
        folder_summary(&provider_link("0123456789abcdef"), &[], &waiting).provider_status.unwrap();
    assert_eq!(status.sync_root_path, None);
}

#[test]
fn unreadable_provider_counters_are_unknown_not_zero() {
    let roots = [WireProviderRoot {
        root_id: "01234567".into(),
        readiness: "kept edits unreadable: disk".into(),
        counters_unreadable: true,
        ..Default::default()
    }];
    let status =
        folder_summary(&provider_link("0123456789abcdef"), &[], &roots).provider_status.unwrap();
    assert_eq!(status.counters, None);
    assert_eq!(status.readiness, "kept edits unreadable: disk");
}

#[test]
fn zero_counts_have_no_oldest_and_plain_folders_have_no_provider_status() {
    let roots = [WireProviderRoot { root_id: "01234567".into(), ..Default::default() }];
    let counters = folder_summary(&provider_link("0123456789abcdef"), &[], &roots)
        .provider_status
        .unwrap()
        .counters
        .unwrap();
    assert_eq!(counters.kept_edits, ProviderCount { count: 0, oldest: None });
    assert_eq!(counters.eager, None);
    assert_eq!(folder_summary(&link("/f/Docs", "g2"), &[], &roots).provider_status, None);
    // A provider folder whose root the daemon reports nothing about stays unknown.
    assert_eq!(folder_summary(&provider_link("ffffffffffff"), &[], &roots).provider_status, None);
}

#[test]
fn the_daemons_engine_api_version_is_none_until_it_reports_one() {
    let mut response = StatusResponse::default();
    assert_eq!(status_snapshot(&response, account(None), secs(1)).engine_api_version, None);
    response.host_api_version = 7;
    assert_eq!(status_snapshot(&response, account(None), secs(1)).engine_api_version, Some(7));
}

#[test]
fn identify_converts_every_ownership_state() {
    use yadorilink_ipc_proto::daemonctl::{
        IdentifyResponse, OwnershipRecordInfo, OwnershipRecordStatus,
    };
    let base = IdentifyResponse {
        version: "1.2.3".into(),
        engine_api_version: 7,
        release_id: "c:d".into(),
        install_source: "app_bundle".into(),
        install_root: "/Applications/YadoriLink.app".into(),
        owner: "gui".into(),
        pid: 42,
        started_at_unix: 1_700_000_000,
        data_dir: "/data/yl".into(),
        ..Default::default()
    };
    let recorded = daemon_identity(&IdentifyResponse {
        ownership_status: OwnershipRecordStatus::Recorded as i32,
        ownership_record: Some(OwnershipRecordInfo {
            owner: "cli".into(),
            install_source: "script".into(),
            install_root: "/r".into(),
            release_id: String::new(),
            written_at_unix: 5,
        }),
        ..base.clone()
    });
    assert_eq!(recorded.owner, DaemonOwner::Gui);
    assert_eq!(recorded.release_id.as_deref(), Some("c:d"));
    assert_eq!(recorded.engine_api_version, 7);
    assert_eq!(recorded.data_dir.as_deref(), Some("/data/yl"));
    assert_eq!(daemon_identity(&IdentifyResponse::default()).data_dir, None);
    let DataAreaOwnership::Recorded { record } = recorded.ownership else { panic!("not recorded") };
    assert_eq!((record.owner, record.release_id), (DaemonOwner::Cli, None));
    assert_eq!(record.install_source, "script");

    let missing = daemon_identity(&IdentifyResponse {
        ownership_status: OwnershipRecordStatus::Missing as i32,
        ..base.clone()
    });
    assert_eq!(missing.ownership, DataAreaOwnership::NotRecorded);

    for status in
        [OwnershipRecordStatus::Unreadable as i32, OwnershipRecordStatus::Unspecified as i32, 99]
    {
        let unreadable = daemon_identity(&IdentifyResponse {
            ownership_status: status,
            ownership_detail: "bad".into(),
            ..base.clone()
        });
        assert_eq!(unreadable.ownership, DataAreaOwnership::Unreadable { detail: "bad".into() });
    }
}

#[test]
fn a_safe_stop_answer_without_an_outcome_is_never_success() {
    use yadorilink_ipc_proto::daemonctl::request_safe_stop_response::Outcome;
    use yadorilink_ipc_proto::daemonctl::{
        RequestSafeStopResponse, SafeStopBusy, SafeStopStopping,
    };
    assert_eq!(
        safe_stop_outcome(&RequestSafeStopResponse {
            outcome: Some(Outcome::Stopping(SafeStopStopping { already_in_progress: true }))
        }),
        SafeStopOutcome::Stopping { already_in_progress: true }
    );
    for (wire, reason) in [
        (1, SafeStopBusyReason::WritesInProgress),
        (2, SafeStopBusyReason::CheckpointFailed),
        (3, SafeStopBusyReason::AnotherRequestInProgress),
        (0, SafeStopBusyReason::WritesInProgress),
        (77, SafeStopBusyReason::WritesInProgress),
    ] {
        let busy = safe_stop_outcome(&RequestSafeStopResponse {
            outcome: Some(Outcome::Busy(SafeStopBusy {
                reason: wire,
                detail: "d".into(),
                retry_after_secs: 0,
            })),
        });
        assert_eq!(busy, SafeStopOutcome::Busy { reason, retry_after_secs: 1, detail: "d".into() });
    }
    assert!(matches!(
        safe_stop_outcome(&RequestSafeStopResponse { outcome: None }),
        SafeStopOutcome::Busy { .. }
    ));
}

/// The attention item for a restored database offers the operation that ends it, and the facade
/// has that operation.
#[test]
fn a_restored_database_offers_the_start_over_action() {
    let reason = attention_reason("database_restored:older_generation", &[], &[]);
    assert_eq!(reason.primary_action, ProductAction::StartOverAsNewDevice);
    assert_eq!(reason.severity, AttentionSeverity::Critical);
}

/// The identity of a condition is the same on every poll, differs between folders, devices and
/// error categories, and ignores everything that merely describes it (the folder's local path,
/// the raw text's other parts), so a shell can notify once per condition and again only after the
/// condition cleared.
#[test]
fn an_attention_identity_is_stable_per_condition_and_distinct_between_conditions() {
    let moved = [link("/Users/a/Docs", "g1")];
    let renamed = [link("/Users/a/Renamed", "g1")];
    let id = |raw: &str, links: &[LinkStatus]| attention_reason(raw, links, &[]).identity;
    assert_eq!(id("conflict:g1", &moved), id("conflict:g1", &renamed));
    assert_eq!(id("conflict:g1", &moved), id("conflict:g1", &[]));
    assert_ne!(id("conflict:g1", &moved), id("conflict:g2", &moved));
    assert_ne!(id("conflict:g1", &moved), id("held:g1", &moved));
    // conflict and a pending conflict are the same condition for the person.
    assert_eq!(id("conflict:g1", &moved), id("conflict_pending:g1", &moved));
    assert_ne!(id("low_disk:/a", &[]), id("low_disk_critical:/a", &[]));
    assert_ne!(id("low_disk:/a", &[]), id("low_disk:/b", &[]));
    assert_ne!(id("recent_error:net", &[]), id("recent_error:disk", &[]));
    assert_eq!(id("approval_pending:g1", &moved), "approval_pending:g1");
    assert_eq!(id("update_required", &[]), "update_required:");
}

/// A failed or canceled received transfer offers a retry and names why it stopped as a closed
/// reason; a code this build does not know stays visible as `Other`.
#[test]
fn a_failed_received_transfer_carries_its_reason_and_offers_a_retry() {
    let failed = incoming_transfer(&InboxTransfer {
        status: "failed".into(),
        failure: "sender_canceled".into(),
        ..Default::default()
    });
    assert_eq!(failed.failure, Some(TransferFailure::SenderCanceled));
    assert!(failed.can_retry);
    let canceled =
        incoming_transfer(&InboxTransfer { status: "canceled".into(), ..Default::default() });
    assert!(canceled.can_retry && canceled.failure.is_none());
    let done =
        incoming_transfer(&InboxTransfer { status: "completed".into(), ..Default::default() });
    assert!(!done.can_retry);
    let newer = incoming_transfer(&InboxTransfer {
        status: "failed".into(),
        failure: "brand_new".into(),
        ..Default::default()
    });
    assert_eq!(newer.failure, Some(TransferFailure::Other { raw: "brand_new".into() }));
}

/// A sent transfer reaches the shell with its lifecycle status, closed failure reason and whether
/// a retry is offered; the daemon decides the last, the shell adds no rule.
#[test]
fn a_sent_transfer_carries_its_status_reason_and_retry_offer() {
    use yadorilink_ipc_proto::daemonctl::SentTransferEntry;
    for (raw, status) in [
        ("offered", OutgoingTransferStatus::Offered),
        ("accepted", OutgoingTransferStatus::Accepted),
        ("completed", OutgoingTransferStatus::Completed),
        ("declined", OutgoingTransferStatus::Declined),
        ("canceled", OutgoingTransferStatus::Canceled),
        ("paused", OutgoingTransferStatus::Other { raw: "paused".into() }),
    ] {
        let t = outgoing_transfer(&SentTransferEntry { status: raw.into(), ..Default::default() });
        assert_eq!(t.status, status);
    }
    let entry = outgoing_transfer(&SentTransferEntry {
        transfer_id: "t".into(),
        target_device_id: "d".into(),
        files: vec![InboxFileSummary { relative_path: "a".into(), size: 3 }],
        total_size: 3,
        created_at_unix_nanos: 5_000_000_000,
        status: "offered".into(),
        failure: "unreachable".into(),
        can_retry: true,
        bytes_sent: 2,
    });
    assert_eq!(entry.bytes_sent, 2);
    assert_eq!(entry.failure, Some(TransferFailure::Unreachable));
    // An accepted transfer whose other device stopped reading keeps its own closed reason, not
    // the open fallback; a code this build does not know stays `Other`.
    let stalled = outgoing_transfer(&SentTransferEntry {
        status: "accepted".into(),
        failure: "stalled".into(),
        ..Default::default()
    });
    assert_eq!(stalled.status, OutgoingTransferStatus::Accepted);
    assert_eq!(stalled.failure, Some(TransferFailure::Stalled));
    for (code, expected) in [
        ("local_network_blocked", TransferFailure::LocalNetworkBlocked),
        ("sender_gone", TransferFailure::SenderGone),
        ("receiver_canceled", TransferFailure::ReceiverCanceled),
        ("receiver_stopped", TransferFailure::ReceiverStopped),
    ] {
        let entry = outgoing_transfer(&SentTransferEntry {
            status: "accepted".into(),
            failure: code.into(),
            ..Default::default()
        });
        assert_eq!(entry.failure, Some(expected), "{code}");
    }
    let none =
        outgoing_transfer(&SentTransferEntry { status: "accepted".into(), ..Default::default() });
    assert_eq!(none.failure, None);
    assert!(entry.can_retry);
    assert_eq!(entry.created_at, Some(secs(5)));
    assert_eq!(entry.files, vec![IncomingFile { relative_path: "a".into(), size: 3 }]);
}

fn unreadable(path: &str, reason: &str) -> yadorilink_ipc_proto::daemonctl::UnreadableFile {
    yadorilink_ipc_proto::daemonctl::UnreadableFile { path: path.into(), reason: reason.into() }
}

#[test]
fn unreadable_files_map_each_reason_with_its_advice_key() {
    let mut l = link("/f/A", "g1");
    l.unreadable_file_count = 4;
    l.unreadable_files = vec![
        unreadable("a/b.txt", "permission_denied"),
        unreadable("sock", "not_a_regular_file"),
        unreadable("c.bin", "read_failed"),
        unreadable("d", "a_reason_from_the_future"),
    ];
    let folder = folder_summary(&l, &[], &[]);
    let seen: Vec<_> = folder
        .unreadable_files
        .iter()
        .map(|f| (f.path.as_str(), f.reason, f.advice_key.as_str()))
        .collect();
    assert_eq!(
        seen,
        vec![
            (
                "a/b.txt",
                UnreadableFileReason::PermissionDenied,
                "unreadable_file.advice.permission_denied"
            ),
            (
                "sock",
                UnreadableFileReason::NotARegularFile,
                "unreadable_file.advice.not_a_regular_file"
            ),
            ("c.bin", UnreadableFileReason::ReadFailed, "unreadable_file.advice.read_failed"),
            ("d", UnreadableFileReason::Unknown, "unreadable_file.advice.unknown"),
        ]
    );
    assert_eq!(folder.unreadable_files_more, 0);
}

#[test]
fn unreadable_files_are_capped_and_the_rest_counted() {
    let mut l = link("/f/A", "g1");
    l.unreadable_file_count = 500;
    l.unreadable_files = (0..60).map(|i| unreadable(&format!("f{i}"), "read_failed")).collect();
    let folder = folder_summary(&l, &[], &[]);
    assert_eq!(folder.unreadable_files.len(), MAX_UNREADABLE_FILES);
    assert_eq!(folder.unreadable_files_more, 500 - MAX_UNREADABLE_FILES as u64);
}

#[test]
fn unreadable_files_never_show_absolute_or_escaping_paths_but_still_count() {
    let mut l = link("/f/A", "g1");
    l.unreadable_file_count = 5;
    l.unreadable_files = vec![
        unreadable("/etc/passwd", "permission_denied"),
        unreadable("C:\\x", "permission_denied"),
        unreadable("c:/x", "permission_denied"),
        unreadable("a/../../b", "permission_denied"),
        unreadable("ab:c/..c", "read_failed"),
    ];
    let folder = folder_summary(&l, &[], &[]);
    assert_eq!(
        folder.unreadable_files.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(),
        vec!["ab:c/..c"]
    );
    assert_eq!(folder.unreadable_files_more, 4);
}

#[test]
fn a_count_without_a_list_still_reports_the_files_as_more() {
    let mut l = link("/f/A", "g1");
    l.unreadable_file_count = 3;
    let folder = folder_summary(&l, &[], &[]);
    assert!(folder.unreadable_files.is_empty());
    assert_eq!(folder.unreadable_files_more, 3);
    assert_eq!(folder_summary(&link("/f/B", "g2"), &[], &[]).unreadable_files_more, 0);
}

#[test]
fn an_appcast_item_check_maps_outcome_reason_and_entry() {
    use yadorilink_ipc_proto::daemonctl::{UpdateVerifiedEntry, UpdateVerifiedEntryResponse};
    let allowed = appcast_item_check(&UpdateVerifiedEntryResponse {
        outcome: "allowed".into(),
        entry: Some(UpdateVerifiedEntry {
            sparkle_build: 42,
            version: "1.0.0".into(),
            ..Default::default()
        }),
        ..Default::default()
    });
    assert_eq!(
        (allowed.outcome, allowed.reason, allowed.message),
        (AppcastItemOutcome::Allowed, None, None)
    );
    assert_eq!(allowed.entry.unwrap().sparkle_build, Some(42));

    let cannot = appcast_item_check(&UpdateVerifiedEntryResponse {
        outcome: "cannot_confirm".into(),
        reason_code: "manifest_expired".into(),
        reason: "expired".into(),
        entry: None,
    });
    assert_eq!(cannot.outcome, AppcastItemOutcome::CannotConfirm);
    assert_eq!(cannot.reason, Some(AppcastItemReason::ManifestExpired));

    // A code a newer daemon adds is kept raw and is never read as allowed.
    let newer = appcast_item_check(&UpdateVerifiedEntryResponse {
        outcome: "later".into(),
        reason_code: "later_reason".into(),
        ..Default::default()
    });
    assert_eq!(newer.outcome, AppcastItemOutcome::Unknown { raw: "later".into() });
    assert_eq!(newer.reason, Some(AppcastItemReason::Unknown { raw: "later_reason".into() }));

    for (code, reason) in [
        ("url_missing", AppcastItemReason::UrlMissing),
        ("url_mismatch", AppcastItemReason::UrlMismatch),
        ("length_missing", AppcastItemReason::LengthMissing),
        ("length_mismatch", AppcastItemReason::LengthMismatch),
        ("sha256_missing", AppcastItemReason::Sha256Missing),
    ] {
        let check = appcast_item_check(&UpdateVerifiedEntryResponse {
            outcome: "refused".into(),
            reason_code: code.into(),
            ..Default::default()
        });
        assert_eq!(check.reason, Some(reason));
    }
}

#[test]
fn dimensions_json_names_the_typed_degraded_cause_per_folder() {
    use yadorilink_ipc_proto::daemonctl::DegradedCause as Wire;
    let status = StatusResponse {
        links: vec![
            LinkStatus {
                degraded: true,
                degraded_reason: "Waiting for disk space".into(),
                degraded_cause: Wire::WaitingForDiskSpace as i32,
                ..link("/tmp/a", "g1")
            },
            link("/tmp/b", "g2"),
        ],
        ..Default::default()
    };
    let json = status_dimensions_json(&status);
    assert_eq!(json["folders"][0]["degraded_cause"], "waiting_for_disk_space");
    assert!(json["folders"][1]["degraded_cause"].is_null());
}

#[test]
fn activity_request_carries_the_filter_and_cursor() {
    let request = activity_request(
        50,
        Some(77),
        Some(&ActivityFilter {
            kinds: vec![ActivityKind::Deleted, ActivityKind::Conflict],
            origin: ActivityOrigin::OtherDevices,
        }),
    );
    assert_eq!(request.limit, 50);
    assert_eq!(request.before_cursor, 77);
    assert_eq!(request.kinds, [yadorilink_ipc_proto::daemonctl::ActivityKind::Deleted as i32, 4]);
    assert_eq!(request.origin(), yadorilink_ipc_proto::daemonctl::ActivityOrigin::OtherDevices);
    let none = activity_request(10, None, None);
    assert_eq!((none.before_cursor, none.kinds.len(), none.origin), (0, 0, 0));
}

#[test]
fn activity_page_names_devices_and_pages_by_cursor() {
    use yadorilink_ipc_proto::daemonctl::{ActivityEventInfo, ActivityKind as Wire};
    let event = |cursor, origin: &str, kind: Wire| ActivityEventInfo {
        cursor,
        local_path: "/f/Docs".into(),
        path: "a.txt".into(),
        kind: kind as i32,
        origin_device_id: origin.into(),
        is_this_device: origin.is_empty(),
        at_unix_nanos: 1_000_000_000,
        other_origin_device_id: String::new(),
    };
    let names = std::collections::HashMap::from([("dev-b".to_string(), "Laptop".to_string())]);
    let events = [event(9, "dev-b", Wire::Updated), event(8, "", Wire::Added)];
    let full = activity_page(2, &events, &names);
    assert_eq!(full.next_cursor, Some(8), "a full page may have more");
    assert_eq!(full.events[0].origin_device_name.as_deref(), Some("Laptop"));
    assert_eq!(full.events[0].kind, ActivityKind::Updated);
    assert!(full.events[1].is_this_device);
    assert_eq!(full.events[1].origin_device_id, None);
    assert!(full.events[0].at.is_some());
    let short = activity_page(3, &events, &names);
    assert_eq!(short.next_cursor, None, "a short page ends the list");
    // A kind this build does not know is dropped, not shown as something else.
    assert!(activity_page(5, &[event(1, "", Wire::Unspecified)], &names).events.is_empty());
}

#[test]
fn send_link_ttl_choices_are_one_hour_one_day_and_seven_days() {
    assert_eq!(SendLinkTtl::OneHour.seconds(), 3_600);
    assert_eq!(SendLinkTtl::OneDay.seconds(), 86_400);
    assert_eq!(SendLinkTtl::SevenDays.seconds(), 604_800);
    // The service refuses less than 60 seconds.
    assert!(SendLinkTtl::OneHour.seconds() >= 60);
}

#[test]
fn a_created_send_link_carries_its_code_and_expiry() {
    let link = send_link(yadorilink_ipc_proto::daemonctl::CreateSendLinkResponse {
        link_id: "link-1".into(),
        code: "ABCD".into(),
        expires_at_unix: 1_800_000_000,
    });
    assert_eq!(link.link_id, "link-1");
    assert_eq!(link.code, "ABCD");
    assert_eq!(
        link.expires_at,
        Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_800_000_000))
    );
}

#[test]
fn every_send_link_state_maps_and_an_unknown_one_does_not() {
    use yadorilink_ipc_proto::daemonctl::{SendLinkState as Wire, SendLinkStatusResponse};
    let status = |state: i32| SendLinkStatusResponse {
        state,
        receiver_device_name: String::new(),
        transfer_id: String::new(),
        failure: String::new(),
    };
    let cases = [
        (Wire::Waiting, SendLinkState::Waiting),
        (Wire::Redeemed, SendLinkState::Redeemed),
        (Wire::Transferring, SendLinkState::Transferring),
        (Wire::Done, SendLinkState::Done),
        (Wire::Cancelled, SendLinkState::Cancelled),
        (Wire::Expired, SendLinkState::Expired),
        (Wire::Interrupted, SendLinkState::Interrupted),
    ];
    for (wire, state) in cases {
        let converted = send_link_status("l".into(), status(wire as i32)).unwrap();
        assert_eq!(converted.state, state);
        // Unset text is absent, not an empty name.
        assert_eq!(converted.receiver_device_name, None);
        assert_eq!(converted.transfer_id, None);
    }
    assert_eq!(send_link_status("l".into(), status(Wire::Unspecified as i32)), None);
    assert_eq!(send_link_status("l".into(), status(999)), None);

    let named = send_link_status(
        "l".into(),
        SendLinkStatusResponse {
            state: Wire::Redeemed as i32,
            receiver_device_name: "Kai's iPhone".into(),
            transfer_id: "t-1".into(),
            failure: "sender_canceled".into(),
        },
    )
    .unwrap();
    assert_eq!(named.failure, Some(TransferFailure::SenderCanceled));
    assert_eq!(named.receiver_device_name.as_deref(), Some("Kai's iPhone"));
    assert_eq!(named.transfer_id.as_deref(), Some("t-1"));
}

#[test]
fn a_no_space_failure_is_its_own_transfer_failure() {
    let sent = yadorilink_ipc_proto::daemonctl::SentTransferEntry {
        transfer_id: "t".into(),
        status: "accepted".into(),
        failure: "no_space".into(),
        ..Default::default()
    };
    assert_eq!(outgoing_transfer(&sent).failure, Some(TransferFailure::NoSpace));
}

#[test]
fn a_send_link_preview_totals_what_the_link_carries() {
    use yadorilink_ipc_proto::daemonctl::{PreviewSendLinkResponse, SendLinkFile};
    let preview = send_link_preview(PreviewSendLinkResponse {
        sender_name: "Kai's Mac".into(),
        files: vec![
            SendLinkFile { name: "a.txt".into(), size: 10 },
            SendLinkFile { name: "d/b.txt".into(), size: 32 },
        ],
        expires_at_unix: 1_800_000_000,
    });
    assert_eq!(preview.sender_name, "Kai's Mac");
    assert_eq!(preview.total_size, 42);
    assert_eq!(preview.files[1], IncomingFile { relative_path: "d/b.txt".into(), size: 32 });
    assert!(preview.expires_at.is_some());
    // A sender who attached no list shows an empty one, not a made-up file.
    let none = send_link_preview(PreviewSendLinkResponse::default());
    assert!(none.files.is_empty() && none.total_size == 0);
}

#[test]
fn a_primary_transfer_listing_converts_with_times_direction_and_status() {
    use crate::ops::primary_transfer::{PrimaryTransfer, TransferDirection};
    let wire = PrimaryTransfer {
        transfer_id: "t".into(),
        group_id: "g".into(),
        group_name: "photos".into(),
        direction: TransferDirection::Incoming,
        status: "pending".into(),
        to_device_id: "d".into(),
        created_at: 100,
        expires_at: 200,
    };
    let summary = primary_transfer_summary(&wire);
    assert_eq!(summary.direction, PrimaryTransferDirection::Incoming);
    assert_eq!(summary.status, PrimaryTransferStatus::Pending);
    assert_eq!(summary.expires_at, UNIX_EPOCH + Duration::from_secs(200));
    let odd = primary_transfer_summary(&PrimaryTransfer { status: "expired".into(), ..wire });
    assert_eq!(odd.status, PrimaryTransferStatus::Other { raw: "expired".into() });
}

#[test]
fn last_synced_reaches_the_snapshot_and_the_folder() {
    let mut response =
        computed(StatusResponse { links: vec![link("/a", "g")], ..Default::default() });
    response.product.as_mut().unwrap().last_synced_unix = Some(1_700_000_000);
    response.links[0].product.as_mut().unwrap().last_synced_unix = Some(1_600_000_000);
    let snapshot = status_snapshot(&response, account(None), secs(1));
    assert_eq!(snapshot.product.last_synced, Some(secs(1_700_000_000)));
    assert_eq!(snapshot.folders[0].product.last_synced, Some(secs(1_600_000_000)));

    response.product.as_mut().unwrap().last_synced_unix = None;
    assert_eq!(status_snapshot(&response, account(None), secs(1)).product.last_synced, None);
}

/// The count of changes no other device holds yet reaches the shells as the daemon reported it.
#[test]
fn a_folder_carries_the_daemons_pending_local_changes() {
    let pending = LinkStatus { pending_local_changes: 7, ..link("/f/Docs", "g1") };
    assert_eq!(folder_summary(&pending, &[], &[]).pending_local_changes, 7);
    assert_eq!(folder_summary(&link("/f/Docs", "g1"), &[], &[]).pending_local_changes, 0);
}

#[test]
fn debug_output_of_a_created_send_link_never_shows_the_code() {
    let link = SendLink { link_id: "link-1".into(), code: "SECRETCODE".into(), expires_at: None };
    let text = format!("{link:?}");
    assert!(!text.contains("SECRETCODE"), "{text}");
    assert!(text.contains("link-1"));
}

#[test]
fn a_folder_carries_the_daemons_retention_apply_state_and_counts_as_they_are() {
    use yadorilink_ipc_proto::daemonctl::RetentionApplyState as Wire;
    let applying = LinkStatus {
        retention_rule_count: 3,
        retention_apply_state: Wire::Pending as i32,
        retention_done_count: 12,
        retention_skipped_count: 4,
        retention_retryable_count: 2,
        ..link("/f/Docs", "g1")
    };
    assert_eq!(
        folder_summary(&applying, &[], &[]).retention,
        RetentionApplySummary {
            rule_count: 3,
            state: RetentionApplyState::Pending,
            freed: 12,
            left_on_purpose: 4,
            to_retry: 2,
        }
    );
    let done = LinkStatus { retention_apply_state: Wire::Done as i32, ..applying };
    assert_eq!(folder_summary(&done, &[], &[]).retention.state, RetentionApplyState::Done);
    // No online-only rule, or a daemon that does not say, reads as nothing to show; the counts of
    // a folder with no rules are zero.
    for state in [Wire::None, Wire::Unspecified] {
        let idle = LinkStatus { retention_apply_state: state as i32, ..link("/f/Docs", "g1") };
        assert_eq!(
            folder_summary(&idle, &[], &[]).retention,
            RetentionApplySummary {
                rule_count: 0,
                state: RetentionApplyState::None,
                freed: 0,
                left_on_purpose: 0,
                to_retry: 0,
            }
        );
    }
}

#[test]
fn a_folder_carries_the_device_its_newest_change_came_from_and_is_named_from_the_device_list() {
    let from_b =
        LinkStatus { last_change_origin_device_id: "device-b".into(), ..link("/f/A", "g1") };
    let mut folders = vec![
        folder_summary(&from_b, &[], &[]),
        folder_summary(&link("/f/B", "g2"), &[], &[]), // newest change made here, or author unknown
    ];
    assert_eq!(folders[0].last_change_origin_device_id.as_deref(), Some("device-b"));
    assert_eq!(folders[0].last_change_origin_device_name, None, "named by the caller");
    assert_eq!(folders[1].last_change_origin_device_id, None);

    let names =
        std::collections::HashMap::from([("device-b".to_string(), "MacBook Air".to_string())]);
    name_last_change_devices(&mut folders, &names);
    assert_eq!(folders[0].last_change_origin_device_name.as_deref(), Some("MacBook Air"));
    assert_eq!(folders[1].last_change_origin_device_name, None);
    // A device the list does not have stays unnamed; the id is still there.
    name_last_change_devices(&mut folders, &std::collections::HashMap::new());
    assert_eq!(folders[0].last_change_origin_device_name, None);
    assert_eq!(folders[0].last_change_origin_device_id.as_deref(), Some("device-b"));
}

#[test]
fn a_conflict_event_names_both_devices_and_other_events_name_one() {
    use yadorilink_ipc_proto::daemonctl::{ActivityEventInfo, ActivityKind as Wire};
    let names = std::collections::HashMap::from([
        ("device-b".to_string(), "MacBook Air".to_string()),
        ("device-c".to_string(), "Studio".to_string()),
    ]);
    let conflict = ActivityEventInfo {
        kind: Wire::Conflict as i32,
        origin_device_id: "device-c".into(),
        other_origin_device_id: "device-b".into(),
        ..Default::default()
    };
    let added = ActivityEventInfo {
        kind: Wire::Added as i32,
        origin_device_id: "device-c".into(),
        ..Default::default()
    };
    let page = activity_page(10, &[conflict, added], &names);
    let (conflict, added) = (&page.events[0], &page.events[1]);
    assert_eq!(conflict.origin_device_name.as_deref(), Some("Studio"));
    assert_eq!(conflict.other_origin_device_id.as_deref(), Some("device-b"));
    assert_eq!(conflict.other_origin_device_name.as_deref(), Some("MacBook Air"));
    assert_eq!((&added.other_origin_device_id, &added.other_origin_device_name), (&None, &None));
}
