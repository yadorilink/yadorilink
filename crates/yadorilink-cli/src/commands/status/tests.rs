#![cfg(test)]

use yadorilink_ipc_proto::daemonctl::{
    ActiveTransferProgress, DurabilityEvidence, HeldFile, RecentSyncError,
};

use super::*;

fn base_link() -> LinkStatus {
    LinkStatus {
        local_path: "/tmp/photos".into(),
        provider_root_id: String::new(),
        provider_display_name: String::new(),
        group_id: "group-1".into(),
        paused: false,
        conflict_count: 0,
        conflicts_pending: 0,
        conflict_note: String::new(),
        materialization_policy: "eager".into(),
        hydrated_count: 0,
        placeholder_count: 0,
        hydrating_count: 0,
        requested_content_count: 0,
        held_file_count: 0,
        held_files: vec![],
        skipped_symlink_count: 0,
        stranded_directory_count: 0,
        degraded: false,
        degraded_reason: String::new(),
        has_active_transfer: false,
        transfer_bytes_done: 0,
        transfer_bytes_total: 0,
        transfer_blocks_done: 0,
        transfer_blocks_total: 0,
        transfer_eta_seconds: 0,
        durability_status: GroupDurabilityStatus::Protected as i32,
        durability_evidence: DurabilityEvidence::CorroboratedIndex as i32,
        durability_check_pending: false,
        policy_stale: false,
        ambiguous: false,
        ambiguous_local_paths: Vec::new(),
        capture_volume_changed: false,
        local_storage_state: LocalStorageState::FullCopy as i32,
        fetch_availability: FetchAvailability::AvailableNow as i32,
        full_replica_device_ids: Vec::new(),
        ..Default::default()
    }
}

/// a link with no held files renders no held-related output
/// at all — no `held=0` suffix, no detail lines.
#[test]
fn no_held_files_renders_no_new_output() {
    let link = base_link();
    assert_eq!(held_summary_suffix(&link), "");
    assert!(held_file_detail_lines(&link, false).is_empty());
}

/// No full-replica peers configured renders no "Complete
/// copies" lines at all.
#[test]
fn no_full_replica_peers_renders_no_complete_copies_lines() {
    let link = base_link();
    assert!(complete_copies_detail_lines(&link, &[], &DeviceNames::default(), false).is_empty());
}

/// the label says "configured
/// full copy," never "complete copy" -- this list is a structural,
/// content-blind netmap declaration, not peer-confirmed content
/// custody (that's `durability_status`'s job). A `Connected` device
/// reads "available".
#[test]
fn complete_copies_lines_report_available_for_a_connected_device() {
    let mut link = base_link();
    link.full_replica_device_ids = vec!["nas-1".into()];
    let mut peer = base_peer();
    peer.device_id = "nas-1".into();
    peer.reachability = PeerReachability::Connected as i32;

    let lines = complete_copies_detail_lines(&link, &[peer], &DeviceNames::default(), false);
    assert_eq!(lines, vec!["    configured full copy: nas-1  (available)".to_string()]);
}

/// a device this daemon has
/// never even seen (absent from `peers` entirely) reads "unknown",
/// NOT "offline" -- "offline" is a positive claim this daemon has no
/// basis for here. Only an explicit `Unreachable` reachability earns
/// "offline".
#[test]
fn unseen_device_reads_unknown_not_offline() {
    let mut link = base_link();
    link.full_replica_device_ids = vec!["unseen-device".into()];

    let lines = complete_copies_detail_lines(&link, &[], &DeviceNames::default(), false);
    assert_eq!(lines, vec!["    configured full copy: unseen-d...  (unknown)".to_string()]);
}

/// `Connecting`/`Unspecified` are ALSO not
/// positive "offline" evidence -- they read "unknown" too, the same
/// as a device absent from `peers` entirely.
#[test]
fn indeterminate_reachability_states_read_unknown() {
    let mut link = base_link();
    link.full_replica_device_ids = vec!["nas-1".into()];
    for state in [PeerReachability::Connecting, PeerReachability::Unspecified] {
        let mut peer = base_peer();
        peer.device_id = "nas-1".into();
        peer.reachability = state as i32;
        let lines = complete_copies_detail_lines(&link, &[peer], &DeviceNames::default(), false);
        assert_eq!(
            lines,
            vec!["    configured full copy: nas-1  (unknown)".to_string()],
            "reachability {state:?} must read unknown, not offline"
        );
    }
}

/// A full-replica device that IS known but currently `Unreachable`
/// (a positive, known-down fact) reads "offline" -- distinct from the
/// "unknown" cases above.
#[test]
fn complete_copies_line_reports_offline_for_a_known_unreachable_device() {
    let mut link = base_link();
    link.full_replica_device_ids = vec!["nas-1".into()];
    let mut peer = base_peer();
    peer.device_id = "nas-1".into();
    peer.reachability = PeerReachability::Unreachable as i32;

    let lines = complete_copies_detail_lines(&link, &[peer], &DeviceNames::default(), false);
    assert_eq!(lines, vec!["    configured full copy: nas-1  (offline)".to_string()]);
}

/// a link with held files shows the count and, for each
/// held file, its path and reason.
#[test]
fn held_files_render_count_and_per_file_reason() {
    let mut link = base_link();
    link.held_file_count = 2;
    link.held_files = vec![
        HeldFile {
            path: "photo.jpg".into(),
            reason: "case_collision: collides with existing 'Photo.jpg'".into(),
            held_since_unix_nanos: 1_000,
        },
        HeldFile {
            path: "CON.txt".into(),
            reason: "invalid_name: reserved device name".into(),
            held_since_unix_nanos: 2_000,
        },
    ];

    assert_eq!(held_summary_suffix(&link), "  held=2");
    let lines = held_file_detail_lines(&link, false);
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("photo.jpg"));
    assert!(lines[0].contains("collides with another file"));
    assert!(lines[1].contains("CON.txt"));
    assert!(lines[1].contains("not allowed here"));
}

/// A healthy (non-degraded) link renders no degraded-related output,
/// matching this file's "empty unless applicable" discipline.
#[test]
fn no_degraded_state_renders_no_new_output() {
    assert_eq!(degraded_suffix(&base_link()), "");
}

/// a degraded link shows its reason.
#[test]
fn degraded_link_shows_its_reason() {
    let mut link = base_link();
    link.degraded = true;
    link.degraded_reason = "insufficient free space to write big.bin".to_string();
    assert_eq!(degraded_suffix(&link), "  degraded (insufficient free space to write big.bin)");
}

/// `Protected` and `Protecting` are both fine to leave as plain "syncing"
/// text -- neither renders the extra durability suffix.
#[test]
fn protected_or_protecting_durability_renders_no_new_output() {
    let mut link = base_link();
    link.durability_status = GroupDurabilityStatus::Protected as i32;
    assert_eq!(durability_suffix(&link), "");
    link.durability_status = GroupDurabilityStatus::Protecting as i32;
    assert_eq!(durability_suffix(&link), "");
}

/// A group whose coverage cannot currently be confirmed -- e.g. right
/// after a `--force` unlink bypassed the durability handoff gate --
/// must show a distinct "durability unknown" suffix, never plain
/// "syncing" (which would read as fully caught up and safe).
#[test]
fn durability_unknown_renders_its_own_suffix() {
    let mut link = base_link();
    link.durability_status = GroupDurabilityStatus::Unknown as i32;
    assert_eq!(durability_suffix(&link), "  durability unknown");
}

/// While the first custody check has not run yet the status is "checking",
/// not "unknown": nothing failed to confirm, nothing has been asked.
#[test]
fn durability_check_pending_renders_checking_not_unknown() {
    let mut link = base_link();
    link.durability_status = GroupDurabilityStatus::Unknown as i32;
    link.durability_check_pending = true;
    assert_eq!(durability_suffix(&link), "  durability checking");
}

/// A group with a confirmed missing durable holder renders its own,
/// more severe suffix, distinct from the merely-unconfirmed case above.
#[test]
fn at_risk_durability_renders_its_own_suffix() {
    let mut link = base_link();
    link.durability_status = GroupDurabilityStatus::AtRisk as i32;
    assert_eq!(durability_suffix(&link), "  durability: at risk");
}

/// an unset value
/// `Unspecified` (proto3's zero default) -- this must fail safe and
/// render exactly like `Unknown`, never like `Protected`.
#[test]
fn unspecified_durability_fails_safe_like_unknown() {
    let mut link = base_link();
    link.durability_status = GroupDurabilityStatus::Unspecified as i32;
    assert_eq!(durability_suffix(&link), "  durability unknown");
}

/// A full copy renders no local-storage suffix at all --
/// the common healthy case, same "empty unless applicable" discipline
/// as every other suffix here.
#[test]
fn full_copy_renders_no_local_storage_suffix() {
    let link = base_link();
    assert_eq!(local_storage_suffix(&link), "");
}

/// `Unspecified` must not render identically to `FullCopy`: that would
/// present a link whose local storage the daemon could not determine as
/// a healthy full copy. It must not consult the raw policy string to
/// guess one either -- the CLI and daemon ship together and the control
/// protocol version is checked exactly, so an unset value is the daemon
/// saying it does not know, not an unset-value to accommodate.
#[test]
fn unspecified_local_storage_says_so_rather_than_guessing() {
    let mut link = base_link();
    link.local_storage_state = LocalStorageState::Unspecified as i32;
    assert_eq!(local_storage_suffix(&link), "  local storage unknown");
    link.materialization_policy = "ondemand".to_string();
    assert_eq!(local_storage_suffix(&link), "  local storage unknown");
}

/// On-demand reads `local_storage_state` directly, not
/// `materialization_policy` string-matching plus raw counts.
#[test]
fn on_demand_renders_hydration_counts() {
    let mut link = base_link();
    link.local_storage_state = LocalStorageState::OnDemand as i32;
    link.hydrated_count = 3;
    link.placeholder_count = 2;
    link.hydrating_count = 1;
    assert_eq!(local_storage_suffix(&link), "  on-demand (hydrated=3 placeholder=2 hydrating=1)");
}

/// An eager link still catching up must render its own
/// distinct label -- never silently as `FullCopy` (the earlier
/// materialization_policy-string-based reconstruction this replaces
/// would have shown nothing at all here, since it only special-cased
/// "ondemand").
#[test]
fn partially_materialized_renders_its_own_suffix() {
    let mut link = base_link();
    link.local_storage_state = LocalStorageState::PartiallyMaterialized as i32;
    link.hydrated_count = 5;
    link.placeholder_count = 1;
    link.hydrating_count = 0;
    assert_eq!(
        local_storage_suffix(&link),
        "  making full copy (hydrated=5 placeholder=1 hydrating=0)"
    );
}

/// `AvailableNow` renders no suffix -- the common case.
#[test]
fn available_now_renders_no_fetch_availability_suffix() {
    let link = base_link();
    assert_eq!(fetch_availability_suffix(&link), "");
}

/// `UnavailableNow` must be visible and distinct from
/// `durability_status` -- protected-but-currently-unfetchable is not
/// the same claim as data loss.
#[test]
fn unavailable_now_renders_its_own_suffix() {
    let mut link = base_link();
    link.fetch_availability = FetchAvailability::UnavailableNow as i32;
    assert_eq!(fetch_availability_suffix(&link), "  fetch not confirmed");
}

/// `Unknown`, and an unset value,
/// must never render as available.
#[test]
fn unknown_fetch_availability_never_reads_as_available() {
    let mut link = base_link();
    link.fetch_availability = FetchAvailability::Unknown as i32;
    assert_eq!(fetch_availability_suffix(&link), "  fetch availability unknown");
    link.fetch_availability = FetchAvailability::Unspecified as i32;
    assert_eq!(fetch_availability_suffix(&link), "  fetch availability unknown");
}

/// `0` reads as "unlimited" — the shared convention
/// between `status` and `limits show`.
#[test]
fn format_rate_zero_is_unlimited() {
    assert_eq!(format_rate_bytes_per_sec(0), "unlimited");
}

/// non-zero rates scale to a human-readable unit.
#[test]
fn format_rate_scales_to_a_human_readable_unit() {
    assert_eq!(format_rate_bytes_per_sec(500), "500 B/s");
    assert_eq!(format_rate_bytes_per_sec(2048), "2.0 KiB/s");
    assert_eq!(format_rate_bytes_per_sec(5 * 1024 * 1024), "5.0 MiB/s");
    assert_eq!(format_rate_bytes_per_sec(3 * 1024 * 1024 * 1024), "3.0 GiB/s");
}

fn base_status() -> StatusResponse {
    StatusResponse {
        links: vec![],
        peers: vec![],
        upload_limit_bytes_per_sec: 0,
        download_limit_bytes_per_sec: 0,
        current_upload_bytes_per_sec: 0,
        current_download_bytes_per_sec: 0,
        volumes: vec![],
        // `..Default::default` rather than listing every new field
        // explicitly, since this struct literal predates those
        // fields and most tests using this helper don't care about
        // them.
        ..Default::default()
    }
}

/// A healthy, up-to-date status (the default) renders no
/// update-related output at all — matches this file's own "empty
/// unless applicable" discipline.
#[test]
fn no_update_available_renders_no_new_output() {
    assert_eq!(update_summary_lines(&base_status()), Vec::<String>::new());
}

/// spec "Status surfaces available update": an available, non-mandatory
/// update not yet at a safe point/holdback renders as simply available.
#[test]
fn available_update_renders_its_version() {
    let mut status = base_status();
    status.update_available_version = "0.2.0".into();
    let lines = update_summary_lines(&status);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("0.2.0"));
    assert!(lines[0].contains("available"));
}

/// A mandatory update's line says so explicitly, distinct from a
/// merely-available one.
#[test]
fn mandatory_update_says_so() {
    let mut status = base_status();
    status.update_available_version = "0.2.0".into();
    status.update_mandatory = true;
    let lines = update_summary_lines(&status);
    assert!(lines[0].contains("mandatory"));
    assert!(!lines[0].contains("automatic"), "{lines:?}");
    assert!(lines[0].contains("yadorilink update download"), "{lines:?}");
}

/// A build below the signed minimum supported version says the update is required, not merely
/// available or mandatory.
#[test]
fn an_update_below_the_minimum_supported_version_says_required() {
    let mut status = base_status();
    status.update_available_version = "0.2.0".into();
    status.update_mandatory = true;
    status.update_required = true;
    let lines = update_summary_lines(&status);
    assert!(lines[0].contains("required"), "{lines:?}");
    assert!(lines[0].contains("yadorilink update download"), "{lines:?}");
}

/// A held-back update shows the holdback reason as a second line.
#[test]
fn held_back_update_shows_its_reason() {
    let mut status = base_status();
    status.update_available_version = "0.2.0".into();
    status.update_holdback_reason = "staged rollout at 10%".into();
    let lines = update_summary_lines(&status);
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("held back"));
    assert!(lines[1].contains("staged rollout at 10%"));
}

/// spec "Status surfaces failed update": a recorded update failure is
/// surfaced with a pointer to `update status` for more detail, even
/// with no update currently available.
#[test]
fn update_failure_is_surfaced_with_a_pointer_to_update_status() {
    let mut status = base_status();
    status.update_last_error_category = "update_manifest_fetch_failed".into();
    let lines = update_summary_lines(&status);
    assert_eq!(lines.len(), 1);
    assert!(!lines[0].contains("update_manifest_fetch_failed"), "{lines:?}");
    assert!(lines[0].contains("did not finish"), "{lines:?}");
    assert!(lines[0].contains("yadorilink update status"));
}

// --- overall-state rendering ---

/// an unset value renders
/// no new output at all.
#[test]
fn empty_overall_state_renders_no_new_output() {
    assert!(overall_state_lines(&base_status(), &DeviceNames::default(), false).is_empty());
}

#[test]
fn healthy_overall_state_renders_with_no_reasons() {
    let mut status = base_status();
    status.overall_state = "healthy".into();
    assert_eq!(
        overall_state_lines(&status, &DeviceNames::default(), false),
        vec!["Overall: healthy".to_string()]
    );
}

#[test]
fn attention_overall_state_renders_its_reasons() {
    let mut status = base_status();
    status.overall_state = "attention".into();
    status.attention_reasons = vec!["conflict:group-1".into(), "low_disk:/data".into()];
    status.links = vec![base_link()];
    assert_eq!(
        overall_state_lines(&status, &DeviceNames::default(), false),
        vec![
            "Overall: attention".to_string(),
            "  - Some files have conflicting copies. [/tmp/photos] Next: yadorilink conflicts list"
                .to_string(),
            "  - The disk is running low on space. [/data] Next: yadorilink gc --dry-run"
                .to_string(),
        ]
    );
    let verbose = overall_state_lines(&status, &DeviceNames::default(), true);
    assert!(verbose[1].ends_with("(code: conflict:group-1)"), "{verbose:?}");
}

/// A waiting join request names the folder, not its group id, and points at the command that
/// lists the requests.
#[test]
fn a_waiting_join_request_names_the_folder_and_the_command() {
    let mut status = base_status();
    status.overall_state = "attention".into();
    status.attention_reasons = vec!["approval_pending:group-1".into()];
    status.links = vec![base_link()];
    let lines = overall_state_lines(&status, &DeviceNames::default(), false);
    assert!(lines[1].contains("[/tmp/photos]"), "{lines:?}");
    assert!(lines[1].ends_with("Next: yadorilink share pending"), "{lines:?}");
    assert!(!lines[1].contains("group-1"), "{lines:?}");
}

/// the limits summary line reports both configured and
/// current rates, `unlimited` when unconfigured.
#[test]
fn limits_summary_line_reports_configured_and_current_rates() {
    let mut status = base_status();
    assert_eq!(
        limits_summary_line(&status),
        "Limits: up=unlimited down=unlimited  (current: up=unlimited down=unlimited)"
    );

    status.upload_limit_bytes_per_sec = 1024;
    status.current_download_bytes_per_sec = 2048;
    assert_eq!(
        limits_summary_line(&status),
        "Limits: up=1.0 KiB/s down=unlimited  (current: up=unlimited down=2.0 KiB/s)"
    );
}

fn base_peer() -> PeerStatus {
    PeerStatus {
        device_id: "device-1".into(),
        reachability: PeerReachability::Connected as i32,
        unreachable_category: UnreachableCategory::Unspecified as i32,
        route_kind: RouteKind::Direct as i32,
        version_incompatible: false,
        replaced_by_device_id: String::new(),
    }
}

/// A reachable peer shows "connected"; an unreachable one shows
/// "cannot connect" with its failure category.
#[test]
fn connectivity_label_reflects_reachability_and_category() {
    let mut peer = base_peer();
    assert_eq!(peer_connectivity_label(&peer), "connected");

    peer.reachability = PeerReachability::Unreachable as i32;
    peer.unreachable_category = UnreachableCategory::NoResponse as i32;
    assert_eq!(peer_connectivity_label(&peer), "cannot connect (no response)");

    peer.reachability = PeerReachability::Connecting as i32;
    assert_eq!(peer_connectivity_label(&peer), "connecting");
}

/// A peer reachable only through a relay server is connected, and says
/// which path carries it.
#[test]
fn a_relayed_peer_reads_as_connected_via_relay() {
    let mut peer = base_peer();
    peer.route_kind = RouteKind::Relay as i32;
    assert_eq!(peer_connectivity_label(&peer), "connected (via relay)");
}

/// an unset value
/// connected peer -- must still read as plain "connected".
#[test]
fn connected_with_unspecified_route_kind_reads_as_plain_connected() {
    let mut peer = base_peer();
    peer.route_kind = RouteKind::Unspecified as i32;
    assert_eq!(peer_connectivity_label(&peer), "connected");
}

/// a volume line reports path, state, and byte counts.
#[test]
fn volume_line_reports_path_state_and_bytes() {
    let volume = VolumeFreeSpace {
        path: "/tmp/photos".into(),
        state: "low".into(),
        available_bytes: 1500,
        headroom_bytes: 1000,
        total_bytes: 0,
        reclaimable_bytes: 0,
    };
    assert_eq!(volume_line(&volume), "  /tmp/photos  low  (available=1500 headroom=1000)");
}

/// Byte formatting scales the same way `format_rate_bytes_per_sec`
/// does, minus the `/s` suffix.
#[test]
fn format_bytes_scales_to_a_human_readable_unit() {
    assert_eq!(format_bytes(500), "500 B");
    assert_eq!(format_bytes(2048), "2.0 KiB");
    assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MiB");
}

/// `0`/negative means "never run" — never rendered as a
/// literal unix-epoch timestamp.
#[test]
fn last_gc_summary_reports_never_when_no_sweep_has_completed() {
    assert_eq!(last_gc_summary(0), "never");
}

/// a recent completion renders as a short relative bucket.
#[test]
fn last_gc_summary_reports_a_relative_bucket_for_a_recent_sweep() {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    assert_eq!(last_gc_summary(now - 30), "30s ago");
    assert_eq!(last_gc_summary(now - 120), "2m ago");
    assert_eq!(last_gc_summary(now - 7200), "2h ago");
    assert_eq!(last_gc_summary(now - 2 * 86400), "2d ago");
}

/// `status` shows non-zero usage after files are synced
/// (block/byte counts) and reports the last-GC time / reclaimable
/// estimate alongside it — this is the pure-formatting half; the
/// daemon-side wiring is exercised by `control_socket.rs`'s own tests
/// and `yadorilink-cli`'s `tests/` integration suite.
#[test]
fn block_store_summary_line_reports_usage_and_gc_health() {
    let mut status = base_status();
    status.block_store_block_count = 42;
    status.block_store_total_bytes = 5 * 1024 * 1024;
    status.last_gc_unix = 0;
    status.gc_reclaimable_estimate_bytes = 1024;

    let line = block_store_summary_line(&status);

    assert!(line.contains("42 block(s)"));
    assert!(line.contains("5.0 MiB used"));
    assert!(line.contains("last GC: never"));
    assert!(line.contains("~1.0 KiB reclaimable"));
}

// --- progress + recent-error rendering ---

/// "Empty unless applicable" discipline: a link with no
/// active transfer renders no transfer-related suffix at all.
#[test]
fn no_active_transfer_renders_no_new_output() {
    assert_eq!(transfer_progress_suffix(&base_link()), "");
}

/// An active transfer's headline reports a percent,
/// byte/block counts, and a best-effort, explicitly-labelled ETA.
#[test]
fn active_transfer_renders_percent_bytes_blocks_and_eta() {
    let mut link = base_link();
    link.has_active_transfer = true;
    link.transfer_bytes_done = 50;
    link.transfer_bytes_total = 200;
    link.transfer_blocks_done = 1;
    link.transfer_blocks_total = 4;
    link.transfer_eta_seconds = 30;

    let suffix = transfer_progress_suffix(&link);
    assert!(suffix.contains("25%"));
    assert!(suffix.contains("50/200 bytes"));
    assert!(suffix.contains("1/4 blocks"));
    assert!(suffix.contains("eta~30s"));
}

/// an active transfer with no ETA signal yet (best-effort)
/// omits the `eta~` fragment rather than claiming `0s`.
#[test]
fn active_transfer_with_no_eta_signal_omits_the_eta_fragment() {
    let mut link = base_link();
    link.has_active_transfer = true;
    link.transfer_bytes_total = 200;
    link.transfer_eta_seconds = 0;

    assert!(!transfer_progress_suffix(&link).contains("eta~"));
}

/// The per-file active-transfer detail list renders one
/// line per entry, including its source peer.
#[test]
fn active_transfer_detail_lines_render_one_line_per_transfer() {
    let mut status = base_status();
    status.active_transfers = vec![ActiveTransferProgress {
        group_id: "group-1".into(),
        path: "big.bin".into(),
        bytes_done: 100,
        bytes_total: 400,
        blocks_done: 1,
        blocks_total: 4,
        source_peer: "device-b".into(),
        started_at_unix: 0,
    }];

    let lines = active_transfer_detail_lines(&status);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("big.bin"));
    assert!(lines[0].contains("25%"));
    assert!(lines[0].contains("device-b"));
}

/// no active transfers renders no "Active transfers:" detail
/// at all.
#[test]
fn no_active_transfers_renders_no_detail_lines() {
    assert!(active_transfer_detail_lines(&base_status()).is_empty());
}

/// Recent errors render their category and coarse
/// context — never anything beyond what the daemon already redacted.
#[test]
fn recent_errors_render_category_and_coarse_context() {
    let mut status = base_status();
    status.recent_errors = vec![RecentSyncError {
        category: "disk_pressure".into(),
        timestamp_unix: 12345,
        coarse_context: "hydration".into(),
    }];

    let lines = recent_errors_summary_lines(&status);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("disk_pressure"));
    assert!(lines[0].contains("hydration"));
}

#[test]
fn no_recent_errors_renders_no_new_output() {
    assert!(recent_errors_summary_lines(&base_status()).is_empty());
}

/// A folder group linked at two folders syncs NOTHING until the user
/// unlinks all but one. Without this the refusal exists only as a daemon
/// log line: loud in the code, invisible to the person who has to act on
/// it, who would see a folder that had silently stopped syncing.
#[test]
fn an_ambiguous_link_says_it_is_not_syncing_and_names_every_folder() {
    let link = LinkStatus {
        ambiguous: true,
        ambiguous_local_paths: vec!["/Users/alice/A".into(), "/Users/alice/B".into()],
        ..base_link()
    };

    let suffix = ambiguous_suffix(&link);

    assert!(suffix.contains("NOT SYNCING"), "got {suffix:?}");
    // The paths are the remedy, not decoration: unlinking is keyed by path.
    assert!(suffix.contains("/Users/alice/A"), "got {suffix:?}");
    assert!(suffix.contains("/Users/alice/B"), "got {suffix:?}");
}

/// Same "empty unless applicable" discipline as every other suffix here: a
/// healthy link's line must be unaffected by this state existing.
#[test]
fn a_healthy_link_renders_no_ambiguity_suffix() {
    assert_eq!(ambiguous_suffix(&base_link()), "");
}

/// One whole `yadorilink status` rendering of an empty daemon, pinned line by
/// line: no folders, the limits and block-store summaries after a blank line.
#[test]
fn status_lines_for_an_empty_daemon_are_pinned_verbatim() {
    assert_eq!(
        status_lines(&base_status(), &DeviceNames::default(), false),
        vec![
            "No linked folders.",
            "",
            "Limits: up=unlimited down=unlimited  (current: up=unlimited down=unlimited)",
            "Block store: 0 block(s), 0 B used  (last GC: never, ~0 B reclaimable)",
        ]
    );
}

/// One whole rendering with a folder, a peer, an available update and a
/// recent error, pinned line by line so the order of the sections is fixed.
#[test]
fn status_lines_for_a_busy_daemon_are_pinned_verbatim() {
    let mut status = base_status();
    status.links.push(base_link());
    status.peers.push(PeerStatus { device_id: "peer-1".into(), ..Default::default() });
    status.update_available_version = "0.2.0".into();
    status
        .recent_errors
        .push(RecentSyncError { category: "disk_full".into(), ..Default::default() });
    assert_eq!(
        status_lines(&status, &DeviceNames::default(), false),
        vec![
            "/tmp/photos  syncing  conflicts=0",
            "",
            "Peers:",
            "  peer-1  unknown",
            "",
            "Limits: up=unlimited down=unlimited  (current: up=unlimited down=unlimited)",
            "Block store: 0 block(s), 0 B used  (last GC: never, ~0 B reclaimable)",
            "",
            "Update: 0.2.0 (available)",
            "",
            "Recent errors:",
            "  disk_full  ()  unknown time",
        ]
    );
}

/// Nothing preserved renders nothing; preserved data renders one line, and a total above the
/// configured size names the commands that deal with it.
#[test]
fn preserved_data_renders_one_line_and_warns_above_the_threshold() {
    use yadorilink_ipc_proto::daemonctl::PreservedSummary;
    let mut status = base_status();
    assert_eq!(preserved_line(&status), None);
    status.preserved = Some(PreservedSummary::default());
    assert_eq!(preserved_line(&status), None);

    status.preserved = Some(PreservedSummary {
        total: 2,
        bytes: 10,
        content_unavailable: 1,
        unreplayed_own_units: 3,
        warn_bytes: 100,
        ..Default::default()
    });
    let line = preserved_line(&status).unwrap();
    assert!(line.contains("2 version(s)") && line.contains("3 own change(s)"), "{line}");
    assert!(!line.contains("preserved list"));

    status.preserved.as_mut().unwrap().warn = true;
    let line = preserved_line(&status).unwrap();
    assert!(line.contains("yadorilink preserved list") && line.contains("discard"), "{line}");
}

/// Retained originals are named with the disk they take and the command that releases them;
/// none render nothing.
#[test]
fn retained_originals_render_one_line_naming_the_release_command() {
    use yadorilink_ipc_proto::daemonctl::PreservedSummary;
    let mut status = base_status();
    assert_eq!(retained_line(&status), None);
    status.preserved = Some(PreservedSummary::default());
    assert_eq!(retained_line(&status), None);

    status.preserved = Some(PreservedSummary { retained_originals: 2, ..Default::default() });
    let line = retained_line(&status).unwrap();
    assert!(line.contains("2 original(s)"), "{line}");
    assert!(line.contains("yadorilink preserved retained"), "{line}");
    assert!(
        status_lines(&status, &DeviceNames::default(), false).contains(&line),
        "shown by status"
    );
}

/// A group whose rebootstrap runs says so, so a paused folder is explained.
#[test]
fn a_rebootstrapping_group_is_named() {
    let mut status = base_status();
    status.rebootstrapping_groups = vec!["g1".into()];
    let lines = status_lines(&status, &DeviceNames::default(), false);
    assert!(lines.iter().any(|line| line.contains("g1") && line.contains("rebootstrap")));
}

/// Retained uploads of undecided operations are on the status, with the age of the oldest; none, no line.
#[test]
fn undecided_uploads_are_reported_with_their_age() {
    let mut status = base_status();
    assert!(!status_lines(&status, &DeviceNames::default(), false)
        .iter()
        .any(|l| l.contains("undecided uploads")));
    status.undecided_uploads = 3;
    status.undecided_uploads_oldest_ms = 5 * 3_600_000;
    let lines = status_lines(&status, &DeviceNames::default(), false);
    assert!(lines.iter().any(|l| l == "undecided uploads: 3, oldest: 5h"), "{lines:?}");
}

/// A provider root says why it is not ready; an Eager root shows its progress and stuck files; kept
/// edits show their count and age.
#[test]
fn provider_roots_are_explained() {
    use yadorilink_ipc_proto::daemonctl::{ProviderRootStatus, StuckFile};
    let mut status = base_status();
    status.provider_roots = vec![ProviderRootStatus {
        root_id: "abcdef01".into(),
        display_name: "Photos".into(),
        readiness: "enable File Provider".into(),
        eager: true,
        eager_state: "running".into(),
        eager_remote: 7,
        eager_hydrating: 2,
        eager_current: 40,
        stuck: vec![StuckFile { path: "a/b.bin".into(), failures: 5 }],
        kept_edits: 3,
        kept_edits_oldest_ms: 3 * 3_600_000,
        pending_publications: 2,
        pending_oldest_ms: 90_000,
        unconfirmed_publications: 1,
        unconfirmed_oldest_ms: 5 * 3_600_000,
        counters_unreadable: false,
        sync_root_path: String::new(),
    }];
    let lines = status_lines(&status, &DeviceNames::default(), false);
    let has = |needle: &str| lines.iter().any(|l| l.contains(needle));
    assert!(has("provider folder Photos: enable File Provider"), "{lines:?}");
    assert!(has("downloading: running, 40 file(s) on this Mac, 7 to fetch, 2 in progress"));
    assert!(has("stuck: a/b.bin (5 failed attempt(s))"));
    assert!(has("edits kept beside the file: 3, oldest: 3h"));
    assert!(has("file in use or release pending): 2, oldest: 90s"), "{lines:?}");
    assert!(has("released but not yet confirmed by the OS: 1, oldest: 5h"));
    assert!(!status_lines(&base_status(), &DeviceNames::default(), false)
        .iter()
        .any(|l| l.contains("provider folder")));
}

/// A provider folder is named, never shown by its identity key; a removal says where the
/// OS kept the downloaded files; an orphan domain is reported as kept.
#[test]
fn provider_folders_removals_and_orphans_are_rendered_without_a_path() {
    use yadorilink_ipc_proto::daemonctl::ProviderRemovalStatus;
    let mut status = base_status();
    let mut link = base_link();
    link.local_path = "provider://token-1".into();
    link.provider_display_name = "Photos".into();
    status.links = vec![link];
    status.provider_removals = vec![
        ProviderRemovalStatus {
            root_id: "aaaaaaaa".into(),
            display_name: "Old".into(),
            removed: true,
            preserved_location: "/Users/u/kept".into(),
            unreadable: false,
        },
        ProviderRemovalStatus {
            root_id: "bbbbbbbb".into(),
            display_name: "Going".into(),
            removed: false,
            preserved_location: String::new(),
            unreadable: false,
        },
    ];
    status.orphan_domains = vec!["cccccccc".into()];
    let lines = status_lines(&status, &DeviceNames::default(), false);
    let has = |needle: &str| lines.iter().any(|l| l.contains(needle));
    assert!(has("provider folder 'Photos'  syncing"), "{lines:?}");
    assert!(!has("provider://"), "the identity key leaked into the output: {lines:?}");
    assert!(has("removed; the downloaded files are kept at /Users/u/kept"), "{lines:?}");
    assert!(has("Going: removing"), "{lines:?}");
    assert!(
        has("domain cccccccc belongs to no folder this database knows; it is kept"),
        "{lines:?}"
    );
}

/// The row standing in for an unreadable removals list is not a removal in progress, and its
/// attention reason names what could not be read.
#[test]
fn an_unreadable_removals_list_is_not_rendered_as_a_removal() {
    use yadorilink_ipc_proto::daemonctl::ProviderRemovalStatus;
    let mut status = base_status();
    status.provider_removals = vec![ProviderRemovalStatus {
        display_name: "removals unreadable: boom".into(),
        unreadable: true,
        ..Default::default()
    }];
    status.overall_state = "attention".into();
    status.attention_reasons = vec!["provider_not_ready:removals".into()];
    let lines = status_lines(&status, &DeviceNames::default(), false);
    let has = |needle: &str| lines.iter().any(|l| l.contains(needle));
    assert!(has("provider folder removals: removals unreadable: boom"), "{lines:?}");
    assert!(!has("removing"), "{lines:?}");
    assert!(has("[provider folder removals]"), "{lines:?}");
}

/// The unreadable-file advice must name a fix that exists on this platform: `chmod` does not on
/// Windows, where the cause is an ACL denial or a program holding the file open.
#[test]
fn unreadable_file_advice_names_a_fix_that_exists_on_this_platform() {
    let text = reasons::explain_reason("unreadable_files:g", "folder", false);
    assert_eq!(text.contains("chmod"), !cfg!(windows), "{text}");
    if cfg!(windows) {
        assert!(text.contains("Security properties"), "{text}");
    }
}

/// Every code the daemon can emit (`overall_status` in the daemon's control socket and the held-file
/// reasons) maps to a sentence and a next step; none leaks its raw code outside verbose mode.
#[test]
fn every_known_reason_code_has_a_sentence_and_a_next_step() {
    let attention = [
        "degraded:g",
        "waiting_for_disk_space:g",
        "file_watch_limit:g",
        "ownership_lost:g",
        "not_joined:g",
        "ambiguous:g",
        "durability_at_risk:g",
        "durability_unknown:g",
        "fetch_unavailable:g",
        "fetch_availability_unknown:g",
        "conflict:g",
        "approval_pending:g",
        "held:g",
        "stranded_directory:g",
        "unreadable_files:g",
        "provider_not_ready:r",
        "provider_stuck:r",
        "kept_edits:r",
        "provider_orphan_domain:d",
        "low_disk_critical:/p",
        "low_disk:/p",
        "peer_disconnected:dev",
        "recent_error:cat",
        "update_failed:cat",
        "peer_update_required:dev",
        "update_required",
        "provider_registry_restored:older_generation",
    ];
    let held = [
        "case_collision: collides with 'A'",
        "invalid_name: bad",
        "normalization_collision",
        "case_and_normalization_collision",
        "metadata_unprovable: unreadable",
    ];
    for raw in attention {
        let text = reasons::explain_reason(raw, "", false);
        assert!(text.contains(" Next: "), "{raw}: {text}");
        assert!(!text.contains("Needs attention"), "{raw}: {text}");
        assert!(!text.contains(raw), "{raw} leaked: {text}");
        assert!(reasons::explain_reason(raw, "", true).contains(&format!("(code: {raw})")));
    }
    for raw in held {
        let text = reasons::explain_held(raw);
        assert!(text.contains(" Next: "), "{raw}: {text}");
        assert!(!text.contains("Needs attention"), "{raw}: {text}");
        assert!(!text.contains(raw), "{raw} leaked: {text}");
    }
}

#[test]
fn an_unknown_reason_falls_back_and_shows_the_code_only_when_verbose() {
    assert_eq!(
        reasons::explain_reason("brand_new:x", "", false),
        "Needs attention Next: yadorilink status --details"
    );
    assert_eq!(
        reasons::explain_reason("brand_new:x", "", true),
        "Needs attention (code: brand_new:x)"
    );
}

#[test]
fn durability_unknown_names_the_folder_not_the_group_id() {
    let mut status = base_status();
    status.overall_state = "attention".into();
    status.attention_reasons = vec!["durability_unknown:group-1".into()];
    status.links = vec![base_link()];
    let lines = overall_state_lines(&status, &DeviceNames::default(), false);
    assert!(lines[1].starts_with("  - This folder cannot confirm it is safely stored on disk yet."));
    assert!(lines[1].contains("/tmp/photos") && !lines[1].contains("group-1"), "{lines:?}");
}

#[test]
fn held_files_get_a_plain_sentence() {
    let mut link = base_link();
    link.held_files = vec![HeldFile {
        path: "a.txt".into(),
        reason: "metadata_unprovable: x".into(),
        ..Default::default()
    }];
    let lines = held_file_detail_lines(&link, false);
    assert!(
        lines[0].contains("cannot be read by you") && !lines[0].contains("metadata_unprovable")
    );
}

#[test]
fn timestamps_render_as_readable_times() {
    let text = format_local_time(1_750_000_000);
    assert!(text.starts_with("2025-06-1"), "{text}");
    assert_eq!(format_local_time(0), "unknown time");
}

#[test]
fn a_timed_pause_says_when_it_ends_and_other_pauses_say_nothing_more() {
    assert_eq!(timed_pause_label(0, 1000), "paused");
    assert_eq!(timed_pause_label(1000 + 29 * 60, 1000), "paused (resumes in 29m)");
    assert_eq!(timed_pause_label(1000 + 61 * 60, 1000), "paused (resumes in 1h 1m)");
    assert_eq!(timed_pause_label(900, 1000), "paused (resumes in 0m)");
}

/// A link stalled by the OS watch limit shows the actionable fix in `status`.
#[test]
fn watch_limit_link_shows_the_fix() {
    let mut link = base_link();
    link.degraded = true;
    link.degraded_reason = "OS file watch limit reached; this folder is not syncing. Fix: raise \
                            fs.inotify.max_user_watches"
        .to_string();
    let suffix = degraded_suffix(&link);
    assert!(suffix.contains("watch limit reached"), "{suffix}");
    assert!(suffix.contains("fs.inotify.max_user_watches"), "{suffix}");
}

/// A provider folder whose counters could not be read says so; it does not print zeros as
/// progress.
#[test]
fn unreadable_provider_counters_are_not_rendered_as_zeros() {
    use yadorilink_ipc_proto::daemonctl::ProviderRootStatus;
    let mut status = base_status();
    status.provider_roots = vec![ProviderRootStatus {
        root_id: "aaaaaaaa".into(),
        display_name: "Photos".into(),
        readiness: "the provider state unreadable: boom".into(),
        eager: true,
        counters_unreadable: true,
        ..Default::default()
    }];
    let lines = status_lines(&status, &DeviceNames::default(), false);
    let has = |needle: &str| lines.iter().any(|l| l.contains(needle));
    assert!(has("counters: unknown"), "{lines:?}");
    assert!(!has("downloading:"), "{lines:?}");
}

/// A peer that is online but on another version reads "update required", never "offline" or
/// "cannot connect"; an unreachable peer next to it still reads offline.
#[test]
fn a_version_mismatched_peer_reads_update_required_not_offline() {
    let mut incompatible = base_peer();
    incompatible.device_id = "nas-1".into();
    incompatible.reachability = PeerReachability::Connected as i32;
    incompatible.version_incompatible = true;
    assert_eq!(peer_connectivity_label(&incompatible), "reachable, update required");

    let mut link = base_link();
    link.full_replica_device_ids = vec!["nas-1".into(), "nas-2".into()];
    let mut gone = base_peer();
    gone.device_id = "nas-2".into();
    gone.reachability = PeerReachability::Unreachable as i32;
    let lines =
        complete_copies_detail_lines(&link, &[incompatible, gone], &DeviceNames::default(), false);
    assert_eq!(
        lines,
        vec![
            "    configured full copy: nas-1  (update required)".to_string(),
            "    configured full copy: nas-2  (offline)".to_string(),
        ]
    );
}

/// `status` names at most five unreadable files per folder with the reason, then counts the rest;
/// a folder with none prints nothing.
#[test]
fn unreadable_files_are_listed_capped_and_the_rest_counted() {
    use yadorilink_ipc_proto::daemonctl::UnreadableFile;
    assert!(unreadable_file_detail_lines(&base_link()).is_empty());

    let files = (0..8)
        .map(|i| UnreadableFile {
            path: format!("dir/f{i}.txt"),
            reason: "permission_denied".into(),
        })
        .collect();
    let link = LinkStatus { unreadable_files: files, unreadable_file_count: 8, ..base_link() };
    let lines = unreadable_file_detail_lines(&link);
    assert_eq!(lines.len(), 6);
    assert_eq!(lines[0], "    unreadable: dir/f0.txt  (permission denied)");
    assert_eq!(lines[5], "    ... and 3 more unreadable file(s)");

    // The daemon's own cap shortens the list but not the count.
    let capped = LinkStatus {
        unreadable_files: vec![UnreadableFile { path: "a".into(), reason: "read_failed".into() }],
        unreadable_file_count: 1,
        ..base_link()
    };
    assert_eq!(unreadable_file_detail_lines(&capped), ["    unreadable: a  (read error)"]);
}

#[test]
fn the_unreadable_files_reason_names_the_folder_and_the_next_step() {
    let text = reasons::explain_reason("unreadable_files:group-1", "photos", false);
    assert!(text.contains("[photos]"), "{text}");
    assert!(
        text.contains("cannot be read") && text.contains("Next: make the listed files readable")
    );
}

#[test]
fn the_unconfirmed_replacement_reasons_say_the_cause_and_the_next_step() {
    let waiting = reasons::explain_reason("replacement_unconfirmed", "", false);
    assert!(waiting.contains("replaced another one") && !waiting.starts_with("Needs attention"));
    let why = reasons::explain_reason(
        "replacement_unconfirmed_waiting:g1: not linked on this device",
        "g1: not linked on this device",
        false,
    );
    assert!(why.contains("[g1: not linked on this device]") && !why.starts_with("Needs attention"));
    let sign_in = reasons::explain_reason("replacement_unconfirmed_sign_in_required", "", false);
    assert!(sign_in.contains("signed out") && sign_in.contains("Next: yadorilink login"));
}

fn named() -> DeviceNames {
    DeviceNames {
        own_device_id: Some("device-self-0001".into()),
        names: [("device-kitchen-0002".to_string(), "Kitchen Mac".to_string())]
            .into_iter()
            .collect(),
    }
}

/// Peers, reasons about a device and configured full copies show the name the account gives the
/// device; this device reads "this device"; a device the account does not name keeps its short
/// id; `--verbose` adds the full id after a name.
#[test]
fn devices_are_shown_by_name_and_by_short_id_only_when_unnamed() {
    let names = named();
    assert_eq!(device_label(&names, "device-kitchen-0002", false), "Kitchen Mac");
    assert_eq!(device_label(&names, "device-self-0001", false), "this device");
    assert_eq!(device_label(&names, "stranger-device-9", false), "stranger...");
    assert_eq!(
        device_label(&names, "device-kitchen-0002", true),
        "Kitchen Mac (device-kitchen-0002)"
    );
    assert_eq!(device_label(&names, "stranger-device-9", true), "stranger-device-9");

    let mut status = base_status();
    status.overall_state = "attention".into();
    status.attention_reasons = vec!["peer_disconnected:device-kitchen-0002".into()];
    let mut peer = base_peer();
    peer.device_id = "device-kitchen-0002".into();
    peer.reachability = PeerReachability::Connected as i32;
    status.peers = vec![peer];
    let mut link = base_link();
    link.full_replica_device_ids = vec!["device-kitchen-0002".into()];
    status.links = vec![link];
    let lines = status_lines(&status, &names, false);
    let text = lines.join("\n");
    assert!(text.contains("[Kitchen Mac]"), "{text}");
    assert!(text.contains("  Kitchen Mac  connected"), "{text}");
    assert!(text.contains("configured full copy: Kitchen Mac  (available)"), "{text}");
    assert!(!text.contains("device-kitchen-0002"), "{text}");
}

/// Names are looked up only when the output has a device to name.
#[test]
fn names_are_wanted_only_when_a_device_is_shown() {
    let mut status = base_status();
    assert!(!names_a_device(&status));
    status.attention_reasons = vec!["conflict:g".into()];
    assert!(!names_a_device(&status));
    status.attention_reasons = vec!["peer_update_required:d".into()];
    assert!(names_a_device(&status));
    let mut status = base_status();
    status.peers = vec![base_peer()];
    assert!(names_a_device(&status));
}

fn dimension_link(
    availability: ProductAvailability,
    protection: DataProtection,
    reachable: &[&str],
    offline: &[&str],
    update: &[&str],
    protected_by: &[&str],
) -> LinkStatus {
    let own = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    LinkStatus {
        availability: availability as i32,
        protection: protection as i32,
        availability_reachable_device_ids: own(reachable),
        availability_offline_device_ids: own(offline),
        availability_update_required_device_ids: own(update),
        protection_device_ids: own(protected_by),
        ..base_link()
    }
}

#[test]
fn details_name_the_device_a_folder_waits_for_and_keep_protection_apart() {
    let link = dimension_link(
        ProductAvailability::WaitingForPeer,
        DataProtection::Protected,
        &["b"],
        &["a"],
        &[],
        &["a"],
    );
    let lines = dimension_detail_lines(&link, &DeviceNames::default());
    assert_eq!(
        lines,
        [
            "    availability: waiting for a to come online (1 of 2 other devices available)",
            "    protection: protected (also on a)",
        ]
    );
}

#[test]
fn details_never_read_unset_or_unknown_as_available_or_protected() {
    let unset = LinkStatus { availability: 0, protection: 0, ..base_link() };
    let lines = dimension_detail_lines(&unset, &DeviceNames::default());
    assert!(lines[0].contains("unknown") && lines[1].contains("unknown"), "{lines:?}");
    let at_risk = dimension_link(
        ProductAvailability::WaitingForExactContent,
        DataProtection::AtRisk,
        &["b"],
        &[],
        &[],
        &[],
    );
    let lines = dimension_detail_lines(&at_risk, &DeviceNames::default());
    assert!(lines[0].contains("a device that has this version"), "{lines:?}");
    assert!(lines[1].contains("at risk"), "{lines:?}");
}

#[test]
fn details_say_update_required_for_a_reachable_incompatible_holder() {
    let link = dimension_link(
        ProductAvailability::UpdateRequired,
        DataProtection::Pending,
        &[],
        &[],
        &["old"],
        &["old"],
    );
    let lines = dimension_detail_lines(&link, &DeviceNames::default());
    assert_eq!(lines[0], "    availability: update required on old before this can sync (0 of 1 other devices available)");
    assert_eq!(lines[1], "    protection: pending (waiting for old to confirm)");
}

#[test]
fn dimension_lines_appear_only_under_details() {
    let mut status = base_status();
    status.links.push(base_link());
    let plain = status_lines(&status, &DeviceNames::default(), false);
    assert!(!plain.iter().any(|l| l.contains("availability:")));
    let detailed = status_lines(&status, &DeviceNames::default(), true);
    assert!(detailed.iter().any(|l| l.starts_with("    availability:")));
}
