#![cfg(test)]

use super::*;

fn base_link() -> LinkStatus {
    LinkStatus {
        local_path: "/Users/alice/Photos".into(),
        group_id: "group-1".into(),
        materialization_policy: "eager".into(),
        ..Default::default()
    }
}

#[test]
fn display_name_uses_the_last_path_segment() {
    assert_eq!(display_name("/Users/alice/Photos"), "Photos");
}

#[test]
fn display_name_falls_back_to_the_whole_path_when_it_has_no_segment() {
    assert_eq!(display_name("/"), "/");
}

#[test]
fn eager_policy_is_synced_mode() {
    assert_eq!(FolderMode::from_link(&base_link()), FolderMode::Synced);
}

#[test]
fn ondemand_policy_is_selective_mode() {
    let link = LinkStatus { materialization_policy: "ondemand".into(), ..base_link() };
    assert_eq!(FolderMode::from_link(&link), FolderMode::Selective);
}

#[test]
fn unrecognized_policy_defaults_to_synced_mode() {
    let link = LinkStatus { materialization_policy: "".into(), ..base_link() };
    assert_eq!(FolderMode::from_link(&link), FolderMode::Synced);
}

#[test]
fn healthy_idle_link_is_up_to_date() {
    assert_eq!(FolderState::from_link(&base_link()), FolderState::UpToDate);
}

#[test]
fn active_transfer_is_syncing() {
    let link = LinkStatus { has_active_transfer: true, ..base_link() };
    assert_eq!(FolderState::from_link(&link), FolderState::Syncing);
}

#[test]
fn paused_link_is_paused_even_while_transferring() {
    let link = LinkStatus { paused: true, has_active_transfer: true, ..base_link() };
    assert_eq!(FolderState::from_link(&link), FolderState::Paused);
}

#[test]
fn degraded_link_is_attention() {
    let link = LinkStatus { degraded: true, ..base_link() };
    assert_eq!(FolderState::from_link(&link), FolderState::Attention);
}

#[test]
fn conflicted_link_is_attention() {
    let link = LinkStatus { conflict_count: 2, ..base_link() };
    assert_eq!(FolderState::from_link(&link), FolderState::Attention);
}

#[test]
fn ambiguous_link_is_blocked_even_when_also_paused() {
    let link = LinkStatus { ambiguous: true, paused: true, ..base_link() };
    assert_eq!(FolderState::from_link(&link), FolderState::Blocked);
}

#[test]
fn paused_outranks_attention() {
    let link = LinkStatus { paused: true, degraded: true, conflict_count: 3, ..base_link() };
    assert_eq!(FolderState::from_link(&link), FolderState::Paused);
}

#[test]
fn attention_outranks_syncing() {
    let link = LinkStatus { degraded: true, has_active_transfer: true, ..base_link() };
    assert_eq!(FolderState::from_link(&link), FolderState::Attention);
}

#[test]
fn from_link_populates_every_field_from_the_wire_struct() {
    let link = LinkStatus {
        local_path: "/data/Docs".into(),
        group_id: "group-42".into(),
        materialization_policy: "ondemand".into(),
        conflict_count: 1,
        hydrated_count: 2,
        placeholder_count: 3,
        hydrating_count: 4,
        held_file_count: 5,
        skipped_symlink_count: 6,
        has_active_transfer: true,
        transfer_bytes_done: 10,
        transfer_bytes_total: 100,
        transfer_blocks_done: 1,
        transfer_blocks_total: 10,
        transfer_eta_seconds: 30,
        policy_stale: true,
        ambiguous_local_paths: vec!["/data/Docs".into(), "/data/Docs2".into()],
        degraded_reason: "disk pressure".into(),
        full_replica_device_ids: vec!["device-a".into()],
        ..Default::default()
    };

    let summary = FolderSummary::from(&link);

    assert_eq!(summary.group_id, "group-42");
    assert_eq!(summary.name, "Docs");
    assert_eq!(summary.local_path, "/data/Docs");
    assert_eq!(summary.mode, FolderMode::Selective);
    assert_eq!(summary.state, FolderState::Attention);
    assert_eq!(summary.conflict_count, 1);
    assert_eq!(summary.files_hydrated, 2);
    assert_eq!(summary.files_placeholder, 3);
    assert_eq!(summary.files_hydrating, 4);
    assert_eq!(summary.files_total(), 9);
    assert_eq!(summary.held_file_count, 5);
    assert_eq!(summary.skipped_symlink_count, 6);
    assert_eq!(
        summary.transfer,
        Some(FolderTransfer {
            bytes_done: 10,
            bytes_total: 100,
            blocks_done: 1,
            blocks_total: 10,
            eta_seconds: 30,
        })
    );
    assert!(summary.policy_stale);
    assert_eq!(summary.ambiguous_local_paths, vec!["/data/Docs", "/data/Docs2"]);
    assert_eq!(summary.degraded_reason, "disk pressure");
    assert_eq!(summary.full_replica_device_ids, vec!["device-a".to_string()]);
}

#[test]
fn no_active_transfer_means_no_transfer_progress() {
    let summary = FolderSummary::from(&base_link());
    assert_eq!(summary.transfer, None);
}
