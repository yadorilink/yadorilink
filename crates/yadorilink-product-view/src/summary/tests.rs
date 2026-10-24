#![cfg(test)]

use super::*;
use yadorilink_ipc_proto::daemonctl::{
    DegradedCause as Wire, FetchAvailability as Fetch, GroupDurabilityStatus as Durability,
    LocalStorageState as Storage,
};

fn link(group: &str) -> LinkStatus {
    LinkStatus {
        local_path: format!("/Users/alice/{group}"),
        group_id: group.into(),
        materialization_policy: "eager".into(),
        local_storage_state: Storage::FullCopy as i32,
        fetch_availability: Fetch::AvailableNow as i32,
        durability_status: Durability::Protected as i32,
        ..Default::default()
    }
}

fn transferring(group: &str, done: u64, total: u64) -> LinkStatus {
    LinkStatus {
        has_active_transfer: true,
        transfer_bytes_done: done,
        transfer_bytes_total: total,
        ..link(group)
    }
}

fn folder(link: &LinkStatus) -> ProductState {
    ProductStatusSummary::for_folder(link).state
}

fn global(links: &[LinkStatus]) -> ProductStatusSummary {
    ProductStatusSummary::global(links)
}

#[test]
fn clean_folder_is_up_to_date() {
    assert_eq!(folder(&link("a")), ProductState::UpToDate);
    assert_eq!(global(&[link("a"), link("b")]).state, ProductState::UpToDate);
}

#[test]
fn no_folders_is_up_to_date_with_no_counts() {
    let s = global(&[]);
    assert_eq!(s.state, ProductState::UpToDate);
    assert_eq!((s.attention_count, s.paused_count, s.syncing_count, s.waiting_count), (0, 0, 0, 0));
}

#[test]
fn active_transfer_is_syncing() {
    assert_eq!(folder(&transferring("a", 1, 10)), ProductState::Syncing);
}

#[test]
fn hydrating_files_and_partial_materialization_with_available_content_are_syncing() {
    let hydrating = LinkStatus { hydrating_count: 2, requested_content_count: 2, ..link("a") };
    assert_eq!(folder(&hydrating), ProductState::Syncing);
    let partial = LinkStatus {
        local_storage_state: Storage::PartiallyMaterialized as i32,
        requested_content_count: 1,
        ..link("a")
    };
    assert_eq!(folder(&partial), ProductState::Syncing);
}

#[test]
fn partially_materialized_with_unavailable_content_is_waiting_not_syncing() {
    let l = LinkStatus {
        local_storage_state: Storage::PartiallyMaterialized as i32,
        requested_content_count: 1,
        fetch_availability: Fetch::UnavailableNow as i32,
        ..link("a")
    };
    assert_eq!(folder(&l), ProductState::Waiting);
}

#[test]
fn bytes_remaining_is_unknown_while_other_eager_work_is_queued() {
    let l = LinkStatus {
        local_storage_state: Storage::PartiallyMaterialized as i32,
        requested_content_count: 1,
        ..transferring("a", 10, 100)
    };
    assert_eq!(folder(&l), ProductState::Syncing);
    assert_eq!(global(&[l]).bytes_remaining, None);
}

#[test]
fn on_demand_placeholders_are_a_normal_steady_state() {
    let l = LinkStatus {
        materialization_policy: "ondemand".into(),
        local_storage_state: Storage::OnDemand as i32,
        placeholder_count: 40,
        ..link("a")
    };
    assert_eq!(folder(&l), ProductState::UpToDate);
}

#[test]
fn on_demand_steady_state_with_unavailable_content_and_no_request_is_not_waiting() {
    for f in [Fetch::UnavailableNow, Fetch::Unknown, Fetch::Unspecified] {
        let l = LinkStatus {
            materialization_policy: "ondemand".into(),
            local_storage_state: Storage::OnDemand as i32,
            placeholder_count: 40,
            fetch_availability: f as i32,
            ..link("a")
        };
        let s = global(std::slice::from_ref(&l));
        assert_eq!(s.state, ProductState::UpToDate, "{f:?}");
        assert_eq!(s.waiting_count, 0, "{f:?}");
        assert_eq!(folder(&l), ProductState::UpToDate, "{f:?}");
    }
}

#[test]
fn a_blocked_request_or_blocked_eager_work_is_waiting() {
    for f in [Fetch::UnavailableNow, Fetch::Unknown, Fetch::Unspecified] {
        // An On-Demand open (a hydrating file) that cannot be fetched.
        let requested = LinkStatus {
            materialization_policy: "ondemand".into(),
            local_storage_state: Storage::OnDemand as i32,
            hydrating_count: 1,
            requested_content_count: 1,
            fetch_availability: f as i32,
            ..link("a")
        };
        assert_eq!(folder(&requested), ProductState::Waiting, "{f:?}");
        assert_eq!(global(&[requested]).waiting_count, 1, "{f:?}");
        // Eager content still wanted but unfetchable.
        let eager = LinkStatus {
            local_storage_state: Storage::PartiallyMaterialized as i32,
            requested_content_count: 1,
            fetch_availability: f as i32,
            ..link("a")
        };
        assert_eq!(folder(&eager), ProductState::Waiting, "{f:?}");
    }
}

#[test]
fn syncing_beats_waiting() {
    let l =
        LinkStatus { fetch_availability: Fetch::UnavailableNow as i32, ..transferring("a", 1, 2) };
    assert_eq!(folder(&l), ProductState::Syncing);
}

#[test]
fn paused_beats_syncing_and_waiting() {
    let l = LinkStatus { paused: true, ..transferring("a", 1, 2) };
    assert_eq!(folder(&l), ProductState::Paused);
    let l = LinkStatus {
        paused: true,
        fetch_availability: Fetch::UnavailableNow as i32,
        hydrating_count: 1,
        requested_content_count: 1,
        ..link("a")
    };
    assert_eq!(folder(&l), ProductState::Paused);
}

#[test]
fn each_attention_condition_is_needs_attention() {
    let cases: Vec<(LinkStatus, AttentionReason)> = vec![
        (LinkStatus { conflict_count: 1, ..link("a") }, AttentionReason::Conflict),
        (LinkStatus { conflicts_pending: 1, ..link("a") }, AttentionReason::Conflict),
        (
            LinkStatus { durability_status: Durability::AtRisk as i32, ..link("a") },
            AttentionReason::DurabilityAtRisk,
        ),
        (
            LinkStatus { durability_status: Durability::Unknown as i32, ..link("a") },
            AttentionReason::DurabilityUnconfirmed,
        ),
        (
            LinkStatus { degraded: true, ..link("a") },
            AttentionReason::Degraded(DegradedCause::Stopped),
        ),
        (
            LinkStatus {
                degraded: true,
                degraded_cause: Wire::WaitingForDiskSpace as i32,
                ..link("a")
            },
            AttentionReason::Degraded(DegradedCause::WaitingForDiskSpace),
        ),
        (
            LinkStatus { degraded: true, degraded_cause: Wire::FileWatchLimit as i32, ..link("a") },
            AttentionReason::Degraded(DegradedCause::FileWatchLimit),
        ),
        (
            LinkStatus { degraded: true, degraded_cause: Wire::OwnershipLost as i32, ..link("a") },
            AttentionReason::Degraded(DegradedCause::OwnershipLost),
        ),
        (
            LinkStatus { degraded: true, degraded_cause: Wire::NotJoined as i32, ..link("a") },
            AttentionReason::Degraded(DegradedCause::NotJoined),
        ),
        (LinkStatus { ambiguous: true, ..link("a") }, AttentionReason::LinkedTwice),
        (LinkStatus { capture_volume_changed: true, ..link("a") }, AttentionReason::VolumeChanged),
        (
            LinkStatus { stranded_directory_count: 1, ..link("a") },
            AttentionReason::StrandedDirectory,
        ),
        (LinkStatus { held_file_count: 1, ..link("a") }, AttentionReason::HeldFile),
    ];
    for (l, reason) in cases {
        let s = ProductStatusSummary::for_folder(&l);
        assert_eq!(s.state, ProductState::NeedsAttention, "{reason:?}");
        assert_eq!(s.attention_reasons, vec![reason]);
        assert_eq!(s.attention_count, 1);
    }
}

/// A folder waiting for disk space is offered what the typed item offers, not a retry of a stopped
/// folder.
#[test]
fn a_disk_space_wait_is_not_offered_a_retry() {
    let stopped = LinkStatus { degraded: true, ..link("a") };
    let waiting = LinkStatus {
        degraded: true,
        degraded_cause: Wire::WaitingForDiskSpace as i32,
        ..link("a")
    };
    assert_eq!(ProductStatusSummary::for_folder(&stopped).next_action, Some(ProductAction::Retry));
    assert_eq!(
        ProductStatusSummary::for_folder(&waiting).next_action,
        Some(ProductAction::ViewDetails)
    );
}

#[test]
fn attention_beats_syncing() {
    let l = LinkStatus { conflict_count: 2, ..transferring("a", 1, 2) };
    assert_eq!(folder(&l), ProductState::NeedsAttention);
}

#[test]
fn attention_beats_paused_even_for_a_paused_degraded_folder() {
    let l = LinkStatus { paused: true, degraded: true, ..link("a") };
    let s = ProductStatusSummary::for_folder(&l);
    assert_eq!(s.state, ProductState::NeedsAttention);
    assert_eq!(s.paused_count, 1);
}

#[test]
fn non_required_capability_gaps_do_not_need_attention() {
    let l = LinkStatus { skipped_symlink_count: 3, ..link("a") };
    assert_eq!(folder(&l), ProductState::UpToDate);
}

#[test]
fn global_precedence_is_attention_paused_syncing_waiting_up_to_date() {
    let attention = LinkStatus { conflict_count: 1, ..link("att") };
    let paused = LinkStatus { paused: true, ..link("pau") };
    let syncing = transferring("syn", 1, 2);
    let waiting = LinkStatus {
        fetch_availability: Fetch::UnavailableNow as i32,
        hydrating_count: 1,
        requested_content_count: 1,
        ..link("wai")
    };
    let ok = link("ok");

    let all = [ok.clone(), waiting.clone(), syncing.clone(), paused.clone(), attention.clone()];
    assert_eq!(global(&all).state, ProductState::NeedsAttention);
    assert_eq!(global(&all[..4]).state, ProductState::Paused);
    assert_eq!(global(&all[..3]).state, ProductState::Syncing);
    assert_eq!(global(&all[..2]).state, ProductState::Waiting);
    assert_eq!(global(&all[..1]).state, ProductState::UpToDate);

    let s = global(&all);
    assert_eq!((s.attention_count, s.paused_count, s.syncing_count, s.waiting_count), (1, 1, 1, 1));
}

#[test]
fn syncing_plus_attention_and_paused_plus_attention_report_attention() {
    let a = LinkStatus { ambiguous: true, ..link("a") };
    assert_eq!(global(&[transferring("s", 1, 2), a.clone()]).state, ProductState::NeedsAttention);
    let p = LinkStatus { paused: true, ..link("p") };
    assert_eq!(global(&[p, a]).state, ProductState::NeedsAttention);
}

#[test]
fn bytes_remaining_sums_known_totals() {
    let s = global(&[transferring("a", 30, 100), transferring("b", 0, 50)]);
    assert_eq!(s.bytes_remaining, Some(120));
}

#[test]
fn bytes_remaining_is_unknown_when_any_syncing_total_is_unknown() {
    let hydrating = LinkStatus { hydrating_count: 1, requested_content_count: 1, ..link("h") };
    assert_eq!(global(&[transferring("a", 30, 100), hydrating]).bytes_remaining, None);
    assert_eq!(global(&[transferring("z", 0, 0)]).bytes_remaining, None);
}

#[test]
fn bytes_remaining_never_underflows_and_is_absent_when_not_syncing() {
    assert_eq!(global(&[transferring("a", 120, 100)]).bytes_remaining, Some(0));
    assert_eq!(global(&[link("a")]).bytes_remaining, None);
}

#[test]
fn labels_are_the_closed_set() {
    let labels: Vec<_> = [
        ProductState::UpToDate,
        ProductState::Syncing,
        ProductState::Waiting,
        ProductState::NeedsAttention,
        ProductState::Paused,
    ]
    .iter()
    .map(|s| s.label())
    .collect();
    assert_eq!(labels, ["Up to date", "Syncing", "Waiting", "Needs attention", "Paused"]);
}

#[test]
fn bytes_remaining_is_unknown_when_another_folder_has_queued_work() {
    let queued = LinkStatus {
        local_storage_state: Storage::PartiallyMaterialized as i32,
        requested_content_count: 1,
        fetch_availability: Fetch::UnavailableNow as i32,
        ..link("q")
    };
    let s = global(&[transferring("a", 10, 100), queued]);
    assert_eq!(s.state, ProductState::Syncing);
    assert_eq!(s.bytes_remaining, None);
}

#[test]
fn a_durability_check_still_pending_is_not_attention() {
    let l = LinkStatus {
        durability_status: Durability::Unknown as i32,
        durability_check_pending: true,
        ..link("a")
    };
    assert_eq!(folder(&l), ProductState::UpToDate);
}

#[test]
fn hydrating_with_unavailable_content_is_waiting_not_syncing() {
    let l = LinkStatus {
        hydrating_count: 1,
        requested_content_count: 1,
        fetch_availability: Fetch::UnavailableNow as i32,
        ..link("a")
    };
    assert_eq!(folder(&l), ProductState::Waiting);
}

#[test]
fn bytes_remaining_is_unknown_while_files_hydrate_beside_an_active_transfer() {
    let l =
        LinkStatus { hydrating_count: 1, requested_content_count: 1, ..transferring("a", 10, 100) };
    assert_eq!(folder(&l), ProductState::Syncing);
    assert_eq!(global(&[l]).bytes_remaining, None);
}

#[test]
fn bytes_remaining_counts_an_active_transfer_in_a_folder_masked_by_attention() {
    let conflicted = LinkStatus { conflict_count: 1, ..transferring("a", 0, 100) };
    let s = global(&[conflicted, transferring("b", 0, 5)]);
    assert_eq!(s.state, ProductState::NeedsAttention);
    assert_eq!(s.bytes_remaining, Some(105));
}

/// An On-Demand open queued for an assembly slot is still a placeholder (no hydrating file) but
/// is requested content: it is Waiting while fetching is unavailable.
#[test]
fn a_queued_on_demand_open_with_unavailable_content_is_waiting() {
    let l = LinkStatus {
        materialization_policy: "ondemand".into(),
        local_storage_state: Storage::OnDemand as i32,
        placeholder_count: 40,
        requested_content_count: 1,
        fetch_availability: Fetch::UnavailableNow as i32,
        ..link("a")
    };
    assert_eq!(folder(&l), ProductState::Waiting);
    assert_eq!(global(&[l]).waiting_count, 1);
}

/// Eviction is not a request for content: an idle folder whose files are being evicted is not
/// Waiting however unavailable fetching is.
#[test]
fn an_idle_folder_evicting_files_is_not_waiting() {
    let l = LinkStatus {
        materialization_policy: "ondemand".into(),
        local_storage_state: Storage::OnDemand as i32,
        placeholder_count: 40,
        hydrating_count: 0,
        requested_content_count: 0,
        fetch_availability: Fetch::UnavailableNow as i32,
        ..link("a")
    };
    let s = global(std::slice::from_ref(&l));
    assert_eq!((s.state, s.waiting_count), (ProductState::UpToDate, 0));
}

#[test]
fn the_summary_carries_both_dimensions_and_they_do_not_change_the_state() {
    use crate::availability::Availability;
    use crate::protection::Protection;
    use yadorilink_ipc_proto::daemonctl::{DataProtection, ProductAvailability};

    let waiting_but_protected = LinkStatus {
        availability: ProductAvailability::WaitingForPeer as i32,
        availability_offline_device_ids: vec!["mini".into()],
        protection: DataProtection::Protected as i32,
        protection_device_ids: vec!["mini".into()],
        ..link("a")
    };
    let s = ProductStatusSummary::for_folder(&waiting_but_protected);
    assert_eq!(s.state, ProductState::UpToDate);
    assert_eq!(s.availability.availability, Availability::WaitingForPeer);
    assert_eq!(s.availability.offline_device_ids, ["mini"]);
    assert_eq!(s.protection.protection, Protection::Protected);
}

#[test]
fn a_global_summary_is_protected_only_if_every_folder_is() {
    use crate::protection::Protection;
    use yadorilink_ipc_proto::daemonctl::DataProtection;

    let protected = LinkStatus { protection: DataProtection::Protected as i32, ..link("a") };
    let unproven = link("b");
    assert_eq!(
        global(std::slice::from_ref(&protected)).protection.protection,
        Protection::Protected
    );
    assert_eq!(global(&[protected.clone(), unproven]).protection.protection, Protection::Unknown);
    let at_risk = LinkStatus { protection: DataProtection::AtRisk as i32, ..link("c") };
    assert_eq!(global(&[protected, at_risk]).protection.protection, Protection::AtRisk);
}

fn next(links: &[LinkStatus]) -> Option<ProductAction> {
    global(links).next_action
}

/// The one thing to offer for the state: resume for a paused folder, the worst problem's action
/// for attention, nothing when there is nothing to do.
#[test]
fn next_action_follows_the_state() {
    assert_eq!(next(&[link("a")]), None);
    assert_eq!(next(&[]), None);

    let paused = LinkStatus { paused: true, ..link("a") };
    assert_eq!(next(std::slice::from_ref(&paused)), Some(ProductAction::Resume));

    let conflict = LinkStatus { conflict_count: 1, ..link("b") };
    assert_eq!(next(std::slice::from_ref(&conflict)), Some(ProductAction::ReviewConflict));
    // Attention outranks pause, as the state does.
    assert_eq!(next(&[paused.clone(), conflict.clone()]), Some(ProductAction::ReviewConflict));

    // The most severe problem wins over an earlier, milder one.
    let at_risk = LinkStatus { durability_status: Durability::AtRisk as i32, ..link("c") };
    assert_eq!(next(&[conflict, at_risk]), Some(ProductAction::ViewDetails));

    let waiting = LinkStatus {
        local_storage_state: Storage::PartiallyMaterialized as i32,
        requested_content_count: 1,
        fetch_availability: Fetch::UnavailableNow as i32,
        ..link("d")
    };
    assert_eq!(folder(&waiting), ProductState::Waiting);
    assert_eq!(next(&[waiting]), None, "waiting is not something the user fixes");
}

/// A request waiting on the owner puts the folder in needs-attention with the review as the one
/// thing to offer; an owner with nothing waiting (or a non-owner, whom the daemon tells nothing)
/// sees nothing.
#[test]
fn a_waiting_approval_request_needs_attention_and_offers_the_review() {
    let waiting = LinkStatus { pending_approvals: 2, ..link("a") };
    let summary = ProductStatusSummary::for_folder(&waiting);
    assert_eq!(summary.state, ProductState::NeedsAttention);
    assert_eq!(summary.attention_reasons, vec![AttentionReason::ApprovalPending]);
    assert_eq!(summary.next_action, Some(ProductAction::ReviewApproval));
    assert_eq!(folder(&link("a")), ProductState::UpToDate);
    // A conflict is milder than nothing else but not milder than a warning of equal rank: the
    // first reported among equals wins, and the severe one still outranks both.
    let at_risk = LinkStatus { durability_status: Durability::AtRisk as i32, ..link("c") };
    assert_eq!(next(&[waiting, at_risk]), Some(ProductAction::ViewDetails));
}
