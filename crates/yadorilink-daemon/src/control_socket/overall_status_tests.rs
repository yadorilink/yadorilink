#![cfg(test)]

use super::*;

/// A link with every status axis in its healthiest state (`Protected`,
/// `AvailableNow`) and nothing else wrong -- the baseline every test
/// below that isn't specifically exercising `durability_status`/
/// `fetch_availability` starts from, so those two axes' own new
/// `overall_status` contribution doesn't leak into an unrelated test's
/// expected reasons. A bare `LinkStatus::default()` would NOT do this:
/// its zero-value `durability_status`/`fetch_availability` are
/// `Unspecified` -- deliberately treated as attention-worthy (an older
/// daemon that predates the field must not read as fine), so it would
/// contribute its own reason to every test that used it.
fn protected_link(group_id: &str) -> LinkStatus {
    LinkStatus {
        group_id: group_id.to_string(),
        durability_status: yadorilink_ipc_proto::daemonctl::GroupDurabilityStatus::Protected as i32,
        fetch_availability: yadorilink_ipc_proto::daemonctl::FetchAvailability::AvailableNow as i32,
        ..Default::default()
    }
}

/// spec "Sync is healthy": no links/volumes/peers/errors at all (the
/// zero-value default) is healthy with no reasons — matches this
/// file's/`status.rs`'s "additive, empty/zero unless applicable"
/// convention for a freshly-started daemon.
#[test]
fn empty_status_is_healthy() {
    let (state, reasons) = overall_status(&StatusResponse::default());
    assert_eq!(state, OverallState::Healthy);
    assert!(reasons.is_empty());
}

/// A directory a removal moved aside and could not put back needs attention,
/// naming the affected group.
#[test]
fn a_stranded_directory_is_attention() {
    let response = StatusResponse {
        links: vec![LinkStatus { stranded_directory_count: 1, ..protected_link("group-1") }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["stranded_directory:group-1".to_string()]);
}

/// Files a scan cannot read need attention (not a degraded folder: the rest keeps syncing).
#[test]
fn unreadable_files_are_attention_naming_the_group() {
    let response = StatusResponse {
        links: vec![LinkStatus { unreadable_file_count: 2, ..protected_link("group-1") }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["unreadable_files:group-1".to_string()]);
}

/// A merely-paused link with nothing else wrong stays healthy — pause
/// is a deliberate user action, not an error state.
#[test]
fn paused_link_alone_is_still_healthy() {
    let response = StatusResponse {
        links: vec![LinkStatus { paused: true, ..protected_link("group-1") }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Healthy);
    assert!(reasons.is_empty());
}

/// spec "Sync needs attention": a conflict on any link needs attention,
/// naming the affected group.
#[test]
fn conflict_is_attention() {
    let response = StatusResponse {
        links: vec![LinkStatus { conflict_count: 1, ..protected_link("group-1") }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["conflict:group-1".to_string()]);
}

/// `Unknown` durability while the first custody check is still pending is
/// "checking" on a freshly linked folder, not something to act on; the same
/// `Unknown` after a check has run still needs attention.
#[test]
fn durability_unknown_needs_attention_only_once_a_check_has_run() {
    let unknown = LinkStatus {
        durability_status: yadorilink_ipc_proto::daemonctl::GroupDurabilityStatus::Unknown as i32,
        ..protected_link("group-1")
    };
    let pending = StatusResponse {
        links: vec![LinkStatus { durability_check_pending: true, ..unknown.clone() }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&pending);
    assert_eq!(state, OverallState::Healthy);
    assert!(reasons.is_empty(), "{reasons:?}");

    let checked = StatusResponse { links: vec![unknown], ..Default::default() };
    let (state, reasons) = overall_status(&checked);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["durability_unknown:group-1".to_string()]);
}

/// A link the daemon has positively confirmed has no durable copy
/// anywhere (`AtRisk`) is `Degraded`, not `Healthy` -- this is the
/// exact overstatement this guards against: the rollup used to
/// never read `durability_status` at all, so a folder with zero
/// durable copies could still read `Overall: healthy`.
#[test]
fn at_risk_durability_is_degraded() {
    let response = StatusResponse {
        links: vec![LinkStatus {
            durability_status: yadorilink_ipc_proto::daemonctl::GroupDurabilityStatus::AtRisk
                as i32,
            ..protected_link("group-1")
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Degraded);
    assert_eq!(reasons, vec!["durability_at_risk:group-1".to_string()]);
}

/// A link whose durability cannot currently be confirmed (`Unknown`,
/// or `Unspecified` from an unset value is
/// `Attention`, never silently `Healthy` -- fail-safe, matching every
/// other "cannot currently confirm" surface in this daemon.
#[test]
fn unknown_durability_is_attention() {
    let response = StatusResponse {
        links: vec![LinkStatus {
            durability_status: yadorilink_ipc_proto::daemonctl::GroupDurabilityStatus::Unknown
                as i32,
            ..protected_link("group-1")
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["durability_unknown:group-1".to_string()]);
}

/// A link that is durably `Protected` but cannot currently be fetched
/// is `Attention` -- "fetch not confirmed" is real and actionable,
/// but must never escalate to `Degraded`: the data itself is not at
/// risk, matching "Durability != Connectivity."
#[test]
fn unavailable_fetch_with_protected_durability_is_attention_not_degraded() {
    let response = StatusResponse {
        links: vec![LinkStatus {
            fetch_availability: yadorilink_ipc_proto::daemonctl::FetchAvailability::UnavailableNow
                as i32,
            hydrating_count: 1,
            requested_content_count: 1,
            ..protected_link("group-1")
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["fetch_unavailable:group-1".to_string()]);
}

/// An idle On-Demand folder (remote placeholders, no file being fetched) with unavailable or
/// unconfirmed content is a healthy steady state, not attention.
#[test]
fn unavailable_fetch_without_wanted_content_is_healthy() {
    use yadorilink_ipc_proto::daemonctl::{FetchAvailability, LocalStorageState};
    for f in [FetchAvailability::UnavailableNow, FetchAvailability::Unknown] {
        let response = StatusResponse {
            links: vec![LinkStatus {
                fetch_availability: f as i32,
                local_storage_state: LocalStorageState::OnDemand as i32,
                placeholder_count: 5,
                ..protected_link("group-1")
            }],
            ..Default::default()
        };
        assert_eq!(overall_status(&response), (OverallState::Healthy, Vec::new()), "{f:?}");
    }
}

/// A link that is durably `Protected` but whose `fetch_availability`
/// cannot currently be confirmed (`Unknown`, or `Unspecified` from an
/// unset-value) is `Attention`, never silently `Healthy` -- an
/// unconfirmed fetch availability must fail closed exactly like an
/// unconfirmed durability status does (an earlier version of this fold-in only
/// checked `UnavailableNow`, so `Unknown`/`Unspecified` fetch
/// availability paired with `Protected` durability silently read as
/// fully `Healthy`).
#[test]
fn unknown_fetch_availability_with_protected_durability_is_attention() {
    let response = StatusResponse {
        links: vec![LinkStatus {
            fetch_availability: yadorilink_ipc_proto::daemonctl::FetchAvailability::Unknown as i32,
            hydrating_count: 1,
            requested_content_count: 1,
            ..protected_link("group-1")
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["fetch_availability_unknown:group-1".to_string()]);
}

/// spec "Sync needs attention": a `"low"` volume needs attention; a
/// `"critical"` one is degraded — the severity split
/// `VolumeFreeSpace.state` already draws.
#[test]
fn low_disk_is_attention_but_critical_disk_is_degraded() {
    let low = StatusResponse {
        volumes: vec![VolumeFreeSpace {
            path: "/data".into(),
            state: "low".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert_eq!(overall_status(&low).0, OverallState::Attention);

    let critical = StatusResponse {
        volumes: vec![VolumeFreeSpace {
            path: "/data".into(),
            state: "critical".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&critical);
    assert_eq!(state, OverallState::Degraded);
    assert_eq!(reasons, vec!["low_disk_critical:/data".to_string()]);
}

/// spec "Sync needs attention": a peer that cannot be connected
/// (unreachable) needs attention.
#[test]
fn unreachable_peer_is_attention() {
    let response = StatusResponse {
        peers: vec![PeerStatus {
            device_id: "device-b".into(),
            reachability: yadorilink_ipc_proto::daemonctl::PeerReachability::Unreachable as i32,
            ..Default::default()
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["peer_disconnected:device-b".to_string()]);
}

/// A peer that is reachable but on another version is "update required", never "offline"; a
/// genuinely unreachable peer next to it is still offline.
#[test]
fn version_mismatched_peer_is_update_required_never_offline() {
    use yadorilink_ipc_proto::daemonctl::PeerReachability;
    let response = StatusResponse {
        peers: vec![
            PeerStatus {
                device_id: "device-old".into(),
                reachability: PeerReachability::Connected as i32,
                version_incompatible: true,
                ..Default::default()
            },
            PeerStatus {
                device_id: "device-gone".into(),
                reachability: PeerReachability::Unreachable as i32,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(
        reasons,
        vec![
            "peer_update_required:device-old".to_string(),
            "peer_disconnected:device-gone".to_string()
        ]
    );
}

/// A client below the manifest's minimum supported version needs attention with the same
/// update-required item a mismatched peer gets, and a client that meets it does not.
#[test]
fn a_client_below_the_minimum_supported_version_is_update_required() {
    let below = StatusResponse { update_required: true, ..Default::default() };
    let (state, reasons) = overall_status(&below);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["update_required".to_string()]);

    let (state, reasons) = overall_status(&StatusResponse::default());
    assert_eq!(state, OverallState::Healthy);
    assert!(reasons.is_empty());
}

/// A degraded link (disk-pressure elsewhere) takes
/// precedence over -- and is reported alongside -- an unrelated
/// attention-level issue.
#[test]
fn degraded_link_outranks_but_still_reports_attention_reasons() {
    let response = StatusResponse {
        links: vec![
            LinkStatus { degraded: true, ..protected_link("group-1") },
            LinkStatus { conflict_count: 1, ..protected_link("group-2") },
        ],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Degraded);
    assert!(reasons.contains(&"degraded:group-1".to_string()));
    assert!(reasons.contains(&"conflict:group-2".to_string()));
}

/// A recorded update failure alone needs attention, even with every
/// link/volume/peer otherwise healthy.
#[test]
fn update_failure_is_attention() {
    let response = StatusResponse {
        update_last_error_category: "update_manifest_fetch_failed".into(),
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["update_failed:update_manifest_fetch_failed".to_string()]);
}

/// The Windows host restored its sync-root registry from an older generation: attention, not a
/// stop, and only that.
#[test]
fn a_restored_provider_registry_is_attention() {
    let response = StatusResponse { provider_registry_restored: true, ..Default::default() };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["provider_registry_restored:older_generation".to_string()]);
}

/// A group linked at two folders syncs nothing at all; the rollup must not
/// read healthy next to the `NOT SYNCING` detail line.
#[test]
fn an_ambiguous_link_makes_the_rollup_degraded() {
    let response = StatusResponse {
        links: vec![LinkStatus {
            ambiguous: true,
            ambiguous_local_paths: vec!["/a".into(), "/b".into()],
            ..protected_link("group-1")
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Degraded);
    assert_eq!(reasons, vec!["ambiguous:group-1".to_string()]);
}

/// A link whose sync-root lock sidecar is gone reports the terminal `ownership_lost` reason.
#[test]
fn an_ownership_lost_link_reports_its_own_reason() {
    let response = StatusResponse {
        links: vec![LinkStatus {
            degraded: true,
            degraded_reason: crate::link_registry::OWNERSHIP_LOST_REASON.into(),
            ..protected_link("group-1")
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Degraded);
    assert_eq!(reasons, vec!["ownership_lost:group-1".to_string()]);
}

/// The daemon's rollup and the canonical product summary must not disagree about whether a
/// folder needs the user. Every per-link attention condition here is `NeedsAttention` in both;
/// a healthy link is neither. Fetch availability is the one deliberate difference: the rollup
/// calls it attention, the summary calls it `Waiting` (never `UpToDate`), and both raise it only
/// while content is wanted: an idle On-Demand folder is healthy / up to date in both.
#[test]
fn the_rollup_and_the_canonical_product_summary_agree_on_what_needs_attention() {
    use yadorilink_product_view::summary::{ProductState, ProductStatusSummary};

    let attention: Vec<(&str, LinkStatus)> = vec![
        ("conflict", LinkStatus { conflict_count: 1, ..protected_link("g") }),
        ("conflict_pending", LinkStatus { conflicts_pending: 1, ..protected_link("g") }),
        ("held", LinkStatus { held_file_count: 1, ..protected_link("g") }),
        ("stranded", LinkStatus { stranded_directory_count: 1, ..protected_link("g") }),
        ("unreadable", LinkStatus { unreadable_file_count: 1, ..protected_link("g") }),
        ("approval_pending", LinkStatus { pending_approvals: 1, ..protected_link("g") }),
        ("volume_changed", LinkStatus { capture_volume_changed: true, ..protected_link("g") }),
        ("degraded", LinkStatus { degraded: true, ..protected_link("g") }),
        ("ambiguous", LinkStatus { ambiguous: true, ..protected_link("g") }),
        (
            "durability_at_risk",
            LinkStatus {
                durability_status: yadorilink_ipc_proto::daemonctl::GroupDurabilityStatus::AtRisk
                    as i32,
                ..protected_link("g")
            },
        ),
        (
            "durability_unknown",
            LinkStatus {
                durability_status: yadorilink_ipc_proto::daemonctl::GroupDurabilityStatus::Unknown
                    as i32,
                ..protected_link("g")
            },
        ),
    ];
    for (name, link) in attention {
        let response = StatusResponse { links: vec![link.clone()], ..Default::default() };
        assert_ne!(overall_status(&response).0, OverallState::Healthy, "{name}: rollup");
        assert_eq!(
            ProductStatusSummary::for_folder(&link).state,
            ProductState::NeedsAttention,
            "{name}: summary"
        );
    }

    for link in [
        protected_link("g"),
        LinkStatus { paused: true, ..protected_link("g") },
        LinkStatus { skipped_symlink_count: 2, ..protected_link("g") },
    ] {
        let response = StatusResponse { links: vec![link.clone()], ..Default::default() };
        assert_eq!(overall_status(&response).0, OverallState::Healthy);
        assert_ne!(ProductStatusSummary::for_folder(&link).state, ProductState::NeedsAttention);
    }

    for availability in [
        yadorilink_ipc_proto::daemonctl::FetchAvailability::UnavailableNow,
        yadorilink_ipc_proto::daemonctl::FetchAvailability::Unknown,
    ] {
        let blocked = LinkStatus {
            fetch_availability: availability as i32,
            hydrating_count: 1,
            requested_content_count: 1,
            ..protected_link("g")
        };
        let response = StatusResponse { links: vec![blocked.clone()], ..Default::default() };
        assert_eq!(overall_status(&response).0, OverallState::Attention);
        assert_eq!(ProductStatusSummary::for_folder(&blocked).state, ProductState::Waiting);

        let idle = LinkStatus {
            fetch_availability: availability as i32,
            local_storage_state: yadorilink_ipc_proto::daemonctl::LocalStorageState::OnDemand
                as i32,
            placeholder_count: 5,
            ..protected_link("g")
        };
        let response = StatusResponse { links: vec![idle.clone()], ..Default::default() };
        assert_eq!(overall_status(&response).0, OverallState::Healthy);
        assert_eq!(ProductStatusSummary::for_folder(&idle).state, ProductState::UpToDate);
    }
}

/// An On-Demand open queued for an assembly slot is requested content though no file is
/// hydrating yet: unavailable fetching is attention.
#[test]
fn a_queued_open_with_unavailable_fetch_is_attention() {
    use yadorilink_ipc_proto::daemonctl::{FetchAvailability, LocalStorageState};
    let response = StatusResponse {
        links: vec![LinkStatus {
            fetch_availability: FetchAvailability::UnavailableNow as i32,
            local_storage_state: LocalStorageState::OnDemand as i32,
            placeholder_count: 5,
            requested_content_count: 1,
            ..protected_link("group-1")
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["fetch_unavailable:group-1".to_string()]);
}

/// Files being evicted are not requested content: an idle folder is healthy whatever the
/// fetch availability says.
#[test]
fn an_idle_evicting_folder_with_unavailable_fetch_is_healthy() {
    use yadorilink_ipc_proto::daemonctl::{FetchAvailability, LocalStorageState};
    let response = StatusResponse {
        links: vec![LinkStatus {
            fetch_availability: FetchAvailability::UnavailableNow as i32,
            local_storage_state: LocalStorageState::OnDemand as i32,
            placeholder_count: 5,
            requested_content_count: 0,
            ..protected_link("group-1")
        }],
        ..Default::default()
    };
    assert_eq!(overall_status(&response), (OverallState::Healthy, Vec::new()));
}

/// A removals list that could not be read is not "no removals": the status carries one row that
/// says so, and the rollup must ask for attention for it like for any other unreadable provider
/// state. An ordinary removal (in progress or done) is not attention.
#[test]
fn an_unreadable_removals_list_is_attention() {
    use yadorilink_ipc_proto::daemonctl::ProviderRemovalStatus;
    let mut response = StatusResponse {
        provider_removals: vec![ProviderRemovalStatus {
            display_name: "Going".into(),
            ..Default::default()
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Healthy, "{reasons:?}");

    response.provider_removals = vec![ProviderRemovalStatus {
        display_name: "removals unreadable: boom".into(),
        unreadable: true,
        ..Default::default()
    }];
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Attention, "{reasons:?}");
    assert!(reasons.iter().any(|r| r == "provider_not_ready:removals"), "{reasons:?}");
}

/// The protection each link reports and the rollup's durability reasons describe the same fact:
/// a confirmed single copy is the rollup's degraded reason, an unconfirmed one its attention
/// reason, and a copy that is protected or on its way is neither.
#[test]
fn the_reported_protection_and_the_rollup_agree() {
    use yadorilink_ipc_proto::daemonctl::GroupDurabilityStatus as Durability;
    use yadorilink_product_view::Protection;

    let cases = [
        (Durability::AtRisk, false, Protection::AtRisk, Some("durability_at_risk:g")),
        (Durability::Unknown, false, Protection::Unknown, Some("durability_unknown:g")),
        (Durability::Unspecified, false, Protection::Unknown, Some("durability_unknown:g")),
        (Durability::Unknown, true, Protection::Pending, None),
        (Durability::Protecting, false, Protection::Pending, None),
        (Durability::Protected, false, Protection::Protected, None),
    ];
    for (durability, check_pending, protection, reason) in cases {
        let mut response = StatusResponse {
            links: vec![LinkStatus {
                durability_status: durability as i32,
                durability_check_pending: check_pending,
                ..protected_link("g")
            }],
            ..Default::default()
        };
        super::status_dimensions::fill_link_dimensions(&mut response);
        let reported =
            yadorilink_product_view::ProtectionSummary::from_link(&response.links[0]).protection;
        assert_eq!(reported, protection, "{durability:?}");
        let (_, reasons) = overall_status(&response);
        assert_eq!(reasons.first().map(String::as_str), reason, "{durability:?}");
    }
}

/// A replacement the service has not confirmed is never healthy, keeps the reasons already
/// reported in front of it, and a daemon with no such record changes nothing.
#[test]
fn an_unconfirmed_replacement_is_attention_with_its_reason_appended() {
    let (mut state, mut reasons) = overall_status(&StatusResponse::default());
    apply_replacement_unconfirmed(false, &mut state, &mut reasons);
    assert_eq!((state, reasons.as_slice()), (OverallState::Healthy, &[][..]));

    let mut reasons = vec!["held:g1".to_owned()];
    let mut state = OverallState::Attention;
    apply_replacement_unconfirmed(true, &mut state, &mut reasons);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, ["held:g1", "replacement_unconfirmed"]);

    let (mut state, mut reasons) = overall_status(&StatusResponse::default());
    apply_replacement_unconfirmed(true, &mut state, &mut reasons);
    assert_eq!((state, reasons), (OverallState::Attention, vec!["replacement_unconfirmed".into()]));
}

/// The sign-in request is one more reason after the others and nothing at all when not needed.
#[test]
fn a_replacement_needing_sign_in_appends_its_reason_last() {
    let mut reasons = vec!["held:g1".to_owned(), "replacement_unconfirmed".to_owned()];
    apply_replacement_sign_in(false, &mut reasons);
    assert_eq!(reasons, ["held:g1", "replacement_unconfirmed"]);
    apply_replacement_sign_in(true, &mut reasons);
    assert_eq!(
        reasons,
        ["held:g1", "replacement_unconfirmed", "replacement_unconfirmed_sign_in_required"]
    );
}

/// The acknowledgement request is one more reason after the others and nothing when not needed.
#[test]
fn a_replacement_awaiting_acknowledgement_appends_its_reason_last() {
    let mut reasons = vec!["replacement_unconfirmed".to_owned()];
    apply_replacement_acknowledgement(false, &mut reasons);
    assert_eq!(reasons, ["replacement_unconfirmed"]);
    apply_replacement_acknowledgement(true, &mut reasons);
    assert_eq!(
        reasons,
        ["replacement_unconfirmed", "replacement_unconfirmed_acknowledgement_required"]
    );
}

/// The wait reason is one more reason after the others, carrying the text, and nothing without one.
#[test]
fn a_replacement_waiting_appends_its_reason_text_last() {
    let mut reasons = vec!["replacement_unconfirmed".to_owned()];
    apply_replacement_waiting(None, &mut reasons);
    assert_eq!(reasons, ["replacement_unconfirmed"]);
    apply_replacement_waiting(Some("g1: not linked on this device".into()), &mut reasons);
    assert_eq!(
        reasons,
        [
            "replacement_unconfirmed",
            "replacement_unconfirmed_waiting:g1: not linked on this device"
        ]
    );
}

/// A request waiting on the owner is attention (never degraded) naming the folder group.
#[test]
fn a_request_waiting_on_the_owner_is_attention_naming_the_group() {
    let response = StatusResponse {
        links: vec![LinkStatus { pending_approvals: 3, ..protected_link("group-1") }],
        ..Default::default()
    };
    assert_eq!(
        overall_status(&response),
        (OverallState::Attention, vec!["approval_pending:group-1".to_owned()])
    );
}

/// What freeing up space would give back is attributed to every entry on the block store's
/// physical volume, summed over the groups; an entry elsewhere (or whose volume is unknown) keeps 0
/// so its low-disk item never offers an action that cannot relieve it.
#[test]
fn reclaimable_bytes_belong_to_entries_on_the_block_store_volume() {
    let volume = |path: &str| VolumeFreeSpace { path: path.to_string(), ..Default::default() };
    let mut volumes =
        vec![volume("<block store>"), volume("/same/a"), volume("/same/b"), volume("/other")];
    let by_group =
        std::collections::HashMap::from([("g1".to_string(), 4096), ("g2".to_string(), 1)]);
    attribute_reclaimable(&mut volumes, &by_group, |p| {
        p == "<block store>" || p.starts_with("/same")
    });
    assert_eq!(volumes[0].reclaimable_bytes, 4097);
    assert_eq!(volumes[1].reclaimable_bytes, 4097);
    assert_eq!(volumes[2].reclaimable_bytes, 4097);
    assert_eq!(volumes[3].reclaimable_bytes, 0);
    // Nothing to give back (not under pressure) leaves every volume at 0.
    let mut none = vec![volume("<block store>")];
    attribute_reclaimable(&mut none, &std::collections::HashMap::new(), |_| true);
    assert_eq!(none[0].reclaimable_bytes, 0);
}
