#![cfg(test)]

use super::*;
use yadorilink_ipc_proto::daemonctl::DegradedCause as Cause;
use yadorilink_ipc_proto::daemonctl::ProductStatus;

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
fn an_unconfirmed_copy_is_never_a_reason_before_or_after_a_check() {
    let unknown = LinkStatus {
        durability_status: yadorilink_ipc_proto::daemonctl::GroupDurabilityStatus::Unknown as i32,
        ..protected_link("group-1")
    };
    for pending in [true, false] {
        let response = StatusResponse {
            links: vec![LinkStatus { durability_check_pending: pending, ..unknown.clone() }],
            ..Default::default()
        };
        let (state, reasons) = overall_status(&response);
        assert_eq!(state, OverallState::Healthy, "pending={pending}");
        assert!(reasons.is_empty(), "{reasons:?}");
    }
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
            full_replica_device_ids: vec!["other".into()],
            ..protected_link("group-1")
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Degraded);
    assert_eq!(reasons, vec!["durability_at_risk:group-1".to_string()]);
}

/// A link whose durability cannot currently be confirmed (`Unknown`, or `Unspecified` from an
/// unset value) is not a reason: the protection line says "Not confirmed yet", and it is never
/// shown as protected.
#[test]
fn unknown_durability_is_the_protection_line_not_a_reason() {
    for status in [
        yadorilink_ipc_proto::daemonctl::GroupDurabilityStatus::Unknown,
        yadorilink_ipc_proto::daemonctl::GroupDurabilityStatus::Unspecified,
    ] {
        let mut response = StatusResponse {
            links: vec![LinkStatus {
                durability_status: status as i32,
                ..protected_link("group-1")
            }],
            ..Default::default()
        };
        let (state, reasons) = overall_status(&response);
        assert_eq!(state, OverallState::Healthy);
        assert!(reasons.is_empty(), "{reasons:?}");
        crate::status_dimensions::fill_link_dimensions(&mut response);
        assert_eq!(
            yadorilink_product_view::ProtectionSummary::from_link(&response.links[0]).protection,
            yadorilink_product_view::Protection::Unknown
        );
    }
}

/// A link that is durably `Protected` but cannot currently be fetched
/// is `Attention` -- "fetch not confirmed" is real and actionable,
/// but must never escalate to `Degraded`: the data itself is not at
/// risk, matching "Durability != Connectivity."
#[test]
fn unavailable_fetch_with_protected_durability_is_a_wait_not_a_reason() {
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
    assert_eq!(overall_status(&response), (OverallState::Healthy, Vec::new()));
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
fn unknown_fetch_availability_with_protected_durability_is_a_wait_not_a_reason() {
    let response = StatusResponse {
        links: vec![LinkStatus {
            fetch_availability: yadorilink_ipc_proto::daemonctl::FetchAvailability::Unknown as i32,
            hydrating_count: 1,
            requested_content_count: 1,
            ..protected_link("group-1")
        }],
        ..Default::default()
    };
    assert_eq!(overall_status(&response), (OverallState::Healthy, Vec::new()));
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

/// A peer that cannot be connected is a device that is away, at any duration: availability
/// (with when it was last seen), never attention.
#[test]
fn an_unreachable_peer_is_never_a_reason() {
    let response = StatusResponse {
        peers: vec![PeerStatus {
            device_id: "device-b".into(),
            reachability: yadorilink_ipc_proto::daemonctl::PeerReachability::Unreachable as i32,
            ..Default::default()
        }],
        ..Default::default()
    };
    assert_eq!(overall_status(&response), (OverallState::Healthy, Vec::new()));
}

/// A peer that is reachable but on another version is "update required", never "offline", and
/// the reason names which side updates: a newer peer means this device, an older one that peer.
/// A genuinely unreachable peer next to them is still offline.
#[test]
fn version_mismatched_peer_names_the_side_to_update_never_offline() {
    use yadorilink_ipc_proto::daemonctl::{PeerReachability, VersionSkew};
    let connected = |id: &str, skew: VersionSkew| PeerStatus {
        device_id: id.into(),
        reachability: PeerReachability::Connected as i32,
        version_skew: skew as i32,
        ..Default::default()
    };
    let response = StatusResponse {
        peers: vec![
            connected("device-newer", VersionSkew::PeerNewer),
            connected("device-older", VersionSkew::PeerOlder),
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
            "peer_newer:device-newer".to_string(),
            "peer_update_required:device-older".to_string()
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

/// The disk-space wait is its own rollup code from the typed flag, whatever the detail text says,
/// and it does not make the folder a stopped one. Text alone never sets it.
#[test]
fn waiting_for_disk_space_is_keyed_by_the_flag_not_the_reason_text() {
    let waiting = LinkStatus {
        degraded: true,
        degraded_cause: Cause::WaitingForDiskSpace as i32,
        degraded_reason: "any wording at all".into(),
        ..protected_link("group-1")
    };
    let (state, reasons) =
        overall_status(&StatusResponse { links: vec![waiting], ..Default::default() });
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["waiting_for_disk_space:group-1".to_string()]);

    let lookalike = LinkStatus {
        degraded: true,
        degraded_reason: "Waiting for disk space on /v".into(),
        ..protected_link("group-1")
    };
    let (state, reasons) =
        overall_status(&StatusResponse { links: vec![lookalike], ..Default::default() });
    assert_eq!(state, OverallState::Degraded);
    assert_eq!(reasons, vec!["degraded:group-1".to_string()]);
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

/// A link whose sync-root lock sidecar is gone reports `folder_needs_relink`.
#[test]
fn an_ownership_lost_link_reports_its_own_reason() {
    let response = StatusResponse {
        links: vec![LinkStatus {
            degraded: true,
            degraded_cause: Cause::OwnershipLost as i32,
            degraded_reason: "any wording at all".into(),
            ..protected_link("group-1")
        }],
        ..Default::default()
    };
    let (state, reasons) = overall_status(&response);
    assert_eq!(state, OverallState::Degraded);
    assert_eq!(reasons, vec!["folder_needs_relink:group-1".to_string()]);
}

/// Every typed cause has its own rollup code, whatever the detail text says, and the text alone
/// never picks one: the old exact-text constants no longer decide anything.
#[test]
fn every_degraded_cause_has_its_own_rollup_code_and_text_never_picks_one() {
    for (cause, code) in [
        (Cause::FileWatchLimit, "file_watch_limit"),
        (Cause::OwnershipLost, "folder_needs_relink"),
        (Cause::NotJoined, "folder_needs_relink"),
        (Cause::Unspecified, "degraded"),
    ] {
        let link = LinkStatus {
            degraded: true,
            degraded_cause: cause as i32,
            degraded_reason: "any wording at all".into(),
            ..protected_link("group-1")
        };
        let (state, reasons) =
            overall_status(&StatusResponse { links: vec![link], ..Default::default() });
        assert_eq!(state, OverallState::Degraded, "{code}");
        assert_eq!(reasons, vec![format!("{code}:group-1")]);
    }
    for text in [
        crate::link_registry::OWNERSHIP_LOST_REASON,
        crate::link_registry::NOT_JOINED_REASON,
        "OS file watch limit reached; this folder is not syncing.",
    ] {
        let link = LinkStatus {
            degraded: true,
            degraded_reason: text.into(),
            ..protected_link("group-1")
        };
        let (_, reasons) =
            overall_status(&StatusResponse { links: vec![link], ..Default::default() });
        assert_eq!(reasons, vec!["degraded:group-1".to_string()], "{text}");
    }
}

/// The daemon's rollup and the canonical product summary must not disagree about whether a
/// folder needs the user. Every per-link attention condition here is `NeedsAttention` in both;
/// a healthy link is neither. Fetch availability is a wait in both: the summary calls it
/// `Waiting` (never `UpToDate`) while content is wanted and the rollup raises nothing; an idle
/// On-Demand folder is healthy / up to date in both.
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
                full_replica_device_ids: vec!["other".into()],
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
        assert_eq!(overall_status(&response).0, OverallState::Healthy);
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
/// hydrating yet: unavailable fetching is a wait (product state Waiting), not a reason.
#[test]
fn a_queued_open_with_unavailable_fetch_is_a_wait() {
    use yadorilink_ipc_proto::daemonctl::{FetchAvailability, LocalStorageState};
    use yadorilink_product_view::summary::{ProductState, ProductStatusSummary};
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
    assert_eq!(overall_status(&response), (OverallState::Healthy, Vec::new()));
    assert_eq!(ProductStatusSummary::for_folder(&response.links[0]).state, ProductState::Waiting);
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
        (Durability::AtRisk, false, Protection::AtRisk, None),
        (Durability::Unknown, false, Protection::Unknown, None),
        (Durability::Unspecified, false, Protection::Unknown, None),
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
        crate::status_dimensions::fill_link_dimensions(&mut response);
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
    apply_replacement_unconfirmed(false, true, true, None, &mut state, &mut reasons);
    assert_eq!((state, reasons.as_slice()), (OverallState::Healthy, &[][..]));

    let mut reasons = vec!["held:g1".to_owned()];
    let mut state = OverallState::Attention;
    apply_replacement_unconfirmed(true, false, false, None, &mut state, &mut reasons);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, ["held:g1", "replacement_unconfirmed"]);

    let (mut state, mut reasons) = overall_status(&StatusResponse::default());
    apply_replacement_unconfirmed(true, false, false, None, &mut state, &mut reasons);
    assert_eq!((state, reasons), (OverallState::Attention, vec!["replacement_unconfirmed".into()]));
}

/// One reason, one step: what the person has to do outranks a wait, a wait outranks the plain
/// "not confirmed yet".
#[test]
fn a_replacement_reports_one_step_by_priority() {
    let step = |sign_in, acknowledge, waiting: Option<&str>| {
        let (mut state, mut reasons) = overall_status(&StatusResponse::default());
        apply_replacement_unconfirmed(
            true,
            sign_in,
            acknowledge,
            waiting.map(str::to_owned),
            &mut state,
            &mut reasons,
        );
        reasons
    };
    assert_eq!(step(true, true, Some("w")), ["replacement_unconfirmed:acknowledge"]);
    assert_eq!(step(true, false, Some("w")), ["replacement_unconfirmed:sign_in"]);
    assert_eq!(
        step(false, false, Some("g1: not linked on this device")),
        ["replacement_unconfirmed:waiting:g1: not linked on this device"]
    );
    assert_eq!(step(false, false, None), ["replacement_unconfirmed"]);
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

/// An account scheduled for deletion is a reason (never healthy meanwhile), `urgent` under its own
/// key, nothing when none is pending, and both keys are the ones the product view reads back.
#[test]
fn a_pending_account_deletion_adds_its_key_and_is_never_healthy() {
    use crate::daemon_state::AccountDeletionState;
    let (mut state, mut reasons) = overall_status(&StatusResponse::default());
    apply_account_deletion(AccountDeletionState::None, &mut state, &mut reasons);
    assert_eq!((state, reasons.clone()), (OverallState::Healthy, vec![]));

    apply_account_deletion(AccountDeletionState::Pending, &mut state, &mut reasons);
    assert_eq!(
        (state, reasons.clone()),
        (OverallState::Attention, vec!["account_deletion_pending".to_owned()])
    );

    let mut reasons = vec![];
    let mut state = OverallState::Degraded;
    apply_account_deletion(AccountDeletionState::Urgent, &mut state, &mut reasons);
    assert_eq!(
        (state, reasons),
        (OverallState::Degraded, vec!["account_deletion_urgent".to_owned()])
    );
    for key in ["account_deletion_requested", "account_deletion_pending", "account_deletion_urgent"]
    {
        let item = yadorilink_product_view::Attention::from_reason(key).item;
        assert_eq!(item.key(), key, "the daemon's key and the product view's key agree");
    }
}

/// The coordination block is a first-class reason (never healthy meanwhile), keyed exactly as the
/// product view reads it back, and nothing at all when there is no block.
#[test]
fn a_coordination_block_adds_its_key_first_and_is_never_healthy() {
    use yadorilink_fapi_client::CoordinationBlock;
    let (mut state, mut reasons) = overall_status(&StatusResponse::default());
    apply_coordination_block(None, &mut state, &mut reasons);
    assert_eq!((state, reasons.clone()), (OverallState::Healthy, vec![]));

    let consent = CoordinationBlock::TermsConsentRequired { terms_version: Some("v".into()) };
    apply_coordination_block(Some(&consent), &mut state, &mut reasons);
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, ["terms_consent_required"]);

    let mut reasons = vec!["held:g1".to_owned()];
    let mut state = OverallState::Degraded;
    apply_coordination_block(Some(&CoordinationBlock::SignInRequired), &mut state, &mut reasons);
    assert_eq!(state, OverallState::Degraded, "a worse state is not softened");
    assert_eq!(reasons, ["sign_in_required", "held:g1"]);
    for key in ["terms_consent_required", "sign_in_required"] {
        let item = yadorilink_product_view::Attention::from_reason(key).item;
        assert_eq!(item.key(), key, "the daemon's key and the product view's key agree");
    }
}

/// A folder only this device holds is at risk in the protection dimension and healthy in the
/// rollup, in the daemon and in the product view alike: it is a configuration, not a fault. The
/// daemon's predicate is the product view's.
#[test]
fn a_folder_only_this_device_holds_is_healthy_in_the_rollup_and_the_product_view() {
    use yadorilink_product_view::summary::{ProductState, ProductStatusSummary};

    let alone = LinkStatus {
        durability_status: yadorilink_ipc_proto::daemonctl::GroupDurabilityStatus::AtRisk as i32,
        ..protected_link("g")
    };
    assert!(yadorilink_product_view::protection::is_single_copy(&alone));
    let (state, reasons) =
        overall_status(&StatusResponse { links: vec![alone.clone()], ..Default::default() });
    assert_eq!(state, OverallState::Healthy);
    assert!(reasons.is_empty(), "{reasons:?}");
    assert_eq!(ProductStatusSummary::for_folder(&alone).state, ProductState::UpToDate);

    let with_peer = LinkStatus { full_replica_device_ids: vec!["other".into()], ..alone };
    assert!(!yadorilink_product_view::protection::is_single_copy(&with_peer));
    let (state, _) =
        overall_status(&StatusResponse { links: vec![with_peer], ..Default::default() });
    assert_eq!(state, OverallState::Degraded);
}

/// A device whose own history can no longer catch up reports it itself, as attention, in the
/// rollup and in the product state.
#[test]
fn a_device_that_needs_a_rebuild_says_so_itself() {
    use yadorilink_product_view::summary::{ProductState, ProductStatusSummary};

    let link = LinkStatus { rebuild_needed: true, ..protected_link("g") };
    let (state, reasons) =
        overall_status(&StatusResponse { links: vec![link.clone()], ..Default::default() });
    assert_eq!(state, OverallState::Attention);
    assert_eq!(reasons, vec!["rebuild_needed:g".to_string()]);
    assert_eq!(ProductStatusSummary::for_folder(&link).state, ProductState::NeedsAttention);
}

/// The reply carries the product status the daemon computed: each folder's own, and the device's,
/// which also counts the reasons that belong to no folder. This is the one place the five-state
/// precedence is decided; readers map the message and do not derive it again.
#[test]
fn the_reply_carries_the_product_status_for_every_folder_and_for_the_device() {
    use yadorilink_ipc_proto::daemonctl::product_status::{Action, State};

    let conflicted = LinkStatus { conflict_count: 1, ..protected_link("g1") };
    let paused = LinkStatus { paused: true, ..protected_link("g2") };
    let idle = protected_link("g3");
    let mut response = StatusResponse {
        links: vec![conflicted, paused, idle],
        attention_reasons: vec!["update_required".into()],
        ..Default::default()
    };
    yadorilink_product_view::wire::fill_product_status(&mut response);

    let folder = |i: usize| response.links[i].product.clone().expect("every folder has a status");
    assert_eq!(folder(0).state(), State::NeedsAttention);
    assert_eq!(folder(0).next_action(), Action::ReviewConflict);
    assert_eq!(folder(1).state(), State::Paused);
    assert_eq!(folder(1).next_action(), Action::Resume);
    assert_eq!(folder(2).state(), State::UpToDate);
    assert_eq!(folder(2).next_action(), Action::None);

    let device = response.product.clone().expect("the device has a status");
    assert_eq!(device.state(), State::NeedsAttention);
    // One folder, plus the update that belongs to no folder.
    assert_eq!(device.attention_count, 2);
    assert_eq!(device.paused_count, 1);
}

/// With nothing wrong a device reads up to date, and the rollup agrees.
#[test]
fn an_idle_reply_is_up_to_date_in_the_product_status_and_healthy_in_the_rollup() {
    use yadorilink_ipc_proto::daemonctl::product_status::State;

    let mut response = StatusResponse { links: vec![protected_link("g")], ..Default::default() };
    yadorilink_product_view::wire::fill_product_status(&mut response);
    assert_eq!(response.product.clone().expect("a status").state(), State::UpToDate);
    assert_eq!(overall_status(&response).0, OverallState::Healthy);
}

/// Conflicts in the folder and conflicts still being resolved are one reason, and a recent failure
/// that another reason already explains is not a second one.
#[test]
fn reasons_are_folded_one_per_cause() {
    let both = LinkStatus { conflict_count: 1, conflicts_pending: 2, ..protected_link("g") };
    let (_, reasons) = overall_status(&StatusResponse { links: vec![both], ..Default::default() });
    assert_eq!(reasons, vec!["conflict:g".to_string()]);

    let disk_error = |category: &str| yadorilink_ipc_proto::daemonctl::RecentSyncError {
        category: category.into(),
        ..Default::default()
    };
    let waiting = LinkStatus {
        degraded: true,
        degraded_cause: yadorilink_ipc_proto::daemonctl::DegradedCause::WaitingForDiskSpace as i32,
        ..protected_link("g")
    };
    let (_, reasons) = overall_status(&StatusResponse {
        links: vec![waiting],
        recent_errors: vec![disk_error("disk_pressure"), disk_error("storage")],
        ..Default::default()
    });
    assert_eq!(
        reasons,
        vec!["waiting_for_disk_space:g".to_string(), "recent_error:storage".to_string()],
        "the disk failure is explained by the wait; an unrelated one still shows"
    );

    let (_, alone) = overall_status(&StatusResponse {
        recent_errors: vec![disk_error("disk_pressure")],
        ..Default::default()
    });
    assert_eq!(alone, vec!["recent_error:disk_pressure".to_string()], "nothing explains it");
}

fn product_in(
    state: yadorilink_ipc_proto::daemonctl::product_status::State,
) -> Option<ProductStatus> {
    Some(ProductStatus { state: state as i32, ..Default::default() })
}

fn reply(state: yadorilink_ipc_proto::daemonctl::product_status::State) -> StatusResponse {
    use yadorilink_ipc_proto::daemonctl::product_status::State;
    let mut link = protected_link("g");
    link.local_path = "/a".to_owned();
    link.product = product_in(state);
    StatusResponse {
        links: vec![link],
        product: product_in(if state == State::UpToDate { State::UpToDate } else { state }),
        ..Default::default()
    }
}

#[test]
fn last_synced_is_stamped_while_up_to_date_and_kept_after() {
    use yadorilink_ipc_proto::daemonctl::product_status::State;
    let clock = LastSynced::default();

    let mut first = reply(State::Syncing);
    clock.stamp(&mut first, 100, false);
    assert_eq!(first.links[0].product.as_ref().unwrap().last_synced_unix, None);

    let mut up = reply(State::UpToDate);
    clock.stamp(&mut up, 200, false);
    assert_eq!(up.links[0].product.as_ref().unwrap().last_synced_unix, Some(200));
    assert_eq!(up.product.as_ref().unwrap().last_synced_unix, Some(200));

    let mut later = reply(State::Syncing);
    clock.stamp(&mut later, 300, false);
    assert_eq!(later.links[0].product.as_ref().unwrap().last_synced_unix, Some(200));
}

#[test]
fn a_stale_reply_does_not_claim_a_sync_and_a_removed_folder_is_forgotten() {
    use yadorilink_ipc_proto::daemonctl::product_status::State;
    let clock = LastSynced::default();
    let mut stale = reply(State::UpToDate);
    clock.stamp(&mut stale, 100, true);
    assert_eq!(stale.links[0].product.as_ref().unwrap().last_synced_unix, None);

    let mut up = reply(State::UpToDate);
    clock.stamp(&mut up, 200, false);
    let mut gone = StatusResponse::default();
    clock.stamp(&mut gone, 210, false);
    let mut back = reply(State::Syncing);
    clock.stamp(&mut back, 220, false);
    assert_eq!(back.links[0].product.as_ref().unwrap().last_synced_unix, None);
}
