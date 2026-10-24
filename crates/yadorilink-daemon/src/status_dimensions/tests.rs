#![cfg(test)]

use super::*;
use yadorilink_ipc_proto::daemonctl::{DataProtection, ProductAvailability};
use yadorilink_ipc_proto::daemonctl::{
    DurabilityEvidence, FetchAvailability as Fetch, GroupDurabilityStatus as Durability,
    PeerReachability as Reach,
};
use DataProtection as Protection;
use ProductAvailability as Availability;

fn peer(id: &str, reach: Reach) -> PeerStatus {
    PeerStatus { device_id: id.into(), reachability: reach as i32, ..Default::default() }
}

/// A settled folder that this device and one other device hold, custody confirmed.
fn confirmed(holders: &[&str]) -> LinkStatus {
    confirmed_by(holders, holders)
}

/// As `confirmed`, with only `confirming` having answered the custody check.
fn confirmed_by(holders: &[&str], confirming: &[&str]) -> LinkStatus {
    LinkStatus {
        protection_device_ids: confirming.iter().map(|s| s.to_string()).collect(),
        group_id: "g".into(),
        durability_status: Durability::Protected as i32,
        durability_evidence: DurabilityEvidence::CorroboratedIndex as i32,
        fetch_availability: Fetch::AvailableNow as i32,
        full_replica_device_ids: holders.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

struct Avail {
    availability: ProductAvailability,
    reachable_device_ids: Vec<String>,
    offline_device_ids: Vec<String>,
    update_required_device_ids: Vec<String>,
}

struct Prot {
    protection: DataProtection,
    device_ids: Vec<String>,
}

fn dims(link: &LinkStatus, peers: &[PeerStatus]) -> (Avail, Prot) {
    let d = link_dimensions(link, peers);
    (
        Avail {
            availability: d.availability,
            reachable_device_ids: d.reachable_device_ids,
            offline_device_ids: d.offline_device_ids,
            update_required_device_ids: d.update_required_device_ids,
        },
        Prot { protection: d.protection, device_ids: d.protection_device_ids },
    )
}

#[test]
fn only_this_device_holds_the_content_is_at_risk() {
    let link = LinkStatus {
        durability_status: Durability::AtRisk as i32,
        durability_evidence: DurabilityEvidence::None as i32,
        ..confirmed(&[])
    };
    let (_, protection) = dims(&link, &[]);
    assert_eq!(protection.protection, Protection::AtRisk);
    assert!(protection.device_ids.is_empty());
}

#[test]
fn a_confirmed_copy_is_protected_whether_its_device_is_online_or_offline() {
    let link = confirmed(&["mini"]);
    for reach in [Reach::Connected, Reach::Unreachable] {
        let (_, protection) = dims(&link, &[peer("mini", reach)]);
        assert_eq!(protection.protection, Protection::Protected, "{reach:?}");
        assert_eq!(protection.device_ids, ["mini"]);
    }
}

#[test]
fn only_the_device_that_confirmed_is_named_as_protecting() {
    let link = confirmed_by(&["mini", "laptop"], &["mini"]);
    let (_, protection) =
        dims(&link, &[peer("mini", Reach::Connected), peer("laptop", Reach::Connected)]);
    assert_eq!(protection.protection, Protection::Protected);
    assert_eq!(protection.device_ids, ["mini"]);
}

#[test]
fn a_copy_not_yet_confirmed_is_pending_and_names_who_is_awaited() {
    let link = LinkStatus {
        durability_status: Durability::Unknown as i32,
        durability_check_pending: true,
        durability_evidence: DurabilityEvidence::None as i32,
        ..confirmed(&["mini"])
    };
    let (_, protection) = dims(&link, &[peer("mini", Reach::Unreachable)]);
    assert_eq!(protection.protection, Protection::Pending);
    assert_eq!(protection.device_ids, ["mini"]);
}

#[test]
fn this_device_still_catching_up_as_a_full_copy_is_pending_without_a_device() {
    let link =
        LinkStatus { durability_status: Durability::Protecting as i32, ..confirmed(&["mini"]) };
    let (_, protection) = dims(&link, &[peer("mini", Reach::Connected)]);
    assert_eq!(protection.protection, Protection::Pending);
    assert!(protection.device_ids.is_empty());
}

#[test]
fn no_evidence_is_unknown_never_protected() {
    for status in [Durability::Unknown, Durability::Unspecified] {
        let link = LinkStatus { durability_status: status as i32, ..confirmed(&["mini"]) };
        assert_eq!(dims(&link, &[]).1.protection, Protection::Unknown, "{status:?}");
    }
    // A distrusted policy is not evidence even if a stale confirmation says protected.
    let stale = LinkStatus { policy_stale: true, ..confirmed(&["mini"]) };
    assert_eq!(dims(&stale, &[]).1.protection, Protection::Unknown);
}

#[test]
fn content_available_now_is_available_even_when_every_copy_is_offline() {
    let link = confirmed(&["mini"]);
    let (availability, _) = dims(&link, &[peer("mini", Reach::Unreachable)]);
    assert_eq!(availability.availability, Availability::Available);
    assert_eq!(availability.offline_device_ids, ["mini"]);
}

#[test]
fn an_offline_confirmed_copy_is_waiting_for_the_peer_while_still_protected() {
    let link =
        LinkStatus { fetch_availability: Fetch::UnavailableNow as i32, ..confirmed(&["mini"]) };
    let (availability, protection) = dims(&link, &[peer("mini", Reach::Unreachable)]);
    assert_eq!(availability.availability, Availability::WaitingForPeer);
    assert_eq!(availability.offline_device_ids, ["mini"]);
    assert!(availability.reachable_device_ids.is_empty());
    assert_eq!(protection.protection, Protection::Protected);
}

#[test]
fn a_connecting_peer_is_not_yet_usable() {
    let link =
        LinkStatus { fetch_availability: Fetch::UnavailableNow as i32, ..confirmed(&["mini"]) };
    let (availability, _) = dims(&link, &[peer("mini", Reach::Connecting)]);
    assert_eq!(availability.availability, Availability::WaitingForPeer);
}

#[test]
fn a_peer_the_daemon_says_nothing_about_is_not_reachable() {
    let link =
        LinkStatus { fetch_availability: Fetch::UnavailableNow as i32, ..confirmed(&["mini"]) };
    let (availability, _) = dims(&link, &[]);
    assert_eq!(availability.availability, Availability::WaitingForPeer);
    assert_eq!(availability.offline_device_ids, ["mini"]);
}

#[test]
fn a_reachable_copy_that_cannot_serve_the_version_is_waiting_for_exact_content() {
    let link = LinkStatus {
        fetch_availability: Fetch::UnavailableNow as i32,
        ..confirmed(&["mini", "nas"])
    };
    let (availability, _) =
        dims(&link, &[peer("mini", Reach::Connected), peer("nas", Reach::Unreachable)]);
    assert_eq!(availability.availability, Availability::WaitingForExactContent);
    assert_eq!(availability.reachable_device_ids, ["mini"]);
    assert_eq!(availability.offline_device_ids, ["nas"]);
}

#[test]
fn an_offline_device_is_named_only_when_the_group_custody_is_confirmed() {
    // Nothing shows the offline device holds the current version, so it is not named as the one
    // being waited for.
    let link = LinkStatus {
        fetch_availability: Fetch::UnavailableNow as i32,
        durability_status: Durability::Unknown as i32,
        durability_evidence: DurabilityEvidence::None as i32,
        ..confirmed(&["mini"])
    };
    let (availability, _) = dims(&link, &[peer("mini", Reach::Unreachable)]);
    assert_eq!(availability.availability, Availability::WaitingForExactContent);
}

#[test]
fn no_device_holds_a_copy_is_waiting_for_exact_content() {
    let link = LinkStatus { fetch_availability: Fetch::UnavailableNow as i32, ..confirmed(&[]) };
    assert_eq!(dims(&link, &[]).0.availability, Availability::WaitingForExactContent);
}

#[test]
fn unconfirmed_fetch_availability_is_unknown() {
    for fetch in [Fetch::Unknown, Fetch::Unspecified] {
        let link = LinkStatus { fetch_availability: fetch as i32, ..confirmed(&["mini"]) };
        assert_eq!(dims(&link, &[]).0.availability, Availability::Unknown, "{fetch:?}");
    }
}

#[test]
fn the_response_is_filled_link_by_link_and_keeps_its_peers() {
    let mut response = StatusResponse {
        links: vec![
            LinkStatus { fetch_availability: Fetch::UnavailableNow as i32, ..confirmed(&["mini"]) },
            LinkStatus { durability_status: Durability::AtRisk as i32, ..confirmed(&[]) },
        ],
        peers: vec![peer("mini", Reach::Unreachable)],
        ..Default::default()
    };
    fill_link_dimensions(&mut response);
    assert_eq!(response.peers.len(), 1);
    assert_eq!(response.links[0].availability(), Availability::WaitingForPeer);
    assert_eq!(response.links[0].protection(), Protection::Protected);
    assert_eq!(response.links[1].availability(), Availability::Available);
    assert_eq!(response.links[1].protection(), Protection::AtRisk);
}

fn incompatible(id: &str) -> PeerStatus {
    PeerStatus { version_incompatible: true, ..peer(id, Reach::Connected) }
}

fn unavailable(holders: &[&str]) -> LinkStatus {
    LinkStatus { fetch_availability: Fetch::UnavailableNow as i32, ..confirmed(holders) }
}

#[test]
fn an_online_holder_of_another_version_is_update_required_not_reachable() {
    let (a, p) = dims(&unavailable(&["old"]), &[incompatible("old")]);
    assert_eq!(a.availability, Availability::UpdateRequired);
    assert!(a.reachable_device_ids.is_empty() && a.offline_device_ids.is_empty());
    assert_eq!(a.update_required_device_ids, ["old"]);
    // Protection reads custody, not versions or reachability.
    assert_eq!(p.protection, Protection::Protected);
}

#[test]
fn a_compatible_online_holder_keeps_waiting_for_exact_content() {
    let peers = [incompatible("old"), peer("new", Reach::Connected)];
    let (a, _) = dims(&unavailable(&["old", "new"]), &peers);
    assert_eq!(a.availability, Availability::WaitingForExactContent);
    assert_eq!(a.reachable_device_ids, ["new"]);
    assert_eq!(a.update_required_device_ids, ["old"]);
}

#[test]
fn an_incompatible_holder_does_not_hide_that_content_is_available_now() {
    let link = confirmed(&["old"]);
    let (a, _) = dims(&link, &[incompatible("old")]);
    assert_eq!(a.availability, Availability::Available);
}

#[test]
fn an_incompatible_marker_on_an_unreachable_peer_stays_offline() {
    let stale = PeerStatus { version_incompatible: true, ..peer("old", Reach::Unreachable) };
    let (a, _) = dims(&unavailable(&["old"]), &[stale]);
    assert_eq!(a.availability, Availability::WaitingForPeer);
    assert_eq!(a.offline_device_ids, ["old"]);
    assert!(a.update_required_device_ids.is_empty());
}
