#![cfg(test)]

use super::*;

fn part(availability: Availability, reachable: &[&str], offline: &[&str]) -> AvailabilitySummary {
    AvailabilitySummary {
        availability,
        reachable_device_ids: reachable.iter().map(|s| s.to_string()).collect(),
        offline_device_ids: offline.iter().map(|s| s.to_string()).collect(),
        update_required_device_ids: Vec::new(),
    }
}

const ALL: [Availability; 5] = [
    Availability::Available,
    Availability::UpdateRequired,
    Availability::WaitingForPeer,
    Availability::WaitingForExactContent,
    Availability::Unknown,
];

#[test]
fn serialized_names_are_pinned() {
    let names: Vec<_> = ALL.iter().map(|a| a.as_str()).collect();
    assert_eq!(
        names,
        [
            "available",
            "update_required",
            "waiting_for_peer",
            "waiting_for_exact_content",
            "unknown"
        ]
    );
}

#[test]
fn every_state_survives_the_wire_and_an_unset_wire_value_is_unknown() {
    for a in ALL {
        assert_eq!(Availability::from_wire(a.to_wire()), a);
    }
    assert_eq!(Availability::from_wire(ProductAvailability::Unspecified), Availability::Unknown);
    assert_eq!(
        AvailabilitySummary::from_link(&LinkStatus::default()).availability,
        Availability::Unknown
    );
}

#[test]
fn aggregation_precedence_is_update_then_content_then_peer_then_unknown_then_available() {
    let order = [
        Availability::UpdateRequired,
        Availability::WaitingForExactContent,
        Availability::WaitingForPeer,
        Availability::Unknown,
        Availability::Available,
    ];
    for (i, strong) in order.iter().enumerate() {
        for weak in &order[i..] {
            for pair in [[*strong, *weak], [*weak, *strong]] {
                let parts = pair.map(|a| part(a, &[], &[]));
                assert_eq!(
                    AvailabilitySummary::aggregate(&parts).availability,
                    *strong,
                    "{pair:?}"
                );
            }
        }
    }
}

#[test]
fn available_only_when_every_part_is_available() {
    let all = [part(Availability::Available, &[], &[]), part(Availability::Available, &[], &[])];
    assert_eq!(AvailabilitySummary::aggregate(&all).availability, Availability::Available);
    let one_unknown =
        [part(Availability::Available, &[], &[]), part(Availability::Unknown, &[], &[])];
    assert_eq!(AvailabilitySummary::aggregate(&one_unknown).availability, Availability::Unknown);
}

#[test]
fn nothing_to_fetch_is_available() {
    assert_eq!(AvailabilitySummary::aggregate(&[]).availability, Availability::Available);
}

#[test]
fn devices_are_unioned_and_offline_for_one_folder_is_offline() {
    let merged = AvailabilitySummary::aggregate(&[
        part(Availability::Available, &["b", "a"], &[]),
        part(Availability::WaitingForPeer, &["c"], &["b"]),
    ]);
    assert_eq!(merged.availability, Availability::WaitingForPeer);
    assert_eq!(merged.reachable_device_ids, ["a", "c"]);
    assert_eq!(merged.offline_device_ids, ["b"]);
}

#[test]
fn a_device_needing_an_update_is_never_counted_reachable_or_offline() {
    let mut a = part(Availability::UpdateRequired, &["a"], &[]);
    a.update_required_device_ids = vec!["old".into()];
    let b = part(Availability::Available, &["old", "b"], &[]);
    let merged = AvailabilitySummary::aggregate(&[a, b]);
    assert_eq!(merged.availability, Availability::UpdateRequired);
    assert_eq!(merged.reachable_device_ids, ["a", "b"]);
    assert_eq!(merged.update_required_device_ids, ["old"]);
}

#[test]
fn a_newer_wire_value_an_older_client_does_not_know_reads_unknown() {
    // prost maps an unknown enum number to the default, which is Unspecified.
    let link = LinkStatus { availability: 99, ..Default::default() };
    assert_eq!(AvailabilitySummary::from_link(&link).availability, Availability::Unknown);
}
