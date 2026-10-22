#![cfg(test)]

use super::*;

// --- Netmap diff tests -------------------------------------------

fn snapshot(entries: &[(&str, &[&str])]) -> NetmapSnapshot {
    entries
        .iter()
        .map(|(device_id, groups)| {
            (device_id.to_string(), groups.iter().map(|g| g.to_string()).collect())
        })
        .collect()
}

/// A device that disappears from the netmap entirely
/// (whole-device revocation) is classified as a removed device, not a
/// removed group edge — the diff must key off device presence in
/// `current`, not just group-set difference.
#[test]
fn device_absent_from_current_netmap_is_classified_as_removed_device() {
    let previous = snapshot(&[("device-a", &["group-1", "group-2"]), ("device-b", &["group-1"])]);
    let current = snapshot(&[("device-b", &["group-1"])]);

    let diff = diff_netmap(&previous, &current);

    assert_eq!(diff.removed_devices, vec!["device-a".to_string()]);
    assert!(
        diff.removed_group_edges.is_empty(),
        "a wholly-removed device must not also be reported as a group-edge removal: {:?}",
        diff.removed_group_edges
    );
}

/// A device still present but with fewer shared groups is a group-edge
/// removal (the tunnel is meant to stay up), not a device removal.
#[test]
fn device_present_with_fewer_groups_is_classified_as_removed_group_edge() {
    let previous = snapshot(&[("device-a", &["group-1", "group-2"])]);
    let current = snapshot(&[("device-a", &["group-1"])]);

    let diff = diff_netmap(&previous, &current);

    assert!(
        diff.removed_devices.is_empty(),
        "a device that still shares another group must not be torn down: {:?}",
        diff.removed_devices
    );
    assert_eq!(diff.removed_group_edges, vec![("device-a".to_string(), "group-2".to_string())]);
}

/// A snapshot with no changes at all (including a peer's group list
/// merely coming back in a different order, since `NetmapSnapshot`
/// values are `HashSet`s) produces an empty diff.
#[test]
fn unchanged_netmap_produces_no_diff() {
    let previous = snapshot(&[("device-a", &["group-1", "group-2"])]);
    let current = snapshot(&[("device-a", &["group-2", "group-1"])]);

    let diff = diff_netmap(&previous, &current);

    assert!(diff.removed_devices.is_empty());
    assert!(diff.removed_group_edges.is_empty());
}

/// A brand-new peer (present in `current`, absent from `previous`) is
/// an addition, not a removal — `diff_netmap` only ever reports what
/// disappeared.
#[test]
fn newly_added_peer_produces_no_diff_entries() {
    let previous = snapshot(&[]);
    let current = snapshot(&[("device-a", &["group-1"])]);

    let diff = diff_netmap(&previous, &current);

    assert!(diff.removed_devices.is_empty());
    assert!(diff.removed_group_edges.is_empty());
}

/// A single netmap update can carry both kinds of removal at once —
/// both must be classified correctly in the same diff.
#[test]
fn mixed_update_classifies_each_device_independently() {
    let previous = snapshot(&[
        ("device-a", &["group-1"]),            // fully removed below
        ("device-b", &["group-1", "group-2"]), // loses group-2 only
        ("device-c", &["group-1"]),            // unchanged
    ]);
    let current = snapshot(&[("device-b", &["group-1"]), ("device-c", &["group-1"])]);

    let diff = diff_netmap(&previous, &current);

    assert_eq!(diff.removed_devices, vec!["device-a".to_string()]);
    assert_eq!(diff.removed_group_edges, vec![("device-b".to_string(), "group-2".to_string())]);
}
