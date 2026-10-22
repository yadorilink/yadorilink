#![cfg(test)]

use super::*;

fn member(device_id: &str, online: bool, last_seen_unix: i64) -> DeviceSummary {
    DeviceSummary {
        device_id: device_id.to_string(),
        display_name: format!("device-{device_id}"),
        online,
        last_seen_unix,
        is_caller_account: true,
    }
}

fn link(group_id: &str) -> LinkStatus {
    LinkStatus { group_id: group_id.to_string(), ..Default::default() }
}

#[test]
fn merge_prefers_online_true_and_max_last_seen() {
    let group_one = [member("device-a", false, 100)];
    let group_two = [member("device-a", true, 50)];
    let merged = device_summaries([&group_one[..], &group_two[..]]);
    assert_eq!(merged.len(), 1, "a device in two groups appears once");
    let a = &merged[0];
    assert!(a.online, "online in either group must win");
    assert_eq!(a.last_seen_unix, 100, "max last_seen_unix across groups must win");
    assert_eq!(a.display_name, "device-device-a");
}

#[test]
fn merge_is_sorted_by_device_id() {
    let group = [member("device-c", true, 1), member("device-a", true, 2)];
    let ids: Vec<String> =
        device_summaries([&group[..]]).into_iter().map(|d| d.device_id).collect();
    assert_eq!(ids, vec!["device-a".to_string(), "device-c".to_string()]);
}

#[test]
fn distinct_group_ids_skips_repeats_and_empty_groups_in_first_seen_order() {
    let links = [link("g2"), link(""), link("g1"), link("g2")];
    assert_eq!(distinct_group_ids(&links), vec!["g2".to_string(), "g1".to_string()]);
}

/// Without a registered local device identity, nothing is excluded from the
/// count -- `peer_count` must fail open to "count everyone" rather than
/// silently returning 0 for every group just because identity couldn't be
/// resolved.
#[test]
fn peer_count_counts_everyone_when_own_identity_is_unknown() {
    let members = vec![member("device-a", true, 1), member("device-b", false, 2)];
    assert_eq!(peer_count(&members, None), 2);
}

#[test]
fn peer_count_excludes_this_device() {
    let members = vec![member("device-a", true, 1), member("device-b", false, 2)];
    assert_eq!(peer_count(&members, Some("device-a")), 1);
}

#[test]
fn peer_count_on_an_empty_group_is_zero() {
    assert_eq!(peer_count(&[], None), 0);
}

#[test]
fn peer_counts_keys_each_group_by_id() {
    let g1 = [member("device-a", true, 1), member("device-b", true, 1)];
    let g2 = [member("device-a", true, 1)];
    let counts = peer_counts([("g1", &g1[..]), ("g2", &g2[..])], Some("device-a"));
    assert_eq!(counts.get("g1"), Some(&1));
    assert_eq!(counts.get("g2"), Some(&0));
}

#[test]
fn another_accounts_device_stays_marked_as_not_the_callers() {
    let mut other = member("other", true, 1);
    other.is_caller_account = false;
    let mine = member("mine", true, 1);
    let merged = device_summaries([[other.clone(), mine.clone()].as_slice(), [other].as_slice()]);
    assert!(!merged.iter().find(|d| d.device_id == "other").unwrap().is_caller_account);
    assert!(merged.iter().find(|d| d.device_id == "mine").unwrap().is_caller_account);
}

#[test]
fn only_another_device_of_this_account_holding_a_full_copy_can_be_managed() {
    let holders: HashSet<String> = ["nas".to_string()].into_iter().collect();
    assert!(can_manage_device("nas", false, true, &holders));
    assert!(!can_manage_device("nas", true, true, &holders), "not this device");
    assert!(!can_manage_device("nas", false, false, &holders), "not another account's device");
    assert!(!can_manage_device("laptop", false, true, &holders), "no full copy");
    assert!(!can_manage_device("nas", false, true, &HashSet::new()), "unknown holders fail closed");
}

#[test]
fn full_replica_holders_are_the_union_over_links() {
    let mut a = link("g1");
    a.full_replica_device_ids = vec!["nas".into(), "box".into()];
    let mut b = link("g2");
    b.full_replica_device_ids = vec!["nas".into()];
    let holders = full_replica_holders(&[a, b, link("g3")]);
    assert_eq!(holders.len(), 2);
    assert!(holders.contains("nas") && holders.contains("box"));
}
