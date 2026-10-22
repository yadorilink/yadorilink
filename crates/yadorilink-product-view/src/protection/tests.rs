#![cfg(test)]

use super::*;

fn part(protection: Protection, devices: &[&str]) -> ProtectionSummary {
    ProtectionSummary { protection, device_ids: devices.iter().map(|s| s.to_string()).collect() }
}

const ALL: [Protection; 4] =
    [Protection::Protected, Protection::AtRisk, Protection::Pending, Protection::Unknown];

fn fold(states: &[Protection]) -> Protection {
    let parts: Vec<_> = states.iter().map(|p| part(*p, &[])).collect();
    ProtectionSummary::aggregate(&parts).protection
}

#[test]
fn serialized_names_are_pinned() {
    let names: Vec<_> = ALL.iter().map(|p| p.as_str()).collect();
    assert_eq!(names, ["protected", "at_risk", "pending", "unknown"]);
}

#[test]
fn unavailable_is_never_a_protection_state() {
    // The closed set has no availability-flavoured member; a name that says so is a regression.
    for p in ALL {
        assert!(!p.as_str().contains("unavailable"), "{p:?}");
        assert!(!p.as_str().contains("waiting"), "{p:?}");
    }
}

#[test]
fn every_state_survives_the_wire_and_an_unset_wire_value_is_unknown() {
    for p in ALL {
        assert_eq!(Protection::from_wire(p.to_wire()), p);
    }
    assert_eq!(Protection::from_wire(DataProtection::Unspecified), Protection::Unknown);
    assert_eq!(
        ProtectionSummary::from_link(&LinkStatus::default()).protection,
        Protection::Unknown
    );
}

#[test]
fn aggregation_precedence_is_at_risk_then_pending_then_unknown_then_protected() {
    let order =
        [Protection::AtRisk, Protection::Pending, Protection::Unknown, Protection::Protected];
    for (i, strong) in order.iter().enumerate() {
        for weak in &order[i..] {
            assert_eq!(fold(&[*strong, *weak]), *strong);
            assert_eq!(fold(&[*weak, *strong]), *strong);
        }
    }
}

#[test]
fn unknown_never_aggregates_to_protected() {
    assert_eq!(fold(&[Protection::Protected, Protection::Unknown]), Protection::Unknown);
    assert_eq!(fold(&[Protection::Unknown, Protection::Unknown]), Protection::Unknown);
    assert_eq!(fold(&[Protection::Protected, Protection::Protected]), Protection::Protected);
}

#[test]
fn a_set_with_no_folders_is_unknown_not_protected() {
    assert_eq!(ProtectionSummary::aggregate(&[]).protection, Protection::Unknown);
}

#[test]
fn only_the_deciding_parts_contribute_devices() {
    let protected = ProtectionSummary::aggregate(&[
        part(Protection::Protected, &["b"]),
        part(Protection::Protected, &["a", "b"]),
    ]);
    assert_eq!(protected.device_ids, ["a", "b"]);

    let pending = ProtectionSummary::aggregate(&[
        part(Protection::Protected, &["a"]),
        part(Protection::Pending, &["m"]),
    ]);
    assert_eq!(
        (pending.protection, pending.device_ids),
        (Protection::Pending, vec!["m".to_string()])
    );

    let at_risk = ProtectionSummary::aggregate(&[
        part(Protection::Protected, &["a"]),
        part(Protection::AtRisk, &[]),
    ]);
    assert!(at_risk.device_ids.is_empty());
}
