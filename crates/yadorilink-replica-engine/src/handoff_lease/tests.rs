#![cfg(test)]

use super::*;

#[test]
fn a_positive_ttl_yields_created_at_plus_ttl_plus_the_safety_margin() {
    let deadline = compute_pin_deadline(1_000, 900).unwrap();
    assert_eq!(deadline, 1_000 + 900 + HANDOFF_LEASE_PIN_SAFETY_MARGIN_SECS);
}

#[test]
fn a_zero_ttl_is_rejected_and_produces_no_deadline() {
    let err = compute_pin_deadline(1_000, 0).unwrap_err();
    assert!(matches!(err, ReplicaEngineError::InvalidInput(_)));
}

#[test]
fn a_negative_ttl_is_rejected_and_produces_no_deadline() {
    let err = compute_pin_deadline(1_000, -1).unwrap_err();
    assert!(matches!(err, ReplicaEngineError::InvalidInput(_)));
}

#[test]
fn the_deadline_computation_saturates_rather_than_overflowing_on_extreme_inputs() {
    let deadline = compute_pin_deadline(i64::MAX, i64::MAX).unwrap();
    assert_eq!(deadline, i64::MAX);
}
