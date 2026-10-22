#![cfg(test)]

use super::types::admit_eager_blocks_impl;
use super::HashMap;

#[test]
fn admits_while_under_budget() {
    let mut admission = HashMap::new();
    assert!(admit_eager_blocks_impl(&mut admission, "group-a", 3, 10));
    assert!(admit_eager_blocks_impl(&mut admission, "group-a", 3, 10));
    assert_eq!(*admission.get("group-a").unwrap(), 6);
}

#[test]
fn admits_exactly_up_to_the_ceiling() {
    let mut admission = HashMap::new();
    assert!(admit_eager_blocks_impl(&mut admission, "group-a", 10, 10));
    assert_eq!(*admission.get("group-a").unwrap(), 10);
}

#[test]
fn denies_once_the_ceiling_would_be_exceeded_and_leaves_the_counter_unchanged() {
    let mut admission = HashMap::new();
    assert!(admit_eager_blocks_impl(&mut admission, "group-a", 8, 10));
    // 8 + 5 = 13 > 10: denied, and the counter must stay at 8, not
    // partially advance — a denied admission fetches nothing at all.
    assert!(!admit_eager_blocks_impl(&mut admission, "group-a", 5, 10));
    assert_eq!(*admission.get("group-a").unwrap(), 8);
}

#[test]
fn budget_is_cumulative_across_many_smaller_admissions_from_the_same_peer() {
    // The doc comment's specific concern: a burst of `IndexUpdate`s
    // each individually small must still be bounded in aggregate.
    let mut admission = HashMap::new();
    for _ in 0..10 {
        assert!(admit_eager_blocks_impl(&mut admission, "group-a", 1, 10));
    }
    assert!(!admit_eager_blocks_impl(&mut admission, "group-a", 1, 10));
}

#[test]
fn each_group_has_an_independent_budget() {
    let mut admission = HashMap::new();
    assert!(admit_eager_blocks_impl(&mut admission, "group-a", 10, 10));
    assert!(!admit_eager_blocks_impl(&mut admission, "group-a", 1, 10));
    // group-b's budget is untouched by group-a's exhaustion.
    assert!(admit_eager_blocks_impl(&mut admission, "group-b", 10, 10));
}

#[test]
fn an_oversized_single_request_does_not_overflow_the_counter() {
    // saturating_add guards against a pathological single block_count
    // near u64::MAX wrapping the cumulative counter back into budget.
    let mut admission = HashMap::new();
    assert!(!admit_eager_blocks_impl(&mut admission, "group-a", u64::MAX, 10));
    assert_eq!(*admission.get("group-a").unwrap(), 0);
}
