#![cfg(test)]

use super::*;

#[test]
fn mark_then_pending_reports_the_group() {
    let wake = GroupWake::new();
    wake.mark_dirty("g1");
    let pending = wake.pending();
    assert_eq!(pending.get("g1"), Some(&1));
}

#[test]
fn repeated_marks_before_claim_coalesce_but_still_advance_requested() {
    let wake = GroupWake::new();
    wake.mark_dirty("g1");
    wake.mark_dirty("g1");
    wake.mark_dirty("g1");
    // Coalesced into one pending entry, but the target generation
    // reflects every mark that landed, not just the first.
    assert_eq!(wake.pending().len(), 1);
    assert_eq!(wake.pending().get("g1"), Some(&3));
}

#[test]
fn complete_at_claimed_generation_clears_pending() {
    let wake = GroupWake::new();
    wake.mark_dirty("g1");
    let generation = *wake.pending().get("g1").unwrap();
    wake.complete("g1", generation);
    assert!(wake.pending().is_empty());
}

#[test]
fn mark_during_claimed_pass_stays_pending_after_stale_complete() {
    let wake = GroupWake::new();
    wake.mark_dirty("g1");
    let claimed_generation = *wake.pending().get("g1").unwrap();
    // A new event lands while the pass claiming `claimed_generation`
    // is still running.
    wake.mark_dirty("g1");
    // The in-flight pass finishes and reports success for the
    // generation it actually claimed -- not the new one.
    wake.complete("g1", claimed_generation);
    // Exactly one follow-up audit's worth of pending work remains.
    let pending = wake.pending();
    assert_eq!(pending.get("g1"), Some(&(claimed_generation + 1)));
}

#[test]
fn busy_pass_that_never_completes_leaves_group_pending() {
    let wake = GroupWake::new();
    wake.mark_dirty("g1");
    let _claimed_generation = *wake.pending().get("g1").unwrap();
    // Guard contention / transient error / retry-required: the pass
    // never calls `complete` at all.
    assert_eq!(wake.pending().get("g1"), Some(&1));
}

#[test]
fn out_of_order_complete_never_regresses_completed() {
    let wake = GroupWake::new();
    wake.mark_dirty("g1");
    wake.mark_dirty("g1");
    // A late pass for generation 1 reports success after a pass for
    // generation 2 already completed.
    wake.complete("g1", 2);
    wake.complete("g1", 1);
    assert!(wake.pending().is_empty());
}

#[test]
fn success_with_no_new_event_is_clean() {
    let wake = GroupWake::new();
    wake.mark_dirty("g1");
    wake.mark_dirty("g2");
    let g1_generation = *wake.pending().get("g1").unwrap();
    wake.complete("g1", g1_generation);
    let pending = wake.pending();
    assert!(!pending.contains_key("g1"));
    assert!(pending.contains_key("g2"));
}

#[test]
fn complete_for_unknown_group_is_a_harmless_no_op() {
    let wake = GroupWake::new();
    wake.complete("never-marked", 1);
    assert!(wake.pending().is_empty());
}
