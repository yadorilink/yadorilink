#![cfg(test)]

use super::*;

#[test]
fn a_second_request_does_not_run_and_is_coalesced_into_one_rerun() {
    let gate = ReconcileGate::default();
    let pass = gate.try_enter("g", ReconcileMode::AddOnly).expect("first request runs");

    assert!(
        gate.try_enter("g", ReconcileMode::AddOnly).is_none(),
        "a second request must never run concurrently -- that is the whole bug"
    );
    assert!(gate.try_enter("g", ReconcileMode::AddOnly).is_none());

    // Three requests, one rerun.
    assert!(gate.take_rerun("g").is_some());
    assert!(gate.take_rerun("g").is_none(), "the coalesced rerun is taken exactly once");
    drop(pass);
}

/// Full must never be downgraded into the add-only rerun of a backstop
/// pass it was coalesced into: that would silently drop the requester's
/// tombstone reconciliation.
#[test]
fn a_coalesced_rerun_takes_the_strongest_mode_requested() {
    let gate = ReconcileGate::default();
    let pass = gate.try_enter("g", ReconcileMode::AddOnly).unwrap();
    gate.try_enter("g", ReconcileMode::AddOnly);
    gate.try_enter("g", ReconcileMode::Full { emit_tombstones: true });
    assert_eq!(gate.take_rerun("g"), Some(ReconcileMode::Full { emit_tombstones: true }));
    drop(pass);
}

/// Two full requesters disagreeing about `emit_tombstones` resolve to
/// the fail-closed answer: the flag asserts this boot can tell a crash
/// apart from a delete, and one requester saying it cannot is enough.
#[test]
fn disagreeing_tombstone_gates_resolve_fail_closed() {
    let gate = ReconcileGate::default();
    let pass = gate.try_enter("g", ReconcileMode::AddOnly).unwrap();
    gate.try_enter("g", ReconcileMode::Full { emit_tombstones: true });
    gate.try_enter("g", ReconcileMode::Full { emit_tombstones: false });
    assert_eq!(gate.take_rerun("g"), Some(ReconcileMode::Full { emit_tombstones: false }));
    drop(pass);
}

#[test]
fn a_finished_pass_frees_the_group_and_leaves_other_groups_alone() {
    let gate = ReconcileGate::default();
    let pass = gate.try_enter("g", ReconcileMode::AddOnly).unwrap();
    assert!(gate.try_enter("other", ReconcileMode::AddOnly).is_some());
    drop(pass);
    assert!(gate.try_enter("g", ReconcileMode::AddOnly).is_some());
}
