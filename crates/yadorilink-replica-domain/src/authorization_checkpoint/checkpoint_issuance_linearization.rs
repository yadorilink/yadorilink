#![cfg(test)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Editor,
    Viewer,
}

struct AuthorityState {
    role: Role,
}

/// The UNSAFE shape: read current role, THEN (later, possibly after
/// an interleaved revoke) write the checkpoint -- exactly what
/// `await`-ing a read and a write as two separate steps against a
/// database gives you if nothing pins them to one atomic operation.
/// `inject_revoke_between_read_and_write` simulates a revoke request
/// landing in the gap between this function's read and its write --
/// the TOCTOU window.
fn issue_checkpoint_naive(
    state: &mut AuthorityState,
    inject_revoke_between_read_and_write: impl FnOnce(&mut AuthorityState),
) -> bool {
    let role_at_read = state.role; // T1: SELECT current_role
    inject_revoke_between_read_and_write(state); // T2 (if any): COMMIT revoke, interleaved
    let currently_writer_as_of_the_stale_read = role_at_read == Role::Editor;
    if currently_writer_as_of_the_stale_read {
        // T1 (continued): sign(root) -- decided using a role reading
        // that may already be stale by the time this executes.
        true // checkpoint issued
    } else {
        false
    }
}

/// The REQUIRED shape: the writer check and the "commit to issuing"
/// decision happen as a single, uninterruptible step -- no callback
/// hook exists between them for a concurrent revoke to land in,
/// because there is no gap. This models what a real implementation
/// must achieve via a single atomic SQL statement (e.g. `INSERT ...
/// SELECT ... WHERE <current role is Editor>`, or an equivalent
/// compare-and-swap against the same row `Revoke` also writes) rather
/// than an app-level read followed by a separate write.
fn issue_checkpoint_atomic(state: &AuthorityState) -> bool {
    state.role == Role::Editor
}

fn revoke(state: &mut AuthorityState) {
    state.role = Role::Viewer;
}

#[test]
fn a_naive_read_then_write_issuance_can_issue_a_checkpoint_for_an_already_revoked_device() {
    // Timeline:
    //   T1 checkpoint: SELECT current_role -> editor
    //   T2 revoke:     COMMIT revoke
    //   T1 checkpoint: sign(root)
    // This is the bug being pinned, not a property to preserve: it
    // demonstrates that a plain "read role, then separately act on
    // it" issuance protocol violates the required XOR contract.
    let mut state = AuthorityState { role: Role::Editor };
    let issued = issue_checkpoint_naive(&mut state, revoke);
    assert!(
        issued,
        "pinning the hazard: the naive protocol issues a checkpoint using a stale pre-revoke read"
    );
    assert_eq!(state.role, Role::Viewer, "the revoke DID commit before issuance completed");
    // issued == true AND role == Viewer simultaneously is exactly the
    // forbidden state the linearization contract rules out: CheckpointIssue
    // succeeded even though Revoke precedes its actual completion.
}

#[test]
fn an_atomic_check_and_decide_issuance_never_issues_across_an_interleaved_revoke() {
    // Same timeline, but modeled with no gap between the read and
    // the decision for a revoke to land in -- because there is only
    // one step. A revoke that completes before this call sees
    // Viewer; a revoke that would complete after it has no earlier
    // opportunity to interleave, by construction.
    let mut state = AuthorityState { role: Role::Editor };
    revoke(&mut state); // revoke precedes the issuance attempt entirely
    let issued = issue_checkpoint_atomic(&state);
    assert!(!issued, "revoke-before-issuance must refuse, with no window for a stale read");
}

#[test]
fn an_atomic_check_and_decide_issuance_still_succeeds_when_no_revoke_interleaves() {
    let state = AuthorityState { role: Role::Editor };
    assert!(issue_checkpoint_atomic(&state), "the non-adversarial case must still work");
}
