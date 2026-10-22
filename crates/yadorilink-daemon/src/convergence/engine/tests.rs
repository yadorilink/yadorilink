#![cfg(test)]

use super::{
    majority_author, origin_first_indices, parse_reconcile_paths, rotation_indices,
    MAX_JOBS_PER_TICK_PER_GROUP, MAX_PATHS_PER_RECONCILE_ATTEMPT, MAX_RECONCILE_PATHS_OVERRIDE,
};

#[test]
fn no_candidates_yields_no_attempts() {
    assert_eq!(rotation_indices(0, 0, 2), Vec::<usize>::new());
    assert_eq!(rotation_indices(0, 5, 2), Vec::<usize>::new());
}

#[test]
fn tries_up_to_max_attempts_starting_at_the_cursor() {
    assert_eq!(rotation_indices(6, 0, 2), vec![0, 1]);
    assert_eq!(rotation_indices(6, 3, 2), vec![3, 4]);
}

#[test]
fn wraps_around_past_the_end_of_the_candidate_list() {
    assert_eq!(rotation_indices(6, 5, 2), vec![5, 0]);
    assert_eq!(rotation_indices(3, 2, 2), vec![2, 0]);
}

#[test]
fn caps_at_candidate_count_when_max_attempts_is_larger() {
    assert_eq!(rotation_indices(2, 0, 5), vec![0, 1]);
}

#[test]
fn a_stale_cursor_far_past_the_candidate_count_still_normalizes_correctly() {
    // The cursor is persisted across ticks and the candidate set can
    // shrink between ticks (a peer disconnects) — a stored cursor value
    // that no longer fits must still normalize via modulo, not panic
    // or index out of bounds.
    assert_eq!(rotation_indices(3, 100, 2), vec![1, 2]);
}

/// F2 / decision-9 regression, exact form: `process_group_via_
/// obligations`'s own path-budget window is exactly `rotation_indices`
/// called with the real `MAX_PATHS_PER_RECONCILE_ATTEMPT` constant, no
/// further logic in between (`windowed_paths` is a straight 1:1 index
/// map). `zero_work_precheck_examines_at_most_the_path_budget_window_
/// per_tick` (below) proves the full async engine respects this bound
/// too, but that test's own assertion is deliberately loosened to
/// tolerate cross-test pollution of the process-global
/// `obligation_tick_metrics` counter it reads (see that test's own comment) -- it could not
/// catch a regression from 8 to, say, 12 or 16. This test has no
/// global state, no async machinery, and no tolerance: it ties the
/// production constant directly to `rotation_indices`'s own
/// already-exact contract.
#[test]
fn the_path_budget_window_is_exactly_bounded_by_max_paths_per_reconcile_attempt() {
    let indices = rotation_indices(50, 0, MAX_PATHS_PER_RECONCILE_ATTEMPT);
    assert_eq!(
        indices.len(),
        MAX_PATHS_PER_RECONCILE_ATTEMPT,
        "50 claimed paths must window down to exactly MAX_PATHS_PER_RECONCILE_ATTEMPT \
         ({MAX_PATHS_PER_RECONCILE_ATTEMPT}), not a looser bound"
    );
    // Fewer claimed paths than the budget must never be padded or
    // over-counted -- the window is capped at, not filled to, the
    // constant.
    let short = rotation_indices(3, 0, MAX_PATHS_PER_RECONCILE_ATTEMPT);
    assert_eq!(short.len(), 3);
}

/// The sweep seam resolves to the value it is given, and an absent
/// setting is byte-for-byte the shipped default.
///
/// Worth its own test because the failure mode is silent in the
/// direction that matters: a seam that accepted the variable but
/// resolved to something else would let a whole sweep run, produce
/// three arms of plausible numbers, and report "no difference" for a
/// knob that was never turned. This project has already had a real
/// architectural direction rejected on exactly that shape of invalid
/// null result.
///
/// The environment is deliberately not touched here -- see
/// `parse_reconcile_paths`'s own doc comment for why doing so would
/// make OTHER tests flaky rather than this one.
#[test]
fn the_reconcile_window_seam_resolves_to_the_configured_value() {
    assert_eq!(
        parse_reconcile_paths(None),
        MAX_PATHS_PER_RECONCILE_ATTEMPT,
        "an unset variable must behave exactly as before this seam existed"
    );
    assert_eq!(parse_reconcile_paths(Some("16")), 16);
    assert_eq!(parse_reconcile_paths(Some("32")), 32);

    // And the resolved value has to reach what consumes it, rather
    // than merely parse.
    assert_eq!(rotation_indices(50, 0, parse_reconcile_paths(Some("32"))).len(), 32);
    assert_eq!(
        rotation_indices(50, 0, parse_reconcile_paths(None)).len(),
        MAX_PATHS_PER_RECONCILE_ATTEMPT
    );

    // Nonsense falls back rather than widening the window to something
    // unintended: a typo in a sweep must not silently become a
    // different experiment.
    for bad in ["0", "-4", "many", "", "8.5"] {
        assert_eq!(
            parse_reconcile_paths(Some(bad)),
            MAX_PATHS_PER_RECONCILE_ATTEMPT,
            "{bad:?} must fall back to the compiled default"
        );
    }
}

#[test]
fn full_rotation_across_repeated_calls_reaches_every_candidate_within_a_few_ticks() {
    // Simulates what `process_group` does across successive ticks:
    // advance the cursor by exactly how many indices were returned
    // (advancing by a fixed 1 regardless of how many were tried would
    // leave candidate 1 freshly re-tried every tick while candidate 2
    // only got reached every other tick, so a 6-candidate group would
    // take 5 ticks to reach every peer once instead of 3).
    let candidate_count = 6;
    let max_attempts = 2;
    let mut cursor = 0usize;
    let mut seen: Vec<usize> = Vec::new();
    for _ in 0..(candidate_count / max_attempts) {
        let indices = rotation_indices(candidate_count, cursor, max_attempts);
        seen.extend(&indices);
        cursor = (cursor + indices.len()) % candidate_count;
    }
    // Every candidate reached exactly once — no gaps (a peer skipped
    // forever) and no overlap (a peer re-tried before every other peer
    // got its first try), achievable here since candidate_count is
    // evenly divisible by max_attempts.
    seen.sort_unstable();
    assert_eq!(seen, vec![0, 1, 2, 3, 4, 5]);
}

#[test]
fn no_origin_preference_is_plain_rotation() {
    assert_eq!(origin_first_indices(6, 3, 2, None), rotation_indices(6, 3, 2));
}

#[test]
fn an_origin_inside_the_window_moves_to_the_front_without_a_duplicate() {
    // Window at cursor 3 is [3, 4]; origin 4 must lead, 3 stays.
    assert_eq!(origin_first_indices(6, 3, 2, Some(4)), vec![4, 3]);
    // Origin already first is a no-op.
    assert_eq!(origin_first_indices(6, 3, 2, Some(3)), vec![3, 4]);
}

#[test]
fn an_origin_outside_the_window_replaces_the_last_slot() {
    // Window at cursor 0 is [0, 1]; origin 5 takes the lead and the
    // attempt budget stays 2, so window position 1 waits its turn.
    assert_eq!(origin_first_indices(6, 0, 2, Some(5)), vec![5, 0]);
}

#[test]
fn a_stale_origin_index_past_the_candidate_count_is_ignored() {
    // The candidate set can shrink between resolving the origin and
    // building the order (a peer disconnects) — never index past it.
    assert_eq!(origin_first_indices(3, 0, 2, Some(7)), vec![0, 1]);
    assert_eq!(origin_first_indices(0, 0, 2, Some(0)), Vec::<usize>::new());
}

#[test]
fn origin_preference_never_starves_the_rotation() {
    // The fairness contract behind `process_group`'s prefix-based
    // cursor advance: with a PERSISTENT origin preference (one author
    // with a standing backlog) and every attempt tried each tick, every
    // other candidate is still reached within a bounded number of
    // ticks — the origin eats one attempt slot, it does not freeze the
    // rotation.
    let candidate_count = 4;
    let max_attempts = 2;
    let origin = 3usize;
    let mut cursor = 0usize;
    let mut seen: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for _ in 0..candidate_count {
        let window = rotation_indices(candidate_count, cursor, max_attempts);
        let indices = origin_first_indices(candidate_count, cursor, max_attempts, Some(origin));
        seen.extend(&indices);
        let tried: std::collections::BTreeSet<usize> = indices.iter().copied().collect();
        let advance = window.iter().take_while(|i| tried.contains(i)).count();
        cursor = (cursor + advance) % candidate_count;
    }
    assert_eq!(seen.into_iter().collect::<Vec<_>>(), vec![0, 1, 2, 3]);
}

#[test]
fn majority_author_picks_the_most_frequent_with_a_deterministic_tie_break() {
    assert_eq!(majority_author(Vec::<String>::new()), None);
    assert_eq!(majority_author(vec!["b".into(), "a".into(), "b".into()]), Some("b".to_string()));
    // Equal counts: the lexicographically smallest id wins, so every
    // replica running this election lands on the same preference.
    assert_eq!(majority_author(vec!["b".into(), "a".into()]), Some("a".to_string()));
}

#[test]
fn the_reconcile_window_override_is_clamped_below_the_claim_cap() {
    for big in ["65", "128", "1000"] {
        assert_eq!(parse_reconcile_paths(Some(big)), MAX_RECONCILE_PATHS_OVERRIDE, "{big}");
    }
    assert_eq!(parse_reconcile_paths(Some("64")), MAX_RECONCILE_PATHS_OVERRIDE);
    assert_eq!(parse_reconcile_paths(Some("0")), MAX_PATHS_PER_RECONCILE_ATTEMPT);
    // No cliff: a window never covers the whole per-group claim.
    const _: () = assert!(MAX_RECONCILE_PATHS_OVERRIDE < MAX_JOBS_PER_TICK_PER_GROUP as usize);
}

#[test]
fn the_default_window_equals_the_default_write_concurrency() {
    // The window must not be the binding limit of the settle by default.
    assert_eq!(
        MAX_PATHS_PER_RECONCILE_ATTEMPT,
        crate::local_convergence::reconcile_native::DEFAULT_RECEIVE_WRITE_CONCURRENCY
    );
}
