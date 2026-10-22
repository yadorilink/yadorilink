#![cfg(test)]

use super::*;
use crate::materialized_generation::{
    bump_mutation_fence, init_materialized_generation_schema,
    publish_materialized_generation_if_fence_current, snapshot_mutation_fence,
    MaterializedObjectKind,
};

/// Full schema this module's tests need: the replica tables
/// (including projection_obligations), the fence/proof tables, and `files`
/// (for the non-exact-outcome tests) -- `yadorilink_sqlite_runtime::
/// init_schema` runs after them, matching the real production schema
/// initialization order.
fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init_for_tests(&c).unwrap();
    init_materialized_generation_schema(&c).unwrap();
    yadorilink_sqlite_runtime::init_schema(&c).unwrap();
    c
}

/// Inserts a minimal, valid `files` row for `(group_id, path)` with the
/// given materialization/held state -- everything this module's
/// completion tests need, nothing `set_materialization_state`/
/// `set_held`'s own richer callers additionally track.
fn seed_file_row(
    conn: &Connection,
    group_id: &str,
    path: &str,
    materialization_state: &str,
    held_reason: Option<&str>,
) {
    conn.execute(
        "INSERT INTO files
            (group_id, path, size, mtime_unix_nanos, blocks_json, materialization_state, held_reason)
         VALUES (?1, ?2, 0, 0, '[]', ?3, ?4)",
        rusqlite::params![group_id, path, materialization_state, held_reason],
    )
    .unwrap();
}

fn hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// The headline case: a claimed generation whose exact proof is
/// current in every dimension (a), (b), (c) closes.
#[test]
fn exact_completion_closes_when_all_three_conditions_hold() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let claimed_obligation = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    let claimed_g = claimed_obligation.invalidation_generation;
    let claimed_i = claimed_obligation.obligation_incarnation;

    let fence = bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
    let published = publish_materialized_generation_if_fence_current(
        &conn,
        "g",
        "a.txt",
        MaterializedObjectKind::RegularFile,
        None,
        None,
        fence,
        3000,
    )
    .unwrap()
    .unwrap();

    assert!(
        complete_obligation_if_exact_proof_current(
            &conn,
            "g",
            "a.txt",
            claimed_g,
            claimed_i,
            &published.resolved_path_state_hash,
        )
        .unwrap(),
        "all three conditions hold -- the completion must close"
    );
    assert!(
        lookup_projection_obligation(&conn, "g", "a.txt").unwrap().is_none(),
        "a closed obligation's row must be gone -- completion is represented by absence, not a status column"
    );
}

/// (a) fails: an independent native admission bumped `invalidation_
/// generation` past the claimed value between claim and completion.
#[test]
fn exact_completion_fails_when_dag_side_generation_moved() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let claimed_obligation = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    let claimed_g = claimed_obligation.invalidation_generation;
    let claimed_i = claimed_obligation.obligation_incarnation;

    let fence = bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
    let published = publish_materialized_generation_if_fence_current(
        &conn,
        "g",
        "a.txt",
        MaterializedObjectKind::RegularFile,
        None,
        None,
        fence,
        2000,
    )
    .unwrap()
    .unwrap();

    // An independent admission re-arms the obligation to G+1.
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 3000).unwrap();

    assert!(!complete_obligation_if_exact_proof_current(
        &conn,
        "g",
        "a.txt",
        claimed_g,
        claimed_i,
        &published.resolved_path_state_hash,
    )
    .unwrap());
    assert_eq!(
        lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap().invalidation_generation,
        claimed_g + 1,
        "a failed completion must leave the re-armed obligation exactly as it was"
    );
}

/// (b) fails: an independent mutator bumped the FILESYSTEM-side fence
/// (never touching native state at all) between publication and
/// completion. The proof row still exists and its content is
/// untouched, but it is no longer usable.
#[test]
fn exact_completion_fails_when_filesystem_side_fence_moved_even_though_dag_side_did_not() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let claimed_obligation = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    let claimed_g = claimed_obligation.invalidation_generation;
    let claimed_i = claimed_obligation.obligation_incarnation;

    let fence = bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
    let published = publish_materialized_generation_if_fence_current(
        &conn,
        "g",
        "a.txt",
        MaterializedObjectKind::RegularFile,
        None,
        None,
        fence,
        2000,
    )
    .unwrap()
    .unwrap();

    // A mutator invisible to native admission (e.g. on-demand hydration/eviction, or a
    // retirement pass for an unrelated reason) bumps the fence without
    // ever touching projection_obligations.
    bump_mutation_fence(&conn, "g", "a.txt", "some-other-mutator", 3000).unwrap();

    assert!(
        !complete_obligation_if_exact_proof_current(
            &conn,
            "g",
            "a.txt",
            claimed_g,
            claimed_i,
            &published.resolved_path_state_hash,
        )
        .unwrap(),
        "a desired-side-only completion must not close once the filesystem-side proof it points \
         at has been invalidated by a mutator native admission never saw"
    );
    assert_eq!(
        lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap().invalidation_generation,
        claimed_g,
        "the obligation is left outstanding at the SAME generation, to be re-resolved -- it \
         was never invalidated on the desired side, only the fs-side proof was"
    );
}

/// (c) fails: the proof row is usable ((a) and (b) both hold) but its
/// content is not what this attempt resolved -- currently redundant
/// with (b) under today's invariants, but checked anyway as defense
/// in depth.
#[test]
fn exact_completion_fails_when_the_usable_proofs_content_does_not_match_the_desired_hash() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let claimed_obligation = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    let claimed_g = claimed_obligation.invalidation_generation;
    let claimed_i = claimed_obligation.obligation_incarnation;

    let fence = bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
    publish_materialized_generation_if_fence_current(
        &conn,
        "g",
        "a.txt",
        MaterializedObjectKind::RegularFile,
        None,
        None,
        fence,
        2000,
    )
    .unwrap();

    // A completely different (wrong) desired hash -- not what the
    // usable, current proof actually says.
    assert!(!complete_obligation_if_exact_proof_current(
        &conn,
        "g",
        "a.txt",
        claimed_g,
        claimed_i,
        &hash(99)
    )
    .unwrap());
    assert!(lookup_projection_obligation(&conn, "g", "a.txt").unwrap().is_some());
}

/// No proof at all: a claimed generation with nothing ever published
/// for this path must never close -- there is no `EXISTS` row to
/// satisfy (b)/(c) against.
#[test]
fn exact_completion_fails_when_no_proof_was_ever_published() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let claimed_obligation = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    let claimed_g = claimed_obligation.invalidation_generation;
    let claimed_i = claimed_obligation.obligation_incarnation;
    assert!(!complete_obligation_if_exact_proof_current(
        &conn,
        "g",
        "a.txt",
        claimed_g,
        claimed_i,
        &hash(1)
    )
    .unwrap());
}

/// Non-exact: a Placeholder settlement closes while the path's
/// `files` row still genuinely reads `materialization_state =
/// 'remote'`.
#[test]
fn non_exact_placeholder_completion_closes_while_still_a_placeholder() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["p.txt"], 1000).unwrap();
    let claimed_obligation = lookup_projection_obligation(&conn, "g", "p.txt").unwrap().unwrap();
    let claimed_g = claimed_obligation.invalidation_generation;
    let claimed_i = claimed_obligation.obligation_incarnation;
    seed_file_row(&conn, "g", "p.txt", "remote", None);

    assert!(complete_obligation_if_non_exact_proof_current(
        &conn,
        "g",
        "p.txt",
        claimed_g,
        claimed_i,
        NonExactProofKind::ContentNotOwed,
    )
    .unwrap());
    assert!(lookup_projection_obligation(&conn, "g", "p.txt").unwrap().is_none());
}

/// Non-exact: a content-not-owed settlement must NOT close once the path
/// has since entered `Hydrating` -- the live, same-transaction re-read is
/// required even though this specific direction of staleness is
/// independently benign. A `Present` object (an older version's bytes kept
/// under the newer row) still owes nothing and does close.
#[test]
fn non_exact_content_not_owed_completion_fails_once_hydrating_in_the_meantime() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["p.txt"], 1000).unwrap();
    let claimed_obligation = lookup_projection_obligation(&conn, "g", "p.txt").unwrap().unwrap();
    let claimed_g = claimed_obligation.invalidation_generation;
    let claimed_i = claimed_obligation.obligation_incarnation;
    seed_file_row(&conn, "g", "p.txt", "hydrating", None);

    assert!(!complete_obligation_if_non_exact_proof_current(
        &conn,
        "g",
        "p.txt",
        claimed_g,
        claimed_i,
        NonExactProofKind::ContentNotOwed,
    )
    .unwrap());
    assert!(lookup_projection_obligation(&conn, "g", "p.txt").unwrap().is_some());
}

/// Non-exact: a HazardHeld settlement closes while `held_reason` is
/// still genuinely set.
#[test]
fn non_exact_hazard_held_completion_closes_while_still_held() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["h.txt"], 1000).unwrap();
    let claimed_obligation = lookup_projection_obligation(&conn, "g", "h.txt").unwrap().unwrap();
    let claimed_g = claimed_obligation.invalidation_generation;
    let claimed_i = claimed_obligation.obligation_incarnation;
    seed_file_row(&conn, "g", "h.txt", "present", Some("case_collision"));

    assert!(complete_obligation_if_non_exact_proof_current(
        &conn,
        "g",
        "h.txt",
        claimed_g,
        claimed_i,
        NonExactProofKind::HazardHeld,
    )
    .unwrap());
    assert!(lookup_projection_obligation(&conn, "g", "h.txt").unwrap().is_none());
}

/// Non-exact: a HazardHeld settlement must NOT close once the hold has
/// been lifted in the meantime -- the HARMFUL staleness direction
/// (unlike the placeholder case above).
#[test]
fn non_exact_hazard_held_completion_fails_once_the_hold_is_lifted() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["h.txt"], 1000).unwrap();
    let claimed_obligation = lookup_projection_obligation(&conn, "g", "h.txt").unwrap().unwrap();
    let claimed_g = claimed_obligation.invalidation_generation;
    let claimed_i = claimed_obligation.obligation_incarnation;
    seed_file_row(&conn, "g", "h.txt", "present", None);

    assert!(!complete_obligation_if_non_exact_proof_current(
        &conn,
        "g",
        "h.txt",
        claimed_g,
        claimed_i,
        NonExactProofKind::HazardHeld,
    )
    .unwrap());
    assert!(lookup_projection_obligation(&conn, "g", "h.txt").unwrap().is_some());
}

/// Non-exact: IgnoreExcluded has no durable proof row to re-check
/// (see `NonExactProofKind::IgnoreExcluded`'s own doc comment) -- its
/// completion checks (a) alone, so a claimed generation that is still
/// current closes regardless of `files` row state (there need not
/// even be one).
#[test]
fn non_exact_ignore_excluded_completion_parks_rather_than_deletes() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["i.txt"], 1000).unwrap();
    let claimed_obligation = lookup_projection_obligation(&conn, "g", "i.txt").unwrap().unwrap();
    let claimed_g = claimed_obligation.invalidation_generation;
    let claimed_i = claimed_obligation.obligation_incarnation;

    assert!(complete_obligation_if_non_exact_proof_current(
        &conn,
        "g",
        "i.txt",
        claimed_g,
        claimed_i,
        NonExactProofKind::IgnoreExcluded,
    )
    .unwrap());
    let row = lookup_projection_obligation(&conn, "g", "i.txt").unwrap().unwrap();
    assert_eq!(
        row.state, "ignore_blocked",
        "an ignore-excluded settlement must park the row, not delete it, so a later \
         re-check sweep has a durable obligation to re-arm"
    );
    assert_eq!(row.invalidation_generation, claimed_g, "the generation must be left untouched");
    assert!(
        claim_runnable_obligations(&conn, 10_000, 10, 10).unwrap().is_empty(),
        "a parked ignore_blocked row must not be reclaimable through the ordinary claim path"
    );
}

#[test]
fn ignore_blocked_obligation_is_rearmed_and_becomes_claimable_again() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["i.txt"], 1000).unwrap();
    let claimed_obligation = lookup_projection_obligation(&conn, "g", "i.txt").unwrap().unwrap();
    let claimed_g = claimed_obligation.invalidation_generation;
    let claimed_i = claimed_obligation.obligation_incarnation;
    complete_obligation_if_non_exact_proof_current(
        &conn,
        "g",
        "i.txt",
        claimed_g,
        claimed_i,
        NonExactProofKind::IgnoreExcluded,
    )
    .unwrap();
    assert_eq!(list_ignore_blocked_paths(&conn, "g").unwrap(), vec!["i.txt".to_string()]);

    assert!(rearm_ignore_blocked_obligation(&conn, "g", "i.txt", 5000).unwrap());

    let row = lookup_projection_obligation(&conn, "g", "i.txt").unwrap().unwrap();
    assert_eq!(row.state, "pending");
    assert_eq!(row.invalidation_generation, claimed_g, "re-arming must not bump the generation");
    assert_eq!(row.next_attempt_at, 5000, "must be immediately claimable again");
    assert!(list_ignore_blocked_paths(&conn, "g").unwrap().is_empty());

    let reclaimed = claim_runnable_obligations(&conn, 5000, 10, 10).unwrap();
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].path, "i.txt");
}

#[test]
fn a_fresh_admission_rearms_an_ignore_blocked_path_too() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["i.txt"], 1000).unwrap();
    let claimed_obligation = lookup_projection_obligation(&conn, "g", "i.txt").unwrap().unwrap();
    let claimed_g = claimed_obligation.invalidation_generation;
    let claimed_i = claimed_obligation.obligation_incarnation;
    complete_obligation_if_non_exact_proof_current(
        &conn,
        "g",
        "i.txt",
        claimed_g,
        claimed_i,
        NonExactProofKind::IgnoreExcluded,
    )
    .unwrap();

    // A genuinely new native admission must re-arm the path regardless of
    // whatever local scheduler state it was parked in.
    bump_projection_obligations_for_touched_paths(&conn, "g", &["i.txt"], 2000).unwrap();

    let row = lookup_projection_obligation(&conn, "g", "i.txt").unwrap().unwrap();
    assert_eq!(row.state, "pending");
    assert_eq!(row.invalidation_generation, claimed_g + 1);
    assert!(list_ignore_blocked_paths(&conn, "g").unwrap().is_empty());
}

/// Non-exact: IgnoreExcluded still fails closed on (a) -- a stale
/// claimed generation is rejected the same as the exact-outcome path.
#[test]
fn non_exact_ignore_excluded_completion_fails_when_generation_moved() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["i.txt"], 1000).unwrap();
    let claimed_obligation = lookup_projection_obligation(&conn, "g", "i.txt").unwrap().unwrap();
    let claimed_g = claimed_obligation.invalidation_generation;
    let claimed_i = claimed_obligation.obligation_incarnation;
    bump_projection_obligations_for_touched_paths(&conn, "g", &["i.txt"], 2000).unwrap();

    assert!(!complete_obligation_if_non_exact_proof_current(
        &conn,
        "g",
        "i.txt",
        claimed_g,
        claimed_i,
        NonExactProofKind::IgnoreExcluded,
    )
    .unwrap());
}

/// Two paths are independent: closing one's obligation must never
/// affect another's, exact or non-exact.
#[test]
fn completing_one_paths_obligation_never_touches_an_unrelated_path() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt", "b.txt"], 1000).unwrap();
    let obligation_a = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    let g_a = obligation_a.invalidation_generation;
    let i_a = obligation_a.obligation_incarnation;

    let fence = bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
    let published = publish_materialized_generation_if_fence_current(
        &conn,
        "g",
        "a.txt",
        MaterializedObjectKind::RegularFile,
        None,
        None,
        fence,
        2000,
    )
    .unwrap()
    .unwrap();

    assert!(complete_obligation_if_exact_proof_current(
        &conn,
        "g",
        "a.txt",
        g_a,
        i_a,
        &published.resolved_path_state_hash,
    )
    .unwrap());

    assert!(lookup_projection_obligation(&conn, "g", "a.txt").unwrap().is_none());
    assert!(
        lookup_projection_obligation(&conn, "g", "b.txt").unwrap().is_some(),
        "b.txt's own obligation must be untouched by a.txt's completion"
    );
}

/// `exact_completion_fails_when_dag_side_generation_moved` above already
/// proves the completion CAS itself rejects a stale claimed generation,
/// reading the re-armed row back with `lookup_projection_obligation`.
/// This test goes one step further and proves it through the ACTUAL
/// entry point a worker would reclaim through: after a concurrent,
/// independent admission bumps the same path mid-attempt,
/// `claim_runnable_obligations` itself -- not just a diagnostic lookup
/// -- must hand the re-armed obligation back at the new generation.
///
/// Confirmed genuinely RED by temporarily dropping the `AND
/// invalidation_generation = ?3` predicate from
/// `complete_obligation_if_exact_proof_current`'s `DELETE` statement:
/// the completion then wrongly reported success and deleted the row,
/// so both the "completion affects zero rows" assertion and the
/// "still claimable at G+1" assertion failed together. Restored and
/// reconfirmed GREEN.
#[test]
fn a_concurrent_admissions_rearmed_obligation_is_independently_claimable_through_the_claim_api() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 10_000, 10, 10).unwrap();
    assert_eq!(claimed.len(), 1);
    let claimed_g = claimed[0].invalidation_generation;
    let claimed_i = claimed[0].obligation_incarnation;

    let fence = bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
    let published = publish_materialized_generation_if_fence_current(
        &conn,
        "g",
        "a.txt",
        MaterializedObjectKind::RegularFile,
        None,
        None,
        fence,
        2000,
    )
    .unwrap()
    .unwrap();

    // A concurrent, independent admission re-arms the obligation to
    // G+1 between this worker's claim and its completion attempt.
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 3000).unwrap();

    assert!(
        !complete_obligation_if_exact_proof_current(
            &conn,
            "g",
            "a.txt",
            claimed_g,
            claimed_i,
            &published.resolved_path_state_hash,
        )
        .unwrap(),
        "a completion attempt at the now-stale claimed generation must affect zero rows"
    );

    let reclaimed = claim_runnable_obligations(&conn, 10_000, 10, 10).unwrap();
    assert_eq!(
        reclaimed.len(),
        1,
        "the re-armed obligation must still be independently claimable, not just visible to a lookup"
    );
    assert_eq!(reclaimed[0].path, "a.txt");
    assert_eq!(
        reclaimed[0].invalidation_generation,
        claimed_g + 1,
        "reclaiming must observe the new generation the concurrent admission produced"
    );
}

/// A content-identical verification's SNAPSHOT (never a bump) of the
/// fence still lets the exact completion close -- the snapshot value
/// is what the publish CASed on, so it is exactly as "current" as a
/// real bump's value for this purpose.
#[test]
fn exact_completion_closes_for_a_content_identical_verifications_snapshot_epoch() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let claimed_obligation = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    let claimed_g = claimed_obligation.invalidation_generation;
    let claimed_i = claimed_obligation.obligation_incarnation;

    let snapshot = snapshot_mutation_fence(&conn, "g", "a.txt").unwrap();
    assert_eq!(snapshot, 0, "sanity: nothing has mutated this path yet");
    let published = publish_materialized_generation_if_fence_current(
        &conn,
        "g",
        "a.txt",
        MaterializedObjectKind::RegularFile,
        None,
        None,
        snapshot,
        2000,
    )
    .unwrap()
    .unwrap();

    assert!(complete_obligation_if_exact_proof_current(
        &conn,
        "g",
        "a.txt",
        claimed_g,
        claimed_i,
        &published.resolved_path_state_hash,
    )
    .unwrap());
}
