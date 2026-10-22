#![cfg(test)]

use super::*;

fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    init_projection_obligations_schema(&c).unwrap();
    c
}

#[test]
fn a_first_bump_creates_a_row_at_generation_one() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(row.invalidation_generation, 1);
    assert_eq!(row.state, "pending");
}

#[test]
fn a_second_bump_increments_the_existing_generation_rather_than_resetting_it() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();
    let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(row.invalidation_generation, 2);
    assert_eq!(row.updated_at, 2000);
}

/// the
/// incarnation allocator used to leave its `INSERT`ed row in place,
/// growing `projection_obligation_incarnations` by one permanent row
/// per touched-path event -- unbounded storage growth proportional to
/// total admitted mutations over a replica's lifetime, not to live
/// obligations. The allocator row is now deleted immediately after its
/// id is captured; this proves the table stays empty across many
/// bumps, and that incarnation values assigned to genuinely distinct
/// rows still never collide (`AUTOINCREMENT`'s `sqlite_sequence`
/// high-water mark is independent of which rows currently exist).
#[test]
fn the_incarnation_allocator_table_never_accumulates_rows() {
    let conn = conn();
    for i in 0..50 {
        let path = format!("path-{i}.txt");
        bump_projection_obligations_for_touched_paths(&conn, "g", &[&path], 1000).unwrap();
        // A second bump of the SAME path (the common ON CONFLICT
        // bump-in-place case) also allocates-and-discards an unused id.
        bump_projection_obligations_for_touched_paths(&conn, "g", &[&path], 2000).unwrap();
    }
    let allocator_rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM projection_obligation_incarnations", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        allocator_rows, 0,
        "the allocator table must never accumulate rows regardless of how many paths were bumped"
    );

    // Every one of the 50 distinct rows must still have a genuinely
    // unique incarnation -- deleting the allocator row must not have
    // let any of them collide.
    let mut incarnations = std::collections::HashSet::new();
    for i in 0..50 {
        let path = format!("path-{i}.txt");
        let obligation = lookup_projection_obligation(&conn, "g", &path).unwrap().unwrap();
        assert!(
            incarnations.insert(obligation.obligation_incarnation),
            "incarnation {} for {path} collided with an earlier path's incarnation",
            obligation.obligation_incarnation
        );
    }
}

#[test]
fn bumping_one_path_never_touches_an_unrelated_path() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["b.txt"], 1000).unwrap();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();
    let a = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    let b = lookup_projection_obligation(&conn, "g", "b.txt").unwrap().unwrap();
    assert_eq!(a.invalidation_generation, 2, "a.txt was bumped twice");
    assert_eq!(b.invalidation_generation, 1, "b.txt must be unaffected by a.txt's second bump");
}

#[test]
fn an_empty_touched_set_is_a_no_op() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &[], 1000).unwrap();
    let count: i64 =
        conn.query_row("SELECT COUNT(*) FROM projection_obligations", [], |r| r.get(0)).unwrap();
    assert_eq!(count, 0);
}

#[test]
fn a_path_with_no_admission_ever_has_no_obligation() {
    let conn = conn();
    assert!(lookup_projection_obligation(&conn, "g", "never.txt").unwrap().is_none());
}

#[test]
fn claim_returns_every_pending_obligation_with_its_current_generation() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt", "b.txt"], 1000).unwrap();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 10_000, 10, 10).unwrap();
    assert_eq!(claimed.len(), 2);
    let a = claimed.iter().find(|c| c.path == "a.txt").unwrap();
    let b = claimed.iter().find(|c| c.path == "b.txt").unwrap();
    assert_eq!(a.invalidation_generation, 2);
    assert_eq!(b.invalidation_generation, 1);
    assert_eq!(a.group_id, "g");
}

#[test]
fn claim_with_no_obligations_returns_empty() {
    let conn = conn();
    assert!(claim_runnable_obligations(&conn, 10_000, 10, 10).unwrap().is_empty());
}

#[test]
fn claim_respects_the_per_group_limit_taking_the_oldest_updated_first() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["b.txt"], 2000).unwrap();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["c.txt"], 3000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 10_000, 2, 10).unwrap();
    assert_eq!(claimed.len(), 2);
    let paths: Vec<&str> = claimed.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(paths, vec!["a.txt", "b.txt"], "the two oldest-updated rows must win, in order");
}

#[test]
fn claim_respects_the_total_limit_across_groups() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g1", &["a.txt"], 1000).unwrap();
    bump_projection_obligations_for_touched_paths(&conn, "g2", &["b.txt"], 1000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 10_000, 10, 1).unwrap();
    assert_eq!(claimed.len(), 1);
}

#[test]
fn claim_gives_every_group_a_share_rather_than_letting_one_group_crowd_out_another() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "heavy", &["1", "2", "3"], 1000).unwrap();
    bump_projection_obligations_for_touched_paths(&conn, "light", &["only"], 1000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 10_000, 1, 10).unwrap();
    let groups: std::collections::BTreeSet<&str> =
        claimed.iter().map(|c| c.group_id.as_str()).collect();
    assert!(groups.contains("heavy") && groups.contains("light"));
}

#[test]
fn a_fresh_obligation_has_zero_attempt_count_and_is_immediately_claimable() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(row.attempt_count, 0);
    assert_eq!(row.next_attempt_at, 1000);
    let claimed = claim_runnable_obligations(&conn, 1000, 10, 10).unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].attempt_count, 0);
}

#[test]
fn a_failed_attempt_is_not_reclaimable_until_its_backoff_deadline_passes() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 1000, 10, 10).unwrap();
    let claimed_g = claimed[0].invalidation_generation;
    let claimed_i = claimed[0].obligation_incarnation;

    assert!(mark_obligation_attempt_failed(&conn, "g", "a.txt", claimed_g, claimed_i, 5000, 1000)
        .unwrap());

    assert!(
        claim_runnable_obligations(&conn, 2000, 10, 10).unwrap().is_empty(),
        "must not be reclaimable before its backoff deadline"
    );
    let reclaimed = claim_runnable_obligations(&conn, 5000, 10, 10).unwrap();
    assert_eq!(reclaimed.len(), 1, "must be reclaimable once the backoff deadline passes");
    assert_eq!(reclaimed[0].attempt_count, 1, "the failed attempt must have incremented the count");
}

#[test]
fn a_fresh_admission_resets_attempt_count_and_backoff_even_after_repeated_failures() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 1000, 10, 10).unwrap();
    let claimed_g = claimed[0].invalidation_generation;
    let claimed_i = claimed[0].obligation_incarnation;
    mark_obligation_attempt_failed(&conn, "g", "a.txt", claimed_g, claimed_i, 100_000, 1000)
        .unwrap();

    // A new native admission supersedes the old generation's backoff --
    // the new desired state must be runnable immediately, not delayed
    // by the old generation's failure history.
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();

    let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(row.invalidation_generation, 2);
    assert_eq!(row.attempt_count, 0, "a new generation must reset the attempt count");
    assert_eq!(row.next_attempt_at, 2000, "a new generation must be immediately runnable");

    let reclaimed = claim_runnable_obligations(&conn, 2000, 10, 10).unwrap();
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].attempt_count, 0);
}

#[test]
fn a_stale_failure_report_at_a_superseded_generation_is_a_no_op() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 1000, 10, 10).unwrap();
    let stale_g = claimed[0].invalidation_generation;
    let claimed_i = claimed[0].obligation_incarnation;

    // A concurrent admission bumps the generation before this stale
    // attempt's own failure report lands -- an ordinary bump-in-place,
    // so the row's incarnation is unchanged; only its generation moves.
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();

    assert!(
        !mark_obligation_attempt_failed(&conn, "g", "a.txt", stale_g, claimed_i, 100_000, 3000)
            .unwrap(),
        "a failure report at a superseded generation must affect zero rows, even with the \
         correct (unchanged) incarnation"
    );
    let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(row.attempt_count, 0, "the fresh generation's reset must survive the stale report");
    assert_eq!(row.next_attempt_at, 2000, "the fresh generation must stay immediately runnable");
}

/// **Obligation row-incarnation ABA**: `mark_obligation_attempt_failed`'s
/// WHERE clause must distinguish "the exact row incarnation this claim was issued
/// against" from "any current row that happens to carry the same
/// `(group_id, path, invalidation_generation)` key" -- a pure key match
/// is not a row identity match. `claim_runnable_obligations`'s own
/// doc comment already documents that two workers concurrently holding
/// a claim on the SAME still-outstanding obligation is expected,
/// tolerated behavior ("a performance question, never a correctness
/// one") -- but that reasoning implicitly assumed the row underneath
/// both claims stays the SAME row for the obligation's whole lifetime.
/// It does not: `complete_obligation_if_exact_proof_current` and the
/// `Remote`/`HazardHeld` arms of `complete_obligation_if_non_exact_
/// proof_current` all `DELETE` the row on success, and `bump_projection_
/// obligations_for_touched_paths` INSERTs a brand-new row at
/// `invalidation_generation = 1` (via `ON CONFLICT DO UPDATE`'s INSERT
/// arm) the next time ANY admission touches that path -- there is no
/// memory of what generation a deleted row was last at. A claimant
/// issued before the delete, still holding `G = 1` (the common case:
/// the very first admission for a path is always `G = 1`), could
/// therefore complete against a brand-new, entirely unrelated later
/// obligation for the same path that also happened to start at `G = 1`.
///
/// Confirmed genuinely RED against the pre-fix API (positional 6-arg
/// `mark_obligation_attempt_failed` with no incarnation parameter): the
/// stale `mark_obligation_attempt_failed(old_claim.invalidation_
/// generation, /* no incarnation */)` call matched and corrupted the
/// reincarnated row. `obligation_incarnation` (assigned fresh, from an
/// `AUTOINCREMENT` sequence that never repeats a value, only on a
/// genuine `INSERT`, never on the `ON CONFLICT` bump-in-place arm) now
/// makes OLD's full claim token strictly stale the moment its own row
/// is deleted, regardless of what generation number a later, unrelated
/// incarnation happens to reuse.
#[test]
fn stale_claimant_cannot_corrupt_a_reincarnated_obligation_row() {
    let conn = conn();

    // OLD claims the obligation for a.txt at its first-ever generation
    // and incarnation.
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let old_claim = claim_runnable_obligations(&conn, 1000, 10, 10)
        .unwrap()
        .into_iter()
        .find(|c| c.path == "a.txt")
        .unwrap();
    assert_eq!(old_claim.invalidation_generation, 1);

    // A DIFFERENT worker successfully completes that SAME obligation --
    // standing in for a real `complete_obligation_if_exact_proof_current`
    // success, which performs exactly this DELETE once its own proof
    // check passes.
    conn.execute(
        "DELETE FROM projection_obligations
          WHERE group_id = 'g' AND path = 'a.txt' AND invalidation_generation = 1",
        [],
    )
    .unwrap();
    assert!(lookup_projection_obligation(&conn, "g", "a.txt").unwrap().is_none());

    // A genuinely NEW, unrelated native admission later touches the same
    // path -- a fresh incarnation, starting at G = 1 again (identical to
    // OLD's stale claim) since there is no surviving row to conflict
    // against, but with a NEW `obligation_incarnation` value.
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 5000).unwrap();
    let reincarnated = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(
        reincarnated.invalidation_generation, 1,
        "sanity: the new admission's row starts fresh at G=1, identical to OLD's stale claim"
    );
    assert_ne!(
        reincarnated.obligation_incarnation, old_claim.obligation_incarnation,
        "sanity: the reincarnated row must get a genuinely different incarnation than OLD's"
    );

    // OLD, still holding its now-stale claim from the deleted
    // incarnation, reports a failed attempt against the generation AND
    // incarnation it originally claimed.
    let affected = mark_obligation_attempt_failed(
        &conn,
        "g",
        "a.txt",
        old_claim.invalidation_generation,
        old_claim.obligation_incarnation,
        99_999,
        5000,
    )
    .unwrap();

    // FIXED: OLD's stale attempt-failure report against a DELETED
    // incarnation must affect zero rows, even though its generation
    // number coincidentally matches the brand-new incarnation's own.
    assert!(
        !affected,
        "OLD's stale claim against a deleted incarnation must not match the new incarnation, \
         even at the same generation number"
    );
    let untouched = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(
        untouched.attempt_count, 0,
        "the new incarnation's attempt_count must be untouched by an attempt nobody made against it"
    );
    assert_eq!(
        untouched.next_attempt_at, 5000,
        "the new incarnation's backoff must be untouched by OLD's stale report"
    );
}

#[test]
fn defer_without_penalty_delays_reclaim_but_never_increments_attempt_count() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
    let claimed = claim_runnable_obligations(&conn, 1000, 10, 10).unwrap();
    let claimed_g = claimed[0].invalidation_generation;
    let claimed_i = claimed[0].obligation_incarnation;

    assert!(defer_obligation_without_penalty(
        &conn, "g", "a.txt", claimed_g, claimed_i, 1200, 1000
    )
    .unwrap());
    assert!(claim_runnable_obligations(&conn, 1100, 10, 10).unwrap().is_empty());
    let reclaimed = claim_runnable_obligations(&conn, 1200, 10, 10).unwrap();
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(
        reclaimed[0].attempt_count, 0,
        "a no-trustworthy-audit reschedule must never count as a failed attempt"
    );
}

/// Nothing in this module ever moves a row's `state` out of `'pending'`
/// or otherwise marks it in-flight -- `claim_runnable_obligations` is a
/// plain `SELECT`, and a fresh admission's bump unconditionally resets
/// `state` back to `'pending'` regardless of what came before. A row a
/// worker never got to before a restart is therefore already sitting
/// exactly where a freshly claimable row needs to be: this is ordinary
/// durable SQLite state, not something that needs its own crash-
/// recovery primitive the way a scheduler with genuine in-flight states
/// (`Planning`/`Fetching`/`ReadyToCommit`) would. This test proves that
/// directly: it commits an admission, then closes and reopens the
/// SQLite connection with no claim or completion call in between --
/// simulating a daemon restart before any worker tick ever touched this
/// obligation -- and checks it survives with its generation intact and
/// is still claimable through the real claim entry point, not merely
/// visible to a diagnostic lookup.
///
/// Confirmed genuinely RED by temporarily changing this module's
/// `CREATE TABLE IF NOT EXISTS projection_obligations` to `CREATE TEMP
/// TABLE IF NOT EXISTS projection_obligations`: a `TEMP` table is
/// scoped to the connection that created it, so the reopened connection
/// got a fresh, empty table and this test failed (`unwrap()` on `None`)
/// exactly as it should for genuinely lost state. Restored and
/// reconfirmed GREEN.
#[test]
fn an_obligation_survives_a_connection_restart_with_no_worker_tick_and_stays_claimable() {
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("projection_obligations.sqlite");

    {
        let conn = Connection::open(&db_path).unwrap();
        init_projection_obligations_schema(&conn).unwrap();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 1000).unwrap();
        bump_projection_obligations_for_touched_paths(&conn, "g", &["a.txt"], 2000).unwrap();
        // `conn` is dropped here, simulating the process exiting before
        // any worker tick ever claims or completes this obligation.
    }

    // Simulated restart: a fresh connection to the same on-disk
    // database, re-running schema init exactly as daemon startup does.
    let conn = Connection::open(&db_path).unwrap();
    init_projection_obligations_schema(&conn).unwrap();

    let row = lookup_projection_obligation(&conn, "g", "a.txt").unwrap().unwrap();
    assert_eq!(
        row.invalidation_generation, 2,
        "the pre-restart generation must survive the restart untouched"
    );
    assert_eq!(row.state, "pending");

    let claimed = claim_runnable_obligations(&conn, 10_000, 10, 10).unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].path, "a.txt");
    assert_eq!(claimed[0].invalidation_generation, 2);
}

/// A block of paths bumped together gets one fresh incarnation per path: unique, ascending in
/// the order the paths were given, above everything allocated before, and never left behind in
/// the allocator table.
#[test]
fn a_bumped_block_gets_unique_ascending_incarnations_above_earlier_ones() {
    let conn = conn();
    bump_projection_obligations_for_touched_paths(&conn, "g", &["early-1", "early-2"], 1000)
        .unwrap();
    let earlier = ["early-1", "early-2"]
        .map(|p| lookup_projection_obligation(&conn, "g", p).unwrap().unwrap());
    let mut paths: Vec<String> = (0..700).map(|i| format!("p-{:04}", 699 - i)).collect();
    paths.push("early-1".to_owned());
    let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    bump_projection_obligations_for_touched_paths(&conn, "g", &refs, 2000).unwrap();
    let mut previous = earlier.iter().map(|o| o.obligation_incarnation).max().unwrap();
    for path in refs.iter().take(700) {
        let row = lookup_projection_obligation(&conn, "g", path).unwrap().unwrap();
        assert!(row.obligation_incarnation > previous, "{path} is not above the one before it");
        previous = row.obligation_incarnation;
        assert_eq!(row.invalidation_generation, 1);
    }
    // A path that already had a row keeps its incarnation and counts the bump.
    let again = lookup_projection_obligation(&conn, "g", "early-1").unwrap().unwrap();
    assert_eq!(again.obligation_incarnation, earlier[0].obligation_incarnation);
    assert_eq!(again.invalidation_generation, 2);
    let leftover: i64 = conn
        .query_row("SELECT COUNT(*) FROM projection_obligation_incarnations", [], |r| r.get(0))
        .unwrap();
    assert_eq!(leftover, 0);
    // The next allocation still lands above the whole block.
    bump_projection_obligations_for_touched_paths(&conn, "g", &["late"], 3000).unwrap();
    let late = lookup_projection_obligation(&conn, "g", "late").unwrap().unwrap();
    assert!(late.obligation_incarnation > previous);
}

/// Bumping with the local origin leaves the same rows as a remote bump followed by overwriting
/// the origin, on fresh rows and on rows a remote bump had written; a remote bump after it
/// resets the origin.
#[test]
fn a_local_origin_bump_matches_a_bump_then_overwriting_the_origin() {
    let rows = |c: &Connection| -> Vec<(String, i64, String, String, i64)> {
        c.prepare(
            "SELECT path, invalidation_generation, state, origin, updated_at \
             FROM projection_obligations ORDER BY path",
        )
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
    };
    let (folded, two_step) = (conn(), conn());
    for c in [&folded, &two_step] {
        bump_projection_obligations_for_touched_paths(c, "g", &["a", "b"], 1000).unwrap();
    }
    let touched = ["b", "c", "d", "c"];
    bump_projection_obligations_with_origin(&folded, "g", &touched, 2000, ObligationOrigin::Local)
        .unwrap();
    bump_projection_obligations_for_touched_paths(&two_step, "g", &touched, 2000).unwrap();
    two_step
        .execute(
            "UPDATE projection_obligations SET origin = 'local' WHERE path IN ('b','c','d')",
            [],
        )
        .unwrap();
    assert_eq!(rows(&folded), rows(&two_step));
    let by_path = rows(&folded);
    assert_eq!(by_path[0].3, "remote", "a path the bump did not touch keeps its origin");
    assert_eq!((by_path[2].1, by_path[2].3.as_str()), (2, "local"), "a repeated path bumps twice");
    bump_projection_obligations_for_touched_paths(&folded, "g", &["b"], 3000).unwrap();
    assert_eq!(rows(&folded)[1].3, "remote");
}

/// A deterministic generator, so a failing corpus can be replayed.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// The claim walks the index in claim order and stops early; it must hand
/// back exactly what the whole-table form hands back: same rows, same order,
/// under every limit, with pending/non-pending rows, backed-off rows (some
/// due, some not), paused/held paths, a frozen group and several groups.
#[test]
fn streamed_claim_matches_the_whole_table_claim() {
    for seed in 0..16u64 {
        let conn = conn();
        // Alternate small and large corpora so both access paths run.
        let rows = if seed % 2 == 0 { 400 } else { 6000 };
        let mut rng = Lcg(seed + 1);
        let groups = ["g0", "g1", "g2", "g3", ""];
        for i in 0..rows {
            let group = groups[rng.below(5) as usize];
            let path = format!("d{}/f{i}", rng.below(5));
            // Few distinct timestamps, so ties are broken by path.
            let updated_at = rng.below(12) as i64 * 100;
            let state = if rng.below(5) == 0 { "done" } else { "pending" };
            let next_attempt_at =
                if rng.below(4) == 0 { 5_000 + rng.below(2) as i64 * 5_000 } else { 0 };
            conn.execute(
                "INSERT INTO projection_obligations (group_id, path, invalidation_generation, \
                 state, created_at, updated_at, attempt_count, next_attempt_at, \
                 obligation_incarnation) VALUES (?1, ?2, 1, ?3, 0, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    group,
                    path,
                    state,
                    updated_at,
                    rng.below(4) as i64,
                    next_attempt_at,
                    i
                ],
            )
            .unwrap();
        }
        for d in 0..2 {
            conn.execute(
                "INSERT INTO paused_items (group_id, path, paused_at_unix_nanos) VALUES (?1, ?2, 0)",
                rusqlite::params![groups[rng.below(5) as usize], format!("d{}", rng.below(5) + d)],
            )
            .unwrap();
        }
        for i in 0..20 {
            conn.execute(
                "INSERT OR IGNORE INTO held_paths (group_id, path, held_at_unix_nanos) VALUES (?1, ?2, 0)",
                rusqlite::params![groups[rng.below(5) as usize], format!("d{}/f{}", rng.below(5), i * 20)],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO native_rebootstrap_journal (group_id, recovery_id, state, \
             target_checkpoint_hash, started_at, updated_at) VALUES ('g3', 'r', 'capturing', x'00', 0, 0)",
            [],
        )
        .unwrap();
        let mut nonempty = 0;
        for now in [0i64, 4_999, 5_000, 10_000] {
            for (per_group, total) in
                [(1u32, 1u32), (2, 3), (3, 100), (10, 7), (1000, 1000), (4, 20), (0, 5), (5, 0)]
            {
                let streamed = claim_runnable_obligations(&conn, now, per_group, total).unwrap();
                let oracle =
                    claim_runnable_obligations_oracle(&conn, now, per_group, total).unwrap();
                let key = |c: &ClaimedObligation| {
                    (
                        c.group_id.clone(),
                        c.path.clone(),
                        c.invalidation_generation,
                        c.obligation_incarnation,
                        c.attempt_count,
                    )
                };
                assert_eq!(
                    streamed.iter().map(key).collect::<Vec<_>>(),
                    oracle.iter().map(key).collect::<Vec<_>>(),
                    "seed {seed} now {now} limits {per_group}/{total}"
                );
                nonempty += usize::from(!streamed.is_empty());
            }
        }
        assert!(nonempty > 10, "the corpus must exercise real claims");
    }
}

fn plan_of(conn: &Connection, sql: &str) -> Vec<String> {
    conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .unwrap()
        .query_map([], |r| r.get::<_, String>(3))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// Both access paths read their window through an index: no scan and no sort.
#[test]
fn claim_access_paths_use_an_index_without_scan_or_sort() {
    let conn = conn();
    let due = plan_of(
        &conn,
        "SELECT group_id FROM projection_obligations INDEXED BY idx_projection_obligations_due \
         WHERE state = 'pending' AND group_id = 'g' AND next_attempt_at <= 1 LIMIT 129",
    );
    let walk = plan_of(
        &conn,
        "SELECT group_id FROM projection_obligations INDEXED BY idx_projection_obligations_runnable \
         WHERE state = 'pending' AND group_id = 'g' AND next_attempt_at <= 1 \
         ORDER BY updated_at ASC, path ASC LIMIT 8",
    );
    for plan in [&due, &walk] {
        assert!(
            plan.iter().all(|p| !p.contains("TEMP B-TREE") && !p.starts_with("SCAN")),
            "no scan or sort: {plan:?}"
        );
    }
    assert!(
        due[0].contains("next_attempt_at<?"),
        "the due probe must seek on the deadline: {due:?}"
    );
}

/// Claim cost by population and window (informal measurement, run with
/// `-- --ignored --nocapture`): the streamed claim should follow the window.
#[test]
#[ignore = "measurement; run explicitly"]
fn claim_cost_by_population_and_window() {
    for rows in [1_000i64, 10_000, 100_000, 1_000_000] {
        let conn = conn();
        conn.execute(
            "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < ?1 - 1) \
             INSERT INTO projection_obligations (group_id, path, invalidation_generation, state, \
             created_at, updated_at, obligation_incarnation) \
             SELECT 'g', 'p/' || i, 1, 'pending', 0, i, i FROM n",
            [rows],
        )
        .unwrap();
        for window in [1u32, 8, 32, 256] {
            let t = std::time::Instant::now();
            let got = claim_runnable_obligations(&conn, 10, window, window).unwrap();
            let streamed = t.elapsed();
            assert_eq!(got.len(), window as usize);
            let t = std::time::Instant::now();
            claim_runnable_obligations_oracle(&conn, 10, window, window).unwrap();
            println!(
                "claim rows={rows:>8} window={window:>4}: streamed {:.3} ms, whole-table {:.1} ms",
                streamed.as_secs_f64() * 1000.0,
                t.elapsed().as_secs_f64() * 1000.0
            );
        }
    }
}

#[test]
#[ignore = "prints the plan"]
fn print_claim_plan() {
    let conn = conn();
    let sql = format!(
        "EXPLAIN QUERY PLAN SELECT group_id, path FROM projection_obligations \
         INDEXED BY idx_projection_obligations_runnable \
         WHERE state = 'pending' AND group_id = 'g' AND next_attempt_at <= 1 AND NOT {} AND NOT {} AND NOT {} \
         ORDER BY updated_at ASC, path ASC LIMIT 8",
        crate::paused_items::covered_by_paused_item_sql("projection_obligations.group_id", "projection_obligations.path"),
        crate::held_path::held_sql("projection_obligations.group_id", "projection_obligations.path"),
        crate::native_rebootstrap::frozen_group_sql("projection_obligations.group_id"),
    );
    for row in conn.prepare(&sql).unwrap().query_map([], |r| r.get::<_, String>(3)).unwrap() {
        println!("PLAN {}", row.unwrap());
    }
}

fn insert_pending(
    conn: &Connection,
    group: &str,
    path: &str,
    updated_at: i64,
    next_attempt_at: i64,
) {
    conn.execute(
        "INSERT INTO projection_obligations (group_id, path, invalidation_generation, state, \
         created_at, updated_at, next_attempt_at, obligation_incarnation) \
         VALUES (?1, ?2, 1, 'pending', 0, ?3, ?4, 0)",
        rusqlite::params![group, path, updated_at, next_attempt_at],
    )
    .unwrap();
}

fn names(claimed: &[ClaimedObligation]) -> Vec<(String, String)> {
    claimed.iter().map(|c| (c.group_id.clone(), c.path.clone())).collect()
}

/// Paused and held rows at the top of a group's order never take a window
/// slot: the runnable rows behind them are still claimed, as the whole-table
/// query did (both access paths, the due probe and the ordered walk).
#[test]
fn held_and_paused_rows_do_not_eat_the_window() {
    for rows in [20usize, 1500] {
        let conn = conn();
        for i in 0..rows {
            insert_pending(&conn, "g", &format!("d/{i:05}"), i as i64, 0);
        }
        for i in 0..6 {
            conn.execute(
                "INSERT INTO held_paths (group_id, path, held_at_unix_nanos) VALUES ('g', ?1, 0)",
                [format!("d/{i:05}")],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO paused_items (group_id, path, paused_at_unix_nanos) VALUES ('g', 'd/00006', 0)",
            [],
        )
        .unwrap();
        let claimed = claim_runnable_obligations(&conn, 10, 3, 3).unwrap();
        assert_eq!(
            claimed.iter().map(|c| c.path.as_str()).collect::<Vec<_>>(),
            ["d/00007", "d/00008", "d/00009"][..],
            "rows {rows}"
        );
        assert_eq!(
            names(&claimed),
            names(&claim_runnable_obligations_oracle(&conn, 10, 3, 3).unwrap())
        );
    }
}

/// More than 128 due rows behind many older not-yet-due ones (the due-index
/// pass with a bounded heap): same rows, same order as the whole-table
/// query, for limits below, at and above the due count, with ties on
/// `updated_at` broken by path and some due rows paused or held.
#[test]
fn many_due_rows_behind_older_backed_off_rows_match_the_whole_table_claim() {
    for due in [129usize, 500] {
        let conn = conn();
        for i in 0..3000 {
            insert_pending(&conn, "g", &format!("old/{i:05}"), (i % 7) as i64, 1_000_000);
        }
        for i in 0..due {
            // Few distinct timestamps: ties are broken by path.
            insert_pending(&conn, "g", &format!("new/{:05}", due - i), 10_000 + (i % 5) as i64, 0);
        }
        insert_pending(&conn, "h", "other", 10_002, 0);
        conn.execute(
            "INSERT INTO held_paths (group_id, path, held_at_unix_nanos) VALUES ('g', 'new/00003', 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO paused_items (group_id, path, paused_at_unix_nanos) VALUES ('g', 'new/00004', 0)",
            [],
        )
        .unwrap();
        for per_group in [1u32, 8, 128, 129, due as u32 - 1, due as u32, 1000] {
            for total in [3u32, 200, 1000] {
                let got = claim_runnable_obligations(&conn, 10, per_group, total).unwrap();
                let want = claim_runnable_obligations_oracle(&conn, 10, per_group, total).unwrap();
                assert_eq!(names(&got), names(&want), "due {due} limits {per_group}/{total}");
            }
        }
    }
}

/// A group whose every deadline is in the future yields nothing, and a group
/// with a few due rows among many backed-off ones yields exactly those.
#[test]
fn backed_off_rows_are_never_claimed_early() {
    let conn = conn();
    for i in 0..3000 {
        insert_pending(&conn, "g", &format!("p/{i:05}"), i, 1_000_000 + i);
    }
    assert!(claim_runnable_obligations(&conn, 999_999, 8, 8).unwrap().is_empty());
    insert_pending(&conn, "g", "z/late", 99_999, 0);
    insert_pending(&conn, "g", "a/early", 99_998, 5);
    let got = claim_runnable_obligations(&conn, 10, 8, 8).unwrap();
    assert_eq!(names(&got), vec![("g".into(), "a/early".into()), ("g".into(), "z/late".into())]);
    assert_eq!(names(&got), names(&claim_runnable_obligations_oracle(&conn, 10, 8, 8).unwrap()));
}

/// Repeated ticks over several groups whose rows tie on `(updated_at, path)`,
/// with more runnable rows than `total_limit`, so every tick returns a full
/// window. Property: while claimed rows leave the runnable set (completed, or
/// backed off after a failed attempt), every row is claimed within
/// ceil(rows / total_limit) ticks, so no group is starved; and where the old
/// query's order is defined (no tie spans groups) each tick equals the old
/// query's tick, while where it is not, each tick still holds the same
/// (updated_at, path) multiset as the old query's.
#[test]
fn repeated_ticks_serve_every_group_and_match_the_whole_table_claim() {
    for (tie_across_groups, complete) in
        [(false, true), (true, true), (false, false), (true, false)]
    {
        let conn = conn();
        let groups = ["a", "b", "c", "d"];
        let per_group_rows = 9;
        for g in groups {
            for i in 0..per_group_rows {
                // Tied runs: same updated_at and path in every group.
                let path = if tie_across_groups { format!("p{i}") } else { format!("p{i}-{g}") };
                insert_pending(&conn, g, &path, (i / 3) as i64, 0);
            }
        }
        let total_limit = 5u32;
        let total_rows = groups.len() * per_group_rows;
        let mut seen = std::collections::HashSet::new();
        let mut now = 100i64;
        let bound = total_rows.div_ceil(total_limit as usize);
        for tick in 0..bound {
            let streamed = claim_runnable_obligations(&conn, now, 3, total_limit).unwrap();
            let oracle = claim_runnable_obligations_oracle(&conn, now, 3, total_limit).unwrap();
            assert_eq!(streamed.len(), oracle.len(), "tick {tick}: the window stays full");
            if !tie_across_groups {
                assert_eq!(names(&streamed), names(&oracle), "tick {tick}");
            } else {
                let mut a: Vec<_> = streamed.iter().map(|c| c.path.clone()).collect();
                let mut b: Vec<_> = oracle.iter().map(|c| c.path.clone()).collect();
                a.sort();
                b.sort();
                assert_eq!(a, b, "tick {tick}: same ranks served, only the tied group may differ");
                // Where the old order is undefined, ties break by group id.
                let key = |c: &ClaimedObligation| -> (i64, String, String) {
                    let at: i64 = conn
                        .query_row(
                            "SELECT updated_at FROM projection_obligations WHERE group_id = ?1 AND path = ?2",
                            rusqlite::params![c.group_id, c.path],
                            |r| r.get(0),
                        )
                        .unwrap();
                    (at, c.path.clone(), c.group_id.clone())
                };
                let keys: Vec<_> = streamed.iter().map(key).collect();
                assert!(keys.windows(2).all(|w| w[0] <= w[1]), "tick {tick}: claim order {keys:?}");
            }
            for c in &streamed {
                assert!(seen.insert((c.group_id.clone(), c.path.clone())), "claimed twice");
                if complete {
                    conn.execute(
                        "DELETE FROM projection_obligations WHERE group_id = ?1 AND path = ?2",
                        rusqlite::params![c.group_id, c.path],
                    )
                    .unwrap();
                } else {
                    // Not completed: the attempt failed and backed off past
                    // every later tick, which is what a lease or backoff does.
                    assert!(mark_obligation_attempt_failed(
                        &conn,
                        &c.group_id,
                        &c.path,
                        c.invalidation_generation,
                        c.obligation_incarnation,
                        1_000_000,
                        now,
                    )
                    .unwrap());
                }
            }
            now += 1;
        }
        assert_eq!(seen.len(), total_rows, "every runnable row claimed within {bound} ticks");
        assert!(claim_runnable_obligations(&conn, now, 3, total_limit).unwrap().is_empty());
    }
}

/// A group id of `''` is permitted by the schema and claimable.
#[test]
fn an_empty_group_id_is_claimed() {
    let conn = conn();
    insert_pending(&conn, "", "a", 1, 0);
    insert_pending(&conn, "g", "b", 2, 0);
    let got = claim_runnable_obligations(&conn, 10, 5, 5).unwrap();
    assert_eq!(names(&got), vec![("".into(), "a".into()), ("g".into(), "b".into())]);
}

/// Claim cost with every deadline in the future, and with a few due rows
/// among them (informal measurement, run with `-- --ignored --nocapture`).
#[test]
#[ignore = "measurement; run explicitly"]
fn claim_cost_when_backed_off() {
    for rows in [100_000i64, 1_000_000] {
        for due in [0i64, 100, 129, 100_000] {
            let conn = conn();
            conn.execute(
                "WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i + 1 FROM n WHERE i < ?1 - 1) \
                 INSERT INTO projection_obligations (group_id, path, invalidation_generation, \
                 state, created_at, updated_at, next_attempt_at, obligation_incarnation) \
                 SELECT 'g', 'p/' || i, 1, 'pending', 0, i, CASE WHEN i >= ?1 - ?2 THEN 0 ELSE 1000000 END, i FROM n",
                [rows, due],
            )
            .unwrap();
            for window in [1u32, 8, 128] {
                let t = std::time::Instant::now();
                let got = claim_runnable_obligations(&conn, 10, window, window).unwrap();
                println!(
                    "backoff rows={rows:>8} due={due:>3} window={window:>3}: {:.3} ms ({} claimed)",
                    t.elapsed().as_secs_f64() * 1000.0,
                    got.len()
                );
            }
        }
    }
}
