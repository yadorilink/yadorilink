#![cfg(test)]

use super::*;
use yadorilink_replica_domain::file::FileRecord;

/// `yadorilink_sqlite_runtime::init_schema` runs after the replica
/// tables, matching the real production initialization order. Uses the REAL schema, not a stand-in, so
/// these tests also prove the `admitted_at_unix_nanos` migration
/// actually put the column on the table.
fn conn() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init_for_tests(&c).unwrap();
    yadorilink_sqlite_runtime::init_schema(&c).unwrap();
    c
}

/// Inserts one `files` row with an explicit admission timestamp.
///
/// Direct SQL rather than `upsert_file_in_tx`, because the production
/// write path deliberately stamps the real wall clock and gives a
/// caller no way to choose the instant -- which is the right design
/// (see that function's doc comment) but makes it useless for building
/// a specific history. `stamps_the_local_admission_clock_at_the_write_
/// chokepoint` below covers the real path separately.
///
/// `size` is the only content knob these tests need: it feeds
/// `FileVersion::from_index_row`, so two rows with the same `size`
/// hash equal and two with different sizes do not.
#[allow(clippy::too_many_arguments)]
fn seed(
    conn: &Connection,
    group_id: &str,
    path: &str,
    version_seq: i64,
    state: &str,
    deleted: bool,
    size: i64,
    admitted_at: Option<i64>,
) {
    conn.execute(
        "INSERT INTO files (group_id, path, version_seq, state, deleted, size, \
                            mtime_unix_nanos, blocks_json, admitted_at_unix_nanos) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, '[]', ?7)",
        rusqlite::params![group_id, path, version_seq, state, deleted as i64, size, admitted_at],
    )
    .unwrap();
}

/// Records the group's local history floor the way its real writers do.
/// Direct SQL for the same reason `seed` is: both of them stamp the
/// wall clock and offer no way to choose the instant. Each real writer
/// is driven end to end by its own test elsewhere --
/// `local_history_floor_tests` in `enrollment` and in `link` for the two
/// link commits that can name a folder this device did not originate.
fn seed_local_history_floor(conn: &Connection, group_id: &str, floor_unix_nanos: i64) {
    conn.execute(
        "INSERT INTO group_local_history_floor (group_id, floor_unix_nanos) VALUES (?1, ?2)",
        rusqlite::params![group_id, floor_unix_nanos],
    )
    .unwrap();
}

/// Erases every row of `path` the way the ignore sweep does
/// (`FileIndexRepository::remove_file`): the rows go and the erasure is
/// recorded in the same step, at `at`. Direct SQL so the instants can be
/// chosen; `the_ignore_sweep_through_the_repository_...`
/// below drives the real repository method end to end.
fn erase_like_the_ignore_sweep(conn: &Connection, group_id: &str, path: &str, at: i64) {
    conn.execute(
        "DELETE FROM files WHERE group_id = ?1 AND path = ?2",
        rusqlite::params![group_id, path],
    )
    .unwrap();
    record_path_history_erased_at(conn, group_id, path, at).unwrap();
}

fn action_for<'a>(plan: &'a RewindPlan, path: &str) -> Option<&'a RewindPathAction> {
    plan.entries.iter().find(|e| e.path == path).map(|e| &e.action)
}

#[test]
fn a_path_untouched_since_the_target_reports_unchanged() {
    let c = conn();
    seed(&c, "g", "steady.txt", 1, "current", false, 10, Some(100));
    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    assert_eq!(action_for(&plan, "steady.txt"), Some(&RewindPathAction::Unchanged));
    assert_eq!(plan.action_counts().unchanged, 1);
}

#[test]
fn a_path_present_at_the_target_but_deleted_since_reports_create() {
    let c = conn();
    // v1 was live at T=500; v2 (the tombstone) came after.
    seed(&c, "g", "gone.txt", 1, "trashed", false, 10, Some(100));
    seed(&c, "g", "gone.txt", 2, "current", true, 0, Some(900));
    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    match action_for(&plan, "gone.txt") {
        Some(RewindPathAction::Create { version_seq, .. }) => assert_eq!(*version_seq, 1),
        other => panic!("expected Create, got {other:?}"),
    }
}

#[test]
fn a_path_created_after_the_target_reports_delete() {
    let c = conn();
    seed(&c, "g", "new.txt", 1, "current", false, 10, Some(900));
    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    assert_eq!(action_for(&plan, "new.txt"), Some(&RewindPathAction::Delete));
}

#[test]
fn a_path_edited_after_the_target_reports_replace() {
    let c = conn();
    seed(&c, "g", "edited.txt", 1, "superseded", false, 10, Some(100));
    seed(&c, "g", "edited.txt", 2, "current", false, 20, Some(900));
    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    match action_for(&plan, "edited.txt") {
        Some(RewindPathAction::Replace { to_version_seq, .. }) => {
            assert_eq!(*to_version_seq, 1);
        }
        other => panic!("expected Replace, got {other:?}"),
    }
}

/// Content, not `version_seq`, decides `Replace` vs `Unchanged`: a file
/// edited and then edited back has a higher `version_seq` but nothing
/// for a rewind to actually do.
#[test]
fn content_edited_back_to_its_earlier_bytes_reports_unchanged_not_replace() {
    let c = conn();
    seed(&c, "g", "roundtrip.txt", 1, "superseded", false, 10, Some(100));
    seed(&c, "g", "roundtrip.txt", 2, "superseded", false, 20, Some(700));
    seed(&c, "g", "roundtrip.txt", 3, "current", false, 10, Some(900));
    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    assert_eq!(action_for(&plan, "roundtrip.txt"), Some(&RewindPathAction::Unchanged));
}

#[test]
fn matching_content_across_a_create_and_delete_pair_is_reported_as_a_rename() {
    let c = conn();
    // At T=500 the content (size 42) lived at old/name.txt. Afterwards
    // it was moved to new/name.txt: the old path was tombstoned and the
    // new one created.
    seed(&c, "g", "old/name.txt", 1, "trashed", false, 42, Some(100));
    seed(&c, "g", "old/name.txt", 2, "current", true, 0, Some(900));
    seed(&c, "g", "new/name.txt", 1, "current", false, 42, Some(900));

    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    // The authoritative per-path entries stand on their own.
    assert!(matches!(action_for(&plan, "old/name.txt"), Some(RewindPathAction::Create { .. })));
    assert_eq!(action_for(&plan, "new/name.txt"), Some(&RewindPathAction::Delete));
    // ... and the auxiliary annotation names the pairing.
    assert_eq!(plan.rename_candidates.len(), 1);
    assert_eq!(plan.rename_candidates[0].from_path, "new/name.txt");
    assert_eq!(plan.rename_candidates[0].to_path, "old/name.txt");
}

/// A coincidental identical-content match on more than one path is
/// ambiguous. The guess is dropped; the per-path verdicts are not.
#[test]
fn ambiguous_identical_content_produces_no_rename_guess_but_keeps_per_path_verdicts() {
    let c = conn();
    seed(&c, "g", "old.txt", 1, "trashed", false, 42, Some(100));
    seed(&c, "g", "old.txt", 2, "current", true, 0, Some(900));
    seed(&c, "g", "copy-a.txt", 1, "current", false, 42, Some(900));
    seed(&c, "g", "copy-b.txt", 1, "current", false, 42, Some(900));

    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    assert!(plan.rename_candidates.is_empty(), "an ambiguous match must not be guessed at");
    assert!(matches!(action_for(&plan, "old.txt"), Some(RewindPathAction::Create { .. })));
    assert_eq!(action_for(&plan, "copy-a.txt"), Some(&RewindPathAction::Delete));
    assert_eq!(action_for(&plan, "copy-b.txt"), Some(&RewindPathAction::Delete));
}

/// The retention sweep deletes expired `superseded`/`trashed` index
/// rows outright, so a path whose history at T is gone has a surviving
/// floor above `version_seq` 1. That must read as "no answer", never as
/// "nothing to do" and never as the closest version still on hand.
#[test]
fn history_expired_by_retention_reports_unavailable_rather_than_guessing() {
    let c = conn();
    // Versions 1..=4 existed; retention already deleted 1..=3. What was
    // current at T=500 was one of the deleted ones.
    seed(&c, "g", "long-lived.txt", 4, "superseded", false, 40, Some(800));
    seed(&c, "g", "long-lived.txt", 5, "current", false, 50, Some(900));
    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    match action_for(&plan, "long-lived.txt") {
        Some(RewindPathAction::Unavailable { reason }) => {
            assert_eq!(*reason, RewindUnavailableReason::RemovedByRetention);
            assert_eq!(reason.message(), "older versions were removed by retention");
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
    let counts = plan.action_counts();
    assert_eq!(counts.unavailable, 1);
    assert_eq!(counts.unchanged, 0, "an unanswerable path must never be tallied as unchanged");
}

/// A row carrying no admission timestamp at all (a database whose
/// first-ever schema init crashed before the column was added, the one
/// stale shape the version gate accepts) is equally unanswerable.
#[test]
fn a_row_with_no_admission_timestamp_reports_unavailable() {
    let c = conn();
    seed(&c, "g", "unstamped.txt", 1, "current", false, 10, None);
    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    match action_for(&plan, "unstamped.txt") {
        Some(RewindPathAction::Unavailable { reason }) => {
            assert_eq!(*reason, RewindUnavailableReason::NoAdmissionTime);
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

/// The `version_seq DESC` tie-break, on its own. Two rows for one path
/// sharing an `admitted_at_unix_nanos` is not a corner case: a
/// coarse clock can stamp two ordinary writes with the same instant. The "at T"
/// side must resolve such a tie to the highest `version_seq` -- the
/// path's current row -- or the plan reports a rollback that is not
/// real.
#[test]
fn an_admission_timestamp_tie_resolves_to_the_highest_version_seq() {
    let c = conn();
    // Different `size`, so the two rows have different `version_hash`es
    // and a wrong pick shows up as a verdict, not just a number.
    seed(&c, "g", "tied.txt", 1, "superseded", false, 10, Some(100));
    seed(&c, "g", "tied.txt", 2, "current", false, 20, Some(100));
    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    assert_eq!(
        action_for(&plan, "tied.txt"),
        Some(&RewindPathAction::Unchanged),
        "a tie must resolve to the current row; picking the superseded one would report a \
         rollback that never happened"
    );
}

#[test]
fn a_group_with_no_history_before_the_target_reports_every_live_path_as_delete() {
    let c = conn();
    seed(&c, "g", "a.txt", 1, "current", false, 10, Some(900));
    seed(&c, "g", "b.txt", 1, "current", false, 20, Some(901));
    // A path already tombstoned before the target existed at all is
    // absent on both sides -- nothing to do, not a delete.
    seed(&c, "g", "c.txt", 1, "trashed", false, 30, Some(902));
    seed(&c, "g", "c.txt", 2, "current", true, 0, Some(903));

    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    assert_eq!(action_for(&plan, "a.txt"), Some(&RewindPathAction::Delete));
    assert_eq!(action_for(&plan, "b.txt"), Some(&RewindPathAction::Delete));
    assert_eq!(action_for(&plan, "c.txt"), Some(&RewindPathAction::Unchanged));
    let counts = plan.action_counts();
    assert_eq!(counts.delete, 2);
    assert_eq!(counts.unavailable, 0, "'created after T' is a real answer, not a gap");
}

/// The `min_version_seq <= 1` reading -- "this path's first version was
/// admitted after T, so at T it did not exist here" -- is only sound
/// while `version_seq` is this device's own admission history. Joining
/// an existing group ends that: every file the group already held arrives
/// as `version_seq = 1`, however old. Below the
/// recorded floor, that must read as "no answer here", not as "created
/// after T".
#[test]
fn below_the_local_history_floor_an_unmodified_path_is_unavailable_not_delete() {
    let c = conn();
    seed_local_history_floor(&c, "g", 1_000);
    // A never-edited file that arrived at version 1.
    seed(&c, "g", "unmodified.txt", 1, "current", false, 10, Some(1_000));

    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    match action_for(&plan, "unmodified.txt") {
        Some(RewindPathAction::Unavailable { reason }) => {
            // Never retention below the floor: the cause is the join, and
            // the person is told where the history is.
            assert_eq!(*reason, RewindUnavailableReason::JoinedAfter);
            assert!(reason.message().contains("from a device that has the history"));
        }
        other => panic!("expected Unavailable below the floor, got {other:?}"),
    }
    assert_eq!(plan.action_counts().delete, 0);
}

/// The other half of the same boundary, which is what keeps the fix from
/// being a blanket "never answer in a joined group": at or above the
/// floor the group's local history IS this device's own unbroken record,
/// so the ordinary classifications still apply -- including the
/// `version_seq = 1` inference the floor suspends below it.
#[test]
fn at_or_after_the_local_history_floor_paths_are_classified_normally() {
    let c = conn();
    seed_local_history_floor(&c, "g", 1_000);
    // Carried in by the join itself.
    seed(&c, "g", "unmodified.txt", 1, "current", false, 10, Some(1_000));
    // Written locally afterwards, so its version 1 really is this
    // device's own first admission of the path.
    seed(&c, "g", "created-later.txt", 1, "current", false, 20, Some(2_000));

    let plan = compute_rewind_plan(&c, "g", 1_500, &|_| false).unwrap();
    assert_eq!(
        action_for(&plan, "unmodified.txt"),
        Some(&RewindPathAction::Unchanged),
        "a path whose arrived row is at or before the target is ordinary evidence"
    );
    assert_eq!(
        action_for(&plan, "created-later.txt"),
        Some(&RewindPathAction::Delete),
        "inside this device's own continuous history, 'first version admitted after T' is \
         still a real answer"
    );
    assert_eq!(plan.action_counts().unavailable, 0);
}

/// The floor is per group, like the plan itself. One group's
/// floor must not make another group's history unanswerable.
#[test]
fn the_local_history_floor_is_scoped_to_its_own_group() {
    let c = conn();
    seed_local_history_floor(&c, "floored", 1_000);
    seed(&c, "floored", "a.txt", 1, "current", false, 10, Some(1_000));
    seed(&c, "untouched", "b.txt", 1, "current", false, 10, Some(1_000));

    assert!(matches!(
        action_for(&compute_rewind_plan(&c, "floored", 500, &|_| false).unwrap(), "a.txt"),
        Some(RewindPathAction::Unavailable { .. })
    ));
    assert_eq!(
        action_for(&compute_rewind_plan(&c, "untouched", 500, &|_| false).unwrap(), "b.txt"),
        Some(&RewindPathAction::Delete),
        "a group that never joined late keeps the ordinary inference"
    );
}

/// A path this device has never indexed is absent from the plan
/// entirely -- documented behavior, not a bug. Modelled here as another
/// group's path, which is the same situation from this query's point of
/// view and doubles as the group-scoping check.
#[test]
fn paths_this_device_never_indexed_for_this_group_are_absent_from_the_plan() {
    let c = conn();
    seed(&c, "g", "mine.txt", 1, "current", false, 10, Some(100));
    seed(&c, "other", "theirs.txt", 1, "current", false, 10, Some(100));
    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    assert_eq!(plan.entries.len(), 1);
    assert_eq!(plan.entries[0].path, "mine.txt");
    assert!(action_for(&plan, "theirs.txt").is_none());
}

#[test]
fn an_empty_group_produces_an_empty_plan_rather_than_an_error() {
    let c = conn();
    let plan = compute_rewind_plan(&c, "never-seen", 500, &|_| false).unwrap();
    assert!(plan.entries.is_empty());
    assert!(plan.rename_candidates.is_empty());
    assert_eq!(plan.group_id, "never-seen");
    assert_eq!(plan.target_unix_nanos, 500);
}

/// The `version_seq = 0` metadata-scaffold writers are NOT
/// `upsert_file_in_tx`, and they insert a real `files` row. They have to
/// stamp it too or the whole path reads as unanswerable until the next
/// real write to it -- see `file_index::upsert_file_in_tx`'s "stamping
/// invariant" section. Both variants are checked, because they are two
/// separate copies of the same statement.
#[test]
fn the_metadata_bootstrap_scaffold_writers_stamp_too() {
    let before =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            as i64;

    // In-transaction variant, called directly.
    let mut c = conn();
    {
        let tx = c.transaction().unwrap();
        crate::file_index::ensure_bootstrap_row_for_metadata_in_tx(&tx, "g", "scaffold.txt")
            .unwrap();
        tx.commit().unwrap();
    }

    // Pooled-connection variant, through the repository.
    let db = std::sync::Arc::new(
        yadorilink_sqlite_runtime::SyncDatabase::open_in_memory(|conn| {
            crate::replica_tables::init_for_tests(conn).map_err(|error| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(error.to_string())
            })?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .unwrap(),
    );
    crate::file_index::FileIndexRepository::new(db.clone())
        .ensure_bootstrap_row_for_metadata("g", "scaffold.txt")
        .unwrap();

    let read = |conn: &Connection| -> Option<i64> {
        conn.query_row(
            "SELECT admitted_at_unix_nanos FROM files \
             WHERE group_id = 'g' AND path = 'scaffold.txt'",
            [],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert!(
        read(&c).is_some_and(|stamp| stamp >= before),
        "the in-transaction scaffold writer must stamp the local clock"
    );
    assert!(
        db.read::<_, SyncSqliteError>(|conn| Ok(read(conn)))
            .unwrap()
            .is_some_and(|stamp| stamp >= before),
        "the pooled-connection scaffold writer must stamp the local clock"
    );

    // The consequence that actually matters: the path is answerable.
    let plan = compute_rewind_plan(&c, "g", i64::MAX, &|_| false).unwrap();
    assert_eq!(
        action_for(&plan, "scaffold.txt"),
        Some(&RewindPathAction::Unchanged),
        "an unstamped scaffold row would make this path unanswerable instead"
    );
}

/// The production write path stamps the column from this device's own
/// clock, on every branch, with no caller involvement -- the property
/// the whole planning layer rests on.
#[test]
fn stamps_the_local_admission_clock_at_the_write_chokepoint() {
    let mut c = conn();
    let before =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            as i64;

    let record = |path: &str, size: u64, deleted: bool| FileRecord {
        path: path.to_string(),
        size,
        mtime_unix_nanos: 0,
        blocks: Vec::new(),
        deleted,
    };
    {
        let tx = c.transaction().unwrap();
        // Branch 1: brand-new path.
        crate::file_index::upsert_file_in_tx(&tx, "g", &record("f.txt", 1, false), "").unwrap();
        // Branch 3: version bump over an existing current row.
        crate::file_index::upsert_file_in_tx(&tx, "g", &record("f.txt", 2, false), "").unwrap();
        tx.commit().unwrap();
    }
    {
        let tx = c.transaction().unwrap();
        // Branch 2: promotion of a `version_seq = 0` bootstrap scaffold.
        tx.execute(
            "INSERT INTO files (group_id, path, version_seq, state, deleted, size, \
                                mtime_unix_nanos, blocks_json) \
             VALUES ('g', 'scaffold.txt', 0, 'current', 0, 0, 0, '[]')",
            [],
        )
        .unwrap();
        crate::file_index::upsert_file_in_tx(&tx, "g", &record("scaffold.txt", 3, false), "")
            .unwrap();
        tx.commit().unwrap();
    }

    let stamped: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM files WHERE group_id = 'g' \
             AND admitted_at_unix_nanos IS NOT NULL AND admitted_at_unix_nanos >= ?1",
            rusqlite::params![before],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stamped, 3, "every row all three branches wrote must carry a local stamp");
    // Never the replicated filesystem timestamp: every record above has
    // `mtime_unix_nanos = 0`, so a stamp derived from it would be 0.
    let from_mtime: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM files WHERE group_id = 'g' AND admitted_at_unix_nanos = 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(from_mtime, 0, "the stamp must not come from the record's own mtime");
}

/// Supersedes `path`'s `current` row and writes `version_seq` as the new
/// one -- the supersede-then-insert pair `upsert_file_in_tx` performs, with
/// the admission instant chosen by the test (see `seed`).
#[allow(clippy::too_many_arguments)]
fn write_new_current(
    conn: &Connection,
    group_id: &str,
    path: &str,
    version_seq: i64,
    deleted: bool,
    size: i64,
    admitted_at: i64,
) {
    conn.execute(
        "UPDATE files SET state = 'superseded' \
         WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
        rusqlite::params![group_id, path],
    )
    .unwrap();
    seed(conn, group_id, path, version_seq, "current", deleted, size, Some(admitted_at));
}

/// One path of each actionable kind plus an untouched one, all at T=500.
fn seed_plan_identity_folder(c: &Connection) {
    seed(c, "g", "steady.txt", 1, "current", false, 10, Some(100));
    seed(c, "g", "edited.txt", 1, "superseded", false, 10, Some(100));
    seed(c, "g", "edited.txt", 2, "current", false, 20, Some(900));
    seed(c, "g", "gone.txt", 1, "trashed", false, 30, Some(100));
    seed(c, "g", "gone.txt", 2, "current", true, 0, Some(900));
    seed(c, "g", "new.txt", 1, "current", false, 40, Some(900));
}

fn plan_id_now(c: &Connection) -> yadorilink_replica_domain::rewind::RewindPlanId {
    compute_rewind_plan(c, "g", 500, &|_| false).unwrap().plan_id()
}

#[test]
fn recomputing_the_plan_of_an_unchanged_index_gives_the_same_plan_id() {
    let c = conn();
    seed_plan_identity_folder(&c);
    let first = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    let second = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    assert_eq!(first.action_counts().unchanged, 1);
    assert_eq!(first.action_counts().create + first.action_counts().delete, 2);
    assert_eq!(first.plan_id(), second.plan_id());
}

/// The path a preview reported as untouched is edited afterwards: the
/// plan now has to roll it back too, which nobody approved.
#[test]
fn editing_an_untouched_path_after_the_preview_changes_the_plan_id() {
    let c = conn();
    seed_plan_identity_folder(&c);
    let previewed = plan_id_now(&c);
    write_new_current(&c, "g", "steady.txt", 2, false, 11, 1_000);
    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    assert!(matches!(action_for(&plan, "steady.txt"), Some(RewindPathAction::Replace { .. })));
    assert_ne!(plan.plan_id(), previewed);
}

/// A path the preview would delete is edited afterwards. Its action is
/// still `Delete`, so only the current version tells the two plans apart
/// -- and executing the old one would delete an edit nobody saw.
#[test]
fn editing_a_delete_target_after_the_preview_changes_the_plan_id() {
    let c = conn();
    seed_plan_identity_folder(&c);
    let previewed = plan_id_now(&c);
    write_new_current(&c, "g", "new.txt", 2, false, 41, 1_000);
    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    assert_eq!(action_for(&plan, "new.txt"), Some(&RewindPathAction::Delete));
    assert_ne!(plan.plan_id(), previewed);
}

/// Same for a path the preview would bring back: it is re-created and
/// deleted again, and its action is `Create` before and after.
#[test]
fn deleting_a_create_target_again_after_the_preview_changes_the_plan_id() {
    let c = conn();
    seed_plan_identity_folder(&c);
    let previewed = plan_id_now(&c);
    write_new_current(&c, "g", "gone.txt", 3, false, 31, 1_000);
    write_new_current(&c, "g", "gone.txt", 4, true, 0, 1_100);
    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    assert!(matches!(action_for(&plan, "gone.txt"), Some(RewindPathAction::Create { .. })));
    assert_ne!(plan.plan_id(), previewed);
}

/// A path that was dropped from the index (it became ignored) and indexed
/// again is dropped and re-indexed once more, with other content, after the
/// preview. Its numbering restarts each time, so its current row has the
/// same `version_seq` as the one the preview saw and its verdict is
/// `Unavailable` both times; only the content tells the two plans apart.
#[test]
fn a_reindexed_path_with_a_reused_seq_changes_the_plan_id() {
    let c = conn();
    seed_plan_identity_folder(&c);
    erase_like_the_ignore_sweep(&c, "g", "new.txt", 800);
    seed(&c, "g", "new.txt", 1, "current", false, 40, Some(900));
    let previewed = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    erase_like_the_ignore_sweep(&c, "g", "new.txt", 950);
    seed(&c, "g", "new.txt", 1, "current", false, 41, Some(1_000));
    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    let entry = plan.entries.iter().find(|e| e.path == "new.txt").unwrap();
    assert!(matches!(entry.action, RewindPathAction::Unavailable { .. }));
    assert_eq!(action_for(&previewed, "new.txt"), Some(&entry.action));
    assert_eq!(entry.current_version_seq, 1, "the seq is reused");
    assert_ne!(plan.plan_id(), previewed.plan_id());
}

#[test]
fn a_path_created_after_the_preview_changes_the_plan_id() {
    let c = conn();
    seed_plan_identity_folder(&c);
    let previewed = plan_id_now(&c);
    seed(&c, "g", "newer.txt", 1, "current", false, 50, Some(1_000));
    assert_ne!(plan_id_now(&c), previewed);
}

/// Retention expires the version a `Replace` would restore: the path
/// becomes unanswerable and the approved plan no longer exists.
#[test]
fn retention_expiring_a_restore_source_changes_the_plan_id() {
    let c = conn();
    seed_plan_identity_folder(&c);
    let previewed = plan_id_now(&c);
    c.execute(
        "DELETE FROM files WHERE group_id = 'g' AND path = 'edited.txt' AND version_seq = 1",
        [],
    )
    .unwrap();
    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    assert!(matches!(action_for(&plan, "edited.txt"), Some(RewindPathAction::Unavailable { .. })));
    assert_ne!(plan.plan_id(), previewed);
}

/// Writes that leave every verdict as it was do not invalidate an
/// approval: an untouched path edited and then edited back to the content
/// it had at the target is still `Unchanged`, and nothing would act on it.
#[test]
fn an_edit_that_ends_with_the_content_it_had_at_the_target_keeps_the_plan_id() {
    let c = conn();
    seed_plan_identity_folder(&c);
    let previewed = plan_id_now(&c);
    write_new_current(&c, "g", "steady.txt", 2, false, 11, 1_000);
    write_new_current(&c, "g", "steady.txt", 3, false, 10, 1_100);
    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    assert_eq!(action_for(&plan, "steady.txt"), Some(&RewindPathAction::Unchanged));
    assert_eq!(plan.plan_id(), previewed);
}

/// The target is part of the identity even where the verdicts agree, so a
/// relative `--at` resolved against a later `now` never validates a plan
/// shown for an earlier one.
#[test]
fn a_different_target_with_identical_verdicts_has_a_different_plan_id() {
    let c = conn();
    seed_plan_identity_folder(&c);
    let at_500 = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    let at_501 = compute_rewind_plan(&c, "g", 501, &|_| false).unwrap();
    assert_eq!(at_500.entries, at_501.entries);
    assert_ne!(at_500.plan_id(), at_501.plan_id());
}

/// A file that existed at the target, was then ignored (its rows erased)
/// and un-ignored (re-indexed from `version_seq = 1`). Its only rows are
/// now admitted after the target, which without the erasure record reads
/// as "created after the target" -- a `Delete` of a file that existed then.
#[test]
fn a_path_ignored_and_unignored_after_the_target_is_unavailable_not_delete() {
    let c = conn();
    seed(&c, "g", "kept.txt", 1, "superseded", false, 10, Some(100));
    seed(&c, "g", "kept.txt", 2, "current", false, 20, Some(300));
    erase_like_the_ignore_sweep(&c, "g", "kept.txt", 800);
    seed(&c, "g", "kept.txt", 1, "current", false, 20, Some(900));

    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    match action_for(&plan, "kept.txt") {
        Some(RewindPathAction::Unavailable { reason }) => {
            assert_eq!(*reason, RewindUnavailableReason::ExcludedFromSync);
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
    let counts = plan.action_counts();
    assert_eq!((counts.delete, counts.unavailable), (0, 1));
}

/// The same erased path, now deleted: absent now, and unknown at the
/// target. "Absent both sides" would be a guess; it may have been live then.
#[test]
fn an_erased_path_deleted_since_is_unavailable_not_unchanged() {
    let c = conn();
    seed(&c, "g", "kept.txt", 1, "current", false, 10, Some(100));
    erase_like_the_ignore_sweep(&c, "g", "kept.txt", 800);
    seed(&c, "g", "kept.txt", 1, "trashed", false, 10, Some(900));
    seed(&c, "g", "kept.txt", 2, "current", true, 0, Some(950));
    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    assert!(matches!(action_for(&plan, "kept.txt"), Some(RewindPathAction::Unavailable { .. })));
}

/// A target while the path was ignored (erased, not yet re-indexed) is
/// unknown as well: this device had no index entry for it then.
#[test]
fn a_target_while_the_path_was_ignored_is_unavailable() {
    let c = conn();
    seed(&c, "g", "kept.txt", 1, "current", false, 10, Some(100));
    erase_like_the_ignore_sweep(&c, "g", "kept.txt", 600);
    seed(&c, "g", "kept.txt", 1, "current", false, 10, Some(900));
    let plan = compute_rewind_plan(&c, "g", 700, &|_| false).unwrap();
    assert!(matches!(action_for(&plan, "kept.txt"), Some(RewindPathAction::Unavailable { .. })));
}

/// After the re-index the path's rows are this device's own stamped
/// history again: a target inside it is answered normally, edits and all.
#[test]
fn a_target_after_the_reindex_is_classified_normally() {
    let c = conn();
    seed(&c, "g", "kept.txt", 1, "current", false, 10, Some(100));
    erase_like_the_ignore_sweep(&c, "g", "kept.txt", 800);
    seed(&c, "g", "kept.txt", 1, "superseded", false, 10, Some(900));
    seed(&c, "g", "kept.txt", 2, "current", false, 20, Some(1_100));
    assert!(matches!(
        action_for(&compute_rewind_plan(&c, "g", 950, &|_| false).unwrap(), "kept.txt"),
        Some(RewindPathAction::Replace { to_version_seq: 1, .. })
    ));
    assert_eq!(
        action_for(&compute_rewind_plan(&c, "g", 1_200, &|_| false).unwrap(), "kept.txt"),
        Some(&RewindPathAction::Unchanged)
    );
}

/// The record is per path and per group: another path of the same group,
/// and the same path in another group, keep the ordinary inference -- and
/// so the plan, and its id, of a group with no erasure is what it was.
#[test]
fn an_erasure_record_leaves_other_paths_and_groups_alone() {
    let c = conn();
    seed(&c, "g", "erased.txt", 1, "current", false, 10, Some(100));
    seed(&c, "g", "new.txt", 1, "current", false, 20, Some(900));
    seed(&c, "other", "erased.txt", 1, "current", false, 10, Some(900));
    let other_before = compute_rewind_plan(&c, "other", 500, &|_| false).unwrap();

    erase_like_the_ignore_sweep(&c, "g", "erased.txt", 800);
    seed(&c, "g", "erased.txt", 1, "current", false, 10, Some(900));

    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    assert!(matches!(action_for(&plan, "erased.txt"), Some(RewindPathAction::Unavailable { .. })));
    assert_eq!(action_for(&plan, "new.txt"), Some(&RewindPathAction::Delete));
    let other = compute_rewind_plan(&c, "other", 500, &|_| false).unwrap();
    assert_eq!(action_for(&other, "erased.txt"), Some(&RewindPathAction::Delete));
    assert_eq!(other.plan_id(), other_before.plan_id());
}

/// The real write path: index a file, erase it through the repository the
/// way the ignore sweep does, re-index it. A target at the file's first
/// admission must not plan its deletion.
#[test]
fn the_ignore_sweep_through_the_repository_makes_earlier_targets_unavailable() {
    let db = std::sync::Arc::new(
        yadorilink_sqlite_runtime::SyncDatabase::open_in_memory(|conn| {
            crate::replica_tables::init_for_tests(conn).map_err(|error| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(error.to_string())
            })?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .unwrap(),
    );
    let repo = crate::file_index::FileIndexRepository::new(db.clone());
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let record = FileRecord {
        path: "kept.txt".to_string(),
        size: 10,
        mtime_unix_nanos: 0,
        blocks: Vec::new(),
        deleted: false,
    };
    let admitted_at = |db: &yadorilink_sqlite_runtime::SyncDatabase| -> i64 {
        db.read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT admitted_at_unix_nanos FROM files \
                 WHERE group_id = 'g' AND path = 'kept.txt' AND state = 'current'",
                [],
                |row| row.get(0),
            )?)
        })
        .unwrap()
    };

    repo.upsert_file("g", &record, &permit).unwrap();
    let target = admitted_at(&db);
    assert!(repo.remove_file("g", "kept.txt", &permit).unwrap());
    std::thread::sleep(std::time::Duration::from_millis(2));
    repo.upsert_file("g", &record, &permit).unwrap();
    assert!(admitted_at(&db) > target, "the re-index is admitted after the target");

    let plan = db
        .read::<_, SyncSqliteError>(|conn| compute_rewind_plan(conn, "g", target, &|_| false))
        .unwrap();
    let entry = plan.entries.iter().find(|e| e.path == "kept.txt").unwrap();
    assert_eq!(entry.current_version_seq, 1, "the re-index restarted the numbering");
    assert!(
        matches!(entry.action, RewindPathAction::Unavailable { .. }),
        "expected Unavailable, got {:?}",
        entry.action
    );
}

/// A file live at the target, erased by the ignore sweep afterwards and
/// never indexed again (un-ignored with nothing on disk, say): no `files`
/// row is left, but the rewind cannot say what it held then, so it is in
/// the plan as unavailable instead of silently missing.
#[test]
fn a_path_erased_after_the_target_and_not_reindexed_is_unavailable() {
    let c = conn();
    seed(&c, "g", "steady.txt", 1, "current", false, 20, Some(100));
    seed(&c, "g", "gone.txt", 1, "current", false, 10, Some(100));
    erase_like_the_ignore_sweep(&c, "g", "gone.txt", 800);

    let plan = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    let entry = plan.entries.iter().find(|e| e.path == "gone.txt").expect("in the plan");
    match &entry.action {
        RewindPathAction::Unavailable { reason } => {
            assert_eq!(*reason, RewindUnavailableReason::ExcludedFromSync);
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
    assert_eq!((entry.current_version_seq, entry.current_version_hash), (0, VersionHash([0; 32])));
    let paths: Vec<&str> = plan.entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths, ["gone.txt", "steady.txt"], "entries stay in path order");
    assert_eq!(plan.action_counts().unavailable, 1);
}

/// A path that is still excluded from sync stays outside the plan, as an
/// ignored path always is: ignoring a folder must not block every rewind to
/// before the ignore. The rest of the plan, and its id, are as if the path
/// had never been indexed.
#[test]
fn a_still_excluded_erased_path_is_not_in_the_plan() {
    let c = conn();
    seed(&c, "g", "steady.txt", 1, "current", false, 20, Some(100));
    seed(&c, "g", "new.txt", 1, "current", false, 30, Some(900));
    let before = compute_rewind_plan(&c, "g", 500, &|_| false).unwrap();
    seed(&c, "g", "ignored.txt", 1, "current", false, 10, Some(100));
    erase_like_the_ignore_sweep(&c, "g", "ignored.txt", 800);

    let plan = compute_rewind_plan(&c, "g", 500, &|path| path == "ignored.txt").unwrap();
    assert!(action_for(&plan, "ignored.txt").is_none());
    assert_eq!(plan.entries, before.entries);
    assert_eq!(plan.plan_id(), before.plan_id());
}

/// Erased at or before the target and not indexed since: no entry here
/// then, none now. Absent on both sides, so nothing to answer for.
#[test]
fn a_path_erased_before_the_target_and_not_reindexed_is_not_in_the_plan() {
    let c = conn();
    seed(&c, "g", "gone.txt", 1, "current", false, 10, Some(100));
    erase_like_the_ignore_sweep(&c, "g", "gone.txt", 400);
    for target in [400, 500] {
        let plan = compute_rewind_plan(&c, "g", target, &|_| false).unwrap();
        assert!(plan.entries.is_empty(), "target {target}: {:?}", plan.entries);
    }
}

/// The real write path: the repository's erasure with nothing indexed
/// again makes a target before it unavailable.
#[test]
fn the_ignore_sweep_through_the_repository_without_a_reindex_is_unavailable() {
    let db = std::sync::Arc::new(
        yadorilink_sqlite_runtime::SyncDatabase::open_in_memory(|conn| {
            crate::replica_tables::init_for_tests(conn).map_err(|error| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(error.to_string())
            })?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .unwrap(),
    );
    let repo = crate::file_index::FileIndexRepository::new(db.clone());
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let record = FileRecord {
        path: "gone.txt".to_string(),
        size: 10,
        mtime_unix_nanos: 0,
        blocks: Vec::new(),
        deleted: false,
    };
    repo.upsert_file("g", &record, &permit).unwrap();
    let target: i64 = db
        .read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT admitted_at_unix_nanos FROM files WHERE group_id = 'g'",
                [],
                |row| row.get(0),
            )?)
        })
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(2));
    assert!(repo.remove_file("g", "gone.txt", &permit).unwrap());

    let plan = db
        .read::<_, SyncSqliteError>(|conn| compute_rewind_plan(conn, "g", target, &|_| false))
        .unwrap();
    assert!(matches!(action_for(&plan, "gone.txt"), Some(RewindPathAction::Unavailable { .. })));
}

/// A clock that stepped back since the erased rows were admitted still
/// dates the erasure no earlier than the newest of them.
#[test]
fn an_erasure_is_never_dated_before_the_history_it_erased() {
    let c = conn();
    let future = i64::MAX / 2;
    record_path_history_erased(&c, "g", "p.txt", Some(future)).unwrap();
    let erased_at: i64 = c
        .query_row(
            "SELECT erased_at_unix_nanos FROM path_local_history_erased \
             WHERE group_id = 'g' AND path = 'p.txt'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(erased_at, future);
}

/// Retention ages a version from when it was superseded (its successor's
/// admission), not from its own admission: a version that stayed current for
/// longer than the age bound survives the sweep that follows its replacement
/// by a burst of quick edits, so a rewind to just before them is answerable.
#[test]
fn a_long_lived_version_is_not_expired_the_moment_a_burst_of_edits_replaces_it() {
    const DAY: i64 = 86_400 * 1_000_000_000;
    let c = conn();
    // v1 current for 40 days, then twelve quick edits at the end.
    seed(&c, "g", "doc.txt", 1, "superseded", false, 1, Some(0));
    for seq in 2..=13 {
        seed(&c, "g", "doc.txt", seq, "superseded", false, seq, Some(40 * DAY + seq));
    }
    seed(&c, "g", "doc.txt", 14, "current", false, 14, Some(40 * DAY + 14));

    let now = 41 * DAY;
    let expired = crate::file_index::expire_superseded_and_trashed_versions_in_tx(
        &c,
        "g",
        now,
        &Default::default(),
    )
    .unwrap();
    let kept: Vec<i64> = c
        .prepare("SELECT version_seq FROM files WHERE group_id = 'g' ORDER BY version_seq")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(expired, 0, "v1 was superseded 1 day ago; nothing is beyond the age bound");
    assert!(kept.contains(&1), "the long-lived version was expired at once: {kept:?}");

    // Once the supersession itself is older than the bound, it expires.
    let later = 40 * DAY + 14 + 31 * DAY;
    let expired = crate::file_index::expire_superseded_and_trashed_versions_in_tx(
        &c,
        "g",
        later,
        &Default::default(),
    )
    .unwrap();
    assert!(expired > 0);
    let left: i64 =
        c.query_row("SELECT COUNT(*) FROM files WHERE group_id = 'g'", [], |r| r.get(0)).unwrap();
    assert_eq!(left, 11, "ten newest superseded rows plus the current row remain");
}
