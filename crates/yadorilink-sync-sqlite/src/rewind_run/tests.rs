use std::sync::Arc;

use yadorilink_replica_domain::rewind::{RewindFailureKind, RewindPlanId, RewindRunState};
use yadorilink_sqlite_runtime::SyncDatabase;

use super::{RewindRunRepository, RewindRunStart};
use crate::error::SyncSqliteError;

const GROUP: &str = "g";
const PLAN: RewindPlanId = RewindPlanId([7u8; 32]);

fn open() -> (Arc<SyncDatabase>, RewindRunRepository) {
    let db = Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            crate::replica_tables::init_for_tests(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            crate::materialized_generation::init_materialized_generation_schema(conn).map_err(
                |e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()),
            )?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .expect("open in-memory db"),
    );
    let runs = RewindRunRepository::new(db.clone());
    (db, runs)
}

fn begin(runs: &RewindRunRepository, run_id: &str, group: &str) {
    assert_eq!(runs.begin_run(run_id, group, 500, &PLAN, 1).unwrap(), RewindRunStart::Started);
}

/// Puts a run where only the later execution stage can put it: committing,
/// with `chunks` chunks committed.
fn force_committing(db: &SyncDatabase, run_id: &str, chunks: i64) {
    db.write::<_, SyncSqliteError>(|conn| {
        Ok(conn.execute(
            "UPDATE rewind_runs SET state = 'committing', chunks_done = ?2 WHERE run_id = ?1",
            rusqlite::params![run_id, chunks],
        )?)
    })
    .unwrap();
}

fn state_of(
    runs: &RewindRunRepository,
    run_id: &str,
) -> (RewindRunState, Option<RewindFailureKind>) {
    let run = runs.get_run(run_id).unwrap().expect("run exists");
    (run.state, run.failure_kind)
}

#[test]
fn a_new_run_is_planned_and_reads_back_whole() {
    let (_db, runs) = open();
    begin(&runs, "r1", GROUP);
    let run = runs.get_run("r1").unwrap().unwrap();
    assert_eq!(run.group_id, GROUP);
    assert_eq!(run.target_unix_nanos, 500);
    assert_eq!(run.plan_id, PLAN);
    assert_eq!(run.state, RewindRunState::Planned);
    assert_eq!(run.chunks_done, 0);
    assert_eq!(run.failure_kind, None);
    assert_eq!(runs.latest_run(GROUP).unwrap(), Some(run));
}

/// A group has at most one unfinished run; another group is unaffected,
/// and an ended run no longer blocks the next one.
#[test]
fn a_second_unfinished_run_of_a_group_is_refused() {
    let (_db, runs) = open();
    begin(&runs, "r1", GROUP);
    assert_eq!(
        runs.begin_run("r2", GROUP, 500, &PLAN, 2).unwrap(),
        RewindRunStart::ActiveRunExists { run_id: "r1".into() }
    );
    assert_eq!(runs.get_run("r2").unwrap(), None, "nothing written for the refused run");
    begin(&runs, "other", "another-group");

    runs.mark_failed("r1", RewindFailureKind::Transient, 0, &[]).unwrap();
    begin(&runs, "r3", GROUP);
}

/// The durable index refuses a second unfinished row even if a writer
/// skipped the repository's own check.
#[test]
fn the_schema_itself_allows_one_unfinished_run_per_group() {
    let (db, runs) = open();
    begin(&runs, "r1", GROUP);
    let raw = db.write::<_, SyncSqliteError>(|conn| {
        Ok(conn.execute(
            "INSERT INTO rewind_runs (run_id, group_id, target_unix_nanos, plan_id, state, \
                                      created_at_unix_nanos) \
             VALUES ('r2', ?1, 1, x'00', 'prefetched', 1)",
            [GROUP],
        )?)
    });
    assert!(raw.is_err(), "a second unfinished run must violate the unique index");
}

#[test]
fn prefetch_then_failure_records_the_kind_and_count() {
    let (_db, runs) = open();
    begin(&runs, "r1", GROUP);
    runs.mark_prefetched("r1", 1).unwrap();
    assert_eq!(state_of(&runs, "r1"), (RewindRunState::Prefetched, None));
    assert!(runs.mark_prefetched("r1", 1).is_err(), "only a planned run becomes prefetched");

    begin(&runs, "r2", "g2");
    runs.mark_failed("r2", RewindFailureKind::ContentUnavailable, 3, &[]).unwrap();
    let run = runs.get_run("r2").unwrap().unwrap();
    assert_eq!(run.state, RewindRunState::Failed);
    assert_eq!(run.failure_kind, Some(RewindFailureKind::ContentUnavailable));
    assert_eq!(run.unavailable_files, 3);
    assert!(
        runs.mark_failed("r2", RewindFailureKind::Transient, 0, &[]).is_err(),
        "an ended run is not ended again"
    );
}

/// `failed` means zero mutations: a run that committed a chunk can never
/// be recorded as failed.
#[test]
fn a_run_that_committed_a_chunk_cannot_be_failed() {
    let (db, runs) = open();
    begin(&runs, "r1", GROUP);
    force_committing(&db, "r1", 1);
    assert!(runs.mark_failed("r1", RewindFailureKind::Transient, 0, &[]).is_err());
    assert_eq!(state_of(&runs, "r1").0, RewindRunState::Committing);
}

/// Startup recovery, decided from each row alone: a committed chunk means
/// `needs_replan`; anything unfinished without one means `failed` /
/// `interrupted`; ended runs are left exactly as they are.
#[test]
fn startup_settles_every_unfinished_run_from_its_row_alone() {
    let (db, runs) = open();
    begin(&runs, "planned", "g-planned");
    begin(&runs, "prefetched", "g-prefetched");
    runs.mark_prefetched("prefetched", 1).unwrap();
    begin(&runs, "committing-0", "g-c0");
    force_committing(&db, "committing-0", 0);
    begin(&runs, "committing-2", "g-c2");
    force_committing(&db, "committing-2", 2);
    begin(&runs, "content", "g-content");
    runs.mark_failed("content", RewindFailureKind::ContentUnavailable, 4, &[]).unwrap();
    begin(&runs, "done", "g-done");
    db.write::<_, SyncSqliteError>(|conn| {
        Ok(conn.execute(
            "UPDATE rewind_runs SET state = 'done', chunks_done = 3 WHERE run_id = 'done'",
            [],
        )?)
    })
    .unwrap();

    assert_eq!(runs.interrupt_unfinished_runs().unwrap(), 4);

    let interrupted = (RewindRunState::Failed, Some(RewindFailureKind::Interrupted));
    assert_eq!(state_of(&runs, "planned"), interrupted);
    assert_eq!(state_of(&runs, "prefetched"), interrupted);
    assert_eq!(state_of(&runs, "committing-0"), interrupted);
    assert_eq!(state_of(&runs, "committing-2"), (RewindRunState::NeedsReplan, None));
    assert_eq!(runs.get_run("committing-2").unwrap().unwrap().chunks_done, 2);
    assert_eq!(
        state_of(&runs, "content"),
        (RewindRunState::Failed, Some(RewindFailureKind::ContentUnavailable))
    );
    assert_eq!(runs.get_run("content").unwrap().unwrap().unavailable_files, 4);
    assert_eq!(state_of(&runs, "done"), (RewindRunState::Done, None));

    assert_eq!(runs.interrupt_unfinished_runs().unwrap(), 0, "settling is idempotent");
}

#[test]
fn interrupting_one_run_leaves_the_others_alone() {
    let (_db, runs) = open();
    begin(&runs, "r1", GROUP);
    begin(&runs, "r2", "g2");
    assert!(runs.interrupt_run("r1").unwrap());
    assert_eq!(
        state_of(&runs, "r1"),
        (RewindRunState::Failed, Some(RewindFailureKind::Interrupted))
    );
    assert_eq!(state_of(&runs, "r2"), (RewindRunState::Planned, None));
    assert!(!runs.interrupt_run("r1").unwrap(), "an ended run is left as it is");
}
