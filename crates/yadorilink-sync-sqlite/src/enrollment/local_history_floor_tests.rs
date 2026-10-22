#![cfg(test)]

use super::*;
use crate::rewind_plan::compute_rewind_plan;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::rewind::RewindPathAction;

const DEVICE: &str = "device-1";
const GROUP: &str = "group-1";
const LOCAL_PATH: &str = "/folders/shared";
/// The distance a preview like `--at 30d` asks about.
const THIRTY_DAYS_NANOS: i64 = 30 * 24 * 60 * 60 * 1_000_000_000;

/// Full schema, pooled exactly as production opens it -- the replica
/// tables first, then `yadorilink_sqlite_runtime::init_schema`.
fn open_full_test_db() -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            crate::replica_tables::init_for_tests(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .expect("open in-memory db"),
    )
}

/// Walks an enrollment through the real journal states and commits its
/// link through the real production entry point -- the same call the
/// daemon's own link adapter makes for both `share create` and
/// `share join`. Nothing here reaches around
/// [`EnrollmentRepository::add_link_with_pending_enrollment_and_begin_setup`].
fn commit_link_through_enrollment(db: &Arc<SyncDatabase>, kind: EnrollmentKind) {
    let repository = EnrollmentRepository::new(db.clone());
    let operation_id = "operation-1";
    assert!(
        repository
            .try_insert_enrollment_operation(&EnrollmentOperation {
                operation_id: operation_id.to_string(),
                kind,
                group_id: Some(GROUP.to_string()),
                // Required of a `Create` row while it is still
                // `PreparePending`, and meaningless for a `Join`.
                group_name: matches!(kind, EnrollmentKind::Create).then(|| "Shared".to_string()),
                device_id: DEVICE.to_string(),
                local_path: LOCAL_PATH.to_string(),
                storage_mode: "eager".to_string(),
                state: EnrollmentOperationState::PreparePending,
                last_error: None,
                attempts: 0,
                created_at_unix: 0,
                updated_at_unix: 0,
            })
            .unwrap(),
        "the journal row must be inserted"
    );
    assert!(
        repository.mark_enrollment_operation_prepared(operation_id, GROUP, 1).unwrap(),
        "prepare must advance the row, or the commit below would refuse it"
    );
    repository
        .add_link_with_pending_enrollment_and_begin_setup(
            LOCAL_PATH,
            GROUP,
            &PendingEnrollment {
                operation_id: operation_id.to_string(),
                kind,
                group_id: GROUP.to_string(),
                device_id: DEVICE.to_string(),
                local_path: LOCAL_PATH.to_string(),
            },
            2,
            None,
        )
        .expect("the link commit must succeed");
}

/// Admits one file through the real file-index write chokepoint, the
/// way an incoming change from a peer does. `origin_device_id` is
/// another device precisely because this models a file the GROUP
/// already had -- but the row it produces still carries
/// `version_seq = 1`, which is the whole problem.
fn admit_file(db: &Arc<SyncDatabase>, path: &str, size: u64) {
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        crate::file_index::upsert_file_in_tx(
            tx,
            GROUP,
            &FileRecord {
                path: path.to_string(),
                size,
                mtime_unix_nanos: 0,
                blocks: Vec::new(),
                deleted: false,
            },
            "device-that-was-here-first",
        )
    })
    .expect("the file admission must succeed");
}

fn action_at(db: &Arc<SyncDatabase>, at_unix_nanos: i64, path: &str) -> RewindPathAction {
    db.read::<_, SyncSqliteError>(|conn| {
        compute_rewind_plan(conn, GROUP, at_unix_nanos, &|_| false)
    })
    .unwrap()
    .entries
    .into_iter()
    .find(|entry| entry.path == path)
    .unwrap_or_else(|| panic!("{path} must appear in the plan"))
    .action
}

fn recorded_floor(db: &Arc<SyncDatabase>) -> Option<i64> {
    db.read::<_, SyncSqliteError>(|conn| {
        Ok(conn
            .query_row(
                "SELECT floor_unix_nanos FROM group_local_history_floor WHERE group_id = ?1",
                [GROUP],
                |row| row.get(0),
            )
            .optional()?)
    })
    .unwrap()
}

/// The headline case. A file the group already held when this device
/// joined must not be reported as something a rewind would delete.
#[test]
fn a_file_inherited_at_a_join_is_unavailable_before_the_join_not_delete() {
    let db = open_full_test_db();
    let before_join = crate::file_index::now_unix_nanos_checked().unwrap();
    commit_link_through_enrollment(&db, EnrollmentKind::Join);
    // Everything the group already held syncs in after the join.
    for path in ["notes.txt", "photos/trip.jpg", "budget.csv"] {
        admit_file(&db, path, 10);
    }

    // The observable verdict first, so a regression reports what the
    // user would actually be shown rather than a missing table row.
    let a_month_ago = before_join - THIRTY_DAYS_NANOS;
    let plan = db
        .read::<_, SyncSqliteError>(|conn| {
            compute_rewind_plan(conn, GROUP, a_month_ago, &|_| false)
        })
        .unwrap();
    let counts = plan.action_counts();
    assert_eq!(
        counts.delete, 0,
        "a folder this device inherited was not created since the target, so a preview must \
         not offer to delete it: {counts:?}"
    );
    assert_eq!(
        counts.unavailable, 3,
        "every inherited path is unanswerable this far back, and `unavailable = 0` is what \
         suppresses a renderer's own hedge: {counts:?}"
    );

    match action_at(&db, a_month_ago, "notes.txt") {
        // The join, never retention: naming retention below the floor would
        // be a confident wrong explanation.
        RewindPathAction::Unavailable { reason } => assert_eq!(
            reason,
            yadorilink_replica_domain::rewind::RewindUnavailableReason::JoinedAfter
        ),
        other => panic!("expected Unavailable before the join, got {other:?}"),
    }

    let floor = recorded_floor(&db).expect("a join must record this group's history floor");
    assert!(floor >= before_join, "the floor must be the join instant, not something earlier");
}

/// The other half of the same boundary: the floor must not turn a
/// joined device into one that can never answer anything. At the floor
/// itself, and above it, ordinary classification resumes -- including
/// the `version_seq = 1` reading the floor suspends below itself.
#[test]
fn at_or_after_the_join_floor_paths_are_classified_normally() {
    let db = open_full_test_db();
    commit_link_through_enrollment(&db, EnrollmentKind::Join);
    admit_file(&db, "notes.txt", 10);
    let floor = recorded_floor(&db).expect("a join must record this group's history floor");

    assert_eq!(
        action_at(&db, floor, "notes.txt"),
        RewindPathAction::Delete,
        "at the floor the group's history is this device's own again, and this row really \
         was admitted after the target"
    );
    assert_eq!(
        action_at(&db, i64::MAX, "notes.txt"),
        RewindPathAction::Unchanged,
        "a target after the row's own admission is answered from the row itself"
    );
}

/// The `Create` path must keep behaving exactly as it did. A folder
/// this device originated locally has no inherited history to guard
/// against: its `version_seq = 1` rows really are its own first
/// admissions, so a target before the folder existed is honestly
/// `Delete`, not `Unavailable`. This is the regression guard on the
/// fix's own blast radius.
#[test]
fn a_locally_created_folder_still_reports_delete_before_it_existed() {
    let db = open_full_test_db();
    let before_create = crate::file_index::now_unix_nanos_checked().unwrap();
    commit_link_through_enrollment(&db, EnrollmentKind::Create);
    admit_file(&db, "notes.txt", 10);

    assert_eq!(
        recorded_floor(&db),
        None,
        "creating a folder locally must record no history floor -- there is no inherited \
         history to bound"
    );
    assert_eq!(
        action_at(&db, before_create - THIRTY_DAYS_NANOS, "notes.txt"),
        RewindPathAction::Delete,
        "before this device created the folder, its files genuinely did not exist"
    );
}

/// The floor is per group. One device's join of one group must not make
/// another group -- one it created itself -- unanswerable.
#[test]
fn a_join_floor_is_scoped_to_the_group_that_was_joined() {
    let db = open_full_test_db();
    let before_join = crate::file_index::now_unix_nanos_checked().unwrap();
    commit_link_through_enrollment(&db, EnrollmentKind::Join);
    admit_file(&db, "inherited.txt", 10);
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        crate::file_index::upsert_file_in_tx(
            tx,
            "another-group",
            &FileRecord {
                path: "mine.txt".to_string(),
                size: 10,
                mtime_unix_nanos: 0,
                blocks: Vec::new(),
                deleted: false,
            },
            DEVICE,
        )
    })
    .unwrap();

    let a_month_ago = before_join - THIRTY_DAYS_NANOS;
    assert!(matches!(
        action_at(&db, a_month_ago, "inherited.txt"),
        RewindPathAction::Unavailable { .. }
    ));
    let other = db
        .read::<_, SyncSqliteError>(|conn| {
            compute_rewind_plan(conn, "another-group", a_month_ago, &|_| false)
        })
        .unwrap();
    assert_eq!(
        other.entries.iter().find(|e| e.path == "mine.txt").unwrap().action,
        RewindPathAction::Delete,
        "a group with no floor of its own keeps the ordinary inference"
    );
}
