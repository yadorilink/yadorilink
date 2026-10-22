#![cfg(test)]

use super::*;
use crate::link::LinkRepository;
use yadorilink_replica_domain::session_state::MaterializationPolicy;

const DEVICE: &str = "device-1";
const GROUP: &str = "group-1";
const LOCAL_PATH: &str = "/folders/shared";
const OPERATION: &str = "operation-1";

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

/// Opens a `Join` journal row, prepares it, and commits its link through
/// the real production entry point, leaving the row `LocalSetupPending` --
/// the state a daemon that crashed mid-setup leaves behind.
fn commit_join_to_local_setup_pending(repository: &EnrollmentRepository) -> LinkRowWrite {
    assert!(repository
        .try_insert_enrollment_operation(&EnrollmentOperation {
            operation_id: OPERATION.to_string(),
            kind: EnrollmentKind::Join,
            group_id: Some(GROUP.to_string()),
            group_name: None,
            device_id: DEVICE.to_string(),
            local_path: LOCAL_PATH.to_string(),
            storage_mode: "eager".to_string(),
            state: EnrollmentOperationState::PreparePending,
            last_error: None,
            attempts: 0,
            created_at_unix: 0,
            updated_at_unix: 0,
        })
        .unwrap());
    assert!(repository.mark_enrollment_operation_prepared(OPERATION, GROUP, 1).unwrap());
    repository
        .add_link_with_pending_enrollment_and_begin_setup(
            LOCAL_PATH,
            GROUP,
            &PendingEnrollment {
                operation_id: OPERATION.to_string(),
                kind: EnrollmentKind::Join,
                group_id: GROUP.to_string(),
                device_id: DEVICE.to_string(),
                local_path: LOCAL_PATH.to_string(),
            },
            2,
            None,
        )
        .expect("the link commit must succeed")
}

/// A folder already linked to the group (with its adopted root token) but
/// with no runtime holding it -- orphaned, or its start failed at boot -- is
/// joined again. The commit updates the existing row, and the daemon dies
/// before local setup is confirmed. Crash recovery must undo only what that
/// commit did: the earlier link, its root token and its orphaned flag stay.
#[test]
fn recovery_rollback_of_a_rejoin_keeps_the_link_row_that_was_already_there() {
    let db = open_full_test_db();
    let links = LinkRepository::new(db.clone());
    let repository = EnrollmentRepository::new(db.clone());
    links.add_link(LOCAL_PATH, GROUP).unwrap();
    links.set_link_root_token_for_path_for_test(LOCAL_PATH, "root-token-1").unwrap();
    links.set_materialization_policy(LOCAL_PATH, MaterializationPolicy::OnDemand).unwrap();
    links.mark_link_orphaned(LOCAL_PATH).unwrap();

    let write = commit_join_to_local_setup_pending(&repository);
    assert!(matches!(write, LinkRowWrite::Updated(_)), "the join must update the existing row");

    assert!(repository
        .rollback_local_setup_to_cancel_pending(
            LOCAL_PATH,
            OPERATION,
            "local setup did not complete before recovery",
            3,
        )
        .expect("recovery rollback"));

    let rows = links.list_links().unwrap();
    let row = rows
        .iter()
        .find(|link| link.key() == LOCAL_PATH)
        .expect("the link row that predates the join must survive recovery");
    assert_eq!(row.group_id, GROUP);
    assert!(row.orphaned, "the row goes back to the orphaned state it was in");
    assert_eq!(row.materialization_policy, MaterializationPolicy::OnDemand);
    assert_eq!(
        links.link_root_tokens_for_group_unchecked_for_test(GROUP).unwrap(),
        vec![Some("root-token-1".to_string())],
        "the adopted root token must survive"
    );
    assert!(repository.list_pending_enrollments().unwrap().is_empty());
    assert_eq!(
        repository.get_enrollment_operation(OPERATION).unwrap().unwrap().state,
        EnrollmentOperationState::CancelPending
    );
}

/// The ordinary case is unchanged: a join that inserted the row has that
/// row removed by the recovery rollback.
#[test]
fn recovery_rollback_of_a_fresh_join_removes_the_row_it_inserted() {
    let db = open_full_test_db();
    let links = LinkRepository::new(db.clone());
    let repository = EnrollmentRepository::new(db.clone());

    let write = commit_join_to_local_setup_pending(&repository);
    assert_eq!(write, LinkRowWrite::Inserted);

    assert!(repository
        .rollback_local_setup_to_cancel_pending(LOCAL_PATH, OPERATION, "crash", 3)
        .expect("recovery rollback"));

    assert!(links.list_links().unwrap().is_empty());
    assert!(repository.list_pending_enrollments().unwrap().is_empty());
    assert_eq!(
        repository.get_enrollment_operation(OPERATION).unwrap().unwrap().state,
        EnrollmentOperationState::CancelPending
    );
}

/// A `LocalSetupPending` row with no recorded link write (it reached that
/// state some other way than its own link commit) is not rolled back by
/// guessing: the row at the path is left alone, and the caller is told so.
#[test]
fn recovery_rollback_without_a_recorded_link_write_touches_nothing() {
    let db = open_full_test_db();
    let links = LinkRepository::new(db.clone());
    let repository = EnrollmentRepository::new(db.clone());
    links.add_link(LOCAL_PATH, GROUP).unwrap();
    links.set_link_root_token_for_path_for_test(LOCAL_PATH, "root-token-1").unwrap();
    assert!(repository
        .try_insert_enrollment_operation(&EnrollmentOperation {
            operation_id: OPERATION.to_string(),
            kind: EnrollmentKind::Join,
            group_id: Some(GROUP.to_string()),
            group_name: None,
            device_id: DEVICE.to_string(),
            local_path: LOCAL_PATH.to_string(),
            storage_mode: "eager".to_string(),
            state: EnrollmentOperationState::Prepared,
            last_error: None,
            attempts: 0,
            created_at_unix: 0,
            updated_at_unix: 0,
        })
        .unwrap());
    assert!(repository
        .mark_enrollment_operation_state(
            OPERATION,
            EnrollmentOperationState::LocalSetupPending,
            None,
            1,
        )
        .unwrap());

    assert!(!repository
        .rollback_local_setup_to_cancel_pending(LOCAL_PATH, OPERATION, "crash", 3)
        .expect("recovery rollback"));

    assert_eq!(links.live_link_paths_for_group(GROUP).unwrap(), vec![LOCAL_PATH.to_string()]);
    assert_eq!(
        links.link_root_tokens_for_group_unchecked_for_test(GROUP).unwrap(),
        vec![Some("root-token-1".to_string())]
    );
    assert_eq!(
        repository.get_enrollment_operation(OPERATION).unwrap().unwrap().state,
        EnrollmentOperationState::LocalSetupPending
    );
}
