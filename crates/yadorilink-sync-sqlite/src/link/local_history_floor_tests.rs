#![cfg(test)]

use super::*;
use crate::rewind_plan::compute_rewind_plan;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::rewind::RewindPathAction;

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

/// Admits one file through the real file-index write chokepoint, the
/// way an incoming change from a peer does -- so the row's
/// `version_seq` and admission stamp are the production ones.
fn admit_file(db: &Arc<SyncDatabase>, path: &str) {
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        crate::file_index::upsert_file_in_tx(
            tx,
            GROUP,
            &FileRecord {
                path: path.to_string(),
                size: 10,
                mtime_unix_nanos: 0,
                blocks: Vec::new(),
                deleted: false,
            },
            "device-that-was-here-first",
        )
    })
    .expect("the file admission must succeed");
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

#[test]
fn a_file_inherited_at_a_plain_link_is_unavailable_before_the_link_not_delete() {
    let db = open_full_test_db();
    let before_link = crate::file_index::now_unix_nanos_checked().unwrap();
    LinkRepository::new(db.clone()).add_link(LOCAL_PATH, GROUP).unwrap();
    // Everything the folder already held syncs in after the link, each
    // path numbered from 1 because this device is seeing it for the
    // first time.
    for path in ["notes.txt", "photos/trip.jpg"] {
        admit_file(&db, path);
    }

    // The observable verdict first, so a regression reports what the
    // user would actually be shown rather than a missing table row.
    let plan = db
        .read::<_, SyncSqliteError>(|conn| {
            compute_rewind_plan(conn, GROUP, before_link - THIRTY_DAYS_NANOS, &|_| false)
        })
        .unwrap();
    let counts = plan.action_counts();
    assert_eq!(
        counts.delete, 0,
        "a folder this device inherited was not created since the target, so a preview must \
         not offer to delete it: {counts:?}"
    );
    assert_eq!(
        counts.unavailable, 2,
        "every inherited path is unanswerable this far back: {counts:?}"
    );
    match &plan.entries.iter().find(|e| e.path == "notes.txt").unwrap().action {
        RewindPathAction::Unavailable { reason } => assert_eq!(
            *reason,
            yadorilink_replica_domain::rewind::RewindUnavailableReason::JoinedAfter,
            "retention cannot be the cause below the floor"
        ),
        other => panic!("expected Unavailable before the link, got {other:?}"),
    }

    let floor = recorded_floor(&db).expect("a first link must record this group's floor");
    assert!(floor >= before_link, "the floor must be the link instant, not something earlier");
}

/// Re-linking a folder this device already has an index for must NOT
/// move the floor. Nothing restarts `version_seq` in that case -- the
/// rows are all still there -- so moving it would throw away real,
/// answerable history for no gain.
#[test]
fn re_linking_a_group_this_device_already_indexed_leaves_the_floor_alone() {
    let db = open_full_test_db();
    let links = LinkRepository::new(db.clone());
    links.add_link(LOCAL_PATH, GROUP).unwrap();
    admit_file(&db, "notes.txt");
    let first_floor = recorded_floor(&db).expect("a first link must record this group's floor");

    links.remove_link(LOCAL_PATH).unwrap();
    links.add_link(LOCAL_PATH, GROUP).unwrap();

    assert_eq!(
        recorded_floor(&db),
        Some(first_floor),
        "a re-link of an already-indexed group must not move the floor forward"
    );
    assert_eq!(
        db.read::<_, SyncSqliteError>(|conn| compute_rewind_plan(conn, GROUP, i64::MAX, &|_| {
            false
        }))
        .unwrap()
        .entries
        .iter()
        .find(|e| e.path == "notes.txt")
        .unwrap()
        .action,
        RewindPathAction::Unchanged,
        "history from before the re-link stays answerable"
    );
}

/// Removing a path no link is recorded at reports that nothing was removed,
/// so a caller cannot mistake a misspelled path for a completed unlink.
#[test]
fn remove_link_reports_whether_a_row_was_deleted() {
    let db = open_full_test_db();
    let links = LinkRepository::new(db);
    links.add_link(LOCAL_PATH, GROUP).unwrap();

    assert!(!links.remove_link("/some/other/path").unwrap());
    assert!(links.remove_link(LOCAL_PATH).unwrap());
    assert!(!links.remove_link(LOCAL_PATH).unwrap());
}

/// A write that names the group it expects applies only to that group's link, and
/// otherwise changes nothing.
#[test]
fn writes_expecting_a_group_apply_only_to_that_groups_link() {
    let db = open_full_test_db();
    let links = LinkRepository::new(db);
    links.add_link(LOCAL_PATH, GROUP).unwrap();

    let mismatch = |r: Result<(), SyncSqliteError>| matches!(r, Err(SyncSqliteError::GroupMismatch { ref local_path }) if local_path == LOCAL_PATH);
    assert!(mismatch(links.set_paused_expecting_group(LOCAL_PATH, true, Some("other"))));
    assert!(mismatch(links.pause_until_expecting_group(LOCAL_PATH, 4_000_000_000, Some("other"))));
    assert!(matches!(
        links.remove_link_expecting_group(LOCAL_PATH, "other"),
        Err(SyncSqliteError::GroupMismatch { .. })
    ));
    assert!(!links.list_links().unwrap()[0].paused, "a refused write paused nothing");
    assert_eq!(links.list_links().unwrap().len(), 1, "a refused removal removed nothing");

    links.set_paused_expecting_group(LOCAL_PATH, true, Some(GROUP)).unwrap();
    assert!(links.list_links().unwrap()[0].paused);
    links.set_paused_expecting_group(LOCAL_PATH, false, None).unwrap();
    assert!(!links.list_links().unwrap()[0].paused);

    // An absent link is not a group mismatch.
    assert!(matches!(
        links.set_paused_expecting_group("/no/such/link", true, Some(GROUP)),
        Err(SyncSqliteError::NotFound(_))
    ));

    assert!(links.remove_link_expecting_group(LOCAL_PATH, GROUP).unwrap());
    assert!(links.list_links().unwrap().is_empty());
}

/// The eager removal re-checks the link's group inside its own transaction, on top of the
/// digest: a digest that matches for the named group still removes nothing when the link at
/// the path belongs to another group.
#[test]
fn recheck_removal_leaves_a_link_of_another_group_in_place() {
    let db = open_full_test_db();
    let links = LinkRepository::new(db.clone());
    links.add_link(LOCAL_PATH, GROUP).unwrap();
    let digest = db
        .read::<_, SyncSqliteError>(|conn| {
            Ok(crate::file_index::enumerate_group_durability_roots_on_conn(conn, "other")?.digest)
        })
        .unwrap();

    assert!(!links.recheck_digest_then_remove_link("other", LOCAL_PATH, digest).unwrap());
    assert_eq!(links.list_links().unwrap().len(), 1, "the link of another group stays");
}
