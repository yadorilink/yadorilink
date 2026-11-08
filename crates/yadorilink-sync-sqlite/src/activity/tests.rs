use std::sync::Arc;

use yadorilink_replica_domain::file::{BlockInfo, FileRecord, RecordKind};
use yadorilink_root_authority::root_commit::RootCommitPermit;
use yadorilink_sqlite_runtime::SyncDatabase;

use super::*;

const G: &str = "g1";
const ME: &str = "dev-me";
const PEER: &str = "dev-peer";

fn open() -> Arc<SyncDatabase> {
    Arc::new(
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
    )
}

fn rec(path: &str, salt: u8, deleted: bool) -> FileRecord {
    FileRecord {
        path: path.to_string(),
        size: 1,
        mtime_unix_nanos: i64::from(salt),
        blocks: vec![BlockInfo { hash: vec![salt; 32], offset: 0, size: 1 }],
        deleted,
    }
}

fn put(repo: &FileIndexRepository, path: &str, salt: u8, deleted: bool, origin: &str) {
    repo.upsert_file_with_origin(
        G,
        &rec(path, salt, deleted),
        origin,
        &RootCommitPermit::for_tests(),
    )
    .unwrap();
}

fn query() -> ActivityQuery {
    ActivityQuery { limit: 100, group_ids: vec![G.into()], ..Default::default() }
}

fn kinds(repo: &FileIndexRepository, q: &ActivityQuery) -> Vec<(String, ActivityKind)> {
    repo.list_activity(q, ME).unwrap().into_iter().map(|e| (e.path, e.kind)).collect()
}

#[test]
fn add_update_delete_and_recreate_are_logged_newest_first() {
    let db = open();
    let repo = FileIndexRepository::new(db);
    put(&repo, "a.txt", 1, false, ME);
    put(&repo, "a.txt", 2, false, PEER);
    put(&repo, "a.txt", 2, true, PEER);
    put(&repo, "a.txt", 3, false, ME);
    assert_eq!(
        kinds(&repo, &query()),
        [
            ("a.txt".into(), ActivityKind::Added),
            ("a.txt".into(), ActivityKind::Deleted),
            ("a.txt".into(), ActivityKind::Updated),
            ("a.txt".into(), ActivityKind::Added),
        ]
    );
}

#[test]
fn a_metadata_only_touch_and_a_tombstone_of_nothing_log_nothing() {
    let repo = FileIndexRepository::new(open());
    put(&repo, "a.txt", 1, false, ME);
    // Same blocks, new mtime.
    let mut touched = rec("a.txt", 1, false);
    touched.mtime_unix_nanos = 99;
    repo.upsert_file_with_origin(G, &touched, ME, &RootCommitPermit::for_tests()).unwrap();
    put(&repo, "never.txt", 1, true, ME);
    assert_eq!(kinds(&repo, &query()), [("a.txt".into(), ActivityKind::Added)]);
}

#[test]
fn a_conflicted_copy_is_a_conflict_event() {
    let repo = FileIndexRepository::new(open());
    put(&repo, "a (conflicted copy, dev-peer 2026-10-28 10-00-00).txt", 1, false, PEER);
    assert_eq!(kinds(&repo, &query())[0].1, ActivityKind::Conflict);
}

#[test]
fn directories_get_no_event() {
    let db = open();
    let repo = FileIndexRepository::new(db);
    put(&repo, "dir", 1, false, ME);
    repo.set_record_kind(G, "dir", RecordKind::Directory, &RootCommitPermit::for_tests()).unwrap();
    put(&repo, "dir", 2, true, ME);
    assert!(kinds(&repo, &query()).is_empty());
}

#[test]
fn restore_relabels_the_committed_version() {
    let db = open();
    let repo = FileIndexRepository::new(db.clone());
    put(&repo, "a.txt", 1, false, ME);
    put(&repo, "a.txt", 2, false, ME);
    db.write_immediate::<_, SyncSqliteError>(|tx| mark_restored_in_tx(tx, G, "a.txt")).unwrap();
    let got = kinds(&repo, &query());
    assert_eq!(got.len(), 2, "relabelled, not duplicated");
    assert_eq!(got[0].1, ActivityKind::Restored);
}

#[test]
fn filters_by_kind_origin_group_and_pages_by_cursor() {
    let repo = FileIndexRepository::new(open());
    put(&repo, "a", 1, false, ME);
    put(&repo, "b", 1, false, PEER);
    put(&repo, "c", 1, false, "");
    put(&repo, "b", 2, true, PEER);

    let q = ActivityQuery { origin: ActivityOrigin::ThisDevice, ..query() };
    assert_eq!(kinds(&repo, &q).len(), 2, "own device or unknown origin");
    let q = ActivityQuery { origin: ActivityOrigin::OtherDevices, ..query() };
    assert_eq!(kinds(&repo, &q).len(), 2);
    let q = ActivityQuery { kinds: vec![ActivityKind::Deleted], ..query() };
    assert_eq!(kinds(&repo, &q), [("b".into(), ActivityKind::Deleted)]);
    let q = ActivityQuery { group_ids: vec!["other".into()], ..query() };
    assert!(kinds(&repo, &q).is_empty());

    let first = repo.list_activity(&ActivityQuery { limit: 3, ..query() }, ME).unwrap();
    assert_eq!(first.len(), 3);
    let rest =
        repo.list_activity(&ActivityQuery { before_id: Some(first[2].id), ..query() }, ME).unwrap();
    assert_eq!(rest.len(), 1);
    assert!(rest[0].id < first[2].id);
}

#[test]
fn the_log_is_bounded_by_count_and_age() {
    let db = open();
    let repo = FileIndexRepository::new(db.clone());
    for i in 0..(MAX_EVENTS + 25) {
        put(&repo, &format!("f{i}"), 1, false, ME);
    }
    let count = |db: &SyncDatabase| -> i64 {
        db.read::<_, SyncSqliteError>(|c| {
            Ok(c.query_row("SELECT count(*) FROM activity_events", [], |r| r.get(0))?)
        })
        .unwrap()
    };
    assert_eq!(count(&db), MAX_EVENTS);
    // Age out everything, then one insert prunes it.
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        tx.execute("UPDATE activity_events SET at_unix_nanos = 1", [])?;
        Ok(())
    })
    .unwrap();
    put(&repo, "fresh", 1, false, ME);
    assert_eq!(count(&db), 1);
}

#[test]
fn the_newest_events_author_is_read_without_a_scan_and_is_per_group() {
    let repo = FileIndexRepository::new(open());
    assert_eq!(repo.newest_activity_origin(G).unwrap(), None, "no event yet");

    put(&repo, "a.txt", 1, false, PEER);
    assert_eq!(repo.newest_activity_origin(G).unwrap(), Some(Some(PEER.to_string())));
    // A later change by this device is the newest now.
    put(&repo, "b.txt", 2, false, ME);
    assert_eq!(repo.newest_activity_origin(G).unwrap(), Some(Some(ME.to_string())));
    // Another group's events say nothing about this one.
    assert_eq!(repo.newest_activity_origin("other").unwrap(), None);
}
