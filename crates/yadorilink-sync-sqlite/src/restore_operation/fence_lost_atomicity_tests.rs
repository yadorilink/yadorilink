#![cfg(test)]

use super::*;
use yadorilink_replica_domain::file::{BlockInfo, RecordKind};
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_root_authority::root_commit::RootCommitPermit;

const GROUP: &str = "g";
const PATH: &str = "notes.txt";

fn open_full_test_db() -> Arc<SyncDatabase> {
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

fn record(size: u64) -> FileRecord {
    FileRecord {
        path: PATH.to_string(),
        size,
        mtime_unix_nanos: 0,
        blocks: vec![BlockInfo { hash: vec![7u8; 32], offset: 0, size: size as u32 }],
        deleted: false,
    }
}

fn meta() -> LocalFileMetaColumns {
    LocalFileMetaColumns {
        record_kind: RecordKind::File,
        symlink_target: None,
        symlink_out_of_root: false,
        unix_mode: None,
        xattrs: Vec::new(),
    }
}

fn identity() -> yadorilink_fs_platform::fs_identity::FileIdentity {
    use yadorilink_fs_platform::fs_identity::{
        ObjectKind, PlatformObjectId, Timestamp, VolumeIdentity,
    };
    yadorilink_fs_platform::fs_identity::FileIdentity {
        volume_identity: VolumeIdentity::Unix { device_id: 7 },
        object_id: PlatformObjectId::Unix { inode: 42 },
        object_kind: ObjectKind::RegularFile,
        generation_or_usn: Some(1),
        birth_or_creation_time: Some(Timestamp {
            seconds_since_unix_epoch: 1_700_000_000,
            subsec_nanos: 0,
        }),
        observed_size: 4,
        metadata_fingerprint: [3u8; 32],
        link_count: Some(1),
        symlink_target_digest: None,
    }
}

fn current_row(db: &SyncDatabase) -> Option<(i64, String)> {
    db.write::<_, SyncSqliteError>(|conn| {
        Ok(conn
            .query_row(
                "SELECT version_seq, materialization_state FROM files \
                 WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                rusqlite::params![GROUP, PATH],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    })
    .unwrap()
}

#[test]
fn a_restore_that_loses_its_fence_writes_nothing_at_all() {
    let db = open_full_test_db();
    let permit = RootCommitPermit::for_tests();
    let file_index = crate::file_index::FileIndexRepository::new(db.clone());
    let restores = RestoreOperationRepository::new(db.clone());

    // The live version the restore is about to supersede, left
    // `Present` the way a previously-materialized path is.
    file_index.upsert_file_with_origin(GROUP, &record(5), "device-a", &permit).unwrap();
    crate::materialization_state::MaterializationStateRepository::new(db.clone())
        .set_materialization_state(GROUP, PATH, MaterializationState::Present, &permit)
        .unwrap();
    let (before_seq, before_state) = current_row(&db).expect("the live row");
    assert_eq!(before_state, MaterializationState::Present.as_db_str());

    restores
        .record_restore_operation(&RestoreOperation {
            operation_id: "op-1".to_string(),
            group_id: GROUP.to_string(),
            path: PATH.to_string(),
            target_version_seq: 1,
            expected_current_version_seq: Some(before_seq),
            state: RestoreOperationState::DiskCommitted,
            record: record(9),
            origin_device_id: "device-a".to_string(),
            meta: meta(),
        })
        .unwrap();

    // The restore's own pre-write bump, then a competing mutator
    // advancing the fence past it while the restore was writing bytes.
    let wrote_under = db
        .write::<_, SyncSqliteError>(|conn| {
            crate::materialized_generation::bump_mutation_fence(
                conn,
                GROUP,
                PATH,
                "restore_write",
                0,
            )
        })
        .unwrap();
    let competing = db
        .write::<_, SyncSqliteError>(|conn| {
            crate::materialized_generation::bump_mutation_fence(conn, GROUP, PATH, "other", 0)
        })
        .unwrap();
    assert_eq!(competing, wrote_under + 1, "the competing mutator must own the live epoch");

    let outcome = restores
        .commit_restore_operation("op-1", Some(&identity()), Some(wrote_under), &permit)
        .unwrap();
    assert!(
        matches!(outcome, RestoreCommitOutcome::FenceLost),
        "a restore whose epoch was taken must report the loss, not a commit: {outcome:?}"
    );

    // Nothing at all: the row is untouched, so it neither advances to a
    // version no proof describes nor carries its predecessor's claim
    // onto one.
    assert_eq!(
        current_row(&db),
        Some((before_seq, before_state)),
        "the row must be exactly as it was -- a committed supersession here is a Hydrated \
         claim for content nothing proved"
    );
    let proof = db
        .write::<_, SyncSqliteError>(|conn| {
            crate::materialized_generation::lookup_materialized_generation_diagnostic(
                conn, GROUP, PATH,
            )
        })
        .unwrap();
    assert!(proof.is_none(), "no proof may be published for an attempt that lost its epoch");

    // And the journal entry stands, still naming a version sequence
    // that is still correct, so recovery can re-verify and decide.
    let retained = restores.list_restore_operations(GROUP).unwrap();
    assert_eq!(retained.len(), 1, "the only record that a write was in flight must survive");
    assert_eq!(retained[0].expected_current_version_seq, Some(before_seq));
}

/// The live restore's settle holds the permit of the one
/// `LinkOperation` the restore runs under, and both of its transactions
/// verify it before writing. A root lost between the physical write and
/// the settle must mark nothing, publish no row and no proof, and leave
/// the journal entry standing for recovery -- on neither the old root nor
/// whatever now sits at its path.
#[test]
fn a_restore_settle_under_a_lost_root_writes_nothing_at_all() {
    use yadorilink_root_authority::root_commit::RootLease;
    use yadorilink_root_authority::sync_root_lock::{SyncRootLock, SYNC_ROOT_LOCK_FILE_NAME};

    let db = open_full_test_db();
    let permit = RootCommitPermit::for_tests();
    let file_index = crate::file_index::FileIndexRepository::new(db.clone());
    let restores = RestoreOperationRepository::new(db.clone());
    file_index.upsert_file_with_origin(GROUP, &record(5), "device-a", &permit).unwrap();
    crate::materialization_state::MaterializationStateRepository::new(db.clone())
        .set_materialization_state(GROUP, PATH, MaterializationState::Present, &permit)
        .unwrap();
    let before = current_row(&db).expect("the live row");
    restores
        .record_restore_operation(&RestoreOperation {
            operation_id: "op-1".to_string(),
            group_id: GROUP.to_string(),
            path: PATH.to_string(),
            target_version_seq: 1,
            expected_current_version_seq: Some(before.0),
            state: RestoreOperationState::Prepared,
            record: record(9),
            origin_device_id: "device-a".to_string(),
            meta: meta(),
        })
        .unwrap();
    let wrote_under = db
        .write::<_, SyncSqliteError>(|conn| {
            crate::materialized_generation::bump_mutation_fence(
                conn,
                GROUP,
                PATH,
                "restore_write",
                0,
            )
        })
        .unwrap();

    let root = tempfile::tempdir().unwrap();
    let lease = RootLease::new(SyncRootLock::acquire(root.path()).unwrap(), GROUP.to_string(), 0);
    let operation = lease.begin_operation().unwrap();
    let lock_path = root.path().join(SYNC_ROOT_LOCK_FILE_NAME);
    std::fs::remove_file(&lock_path).unwrap();
    std::fs::File::create(&lock_path).unwrap();
    assert!(
        operation.permit().verify().is_err(),
        "fixture check: the root must really look lost, or this test proves nothing"
    );

    assert!(
        restores.mark_restore_disk_committed("op-1", &operation.permit()).is_err(),
        "marking the write disk-committed under a lost root must fail"
    );
    assert!(
        restores
            .commit_restore_operation(
                "op-1",
                Some(&identity()),
                Some(wrote_under),
                &operation.permit()
            )
            .is_err(),
        "the restore commit under a lost root must fail"
    );

    assert_eq!(current_row(&db), Some(before), "no index version may be committed");
    let proof = db
        .write::<_, SyncSqliteError>(|conn| {
            crate::materialized_generation::lookup_materialized_generation_diagnostic(
                conn, GROUP, PATH,
            )
        })
        .unwrap();
    assert!(proof.is_none(), "no proof may be published under a lost root");
    let retained = restores.list_restore_operations(GROUP).unwrap();
    assert_eq!(retained.len(), 1, "the journal entry must stand for recovery");
    assert_eq!(retained[0].state, RestoreOperationState::Prepared, "nothing was marked");
}
