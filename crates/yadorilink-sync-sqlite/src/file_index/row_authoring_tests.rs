#![cfg(test)]

//! What a row says produced it: the NativeState head it shows, or -- for a
//! tombstone -- the identity of the row it removed.

use super::*;
use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, SyncPath};
use yadorilink_replica_domain::native_plan::NativeRowIdentity;
use yadorilink_replica_domain::native_state::{DeltaHash, Dot};

const GROUP: &str = "g";

fn db() -> Arc<SyncDatabase> {
    crate::replica_tables::open_for_tests()
}

fn record(path: &str, mtime: i64, deleted: bool) -> FileRecord {
    FileRecord { path: path.into(), size: 0, mtime_unix_nanos: mtime, blocks: Vec::new(), deleted }
}

fn identity(seq: u64) -> NativeRowIdentity {
    NativeRowIdentity {
        source_path: SyncPath("x".into()),
        dot: Dot {
            author: AuthorId {
                device: DeviceId("device-a".into()),
                incarnation: IncarnationId([1; 16]),
            },
            seq: AuthorSeq(seq),
        },
        provenance: DeltaHash([seq as u8; 32]),
    }
}

fn write(db: &SyncDatabase, record: &FileRecord, authority: Option<&NativeRowIdentity>) {
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        upsert_file_with_authoring_in_tx(
            tx,
            GROUP,
            record,
            "device-a",
            authority,
            crate::retention::Retention::OwnEdit,
        )
    })
    .unwrap();
}

fn read(db: &SyncDatabase, path: &str) -> Option<NativeRowIdentity> {
    db.read::<_, SyncSqliteError>(|conn| row_authoring_in_tx(conn, GROUP, path)).unwrap()
}

#[test]
fn a_native_row_reads_back_its_identity() {
    let db = db();
    write(&db, &record("x", 1, false), Some(&identity(1)));
    assert_eq!(read(&db, "x"), Some(identity(1)));
    assert_eq!(read(&db, "absent"), None);
}

#[test]
fn a_row_shows_the_head_it_was_last_written_from() {
    let db = db();
    write(&db, &record("x", 1, false), Some(&identity(1)));
    write(&db, &record("x", 2, false), Some(&identity(2)));
    assert_eq!(read(&db, "x"), Some(identity(2)));
}

#[test]
fn a_tombstone_keeps_the_identity_of_the_row_it_removed() {
    let db = db();
    write(&db, &record("x", 1, false), Some(&identity(3)));
    write(&db, &record("x", 2, true), None);
    assert_eq!(read(&db, "x"), Some(identity(3)));
}

#[test]
fn a_plain_upsert_carries_the_previous_identity_forward() {
    let db = db();
    write(&db, &record("x", 1, false), Some(&identity(4)));
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        upsert_file_in_tx(
            tx,
            GROUP,
            &record("x", 2, false),
            "device-a",
            crate::retention::Retention::OwnEdit,
        )
    })
    .unwrap();
    assert_eq!(read(&db, "x"), Some(identity(4)));
}

/// The current rows whose authoring evidence is missing: exactly the
/// predicate the schema's authoring triggers enforce.
fn unauthored(db: &SyncDatabase) -> HashSet<String> {
    db.read::<_, SyncSqliteError>(|conn| {
        let mut stmt = conn.prepare(&format!(
            "SELECT path FROM files f
              WHERE f.group_id = ?1 AND f.state = 'current' AND f.version_seq > 0
                AND {}",
            yadorilink_sqlite_runtime::authoring_evidence_missing("f")
        ))?;
        let rows = stmt.query_map([GROUP], |r| r.get::<_, String>(0))?;
        let mut out = HashSet::new();
        for row in rows {
            out.insert(row?);
        }
        Ok(out)
    })
    .unwrap()
}

/// The evidence behind a row's native identity outlives the delta log and the
/// head: a row shows its head long after both are gone.
#[test]
fn a_native_row_stays_authored_after_its_delta_and_head_are_truncated() {
    use yadorilink_replica_domain::ids::VersionHash;
    use yadorilink_replica_domain::native_state::{HeadPayload, NativeState};
    let db = db();
    let (x, version) = (SyncPath("x".into()), VersionHash([3; 32]));
    let author =
        AuthorId { device: DeviceId("device-a".into()), incarnation: IncarnationId([1; 16]) };
    let mut state = NativeState::new();
    let dot = state
        .put(&author, x.clone(), &[], HeadPayload { version, provenance: DeltaHash([9; 32]) })
        .unwrap();
    db.write::<_, SyncSqliteError>(|conn| {
        crate::native_store::install_state(
            conn,
            &yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            &state,
        )
    })
    .unwrap();
    let identity = NativeRowIdentity { source_path: x, dot, provenance: DeltaHash([9; 32]) };

    write(&db, &record("x", 1, false), Some(&identity));
    assert!(!unauthored(&db).contains("x"), "the head is held: the row is authored");

    // Supersession (and any other removal of the delta and its heads) removes both.
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute("DELETE FROM native_delta_log", [])?;
        conn.execute("DELETE FROM native_heads", [])?;
        Ok(())
    })
    .unwrap();
    assert!(
        !unauthored(&db).contains("x"),
        "the row is still authored once the log and head are gone"
    );
}

/// An identity naming a head this replica never held is not evidence of
/// anything: the row is unauthored, and in a native group the trigger
/// refuses it.
#[test]
fn a_native_identity_for_a_head_never_held_leaves_the_row_unauthored() {
    let db = db();
    write(&db, &record("x", 1, false), Some(&identity(5)));
    assert!(unauthored(&db).contains("x"));
}

/// The evidence is the whole identity: a head that IS held does not license
/// another row to cite its provenance for another dot or another path.
#[test]
fn a_held_heads_provenance_does_not_license_another_identity() {
    use yadorilink_replica_domain::ids::VersionHash;
    use yadorilink_replica_domain::native_state::{HeadPayload, NativeState};
    let db = db();
    let author =
        AuthorId { device: DeviceId("device-a".into()), incarnation: IncarnationId([1; 16]) };
    let mut state = NativeState::new();
    let dot = state
        .put(
            &author,
            SyncPath("x".into()),
            &[],
            HeadPayload { version: VersionHash([3; 32]), provenance: DeltaHash([9; 32]) },
        )
        .unwrap();
    db.write::<_, SyncSqliteError>(|conn| {
        crate::native_store::install_state(
            conn,
            &yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            &state,
        )
    })
    .unwrap();

    let held = NativeRowIdentity {
        source_path: SyncPath("x".into()),
        dot: dot.clone(),
        provenance: DeltaHash([9; 32]),
    };
    let other_path = NativeRowIdentity { source_path: SyncPath("y".into()), ..held.clone() };
    let other_dot = NativeRowIdentity {
        dot: Dot { seq: AuthorSeq(dot.seq.get() + 1), ..dot.clone() },
        ..held.clone()
    };

    write(&db, &record("held", 1, false), Some(&held));
    let refused = |name: &str, identity: &NativeRowIdentity| {
        db.write_immediate::<_, SyncSqliteError>(|tx| {
            upsert_file_with_authoring_in_tx(
                tx,
                GROUP,
                &record(name, 1, false),
                "device-a",
                Some(identity),
                crate::retention::Retention::OwnEdit,
            )
        })
        .is_err()
    };
    // The group has native history, so a row citing evidence that was never
    // verified is refused outright.
    assert!(refused("elsewhere", &other_path), "another path's identity was never verified");
    assert!(refused("later", &other_dot), "another dot's identity was never verified");
    assert!(!unauthored(&db).contains("held"));
}

fn install_head(
    db: &SyncDatabase,
    version: yadorilink_replica_domain::ids::VersionHash,
) -> NativeRowIdentity {
    use yadorilink_replica_domain::native_state::{HeadPayload, NativeState};
    let author =
        AuthorId { device: DeviceId("device-a".into()), incarnation: IncarnationId([1; 16]) };
    let mut state = NativeState::new();
    let dot = state
        .put(
            &author,
            SyncPath("x".into()),
            &[],
            HeadPayload { version, provenance: DeltaHash([9; 32]) },
        )
        .unwrap();
    db.write::<_, SyncSqliteError>(|conn| {
        crate::native_store::install_state(
            conn,
            &yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
            &state,
        )
    })
    .unwrap();
    NativeRowIdentity { source_path: SyncPath("x".into()), dot, provenance: DeltaHash([9; 32]) }
}

fn require(
    db: &SyncDatabase,
    path: &str,
    authoring: Option<&NativeRowIdentity>,
) -> Result<(), SyncSqliteError> {
    db.read::<_, SyncSqliteError>(|conn| {
        require_row_shows_native_head(conn, GROUP, path, authoring)
    })
}

/// The witness proves the head existed; the row must also show what that head
/// carried, or a row of other content could cite a real head.
#[test]
fn a_row_may_cite_a_native_head_only_while_it_shows_that_heads_version() {
    let db = db();
    // The version a plain row at "x" shows.
    write(&db, &record("x", 1, false), None);
    let shown = db
        .read::<_, SyncSqliteError>(|conn| {
            Ok(crate::store::read_canonical_current_row(conn, GROUP, "x")?.unwrap().version_hash())
        })
        .unwrap();

    let head = install_head(&db, shown);
    write(&db, &record("x", 1, false), Some(&head));
    require(&db, "x", Some(&head)).unwrap();

    // The same head cited by a row of other content.
    write(&db, &record("x", 2, false), Some(&head));
    assert!(require(&db, "x", Some(&head)).is_err());
}

fn files_of(db: &SyncDatabase, path: &str) -> Vec<(i64, String)> {
    db.read::<_, SyncSqliteError>(|conn| {
        let mut stmt = conn.prepare(
            "SELECT version_seq, state FROM files WHERE group_id = ?1 AND path = ?2 \
             ORDER BY version_seq",
        )?;
        let rows = stmt
            .query_map([GROUP, path], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .unwrap()
}

#[test]
fn retiring_a_scaffold_drops_that_row_and_keeps_the_versions_and_real_rows() {
    let db = db();
    let repo = FileIndexRepository::new(db.clone());
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    // A path whose only history is a superseded version: the scaffold is its current row.
    write(&db, &record("x", 1, false), Some(&identity(1)));
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        tx.execute("UPDATE files SET state = 'superseded' WHERE path = 'x'", [])?;
        Ok(())
    })
    .unwrap();
    repo.ensure_bootstrap_row_for_metadata(GROUP, "x").unwrap();
    assert_eq!(files_of(&db, "x"), vec![(0, "current".into()), (1, "superseded".into())]);

    assert!(repo.retire_bootstrap_scaffold(GROUP, "x", &permit).unwrap());

    assert_eq!(files_of(&db, "x"), vec![(1, "superseded".into())]);
    // A real current row is never retired.
    write(&db, &record("y", 1, false), Some(&identity(2)));
    assert!(!repo.retire_bootstrap_scaffold(GROUP, "y", &permit).unwrap());
    assert_eq!(files_of(&db, "y"), vec![(1, "current".into())]);
}

fn rows_of(db: &SyncDatabase, path: &str) -> i64 {
    db.read::<_, SyncSqliteError>(|conn| {
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM files WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![GROUP, path],
            |row| row.get(0),
        )?)
    })
    .unwrap()
}

#[test]
fn a_path_with_replicated_history_is_not_erased_as_a_local_only_artifact() {
    let db = db();
    write(&db, &record("x", 1, false), Some(&identity(1)));
    write(&db, &record("x", 2, false), Some(&identity(2)));
    let repo = FileIndexRepository::new(db.clone());
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    let before = rows_of(&db, "x");

    let refused = repo.remove_file(GROUP, "x", ErasureReason::LocalOnlyArtifact, &permit);

    assert!(matches!(refused, Err(SyncSqliteError::InvalidInput(_))), "{refused:?}");
    assert_eq!(rows_of(&db, "x"), before, "a refused erasure removes nothing");
}

#[test]
fn a_tombstoned_path_that_once_had_replicated_history_is_still_refused() {
    let db = db();
    write(&db, &record("x", 1, false), Some(&identity(1)));
    write(&db, &record("x", 2, true), None);
    let repo = FileIndexRepository::new(db.clone());
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    let refused = repo.remove_file(GROUP, "x", ErasureReason::LocalOnlyArtifact, &permit);

    assert!(matches!(refused, Err(SyncSqliteError::InvalidInput(_))), "{refused:?}");
}

#[test]
fn a_local_only_artifact_without_replicated_history_is_erased() {
    let db = db();
    write(&db, &record("local", 1, false), None);
    let repo = FileIndexRepository::new(db.clone());
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    let removed =
        repo.remove_file(GROUP, "local", ErasureReason::LocalOnlyArtifact, &permit).unwrap();

    assert!(removed);
    assert_eq!(rows_of(&db, "local"), 0);
}

/// The user adds the path to the ignore list: its rows go, replicated history included (the file
/// itself is not this layer's business and stays on disk).
#[test]
fn the_ignore_sweep_erases_a_path_even_when_it_has_replicated_history() {
    let db = db();
    write(&db, &record("x", 1, false), Some(&identity(1)));
    write(&db, &record("x", 2, false), Some(&identity(2)));
    let repo = FileIndexRepository::new(db.clone());
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    let removed = repo.remove_file(GROUP, "x", ErasureReason::IgnoreSweep, &permit).unwrap();

    assert!(removed);
    assert_eq!(rows_of(&db, "x"), 0);
}

/// A sync gives up a name that descendants need: today the rows go, history included. This keeps
/// that behaviour and says so; the history of such a path is not kept by this erasure.
#[test]
fn a_namespace_displacement_erases_a_path_that_has_replicated_history() {
    let db = db();
    write(&db, &record("x", 1, false), Some(&identity(1)));
    let repo = FileIndexRepository::new(db.clone());
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();

    let removed =
        repo.remove_file(GROUP, "x", ErasureReason::DisplacedByNamespace, &permit).unwrap();

    assert!(removed);
    assert_eq!(rows_of(&db, "x"), 0);
}
