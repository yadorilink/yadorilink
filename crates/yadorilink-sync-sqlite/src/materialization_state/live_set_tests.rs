#![cfg(test)]

use yadorilink_replica_domain::file::{BlockInfo, FileMeta, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{BlockHash, VersionHash};

use super::*;

const GROUP: &str = "g";
const BLOCK: [u8; 32] = [7; 32];

/// A file-backed database: a read snapshot only means something where a
/// writer on another connection can commit while the read is open.
fn open_file_db(dir: &tempfile::TempDir) -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open(dir.path().join("index.db"), |conn| {
            crate::replica_tables::init_for_tests(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            crate::materialized_generation::init_materialized_generation_schema(conn).map_err(
                |e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()),
            )?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .expect("open file-backed db"),
    )
}

fn version_with_block() -> FileVersion {
    FileVersion::new(
        vec![yadorilink_replica_domain::file::VersionBlock {
            hash: BlockHash(BLOCK.to_vec()),
            size: 4,
        }],
        4,
        FileMeta {
            mtime_unix_nanos: 1,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

/// A block that is referenced at every instant must be in the live set, even
/// when the reference moves from a retained `files` row to a native head while
/// the set is being computed: the heads half is read first (no head yet), the
/// head is then admitted and retention drops the old row, and the rows half is
/// read last (no row any more). Computed from two separate reads the block
/// appears in neither half and the sweep would delete it.
#[test]
fn a_block_moving_from_a_row_to_a_head_mid_computation_stays_live() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_file_db(&dir);
    let version = version_with_block();
    let blocks_json =
        serde_json::to_string(&[BlockInfo { hash: BLOCK.to_vec(), offset: 0, size: 4 }]).unwrap();
    db.write::<_, SyncSqliteError>(|conn| {
        crate::dag_store::put_file_version(conn, GROUP, &version)?;
        conn.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted) \
             VALUES (?1, 'old.txt', 4, 0, ?2, 0)",
            rusqlite::params![GROUP, blocks_json],
        )?;
        Ok(())
    })
    .unwrap();
    let repository = MaterializationStateRepository::new(db.clone());
    let VersionHash(version_hash) = version.version_hash;

    let live = repository
        .live_block_hashes_including_native_heads_between(|| {
            db.write::<_, SyncSqliteError>(|conn| {
                conn.execute(
                    "INSERT INTO native_heads \
                     (group_id, path, author, incarnation, seq, version, provenance) \
                     VALUES (?1, 'new.txt', 'device', ?2, 1, ?3, ?4)",
                    rusqlite::params![GROUP, vec![1u8; 16], version_hash.to_vec(), vec![0u8; 32]],
                )?;
                conn.execute("DELETE FROM files WHERE path = 'old.txt'", [])?;
                Ok(())
            })
            .unwrap();
        })
        .unwrap();

    assert!(live.contains(&hex::encode(BLOCK)), "the block was referenced throughout: {live:?}");
}

fn insert_head(db: &SyncDatabase, group: &str, path: &str, version: &[u8; 32], incarnation: u8) {
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO native_heads \
             (group_id, path, author, incarnation, seq, version, provenance) \
             VALUES (?1, ?2, 'device', ?3, 1, ?4, ?5)",
            rusqlite::params![group, path, vec![incarnation; 16], version.to_vec(), vec![0u8; 32]],
        )?;
        Ok(())
    })
    .unwrap();
}

fn stored_version(db: &SyncDatabase, group: &str, version: &FileVersion) {
    db.write::<_, SyncSqliteError>(|conn| {
        crate::dag_store::put_file_version(conn, group, version)?;
        Ok(())
    })
    .unwrap();
}

fn referenced(db: Arc<SyncDatabase>, version: &FileVersion) -> std::collections::HashSet<String> {
    MaterializationStateRepository::new(db)
        .blocks_referenced_outside_current_file(GROUP, "cur.txt", &version.version_hash, &[])
        .unwrap()
}

/// Cache reclamation of one file must not free a block a committed native head at ANOTHER path
/// names, in the window before that head is projected into any `files` row.
#[test]
fn per_file_reclamation_treats_an_unprojected_native_head_at_another_path_as_a_root() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_file_db(&dir);
    let version = version_with_block();
    stored_version(&db, GROUP, &version);
    insert_head(&db, GROUP, "new.txt", &version.version_hash.0, 1);
    assert!(referenced(db, &version).contains(&hex::encode(BLOCK)));
}

/// The head of the version being reclaimed is that file's own reference, like its current row:
/// with only it left the block is reclaimable.
#[test]
fn per_file_reclamation_ignores_the_native_head_of_the_version_it_decides_about() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_file_db(&dir);
    let version = version_with_block();
    stored_version(&db, GROUP, &version);
    insert_head(&db, GROUP, "cur.txt", &version.version_hash.0, 1);
    assert!(!referenced(db, &version).contains(&hex::encode(BLOCK)));
}

/// A head at the same path but another version, or in another group at the same path and
/// version, still roots the blocks it names.
#[test]
fn per_file_reclamation_roots_a_same_path_head_of_another_version_or_group() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_file_db(&dir);
    let current = version_with_block();
    // Another version naming the same block.
    let other = FileVersion::new(
        current.blocks.clone(),
        current.size,
        FileMeta { mtime_unix_nanos: 2, ..current.meta.clone() },
    );
    assert_ne!(other.version_hash, current.version_hash);
    stored_version(&db, GROUP, &other);
    insert_head(&db, GROUP, "cur.txt", &other.version_hash.0, 1);
    assert!(referenced(db.clone(), &current).contains(&hex::encode(BLOCK)));

    let dir2 = tempfile::tempdir().unwrap();
    let db2 = open_file_db(&dir2);
    stored_version(&db2, "other-group", &current);
    insert_head(&db2, "other-group", "cur.txt", &current.version_hash.0, 1);
    assert!(referenced(db2, &current).contains(&hex::encode(BLOCK)));
}

/// A block a recovery item retains may be the only local copy of unsaved content: per-file
/// reclamation must keep it even when it is also the evicted version's block.
#[test]
fn per_file_reclamation_roots_the_blocks_a_recovery_item_retains() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_file_db(&dir);
    let version = version_with_block();
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO native_recovery_item \
             (group_id, item_id, kind, path, version_hash, content, size, content_sha256, \
              retained_blocks, source_recovery_id, created_at) \
             VALUES (?1, 'item', 'late_edit', 'x.txt', ?2, 'complete', 4, ?3, ?4, 'src', 1)",
            rusqlite::params![
                GROUP,
                version.version_hash.0.to_vec(),
                vec![0u8; 32],
                serde_json::to_string(&[hex::encode(BLOCK)]).unwrap()
            ],
        )?;
        Ok(())
    })
    .unwrap();
    assert!(referenced(db, &version).contains(&hex::encode(BLOCK)));
}

/// The per-file reclamation read is one snapshot too: a block that moves from a native head to a
/// retained `files` row while the sources are read one after another must not be reported
/// unreferenced. Read separately, the rows half sees no row yet and the heads half sees no head
/// any more.
#[test]
fn per_file_reclamation_keeps_a_block_moving_from_a_head_to_a_row_mid_read() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_file_db(&dir);
    let version = version_with_block();
    stored_version(&db, GROUP, &version);
    insert_head(&db, GROUP, "other.txt", &version.version_hash.0, 1);
    let blocks_json =
        serde_json::to_string(&[BlockInfo { hash: BLOCK.to_vec(), offset: 0, size: 4 }]).unwrap();
    let evicted =
        FileVersion::new(Vec::new(), 0, FileMeta { mtime_unix_nanos: 9, ..version.meta.clone() });
    let repository = MaterializationStateRepository::new(db.clone());

    let referenced = repository
        .blocks_referenced_outside_current_file_between(
            GROUP,
            "cur.txt",
            &evicted.version_hash,
            &[],
            || {
                db.write::<_, SyncSqliteError>(|conn| {
                    conn.execute(
                        "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, \
                         deleted) VALUES (?1, 'other.txt', 4, 0, ?2, 0)",
                        rusqlite::params![GROUP, blocks_json],
                    )?;
                    conn.execute("DELETE FROM native_heads WHERE path = 'other.txt'", [])?;
                    Ok(())
                })
                .unwrap();
            },
        )
        .unwrap();

    assert!(
        referenced.contains(&hex::encode(BLOCK)),
        "the block was referenced throughout: {referenced:?}"
    );
}
