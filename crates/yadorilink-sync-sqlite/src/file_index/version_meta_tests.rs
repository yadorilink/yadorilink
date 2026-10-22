#![cfg(test)]

//! The metadata columns of an upserted version belong to the row that
//! version inserts. The row it supersedes keeps what it was authored with.

use super::*;

const GROUP: &str = "g";

fn open_test_db() -> Arc<SyncDatabase> {
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

fn record(path: &str, mtime: i64) -> FileRecord {
    FileRecord {
        path: path.to_string(),
        size: 0,
        mtime_unix_nanos: mtime,
        blocks: vec![],
        deleted: false,
    }
}

fn columns(kind: RecordKind, target: Option<&[u8]>, mode: u32) -> LocalFileMetaColumns {
    LocalFileMetaColumns {
        record_kind: kind,
        symlink_target: target.map(<[u8]>::to_vec),
        symlink_out_of_root: false,
        unix_mode: Some(mode),
        xattrs: vec![("user.k".to_string(), b"v".to_vec())],
    }
}

/// `(version_seq, record_kind, symlink_target, unix_mode, xattrs_json)` per row.
type Row = (i64, String, Option<Vec<u8>>, i64, String);

fn rows(db: &SyncDatabase) -> Vec<Row> {
    db.read::<_, SyncSqliteError>(|conn| {
        let mut stmt = conn.prepare(
            "SELECT version_seq, record_kind, symlink_target, unix_mode, xattrs_json \
             FROM files WHERE group_id = ?1 AND path = 'p' ORDER BY version_seq",
        )?;
        let rows = stmt
            .query_map([GROUP], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    })
    .unwrap()
}

#[test]
fn an_upsert_with_metadata_leaves_the_superseded_row_as_it_was_authored() {
    let db = open_test_db();
    let first = columns(RecordKind::File, None, 0o755);
    let second = columns(RecordKind::Symlink, Some(b"../b"), 0o644);
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        upsert_file_with_meta_in_tx(tx, GROUP, &record("p", 1), "dev", None, Some(&first))?;
        upsert_file_with_meta_in_tx(tx, GROUP, &record("p", 2), "dev", None, Some(&second))
    })
    .unwrap();

    let rows = rows(&db);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!((rows[0].1.as_str(), &rows[0].2, rows[0].3), ("file", &None, 0o755), "{rows:?}");
    assert_eq!(
        (rows[1].1.as_str(), rows[1].2.as_deref(), rows[1].3),
        ("symlink", Some(&b"../b"[..]), 0o644),
        "{rows:?}"
    );
    assert_eq!(rows[0].4, rows[1].4, "both versions carry the same xattrs here");
}

#[test]
fn an_upsert_without_metadata_carries_the_superseded_columns_forward() {
    let db = open_test_db();
    let first = columns(RecordKind::File, None, 0o755);
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        upsert_file_with_meta_in_tx(tx, GROUP, &record("p", 1), "dev", None, Some(&first))?;
        upsert_file_with_meta_in_tx(tx, GROUP, &record("p", 2), "dev", None, None)
    })
    .unwrap();

    let rows = rows(&db);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].1.as_str(), rows[1].1.as_str());
    assert_eq!(rows[0].3, rows[1].3);
    assert_eq!(rows[1].3, 0o755);
}
