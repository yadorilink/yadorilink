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

fn columns(kind: RecordKind, target: Option<&[u8]>, exec: bool) -> LocalFileMetaColumns {
    LocalFileMetaColumns {
        record_kind: kind,
        symlink_target: target.map(<[u8]>::to_vec),
        symlink_out_of_root: false,
        exec,
    }
}

/// `(version_seq, record_kind, symlink_target, exec)` per row.
type Row = (i64, String, Option<Vec<u8>>, i64);

fn rows(db: &SyncDatabase) -> Vec<Row> {
    db.read::<_, SyncSqliteError>(|conn| {
        let mut stmt = conn.prepare(
            "SELECT version_seq, record_kind, symlink_target, exec \
             FROM files WHERE group_id = ?1 AND path = 'p' ORDER BY version_seq",
        )?;
        let rows = stmt.query_map([GROUP], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    })
    .unwrap()
}

#[test]
fn an_upsert_with_metadata_leaves_the_superseded_row_as_it_was_authored() {
    let db = open_test_db();
    let first = columns(RecordKind::File, None, true);
    let second = columns(RecordKind::Symlink, Some(b"../b"), false);
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        upsert_file_with_meta_in_tx(
            tx,
            GROUP,
            &record("p", 1),
            "dev",
            None,
            Some(&first),
            crate::retention::Retention::OwnEdit,
        )?;
        upsert_file_with_meta_in_tx(
            tx,
            GROUP,
            &record("p", 2),
            "dev",
            None,
            Some(&second),
            crate::retention::Retention::OwnEdit,
        )
    })
    .unwrap();

    let rows = rows(&db);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!((rows[0].1.as_str(), &rows[0].2, rows[0].3), ("file", &None, 1), "{rows:?}");
    assert_eq!(
        (rows[1].1.as_str(), rows[1].2.as_deref(), rows[1].3),
        ("symlink", Some(&b"../b"[..]), 0),
        "{rows:?}"
    );
}

#[test]
fn an_upsert_without_metadata_carries_the_superseded_columns_forward() {
    let db = open_test_db();
    let first = columns(RecordKind::File, None, true);
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        upsert_file_with_meta_in_tx(
            tx,
            GROUP,
            &record("p", 1),
            "dev",
            None,
            Some(&first),
            crate::retention::Retention::OwnEdit,
        )?;
        upsert_file_with_meta_in_tx(
            tx,
            GROUP,
            &record("p", 2),
            "dev",
            None,
            None,
            crate::retention::Retention::OwnEdit,
        )
    })
    .unwrap();

    let rows = rows(&db);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].1.as_str(), rows[1].1.as_str());
    assert_eq!(rows[0].3, rows[1].3);
    assert_eq!(rows[1].3, 1);
}
