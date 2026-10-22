//! Which of this device's own heads were derived from capturing its own disk.
//!
//! A delta this device authors is one of two kinds, and they call for
//! opposite treatment when projected back onto the same disk:
//!
//! * a **capture**: local capture read a file (or observed its absence)
//!   and signed what it saw. The disk was the source of the head, so
//!   projecting it can never legitimately change the disk. If the disk no
//!   longer holds what was captured, what is there is a newer local state,
//!   to be captured in turn -- never overwritten with the older one.
//! * an **intentional mutation**: a restore and every other delta authored
//!   in order to change the disk. The disk not holding it yet is the point.
//!
//! The signed delta does not say which one it is: a restore and a capture
//! are both ordinary `Put`s. So the capture routes record it themselves, in
//! the transaction that authors the delta, and nothing else writes here. A
//! head with no record is treated as an intentional mutation -- the
//! conservative reading.
//!
//! One row per path, naming the head the most recent capture of it authored.
//! That is exact for the question asked of it: "is this path's winning own
//! head the one a capture of this path authored?" A capture supersedes every
//! earlier own head of the path, so an older capture of it is never the
//! winner again; and a later non-capture head (a restore) has a different
//! identity from the one recorded, so it is correctly not a capture. The
//! table is bounded by the number of paths ever captured.
//!
//! A captured deletion is recorded too, so that it replaces the record of
//! the capture it deleted. Nothing asks about a deletion itself yet: only a
//! content head can be written over newer local state.

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncSqliteError;

pub fn init_local_capture_provenance_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        -- One row per path: the identity of the head the most recent capture
        -- of it authored.
        CREATE TABLE IF NOT EXISTS native_local_capture (
            group_id TEXT NOT NULL,
            path     TEXT NOT NULL,
            identity BLOB NOT NULL,
            PRIMARY KEY (group_id, path)
        );
        "#,
    )?;
    Ok(())
}

/// Records that the native head `identity` was put by local capture for
/// `path`, in the transaction that authored it. `None` (a captured deletion,
/// or a capture native did not author) retires the record of the capture it
/// replaces.
pub(crate) fn record_native_local_capture_in_tx(
    conn: &Connection,
    group_id: &str,
    path: &str,
    identity: Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>,
) -> Result<(), SyncSqliteError> {
    match identity {
        Some(identity) => {
            conn.prepare_cached(
                "INSERT INTO native_local_capture (group_id, path, identity) VALUES (?1, ?2, ?3)
                 ON CONFLICT (group_id, path) DO UPDATE SET identity = excluded.identity",
            )?
            .execute(rusqlite::params![group_id, path, identity.to_bytes()])?;
        }
        None => {
            conn.prepare_cached(
                "DELETE FROM native_local_capture WHERE group_id = ?1 AND path = ?2",
            )?
            .execute(rusqlite::params![group_id, path])?;
        }
    }
    Ok(())
}

/// [`record_native_local_capture_in_tx`] for the mutations of one bulk capture group, in order:
/// the records the group leaves are those of recording them one by one (the last entry for a
/// path wins), written as multi-row upserts and one `DELETE ... IN` per chunk.
pub(crate) fn record_native_local_captures_in_tx(
    conn: &Connection,
    group_id: &str,
    entries: &[(&str, Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity>)],
) -> Result<(), SyncSqliteError> {
    // Rows per insert: three parameters each, within SQLite's historical variable limit.
    const ROWS_PER_INSERT: usize = 300;
    let mut last: std::collections::BTreeMap<&str, Option<&_>> = std::collections::BTreeMap::new();
    for (path, identity) in entries {
        last.insert(path, *identity);
    }
    let mut puts = Vec::new();
    let mut deletes = Vec::new();
    for (path, identity) in last {
        match identity {
            Some(identity) => puts.push((path, identity.to_bytes())),
            None => deletes.push(path),
        }
    }
    for chunk in puts.chunks(ROWS_PER_INSERT) {
        let marks = vec!["(?,?,?)"; chunk.len()].join(",");
        let mut stmt = conn.prepare_cached(&format!(
            "INSERT INTO native_local_capture (group_id, path, identity) VALUES {marks} \
             ON CONFLICT (group_id, path) DO UPDATE SET identity = excluded.identity"
        ))?;
        let params = chunk.iter().flat_map(|(path, identity)| {
            [
                rusqlite::types::Value::from(group_id.to_owned()),
                rusqlite::types::Value::from((*path).to_owned()),
                rusqlite::types::Value::from(identity.clone()),
            ]
        });
        stmt.execute(rusqlite::params_from_iter(params))?;
    }
    for chunk in deletes.chunks(crate::store::PATHS_PER_QUERY) {
        let marks = vec!["?"; chunk.len()].join(",");
        let mut stmt = conn.prepare_cached(&format!(
            "DELETE FROM native_local_capture WHERE group_id = ?1 AND path IN ({marks})"
        ))?;
        let params = std::iter::once(group_id).chain(chunk.iter().copied());
        stmt.execute(rusqlite::params_from_iter(params))?;
    }
    Ok(())
}

/// Whether `identity` is the native head local capture most recently put for
/// `path`: this device's disk was its source.
pub fn is_native_local_capture(
    conn: &Connection,
    group_id: &str,
    path: &str,
    identity: &yadorilink_replica_domain::native_plan::NativeRowIdentity,
) -> Result<bool, SyncSqliteError> {
    let recorded: Option<Vec<u8>> = conn
        .prepare_cached(
            "SELECT identity FROM native_local_capture WHERE group_id = ?1 AND path = ?2",
        )?
        .query_row(rusqlite::params![group_id, path], |row| row.get(0))
        .optional()?;
    Ok(recorded.is_some_and(|recorded| recorded == identity.to_bytes()))
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
    use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, SyncPath};
    use yadorilink_replica_domain::native_plan::NativeRowIdentity;
    use yadorilink_replica_domain::native_state::{DeltaHash, Dot};

    fn identity(seq: u64) -> NativeRowIdentity {
        NativeRowIdentity {
            source_path: SyncPath("a.txt".into()),
            dot: Dot {
                author: AuthorId {
                    device: DeviceId("d".into()),
                    incarnation: IncarnationId([1; 16]),
                },
                seq: AuthorSeq(seq),
            },
            provenance: DeltaHash([seq as u8; 32]),
        }
    }

    #[test]
    fn a_native_capture_is_the_most_recent_one_and_a_deletion_retires_it() {
        let conn = Connection::open_in_memory().unwrap();
        init_local_capture_provenance_schema(&conn).unwrap();
        assert!(!is_native_local_capture(&conn, "g", "a.txt", &identity(1)).unwrap());

        record_native_local_capture_in_tx(&conn, "g", "a.txt", Some(&identity(1))).unwrap();
        assert!(is_native_local_capture(&conn, "g", "a.txt", &identity(1)).unwrap());
        assert!(!is_native_local_capture(&conn, "g", "a.txt", &identity(2)).unwrap());

        record_native_local_capture_in_tx(&conn, "g", "a.txt", Some(&identity(2))).unwrap();
        assert!(!is_native_local_capture(&conn, "g", "a.txt", &identity(1)).unwrap());
        assert!(is_native_local_capture(&conn, "g", "a.txt", &identity(2)).unwrap());

        record_native_local_capture_in_tx(&conn, "g", "a.txt", None).unwrap();
        assert!(!is_native_local_capture(&conn, "g", "a.txt", &identity(2)).unwrap());
        assert!(!is_native_local_capture(&conn, "other", "a.txt", &identity(2)).unwrap());
    }

    fn rows(conn: &Connection) -> Vec<(String, Vec<u8>)> {
        conn.prepare("SELECT path, identity FROM native_local_capture ORDER BY path")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// Recording a group's captures together leaves the rows recording them one by one leaves:
    /// puts over existing records, deletions, a path acted on twice (the last wins), and more
    /// puts and deletions than one statement carries.
    #[test]
    fn recording_a_group_together_matches_recording_one_by_one() {
        let (grouped, one_by_one) =
            (Connection::open_in_memory().unwrap(), Connection::open_in_memory().unwrap());
        for c in [&grouped, &one_by_one] {
            init_local_capture_provenance_schema(c).unwrap();
            for i in 0..600 {
                record_native_local_capture_in_tx(
                    c,
                    "g",
                    &format!("old-{i:04}"),
                    Some(&identity(1)),
                )
                .unwrap();
            }
            record_native_local_capture_in_tx(c, "other", "old-0001", Some(&identity(9))).unwrap();
        }
        let ids: Vec<NativeRowIdentity> = (0..700).map(|i| identity(2 + i % 5)).collect();
        let mut paths: Vec<String> = (0..700).map(|i| format!("new-{i:04}")).collect();
        paths.extend((0..600).map(|i| format!("old-{i:04}")));
        let mut entries: Vec<(&str, Option<&NativeRowIdentity>)> = Vec::new();
        for (i, path) in paths.iter().enumerate() {
            // New paths are put; the old ones are deleted, except every tenth, which is put.
            let identity = (i < 700 || i % 10 == 0).then(|| &ids[i % 700]);
            entries.push((path, identity));
        }
        // A path put and then deleted, and one deleted and then put again.
        entries.push(("new-0001", None));
        entries.push(("old-0003", Some(&ids[3])));
        record_native_local_captures_in_tx(&grouped, "g", &entries).unwrap();
        for (path, identity) in &entries {
            record_native_local_capture_in_tx(&one_by_one, "g", path, *identity).unwrap();
        }
        assert_eq!(rows(&grouped), rows(&one_by_one));
        let other: i64 = grouped
            .query_row(
                "SELECT COUNT(*) FROM native_local_capture WHERE group_id = 'other'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(other, 1, "another group's record is untouched");
        assert!(rows(&grouped).len() > 600);
    }
}
