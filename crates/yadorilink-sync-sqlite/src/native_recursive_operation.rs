//! Recursive operations under NativeState: a folder delete or directory rename
//! is authored as several signed deltas, each tagged with the operation it is a
//! part of ([`yadorilink_replica_domain::signed_delta::RecursivePart`]).
//!
//! Two facts are recorded as each delta is installed, locally authored or
//! admitted from a peer:
//!
//! * which parts of an operation have arrived, so a folder restore can say
//!   whether it is partial; and
//! * which operation removed each head (keyed by the removed head's
//!   provenance), so that when the removal is projected the trashed row can be
//!   stamped with the operation and a folder restore can find its siblings.

use rusqlite::{Connection, OptionalExtension};

use yadorilink_replica_domain::ids::DeviceId;
use yadorilink_replica_domain::recursive_operation::{RecursiveOperationId, RecursiveOperationRef};
use yadorilink_replica_domain::signed_delta::NativeDelta;

use crate::SyncSqliteError;

pub(crate) fn init_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS native_recursive_operation_parts (
            group_id     TEXT NOT NULL,
            author       TEXT NOT NULL,
            operation_id BLOB NOT NULL,
            part_index   INTEGER NOT NULL,
            part_count   INTEGER NOT NULL,
            PRIMARY KEY (group_id, author, operation_id, part_index)
        );

        -- The operation that removed the head at `path` with this provenance.
        -- One delta can put several paths under one provenance, so a head is
        -- named by its path as well.
        CREATE TABLE IF NOT EXISTS native_removal_operation (
            group_id     TEXT NOT NULL,
            path         TEXT NOT NULL,
            provenance   BLOB NOT NULL,
            author       TEXT NOT NULL,
            operation_id BLOB NOT NULL,
            PRIMARY KEY (group_id, path, provenance)
        );
        "#,
    )?;
    Ok(())
}

/// The part count an earlier part of `delta`'s recursive operation recorded,
/// when it differs from the one `delta` claims: the operation's parts disagree
/// about their total, so `delta` is not a part of the operation the earlier
/// ones describe.
pub(crate) fn conflicting_part_count(
    conn: &Connection,
    group_id: &str,
    delta: &NativeDelta,
) -> Result<Option<u32>, SyncSqliteError> {
    let Some(part) = delta.recursive_part else { return Ok(None) };
    let recorded: Option<u32> = conn
        .query_row(
            "SELECT part_count FROM native_recursive_operation_parts \
             WHERE group_id = ?1 AND author = ?2 AND operation_id = ?3 LIMIT 1",
            rusqlite::params![group_id, delta.author.device.as_str(), &part.operation_id.0[..]],
            |row| row.get(0),
        )
        .optional()?;
    Ok(recorded.filter(|count| *count != part.part_count))
}

/// Records what `delta` says about its recursive operation; nothing for a
/// delta that is not part of one. A part that claims another total than an
/// earlier part of the same operation is refused; the same claim again is
/// recorded once.
pub(crate) fn record_delta(
    conn: &Connection,
    group_id: &str,
    delta: &NativeDelta,
) -> Result<(), SyncSqliteError> {
    let Some(part) = delta.recursive_part else { return Ok(()) };
    if let Some(recorded) = conflicting_part_count(conn, group_id, delta)? {
        return Err(SyncSqliteError::InvalidInput(format!(
            "recursive operation {:?} of {} is claimed to have {} parts by one part and {recorded} \
             by another",
            part.operation_id, delta.author.device.as_str(), part.part_count
        )));
    }
    let author = delta.author.device.0.as_str();
    conn.execute(
        "INSERT OR IGNORE INTO native_recursive_operation_parts \
         (group_id, author, operation_id, part_index, part_count) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            group_id,
            author,
            &part.operation_id.0[..],
            part.part_index,
            part.part_count
        ],
    )?;
    for op in &delta.ops {
        for removal in &op.removes {
            conn.execute(
                "INSERT OR IGNORE INTO native_removal_operation \
                 (group_id, path, provenance, author, operation_id) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    group_id,
                    op.path.as_str(),
                    &removal.provenance.0[..],
                    author,
                    &part.operation_id.0[..]
                ],
            )?;
        }
    }
    Ok(())
}

/// The operation that removed the head at `path` with `provenance`, if one did.
pub(crate) fn operation_removing(
    conn: &Connection,
    group_id: &str,
    path: &str,
    provenance: &[u8],
) -> Result<Option<RecursiveOperationRef>, SyncSqliteError> {
    let row: Option<(String, Vec<u8>)> = conn
        .query_row(
            "SELECT author, operation_id FROM native_removal_operation \
             WHERE group_id = ?1 AND path = ?2 AND provenance = ?3",
            rusqlite::params![group_id, path, provenance],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(author, id)| {
        let id: [u8; 16] = id.try_into().map_err(|_| {
            SyncSqliteError::CorruptState("native removal operation id is not 16 bytes".into())
        })?;
        Ok(RecursiveOperationRef {
            author: DeviceId(author),
            operation_id: RecursiveOperationId(id),
        })
    })
    .transpose()
}

/// How much of a recursive operation this replica has seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeOperationCompleteness {
    Complete,
    Partial {
        missing_part_indexes: Vec<u32>,
    },
    /// The parts disagree about how many there are, or none is recorded.
    Inconsistent,
}

pub fn completeness(
    conn: &Connection,
    group_id: &str,
    operation: &RecursiveOperationRef,
) -> Result<NativeOperationCompleteness, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT part_index, part_count FROM native_recursive_operation_parts \
         WHERE group_id = ?1 AND author = ?2 AND operation_id = ?3 ORDER BY part_index",
    )?;
    let rows = stmt
        .query_map(
            rusqlite::params![group_id, operation.author.as_str(), &operation.operation_id.0[..]],
            |row| Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?)),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let Some(&(_, count)) = rows.first() else {
        return Ok(NativeOperationCompleteness::Inconsistent);
    };
    if rows.iter().any(|&(_, c)| c != count) {
        return Ok(NativeOperationCompleteness::Inconsistent);
    }
    let have: std::collections::BTreeSet<u32> = rows.iter().map(|&(i, _)| i).collect();
    let missing: Vec<u32> = (0..count).filter(|i| !have.contains(i)).collect();
    Ok(if missing.is_empty() {
        NativeOperationCompleteness::Complete
    } else {
        NativeOperationCompleteness::Partial { missing_part_indexes: missing }
    })
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
    use yadorilink_replica_domain::ids::{AuthorSeq, FolderGroupId, SyncPath, VersionHash};
    use yadorilink_replica_domain::signed_delta::{
        DeltaOp, DeltaPut, HeadRef, NativeDelta, RecursivePart,
    };

    use super::*;

    const GROUP: &str = "g";

    fn author() -> AuthorId {
        AuthorId { device: DeviceId("device-a".into()), incarnation: IncarnationId([1; 16]) }
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[5; 32])
    }

    fn operation() -> RecursiveOperationRef {
        RecursiveOperationRef {
            author: DeviceId("device-a".into()),
            operation_id: RecursiveOperationId([8; 16]),
        }
    }

    /// Installs the author's next delta.
    fn install(conn: &Connection, op: DeltaOp, part: Option<RecursivePart>) -> NativeDelta {
        let group = FolderGroupId(GROUP.into());
        let (seq, prev) =
            match crate::native_store::frontier_entry_get(conn, &group, &author()).unwrap() {
                None => (AuthorSeq::FIRST, None),
                Some(entry) => (entry.seq.checked_next().unwrap(), Some(entry.tip)),
            };
        let mut delta = NativeDelta {
            recursive_part: part,
            group_id: group.clone(),
            author: author(),
            seq,
            prev,
            ops: vec![op],
            signature: [0; 64],
        };
        delta.sign(&key());
        crate::native_store::install_verified_delta(conn, &group, &delta, &key().verifying_key())
            .unwrap();
        delta
    }

    fn put(path: &str, byte: u8) -> DeltaOp {
        DeltaOp {
            path: SyncPath(path.into()),
            removes: Vec::new(),
            put: Some(DeltaPut { version: VersionHash([byte; 32]) }),
        }
    }

    fn part(index: u32, count: u32) -> Option<RecursivePart> {
        Some(RecursivePart {
            operation_id: operation().operation_id,
            part_index: index,
            part_count: count,
        })
    }

    #[test]
    fn an_operation_is_partial_until_every_part_has_been_installed() {
        let conn = Connection::open_in_memory().unwrap();
        crate::replica_tables::init(&conn).unwrap();
        let first = install(&conn, put("a", 1), None);
        let second = install(&conn, put("b", 2), None);
        let removal = |delta: &NativeDelta, path: &str| DeltaOp {
            path: SyncPath(path.into()),
            removes: vec![HeadRef { dot: delta.dot(), provenance: delta.delta_hash() }],
            put: None,
        };

        install(&conn, removal(&first, "a"), part(0, 2));
        assert_eq!(
            completeness(&conn, GROUP, &operation()).unwrap(),
            NativeOperationCompleteness::Partial { missing_part_indexes: vec![1] }
        );
        install(&conn, removal(&second, "b"), part(1, 2));
        assert_eq!(
            completeness(&conn, GROUP, &operation()).unwrap(),
            NativeOperationCompleteness::Complete
        );

        // The removed heads name the operation; an untouched head does not.
        assert_eq!(
            operation_removing(&conn, GROUP, "a", &first.delta_hash().0).unwrap(),
            Some(operation())
        );
        assert_eq!(
            operation_removing(&conn, GROUP, "b", &second.delta_hash().0).unwrap(),
            Some(operation())
        );
        assert_eq!(operation_removing(&conn, GROUP, "b", &[9; 32]).unwrap(), None);
        // The same provenance at another path is not that head's removal.
        assert_eq!(
            operation_removing(&conn, GROUP, "elsewhere", &first.delta_hash().0).unwrap(),
            None
        );
    }

    /// A part that claims another total than an earlier part of the same
    /// operation is refused as malformed, not silently ignored (which would
    /// leave the operation looking complete under the first claim); the same
    /// claim delivered again changes nothing.
    #[test]
    fn a_part_claiming_another_count_than_a_recorded_part_is_refused() {
        use crate::native_admission::{admit_native_delta, NativeAdmission};
        let conn = Connection::open_in_memory().unwrap();
        crate::replica_tables::init(&conn).unwrap();
        let group = FolderGroupId(GROUP.into());
        let first = install(&conn, put("a", 1), part(0, 2));

        // The author's next delta claims three parts for the same operation.
        let tip =
            crate::native_store::frontier_entry_get(&conn, &group, &author()).unwrap().unwrap();
        let mut lying = NativeDelta {
            recursive_part: part(1, 3),
            group_id: group.clone(),
            author: author(),
            seq: tip.seq.checked_next().unwrap(),
            prev: Some(tip.tip),
            ops: vec![put("b", 2)],
            signature: [0; 64],
        };
        lying.sign(&key());
        let verdict =
            admit_native_delta(&conn, &group, &lying, &|_: &AuthorId| Some(key().verifying_key()))
                .unwrap();
        assert!(matches!(verdict, NativeAdmission::Malformed(_)), "{verdict:?}");
        assert_eq!(
            completeness(&conn, GROUP, &operation()).unwrap(),
            NativeOperationCompleteness::Partial { missing_part_indexes: vec![1] },
            "the recorded claim is unchanged"
        );

        // Recording the same part again is idempotent; a conflicting one is an error.
        record_delta(&conn, GROUP, &first).unwrap();
        assert!(record_delta(&conn, GROUP, &lying).is_err());
    }

    #[test]
    fn an_operation_no_part_of_which_is_recorded_is_not_complete() {
        let conn = Connection::open_in_memory().unwrap();
        crate::replica_tables::init(&conn).unwrap();
        assert_eq!(
            completeness(&conn, GROUP, &operation()).unwrap(),
            NativeOperationCompleteness::Inconsistent
        );
    }
}
