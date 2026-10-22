//! This replica's authoring identity and the clone/restore guard.
//!
//! The replica authors as an [`AuthorId`]: its device and its current
//! incarnation, stored in the singleton table `author_incarnation`
//! ([`IncarnationRecord`]). Authoring reads the author and the guard
//! through this module and keeps no incarnation state of its own.
//!
//! An incarnation is 16 random bytes, minted when the database is created
//! and replaced (rotated) whenever the database may be a copy of another
//! replica's, so that two copies never write under one author:
//!
//! * the database no longer matches its sidecar: the `<db>.instance` file
//!   kept beside it ([`InstanceSidecar`]) is missing, or its random
//!   database instance nonce or its incarnation differs from the record, as
//!   after a restore from backup, a copy of the database file alone, or a
//!   crash between storing a new record and writing its sidecar
//!   ([`IncarnationMintReason::Restore`]);
//! * the machine fingerprint changed: the database moved to another machine
//!   ([`IncarnationMintReason::Migration`]);
//! * the device identity changed ([`IncarnationMintReason::IdentityMismatch`]);
//! * a peer reported this replica's own author above its local watermark:
//!   another copy already wrote under it ([`IncarnationMintReason::
//!   OwnAuthorAhead`]). Until the rotation, authoring in that group is
//!   refused ([`own_author_ahead`]).
//!
//! A rotation starts a new author; the old author's history stays valid and
//! is never written to again. Every mint draws a fresh random incarnation
//! and a fresh random nonce. The sidecar is only ever compared with the
//! record, never read into it, so an incarnation rotated away is never
//! adopted again. No signing-key fingerprint takes part: the device ↔
//! signing-key binding belongs to the policy layer.
//!
//! The machine fingerprint is not part of the author identity; it only
//! detects a database copied together with its sidecar to another machine.
//!
//! [`IncarnationRecord`]: yadorilink_replica_domain::author::IncarnationRecord

use rusqlite::{params, Connection, OptionalExtension};
use yadorilink_replica_domain::author::{
    AuthorId, IncarnationId, IncarnationMintReason, IncarnationRecord,
};
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId};

use crate::SyncSqliteError;

/// A peer reported this replica's own author (same incarnation) above the
/// local watermark in a group: another copy of this replica wrote under the
/// same identity.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OwnAuthorAhead {
    pub author: AuthorId,
    pub local: AuthorSeq,
    pub reported: AuthorSeq,
}

/// The content of the `<db>.instance` sidecar kept beside the replica
/// database: the nonce and incarnation of the record it was written for.
/// The daemon reads and writes the file; this module only compares it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InstanceSidecar {
    pub db_instance_nonce: [u8; 16],
    pub incarnation: IncarnationId,
}

impl InstanceSidecar {
    /// The sidecar that belongs beside `record`.
    pub fn for_record(record: &IncarnationRecord) -> Self {
        Self { db_instance_nonce: record.db_instance_nonce, incarnation: record.author.incarnation }
    }
}

/// What the database is opened in, compared with what its incarnation was
/// minted in.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IncarnationEnvironment {
    /// The device identity the replica runs as.
    pub device_id: DeviceId,
    /// The sidecar read from beside the database; `None` when it is absent
    /// (or unreadable, which is treated the same way).
    pub sidecar: Option<InstanceSidecar>,
    /// A fingerprint of the machine the database is opened on.
    pub machine_fingerprint: Vec<u8>,
}

/// Creates the incarnation tables (`replica_tables::init`).
pub fn init_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS author_incarnation (
            singleton           INTEGER PRIMARY KEY CHECK (singleton = 1),
            device_id           TEXT NOT NULL,
            incarnation         BLOB NOT NULL CHECK (length(incarnation) = 16),
            db_instance_nonce   BLOB NOT NULL CHECK (length(db_instance_nonce) = 16),
            machine_fingerprint BLOB NOT NULL,
            minted_reason       TEXT NOT NULL,
            previous            BLOB CHECK (previous IS NULL OR length(previous) = 16)
        );
        CREATE TABLE IF NOT EXISTS install_witness (
            singleton   INTEGER PRIMARY KEY CHECK (singleton = 1),
            token       BLOB NOT NULL CHECK (length(token) = 16),
            generation  INTEGER NOT NULL CHECK (generation >= 1)
        );
        CREATE TABLE IF NOT EXISTS author_own_ahead (
            group_id     TEXT NOT NULL,
            device_id    TEXT NOT NULL,
            incarnation  BLOB NOT NULL,
            local_seq    INTEGER NOT NULL,
            reported_seq INTEGER NOT NULL,
            PRIMARY KEY (group_id, device_id, incarnation)
        ) WITHOUT ROWID;",
    )?;
    Ok(())
}

/// The installation token and write generation the database holds. A copy of
/// both is kept outside the database's backup set (the daemon's
/// `install_witness`), so a restored or copied database disagrees with it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct InstallWitness {
    pub token: [u8; 16],
    pub generation: u64,
}

/// The stored installation witness, or `None` for a database that has none
/// (new, or from before witnesses existed).
pub fn install_witness(conn: &Connection) -> Result<Option<InstallWitness>, SyncSqliteError> {
    init_schema(conn)?;
    let row = conn
        .query_row("SELECT token, generation FROM install_witness WHERE singleton = 1", [], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })
        .optional()?;
    let Some((token, generation)) = row else {
        return Ok(None);
    };
    Ok(Some(InstallWitness {
        token: bytes16(token, "install_witness.token")?,
        generation: u64::try_from(generation).map_err(|_| {
            SyncSqliteError::CorruptState(format!("install_witness holds generation {generation}"))
        })?,
    }))
}

/// Replaces the stored installation witness.
pub fn store_install_witness(
    conn: &Connection,
    witness: &InstallWitness,
) -> Result<(), SyncSqliteError> {
    init_schema(conn)?;
    let generation = i64::try_from(witness.generation).map_err(|_| {
        SyncSqliteError::InvalidInput(format!("install witness generation {}", witness.generation))
    })?;
    conn.execute(
        "INSERT OR REPLACE INTO install_witness (singleton, token, generation) \
         VALUES (1, ?1, ?2)",
        params![&witness.token[..], generation],
    )?;
    Ok(())
}

fn reason_name(reason: IncarnationMintReason) -> &'static str {
    match reason {
        IncarnationMintReason::Install => "install",
        IncarnationMintReason::Restore => "restore",
        IncarnationMintReason::Migration => "migration",
        IncarnationMintReason::IdentityMismatch => "identity-mismatch",
        IncarnationMintReason::OwnAuthorAhead => "own-author-ahead",
        IncarnationMintReason::Rebootstrap => "rebootstrap",
    }
}

fn reason_of(name: &str) -> Option<IncarnationMintReason> {
    Some(match name {
        "install" => IncarnationMintReason::Install,
        "restore" => IncarnationMintReason::Restore,
        "migration" => IncarnationMintReason::Migration,
        "identity-mismatch" => IncarnationMintReason::IdentityMismatch,
        "own-author-ahead" => IncarnationMintReason::OwnAuthorAhead,
        "rebootstrap" => IncarnationMintReason::Rebootstrap,
        _ => return None,
    })
}

fn bytes16(bytes: Vec<u8>, column: &str) -> Result<[u8; 16], SyncSqliteError> {
    bytes.try_into().map_err(|_| {
        SyncSqliteError::CorruptState(format!("author_incarnation.{column} is not 16 bytes"))
    })
}

/// The stored incarnation record, or `None` before the first mint.
pub fn incarnation_record(conn: &Connection) -> Result<Option<IncarnationRecord>, SyncSqliteError> {
    init_schema(conn)?;
    let row = conn
        .prepare_cached(
            "SELECT device_id, incarnation, db_instance_nonce, machine_fingerprint, \
                    minted_reason, previous \
             FROM author_incarnation WHERE singleton = 1",
        )?
        .query_row([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
            ))
        })
        .optional()?;
    let Some((device, incarnation, db_instance_nonce, machine_fingerprint, reason, previous)) = row
    else {
        return Ok(None);
    };
    let minted_reason = reason_of(&reason).ok_or_else(|| {
        SyncSqliteError::CorruptState(format!("author_incarnation has mint reason {reason:?}"))
    })?;
    Ok(Some(IncarnationRecord {
        author: AuthorId {
            device: DeviceId(device),
            incarnation: IncarnationId(bytes16(incarnation, "incarnation")?),
        },
        db_instance_nonce: bytes16(db_instance_nonce, "db_instance_nonce")?,
        machine_fingerprint,
        minted_reason,
        previous: previous
            .map(|bytes| bytes16(bytes, "previous").map(IncarnationId))
            .transpose()?,
    }))
}

/// Stores `record` as the current incarnation and drops every
/// own-author-ahead report: they were about an author this replica no
/// longer writes as.
fn store(conn: &Connection, record: &IncarnationRecord) -> Result<(), SyncSqliteError> {
    atomically(conn, || {
        conn.execute(
            "INSERT OR REPLACE INTO author_incarnation \
             (singleton, device_id, incarnation, db_instance_nonce, machine_fingerprint, \
              minted_reason, previous) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.author.device.as_str(),
                &record.author.incarnation.0[..],
                &record.db_instance_nonce[..],
                &record.machine_fingerprint,
                reason_name(record.minted_reason),
                record.previous.as_ref().map(|previous| previous.0.to_vec()),
            ],
        )?;
        conn.execute("DELETE FROM author_own_ahead", [])?;
        Ok(())
    })
}

fn atomically<T>(
    conn: &Connection,
    body: impl FnOnce() -> Result<T, SyncSqliteError>,
) -> Result<T, SyncSqliteError> {
    conn.execute_batch("SAVEPOINT author_incarnation")?;
    match body() {
        Ok(value) => {
            conn.execute_batch("RELEASE author_incarnation")?;
            Ok(value)
        }
        Err(error) => {
            let _ =
                conn.execute_batch("ROLLBACK TO author_incarnation; RELEASE author_incarnation");
            Err(error)
        }
    }
}

fn mint(
    device: DeviceId,
    machine_fingerprint: Vec<u8>,
    reason: IncarnationMintReason,
    previous: Option<IncarnationId>,
) -> IncarnationRecord {
    IncarnationRecord {
        author: AuthorId { device, incarnation: IncarnationId(rand::random()) },
        db_instance_nonce: rand::random(),
        machine_fingerprint,
        minted_reason: reason,
        previous,
    }
}

/// Makes sure the replica has an incarnation that is safe to author under
/// in `environment` (module doc), minting or rotating one if not, and
/// returns it. The caller writes [`InstanceSidecar::for_record`] of the
/// returned record beside the database before authoring under it; writing
/// it when it is unchanged is harmless.
///
/// The checks, in order: the device identity differs
/// ([`IncarnationMintReason::IdentityMismatch`]); the sidecar is absent or
/// its nonce or incarnation differs from the record
/// ([`IncarnationMintReason::Restore`]); the machine fingerprint differs
/// ([`IncarnationMintReason::Migration`]). Each mismatch mints a fresh
/// incarnation and nonce and records the old incarnation as `previous`.
pub fn ensure_incarnation(
    conn: &Connection,
    environment: &IncarnationEnvironment,
) -> Result<IncarnationRecord, SyncSqliteError> {
    let Some(current) = incarnation_record(conn)? else {
        let record = mint(
            environment.device_id.clone(),
            environment.machine_fingerprint.clone(),
            IncarnationMintReason::Install,
            None,
        );
        store(conn, &record)?;
        return Ok(record);
    };
    let reason = if current.author.device != environment.device_id {
        IncarnationMintReason::IdentityMismatch
    } else if environment.sidecar != Some(InstanceSidecar::for_record(&current))
        && !sidecar_is_the_one_a_rebootstrap_replaced(&current, environment.sidecar)
    {
        IncarnationMintReason::Restore
    } else if current.machine_fingerprint != environment.machine_fingerprint {
        IncarnationMintReason::Migration
    } else {
        return Ok(current);
    };
    let record = mint(
        environment.device_id.clone(),
        environment.machine_fingerprint.clone(),
        reason,
        Some(current.author.incarnation),
    );
    store(conn, &record)?;
    Ok(record)
}

/// Whether `sidecar` is the stale one of this record's own rotation: the record
/// was minted by a rebootstrap and the sidecar still names the incarnation it
/// replaced. The rotation commits with the rebootstrap's install but the sidecar
/// is written after it, so a crash between the two leaves exactly this pair; it
/// is not a restored or copied database, and minting another incarnation for it
/// would orphan the changes already authored under this one. The caller writes
/// the sidecar of the returned record, which repairs it.
fn sidecar_is_the_one_a_rebootstrap_replaced(
    record: &IncarnationRecord,
    sidecar: Option<InstanceSidecar>,
) -> bool {
    record.minted_reason == IncarnationMintReason::Rebootstrap
        && record.previous.is_some()
        && sidecar.is_some_and(|sidecar| Some(sidecar.incarnation) == record.previous)
}

/// Replaces the current incarnation with a fresh one for `reason`, keeping
/// the device and machine. Refused before the first mint. The caller
/// writes the new sidecar before authoring under the new incarnation.
pub fn rotate_incarnation(
    conn: &Connection,
    reason: IncarnationMintReason,
) -> Result<IncarnationRecord, SyncSqliteError> {
    let current = incarnation_record(conn)?
        .ok_or_else(|| SyncSqliteError::NotFound("no author incarnation to rotate".into()))?;
    let record = mint(
        current.author.device.clone(),
        current.machine_fingerprint.clone(),
        reason,
        Some(current.author.incarnation),
    );
    store(conn, &record)?;
    Ok(record)
}

/// The author this replica signs new changes as. Fails closed before an
/// incarnation is minted ([`ensure_incarnation`]).
pub fn current_author(conn: &Connection) -> Result<AuthorId, SyncSqliteError> {
    incarnation_record(conn)?
        .map(|record| record.author)
        .ok_or_else(|| SyncSqliteError::NotFound("no author incarnation has been minted".into()))
}

/// Records that a peer reported `author` at `reported` in `group_id`, above
/// the local watermark `local`. Only a report about this replica's current
/// author above its watermark is kept (the greatest reported sequence per
/// group); anything else is ignored. Returns whether a report is now held.
pub fn note_own_author_ahead(
    conn: &Connection,
    group_id: &str,
    report: &OwnAuthorAhead,
) -> Result<bool, SyncSqliteError> {
    if report.reported <= report.local || current_author(conn)? != report.author {
        return Ok(false);
    }
    conn.execute(
        "INSERT INTO author_own_ahead \
         (group_id, device_id, incarnation, local_seq, reported_seq) \
         VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT (group_id, device_id, incarnation) DO UPDATE SET \
           local_seq = excluded.local_seq, \
           reported_seq = max(reported_seq, excluded.reported_seq)",
        params![
            group_id,
            report.author.device.as_str(),
            &report.author.incarnation.0[..],
            seq_param(report.local)?,
            seq_param(report.reported)?,
        ],
    )?;
    Ok(true)
}

fn seq_param(seq: AuthorSeq) -> Result<i64, SyncSqliteError> {
    i64::try_from(seq.0).map_err(|_| SyncSqliteError::InvalidInput(format!("author seq {seq:?}")))
}

/// The unresolved own-author-ahead report for `group_id`, if any. While one
/// is present the replica refuses to author in the group
/// (`AuthoringRefusal::OwnAuthorAhead`) until the incarnation is rotated.
pub fn own_author_ahead(
    conn: &Connection,
    group_id: &str,
) -> Result<Option<OwnAuthorAhead>, SyncSqliteError> {
    let author = current_author(conn)?;
    let row = conn
        .prepare_cached(
            "SELECT local_seq, reported_seq FROM author_own_ahead \
             WHERE group_id = ?1 AND device_id = ?2 AND incarnation = ?3",
        )?
        .query_row(params![group_id, author.device.as_str(), &author.incarnation.0[..]], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })
        .optional()?;
    let Some((local, reported)) = row else {
        return Ok(None);
    };
    let seq = |value: i64| {
        u64::try_from(value).map(AuthorSeq).map_err(|_| {
            SyncSqliteError::CorruptState(format!("author_own_ahead holds sequence {value}"))
        })
    };
    Ok(Some(OwnAuthorAhead { author, local: seq(local)?, reported: seq(reported)? }))
}

/// Whether an unresolved own-author-ahead report about the current author
/// is held in any group. The daemon rotates before handing out an author
/// handle while one is.
pub fn any_own_author_ahead(conn: &Connection) -> Result<bool, SyncSqliteError> {
    let author = current_author(conn)?;
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS (SELECT 1 FROM author_own_ahead \
             WHERE device_id = ?1 AND incarnation = ?2)",
        )?
        .query_row(params![author.device.as_str(), &author.incarnation.0[..]], |row| {
            row.get::<_, bool>(0)
        })?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment(
        device: &str,
        sidecar: Option<InstanceSidecar>,
        machine: &[u8],
    ) -> IncarnationEnvironment {
        IncarnationEnvironment {
            device_id: DeviceId(device.into()),
            sidecar,
            machine_fingerprint: machine.to_vec(),
        }
    }

    fn fresh() -> (Connection, IncarnationRecord) {
        let conn = Connection::open_in_memory().unwrap();
        let record = ensure_incarnation(&conn, &environment("dev", None, b"m1")).unwrap();
        (conn, record)
    }

    #[test]
    fn nothing_is_authored_before_an_incarnation_is_minted() {
        let conn = Connection::open_in_memory().unwrap();
        assert!(matches!(current_author(&conn), Err(SyncSqliteError::NotFound(_))));
        assert!(matches!(own_author_ahead(&conn, "g"), Err(SyncSqliteError::NotFound(_))));
    }

    #[test]
    fn a_fresh_database_mints_an_incarnation() {
        let (conn, record) = fresh();
        assert_eq!(record.minted_reason, IncarnationMintReason::Install);
        assert_eq!(record.previous, None);
        assert_eq!(current_author(&conn).unwrap(), record.author);
        assert_eq!(incarnation_record(&conn).unwrap(), Some(record));
    }

    #[test]
    fn a_normal_restart_keeps_the_incarnation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.sqlite");
        let first = {
            let conn = Connection::open(&path).unwrap();
            ensure_incarnation(&conn, &environment("dev", None, b"m1")).unwrap()
        };
        let conn = Connection::open(&path).unwrap();
        let again = ensure_incarnation(
            &conn,
            &environment("dev", Some(InstanceSidecar::for_record(&first)), b"m1"),
        )
        .unwrap();
        assert_eq!(again, first);
    }

    fn assert_rotated(
        conn: &Connection,
        before: &IncarnationRecord,
        after: &IncarnationRecord,
        reason: IncarnationMintReason,
    ) {
        assert_eq!(after.minted_reason, reason);
        assert_ne!(after.author.incarnation, before.author.incarnation);
        assert_ne!(after.db_instance_nonce, before.db_instance_nonce);
        assert_eq!(after.previous, Some(before.author.incarnation));
        assert_eq!(current_author(conn).unwrap(), after.author);
    }

    #[test]
    fn a_database_restored_without_its_sidecar_rotates() {
        let (conn, before) = fresh();
        for sidecar in [
            None,
            Some(InstanceSidecar {
                db_instance_nonce: [0xee; 16],
                incarnation: before.author.incarnation,
            }),
        ] {
            let current = incarnation_record(&conn).unwrap().unwrap();
            let after = ensure_incarnation(&conn, &environment("dev", sidecar, b"m1")).unwrap();
            assert_rotated(&conn, &current, &after, IncarnationMintReason::Restore);
        }
        assert_ne!(current_author(&conn).unwrap(), before.author);
    }

    #[test]
    fn a_device_id_mismatch_rotates() {
        let (conn, before) = fresh();
        let after = ensure_incarnation(
            &conn,
            &environment("other", Some(InstanceSidecar::for_record(&before)), b"m1"),
        )
        .unwrap();
        assert_rotated(&conn, &before, &after, IncarnationMintReason::IdentityMismatch);
        assert_eq!(after.author.device, DeviceId("other".into()));
    }

    #[test]
    fn a_copied_database_on_a_second_machine_rotates() {
        let (conn, before) = fresh();
        let after = ensure_incarnation(
            &conn,
            &environment("dev", Some(InstanceSidecar::for_record(&before)), b"m2"),
        )
        .unwrap();
        assert_rotated(&conn, &before, &after, IncarnationMintReason::Migration);
    }

    /// The sidecar must match the record in both its nonce and its
    /// incarnation: a sidecar with the right nonce beside a different
    /// incarnation is a mismatch too.
    #[test]
    fn a_sidecar_naming_another_incarnation_rotates() {
        let (conn, before) = fresh();
        let stale = InstanceSidecar {
            db_instance_nonce: before.db_instance_nonce,
            incarnation: IncarnationId([0x42; 16]),
        };
        let after = ensure_incarnation(&conn, &environment("dev", Some(stale), b"m1")).unwrap();
        assert_rotated(&conn, &before, &after, IncarnationMintReason::Restore);
    }

    /// A crash after the new record commits but before its sidecar is
    /// written leaves the old sidecar beside the new record. The next open
    /// rotates again: the abandoned incarnation is never used, and neither
    /// the old one nor the abandoned one is ever adopted from a sidecar.
    #[test]
    fn a_crash_between_the_record_and_the_sidecar_rotates_and_never_reuses() {
        let (conn, first) = fresh();
        let old_sidecar = InstanceSidecar::for_record(&first);
        // Rotation stored, crash before the sidecar write.
        let abandoned = rotate_incarnation(&conn, IncarnationMintReason::OwnAuthorAhead).unwrap();
        let reopened =
            ensure_incarnation(&conn, &environment("dev", Some(old_sidecar), b"m1")).unwrap();
        assert_rotated(&conn, &abandoned, &reopened, IncarnationMintReason::Restore);
        assert_ne!(reopened.author.incarnation, first.author.incarnation);
        // The sidecar of the rotated-away record, presented again, is still
        // a mismatch and mints yet another incarnation.
        for stale in [old_sidecar, InstanceSidecar::for_record(&abandoned)] {
            let current = incarnation_record(&conn).unwrap().unwrap();
            let next = ensure_incarnation(&conn, &environment("dev", Some(stale), b"m1")).unwrap();
            assert_rotated(&conn, &current, &next, IncarnationMintReason::Restore);
            for retired in [first.author.incarnation, abandoned.author.incarnation] {
                assert_ne!(next.author.incarnation, retired);
            }
        }
        // Writing the sidecar for the current record makes the next open
        // keep it.
        let current = incarnation_record(&conn).unwrap().unwrap();
        let kept = ensure_incarnation(
            &conn,
            &environment("dev", Some(InstanceSidecar::for_record(&current)), b"m1"),
        )
        .unwrap();
        assert_eq!(kept, current);
    }

    /// The check order is device, then sidecar, then machine: a mismatch of
    /// an earlier check is reported even when a later one also differs.
    #[test]
    fn the_checks_run_device_then_sidecar_then_machine() {
        let (conn, _) = fresh();
        let after = ensure_incarnation(&conn, &environment("other", None, b"m2")).unwrap();
        assert_eq!(after.minted_reason, IncarnationMintReason::IdentityMismatch);
        let after = ensure_incarnation(&conn, &environment("other", None, b"m3")).unwrap();
        assert_eq!(after.minted_reason, IncarnationMintReason::Restore);
    }

    /// Schema 68 creates the incarnation table eagerly, with the renamed
    /// nonce column.
    #[test]
    fn schema_71_creates_the_incarnation_table() {
        let database = crate::replica_tables::open_for_tests();
        database
            .read(|conn| {
                let columns: Vec<String> = conn
                    .prepare("SELECT name FROM pragma_table_info('author_incarnation')")?
                    .query_map([], |row| row.get(0))?
                    .collect::<Result<_, _>>()?;
                assert!(columns.iter().any(|c| c == "db_instance_nonce"), "{columns:?}");
                assert!(!columns.iter().any(|c| c == "db_instance_id"), "{columns:?}");
                Ok::<_, SyncSqliteError>(())
            })
            .unwrap();
    }

    /// A report of this replica's own author above its watermark blocks
    /// authoring in that group only, keeps the greatest reported sequence,
    /// and is resolved by rotating: the new author has no report.
    #[test]
    fn an_own_author_ahead_report_holds_until_the_incarnation_rotates() {
        let (conn, record) = fresh();
        let report = |local, reported| OwnAuthorAhead {
            author: record.author.clone(),
            local: AuthorSeq(local),
            reported: AuthorSeq(reported),
        };
        assert!(!note_own_author_ahead(&conn, "g", &report(5, 5)).unwrap());
        assert_eq!(own_author_ahead(&conn, "g").unwrap(), None);
        assert!(note_own_author_ahead(&conn, "g", &report(5, 9)).unwrap());
        assert!(note_own_author_ahead(&conn, "g", &report(5, 7)).unwrap());
        assert_eq!(own_author_ahead(&conn, "g").unwrap(), Some(report(5, 9)));
        assert_eq!(own_author_ahead(&conn, "h").unwrap(), None);
        assert!(any_own_author_ahead(&conn).unwrap());

        let stranger = OwnAuthorAhead {
            author: AuthorId {
                device: DeviceId("dev".into()),
                incarnation: IncarnationId([1; 16]),
            },
            local: AuthorSeq(1),
            reported: AuthorSeq(4),
        };
        assert!(!note_own_author_ahead(&conn, "h", &stranger).unwrap());

        let rotated = rotate_incarnation(&conn, IncarnationMintReason::OwnAuthorAhead).unwrap();
        assert_eq!(rotated.previous, Some(record.author.incarnation));
        assert_eq!(own_author_ahead(&conn, "g").unwrap(), None);
        assert!(!any_own_author_ahead(&conn).unwrap());
        // A late report about the retired author changes nothing.
        assert!(!note_own_author_ahead(&conn, "g", &report(5, 11)).unwrap());
    }
}
