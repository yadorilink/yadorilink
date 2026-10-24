//! Opening this replica's author identity: the [`LocalAuthorKey`] new
//! changes are signed with, bound to a safe author incarnation.
//!
//! [`open_author_identity`] reads the `<db>.instance` sidecar
//! ([`crate::author_sidecar`]), runs the incarnation check
//! (`author_incarnation::ensure_incarnation`: device, then sidecar, then
//! machine fingerprint), rotates once more if a peer has reported this
//! replica's own author ahead in any group, writes the sidecar durably, and
//! only then hands out the handle. Crash ordering: the database commit of a
//! new record comes first, the sidecar write second, the handle last. A
//! crash between the first two leaves the old sidecar beside the new record;
//! the next open sees the mismatch and rotates again, abandoning the
//! never-used incarnation. The sidecar is compared, never adopted, so an
//! incarnation rotated away is never used again.
//!
//! [`rotate_on_own_author_ahead`] is the reaction to
//! `AuthoringRefusal::OwnAuthorAhead`: rotate, write the sidecar, swap the
//! shared handle under its lock. It is also the reaction to
//! `AuthoringRefusal::StaleAuthor`, which authoring returns for any handle
//! that does not name the current incarnation: one cloned out of the slot
//! before a rotation, or the slot itself when a rotation committed but its
//! sidecar write failed. Without a report left to act on, the call re-reads
//! the current incarnation, writes its sidecar and swaps the slot to it.
//! Authoring itself never signs as a retired incarnation, so a stale handle
//! can only be refused, never fork the retired author.
//!
//! What the sidecar cannot detect: a database restored together with its
//! own matching sidecar on the same machine and device passes the device,
//! sidecar and machine checks. The installation witness
//! ([`crate::install_witness`]), kept outside the backed-up data set, is
//! compared first: a restored or copied database is refused
//! ([`AuthorIdentityError::DatabaseRestored`]) before anything is minted or
//! rotated, and status reports `database_restored`. A restore within the
//! same daemon run as its backup is left to the network: a peer that holds
//! the incarnation's later changes reports it ahead, and the replica
//! rotates before authoring again.
//!
//! [`ReplicaAuthor`] is how the daemon holds it: the replica coordinator
//! opens one when the device's signing key is wired
//! (`DaemonState::set_device_signing_key`), before anything authors, and
//! every local write, import, backfill and restore signs with its current
//! handle. An authoring refusal for a stale or overtaken author refreshes it
//! ([`ReplicaAuthor::refresh`]) and the write is retried with the new handle.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::Connection;
use yadorilink_replica_domain::admission::LocalAuthorKey;
use yadorilink_replica_domain::author::{IncarnationMintReason, IncarnationRecord};
use yadorilink_replica_domain::ids::DeviceId;
use yadorilink_sync_sqlite::author_incarnation::{self, IncarnationEnvironment, InstanceSidecar};
use yadorilink_sync_sqlite::SyncSqliteError;

use crate::author_sidecar;

#[derive(Debug, thiserror::Error)]
pub enum AuthorIdentityError {
    #[error("author incarnation store: {0}")]
    Store(#[from] SyncSqliteError),
    #[error("replica instance sidecar: {0}")]
    Sidecar(#[from] std::io::Error),
    /// The connection is inside a transaction, so a new record would not be
    /// committed before its sidecar is written.
    #[error("the author identity must be opened outside a transaction")]
    InTransaction,
    /// The database was restored or copied ([`crate::install_witness`]): no
    /// author handle is handed out, and nothing is rotated or minted.
    #[error("{0}")]
    DatabaseRestored(crate::install_witness::Restored),
    #[error("installation witness: {0}")]
    Witness(std::io::Error),
}

/// Opens the author identity of the replica database at `db_path` (module
/// doc), for `device_id` signing with `signing_key`. `conn` must be a
/// connection to that database outside any transaction.
///
/// `placement` is where the installation witness is kept. The engine's composition root chooses
/// it; nothing is read from the environment here.
pub fn open_author_identity(
    conn: &Connection,
    db_path: &Path,
    placement: &crate::install_witness::WitnessPlacement,
    device_id: &str,
    signing_key: ed25519_dalek::SigningKey,
) -> Result<Arc<LocalAuthorKey>, AuthorIdentityError> {
    let witness = placement.store(db_path).map_err(AuthorIdentityError::Witness)?;
    open_author_identity_on(
        conn,
        db_path,
        device_id,
        signing_key,
        crate::machine_fingerprint::machine_fingerprint(),
        &witness,
    )
}

/// [`open_author_identity`] with an injected machine fingerprint.
pub(crate) fn open_author_identity_on(
    conn: &Connection,
    db_path: &Path,
    device_id: &str,
    signing_key: ed25519_dalek::SigningKey,
    machine_fingerprint: Vec<u8>,
    witness: &dyn crate::install_witness::WitnessStore,
) -> Result<Arc<LocalAuthorKey>, AuthorIdentityError> {
    if !conn.is_autocommit() {
        return Err(AuthorIdentityError::InTransaction);
    }
    check_install_witness(conn, device_id, witness)?;
    let environment = IncarnationEnvironment {
        device_id: DeviceId(device_id.to_owned()),
        sidecar: author_sidecar::read_sidecar(db_path)?,
        machine_fingerprint: comparable_fingerprint(conn, machine_fingerprint)?,
    };
    let mut record = author_incarnation::ensure_incarnation(conn, &environment)?;
    if author_incarnation::any_own_author_ahead(conn)? {
        record =
            author_incarnation::rotate_incarnation(conn, IncarnationMintReason::OwnAuthorAhead)?;
    }
    Ok(Arc::new(publish(db_path, &record, signing_key)?))
}

/// Compares the database's installation witness with the side copy
/// ([`crate::install_witness::judge`]) before anything is minted or rotated;
/// a restored or copied database is refused, otherwise the advanced witness
/// is stored in the database and then in the side store. The database goes
/// first, so a crash between the two leaves the database ahead, which the
/// next open accepts.
fn check_install_witness(
    conn: &Connection,
    device_id: &str,
    witness: &dyn crate::install_witness::WitnessStore,
) -> Result<(), AuthorIdentityError> {
    use crate::install_witness::{judge_with, Verdict};
    // A side copy that cannot be read cannot be compared: refused, and reported.
    let side = witness.read().unwrap_or(crate::install_witness::SideCopy::Unreadable);
    // A database with no author for this device has no identity to protect: it
    // is new, or the device was registered again (the incarnation check then
    // rotates it away from the old device's author).
    let no_identity_here = author_incarnation::incarnation_record(conn)?
        .is_none_or(|record| record.author.device.as_str() != device_id);
    match judge_with(
        author_incarnation::install_witness(conn)?,
        side,
        no_identity_here,
        rand::random(),
        witness.persists(),
    ) {
        Verdict::Refuse(reason) => Err(AuthorIdentityError::DatabaseRestored(reason)),
        Verdict::Record(next) => {
            author_incarnation::store_install_witness(conn, &next)?;
            witness.write(&next).map_err(AuthorIdentityError::Witness)
        }
    }
}

/// The fingerprint to compare with the record's. When this machine's id could
/// not be read (possibly only for this boot), the record's own fingerprint is
/// used instead, so an unreadable id never causes a `Migration` rotation, nor
/// a second one on the next boot when the id reads again. A database that
/// was first opened without a readable id rotates once when the id first
/// reads.
fn comparable_fingerprint(
    conn: &Connection,
    machine_fingerprint: Vec<u8>,
) -> Result<Vec<u8>, AuthorIdentityError> {
    if !crate::machine_fingerprint::is_unavailable(&machine_fingerprint) {
        return Ok(machine_fingerprint);
    }
    Ok(author_incarnation::incarnation_record(conn)?
        .map_or(machine_fingerprint, |record| record.machine_fingerprint))
}

/// Writes the sidecar for the committed `record`, then builds its handle.
fn publish(
    db_path: &Path,
    record: &IncarnationRecord,
    signing_key: ed25519_dalek::SigningKey,
) -> Result<LocalAuthorKey, AuthorIdentityError> {
    author_sidecar::write_sidecar(db_path, &InstanceSidecar::for_record(record))?;
    Ok(LocalAuthorKey::new(record.author.clone(), signing_key))
}

/// Reacts to an own-author-ahead or stale-author refusal: under `handle`'s
/// lock, rotates the incarnation if an own-author-ahead report about the
/// current author is held, writes the sidecar, and swaps in a handle for the
/// current author with the same signing key. Returns the handle now current;
/// the caller retries authoring with it.
///
/// Idempotent: when no report is held (a concurrent caller already rotated,
/// or the refusal was a stale author), it only makes sure `handle` names the
/// current author and its sidecar is written. When the sidecar write fails
/// after a rotation committed, the slot keeps the retired author, which
/// authoring refuses as stale; calling this again completes the swap.
pub fn rotate_on_own_author_ahead(
    conn: &Connection,
    db_path: &Path,
    handle: &Mutex<Arc<LocalAuthorKey>>,
) -> Result<Arc<LocalAuthorKey>, AuthorIdentityError> {
    if !conn.is_autocommit() {
        return Err(AuthorIdentityError::InTransaction);
    }
    let mut current = handle.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let signing_key = current.signing_key().clone();
    let record = if author_incarnation::any_own_author_ahead(conn)? {
        author_incarnation::rotate_incarnation(conn, IncarnationMintReason::OwnAuthorAhead)?
    } else {
        let record = author_incarnation::incarnation_record(conn)?.ok_or_else(|| {
            SyncSqliteError::NotFound("no author incarnation has been minted".into())
        })?;
        if current.author() == record.author {
            return Ok(current.clone());
        }
        record
    };
    *current = Arc::new(publish(db_path, &record, signing_key)?);
    Ok(current.clone())
}

/// The file of `conn`'s main database; `None` for an in-memory one.
fn main_database_path(conn: &Connection) -> Result<Option<PathBuf>, SyncSqliteError> {
    let file: String =
        conn.query_row("SELECT file FROM pragma_database_list WHERE name = 'main'", [], |row| {
            row.get(0)
        })?;
    Ok((!file.is_empty()).then(|| PathBuf::from(file)))
}

/// A replica's author identity as the daemon holds it: the current handle,
/// behind the lock [`rotate_on_own_author_ahead`] swaps it under, and the
/// database file whose sidecar binds it.
///
/// An in-memory database (test replicas only; production always opens a
/// file) has no sidecar to write: its identity is the record alone, minted
/// once and rotated only on an own-author-ahead report. Nothing can restore
/// or copy an in-memory database, which is all the sidecar detects.
pub struct ReplicaAuthor {
    db_path: Option<PathBuf>,
    slot: Mutex<Arc<LocalAuthorKey>>,
}

impl ReplicaAuthor {
    /// Opens the author identity of `database` for `device_id` signing with
    /// `signing_key`: [`open_author_identity`] for a database file.
    pub fn open(
        database: &yadorilink_sqlite_runtime::SyncDatabase,
        placement: &crate::install_witness::WitnessPlacement,
        device_id: &str,
        signing_key: ed25519_dalek::SigningKey,
    ) -> Result<Self, AuthorIdentityError> {
        database
            .write::<_, IdentityStep>(|conn| {
                let db_path = main_database_path(conn)?;
                let handle = match &db_path {
                    Some(path) => {
                        open_author_identity(conn, path, placement, device_id, signing_key.clone())?
                    }
                    None => Arc::new(LocalAuthorKey::new(
                        in_memory_record(conn, device_id)?.author,
                        signing_key.clone(),
                    )),
                };
                Ok(Self { db_path, slot: Mutex::new(handle) })
            })
            .map_err(IdentityStep::into_inner)
    }

    /// The handle new changes are signed with.
    pub fn current(&self) -> Arc<LocalAuthorKey> {
        self.slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
    }

    /// Reacts to an `OwnAuthorAhead` or `StaleAuthor` authoring refusal
    /// ([`rotate_on_own_author_ahead`]); the handle now current.
    pub fn refresh(
        &self,
        database: &yadorilink_sqlite_runtime::SyncDatabase,
    ) -> Result<Arc<LocalAuthorKey>, AuthorIdentityError> {
        database
            .write::<_, IdentityStep>(|conn| match &self.db_path {
                Some(path) => Ok(rotate_on_own_author_ahead(conn, path, &self.slot)?),
                None => {
                    let mut current =
                        self.slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    let record = if author_incarnation::any_own_author_ahead(conn)? {
                        author_incarnation::rotate_incarnation(
                            conn,
                            IncarnationMintReason::OwnAuthorAhead,
                        )?
                    } else {
                        in_memory_record(conn, current.device_id())?
                    };
                    *current =
                        Arc::new(LocalAuthorKey::new(record.author, current.signing_key().clone()));
                    Ok(current.clone())
                }
            })
            .map_err(IdentityStep::into_inner)
    }
}

/// The incarnation record of an in-memory replica, minted (`Install`) when
/// it has none.
fn in_memory_record(
    conn: &Connection,
    device_id: &str,
) -> Result<IncarnationRecord, SyncSqliteError> {
    match author_incarnation::incarnation_record(conn)? {
        Some(record) => Ok(record),
        None => author_incarnation::ensure_incarnation(
            conn,
            &IncarnationEnvironment {
                device_id: DeviceId(device_id.to_owned()),
                sidecar: None,
                machine_fingerprint: Vec::new(),
            },
        ),
    }
}

/// An [`AuthorIdentityError`] carried through the database's write closure,
/// whose error type must convert from the SQLite and pool errors.
#[derive(Debug)]
struct IdentityStep(AuthorIdentityError);

impl IdentityStep {
    fn into_inner(self) -> AuthorIdentityError {
        self.0
    }
}

impl From<AuthorIdentityError> for IdentityStep {
    fn from(error: AuthorIdentityError) -> Self {
        Self(error)
    }
}

impl From<SyncSqliteError> for IdentityStep {
    fn from(error: SyncSqliteError) -> Self {
        Self(AuthorIdentityError::Store(error))
    }
}

impl From<rusqlite::Error> for IdentityStep {
    fn from(error: rusqlite::Error) -> Self {
        Self(AuthorIdentityError::Store(error.into()))
    }
}

impl From<r2d2::Error> for IdentityStep {
    fn from(error: r2d2::Error) -> Self {
        Self(AuthorIdentityError::Store(error.into()))
    }
}

impl yadorilink_sqlite_runtime::SqlOperationError for IdentityStep {
    fn is_locked(&self) -> bool {
        matches!(
            &self.0,
            AuthorIdentityError::Store(error)
                if yadorilink_sqlite_runtime::SqlOperationError::is_locked(error)
        )
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use yadorilink_replica_domain::author::{AuthorId, AuthoringRefusal};
    use yadorilink_replica_domain::ids::{AuthorSeq, SyncPath, VersionHash};
    use yadorilink_replica_domain::local_op::Op;
    use yadorilink_sync_sqlite::author_incarnation::OwnAuthorAhead;
    use yadorilink_sync_sqlite::local_author::LocalAuthor;
    use yadorilink_sync_sqlite::native_authoring::author_op;
    use yadorilink_sync_sqlite::SyncSqliteError;

    use super::*;

    const DEVICE: &str = "device-a";

    struct Replica {
        _dir: tempfile::TempDir,
        db: PathBuf,
        witness: crate::install_witness::fake::MemoryWitness,
    }

    impl Replica {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let db = dir.path().join("replica.sqlite");
            Self { _dir: dir, db, witness: crate::install_witness::fake::MemoryWitness::new() }
        }

        fn conn(&self) -> Connection {
            Connection::open(&self.db).unwrap()
        }

        fn open_on(&self, device: &str, machine: &[u8]) -> Arc<LocalAuthorKey> {
            open_author_identity_on(
                &self.conn(),
                &self.db,
                device,
                key(),
                machine.to_vec(),
                &self.witness,
            )
            .unwrap()
        }

        fn open(&self) -> Arc<LocalAuthorKey> {
            self.open_on(DEVICE, b"machine-1")
        }

        fn record(&self) -> IncarnationRecord {
            author_incarnation::incarnation_record(&self.conn()).unwrap().unwrap()
        }

        fn sidecar(&self) -> Option<InstanceSidecar> {
            author_sidecar::read_sidecar(&self.db).unwrap()
        }

        fn assert_consistent(&self, handle: &LocalAuthorKey) {
            let record = self.record();
            assert_eq!(handle.author(), record.author.clone());
            assert_eq!(self.sidecar(), Some(InstanceSidecar::for_record(&record)));
        }
    }

    fn key() -> ed25519_dalek::SigningKey {
        yadorilink_replica_domain::author::fixtures::signing_key(&DeviceId(DEVICE.to_owned()))
    }

    fn author(handle: &LocalAuthorKey) -> AuthorId {
        handle.author()
    }

    #[test]
    fn a_fresh_replica_mints_writes_its_sidecar_and_keeps_it_on_restart() {
        let replica = Replica::new();
        assert_eq!(replica.sidecar(), None);
        let first = replica.open();
        assert_eq!(replica.record().minted_reason, IncarnationMintReason::Install);
        assert_eq!(first.device_id(), DEVICE);
        assert_eq!(first.signing_key().to_bytes(), key().to_bytes());
        replica.assert_consistent(&first);

        let again = replica.open();
        assert_eq!(author(&again), author(&first));
        replica.assert_consistent(&again);
    }

    #[test]
    fn a_missing_or_foreign_sidecar_rotates() {
        let replica = Replica::new();
        let first = replica.open();
        std::fs::remove_file(author_sidecar::sidecar_path(&replica.db)).unwrap();
        let restored = replica.open();
        assert_ne!(author(&restored), author(&first));
        assert_eq!(replica.record().minted_reason, IncarnationMintReason::Restore);
        replica.assert_consistent(&restored);

        // The database file copied alone beside another replica's sidecar.
        let other = Replica::new();
        other.open();
        std::fs::copy(
            author_sidecar::sidecar_path(&other.db),
            author_sidecar::sidecar_path(&replica.db),
        )
        .unwrap();
        let copied = replica.open();
        assert_ne!(author(&copied), author(&restored));
        assert_eq!(replica.record().minted_reason, IncarnationMintReason::Restore);
        replica.assert_consistent(&copied);
    }

    fn snapshot(replica: &Replica, to: &std::path::Path) {
        let conn = replica.conn();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").ok();
        std::fs::copy(&replica.db, to).unwrap();
        std::fs::copy(author_sidecar::sidecar_path(&replica.db), author_sidecar::sidecar_path(to))
            .unwrap();
    }

    fn put_back(replica: &Replica, from: &std::path::Path) {
        std::fs::copy(from, &replica.db).unwrap();
        std::fs::copy(
            author_sidecar::sidecar_path(from),
            author_sidecar::sidecar_path(&replica.db),
        )
        .unwrap();
    }

    fn refused(replica: &Replica) -> crate::install_witness::Restored {
        match open_author_identity_on(
            &replica.conn(),
            &replica.db,
            DEVICE,
            key(),
            b"machine-1".to_vec(),
            &replica.witness,
        ) {
            Err(AuthorIdentityError::DatabaseRestored(reason)) => reason,
            Err(other) => panic!("expected a refusal, got {other}"),
            Ok(_) => panic!("expected a refusal, got a handle"),
        }
    }

    /// The database and its sidecar are restored together on the same
    /// machine: the sidecar and machine checks pass, the witness does not.
    #[test]
    fn an_older_database_restored_with_its_sidecar_is_refused() {
        use crate::install_witness::Restored;
        let replica = Replica::new();
        replica.open();
        let backup = replica._dir.path().join("backup.sqlite");
        snapshot(&replica, &backup);
        replica.open();

        put_back(&replica, &backup);
        let restored_record = replica.record();
        assert_eq!(refused(&replica), Restored::OlderGeneration);
        // Refusing mints and rotates nothing.
        assert_eq!(replica.record(), restored_record);
        // And it stays refused on the next open.
        assert_eq!(refused(&replica), Restored::OlderGeneration);
    }

    /// The recovery the status text names: the device is registered again,
    /// so the database no longer holds an author of the current device.
    #[test]
    fn registering_the_device_again_clears_a_refusal() {
        use crate::install_witness::Restored;
        let replica = Replica::new();
        let first = replica.open();
        let backup = replica._dir.path().join("backup.sqlite");
        snapshot(&replica, &backup);
        replica.open();
        put_back(&replica, &backup);
        assert_eq!(refused(&replica), Restored::OlderGeneration);

        let renewed = replica.open_on("device-b", b"machine-1");
        assert_eq!(renewed.device_id(), "device-b");
        assert_ne!(author(&renewed).incarnation, author(&first).incarnation);
        assert_eq!(replica.record().minted_reason, IncarnationMintReason::IdentityMismatch);
        // And it opens normally from then on.
        assert_eq!(author(&replica.open_on("device-b", b"machine-1")), author(&renewed));
    }

    #[test]
    fn a_database_of_another_install_is_refused() {
        use crate::install_witness::Restored;
        let replica = Replica::new();
        let other = Replica::new();
        other.open();
        replica.open();
        std::fs::copy(&other.db, &replica.db).unwrap();
        std::fs::copy(
            author_sidecar::sidecar_path(&other.db),
            author_sidecar::sidecar_path(&replica.db),
        )
        .unwrap();
        assert_eq!(refused(&replica), Restored::DifferentInstall);
    }

    #[test]
    fn the_first_run_after_an_upgrade_is_recorded_not_refused() {
        let replica = Replica::new();
        let first = replica.open();
        // A database from before the witness: no witness row, no side copy.
        replica.conn().execute("DROP TABLE install_witness", []).unwrap();
        replica.witness.0.set(crate::install_witness::SideCopy::Absent);
        let again = replica.open();
        assert_eq!(author(&again), author(&first));
        assert!(author_incarnation::install_witness(&replica.conn()).unwrap().is_some());
    }

    #[test]
    fn an_unreadable_side_copy_is_refused() {
        let replica = Replica::new();
        replica.open();
        replica.witness.0.set(crate::install_witness::SideCopy::Unreadable);
        assert_eq!(refused(&replica), crate::install_witness::Restored::Unverifiable);
    }

    /// The new record commits, then the process dies before the sidecar
    /// write. The next open rotates again: the incarnation of the crashed
    /// open is abandoned, and neither it nor the previous one is reused.
    #[test]
    fn a_crash_between_the_commit_and_the_sidecar_write_rotates() {
        let replica = Replica::new();
        let first = replica.open();
        let abandoned = author_incarnation::rotate_incarnation(
            &replica.conn(),
            IncarnationMintReason::OwnAuthorAhead,
        )
        .unwrap();
        let reopened = replica.open();
        assert_eq!(replica.record().minted_reason, IncarnationMintReason::Restore);
        assert_eq!(replica.record().previous, Some(abandoned.author.incarnation));
        for retired in [author(&first), abandoned.author] {
            assert_ne!(author(&reopened), retired);
        }
        replica.assert_consistent(&reopened);
    }

    /// Putting back the sidecar of an incarnation that was rotated away,
    /// beside the database that rotated it away, never brings that
    /// incarnation back. This covers the sidecar restored alone only: a
    /// database restored together with its own matching sidecar passes every
    /// local check and keeps its incarnation, and is left to the
    /// own-author-ahead report of a peer (module doc).
    #[test]
    fn a_rotated_away_incarnation_is_never_readopted() {
        let replica = Replica::new();
        let first = replica.open();
        let old_sidecar = std::fs::read(author_sidecar::sidecar_path(&replica.db)).unwrap();
        std::fs::remove_file(author_sidecar::sidecar_path(&replica.db)).unwrap();
        let second = replica.open();
        std::fs::write(author_sidecar::sidecar_path(&replica.db), old_sidecar).unwrap();
        let third = replica.open();
        for retired in [author(&first), author(&second)] {
            assert_ne!(author(&third), retired);
        }
        replica.assert_consistent(&third);
    }

    #[test]
    fn a_database_and_sidecar_moved_to_another_machine_rotates() {
        let replica = Replica::new();
        let first = replica.open_on(DEVICE, b"machine-1");
        let moved = replica.open_on(DEVICE, b"machine-2");
        assert_ne!(author(&moved), author(&first));
        assert_eq!(replica.record().minted_reason, IncarnationMintReason::Migration);
        replica.assert_consistent(&moved);
    }

    #[test]
    fn a_device_identity_change_rotates() {
        let replica = Replica::new();
        replica.open();
        let other = replica.open_on("device-b", b"machine-1");
        assert_eq!(other.device_id(), "device-b");
        assert_eq!(replica.record().minted_reason, IncarnationMintReason::IdentityMismatch);
        replica.assert_consistent(&other);
    }

    fn report_ahead(replica: &Replica, handle: &LocalAuthorKey, group: &str) {
        let report =
            OwnAuthorAhead { author: author(handle), local: AuthorSeq(1), reported: AuthorSeq(4) };
        assert!(author_incarnation::note_own_author_ahead(&replica.conn(), group, &report).unwrap());
    }

    #[test]
    fn an_own_author_ahead_report_rotates_before_the_handle_is_handed_out() {
        let replica = Replica::new();
        let first = replica.open();
        report_ahead(&replica, &first, "g");
        let reopened = replica.open();
        assert_ne!(author(&reopened), author(&first));
        assert_eq!(replica.record().minted_reason, IncarnationMintReason::OwnAuthorAhead);
        assert!(!author_incarnation::any_own_author_ahead(&replica.conn()).unwrap());
        replica.assert_consistent(&reopened);
    }

    #[test]
    fn own_author_ahead_rotates_writes_the_sidecar_and_swaps_the_handle() {
        let replica = Replica::new();
        let first = replica.open();
        let handle = Mutex::new(first.clone());
        report_ahead(&replica, &first, "g");

        let rotated = rotate_on_own_author_ahead(&replica.conn(), &replica.db, &handle).unwrap();
        assert_ne!(author(&rotated), author(&first));
        assert!(Arc::ptr_eq(&rotated, &handle.lock().unwrap()));
        assert_eq!(rotated.signing_key().to_bytes(), key().to_bytes());
        assert_eq!(replica.record().minted_reason, IncarnationMintReason::OwnAuthorAhead);
        replica.assert_consistent(&rotated);

        // A second refusal racing the first finds nothing left to rotate.
        let again = rotate_on_own_author_ahead(&replica.conn(), &replica.db, &handle).unwrap();
        assert!(Arc::ptr_eq(&again, &rotated));

        // And the rotated handle survives a restart.
        assert_eq!(author(&replica.open()), author(&rotated));
    }

    fn authoring_db(replica: &Replica) -> Connection {
        let conn = replica.conn();
        yadorilink_sync_sqlite::replica_tables::init_for_tests(&conn).unwrap();
        conn
    }

    /// Authors one put of `path` in group `g` as `handle`.
    fn author_with(
        conn: &Connection,
        handle: &LocalAuthorKey,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        let local = LocalAuthor {
            author: author(handle),
            signing_key: handle.signing_key(),
            capture: None,
        };
        let path = SyncPath(path.to_owned());
        let op = Op::Put { path: path.clone(), version: VersionHash([1; 32]) };
        author_op(conn, &yadorilink_replica_domain::ids::FolderGroupId("g".to_owned()), &local, &op)
            .map(drop)
    }

    fn assert_stale(result: Result<(), SyncSqliteError>, retired: &LocalAuthorKey) {
        assert!(matches!(
            result,
            Err(SyncSqliteError::AuthoringRefused {
                refusal: AuthoringRefusal::StaleAuthor { ref author, .. }
            }) if *author == self::author(retired)
        ));
    }

    /// A handle cloned out of the slot before a rotation keeps naming the
    /// retired incarnation; authoring refuses it, and the handle re-read
    /// from the slot authors.
    #[test]
    fn a_handle_from_before_a_rotation_is_refused_and_the_slot_authors() {
        let replica = Replica::new();
        let conn = authoring_db(&replica);
        let first = replica.open();
        let handle = Mutex::new(first.clone());
        let old = handle.lock().unwrap().clone();
        author_with(&conn, &old, "before").unwrap();
        report_ahead(&replica, &first, "g");

        rotate_on_own_author_ahead(&conn, &replica.db, &handle).unwrap();
        assert_stale(author_with(&conn, &old, "after"), &first);

        let current = handle.lock().unwrap().clone();
        assert_ne!(author(&current), author(&first));
        author_with(&conn, &current, "after").unwrap();
    }

    /// The rotation commits, then the sidecar write fails: the slot still
    /// names the retired author and the report that refused it is gone.
    /// Authoring refuses the slot as stale; calling the reaction again
    /// writes the sidecar and swaps the slot to the new incarnation.
    #[test]
    fn a_failed_sidecar_write_after_a_rotation_leaves_a_refused_slot_until_retried() {
        let replica = Replica::new();
        let conn = authoring_db(&replica);
        let first = replica.open();
        let handle = Mutex::new(first.clone());
        report_ahead(&replica, &first, "g");
        let sidecar = author_sidecar::sidecar_path(&replica.db);
        std::fs::remove_file(&sidecar).unwrap();
        std::fs::create_dir(&sidecar).unwrap();

        let failed = rotate_on_own_author_ahead(&conn, &replica.db, &handle);
        assert!(matches!(failed, Err(AuthorIdentityError::Sidecar(_))));
        let rotated = replica.record();
        assert_eq!(rotated.minted_reason, IncarnationMintReason::OwnAuthorAhead);
        assert_ne!(rotated.author, author(&first));
        assert!(!author_incarnation::any_own_author_ahead(&conn).unwrap());
        let slot = handle.lock().unwrap().clone();
        assert!(Arc::ptr_eq(&slot, &first));
        assert_stale(author_with(&conn, &slot, "a"), &first);

        std::fs::remove_dir(&sidecar).unwrap();
        let current = rotate_on_own_author_ahead(&conn, &replica.db, &handle).unwrap();
        assert_eq!(author(&current), rotated.author);
        assert!(Arc::ptr_eq(&current, &handle.lock().unwrap()));
        replica.assert_consistent(&current);
        author_with(&conn, &current, "a").unwrap();
        assert_eq!(author(&replica.open()), rotated.author);
    }

    /// An unreadable machine id (for this boot only, say) never rotates,
    /// neither when it fails to read nor when it reads again.
    #[test]
    fn an_unreadable_machine_id_does_not_rotate() {
        let replica = Replica::new();
        let unavailable = crate::machine_fingerprint::fingerprint_of(None);
        let first = replica.open_on(DEVICE, b"machine-1");
        let unreadable = replica.open_on(DEVICE, &unavailable);
        assert_eq!(author(&unreadable), author(&first));
        let readable = replica.open_on(DEVICE, b"machine-1");
        assert_eq!(author(&readable), author(&first));
        assert_eq!(replica.record().minted_reason, IncarnationMintReason::Install);
        replica.assert_consistent(&readable);
    }

    /// Opening through the real placements: with a persistent witness, one that has gone missing
    /// (a purge) while the database records it refuses the open; with a clearable one the
    /// witness is recorded again; and the first open of a fresh install works either way.
    #[test]
    fn a_purged_persistent_witness_refuses_the_open_and_a_clearable_one_is_recorded_again() {
        use crate::install_witness::WitnessPlacement;
        for (persistent, reopen_refused) in [(true, true), (false, false)] {
            let replica = Replica::new();
            let dir = replica._dir.path().join("witness");
            let placement = if persistent {
                WitnessPlacement::Persistent(dir.clone())
            } else {
                WitnessPlacement::At(dir.clone())
            };
            let open =
                || open_author_identity(&replica.conn(), &replica.db, &placement, DEVICE, key());
            open().expect("a fresh install opens");
            open().expect("a normal restart opens");
            for entry in std::fs::read_dir(&dir).unwrap() {
                std::fs::remove_file(entry.unwrap().path()).unwrap();
            }
            match open() {
                Err(AuthorIdentityError::DatabaseRestored(
                    crate::install_witness::Restored::Unverifiable,
                )) => assert!(reopen_refused, "a clearable witness is recorded again"),
                Ok(_) => assert!(!reopen_refused, "a persistent witness that vanished must refuse"),
                Err(other) => panic!("unexpected: {other}"),
            }
        }
    }

    #[test]
    fn opening_inside_a_transaction_is_refused() {
        let replica = Replica::new();
        let conn = replica.conn();
        conn.execute_batch("BEGIN").unwrap();
        let refused = open_author_identity_on(
            &conn,
            &replica.db,
            DEVICE,
            key(),
            b"m".to_vec(),
            &replica.witness,
        );
        assert!(matches!(refused, Err(AuthorIdentityError::InTransaction)));
        assert_eq!(replica.sidecar(), None);
    }
}
