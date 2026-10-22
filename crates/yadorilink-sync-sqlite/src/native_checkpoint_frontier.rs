//! What a trusted checkpoint covers: the author states it was sealed over,
//! persisted with the adoption of the checkpoint.
//!
//! A checkpoint row (`native_checkpoints`) holds only the roots the sealer
//! signed. The per-author states those roots commit to live here, in
//! `native_checkpoint_frontier`, and are the single answer to "which deltas does
//! trusted checkpoint X cover". An open author's row is a real entry (sequence
//! at least 1 with a real tip); a closed author's row carries its cutoff entry,
//! or none when it was closed before its first delta.
//!

use rusqlite::Connection;

use yadorilink_replica_domain::author::AuthorId;
use yadorilink_replica_domain::ids::{AuthorSeq, FolderGroupId};
use yadorilink_replica_domain::native_checkpoint::NativeCheckpoint;
use yadorilink_replica_domain::native_checkpoint_seal::NativeCheckpointSealEvidence;
use yadorilink_replica_domain::native_frontier::{
    author_state_root, frontier_of_states, AuthorState, NativeAuthorFrontier,
    NativeAuthorFrontierEntry, NativeAuthorStates,
};
use yadorilink_replica_domain::native_state::DeltaHash;

use crate::error::SyncSqliteError;

/// The author states a checkpoint covers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CheckpointCoverage {
    /// Every author the checkpoint holds a state for, closed ones included.
    pub states: NativeAuthorStates,
}

impl CheckpointCoverage {
    /// The positions the checkpoint covers: every author with an entry.
    pub fn frontier(&self) -> NativeAuthorFrontier {
        frontier_of_states(&self.states)
    }

    /// The author-state root these states build.
    pub fn recomputed_root(&self) -> [u8; 32] {
        author_state_root(&self.states)
    }

    /// Whether these states are what `checkpoint` committed to.
    fn check_commits_to(&self, checkpoint: &NativeCheckpoint) -> Result<(), SyncSqliteError> {
        self.check_against_root(&checkpoint.author_state_root.0)
    }

    /// Whether these states build exactly the root `signed_root`. Run on states
    /// read back from storage, it detects a single altered state, cutoff or row.
    pub(crate) fn check_against_root(&self, signed_root: &[u8]) -> Result<(), SyncSqliteError> {
        if self.recomputed_root().as_slice() != signed_root {
            return Err(SyncSqliteError::InvalidInput(
                "checkpoint coverage refused: the author states do not build the checkpoint's \
                 author-state root"
                    .into(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn init_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        -- The author states each trusted checkpoint covers: one row per
        -- author-incarnation. An entry is real (seq >= 1, a real tip); a closed
        -- author's entry is its cutoff, and a closed author with no entry was
        -- closed before its first delta. An open author always has an entry.
        CREATE TABLE IF NOT EXISTS native_checkpoint_frontier (
            group_id         TEXT NOT NULL,
            checkpoint_id    BLOB NOT NULL,
            author           TEXT NOT NULL,
            incarnation      BLOB NOT NULL,
            closed           INTEGER NOT NULL CHECK (closed IN (0, 1)),
            seq              INTEGER CHECK (seq IS NULL OR seq >= 1),
            tip              BLOB,
            PRIMARY KEY (group_id, checkpoint_id, author, incarnation),
            CHECK ((seq IS NULL) = (tip IS NULL)),
            CHECK (closed = 1 OR seq IS NOT NULL)
        ) WITHOUT ROWID;
        "#,
    )?;
    Ok(())
}

/// Adopts `checkpoint`: stores it with its seal evidence and the author states it
/// covers, as one step. The caller has verified the seal
/// authorization (`seal`) and `sealer_key` is the key that authorization names; this
/// function trusts that, so it is crate-private and reached only through the
/// verifying entry points ([`crate::native_checkpoint_authorization::install_authorized_checkpoint`]
/// and the bootstrap join).
///
/// Refused, with nothing written, when the signature does not verify or `coverage`
/// does not build the root the checkpoint signed. Adopting a checkpoint that is
/// already held changes nothing. Safe inside the caller's transaction (it runs under
/// a savepoint) and on its own.
pub(crate) fn adopt_verified_checkpoint(
    conn: &Connection,
    group_id: &FolderGroupId,
    checkpoint: &NativeCheckpoint,
    seal: &NativeCheckpointSealEvidence,
    sealer_key: &ed25519_dalek::VerifyingKey,
    coverage: &CheckpointCoverage,
) -> Result<(), SyncSqliteError> {
    coverage.check_commits_to(checkpoint)?;
    conn.execute_batch("SAVEPOINT native_adopt_checkpoint")?;
    match write_adoption(conn, group_id, checkpoint, seal, sealer_key, coverage) {
        Ok(()) => {
            conn.execute_batch("RELEASE native_adopt_checkpoint")?;
            Ok(())
        }
        Err(error) => {
            conn.execute_batch(
                "ROLLBACK TO native_adopt_checkpoint; RELEASE native_adopt_checkpoint",
            )?;
            Err(error)
        }
    }
}

fn write_adoption(
    conn: &Connection,
    group_id: &FolderGroupId,
    checkpoint: &NativeCheckpoint,
    seal: &NativeCheckpointSealEvidence,
    sealer_key: &ed25519_dalek::VerifyingKey,
    coverage: &CheckpointCoverage,
) -> Result<(), SyncSqliteError> {
    let hash = checkpoint.checkpoint_hash().0;
    crate::native_store::install_checkpoint(conn, group_id, checkpoint, sealer_key)?;
    crate::native_checkpoint_authorization::store_seal_evidence(conn, group_id, &hash, seal)?;
    let mut insert = conn.prepare_cached(
        "INSERT OR IGNORE INTO native_checkpoint_frontier \
         (group_id, checkpoint_id, author, incarnation, closed, seq, tip) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;
    for (author, state) in &coverage.states {
        let entry = state.entry();
        insert.execute((
            group_id.as_str(),
            hash.as_slice(),
            author.device.as_str(),
            author.incarnation.0.as_slice(),
            state.is_closed() as i64,
            entry.map(|entry| entry.seq.get() as i64),
            entry.map(|entry| entry.tip.0.to_vec()),
        ))?;
    }
    Ok(())
}

/// The frontier `checkpoint_id` covers, as persisted at its adoption (empty for a
/// checkpoint that was never adopted): every author with an entry, closed ones
/// included.
pub fn checkpoint_frontier(
    conn: &Connection,
    group_id: &FolderGroupId,
    checkpoint_id: &[u8; 32],
) -> Result<NativeAuthorFrontier, SyncSqliteError> {
    Ok(frontier_of_states(&checkpoint_states(conn, group_id, checkpoint_id)?))
}

fn checkpoint_states(
    conn: &Connection,
    group_id: &FolderGroupId,
    checkpoint_id: &[u8; 32],
) -> Result<NativeAuthorStates, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT author, incarnation, closed, seq, tip \
         FROM native_checkpoint_frontier WHERE group_id = ?1 AND checkpoint_id = ?2",
    )?;
    let mut rows = stmt.query((group_id.as_str(), checkpoint_id.as_slice()))?;
    let mut states = NativeAuthorStates::new();
    while let Some(row) = rows.next()? {
        let author: AuthorId = crate::native_store::read_author(row.get(0)?, row.get(1)?)?;
        let closed = row.get::<_, i64>(2)? != 0;
        let entry = match (row.get::<_, Option<i64>>(3)?, row.get::<_, Option<Vec<u8>>>(4)?) {
            (Some(seq), Some(tip)) => Some(NativeAuthorFrontierEntry {
                seq: AuthorSeq(seq as u64),
                tip: DeltaHash(crate::native_store::as_array32(&tip)?),
            }),
            _ => None,
        };
        let state = match (closed, entry) {
            (true, frontier) => AuthorState::Closed { frontier },
            (false, Some(entry)) => AuthorState::Open(entry),
            (false, None) => {
                return Err(SyncSqliteError::CorruptState(
                    "an open author of a checkpoint has no entry".into(),
                ))
            }
        };
        states.insert(author, state);
    }
    Ok(states)
}

/// The author states `checkpoint_id` covers.
pub fn checkpoint_coverage(
    conn: &Connection,
    group_id: &FolderGroupId,
    checkpoint_id: &[u8; 32],
) -> Result<CheckpointCoverage, SyncSqliteError> {
    Ok(CheckpointCoverage { states: checkpoint_states(conn, group_id, checkpoint_id)? })
}

/// Seals and adopts the group's current state as a trusted checkpoint without a
/// real authority: for tests that need a trusted checkpoint to exist.
#[cfg(any(test, feature = "test-support"))]
pub fn adopt_current_state_for_test(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<[u8; 32], SyncSqliteError> {
    let key = ed25519_dalek::SigningKey::from_bytes(&[13; 32]);
    let checkpoint = crate::native_store::seal_checkpoint(conn, group_id, &key)?;
    let coverage =
        CheckpointCoverage { states: crate::native_store::load_author_states(conn, group_id)? };
    let seal = NativeCheckpointSealEvidence {
        sealer: yadorilink_replica_domain::ids::DeviceId("test-sealer".into()),
        evidence: vec![1],
    };
    adopt_verified_checkpoint(conn, group_id, &checkpoint, &seal, &key.verifying_key(), &coverage)?;
    Ok(checkpoint.checkpoint_hash().0)
}

/// A trusted checkpoint: one adopted through [`adopt_verified_checkpoint`], which
/// stores the seal authorization it was verified under with it. A checkpoint row
/// with no such evidence was installed without that verification and is not
/// trusted by anything that asks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedCheckpoint {
    /// The checkpoint's identity hash, the key of its frontier rows.
    pub checkpoint_id: [u8; 32],
    pub namespace_root: [u8; 32],
    pub author_state_root: [u8; 32],
    pub adopted_at_unixtime: i64,
}

/// The most recently adopted trusted checkpoint of `group_id`, if any. For
/// diagnostics and tests only: neither admission nor the choice of a rebootstrap
/// target may read it.
///
/// "Most recently adopted" is the order of adoption: the adoption time in seconds,
/// then the row order within a second. It is not the order of the checkpoints'
/// ages, so the result is not monotone along the frontier: the clock can step back
/// between two adoptions, and a checkpoint adopted later may be behind or beside an
/// earlier one. A consumer that needs one that covers another compares frontiers
/// (`native_history_floor::frontier_covers`) or reads the history floor.
pub fn most_recently_adopted_checkpoint(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<Option<TrustedCheckpoint>, SyncSqliteError> {
    use rusqlite::OptionalExtension;
    let row = conn
        .query_row(
            "SELECT c.checkpoint_hash, c.namespace_root, c.author_state_root, \
                    c.installed_at_unixtime \
             FROM native_checkpoints c \
             JOIN native_checkpoint_seal_evidence e \
               ON e.group_id = c.group_id AND e.checkpoint_hash = c.checkpoint_hash \
             WHERE c.group_id = ?1 \
             ORDER BY c.installed_at_unixtime DESC, c.rowid DESC LIMIT 1",
            [group_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?;
    row.map(|(id, namespace, author_state, at)| {
        let as32 = |bytes: &[u8]| crate::native_store::as_array32(bytes);
        Ok(TrustedCheckpoint {
            checkpoint_id: as32(&id)?,
            namespace_root: as32(&namespace)?,
            author_state_root: as32(&author_state)?,
            adopted_at_unixtime: at,
        })
    })
    .transpose()
}
