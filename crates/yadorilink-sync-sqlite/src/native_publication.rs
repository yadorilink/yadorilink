//! Storage-layer half of `NativeDelta` publication -- native's counterpart
//! to `dag_store::published_view`, over the SAME shared authority layer
//! (`authorization_checkpoint`/`proof_carrying_delta`), keyed by a delta's
//! own [`DeltaHash`] rather than a `DeltaHash`. This module does not
//! verify anything cryptographically -- that is
//! `yadorilink_replica_domain::proof_carrying_delta::verify_proof_carrying_delta`'s
//! job, called by [`crate::native_admission::admit_published_native_delta`]
//! before this module's [`attach_authorization_evidence`] ever runs; this
//! module stores what it is given and trusts the caller verified it first,
//! exactly the same layering `published_view` already has with
//! `verify_change_admission`.
//!
//! Two schemas, two lifecycles, never conflated:
//!
//! * `native_checkpoint::NativeCheckpoint`/`native_store::seal_checkpoint`
//!   -- a GROUP-level Merkle namespace/frontier-root snapshot, sealed by a
//!   writer. Answers "what did this group's content
//!   and author-frontier look like at this point."
//! * `AuthorizationCheckpoint` (this module) -- a PER-DELTA writer-
//!   legitimacy proof, issued by the coordination-plane authority.
//!   Answers "was this delta's author a legitimate writer when it was
//!   published."
//!
//! A delta can be fully admitted into `NativeState` (via
//! `native_admission::admit_native_delta`, chain+context gated) without yet
//! having authorization evidence attached -- that is the ordinary state of
//! this device's OWN just-authored deltas before its next checkpoint flush
//! (a Pending/Published split).
//! A REMOTELY received delta, by contrast, always arrives already bundled
//! with its evidence (see `admit_published_native_delta`'s doc): there is
//! no "remotely admitted but not yet published" native delta, the same way
//! there is none: admission attaches evidence in the same transaction,
//! unconditionally.

use rusqlite::{Connection, OptionalExtension};

use yadorilink_replica_domain::author::AuthorId;
use yadorilink_replica_domain::ids::{AuthorSeq, FolderGroupId};
use yadorilink_replica_domain::native_state::DeltaHash;

use crate::error::SyncSqliteError;
use crate::native_store::{self, as_array32};

/// Creates this module's tables on `conn`.
pub fn init_native_publication_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS native_authorization_checkpoints (
            checkpoint_hash            BLOB PRIMARY KEY,
            group_id                   TEXT NOT NULL,
            device_id                  TEXT NOT NULL,
            checkpoint_seq             INTEGER NOT NULL,
            encoded                    BLOB NOT NULL,
            signature                  BLOB NOT NULL,
            author_signing_public_key  BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS native_authorization_checkpoints_by_device
            ON native_authorization_checkpoints(group_id, device_id);

        CREATE TABLE IF NOT EXISTS native_delta_authorization (
            delta_hash      BLOB PRIMARY KEY,
            checkpoint_hash BLOB NOT NULL,
            merkle_proof    BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS native_delta_authorization_by_checkpoint
            ON native_delta_authorization(checkpoint_hash);

        -- A verified-but-not-yet-installed delta's evidence: exactly the
        -- `native_delta_holds` case (the chain/context gates held it for
        -- a missing predecessor or dot), except that gate has nothing to do
        -- with authorization -- this delta already independently verified,
        -- via `verify_proof_carrying_delta`, BEFORE `admit_native_delta`
        -- ever saw it (see `admit_published_native_delta`'s doc for why
        -- verification always runs first, unconditionally). One row per
        -- pending delta_hash; consumed (moved into
        -- `native_delta_authorization`) the moment `admit_native_delta`
        -- actually installs it, whether immediately or via a later release.
        CREATE TABLE IF NOT EXISTS native_delta_pending_evidence (
            delta_hash      BLOB PRIMARY KEY,
            checkpoint_hash BLOB NOT NULL,
            merkle_proof    BLOB NOT NULL
        );

        -- Same referential discipline as `change_authorization_requires_checkpoint`/
        -- `authorization_checkpoints_protect_referenced` (dag_store/mod.rs) and for
        -- the identical reason: a trigger fires on every connection regardless of
        -- any per-connection `PRAGMA foreign_keys` setting, which a `REFERENCES`
        -- constraint alone does not.
        CREATE TRIGGER IF NOT EXISTS native_delta_authorization_requires_checkpoint
        BEFORE INSERT ON native_delta_authorization
        WHEN NOT EXISTS (
            SELECT 1 FROM native_authorization_checkpoints
            WHERE checkpoint_hash = NEW.checkpoint_hash
        )
        BEGIN
            SELECT RAISE(ABORT, 'native_delta_authorization.checkpoint_hash references a checkpoint that does not exist');
        END;
        CREATE TRIGGER IF NOT EXISTS native_authorization_checkpoints_protect_referenced
        BEFORE DELETE ON native_authorization_checkpoints
        WHEN EXISTS (
            SELECT 1 FROM native_delta_authorization
            WHERE checkpoint_hash = OLD.checkpoint_hash
        )
        BEGIN
            SELECT RAISE(ABORT, 'native_authorization_checkpoints row is still referenced by native_delta_authorization');
        END;
        "#,
    )?;
    Ok(())
}

/// Whether `delta_hash` has authorization evidence attached.
pub fn is_published(conn: &Connection, delta_hash: &DeltaHash) -> Result<bool, SyncSqliteError> {
    let present: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM native_delta_authorization WHERE delta_hash = ?1",
            [&delta_hash.0[..]],
            |r| r.get(0),
        )
        .optional()?;
    Ok(present.is_some())
}

/// Atomically attaches one checkpoint's authorization evidence to every
/// delta in `entries` it covers. Mirrors
/// `published_view::attach_authorization_evidence`'s own doc exactly:
/// idempotent for a byte-identical re-attach, `SyncSqliteError::CorruptState`
/// for a DIFFERENT payload arriving under an already-used hash (never a
/// silent overwrite).
#[allow(clippy::too_many_arguments)]
pub fn attach_authorization_evidence(
    conn: &Connection,
    checkpoint_hash: &[u8; 32],
    group_id: &str,
    device_id: &str,
    checkpoint_seq: u64,
    checkpoint_encoded: &[u8],
    checkpoint_signature: &[u8],
    author_signing_public_key: &[u8; 32],
    entries: &[(DeltaHash, Vec<u8>)],
) -> Result<(), SyncSqliteError> {
    let tx = conn.unchecked_transaction()?;
    attach_authorization_evidence_on_conn(
        &tx,
        checkpoint_hash,
        group_id,
        device_id,
        checkpoint_seq,
        checkpoint_encoded,
        checkpoint_signature,
        author_signing_public_key,
        entries,
    )?;
    tx.commit()?;
    Ok(())
}

/// [`attach_authorization_evidence`]'s body without its own transaction, so
/// a caller already inside one (`native_admission::admit_published_native_delta`,
/// admitting a remotely received delta and its evidence atomically) can
/// call this without SQLite rejecting a nested `BEGIN`.
#[allow(clippy::too_many_arguments)]
pub fn attach_authorization_evidence_on_conn(
    conn: &Connection,
    checkpoint_hash: &[u8; 32],
    group_id: &str,
    device_id: &str,
    checkpoint_seq: u64,
    checkpoint_encoded: &[u8],
    checkpoint_signature: &[u8],
    author_signing_public_key: &[u8; 32],
    entries: &[(DeltaHash, Vec<u8>)],
) -> Result<(), SyncSqliteError> {
    store_checkpoint(
        conn,
        checkpoint_hash,
        group_id,
        device_id,
        checkpoint_seq,
        checkpoint_encoded,
        checkpoint_signature,
        author_signing_public_key,
    )?;
    for (delta_hash, proof_encoded) in entries {
        attach_delta_evidence(conn, delta_hash, checkpoint_hash, proof_encoded)?;
    }
    Ok(())
}

/// Idempotently stores one checkpoint's envelope, independent of which (if
/// any) deltas it covers are attached yet -- shared by
/// [`attach_authorization_evidence_on_conn`] and
/// [`crate::native_admission::admit_published_native_delta`]'s pending-
/// evidence path, so a checkpoint a delta is merely HELD against (not yet
/// installed) is still available for [`checkpoint_envelope`] and for the
/// later `attach_delta_evidence` call its eventual release performs.
#[allow(clippy::too_many_arguments)]
pub(crate) fn store_checkpoint(
    conn: &Connection,
    checkpoint_hash: &[u8; 32],
    group_id: &str,
    device_id: &str,
    checkpoint_seq: u64,
    checkpoint_encoded: &[u8],
    checkpoint_signature: &[u8],
    author_signing_public_key: &[u8; 32],
) -> Result<(), SyncSqliteError> {
    type StoredCheckpoint = (String, String, i64, Vec<u8>, Vec<u8>, Vec<u8>);
    let existing_checkpoint: Option<StoredCheckpoint> = conn
        .query_row(
            "SELECT group_id, device_id, checkpoint_seq, encoded, signature, \
             author_signing_public_key FROM native_authorization_checkpoints WHERE checkpoint_hash = ?1",
            [&checkpoint_hash[..]],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .optional()?;
    match existing_checkpoint {
        None => {
            conn.execute(
                "INSERT INTO native_authorization_checkpoints \
                 (checkpoint_hash, group_id, device_id, checkpoint_seq, encoded, signature, \
                  author_signing_public_key) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    &checkpoint_hash[..],
                    group_id,
                    device_id,
                    checkpoint_seq as i64,
                    checkpoint_encoded,
                    checkpoint_signature,
                    &author_signing_public_key[..],
                ],
            )?;
            Ok(())
        }
        Some((g, d, seq, enc, sig, key)) => {
            let identical = g == group_id
                && d == device_id
                && seq == checkpoint_seq as i64
                && enc == checkpoint_encoded
                && sig == checkpoint_signature
                && key == author_signing_public_key;
            if identical {
                Ok(())
            } else {
                Err(SyncSqliteError::CorruptState(format!(
                    "native_authorization_checkpoints already has a DIFFERENT payload for \
                     checkpoint_hash {checkpoint_hash:x?} -- refusing to silently pick a winner"
                )))
            }
        }
    }
}

/// Idempotently attaches one already-`store_checkpoint`ed checkpoint's
/// evidence to one delta. `SyncSqliteError::CorruptState` for a DIFFERENT
/// payload arriving under an already-used `delta_hash` (never a silent
/// overwrite) -- same discipline as `published_view::attach_authorization_evidence`.
pub(crate) fn attach_delta_evidence(
    conn: &Connection,
    delta_hash: &DeltaHash,
    checkpoint_hash: &[u8; 32],
    proof_encoded: &[u8],
) -> Result<(), SyncSqliteError> {
    let existing_evidence: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT checkpoint_hash, merkle_proof FROM native_delta_authorization \
             WHERE delta_hash = ?1",
            [&delta_hash.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match existing_evidence {
        None => {
            conn.execute(
                "INSERT INTO native_delta_authorization \
                 (delta_hash, checkpoint_hash, merkle_proof) VALUES (?1, ?2, ?3)",
                rusqlite::params![&delta_hash.0[..], &checkpoint_hash[..], proof_encoded],
            )?;
            Ok(())
        }
        Some((existing_checkpoint_hash, existing_proof)) => {
            let identical =
                existing_checkpoint_hash == checkpoint_hash && existing_proof == proof_encoded;
            if identical {
                Ok(())
            } else {
                Err(SyncSqliteError::CorruptState(format!(
                    "native_delta_authorization already has DIFFERENT evidence for delta_hash \
                     {delta_hash:?} -- refusing to silently overwrite published evidence"
                )))
            }
        }
    }
}

/// Records that `delta_hash` verified successfully and is covered by
/// `checkpoint_hash`/`proof_encoded`, but has not necessarily been
/// installed into [`crate::native_store`] yet (it may still be held on a
/// chain/context gate). Idempotent for the identical payload.
pub(crate) fn record_pending_evidence(
    conn: &Connection,
    delta_hash: &DeltaHash,
    checkpoint_hash: &[u8; 32],
    proof_encoded: &[u8],
) -> Result<(), SyncSqliteError> {
    let existing: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT checkpoint_hash, merkle_proof FROM native_delta_pending_evidence WHERE delta_hash = ?1",
            [&delta_hash.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match existing {
        None => {
            conn.execute(
                "INSERT INTO native_delta_pending_evidence (delta_hash, checkpoint_hash, merkle_proof) \
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![&delta_hash.0[..], &checkpoint_hash[..], proof_encoded],
            )?;
            Ok(())
        }
        Some((existing_checkpoint_hash, existing_proof)) => {
            let identical =
                existing_checkpoint_hash == checkpoint_hash && existing_proof == proof_encoded;
            if identical {
                Ok(())
            } else {
                Err(SyncSqliteError::CorruptState(format!(
                    "native_delta_pending_evidence already has DIFFERENT evidence for delta_hash \
                     {delta_hash:?} -- refusing to silently overwrite it"
                )))
            }
        }
    }
}

/// Reads `delta_hash`'s pending evidence without removing it -- for a HELD
/// delta this replica already independently verified via its proof-carrying bundle (its
/// evidence was recorded before the chain/context gates ever saw it, see
/// `native_admission::admit_published_native_delta`'s doc), this is how a
/// later `release_waiters` retry re-derives the delta's own historical
/// author key from stored evidence instead of a live `key_for` lookup --
/// exactly the same evidence [`take_pending_evidence`] would consume on
/// actual admission, just not consumed here since the delta may still not
/// be admissible yet.
pub(crate) fn peek_pending_evidence(
    conn: &Connection,
    delta_hash: &DeltaHash,
) -> Result<Option<DeltaEvidenceRef>, SyncSqliteError> {
    let row: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT checkpoint_hash, merkle_proof FROM native_delta_pending_evidence WHERE delta_hash = ?1",
            [&delta_hash.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((checkpoint_hash, merkle_proof)) = row else { return Ok(None) };
    Ok(Some((as_array32(&checkpoint_hash)?, merkle_proof)))
}

/// Takes (removes) `delta_hash`'s pending evidence, if any -- called the
/// moment `admit_native_delta` actually installs a delta this replica
/// already independently verified, whether on first attempt or via a later
/// release.
pub(crate) fn take_pending_evidence(
    conn: &Connection,
    delta_hash: &DeltaHash,
) -> Result<Option<DeltaEvidenceRef>, SyncSqliteError> {
    let row: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT checkpoint_hash, merkle_proof FROM native_delta_pending_evidence WHERE delta_hash = ?1",
            [&delta_hash.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((checkpoint_hash, merkle_proof)) = row else { return Ok(None) };
    conn.execute(
        "DELETE FROM native_delta_pending_evidence WHERE delta_hash = ?1",
        [&delta_hash.0[..]],
    )?;
    Ok(Some((as_array32(&checkpoint_hash)?, merkle_proof)))
}

/// `(checkpoint_hash, merkle_proof)` -- see [`evidence_for`] and
/// [`take_pending_evidence`].
pub type DeltaEvidenceRef = ([u8; 32], Vec<u8>);

/// `(encoded, signature, author_signing_public_key)` -- see
/// [`checkpoint_envelope`].
pub type NativeCheckpointEnvelope = (Vec<u8>, Vec<u8>, [u8; 32]);

/// `(checkpoint_hash, merkle_proof)` for `delta_hash`, or `None` if
/// unpublished.
pub fn evidence_for(
    conn: &Connection,
    delta_hash: &DeltaHash,
) -> Result<Option<DeltaEvidenceRef>, SyncSqliteError> {
    let row: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT checkpoint_hash, merkle_proof FROM native_delta_authorization WHERE delta_hash = ?1",
            [&delta_hash.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((checkpoint_hash, merkle_proof)) = row else { return Ok(None) };
    Ok(Some((as_array32(&checkpoint_hash)?, merkle_proof)))
}

/// `(encoded, signature, author_signing_public_key)` for `checkpoint_hash`,
/// or `None` if unknown -- the wire-transportable envelope, mirroring
/// `published_view::checkpoint_envelope`.
pub fn checkpoint_envelope(
    conn: &Connection,
    checkpoint_hash: &[u8; 32],
) -> Result<Option<NativeCheckpointEnvelope>, SyncSqliteError> {
    let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT encoded, signature, author_signing_public_key \
             FROM native_authorization_checkpoints WHERE checkpoint_hash = ?1",
            [&checkpoint_hash[..]],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((encoded, signature, author_key)) = row else { return Ok(None) };
    Ok(Some((encoded, signature, as_array32(&author_key)?)))
}

/// The authorization checkpoint (encoded) followed by its 64-byte authority
/// signature that vouches for `device`'s `key` in `group_id`, the latest this
/// replica holds: what a closure signed with that key carries. `None` when no
/// checkpoint for that device and key is held.
pub fn latest_authorization_for_device(
    conn: &Connection,
    group_id: &str,
    device_id: &str,
    key: &[u8; 32],
) -> Result<Option<Vec<u8>>, SyncSqliteError> {
    let row: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT encoded, signature FROM native_authorization_checkpoints \
             WHERE group_id = ?1 AND device_id = ?2 AND author_signing_public_key = ?3 \
             ORDER BY checkpoint_seq DESC LIMIT 1",
            (group_id, device_id, &key[..]),
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(row.map(|(mut encoded, signature)| {
        encoded.extend_from_slice(&signature);
        encoded
    }))
}

/// `author`'s own installed deltas in `group_id` that have no authorization
/// evidence attached yet, in seq order. A flush batches a whole device with
/// [`pending_native_deltas_for_device`].
pub fn pending_native_deltas_for_author(
    conn: &Connection,
    group_id: &FolderGroupId,
    author: &AuthorId,
) -> Result<Vec<(AuthorSeq, DeltaHash)>, SyncSqliteError> {
    native_store::unpublished_delta_log_entries(conn, group_id, author)
}

/// Every installed delta of `device_id`, over all of its incarnations, that
/// has no authorization evidence yet, grouped by author and in seq order:
/// one checkpoint flush's batch.
pub fn pending_native_deltas_for_device(
    conn: &Connection,
    group_id: &FolderGroupId,
    device_id: &str,
) -> Result<Vec<(AuthorId, AuthorSeq, DeltaHash)>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT l.incarnation, l.seq, l.delta_hash FROM native_delta_log l \
         WHERE l.group_id = ?1 AND l.author = ?2 \
         AND NOT EXISTS (SELECT 1 FROM native_delta_authorization a WHERE a.delta_hash = l.delta_hash) \
         ORDER BY l.incarnation, l.seq",
    )?;
    let rows = stmt.query_map((group_id.as_str(), device_id), |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?, row.get::<_, Vec<u8>>(2)?))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (incarnation, seq, hash) = row?;
        let incarnation: [u8; 16] = incarnation.as_slice().try_into().map_err(|_| {
            SyncSqliteError::CorruptState("native_delta_log incarnation is not 16 bytes".into())
        })?;
        out.push((
            AuthorId {
                device: yadorilink_replica_domain::ids::DeviceId(device_id.to_owned()),
                incarnation: yadorilink_replica_domain::author::IncarnationId(incarnation),
            },
            AuthorSeq(seq as u64),
            DeltaHash(as_array32(&hash)?),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
