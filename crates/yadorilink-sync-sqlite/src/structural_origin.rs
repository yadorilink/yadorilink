//! Which directories on disk this device created only to hold replicated
//! descendants.
//!
//! A directory that exists on disk is one of two things, and they must
//! never be confused:
//!
//! * a **structural** directory: the materializer created it (`mkdir -p`
//!   of a parent) because a replicated entry below it needed a place to
//!   live. It is derived state. Nobody wrote it, so it is never captured as
//!   an explicit directory, and it goes away once nothing below it is
//!   live.
//! * an **explicit** directory: a user (or any other process) made it. It
//!   is a replicated entry in its own right, and outlives its contents.
//!
//! The filesystem does not say which one a directory is, and nothing
//! observable later can reconstruct it: "no explicit head, but children on
//! disk" fits a directory this device created for a peer's file exactly as
//! well as one a user created while the folder was unlinked. So the answer
//! is recorded at the moment it is known -- when this device creates the
//! directory -- and bound to the directory's filesystem identity, never
//! guessed afterwards. A directory with no record is `OriginUnknown`: it is
//! kept on disk and not authored as anything.
//!
//! # Two phases around the `mkdir`
//!
//! A directory's identity exists only after it is created, but the claim
//! has to be durable before it is created, or a crash between the two
//! leaves a directory this device made that nothing says it made -- which
//! capture would then read as a user's `mkdir`. So creation is bracketed:
//!
//! 1. [`record_structural_intent`] before the `mkdir`: a pending intent
//!    row, and a bump of the path's mutation fence, in one transaction.
//! 2. [`complete_structural_origin`] after a successful `mkdir`, with the
//!    identity observed (`lstat`) on the new directory: the intent becomes
//!    an origin bound to that identity.
//! 3. [`abandon_structural_intent`] if the `mkdir` found the name taken
//!    (`EEXIST`): whatever is there was not created by this call, so no
//!    origin is claimed for it.
//!
//! An intent that outlives its writer (a crash after `mkdir`, before step
//! 2) is dropped by [`drop_structural_intent_recording_lost_provenance`],
//! never completed. Completing it would mean deciding after the fact that the
//! directory now at the path is the one this device created, and nothing
//! on disk can prove that. Dropping it errs towards `OriginUnknown`, which
//! keeps the directory and authors nothing -- the direction that loses no
//! data.
//!
//! # Lost provenance is recorded too
//!
//! A directory with no record at all is one a user (or any other process)
//! made, and capture authors it as an explicit entry. That must not be
//! the reading for a directory this device may have made itself whose
//! record was lost -- an intent dropped before its `mkdir` completed, or
//! a completion refused because its intent was gone. Such a directory is
//! recorded with [`record_lost_structural_provenance`], bound to its
//! identity like an origin: [`structural_directory_origin`] reports it as
//! [`StructuralDirectoryOrigin::ProvenanceLost`], and capture keeps it and
//! authors nothing. Only that object: a directory made at the path later
//! is not covered by the record.
//!
//! # Identity, not path
//!
//! An origin names a directory by filesystem identity. The path is where
//! it was last seen: [`rekey_structural_origin`] follows a directory a
//! rename moved, and [`structural_directory_origin`]'s caller only ever
//! accepts the record for the object it is looking at
//! ([`StructuralDirectoryOrigin::status`]). A directory at a recorded path
//! with a different identity -- deleted and recreated, perhaps by a user --
//! inherits nothing.
//!
//! The ledger is device-local and outlives any one link of the folder: it
//! is about this disk, not about the history, so pruning or replacing the
//! history leaves it alone.
//!
//! Records are keyed by `(group_id, path)` with no separate root identity
//! (D6's "group / root identity"). The root is already bound per record:
//! each one carries the directory's full filesystem identity (volume,
//! object id and an anti-reuse discriminator), and nothing is accepted for
//! an object other than the one recorded. A group relinked at a different
//! root finds different objects at its paths, so the old records match
//! nothing and those directories are `OriginUnknown`; a root that was
//! moved or renamed keeps its objects, and keeps its provenance with them,
//! which a root-identity key would throw away.

use rusqlite::{Connection, OptionalExtension};

use crate::error::SyncSqliteError;
use crate::file_identity_codec::{
    decode_file_identity, encode_file_identity, encode_object_address,
};
use crate::materialized_generation::{bump_mutation_fence, snapshot_mutation_fence};
use yadorilink_fs_platform::fs_identity::{
    FileIdentity, IdentityComparison, ObjectKind, TimestampGranularity,
};

pub fn init_structural_origin_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        -- A directory this device is about to create for descendants, not
        -- yet bound to an identity, is a `structural_mkdir` row of
        -- `materialization_intents` (see that table). Its
        -- `mutation_generation` is the path's mutation fence as the intent
        -- bumped it; completion is refused once anything else has moved the
        -- fence.

        -- A directory this device created (or kept) only to hold
        -- descendants, bound to its filesystem identity. `object_address`
        -- is the identity's volume and object id alone, the key a rename
        -- is followed by.
        CREATE TABLE IF NOT EXISTS structural_directory_origins (
            group_id               TEXT NOT NULL,
            path                   TEXT NOT NULL,
            object_address         BLOB NOT NULL,
            filesystem_identity    BLOB NOT NULL,
            recorded_at_unix_nanos INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );
        CREATE INDEX IF NOT EXISTS structural_directory_origins_by_object
            ON structural_directory_origins(group_id, object_address);

        -- A directory this device may have created for descendants whose
        -- structural record was lost before it was written (an intent
        -- dropped before its `mkdir` completed, or a completion that found
        -- its intent gone), bound to the identity it had when the loss
        -- was noticed. Neither structural nor a user's: kept, never
        -- authored. A later origin for the path replaces it.
        CREATE TABLE IF NOT EXISTS structural_provenance_lost (
            group_id               TEXT NOT NULL,
            path                   TEXT NOT NULL,
            filesystem_identity    BLOB NOT NULL,
            recorded_at_unix_nanos INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );

        -- A directory whose replicated entry is deleted (or never existed
        -- here) but which stays on disk because it is not empty: it holds
        -- something this device does not replicate (a user's
        -- untracked file, an ignored `.git`, an OS's `.DS_Store`), or
        -- descendants that are still live. Nothing in it is removed on
        -- anyone's behalf. `reason` is for status; the row is also what a
        -- retained settlement closes its projection obligation against.
        -- `filesystem_identity` is set only for the directory a delete was
        -- aimed at and found not empty: that object, and no other, is
        -- removed once it is empty. NULL for a directory no delete aimed
        -- at (one standing where a file was, or made after the delete),
        -- which is kept however empty it becomes.
        CREATE TABLE IF NOT EXISTS retained_directories (
            group_id               TEXT NOT NULL,
            path                   TEXT NOT NULL,
            reason                 TEXT NOT NULL,
            filesystem_identity    BLOB,
            retained_at_unix_nanos INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );
        "#,
    )?;
    Ok(())
}

/// A pending structural `mkdir`, as [`record_structural_intent`] wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuralIntent {
    /// The path's mutation fence after the intent bumped it.
    pub mutation_generation: i64,
}

/// What [`complete_structural_origin`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralOriginCompletion {
    /// The origin is recorded, bound to the observed identity.
    Recorded,
    /// No pending intent for the path: recovery dropped it, or it was
    /// never written. Nothing is recorded.
    NoPendingIntent,
    /// The path's mutation fence moved after the intent was written, so
    /// the directory observed now is not provably the one this intent
    /// created. The intent is dropped and nothing is recorded.
    FenceMoved,
    /// What is at the path is not a directory. The intent is dropped and
    /// nothing is recorded.
    NotADirectory,
}

/// What the ledger holds for one path. Read with
/// [`structural_directory_origin`]; turned into a verdict about the object
/// actually on disk with [`Self::status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralDirectoryOrigin {
    /// Nothing is recorded for the path.
    None,
    /// A structural `mkdir` of the path is in flight (or was interrupted
    /// and not yet recovered). Whatever directory is there may be the one
    /// it is creating, so it must not be read as a user's.
    IntentPending,
    /// A structural directory was recorded at the path with this identity.
    Recorded(FileIdentity),
    /// Nothing is recorded as structural, but the directory with this
    /// identity may be one this device created for descendants: its
    /// structural record was lost (see
    /// [`record_lost_structural_provenance`]). That object is of unknown
    /// origin; any other object at the path has no record at all.
    ProvenanceLost(FileIdentity),
}

/// Whether the directory on disk at a path is one this device created only
/// for descendants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructuralOriginStatus {
    /// The recorded origin names exactly this directory, and the
    /// directory's own tracked metadata is as recorded.
    Structural,
    /// The recorded origin names this directory, but its own tracked
    /// metadata (the `metadata_fingerprint`: the Unix mode, or the Windows
    /// attributes) differs from what was recorded. Something operated on
    /// the directory itself. Under D5=B a user's change of the Unix mode
    /// makes the directory explicit (`ExplicitDirectory(path, mode)`), so
    /// this is not read as plain `Structural`; the caller decides from the
    /// observation what, if anything, to author.
    StructuralMetadataChanged,
    /// A structural `mkdir` of the path is pending. Not a user's
    /// directory, not yet a proven structural one either.
    IntentPending,
    /// No record names this object -- none at all, or one for a different
    /// object (the directory was replaced), or a comparison that cannot
    /// prove it is the same object. Keep the directory; author nothing.
    OriginUnknown,
}

impl StructuralDirectoryOrigin {
    /// The verdict for `observed`, the identity of what is on disk at the
    /// path now (`None` when nothing is, or it could not be observed).
    /// Only a conclusive same-object comparison counts as structural: an
    /// ambiguous one (a coarse clock that cannot rule out inode reuse) is
    /// `OriginUnknown`. A conclusive one whose metadata fingerprint moved is
    /// `StructuralMetadataChanged` (D5).
    #[must_use]
    pub fn status(
        &self,
        observed: Option<&FileIdentity>,
        birth_time_granularity: TimestampGranularity,
    ) -> StructuralOriginStatus {
        match self {
            Self::None | Self::ProvenanceLost(_) => StructuralOriginStatus::OriginUnknown,
            Self::IntentPending => StructuralOriginStatus::IntentPending,
            Self::Recorded(recorded) => match observed {
                Some(observed)
                    if observed.object_kind == ObjectKind::Directory
                        && recorded.compare(observed, birth_time_granularity)
                            == IdentityComparison::SameObject =>
                {
                    if observed.metadata_fingerprint == recorded.metadata_fingerprint {
                        StructuralOriginStatus::Structural
                    } else {
                        StructuralOriginStatus::StructuralMetadataChanged
                    }
                }
                _ => StructuralOriginStatus::OriginUnknown,
            },
        }
    }
}

/// Phase 1: records that this device is about to create `path` as a
/// structural directory, and bumps the path's mutation fence, in the
/// caller's transaction. Call it before the `mkdir`, with the path lock
/// held, and commit before the syscall.
///
/// A completed origin already recorded at `path` is left as it is: the
/// materializer only creates a directory it found missing, and if the
/// `mkdir` then finds the name taken after all, that record may still
/// describe what is there.
pub fn record_structural_intent(
    conn: &Connection,
    group_id: &str,
    path: &str,
    now_unix_nanos: i64,
) -> Result<StructuralIntent, SyncSqliteError> {
    let mutation_generation =
        bump_mutation_fence(conn, group_id, path, "structural-mkdir", now_unix_nanos)?;
    conn.prepare_cached(
        "INSERT INTO materialization_intents
            (group_id, path, kind, target_version_hash, created_at_unix_nanos,
             mutation_generation)
         VALUES (?1, ?2, 'structural_mkdir', x'', ?4, ?3)
         ON CONFLICT (group_id, path, kind) DO UPDATE SET
            mutation_generation = excluded.mutation_generation,
            created_at_unix_nanos = excluded.created_at_unix_nanos",
    )?
    .execute(rusqlite::params![group_id, path, mutation_generation, now_unix_nanos])?;
    Ok(StructuralIntent { mutation_generation })
}

/// Phase 2: binds the pending intent for `path` to `identity`, observed
/// with `lstat` on the directory the `mkdir` just created, in the caller's
/// transaction.
///
/// Records nothing as structural -- and says why -- unless an intent is
/// pending, the path's mutation fence is still the one the intent bumped
/// it to, and `identity` is a directory. Each refusal errs towards
/// `OriginUnknown`: a directory the `mkdir` did create, refused because
/// its intent was gone or its fence moved, is recorded as of lost
/// provenance, so capture does not read it as a user's.
pub fn complete_structural_origin(
    conn: &Connection,
    group_id: &str,
    path: &str,
    identity: &FileIdentity,
    now_unix_nanos: i64,
) -> Result<StructuralOriginCompletion, SyncSqliteError> {
    let Some(intended_generation) = pending_intent_generation(conn, group_id, path)? else {
        record_lost_structural_provenance(conn, group_id, path, identity, now_unix_nanos)?;
        return Ok(StructuralOriginCompletion::NoPendingIntent);
    };
    delete_intent(conn, group_id, path)?;
    if snapshot_mutation_fence(conn, group_id, path)? != intended_generation {
        record_lost_structural_provenance(conn, group_id, path, identity, now_unix_nanos)?;
        return Ok(StructuralOriginCompletion::FenceMoved);
    }
    if identity.object_kind != ObjectKind::Directory {
        return Ok(StructuralOriginCompletion::NotADirectory);
    }
    upsert_origin(conn, group_id, path, identity, now_unix_nanos)?;
    Ok(StructuralOriginCompletion::Recorded)
}

/// Phase 2 when the `mkdir` found the name taken (`EEXIST`): drops the
/// pending intent without claiming anything, in the caller's transaction.
/// Returns whether an intent was pending. An origin recorded earlier for
/// the path is kept: it may be exactly what the `mkdir` ran into.
pub fn abandon_structural_intent(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<bool, SyncSqliteError> {
    delete_intent(conn, group_id, path)
}

/// Drops every structural intent, across all groups, and returns the
/// `(group_id, path)` pairs dropped -- recording nothing in their place.
/// Recovery does not use it: a directory an interrupted `mkdir` made would
/// then read as a user's. It resolves each intent with
/// [`drop_structural_intent_recording_lost_provenance`] instead.
///
/// Dropped, never completed: whether the directory now at the path is the
/// one the interrupted `mkdir` created cannot be proven from disk, and an
/// unproven claim is exactly what this ledger exists not to make. The
/// directory is left as it is and becomes `OriginUnknown`.
pub fn drop_unresolved_structural_intents(
    conn: &Connection,
) -> Result<Vec<(String, String)>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "DELETE FROM materialization_intents WHERE kind = 'structural_mkdir'
         RETURNING group_id, path",
    )?;
    let rows =
        stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
    let mut dropped: Vec<(String, String)> = rows.collect::<Result<_, _>>()?;
    dropped.sort();
    Ok(dropped)
}

/// An unresolved structural intent, as [`list_unresolved_structural_intents`]
/// reads it: the intent to resolve with
/// [`drop_structural_intent_recording_lost_provenance`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedStructuralIntent {
    pub group_id: String,
    pub path: String,
    /// The fence value the intent bumped the path to: it names this intent
    /// and no later one recorded for the same path.
    pub mutation_generation: i64,
}

/// Every structural intent of `group_id` (of every group when `None`),
/// ordered by group and path. Reads only: recovery
/// observes what is at each path, then resolves each intent with
/// [`drop_structural_intent_recording_lost_provenance`].
pub fn list_unresolved_structural_intents(
    conn: &Connection,
    group_id: Option<&str>,
) -> Result<Vec<UnresolvedStructuralIntent>, SyncSqliteError> {
    let mut stmt = conn.prepare_cached(
        "SELECT group_id, path, mutation_generation FROM materialization_intents
         WHERE kind = 'structural_mkdir' AND (?1 IS NULL OR group_id = ?1)
         ORDER BY group_id, path",
    )?;
    let rows = stmt.query_map([group_id], |row| {
        Ok(UnresolvedStructuralIntent {
            group_id: row.get(0)?,
            path: row.get(1)?,
            mutation_generation: row.get(2)?,
        })
    })?;
    Ok(rows.collect::<Result<_, _>>()?)
}

/// Recovery of one interrupted structural `mkdir`, in the caller's
/// transaction: drops `intent` -- only if it is still the intent pending
/// for its path, not a later one -- and, in the same transaction, records
/// `found`, the directory observed at the path, as of lost provenance
/// (see [`record_lost_structural_provenance`]). `found` is `None` only
/// when nothing that could be the `mkdir`'s directory is there.
///
/// The drop and the record are one write, so no reader, and no crash,
/// ever sees the intent gone with nothing in its place: a directory with
/// neither reads as a user's. Returns whether the intent was dropped.
pub fn drop_structural_intent_recording_lost_provenance(
    conn: &Connection,
    intent: &UnresolvedStructuralIntent,
    found: Option<&FileIdentity>,
    now_unix_nanos: i64,
) -> Result<bool, SyncSqliteError> {
    let dropped = conn
        .prepare_cached(
            "DELETE FROM materialization_intents
             WHERE group_id = ?1 AND path = ?2 AND kind = 'structural_mkdir'
               AND mutation_generation = ?3",
        )?
        .execute(rusqlite::params![intent.group_id, intent.path, intent.mutation_generation])?
        > 0;
    if dropped {
        if let Some(identity) = found {
            record_lost_structural_provenance(
                conn,
                &intent.group_id,
                &intent.path,
                identity,
                now_unix_nanos,
            )?;
        }
    }
    Ok(dropped)
}

/// Records that the directory at `path`, observed as `identity`, may be
/// one this device created for descendants but has no structural record
/// for, in the caller's transaction: its record was lost. Nothing is
/// recorded for something other than a directory, and an origin already
/// recorded for the path is left as it is (it may name exactly this
/// object). Replaces an earlier lost-provenance record for the path.
pub fn record_lost_structural_provenance(
    conn: &Connection,
    group_id: &str,
    path: &str,
    identity: &FileIdentity,
    now_unix_nanos: i64,
) -> Result<bool, SyncSqliteError> {
    if identity.object_kind != ObjectKind::Directory {
        return Ok(false);
    }
    let recorded: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM structural_directory_origins
                            WHERE group_id = ?1 AND path = ?2)",
        )?
        .query_row(rusqlite::params![group_id, path], |row| row.get(0))?;
    if recorded {
        return Ok(false);
    }
    conn.prepare_cached(
        "INSERT INTO structural_provenance_lost
            (group_id, path, filesystem_identity, recorded_at_unix_nanos)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (group_id, path) DO UPDATE SET
            filesystem_identity = excluded.filesystem_identity,
            recorded_at_unix_nanos = excluded.recorded_at_unix_nanos",
    )?
    .execute(rusqlite::params![
        group_id,
        path,
        encode_file_identity(identity),
        now_unix_nanos
    ])?;
    Ok(true)
}

/// Records an existing directory at `path` as structural, bound to
/// `identity`, in the caller's transaction.
///
/// For a directory that was explicit and stops being so while it still
/// holds live descendants: its explicit entry was deleted, but it stays on
/// disk as their container. From then on it is derived state like any
/// directory this device created for descendants, and must be recognized
/// as such -- otherwise capture would see a directory with no explicit
/// entry and no origin, and re-author the entry the deletion removed.
/// Replaces any earlier record for the path and drops a pending intent.
pub fn adopt_structural_directory(
    conn: &Connection,
    group_id: &str,
    path: &str,
    identity: &FileIdentity,
    now_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    if identity.object_kind != ObjectKind::Directory {
        return Err(SyncSqliteError::InvalidInput(format!(
            "only a directory can be adopted as structural; {path:?} is {:?}",
            identity.object_kind
        )));
    }
    delete_intent(conn, group_id, path)?;
    upsert_origin(conn, group_id, path, identity, now_unix_nanos)
}

/// Follows a structural directory a rename moved: if a recorded origin in
/// `group_id` names the same object as `identity` (observed at `to_path`)
/// under another path, its record moves to `to_path`, replacing whatever
/// was recorded there. Returns the path it moved from, if any. Runs in the
/// caller's transaction.
///
/// Only a conclusive same-object comparison moves a record. The rename
/// itself does not make the directory explicit: it is still the container
/// this device created, now under a new name. The record keeps the
/// identity as recorded, metadata fingerprint included, so a `chmod` made
/// around the rename still reads as
/// [`StructuralOriginStatus::StructuralMetadataChanged`] at the new name.
///
/// The directory's subtree moved with it, so the records below `from`
/// move to the same place below `to_path`, and any record left below
/// `to_path` (which named nothing now there) is dropped. A moved record
/// still names its object by identity: [`StructuralDirectoryOrigin::status`]
/// accepts it only for that object.
pub fn rekey_structural_origin(
    conn: &Connection,
    group_id: &str,
    to_path: &str,
    identity: &FileIdentity,
    birth_time_granularity: TimestampGranularity,
    now_unix_nanos: i64,
) -> Result<Option<String>, SyncSqliteError> {
    if identity.object_kind != ObjectKind::Directory {
        return Ok(None);
    }
    let candidates: Vec<(String, Vec<u8>)> = {
        let mut stmt = conn.prepare_cached(
            "SELECT path, filesystem_identity FROM structural_directory_origins
             WHERE group_id = ?1 AND object_address = ?2 AND path <> ?3
             ORDER BY path",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![group_id, encode_object_address(identity), to_path],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        rows.collect::<Result<_, _>>()?
    };
    for (from_path, blob) in candidates {
        let recorded = decode_file_identity(&blob)?;
        if recorded.compare(identity, birth_time_granularity) == IdentityComparison::SameObject {
            forget_structural_origin(conn, group_id, &from_path)?;
            move_origin_subtree(conn, group_id, &from_path, to_path)?;
            upsert_origin(conn, group_id, to_path, &recorded, now_unix_nanos)?;
            return Ok(Some(from_path));
        }
    }
    Ok(None)
}

/// Removes the record for `path` (after the directory is removed, or once
/// it has been found to be a different object). Returns whether one was
/// recorded. A pending intent is left alone.
pub fn forget_structural_origin(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<bool, SyncSqliteError> {
    let removed = conn
        .prepare_cached(
            "DELETE FROM structural_directory_origins WHERE group_id = ?1 AND path = ?2",
        )?
        .execute(rusqlite::params![group_id, path])?;
    delete_lost_provenance(conn, group_id, path)?;
    Ok(removed > 0)
}

/// What the ledger holds for `path`. A pending intent takes precedence
/// over a recorded origin: while a structural `mkdir` of the path is in
/// flight, what is there may be the directory it is creating.
pub fn structural_directory_origin(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<StructuralDirectoryOrigin, SyncSqliteError> {
    if pending_intent_generation(conn, group_id, path)?.is_some() {
        return Ok(StructuralDirectoryOrigin::IntentPending);
    }
    let blob: Option<Vec<u8>> = conn
        .prepare_cached(
            "SELECT filesystem_identity FROM structural_directory_origins
             WHERE group_id = ?1 AND path = ?2",
        )?
        .query_row(rusqlite::params![group_id, path], |row| row.get(0))
        .optional()?;
    if let Some(blob) = blob {
        return Ok(StructuralDirectoryOrigin::Recorded(decode_file_identity(&blob)?));
    }
    let lost: Option<Vec<u8>> = conn
        .prepare_cached(
            "SELECT filesystem_identity FROM structural_provenance_lost
             WHERE group_id = ?1 AND path = ?2",
        )?
        .query_row(rusqlite::params![group_id, path], |row| row.get(0))
        .optional()?;
    match lost {
        None => Ok(StructuralDirectoryOrigin::None),
        Some(blob) => Ok(StructuralDirectoryOrigin::ProvenanceLost(decode_file_identity(&blob)?)),
    }
}

/// Why a directory whose entry is deleted is still on disk: it holds
/// something this device does not replicate. See [`record_retained_directory`].
pub const RETAINED_UNTRACKED_CONTENT: &str = "retained: local untracked content";

/// Why a directory whose entry is deleted is still on disk: replicated
/// entries below it are still live.
pub const RETAINED_LIVE_DESCENDANTS: &str = "retained: live descendants";

/// Why a directory whose entry is deleted is still on disk: the directory
/// at the path is not the one this device materialized for the entry (the
/// user replaced it, or this device never recorded which object it was),
/// so the delete never aimed at it. Kept for good, however empty.
pub const RETAINED_REPLACED_LOCALLY: &str = "retained: replaced by local directory";

/// Records that the directory at `path` stays on disk although its entry
/// is deleted, and why, in the caller's transaction. Replaces an earlier
/// record for the path.
///
/// `removable` is the identity of the directory a delete was aimed at and
/// found not empty: that object is removed once it is empty. `None` keeps
/// the directory at `path` for good -- no delete ever aimed at it.
pub fn record_retained_directory(
    conn: &Connection,
    group_id: &str,
    path: &str,
    reason: &str,
    removable: Option<&FileIdentity>,
    now_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    conn.prepare_cached(
        "INSERT INTO retained_directories
            (group_id, path, reason, filesystem_identity, retained_at_unix_nanos)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (group_id, path) DO UPDATE SET
            reason = excluded.reason,
            filesystem_identity = excluded.filesystem_identity,
            retained_at_unix_nanos = CASE
                WHEN retained_directories.reason = excluded.reason
                THEN retained_directories.retained_at_unix_nanos
                ELSE excluded.retained_at_unix_nanos END",
    )?
    .execute(rusqlite::params![
        group_id,
        path,
        reason,
        removable.map(encode_file_identity),
        now_unix_nanos
    ])?;
    Ok(())
}

/// A retained-directory record, as [`retained_directory`] reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedDirectory {
    /// Nothing is recorded for the path.
    None,
    /// Kept for good: no delete aimed at the directory there.
    Kept,
    /// The directory a delete aimed at, to remove once it is empty -- but
    /// only while the object at the path is still this one.
    RemovableWhenEmpty(FileIdentity),
}

/// The retained-directory record for `path`.
pub fn retained_directory(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<RetainedDirectory, SyncSqliteError> {
    let row: Option<Option<Vec<u8>>> = conn
        .prepare_cached(
            "SELECT filesystem_identity FROM retained_directories
             WHERE group_id = ?1 AND path = ?2",
        )?
        .query_row(rusqlite::params![group_id, path], |row| row.get(0))
        .optional()?;
    Ok(match row {
        None => RetainedDirectory::None,
        Some(None) => RetainedDirectory::Kept,
        Some(Some(blob)) => RetainedDirectory::RemovableWhenEmpty(decode_file_identity(&blob)?),
    })
}

/// Drops the retained record for `path` (the directory was removed, or
/// the path holds an entry again). Returns whether one was recorded.
pub fn clear_retained_directory(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<bool, SyncSqliteError> {
    let removed = conn
        .prepare_cached("DELETE FROM retained_directories WHERE group_id = ?1 AND path = ?2")?
        .execute(rusqlite::params![group_id, path])?;
    Ok(removed > 0)
}

/// The reason recorded for a retained directory at `path`, if any.
pub fn retained_directory_reason(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<String>, SyncSqliteError> {
    Ok(conn
        .prepare_cached(
            "SELECT reason FROM retained_directories WHERE group_id = ?1 AND path = ?2",
        )?
        .query_row(rusqlite::params![group_id, path], |row| row.get(0))
        .optional()?)
}

/// Every path with a retained record for `reason`.
pub fn retained_paths_with_reason(
    conn: &Connection,
    group_id: &str,
    reason: &str,
) -> Result<Vec<String>, SyncSqliteError> {
    let mut statement = conn.prepare_cached(
        "SELECT path FROM retained_directories WHERE group_id = ?1 AND reason = ?2 ORDER BY path",
    )?;
    let paths = statement
        .query_map(rusqlite::params![group_id, reason], |row| row.get(0))?
        .collect::<Result<Vec<String>, _>>()?;
    Ok(paths)
}

fn pending_intent_generation(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<i64>, SyncSqliteError> {
    Ok(conn
        .prepare_cached(
            "SELECT mutation_generation FROM materialization_intents
             WHERE group_id = ?1 AND path = ?2 AND kind = 'structural_mkdir'",
        )?
        .query_row(rusqlite::params![group_id, path], |row| row.get(0))
        .optional()?)
}

fn delete_intent(conn: &Connection, group_id: &str, path: &str) -> Result<bool, SyncSqliteError> {
    let removed = conn
        .prepare_cached(
            "DELETE FROM materialization_intents
             WHERE group_id = ?1 AND path = ?2 AND kind = 'structural_mkdir'",
        )?
        .execute(rusqlite::params![group_id, path])?;
    Ok(removed > 0)
}

/// Moves every origin strictly below `from` to the same relative place
/// below `to`, first dropping whatever was recorded below `to`. The ranges
/// are the half-open byte intervals (`p/`, `p0`), as in
/// [`crate::dag_store::live_descendant_paths`]: exactly the paths below
/// `p`, no `LIKE`.
fn move_origin_subtree(
    conn: &Connection,
    group_id: &str,
    from: &str,
    to: &str,
) -> Result<(), SyncSqliteError> {
    if from == to || to.starts_with(&format!("{from}/")) || from.starts_with(&format!("{to}/")) {
        // A directory cannot be renamed into its own subtree or onto an
        // ancestor; nothing coherent to move.
        return Ok(());
    }
    conn.prepare_cached(
        "DELETE FROM structural_directory_origins
         WHERE group_id = ?1 AND path > ?2 AND path < ?3",
    )?
    .execute(rusqlite::params![group_id, format!("{to}/"), format!("{to}0")])?;
    let below: Vec<String> = {
        let mut stmt = conn.prepare_cached(
            "SELECT path FROM structural_directory_origins
             WHERE group_id = ?1 AND path > ?2 AND path < ?3",
        )?;
        let rows = stmt.query_map(
            rusqlite::params![group_id, format!("{from}/"), format!("{from}0")],
            |row| row.get(0),
        )?;
        rows.collect::<Result<_, _>>()?
    };
    let mut update = conn.prepare_cached(
        "UPDATE structural_directory_origins SET path = ?3 WHERE group_id = ?1 AND path = ?2",
    )?;
    for old_path in below {
        let new_path = format!("{to}{}", &old_path[from.len()..]);
        update.execute(rusqlite::params![group_id, old_path, new_path])?;
    }
    Ok(())
}

fn delete_lost_provenance(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    conn.prepare_cached(
        "DELETE FROM structural_provenance_lost WHERE group_id = ?1 AND path = ?2",
    )?
    .execute(rusqlite::params![group_id, path])?;
    Ok(())
}

fn upsert_origin(
    conn: &Connection,
    group_id: &str,
    path: &str,
    identity: &FileIdentity,
    now_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    delete_lost_provenance(conn, group_id, path)?;
    conn.prepare_cached(
        "INSERT INTO structural_directory_origins
            (group_id, path, object_address, filesystem_identity, recorded_at_unix_nanos)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (group_id, path) DO UPDATE SET
            object_address = excluded.object_address,
            filesystem_identity = excluded.filesystem_identity,
            recorded_at_unix_nanos = excluded.recorded_at_unix_nanos",
    )?
    .execute(rusqlite::params![
        group_id,
        path,
        encode_object_address(identity),
        encode_file_identity(identity),
        now_unix_nanos,
    ])?;
    Ok(())
}

#[cfg(test)]
mod tests;
