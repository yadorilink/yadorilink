//! What a local writer was shown, and whether it still holds.
//!
//! A capture reads the materialization proof of a path and, in the same
//! snapshot, the native heads of that path: the witness records the version
//! the disk is guaranteed to hold and the live heads of exactly that version.
//! Authoring then supersedes those heads and nothing else.
//!
//! The version is the proof's, never the index row's. A row can run ahead of
//! the disk (a write that moved the row and then failed or crashed before its
//! rename); an edit of the bytes still on disk saw the older version, and
//! superseding the row's newer one would delete a peer's change nobody had
//! looked at. A proof whose mutation fence has moved vouches for nothing, so
//! the edit then supersedes nothing and lands beside what is live.

use rusqlite::Connection;

use yadorilink_replica_domain::ids::{FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::native_state::{Dot, NativeCaptureWitness};

use crate::error::SyncSqliteError;

/// Every live head at `path` whose version is `version`, sorted by dot.
fn live_class(
    conn: &Connection,
    group_id: &FolderGroupId,
    path: &SyncPath,
    version: &VersionHash,
) -> Result<Vec<Dot>, SyncSqliteError> {
    let mut class: Vec<Dot> = crate::native_store::native_heads_at(conn, group_id, path)?
        .into_iter()
        .filter(|head| head.payload.version == *version)
        .map(|head| head.dot)
        .collect();
    class.sort();
    Ok(class)
}

/// The version the disk of `path` is guaranteed to hold: the version of its
/// usable materialization proof, when the index still has a live row for it.
fn guaranteed_version(
    conn: &Connection,
    group_id: &FolderGroupId,
    path: &str,
) -> Result<Option<VersionHash>, SyncSqliteError> {
    let live_row = matches!(
        crate::store::read_canonical_current_row(conn, group_id.as_str(), path)?,
        Some(row) if !row.snapshot.deleted
    );
    if !live_row {
        return Ok(None);
    }
    Ok(crate::materialized_generation::lookup_materialized_generation(
        conn,
        group_id.as_str(),
        path,
    )?
    .and_then(|proof| proof.version))
}

fn row_version_of(
    conn: &Connection,
    group_id: &FolderGroupId,
    path: &str,
) -> Result<Option<VersionHash>, SyncSqliteError> {
    Ok(crate::store::read_canonical_current_row(conn, group_id.as_str(), path)?
        .filter(|row| !row.snapshot.deleted)
        .map(|row| row.version_hash()))
}

/// The witness of a path native has no row for.
pub fn absent_native_witness(path: &str) -> NativeCaptureWitness {
    NativeCaptureWitness {
        path: SyncPath(path.to_owned()),
        shown_class: Vec::new(),
        shown_version: None,
        row_version: None,
    }
}

/// Native's capture witness for `path`, read at the same moment a caller
/// reads the canonical current row.
pub fn capture_native_witness(
    conn: &Connection,
    group_id: &FolderGroupId,
    path: &str,
) -> Result<NativeCaptureWitness, SyncSqliteError> {
    let sync = SyncPath(path.to_owned());
    // The content the disk is guaranteed to hold, and every live head of it:
    // what an edit of this file has to supersede.
    let (shown_version, shown_class) = match guaranteed_version(conn, group_id, path)? {
        Some(version) => (Some(version), live_class(conn, group_id, &sync, &version)?),
        None => (None, Vec::new()),
    };
    let row_version = row_version_of(conn, group_id, path)?;
    Ok(NativeCaptureWitness { path: sync, shown_class, shown_version, row_version })
}

/// [`capture_native_witness`] for every path native holds a head for, from
/// one read of the group's state. A path missing from the result has no head,
/// so its witness is the absent one ([`absent_native_witness`]).
pub fn capture_native_witnesses(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<std::collections::HashMap<String, NativeCaptureWitness>, SyncSqliteError> {
    let state = crate::native_store::load_state(conn, group_id)?;
    let mut witnesses = std::collections::HashMap::with_capacity(state.heads.len());
    for (path, heads) in &state.heads {
        let (shown_version, shown_class) = match guaranteed_version(conn, group_id, path.as_str())?
        {
            Some(shown) => {
                let mut class: Vec<Dot> = heads
                    .iter()
                    .filter(|(_, payload)| payload.version == shown)
                    .map(|(dot, _)| dot.clone())
                    .collect();
                class.sort();
                (Some(shown), class)
            }
            None => (None, Vec::new()),
        };
        witnesses.insert(
            path.as_str().to_owned(),
            NativeCaptureWitness {
                path: path.clone(),
                shown_class,
                shown_version,
                row_version: row_version_of(conn, group_id, path.as_str())?,
            },
        );
    }
    Ok(witnesses)
}

/// Why a re-verified witness no longer matches what the row shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeStaleCaptureReason {
    /// The witness captured an absent row (a create); the row is no longer
    /// absent.
    UnexpectedContentAppeared,
    /// The row the capture was taken from shows nothing any more.
    RowGone,
    /// The disk's guaranteed version is another one now: something replaced
    /// it before the commit.
    RowChanged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeStaleCaptureVerdict {
    /// The row still shows exactly what the witness captured.
    Fresh,
    Stale(NativeStaleCaptureReason),
}

/// Re-verifies `witness` against the current state, inside the caller's own
/// transaction: read-only, never refuses anything itself.
///
/// What the writer saw is the CONTENT its row displayed, not the head that
/// happened to represent it. A different head of the same content arriving,
/// or the captured heads going away, does not change what the writer saw: the
/// edit supersedes the heads of that content its capture held and leaves every
/// other head concurrent. Only the row moving off that content makes the
/// capture stale.
pub fn verify_native_capture_witness(
    conn: &Connection,
    group_id: &FolderGroupId,
    witness: &NativeCaptureWitness,
) -> Result<NativeStaleCaptureVerdict, SyncSqliteError> {
    let current = capture_native_witness(conn, group_id, witness.path.as_str())?;
    Ok(match (witness.row_version, current.row_version) {
        (None, None) => NativeStaleCaptureVerdict::Fresh,
        (None, Some(_)) => {
            NativeStaleCaptureVerdict::Stale(NativeStaleCaptureReason::UnexpectedContentAppeared)
        }
        (Some(_), None) => NativeStaleCaptureVerdict::Stale(NativeStaleCaptureReason::RowGone),
        (Some(then), Some(now)) if then == now => NativeStaleCaptureVerdict::Fresh,
        (Some(_), Some(_)) => {
            NativeStaleCaptureVerdict::Stale(NativeStaleCaptureReason::RowChanged)
        }
    })
}

/// Refuses with [`SyncSqliteError::LocalWriteCaptureStale`] when the row a
/// write acts on no longer shows what native captured for it. `None` means no
/// earlier observation was taken, so there is nothing to refuse.
pub fn require_fresh_native_capture(
    conn: &Connection,
    group_id: &str,
    row_path: &str,
    witness: Option<&NativeCaptureWitness>,
) -> Result<(), SyncSqliteError> {
    let Some(witness) = witness else { return Ok(()) };
    if witness.path.as_str() != row_path {
        return Err(SyncSqliteError::InvalidInput(format!(
            "native capture witness is for {:?} but the write acts on {row_path:?}",
            witness.path.as_str()
        )));
    }
    let group = FolderGroupId(group_id.to_owned());
    match verify_native_capture_witness(conn, &group, witness)? {
        NativeStaleCaptureVerdict::Fresh => Ok(()),
        NativeStaleCaptureVerdict::Stale(_) => Err(SyncSqliteError::LocalWriteCaptureStale {
            group_id: group_id.to_string(),
            path: row_path.to_string(),
        }),
    }
}
