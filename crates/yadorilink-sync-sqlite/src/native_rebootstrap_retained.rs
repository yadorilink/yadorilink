//! The lifecycle of an original a rebootstrap kept instead of unlinking.
//!
//! Where the platform cannot prove that no program still holds the moved original open for
//! writing, the quarantine keeps the object under its claimed name and records it in its
//! `retained` row (see [`Removal::Retained`](crate::native_rebootstrap_install::Removal)). The
//! row survives the end of the rebootstrap: it is the only record of where the object is.
//!
//! This module lists those rows and offers the one way to release them: a cleanup that retries
//! the same writer exclusion the quarantine used, and removes the object only while it still has
//! the bytes the row recorded. Other bytes are saved first as a recovery item (a late edit),
//! then the retry goes on. Where the exclusion cannot be proved the object stays retained. No
//! age, name shape or modification time is consulted: only the row's claim and digest.

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use yadorilink_replica_domain::ids::FolderGroupId;

use crate::error::SyncSqliteError;
use crate::native_rebootstrap_install::{
    observe_through, require_same_object, Observed, WriteExclusion,
};
use crate::native_recovery_items::{
    late_edit_item_is_durable, prepare_late_edit, LateEdit, LateEditError, LateEditMeta,
};

/// A retained original: where it was and the claim it is kept under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedOriginal {
    pub recovery_id: String,
    /// The path the original had in the root.
    pub path: String,
    /// The private name token the object is kept under.
    pub claim: String,
}

/// The retained originals of `group`, in path order, whether or not a rebootstrap is running.
pub fn retained_originals(
    conn: &Connection,
    group: &FolderGroupId,
) -> Result<Vec<RetainedOriginal>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT recovery_id, path, removal_claim FROM native_rebootstrap_quarantine \
         WHERE group_id = ?1 AND status = 'retained' ORDER BY path ASC, recovery_id ASC",
    )?;
    let rows = stmt
        .query_map([group.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(recovery_id, path, claim)| {
            // A retained row always names its claim: the claim is the only record of where the
            // object is, so a row without one is corruption, never guessed around.
            let claim = claim.ok_or_else(|| {
                SyncSqliteError::CorruptState(format!(
                    "retained rebootstrap original {path}: no claim"
                ))
            })?;
            Ok(RetainedOriginal { recovery_id, path, claim })
        })
        .collect()
}

/// The groups that have a retained original, removed groups included: the originals belong to
/// the device, not to a linked folder.
pub fn groups_with_retained_originals(
    conn: &Connection,
) -> Result<Vec<FolderGroupId>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT group_id FROM native_rebootstrap_quarantine \
         WHERE status = 'retained' ORDER BY group_id ASC",
    )?;
    let groups = stmt
        .query_map([], |row| row.get::<_, String>(0).map(FolderGroupId))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(groups)
}

/// How many originals are retained, of every group: one indexed count, for a status path.
pub fn count_retained_originals(conn: &Connection) -> Result<u32, SyncSqliteError> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM native_rebootstrap_quarantine WHERE status = 'retained'",
        [],
        |row| row.get(0),
    )?)
}

/// What identifies the kept object's content and the metadata a restore would give back (mtime,
/// permission bits and replicated xattrs where the platform has them), as one digest. A change
/// to any of them is an edit that must be saved before the object goes.
pub fn kept_fingerprint(observed: &Observed) -> Option<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let Observed::File { size, sha256, mtime_unix_nanos, unix_mode, xattrs } = observed else {
        return None;
    };
    let mut hasher = Sha256::new();
    hasher.update(sha256);
    hasher.update(size.to_be_bytes());
    hasher.update(mtime_unix_nanos.to_be_bytes());
    match unix_mode {
        Some(mode) => {
            hasher.update([1]);
            hasher.update(mode.to_be_bytes());
        }
        None => hasher.update([0]),
    }
    match xattrs {
        Some(xattrs) => {
            hasher.update([1]);
            hasher.update((xattrs.len() as u64).to_be_bytes());
            for (name, value) in xattrs {
                for part in [name.as_bytes(), value.as_slice()] {
                    hasher.update((part.len() as u64).to_be_bytes());
                    hasher.update(part);
                }
            }
        }
        None => hasher.update([0]),
    }
    Some(hasher.finalize().into())
}

/// The root, as the cleanup of retained originals sees it: only the claimed objects.
pub trait RetainedRoot {
    /// What stands under the claim of `path` (`Absent` when nothing does).
    fn observe_claimed(&self, path: &str, claim: &str) -> Result<Observed, String>;
    /// The claimed regular file, opened for streaming.
    fn open_claimed(&self, path: &str, claim: &str) -> Result<Box<dyn std::io::Read>, String>;
    /// Unlinks the claimed object if the exclusion of writers can be proved and the object still
    /// has `expected_fingerprint` ([`kept_fingerprint`]).
    fn unlink_claimed(
        &self,
        path: &str,
        claim: &str,
        expected_fingerprint: &[u8; 32],
    ) -> Result<ClaimedUnlink, String>;
}

/// How an attempt to unlink a claimed object ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimedUnlink {
    Removed,
    /// The exclusion of writers could not be proved; nothing was unlinked.
    Retained,
    /// The object does not have the expected bytes; nothing was unlinked.
    Changed,
}

/// [`unlink_exclusively`](crate::native_rebootstrap_install::unlink_exclusively) for an object
/// known by its digest.
pub fn unlink_claimed_exclusively(
    private: &Path,
    expected_fingerprint: &[u8; 32],
    open: &dyn Fn(&Path) -> std::io::Result<WriteExclusion>,
    unlink: &dyn Fn(&Path) -> std::io::Result<()>,
) -> Result<ClaimedUnlink, String> {
    let held = open(private).map_err(|e| e.to_string())?;
    if !held.file.metadata().map_err(|e| e.to_string())?.is_file() {
        return Ok(ClaimedUnlink::Changed);
    }
    if kept_fingerprint(&observe_through(&held.file)?).as_ref() != Some(expected_fingerprint) {
        return Ok(ClaimedUnlink::Changed);
    }
    // Verified through the handle that holds the exclusion: with no writer possible the
    // verified content is the final content.
    if !held.still_excludes_writers().map_err(|e| e.to_string())? {
        return Ok(ClaimedUnlink::Retained);
    }
    // The name still leads to the verified object: the unlink is by name.
    require_same_object(private, &held.file)?;
    unlink(private).map_err(|e| e.to_string())?;
    Ok(ClaimedUnlink::Removed)
}

/// What the cleanup of one retained original did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetainedOutcome {
    /// The object was removed and its row cleared.
    Removed,
    /// Nothing stood under the claim any more; the row was cleared.
    Gone,
    /// The exclusion of writers cannot be proved; the object stays retained.
    StillRetained,
    /// The object had other bytes than the row recorded: they were saved as a recovery item
    /// first. `removed` says whether the retry then removed it.
    PreservedChange { removed: bool },
    /// The row cannot be judged (no recorded digest, or the object is not a regular file) or
    /// the attempt failed; the object stays retained.
    Left(String),
}

/// What the cleanup needs besides the root.
pub struct RetainedContext<'a> {
    pub items_root: &'a Path,
    pub sync_roots: &'a [PathBuf],
    pub now_unix: i64,
    pub root: &'a dyn RetainedRoot,
}

/// Tries to release every retained original of `group`. A row whose attempt fails stays; the
/// others go on. Running it again is safe at any point.
pub fn cleanup_retained(
    conn: &Connection,
    ctx: &RetainedContext<'_>,
    group: &FolderGroupId,
) -> Result<Vec<(RetainedOriginal, RetainedOutcome)>, SyncSqliteError> {
    let mut outcomes = Vec::new();
    for original in retained_originals(conn, group)? {
        let outcome = match release_one(conn, ctx, group, &original) {
            Ok(outcome) => outcome,
            Err(Failure::Store(error)) => return Err(error),
            Err(Failure::Left(why)) => RetainedOutcome::Left(why),
        };
        outcomes.push((original, outcome));
    }
    Ok(outcomes)
}

enum Failure {
    Store(SyncSqliteError),
    Left(String),
}

impl From<SyncSqliteError> for Failure {
    fn from(error: SyncSqliteError) -> Self {
        Self::Store(error)
    }
}

impl From<rusqlite::Error> for Failure {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(error.into())
    }
}

fn clear_row(
    conn: &Connection,
    group: &FolderGroupId,
    original: &RetainedOriginal,
) -> Result<(), SyncSqliteError> {
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    for table in ["native_rebootstrap_retained_digest", "native_rebootstrap_quarantine"] {
        let only_retained =
            if table == "native_rebootstrap_quarantine" { " AND status = 'retained'" } else { "" };
        tx.execute(
            &format!(
                "DELETE FROM {table} WHERE group_id = ?1 AND recovery_id = ?2 AND path = ?3\
                 {only_retained}"
            ),
            (group.as_str(), &original.recovery_id, &original.path),
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn release_one(
    conn: &Connection,
    ctx: &RetainedContext<'_>,
    group: &FolderGroupId,
    original: &RetainedOriginal,
) -> Result<RetainedOutcome, Failure> {
    let (path, claim) = (original.path.as_str(), original.claim.as_str());
    let observed = ctx.root.observe_claimed(path, claim).map_err(Failure::Left)?;
    // Nothing under the claim: the object is gone, and the row only pointed at it.
    if observed == Observed::Absent {
        clear_row(conn, group, original)?;
        return Ok(RetainedOutcome::Gone);
    }
    let Some(observed_fingerprint) = kept_fingerprint(&observed) else {
        return Ok(RetainedOutcome::Left("the claimed object is not a regular file".into()));
    };
    let Observed::File { size, sha256: observed_sha, mtime_unix_nanos, unix_mode, xattrs } =
        observed
    else {
        unreachable!("a fingerprint exists only for a regular file")
    };
    let (recorded, item_id): (Option<Vec<u8>>, Option<String>) = conn.query_row(
        "SELECT (SELECT fingerprint FROM native_rebootstrap_retained_digest d \
                      WHERE d.group_id = q.group_id AND d.recovery_id = q.recovery_id \
                        AND d.path = q.path), q.late_item_id \
             FROM native_rebootstrap_quarantine q \
             WHERE q.group_id = ?1 AND q.recovery_id = ?2 AND q.path = ?3 \
               AND q.status = 'retained'",
        (group.as_str(), &original.recovery_id, path),
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let Some(recorded) = recorded.and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
    else {
        return Ok(RetainedOutcome::Left("the row records no digest of the kept object".into()));
    };
    let mut expected = recorded;
    let mut preserved = false;
    // The bytes are kept by a recovery item when the row names one: a user can discard that item,
    // and the object must not then be the last copy that is unlinked.
    let item_missing = match &item_id {
        Some(item_id) => !late_edit_item_is_durable(conn, ctx.items_root, group, path, item_id)?,
        None => false,
    };
    if observed_fingerprint != recorded || item_missing {
        // Not the bytes the row recorded: they are saved as a recovery item, registered, before
        // anything is removed, and the row then names them as the expected content.
        let meta = LateEditMeta { mtime_unix_nanos, unix_mode, xattrs: xattrs.unwrap_or_default() };
        let edit = LateEdit {
            path,
            symlink: false,
            size,
            sha256: observed_sha,
            symlink_target: &[],
            meta: Some(meta),
        };
        let open = || ctx.root.open_claimed(path, claim);
        let prepared = prepare_late_edit(
            conn,
            ctx.items_root,
            ctx.sync_roots,
            group,
            &edit,
            &open,
            ctx.now_unix,
        )
        .map_err(|e| match e {
            LateEditError::Source(why) => Failure::Left(why),
            LateEditError::Store(error) => Failure::Store(error),
        })?;
        let tx =
            rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
        prepared.register(&tx, group, &original.recovery_id, ctx.now_unix)?;
        tx.execute(
            "UPDATE native_rebootstrap_quarantine SET late_sha256 = ?4, late_item_id = ?5 \
             WHERE group_id = ?1 AND recovery_id = ?2 AND path = ?3 AND status = 'retained'",
            (
                group.as_str(),
                &original.recovery_id,
                path,
                observed_sha.as_slice(),
                prepared.item_id(),
            ),
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO native_rebootstrap_retained_digest \
             (group_id, recovery_id, path, fingerprint) VALUES (?1, ?2, ?3, ?4)",
            (group.as_str(), &original.recovery_id, path, observed_fingerprint.as_slice()),
        )?;
        tx.commit()?;
        expected = observed_fingerprint;
        preserved = true;
    }
    let result = ctx.root.unlink_claimed(path, claim, &expected).map_err(Failure::Left)?;
    Ok(match (result, preserved) {
        (ClaimedUnlink::Removed, preserved) => {
            clear_row(conn, group, original)?;
            if preserved {
                RetainedOutcome::PreservedChange { removed: true }
            } else {
                RetainedOutcome::Removed
            }
        }
        (ClaimedUnlink::Retained, true) | (ClaimedUnlink::Changed, true) => {
            RetainedOutcome::PreservedChange { removed: false }
        }
        (ClaimedUnlink::Retained, false) | (ClaimedUnlink::Changed, false) => {
            RetainedOutcome::StillRetained
        }
    })
}
