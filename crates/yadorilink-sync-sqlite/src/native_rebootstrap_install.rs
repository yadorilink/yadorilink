//! Quarantining and installing: from the preserved barrier to an installed target.
//!
//! It starts from [`Preserved`](crate::native_rebootstrap::RebootstrapState)
//! and takes its input only from the recovery area of the journal's recovery id:
//! the target is the exact bundle stored there, verified again locally from what
//! is stored with it, never an argument and never a bundle fetched again.
//!
//! The group has been frozen since the final capture pass began (see
//! [`crate::native_rebootstrap::group_frozen`]): nothing is authored, admitted or
//! materialized, so the barrier's protected set cannot change under the install.
//!
//! 1. In the transaction that finds that set still identical to what the barrier
//!    recorded (the frontier hash), the journal moves to `Quarantining`. Nothing in
//!    the sync root has been touched yet.
//! 2. The originals of the changes this device may no longer author (a Viewer, a
//!    revoked Writer, a withheld path) leave the root, each only after its
//!    verified copy is in the recovery area, and exactly once. A user's edit made
//!    after the barrier is saved first as a permanent recovery item (see
//!    [`crate::native_recovery_items`]), registered in the transaction that
//!    authorizes the removal.
//! 3. One transaction replaces the group's native state by the target's, through
//!    [`install_checkpoint`](crate::native_checkpoint_install::install_checkpoint), the
//!    only place a group's state is cleared: it re-checks the barrier immediately
//!    before the clear, installs the target, arms the projection, rotates this
//!    device to a new incarnation and closes the old ones at the target's position
//!    with closures this device signs; this transaction then moves the journal to
//!    `CatchingUp`. A crash before the commit leaves the old state; after it, the new
//!    one. The journal and the closures survive the clear (see
//!    [`CLEARED_BY_INSTALL`](crate::native_checkpoint_install::CLEARED_BY_INSTALL)). What
//!    follows is [`crate::native_rebootstrap_replay`]: the bounded catch-up, the replay of
//!    own intent, and [`crate::native_rebootstrap::finish_rebootstrap`], which ends the
//!    freeze.
//!
//! The materializer is not asked to do anything here: the installed projection is
//! followed through the ordinary scheduler once the freeze ends.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::Connection;

use yadorilink_replica_domain::author::AuthorId;
use yadorilink_replica_domain::ids::{FolderGroupId, VersionHash};

use crate::error::SyncSqliteError;
use crate::native_checkpoint_install::{CheckpointError, InstallKind, RebootstrapBarrier};
use crate::native_rebootstrap::{
    area_failure, frozen_frontier_unchanged, rebootstrap_status, resume_preserved, set_state,
    verify_target_in_area, BlockedReason, CaptureBarrier, Crash, InstallAuthority,
    PreservationFailure, PreserveContext, ReassertAuthority, RebootstrapState,
};
use crate::native_rebootstrap_recovery::{io_chunk, sha256, Manifest, RecoveryArea};
use crate::native_rebootstrap_replay::units_replayable_now;
use crate::native_recovery_items::{
    late_edit_item_is_durable, prepare_late_edit, verify_items, LateEdit, LateEditError,
    LateEditMeta,
};

pub(crate) fn init_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        -- The originals of changes this device may no longer author, and what
        -- became of each: progress bookkeeping and the user's pointer to the copy
        -- in the recovery area (the manifest names the versions).
        CREATE TABLE IF NOT EXISTS native_rebootstrap_quarantine (
            group_id    TEXT NOT NULL,
            recovery_id TEXT NOT NULL,
            path        TEXT NOT NULL,
            status      TEXT NOT NULL,
            -- The digest of an edit made after the barrier, whose recovery item is
            -- registered in the transaction that sets `removing`. Progress only: the
            -- item, not this column, keeps the edit.
            late_sha256 BLOB,
            -- The id of that registered item, written with `late_sha256` in the same
            -- transaction. A crash-resume that finds the original gone confirms exactly this
            -- item, not merely some late edit of the same path and bytes.
            late_item_id TEXT,
            -- The name token under which the root moves the original aside for its removal,
            -- written before the move. The moved object is owned through this row: a resume
            -- gives it back to its path before looking again, so nothing is left under a
            -- name no record points at.
            removal_claim TEXT,
            PRIMARY KEY (group_id, recovery_id, path)
        ) WITHOUT ROWID;
        -- The fingerprint (content and metadata) of the object a `retained` quarantine row names
        -- under its claim, as it was verified when it was kept. A later cleanup removes the object
        -- only while it still has it; other bytes are saved as a late edit first. Its own table, so databases
        -- that predate it need no column added.
        CREATE TABLE IF NOT EXISTS native_rebootstrap_retained_digest (
            group_id    TEXT NOT NULL,
            recovery_id TEXT NOT NULL,
            path        TEXT NOT NULL,
            fingerprint BLOB NOT NULL,
            PRIMARY KEY (group_id, recovery_id, path)
        ) WITHOUT ROWID;
        "#,
    )?;
    Ok(())
}

// --- the root, as the quarantine sees it ---------------------------------------------------------

/// What stands at a path of the sync root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observed {
    Absent,
    File {
        size: u64,
        sha256: [u8; 32],
        mtime_unix_nanos: i64,
        /// `None` where the platform has no permission bits to observe.
        unix_mode: Option<u32>,
        /// The replicated extended attributes, `None` where the platform cannot observe them.
        xattrs: Option<Vec<(String, Vec<u8>)>>,
    },
    Symlink {
        target: Vec<u8>,
    },
    /// A directory is never the quarantine's to remove: its entries are other
    /// paths.
    Directory,
    Other,
}

/// Observes an open regular file: its bytes and the metadata ordinary capture would read from
/// the same handle (the permission bits and replicated xattrs where the platform has them).
///
/// The bytes are hashed through one fixed buffer, never held.
pub fn observe_regular_file(mut file: std::fs::File) -> Result<Observed, String> {
    let meta = file.metadata().map_err(|e| e.to_string())?;
    let (digest, size) = crate::native_rebootstrap_recovery::sha256_stream(&mut file, io_chunk())
        .map_err(|e| e.to_string())?;
    let mtime_unix_nanos =
        match meta.modified().map_err(|e| e.to_string())?.duration_since(std::time::UNIX_EPOCH) {
            Ok(after) => i64::try_from(after.as_nanos()).unwrap_or(i64::MAX),
            Err(before) => -i64::try_from(before.duration().as_nanos()).unwrap_or(i64::MAX),
        };
    // A failed xattr read must not look like "no attributes": that would let a changed file
    // pass as unchanged and be removed.
    #[cfg(target_os = "linux")]
    let xattrs = Some(
        yadorilink_local_storage::read_replicated_xattrs_strict(&file)
            .map_err(|e| format!("reading extended attributes: {e}"))?,
    );
    #[cfg(not(target_os = "linux"))]
    let xattrs = None;
    Ok(Observed::File {
        size,
        sha256: digest,
        mtime_unix_nanos,
        unix_mode: yadorilink_local_storage::unix_mode_from_metadata(&meta),
        xattrs,
    })
}

/// The sync root, reached by the daemon through its root-confined operations.
pub trait QuarantineRoot {
    fn observe(&self, path: &str) -> Result<Observed, String>;
    /// The regular file at `path`, opened for streaming: its content is read through a bounded
    /// buffer and never held whole.
    fn open_file(&self, path: &str) -> Result<Box<dyn std::io::Read>, String>;
    /// Removes the object at `path` if it is still exactly `expected`, moving it aside under
    /// the private name `claim` names (the caller recorded `claim` durably before this call).
    ///
    /// Comparing and then unlinking by name is not atomic: the user can save in
    /// between, and the save would be unlinked unseen. A real implementation
    /// therefore renames the object to a private name INSIDE the root (same
    /// volume, so the rename is atomic and the object cannot be written under its
    /// old name any more), verifies the renamed object against `expected`, and
    /// only then unlinks it. If it is not `expected` any more it renames it back
    /// (unless the name was taken again meanwhile, in which case it keeps the
    /// renamed object in the recovery area as a late edit) and returns an error,
    /// so the next attempt observes the new content and saves it first.
    ///
    /// A regular file is unlinked only through [`unlink_exclusively`]: where the operating
    /// system cannot prove that no program holds the moved object open for writing, the object
    /// is kept under `claim` ([`Removal::Retained`]) instead of being unlinked.
    fn remove(&self, path: &str, expected: &Observed, claim: &str) -> Result<Removal, String>;
    /// Gives an object moved aside under `claim` back to `path`, if one is still there (the
    /// removal that moved it did not finish). Nothing under `claim` is a completed removal and
    /// is `Ok`. If `path` is occupied again the object stays where it is and this fails: the
    /// install blocks rather than choosing between two files.
    fn release_claim(&self, path: &str, claim: &str) -> Result<(), String>;
}

/// What a removal did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Removal {
    /// The object is gone, exactly as it was observed.
    Removed,
    /// The object left its path but was not unlinked: it stays under the private name of its
    /// claim, owned by the quarantine row, because a program may hold it open for writing and
    /// whatever it writes through that handle must stay reachable. Nothing deletes it
    /// automatically; it is the user's file, and the claim in the row names where it is.
    Retained,
}

/// How an attempt to unlink a verified regular file ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unlinked {
    /// The object was not `expected` when it was verified; nothing was unlinked.
    ChangedBeforeUnlink,
    Done(Removal),
}

pub(crate) fn observe_through(file: &std::fs::File) -> Result<Observed, String> {
    use std::io::Seek;
    let mut handle = file.try_clone().map_err(|e| e.to_string())?;
    handle.rewind().map_err(|e| e.to_string())?;
    observe_regular_file(handle)
}

/// Unlinks the regular file at `private` (already moved aside under a name no program uses) only
/// if the operating system guarantees that no program can write to it, and keeps it otherwise.
///
/// Verifying and then unlinking by name or by handle cannot be made safe against a program that
/// opened the file before the move: it shares the object, not the name, and can write after any
/// check and after the unlink. So the object is opened with
/// [`open_excluding_writers`](yadorilink_fs_platform::write_exclusion::open_excluding_writers)
/// (a write lease on Linux, a share mode without write sharing on Windows), verified through that
/// handle, and unlinked while the exclusion holds: no writer can exist, so the verified content is
/// the final content. Where the exclusion is not granted (another program has the file open, or
/// the platform has no such primitive) the object is retained, never unlinked.
/// `open` is [`open_excluding_writers`] (a parameter so tests can stand in for a platform that
/// grants the exclusion); `before_unlink` runs between the verification and the unlink, for tests.
pub fn unlink_exclusively(
    private: &std::path::Path,
    expected: &Observed,
    open: &dyn Fn(&std::path::Path) -> std::io::Result<WriteExclusion>,
    before_unlink: &dyn Fn(),
    unlink: &dyn Fn(&std::path::Path) -> std::io::Result<()>,
) -> Result<Unlinked, String> {
    let held = open(private).map_err(|e| e.to_string())?;
    if !held.file.metadata().map_err(|e| e.to_string())?.is_file()
        || observe_through(&held.file)? != *expected
    {
        return Ok(Unlinked::ChangedBeforeUnlink);
    }
    before_unlink();
    if !held.still_excludes_writers().map_err(|e| e.to_string())? {
        return Ok(Unlinked::Done(Removal::Retained));
    }
    // The name still leads to the verified object: the unlink is by name.
    require_same_object(private, &held.file)?;
    unlink(private).map_err(|e| e.to_string())?;
    Ok(Unlinked::Done(Removal::Removed))
}

pub use yadorilink_fs_platform::write_exclusion::{open_excluding_writers, WriteExclusion};

/// What the name of an object to unlink leads to, compared with the handle that verified it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NameCheck {
    Same,
    /// The name leads to another object now (it was swapped after the verification).
    Different,
    /// The identity of either side could not be read or is not conclusive: treated as not the
    /// verified object, never as the same.
    Unverifiable,
}

/// Decides [`NameCheck`] from the two identity observations; every failure to observe, and every
/// inconclusive comparison, fails closed to [`NameCheck::Unverifiable`].
#[cfg(any(windows, test))]
pub(crate) fn judge_identities(
    by_name: std::io::Result<yadorilink_fs_platform::fs_identity::FileIdentity>,
    by_handle: std::io::Result<yadorilink_fs_platform::fs_identity::FileIdentity>,
) -> NameCheck {
    use yadorilink_fs_platform::fs_identity::{IdentityComparison, TimestampGranularity};
    match (by_name, by_handle) {
        (Ok(name), Ok(handle)) => match name.compare(&handle, TimestampGranularity::Fine) {
            IdentityComparison::SameObject => NameCheck::Same,
            IdentityComparison::DefinitelyDifferent => NameCheck::Different,
            IdentityComparison::Ambiguous(_) => NameCheck::Unverifiable,
        },
        _ => NameCheck::Unverifiable,
    }
}

#[cfg(unix)]
pub(crate) fn name_check(path: &std::path::Path, file: &std::fs::File) -> NameCheck {
    use std::os::unix::fs::MetadataExt;
    let (Ok(by_name), Ok(by_handle)) = (std::fs::symlink_metadata(path), file.metadata()) else {
        return NameCheck::Unverifiable;
    };
    if by_name.dev() == by_handle.dev() && by_name.ino() == by_handle.ino() {
        NameCheck::Same
    } else {
        NameCheck::Different
    }
}

/// Windows: the volume serial number and file id of the path and of the handle (through the
/// shared identity helpers); an id that cannot be read or proved is not "the same".
#[cfg(windows)]
pub(crate) fn name_check(path: &std::path::Path, file: &std::fs::File) -> NameCheck {
    use yadorilink_fs_platform::fs_identity::FileIdentity;
    judge_identities(FileIdentity::observe_path(path), FileIdentity::observe_handle(file))
}

/// No identity primitive on other platforms: nothing is unlinked on their account.
#[cfg(not(any(unix, windows)))]
pub(crate) fn name_check(_: &std::path::Path, _: &std::fs::File) -> NameCheck {
    NameCheck::Unverifiable
}

/// The name still leads to the verified object, or an error that says which way it does not.
pub(crate) fn require_same_object(
    path: &std::path::Path,
    file: &std::fs::File,
) -> Result<(), String> {
    match name_check(path, file) {
        NameCheck::Same => Ok(()),
        NameCheck::Different => {
            Err(format!("{} no longer names the verified object", path.display()))
        }
        NameCheck::Unverifiable => {
            Err(format!("{} cannot be proved to name the verified object", path.display()))
        }
    }
}

pub struct InstallContext<'a> {
    pub preserve: &'a PreserveContext<'a>,
    pub root: &'a dyn QuarantineRoot,
    /// The signing key of this device, when it may close its own old
    /// incarnations. Without it (a replica that holds no write authority) the
    /// install signs no closure.
    pub closure_key: Option<&'a ed25519_dalek::SigningKey>,
}

// --- failpoints and results ------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallStep {
    /// Inside the install transaction, after the old native state was deleted.
    NativeStateCleared,
    /// ... after the target was installed through the join.
    TargetInstalled,
    /// ... after the projection was armed for the paths that changed.
    ProjectionArmed,
    /// ... after the incarnation was rotated and the old one closed.
    Rotated,
    /// ... after the journal says `catching_up`.
    Recorded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallPoint {
    /// The journal says `Quarantining`; no original has left the root.
    AfterBeginQuarantine,
    /// The quarantine of the item with this index is complete.
    AfterQuarantineItem(usize),
    InTransaction(InstallStep),
    /// The original with this index has left the root; its record is not yet written.
    AfterOriginalRemoved(usize),
    /// The install is committed.
    AfterCommit,
}

#[derive(Debug)]
pub enum InstallError {
    /// No such rebootstrap, or it is not at a stage the install runs from.
    NotInstallable(String),
    Blocked(BlockedReason),
    /// The stored target was refused by the join.
    BundleRefused(String),
    Crashed,
    /// Another call holds this group's rebootstrap.
    Busy,
    /// What the barrier protected is not what it recorded: the frontier, the closure
    /// rows, the manifest or the capture result moved while the group was frozen, so
    /// something wrote past the freeze. Found before anything was cleared; nothing was.
    FrontierChanged,
    Store(SyncSqliteError),
}

impl From<SyncSqliteError> for InstallError {
    fn from(error: SyncSqliteError) -> Self {
        Self::Store(error)
    }
}

impl From<CheckpointError> for InstallError {
    fn from(error: CheckpointError) -> Self {
        match error {
            CheckpointError::NotEmpty => {
                Self::NotInstallable("a rebootstrap install met a fresh-install refusal".into())
            }
            CheckpointError::NotInstallable(why) => Self::NotInstallable(why),
            CheckpointError::FrontierChanged => Self::FrontierChanged,
            CheckpointError::Blocked(reason) => Self::Blocked(reason),
            CheckpointError::Crashed => Self::Crashed,
            CheckpointError::Store(error) => Self::Store(error),
            refusal @ (CheckpointError::RetiredAuthorLifted { .. }
            | CheckpointError::ClosureFork { .. }
            | CheckpointError::ClosureNotBound { .. }) => Self::BundleRefused(refusal.to_string()),
        }
    }
}

impl From<rusqlite::Error> for InstallError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(error.into())
    }
}

/// What the install did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installed {
    pub recovery_id: String,
    /// The incarnation this device authors as from now on.
    pub new_author: AuthorId,
    /// The incarnations whose uncovered changes were preserved, now closed.
    pub old_authors: Vec<AuthorId>,
}

// --- the entry --------------------------------------------------------------------------------------

/// Installs the target of rebootstrap `recovery_id` of `group`, from the
/// preserved barrier. Idempotent and resumable: called again after a crash it
/// continues from the journal, and once installed it returns the same answer.
pub fn install_rebootstrap(
    conn: &Connection,
    ctx: &InstallContext<'_>,
    group: &FolderGroupId,
    recovery_id: &str,
    hook: &mut dyn FnMut(InstallPoint) -> Result<(), Crash>,
) -> Result<Installed, InstallError> {
    let status = rebootstrap_status(conn, group)?
        .ok_or_else(|| InstallError::NotInstallable("no rebootstrap".into()))?;
    if status.recovery_id != recovery_id {
        return Err(InstallError::NotInstallable(format!(
            "the rebootstrap of {group:?} is {}, not {recovery_id}",
            status.recovery_id
        )));
    }
    if !(matches!(status.state, RebootstrapState::Preserved | RebootstrapState::Quarantining)
        || status.state.is_installed())
    {
        return Err(InstallError::NotInstallable(format!("it is {:?}", status.state)));
    }
    let _busy = match crate::native_rebootstrap::acquire(conn, group) {
        Ok(guard) => guard,
        Err(crate::native_rebootstrap::BusyOrStore::Busy) => return Err(InstallError::Busy),
        Err(crate::native_rebootstrap::BusyOrStore::Store(error)) => {
            return Err(InstallError::Store(error))
        }
    };
    // The target is the stored one, anchored to the journal and verified again
    // from what is stored with it: no peer, no authority, no live policy.
    let preserved =
        resume_preserved(conn, ctx.preserve.recovery_root, group).map_err(InstallError::Blocked)?;
    let area = RecoveryArea::open_dir(&preserved.dir).map_err(|e| blocked_by(area_failure(e)))?;
    let intent = area.read_intent().map_err(|e| blocked_by(area_failure(e)))?;
    let manifest = intent.manifest;

    if status.state.is_installed() {
        return installed_summary(conn, recovery_id, &manifest);
    }

    if status.state == RebootstrapState::Preserved {
        if let CaptureBarrier::Partial { detail } = &ctx.preserve.capture {
            return Err(InstallError::Blocked(BlockedReason::PreservationFailed(
                PreservationFailure::CapturePartial { detail: detail.clone() },
            )));
        }
        verify_target_in_area(&area, group).map_err(|e| {
            InstallError::Blocked(BlockedReason::PreservationFailed(
                PreservationFailure::TargetNotVerifiable { detail: e.to_string() },
            ))
        })?;
        let tx =
            rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
        // The stage is read again inside the write transaction: it may have moved
        // since the first read.
        let still = rebootstrap_status(&tx, group)?;
        if still.as_ref().map(|s| (&s.state, &s.recovery_id))
            != Some((&RebootstrapState::Preserved, &recovery_id.to_owned()))
        {
            return Err(InstallError::NotInstallable("the stage moved".into()));
        }
        if !frozen_frontier_unchanged(&tx, group, &preserved.manifest_sha256)? {
            return Err(InstallError::FrontierChanged);
        }
        verify_items(&tx, &ctx.preserve.items_root, group, &manifest.remote_only)
            .map_err(InstallError::Blocked)?;
        begin_quarantine(
            &tx,
            group,
            recovery_id,
            &manifest,
            ctx.preserve.authority,
            ctx.preserve.now_unix,
        )?;
        tx.commit()?;
    }
    hook(InstallPoint::AfterBeginQuarantine).map_err(|_| InstallError::Crashed)?;

    quarantine(conn, ctx, group, recovery_id, &area, &manifest, hook)?;

    install_in_tx(conn, ctx, group, &area, recovery_id, &manifest, &preserved.manifest_sha256, hook)
}

fn blocked_by(reason: BlockedReason) -> InstallError {
    InstallError::Blocked(reason)
}

// --- beginning the quarantine -------------------------------------------------------------------------------

/// The paths a manifest's changes touch, each marked re-assertable if any change
/// to it is, as the authority answers now.
fn protected_paths(manifest: &Manifest, replayable: &[bool]) -> BTreeMap<String, bool> {
    let mut paths: BTreeMap<String, bool> = BTreeMap::new();
    for item in &manifest.items {
        let entry = paths.entry(item.path.clone()).or_insert(false);
        *entry |= replayable[item.unit];
    }
    paths
}

fn begin_quarantine(
    tx: &Connection,
    group: &FolderGroupId,
    recovery_id: &str,
    manifest: &Manifest,
    authority: &dyn ReassertAuthority,
    now: i64,
) -> Result<(), SyncSqliteError> {
    // The authority is asked again here, immediately before the install: a device that was a
    // Writer when the plan was made and is not now keeps nothing of its intent in the root, it
    // is quarantined. A path is quarantined only if every change to it is one that may not be
    // re-authored: a re-assertable change keeps the file where it is.
    let replayable = units_replayable_now(manifest, authority);
    for (path, reassertable) in &protected_paths(manifest, &replayable) {
        let puts = manifest
            .items
            .iter()
            .any(|item| item.path == *path && !replayable[item.unit] && item.put_version.is_some());
        if !reassertable && puts {
            tx.execute(
                "INSERT OR IGNORE INTO native_rebootstrap_quarantine \
                 (group_id, recovery_id, path, status) VALUES (?1, ?2, ?3, 'pending')",
                (group.as_str(), recovery_id, path),
            )?;
        }
    }
    set_state(tx, group, "quarantining", now)
}

// --- quarantine --------------------------------------------------------------------------------------------

/// What became of a quarantined original.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QuarantineStatus {
    /// Not yet looked at.
    Pending,
    /// The original left the root; its verified copy is in the recovery area.
    Removed,
    /// The original left the root, but it was an edit made after the barrier: it
    /// was saved first as a permanent recovery item.
    RemovedLateEdit { sha256: [u8; 32] },
    /// Nothing was there to remove (already gone); the copy is in the area.
    AlreadyAbsent,
    /// A directory stands there: not the quarantine's to remove.
    LeftInPlace,
    /// The original left its path and its copy is in the recovery area, but the object itself
    /// was not unlinked (see [`Removal::Retained`]): it stays under its claimed name.
    Retained,
}

/// A change this device can no longer author, kept in the recovery area instead
/// of the sync root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantinedItem {
    pub recovery_id: String,
    pub path: String,
    pub status: QuarantineStatus,
    /// The versions of this path the area holds, as the manifest names them.
    pub versions: Vec<VersionHash>,
}

fn status_text(status: &QuarantineStatus) -> (&'static str, Option<Vec<u8>>) {
    match status {
        QuarantineStatus::Pending => ("pending", None),
        QuarantineStatus::Removed => ("removed", None),
        QuarantineStatus::RemovedLateEdit { sha256 } => {
            ("removed_late_edit", Some(sha256.to_vec()))
        }
        QuarantineStatus::AlreadyAbsent => ("already_absent", None),
        QuarantineStatus::LeftInPlace => ("left_in_place", None),
        QuarantineStatus::Retained => ("retained", None),
    }
}

/// The quarantined items of `group`'s rebootstrap, for the user's status: the
/// recovery id, the relative path and the versions the recovery area holds for it
/// (the manifest at `<recovery id>/manifest.json` names each).
pub fn quarantined_items(
    conn: &Connection,
    group: &FolderGroupId,
    manifest: Option<&Manifest>,
) -> Result<Vec<QuarantinedItem>, SyncSqliteError> {
    let Some(status) = rebootstrap_status(conn, group)? else { return Ok(Vec::new()) };
    let mut stmt = conn.prepare(
        "SELECT path, status, late_sha256 FROM native_rebootstrap_quarantine \
         WHERE group_id = ?1 AND recovery_id = ?2 ORDER BY path ASC",
    )?;
    let rows = stmt
        .query_map((group.as_str(), &status.recovery_id), |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(path, state, late)| {
            let corrupt = |what: &str| {
                SyncSqliteError::CorruptState(format!("rebootstrap quarantine {path}: {what}"))
            };
            let status_value = match state.as_str() {
                "pending" | "removing" => QuarantineStatus::Pending,
                "removed" => QuarantineStatus::Removed,
                "removed_late_edit" => {
                    let late = late.ok_or_else(|| corrupt("a late edit without its digest"))?;
                    QuarantineStatus::RemovedLateEdit {
                        sha256: <[u8; 32]>::try_from(late.as_slice())
                            .map_err(|_| corrupt("a digest that is not 32 bytes"))?,
                    }
                }
                "already_absent" => QuarantineStatus::AlreadyAbsent,
                "left_in_place" => QuarantineStatus::LeftInPlace,
                "retained" => QuarantineStatus::Retained,
                _ => return Err(corrupt("an unknown status")),
            };
            let versions = manifest
                .map(|manifest| quarantined_versions(manifest, &path).into_iter().collect())
                .unwrap_or_default();
            Ok(QuarantinedItem {
                recovery_id: status.recovery_id.clone(),
                path,
                status: status_value,
                versions,
            })
        })
        .collect()
}

/// The versions the preserved changes put at `path`: whichever of them stands in the root is
/// a copy the recovery area already holds, so the unit that is not replayed loses none.
fn quarantined_versions(manifest: &Manifest, path: &str) -> BTreeSet<VersionHash> {
    manifest
        .items
        .iter()
        .filter(|item| item.path == path)
        .filter_map(|item| item.put_version)
        .collect()
}

/// A late edit a quarantine row recorded: its content digest and the exact item registered for it.
type LateRecord = ([u8; 32], String);

fn quarantine(
    conn: &Connection,
    ctx: &InstallContext<'_>,
    group: &FolderGroupId,
    recovery_id: &str,
    area: &RecoveryArea,
    manifest: &Manifest,
    hook: &mut dyn FnMut(InstallPoint) -> Result<(), Crash>,
) -> Result<(), InstallError> {
    // Item files a crash left before their row landed belong to the store's sweep, which runs
    // before any late edit is saved; no edit is ever inferred from them.
    crate::native_recovery_items::sweep_unregistered(conn, &ctx.preserve.items_root, group)?;
    // `removing` is an original whose copy is referenced and whose removal may or
    // may not have happened: the resume looks again.
    let pending: Vec<(String, Option<LateRecord>, Option<String>)> = {
        let mut stmt = conn.prepare(
            "SELECT path, late_sha256, late_item_id, removal_claim FROM native_rebootstrap_quarantine \
             WHERE group_id = ?1 AND recovery_id = ?2 AND status IN ('pending', 'removing') \
             ORDER BY path ASC",
        )?;
        let rows = stmt
            .query_map((group.as_str(), recovery_id), |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(path, late, item_id, claim)| {
                // The digest and the item id are written together; one without the other is
                // not a state this code writes, so it is corruption, never guessed around.
                let late = match (late, item_id) {
                    (None, None) => None,
                    (Some(bytes), Some(item_id)) => {
                        let digest = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                            SyncSqliteError::CorruptState(
                                "a late edit digest is not 32 bytes".into(),
                            )
                        })?;
                        Some((digest, item_id))
                    }
                    _ => {
                        return Err(SyncSqliteError::CorruptState(format!(
                            "rebootstrap quarantine {path}: a late edit digest and item id \
                             that do not go together"
                        )))
                    }
                };
                Ok::<_, SyncSqliteError>((path, late, claim))
            })
            .collect::<Result<_, _>>()?
    };
    let failed = |detail: String| {
        InstallError::Blocked(BlockedReason::PreservationFailed(PreservationFailure::Io { detail }))
    };
    // A late edit is saved as a permanent recovery item before the original leaves: its files
    // are durable in the item store, then one transaction registers the item and marks the
    // quarantine row `removing`. Only after that commit may the original be removed, and the
    // item outlives the rebootstrap's transient area.
    let preserve_late_edit = |path: &str,
                              symlink: bool,
                              size: u64,
                              digest: &[u8; 32],
                              symlink_target: &[u8],
                              meta: Option<LateEditMeta>|
     -> Result<(), InstallError> {
        let edit = LateEdit { path, symlink, size, sha256: *digest, symlink_target, meta };
        // The file is streamed from the root into the item store; a symlink's target is a
        // small byte string already in hand.
        let open = || -> Result<Box<dyn std::io::Read + '_>, String> {
            if symlink {
                Ok(Box::new(symlink_target))
            } else {
                ctx.root.open_file(path)
            }
        };
        let prepared = prepare_late_edit(
            conn,
            &ctx.preserve.items_root,
            ctx.preserve.sync_roots,
            group,
            &edit,
            &open,
            ctx.preserve.now_unix,
        )
        .map_err(|e| match e {
            LateEditError::Source(detail) => failed(detail),
            LateEditError::Store(e) => InstallError::Store(e),
        })?;
        let tx =
            rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
        prepared.register(&tx, group, recovery_id, ctx.preserve.now_unix)?;
        tx.execute(
            "UPDATE native_rebootstrap_quarantine \
             SET status = 'removing', late_sha256 = ?4, late_item_id = ?5 \
                 WHERE group_id = ?1 AND recovery_id = ?2 AND path = ?3",
            (group.as_str(), recovery_id, path, digest.as_slice(), prepared.item_id()),
        )?;
        tx.commit()?;
        Ok(())
    };
    // The original is moved aside under a fresh claim recorded first, so the moved object is
    // always owned by this row.
    let remove_original = |path: &str, observed: &Observed| -> Result<Removal, InstallError> {
        let claim = hex::encode(rand::random::<[u8; 8]>());
        conn.execute(
            "UPDATE native_rebootstrap_quarantine SET removal_claim = ?4 \
             WHERE group_id = ?1 AND recovery_id = ?2 AND path = ?3",
            (group.as_str(), recovery_id, path, claim.as_str()),
        )?;
        let removal = ctx.root.remove(path, observed, &claim).map_err(failed)?;
        // A retained object stays claimed: the row keeps naming where it is.
        if removal == Removal::Removed {
            conn.execute(
                "UPDATE native_rebootstrap_quarantine SET removal_claim = NULL \
                 WHERE group_id = ?1 AND recovery_id = ?2 AND path = ?3",
                (group.as_str(), recovery_id, path),
            )?;
        }
        Ok(removal)
    };
    // The status a completed removal is recorded as.
    let removed_status = |removal: Removal, removed: QuarantineStatus| match removal {
        Removal::Removed => removed,
        Removal::Retained => QuarantineStatus::Retained,
    };
    for (index, (path, recorded, claim)) in pending.iter().enumerate() {
        // An earlier attempt may have moved the original aside and not finished: it is given
        // back to its path, so it is observed again (and its newer bytes saved) like any file.
        if let Some(claim) = claim {
            ctx.root.release_claim(path, claim).map_err(failed)?;
        }
        let versions: Vec<&crate::native_rebootstrap_recovery::ManifestVersion> =
            quarantined_versions(manifest, path)
                .into_iter()
                .filter_map(|v| manifest.versions.iter().find(|m| m.version == v))
                .collect();
        // Every copy the original could be is read back before anything is removed.
        for version in versions.iter().filter(|v| v.has_bytes) {
            let matches = area
                .version_matches(&version.version, &version.sha256, version.size)
                .map_err(|e| blocked_by(area_failure(e)))?;
            if !matches {
                return Err(blocked_by(BlockedReason::PreservationFailed(
                    PreservationFailure::CopyVerification { item: format!("versions/{path}") },
                )));
            }
        }
        let observed = ctx.root.observe(path).map_err(failed)?;
        let status = match &observed {
            Observed::Absent => match recorded {
                // The removal happened and its record did not.
                Some((digest, item_id)) => {
                    require_late_edit_item(conn, ctx, group, path, item_id)?;
                    QuarantineStatus::RemovedLateEdit { sha256: *digest }
                }
                None => QuarantineStatus::AlreadyAbsent,
            },
            Observed::Directory | Observed::Other => QuarantineStatus::LeftInPlace,
            Observed::File { size, sha256: digest, mtime_unix_nanos, unix_mode, xattrs } => {
                // The preserved version this file may be an unchanged copy of: same bytes, and
                // every metadata field (mtime, and the others where the platform can observe them) the same as that version's.
                // The fields it cannot observe are inherited from that version, as ordinary
                // capture inherits them from the live predecessor.
                let mut predecessor = None;
                for version in versions.iter().filter(|v| v.has_bytes && v.sha256 == *digest) {
                    let record = area
                        .read_record(&version.version)
                        .map_err(|e| blocked_by(area_failure(e)))?;
                    // The nanosecond equality ordinary capture applies
                    // (`metadata_mtime_matches`): a touch is a distinct version.
                    let same_mtime = *mtime_unix_nanos == record.meta.mtime_unix_nanos;
                    let same_mode = unix_mode.is_none() || *unix_mode == record.meta.unix_mode;
                    let same_xattrs =
                        xattrs.as_ref().is_none_or(|observed| *observed == record.meta.xattrs);
                    if same_mtime && same_mode && same_xattrs {
                        predecessor = Some(record);
                        break;
                    }
                }
                if recorded.is_none() && predecessor.is_some() {
                    removed_status(remove_original(path, &observed)?, QuarantineStatus::Removed)
                } else {
                    // An edit nobody has captured: it becomes a recovery item,
                    // registered, before the original leaves.
                    // The predecessor the unobservable fields come from: the version of the
                    // same bytes if there is one, else the path's first preserved version.
                    let inherited = versions
                        .iter()
                        .filter(|v| v.sha256 == *digest)
                        .chain(versions.iter())
                        .find_map(|v| area.read_record(&v.version).ok());
                    let meta = LateEditMeta {
                        mtime_unix_nanos: *mtime_unix_nanos,
                        unix_mode: unix_mode
                            .or_else(|| inherited.as_ref().and_then(|r| r.meta.unix_mode)),
                        xattrs: xattrs.clone().unwrap_or_else(|| {
                            inherited.map(|r| r.meta.xattrs).unwrap_or_default()
                        }),
                    };
                    preserve_late_edit(path, false, *size, digest, &[], Some(meta))?;
                    removed_status(
                        remove_original(path, &observed)?,
                        QuarantineStatus::RemovedLateEdit { sha256: *digest },
                    )
                }
            }
            Observed::Symlink { target } => {
                if recorded.is_none()
                    && versions
                        .iter()
                        .any(|v| v.symlink_target.as_deref() == Some(target.as_slice()))
                {
                    removed_status(remove_original(path, &observed)?, QuarantineStatus::Removed)
                } else {
                    let digest = sha256(target);
                    preserve_late_edit(path, true, target.len() as u64, &digest, target, None)?;
                    removed_status(
                        remove_original(path, &observed)?,
                        QuarantineStatus::RemovedLateEdit { sha256: digest },
                    )
                }
            }
        };
        hook(InstallPoint::AfterOriginalRemoved(index)).map_err(|_| InstallError::Crashed)?;
        let (text, late) = status_text(&status);
        conn.execute(
            "UPDATE native_rebootstrap_quarantine SET status = ?4, late_sha256 = ?5, \
             removal_claim = CASE WHEN ?4 = 'retained' THEN removal_claim ELSE NULL END \
             WHERE group_id = ?1 AND recovery_id = ?2 AND path = ?3",
            (group.as_str(), recovery_id, path, text, late),
        )?;
        record_retained_digest(conn, group, recovery_id, path, &status, &observed)?;
        hook(InstallPoint::AfterQuarantineItem(index)).map_err(|_| InstallError::Crashed)?;
    }
    Ok(())
}

/// Records the digest of the object a `retained` row keeps, as verified when it was kept.
fn record_retained_digest(
    conn: &Connection,
    group: &FolderGroupId,
    recovery_id: &str,
    path: &str,
    status: &QuarantineStatus,
    observed: &Observed,
) -> Result<(), SyncSqliteError> {
    if let (QuarantineStatus::Retained, Some(fingerprint)) =
        (status, crate::native_rebootstrap_retained::kept_fingerprint(observed))
    {
        conn.execute(
            "INSERT OR REPLACE INTO native_rebootstrap_retained_digest \
             (group_id, recovery_id, path, fingerprint) VALUES (?1, ?2, ?3, ?4)",
            (group.as_str(), recovery_id, path, fingerprint.as_slice()),
        )?;
    }
    Ok(())
}

/// The recovery item the quarantine row recorded, by exact id, is registered for `path` and
/// reads back. A different late edit of the same path and bytes does not confirm it. The
/// removal happened and its status did not; the item, not any transient file, is what keeps
/// the edit.
fn require_late_edit_item(
    conn: &Connection,
    ctx: &InstallContext<'_>,
    group: &FolderGroupId,
    path: &str,
    item_id: &str,
) -> Result<(), InstallError> {
    if late_edit_item_is_durable(conn, &ctx.preserve.items_root, group, path, item_id)? {
        return Ok(());
    }
    Err(blocked_by(BlockedReason::PreservationFailed(PreservationFailure::CopyVerification {
        item: "late edit".into(),
    })))
}

// --- the transaction ---------------------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn install_in_tx(
    conn: &Connection,
    ctx: &InstallContext<'_>,
    group: &FolderGroupId,
    area: &RecoveryArea,
    recovery_id: &str,
    manifest: &Manifest,
    manifest_sha256: &[u8; 32],
    hook: &mut dyn FnMut(InstallPoint) -> Result<(), Crash>,
) -> Result<Installed, InstallError> {
    // The target is read from the stored bytes here, as a restart would.
    let verified = verify_target_in_area(area, group).map_err(|e| {
        InstallError::Blocked(BlockedReason::PreservationFailed(
            PreservationFailure::TargetNotVerifiable { detail: e.to_string() },
        ))
    })?;
    let tx = rusqlite::Transaction::new_unchecked(conn, rusqlite::TransactionBehavior::Immediate)?;
    let status = rebootstrap_status(&tx, group)?
        .ok_or_else(|| InstallError::NotInstallable("no rebootstrap".into()))?;
    if status.state != RebootstrapState::Quarantining || status.recovery_id != recovery_id {
        return Err(InstallError::NotInstallable(format!("it is {:?}", status.state)));
    }
    let unfinished: i64 = tx.query_row(
        "SELECT COUNT(*) FROM native_rebootstrap_quarantine \
         WHERE group_id = ?1 AND recovery_id = ?2 AND status IN ('pending', 'removing')",
        (group.as_str(), recovery_id),
        |row| row.get(0),
    )?;
    if unfinished > 0 {
        return Err(InstallError::NotInstallable("an original is not yet quarantined".into()));
    }
    let marker = InstallAuthority::issue(&tx, group, recovery_id)?;
    let installed = crate::native_checkpoint_install::install_checkpoint(
        &tx,
        group,
        verified,
        InstallKind::Rebootstrap(RebootstrapBarrier {
            authority: &marker,
            manifest,
            manifest_sha256,
            items_root: &ctx.preserve.items_root,
            closure_key: ctx.closure_key,
        }),
        &mut |step| hook(InstallPoint::InTransaction(step)),
    )
    .map_err(InstallError::from)?;
    set_state(&tx, group, "catching_up", ctx.preserve.now_unix)?;
    hook(InstallPoint::InTransaction(InstallStep::Recorded)).map_err(|_| InstallError::Crashed)?;
    tx.commit()?;
    hook(InstallPoint::AfterCommit).map_err(|_| InstallError::Crashed)?;

    Ok(Installed {
        recovery_id: recovery_id.to_owned(),
        new_author: installed.new_author.ok_or_else(|| {
            InstallError::NotInstallable("a rebootstrap install rotates this device".into())
        })?,
        old_authors: manifest.old_authors.clone(),
    })
}

fn installed_summary(
    conn: &Connection,
    recovery_id: &str,
    manifest: &Manifest,
) -> Result<Installed, InstallError> {
    let record = crate::author_incarnation::incarnation_record(conn)?
        .ok_or_else(|| InstallError::NotInstallable("no incarnation".into()))?;
    Ok(Installed {
        recovery_id: recovery_id.to_owned(),
        new_author: record.author,
        old_authors: manifest.old_authors.clone(),
    })
}
