//! Reconciles the disk under held paths: removes stale bytes,
//! preserves what it cannot account for, leaves the path empty for the row's
//! projection, and releases the hold.
//!
//! A path is held when its object on disk belongs to no row this device
//! placed (a local edit native could not author there). While
//! a path is held nothing captures it and nothing projects it; this pass is
//! its one writer. See `yadorilink_sync_sqlite::held_path` for
//! the hold itself.
//!
//! Each step is idempotent against the state a crash can leave between
//! any two of them, because every decision is made from what is on disk
//! now:
//!
//! - stale bytes are first renamed to a reserved preimage name beside the
//!   path, and only removed once the object renamed is confirmed to be
//!   them; a preimage found at the start of a pass is settled the same way
//!   before anything else;
//! - after removing stale bytes or moving divergent ones aside, the path
//!   is empty, which reads as [`DiskVerdict::Absent`] on the next pass;
//! - the hold is released last, in one transaction, so a crash before it
//!   leaves the path held and the next pass finishes it.
//!
//! Nothing locks a user out of a held path, so no step acts on what an
//! earlier one saw there: the object a removal takes is re-examined after
//! it is taken, and a path is only released while it is still empty. A user
//! write that lands in between is preserved as a conflict copy, or left where
//! it is for the next pass.
//!
//! Directories follow the namespace the rows describe (a file whose name a
//! live row below needs has already been moved to its copy name, so the
//! rows are the namespace's shape):
//!
//! - a Directory row is placed through the Directory lane: a
//!   real directory with the row's mode, and its proof;
//! - a path only live rows below need becomes a structural directory,
//!   created through the recording `mkdir` helper, or adopted as
//!   structural when it is the held row's explicit directory;
//! - a directory nothing needs any more is removed only when this device
//!   made it (the held row's directory, or a structural one) and it is
//!   empty, with one non-recursive `rmdir`; one that still holds content
//!   this device does not replicate is kept and recorded as retained (D4),
//!   and a directory the user made is never touched. Structural ancestors
//!   of a dropped path go with it the same way.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use yadorilink_fs_platform::fs_identity::{FileIdentity, ObjectKind};
use yadorilink_fs_platform::reserved_namespace::{artefact_component_name, ArtefactKind};
use yadorilink_local_storage::{
    apply_unix_mode, create_dir_all_never_through_a_symlink, create_explicit_directory,
    intent_target_hash, remove_empty_dir_in, verify_write_target_within_root,
    EmptyDirectoryRemoval, ExplicitDirectoryCreation, StructuralDirectoryLedger,
};
use yadorilink_replica_domain::conflict::conflict_copy_path;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::session_state::HeldPath;
use yadorilink_root_authority::root_commit::RootCommitPermit;

use crate::materialization_execution::{
    GroupStructuralLedger, GroupTempLedger, MaterializationExecutionError,
    MaterializationExecutionPort, RepairRowSnapshot,
};

/// What one reconciliation pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HeldPathReconcileReport {
    /// Held paths whose disk now agrees with the installed row, released.
    pub released: Vec<String>,
    /// `(held path, conflict-copy path)`: an object the replaced row
    /// cannot account for, moved aside rather than discarded or authored.
    pub preserved: Vec<(String, String)>,
    /// Held paths whose reconciliation failed on this path alone; they stay
    /// held for the next pass.
    pub failed: Vec<String>,
    /// Held paths an install held again while this pass reconciled them for
    /// the row it had read; they stay held for the next pass, which reads
    /// the row now installed.
    pub renewed: Vec<String>,
}

/// What is on disk under a held path, measured against the row the index
/// holds there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiskVerdict {
    Absent,
    /// A directory. Not this path's to move: its entries are other paths.
    Directory,
    /// Anything else: an edit no row accounts for.
    Divergent,
}

/// What the rows need at a held path: the namespace's node
/// there. Read from the index, because the rows are what the disk has to
/// end up matching -- they already have the namespace's shape (a file whose name a live descendant needs sits at
/// its copy name; see `yadorilink_sync_sqlite::held_path`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstalledNode {
    /// No live row, and nothing live below: nothing is needed here.
    Absent,
    /// A live File or Symlink row with nothing live below it.
    Entry,
    /// A live Directory row: a directory that is itself an entry.
    ExplicitDirectory,
    /// Live rows below and no Directory row: a directory that exists only
    /// to hold them.
    StructuralDirectory,
}

fn installed_node(row: &RepairRowSnapshot, has_live_descendant: bool) -> InstalledNode {
    let live_kind = row
        .file
        .as_ref()
        .filter(|record| !record.deleted)
        .map(|_| row.record_kind.unwrap_or_default());
    match live_kind {
        Some(RecordKind::Directory) => InstalledNode::ExplicitDirectory,
        // A File or Symlink row with live rows below is one the install
        // should have relocated; the directory wins, as in the projection,
        // and the row is left to the projection its release schedules.
        _ if has_live_descendant => InstalledNode::StructuralDirectory,
        Some(_) => InstalledNode::Entry,
        None => InstalledNode::Absent,
    }
}

/// Reconciles every held path of `group_id` under `root`. A path whose lock
/// stays busy through the pass's short retries is left for the next pass.
///
/// In namespace order: first the paths nothing is needed at any more,
/// deepest first, so a dropped directory's dropped contents are gone before
/// the directory is looked at; then the rest, shallowest first, so a
/// directory is in place before anything is placed inside it.
pub fn reconcile_held_paths(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    permit: &RootCommitPermit,
) -> Result<HeldPathReconcileReport, MaterializationExecutionError> {
    let mut report = HeldPathReconcileReport::default();
    let holds = state.list_held_paths(group_id)?;
    let held: HashSet<String> = holds.iter().map(|hold| hold.path.clone()).collect();
    // Read without the path locks, for the order only: every decision is
    // made again from what is read under the lock.
    let mut removals = Vec::new();
    let mut rest = Vec::new();
    for hold in holds {
        let row = state.repair_row_snapshot(group_id, &hold.path)?;
        let descendant = state.index_has_live_descendant(group_id, &hold.path)?;
        if installed_node(&row, descendant) == InstalledNode::Absent {
            removals.push(hold);
        } else {
            rest.push(hold);
        }
    }
    // The holds come in path order, where a path sorts before everything
    // below it; reversed, everything below comes first.
    removals.reverse();
    let mut pending: Vec<HeldPath> = removals.into_iter().chain(rest).collect();
    // A path whose lock is busy is tried again a few times within this
    // pass rather than left for the next one: its holder is typically
    // local capture passing over the held path (or the capture that just
    // held it, still releasing its lock), and what wakes this pass may
    // already have been spent on the attempt that found it busy. A path
    // still busy after the last round stays held for the next pass.
    for round in 0..=BUSY_RETRY_ROUNDS {
        if round > 0 {
            std::thread::sleep(BUSY_RETRY_DELAY);
        }
        let mut busy = Vec::new();
        for hold in pending {
            let path_lock = state.path_lock(group_id, &hold.path);
            let Ok(_path_guard) = path_lock.try_lock() else {
                busy.push(hold);
                continue;
            };
            match reconcile_one(state, root, group_id, &hold, &held, permit, &mut report) {
                Ok(()) => {}
                Err(e) if e.is_path_local() => {
                    tracing::warn!(
                        group_id,
                        path = %hold.path,
                        error = %e,
                        "could not reconcile a held path; it stays held"
                    );
                    report.failed.push(hold.path.clone());
                }
                Err(e) => return Err(e),
            }
        }
        if busy.is_empty() {
            break;
        }
        pending = busy;
    }
    Ok(report)
}

/// How many more times one pass tries a held path whose lock was busy, and
/// how long it waits before each retry: at most about a second in all.
const BUSY_RETRY_ROUNDS: u32 = 20;
const BUSY_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

fn reconcile_one(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    hold: &HeldPath,
    held: &HashSet<String>,
    permit: &RootCommitPermit,
    report: &mut HeldPathReconcileReport,
) -> Result<(), MaterializationExecutionError> {
    let out_path = root.join(&hold.path);
    let ledger = GroupStructuralLedger::new(state, group_id);
    let preimage = preimage_path(&out_path, &hold.path)?;
    let installed = state.repair_row_snapshot(group_id, &hold.path)?;
    let node = installed_node(&installed, state.index_has_live_descendant(group_id, &hold.path)?);
    if node == InstalledNode::Absent && !object_at(&out_path)? && !object_at(&preimage)? {
        // Dropped, and nothing of it is on disk: nothing to take and
        // nothing to place, so no parent to create for either. A directory
        // record left here names one a crashed pass removed.
        state.forget_removed_directory(group_id, &hold.path)?;
        return release(state, root, group_id, hold, held, node, None, report);
    }
    verify_write_target_within_root(&out_path, root, &ledger)?;
    if object_at(&preimage)? {
        // A previous pass took the object aside and crashed before it
        // settled it.
        state.begin_held_path_disk_write(group_id, &hold.path)?;
        settle_taken_object(root, &ledger, group_id, hold, &preimage, report)?;
    }
    // The explicit directory this pass itself creates, if it creates one.
    let mut made_directory = None;
    let verdict = classify(&out_path)?;
    reached(ReconcileStepForTest::Classified, &out_path);
    if verdict == DiskVerdict::Absent {
        // Nothing is at the path. A structural or retained record for it
        // names a directory a pass removed and crashed before forgetting;
        // left, it would outlive the directory under whatever is placed
        // here next. This pass holds the path's lock, and a held path has
        // no other writer.
        state.forget_removed_directory(group_id, &hold.path)?;
    }
    if verdict == DiskVerdict::Divergent {
        state.begin_held_path_disk_write(group_id, &hold.path)?;
    }
    match verdict {
        DiskVerdict::Absent | DiskVerdict::Directory => {}
        DiskVerdict::Divergent => {
            preserve(root, &ledger, group_id, hold, &out_path, report)?;
            reached(ReconcileStepForTest::PathEmptied, &out_path);
        }
    }

    match node {
        InstalledNode::Entry => {
            // A directory where an entry is installed goes only when this
            // device made it and it is empty. While a held path below it
            // still waits for its own reconciliation, the path stays held
            // for the pass after that one. Anything else is kept, with
            // everything in it, and the entry goes to its copy name beside
            // it, as the live projection places it.
            if verdict == DiskVerdict::Directory {
                if remove_directory_at_held_path(state, root, group_id, hold, &out_path, false)? {
                    state.begin_held_path_disk_write(group_id, &hold.path)?;
                } else if has_held_descendant(state, group_id, &hold.path)? {
                    return Ok(());
                } else {
                    keep_directory_and_hold_entry(group_id, hold);
                    return Ok(());
                }
            }
            if installed_regular_file(&installed).is_some() {
                // A `Remote` row has no object in the user tree: nothing is
                // placed. The path must still be empty when the hold is
                // released, and nothing locks a user out of it, so a write
                // that landed since the path was emptied fails this path,
                // which stays held for the next pass to preserve it.
                reached(ReconcileStepForTest::ReleasingEntry, &out_path);
                if object_at(&out_path)? {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "{} appeared while the hold was being reconciled",
                            out_path.display()
                        ),
                    )
                    .into());
                }
            }
        }
        InstalledNode::ExplicitDirectory => {
            made_directory = place_installed_directory(
                state, root, group_id, hold, &out_path, &installed, permit,
            )?;
        }
        InstalledNode::StructuralDirectory => {
            settle_structural_directory(root, &out_path, &ledger)?;
        }
        InstalledNode::Absent => {
            if verdict == DiskVerdict::Directory {
                // Not empty only because a held path below has not been
                // reconciled yet (its lock was busy, or it failed): that is
                // no untracked content, and the path stays held until the
                // pass that finds it gone.
                let waits_for_descendant = has_held_descendant(state, group_id, &hold.path)?;
                if !remove_directory_at_held_path(
                    state,
                    root,
                    group_id,
                    hold,
                    &out_path,
                    !waits_for_descendant,
                )? && waits_for_descendant
                {
                    return Ok(());
                }
            }
        }
    }
    release(state, root, group_id, hold, held, node, made_directory, report)
}

/// Whether a path strictly below `path` is still held: installed or
/// dropped content under it that its own reconciliation has not settled.
fn has_held_descendant(
    state: &dyn MaterializationExecutionPort,
    group_id: &str,
    path: &str,
) -> Result<bool, MaterializationExecutionError> {
    let below = format!("{path}/");
    Ok(state.list_held_paths(group_id)?.iter().any(|h| h.path.starts_with(&below)))
}

/// A directory this pass may not remove -- the user's, or one holding
/// content this device does not replicate -- holds the name the installed
/// entry at `out_path` needs. Nothing is moved and nothing is released: the
/// path stays held, the directory stays, and the obstacle is the user's to
/// resolve. A device-local obstacle never becomes a replicated or derived
/// copy name.
fn keep_directory_and_hold_entry(group_id: &str, hold: &HeldPath) {
    tracing::info!(
        group_id,
        path = %hold.path,
        "a directory this device may not remove holds the name an installed entry needs; the \
         path stays held"
    );
}

/// Places the installed explicit Directory row at `out_path` through the
/// Directory lane: the directory itself (its missing ancestors structural,
/// recorded by the `mkdir` helper), its mode, and the proof naming the
/// installed version, journaled like any other rebuild of a single object.
/// A directory already there is kept, with whatever is in it (D4), and
/// becomes the entry's. Returns the identity of a directory this call
/// created, which a renewed hold withdraws while it is still empty.
fn place_installed_directory(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    hold: &HeldPath,
    out_path: &Path,
    installed: &RepairRowSnapshot,
    permit: &RootCommitPermit,
) -> Result<Option<FileIdentity>, MaterializationExecutionError> {
    let Some(version) = installed.current_version else {
        tracing::warn!(
            group_id,
            path = %hold.path,
            "an installed directory row names no version; nothing to prove it against"
        );
        return Ok(None);
    };
    let canonical_root = std::fs::canonicalize(root)?;
    let (mutation_generation, intent_guard) = state.open_repair_object_rebuild(
        group_id,
        &hold.path,
        RecordKind::Directory,
        &intent_target_hash(&[]),
        permit,
    )?;
    let created = create_explicit_directory(
        out_path,
        &canonical_root,
        &GroupStructuralLedger::new(state, group_id),
    )?;
    apply_unix_mode(out_path, installed.unix_mode)?;
    reached(ReconcileStepForTest::DirectoryPlaced, out_path);
    // The settle below clears the intent; dropping the guard uncleared is
    // inert.
    drop(intent_guard);
    let made = match created {
        ExplicitDirectoryCreation::Created => FileIdentity::observe_path(out_path).ok(),
        ExplicitDirectoryCreation::AlreadyDirectory => None,
    };
    let published = state.settle_repair_object_rebuild(
        group_id,
        &hold.path,
        RecordKind::Directory,
        out_path,
        version,
        installed.materialization_state,
        mutation_generation,
        permit,
    )?;
    if !published {
        tracing::info!(
            group_id,
            path = %hold.path,
            "the installed directory row moved before its proof was committed; the intent \
             stays open for the next pass"
        );
    }
    Ok(made)
}

/// Makes `out_path` the directory the installed rows below it need, when it
/// has no Directory row of its own: creates it (recorded as structural)
/// when nothing is there, and keeps a directory that is.
fn settle_structural_directory(
    root: &Path,
    out_path: &Path,
    ledger: &dyn StructuralDirectoryLedger,
) -> Result<(), MaterializationExecutionError> {
    match std::fs::symlink_metadata(out_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let canonical_root = std::fs::canonicalize(root)?;
            create_dir_all_never_through_a_symlink(out_path, &canonical_root, out_path, ledger)?;
            reached(ReconcileStepForTest::StructuralDirectoryMade, out_path);
            Ok(())
        }
        Err(e) => Err(e.into()),
        Ok(metadata) if metadata.is_dir() => Ok(()),
        // Appeared since the path was emptied: the next pass preserves it.
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{} is occupied by something that is not a directory", out_path.display()),
        )
        .into()),
    }
}

/// Removes the directory at a held path when this device made it (a
/// structural directory) and it is empty: one non-recursive `rmdir`, after a fence bump. `true` when it is
/// gone. A directory the user made is kept as it is. One this device made
/// that still holds something is kept too (D4: nothing untracked is ever
/// deleted); with `retain` it is recorded as retained, removable once it is
/// empty.
fn remove_directory_at_held_path(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    hold: &HeldPath,
    out_path: &Path,
    retain: bool,
) -> Result<bool, MaterializationExecutionError> {
    let Ok(identity) = FileIdentity::observe_path(out_path) else { return Ok(false) };
    if identity.object_kind != ObjectKind::Directory {
        return Ok(false);
    }
    if !state.is_structural_directory(group_id, &hold.path, root, &identity)? {
        return Ok(false);
    }
    state.begin_held_path_disk_write(group_id, &hold.path)?;
    match remove_empty_dir_in(out_path, &GroupTempLedger::new(state, group_id))? {
        EmptyDirectoryRemoval::Removed | EmptyDirectoryRemoval::Absent => {
            reached(ReconcileStepForTest::DirectoryRemoved, out_path);
            state.forget_removed_directory(group_id, &hold.path)?;
            Ok(true)
        }
        EmptyDirectoryRemoval::NotEmpty | EmptyDirectoryRemoval::Stranded(_) => {
            if retain {
                tracing::info!(
                    group_id,
                    path = %hold.path,
                    "a held directory no row needs any more still holds content this device does \
                     not replicate; it is kept"
                );
                state.retain_directory_with_untracked_content(
                    group_id,
                    &hold.path,
                    Some(&identity),
                )?;
            }
            Ok(false)
        }
        EmptyDirectoryRemoval::NotADirectory => Ok(false),
    }
}

/// Releases the hold at the generation this pass read. When an install
/// renewed it meanwhile, what this pass made for a row no longer installed is
/// withdrawn instead and the hold stays for the next pass.
#[allow(clippy::too_many_arguments)]
fn release(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    hold: &HeldPath,
    held: &HashSet<String>,
    node: InstalledNode,
    made_directory: Option<FileIdentity>,
    report: &mut HeldPathReconcileReport,
) -> Result<(), MaterializationExecutionError> {
    let out_path = root.join(&hold.path);
    if node == InstalledNode::Absent {
        // The structural ancestors go before the hold does: the hold is
        // what brings a dropped path back to this pass, and nothing else
        // would ever look at an ancestor left behind by a crash here or by
        // a busy ancestor lock. While one is busy the hold stays, and the
        // next pass tries again.
        reached(ReconcileStepForTest::PruningAncestors, &out_path);
        if !prune_structural_ancestors(state, root, group_id, &hold.path, held)? {
            return Ok(());
        }
    }
    if !state.release_held_path(group_id, &hold.path, hold.generation)? {
        // An install held the path again after this pass read its row, so
        // what this pass made was for a row that is no longer installed. The
        // hold stays for the next pass. The directory this pass created is
        // withdrawn while it is still untouched, since the path lock does
        // not keep the install from replacing the row: left in place, it
        // would be read as the newer row's projection or moved aside as a
        // conflict copy of nothing.
        if let Some(identity) = made_directory {
            withdraw_own_directory(state, group_id, &out_path, &identity)?;
        }
        report.renewed.push(hold.path.clone());
        return Ok(());
    }
    report.released.push(hold.path.clone());
    Ok(())
}

/// Removes the directory this pass created at `out_path` while it is still
/// exactly that object and empty. Anything else is left for the next pass.
fn withdraw_own_directory(
    state: &dyn MaterializationExecutionPort,
    group_id: &str,
    out_path: &Path,
    identity: &FileIdentity,
) -> Result<(), MaterializationExecutionError> {
    let Ok(observed) = FileIdentity::observe_path(out_path) else { return Ok(()) };
    if observed.volume_identity == identity.volume_identity
        && observed.object_id == identity.object_id
    {
        remove_empty_dir_in(out_path, &GroupTempLedger::new(state, group_id))?;
    }
    Ok(())
}

/// After a dropped path is gone, removes each ancestor directory this
/// device created only for descendants that no installed row needs any
/// more: nearest first, each with one non-recursive `rmdir` while it is
/// empty, stopping at the first that stays. An ancestor that is itself held
/// is left to its own reconciliation, which comes after this one.
///
/// `false` only when an ancestor that would be removed has its lock busy:
/// the one outcome a later attempt can change. Every other stop (a live
/// row, a directory this device did not make, one that is not empty) is
/// settled, and `true`.
fn prune_structural_ancestors(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    path: &str,
    held: &HashSet<String>,
) -> Result<bool, MaterializationExecutionError> {
    let ancestors = std::iter::successors(path.rsplit_once('/').map(|(parent, _)| parent), |p| {
        p.rsplit_once('/').map(|(parent, _)| parent)
    });
    for ancestor in ancestors {
        if held.contains(ancestor) {
            return Ok(true);
        }
        let row = state.repair_row_snapshot(group_id, ancestor)?;
        if row.file.as_ref().is_some_and(|record| !record.deleted)
            || state.index_has_live_descendant(group_id, ancestor)?
        {
            return Ok(true);
        }
        let dir = root.join(ancestor);
        if !object_at(&dir)? {
            // Already removed, by a pass that crashed before it forgot the
            // record (see below): nothing is there for the record to name.
            // Forgotten under the ancestor's lock, and the ancestors above
            // are still this pass's to prune -- stopping here would leave
            // them for good, since the hold that brings this path back is
            // released next.
            let path_lock = state.path_lock(group_id, ancestor);
            let Ok(_guard) = path_lock.try_lock() else { return Ok(false) };
            if !object_at(&dir)? {
                state.forget_removed_directory(group_id, ancestor)?;
            }
            continue;
        }
        let Ok(identity) = FileIdentity::observe_path(&dir) else { return Ok(true) };
        if identity.object_kind != ObjectKind::Directory
            || !state.is_structural_directory(group_id, ancestor, root, &identity)?
        {
            return Ok(true);
        }
        let path_lock = state.path_lock(group_id, ancestor);
        let Ok(_guard) = path_lock.try_lock() else { return Ok(false) };
        state.begin_held_path_disk_write(group_id, ancestor)?;
        match remove_empty_dir_in(&dir, &GroupTempLedger::new(state, group_id))? {
            EmptyDirectoryRemoval::Removed | EmptyDirectoryRemoval::Absent => {
                reached(ReconcileStepForTest::AncestorRemoved, &dir);
                state.forget_removed_directory(group_id, ancestor)?;
            }
            EmptyDirectoryRemoval::NotEmpty
            | EmptyDirectoryRemoval::NotADirectory
            | EmptyDirectoryRemoval::Stranded(_) => {
                return Ok(true);
            }
        }
    }
    Ok(true)
}

/// Whether anything is at `path`, by name. A parent that is not a
/// directory (`ENOTDIR`) means nothing can be.
fn object_at(path: &Path) -> Result<bool, MaterializationExecutionError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(false)
        }
        Err(e) => Err(e.into()),
    }
}

/// The installed row, when it is a live regular file: its content is
/// materialized by the projection the release schedules, like a live
/// symlink's; a deleted or absent row needs nothing on disk.
fn installed_regular_file(
    row: &RepairRowSnapshot,
) -> Option<&yadorilink_replica_domain::file::FileRecord> {
    let record = row.file.as_ref()?;
    (!record.deleted && row.record_kind.unwrap_or_default() == RecordKind::File).then_some(record)
}

fn classify(out_path: &Path) -> Result<DiskVerdict, MaterializationExecutionError> {
    let metadata = match std::fs::symlink_metadata(out_path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(DiskVerdict::Absent),
        Err(e) => return Err(e.into()),
    };
    let file_type = metadata.file_type();
    if file_type.is_dir() {
        return Ok(DiskVerdict::Directory);
    }
    Ok(DiskVerdict::Divergent)
}

/// Where a held path's object is taken while it is examined: a reserved
/// name beside it, which nothing captures or sweeps, fixed per path so a
/// pass that crashed holding one is finished by the next.
fn preimage_path(
    out_path: &Path,
    rel_path: &str,
) -> Result<PathBuf, MaterializationExecutionError> {
    let id = hex::encode(Sha256::digest(rel_path.as_bytes()));
    let name = artefact_component_name(ArtefactKind::Preimage, &id)
        .map_err(|e| MaterializationExecutionError::CorruptState(e.to_string()))?;
    Ok(out_path.with_file_name(name))
}

/// Preserves the object taken to `taken`: nothing places an object a held
/// path could account for, so whatever was taken is an edit.
fn settle_taken_object(
    root: &Path,
    ledger: &dyn StructuralDirectoryLedger,
    group_id: &str,
    hold: &HeldPath,
    taken: &Path,
    report: &mut HeldPathReconcileReport,
) -> Result<(), MaterializationExecutionError> {
    preserve(root, ledger, group_id, hold, taken, report)
}

/// Moves the object at `src` aside as a conflict copy of the held path.
fn preserve(
    root: &Path,
    ledger: &dyn StructuralDirectoryLedger,
    group_id: &str,
    hold: &HeldPath,
    src: &Path,
    report: &mut HeldPathReconcileReport,
) -> Result<(), MaterializationExecutionError> {
    let preserved_as = move_aside(root, &hold.path, src, ledger, "local-preserved")?;
    tracing::warn!(
        group_id,
        path = %hold.path,
        preserved_as = %preserved_as,
        "a held path held something its row's version cannot account for; moved it aside \
         as a conflict copy rather than authoring it over the row's version"
    );
    report.preserved.push((hold.path.clone(), preserved_as));
    Ok(())
}

/// Moves the object at `src` to a conflict-copy sibling of `rel_path` and
/// returns the sibling's link-relative path. Named like any other conflict
/// copy, so local capture captures it as a new file and every peer gets it.
/// The disambiguator digests the object's own bytes, so two different
/// objects moved aside from one path get different names however alike
/// their size and timestamps are, and the move never replaces anything
/// already under the name it picks: an occupied name moves on to the next.
/// `origin` is the device component of the conflict-copy name, naming which
/// recovery moved the object.
pub(crate) fn move_aside(
    root: &Path,
    rel_path: &str,
    src: &Path,
    ledger: &dyn StructuralDirectoryLedger,
    origin: &str,
) -> Result<String, MaterializationExecutionError> {
    /// Far more than distinct objects at one path ever need; reaching it
    /// means something keeps occupying the names, and the path stays held.
    const MAX_NAME_ATTEMPTS: u32 = 64;
    let metadata = std::fs::symlink_metadata(src)?;
    let mtime_unix_nanos = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    let content = object_digest(src, &metadata)?;
    for attempt in 0..MAX_NAME_ATTEMPTS {
        let disambiguator = if attempt == 0 {
            content
        } else {
            Sha256::new().chain_update(content).chain_update(attempt.to_le_bytes()).finalize()
        };
        let preserved_as = conflict_copy_path(rel_path, mtime_unix_nanos, origin, &disambiguator);
        let dst = root.join(&preserved_as);
        verify_write_target_within_root(&dst, root, ledger)?;
        match yadorilink_local_storage::move_no_replace_durably(src, &dst) {
            Ok(()) => {
                // The conflict copy is the object's only name now, and the move
                // that gave it that name is durable before anyone treats the
                // object as recovered.
                crate::materialization_eviction::trace_step("synced");
                return Ok(preserved_as);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("every conflict-copy name for {rel_path} tried is already taken"),
    )
    .into())
}

/// A digest of what the object at `path` holds: a regular file's bytes, a
/// symlink's target, and for anything else (which has no content to read
/// without side effects) its identity on disk.
fn object_digest(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<sha2::digest::Output<Sha256>, MaterializationExecutionError> {
    let mut hasher = Sha256::new();
    let file_type = metadata.file_type();
    if file_type.is_file() {
        hasher.update(b"file");
        let mut file = std::fs::File::open(path)?;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = std::io::Read::read(&mut file, &mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
    } else if file_type.is_symlink() {
        hasher.update(b"symlink");
        let target = std::fs::read_link(path)?;
        hasher.update(yadorilink_fs_platform::fs_identity::target_to_bytes(&target));
    } else {
        hasher.update(b"other");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            hasher.update(metadata.dev().to_le_bytes());
            hasher.update(metadata.ino().to_le_bytes());
        }
    }
    Ok(hasher.finalize())
}

/// A point inside one held path's reconciliation at which a test can act
/// on the disk the way a concurrent user would, or stop the pass the way a
/// crash would (by panicking in the hook). Nothing locks a user out of a
/// held path, so every step after one of these must hold up against
/// whatever such a write left there; and every step is a boundary a crash
/// can fall on, so the next pass must finish from what any of them left.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileStepForTest {
    /// The disk has been classified; nothing on it has been changed yet.
    Classified,
    /// An installed entry's path is empty and about to be checked once more
    /// before its hold is released.
    ReleasingEntry,
    /// The installed explicit directory is on disk with its mode; its proof
    /// is not committed yet.
    DirectoryPlaced,
    /// A dropped path is gone from disk; its structural ancestors are
    /// about to be pruned.
    PruningAncestors,
    /// The object at the path was taken to its preimage name; it is not
    /// settled (removed or preserved) yet.
    /// What the replaced row left at the path is removed or moved aside;
    /// nothing is placed yet.
    PathEmptied,
    /// A structural directory the installed rows below need is created and
    /// recorded; the hold is not released yet.
    StructuralDirectoryMade,
    /// A directory the install dropped (or one standing where an entry is
    /// installed) is removed from disk; its structural record is not
    /// forgotten yet. The path given is the directory's.
    DirectoryRemoved,
    /// A structural ancestor of a dropped path is removed from disk; its
    /// structural record is not forgotten yet. The path given is the
    /// ancestor's.
    AncestorRemoved,
}

/// Where reconciliation takes the object at `rel_path` under `root` while
/// it examines it -- for a test to leave one there, as a crash would.
#[cfg(any(test, feature = "test-support"))]
pub fn taken_object_path_for_test(root: &Path, rel_path: &str) -> PathBuf {
    preimage_path(&root.join(rel_path), rel_path).expect("a digest id always names an artefact")
}

#[cfg(any(test, feature = "test-support"))]
type StepHook = Box<dyn FnMut(ReconcileStepForTest, &Path)>;

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static STEP_HOOK: std::cell::RefCell<Option<StepHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Clears the hook [`set_reconcile_step_hook_for_test`] installed when
/// dropped. Per thread, so concurrently running tests never see each
/// other's hooks.
#[cfg(any(test, feature = "test-support"))]
pub struct ReconcileStepHookForTest(());

#[cfg(any(test, feature = "test-support"))]
impl Drop for ReconcileStepHookForTest {
    fn drop(&mut self) {
        STEP_HOOK.with(|hook| hook.borrow_mut().take());
    }
}

/// Runs `hook` with each step and the held path's absolute path whenever
/// this thread's reconciliation reaches one.
#[cfg(any(test, feature = "test-support"))]
pub fn set_reconcile_step_hook_for_test(
    hook: impl FnMut(ReconcileStepForTest, &Path) + 'static,
) -> ReconcileStepHookForTest {
    STEP_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    ReconcileStepHookForTest(())
}

#[cfg(any(test, feature = "test-support"))]
fn reached(step: ReconcileStepForTest, out_path: &Path) {
    STEP_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(step, out_path);
        }
    });
}

#[cfg(not(any(test, feature = "test-support")))]
#[derive(Clone, Copy)]
enum ReconcileStepForTest {
    Classified,
    ReleasingEntry,
    DirectoryPlaced,
    PruningAncestors,
    PathEmptied,
    StructuralDirectoryMade,
    DirectoryRemoved,
    AncestorRemoved,
}

#[cfg(not(any(test, feature = "test-support")))]
fn reached(_step: ReconcileStepForTest, _out_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Moving aside never creates a directory: the copy is a sibling of
    /// the object it preserves. Nothing to record.
    struct NoLedger;
    impl StructuralDirectoryLedger for NoLedger {
        fn record_intent(
            &self,
            rel_path: &str,
        ) -> Result<(), yadorilink_local_storage::StorageError> {
            panic!("moving aside created a directory: {rel_path}")
        }
        fn complete(
            &self,
            rel_path: &str,
            _identity: &yadorilink_fs_platform::fs_identity::FileIdentity,
        ) -> Result<(), yadorilink_local_storage::StorageError> {
            panic!("moving aside created a directory: {rel_path}")
        }
        fn abandon(&self, rel_path: &str) -> Result<(), yadorilink_local_storage::StorageError> {
            panic!("moving aside created a directory: {rel_path}")
        }
        fn interrupted(
            &self,
            rel_path: &str,
        ) -> Result<(), yadorilink_local_storage::StorageError> {
            panic!("moving aside created a directory: {rel_path}")
        }
    }

    /// Two different objects moved aside from one path must both survive,
    /// even when they agree on everything but their bytes: the same size
    /// and the same modification time, as a tool that restores timestamps
    /// or a coarse-timestamp filesystem produces.
    #[test]
    fn two_objects_moved_aside_from_one_path_do_not_overwrite_each_other() {
        let root = tempfile::tempdir().unwrap();
        let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let mut preserved = Vec::new();
        for content in [b"first edit!".as_slice(), b"other edit!".as_slice()] {
            let src = root.path().join("doc.txt");
            std::fs::write(&src, content).unwrap();
            std::fs::File::options().write(true).open(&src).unwrap().set_modified(mtime).unwrap();
            preserved.push(
                move_aside(root.path(), "doc.txt", &src, &NoLedger, "local-preserved").unwrap(),
            );
        }

        assert_ne!(preserved[0], preserved[1], "both objects were given one name");
        assert_eq!(std::fs::read(root.path().join(&preserved[0])).unwrap(), b"first edit!");
        assert_eq!(std::fs::read(root.path().join(&preserved[1])).unwrap(), b"other edit!");
    }

    /// Moving aside never replaces what already has the name it picks,
    /// whatever that is.
    #[test]
    fn moving_aside_does_not_replace_an_object_already_at_its_name() {
        let root = tempfile::tempdir().unwrap();
        let src = root.path().join("doc.txt");
        let mtime = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        let place = || {
            std::fs::write(&src, b"an edit").unwrap();
            std::fs::File::options().write(true).open(&src).unwrap().set_modified(mtime).unwrap();
        };
        place();
        let first = move_aside(root.path(), "doc.txt", &src, &NoLedger, "local-preserved").unwrap();
        // The user edits the conflict copy, then the same bytes turn up at
        // the held path again.
        std::fs::write(root.path().join(&first), b"the user's edit of the copy").unwrap();
        place();

        let second =
            move_aside(root.path(), "doc.txt", &src, &NoLedger, "local-preserved").unwrap();

        assert_ne!(first, second);
        assert_eq!(
            std::fs::read(root.path().join(&first)).unwrap(),
            b"the user's edit of the copy"
        );
        assert_eq!(std::fs::read(root.path().join(&second)).unwrap(), b"an edit");
    }
}
