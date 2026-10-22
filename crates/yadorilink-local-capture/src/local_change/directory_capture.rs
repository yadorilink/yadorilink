//! Directories as replicated entries.
//!
//! A directory on disk is one of two things. One a user (or any other
//! process) made is an explicit entry: it is authored like a file, with its
//! mode as its only metadata. One this device made only to hold replicated
//! descendants is structural: derived state, never authored. The
//! structural-origin ledger is the only thing that tells them apart --
//! nothing observable on disk can -- so every decision here reads it, and
//! a directory whose origin nobody can state is kept and authored as
//! nothing.
//!
//! Deleting a directory deletes the entries this device observed in it,
//! one point delete each: never a prefix, so an entry a peer created there
//! concurrently, or one indexed here but not yet written to disk, survives.
//! The deletes are authored as one signed recursive operation, cut into
//! parts, so the folder can later be restored as the unit it was removed
//! as. Renaming a directory is one operation the same way: each observed
//! explicit entry deleted at its old path and put at its new one. A
//! structural directory stays structural when renamed.

use std::path::Path;

use crate::error::LocalCaptureError;
use crate::ports::CapturedDirectory;
use yadorilink_fs_platform::fs_identity::{
    disk_race_fingerprint, FileIdentity, IdentityComparison,
};
use yadorilink_fs_platform::ignore_patterns::{is_ignore_file_relative_path, EffectiveIgnoreSet};
use yadorilink_replica_domain::file::{FileRecord, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::SyncPath;
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::native_state::NativeCaptureWitness;
use yadorilink_replica_domain::recursive_operation::is_ancestor_or_self;
use yadorilink_replica_domain::session_state::{
    LocalFileMetaColumns, MaterializationState, PreparedLocalMutation,
};
use yadorilink_sync_sqlite::file_index::LocalCaptureActualStateEvidence;
use yadorilink_sync_sqlite::structural_origin::{
    RetainedDirectory, StructuralDirectoryOrigin, StructuralOriginStatus,
};
use yadorilink_sync_sqlite::CanonicalCurrentRow;

use super::disk_observation::{
    closed_disk_observation_if_unraced, error_means_absent, exact_leaf_exists_as_directory,
    exact_leaf_exists_as_file_or_symlink, is_exact_path_confirmed_absent,
};
use super::flush::path_lock_order;
use super::path_policy::{
    is_excluded_from_sync, path_to_wire_relative_string, skip_reason_for_inadmissible_wire_path,
};
use super::record_builder::metadata_columns_for;
use super::semantic_delete::Removal;
use super::{LocalChangeOutcome, LocalChangeProcessor};

/// What capture does with a directory it finds on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DirectoryVerdict {
    /// Author the directory as an explicit entry with this mode.
    Author { unix_mode: Option<u32> },
    /// Nothing to author: already current, structural, of unknown origin,
    /// in flight, or not this module's to decide.
    Nothing,
}

/// The record, op, version and index metadata of an explicit directory
/// entry at `rel_path` with `unix_mode`: blockless, size and mtime 0, the
/// canonical directory version.
pub(super) fn directory_entry(
    rel_path: &str,
    unix_mode: Option<u32>,
) -> (FileRecord, Op, FileVersion, LocalFileMetaColumns) {
    let record = FileRecord {
        path: rel_path.to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: Vec::new(),
        deleted: false,
    };
    let version = FileVersion::directory(unix_mode);
    let op = Op::Put { path: SyncPath(rel_path.to_string()), version: version.version_hash };
    let meta = LocalFileMetaColumns {
        record_kind: RecordKind::Directory,
        symlink_target: None,
        symlink_out_of_root: false,
        unix_mode,
        xattrs: Vec::new(),
    };
    (record, op, version, meta)
}

/// Whether the directory observed as `lstat` has other permission bits
/// (`0o777`, the mode a Directory version replicates) than the structural
/// one recorded as `recorded` had.
#[cfg(unix)]
fn permission_bits_changed(recorded: &FileIdentity, lstat: &std::fs::Metadata) -> bool {
    yadorilink_fs_platform::fs_identity::directory_permission_bits_changed(recorded, lstat)
}

#[cfg(not(unix))]
fn permission_bits_changed(_recorded: &FileIdentity, _lstat: &std::fs::Metadata) -> bool {
    false
}

/// What [`LocalChangeProcessor::lock_observed_subtree`] found: the locks
/// it holds and the observed entries, parent before child.
pub(super) struct ObservedSubtree {
    guards: Vec<tokio::sync::OwnedMutexGuard<()>>,
    entries: Vec<(String, CanonicalCurrentRow, NativeCaptureWitness)>,
}

#[cfg(all(test, unix))]
impl ObservedSubtree {
    pub(super) fn entries(&self) -> Vec<&str> {
        self.entries.iter().map(|(path, ..)| path.as_str()).collect()
    }
}

/// The tombstone of the live `row` at `path`, deleted at `observed_at`.
fn tombstone_of(
    path: String,
    row: &CanonicalCurrentRow,
    observed_at_unix_nanos: i64,
) -> FileRecord {
    FileRecord {
        path,
        size: row.snapshot.size,
        mtime_unix_nanos: observed_at_unix_nanos,
        blocks: row.snapshot.blocks.clone(),
        deleted: true,
    }
}

/// The delete of the live `row` at `path`, deleted at `observed_at`.
fn delete_mutation(
    path: String,
    row: &CanonicalCurrentRow,
    native_witness: NativeCaptureWitness,
    observed_at_unix_nanos: i64,
) -> PreparedLocalMutation {
    let record = tombstone_of(path, row, observed_at_unix_nanos);
    let op = Op::Delete { path: SyncPath(record.path.clone()) };
    PreparedLocalMutation::Delete { record, op, native_witness: Some(native_witness) }
}

impl LocalChangeProcessor {
    /// Whether the directory at `rel_path` (`lstat` is its metadata) is to
    /// be authored.
    ///
    /// * A live explicit Directory row: authored again only when the mode
    ///   it states changed (a `chmod`), and not while the materializer is
    ///   writing it.
    /// * A live File or Symlink row: a type change, not decided here.
    /// * No live row: the ledger decides. No record at all is a directory
    ///   someone made -- explicit. A record naming exactly this object is
    ///   structural -- nothing, unless its mode changed, which is the user
    ///   operating on the directory itself and makes it explicit (D5). A
    ///   record naming a conclusively different object means this one
    ///   replaced it, which is again someone's directory -- explicit; a
    ///   comparison that cannot tell is of unknown origin -- nothing. A
    ///   structural `mkdir` in flight and a directory whose structural
    ///   record was lost are nothing; so is the directory a deleted entry's
    ///   delete kept on disk, but not one made at its path since.
    pub(super) fn directory_verdict(
        &self,
        group_id: &str,
        root: &Path,
        rel_path: &str,
        lstat: &std::fs::Metadata,
    ) -> Result<DirectoryVerdict, LocalCaptureError> {
        self.directory_verdict_replacing(group_id, root, rel_path, lstat, false)
    }

    /// [`Self::directory_verdict`], where `replacing_leaf` says the
    /// directory may stand where a live File or Symlink row's object was:
    /// the file was removed and a directory made at its name (a type
    /// change). Such a directory is decided as if the path had no live
    /// row, so a user's directory replaces the file's entry -- unless the
    /// row's object was never on disk here to be replaced. The full
    /// scan does not pass it: it tombstones the file's row first, and
    /// decides the directory on its next pass.
    pub(super) fn directory_verdict_replacing(
        &self,
        group_id: &str,
        root: &Path,
        rel_path: &str,
        lstat: &std::fs::Metadata,
        replacing_leaf: bool,
    ) -> Result<DirectoryVerdict, LocalCaptureError> {
        if !self.directory_capture || !lstat.is_dir() {
            return Ok(DirectoryVerdict::Nothing);
        }
        // Nothing reached through a symlinked component is this folder's.
        if yadorilink_local_storage::resolve_read_path_without_traversal(root, Path::new(rel_path))
            .is_err()
        {
            return Ok(DirectoryVerdict::Nothing);
        }
        let row = self.state.canonical_current_row(group_id, rel_path)?;
        let unix_mode = self.captured_unix_mode(
            lstat,
            &super::Predecessor::of_row(
                row.as_ref().filter(|row| row.snapshot.record_kind == RecordKind::Directory),
            ),
        );
        // Only a leaf that was on disk here can have been replaced: a peer's
        // entry still being written, admitted but not yet projected, or
        // held off disk by a name hazard never stood at the path, so the
        // directory is decided against it like any other live row. These
        // are the vetoes `lock_observed_subtree` applies the other way.
        let leaf_replaced = replacing_leaf
            && row.as_ref().is_some_and(|row| {
                !row.snapshot.deleted && row.snapshot.record_kind != RecordKind::Directory
            })
            && !self.state.has_materialization_intent(group_id, rel_path)?
            && !self.state.has_unsettled_projection_obligation(group_id, rel_path)?
            && !self.state.is_held(group_id, rel_path)?;
        if let Some(row) = row.as_ref().filter(|row| !row.snapshot.deleted && !leaf_replaced) {
            // A version with no mode (authored where there is no Unix mode
            // model) states nothing about the mode, so whatever mode the
            // directory got here is not a change to it.
            if row.snapshot.record_kind != RecordKind::Directory
                || row.snapshot.unix_mode.is_none()
                || unix_mode == row.snapshot.unix_mode
                || self.state.has_materialization_intent(group_id, rel_path)?
            {
                return Ok(DirectoryVerdict::Nothing);
            }
            return Ok(DirectoryVerdict::Author { unix_mode });
        }
        // The materializer is placing an entry here (an explicit directory
        // it has not settled yet): its row lands with the settle.
        if self.state.has_materialization_intent(group_id, rel_path)? {
            return Ok(DirectoryVerdict::Nothing);
        }
        let observed = FileIdentity::observe_path(&root.join(rel_path)).ok();
        let granularity = self.state.birth_time_granularity(root);
        // A different object -- conclusively, not merely one that cannot be
        // proven the same -- replaced the recorded one: someone made it.
        let replaced = |recorded: &FileIdentity| {
            observed.as_ref().is_some_and(|observed| {
                recorded.compare(observed, granularity) == IdentityComparison::DefinitelyDifferent
            })
        };
        // A directory a deleted entry's delete kept on disk is not authored
        // back. The record covers only the directory that delete concerned:
        // one made at the path since (D6: it inherits nothing) is decided
        // like any other directory.
        match self.state.retained_directory(group_id, rel_path)? {
            RetainedDirectory::None => {}
            // The very object the delete aimed at.
            RetainedDirectory::RemovableWhenEmpty(aimed_at) => {
                if !replaced(&aimed_at) {
                    return Ok(DirectoryVerdict::Nothing);
                }
            }
            // Kept for good: no delete aimed at the directory there, which
            // binds no identity. It may still be the directory this device
            // materialized for the deleted Directory entry (its identity
            // unrecorded, or not provably different) -- that one is not
            // authored back. Only a directory conclusively not the
            // materialized one, or one standing where the deleted entry was
            // not a directory at all, is someone else's.
            RetainedDirectory::Kept => {
                let someone_elses =
                    match self.state.materialized_directory_identity(group_id, rel_path)? {
                        Some(materialized) => replaced(&materialized),
                        None => row
                            .as_ref()
                            .is_some_and(|row| row.snapshot.record_kind != RecordKind::Directory),
                    };
                if !someone_elses {
                    return Ok(DirectoryVerdict::Nothing);
                }
            }
        }
        let origin = self.state.structural_directory_origin(group_id, rel_path)?;
        // No record here, but the ledger may name this very object under
        // another path: a structural directory someone renamed. It stays
        // structural under its new name, its record following it, and is
        // never promoted by the rename.
        if matches!(origin, StructuralDirectoryOrigin::None) {
            if let Some(observed) = observed.as_ref() {
                if self
                    .state
                    .follow_renamed_structural_directory(group_id, rel_path, observed, granularity)?
                    .is_some()
                {
                    return Ok(DirectoryVerdict::Nothing);
                }
            }
        }
        let verdict = match origin {
            StructuralDirectoryOrigin::None => DirectoryVerdict::Author { unix_mode },
            StructuralDirectoryOrigin::IntentPending => DirectoryVerdict::Nothing,
            StructuralDirectoryOrigin::ProvenanceLost(lost) => {
                if replaced(&lost) {
                    DirectoryVerdict::Author { unix_mode }
                } else {
                    DirectoryVerdict::Nothing
                }
            }
            StructuralDirectoryOrigin::Recorded(recorded) => {
                match origin.status(observed.as_ref(), granularity) {
                    StructuralOriginStatus::Structural | StructuralOriginStatus::IntentPending => {
                        DirectoryVerdict::Nothing
                    }
                    // D5: only the replicated Unix mode (the permission
                    // bits) promotes. A setuid, setgid or sticky bit, or a
                    // change of attributes a device with no Unix mode model
                    // tracks, moves the fingerprint but does not.
                    StructuralOriginStatus::StructuralMetadataChanged
                        if unix_mode.is_some() && permission_bits_changed(&recorded, lstat) =>
                    {
                        DirectoryVerdict::Author { unix_mode }
                    }
                    StructuralOriginStatus::StructuralMetadataChanged => DirectoryVerdict::Nothing,
                    StructuralOriginStatus::OriginUnknown if replaced(&recorded) => {
                        DirectoryVerdict::Author { unix_mode }
                    }
                    StructuralOriginStatus::OriginUnknown => DirectoryVerdict::Nothing,
                }
            }
        };
        Ok(verdict)
    }

    /// Captures the directory at `rel_path` from a watcher event, with the
    /// path's lock held by the caller: authors it when
    /// [`Self::directory_verdict`] says so, committed on its own rather than
    /// in the flush's batch (a directory's stat moves whenever an entry
    /// inside it changes, which would fail the batch's revalidation for no
    /// change to the directory's own version).
    pub(super) fn capture_directory(
        &self,
        group_id: &str,
        root: &Path,
        rel_path: &str,
        event_path: &Path,
    ) -> Result<LocalChangeOutcome, LocalCaptureError> {
        let Ok(lstat) = std::fs::symlink_metadata(event_path) else {
            return Ok(LocalChangeOutcome::None);
        };
        let DirectoryVerdict::Author { unix_mode } =
            self.directory_verdict_replacing(group_id, root, rel_path, &lstat, true)?
        else {
            return Ok(LocalChangeOutcome::None);
        };
        let (record, op, version, meta) = directory_entry(rel_path, unix_mode);
        // The proof names the directory only if it is still the directory
        // the verdict was taken on, with the mode being authored.
        let identity = FileIdentity::observe_path(event_path).ok().filter(|identity| {
            identity.object_kind == yadorilink_fs_platform::fs_identity::ObjectKind::Directory
                && std::fs::symlink_metadata(event_path)
                    .is_ok_and(|now| now.is_dir() && self.mode_unchanged_since(&now, unix_mode))
        });
        let directory = CapturedDirectory { record, op, version, meta, identity };
        self.state.commit_captured_directory(
            group_id,
            &directory,
            &self.device_id,
            self.change_emitter.as_deref(),
            &self.begin_operation()?.permit(),
        )?;
        let record = directory.record;
        Ok(LocalChangeOutcome::FileChanged(record))
    }

    /// The explicit entries this device observed in the vanished directory
    /// at `rel_path`, parent before child, each still live and still gone
    /// from disk under its own lock -- the set a recursive delete or rename
    /// of `rel_path` acts on.
    ///
    /// For a delete (`rename_to` is `None`) the caller holds `rel_path`'s
    /// lock, and the returned guards hold every other candidate's: each is
    /// below `rel_path`, so it sorts after it and the canonical order holds.
    /// For a rename to `rename_to` the caller holds no lock, and the guards
    /// hold `rel_path`'s, `rename_to`'s and every candidate's at its old and
    /// its new path, all taken in one canonical order: a new path can sort
    /// before the old one, so none may be held while waiting on another.
    ///
    /// `rel_path`'s own explicit entry if live, and each live entry below
    /// it that was on disk here. An entry below it that never was -- a
    /// peer's entry indexed while its bytes were still being written (an
    /// open materialization intent), one admitted whose projection has not
    /// started (an unsettled REMOTE-origin projection obligation), or one
    /// held off disk by a name collision -- was not deleted by whoever
    /// removed the directory, and is not in the set. These are the full
    /// scan's own vetoes on reading an absent path as a deletion. Neither
    /// is an entry under a paused item, nor one whose delete is already in
    /// `pending_deletes` (the same flush's batch).
    ///
    /// "Was on disk here" is a `Present` object that the vetoes above do not
    /// contradict: a `Remote` entry has no object, a `Hydrating` one is
    /// producing it and an `Evicting` one is removing it, so none of them
    /// was deleted by whoever removed the directory. That is for a physical
    /// removal that was merely observed. A [`Removal::Semantic`] delete of the
    /// directory deletes the logical namespace the user saw, so entries
    /// without a local object go with it -- but only the versions the delete
    /// saw (the other vetoes stand).
    pub(super) async fn lock_observed_subtree(
        &self,
        group_id: &str,
        root: &Path,
        rel_path: &str,
        pending_deletes: &[String],
        rename_to: Option<&str>,
        removal: Removal<'_>,
    ) -> Result<ObservedSubtree, LocalCaptureError> {
        let prefix = format!("{rel_path}/");
        let paused = self.paused_items(group_id)?;
        let candidates: std::collections::BTreeSet<String> = self
            .state
            .list_files_with_kind(group_id)?
            .into_iter()
            .filter(|(row, kind)| {
                !row.deleted
                    && ((row.path == rel_path && *kind == RecordKind::Directory)
                        || row.path.starts_with(&prefix))
                    && !yadorilink_sync_sqlite::paused_items::path_is_covered(&paused, &row.path)
                    && !pending_deletes.contains(&row.path)
            })
            .map(|(row, _)| row.path)
            .collect();
        if candidates.is_empty() && rename_to.is_none() {
            return Ok(ObservedSubtree { guards: Vec::new(), entries: Vec::new() });
        }
        // One canonical order for every lock taken: parent before child, by
        // the lock key (see `path_lock_order`) -- `Photos` and `photos` are
        // one lock, and taking it twice would wait on itself.
        let mut to_lock: Vec<String> = candidates.iter().cloned().collect();
        match rename_to {
            None => {
                // The caller holds this one.
                let held = yadorilink_fs_platform::canonical_fold::canonical_fold(rel_path);
                to_lock.retain(|path| {
                    yadorilink_fs_platform::canonical_fold::canonical_fold(path) != held
                });
            }
            Some(to) => {
                to_lock.push(rel_path.to_string());
                to_lock.push(to.to_string());
                to_lock.extend(
                    candidates.iter().map(|path| format!("{to}{}", &path[rel_path.len()..])),
                );
            }
        }
        let mut guards = Vec::with_capacity(to_lock.len());
        for path in path_lock_order(&to_lock) {
            guards.push(self.state.path_lock(group_id, path).lock_owned().await);
        }
        let mut entries = Vec::with_capacity(candidates.len());
        // Nothing below a directory that is gone under its exact spelling is there under
        // its own: one answer for the whole subtree, not a listing per entry.
        let subtree_gone = is_exact_path_confirmed_absent(root, rel_path);
        for path in candidates {
            // Native's witness before the row it accompanies.
            let native_witness = self.state.native_capture_witness(group_id, &path)?;
            let Some(row) = self.state.canonical_current_row(group_id, &path)? else { continue };
            if row.snapshot.deleted
                || (path == rel_path && row.snapshot.record_kind != RecordKind::Directory)
                || self.state.has_materialization_intent(group_id, &path)?
                || self.state.has_unsettled_projection_obligation(group_id, &path)?
                || self.state.is_held(group_id, &path)?
                || match removal {
                    Removal::Observed => {
                        self.state.get_materialization_state(group_id, &path)?
                            != Some(MaterializationState::Present)
                    }
                    Removal::Semantic(delete) => !delete.names_current_version(&path, Some(&row)),
                }
                || !(subtree_gone || is_exact_path_confirmed_absent(root, &path))
            {
                continue;
            }
            entries.push((path, row, native_witness));
        }
        Ok(ObservedSubtree { guards, entries })
    }

    /// Deletes what a vanished directory held, for a `Removed` event at
    /// `rel_path` whose row is an explicit directory or absent, with the
    /// path's own lock held by the caller.
    ///
    /// The set deleted is the explicit entries this device observed there
    /// (see [`Self::lock_observed_subtree`]): one point delete each, never
    /// a prefix, so an entry this device never had on disk survives. It is
    /// authored as one recursive operation rooted at `rel_path`, cut into
    /// parts, each parented on the state its paths had on disk here, and
    /// committed with every deleted path's lock held and its absence
    /// rechecked under it.
    pub(super) async fn delete_vanished_directory(
        &self,
        group_id: &str,
        root: &Path,
        rel_path: &str,
        pending_deletes: &[String],
        observed_at_unix_nanos: i64,
        removal: Removal<'_>,
    ) -> Result<LocalChangeOutcome, LocalCaptureError> {
        let ObservedSubtree { guards, entries } = self
            .lock_observed_subtree(group_id, root, rel_path, pending_deletes, None, removal)
            .await?;
        let mut tombstones: Vec<PreparedLocalMutation> = entries
            .into_iter()
            .map(|(path, row, witness)| {
                delete_mutation(path, &row, witness, observed_at_unix_nanos)
            })
            .collect();
        if tombstones.is_empty() {
            return Ok(LocalChangeOutcome::None);
        }
        // Deepest first, as `rm -rf` removes them.
        tombstones.reverse();
        self.state.commit_directory_removal(
            group_id,
            rel_path,
            &tombstones,
            &self.device_id,
            observed_at_unix_nanos,
            self.change_emitter.as_deref(),
            &self.begin_operation()?.permit(),
        )?;
        drop(guards);
        self.records_now_at(group_id, tombstones.iter().map(|t| t.record().path.as_str()))
    }

    /// Captures the rename of the directory `from` to `to` (both relative,
    /// neither inside the other, `from` gone from disk and `to` a
    /// directory on it) as one recursive rename operation. It takes every
    /// lock it needs itself, `from`'s and `to`'s included, in one canonical
    /// order (see [`Self::lock_observed_subtree`]), so the caller holds
    /// none.
    ///
    /// Each explicit entry observed under `from` (see
    /// [`Self::lock_observed_subtree`]) is deleted at its old path and put
    /// at the same place under `to`, with what is on disk there now: its
    /// content read again, so the put is exactly the bytes the user has.
    /// An entry below `from` this device never had on disk is not moved and
    /// stays in the old namespace. A structural `from` has no entry to
    /// move: the directory stays structural under `to`, its ledger record
    /// following it, and only the explicit entries below it move.
    ///
    /// An entry whose new path cannot be captured now (it is not on disk
    /// there as the same kind, already has a live row, or is being
    /// written) is deleted at its old path only; the new path is captured
    /// by its own event like any other path.
    ///
    /// Only with an emitter: without one there is no operation to sign,
    /// and the caller falls back to the two sides' own events.
    pub(super) async fn capture_directory_rename(
        &self,
        group_id: &str,
        root: &Path,
        from: &str,
        to: &str,
        ignore_set: &EffectiveIgnoreSet,
        observed_at_unix_nanos: i64,
    ) -> Result<LocalChangeOutcome, LocalCaptureError> {
        let Some(emitter) = &self.change_emitter else { return Ok(LocalChangeOutcome::None) };
        let to_abs = root.join(to);
        let Ok(to_lstat) = std::fs::symlink_metadata(&to_abs) else {
            return Ok(LocalChangeOutcome::None);
        };
        if !to_lstat.is_dir() || !is_exact_path_confirmed_absent(root, from) {
            return Ok(LocalChangeOutcome::None);
        }
        let dest_of = |path: &str| format!("{to}{}", &path[from.len()..]);
        let ObservedSubtree { guards, entries } = self
            .lock_observed_subtree(group_id, root, from, &[], Some(to), Removal::Observed)
            .await?;
        if self.is_paused(group_id, from)? || self.is_paused(group_id, to)? {
            return Ok(LocalChangeOutcome::None);
        }

        let mut mutations: Vec<PreparedLocalMutation> = Vec::with_capacity(entries.len() * 2);
        let mut evidence: Vec<Option<LocalCaptureActualStateEvidence>> =
            Vec::with_capacity(entries.len() * 2);
        for (path, row, witness) in &entries {
            mutations.push(delete_mutation(
                path.clone(),
                row,
                witness.clone(),
                observed_at_unix_nanos,
            ));
            evidence.push(Some(LocalCaptureActualStateEvidence::Absent));
            if let Some((put, proof)) =
                self.prepare_moved_entry(group_id, root, &dest_of(path), row, ignore_set)?
            {
                mutations.push(put);
                evidence.push(proof);
            }
        }
        if !mutations.is_empty() {
            self.state.commit_directory_rename(
                group_id,
                from,
                to,
                &mutations,
                &evidence,
                &self.device_id,
                crate::ports::LocalChangeEmission {
                    author: emitter,
                    permit: &self.begin_operation()?.permit(),
                },
            )?;
        }
        if !entries.iter().any(|(path, _, _)| path == from) {
            // A structural (or never captured) directory: nothing to move
            // for it, but its record follows it so it is still recognized
            // as the container this device made. Only once the operation
            // is committed: moved first, a failed or interrupted commit
            // would leave `from` with no record to pair the rename by.
            // Left unmoved, the verdict on `to` still finds the record by
            // the object's identity and moves it then.
            if let Ok(identity) = FileIdentity::observe_path(&to_abs) {
                let granularity = self.state.birth_time_granularity(root);
                self.state.follow_renamed_structural_directory(
                    group_id,
                    to,
                    &identity,
                    granularity,
                )?;
            }
        }
        drop(guards);
        if mutations.is_empty() {
            return Ok(LocalChangeOutcome::None);
        }
        let touched: Vec<String> = mutations.iter().map(|m| m.record().path.clone()).collect();
        self.records_now_at(group_id, touched.iter().map(String::as_str))
    }

    /// The put of an entry a rename moved to `dest`, prepared from what is
    /// on disk at `dest` now, with the proof of what the put leaves there.
    /// `dest` has no live row (or it is not prepared), so the put was shown
    /// nothing there;
    /// `None` when `dest` cannot be captured as the moved entry here and
    /// now (see [`Self::capture_directory_rename`]).
    fn prepare_moved_entry(
        &self,
        group_id: &str,
        root: &Path,
        dest: &str,
        moved: &CanonicalCurrentRow,
        ignore_set: &EffectiveIgnoreSet,
    ) -> Result<
        Option<(PreparedLocalMutation, Option<LocalCaptureActualStateEvidence>)>,
        LocalCaptureError,
    > {
        let dest_abs = root.join(dest);
        let Ok(lstat) = std::fs::symlink_metadata(&dest_abs) else { return Ok(None) };
        // Native's witness of `dest` before its row is read below.
        let native_witness = self.state.native_capture_witness(group_id, dest)?;
        // Whatever the ordinary capture of `dest` would leave unauthored is
        // left unauthored here too: an ignored or unrepresentable name
        // (which would also fail the whole operation's commit), the ignore
        // file itself, and a path a pause or an install holds.
        if is_ignore_file_relative_path(Path::new(dest))
            || is_excluded_from_sync(dest, lstat.is_dir(), ignore_set)
            || skip_reason_for_inadmissible_wire_path(dest).is_some()
            || self.is_under_user_pause(group_id, dest)?
            || self.is_paused(group_id, dest)?
            || self
                .state
                .canonical_current_row(group_id, dest)?
                .is_some_and(|row| !row.snapshot.deleted)
            || self.state.has_materialization_intent(group_id, dest)?
            || yadorilink_local_storage::resolve_read_path_without_traversal(root, Path::new(dest))
                .is_err()
        {
            return Ok(None);
        }
        if moved.snapshot.record_kind == RecordKind::Directory {
            if !lstat.is_dir() || !exact_leaf_exists_as_directory(root, dest) {
                return Ok(None);
            }
            let unix_mode =
                self.captured_unix_mode(&lstat, &super::Predecessor::of_row(Some(moved)));
            let (record, op, version, meta) = directory_entry(dest, unix_mode);
            let proof = FileIdentity::observe_path(&dest_abs)
                .ok()
                .filter(|identity| {
                    identity.object_kind
                        == yadorilink_fs_platform::fs_identity::ObjectKind::Directory
                        && std::fs::symlink_metadata(&dest_abs).is_ok_and(|now| {
                            now.is_dir() && self.mode_unchanged_since(&now, unix_mode)
                        })
                })
                .map(|filesystem_identity| LocalCaptureActualStateEvidence::Present {
                    filesystem_identity,
                });
            return Ok(Some((
                PreparedLocalMutation::Upsert {
                    record,
                    op,
                    version,
                    meta: Some(meta),
                    native_witness: Some(native_witness),
                },
                proof,
            )));
        }
        let expect_symlink = moved.snapshot.record_kind == RecordKind::Symlink;
        if lstat.is_dir()
            || lstat.file_type().is_symlink() != expect_symlink
            || !exact_leaf_exists_as_file_or_symlink(root, dest)
        {
            return Ok(None);
        }
        let fingerprint_before = disk_race_fingerprint(&dest_abs);
        let (outcome, classification, unix_mode) = self.build_record_for_created_or_modified(
            group_id,
            root,
            dest.to_string(),
            &dest_abs,
            None,
            None,
            None,
            None,
        )?;
        let LocalChangeOutcome::FileChanged(record) = outcome else { return Ok(None) };
        // The moved entry's predecessor is the row it moved from, for the mode
        // as for the attributes: the destination has no row of its own.
        let unix_mode = match (&classification, std::fs::metadata(&dest_abs)) {
            (None, Ok(now)) => {
                Some(self.captured_unix_mode(&now, &super::Predecessor::of_row(Some(moved))))
            }
            _ => unix_mode,
        };
        let xattrs = if classification.is_none() {
            self.captured_xattrs(&dest_abs, &super::Predecessor::of_row(Some(moved)))
        } else {
            Vec::new()
        };
        let (op, version) = self.content_op(
            &record,
            unix_mode.flatten(),
            classification.as_ref().map(|c| c.target.clone()),
            xattrs.clone(),
        );
        let meta = metadata_columns_for(&classification, unix_mode, xattrs);
        let proof =
            closed_disk_observation_if_unraced(&dest_abs, fingerprint_before).map(|observation| {
                LocalCaptureActualStateEvidence::Present {
                    filesystem_identity: observation.identity,
                }
            });
        Ok(Some((
            PreparedLocalMutation::Upsert {
                record,
                op,
                version,
                meta: Some(meta),
                native_witness: Some(native_witness),
            },
            proof,
        )))
    }

    /// The recursive half of one debounced flush, run before its paths are
    /// processed one at a time: every directory this device observed that
    /// the flush reports gone is captured here as one recursive operation
    /// over everything it held, so the per-path pass that follows finds
    /// those entries already settled and authors nothing more for them.
    /// Left to the per-path pass, a child's own `Removed` could be
    /// authored on its own before its directory's, splitting one `rm -rf`
    /// into unrelated changes.
    ///
    /// A removed path whose directory is gone too stands for that
    /// directory (the topmost one gone), even when the directory's own
    /// `Removed` is not in this flush: a large `rm -rf` spans several
    /// flushes (the debouncer flushes early on a burst and at least every
    /// few seconds), and `rm` removes the children first. What this cannot
    /// group is a child whose flush is processed while its directory is
    /// still on disk: nothing yet tells that apart from the user deleting
    /// that one file, and it is authored as such.
    ///
    /// A gone directory is paired with a directory the flush reports
    /// appearing when the appearing one is the same filesystem object:
    /// that is a rename, captured as one rename operation. Pairing reads
    /// what is on disk, never the event kinds, because FSEvents reports
    /// both sides of a rename with no direction and in no set order. A
    /// rename whose two sides land in different flushes is still captured
    /// correctly, as a recursive delete and the new directory's own
    /// capture.
    ///
    /// Returns the records it changed. A failure is logged and left to the
    /// per-path pass, which reports it like any other.
    pub(super) async fn capture_recursive_operations_in_flush(
        &self,
        group_id: &str,
        root: &Path,
        paths: &[(std::path::PathBuf, i64)],
        ignore_set: &EffectiveIgnoreSet,
    ) -> Vec<FileRecord> {
        match self
            .capture_recursive_operations_in_flush_inner(group_id, root, paths, ignore_set)
            .await
        {
            Ok(records) => records,
            Err(error) => {
                tracing::warn!(
                    group_id,
                    error = %error,
                    "capturing a flush's directory removals and renames as recursive operations \
                     failed; its paths are captured one at a time instead"
                );
                Vec::new()
            }
        }
    }

    async fn capture_recursive_operations_in_flush_inner(
        &self,
        group_id: &str,
        root: &Path,
        paths: &[(std::path::PathBuf, i64)],
        ignore_set: &EffectiveIgnoreSet,
    ) -> Result<Vec<FileRecord>, LocalCaptureError> {
        let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
        self.verified_root_of_established_link(group_id, &root)?;
        let mut vanished: Vec<(String, i64)> = Vec::new();
        let mut appeared: Vec<String> = Vec::new();
        for (path, observed_at) in paths {
            let Ok(rel) = path.strip_prefix(&root) else { continue };
            let Some(rel) = path_to_wire_relative_string(rel) else { continue };
            if rel.is_empty() || skip_reason_for_inadmissible_wire_path(&rel).is_some() {
                continue;
            }
            // Gone under its exact spelling: nothing answers to the name, or only a folded
            // sibling does (a case-only rename leaves the old spelling answering).
            // (Only a directory answering to the name is looked at exactly: a file or a
            // directory edited in place is not listed for, and a vanished entry is `Err`.)
            let gone = match std::fs::symlink_metadata(path) {
                Err(error) if error_means_absent(&error) => true,
                // Unobservable (EIO, EACCES, ...) is not gone: leave it to the next event.
                Err(_) => continue,
                Ok(meta) => {
                    meta.is_dir()
                        && self.was_directory(group_id, &rel)?
                        && is_exact_path_confirmed_absent(&root, &rel)
                }
            };
            match std::fs::symlink_metadata(path).ok().filter(|_| !gone) {
                None => {
                    // The topmost gone directory this path was in, or the
                    // path itself: a child reported before its directory
                    // (in an earlier flush of the same `rm -rf`) is part of
                    // the directory's removal, not one of its own.
                    let mut gone = vec![rel.as_str()];
                    while let Some((parent, _)) = gone[gone.len() - 1].rsplit_once('/') {
                        if !is_exact_path_confirmed_absent(&root, parent) {
                            break;
                        }
                        gone.push(parent);
                    }
                    for candidate in gone.into_iter().rev() {
                        if self.was_directory(group_id, candidate)?
                            && !is_excluded_from_sync(candidate, true, ignore_set)
                        {
                            vanished.push((candidate.to_string(), *observed_at));
                            break;
                        }
                    }
                }
                Some(meta) if meta.is_dir() => {
                    let live_row = self
                        .state
                        .canonical_current_row(group_id, &rel)?
                        .filter(|row| !row.snapshot.deleted);
                    if live_row.is_none()
                        && exact_leaf_exists_as_directory(&root, &rel)
                        && !is_excluded_from_sync(&rel, true, ignore_set)
                    {
                        appeared.push(rel);
                    }
                }
                Some(_) => {}
            }
        }
        if vanished.is_empty() {
            return Ok(Vec::new());
        }
        // Only the topmost gone directory: what is below it is in its set.
        let tops: Vec<String> = vanished.iter().map(|(rel, _)| rel.clone()).collect();
        vanished
            .retain(|(rel, _)| !tops.iter().any(|top| top != rel && is_ancestor_or_self(top, rel)));
        vanished.sort();
        vanished.dedup_by(|a, b| a.0 == b.0);

        let granularity = self.state.birth_time_granularity(&root);
        let mut records = Vec::new();
        let mut paired: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (from, observed_at) in vanished {
            if self.is_under_user_pause(group_id, &from)? {
                continue;
            }
            let recorded = match self.state.canonical_current_row(group_id, &from)? {
                Some(row)
                    if !row.snapshot.deleted
                        && row.snapshot.record_kind == RecordKind::Directory =>
                {
                    self.state.materialized_directory_identity(group_id, &from)?
                }
                _ => match self.state.structural_directory_origin(group_id, &from)? {
                    StructuralDirectoryOrigin::Recorded(identity) => Some(identity),
                    _ => None,
                },
            };
            let to = recorded.and_then(|recorded| {
                appeared
                    .iter()
                    .filter(|to| {
                        !paired.contains(*to)
                            && !is_ancestor_or_self(&from, to)
                            && !is_ancestor_or_self(to, &from)
                    })
                    .find(|to| {
                        FileIdentity::observe_path(&root.join(to)).is_ok_and(|observed| {
                            recorded.compare(&observed, granularity)
                                == IdentityComparison::SameObject
                        })
                    })
                    .cloned()
            });
            let to = match to {
                Some(to)
                    if !self.is_under_user_pause(group_id, &to)?
                        && !self.is_paused(group_id, &to)? =>
                {
                    Some(to)
                }
                _ => None,
            };
            let outcome = match to {
                // The rename takes its own locks, `from`'s among them.
                Some(to) => {
                    paired.insert(to.clone());
                    self.capture_directory_rename(
                        group_id,
                        &root,
                        &from,
                        &to,
                        ignore_set,
                        observed_at,
                    )
                    .await?
                }
                None => {
                    let lock = self.state.path_lock(group_id, &from);
                    let _guard = lock.lock().await;
                    if self.is_paused(group_id, &from)? {
                        continue;
                    }
                    self.delete_vanished_directory(
                        group_id,
                        &root,
                        &from,
                        &[],
                        observed_at,
                        Removal::Observed,
                    )
                    .await?
                }
            };
            match outcome {
                LocalChangeOutcome::FilesChanged(changed) => records.extend(changed),
                LocalChangeOutcome::FileChanged(changed) => records.push(changed),
                LocalChangeOutcome::None | LocalChangeOutcome::RetryLater => {}
            }
        }
        Ok(records)
    }

    /// Whether the index held a directory at `rel_path`: a live explicit
    /// Directory row, or no live row and live entries below it.
    fn was_directory(&self, group_id: &str, rel_path: &str) -> Result<bool, LocalCaptureError> {
        Ok(match self.state.canonical_current_row(group_id, rel_path)? {
            Some(row) if !row.snapshot.deleted => row.snapshot.record_kind == RecordKind::Directory,
            _ => self.state.has_live_descendant_row(group_id, rel_path)?,
        })
    }

    /// The index rows now at `paths`, as a capture outcome.
    fn records_now_at<'a>(
        &self,
        group_id: &str,
        paths: impl Iterator<Item = &'a str>,
    ) -> Result<LocalChangeOutcome, LocalCaptureError> {
        let mut records = Vec::new();
        for path in paths {
            if let Some(record) = self.state.get_file(group_id, path)? {
                records.push(record);
            }
        }
        Ok(match records.len() {
            0 => LocalChangeOutcome::None,
            _ => LocalChangeOutcome::FilesChanged(records),
        })
    }
}
