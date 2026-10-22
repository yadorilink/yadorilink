//! Manual eviction: removes a present local object so its row becomes
//! `Remote` and, on an on-demand device, reclaims its now-cached blocks once
//! a full replica's custody is confirmed.
//!
//! Every `state.<method>` call in this module goes through `&dyn
//! MaterializationExecutionPort`, never a concrete storage type, so this
//! module's own code is policy/filesystem-lifecycle-flavored, not
//! SQL-flavored -- it has no idea how, or whether, the state behind the
//! trait is persisted.

use std::path::Path;

use yadorilink_local_storage::disk_bytes_match_indexed_blocks;
use yadorilink_local_storage::verify_write_target_within_root;
use yadorilink_local_storage::BlockReclamationStore;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::session_state::MaterializationState;
use yadorilink_replica_engine::custody::FullReplicaCustody;
use yadorilink_root_authority::root_commit::RootCommitPermit;

use crate::block_liveness::BlockLivenessGate;
use crate::materialization_execution::{
    AbandonedEviction, MaterializationExecutionError, MaterializationExecutionPort,
};

/// Reuses `yadorilink-root-authority`'s `disk_race_fingerprint` rather than a
/// local `(size, mtime)` pair: size+mtime alone lets a same-size local edit
/// landing within the filesystem's mtime granularity slip past the
/// pre-eviction revalidation below undetected -- and unlike the hydration
/// race this same fingerprint also closes, eviction's outcome on a false
/// match is more destructive: removing the object below destroys the
/// user's just-edited bytes, not merely stale remote content.
type DiskIdentity = Option<yadorilink_fs_platform::fs_identity::DiskRaceFingerprint>;

fn disk_identity(path: &Path) -> Result<DiskIdentity, MaterializationExecutionError> {
    Ok(yadorilink_fs_platform::fs_identity::disk_race_fingerprint(path))
}

/// A point between eviction's last check of the object and its removal, at
/// which a test can act on the disk the way a concurrent user would. Per
/// thread, so concurrently running tests never see each other's hooks.
#[cfg(any(test, feature = "test-support"))]
type PreRemovalHook = Box<dyn FnMut(&Path)>;

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static PRE_REMOVAL_HOOK: std::cell::RefCell<Option<PreRemovalHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs `hook` with the object's path at the point described on
/// [`PreRemovalHook`], until the returned guard is dropped.
#[cfg(any(test, feature = "test-support"))]
pub fn set_pre_removal_hook_for_test(
    hook: impl FnMut(&Path) + 'static,
) -> PreRemovalHookGuardForTest {
    PRE_REMOVAL_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    PreRemovalHookGuardForTest(())
}

/// Clears the hook installed by [`set_pre_removal_hook_for_test`] on drop.
#[cfg(any(test, feature = "test-support"))]
pub struct PreRemovalHookGuardForTest(());

#[cfg(any(test, feature = "test-support"))]
impl Drop for PreRemovalHookGuardForTest {
    fn drop(&mut self) {
        PRE_REMOVAL_HOOK.with(|slot| slot.borrow_mut().take());
    }
}

/// Tests only: the verdict of every volume, in place of the durable-namespace probe. Per thread.
#[cfg(any(test, feature = "test-support"))]
type VolumeVerdictOverride = Box<dyn Fn(Option<&Path>) -> bool>;

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static VOLUME_VERDICT_OVERRIDE: std::cell::RefCell<Option<VolumeVerdictOverride>> =
        const { std::cell::RefCell::new(None) };
}

/// Replaces the volume verdict eviction takes before it removes any bytes, until the returned
/// guard is dropped.
#[cfg(any(test, feature = "test-support"))]
pub fn set_volume_verdict_for_test(
    verdict: impl Fn(Option<&Path>) -> bool + 'static,
) -> VolumeVerdictGuardForTest {
    VOLUME_VERDICT_OVERRIDE.with(|slot| *slot.borrow_mut() = Some(Box::new(verdict)));
    VolumeVerdictGuardForTest(())
}

/// Clears the verdict installed by [`set_volume_verdict_for_test`] on drop.
#[cfg(any(test, feature = "test-support"))]
pub struct VolumeVerdictGuardForTest(());

#[cfg(any(test, feature = "test-support"))]
impl Drop for VolumeVerdictGuardForTest {
    fn drop(&mut self) {
        VOLUME_VERDICT_OVERRIDE.with(|slot| slot.borrow_mut().take());
    }
}

/// Whether the bytes on `dir`'s volume may be deleted: the production durable-namespace verdict
/// (on Windows the global gate and the volume's probe), unless a test replaced it.
fn volume_durable(dir: Option<&Path>) -> bool {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(verdict) =
        VOLUME_VERDICT_OVERRIDE.with(|slot| slot.borrow().as_ref().map(|verdict| verdict(dir)))
    {
        return verdict;
    }
    yadorilink_fs_platform::durable_dir::volume_offers_durable_namespace(dir)
}

/// A point at which eviction asks for custody, so a test can observe what is
/// held and what has been checked by then. Per thread, like [`PreRemovalHook`].
#[cfg(any(test, feature = "test-support"))]
type CustodyProbe = Box<dyn FnMut()>;

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static CUSTODY_PROBE: std::cell::RefCell<Option<CustodyProbe>> =
        const { std::cell::RefCell::new(None) };
}

/// Runs `probe` each time eviction is about to ask for custody, until the
/// returned guard is dropped.
#[cfg(any(test, feature = "test-support"))]
pub fn set_custody_probe_for_test(probe: impl FnMut() + 'static) -> CustodyProbeGuardForTest {
    CUSTODY_PROBE.with(|slot| *slot.borrow_mut() = Some(Box::new(probe)));
    CustodyProbeGuardForTest(())
}

/// Clears the probe installed by [`set_custody_probe_for_test`] on drop.
#[cfg(any(test, feature = "test-support"))]
pub struct CustodyProbeGuardForTest(());

#[cfg(any(test, feature = "test-support"))]
impl Drop for CustodyProbeGuardForTest {
    fn drop(&mut self) {
        CUSTODY_PROBE.with(|slot| slot.borrow_mut().take());
    }
}

/// Where eviction detaches an object before removing it, beside the object
/// so the rename stays on one volume. A reserved artefact name: invisible to
/// the watcher, the scan and capture.
pub fn eviction_quarantine_path(
    out_path: &Path,
    rel_path: &str,
) -> Result<std::path::PathBuf, MaterializationExecutionError> {
    use sha2::{Digest, Sha256};
    let id = hex::encode(Sha256::digest(format!("evict\0{rel_path}").as_bytes()));
    let name = yadorilink_fs_platform::reserved_namespace::artefact_component_name(
        yadorilink_fs_platform::reserved_namespace::ArtefactKind::Preimage,
        &id,
    )
    .map_err(|e| MaterializationExecutionError::CorruptState(e.to_string()))?;
    Ok(out_path.with_file_name(name))
}

/// Startup recovery of an eviction a crash stopped after it detached the
/// object (see [`eviction_quarantine_path`]): the object goes back to its
/// path if the path is free; if something stands there now, the detached
/// object is kept as a recoverable conflict copy for capture to see. Nothing
/// is ever deleted here.
pub fn recover_eviction_quarantine(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    rel_path: &str,
) -> Result<(), MaterializationExecutionError> {
    let out_path = root.join(rel_path);
    let q = eviction_quarantine_path(&out_path, rel_path)?;
    // Only a CONFIRMED absence counts as recovered; anything else (a
    // permission or I/O error) is an error and keeps the caller's marker.
    match std::fs::symlink_metadata(&q) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    restore_detached(state, root, group_id, rel_path, &q, &out_path)
}

/// Puts a detached object back at `out_path` without replacing anything: a
/// hard link fails if the name is taken, and only then is the quarantine name
/// dropped. When the name is taken, or links are unsupported, the object is
/// moved aside as a conflict copy instead.
fn restore_detached(
    state: &dyn MaterializationExecutionPort,
    root: &Path,
    group_id: &str,
    rel_path: &str,
    q: &Path,
    out_path: &Path,
) -> Result<(), MaterializationExecutionError> {
    match std::fs::hard_link(q, out_path) {
        Ok(()) => {
            trace_step("linked");
            directory_barrier(out_path)?;
            std::fs::remove_file(q)?;
            trace_step("unlinked");
            directory_barrier(out_path)?;
            Ok(())
        }
        Err(_) => {
            let ledger =
                crate::materialization_execution::GroupStructuralLedger::new(state, group_id);
            crate::held_path_reconcile::move_aside(root, rel_path, q, &ledger, "local-preserved")
                .map(|_| ())
        }
    }
}

// Test-only trace of the steps eviction and its restore take, in order.
#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static RESTORE_TRACE: std::cell::RefCell<Vec<&'static str>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Takes (and clears) this thread's restore trace.
#[cfg(any(test, feature = "test-support"))]
pub fn take_restore_trace_for_test() -> Vec<&'static str> {
    RESTORE_TRACE.with(|t| std::mem::take(&mut *t.borrow_mut()))
}

// Test-only: makes the Nth (1-based) directory barrier on this thread fail.
#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static FAIL_BARRIER: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    static BARRIERS_SEEN: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Arms the failure described on `FAIL_BARRIER` (`None` disarms) and resets
/// the barrier count.
#[cfg(any(test, feature = "test-support"))]
pub fn fail_directory_barrier_for_test(nth: Option<usize>) {
    FAIL_BARRIER.with(|c| c.set(nth));
    BARRIERS_SEEN.with(|c| c.set(0));
}

/// Makes the parent directory's entries durable and records the barrier. The
/// link and the quarantine name are the only two references to a detached
/// object, so each step that changes one must be durable before the step that
/// drops the other.
fn directory_barrier(path: &Path) -> Result<(), MaterializationExecutionError> {
    #[cfg(any(test, feature = "test-support"))]
    {
        let seen = BARRIERS_SEEN.with(|c| {
            c.set(c.get() + 1);
            c.get()
        });
        if FAIL_BARRIER.with(std::cell::Cell::get) == Some(seen) {
            return Err(MaterializationExecutionError::CorruptState(
                "injected directory sync failure".to_string(),
            ));
        }
    }
    yadorilink_local_storage::sync_parent_dir(path)?;
    trace_step("synced");
    Ok(())
}

pub(crate) fn trace_step(_step: &'static str) {
    #[cfg(any(test, feature = "test-support"))]
    RESTORE_TRACE.with(|t| t.borrow_mut().push(_step));
}

/// Opens the detached object for verification, claiming the operating system's exclusion of
/// writers where it can prove it (see `yadorilink_fs_platform::write_exclusion`).
#[cfg(not(windows))]
fn open_excluding_writers_for_eviction(
    q: &Path,
) -> std::io::Result<yadorilink_fs_platform::write_exclusion::WriteExclusion> {
    #[cfg(any(test, feature = "test-support"))]
    if ASSUME_EXCLUSION.with(std::cell::Cell::get) {
        return Ok(yadorilink_fs_platform::write_exclusion::WriteExclusion::assumed(
            std::fs::File::open(q)?,
        ));
    }
    yadorilink_fs_platform::write_exclusion::open_excluding_writers(q)
}

/// The held object's bytes match the approved blocks, read through the handle itself.
#[cfg(not(windows))]
fn verify_through_handle(
    file: &std::fs::File,
    blocks: &[yadorilink_replica_domain::file::BlockInfo],
) -> bool {
    use std::io::Seek;
    let Ok(mut handle) = file.try_clone() else { return false };
    handle.rewind().is_ok()
        && matches!(
            yadorilink_local_storage::file_content_comparison(&mut handle, blocks),
            Ok(yadorilink_local_storage::DiskContentComparison::Matched)
        )
}

// Test-only: stands in for a platform that grants the exclusion, so the unlink path runs on a
// host (macOS) that never grants it.
#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static ASSUME_EXCLUSION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static PRE_UNLINK_HOOK: std::cell::RefCell<Option<PreRemovalHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Makes eviction on this thread behave as if the platform granted the write exclusion, until
/// the returned guard is dropped.
#[cfg(any(test, feature = "test-support"))]
pub fn assume_write_exclusion_for_test() -> AssumedExclusionGuardForTest {
    ASSUME_EXCLUSION.with(|c| c.set(true));
    AssumedExclusionGuardForTest(())
}

/// Ends the assumption made by [`assume_write_exclusion_for_test`] on drop.
#[cfg(any(test, feature = "test-support"))]
pub struct AssumedExclusionGuardForTest(());

#[cfg(any(test, feature = "test-support"))]
impl Drop for AssumedExclusionGuardForTest {
    fn drop(&mut self) {
        ASSUME_EXCLUSION.with(|c| c.set(false));
    }
}

/// Runs `hook` with the detached object's path between its verification and its unlink, until
/// the returned guard is dropped.
#[cfg(any(test, feature = "test-support"))]
pub fn set_pre_unlink_hook_for_test(
    hook: impl FnMut(&Path) + 'static,
) -> PreUnlinkHookGuardForTest {
    PRE_UNLINK_HOOK.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
    PreUnlinkHookGuardForTest(())
}

/// Clears the hook installed by [`set_pre_unlink_hook_for_test`] on drop.
#[cfg(any(test, feature = "test-support"))]
pub struct PreUnlinkHookGuardForTest(());

#[cfg(any(test, feature = "test-support"))]
impl Drop for PreUnlinkHookGuardForTest {
    fn drop(&mut self) {
        PRE_UNLINK_HOOK.with(|slot| slot.borrow_mut().take());
    }
}

#[cfg(not(windows))]
fn fire_pre_unlink_hook(_q: &Path) {
    #[cfg(any(test, feature = "test-support"))]
    PRE_UNLINK_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(_q);
        }
    });
}

#[cfg(not(windows))]
fn fire_pre_removal_hook(_out_path: &Path) {
    #[cfg(any(test, feature = "test-support"))]
    PRE_REMOVAL_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook(_out_path);
        }
    });
}

/// Removes the present object at `out_path` so its row can become `Remote`.
///
/// Without a native provider: the object is removed outright, so nothing
/// stands in the user tree for the evicted file; the caller has just verified
/// byte for byte that what is removed is the version being evicted.
///
/// Windows: the object is a CfAPI placeholder this device created, and
/// `CfDehydratePlaceholder` keeps its `FileIdentity`, so the identity ALREADY
/// recorded for this row is read before dehydration, the native dehydrate is
/// confirmed through `MaterializationExecutionPort::dehydrate_windows_
/// placeholder`, and the same identity is re-affirmed. Minting a fresh
/// generation here would record an identity that no longer matches what is
/// on disk. With no identity recorded there is no provider object to
/// dehydrate, and the eviction fails closed (`EvictionRejected`) rather than
/// leave a `Remote` row over a fully materialized file; the caller rolls the
/// row back to `Present`.
///
/// Commit order on Windows is `Evicting -> native dehydrate confirmed ->
/// Remote -> identity re-affirmed -> blocks reclaimed`: safe only because the
/// value the returned outcome carries is READ before dehydration and never
/// changes, so there is no window where the row reads `Remote` with a wrong
/// or absent identity.
fn evict_to_remote(
    state: &dyn MaterializationExecutionPort,
    group_id: &str,
    path: &str,
    out_path: &Path,
    root: &Path,
    approved: &ApprovedObject<'_>,
) -> Result<Removal, MaterializationExecutionError> {
    #[cfg(windows)]
    {
        let _ = (root, approved);
        let recorded = state.get_recorded_placeholder_identity(group_id, path)?;
        let Some((identity, provider_kind)) = recorded else {
            return Err(MaterializationExecutionError::EvictionRejected(format!(
                "{path} has no recorded Windows placeholder identity to dehydrate; refusing to \
                 evict rather than strand a Remote row with no real placeholder object \
                 underneath it"
            )));
        };
        if provider_kind != yadorilink_local_storage::WINDOWS_CFAPI_GENERATION_PROVIDER_KIND {
            return Err(MaterializationExecutionError::EvictionRejected(format!(
                "{path}'s recorded placeholder identity is provider {provider_kind:?}, not \
                 {:?}; refusing to evict",
                yadorilink_local_storage::WINDOWS_CFAPI_GENERATION_PROVIDER_KIND
            )));
        }
        state.dehydrate_windows_placeholder(path, out_path, identity.ino)?;
        // Identity is unchanged by dehydration -- re-affirmed, not
        // replaced, since `CfDehydratePlaceholder` never reassigns
        // `FileIdentity`.
        Ok(Removal::Removed(
            yadorilink_local_storage::PlaceholderIdentityToRecord::RecordOverwrite {
                identity,
                provider_kind: yadorilink_local_storage::WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
            },
        ))
    }
    #[cfg(not(windows))]
    {
        fire_pre_removal_hook(out_path);
        // Detach first, then look: a path-based unlink would destroy whatever
        // is at the path at that instant, and an editor can save between the
        // last check and the unlink. A rename moves exactly the object that
        // has the name, so what is deleted is exactly what is examined.
        let q = eviction_quarantine_path(out_path, path)?;
        // Never replacing: whatever already has the quarantine name (a
        // leftover of a crashed eviction, or a user's file) is recovered
        // first, as a conflict copy because the path is occupied, and the
        // rename is tried once more. Still taken: fail closed.
        let mut attempts = 0;
        loop {
            match yadorilink_local_storage::rename_no_replace(out_path, &q) {
                Ok(()) => break,
                // Something else removed it first: not this eviction's removal.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Removal::Competing)
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempts == 0 => {
                    attempts += 1;
                    recover_eviction_quarantine(state, root, group_id, path)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(MaterializationExecutionError::EvictionRejected(format!(
                        "{path}: its quarantine name is occupied"
                    )))
                }
                Err(e) => return Err(e.into()),
            }
        }
        trace_step("detached");
        // The detach is durable before anything is decided about the object:
        // a crash from here leaves it under one of the two names.
        if let Err(error) = directory_barrier(out_path) {
            if let Err(restore_error) = restore_detached(state, root, group_id, path, &q, out_path)
            {
                return Ok(Removal::Unconfirmed(restore_error));
            }
            return Err(error);
        }
        // The object is unlinked only while the operating system guarantees that no program can
        // write to it. A program that opened the file before the rename above still writes the
        // same object through its handle, and no check by name or by content fences it: it can
        // write after any check and after the unlink, and the unlink would make those bytes
        // unreachable. Without the guarantee (another program holds the file open, or the
        // platform has no such primitive) the object is not unlinked: it goes back to its path,
        // where the handle's writes stay reachable and the row stays `Present`.
        let held = match open_excluding_writers_for_eviction(&q) {
            Ok(held) => held,
            Err(error) => {
                if let Err(restore_error) =
                    restore_detached(state, root, group_id, path, &q, out_path)
                {
                    return Ok(Removal::Unconfirmed(restore_error));
                }
                return Err(error.into());
            }
        };
        let approved_object = approved.matches_handle(&held.file)
            && verify_through_handle(&held.file, approved.blocks);
        if !approved_object {
            if let Err(restore_error) = restore_detached(state, root, group_id, path, &q, out_path)
            {
                return Ok(Removal::Unconfirmed(restore_error));
            }
            return Ok(Removal::Diverged);
        }
        trace_step("verified");
        fire_pre_unlink_hook(&q);
        if !held.still_excludes_writers().unwrap_or(false) {
            if let Err(restore_error) = restore_detached(state, root, group_id, path, &q, out_path)
            {
                return Ok(Removal::Unconfirmed(restore_error));
            }
            return Ok(Removal::WriterMayExist);
        }
        // The name still leads to the verified object: the unlink is by name.
        if !approved.matches(&q) {
            if let Err(restore_error) = restore_detached(state, root, group_id, path, &q, out_path)
            {
                return Ok(Removal::Unconfirmed(restore_error));
            }
            return Ok(Removal::Diverged);
        }
        match std::fs::remove_file(&q) {
            Ok(()) => {}
            Err(error) => {
                if let Err(restore_error) =
                    restore_detached(state, root, group_id, path, &q, out_path)
                {
                    return Ok(Removal::Unconfirmed(restore_error));
                }
                return Err(error.into());
            }
        }
        drop(held);
        trace_step("unlinked");
        // Nothing settles `Remote` and no block is reclaimed until the unlink
        // is durable: a crash could otherwise bring the object back under its
        // quarantine name while the row already says `Remote`. A failed sync
        // leaves the row `Evicting` and returns the error; startup re-decides
        // (the object back under the quarantine name -> restored; absent ->
        // `Remote`).
        if let Err(error) = directory_barrier(out_path) {
            return Ok(Removal::Unconfirmed(error));
        }
        Ok(Removal::Removed(yadorilink_local_storage::PlaceholderIdentityToRecord::Clear))
    }
}

/// What eviction found when it removed the object.
enum Removal {
    /// This eviction removed the object it had approved.
    Removed(yadorilink_local_storage::PlaceholderIdentityToRecord),
    /// The object was unlinked but the unlink could not be made durable, or it was detached and
    /// could not be put back. Either way the row stays `Evicting` so startup recovery decides
    /// from where the object is.
    #[cfg(not(windows))]
    Unconfirmed(MaterializationExecutionError),
    /// The object was already gone: a competing removal, not this eviction's.
    #[cfg(not(windows))]
    Competing,
    /// The object that was detached is not the one that was approved (a save
    /// landed in between); it has been put back, or kept as a recoverable
    /// copy, untouched.
    #[cfg(not(windows))]
    Diverged,
    /// The operating system could not guarantee that no program holds the object open for
    /// writing, so it was not unlinked: it has been put back, or kept as a recoverable copy,
    /// untouched. Its content may differ from the approved one by now.
    #[cfg(not(windows))]
    WriterMayExist,
}

/// The object eviction approved by its last check: which file it was and
/// which bytes it held.
struct ApprovedObject<'a> {
    #[cfg(unix)]
    inode: Option<(u64, u64)>,
    // Only the detach-and-verify removal reads the bytes; the Windows dehydration does not.
    #[cfg_attr(windows, allow(dead_code))]
    blocks: &'a [yadorilink_replica_domain::file::BlockInfo],
}

impl<'a> ApprovedObject<'a> {
    fn observe(_path: &Path, blocks: &'a [yadorilink_replica_domain::file::BlockInfo]) -> Self {
        Self {
            #[cfg(unix)]
            inode: Self::inode_of(_path),
            blocks,
        }
    }

    #[cfg(unix)]
    fn inode_of(path: &Path) -> Option<(u64, u64)> {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path).ok().map(|m| (m.dev(), m.ino()))
    }

    #[cfg(unix)]
    fn matches(&self, detached: &Path) -> bool {
        self.inode.is_some() && Self::inode_of(detached) == self.inode
    }

    #[cfg(unix)]
    fn matches_handle(&self, file: &std::fs::File) -> bool {
        use std::os::unix::fs::MetadataExt;
        let by_handle = file.metadata().ok().filter(|m| m.is_file()).map(|m| (m.dev(), m.ino()));
        self.inode.is_some() && by_handle == self.inode
    }
}

/// What one [`evict_file`] call did. The materialized file is always reduced
/// to a placeholder; whether its cached blocks were reclaimed (freeing real
/// space) depends on full-replica custody, and never happens on a full
/// replica.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EvictionOutcome {
    /// Cached blocks deleted from the block store.
    pub blocks_reclaimed: u64,
    /// Bytes freed by reclaiming those blocks.
    pub bytes_reclaimed: u64,
    /// The file became a placeholder but its blocks were retained (custody
    /// unconfirmed, this is a full replica, or the blocks still back other
    /// locally hydrated content) rather than freed.
    pub blocks_retained: bool,
    /// The on-disk file was reduced to a placeholder — the materialized
    /// working-tree copy was freed. `false` means this call left the file
    /// materialized (an early-return path: no longer current, not
    /// `Present`, path dirty, or its on-disk identity changed), so it freed
    /// no working-tree bytes.
    pub dehydrated: bool,
}

/// The handles a materialization/eviction operation needs: the index, the
/// block-liveness gate, the block store, and the linked folder's local root.
/// Taken by [`evict_file`].
pub struct MaterializationContext<'a> {
    pub state: &'a dyn MaterializationExecutionPort,
    pub liveness_gate: &'a BlockLivenessGate,
    // Narrowed to the reclamation surface: `evict_file` only ever forwards
    // `store` into `MaterializationExecutionPort::
    // reclaim_cached_blocks`, never calls a content method
    // (`put`/`get`/`present_blocks`) on it directly.
    pub store: &'a dyn BlockReclamationStore,
    pub root: &'a Path,
    /// Minted from the caller's per-link root authority (the daemon's
    /// operation fence + root-identity check); re-verified by every state
    /// mutation this module makes, immediately before its commit. See
    /// `root_commit::RootCommitPermit`'s own doc.
    pub permit: &'a RootCommitPermit<'a>,
}

/// The most placeholders sharing an evicted file's blocks that one eviction asks custody for.
const MAX_CUSTODIED_SIBLINGS: usize = 16;

/// Exact-version custody for the reclaim decision. Only this crate's own unit
/// tests use the custody bypass; downstream crates always get the real
/// fails-closed verifier.
fn verify_custody<'a>(
    custody: &'a dyn FullReplicaCustody,
    store: &dyn BlockReclamationStore,
    root: &Path,
    group_id: &str,
    path: &str,
    version: &yadorilink_replica_domain::file::FileVersion,
) -> Option<yadorilink_replica_engine::custody::VerifiedCustody<'a>> {
    #[cfg(any(test, feature = "test-support"))]
    CUSTODY_PROBE.with(|slot| {
        if let Some(probe) = slot.borrow_mut().as_mut() {
            probe();
        }
    });
    #[cfg(test)]
    {
        let _ = (root, store);
        yadorilink_replica_engine::custody::verify_reclaim_custody_for_test(
            custody,
            group_id,
            path,
            &version.version_hash,
            &version.blocks,
        )
    }
    #[cfg(not(test))]
    {
        // Same Windows gate as the provider reclaim, and per volume: no byte deletion unless the
        // volume holding the deleted blocks (the block store's) and the linked folder's volume
        // both offer durable namespace changes (the global gate is part of the verdict).
        if !yadorilink_fs_platform::durable_dir::all_volumes_durable(
            volume_durable,
            &[store.storage_root(), Some(root)],
        ) {
            return None;
        }
        yadorilink_replica_engine::custody::verify_reclaim_custody(
            custody,
            group_id,
            path,
            &version.version_hash,
            &version.blocks,
        )
    }
}

/// Other placeholders sharing the evicted file's blocks were evicted while a hydrated referrer
/// (maybe this very file) still needed them, so they kept the blocks and nothing revisits them:
/// without this, the last of several identical files frees nothing and a sweep cannot either,
/// since a current row roots its blocks. Asks custody for each such sibling too, under its
/// own path lock (returned, held while the confirmations are taken so the hold reconciler cannot
/// release what was just confirmed). A sibling that is busy, over the cap or unconfirmed
/// simply stays a reference.
#[allow(clippy::type_complexity)]
fn confirm_sibling_custody<'a>(
    state: &dyn MaterializationExecutionPort,
    custody: &'a dyn FullReplicaCustody,
    store: &dyn BlockReclamationStore,
    root: &Path,
    group_id: &str,
    path: &str,
    version: &yadorilink_replica_domain::file::FileVersion,
) -> Result<
    (
        Vec<yadorilink_replica_engine::custody::VerifiedCustody<'a>>,
        Vec<tokio::sync::OwnedMutexGuard<()>>,
    ),
    MaterializationExecutionError,
> {
    let mut verified = Vec::new();
    let mut guards = Vec::new();
    for (sibling_group, sibling_path, sibling_version) in
        state.remote_siblings_sharing_blocks(group_id, path, &version.blocks)?
    {
        if verified.len() >= MAX_CUSTODIED_SIBLINGS {
            break;
        }
        let Ok(guard) = state.path_lock(&sibling_group, &sibling_path).try_lock_owned() else {
            continue;
        };
        if let Some(sibling) =
            verify_custody(custody, store, root, &sibling_group, &sibling_path, &sibling_version)
        {
            verified.push(sibling);
            guards.push(guard);
        }
    }
    Ok((verified, guards))
}

/// Evicts one hydrated file back to a placeholder and, on an on-demand
/// device, reclaims its now-cached blocks from the block store to free real
/// disk space — the sync state (version, block list) is untouched.
///
/// Block reclamation is gated fail-closed by two rules:
/// - `is_full_replica`: a full replica is the group's durable holder and MUST
///   NOT drop live blocks, so it never reclaims — the file is placeholdered
///   but every block is kept.
/// - `custody`: an on-demand device deletes a block only once a full replica
///   is confirmed to hold it. When custody is unconfirmed (e.g. a brand-new
///   local edit no full replica has yet), the file may still become a
///   placeholder but its blocks are retained, so this device is never the
///   sole holder of content.
///
/// Even when custody is confirmed, only blocks that no longer back any
/// locally hydrated file are freed; a block still shared with such
/// a file is kept so its bytes stay materializable on disk.
///
/// Custody is confirmed under the path lock (see the comment at the call), so
/// the requester's hold on the leased version cannot be released from under an
/// eviction that relies on it.
///
/// Physical reclamation is currently fail-closed in production: until a
/// responder that loses its full-replica role hands its leases off, a manual
/// eviction writes the placeholder but retains every local block. A
/// VersionPresent acknowledgement alone is instantaneous and cannot authorize
/// deleting the requester's last recoverable copy.
///
/// Index update happens before the disk write, same discipline as
/// `PeerSyncSession::materialize` and for the same reason: this device's
/// own watcher would otherwise race the state transition (see
/// `local_change::process_event`'s placeholder-aware self-echo
/// suppression, which only works if the index already says `Remote`
/// by the time the watcher processes the resulting filesystem event).
pub fn evict_file(
    ctx: MaterializationContext<'_>,
    group_id: &str,
    path: &str,
    is_full_replica: bool,
    custody: &dyn FullReplicaCustody,
) -> Result<EvictionOutcome, MaterializationExecutionError> {
    let MaterializationContext { state, liveness_gate, store, root, permit } = ctx;
    let reference_write = liveness_gate.begin_reference_write();
    state.verify_root(root, group_id)?;
    // One snapshot-shaped read replacing the unconditional pre-lock CRUD
    // reads (`get_current_version_record`/`get_record_kind`) this function
    // used to make individually — see
    // `MaterializationExecutionPort::eviction_eligibility_snapshot`'s doc
    // comment for why this changes nothing about consistency, only call
    // count.
    let eligibility = state.eviction_eligibility_snapshot(group_id, path)?;
    // Read the current row's blocks AND metadata as ONE atomic snapshot, so
    // the `change::VersionHash` the custody query carries describes a version
    // some single row actually held — never a hybrid stitched across
    // separate `get_file` + metadata reads that a concurrent transition could
    // tear apart.
    let Some(record) = eligibility.current_version else {
        return Err(MaterializationExecutionError::NotFound(format!("file {group_id}/{path}")));
    };
    if record.deleted {
        return Err(MaterializationExecutionError::NotFound(format!("file {group_id}/{path}")));
    }
    if eligibility.record_kind.unwrap_or_default() != RecordKind::File {
        return Err(MaterializationExecutionError::EvictionRejected(format!(
            "{path} is not a regular file and cannot be represented by a placeholder"
        )));
    }
    // The exact version being evicted, pinned up front. Custody below is
    // confirmed for *this* version, and the deletion coordinator later
    // rechecks that exact version before deriving the reclaimable hashes.
    let evicting_version = record.to_file_version();
    let out_path = root.join(path);
    // defense-in-depth — see `verify_write_target_within_root`'s
    // doc comment; applied here too for consistency with the other
    // materialization write paths, even though eviction writes through an
    // already-indexed path rather than fresh peer input.
    verify_write_target_within_root(
        &out_path,
        root,
        &crate::materialization_execution::GroupStructuralLedger::new(state, group_id),
    )?;
    let initial_disk_identity = disk_identity(&out_path)?;
    let approved_object = ApprovedObject::observe(&out_path, &record.blocks);
    let path_lock = state.path_lock(group_id, path);
    let _path_guard = path_lock
        .try_lock()
        .map_err(|_| MaterializationExecutionError::EvictionRejected(format!("{path} is busy")))?;
    // One snapshot-shaped read replacing the four separate CRUD re-checks
    // this function used to make individually, immediately after acquiring
    // the lock — this IS the "permit/lease re-verification point" the
    // module's behavioral invariants pin in place; grouping the reads does
    // not move it. See `MaterializationExecutionPort::eviction_revalidation_snapshot`.
    let revalidation = state.eviction_revalidation_snapshot(group_id, path)?;
    // A pin is the user's standing request to keep the bytes here, checked at the commit point
    // (a read that failed already returned above: an unknown policy never frees anything).
    if revalidation.pinned {
        return Err(MaterializationExecutionError::EvictionRejected(format!(
            "{path} is kept on this device; stop keeping it first to free up its space"
        )));
    }
    let still_current = revalidation.current_version.is_some_and(|current| {
        !current.deleted && current.to_file_version().version_hash == evicting_version.version_hash
    });
    if !still_current
        || revalidation.materialization_state != Some(MaterializationState::Present)
        || revalidation.path_dirty
        || disk_identity(&out_path)? != initial_disk_identity
        || !disk_bytes_match_indexed_blocks(&out_path, &record.blocks)?
    {
        // Bail out before writing the placeholder: the file is left fully
        // materialized, so `dehydrated` stays `false` (the default): nothing
        // was freed.
        return Ok(EvictionOutcome { blocks_retained: true, ..Default::default() });
    }

    // Custody is confirmed HERE, under the path lock and after the
    // revalidation above, never before the lock: the confirmation commits a
    // hold on the version about to be reclaimed, and the one reconciler that
    // releases holds takes this same lock, so it can never release a lease an
    // in-flight eviction is about to rely on. The lock is held across one
    // bounded round trip. A full replica never reclaims, so it never asks.
    let verified_custody = (!is_full_replica)
        .then(|| verify_custody(custody, store, root, group_id, path, &evicting_version))
        .flatten();

    // The working-tree bytes are removed (Windows: dehydrated) below whatever the custody says,
    // so the sync root's own volume must be known durable too; otherwise nothing is touched.
    if !volume_durable(Some(root)) {
        return Ok(EvictionOutcome { blocks_retained: true, ..Default::default() });
    }

    // Every check that does NOT touch the file runs BEFORE the row enters
    // the transient `Evicting` state. This ordering is load-bearing, not
    // tidiness: the disk revalidation below is exactly how a concurrent
    // external edit is detected, and detecting one means this attempt has
    // changed nothing at all -- no fence bump, no write, the existing
    // actual-state generation still valid. Returning from here leaves the
    // row `Present` with that proof intact, which is the truth.
    //
    // Rejecting from INSIDE `Evicting` and then rolling forward to
    // `Remote` is a data-loss race: the rejected file is the user's
    // freshly edited content, `path_lock` kept the watcher from capturing
    // the edit, and once this releases the lock a `hydrate` that wins the
    // race against the queued watcher event sees a `Remote` row whose
    // on-disk bytes are stable, satisfies its own commit check, and
    // reconstructs the indexed blocks straight over the edit.
    state.verify_root(root, group_id)?;
    verify_write_target_within_root(
        &out_path,
        root,
        &crate::materialization_execution::GroupStructuralLedger::new(state, group_id),
    )?;
    if disk_identity(&out_path)? != initial_disk_identity
        || !disk_bytes_match_indexed_blocks(&out_path, &record.blocks)?
    {
        return Err(MaterializationExecutionError::EvictionRejected(format!(
            "{path} changed before placeholder commit"
        )));
    }

    // `Evicting` (a failure here fails the eviction with nothing else
    // touched), then the fence bump for the physical write below. The
    // bump's own result comes back unpropagated: it is chained into the
    // placeholder write and handled as that write's failure. From here on
    // every failure closes the row with `abandon_eviction` rather than
    // leave it `Evicting`.
    let eviction_fence = state.open_eviction(group_id, path, permit)?;
    let placeholder_result: Result<Removal, MaterializationExecutionError> = {
        // The mutator's own physical write (hydrated content ->
        // placeholder) -- bumped before it, inside `path_lock` (held by
        // `_path_guard` for this whole function). No frontier proof to
        // publish under here, so this only ever invalidates. Everything
        // after this point has touched, or may have touched, the file.
        eviction_fence
            .and_then(|_| evict_to_remote(state, group_id, path, &out_path, root, &approved_object))
    };
    let placeholder_outcome = match placeholder_result {
        Ok(Removal::Removed(outcome)) => outcome,
        // The row stays `Evicting` (not rolled back, not settled).
        #[cfg(not(windows))]
        Ok(Removal::Unconfirmed(error)) => return Err(error),
        #[cfg(not(windows))]
        Ok(not_removed @ (Removal::Competing | Removal::Diverged | Removal::WriterMayExist)) => {
            // (`Unconfirmed` returned above.)
            // Nothing of this eviction's was removed. The row goes back to
            // `Present` (no proof: the fence was bumped), and what happened
            // to the object is journaled for capture: a competing removal
            // stays delete evidence, a save stays an edit.
            let kind = match not_removed {
                Removal::Competing => "removed",
                // A held object may have been written through its handle: capture re-reads it.
                _ => "created_or_modified",
            };
            abandon_failed_eviction(
                state,
                group_id,
                path,
                &evicting_version.version_hash,
                AbandonedEviction::NotWritten,
                permit,
            )?;
            let observed_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(0);
            state.record_dirty_path(group_id, path, kind, observed_at, permit)?;
            return Ok(EvictionOutcome { blocks_retained: true, ..Default::default() });
        }
        Err(MaterializationExecutionError::EvictionOutcomeAmbiguous(reason)) => {
            // Unlike every other error
            // here, this one does NOT mean "the file is still fully
            // materialized" -- the native dehydrate call's outcome could
            // not be confirmed (see the variant's own doc comment), so it
            // may have already succeeded on disk. Rolling back to
            // `Present` here would be actively wrong in that case (a
            // dehydrated placeholder mislabeled `Present`, no longer
            // reconciled by anything). Resolve it to `Remote` now, as
            // `reset_stale_evicting`'s startup recovery
            // would, which is safe regardless of which outcome actually
            // happened (Windows eviction never mints a fresh identity, so the already-recorded one
            // stays correct either
            // way).
            tracing::warn!(
                group_id,
                path = %path,
                reason = %reason,
                "eviction dehydrate outcome unconfirmed; resolving the row to Placeholder, as \
                 startup recovery would, rather than assuming Hydrated"
            );
            abandon_failed_eviction(
                state,
                group_id,
                path,
                &evicting_version.version_hash,
                AbandonedEviction::PlaceholderMayExist,
                permit,
            )?;
            return Err(MaterializationExecutionError::EvictionOutcomeAmbiguous(reason));
        }
        Err(error) => {
            // Everything reachable here is POST fence bump (or the bump
            // itself failed), and no placeholder was published: the
            // Windows arm reports a dehydrate that may have happened as
            // the ambiguous variant above, and the non-Windows write fails
            // only before its rename. So the path still holds whatever it
            // held before the write, and the row goes back to `Present`,
            // its entry state -- with a fresh proof when the bytes still
            // verify as the version revalidated above (the bump
            // invalidated the old one), without one when a local edit or
            // removal landed meanwhile, which the watcher and the
            // dirty-path journal then capture. Leaving it `Evicting`
            // stranded it until the next daemon start.
            tracing::warn!(
                group_id,
                path = %path,
                error = %error,
                "placeholder write failed after the eviction opened; returning the row to \
                 Hydrated"
            );
            let intact = disk_identity(&out_path).ok() == Some(initial_disk_identity)
                && disk_bytes_match_indexed_blocks(&out_path, &record.blocks).unwrap_or(false);
            let abandoned = match intact
                .then(|| {
                    yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(&out_path).ok()
                })
                .flatten()
            {
                Some(identity) => AbandonedEviction::Intact { identity },
                None => AbandonedEviction::NotWritten,
            };
            abandon_failed_eviction(
                state,
                group_id,
                path,
                &evicting_version.version_hash,
                abandoned,
                permit,
            )?;
            return Err(error);
        }
    };
    // `Evicting` -> `Remote` only if the row is still `Evicting`,
    // then the placeholder's identity. The placeholder is on disk by now,
    // so a failed settle resolves the row to `Remote` rather than
    // leave it `Evicting`.
    let settled = match state.settle_eviction(group_id, path, placeholder_outcome, permit) {
        Ok(settled) => settled,
        Err(error) => {
            abandon_failed_eviction(
                state,
                group_id,
                path,
                &evicting_version.version_hash,
                AbandonedEviction::PlaceholderMayExist,
                permit,
            )?;
            return Err(error);
        }
    };
    if !settled {
        return Ok(EvictionOutcome {
            blocks_retained: true,
            dehydrated: true,
            ..Default::default()
        });
    }

    // A full replica never drops live blocks; an on-demand device reclaims
    // only after a full replica is confirmed to hold this exact version. Either
    // way, fail closed to retaining the blocks.
    let Some(verified_custody) = verified_custody else {
        return Ok(EvictionOutcome {
            blocks_retained: true,
            dehydrated: true,
            ..Default::default()
        });
    };

    let (sibling_custody, _sibling_guards) =
        confirm_sibling_custody(state, custody, store, root, group_id, path, &evicting_version)?;

    // Upgrade from the shared reference-write phase to an exclusive physical
    // deletion phase. The coordinator revalidates the exact version and all
    // cross-group references only after exclusivity is established.
    //
    // The path lock is released first: a reference writer (a local-change flush, a hydration) can
    // hold its write while it waits for that lock, and waiting for the writers with the lock held
    // would deadlock the two. Nothing is lost by letting go: the coordinator revalidates, under
    // the exclusive guard, that the path is still `Remote` at this exact version and that the
    // custody is still valid, and refuses (keeping every block) otherwise.
    //
    // The sibling locks go for the same reason: a writer holding its reference write may be
    // waiting for one of them, and the coordinator revalidates each sibling's version, state,
    // pin and custody under the exclusive guard just as it does for this file.
    drop(_path_guard);
    drop(_sibling_guards);
    drop(reference_write);
    let physical_deletion = liveness_gate.begin_physical_deletion();
    let report = state.reclaim_verified_cached_blocks(
        &physical_deletion,
        verified_custody,
        sibling_custody,
        store,
    )?;
    if report.blocks_deleted == 0 {
        return Ok(EvictionOutcome {
            blocks_retained: true,
            dehydrated: true,
            ..Default::default()
        });
    }
    Ok(EvictionOutcome {
        blocks_reclaimed: report.blocks_deleted,
        bytes_reclaimed: report.bytes_reclaimed,
        blocks_retained: false,
        dehydrated: true,
    })
}

/// Runs `abandon_eviction` for an eviction that failed after it opened.
///
/// A failure of its own that belongs to this path is logged and dropped:
/// the caller then returns the eviction's error, and a row this leaves
/// `Evicting` is still resolved by the startup reset. Any other failure
/// (the database refused, the root was lost) is returned, and the caller
/// returns it in place of its own path-local error.
fn abandon_failed_eviction(
    state: &dyn MaterializationExecutionPort,
    group_id: &str,
    path: &str,
    version: &yadorilink_replica_domain::ids::VersionHash,
    abandoned: AbandonedEviction,
    permit: &RootCommitPermit<'_>,
) -> Result<(), MaterializationExecutionError> {
    match state.abandon_eviction(group_id, path, version, abandoned, permit) {
        Ok(true) => {}
        Ok(false) => tracing::debug!(
            group_id,
            path = %path,
            "a failed eviction's row had already left Evicting; nothing to abandon"
        ),
        Err(error) if error.is_path_local() => tracing::warn!(
            group_id,
            path = %path,
            error = %error,
            "could not resolve a failed eviction's row; it stays Evicting until the startup reset"
        ),
        Err(error) => return Err(error),
    }
    Ok(())
}
