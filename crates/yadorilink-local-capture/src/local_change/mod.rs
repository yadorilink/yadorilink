//! Bridges a raw filesystem event into an indexed,
//! chunked `FileRecord`. Local changes are always
//! indexed immediately regardless of the link's pause state — pausing
//! only stops *propagating* changes to peers, so nothing is
//! lost while paused; the local index itself is the queued-change backlog.
//!
//! The property that renaming a file doesn't re-transfer content falls out of this
//! design for free: chunking is content-addressed, so renaming a file
//! without editing it re-derives the exact same block hashes the local
//! store (and any peer that already synced the old path) already holds —
//! `ensure_blocks_present`'s dedup check means no bytes cross the network
//! for the unchanged content, even though the wire protocol has no
//! dedicated "rename" message.

use std::path::Path;
use std::sync::Arc;

use crate::error::LocalCaptureError;
use crate::reconcile_gate::ReconcileGate;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_sync_sqlite::dag_store::LocalAuthorKey;

mod directory_capture;
mod dirty_journal;
mod disk_observation;
mod event_ingest;
mod flush;
mod path_policy;
mod paused_items;
mod record_builder;
mod scan;
mod semantic_delete;

pub use disk_observation::cfapi_placeholder_untouched;
pub(crate) use scan::ReconcileMode;
pub use semantic_delete::SemanticDelete;

#[cfg(any(test, feature = "test-support"))]
pub use record_builder::{
    arm_content_read_race_hook, arm_post_capture_race_hook, arm_post_identity_race_hook,
    disarm_content_read_race_hook, disarm_post_capture_race_hook, disarm_post_identity_race_hook,
};

// The in-module tests below reach helpers from every submodule through
// `use super::*`.
#[cfg(all(test, unix))]
use self::path_policy::*;
#[cfg(test)]
use self::{
    dirty_journal::*, disk_observation::*, event_ingest::*, flush::*, record_builder::*, scan::*,
};

/// Same shape as this crate's other private `now_unix_nanos` helpers —
/// the default `process_event_with_ignore_at`'s `Removed` branch falls
/// back to when the caller has no better (debounce-observed) timestamp
/// to supply.
fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// What one filesystem event turned out to mean, once interpreted —
/// `process_event`'s result.
#[derive(Debug, Clone, PartialEq)]
pub enum LocalChangeOutcome {
    /// Nothing worth acting on: a directory event, a file that vanished
    /// again before it could be read, a placeholder's own write, or
    /// content that hashed identical to what was already indexed.
    None,
    /// An ordinary file was created, modified, or deleted.
    FileChanged(FileRecord),
    /// A `Removed` event for a directory (a path whose row is an explicit
    /// directory, or that has no row of its own) deleted the entries this
    /// device had observed in it: the directory's own entry if it had
    /// one, and every live entry below it that was on disk here (`path`
    /// was deleted, or renamed away, and no individual event arrives for
    /// what was inside it -- see `watcher.rs`'s `RenameMode::From`
    /// handling). Each is reported here so the caller broadcasts all of
    /// them, not just one.
    FilesChanged(Vec<FileRecord>),
    /// The file changed while it was being read, so this pass has no
    /// consistent record to build: nothing was indexed or emitted, and the
    /// path is left journaled dirty for a later pass. Not a no-op -- the
    /// path holds a local edit this device has not captured yet, and a
    /// caller about to write to it must treat it as unsettled.
    ///
    /// There is no bound on how often this repeats: a file written
    /// continuously (a live database, a VM image) is not captured until
    /// one full read sees no write, and until then a remote change to the
    /// path is deferred. Each such pass also leaves the blocks it put in
    /// the store unreferenced until garbage collection. A torn capture
    /// would sync bytes no one ever wrote, so this is the chosen trade-off,
    /// not an oversight.
    RetryLater,
}

/// The mode and replicated attributes a path's current row records, and
/// whether that row is live: what [`LocalChangeProcessor::captured_unix_mode`]
/// inherits where the platform cannot observe them.
pub(super) struct Predecessor {
    pub(super) unix_mode: Option<u32>,
    pub(super) xattrs: Vec<(String, Vec<u8>)>,
    live: bool,
}

impl Predecessor {
    pub(super) fn of_row(row: Option<&yadorilink_sync_sqlite::CanonicalCurrentRow>) -> Self {
        match row {
            Some(row) => Self {
                unix_mode: row.snapshot.unix_mode,
                xattrs: row.snapshot.xattrs.clone(),
                live: !row.snapshot.deleted,
            },
            None => Self { unix_mode: None, xattrs: Vec::new(), live: false },
        }
    }

    fn inherited_unix_mode(&self) -> Option<u32> {
        self.live.then_some(self.unix_mode).flatten()
    }

    fn inherited_xattrs(&self) -> Vec<(String, Vec<u8>)> {
        if self.live {
            self.xattrs.clone()
        } else {
            Vec::new()
        }
    }
}

pub struct LocalChangeProcessor {
    state: Arc<dyn crate::ports::LocalMutationStore>,
    store: Arc<dyn crate::ports::BlockContentStore>,
    device_id: String,
    /// When set, every accepted local mutation additionally authors a signed
    /// delta into native state in the same transaction as its index write.
    /// `None` (the default) leaves the index write on its own, no delta is
    /// emitted — so a build that
    /// hasn't provisioned a signing key is unaffected. The daemon injects the
    /// emitter once the device's signing key is loaded.
    change_emitter: Option<Arc<LocalAuthorKey>>,
    /// Required, not optional (unlike `change_emitter`): every one of this
    /// processor's mutation methods admits a `LinkOperation` against this
    /// lease and mints a `RootCommitPermit` from it, held for that
    /// operation's own commit -- see `root_commit::RootLease`'s own doc.
    /// The daemon injects its per-link lease here; tests with no real link
    /// lifecycle use `root_commit::RootLease::for_tests()`.
    root_lease: Arc<yadorilink_root_authority::root_commit::RootLease>,
    /// One reconcile at a time for a given group, with anything requested
    /// meanwhile coalesced into a single fresh-snapshot rerun. Lives on the
    /// processor because the link's startup executor, its live flush loop
    /// and the periodic disk-reconcile backstop all hold the same
    /// `Arc<LocalChangeProcessor>` -- see `reconcile_gate`'s module doc.
    reconcile_gate: ReconcileGate,
    /// Whether this link authors directories a user made as explicit
    /// entries. Telling those apart from the directories this device made
    /// only to hold descendants takes the structural-origin ledger, which
    /// every directory the materializer creates is recorded in; a link
    /// whose placeholder backend creates directories without recording
    /// them must not author directories at all, or it would author those.
    /// On for every backend today; see [`Self::without_directory_capture`].
    directory_capture: bool,
    /// The `(group, path)`s a waiter is already queued to journal once
    /// their path lock frees (see `journal_uncaptured_once_unlocked`): one
    /// waiter per path, however many scans find the path busy meanwhile.
    deferred_journal_waiters: Arc<std::sync::Mutex<std::collections::HashSet<(String, String)>>>,
    /// The files this processor's scans could not read. Shared with whoever reports status.
    unreadable: Arc<crate::unreadable::UnreadableFileLedger>,
    /// Edits an accumulator handed to a requester whose dirty-journal commit failed: the
    /// accumulator no longer holds them, so this processor keeps them until a commit succeeds.
    /// See `journal_handed_over_edits` for the ownership invariant.
    retained_handoffs: std::sync::Mutex<Vec<dirty_journal::RetainedHandoff>>,
    /// Test-only: makes every disk observation report no unix mode, as a
    /// platform without permission bits (Windows) always does.
    #[cfg(test)]
    modes_unobservable: std::sync::atomic::AtomicBool,
}

impl LocalChangeProcessor {
    pub fn new(
        state: Arc<dyn crate::ports::LocalMutationStore>,
        store: Arc<dyn crate::ports::BlockContentStore>,
        device_id: String,
        root_lease: Arc<yadorilink_root_authority::root_commit::RootLease>,
    ) -> Self {
        Self {
            state,
            store,
            device_id,
            change_emitter: None,
            root_lease,
            reconcile_gate: ReconcileGate::default(),
            deferred_journal_waiters: Arc::default(),
            unreadable: Arc::default(),
            retained_handoffs: std::sync::Mutex::default(),
            directory_capture: true,
            #[cfg(test)]
            modes_unobservable: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Reports unreadable files into `ledger` (the daemon's, so status can read it) instead of a
    /// private one.
    #[must_use]
    pub fn with_unreadable_ledger(
        mut self,
        ledger: Arc<crate::unreadable::UnreadableFileLedger>,
    ) -> Self {
        self.unreadable = ledger;
        self
    }

    /// The files this processor could not read, for the status of a folder group.
    #[must_use]
    pub fn unreadable_ledger(&self) -> &Arc<crate::unreadable::UnreadableFileLedger> {
        &self.unreadable
    }

    /// The unix mode a disk object reports: none on a platform with no
    /// permission bits.
    fn observed_unix_mode(&self, metadata: &std::fs::Metadata) -> Option<u32> {
        #[cfg(test)]
        if self.modes_unobservable.load(std::sync::atomic::Ordering::Relaxed) {
            return None;
        }
        yadorilink_local_storage::unix_mode_from_metadata(metadata)
    }

    /// Whether this platform reports a file's unix mode at all.
    fn mode_observable(&self) -> bool {
        #[cfg(test)]
        if self.modes_unobservable.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
        cfg!(unix)
    }

    /// Whether a disk object's mode is still the one captured: always, where
    /// the platform cannot report it.
    pub(super) fn mode_unchanged_since(
        &self,
        now: &std::fs::Metadata,
        captured: Option<u32>,
    ) -> bool {
        !self.mode_observable() || self.observed_unix_mode(now) == captured
    }

    /// Whether this platform reports the replicated extended attributes at all.
    fn xattrs_observable(&self) -> bool {
        #[cfg(test)]
        if self.modes_unobservable.load(std::sync::atomic::Ordering::Relaxed) {
            return false;
        }
        cfg!(target_os = "linux")
    }

    /// THE rule for metadata capture: a field the platform can observe is what
    /// the disk shows; a field it cannot is inherited from the path's semantic
    /// predecessor (a live row), and is absent when there is none. Capturing
    /// "nothing observed" as "removed" would author a new version against the
    /// very version the file was written from, and strip a POSIX-origin file's
    /// mode and attributes on every edit made where they cannot be read.
    pub(super) fn captured_unix_mode(
        &self,
        metadata: &std::fs::Metadata,
        predecessor: &Predecessor,
    ) -> Option<u32> {
        if self.mode_observable() {
            self.observed_unix_mode(metadata)
        } else {
            predecessor.inherited_unix_mode()
        }
    }

    /// See [`Self::captured_unix_mode`].
    pub(super) fn captured_xattrs(
        &self,
        path: &Path,
        predecessor: &Predecessor,
    ) -> Vec<(String, Vec<u8>)> {
        if self.xattrs_observable() {
            std::fs::File::open(path)
                .map(|f| yadorilink_local_storage::read_replicated_xattrs(&f))
                .unwrap_or_default()
        } else {
            predecessor.inherited_xattrs()
        }
    }

    /// Test-only: from here on the disk reports no unix mode.
    #[cfg(test)]
    pub(crate) fn simulate_unobservable_modes(&self) {
        self.modes_unobservable.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Turns off authoring directories as entries, for a link whose
    /// backend creates directories the structural-origin ledger does not
    /// hear about. Deletions of directory entries still author: a directory
    /// that vanished is gone whoever made it.
    pub fn without_directory_capture(mut self) -> Self {
        self.directory_capture = false;
        self
    }

    /// Admits a fresh `LinkOperation` against this processor's lease --
    /// called immediately before every `LocalMutationStore` mutation this processor
    /// makes. The caller MUST hold the returned operation for at least the
    /// duration of the specific write/commit it is admitting (Rust's own
    /// temporary-lifetime rules do this automatically for the common
    /// `&self.begin_operation()?.permit()` call-argument shape), and should
    /// hold it across any preceding same-call filesystem work whenever that
    /// work is in the same function -- see `root_commit::RootLease`'s own
    /// doc for why a momentary, immediately-dropped admission is not
    /// sufficient on its own.
    fn begin_operation(
        &self,
    ) -> Result<yadorilink_root_authority::root_commit::LinkOperation<'_>, LocalCaptureError> {
        Ok(self.root_lease.begin_operation()?)
    }

    /// See [`yadorilink_root_authority::root_commit::RootLease::hold_blocking_work`]: for a
    /// caller that runs this processor on the blocking pool, where aborting the awaiting task
    /// does not stop the work.
    pub fn hold_blocking_work(&self) -> yadorilink_root_authority::root_commit::BlockingWorkHold {
        self.root_lease.hold_blocking_work()
    }

    /// Admission for writing a dirty-journal row. Unlike [`Self::begin_operation`] it is also
    /// granted while the link is paused for a safe stop: a change that was observed must be
    /// journaled before anything can refuse it, so that it is found again when the pause lifts.
    /// Refused only once the link is stopping, when the next start's rescan covers it.
    fn begin_journal_operation(
        &self,
    ) -> Result<yadorilink_root_authority::root_commit::LinkOperation<'_>, LocalCaptureError> {
        Ok(self.root_lease.begin_journal_operation()?)
    }

    /// Enables native delta emission: from here on, accepted local
    /// mutations write a signed delta alongside the index mutation.
    pub fn with_change_emitter(mut self, emitter: Arc<LocalAuthorKey>) -> Self {
        self.change_emitter = Some(emitter);
        self
    }
}

/// The result of processing one debounce flush — see `process_flush`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FlushOutcome {
    pub records: Vec<FileRecord>,
}

/// Test-only injection point for `reconcile_disk_with_ignore`. A hook, if set,
/// is invoked right after the scan has read its whole-index snapshot and before
/// it commits any record derived from that snapshot. Keyed nowhere — the hook
/// itself inspects the `group_id` and no-ops for scans it does not care about —
/// so a serial test guard plus a per-test sentinel group keep it from
/// perturbing the other scan tests in this crate. Compiled out of non-test
/// builds; production `reconcile_disk_with_ignore` never references it.
#[cfg(test)]
pub(crate) mod scan_test_hooks;

/// Pins `cfapi_placeholder_untouched`'s Windows overload -- there is no
/// size/mtime fallback on non-Unix platforms; every scenario below proves
/// the verdict comes
/// ONLY from `LocalMutationStore::inspect_windows_placeholder` (stubbed
/// here via `TestReplica::set_windows_placeholder_inspect_result`, since
/// nothing on this crate's own test matrix can exercise a real
/// `CfGetPlaceholderInfo` call -- see that module's own doc comment).
/// `#[cfg(all(test, windows))]`, not `not(unix)`: the fallback these tests
/// replace ran on any non-Unix target as a catch-all; this project ships
/// only macOS and Windows, so there is no longer a third platform to hedge
/// for.
#[cfg(all(test, windows))]
mod cfapi_placeholder_untouched_windows_tests {
    use super::{cfapi_placeholder_untouched, FileRecord};
    use crate::ports::PlaceholderStatus;
    use crate::test_support::TestReplica;
    use yadorilink_local_storage::{
        PlaceholderDiskIdentity, WINDOWS_CFAPI_GENERATION_PROVIDER_KIND,
    };
    use yadorilink_sync_sqlite::RecordedPlaceholderGeneration;

    fn record(size: u64, mtime_unix_nanos: i64) -> FileRecord {
        FileRecord {
            path: "placeholder.bin".into(),
            size,
            mtime_unix_nanos,
            blocks: Vec::new(),
            deleted: false,
        }
    }

    fn metadata_for(size: u64) -> std::fs::Metadata {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f");
        std::fs::write(&path, vec![0u8; size as usize]).unwrap();
        std::fs::metadata(&path).unwrap()
    }

    fn generation(value: u64) -> RecordedPlaceholderGeneration {
        RecordedPlaceholderGeneration {
            identity: PlaceholderDiskIdentity { dev: 0, ino: value },
            provider_kind: WINDOWS_CFAPI_GENERATION_PROVIDER_KIND.to_string(),
        }
    }

    /// A same-size, same-mtime "real edit" is exactly what the removed
    /// size/mtime fallback would have silently swallowed as a self-echo --
    /// proves that path no longer exists: with a real generation recorded
    /// but `inspect_windows_placeholder` reporting `Dirty`, the verdict is
    /// `false` (captured) regardless of size/mtime agreement.
    #[test]
    fn same_size_and_mtime_real_edit_is_still_captured_when_inspect_says_dirty() {
        let replica = TestReplica::open_in_memory().unwrap();
        replica.set_windows_placeholder_inspect_result(PlaceholderStatus::Dirty);
        let metadata = metadata_for(4096);
        let mtime =
            metadata.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
                as i64;
        let recorded = generation(7);
        assert!(!cfapi_placeholder_untouched(
            &replica,
            std::path::Path::new("placeholder.bin"),
            &metadata,
            Some(&record(4096, mtime)),
            Some(&recorded),
        ));
    }

    #[test]
    fn matching_generation_and_in_sync_is_ignored_as_self_echo() {
        let replica = TestReplica::open_in_memory().unwrap();
        replica.set_windows_placeholder_inspect_result(PlaceholderStatus::Untouched);
        let metadata = metadata_for(4096);
        let recorded = generation(7);
        assert!(cfapi_placeholder_untouched(
            &replica,
            std::path::Path::new("placeholder.bin"),
            &metadata,
            None,
            Some(&recorded),
        ));
    }

    /// Represents `inspect_windows_placeholder` detecting an ABA mismatch
    /// (the placeholder at `path` decodes an identity that doesn't match
    /// the expected generation -- a different object now sits at this
    /// path) -- `inspect_placeholder`'s own real implementation collapses
    /// this into `Unknown`, same as an outright API failure (see the next
    /// test): this layer cannot and must not distinguish the two, both
    /// must fail closed identically.
    #[test]
    fn generation_mismatch_is_captured() {
        let replica = TestReplica::open_in_memory().unwrap();
        replica.set_windows_placeholder_inspect_result(PlaceholderStatus::Unknown);
        let metadata = metadata_for(4096);
        let recorded = generation(7);
        assert!(!cfapi_placeholder_untouched(
            &replica,
            std::path::Path::new("placeholder.bin"),
            &metadata,
            None,
            Some(&recorded),
        ));
    }

    #[test]
    fn inspect_failure_is_captured() {
        let replica = TestReplica::open_in_memory().unwrap();
        replica.set_windows_placeholder_inspect_result(PlaceholderStatus::Unknown);
        let metadata = metadata_for(4096);
        let recorded = generation(7);
        assert!(!cfapi_placeholder_untouched(
            &replica,
            std::path::Path::new("placeholder.bin"),
            &metadata,
            None,
            Some(&recorded),
        ));
    }

    /// A legacy (non-CfAPI, or cross-platform-mismatched) recorded identity
    /// must never be silently trusted as `Untouched`, even if
    /// `inspect_windows_placeholder` -- which this test deliberately
    /// leaves stubbed to say `Untouched` -- would have said so: the
    /// `provider_kind` gate must short-circuit BEFORE that call is
    /// consulted at all.
    #[test]
    fn legacy_identity_is_never_silently_untouched() {
        let replica = TestReplica::open_in_memory().unwrap();
        replica.set_windows_placeholder_inspect_result(PlaceholderStatus::Untouched);
        let metadata = metadata_for(4096);
        let legacy = RecordedPlaceholderGeneration {
            identity: PlaceholderDiskIdentity { dev: 0, ino: 7 },
            provider_kind: "internal-inode".to_string(),
        };
        assert!(!cfapi_placeholder_untouched(
            &replica,
            std::path::Path::new("placeholder.bin"),
            &metadata,
            None,
            Some(&legacy),
        ));
    }

    #[test]
    fn no_recorded_generation_is_never_silently_untouched() {
        let replica = TestReplica::open_in_memory().unwrap();
        replica.set_windows_placeholder_inspect_result(PlaceholderStatus::Untouched);
        let metadata = metadata_for(4096);
        assert!(!cfapi_placeholder_untouched(
            &replica,
            std::path::Path::new("placeholder.bin"),
            &metadata,
            None,
            None,
        ));
    }

    /// A generation read back from storage classifies identically on
    /// repeat reads -- the property that makes "restart, then re-read the
    /// persisted generation" safe: nothing about re-fetching the same
    /// already-recorded value (as a restarted daemon would) changes the
    /// verdict.
    #[test]
    fn repeated_reads_of_the_same_persisted_generation_classify_identically() {
        let replica = TestReplica::open_in_memory().unwrap();
        replica.set_windows_placeholder_inspect_result(PlaceholderStatus::Untouched);
        let metadata = metadata_for(4096);
        let recorded = generation(99);
        for _ in 0..2 {
            assert!(cfapi_placeholder_untouched(
                &replica,
                std::path::Path::new("placeholder.bin"),
                &metadata,
                None,
                Some(&recorded),
            ));
        }
    }
}

#[cfg(test)]
mod tests;

/// The scan computes a path's version when it reads the bytes, and commits
/// it later -- unlocked, with every other path's work in between. The
/// identity published beside that version has to come from the same moment
/// the version did.
///
/// Taking a fresh look at commit time instead is not a smaller version of
/// the same check, it is a different and wrong one: it pairs the version
/// computed from the OLD bytes with an identity describing the NEW ones, so
/// an external write landing in that window publishes a proof asserting the
/// old version is on disk, carrying identity evidence that will keep
/// agreeing. `revalidate_identity_against_disk` compares against exactly
/// that identity and confirms; nothing downstream can notice.
#[cfg(test)]
mod disk_observation_gate_tests;

#[cfg(test)]
mod remote_absence_tests;

#[cfg(test)]
mod pairwise_matrix_tests;
