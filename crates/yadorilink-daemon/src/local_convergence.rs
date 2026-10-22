//! Convergence work that has no peer in it.
//!
//! Some of what a device owes a folder is decided entirely by its own state:
//! projecting its native state onto its disk, which no peer is consulted for.
//!
//! That work lived on `PeerSyncSession`, which had two consequences. A device
//! with no peer connected — solo, newly linked, offline — could not do it at
//! all, so the daemon manufactured a session over an inert channel with its
//! own device id standing in as the peer's. And because constructing that
//! session ran the netmap authenticator, doing so could quarantine another
//! session's authorization, which is why callers preferred to borrow a live
//! peer's session when one happened to exist. A synthetic peer, a fabricated
//! identity, and a construction-order hazard, all to run work that never
//! needed a peer.
//!
//! Here that work has no peer to fabricate:
//!
//! ```text
//!   LocalConvergenceExecutor   this device's native state, index, roots and disk
//!   PeerSyncSession            a real peer, real transports, and one of these
//! ```
//!
//! Deliberately no transport field, of any shape. A `None` here would be the
//! same defect one type further along: the point is not that the transport is
//! absent, it is that there is nothing for it to do.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use yadorilink_local_storage::{
    verify_delete_target_within_canonical_root, verify_delete_target_within_root,
};
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::session_state::LinkGate;
use yadorilink_root_authority::root_commit::{RootCommitPermit, RootLease};

use yadorilink_fs_platform::ignore_patterns::{is_ignore_file_relative_path, EffectiveIgnoreSet};
use yadorilink_peer_session::hazard;
use yadorilink_peer_session::peer_session::RootCommitAuthorityProvider;

/// The local half of convergence: everything decided from this device alone.
pub struct LocalConvergenceExecutor {
    pub(crate) state: Arc<crate::replica_coordinator::ReplicaCoordinator>,
    /// This device. Not a peer's id standing in for one — the origin recorded
    /// for a purely local mutation is genuinely this device.
    pub(crate) local_device_id: String,
    pub(crate) root_commit_authority_provider: Arc<dyn RootCommitAuthorityProvider>,
    /// This device's own effective ignore set per group, with bounded
    /// staleness.
    ///
    /// Device-local by definition: it is *this* device's filter on what it
    /// projects, unsynced, and independent of what any peer thinks. It sat on
    /// the session only because the code that consulted it did.
    pub(crate) ignore_sets:
        StdMutex<HashMap<String, (Arc<EffectiveIgnoreSet>, std::time::Instant)>>,
    /// Forces a path's pending local debounce entry into the index before
    /// this device reconciles it.
    ///
    /// Local by nature: it flushes *this* device's own accumulator, and had
    /// nothing to do with a peer beyond being reached from a session.
    pub(crate) pending_local_change_flush:
        Arc<dyn yadorilink_peer_session::peer_session::PendingLocalChangeFlush>,
    /// `raw root -> canonical root`, per group. See
    /// [`Self::canonical_sync_root`].
    pub(crate) canonical_sync_roots: StdMutex<HashMap<String, (PathBuf, PathBuf)>>,
    /// This device's block content. Reading and writing it is local work; only
    /// *obtaining* a block this device does not have needs a peer.
    pub(crate) store: Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
    /// How many blocks each group has been allowed to eagerly fetch.
    ///
    /// A budget on this device's own appetite for content, spent by whatever
    /// drives convergence here. It bounds work, so it is charged exactly once
    /// per record -- see `materialize_local`'s own note on why re-entry after
    /// a block request must not charge it again.
    pub(crate) eager_admission: StdMutex<HashMap<String, u64>>,
    /// Announces that this device is writing block content, so unrelated
    /// bookkeeping can stand back while it does.
    pub(crate) block_write_activity_provider:
        Arc<dyn yadorilink_peer_session::peer_session::BlockWriteActivityProvider>,
    /// Test-only, one-shot: runs between the assembly of an eager write's
    /// temp file and the final local-edit check that precedes its rename, so
    /// a test can land a local write in exactly that window.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) between_assemble_and_persist_hook: StdMutex<Option<AssembleHook>>,
    /// Test-only, one-shot: runs after an eager write's bytes and metadata
    /// are on disk and before the proof observes the object, so a test can
    /// land a local write in the window the proof would otherwise absorb.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) after_write_before_proof_hook: StdMutex<Option<AssembleHook>>,
    /// Test-only: pins how many own-name entries a pass settles at once
    /// (`0` leaves the configured value in force).
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) receive_write_concurrency_override: std::sync::atomic::AtomicUsize,
    /// Test-only: pins the collectors' flush cap (`0` leaves the configured value).
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) collector_flush_cap_override: std::sync::atomic::AtomicUsize,
    /// Test-only: pins whether a pass batches its files' completions
    /// (`0` leaves the configured value, `1` batches, `2` commits per file).
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) batch_completion_override: std::sync::atomic::AtomicU8,
    /// Test-only: pins whether a pass batches its files' open step
    /// (0 = environment, 1 = on, 2 = off).
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) batch_open_override: std::sync::atomic::AtomicU8,
    /// Test-only: pins the deferred receive flush (`0` leaves the environment's
    /// choice, `1` flushes each file with a full flush, `2` the single-barrier
    /// mode, `3` off).
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) deferred_flush_override: std::sync::atomic::AtomicU8,
    /// The volume probes the concurrent files of a pass share.
    pub(crate) volume_probes: volume_probe::VolumeProbes,
    /// The batch barriers of finished runs that are still flushing.
    pub(crate) flush_barriers:
        StdMutex<Vec<tokio::task::JoinHandle<received_flush_barrier::BarrierReport>>>,
    /// Test-only: the path whose write never reaches its completion, so a
    /// test can hold a run's other files queued behind a sibling still running.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) completion_straggler: StdMutex<Option<String>>,
    /// Test-only: the longest a queued completion waits for its batch, in
    /// milliseconds (`0` leaves the default).
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) completion_max_latency_override_ms: std::sync::atomic::AtomicU64,
    /// Test-only: observes eager writes while their path locks are held.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) overlap_probe: StdMutex<Option<Arc<OverlapProbe>>>,
    /// Test-only: the free space the headroom preflight sees, in place of the
    /// volume's real one.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fake_available_bytes: StdMutex<Option<u64>>,
    /// Test-only: names the volume this executor's writes are accounted on.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) volume_key_override: StdMutex<Option<String>>,
    /// Test-only: runs where the preflight asks the volume for its free space.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) free_space_probe: StdMutex<Option<Arc<dyn Fn() + Send + Sync>>>,
    pub(crate) headroom_override_bytes: StdMutex<Option<u64>>,
    pub(crate) headroom_enforced: std::sync::atomic::AtomicBool,
}

/// Where an eager write is observed by an [`OverlapProbe`].
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ProbeSeam {
    /// Temp file written and synced, rename not yet done.
    BeforeRename,
    /// Renamed and synced into place, nothing committed.
    BeforeCommit,
}

/// Records which eager writes are at a seam at the same time, and holds each
/// there until `want` of them have been and `hold` is released, so a test can
/// tell a concurrent run from a serial one. A serial run never reaches `want`;
/// the wait then ends after `patience` and the write continues. Each write
/// holds its path lock for the whole time.
#[cfg(any(test, feature = "test-support"))]
pub(crate) struct OverlapProbe {
    seam: ProbeSeam,
    want: usize,
    patience: std::time::Duration,
    hold: std::sync::atomic::AtomicBool,
    in_flight: std::sync::atomic::AtomicUsize,
    max_in_flight: std::sync::atomic::AtomicUsize,
    /// `(path, entered)` in the order the writes reached the seam and left it.
    events: StdMutex<Vec<(String, bool)>>,
}

#[cfg(test)]
impl OverlapProbe {
    pub(crate) fn new(seam: ProbeSeam, want: usize, patience_ms: u64) -> Arc<Self> {
        Arc::new(Self {
            seam,
            want,
            patience: std::time::Duration::from_millis(patience_ms),
            hold: std::sync::atomic::AtomicBool::new(false),
            in_flight: Default::default(),
            max_in_flight: Default::default(),
            events: Default::default(),
        })
    }

    /// Keeps every write at the seam until [`Self::release`].
    pub(crate) fn hold_until_released(&self) {
        self.hold.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn release(&self) {
        self.hold.store(false, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) fn in_flight(&self) -> usize {
        self.in_flight.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn events(&self) -> Vec<(String, bool)> {
        self.events.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl OverlapProbe {
    pub(crate) async fn pass(&self, seam: ProbeSeam, path: &str) {
        use std::sync::atomic::Ordering::SeqCst;
        if seam != self.seam {
            return;
        }
        let now = self.in_flight.fetch_add(1, SeqCst) + 1;
        self.max_in_flight.fetch_max(now, SeqCst);
        self.events.lock().unwrap_or_else(|p| p.into_inner()).push((path.to_owned(), true));
        let deadline = std::time::Instant::now() + self.patience;
        while (self.hold.load(SeqCst) || self.max_in_flight.load(SeqCst) < self.want)
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        self.events.lock().unwrap_or_else(|p| p.into_inner()).push((path.to_owned(), false));
        self.in_flight.fetch_sub(1, SeqCst);
    }
}

/// A one-shot closure run with the path whose content was just assembled.
#[cfg(any(test, feature = "test-support"))]
pub(crate) type AssembleHook = Box<dyn FnOnce(&Path) + Send>;

/// Whether this executor runs the materialize-time disk-headroom preflight,
/// and against what reserve.
///
/// A constructor argument rather than a post-construction setter on purpose.
/// The preflight used to be switched on by a caller reaching in afterwards,
/// and when the peer-session facade that did the reaching was collapsed the
/// call went with it: every executor was built with enforcement off, while
/// the value it should have been built with was still being computed and
/// passed on every peer connection. A decision that must be made for the
/// executor to exist cannot be forgotten by the next caller that builds one.
#[derive(Clone, Copy, Debug)]
pub struct HeadroomPolicy {
    /// `false` leaves `preflight_disk_headroom` an unconditional `Ok` -- see
    /// its doc comment for why that, not enforcement, is the default.
    pub enforced: bool,
    /// `None` means the built-in `max(1 GiB, 5%)` formula.
    pub override_bytes: Option<u64>,
}

impl HeadroomPolicy {
    /// No preflight at all: what every executor in a test gets unless that
    /// test is specifically about disk pressure.
    pub fn disabled() -> Self {
        Self { enforced: false, override_bytes: None }
    }
}

pub use yadorilink_peer_session::convergence_driver::ConvergenceDriver;

mod hydrate;
pub mod types;
use types::*;
pub mod call_timer;
mod completion_window;
mod knobs;
mod materialize;
pub mod obligation_claims;
mod receive_write_gate;
mod received_flush_barrier;
mod volume_probe;

/// Whether `set` excludes `path` of `group_id` from sync: the ignore file
/// itself, a pattern that matches it as a file, or a directory-only pattern
/// (`build/`) when the namespace places a directory there (an explicit or a
/// structural one, never inferred from this device's disk).
pub(crate) fn path_is_ignored(
    set: &EffectiveIgnoreSet,
    state: &crate::replica_coordinator::ReplicaCoordinator,
    group_id: &str,
    path: &str,
) -> bool {
    is_ignore_file_relative_path(path)
        || set.is_ignored(path, false)
        || (set.is_ignored(path, true)
            && matches!(
                state.desired_path_state(group_id, path),
                Ok(yadorilink_sync_sqlite::desired_state::DesiredPathState::ExplicitDirectory { .. }
                    | yadorilink_sync_sqlite::desired_state::DesiredPathState::StructuralDirectory)
            ))
}

/// A file this device is still writing must never be overwritten with
/// this device's own older version of it.
#[cfg(test)]
mod growing_file_projection_tests;

/// An own change derived from local disk capture never writes that disk
/// back; a disk that moved on is captured instead.
#[cfg(test)]
mod own_head_recapture_tests;

/// A peer's content written here end to end, and a write touched after its
/// pre-write commit publishing nothing.
#[cfg(test)]
mod receive_content_write_tests;

/// A removal is projected only over what it superseded; an
/// unobserved local edit survives as a head.
#[cfg(test)]
mod delete_projection_tests;

/// A path a rebootstrap protects is written, removed, moved and authored by
/// nothing but the rebootstrap, on every lane.
#[cfg(test)]
mod rebootstrap_freeze_tests;

/// What the namespace makes a reconcile do on disk -- relocating a file a
/// live descendant displaces, putting it back, adopting and removing
/// directories held only for descendants -- is never captured as a change.
#[cfg(test)]
mod namespace_capture_tests;

/// A contested path keeps the disk until forked; the displacement guard and
/// the durability gate stand between a winner and the loser's only copy.
#[cfg(test)]
mod contest_displacement_tests;

#[cfg(test)]
mod projection_attempt_tests;

/// A newer version or a removal arriving for a path wakes the custody-hold
/// reconciler.
#[cfg(test)]
mod custody_hold_nudge_tests;

/// `materialize_symlink_at` and
/// `try_apply_metadata_only_update`, exercised directly against a
/// `SyncState` + tempdir — no `PeerSyncSession`/channel needed, since
/// neither function touches the network (see both functions' doc
/// comments for why, and for the wire-schema gap they operate under).
#[cfg(test)]
mod symlink_and_metadata_only_update_tests;

/// the per-(session, group) eager-fetch admission
/// budget (`admit_eager_blocks_impl`, wired into
/// `PeerSyncSession::admit_eager_blocks`) — exercised against a small
/// synthetic `max_per_group` rather than the real (deliberately huge)
/// `MAX_EAGER_BLOCKS_PER_GROUP_PER_SESSION`, for the same reason as
/// `cardinality_cap_tests` above.
#[cfg(test)]
mod eager_admission_tests;

#[cfg(test)]
mod completion_window_tests;
#[cfg(test)]
mod receive_deferred_flush_tests;
#[cfg(test)]
mod receive_edit_crash_sequence_tests;

#[cfg(all(test, unix))]
mod power_cut_tests;

#[cfg(test)]
mod offloaded_commit_tests;

#[cfg(test)]
mod batched_open_tests;

#[cfg(test)]
mod receive_batched_completion_tests;

#[cfg(test)]
#[cfg(test)]
#[cfg(test)]
mod native_prefetch_tests;

#[cfg(test)]
mod prefetch_overlap_tests;

/// The plain own-name entries of a pass are written concurrently, with the
/// serial order's guarantees kept.
#[cfg(test)]
mod receive_window_concurrency_tests;

/// A directory a pass only passes through is settled again only when
/// something about it could have changed.
#[cfg(all(test, unix))]
mod ancestor_directory_tests;

#[cfg(test)]
mod hazard_reason_tests;

#[cfg(test)]
mod hazard_index_equivalence_tests;

#[cfg(test)]
mod require_physical_kind_matches_tests;

/// Liveness regression for `ignore_sets`'s bounded-staleness reload: a
/// `.yadorilinkignore` edit must eventually take effect for incoming records
/// on a peer session that never gets reconstructed, not stay frozen for the
/// session's whole lifetime. Rewinds the cached entry's own `Instant`
/// (`rewind_ignore_set_cache_for_tests`) instead of sleeping the real
/// `IGNORE_SET_REFRESH_INTERVAL`, so this stays fast and deterministic.
#[cfg(test)]
mod ignore_set_liveness_tests;
mod namespace_steps;
mod reconcile;
pub(crate) use reconcile::{reserve_volume_headroom, HeadroomReservation};
pub(crate) mod reconcile_native;

/// What `LocalConvergenceExecutor::own_capture_on_disk` found about a
/// head's relation to the disk it would be projected onto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnCaptureOnDisk {
    /// Not this device's own capture of the path: projection is decided as
    /// for any other change.
    NotACapture,
    /// An own capture the disk still holds, or whose disk state is not this
    /// check's finding: the existing handling decides.
    Holds,
    /// An own capture the disk has moved on from: something else is there
    /// now, and it is newer local state.
    MovedOn,
    /// An own capture whose file was deleted or renamed away since.
    Removed,
}

impl OwnCaptureOnDisk {
    /// Whether what disk holds now has to be captured instead of the head
    /// being projected.
    pub(crate) fn superseded(self) -> bool {
        matches!(self, Self::MovedOn | Self::Removed)
    }
}

/// How a materialization's head is elected, and re-elected under the path
/// lock. The steps after the election read the elected [`Head`] only.
#[derive(Clone, Copy)]
pub(crate) enum Election<'a> {
    /// The node native's plan puts at the physical path. Fresh only while a
    /// re-plan under the path lock still puts exactly this node there (head,
    /// kind, placement and the source it stands for); any difference declines,
    /// and the next pass plans afresh.
    Native { expected: &'a yadorilink_replica_domain::native_plan::NativePlannedNode },
}

/// Whether a materialization applies the recapture rule to an
/// own captured head the disk has moved on from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnCaptureRule {
    /// Capture what disk holds instead of projecting the head.
    RecaptureFirst,
    /// A recapture already ran and found nothing newer: project as for any
    /// other change.
    ProjectAsBefore,
}

/// Whether the regular file at `out_path` already has `version`'s mode and
/// replicated extended attributes -- read-only, the same comparison that
/// decides whether a metadata repair has anything to write.
pub(crate) fn mode_and_xattrs_match_disk(
    out_path: &Path,
    version: &yadorilink_replica_domain::file::FileVersion,
) -> Result<bool, PeerSessionError> {
    Ok(yadorilink_local_storage::unix_mode_already_matches_disk(out_path, version.meta.unix_mode)?
        && yadorilink_local_storage::xattrs_already_match_disk(out_path, &version.meta.xattrs)?)
}

/// What `recapture_instead_of_projecting` achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Recapture {
    /// A newer change now supersedes the head.
    Superseded,
    /// The path could not be captured yet (it is still changing).
    StillChanging,
    /// The capture authored nothing: the head is still the path's winner.
    NothingNewer,
}

impl LocalConvergenceExecutor {
    // One argument per injected dependency of the executor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: Arc<crate::replica_coordinator::ReplicaCoordinator>,
        local_device_id: String,
        root_commit_authority_provider: Arc<dyn RootCommitAuthorityProvider>,
        pending_local_change_flush: Arc<
            dyn yadorilink_peer_session::peer_session::PendingLocalChangeFlush,
        >,
        sync_roots: HashMap<String, PathBuf>,
        store: Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
        block_write_activity_provider: Arc<
            dyn yadorilink_peer_session::peer_session::BlockWriteActivityProvider,
        >,
        headroom: HeadroomPolicy,
    ) -> Arc<Self> {
        // Seeded from the roots known at construction. A root that cannot be
        // canonicalized — an external volume that is not mounted — is simply
        // absent, and the containment checks fall back to the raw path rather
        // than treating its absence as permission to write.
        let canonical_sync_roots = StdMutex::new(
            sync_roots
                .iter()
                .filter_map(|(group_id, root)| {
                    let canonical = std::fs::canonicalize(root).ok()?;
                    Some((group_id.clone(), (root.clone(), canonical)))
                })
                .collect(),
        );
        Arc::new(Self {
            state,
            local_device_id,
            root_commit_authority_provider,
            ignore_sets: StdMutex::new(
                sync_roots
                    .iter()
                    .map(|(group_id, root)| {
                        // A load failure -- an I/O error other than "file not
                        // found", which `load_for_link_root` already handles
                        // -- falls back to the built-in defaults rather than
                        // to no filtering, so a transient read error never
                        // widens what this device projects.
                        let set = EffectiveIgnoreSet::load_for_link_root(root)
                            .unwrap_or_else(|_| EffectiveIgnoreSet::defaults_only());
                        (group_id.clone(), (Arc::new(set), std::time::Instant::now()))
                    })
                    .collect(),
            ),
            pending_local_change_flush,
            canonical_sync_roots,
            store,
            eager_admission: StdMutex::new(HashMap::new()),
            block_write_activity_provider,
            #[cfg(any(test, feature = "test-support"))]
            between_assemble_and_persist_hook: StdMutex::new(None),
            #[cfg(any(test, feature = "test-support"))]
            after_write_before_proof_hook: StdMutex::new(None),
            #[cfg(any(test, feature = "test-support"))]
            receive_write_concurrency_override: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            collector_flush_cap_override: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(any(test, feature = "test-support"))]
            batch_completion_override: std::sync::atomic::AtomicU8::new(0),
            #[cfg(any(test, feature = "test-support"))]
            #[cfg(any(test, feature = "test-support"))]
            batch_open_override: std::sync::atomic::AtomicU8::new(0),
            #[cfg(any(test, feature = "test-support"))]
            deferred_flush_override: std::sync::atomic::AtomicU8::new(0),
            volume_probes: volume_probe::VolumeProbes::default(),
            flush_barriers: StdMutex::new(Vec::new()),
            #[cfg(any(test, feature = "test-support"))]
            completion_max_latency_override_ms: std::sync::atomic::AtomicU64::new(0),
            #[cfg(any(test, feature = "test-support"))]
            completion_straggler: StdMutex::new(None),
            #[cfg(any(test, feature = "test-support"))]
            overlap_probe: StdMutex::new(None),
            #[cfg(any(test, feature = "test-support"))]
            fake_available_bytes: StdMutex::new(None),
            #[cfg(any(test, feature = "test-support"))]
            volume_key_override: StdMutex::new(None),
            #[cfg(any(test, feature = "test-support"))]
            free_space_probe: StdMutex::new(None),
            headroom_override_bytes: StdMutex::new(headroom.override_bytes),
            headroom_enforced: std::sync::atomic::AtomicBool::new(headroom.enforced),
        })
    }

    pub fn state(&self) -> &Arc<crate::replica_coordinator::ReplicaCoordinator> {
        &self.state
    }

    pub fn local_device_id(&self) -> &str {
        &self.local_device_id
    }

    /// This group's local root, resolved live from the link table.
    ///
    /// Never cached: a relink moves it, and a write aimed at where a folder
    /// used to be is a write outside the folder that exists.
    pub fn sync_root(&self, group_id: &str) -> Result<PathBuf, PeerSessionError> {
        match self.state.link_gate_for_group(group_id)? {
            LinkGate::Live { local_path, .. } | LinkGate::Paused { local_path } => {
                Ok(PathBuf::from(local_path))
            }
            LinkGate::NoLiveLink => Err(PeerSessionError::PathEscapesRoot(format!(
                "no live link for group {group_id}; refusing to resolve a local path"
            ))),
        }
    }

    /// `raw_root`'s canonical form, cached per group.
    ///
    /// Keyed by the raw root the caller just resolved, not merely by group: a
    /// cache that remembered only "group → canonical" would keep handing back
    /// the canonical form of a *previous* root after a relink, which is
    /// exactly the stale-root failure `sync_root` resolves live to avoid. A
    /// mismatch re-canonicalizes rather than trusting the entry.
    ///
    /// `None` when the root cannot be canonicalized — most often because it
    /// does not exist, an external volume that is not mounted. The caller
    /// falls back to the non-canonical containment check rather than treating
    /// this as permission to write.
    pub fn canonical_sync_root(&self, group_id: &str, raw_root: &Path) -> Option<PathBuf> {
        let mut cache =
            self.canonical_sync_roots.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((cached_raw, canonical)) = cache.get(group_id) {
            if cached_raw == raw_root {
                return Some(canonical.clone());
            }
        }
        let canonical = std::fs::canonicalize(raw_root).ok()?;
        cache.insert(group_id.to_string(), (raw_root.to_path_buf(), canonical.clone()));
        Some(canonical)
    }

    /// Where `path` lives on this device's disk for `group_id`.
    /// Whether this path is observably absent on disk right now.
    ///
    /// A tombstoned index row does not answer this. Local capture marks
    /// a directory's orphaned children deleted while holding no lock on
    /// the children -- it passes `publish_absent_proof = false` for
    /// exactly that reason -- and an external create under an ignored
    /// path is never adopted at all, so the mutation fence never moves
    /// to invalidate a proof minted from the row alone.
    ///
    /// `symlink_metadata`, not `metadata`: a dangling symlink at this
    /// name is something on disk, not an absence.
    ///
    /// Only for the lanes that want to settle `ExactAbsent` WITHOUT
    /// performing a delete. A lane that just removed the file has
    /// already observed the absence it is about to claim, and needs no
    /// second look -- this is the same line
    /// `dag_zero_work_settlement_if_already_current` draws when it
    /// re-checks disk before authorizing skipped physical work.
    pub(crate) fn observably_absent_on_disk(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        let out_path = self.local_file_path(group_id, path)?;
        match std::fs::symlink_metadata(&out_path) {
            // `ENOTDIR`: a component above the name is not a directory, so
            // nothing can be at the name.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                Ok(true)
            }
            // Present, or unreadable. Either way this attempt has not
            // observed an absence, so it may not claim one.
            _ => Ok(false),
        }
    }

    /// [`Self::observably_absent_on_disk`] for a path this device has
    /// already found to collide with a live sibling under this volume's
    /// case/normalization folding.
    ///
    /// On such a volume, looking the path up resolves to the sibling's own
    /// entry, so the lookup alone can never report this path absent while
    /// the sibling lives: an already-landed tombstone would come back for
    /// another pass on every redelivery for as long as the sibling exists.
    /// So the path is also looked for component by component in directory
    /// listings, where the collision -- in the leaf or in any ancestor --
    /// is visible; see [`hazard::observably_absent_by_exact_name`] for what
    /// counts as a match and why an unanswerable listing is not an absence.
    fn observably_absent_by_exact_name(
        &self,
        group_id: &str,
        path: &str,
        volume: types::VolumeFolding,
    ) -> Result<bool, PeerSessionError> {
        if self.observably_absent_on_disk(group_id, path)? {
            return Ok(true);
        }
        let root = self.sync_root(group_id)?;
        Ok(hazard::observably_absent_by_exact_name(&root, path, volume.normalization_insensitive))
    }

    /// Whether the regular file at `out_path` holds bytes this device has
    /// not captured, so writing over it (or deleting it) now would destroy
    /// a local edit with no conflict copy and no trace.
    ///
    /// Asked of the bytes themselves, right before the write, because the
    /// flush guard that runs earlier is scheduling-dependent: a write can
    /// land after it, and a capture can fail on a file that is still being
    /// written. Which bytes count as "captured" depends on the row:
    ///
    /// * `Present` with a usable proof: the daemon wrote what is here. The
    ///   daemon's own write, untouched since, is captured whichever version
    ///   it holds (`Present` never says the object equals the row's version;
    ///   the proof does). Anything that moved off the proof must still equal
    ///   the row, so any divergence is an unauthored edit -- including a row
    ///   with no blocks, whose version says the file is empty.
    /// * `Present` with no proof, or `Remote` with an object at the path: no
    ///   evidence vouches for what is there. A capture whose own disk
    ///   observation raced leaves exactly this, naming what it read while
    ///   disk moved on. Real bytes that match neither the row's version nor
    ///   `incoming` (the version about to be written, if any) are an
    ///   uncaptured edit. A native provider's untouched placeholder (Windows
    ///   only) is left out: disagreeing with its row is its whole point, and
    ///   reading it could trigger its hydration.
    ///
    /// * No row at all: a regular file here is a new local file capture has
    ///   not reached, unless its bytes are `incoming`'s.
    ///
    /// Every other state keeps its own handling. A missing path, a
    /// symlink, a directory or a tombstoned row is not this check's
    /// finding either -- see `revalidate_target` for why an absent path
    /// in particular must not be declined.
    pub(crate) fn disk_holds_uncaptured_local_bytes(
        &self,
        group_id: &str,
        rel_path: &str,
        out_path: &Path,
        incoming: Option<&[yadorilink_replica_domain::file::BlockInfo]>,
    ) -> Result<bool, PeerSessionError> {
        use yadorilink_local_storage::{disk_content_comparison, DiskContentComparison};
        use yadorilink_replica_domain::session_state::MaterializationState;
        let Some(lstat) = lstat_or_absent(out_path)? else { return Ok(false) };
        if !lstat.is_file() {
            return Ok(false);
        }
        let Some(local_row) = self.state.get_file(group_id, rel_path)? else {
            // A regular file where this device has no row at all was created
            // here after the capture that preceded this call, so nothing has
            // recorded it. Bytes equal to what is about to be written are
            // not lost by writing them.
            return match incoming {
                Some(incoming) => Ok(disk_content_comparison(out_path, incoming)?
                    == DiskContentComparison::PresentButDifferent),
                None => Ok(true),
            };
        };
        if local_row.deleted {
            return Ok(false);
        }
        let differs_from = |blocks: &[yadorilink_replica_domain::file::BlockInfo]| {
            disk_content_comparison(out_path, blocks)
                .map(|found| found == DiskContentComparison::PresentButDifferent)
        };
        let state = self.state.get_materialization_state(group_id, rel_path)?;
        if !matches!(state, Some(MaterializationState::Present | MaterializationState::Remote)) {
            return Ok(false);
        }
        if state == Some(MaterializationState::Remote)
            && self.is_untouched_placeholder_of_this_device(group_id, rel_path, out_path)?
        {
            return Ok(false);
        }
        // Bytes are not the whole of a local edit: a chmod or xattr change
        // moves neither, yet the scanner captures it as one. Ask the scanner's
        // own question (disk mode and xattrs against the row's, exactly).
        let metadata_edited = self.disk_metadata_differs_from_row(group_id, rel_path, out_path)?;
        if state == Some(MaterializationState::Present)
            && self.state.dag_has_usable_materialized_generation(group_id, rel_path)?
        {
            // A proof vouches for what is here. `Present` alone never says the
            // object equals the row's version, so ask the evidence: the
            // daemon's own write, untouched since, is not an edit whichever
            // version it holds (an older version's bytes under a newer row);
            // anything that moved off the proof must still equal the row.
            if self.state.disk_is_untouched_proven_write_at(group_id, rel_path, out_path)? {
                return Ok(false);
            }
            return Ok(metadata_edited || differs_from(&local_row.blocks)?);
        }
        // An object no proof vouches for (`Remote` over bytes, or `Present`
        // without evidence): a capture whose own disk observation raced
        // leaves exactly this, naming what it read while disk moved on. Real
        // bytes that match neither the row's version nor `incoming` are an
        // uncaptured edit.
        if metadata_edited {
            return Ok(true);
        }
        if !differs_from(&local_row.blocks)? {
            return Ok(false);
        }
        match incoming {
            Some(incoming) => Ok(differs_from(incoming)?),
            None => Ok(true),
        }
    }

    /// Whether the mode or replicated xattrs on disk differ from the row's,
    /// compared as the scanner does (`on_disk != indexed`, a row without a
    /// mode included).
    fn disk_metadata_differs_from_row(
        &self,
        group_id: &str,
        rel_path: &str,
        out_path: &Path,
    ) -> Result<bool, PeerSessionError> {
        let Some(row) = self.state.current_row_snapshot(group_id, rel_path)? else {
            return Ok(false);
        };
        let meta = row.to_file_version().meta;
        let file = match std::fs::File::open(out_path) {
            Ok(file) => file,
            Err(error) if is_absent(&error) => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        // Off Unix a disk has no mode to compare.
        let mode_differs = cfg!(unix)
            && file.metadata().map(|m| yadorilink_local_storage::unix_mode_from_metadata(&m))?
                != meta.unix_mode;
        Ok(mode_differs || yadorilink_local_storage::read_replicated_xattrs(&file) != meta.xattrs)
    }

    /// Whether removing `rel_path` on a projected removal would destroy
    /// local state capture has not recorded: bytes that are not the row's
    /// ([`Self::disk_holds_uncaptured_local_bytes`]), a mode or replicated
    /// xattrs that are not the row's, a regular file whose materialization
    /// state is unknown, a symlink whose target
    /// is not the row's, or an object of another kind than the row's where
    /// the removal would unlink it. A removal supersedes only the version
    /// the row records; anything else on disk is a local change its author
    /// never observed, left for capture to record as a head of its own. A
    /// directory is never this check's finding: a removal only ever removes
    /// an empty one.
    pub(crate) fn removal_would_destroy_unrecorded_state(
        &self,
        group_id: &str,
        rel_path: &str,
        out_path: &Path,
    ) -> Result<bool, PeerSessionError> {
        use yadorilink_replica_domain::file::RecordKind;
        if self.disk_holds_uncaptured_local_bytes(group_id, rel_path, out_path, None)? {
            return Ok(true);
        }
        let Some(lstat) = lstat_or_absent(out_path)? else { return Ok(false) };
        if lstat.is_dir() {
            return Ok(false);
        }
        let Some(row) = self.state.current_row_snapshot(group_id, rel_path)? else {
            return Ok(false);
        };
        if row.record.deleted {
            return Ok(false);
        }
        Ok(match row.record_kind {
            RecordKind::File if lstat.is_file() => {
                use yadorilink_replica_domain::session_state::MaterializationState;
                // A version covers mode and replicated xattrs as well as
                // bytes, so a local chmod or xattr change capture has not
                // recorded is as unobserved by the remover as a content
                // edit. An untouched placeholder is left out as above; any
                // state this cannot vouch for (missing, or mid-hydration or
                // eviction) is refused rather than removed unchecked.
                match row.materialization_state {
                    Some(MaterializationState::Present) => {
                        !mode_and_xattrs_match_disk(out_path, &row.to_file_version())?
                    }
                    Some(MaterializationState::Remote) => {
                        !self
                            .is_untouched_placeholder_of_this_device(group_id, rel_path, out_path)?
                            && !mode_and_xattrs_match_disk(out_path, &row.to_file_version())?
                    }
                    _ => true,
                }
            }
            RecordKind::File => lstat.file_type().is_symlink(),
            RecordKind::Directory => true,
            RecordKind::Symlink => {
                if !lstat.file_type().is_symlink() {
                    true
                } else {
                    let target = std::fs::read_link(out_path)?;
                    #[cfg(unix)]
                    let on_disk = {
                        use std::os::unix::ffi::OsStrExt as _;
                        target.as_os_str().as_bytes().to_vec()
                    };
                    #[cfg(not(unix))]
                    let on_disk = target.to_string_lossy().as_bytes().to_vec();
                    row.symlink_target.as_deref() != Some(on_disk.as_slice())
                }
            }
        })
    }

    /// Whether projecting `head` at `rel_path` would write this device's
    /// own capture of the path back over a disk that has moved on since.
    ///
    /// A change local capture emitted was read off this disk: the disk was
    /// its source, so projecting it can never legitimately change the disk.
    /// Either the disk still holds what was captured (and the caller's
    /// "already current" checks settle it with no write), or what is there
    /// now is a newer local state -- this device's own, whatever the row
    /// claims about it -- that has to be captured as a newer change, never
    /// overwritten with the older one.
    ///
    /// Which changes are captures is recorded by the capture routes when
    /// they emit (`ReplicaCoordinator::is_local_capture`), not inferred
    /// here: a restore or a repair carrier is just as much this device's
    /// own change, and writing the disk is exactly what it is for. A peer's
    /// change is never a capture of this disk, and neither is an own head
    /// projected as a conflict copy, at a path other than the one captured.
    ///
    /// What counts as the disk having moved on, by the kind `version`
    /// names:
    /// * a regular file: a regular file whose bytes, mode or replicated
    ///   extended attributes are not `version`'s (capture records a change
    ///   to any of them as an edit; an mtime alone it does not), unless it
    ///   is an untouched placeholder this device wrote for the head -- it
    ///   stands for the head's content, and hydrating it destroys nothing
    ///   -- or a symlink in its place;
    /// * a symlink: a symlink with another target, or a regular file in
    ///   its place;
    /// * a directory: a directory with another mode, or anything else in
    ///   its place;
    /// * a file or a symlink: nothing at the path while the row still
    ///   holds it live and hydrated -- the file was deleted or renamed away
    ///   (`OwnCaptureOnDisk::Removed`). A row that is not hydrated keeps
    ///   its existing handling: nothing proves a file was ever there;
    /// * a directory: nothing at the path while the row still holds it
    ///   live. Capturing it proved it was there, so it was removed.
    ///
    /// A directory where a file or a link was captured is left to its
    /// existing handling (a type change, which capture does not author
    /// over a live file row).
    pub(crate) fn own_capture_on_disk(
        &self,
        group_id: &str,
        rel_path: &str,
        head: &Head,
        version: &yadorilink_replica_domain::file::FileVersion,
    ) -> Result<OwnCaptureOnDisk, PeerSessionError> {
        use yadorilink_local_storage::{disk_content_comparison, DiskContentComparison};
        use yadorilink_replica_domain::file::RecordKind;
        use yadorilink_replica_domain::session_state::MaterializationState;
        if head.device_id != self.local_device_id
            || !self.state.is_local_capture_head(group_id, rel_path, head)?
        {
            return Ok(OwnCaptureOnDisk::NotACapture);
        }
        let kind = version.meta.record_kind;
        let out_path = self.local_file_path(group_id, rel_path)?;
        let lstat = match std::fs::symlink_metadata(&out_path) {
            Ok(lstat) => lstat,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                let live_row =
                    self.state.get_file(group_id, rel_path)?.is_some_and(|row| !row.deleted);
                // A state that cannot be read is not "not Present": nothing then
                // proves the absence is not the user's delete, so the pass stops
                // here (and is retried) rather than projecting the old head.
                let removed = live_row
                    && (kind == RecordKind::Directory
                        || self.state.get_materialization_state(group_id, rel_path)?
                            == Some(MaterializationState::Present));
                return Ok(if removed {
                    OwnCaptureOnDisk::Removed
                } else {
                    OwnCaptureOnDisk::Holds
                });
            }
            Err(_) => return Ok(OwnCaptureOnDisk::Holds),
        };
        let file_type = lstat.file_type();
        let moved_on = match kind {
            RecordKind::Directory if file_type.is_dir() => {
                // Off Unix a disk has no mode to compare.
                cfg!(unix)
                    && version.meta.unix_mode.is_some()
                    && yadorilink_local_storage::unix_mode_from_metadata(&lstat)
                        != version.meta.unix_mode
            }
            RecordKind::Directory => true,
            RecordKind::Symlink if file_type.is_symlink() => {
                let target = std::fs::read_link(&out_path)
                    .map_err(yadorilink_local_storage::StorageError::Io)?;
                version.meta.symlink_target.as_deref()
                    != Some(
                        yadorilink_fs_platform::fs_identity::target_to_bytes(&target).as_slice(),
                    )
            }
            RecordKind::Symlink => file_type.is_file(),
            _ if file_type.is_symlink() => true,
            _ if !file_type.is_file() => false,
            _ => {
                if self.state.get_materialization_state(group_id, rel_path)?
                    == Some(MaterializationState::Remote)
                    && self
                        .is_untouched_placeholder_of_this_device(group_id, rel_path, &out_path)?
                {
                    return Ok(OwnCaptureOnDisk::Holds);
                }
                let record = file_record_from_version(rel_path, version);
                disk_content_comparison(&out_path, &record.blocks)?
                    == DiskContentComparison::PresentButDifferent
                    || !mode_and_xattrs_match_disk(&out_path, version)?
            }
        };
        Ok(if moved_on { OwnCaptureOnDisk::MovedOn } else { OwnCaptureOnDisk::Holds })
    }

    /// Whether the object at a `Remote` row's path is still the native
    /// provider placeholder this device wrote, rather than real bytes someone
    /// wrote there. On Windows this is the rule local capture applies
    /// (`cfapi_placeholder_untouched`) and nothing looser: only a CfAPI
    /// placeholder this device recorded a generation for, still reporting
    /// `Untouched` for that generation, is untouched. No recorded generation,
    /// another provider's generation, or a recall attribute alone say nothing
    /// about who wrote the object, so they answer `false` (the caller then
    /// compares bytes or refuses). A generation that cannot be read is an
    /// error for the caller, which stops and retries; it is never an answer.
    #[cfg(windows)]
    fn is_untouched_placeholder_of_this_device(
        &self,
        group_id: &str,
        rel_path: &str,
        out_path: &Path,
    ) -> Result<bool, PeerSessionError> {
        use yadorilink_local_capture::ports::PlaceholderStatus;
        Ok(
            match self
                .state
                .materialization_state_repository()
                .get_placeholder_generation(group_id, rel_path)
                .map_err(crate::sync_error::SyncError::from)?
            {
                Some(recorded)
                    if recorded.provider_kind
                        == yadorilink_local_storage::WINDOWS_CFAPI_GENERATION_PROVIDER_KIND =>
                {
                    crate::placeholder_inspect_windows::inspect_placeholder(
                        out_path,
                        recorded.identity.ino,
                    ) == PlaceholderStatus::Untouched
                }
                Some(_) | None => false,
            },
        )
    }

    /// Where no native provider exists, no object is a provider placeholder:
    /// whatever stands at a path is user bytes, so nothing is taken at its
    /// word.
    #[cfg(not(windows))]
    fn is_untouched_placeholder_of_this_device(
        &self,
        _group_id: &str,
        _rel_path: &str,
        _out_path: &Path,
    ) -> Result<bool, PeerSessionError> {
        Ok(false)
    }

    pub fn local_file_path(&self, group_id: &str, path: &str) -> Result<PathBuf, PeerSessionError> {
        Ok(self.sync_root(group_id)?.join(path))
    }

    /// Applies a tombstone: remove the file, then record the deletion.
    ///
    /// No blocks, by construction — an absence has no content to fetch — which
    /// is why this belongs here and the rest of `materialize` does not. The
    /// ordering is the point: recording the tombstone *before* a removal that
    /// then fails (a locked or open file, common on Windows) would leave the
    /// index saying `deleted = true` while the file is still there, and the
    /// next scan would resurrect it as a brand-new local edit.
    pub async fn materialize_tombstone(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        root_commit_permit: &RootCommitPermit<'_>,
    ) -> Result<MaterializeResult, PeerSessionError> {
        // Recomputed here rather than passed in: a hazardous name is a fact
        // about this device's own root and policy, and this is the type that
        // owns both.
        let hazard_reason = self.hazard_reason_for(group_id, record).await?;
        // A hazardous tombstone must NOT go through the ordinary `hold`
        // path used below for non-delete records: `hold_record` upserts
        // the INCOMING record as-is, and for a tombstone that means
        // writing `deleted=true` over whatever row already exists at
        // `record.path` -- while `remove_file` is deliberately never
        // called, so any content already on disk there is untouched. That
        // is exactly the "index says deleted, disk still has the file"
        // divergence this same branch's own comment above already
        // identifies as dangerous (a later scan reads it as a brand-new
        // local edit and resurrects + re-propagates it) -- for a held
        // CREATE this divergence is intentional and accounted for (disk
        // keeps whatever it had, index tracks the latest
        // known-but-unwritten metadata), but for a held DELETE it
        // recreates the exact hazard the ordering comment above was
        // written to prevent. So: only mark the existing row held, in
        // place, without adopting the incoming tombstone's fields. If
        // there is no GENUINE content row for this path, there is nothing
        // on disk to diverge from and the tombstone is simply dropped.
        // "Genuine" is `has_real_current_row`, not `get_file(...)
        // .is_some()`: `apply_locked_record`'s caller no longer bootstraps
        // a metadata scaffold for a tombstone record (a tombstone has no
        // kind/target/exec-bit to materialize), but a scaffold can still
        // exist here from an earlier, unrelated record at the same path
        // (e.g. a held CREATE's own bootstrap), so this check stays
        // defense-in-depth rather than relying on that invariant alone. A
        // dropped tombstone reports `Settled` or `RetryRequired` depending
        // on WHY there was no genuine row to hold, not uniformly: an
        // already-deleted genuine row (the redelivery case just below)
        // means this exact deletion already converged -- nothing is
        // pending, so `Settled` is correct and reporting `RetryRequired`
        // would just churn forever on a redundant resend. Every other case
        // -- a genuine LIVE row moved to `held`, or a scaffold/no row at
        // all -- means the deletion has NOT converged anywhere yet, so a
        // caller must not treat this path as resolved for this attempt.
        // The held-live-row case looks superficially like "a hazard
        // correctly moved the record to hold", which `MaterializeResult`'s
        // own doc comment reserves for `Settled`. It is not: `set_held`
        // only stamps `held_reason`/`held_since_unix_nanos` onto the
        // EXISTING (still-live) row -- it records neither the pending
        // tombstone's authoring identity nor that a deletion is even
        // pending, so nothing downstream can tell "this path is durably
        // resolved" from "this path has a live file that happens to carry
        // a hold reason". `RetryRequired` keeps the change unprojected, so
        // the periodic audit keeps retrying this exact path (cheap: just
        // this hazard check plus a `set_held` UPDATE) until the collision
        // genuinely clears -- no dependency on the original sending peer
        // still being connected, or on any peer resending at all.
        if let Some(reason) = &hazard_reason {
            let has_real_row = self.state.has_real_current_row(group_id, &record.path)?;
            let existing = self.state.get_file(group_id, &record.path)?;
            match existing {
                Some(row) if has_real_row && !row.deleted => {
                    // `RetryRequired` (below) means the periodic
                    // materialization audit re-enters this exact
                    // branch on every tick while the collision
                    // persists (see this `if let Some(reason)`
                    // block's own doc comment) -- calling `set_held`
                    // unconditionally on every one of those re-drives
                    // would stamp a fresh `now_unix_nanos()` each
                    // time, so a path held for hours would always
                    // read as "held since a moment ago". Only stamp
                    // when the reason actually changes (a first hold,
                    // or the collision shifted to a different sibling)
                    // so `held_since_unix_nanos` reflects when THIS
                    // hold reason first applied, not when it was last
                    // re-confirmed.
                    self.state.rehold_if_reason_changed(group_id, &record.path, reason)?;
                    return Ok(MaterializeResult::RetryRequired);
                }
                // Already a genuine tombstone, not a scaffold: holding
                // it would be the "orphaned held entry on a
                // tombstoned path" state `clear_held`'s own doc
                // comment says this crate deliberately avoids --
                // reachable if this exact tombstone already landed
                // once (clearing any prior hold) and a peer's
                // periodic resend redelivers it after a fresh
                // collision appears.
                Some(row) if has_real_row && row.deleted => {
                    // "Already absent" has to be observed, not inferred
                    // from the row: see `observably_absent_on_disk`. By
                    // exact name, because this name collides with a live
                    // sibling that a plain lookup resolves to instead.
                    let root = self.sync_root(group_id)?;
                    let volume = types::VolumeFolding {
                        case_insensitive: hazard::is_case_insensitive_filesystem(&root),
                        normalization_insensitive: hazard::is_normalization_insensitive_filesystem(
                            &root,
                        ),
                    };
                    if !self.observably_absent_by_exact_name(group_id, &record.path, volume)? {
                        return Ok(MaterializeResult::RetryRequired);
                    }
                    // No disk mutation occurred here
                    // (the path is now, verifiably, absent) -- a
                    // snapshot, never a bump, of the mutation fence.
                    let mutation_generation =
                        self.state.dag_snapshot_mutation_fence(group_id, &record.path)?;
                    return Ok(MaterializeResult::Settled(SettlementEvidence::ExactAbsent {
                        mutation_generation,
                    }));
                }
                _ => return Ok(MaterializeResult::RetryRequired),
            }
        }
        let out_path = self.local_file_path(group_id, &record.path)?;
        // Same defense-in-depth as every write branch's
        // `verify_write_target` call: an intermediate directory symlink
        // can redirect this lexically-safe (`..`-free,
        // non-absolute) path outside `group_id`'s sync root, and
        // `remove_file` follows that symlink chain exactly as
        // `create`/`rename` do. See `verify_delete_target`'s doc
        // comment.
        self.verify_delete_target(group_id, &out_path)?;
        // The same last line of defence the content write has: a delete is
        // just as final for bytes this device never captured. A local edit
        // still on disk here is retried, not removed -- once captured, it
        // meets this tombstone as a concurrent edit instead of vanishing.
        if self.removal_would_destroy_unrecorded_state(group_id, &record.path, &out_path)? {
            tracing::info!(
                group_id,
                path = %record.path,
                "declining a tombstone whose target no longer matches this device's indexed \
                 content; an unauthored local edit is on disk and deleting it would destroy it"
            );
            return Ok(MaterializeResult::RetryRequired);
        }
        // Opened before the delete syscall below, not after -- same
        // "before the bytes are written" contract every OTHER physical
        // mutator in this codebase already follows
        // (`MaterializationIntentGuard::open`'s own doc comment), just
        // applied to a removal instead of a write. Without this, a
        // crash between the `remove_file` below and `persist_
        // materialized_record`'s own index commit leaves this row at
        // whatever `materialization_state` it had BEFORE this
        // tombstone (typically `Present`, from being genuinely
        // materialized until a moment ago) with the file now
        // genuinely missing and `record.deleted` still `false` in the
        // index -- exactly the "Hydrated + missing + no intent" shape
        // every repair/reconcile scan disambiguates via this same
        // intent journal. This path's projection obligation (bumped at
        // this Delete `Change`'s own admission, before `materialize`
        // was ever called for it) already covers most of that window,
        // but only reliably for `reconcile_disk_with_ignore`'s live
        // per-path read -- `materialization_repair.rs`'s own sweep
        // reads a whole-pass SNAPSHOT of outstanding obligations, taken
        // once per pass, so a sweep that started before this exact
        // admission would miss it and could still emit a second,
        // redundant tombstone for a path that is (accurately, just not
        // yet index-confirmed) already gone -- harmless in outcome
        // (the file really is deleted) but not something worth relying
        // on when a real intent closes the gap outright. A deletion's
        // own intent has no content to name; the owner records a delete
        // marker as its target and classifies the intent as a delete,
        // so repair leaves a file missing under it to this delete
        // rather than rebuilding it.
        //
        // The fence is bumped right after, inside this path's lock (held by every
        // caller of `materialize` for
        // its whole call), before the first mutating syscall below --
        // the bump is what invalidates this path's existing proof, and
        // it must land even if the delete itself turns out to be a
        // same-instant no-op (`NotFound`, below): a mutator's OWN
        // absence of visible effect never licenses skipping the
        // invalidation, since a concurrent mutator elsewhere could
        // otherwise still be trusted to hold a proof this call is
        // about to make stale. Safe-but-pessimistic, never a lock:
        // `path_lock` alone still serializes writers of this path.
        let (delete_intent_guard, mutation_generation) =
            self.state.open_tombstone_delete(group_id, &record.path, root_commit_permit)?;
        // `std::fs::remove_file` on a
        // symlink path is a plain `unlink` of that directory entry
        // — it removes the link itself and never follows it to
        // touch whatever the link points at, symlink or not. This is
        // exactly the "tombstone removes the link, never the
        // target" requirement, and needs no kind-specific branching
        // here: the same call is already correct for a symlink
        // record's tombstone as it is for a regular file's. See
        // `tests/peer_session.rs`'s
        // `symlink_tombstone_removes_link_but_never_its_target` for
        // a real assertion of this against an actual target file.
        let removal = self.remove_for_tombstone(group_id, &record.path, &out_path)?;
        // Settle: clear any hold, record the deletion in the index, and
        // only then clear the intent -- see the settle operations' own doc
        // comments. A retained directory settles the same way: the entry is
        // deleted, only the directory stays.
        // A native removal names no authoring of its own: the tombstone keeps
        // the identity of the row it removes, so the deletion stays recorded
        // and the last live content stays recoverable from trash.
        let inherits = self.state.row_authoring(group_id, &record.path)?.is_some();
        if inherits {
            self.state.settle_tombstone_delete(
                delete_intent_guard,
                group_id,
                record,
                origin_device_id,
                None,
                &|| self.root_lease_for(group_id),
            )?;
        } else {
            // The path carries no native head: it is a pure local artifact
            // (a displaced leaf that no admitted delta touched) that no
            // admitted delta ever touched, and
            // `persist_row_under_fresh_operation` would upsert a 'current'
            // row via `upsert_file_with_origin`, which the schema's
            // `files_require_authoring_identity_on_*` triggers reject once
            // this group has native history: nothing about a purely local
            // decision can ever satisfy "verified authoring identity". There
            // is no fact to assert here, so erase the row instead of
            // asserting a tombstone -- exactly `erase_local_only_file`'s
            // ("not a tombstone, an erasure", mirroring
            // `FileIndexRepository::remove_file`'s own existing ignore-sweep
            // use) documented semantics.
            self.state.settle_retired_copy_erase(
                delete_intent_guard,
                group_id,
                &record.path,
                root_commit_permit,
            )?;
        }
        if let TombstoneRemoval::Retained { reason, removable } = removal {
            self.keep_directory_a_delete_found_not_empty(
                group_id,
                &record.path,
                reason,
                removable.as_deref(),
            )?;
            return Ok(MaterializeResult::Settled(SettlementEvidence::Retained {
                reason: reason.to_string(),
            }));
        }
        Ok(MaterializeResult::Settled(SettlementEvidence::ExactAbsent { mutation_generation }))
    }

    /// Removes what a tombstone deletes at `out_path`: the file or symlink
    /// (a plain unlink, which never follows a link), or the directory --
    /// only when it is empty, with a single non-recursive `rmdir`.
    ///
    /// A directory that is not empty is kept, with everything in it, and
    /// reported [`TombstoneRemoval::Retained`]: whatever keeps it is either
    /// something this device does not replicate (a user's untracked file,
    /// an ignored `.git`, the `.DS_Store` a Finder window leaves), which the
    /// sync engine never deletes on anyone's behalf, or live descendants,
    /// which a directory delete does not reach. Either way the entry's
    /// delete is settled; retrying would only find the same directory. A
    /// directory that was removed has nothing structural or retained left
    /// to record.
    ///
    /// Only a directory the index holds as a replicated directory is
    /// removed. A directory standing where the index holds a file or a
    /// symlink was put there by something else -- a local change of kind
    /// that capture has not recorded -- and is kept even when empty.
    pub(crate) fn remove_for_tombstone(
        &self,
        group_id: &str,
        rel_path: &str,
        out_path: &Path,
    ) -> Result<TombstoneRemoval, PeerSessionError> {
        if std::fs::symlink_metadata(out_path).is_ok_and(|meta| meta.is_dir()) {
            if self.state.get_record_kind(group_id, rel_path)?
                != Some(yadorilink_replica_domain::file::RecordKind::Directory)
            {
                return Ok(TombstoneRemoval::Retained {
                    reason: self.retained_directory_reason_for(group_id, rel_path)?,
                    removable: None,
                });
            }
            if !self.is_materialized_directory_at(group_id, rel_path, out_path)? {
                return Ok(TombstoneRemoval::Retained {
                    reason: yadorilink_sync_sqlite::structural_origin::RETAINED_REPLACED_LOCALLY,
                    removable: None,
                });
            }
            if let Some(removal) = self.remove_directory_if_empty(group_id, rel_path, out_path)? {
                return Ok(removal);
            }
        }
        // The caller records the path as absent next, so the removal is durable
        // when this returns (a failed flush is an error: nothing is recorded).
        yadorilink_local_storage::remove_durably(out_path, &self.state.temp_ledger(group_id))?;
        #[cfg(test)]
        removal_ordering_probe::fire(out_path);
        Ok(TombstoneRemoval::Removed)
    }

    /// Whether the directory at `out_path` is the object this device
    /// materialized for `rel_path`'s Directory entry. The row's kind says
    /// the entry is a directory, not that the directory now standing at its
    /// name is the one the entry put there: the user may have removed it and
    /// made another. An unobservable path, or no recorded identity, is not a
    /// match -- the directory is kept.
    fn is_materialized_directory_at(
        &self,
        group_id: &str,
        rel_path: &str,
        out_path: &Path,
    ) -> Result<bool, PeerSessionError> {
        let Ok(observed) =
            yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(out_path)
        else {
            return Ok(false);
        };
        self.state
            .is_materialized_directory_object(
                group_id,
                rel_path,
                &self.sync_root(group_id)?,
                &observed,
            )
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// One non-recursive `rmdir` of the directory at `out_path`: removed
    /// (and its structural and retained records forgotten) when empty,
    /// retained when not. `None` when what is there is no longer a
    /// directory.
    ///
    /// Every caller first checks that the directory at `out_path` is the
    /// object it may remove (the materialized directory, or the retained one
    /// a delete aimed at) and only then calls this, and the `rmdir` goes by
    /// name. Neither macOS nor Linux can remove a directory by descriptor or
    /// make a removal conditional on the object's identity, so a directory
    /// swapped in at the same name between that check and the `rmdir` --
    /// by a process that does not take this daemon's path lock -- is removed
    /// in its place if it is empty. Only an empty directory can be affected:
    /// the `rmdir` refuses anything with an entry in it, and never touches a
    /// file. Moving the directory aside first to check it under a private
    /// name would close that gap only by making a non-empty directory, with
    /// its tracked children, vanish from its name for a moment, which is
    /// worse. The same gap sits between a failed `rmdir` and the identity
    /// recorded for a retained directory below.
    fn remove_directory_if_empty(
        &self,
        group_id: &str,
        rel_path: &str,
        out_path: &Path,
    ) -> Result<Option<TombstoneRemoval>, PeerSessionError> {
        use yadorilink_local_storage::EmptyDirectoryRemoval;
        Ok(
            match yadorilink_local_storage::remove_empty_dir_in(
                out_path,
                &self.state.temp_ledger(group_id),
            )? {
                EmptyDirectoryRemoval::Removed => {
                    self.state
                        .forget_removed_directory(group_id, rel_path)
                        .map_err(crate::sync_error::SyncError::from)?;
                    Some(TombstoneRemoval::Removed)
                }
                EmptyDirectoryRemoval::Absent => Some(TombstoneRemoval::Removed),
                // The directory this delete aimed at: bound to its identity,
                // so a later pass removes this object once it is empty, and
                // never a different directory made at the same path.
                EmptyDirectoryRemoval::NotEmpty => Some(TombstoneRemoval::Retained {
                    reason: self.retained_directory_reason_for(group_id, rel_path)?,
                    removable: yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(
                        out_path,
                    )
                    .ok()
                    .map(Box::new),
                }),
                // A child appeared while the directory was being removed and its name
                // was taken meanwhile: nothing was deleted, and what stands at the
                // name now is not this delete's to touch.
                EmptyDirectoryRemoval::Stranded(_) => Some(TombstoneRemoval::Retained {
                    reason: self.retained_directory_reason_for(group_id, rel_path)?,
                    removable: None,
                }),
                EmptyDirectoryRemoval::NotADirectory => None,
            },
        )
    }

    /// Records the directory a delete aimed at and found not empty as
    /// retained. When what keeps it is live descendants, it is adopted as
    /// structural too: from now on it is their container, derived state
    /// like any directory this device created for descendants, and capture
    /// must never read it as a user's directory and author back the entry
    /// the delete removed. Once the last descendant goes, it is removed.
    pub(crate) fn keep_directory_a_delete_found_not_empty(
        &self,
        group_id: &str,
        rel_path: &str,
        reason: &str,
        removable: Option<&yadorilink_fs_platform::fs_identity::FileIdentity>,
    ) -> Result<(), PeerSessionError> {
        self.state
            .keep_retained_directory(group_id, rel_path, reason, removable)
            .map_err(crate::sync_error::SyncError::from)?;
        if let Some(identity) = removable {
            if reason == yadorilink_sync_sqlite::structural_origin::RETAINED_LIVE_DESCENDANTS {
                self.state
                    .adopt_as_structural_directory(group_id, rel_path, identity)
                    .map_err(crate::sync_error::SyncError::from)?;
            }
        }
        Ok(())
    }

    /// Why a non-empty directory whose entry is deleted stays: live
    /// descendants, or content this device does not replicate.
    fn retained_directory_reason_for(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> Result<&'static str, PeerSessionError> {
        Ok(
            if self
                .state
                .has_live_descendant(group_id, rel_path)
                .map_err(crate::sync_error::SyncError::from)?
            {
                yadorilink_sync_sqlite::structural_origin::RETAINED_LIVE_DESCENDANTS
            } else {
                yadorilink_sync_sqlite::structural_origin::RETAINED_UNTRACKED_CONTENT
            },
        )
    }

    /// Removes the directory at `rel_path` if it is the very object an
    /// earlier delete aimed at and retained, and it is now empty
    /// (`ExactAbsent`); if it is that object but still not empty, keeps it
    /// (`Retained`). `None` when what is at the path is not such a
    /// directory: nothing recorded, recorded as kept, or a different
    /// object at the same path.
    fn remove_retained_directory_if_empty(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> Result<Option<SettlementEvidence>, PeerSessionError> {
        let out_path = self.local_file_path(group_id, rel_path)?;
        let Ok(observed) =
            yadorilink_fs_platform::fs_identity::FileIdentity::observe_path(&out_path)
        else {
            return Ok(None);
        };
        if !self
            .state
            .is_removable_retained_directory(
                group_id,
                rel_path,
                &self.sync_root(group_id)?,
                &observed,
            )
            .map_err(crate::sync_error::SyncError::from)?
        {
            return Ok(None);
        }
        self.verify_delete_target(group_id, &out_path)?;
        let mutation_generation =
            self.state.begin_retained_directory_removal(group_id, rel_path)?;
        Ok(match self.remove_directory_if_empty(group_id, rel_path, &out_path)? {
            Some(TombstoneRemoval::Removed) => {
                Some(SettlementEvidence::ExactAbsent { mutation_generation })
            }
            Some(TombstoneRemoval::Retained { reason, removable }) => {
                self.keep_directory_a_delete_found_not_empty(
                    group_id,
                    rel_path,
                    reason,
                    removable.as_deref(),
                )?;
                Some(SettlementEvidence::Retained { reason: reason.to_string() })
            }
            None => None,
        })
    }

    /// Re-examines every retained directory above a path this pass
    /// removed, deepest first, and removes each one that is now empty.
    ///
    /// A directory's delete can run before its children's: a peer's
    /// `rm -rf` wider than one commit chunk puts the directory in an
    /// earlier chunk than some of its children, the engine's bounded calls
    /// can split the paths across passes, and a child's delete can be
    /// retried. The directory's `rmdir` then finds it not empty and it is
    /// retained, and its own path is never reconciled again. Removing its
    /// last child is what empties it, so that is when it is re-examined.
    /// Only a directory a delete aimed at, and only that same object, is
    /// ever removed here.
    ///
    /// Takes each ancestor's path lock, so it must be called holding none.
    /// Best effort: a failure is logged and leaves the directory retained,
    /// exactly as it was before this ran.
    pub(crate) async fn remove_emptied_retained_ancestors<'a>(
        &self,
        group_id: &str,
        removed_paths: impl IntoIterator<Item = &'a String>,
    ) {
        let mut ancestors = std::collections::BTreeSet::new();
        for path in removed_paths {
            let mut rest = path.as_str();
            while let Some((parent, _)) = rest.rsplit_once('/') {
                ancestors.insert(parent.to_string());
                rest = parent;
            }
        }
        // Reverse order: every descendant sorts after its ancestor.
        for ancestor in ancestors.into_iter().rev() {
            let path_lock = self.state.path_lock(group_id, &ancestor);
            let _guard = crate::receive_diag::lock_path(&path_lock).await;
            let outcome = (|| -> Result<Option<SettlementEvidence>, PeerSessionError> {
                if self
                    .state
                    .retained_directory_reason(group_id, &ancestor)
                    .map_err(crate::sync_error::SyncError::from)?
                    .is_some()
                    && self.state.get_file(group_id, &ancestor)?.is_some_and(|row| row.deleted)
                {
                    if let Some(evidence) =
                        self.remove_retained_directory_if_empty(group_id, &ancestor)?
                    {
                        return Ok(Some(evidence));
                    }
                }
                // A directory this device created only to hold what was
                // just removed goes with it, once nothing else needs it.
                self.prune_directory_made_for_descendants(group_id, &ancestor)
            })();
            match outcome {
                Ok(Some(SettlementEvidence::ExactAbsent { .. })) => tracing::debug!(
                    group_id,
                    path = %ancestor,
                    "removed a retained directory its last child's delete emptied"
                ),
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    group_id,
                    path = %ancestor,
                    %error,
                    "could not re-examine a retained directory after a child's delete; it \
                     stays retained"
                ),
            }
        }
    }

    /// Whether this device refuses to write `record`'s name.
    ///
    /// A removal of a name whose exact spelling is a listed entry of its directory, and whose
    /// folded siblings are all the verified destination of a move of that very head, is not
    /// ambiguous: it removes that entry and nothing the siblings name that is not also kept.
    /// This is a case-only rename (with or without an edit) seen from a folding volume, where holding the removal leaves the new
    /// spelling waiting on the old one's row and the old one's removal waiting on the new.
    pub(crate) async fn hazard_reason_for(
        &self,
        group_id: &str,
        record: &FileRecord,
    ) -> Result<Option<String>, PeerSessionError> {
        let folding = self.volume_probes.folding(&self.sync_root(group_id)?).await;
        self.hazard_reason_on_folding(group_id, record, folding)
    }

    /// [`Self::hazard_reason_for`] probing the volume on the calling thread.
    #[cfg(test)]
    pub(crate) fn hazard_reason_for_now(
        &self,
        group_id: &str,
        record: &FileRecord,
    ) -> Result<Option<String>, PeerSessionError> {
        let folding = volume_probe::ProbedFolding::probe_now(&self.sync_root(group_id)?);
        self.hazard_reason_on_folding(group_id, record, folding)
    }

    /// The hazard decision for a volume probed once for the whole call.
    fn hazard_reason_on_folding(
        &self,
        group_id: &str,
        record: &FileRecord,
        folding: volume_probe::ProbedFolding,
    ) -> Result<Option<String>, PeerSessionError> {
        let mut reason = types::hazard_reason_for_policy_on_volume(
            self.state.as_ref(),
            group_id,
            record,
            hazard::NamePolicy::local(),
            folding.or_conservative(),
        )?;
        if reason.is_none() && !record.deleted {
            reason = self.on_disk_spelling_differs(group_id, &record.path, folding.known())?;
        }
        if reason.is_some()
            && record.deleted
            && hazard::invalid_name_reason(hazard::NamePolicy::local(), &record.path).is_none()
        {
            // Only on a volume whose folding is known: a failed probe keeps the hold.
            if let Some(volume) = folding.known() {
                if self.exact_leaf_listed(group_id, &record.path, volume)?
                    && self.folded_siblings_are_the_move_of(group_id, &record.path, volume)?
                {
                    return Ok(None);
                }
            }
        }
        Ok(reason)
    }

    /// Why this path must wait because a directory it would be written under (an ancestor, or
    /// the path itself when it is a directory) is on disk under another spelling: on a folding
    /// volume the write would land inside the old spelling, and the watcher would report that
    /// physical path as a local create of its own. The old directory has to go first (its
    /// removal is a verified move, see `folded_siblings_are_the_move_of`), then this path is
    /// written under its own spelling. Only a volume that folds, and only a successful look,
    /// can answer; anything else is "no known mismatch".
    fn on_disk_spelling_differs(
        &self,
        group_id: &str,
        path: &str,
        volume: Option<VolumeFolding>,
    ) -> Result<Option<String>, PeerSessionError> {
        let root = self.sync_root(group_id)?;
        let Some(volume) = volume else { return Ok(None) };
        if !volume.folds_anything() {
            return Ok(None);
        }
        let Ok(canonical_root) = root.canonicalize() else { return Ok(None) };
        let full = root.join(path);
        // The directory whose exact spelling matters: the path itself when it is a real
        // directory, else its parent.
        let own_is_directory = std::fs::symlink_metadata(&full).is_ok_and(|meta| meta.is_dir());
        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let checked = if own_is_directory { components.len() } else { components.len() - 1 };
        if checked == 0 {
            return Ok(None);
        }
        let probe =
            if own_is_directory { full } else { full.parent().unwrap_or(&root).to_path_buf() };
        let Ok(actual) = probe.canonicalize() else { return Ok(None) };
        let Ok(relative) = actual.strip_prefix(&canonical_root) else { return Ok(None) };
        let actual: Vec<_> = relative.components().collect();
        if actual.len() != checked {
            return Ok(None);
        }
        for (wanted, found) in components.iter().zip(&actual) {
            let found = found.as_os_str();
            if !namespace_steps::listed_name_is(
                found,
                std::ffi::OsStr::new(wanted),
                volume.normalization_insensitive,
            ) {
                return Ok(Some(format!(
                    "{}: an existing directory holds this path under another spelling '{}'",
                    hazard::HELD_REASON_CASE_COLLISION,
                    found.to_string_lossy()
                )));
            }
        }
        Ok(None)
    }

    /// Whether `path` is a regular file or directory whose removal is the delete half of a move: every
    /// live row whose name this volume folds onto it is a head that descends from a delta
    /// that removed `path`'s own head and put the sibling (verified from the stored deltas,
    /// never from bytes or names). A sibling another device created, or this device's
    /// author created unrelated to the removed head, is not one: the hold stays.
    fn folded_siblings_are_the_move_of(
        &self,
        group_id: &str,
        path: &str,
        volume: VolumeFolding,
    ) -> Result<bool, PeerSessionError> {
        use yadorilink_sync_sqlite::file_index::NameFoldKey;
        if self.state.get_file(group_id, path)?.is_none_or(|row| row.deleted)
            || !matches!(
                self.state.get_record_kind(group_id, path)?,
                Some(
                    yadorilink_replica_domain::file::RecordKind::File
                        | yadorilink_replica_domain::file::RecordKind::Directory
                )
            )
        {
            return Ok(false);
        }
        let Some(removed) = self.state.row_authoring(group_id, path)? else {
            return Ok(false);
        };
        if removed.source_path.0 != path {
            return Ok(false);
        }
        let mut siblings = self.state.name_fold_matches(
            group_id,
            NameFoldKey::Case,
            &yadorilink_fs_platform::canonical_fold::case_fold(path),
            path,
        )?;
        siblings.extend(self.state.name_fold_matches(
            group_id,
            NameFoldKey::Canonical,
            &yadorilink_fs_platform::canonical_fold::canonical_fold(path),
            path,
        )?);
        siblings.sort();
        siblings.dedup();
        // Only the names this volume really folds together are collisions here.
        siblings.retain(|sibling| reconcile_native::volume_folds_together(volume, path, sibling));
        if siblings.is_empty() {
            return Ok(false);
        }
        for sibling in &siblings {
            if !self.state.native_head_descends_from_move_of(group_id, &removed, sibling)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Refuses a delete aimed outside this group's root.
    ///
    /// An intermediate directory symlink can redirect a lexically safe,
    /// `..`-free path outside the sync root, and `remove_file` follows that
    /// chain exactly as `create`/`rename` do.
    pub fn verify_delete_target(
        &self,
        group_id: &str,
        out_path: &Path,
    ) -> Result<(), PeerSessionError> {
        let raw_root = self.sync_root(group_id)?;
        let raw_root = raw_root.as_path();
        self.state.verify_root(raw_root, group_id)?;
        if out_path.parent() == Some(raw_root) {
            return Ok(());
        }
        match self.canonical_sync_root(group_id, raw_root) {
            Some(canonical_root) => {
                Ok(verify_delete_target_within_canonical_root(out_path, &canonical_root)?)
            }
            None => Ok(verify_delete_target_within_root(out_path, raw_root)?),
        }
    }

    /// This session's currently-effective ignore set for `group_id` --
    /// see `ignore_sets`'s own doc comment for the bounded-staleness
    /// reasoning. Reloads from the group's current live root (`self.
    /// sync_root`, not a cached one) once the cached entry is older than
    /// `IGNORE_SET_REFRESH_INTERVAL`; a reload that fails (no live link
    /// right now, e.g. a transient relink) falls back to whatever is
    /// already cached rather than discarding it, and only returns `None`
    /// if nothing has ever been successfully loaded for this group at
    /// all.
    pub(crate) fn effective_ignore_set(&self, group_id: &str) -> Option<Arc<EffectiveIgnoreSet>> {
        let mut cache = self.ignore_sets.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((set, loaded_at)) = cache.get(group_id) {
            if loaded_at.elapsed() < IGNORE_SET_REFRESH_INTERVAL {
                return Some(set.clone());
            }
        }
        match self.sync_root(group_id) {
            Ok(root) => {
                let set = Arc::new(
                    EffectiveIgnoreSet::load_for_link_root(&root)
                        .unwrap_or_else(|_| EffectiveIgnoreSet::defaults_only()),
                );
                cache.insert(group_id.to_string(), (set.clone(), std::time::Instant::now()));
                Some(set)
            }
            Err(_) => cache.get(group_id).map(|(set, _)| set.clone()),
        }
    }

    /// Whether `path` matches this device's
    /// own effective ignore pattern set for `group_id` (built-in defaults
    /// plus this device's `.yadorilinkignore`, if any). A group with no
    /// entry in `ignore_sets` (not one of `sync_roots`) is never ignored
    /// by this check — that shouldn't happen for a group this session
    /// actually shares, since `ignore_sets` is derived from the same
    /// `sync_roots` map `shares_group`'s caller relies on.
    ///
    /// This is a purely local filter (ignore patterns are
    /// device-local, never synced) — it decides what *this* device does
    /// with an incoming record (skip materializing/indexing/forwarding
    /// it), and has no effect on what the sending peer, or this device's
    /// other peers, do with the same path.
    ///
    /// A directory-only pattern (`build/`) covers the path only when the
    /// path is a directory: whether it is comes from what the namespace
    /// places there, an explicit or a structural directory, never from
    /// what happens to be on this device's disk.
    pub fn is_locally_ignored(&self, group_id: &str, path: &str) -> bool {
        self.effective_ignore_set(group_id)
            .is_some_and(|set| path_is_ignored(&set, &self.state, group_id, path))
    }

    /// Test-only accessor letting `ignore_set_liveness_tests` age a cached
    /// entry past `IGNORE_SET_REFRESH_INTERVAL` without a real sleep.
    #[cfg(test)]
    pub(crate) fn rewind_ignore_set_cache_for_tests(
        &self,
        group_id: &str,
        age: std::time::Duration,
    ) {
        let mut cache = self.ignore_sets.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((_, loaded_at)) = cache.get_mut(group_id) {
            *loaded_at =
                std::time::Instant::now().checked_sub(age).expect("age must not underflow Instant");
        }
    }

    /// The zero-work-close pre-check for one path: without any block fetch
    /// or disk write, resolves `path`'s current native heads (the SAME
    /// resolution `reconcile_group_paths` performs internally, just for
    /// one path and with none of its write-side effects) and asks the
    /// zero-work port method whether disk already, verifiably, holds that
    /// exact state. Returns the ready-to-close evidence when it does;
    /// `None` whenever it cannot conclusively confirm this (an ignored
    /// path, no live heads, an `Absent` resolution -- retirement's own
    /// publication path already covers deletes, so this pre-check only
    /// ever concerns itself with `Present` -- or the port method itself
    /// reporting "not confirmable"). `None` must always be read as "let
    /// the ordinary reconcile attempt handle this path," never as an
    /// error.
    pub fn zero_work_settlement_for_path(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<SettlementEvidence>, PeerSessionError> {
        if self.is_locally_ignored(group_id, path) {
            return Ok(None);
        }
        // Cheapest question first: the settlement check cannot return anything
        // but `None` without a usable `path_materialized_generations` record
        // for this path, and resolving the path's heads to ask it costs far
        // more than that point lookup.
        //
        // Asking the O(1) question first cannot change any answer -- it is the
        // same conjunct, evaluated earlier -- and a record that appears just
        // after this returns `false` only means the ordinary reconcile attempt
        // handles the path, which is exactly what `None` already means here.
        if !self.state.dag_has_usable_materialized_generation(group_id, path)? {
            return Ok(None);
        }
        // The question is native's.
        self.native_zero_work_settlement(group_id, path)
    }

    /// This group's root-commit authority, for a mutation that needs one.
    ///
    /// Fails closed. A caller with no real per-link fence lookup is built with
    /// a deny-by-default provider, which reports no live link for every group
    /// and lands here — never a permissive fallback lease.
    pub fn root_lease_for(&self, group_id: &str) -> Result<Arc<RootLease>, PeerSessionError> {
        self.root_commit_authority_provider.root_lease_for(group_id).ok_or_else(|| {
            PeerSessionError::NotFound(format!(
                "no live root-commit authority for group {group_id} (no established link, \
                 or no provider injected)"
            ))
        })
    }
}

/// Whether `error` says only that nothing (or no directory) is at the path.
fn is_absent(error: &std::io::Error) -> bool {
    matches!(error.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory)
}

/// `symlink_metadata`, where only an absent path is `None`: any other error
/// (the object exists but cannot be examined) is an error, never "nothing to
/// protect".
fn lstat_or_absent(path: &Path) -> Result<Option<std::fs::Metadata>, PeerSessionError> {
    match std::fs::symlink_metadata(path) {
        Ok(lstat) => Ok(Some(lstat)),
        Err(error) if is_absent(&error) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Test probe: runs a closure at the moment a removal has returned durable and
/// the caller has not recorded it yet, so a test can observe what the index
/// holds at that point.
#[cfg(test)]
pub(crate) mod removal_ordering_probe {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    type Probe = Arc<dyn Fn() + Send + Sync>;
    static PROBES: Mutex<Option<HashMap<PathBuf, Probe>>> = Mutex::new(None);

    #[cfg(unix)]
    pub(crate) fn arm(removed: PathBuf, probe: impl Fn() + Send + Sync + 'static) {
        PROBES.lock().unwrap().get_or_insert_with(HashMap::new).insert(removed, Arc::new(probe));
    }

    pub(super) fn fire(removed: &Path) {
        let probe = PROBES.lock().unwrap().as_ref().and_then(|m| m.get(removed).cloned());
        if let Some(probe) = probe {
            probe();
        }
    }
}
