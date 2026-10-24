//! What the hydrate/evict/status control commands need from the on-disk materialization
//! engine (the `hydration` module), expressed as a port so `application`
//! never imports the hydration or daemon-state modules directly.

use crate::sync_error::SyncError;

use super::common::BoxFuture;

/// `MaterializationPort::evict`'s own truthful outcome DTO --
/// this port's own vocabulary (see this module's doc comment: `application`
/// never imports the hydration/daemon-state/filesystem-sync layers
/// directly), decoupled from but mirroring `yadorilink_filesystem_sync::
/// materialization_eviction::EvictionOutcome`'s own fields. Exists because
/// the eviction control-socket path used to discard this entirely
/// (`.map(|_| ())`), so a request that daemon-side silently did nothing --
/// the file was busy, not fully hydrated, or changed on disk right
/// before the commit -- still returned a bare `Ok`, and the CLI printed
/// "Evicted" regardless. `dehydrated: false` is the one fact that closes
/// that gap: the caller can no longer claim success without evidence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EvictOutcome {
    /// Whether the on-disk file was actually reduced to a placeholder.
    /// `false` means this call left the file exactly as it was --
    /// nothing was freed, regardless of the exact reason (busy, not yet
    /// `Present`, or its on-disk identity changed out from under the
    /// request).
    pub dehydrated: bool,
    pub blocks_reclaimed: u64,
    pub bytes_reclaimed: u64,
}

/// The transition a path is in the middle of, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalTransition {
    None,
    Hydrating,
    Evicting,
}

/// What stands on this device for one path: two independent facts, decoupled
/// from the persisted `MaterializationState` (per this module's own doc
/// comment, never import that layer directly).
///
/// * `object_present`: a physical local object stands at the path or is being
///   detached (a `Present` or `Evicting` row). `Hydrating` and `Remote` rows
///   report false.
/// * `current_content_present`: a usable proof names the current version, so
///   the bytes are usable. Implies `object_present`; false while a transition
///   is under way and whenever the evidence cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LocalPresence {
    pub object_present: bool,
    pub current_content_present: bool,
    pub transition: LocalTransition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MaterializationStatusSummary {
    pub state: LocalPresence,
}

/// A request to assemble the CURRENT version of one file into a temp file (a provider root's
/// sink: the OS takes the bytes, the daemon writes no user-visible path).
pub(crate) struct TempMaterialization<'a> {
    pub group_id: &'a str,
    pub path: &'a str,
    /// `Some` only when the caller names a version; it must still be current.
    pub requested_version: Option<yadorilink_replica_domain::ids::VersionHash>,
    /// A file name inside the daemon's staging directory; the assembly is built beside it.
    pub staging_file: &'a std::path::Path,
    /// `Some`: only the bytes of this window of the version, not the whole file. Only the blocks
    /// covering it are fetched; the file's materialization state is untouched either way.
    pub range: Option<ByteRange>,
    /// Where the attempt reports how far it is, for a requester that wants to show progress.
    pub progress: Option<std::sync::Arc<AssemblyProgress>>,
}

/// How far one temp materialization is, reported to whoever waits for it.
///
/// The work is three kinds of bytes: fetched from peers (only the blocks not yet local), written
/// to the staging file, and verified against the version's blocks. `snapshot` scales the sum to
/// the bytes of the content, so it is `completed <= total` and reaches `total` only once
/// [`AssemblyProgress::finish`] is called, which the caller does only after verification
/// succeeded. Progress never goes back while the total is unchanged.
#[derive(Debug, Default)]
pub(crate) struct AssemblyProgress {
    state: std::sync::Mutex<ProgressState>,
}

#[derive(Debug, Default)]
struct ProgressState {
    content: u64,
    planned: u64,
    done: u64,
    reported: u64,
    finished: bool,
}

impl AssemblyProgress {
    /// Starts (or, when the version moved and the attempt restarts, restarts) the plan for
    /// `content` bytes: they are written and verified, so twice that much work.
    pub(crate) fn begin(&self, content: u64) {
        let mut state = self.lock();
        state.content = content;
        state.planned = content.saturating_mul(2);
        state.done = 0;
    }

    /// Adds `bytes` to be fetched from peers to the plan. Called once per attempt, before any
    /// fetched byte is reported.
    pub(crate) fn plan_fetch(&self, bytes: u64) {
        let mut state = self.lock();
        state.planned = state.planned.saturating_add(bytes);
    }

    /// `bytes` more were fetched, written or verified.
    pub(crate) fn advance(&self, bytes: u64) {
        let mut state = self.lock();
        state.done = state.done.saturating_add(bytes).min(state.planned);
    }

    /// The content is verified and complete.
    pub(crate) fn finish(&self) {
        self.lock().finished = true;
    }

    /// `(completed, total)` in bytes of the content, or `None` before the plan is known or for
    /// content with no bytes.
    pub(crate) fn snapshot(&self) -> Option<(u64, u64)> {
        let mut state = self.lock();
        let total = state.content;
        if total == 0 || state.planned == 0 {
            return None;
        }
        let completed = if state.finished {
            total
        } else {
            // Short of the total until `finish`, and never lower than what was reported.
            let scaled = (u128::from(state.done) * u128::from(total)) / u128::from(state.planned);
            (scaled as u64).min(total - 1).max(state.reported.min(total - 1))
        };
        state.reported = completed;
        Some((completed, total))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ProgressState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// A byte window `[offset, offset + len)` of one file version. The end is clamped to the file's
/// size; an offset past the size cannot be satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ByteRange {
    pub offset: u64,
    pub len: u64,
}

/// A fully written, verified, fsynced file in the staging directory.
#[derive(Debug)]
pub(crate) struct TempAssembly {
    pub assembled: std::path::PathBuf,
    pub version_hash: yadorilink_replica_domain::ids::VersionHash,
    /// The size of the whole file version.
    pub size: u64,
    /// For a ranged request, the window the file holds (clamped to the size); `None`: the whole
    /// file.
    pub range: Option<ByteRange>,
}

#[derive(Debug)]
pub(crate) enum TempOutcome {
    Assembled(TempAssembly),
    /// The named version is not the current one, or the version kept moving while it was
    /// assembled. Old bytes are never returned.
    VersionOutOfDate,
    /// A ranged request whose offset is past the end of the version. Nothing was fetched.
    RangeNotSatisfiable,
    /// A ranged request whose window is longer than the daemon serves
    /// (`MAX_RANGE_WINDOW_LEN`). Nothing was fetched; the caller asks for the whole file.
    RangeTooLarge,
}

/// The retention policy in force at one path, apart from what is stored there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RetentionState {
    /// Local space for the path must not be reclaimed.
    pub pinned: bool,
    /// The pin was set at exactly this path; otherwise it is inherited from a folder above.
    pub explicit: bool,
}

/// What pinning a path did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PinOutcome {
    pub retention: RetentionState,
    /// Why the path's content could not be downloaded just now, when it could not. The pin
    /// stands regardless.
    pub download_error: Option<String>,
}

pub(crate) trait MaterializationPort: Send + Sync {
    /// Assembles the current version into a staging temp file. The same hydration body as
    /// `hydrate`, with a different sink.
    fn materialize_to_temp<'a>(
        &'a self,
        request: TempMaterialization<'a>,
    ) -> BoxFuture<'a, Result<TempOutcome, SyncError>>;

    /// Fetches what is not here yet. Returns whether any content was fetched from peers:
    /// `false` when everything asked for was already on this device.
    fn hydrate<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<bool, SyncError>>;

    /// Synchronous: eviction is a local index/block-store operation with no
    /// remote round trip, unlike `hydrate`.
    fn evict(&self, group_id: &str, path: &str) -> Result<EvictOutcome, SyncError>;

    /// Whether `evict` may run for this root at all: the same gate `evict` applies first, so a
    /// menu can decline to offer an action the daemon would refuse. Fails closed.
    fn evict_supported(&self, group_id: &str) -> bool;

    /// Synchronous, same reasoning as `evict`: a plain local index read,
    /// never a peer round trip. `None` means the daemon has no
    /// materialization-state row for this path at all.
    fn status(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationStatusSummary>, SyncError>;

    /// Marks `path` "always keep on this device" and fetches what is not here yet through the
    /// ordinary hydration path. The pin is recorded first and stands even when the download
    /// fails. A provider folder's content is fetched by the OS, so there it only records.
    fn pin<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
    ) -> BoxFuture<'a, Result<PinOutcome, SyncError>>;

    /// Removes the pin set at exactly `path`, touching no content, and reports the policy in
    /// force afterwards (still pinned when a folder above is).
    fn unpin(&self, group_id: &str, path: &str) -> Result<RetentionState, SyncError>;

    fn retention(&self, group_id: &str, path: &str) -> Result<RetentionState, SyncError>;
}
