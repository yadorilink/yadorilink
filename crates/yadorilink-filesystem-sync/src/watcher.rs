// apple-cfg-file: macos-only FSEvents is the macOS notify backend; iOS watches per directory like any non-FSEvents backend
//! Local filesystem change detection, watching a linked folder
//! for create/modify/delete/rename events without requiring a manual scan
//! trigger (`sync-engine` spec's "Local Change Detection" requirement).
//!
//! `notify`'s `RecommendedWatcher::watch`/`unwatch` must never be called
//! synchronously from within the watcher's own event-callback closure.
//! Every one of `notify` 8.2's backends (verified directly against its
//! vendored source, not assumed) funnels callback delivery and
//! watch-registration requests through the *same single dedicated event-
//! loop thread*: macOS FSEvents delivers callbacks on a `CFRunLoop` thread
//! and `watch`'s `stop` step busy-waits for that exact thread to go
//! idle before reconfiguring; Linux inotify and Windows
//! `ReadDirectoryChangesW` both process a `watch` call as a message sent
//! to that same event-loop thread, then block the caller on a reply that
//! only that thread can send. Calling `watch` reentrantly from inside
//! the callback therefore blocks the one thread the backend needs in order
//! to ever unblock it — an indefinite deadlock on every backend, not an
//! FSEvents-specific quirk. See `spawn_new_directory_registrar` below,
//! which hands new-directory registration off to a tokio task instead.
//!
//! On macOS the gap described next is closed by never registering a watch
//! after startup: the root is watched once, recursively (see
//! [`RootWatch`]), and a new directory only has its contents re-reported.
//! Windows watches the root once, recursively, too: a
//! `ReadDirectoryChangesW` handle per directory would make NTFS refuse to
//! rename any directory above a watched one. The per-directory registration
//! below is what inotify uses, where adding a watch leaves the others
//! alone.
//!
//! Moving `watch` off the callback thread closed that deadlock, but not a
//! residual gap — confirmed directly against `notify` 8.2.0's vendored
//! FSEvents source (`fsevent.rs`): `watch_inner`/`unwatch_inner` always
//! call `stop` (tear down the *entire* `FSEventStream` and block until
//! its dedicated thread joins) followed by `run` (a brand-new
//! `FSEventStreamCreate`, covering every currently-watched path, not just
//! the one being added/removed). `since_when` is fixed to
//! `kFSEventStreamEventIdSinceNow` once, at `FsEventWatcher` construction,
//! and is never advanced to the last-delivered event ID on a restart — so
//! the recreated stream genuinely starts "since now" at whatever moment
//! `FSEventStreamCreate` happens to run. Any real filesystem event for
//! *any* watched path (not only the newly-registered one) that lands in
//! the gap between the old stream stopping and the new one starting is
//! never delivered by the OS at all: not delayed, not coalesced, not
//! recoverable by anything watching the callback — confirmed empirically
//! too (raw `notify::Event`-level instrumentation during a 100%-
//! reproducible failure showed zero trace of the lost event ever reaching
//! the callback). Every `register_new_directory_tree` call is a `watch`
//! call, so it always opens this window. Since this is an OS-level
//! delivery gap this codebase's own code cannot observe or narrow (there
//! is nothing to lock more tightly — `notify` itself never sees the
//! event, so which specific path, if any, was affected is unknowable from
//! here), the fix in `spawn_new_directory_registrar` below is a
//! reconciling safety net rather than a targeted capture: every
//! registration trigger re-scans from `root` (not just the specific
//! directory that triggered it) for any directory not yet in
//! `watched_dirs`, registering and reconciling each one found this way —
//! this is how a lost rename's *destination* directory (never reported by
//! the callback as "new" at all) still gets discovered and its contents
//! indexed. This scan is purely path-level (which directories exist and
//! are/aren't already watched) and never touches file content or the
//! index — deliberately not implemented by reusing the watcher-channel-
//! overflow/`DebounceFlush::RescanRequired` full index-vs-disk
//! reconciliation, which was tried first and found unsafe: triggering a
//! full `scan_existing_files_with_ignore` this often can re-derive and
//! re-version a file that's concurrently mid-conflict-resolution between
//! two devices, permanently stalling convergence (reproduced
//! deterministically — see `spawn_new_directory_registrar`'s doc comment
//! for the full account).

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use tokio::sync::mpsc;
use yadorilink_fs_platform::ignore_patterns::EffectiveIgnoreSet;

#[cfg(feature = "os-watch")]
mod os;
#[cfg(feature = "os-watch")]
pub use os::{
    watch_folder, watch_folder_with_capacity, watch_folder_with_capacity_and_ignore,
    watch_folder_with_ignore, RealFolderWatchSource,
};

/// Why the OS watcher could not watch, without naming the watcher library: the engine's error
/// types carry this, so a build without the OS watcher still has them.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct WatchError {
    message: String,
    limit_reached: bool,
}

impl WatchError {
    /// A watch that cannot be started because this build has no OS watcher.
    #[must_use]
    pub fn unavailable(message: &str) -> Self {
        Self { message: message.to_owned(), limit_reached: false }
    }

    /// A watch failure the OS reports as its per-user watch limit being used up.
    #[must_use]
    pub fn watch_limit() -> Self {
        Self { message: "OS watch limit reached".to_owned(), limit_reached: true }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WatcherError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("filesystem watcher error: {0}")]
    Watch(#[from] WatchError),
}

impl WatcherError {
    /// Whether the OS refused another watch because the per-user limit is
    /// used up (Linux `fs.inotify.max_user_watches`: `ENOSPC` from
    /// `inotify_add_watch`). Nothing a retry fixes until the limit is raised
    /// or directories are freed.
    #[must_use]
    pub fn is_watch_limit(&self) -> bool {
        match self {
            Self::Watch(err) => err.limit_reached,
            Self::Io(io) => io_is_watch_limit(io),
        }
    }
}

#[cfg(target_os = "linux")]
fn io_is_watch_limit(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(28) // ENOSPC
}

#[cfg(not(target_os = "linux"))]
fn io_is_watch_limit(_err: &std::io::Error) -> bool {
    false
}

#[cfg(feature = "os-watch")]
impl From<notify::Error> for WatchError {
    fn from(err: notify::Error) -> Self {
        let limit_reached = matches!(err.kind, notify::ErrorKind::MaxFilesWatch)
            || matches!(&err.kind, notify::ErrorKind::Io(io) if io_is_watch_limit(io));
        Self { message: err.to_string(), limit_reached }
    }
}

#[cfg(feature = "os-watch")]
impl From<notify::Error> for WatcherError {
    fn from(err: notify::Error) -> Self {
        Self::Watch(err.into())
    }
}

/// Default channel capacity between the OS watcher callback and whatever
/// consumes `FolderWatcher::events` — a tuning knob for how early the
/// overflow fallback (see `overflowed`) engages, not the only thing
/// standing between "keep events" and "block the OS callback thread"
/// (non-blocking `try_send`, below, already guarantees the latter
/// regardless of capacity).
pub const DEFAULT_CHANNEL_CAPACITY: usize = 256;

/// What a watcher (or a scan, or a journal replay) OBSERVED at a path. A
/// removal here is an observation that an object this device had is gone;
/// whether that is evidence of a delete depends on the row's state. A user's
/// delete of the LOGICAL item (a platform provider's `deleteItem`) is not an
/// observation and is not one of these: it is a separate type, handled by a
/// separate entry point (`SemanticDelete` in `yadorilink-local-capture`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsChangeKind {
    CreatedOrModified,
    ObservedRemoval,
}

#[derive(Debug, Clone)]
pub struct FsChangeEvent {
    pub path: PathBuf,
    pub kind: FsChangeKind,
}

/// Keeps the underlying OS watcher alive for as long as this is held;
/// dropping it stops watching.
pub struct FolderWatcher {
    _watcher: WatcherGuard,
    pub events: mpsc::Receiver<FsChangeEvent>,
    overflowed: Arc<AtomicBool>,
    watch_limited: Arc<AtomicBool>,
}

/// Keeps whatever underlying event source is producing `FolderWatcher`'s
/// events alive for as long as this is held; dropping it stops that
/// source. Opaque (not the concrete `notify` watcher type) so that
/// `FolderWatchSource` implementations other than `RealFolderWatchSource`
/// (a simulated source feeding synthetic `FsChangeEvent`s under a
/// deterministic-simulation test harness) can return a `FolderWatcher` too,
/// without this crate's consumers (`run_debouncer` and everyone above it)
/// ever needing to know which kind they're holding.
pub struct WatcherGuard {
    _guard: Box<dyn std::any::Any + Send + Sync>,
}

impl FolderWatcher {
    /// True while the OS watch limit keeps some directory from being
    /// watched. Changes there are then found only by the full rescans the
    /// registrar requests, not live. Clears once a registration succeeds.
    #[must_use]
    pub fn watch_limited_flag(&self) -> Arc<AtomicBool> {
        self.watch_limited.clone()
    }

    /// Splits into the event receiver, the overflow flag (see
    /// `watch_folder`'s doc comment), and an opaque guard that keeps
    /// the underlying OS watch alive for as long as it's held: the
    /// debounce accumulator needs to own `events` and the
    /// overflow flag directly, in a different task than whatever holds
    /// the OS-watcher guard, since the accumulator and the executor
    /// consuming its output are two independently-scheduled tasks.
    pub fn split(self) -> (mpsc::Receiver<FsChangeEvent>, Arc<AtomicBool>, WatcherGuard) {
        (self.events, self.overflowed, self._watcher)
    }
}

/// Constructs a `FolderWatcher` for a linked folder root.
/// `link_manager::start_link_watch` depends on this trait (rather than
/// calling `watch_folder_with_ignore` directly) so a deterministic-
/// simulation test scenario can substitute a source that feeds synthetic
/// `FsChangeEvent`s under simulated timing instead of a real OS
/// filesystem watcher, while every consumer downstream of the returned
/// `FolderWatcher` (the debounce accumulator, indexing, peer
/// reconciliation, materialization) runs the same production code either
/// way.
pub trait FolderWatchSource: Send + Sync {
    fn watch(
        &self,
        root: &Path,
        ignore_set: Arc<EffectiveIgnoreSet>,
    ) -> Result<FolderWatcher, WatcherError>;
}

/// A `FolderWatchSource` a deterministic-simulation test scenario
/// constructs itself, feeding synthetic `FsChangeEvent`s through the same
/// `mpsc` channel/overflow-flag boundary a real OS watcher would, so
/// `run_debouncer` and everything above it (indexing, peer reconciliation,
/// materialization) runs unmodified against events the scenario script
/// controls directly instead of ones a real filesystem produces. Pure
/// channel plumbing — no OS-specific API — so it works identically in a
/// native and a simulated build; only the *scheduling* around it differs.
///
/// `watch` can only be called once per instance (mirroring a real
/// link's one-watcher-per-root lifecycle); a second call is a
/// programming error in the scenario driver, not a recoverable runtime
/// condition.
pub struct SimulatedFolderWatchSource {
    events_rx: std::sync::Mutex<Option<mpsc::Receiver<FsChangeEvent>>>,
    overflowed: Arc<AtomicBool>,
}

impl SimulatedFolderWatchSource {
    /// Returns the source (to hand to `link_manager::start_link_watch_
    /// with_source`-equivalent wiring) paired with the `Sender` a DST
    /// scenario uses to inject synthetic filesystem events afterward.
    pub fn new(capacity: usize) -> (Self, mpsc::Sender<FsChangeEvent>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            Self {
                events_rx: std::sync::Mutex::new(Some(rx)),
                overflowed: Arc::new(AtomicBool::new(false)),
            },
            tx,
        )
    }
}

impl FolderWatchSource for SimulatedFolderWatchSource {
    fn watch(
        &self,
        _root: &Path,
        _ignore_set: Arc<EffectiveIgnoreSet>,
    ) -> Result<FolderWatcher, WatcherError> {
        let events = self
            .events_rx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .ok_or_else(|| {
                WatcherError::from(std::io::Error::other(
                    "SimulatedFolderWatchSource::watch called more than once",
                ))
            })?;
        Ok(FolderWatcher {
            _watcher: WatcherGuard { _guard: Box::new(()) },
            events,
            overflowed: self.overflowed.clone(),
            watch_limited: Arc::new(AtomicBool::new(false)),
        })
    }
}

/// The `FolderWatchSource` of a build without the OS watcher: it refuses, so a folder that would
/// need one fails to start instead of running with no source of changes.
pub struct NoWatchSource;

impl FolderWatchSource for NoWatchSource {
    fn watch(
        &self,
        _root: &Path,
        _ignore_set: Arc<EffectiveIgnoreSet>,
    ) -> Result<FolderWatcher, WatcherError> {
        Err(WatchError::unavailable(
            "this build has no OS filesystem watcher, so an ordinary folder has no source of \
             changes",
        )
        .into())
    }
}
