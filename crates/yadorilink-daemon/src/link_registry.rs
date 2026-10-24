//! Owns this device's live per-link runtime state: which links currently
//! have a running watcher/executor/repair task set, the notification
//! primitive `stop_link_watch`/`start_link_watch` use to coordinate
//! concurrent transitions on the same path, the per-path locks serializing
//! overlapping `stop_link_watch` calls, and which links are currently
//! degraded by disk pressure or waiting for their folder's volume. Every
//! field is private -- every caller
//! reaches them through this type's own methods.
//!
//! `LinkSlot` and the `StartingReservation` RAII guard live here too now
//! (moved from `link_runtime.rs`) -- they are this registry's own internal
//! coordination state, not `LinkRuntime`'s. `link_runtime.rs` depends on
//! this module (for `LinkRegistry`/`DrainedLink`), never the reverse.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::error::DaemonError;
use crate::link_runtime::LinkRuntime;
use crate::start_gate_core::{ReserveError, SlotTable};

/// A `LinkRegistry` entry: either a start attempt in progress (nothing to
/// serve yet, but a real, visible placeholder — see [`StartingReservation`]'s
/// own doc for the race this closes) or a fully published, running link.
enum LinkSlot {
    Starting,
    Ready(Arc<LinkRuntime>),
}

/// RAII reservation for a `LinkSlot::Starting` entry, held for
/// `start_link_watch_inner`'s whole fallible setup.
///
/// Closes a start-vs-stop race `LinkRuntime`'s single-atomic-insert design
/// does not, on its own, prevent: before this guard existed,
/// `start_link_watch_inner` published nothing into the registry until every
/// fallible step had already succeeded, so a concurrent `stop_link_watch`
/// (or `control_socket::unlink`, which calls it) for the SAME path arriving
/// mid-start-attempt would find nothing, return immediately, and `unlink`
/// would go on to delete the link's DB row — only for the still-running
/// start attempt to finish moments later and publish a live `LinkRuntime`
/// for a link whose database row no longer exists, a genuine zombie:
/// watching, indexing, and broadcasting for a link `SyncState` itself no
/// longer knows about.
///
/// Reserving `Starting` as the very first step (`reserve_starting`, before
/// any other fallible work, including `begin_group_startup`) makes the
/// start attempt visible immediately, so `stop_link_watch` waits for it
/// (via `wait_and_take_ready`) instead of racing past it. Reservation
/// itself fails if an entry (starting OR ready) already exists for this
/// path -- two concurrent start attempts for the same path is a real shape
/// (a retried `link` control-socket call) that must refuse the second, not
/// let it clobber the first's slot.
pub(crate) struct StartingReservation {
    registry: Arc<LinkRegistry>,
    local_path: String,
    resolved: bool,
}

impl StartingReservation {
    /// Success path: replaces the `Starting` reservation with the fully
    /// built runtime, in one atomic map operation, and wakes any
    /// `stop_link_watch` call waiting on this path's slot to resolve.
    pub(crate) fn publish(mut self, runtime: Arc<LinkRuntime>) {
        self.registry.publish_ready(&self.local_path, runtime);
        self.resolved = true;
    }
}

impl Drop for StartingReservation {
    fn drop(&mut self) {
        if !self.resolved {
            // Every fallible step in `start_link_watch_inner` returns via
            // `?` on failure, unwinding straight past `publish` -- this is
            // the failure path's cleanup, symmetric with `GroupStartup
            // ReadyGuard`'s identical "explicit success call defuses a
            // fail-closed Drop" shape.
            self.registry.remove_starting_reservation(&self.local_path);
        }
    }
}

/// One drained entry from [`LinkRegistry::drain_for_shutdown`] -- a plain,
/// public shape so callers outside this module (whole-process shutdown)
/// never need to know about the private `LinkSlot` enum.
pub(crate) enum DrainedLink {
    Starting { local_path: String },
    Ready { local_path: String, runtime: Arc<LinkRuntime> },
}

/// A linked folder's Degraded (disk-pressure) state -- in-memory only,
/// deliberately not persisted: it's re-derived from live disk state on the very next
/// preflight/re-check either way, so persisting it across a restart would
/// only risk it going stale.
#[derive(Debug, Clone)]
pub struct DegradedLinkInfo {
    /// Human-readable cause (the triggering `SyncError::DiskPressure`'s
    /// `Display`), shown by `yadorilink status`.
    pub reason: String,
    pub since_unix: i64,
    /// how many consecutive re-checks have found the link still
    /// under pressure -- drives `BackoffConfig::DEGRADED_LINK_RECHECK`'s
    /// increasing interval. `0` for a link that just became degraded.
    pub backoff_attempt: u32,
    pub next_recheck_unix: i64,
    /// Terminal (ownership lost): never rechecked; only relink/restart clears it.
    pub terminal: bool,
    /// Why the link is degraded. Status reports this, never a match on `reason`.
    pub cause: DegradedCause,
}

/// Why a link is degraded: the one typed cause every consumer (status, rollup, shells) keys on.
/// The human text beside it (`DegradedLinkInfo::reason`) is detail only and never decides
/// anything. Mirrors the wire `DegradedCause`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradedCause {
    /// A receive or provider read was refused for lack of disk space; clears by itself.
    WaitingForDiskSpace,
    /// The OS file-watch limit is hit; only the user can raise it.
    FileWatchLimit,
    /// The ownership marker is gone; only re-linking or a restart clears it.
    OwnershipLost,
    /// An orphaned link: no longer joined to its folder group.
    NotJoined,
    /// Stopped with no more specific cause: shown as a stopped folder.
    Stopped,
}

impl DegradedCause {
    pub fn to_wire(self) -> yadorilink_ipc_proto::daemonctl::DegradedCause {
        use yadorilink_ipc_proto::daemonctl::DegradedCause as Wire;
        match self {
            Self::WaitingForDiskSpace => Wire::WaitingForDiskSpace,
            Self::FileWatchLimit => Wire::FileWatchLimit,
            Self::OwnershipLost => Wire::OwnershipLost,
            Self::NotJoined => Wire::NotJoined,
            Self::Stopped => Wire::Unspecified,
        }
    }
}

/// The detail of a folder whose build has no OS watcher.
pub const NO_CHANGE_SOURCE_REASON: &str = "This build cannot watch ordinary folders for changes, \
     so this folder is not syncing. Use a provider folder on this platform.";

/// Opening words of the human detail of a link waiting for free disk space. Text only: nothing
/// may decide the state from it (see `DegradedLinkInfo::cause`).
const WAITING_FOR_DISK_SPACE_DETAIL: &str = "Waiting for disk space";

/// The Degraded reason of a link that is waiting for free disk space: what stalled, how much
/// room is left, how much must stay free, and what to do. Sync resumes by itself once the
/// volume has room again.
pub fn waiting_for_disk_space_reason(
    volume: &str,
    available_bytes: u64,
    required_free_bytes: u64,
) -> String {
    format!(
        "{WAITING_FOR_DISK_SPACE_DETAIL} on {volume}: {available_bytes} bytes free, \
         {required_free_bytes} bytes must stay free; free up space on that volume and \
         syncing resumes automatically"
    )
}

/// `DegradedLinkInfo::reason` (human detail) of an ownership-lost link.
pub const OWNERSHIP_LOST_REASON: &str = "ownership_lost";

/// The degraded reason of an orphaned link (one that no longer takes part in sync because its
/// folder group was not joined again, or its authorization is gone). Human detail only.
pub const NOT_JOINED_REASON: &str =
    "not joined to its folder group; accept an invite to it again, or unlink this folder";

/// A link's OS file-watch-limit condition. In memory only: it is re-derived by
/// the very next watch registration, so persisting it could only go stale.
#[derive(Debug, Clone)]
struct WatchLimitEntry {
    /// The live watcher's flag (see `FolderWatcher::watch_limited_flag`); a
    /// link that failed to start holds a flag that is permanently set.
    flag: Arc<AtomicBool>,
    /// The watcher could not be bound at all, so the link is not running.
    startup_failed: bool,
}

/// The fix for an exhausted OS watch limit, in the words `status` and
/// `doctor` show (Linux only: no other platform's watcher has this limit).
pub const WATCH_LIMIT_FIX: &str = "raise fs.inotify.max_user_watches (e.g. \
    `sudo sysctl fs.inotify.max_user_watches=524288`, and persist it in /etc/sysctl.d), \
    then restart yadorilink";

pub struct LinkRegistry {
    /// local_path -> that link's single runtime record: `Starting`
    /// (published as soon as `start_link_watch` commits to bringing the
    /// link up, before any fallible step runs, so a racing
    /// `stop_link_watch` can see it and wait rather than finding nothing),
    /// replaced by `LinkSlot::Ready` once every fallible step has
    /// succeeded, and removed as a single entry by `stop_link_watch`.
    link_runtimes: SlotTable<LinkSlot>,
    /// Notified whenever a `link_runtimes` entry transitions. A single,
    /// device-wide `Notify` rather than one per path: contention is a
    /// `stop_link_watch` call finding a `Starting` entry it must wait out,
    /// which is rare (link start is fast) and self-limiting, so the cost
    /// of every waiter re-checking its own path on every transition
    /// anywhere is not worth a per-path map's bookkeeping.
    link_lifecycle_notify: tokio::sync::Notify,
    /// local_path -> a lock serializing concurrent `stop_link_watch` calls
    /// for that same path. An `async` lock, not `std::sync::Mutex`: held
    /// across `stop_link_watch`'s own awaits. Entries are never removed (a
    /// link's local_path is reused across relink/unlink cycles, and a
    /// small number of long-lived per-path locks is not worth the
    /// bookkeeping to prune).
    link_watch_stop_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// local_path -> Degraded (disk-pressure) state for that link.
    degraded_links: Mutex<HashMap<String, DegradedLinkInfo>>,
    /// local_path -> its OS file-watch-limit condition, if one was ever hit.
    watch_limits: Mutex<HashMap<String, WatchLimitEntry>>,
    /// Links whose start was refused because the folder is missing or off
    /// the volume recorded for it (an unmounted or replaced disk). Started
    /// again once the folder is back; in-memory only, since every daemon
    /// start re-derives it.
    awaiting_volume: Mutex<HashSet<String>>,
    /// Links whose volume probe is still running (a hung network mount): the
    /// next probe of the same folder is skipped rather than stacked on it.
    volume_probes: Mutex<HashSet<String>>,
}

/// Held by a safe-stop request: new link starts are refused until it is dropped. Dropping it
/// (a failed, busy or cancelled stop) reopens the gate; [`StartGate::keep_closed`] leaves it
/// closed for good once the stop is committed and the process is shutting down.
pub(crate) struct StartGate {
    registry: Option<Arc<LinkRegistry>>,
}

impl StartGate {
    pub(crate) fn keep_closed(mut self) {
        self.registry = None;
    }
}

impl Drop for StartGate {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.take() {
            registry.link_runtimes.open_gate();
        }
    }
}

/// Held while one link's volume probe runs; see [`LinkRegistry::begin_volume_probe`].
pub(crate) struct VolumeProbe {
    registry: Arc<LinkRegistry>,
    local_path: String,
}

impl Drop for VolumeProbe {
    fn drop(&mut self) {
        self.registry
            .volume_probes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.local_path);
    }
}

impl LinkRegistry {
    pub(crate) fn new() -> Self {
        Self {
            link_runtimes: SlotTable::new(),
            link_lifecycle_notify: tokio::sync::Notify::new(),
            link_watch_stop_locks: Mutex::new(HashMap::new()),
            degraded_links: Mutex::new(HashMap::new()),
            watch_limits: Mutex::new(HashMap::new()),
            awaiting_volume: Mutex::new(HashSet::new()),
            volume_probes: Mutex::new(HashSet::new()),
        }
    }

    /// Refuses new link starts until the returned gate is dropped. A start already reserved is
    /// not interrupted; [`Self::wait_no_starting`] waits it out.
    pub(crate) fn close_start_gate(registry: &Arc<LinkRegistry>) -> StartGate {
        registry.link_runtimes.close_gate();
        StartGate { registry: Some(Arc::clone(registry)) }
    }

    /// Returns once no link is `Starting`. With the start gate closed, none can begin again.
    pub(crate) async fn wait_no_starting(&self) {
        loop {
            let notified = self.link_lifecycle_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let any_starting =
                self.lock_runtimes().values().any(|slot| matches!(slot, LinkSlot::Starting));
            if !any_starting {
                return;
            }
            notified.await;
        }
    }

    /// Claims `local_path`'s volume probe; `None` while a previous one is
    /// still running.
    pub(crate) fn begin_volume_probe(
        registry: &Arc<LinkRegistry>,
        local_path: &str,
    ) -> Option<VolumeProbe> {
        let claimed = registry
            .volume_probes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(local_path.to_string());
        claimed.then(|| VolumeProbe {
            registry: Arc::clone(registry),
            local_path: local_path.to_string(),
        })
    }

    fn lock_awaiting_volume(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.awaiting_volume.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Records that `local_path`'s start was refused because its folder is
    /// not on its recorded volume.
    pub fn mark_awaiting_volume(&self, local_path: &str) {
        self.lock_awaiting_volume().insert(local_path.to_string());
    }

    /// A link that started (or was unlinked) is no longer waiting.
    pub fn clear_awaiting_volume(&self, local_path: &str) {
        self.lock_awaiting_volume().remove(local_path);
    }

    pub fn is_awaiting_volume(&self, local_path: &str) -> bool {
        self.lock_awaiting_volume().contains(local_path)
    }

    fn lock_runtimes(&self) -> std::sync::MutexGuard<'_, HashMap<String, LinkSlot>> {
        self.link_runtimes.lock()
    }

    fn lock_degraded(&self) -> std::sync::MutexGuard<'_, HashMap<String, DegradedLinkInfo>> {
        self.degraded_links.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_watch_limits(&self) -> std::sync::MutexGuard<'_, HashMap<String, WatchLimitEntry>> {
        self.watch_limits.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    // --- watch_limits -----------------------------------------------------

    /// Records `local_path`'s watcher as bound, tracking its live limit flag.
    pub fn track_watcher(&self, local_path: &str, flag: Arc<AtomicBool>) {
        self.lock_watch_limits()
            .insert(local_path.to_string(), WatchLimitEntry { flag, startup_failed: false });
    }

    /// Records that `local_path`'s watcher could not be bound for lack of
    /// watches, so the link is not running.
    pub fn record_watch_limit_startup_failure(&self, local_path: &str) {
        self.lock_watch_limits().insert(
            local_path.to_string(),
            WatchLimitEntry { flag: Arc::new(AtomicBool::new(true)), startup_failed: true },
        );
    }

    /// Forgets `local_path`'s watch-limit condition (its watcher bind failed
    /// for another reason, so the old condition no longer describes it).
    pub fn clear_watch_limit(&self, local_path: &str) {
        self.lock_watch_limits().remove(local_path);
    }

    /// What to tell the user about `local_path`'s watch limit, if it is hit
    /// right now.
    pub fn watch_limit_reason(&self, local_path: &str) -> Option<String> {
        let limits = self.lock_watch_limits();
        let entry = limits.get(local_path)?;
        if !entry.flag.load(Ordering::Relaxed) {
            return None;
        }
        Some(if entry.startup_failed {
            format!(
                "OS file watch limit reached; this folder is not syncing. Fix: {WATCH_LIMIT_FIX}"
            )
        } else {
            format!(
                "OS file watch limit reached; some folders are only picked up by periodic \
                 rescans, so changes arrive late. Fix: {WATCH_LIMIT_FIX}"
            )
        })
    }

    /// Every link whose watch limit is hit right now.
    pub fn watch_limited_paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = self
            .lock_watch_limits()
            .iter()
            .filter(|(_, e)| e.flag.load(Ordering::Relaxed))
            .map(|(p, _)| p.clone())
            .collect();
        paths.sort();
        paths
    }

    // --- link_runtimes / lifecycle -----------------------------------

    /// Reserves `local_path` as `Starting`, the very first step of
    /// `start_link_watch_inner`'s fallible setup -- `Err` if any entry
    /// (`Starting` or `Ready`) already exists for this path. `registry`
    /// must be the same `Arc<LinkRegistry>` the caller holds (typically
    /// `Arc::clone(&state.links)`); the returned guard clones it so it can
    /// resolve itself on `publish`/`Drop` without needing `DaemonState`.
    pub(crate) fn reserve_starting(
        registry: &Arc<LinkRegistry>,
        local_path: String,
    ) -> Result<StartingReservation, DaemonError> {
        registry.link_runtimes.reserve(local_path.clone(), LinkSlot::Starting).map_err(
            |e| match e {
                ReserveError::GateClosed => DaemonError::SafeStopInProgress,
                ReserveError::Occupied => DaemonError::Config(format!(
                    "a watch is already starting or running for {local_path}"
                )),
            },
        )?;
        Ok(StartingReservation { registry: Arc::clone(registry), local_path, resolved: false })
    }

    /// Replaces a `Starting` reservation with the fully built runtime and
    /// wakes every `stop_link_watch` call waiting on this path's slot to
    /// resolve. Only called by [`StartingReservation::publish`].
    fn publish_ready(&self, local_path: &str, runtime: Arc<LinkRuntime>) {
        self.lock_runtimes().insert(local_path.to_string(), LinkSlot::Ready(runtime));
        self.link_lifecycle_notify.notify_waiters();
    }

    /// Removes a `Starting` reservation (the failure path of
    /// [`StartingReservation`]'s `Drop`) and wakes any waiter.
    fn remove_starting_reservation(&self, local_path: &str) {
        self.lock_runtimes().remove(local_path);
        self.link_lifecycle_notify.notify_waiters();
    }

    /// The live runtime for `local_path`, if its slot is `Ready` -- `None`
    /// for `Starting` or absent alike (nothing to act on yet either way).
    pub fn runtime(&self, local_path: &str) -> Option<Arc<LinkRuntime>> {
        match self.lock_runtimes().get(local_path) {
            Some(LinkSlot::Ready(runtime)) => Some(runtime.clone()),
            Some(LinkSlot::Starting) | None => None,
        }
    }

    /// The root lease of every link whose runtime is up. A link still starting has none yet.
    pub(crate) fn ready_root_leases(
        &self,
    ) -> Vec<Arc<yadorilink_root_authority::root_commit::RootLease>> {
        self.lock_runtimes()
            .values()
            .filter_map(|slot| match slot {
                LinkSlot::Ready(runtime) => Some(runtime.root_lease().clone()),
                LinkSlot::Starting => None,
            })
            .collect()
    }

    /// Whether any entry (`Starting` or `Ready`) exists for `local_path`.
    pub fn has_entry(&self, local_path: &str) -> bool {
        self.lock_runtimes().contains_key(local_path)
    }

    /// Waits out a `Starting` entry rather than treating it as absent (see
    /// [`StartingReservation`]'s own doc for the zombie-runtime race this
    /// closes), then removes and returns the `Ready` runtime, if any.
    /// Panics if the slot is somehow still `Starting` once the wait loop
    /// exits -- provably unreachable, since nothing between this method's
    /// own observation and its own removal can turn a `Ready` entry back
    /// into `Starting` (`reserve_starting` refuses a path that already
    /// has any entry), and callers serialize concurrent calls for the same
    /// path via [`Self::stop_lock`] before calling this.
    pub async fn wait_and_take_ready(&self, local_path: &str) -> Option<Arc<LinkRuntime>> {
        loop {
            let notified = self.link_lifecycle_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let is_starting =
                matches!(self.lock_runtimes().get(local_path), Some(LinkSlot::Starting));
            if is_starting {
                notified.await;
                continue;
            }
            break;
        }
        self.lock_watch_limits().remove(local_path);
        match self.lock_runtimes().remove(local_path) {
            None => None,
            Some(LinkSlot::Ready(runtime)) => Some(runtime),
            Some(LinkSlot::Starting) => {
                unreachable!(
                    "wait_and_take_ready: {local_path} was Ready and is now Starting again"
                )
            }
        }
    }

    /// Removes `local_path`'s entry unconditionally, returning the runtime
    /// only if it was `Ready` -- used by best-effort teardown paths that
    /// don't need `wait_and_take_ready`'s Starting-aware wait (e.g. a test
    /// harness tearing down between seeds).
    pub fn remove_if_ready(&self, local_path: &str) -> Option<Arc<LinkRuntime>> {
        match self.lock_runtimes().remove(local_path) {
            Some(LinkSlot::Ready(runtime)) => Some(runtime),
            _ => None,
        }
    }

    /// Drains every entry, for whole-process shutdown -- each link's
    /// runtime (or in-flight `Starting` reservation) is handed to the
    /// caller to shut down independently and concurrently. Returns
    /// [`DrainedLink`], not the private `LinkSlot`, so shutdown code
    /// outside this module never needs to know that type exists.
    pub(crate) fn drain_for_shutdown(&self) -> Vec<DrainedLink> {
        self.lock_runtimes()
            .drain()
            .map(|(local_path, slot)| match slot {
                LinkSlot::Starting => DrainedLink::Starting { local_path },
                LinkSlot::Ready(runtime) => DrainedLink::Ready { local_path, runtime },
            })
            .collect()
    }

    /// The per-path lock serializing concurrent `stop_link_watch` calls
    /// for `local_path`, creating one if this is the first call for it.
    pub fn stop_lock(&self, local_path: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.link_watch_stop_locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(local_path.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    // --- degraded_links -------------------------------------------------

    /// Marks `local_path` Degraded (disk-pressure), scheduling its next
    /// re-check via `recheck_delay_secs` -- a link already degraded has its
    /// backoff attempt count bumped (spacing repeated pressure further
    /// apart) rather than reset, and keeps its original `since_unix` onset
    /// time. `recheck_delay_secs` takes the (possibly bumped) backoff
    /// attempt and returns how many seconds from now the next re-check is
    /// due, keeping the backoff policy itself in the caller
    /// (`supervise::BackoffConfig`) rather than duplicating it here.
    pub fn mark_degraded(
        &self,
        local_path: &str,
        reason: String,
        cause: DegradedCause,
        now_unix: i64,
        recheck_delay_secs: impl FnOnce(u32) -> i64,
    ) {
        let mut degraded = self.lock_degraded();
        if degraded.get(local_path).is_some_and(|i| i.terminal) {
            return;
        }
        let (since_unix, backoff_attempt) = match degraded.get(local_path) {
            Some(existing) => (existing.since_unix, existing.backoff_attempt + 1),
            None => (now_unix, 0),
        };
        let next_recheck_unix = now_unix + recheck_delay_secs(backoff_attempt);
        degraded.insert(
            local_path.to_string(),
            DegradedLinkInfo {
                reason,
                since_unix,
                backoff_attempt,
                next_recheck_unix,
                terminal: false,
                cause,
            },
        );
    }

    /// Marks `local_path` terminally OwnershipLost. Returns true only on the
    /// first transition, so callers log once.
    pub fn mark_ownership_lost(&self, local_path: &str, now_unix: i64) -> bool {
        let mut degraded = self.lock_degraded();
        if degraded.get(local_path).is_some_and(|i| i.terminal) {
            return false;
        }
        degraded.insert(
            local_path.to_string(),
            DegradedLinkInfo {
                reason: OWNERSHIP_LOST_REASON.to_string(),
                since_unix: now_unix,
                backoff_attempt: 0,
                next_recheck_unix: i64::MAX,
                terminal: true,
                cause: DegradedCause::OwnershipLost,
            },
        );
        true
    }

    pub fn is_ownership_lost(&self, local_path: &str) -> bool {
        self.lock_degraded()
            .get(local_path)
            .is_some_and(|i| i.terminal && i.cause == DegradedCause::OwnershipLost)
    }

    /// Marks `local_path` stopped because this build has no OS watcher, so the folder has no
    /// source of changes. Terminal: nothing in this build clears it but unlinking.
    pub fn mark_no_change_source(&self, local_path: &str, now_unix: i64) {
        self.lock_degraded().insert(
            local_path.to_string(),
            DegradedLinkInfo {
                reason: NO_CHANGE_SOURCE_REASON.to_string(),
                since_unix: now_unix,
                backoff_attempt: 0,
                next_recheck_unix: i64::MAX,
                terminal: true,
                cause: DegradedCause::Stopped,
            },
        );
    }

    /// Clears a terminal OwnershipLost mark (a fresh link start).
    pub fn clear_ownership_lost(&self, local_path: &str) {
        let mut degraded = self.lock_degraded();
        if degraded
            .get(local_path)
            .is_some_and(|i| i.terminal && i.cause == DegradedCause::OwnershipLost)
        {
            degraded.remove(local_path);
        }
    }

    /// Clears `local_path`'s disk-pressure Degraded state, if any -- a no-op if it
    /// wasn't degraded; a terminal OwnershipLost mark is left alone.
    pub fn clear_degraded(&self, local_path: &str) {
        let mut degraded = self.lock_degraded();
        if !degraded.get(local_path).is_some_and(|i| i.terminal) {
            degraded.remove(local_path);
        }
    }

    pub fn is_degraded(&self, local_path: &str) -> bool {
        self.lock_degraded().contains_key(local_path)
    }

    pub fn degraded_info(&self, local_path: &str) -> Option<DegradedLinkInfo> {
        self.lock_degraded().get(local_path).cloned()
    }

    /// Every Degraded link whose `next_recheck_unix` has elapsed, as
    /// `(local_path, info)` pairs -- the re-check sweep's own input.
    pub fn degraded_due_snapshot(&self, now_unix: i64) -> Vec<(String, DegradedLinkInfo)> {
        self.lock_degraded()
            .iter()
            .filter(|(_, info)| !info.terminal && info.next_recheck_unix <= now_unix)
            .map(|(path, info)| (path.clone(), info.clone()))
            .collect()
    }

    /// Test/harness-only: forces `local_path`'s next re-check to be due
    /// immediately, so a test doesn't have to wait out a real backoff
    /// window.
    #[cfg(test)]
    pub(crate) fn force_degraded_recheck_due_now(&self, local_path: &str, now_unix: i64) {
        if let Some(info) = self.lock_degraded().get_mut(local_path) {
            info.next_recheck_unix = now_unix - 1;
        }
    }
}

#[cfg(test)]
mod no_change_source_tests {
    use super::*;

    /// A folder with no source of changes is shown stopped, with the reason, and is not mistaken
    /// for a lost ownership marker (which a fresh link start clears).
    #[test]
    fn a_folder_without_a_change_source_is_stopped_with_its_reason() {
        let links = LinkRegistry::new();
        links.mark_no_change_source("/f", 7);
        let info = links.degraded_info("/f").unwrap();
        assert_eq!(info.cause, DegradedCause::Stopped);
        assert_eq!(
            info.cause.to_wire(),
            yadorilink_ipc_proto::daemonctl::DegradedCause::Unspecified
        );
        assert!(info.reason.contains("cannot watch ordinary folders"));
        assert!(info.terminal);
        assert!(!links.is_ownership_lost("/f"));
        links.clear_ownership_lost("/f");
        links.clear_degraded("/f");
        assert!(links.degraded_info("/f").is_some(), "neither clears it");
    }

    #[test]
    fn the_no_watcher_source_refuses_instead_of_running_without_changes() {
        use yadorilink_filesystem_sync::watcher::{FolderWatchSource, NoWatchSource};
        let dir = tempfile::tempdir().unwrap();
        let ignore = Arc::new(
            yadorilink_fs_platform::ignore_patterns::EffectiveIgnoreSet::load_for_link_root(
                dir.path(),
            )
            .unwrap(),
        );
        assert!(NoWatchSource.watch(dir.path(), ignore).is_err());
    }
}
