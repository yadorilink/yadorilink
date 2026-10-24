// apple-cfg-file: macos-only FSEvents is the macOS notify backend; iOS watches per directory like any non-FSEvents backend
//! The OS-backed folder watcher: `notify`, and on Windows `win_watch`. Compiled with the
//! `os-watch` feature, which a host that owns no watchable folders leaves off.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use notify::event::{ModifyKind, RenameMode};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use yadorilink_fs_platform::ignore_patterns::{is_ignore_file_relative_path, EffectiveIgnoreSet};
use yadorilink_fs_platform::reserved_namespace::path_has_reserved_component;

use super::{
    FolderWatchSource, FolderWatcher, FsChangeEvent, FsChangeKind, WatcherError, WatcherGuard,
    DEFAULT_CHANNEL_CAPACITY,
};

/// The OS watcher: `notify`'s, except on Windows, where `notify` ignores a
/// buffer overflow and the loss would go unnoticed (see `win_watch`).
#[cfg(not(windows))]
type PlatformWatcher = notify::RecommendedWatcher;
#[cfg(windows)]
type PlatformWatcher = crate::win_watch::RootWatcher;

/// Watches `root` with the default channel capacity — see
/// `watch_folder_with_capacity` for the full behavior and the overflow
/// flag's meaning.
pub fn watch_folder(root: &Path) -> Result<FolderWatcher, WatcherError> {
    watch_folder_with_capacity(root, DEFAULT_CHANNEL_CAPACITY)
}

pub fn watch_folder_with_ignore(
    root: &Path,
    ignore_set: Arc<EffectiveIgnoreSet>,
) -> Result<FolderWatcher, WatcherError> {
    watch_folder_with_capacity_and_ignore(root, DEFAULT_CHANNEL_CAPACITY, ignore_set)
}

/// Watches `root` for filesystem events, delivered on `FolderWatcher::events`
/// with the given channel `capacity`.
///
/// The OS callback (running on notify's own thread, not tokio) uses a
/// non-blocking `try_send` rather than `blocking_send`: it never blocks
/// waiting for a consumer, regardless of how full the channel gets or
/// how slow the consumer is. When the channel is full,
/// that specific event's data is unavoidably dropped — there is no way
/// to block without risking the *upstream* OS-level notification queue
/// (inotify/FSEvents/`ReadDirectoryChangesW`) overflowing instead, which
/// would be silent and undetectable. Instead, a drop is recorded via
/// `overflowed` (an `AtomicBool`, checked and cleared by the consumer —
/// see `FolderWatcher::split`), which the debounce accumulator treats as
/// a trigger for the same full-reconciliation recovery as an oversized
/// debounce burst: an overflow means precise per-path tracking is no
/// longer trustworthy, so only a full rescan restores a correct index —
/// but nothing is ever silently, permanently lost.
pub fn watch_folder_with_capacity(
    root: &Path,
    capacity: usize,
) -> Result<FolderWatcher, WatcherError> {
    let ignore_set = Arc::new(EffectiveIgnoreSet::load_for_link_root(root)?);
    watch_folder_with_capacity_and_ignore(root, capacity, ignore_set)
}

pub fn watch_folder_with_capacity_and_ignore(
    root: &Path,
    capacity: usize,
    ignore_set: Arc<EffectiveIgnoreSet>,
) -> Result<FolderWatcher, WatcherError> {
    let root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let (tx, rx) = mpsc::channel(capacity);
    let overflowed = Arc::new(AtomicBool::new(false));
    let callback_overflowed = overflowed.clone();
    let watcher_holder: Arc<Mutex<Option<PlatformWatcher>>> = Arc::new(Mutex::new(None));
    let watched_dirs = Arc::new(Mutex::new(BTreeSet::new()));
    let callback_root = root.clone();
    let callback_ignore_set = ignore_set.clone();

    // The callback below must never call `RecommendedWatcher::watch`
    // itself (see the module doc comment) — it only ever sends the
    // newly-observed directory's path over this unbounded channel.
    // Unbounded (not the bounded, drop-on-full `tx`/`overflowed` pair
    // above): a dropped `FsChangeEvent` is recoverable by design (the
    // consumer's overflow-triggered full rescan, per `watch_folder_with_
    // capacity`'s doc comment), but a dropped new-directory registration
    // request has no such recovery path — the directory's watch would
    // simply never be registered, and nothing would ever retry it. These
    // messages are just `PathBuf`s and only ever produced on genuine new-
    // directory events (not a hot per-event path), so never bounding this
    // channel is safe.
    let (new_dir_tx, new_dir_rx) = mpsc::unbounded_channel::<RegistrarTrigger>();
    let callback_new_dir_tx = new_dir_tx.clone();
    // The registrar task (spawned below, after `watcher_holder` is
    // populated) needs its own handle to synthesize reconciliation events
    // through the same `FsChangeEvent` channel/overflow flag the callback
    // uses — cloned here, before `tx`/`overflowed` are moved into the
    // callback closure below.
    let registrar_tx = tx.clone();
    let registrar_overflowed = overflowed.clone();
    let watch_limited = Arc::new(AtomicBool::new(false));
    let registrar_watch_limited = watch_limited.clone();

    let mut watcher = PlatformWatcher::new(
        move |res: notify::Result<Event>| {
            // Changes may have been lost (an overflowed buffer, a failed
            // watcher): only a full reconciliation restores a correct index.
            // The flag is only looked at when the debouncer runs, so a
            // synthetic event for the root wakes it.
            if crate::win_watch::result_means_changes_were_lost(&res) {
                callback_overflowed.store(true, Ordering::Relaxed);
                let _ = tx.try_send(FsChangeEvent {
                    path: callback_root.clone(),
                    kind: FsChangeKind::CreatedOrModified,
                });
                return;
            }
            let Ok(event) = res else { return };
            let enqueue_path = |path: PathBuf, kind: FsChangeKind| {
                if !should_queue_path(&callback_root, &callback_ignore_set, &path, kind) {
                    return;
                }
                // `path.is_dir` follows a symlink to decide, which would let
                // a freshly-created symlink-to-directory register recursive
                // watches into whatever it points to (including outside
                // `root`) — use an lstat-equivalent check instead so a
                // symlink is never treated as something to descend into,
                // matching the scanner's lstat-first classification.
                if matches!(kind, FsChangeKind::CreatedOrModified) && is_real_directory(&path) {
                    // Send-only, off this callback thread — see the module
                    // doc comment and `spawn_new_directory_registrar` below.
                    // `send` on an unbounded channel only fails if the
                    // receiving task is gone (shutdown race), never because
                    // it's full; either way there is nothing more to do here.
                    let _ = callback_new_dir_tx.send(RegistrarTrigger::NewDirectory(path.clone()));
                }
                // A removal may be a watched directory's: the registrar drops
                // it (and what was below it) from the registered set, so the
                // directory is registered again if it is made anew.
                if matches!(kind, FsChangeKind::ObservedRemoval) {
                    let _ = callback_new_dir_tx.send(RegistrarTrigger::Removed(path.clone()));
                }
                // Zero-field `phase T_*` marker: a timestamp anchor for offline
                // timing analysis of captured logs.
                if matches!(kind, FsChangeKind::CreatedOrModified) {
                    tracing::trace!("phase T_watch: raw filesystem watcher event received");
                }
                if tx.try_send(FsChangeEvent { path, kind }).is_err() {
                    callback_overflowed.store(true, Ordering::Relaxed);
                }
            };

            // A plain `EventKind::Modify(_) => CreatedOrModified` blanket
            // match (the previous behavior) misclassifies a rename's *source*
            // path as a live edit — `process_event` then sees the path no
            // longer exists on disk and just drops the event (`None`), so the
            // old path's index row is never tombstoned and propagates to
            // peers as live forever. `ModifyKind::Name` carries a `RenameMode`
            // telling us which of the (possibly two) `event.paths` is the old
            // path, the new path, or both — classify each accordingly instead
            // of collapsing every rename mode to `CreatedOrModified`.
            if let EventKind::Modify(ModifyKind::Name(rename_mode)) = event.kind {
                let pairs: Vec<(PathBuf, FsChangeKind)> = match rename_mode {
                    RenameMode::From => event
                        .paths
                        .into_iter()
                        .map(|p| (p, FsChangeKind::ObservedRemoval))
                        .collect(),
                    RenameMode::To => event
                        .paths
                        .into_iter()
                        .map(|p| (p, FsChangeKind::CreatedOrModified))
                        .collect(),
                    RenameMode::Both => {
                        let mut paths = event.paths.into_iter();
                        match (paths.next(), paths.next()) {
                            (Some(from), Some(to)) => {
                                vec![
                                    (from, FsChangeKind::ObservedRemoval),
                                    (to, FsChangeKind::CreatedOrModified),
                                ]
                            }
                            // Malformed (should always carry exactly two paths
                            // per notify's own contract) — fail soft rather
                            // than panic or silently drop.
                            (Some(only), None) => vec![(only, FsChangeKind::CreatedOrModified)],
                            (None, _) => vec![],
                        }
                    }
                    // `Any`/`Other`: the backend can't tell us which side this
                    // is. Treating it as a removal risks false-tombstoning a
                    // file that was actually just renamed *in* (not deleted);
                    // treating it as CreatedOrModified — the previous,
                    // unconditional behavior — is the conservative choice
                    // here, same as before this fix for these two modes.
                    RenameMode::Any | RenameMode::Other => event
                        .paths
                        .into_iter()
                        .map(|p| (p, FsChangeKind::CreatedOrModified))
                        .collect(),
                };
                for (path, kind) in pairs {
                    enqueue_path(path, kind);
                }
                return;
            }

            let kind = match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => FsChangeKind::CreatedOrModified,
                EventKind::Remove(_) => FsChangeKind::ObservedRemoval,
                _ => return,
            };
            for path in event.paths {
                enqueue_path(path, kind);
            }
        },
        notify::Config::default(),
    )
    .map_err(WatcherError::from)?;

    {
        let mut watched = watched_dirs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        register_initial_watches(&mut watcher, &mut watched, &root, &ignore_set, ROOT_WATCH)?;
    }
    *watcher_holder.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(watcher);

    // The registrar task owns only a `Weak` handle to `watcher_holder` —
    // the `WatcherGuard` returned below (via `FolderWatcher`/`FolderWatcher::
    // split`) holds the only strong `Arc`. When that guard is dropped, the
    // `RecommendedWatcher` (and, with it, this closure and its own
    // `new_dir_tx` clone) is dropped, so `new_dir_rx.recv` below
    // eventually returns `None` and this task exits on its own — no
    // separate abort handle is needed, and this task's lifetime is tied
    // exactly to the underlying OS watch's, matching `WatcherGuard`'s own
    // documented contract ("dropping it stops watching").
    spawn_new_directory_registrar(
        Arc::downgrade(&watcher_holder),
        watched_dirs,
        root.clone(),
        ignore_set,
        new_dir_rx,
        registrar_tx,
        RegistrarFlags { overflowed: registrar_overflowed, watch_limited: registrar_watch_limited },
    );

    Ok(FolderWatcher {
        _watcher: WatcherGuard { _guard: Box::new(watcher_holder) },
        events: rx,
        overflowed,
        watch_limited,
    })
}

/// The real, OS-backed `FolderWatchSource` — what every production
/// caller and today's existing tests use.
pub struct RealFolderWatchSource;

impl FolderWatchSource for RealFolderWatchSource {
    fn watch(
        &self,
        root: &Path,
        ignore_set: Arc<EffectiveIgnoreSet>,
    ) -> Result<FolderWatcher, WatcherError> {
        watch_folder_with_ignore(root, ignore_set)
    }
}

/// Runs off the FSEvents/inotify/`ReadDirectoryChangesW` callback thread —
/// see the module doc comment for why that call site can never do this
/// work itself. Receives newly-observed directory paths from the callback
/// closure (`new_dir_rx`) purely as a trigger signal — see below for why
/// the actual registration scan below always starts at `root`, not at the
/// specific path a given trigger names.
///
/// A `watch` call opens an OS-level blind window (module doc comment)
/// that can lose a live event for *any* currently-watched path, not only
/// the specific directory that triggered this iteration — so scanning
/// only that one directory's subtree (the original, narrower approach)
/// cannot discover a directory that appeared elsewhere in the tree as a
/// result of a lost event (e.g. a
/// lost rename's *destination* name, which the callback never got a
/// chance to report at all). Scanning from `root` instead — via
/// `register_new_directory_tree`, unchanged except for this call's `start`
/// argument — is index-free and safe to run this often: it is a pure
/// path-registration walk (`register_non_ignored_directories`'s existing
/// logic, exactly what the initial startup registration already does from
/// `root`), calling `watcher.watch` only for directories not already in
/// `watched_dirs`; every already-known directory is untouched. This
/// deliberately does *not* reuse the watcher-channel-overflow /
/// `DebounceFlush::RescanRequired` full index-vs-disk reconciliation
/// (`local_change.rs::scan_existing_files_with_ignore`) as the recovery
/// mechanism — confirmed via direct experiment that doing so is unsafe:
/// triggering it this often (once per directory-watch registration, not
/// only on a rare genuine channel overflow) can re-derive and re-version
/// a file that is concurrently mid-conflict-resolution between two
/// devices, colliding with peer_session.rs's own version-vector
/// comparison and permanently stalling convergence (reproduced
/// deterministically, isolated from unrelated confounds, with
/// `directory_conflict_matrix.rs`'s `concurrently_creating_same_named_
/// directory_with_a_conflicting_file_inside` — a file it never touches).
/// The scan below cannot cause this: it never looks at file content or the
/// index, only at which *directories* are already watched.
///
/// For every directory this scan newly registers (including, but not
/// limited to, the one that triggered this iteration), closes the
/// registration-race window (a write landing in the gap between
/// "directory observed" and "watch registered" would otherwise be
/// silently missed forever) by synthesizing a
/// `CreatedOrModified` event for every real file already present in it,
/// exactly as if the watcher had observed each one live — this is what
/// recovers a lost rename's destination content: it was never reported as
/// "new" by the callback, but this scan still discovers it directly on
/// disk and registers/reconciles it like any other not-yet-watched
/// directory.
///
/// Requires an active tokio runtime (`tokio::spawn`) — true of every real
/// caller: `link_manager::start_link_watch` runs inside the daemon's tokio
/// runtime, and this module's own tests are all `#[tokio::test]`.
fn spawn_new_directory_registrar(
    watcher_holder: Weak<Mutex<Option<PlatformWatcher>>>,
    watched_dirs: Arc<Mutex<BTreeSet<PathBuf>>>,
    root: PathBuf,
    ignore_set: Arc<EffectiveIgnoreSet>,
    mut new_dir_rx: mpsc::UnboundedReceiver<RegistrarTrigger>,
    tx: mpsc::Sender<FsChangeEvent>,
    flags: RegistrarFlags,
) {
    tokio::spawn(async move {
        let RegistrarFlags { overflowed, watch_limited } = flags;
        // When a registration failed, the next attempt and how many have
        // failed in a row. The failure is not reported to anyone else: no
        // event names the directory again, so without this it would stay
        // unwatched for as long as the link runs.
        let mut retry: Option<(tokio::time::Instant, u32)> = None;
        loop {
            let first = match retry {
                Some((due, _)) => tokio::select! {
                    trigger = new_dir_rx.recv() => match trigger {
                        Some(trigger) => trigger,
                        None => break,
                    },
                    () = tokio::time::sleep_until(due) => RegistrarTrigger::RetryRegistration,
                },
                None => match new_dir_rx.recv().await {
                    Some(trigger) => trigger,
                    None => break,
                },
            };
            // One pass serves every trigger queued while the last one ran:
            // registration starts from `root` whichever directory
            // triggered it, so running it once per queued trigger only
            // repeats the same walk (and the re-reports below).
            let mut queued = vec![first];
            while let Ok(more) = new_dir_rx.try_recv() {
                queued.push(more);
            }
            let mut triggers = Vec::new();
            for trigger in queued {
                match trigger {
                    RegistrarTrigger::NewDirectory(path) => triggers.push(path),
                    RegistrarTrigger::RetryRegistration => {}
                    RegistrarTrigger::Removed(path) => {
                        let mut watched =
                            watched_dirs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                        forget_removed_directories(&mut watched, &path);
                    }
                }
            }
            if triggers.is_empty() && retry.is_none() {
                continue;
            }
            if ROOT_WATCH == RootWatch::Recursive {
                // The root's one recursive watch already covers every new
                // directory: nothing to register, so no watch call and no
                // blind window. What a directory moved or copied in holds
                // is still named by no event of its own, so a directory not
                // seen before has its contents re-reported. One already
                // known (an event for its mode, its attributes, or a
                // repeat) re-reports nothing.
                let new_dirs = {
                    let mut watched =
                        watched_dirs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    newly_known_directories(&mut watched, &root, &triggers, &ignore_set)
                };
                for new_dir in &new_dirs {
                    reconcile_new_directory_subtree(&tx, &overflowed, &root, new_dir, &ignore_set);
                }
                continue;
            }
            match register_new_directory_tree(
                &watcher_holder,
                &watched_dirs,
                &root,
                &root,
                &ignore_set,
            ) {
                Ok(newly_registered) if !newly_registered.is_empty() => {
                    retry = None;
                    watch_limited.store(false, Ordering::Relaxed);
                    // Strictly after `watch` has succeeded for each of
                    // these subtrees, never concurrent with it.
                    for dir in &newly_registered {
                        reconcile_new_directory_subtree(&tx, &overflowed, &root, dir, &ignore_set);
                    }
                }
                Ok(_) => {
                    retry = None;
                    watch_limited.store(false, Ordering::Relaxed);
                    // Nothing was newly registered anywhere in the tree
                    // (e.g. a redundant notification for an
                    // already-watched directory, or the watcher/guard is
                    // already gone on a shutdown race) — no
                    // `watch`/`stop`/recreate cycle occurred, so no
                    // OS-level blind window could have opened; nothing to
                    // reconcile.
                }
                Err(err) => {
                    let failures = retry.map_or(1, |(_, failures)| failures + 1);
                    retry = Some((
                        tokio::time::Instant::now() + registration_retry_delay(failures),
                        failures,
                    ));
                    if err.is_watch_limit() {
                        // Directories the OS cannot watch are invisible to
                        // live events: fall back to the full rescan (the same
                        // path a lost-events overflow takes), once per retry.
                        if !watch_limited.swap(true, Ordering::Relaxed) {
                            tracing::warn!(
                                error = %err,
                                "OS file watch limit reached; unwatched folders are found only \
                                 by periodic rescans until the limit is raised"
                            );
                        }
                        overflowed.store(true, Ordering::Relaxed);
                        let _ = tx.try_send(FsChangeEvent {
                            path: root.clone(),
                            kind: FsChangeKind::CreatedOrModified,
                        });
                    }
                    tracing::debug!(
                        error = %err,
                        trigger = ?triggers.first(),
                        triggers = triggers.len(),
                        failures,
                        "failed to re-register the watched directory tree; will retry"
                    );
                    // Most often something in the new tree is already gone
                    // again (`mkdir` then `rmdir`). Re-report each new
                    // directory itself (capture classifies it from what is
                    // on disk now, a removal included) and what is in it.
                    for new_dir in &triggers {
                        reconcile_new_directory_subtree(
                            &tx,
                            &overflowed,
                            &root,
                            new_dir,
                            &ignore_set,
                        );
                        if tx
                            .try_send(FsChangeEvent {
                                path: new_dir.clone(),
                                kind: FsChangeKind::CreatedOrModified,
                            })
                            .is_err()
                        {
                            overflowed.store(true, Ordering::Relaxed);
                        }
                    }
                }
            }
        }
    });
}

/// Emits a synthesized `CreatedOrModified` event (through the same
/// channel/overflow discipline as a live callback event — using a
/// non-blocking `try_send`, never a blocking send that could stall this
/// a slow consumer) for every file, symlink (as a leaf, never followed) and directory
/// already present under `start`, so a
/// write that landed there before this subtree's watch registration
/// completed is still picked up by `local_change.rs`'s ordinary dispatch,
/// exactly as if the watcher had seen it live. Only ever called after
/// `register_new_directory_tree` reports `start` among the directories it
/// just newly registered (see `spawn_new_directory_registrar`) — never
/// concurrent with, or ahead of, that registration succeeding.
fn reconcile_new_directory_subtree(
    tx: &mpsc::Sender<FsChangeEvent>,
    overflowed: &Arc<AtomicBool>,
    root: &Path,
    start: &Path,
    ignore_set: &EffectiveIgnoreSet,
) {
    let walker = walkdir::WalkDir::new(start)
        .follow_links(false)
        .same_file_system(true)
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 {
                return true;
            }
            if !entry.file_type().is_dir() {
                return true;
            }
            if crate::device_boundary::is_foreign_device_dir(root, entry.path()) {
                return false;
            }
            let Ok(relative_path) = entry.path().strip_prefix(root) else { return false };
            !ignore_set.is_ignored(relative_path, true)
        });

    for entry in walker.filter_map(Result::ok) {
        // `file_type` is lstat-based here (no `follow_links`, matching
        // `register_non_ignored_directories`'s own reasoning), so a symlink
        // is neither `is_dir` nor `is_file`. It is reported as a leaf and
        // never descended into: a symlink created before this subtree's
        // watch registered is named by no other event. Every directory
        // below `start` is re-reported too: a directory is an entry
        // capture decides on its own, and an empty one moved or copied in
        // is named by no other event.
        let is_subdirectory = entry.depth() > 0 && entry.file_type().is_dir();
        if !entry.file_type().is_file() && !entry.file_type().is_symlink() && !is_subdirectory {
            continue;
        }
        let path = entry.path().to_path_buf();
        if !should_queue_path(root, ignore_set, &path, FsChangeKind::CreatedOrModified) {
            continue;
        }
        if tx.try_send(FsChangeEvent { path, kind: FsChangeKind::CreatedOrModified }).is_err() {
            overflowed.store(true, Ordering::Relaxed);
        }
    }
}

/// The watcher backends whose root-watch policy differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchBackend {
    /// FSEvents: registering a directory recreates the whole event stream,
    /// blinding it over every watched path.
    FsEvents,
    /// `ReadDirectoryChangesW`: a handle is held open on every watched
    /// directory, and NTFS refuses to rename a directory while any handle
    /// is open on a descendant of it -- so per-directory watches make
    /// renaming any folder that contains a subfolder fail with access
    /// denied.
    ReadDirectoryChanges,
    /// inotify and anything else: adding a watch touches no other.
    Other,
}

/// The backend this build runs on.
const WATCH_BACKEND: WatchBackend = if cfg!(target_os = "macos") {
    WatchBackend::FsEvents
} else if cfg!(windows) {
    WatchBackend::ReadDirectoryChanges
} else {
    WatchBackend::Other
};

/// How `backend` is to be watched: one recursive watch of the root where
/// per-directory registration is harmful (FSEvents, Windows), one watch
/// per directory otherwise.
const fn root_watch_for(backend: WatchBackend) -> RootWatch {
    match backend {
        WatchBackend::FsEvents | WatchBackend::ReadDirectoryChanges => RootWatch::Recursive,
        WatchBackend::Other => RootWatch::PerDirectory,
    }
}

/// The two flags the registrar raises: lost events (full rescan) and an
/// exhausted OS watch limit.
struct RegistrarFlags {
    overflowed: Arc<AtomicBool>,
    watch_limited: Arc<AtomicBool>,
}

/// What the directory registrar is told by the watcher callback.
#[derive(Debug)]
enum RegistrarTrigger {
    /// A directory appeared (or was modified) at this path.
    NewDirectory(PathBuf),
    /// Something at this path was removed; it may have been a watched
    /// directory.
    Removed(PathBuf),
    /// A registration failed earlier and is due again.
    RetryRegistration,
}

/// How long to wait before registration is tried again after `failures`
/// failures in a row: doubling from 100 ms, never more than 30 s.
fn registration_retry_delay(failures: u32) -> std::time::Duration {
    std::time::Duration::from_millis(100)
        .saturating_mul(1u32 << failures.saturating_sub(1).min(12))
        .min(std::time::Duration::from_secs(30))
}

/// How the root is watched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootWatch {
    /// One non-recursive watch per directory, each registered when the
    /// directory is first seen: inotify's model, where adding a watch
    /// touches no other.
    PerDirectory,
    /// One recursive watch of the root, registered once. On FSEvents,
    /// registering each new directory would blind the stream for every
    /// watched path each time a directory appears, and an event anywhere
    /// in the tree during that moment is never delivered. On Windows, a
    /// handle per directory blocks renaming any directory above a watched
    /// one. A recursive watch of the root never registers again and holds
    /// one handle, at the root.
    Recursive,
}

/// This platform's [`RootWatch`].
const ROOT_WATCH: RootWatch = root_watch_for(WATCH_BACKEND);

/// The watches a new watcher starts with: the root recursively, or every
/// non-ignored directory under it one by one. Every path watched is
/// recorded in `watched`.
fn register_initial_watches<W: Watcher>(
    watcher: &mut W,
    watched: &mut BTreeSet<PathBuf>,
    root: &Path,
    ignore_set: &EffectiveIgnoreSet,
    root_watch: RootWatch,
) -> Result<Vec<PathBuf>, WatcherError> {
    match root_watch {
        RootWatch::PerDirectory => {
            register_non_ignored_directories(watcher, watched, root, root, ignore_set)
        }
        RootWatch::Recursive => {
            watcher.watch(root, RecursiveMode::Recursive).map_err(WatcherError::from)?;
            // Every directory already there is known, so a later event on
            // one is not taken for a new directory.
            record_non_ignored_directories(watched, root, root, ignore_set, |_| Ok(()))?;
            Ok(vec![root.to_path_buf()])
        }
    }
}

/// Under a recursive root watch: records every directory under each of
/// `triggers` not yet known, and returns the ones whose contents are to be
/// re-reported -- each newly known directory not inside another one
/// returned (its subtree re-report covers them).
fn newly_known_directories(
    watched: &mut BTreeSet<PathBuf>,
    root: &Path,
    triggers: &[PathBuf],
    ignore_set: &EffectiveIgnoreSet,
) -> Vec<PathBuf> {
    let mut known = Vec::new();
    for trigger in triggers {
        // A known directory is not walked again: a directory made inside
        // it has an event of its own.
        if watched.contains(trigger) || !is_real_directory(trigger) {
            continue;
        }
        if let Ok(found) =
            record_non_ignored_directories(watched, root, trigger, ignore_set, |_| Ok(()))
        {
            known.extend(found);
        }
    }
    known.sort();
    let mut tops: Vec<PathBuf> = Vec::new();
    for dir in known {
        if !tops.iter().any(|top| dir.starts_with(top)) {
            tops.push(dir);
        }
    }
    tops
}

/// Drops `removed` and every registered directory below it from
/// `watched`. inotify ends a watch when its directory is deleted, so a
/// directory made again at the same path must be registered again, which
/// only happens for a path not in the set. Nothing is unwatched: the watch
/// the backend held is already gone.
///
/// Whatever is at `removed` now is not consulted. The removal and a
/// re-creation at the same path reach the registrar in that order, often
/// in one batch, so by the time the removal is handled the new directory
/// may already be there; keeping it in the set would leave it unwatched.
/// A directory forgotten while its watch is still live is registered again
/// by the next pass, which the backend treats as the watch it already has.
fn forget_removed_directories(watched: &mut BTreeSet<PathBuf>, removed: &Path) {
    let gone: Vec<PathBuf> = watched
        .range(removed.to_path_buf()..)
        .take_while(|path| path.starts_with(removed))
        .cloned()
        .collect();
    for path in gone {
        watched.remove(&path);
    }
}

fn should_queue_path(
    root: &Path,
    ignore_set: &EffectiveIgnoreSet,
    path: &Path,
    kind: FsChangeKind,
) -> bool {
    let Ok(relative_path) = path.strip_prefix(root) else { return false };
    if relative_path.as_os_str().is_empty() {
        return false;
    }
    // The reserved artefact namespace is excluded before anything else,
    // including the `.yadorilinkignore` special-case just below — a
    // transaction artefact must never be queued as a local change no
    // matter what a user's ignore file says about it.
    if path_has_reserved_component(relative_path) {
        return false;
    }
    if is_ignore_file_relative_path(relative_path) {
        return true;
    }
    // Lstat-equivalent, not `path.is_dir` — a symlink to a
    // directory must be treated as a (symlink) leaf for ignore-pattern
    // purposes, not as a directory, matching the scanner's classification
    // and keeping this consistent with `is_real_directory` above.
    let is_dir = matches!(kind, FsChangeKind::CreatedOrModified) && is_real_directory(path);
    !ignore_set.is_ignored(relative_path, is_dir)
}

/// True only for a genuine directory — never for a symlink, even one
/// whose target is a directory (the watcher must never treat a symlink
/// as something to register recursive/new-subtree watches into,
/// mirroring the scanner's lstat-first classification in
/// `local_change.rs`). `symlink_metadata` never follows the final path
/// component, unlike `Path::is_dir`.
fn is_real_directory(path: &Path) -> bool {
    path.symlink_metadata().map(|m| m.is_dir()).unwrap_or(false)
}

/// Now called only from `spawn_new_directory_registrar`'s tokio task,
/// never from the watcher callback thread directly (see the module doc
/// comment for why).
/// Returns an empty `Vec` both when registration genuinely finds nothing
/// new to watch and when there is nothing to do (the watcher has already
/// been dropped, e.g. a shutdown race between this call and
/// `FolderWatcher`/`WatcherGuard` being dropped) — the caller's
/// reconciling scan is harmless to run on an empty list in either case,
/// and treating "already gone" as an error would just be extra noise on
/// an ordinary shutdown path. A non-empty `Vec` lists every directory this
/// call newly registered a watch on (each is a genuine `stop`/recreate
/// cycle on the underlying OS watch — see the module doc comment — so the
/// caller reconciles each one's contents).
fn register_new_directory_tree(
    watcher_holder: &Weak<Mutex<Option<PlatformWatcher>>>,
    watched_dirs: &Arc<Mutex<BTreeSet<PathBuf>>>,
    root: &Path,
    start: &Path,
    ignore_set: &EffectiveIgnoreSet,
) -> Result<Vec<PathBuf>, WatcherError> {
    let Some(watcher_holder) = watcher_holder.upgrade() else { return Ok(Vec::new()) };
    let mut watcher_guard = watcher_holder.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(watcher) = watcher_guard.as_mut() else { return Ok(Vec::new()) };
    let mut watched = watched_dirs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    register_non_ignored_directories(watcher, &mut watched, root, start, ignore_set)
}

/// Returns every directory under `start`'s subtree this call newly
/// registered a watch on — empty when every directory in `start`'s
/// subtree was already registered, so no OS-level `stop`/recreate cycle
/// occurred and there is nothing for a caller to reconcile. A directory whose
/// registration fails is left out of `watched`, so a later call tries it
/// again.
fn register_non_ignored_directories<W: Watcher>(
    watcher: &mut W,
    watched: &mut BTreeSet<PathBuf>,
    root: &Path,
    start: &Path,
    ignore_set: &EffectiveIgnoreSet,
) -> Result<Vec<PathBuf>, WatcherError> {
    record_non_ignored_directories(watched, root, start, ignore_set, |dir| {
        watcher.watch(dir, RecursiveMode::NonRecursive).map_err(WatcherError::from)
    })
}

/// Walks every non-ignored directory under `start` (itself included),
/// records each not yet in `watched` and calls `on_new` for it; returns
/// those, in walk order.
fn record_non_ignored_directories(
    watched: &mut BTreeSet<PathBuf>,
    root: &Path,
    start: &Path,
    ignore_set: &EffectiveIgnoreSet,
    mut on_new: impl FnMut(&Path) -> Result<(), WatcherError>,
) -> Result<Vec<PathBuf>, WatcherError> {
    // Defense-in-depth: refuse to walk from a symlink root.
    // walkdir's `follow_links(false)` (explicit below) does NOT protect an
    // explicitly-given walk root — verified empirically that
    // `WalkDir::new(symlink_to_dir)` still descends into the target at
    // depth 1 even in non-following mode; only entries *discovered
    // during* a walk are protected by `follow_links(false)`. The one
    // caller that can pass a freshly-observed path here
    // (`register_new_directory_tree`, from the watcher callback) already
    // guards this via `is_real_directory` before ever reaching this
    // function, but this holds the invariant even if a future call site
    // forgets to.
    match start.symlink_metadata() {
        Ok(m) if m.is_dir() => {}
        _ => return Ok(Vec::new()),
    }

    let walker = walkdir::WalkDir::new(start)
        .follow_links(false)
        .same_file_system(true)
        .into_iter()
        .filter_entry(|entry| {
            if entry.depth() == 0 && entry.path() == root {
                return true;
            }
            if !entry.file_type().is_dir() {
                return true;
            }
            if crate::device_boundary::is_foreign_device_dir(root, entry.path()) {
                return false;
            }
            let Ok(relative_path) = entry.path().strip_prefix(root) else { return false };
            // Same ordering as every other entry point: the reserved
            // namespace is excluded before user ignore rules. This is
            // reachable: `hazard`'s filesystem-behaviour probes create a
            // short-lived `ArtefactKind::Probe` *directory* under the sync
            // root, and a native OS watch must never be registered on a
            // reserved path.
            if path_has_reserved_component(relative_path) {
                return false;
            }
            !ignore_set.is_ignored(relative_path, true)
        });

    let mut newly_registered = Vec::new();
    for entry in walker.filter_map(Result::ok) {
        if !entry.file_type().is_dir() {
            continue;
        }
        // Recorded only once the registration has succeeded. A directory
        // recorded before its `watch` failed would be skipped by every later
        // pass as already watched, and nothing under it would ever be
        // reported again.
        if !watched.contains(entry.path()) {
            on_new(entry.path())?;
            watched.insert(entry.path().to_path_buf());
            newly_registered.push(entry.path().to_path_buf());
        }
    }
    Ok(newly_registered)
}

#[cfg(test)]
mod tests;
