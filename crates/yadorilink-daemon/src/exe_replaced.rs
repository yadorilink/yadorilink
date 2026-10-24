//! Restarts the daemon when the executable it runs from was replaced under it.
//!
//! The macOS app updates itself by replacing its bundle, and the daemon lives inside that bundle.
//! The updater's installer runs when the app ends for any reason (crash, Force Quit, forced
//! shutdown), so the app cannot promise that it stopped the daemon first. The promise has to come
//! from the daemon: one whose own installation was replaced notices, stops at a safe point through
//! the same safe-stop request a person or an updater uses, and exits with
//! [`RESTART_EXIT_CODE`] so that a restarting supervisor (launchd `KeepAlive`/`SuccessfulExit =
//! false`) starts the new binary.
//!
//! Only when told to: a daemon that nobody restarts must not turn an update into an outage, so
//! the watch is off unless the supervisor passed [`SUPERVISED_ARG`]. Deletion of the installation
//! is a different matter and stays with [`crate::exe_watch`].
//!
//! Conservative on purpose. The watch looks at the executable's path every
//! [`ReplacedConfig::interval`] (no file-system notification dependency) and compares what it
//! finds with what the daemon recorded at start. A change counts only when two consecutive looks
//! find the same changed identity; a path that is missing at a look, or a look that fails, is
//! never a change and breaks the run (an updater's swap leaves the path missing for an instant).
//! A stop that cannot happen yet (`busy`) is asked again later with a growing wait, never forced.

use std::hash::{Hash as _, Hasher as _};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use crate::application::ports::{DaemonLifecyclePort, SafeStopOutcome};

/// The status of a daemon that exited so that its supervisor starts it again (EX_TEMPFAIL). The
/// contract with the macOS app's launchd job: a non-zero status restarts it.
pub const RESTART_EXIT_CODE: i32 = 75;

/// The argument a restarting supervisor passes to turn the watch on.
pub const SUPERVISED_ARG: &str = "--restart-on-replace";

static ARMED: OnceLock<Armed> = OnceLock::new();

/// What the entry point recorded before the daemon started.
struct Armed {
    target: Target,
    baseline: Identity,
}

/// Called once by the binary's entry point, before the daemon starts, when the supervisor passed
/// [`SUPERVISED_ARG`]: resolves the executable and records its identity now, so that a swap during
/// the daemon's (possibly long) startup is a change from this baseline and not part of it. Does
/// nothing on Windows: a running executable cannot be replaced there (the swap fails with a
/// sharing violation), an installer stops the daemon first and the platform's own supervisor
/// starts it again, so the argument is accepted and ignored. Does nothing when the executable
/// cannot be identified (logged), which leaves the daemon as an unsupervised one.
pub fn arm() {
    if !cfg!(unix) {
        return;
    }
    let Some(target) = Target::current() else {
        tracing::warn!("cannot resolve the running executable; not watching for replacement");
        return;
    };
    match target.observe() {
        Observation::Present(baseline) => {
            let _ = ARMED.set(Armed { target, baseline });
        }
        _ => tracing::warn!("cannot identify the running executable; not watching for replacement"),
    }
}

/// Whether the watch was armed.
#[must_use]
pub fn supervised() -> bool {
    ARMED.get().is_some()
}

#[derive(Debug, Clone, Copy)]
pub struct ReplacedConfig {
    /// Time between two looks at the path.
    pub interval: Duration,
    /// The deadline handed to the safe-stop request.
    pub stop_deadline: Duration,
    /// Each `busy` answer doubles the wait before the next request, up to this.
    pub busy_backoff_cap: Duration,
}

impl Default for ReplacedConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(30),
            stop_deadline: Duration::from_secs(30),
            busy_backoff_cap: Duration::from_secs(300),
        }
    }
}

/// What identifies the file at a path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileId {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    len: u64,
    mtime: Option<SystemTime>,
}

impl FileId {
    fn of(meta: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;
        Self {
            #[cfg(unix)]
            dev: meta.dev(),
            #[cfg(unix)]
            ino: meta.ino(),
            len: meta.len(),
            mtime: meta.modified().ok(),
        }
    }
}

/// The identity of a running installation: the executable and, inside an app bundle, the
/// version record of the bundle that holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    exe: FileId,
    /// A digest of the enclosing bundle's `Contents/Info.plist` (which carries
    /// `CFBundleVersion` and `CFBundleShortVersionString`), `None` outside a bundle or when the
    /// bundle has no such file. The whole file is digested, so an in-place version bump is seen
    /// whatever its format (XML or binary plist) and whatever it does to size and mtime.
    bundle_info: Option<u64>,
}

/// What one look found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Observation {
    Present(Identity),
    /// The file system answered that the executable is not there.
    Missing,
    /// The look failed for another reason: nothing is known.
    Unverifiable,
}

/// The paths the watch looks at.
#[derive(Debug, Clone)]
pub(crate) struct Target {
    exe: PathBuf,
    /// The enclosing `.app` directory, when the executable is in one.
    bundle: Option<PathBuf>,
}

impl Target {
    /// The running executable (resolved, like the installation facts are).
    pub(crate) fn current() -> Option<Self> {
        let exe = crate::update::install_source::running_exe();
        if exe.as_os_str().is_empty() {
            return None;
        }
        Some(Self::new(exe))
    }

    pub(crate) fn new(exe: PathBuf) -> Self {
        let bundle = yadorilink_local_storage::ownership::app_bundle_root(&exe);
        Self { exe, bundle }
    }

    pub(crate) fn observe(&self) -> Observation {
        let exe = match std::fs::metadata(&self.exe) {
            Ok(meta) => FileId::of(&meta),
            Err(e) => return classify(&e),
        };
        let bundle_info = match &self.bundle {
            None => None,
            Some(bundle) => match digest_file(&bundle.join("Contents").join("Info.plist")) {
                Ok(d) => d,
                Err(()) => return Observation::Unverifiable,
            },
        };
        Observation::Present(Identity { exe, bundle_info })
    }
}

fn classify(e: &std::io::Error) -> Observation {
    if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) {
        Observation::Missing
    } else {
        Observation::Unverifiable
    }
}

/// `Ok(None)` when the file is not there, `Err` when it could not be read for another reason.
fn digest_file(path: &Path) -> Result<Option<u64>, ()> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            bytes.hash(&mut hasher);
            Ok(Some(hasher.finish()))
        }
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => Ok(None),
        Err(_) => Err(()),
    }
}

/// Decides, look by look, whether the installation was replaced.
#[derive(Debug)]
pub(crate) struct Detector {
    baseline: Identity,
    /// A changed identity seen at the previous look.
    pending: Option<Identity>,
}

impl Detector {
    pub(crate) fn new(baseline: Identity) -> Self {
        Self { baseline, pending: None }
    }

    /// Feeds one look; `true` once the same change was seen at two consecutive looks.
    pub(crate) fn observe(&mut self, observation: Observation) -> bool {
        // The bundle's version record existed at the baseline and is gone now: absence alone is
        // not a change (as with the executable itself), so it breaks the run like a missing path;
        // a changed executable still counts.
        let observation = match observation {
            Observation::Present(id)
                if self.baseline.bundle_info.is_some()
                    && id.bundle_info.is_none()
                    && id.exe == self.baseline.exe =>
            {
                Observation::Missing
            }
            other => other,
        };
        match observation {
            Observation::Present(id) if id == self.baseline => {
                self.pending = None;
                false
            }
            Observation::Present(id) => {
                if self.pending.as_ref() == Some(&id) {
                    true
                } else {
                    self.pending = Some(id);
                    false
                }
            }
            Observation::Missing | Observation::Unverifiable => {
                self.pending = None;
                false
            }
        }
    }
}

/// The hook the run loop calls: starts the watch when the entry point armed it.
pub(crate) fn spawn_if_supervised(
    lifecycle: Arc<dyn DaemonLifecyclePort>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let Some(armed) = ARMED.get() else { return };
    tokio::spawn(watch_with(
        ReplacedConfig::default(),
        lifecycle,
        armed.baseline.clone(),
        shutdown,
        || armed.target.observe(),
    ));
}

/// Watches until its safe stop committed, or until the daemon is shutting down for another
/// reason.
///
/// The watch does not decide the exit status, and does not set anything after the fact: it asks
/// through [`DaemonLifecyclePort::request_safe_stop_to_restart`], and the safe-stop commit itself
/// records the restart reason before it fires the shutdown signal (`DaemonState::restart_on_exit`,
/// read by `app::run` once the shutdown path is taken). Only the request that commits the stop
/// records it; a stop somebody else began (`already_in_progress`) is theirs, and a daemon the
/// user stopped stays stopped. The request is awaited to its end, never cancelled; shutdown is
/// looked at only while waiting between looks. A retry after `busy` looks at the path again first, and starts over if the change is gone.
pub(crate) async fn watch_with(
    config: ReplacedConfig,
    lifecycle: Arc<dyn DaemonLifecyclePort>,
    baseline: Identity,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    observe: impl Fn() -> Observation,
) {
    let mut detector = Detector::new(baseline);
    let mut delay = config.interval;
    loop {
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            _ = shutdown.wait_for(|stopped| *stopped) => return,
        }
        // Every request, a retry after `busy` included, rests on a fresh look: a replacement that
        // is gone again (the file deleted or put back) is no longer a reason to stop.
        if !detector.observe(observe()) {
            delay = config.interval;
            continue;
        }
        tracing::info!("the executable this daemon runs from was replaced; stopping safely");
        match lifecycle.request_safe_stop_to_restart(config.stop_deadline).await {
            SafeStopOutcome::Stopping { .. } => return,
            SafeStopOutcome::Busy { reason, detail, .. } => {
                delay = (delay * 2).min(config.busy_backoff_cap).max(config.interval);
                tracing::warn!(
                    ?reason,
                    detail,
                    retry_in_secs = delay.as_secs(),
                    "safe stop is not possible yet; asking again later"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests;
