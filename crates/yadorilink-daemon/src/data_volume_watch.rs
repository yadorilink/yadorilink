//! Fails the daemon closed when the volume holding its data directory goes away.
//!
//! A daemon whose data directory sat on a removable disk that dropped (and came back) kept running at
//! several hundred percent CPU in the kernel: its open files were revoked, every write stalled or failed,
//! and its threads were woken and re-run continuously, with no log line and no control socket left to
//! say why. Nothing in the process can repair that, and idling on a half-dead store is not an option
//! either, so the daemon stops: it exits with [`DATA_VOLUME_UNAVAILABLE_EXIT_CODE`] and a supervisor
//! (launchd `KeepAlive`, systemd `Restart=`) starts it again once the volume is back.
//!
//! The check runs on plain OS threads, not on the async runtime, so it still runs when the runtime is
//! the thing that is stuck. One thread looks at the directory (it may block forever on a hung mount),
//! another watches that the looks keep finishing. The directory counts as gone when it is not found,
//! when the file system answers with an I/O error on it, when it is no longer the directory the
//! daemon started in (the volume came back as another file system or the directory was replaced: the
//! files the daemon holds open are not the files at that path any more), or when a look does not finish
//! for a long time. A look that fails for any other reason (permissions) proves nothing and counts as
//! neither; and a single bad look is not enough, several in a row are required.
//!
//! **At startup the opposite rule holds.** A volume that is absent when the daemon starts (the disk is
//! not plugged in, not mounted yet) is not a failure to report with an exit status: a supervisor would
//! restart the daemon every few seconds until the disk returns. [`wait_until_available`] idles instead,
//! looks again every 30 s, logs once, and lets startup go on when the directory can be used. Exit 74 is
//! only for a volume that vanishes while the daemon runs. (The control socket lives in the data
//! directory, so while waiting the log line and the process's presence are the only report.)
//!
//! Only the standalone daemon arms it ([`arm`], from its entry point): a daemon embedded in another
//! process must never take that process down.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// The status of a daemon that stopped because its data volume is unavailable (EX_IOERR). A
/// supervisor that restarts on a non-zero status starts it again once the volume is back.
pub const DATA_VOLUME_UNAVAILABLE_EXIT_CODE: i32 = 74;

#[derive(Debug, Clone, Copy)]
pub struct WatchConfig {
    /// Time between two looks.
    pub interval: Duration,
    /// Looks in a row that must find the directory gone.
    pub misses_needed: u32,
    /// A look that has not finished for this long counts as the volume being unavailable (a metadata
    /// call that takes two minutes is a hung volume, not a slow one).
    pub stall_limit: Duration,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            misses_needed: 3,
            stall_limit: Duration::from_secs(120),
        }
    }
}

/// What one look found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Probe {
    Present,
    Gone,
}

/// Why the daemon stops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The directory (or the volume under it) was not there for several looks in a row.
    Gone,
    /// A look did not finish within the stall limit: the volume hangs.
    Stalled,
}

static ARMED: AtomicBool = AtomicBool::new(false);
static STARTED: OnceLock<()> = OnceLock::new();

/// Called once by the standalone daemon's entry point: lets [`start_if_armed`] watch (and stop the
/// process) when the data directory goes away. Not called by an embedded host or by tests.
pub fn arm() {
    ARMED.store(true, Ordering::SeqCst);
}

/// Whether the standalone daemon armed the watch (and with it the wait at startup).
pub fn is_armed() -> bool {
    ARMED.load(Ordering::SeqCst)
}

/// Whether `dir` can be used as the data directory right now: it exists and can be read, or it
/// does not exist and can be created (a first start). A directory that is missing and cannot be
/// created (its volume is not mounted, its parent is unwritable) or that answers with an I/O error is
/// not usable yet.
pub(crate) fn startup_check(dir: &Path) -> Result<(), String> {
    match std::fs::metadata(dir) {
        Ok(meta) if meta.is_dir() => {
            std::fs::read_dir(dir).map(|_| ()).map_err(|error| format!("cannot read it: {error}"))
        }
        // Not a directory: a different problem, reported by the normal startup checks.
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound || is_volume_error(&error) => {
            yadorilink_fs_platform::durable_dir::create_dir_all_durably(dir)
                .map_err(|error| format!("it is absent and cannot be created: {error}"))
        }
        // Permissions and the like: the normal startup checks say so in their own words.
        Err(_) => Ok(()),
    }
}

/// Waits until [`startup_check`] passes, looking every `interval`; logs once when it first fails
/// and once when it passes after that.
pub async fn wait_until_available(dir: &Path, interval: Duration) {
    let mut waited = false;
    loop {
        match startup_check(dir) {
            Ok(()) => {
                if waited {
                    tracing::info!(dir = %dir.display(), "the data volume is available; starting");
                }
                return;
            }
            Err(reason) => {
                if !waited {
                    waited = true;
                    tracing::warn!(
                        dir = %dir.display(),
                        %reason,
                        "data volume unavailable: waiting for it (checking every {} s); the daemon starts by itself when it returns",
                        interval.as_secs()
                    );
                }
                tokio::time::sleep(interval).await;
            }
        }
    }
}

/// The time between two looks while waiting at startup.
pub const STARTUP_WAIT_INTERVAL: Duration = Duration::from_secs(30);

/// Starts the watch on `dir` when [`arm`] was called, once per process.
pub fn start_if_armed(dir: &Path) {
    start_if_armed_with(dir, WatchConfig::default());
}

fn start_if_armed_with(dir: &Path, config: WatchConfig) {
    if !ARMED.load(Ordering::SeqCst) || STARTED.set(()).is_err() {
        return;
    }
    let probe = match DirIdentity::observe(dir) {
        Ok(identity) => identity,
        Err(error) => {
            tracing::warn!(%error, dir = %dir.display(), "cannot look at the data directory; not watching its volume");
            return;
        }
    };
    let dir = dir.to_path_buf();
    let look_dir = dir.clone();
    spawn_with(
        Arc::new(move || probe.look(&look_dir)),
        config,
        Box::new(move |failure| exit_unavailable(&dir, failure)),
    );
}

/// Logs and ends the process without running destructors or flushing anything to the volume.
fn exit_unavailable(dir: &Path, failure: Failure) -> ! {
    // Logging can itself block on the lost volume (a log file, a full pipe): whatever it does, the
    // process ends within a couple of seconds.
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(2));
        end_process();
    });
    let why = match failure {
        Failure::Gone => "is gone",
        Failure::Stalled => "does not answer",
    };
    tracing::error!(
        dir = %dir.display(),
        "the data volume {why}: stopping so that nothing is written to a store that cannot be trusted; \
         the daemon starts again when it is back"
    );
    eprintln!(
        "yadorilink-daemon: the data volume ({}) {why}; stopping (status {DATA_VOLUME_UNAVAILABLE_EXIT_CODE})",
        dir.display()
    );
    end_process()
}

fn end_process() -> ! {
    #[cfg(unix)]
    // SAFETY: `_exit` takes a status and ends the process at once; no Rust state is used afterwards.
    unsafe {
        libc::_exit(DATA_VOLUME_UNAVAILABLE_EXIT_CODE)
    }
    #[cfg(not(unix))]
    std::process::exit(DATA_VOLUME_UNAVAILABLE_EXIT_CODE)
}

/// The identity of the data directory at startup, and (on Unix) a handle held on it.
///
/// Not on Windows: a directory cannot be opened there without backup semantics, and a directory
/// held open and then removed stays "delete pending" (access denied for every look at its path)
/// until the handle closes, which would read as a present directory. A path look is enough there.
struct DirIdentity {
    #[cfg(unix)]
    dev_ino: (u64, u64),
    #[cfg(unix)]
    held: std::fs::File,
}

impl DirIdentity {
    fn observe(dir: &Path) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let held = std::fs::File::open(dir)?;
            let meta = held.metadata()?;
            Ok(Self { dev_ino: (meta.dev(), meta.ino()), held })
        }
        #[cfg(not(unix))]
        {
            std::fs::metadata(dir).map(|_| Self {})
        }
    }

    fn look(&self, dir: &Path) -> Probe {
        match std::fs::metadata(dir) {
            Err(error) if is_volume_error(&error) => return Probe::Gone,
            Err(_) => return Probe::Present,
            Ok(_meta) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    // The device always (a volume that came back is another device); the inode only
                    // where it is stable (APFS/HFS+: an overlay file system may renumber directories).
                    if _meta.dev() != self.dev_ino.0
                        || (cfg!(target_vendor = "apple") && _meta.ino() != self.dev_ino.1)
                    {
                        return Probe::Gone;
                    }
                }
            }
        }
        // The handle held since startup: a revoked one answers with an error.
        #[cfg(unix)]
        match self.held.metadata() {
            Err(error) if is_volume_error(&error) => return Probe::Gone,
            // The directory was deleted while held.
            Ok(meta) if std::os::unix::fs::MetadataExt::nlink(&meta) == 0 => return Probe::Gone,
            _ => {}
        }
        Probe::Present
    }
}

/// Whether an error says the directory or its volume is not there, as opposed to this process
/// not being allowed to look.
pub(crate) fn is_volume_error(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::NotFound {
        return true;
    }
    #[cfg(unix)]
    {
        matches!(
            error.raw_os_error(),
            Some(
                libc::EIO
                    | libc::ENXIO
                    | libc::ENODEV
                    | libc::ESTALE
                    | libc::EBADF
                    | libc::ENOTCONN
            )
        )
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// How long the monitor can sleep before it has to look again: `None` when the last look finished
/// longer ago than `limit` (the volume is stalled now), else the time until it would be, plus a
/// little so the check lands after the moment and not before it.
fn next_stall_check(since_last_look: Duration, limit: Duration) -> Option<Duration> {
    (since_last_look <= limit).then(|| limit - since_last_look + Duration::from_millis(10))
}

/// Starts the two threads: `look` runs every interval on the first, which stops the daemon through
/// `on_failure` when enough looks in a row found the directory gone; the second does so when a look
/// never finishes.
///
/// The second thread does not poll. A look that never finishes is the one case the first thread cannot
/// report, and it can be declared stalled at one moment only: [`WatchConfig::stall_limit`] plus the
/// interval after the last look finished. So it sleeps until that moment, looks again, and sleeps until
/// the new moment if the first thread has finished a look meanwhile: a healthy daemon wakes it about
/// once per stall limit, not once per second.
pub(crate) fn spawn_with(
    look: Arc<dyn Fn() -> Probe + Send + Sync>,
    config: WatchConfig,
    on_failure: Box<dyn Fn(Failure) + Send + Sync>,
) {
    let epoch = Instant::now();
    let finished_at = Arc::new(AtomicU64::new(0));
    let fired = Arc::new(AtomicBool::new(false));
    let on_failure: Arc<dyn Fn(Failure) + Send + Sync> = Arc::from(on_failure);
    let probe_thread = {
        let (finished_at, fired, on_failure) =
            (finished_at.clone(), fired.clone(), on_failure.clone());
        std::thread::Builder::new().name("data-volume-look".into()).spawn(move || {
            let mut misses = 0u32;
            loop {
                match look() {
                    Probe::Gone => misses += 1,
                    Probe::Present => misses = 0,
                }
                finished_at.store(epoch.elapsed().as_millis() as u64, Ordering::SeqCst);
                if misses >= config.misses_needed {
                    if !fired.swap(true, Ordering::SeqCst) {
                        on_failure(Failure::Gone);
                    }
                    return;
                }
                std::thread::sleep(config.interval);
            }
        })
    };
    // Without the thread that looks there is nothing to wait for: a monitor alone would read its
    // silence as a hung volume.
    if let Err(error) = probe_thread {
        tracing::warn!(%error, "cannot start the data volume check; not watching the volume");
        return;
    }
    let limit = config.stall_limit + config.interval;
    std::thread::Builder::new()
        .name("data-volume-watch".into())
        .spawn(move || loop {
            let since_last_look = epoch
                .elapsed()
                .saturating_sub(Duration::from_millis(finished_at.load(Ordering::SeqCst)));
            if fired.load(Ordering::SeqCst) {
                return;
            }
            match next_stall_check(since_last_look, limit) {
                None => {
                    if !fired.swap(true, Ordering::SeqCst) {
                        on_failure(Failure::Stalled);
                    }
                    return;
                }
                Some(wait) => std::thread::sleep(wait),
            }
        })
        .ok();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;
    use std::sync::Mutex;

    const FAST: WatchConfig = WatchConfig {
        interval: Duration::from_millis(20),
        misses_needed: 3,
        stall_limit: Duration::from_millis(300),
    };

    fn watch(
        look: Arc<dyn Fn() -> Probe + Send + Sync>,
        config: WatchConfig,
    ) -> Arc<Mutex<Vec<Failure>>> {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = seen.clone();
        spawn_with(look, config, Box::new(move |failure| sink.lock().unwrap().push(failure)));
        seen
    }

    fn wait_for(seen: &Arc<Mutex<Vec<Failure>>>, ms: u64) -> Vec<Failure> {
        std::thread::sleep(Duration::from_millis(ms));
        seen.lock().unwrap().clone()
    }

    /// The monitor sleeps until the one moment a stall could be declared, not a second at a time.
    #[test]
    fn the_monitor_sleeps_until_the_moment_a_stall_could_be_declared() {
        let limit = Duration::from_secs(125);
        assert_eq!(
            next_stall_check(Duration::from_secs(1), limit),
            Some(Duration::from_secs(124) + Duration::from_millis(10))
        );
        assert_eq!(next_stall_check(limit, limit), Some(Duration::from_millis(10)));
        assert_eq!(next_stall_check(limit + Duration::from_millis(1), limit), None);
        assert_eq!(
            next_stall_check(Duration::ZERO, limit),
            Some(limit + Duration::from_millis(10))
        );
    }

    #[test]
    fn a_present_directory_is_never_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let identity = DirIdentity::observe(dir.path()).unwrap();
        let path = dir.path().to_path_buf();
        let seen = watch(Arc::new(move || identity.look(&path)), FAST);
        assert!(wait_for(&seen, 600).is_empty());
    }

    #[test]
    fn a_removed_directory_stops_the_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        std::fs::create_dir(&path).unwrap();
        let identity = DirIdentity::observe(&path).unwrap();
        let look_path = path.clone();
        let seen = watch(Arc::new(move || identity.look(&look_path)), FAST);
        assert!(wait_for(&seen, 150).is_empty());
        std::fs::remove_dir(&path).unwrap();
        assert_eq!(wait_for(&seen, 600), vec![Failure::Gone]);
    }

    /// The volume came back as something else (or the directory was swapped): the handles the daemon
    /// holds are not the files at that path, so it stops too.
    #[cfg(target_vendor = "apple")]
    #[test]
    fn a_replaced_directory_stops_the_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        std::fs::create_dir(&path).unwrap();
        let identity = DirIdentity::observe(&path).unwrap();
        let look_path = path.clone();
        let seen = watch(Arc::new(move || identity.look(&look_path)), FAST);
        std::fs::rename(&path, dir.path().join("aside")).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_eq!(wait_for(&seen, 600), vec![Failure::Gone]);
    }

    #[test]
    fn one_bad_look_is_not_enough() {
        let looks = Arc::new(AtomicU32::new(0));
        let counter = looks.clone();
        // Gone on the 2nd look only.
        let seen = watch(
            Arc::new(move || {
                if counter.fetch_add(1, Ordering::SeqCst) == 1 {
                    Probe::Gone
                } else {
                    Probe::Present
                }
            }),
            FAST,
        );
        assert!(wait_for(&seen, 600).is_empty());
    }

    #[test]
    fn a_look_that_never_finishes_stops_the_daemon() {
        let seen = watch(
            Arc::new(|| {
                std::thread::sleep(Duration::from_secs(3600));
                Probe::Present
            }),
            FAST,
        );
        assert_eq!(wait_for(&seen, 900), vec![Failure::Stalled]);
    }

    #[test]
    fn only_a_missing_or_failing_volume_is_gone_not_a_refusal() {
        assert!(is_volume_error(&std::io::Error::from(std::io::ErrorKind::NotFound)));
        assert!(!is_volume_error(&std::io::Error::from(std::io::ErrorKind::PermissionDenied)));
        #[cfg(unix)]
        {
            assert!(is_volume_error(&std::io::Error::from_raw_os_error(libc::EIO)));
            assert!(is_volume_error(&std::io::Error::from_raw_os_error(libc::ENXIO)));
            assert!(!is_volume_error(&std::io::Error::from_raw_os_error(libc::EACCES)));
        }
    }

    /// The real exit: a child process (this test binary run again) arms the watch, loses its data
    /// directory, and ends with the volume status without running anything else.
    #[cfg(unix)]
    #[test]
    fn the_process_ends_with_the_volume_status_when_the_directory_goes() {
        if let Ok(dir) = std::env::var("YL_DATA_VOLUME_CHILD") {
            let dir = std::path::PathBuf::from(dir);
            arm();
            start_if_armed_with(&dir, FAST);
            std::fs::remove_dir(&dir).unwrap();
            std::thread::sleep(Duration::from_secs(30));
            std::process::exit(0); // not reached when the watch works
        }
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        std::fs::create_dir(&data).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "data_volume_watch::tests::the_process_ends_with_the_volume_status_when_the_directory_goes",
                "--nocapture",
            ])
            .env("YL_DATA_VOLUME_CHILD", &data)
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(DATA_VOLUME_UNAVAILABLE_EXIT_CODE));
    }

    #[cfg(unix)]
    #[tokio::test(start_paused = true)]
    async fn startup_waits_for_a_missing_volume_and_goes_on_when_it_returns() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        // The "volume": an empty mount point nobody may write to, as an unmounted one is. When the
        // disk "returns" it is writable and the data directory can be made.
        let mount = root.path().join("volume");
        std::fs::create_dir(&mount).unwrap();
        std::fs::set_permissions(&mount, std::fs::Permissions::from_mode(0o555)).unwrap();
        let data = mount.join("data");
        if startup_check(&data).is_ok() {
            return; // running as a user that ignores permissions (root): nothing to simulate
        }

        let waiting = tokio::spawn({
            let data = data.clone();
            async move { wait_until_available(&data, STARTUP_WAIT_INTERVAL).await }
        });
        tokio::time::sleep(Duration::from_secs(95)).await;
        assert!(!waiting.is_finished(), "still waiting while the volume is absent");

        std::fs::set_permissions(&mount, std::fs::Permissions::from_mode(0o755)).unwrap();
        tokio::time::sleep(STARTUP_WAIT_INTERVAL + Duration::from_secs(1)).await;
        waiting.await.unwrap();
        assert!(data.is_dir());
    }

    #[test]
    fn startup_does_not_wait_for_a_first_start_or_an_existing_directory() {
        let root = tempfile::tempdir().unwrap();
        assert!(
            startup_check(&root.path().join("new").join("data")).is_ok(),
            "created on a first start"
        );
        assert!(startup_check(root.path()).is_ok());
        let file = root.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(startup_check(&file).is_ok(), "not a directory: the normal checks report it");
    }

    /// Not armed (an embedded host, a test): nothing starts, so nothing can end the process.
    #[test]
    fn an_unarmed_watch_does_nothing() {
        let before = STARTED.get().is_some();
        start_if_armed(Path::new("/definitely/not/there"));
        assert_eq!(STARTED.get().is_some(), before);
    }
}
