//! The data area's runtime lock, as seen by a tool that must not take it.
//!
//! The daemon holds an exclusive advisory lock on `.daemon.lock` in the config directory for its
//! whole life (`yadorilink-daemon`'s `DaemonInstanceLock`); the OS releases it on any exit, so it
//! is never stale. [`probe`] answers "does a daemon own this data area right now" for the CLI, the
//! apps and installers, without starting anything, creating anything or parsing a PID.
//!
//! The probe takes a *shared* lock and drops it again at once, so two probes never see each
//! other. A daemon that starts in that instant is refused as "already running" and is started
//! again by its supervisor; nothing is damaged. The answer is a moment-in-time fact: a caller that
//! wants to act on "free" must take the exclusive lock itself.

use std::fs::OpenOptions;
use std::path::Path;

/// The lock file's name inside the config directory.
pub const LOCK_FILE_NAME: &str = ".daemon.lock";

/// Whether a daemon owns the data area.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LockProbe {
    /// Nothing holds the lock (or the lock file was never created): no daemon runs.
    Free,
    /// Another process holds the exclusive lock: a daemon owns the data area.
    Held,
    /// The lock could not be examined. Callers treat this as [`LockProbe::Held`].
    Unknown(String),
}

/// Probes the config directory's lock without taking ownership. Creates nothing.
#[must_use]
pub fn probe(config_dir: &Path) -> LockProbe {
    let file = match OpenOptions::new().read(true).open(config_dir.join(LOCK_FILE_NAME)) {
        Ok(file) => file,
        // No lock file means no daemon ever started here (the daemon never deletes it).
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return LockProbe::Free,
        Err(e) => return LockProbe::Unknown(format!("cannot open {LOCK_FILE_NAME}: {e}")),
    };
    if !file.metadata().is_ok_and(|m| m.is_file()) {
        return LockProbe::Unknown(format!("{LOCK_FILE_NAME} is not a regular file"));
    }
    match fs2::FileExt::try_lock_shared(&file) {
        Ok(()) => {
            let _ = fs2::FileExt::unlock(&file);
            LockProbe::Free
        }
        // Raw OS error, as the daemon's own acquire compares it: `ErrorKind::WouldBlock` does not
        // reliably match Windows' contention error.
        Err(e) if e.raw_os_error() == fs2::lock_contended_error().raw_os_error() => LockProbe::Held,
        Err(e) => LockProbe::Unknown(format!("cannot examine {LOCK_FILE_NAME}: {e}")),
    }
}

/// An exclusive advisory lock on one of the config directory's lock files, held until dropped.
/// The OS releases it on any exit, so a crashed holder never leaves it taken.
#[derive(Debug)]
pub struct HeldLock {
    _file: std::fs::File,
}

/// Why [`HeldLock::acquire`] did not take the lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcquireError {
    /// Another process holds it (or is probing it at this instant).
    Contended,
    /// The lock file could not be opened or examined.
    Unusable(String),
}

impl HeldLock {
    /// Takes the exclusive lock on `file_name` in the config directory without waiting, creating
    /// the file when it does not exist (the daemon's own lock file is created the same way).
    ///
    /// # Errors
    /// [`AcquireError::Contended`] when someone else holds the lock; [`AcquireError::Unusable`]
    /// when the file cannot be opened or locked for another reason.
    pub fn acquire(config_dir: &Path, file_name: &str) -> Result<Self, AcquireError> {
        let path = config_dir.join(file_name);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| AcquireError::Unusable(format!("cannot open {}: {e}", path.display())))?;
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => Ok(Self { _file: file }),
            Err(e) if e.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
                Err(AcquireError::Contended)
            }
            Err(e) => Err(AcquireError::Unusable(format!("cannot lock {}: {e}", path.display()))),
        }
    }

    /// The data area's runtime lock: while it is held no daemon can start.
    ///
    /// # Errors
    /// See [`HeldLock::acquire`].
    pub fn acquire_daemon_lock(config_dir: &Path) -> Result<Self, AcquireError> {
        Self::acquire(config_dir, LOCK_FILE_NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs2::FileExt;

    #[test]
    fn a_held_exclusive_lock_keeps_a_second_taker_and_the_probe_out_until_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let first = HeldLock::acquire_daemon_lock(dir.path()).unwrap();
        assert_eq!(HeldLock::acquire_daemon_lock(dir.path()).unwrap_err(), AcquireError::Contended);
        assert_eq!(probe(dir.path()), LockProbe::Held);
        drop(first);
        assert_eq!(probe(dir.path()), LockProbe::Free);
        HeldLock::acquire_daemon_lock(dir.path()).unwrap();
    }

    fn hold_exclusively(dir: &Path) -> std::fs::File {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(dir.join(LOCK_FILE_NAME))
            .unwrap();
        file.try_lock_exclusive().unwrap();
        file
    }

    #[test]
    fn a_data_area_without_a_lock_file_is_free_and_stays_untouched() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(probe(dir.path()), LockProbe::Free);
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "the probe must create nothing"
        );
        let missing = dir.path().join("no-such-config-dir");
        assert_eq!(probe(&missing), LockProbe::Free);
        assert!(!missing.exists());
    }

    #[test]
    fn a_held_lock_is_reported_and_a_released_one_is_free() {
        let dir = tempfile::tempdir().unwrap();
        let owner = hold_exclusively(dir.path());
        assert_eq!(probe(dir.path()), LockProbe::Held);
        // Probing did not disturb the owner.
        assert_eq!(probe(dir.path()), LockProbe::Held);
        drop(owner);
        assert_eq!(probe(dir.path()), LockProbe::Free);
    }

    #[test]
    fn a_probe_never_takes_the_lock_from_a_later_daemon() {
        let dir = tempfile::tempdir().unwrap();
        drop(hold_exclusively(dir.path()));
        assert_eq!(probe(dir.path()), LockProbe::Free);
        // The probe released everything it took: an exclusive lock is available again.
        let _owner = hold_exclusively(dir.path());
    }

    #[test]
    fn concurrent_probes_do_not_see_each_other() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(LOCK_FILE_NAME), b"").unwrap();
        let other = OpenOptions::new().read(true).open(dir.path().join(LOCK_FILE_NAME)).unwrap();
        other.try_lock_shared().unwrap();
        assert_eq!(probe(dir.path()), LockProbe::Free);
    }

    #[test]
    fn an_unexaminable_lock_is_unknown_not_free() {
        let dir = tempfile::tempdir().unwrap();
        // A directory in place of the lock file cannot be locked.
        std::fs::create_dir(dir.path().join(LOCK_FILE_NAME)).unwrap();
        assert!(matches!(probe(dir.path()), LockProbe::Unknown(_)));
    }
}
