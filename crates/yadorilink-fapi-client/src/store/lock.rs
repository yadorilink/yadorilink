//! The cross-process refresh-token rotation lock.
//!
//! # Why this has to exist
//!
//! Refresh tokens rotate. The Authorization Server hands back a new one and
//! kills the one just spent, and replaying a spent refresh token does not fail
//! harmlessly -- it fires the reuse defence, which tears down the whole grant
//! family (measured against the deployed server). The CLI
//! and the daemon run as separate processes against the same stored
//! credential, so without a lock the ordinary case of "the user runs a command
//! while the daemon is refreshing" is two processes presenting the same
//! refresh token. The server is right to revoke; the user is logged out of
//! everything for no reason they can see.
//!
//! # What it is
//!
//! An advisory whole-file lock (`flock` on Unix, `LockFileEx` on Windows) on a
//! zero-byte file in the config directory, held across *read the stored token,
//! refresh, persist the rotated token*. The file lives in the config directory
//! whichever backend holds the secret, because the OS keyring has no lock of
//! its own and because the CLI and the daemon already agree on that directory.
//!
//! The lock file is never deleted. Unlinking a file another process is waiting
//! on gives the next waiter a lock on a file nobody else can see, which is
//! worse than no lock at all -- it succeeds.
//!
//! # Why a bounded retry loop rather than a blocking acquire
//!
//! `lock_exclusive` blocks the calling thread for as long as the holder takes,
//! which in a daemon means parking a reactor thread on a network round trip
//! happening in another process. `try_lock_exclusive` plus a short sleep needs
//! no blocking pool to exist -- which also keeps this crate free of
//! `spawn_blocking`, whose absence is what lets it link into a build whose
//! tokio is the simulation shim.
//!
//! A timeout is a refusal, not a "carry on anyway". Proceeding without the
//! lock is precisely the grant-destroying case.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fs2::FileExt as _;

use super::{StoreError, StoreResult};

/// How long to wait between attempts. Short: the holder's critical section is
/// one HTTP round trip.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Held for the duration of a rotation. Releasing is dropping it.
#[derive(Debug)]
pub struct CredentialLock {
    file: std::fs::File,
    path: PathBuf,
}

impl CredentialLock {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CredentialLock {
    fn drop(&mut self) {
        // Closing the descriptor releases the lock on every platform this
        // ships on, so an explicit unlock only turns a no-op into a possible
        // error path. It is done anyway so the release is visible in the code
        // rather than implied by a `drop`.
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

/// On Windows, `fs2` reports a contended lock as the raw `ERROR_LOCK_VIOLATION`
/// (33) OS error rather than as `io::ErrorKind::WouldBlock` -- std's Windows
/// error-code mapping does not classify it as `WouldBlock`, so it otherwise
/// reads as a real I/O failure. Recognizing it here is what makes the retry
/// loop below retry on Windows instead of bailing out on the first
/// collision with another process, which is the ordinary case this lock
/// exists to handle.
#[cfg(windows)]
const ERROR_LOCK_VIOLATION: i32 = 33;

fn is_contended(e: &std::io::Error) -> bool {
    if e.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(windows)]
    if e.raw_os_error() == Some(ERROR_LOCK_VIOLATION) {
        return true;
    }
    false
}

pub(super) async fn acquire(path: &Path, timeout: Duration) -> StoreResult<CredentialLock> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    yadorilink_fs_platform::durable_dir::create_dir_all_durably(parent)
        .map_err(|source| StoreError::Io { path: parent.to_path_buf(), source })?;

    let file = open(path)?;
    let deadline = Instant::now() + timeout;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(CredentialLock { file, path: path.to_path_buf() }),
            Err(e) if is_contended(&e) => {}
            Err(source) => return Err(StoreError::Io { path: path.to_path_buf(), source }),
        }
        if Instant::now() >= deadline {
            return Err(StoreError::LockTimeout { path: path.to_path_buf(), waited: timeout });
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[cfg(unix)]
fn open(path: &Path) -> StoreResult<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| StoreError::Io { path: path.to_path_buf(), source })
}

#[cfg(not(unix))]
fn open(path: &Path) -> StoreResult<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .map_err(|source| StoreError::Io { path: path.to_path_buf(), source })
}

#[cfg(test)]
mod tests;
