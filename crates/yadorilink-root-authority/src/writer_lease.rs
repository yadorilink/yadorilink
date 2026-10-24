//! A time-bounded writer lease with a fence token, for hosts that cannot hold an OS lock
//! for their whole lifetime and have no daemon in front of them.
//!
//! # Why a lease and not only a lock
//!
//! [`crate::sync_root_lock::SyncRootLock`] and the data-resource locks are advisory OS locks
//! held by an open file description for the process lifetime. That fits a desktop daemon. An
//! embedded host (a mobile app and its file-provider extension are separate processes sharing
//! one container) must not sit on a lock across a process suspension, and has no supervising
//! daemon to arbitrate. This lease keeps ownership in a small record file instead:
//!
//! ```text
//! { "generation": 7, "holder": "<random id>" | null, "expires_at_ms": 1760000000000 }
//! ```
//!
//! The OS lock is taken only for the duration of one read-modify-write of that record (a
//! bounded session: no lock is held when any call here returns), so the record is always
//! updated atomically and a suspended or killed process never strands a lock.
//!
//! # Protocol
//!
//! * [`WriterLease::acquire`] succeeds when the record names no holder (released) or its
//!   `expires_at_ms` is not after the clock's now (expired: the previous holder crashed or
//!   stalled past its term). It then increments `generation`, the **fence token**, names
//!   itself holder and sets a new expiry. Otherwise it fails closed with
//!   [`RootAuthorityError::WriterLeaseHeld`] and changes nothing.
//! * [`WriterLease::renew`] extends the expiry while the record still carries this lease's
//!   generation and holder. A lease that was taken over gets [`RootAuthorityError::StaleWriter`].
//! * [`WriterLease::verify`] is the fence: it passes only when the record still carries this
//!   lease's generation and holder and the term has not run out. Wire it into the commit path
//!   (see [`crate::root_commit::RootLease::with_writer_lease`]) so a late writer's commit is
//!   refused. A writer must verify immediately before each commit and renew well within its
//!   term; takeover happens only after expiry, so a commit that verified inside the term and
//!   finishes promptly cannot interleave with a takeover.
//! * [`WriterLease::release`] (and `Drop`) clears the holder if it is still this lease, and
//!   never lowers the generation, so tokens are never reused.
//!
//! Readers need no lease. [`read_state`] reports the record without locking and without
//! changing anything, so any number of readers can look while one writer holds the lease.
//!
//! A corrupt record is reported as [`RootAuthorityError::CorruptState`]; it is never guessed
//! at or reset, because resetting the generation could re-admit a stale writer.
//!
//! Time comes from a [`LeaseClock`]: wall-clock milliseconds in production (it must be
//! comparable between the processes sharing the container), a settable fake in tests.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::RootAuthorityError;

const RECORD_FILE: &str = ".yadorilink-writer-lease.json";
const RECORD_TMP_FILE: &str = ".yadorilink-writer-lease.json.tmp";
const GUARD_FILE: &str = ".yadorilink-writer-lease.guard";

/// Source of "now" for lease terms, in milliseconds since the Unix epoch.
pub trait LeaseClock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// The wall clock, shared by every process on the device.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemLeaseClock;

impl LeaseClock for SystemLeaseClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }
}

/// A settable clock for deterministic tests.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default)]
pub struct FakeLeaseClock(std::sync::atomic::AtomicU64);

#[cfg(any(test, feature = "test-support"))]
impl FakeLeaseClock {
    pub fn new(now_ms: u64) -> Arc<Self> {
        Arc::new(Self(std::sync::atomic::AtomicU64::new(now_ms)))
    }

    pub fn set(&self, now_ms: u64) {
        self.0.store(now_ms, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn advance(&self, by: Duration) {
        let by = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        self.0.fetch_add(by, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(any(test, feature = "test-support"))]
impl LeaseClock for FakeLeaseClock {
    fn now_ms(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// The persisted lease record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseState {
    /// The fence token: incremented on every acquisition, never lowered.
    pub generation: u64,
    /// The current holder, or `None` once released.
    pub holder: Option<String>,
    pub expires_at_ms: u64,
}

impl LeaseState {
    fn is_free_at(&self, now_ms: u64) -> bool {
        self.holder.is_none() || self.expires_at_ms <= now_ms
    }
}

/// Reads the lease record without locking or changing anything. `None` when no lease was
/// ever taken in `dir`. For readers, which never hold a lease.
pub fn read_state(dir: &Path) -> Result<Option<LeaseState>, RootAuthorityError> {
    read_record(&dir.join(RECORD_FILE))
}

fn read_record(path: &Path) -> Result<Option<LeaseState>, RootAuthorityError> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| {
            RootAuthorityError::corrupt_state(format!(
                "writer lease record {} is unreadable: {e}",
                path.display()
            ))
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Exclusive ownership of one data area, fenced by a generation token.
pub struct WriterLease {
    dir: PathBuf,
    holder: String,
    generation: u64,
    term_ms: u64,
    clock: Arc<dyn LeaseClock>,
}

impl std::fmt::Debug for WriterLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriterLease")
            .field("dir", &self.dir)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}

impl WriterLease {
    /// Takes the lease on `dir` (created if absent) for `term`, or fails closed if another
    /// holder's term has not run out.
    pub fn acquire(
        dir: &Path,
        term: Duration,
        clock: Arc<dyn LeaseClock>,
    ) -> Result<Self, RootAuthorityError> {
        yadorilink_fs_platform::durable_dir::create_dir_all_durably(dir)?;
        let term_ms = u64::try_from(term.as_millis()).unwrap_or(u64::MAX).max(1);
        let holder = new_holder_id();
        let path = dir.join(RECORD_FILE);
        let generation = with_guard(dir, || {
            let now = clock.now_ms();
            let previous = read_record(&path)?;
            if let Some(state) = &previous {
                if !state.is_free_at(now) {
                    return Err(RootAuthorityError::WriterLeaseHeld(format!(
                        "data area {} is already in use by another writer (generation {}, \
                         lease runs for another {} ms)",
                        dir.display(),
                        state.generation,
                        state.expires_at_ms - now
                    )));
                }
            }
            let generation = previous.map_or(1, |s| s.generation.saturating_add(1));
            write_record(
                dir,
                &LeaseState {
                    generation,
                    holder: Some(holder.clone()),
                    expires_at_ms: now.saturating_add(term_ms),
                },
            )?;
            Ok(generation)
        })?;
        Ok(Self { dir: dir.to_path_buf(), holder, generation, term_ms, clock })
    }

    /// The fence token this lease was granted.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Extends the term by a full term from now, if this lease still owns the record.
    pub fn renew(&self) -> Result<(), RootAuthorityError> {
        let path = self.dir.join(RECORD_FILE);
        with_guard(&self.dir, || {
            let state = self.owned_record(&path)?;
            write_record(
                &self.dir,
                &LeaseState {
                    expires_at_ms: self.clock.now_ms().saturating_add(self.term_ms),
                    ..state
                },
            )
        })
    }

    /// The fence: errors unless the record still carries this lease's generation and holder
    /// and the term has not run out. Call immediately before a commit.
    pub fn verify(&self) -> Result<(), RootAuthorityError> {
        let path = self.dir.join(RECORD_FILE);
        with_guard(&self.dir, || {
            let state = self.owned_record(&path)?;
            if state.expires_at_ms <= self.clock.now_ms() {
                return Err(RootAuthorityError::StaleWriter(format!(
                    "writer lease generation {} on {} has expired; renew it before committing",
                    self.generation,
                    self.dir.display()
                )));
            }
            Ok(())
        })
    }

    /// Gives the lease up now so the next writer need not wait out the term.
    pub fn release(self) {
        drop(self);
    }

    fn owned_record(&self, path: &Path) -> Result<LeaseState, RootAuthorityError> {
        match read_record(path)? {
            Some(state)
                if state.generation == self.generation
                    && state.holder.as_deref() == Some(self.holder.as_str()) =>
            {
                Ok(state)
            }
            other => Err(RootAuthorityError::StaleWriter(format!(
                "writer lease generation {} on {} was taken over (record now at generation {})",
                self.generation,
                self.dir.display(),
                other.map_or_else(|| "none".to_string(), |s| s.generation.to_string())
            ))),
        }
    }
}

impl Drop for WriterLease {
    fn drop(&mut self) {
        let path = self.dir.join(RECORD_FILE);
        // Best effort: a failed release only means the next writer waits out the term.
        let _ = with_guard(&self.dir, || {
            let state = self.owned_record(&path)?;
            write_record(&self.dir, &LeaseState { holder: None, ..state })
        });
    }
}

/// Runs `body` while holding the guard flock, then releases it: the only time any lock is
/// held, so none is held when a public call returns.
fn with_guard<T>(
    dir: &Path,
    body: impl FnOnce() -> Result<T, RootAuthorityError>,
) -> Result<T, RootAuthorityError> {
    let guard: File = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(dir.join(GUARD_FILE))?;
    fs2::FileExt::lock_exclusive(&guard)?;
    let result = body();
    let _ = fs2::FileExt::unlock(&guard);
    result
}

fn write_record(dir: &Path, state: &LeaseState) -> Result<(), RootAuthorityError> {
    let tmp = dir.join(RECORD_TMP_FILE);
    let bytes = serde_json::to_vec(state)
        .map_err(|e| RootAuthorityError::corrupt_state(format!("encoding lease record: {e}")))?;
    let mut file = File::create(&tmp)?;
    file.write_all(&bytes)?;
    yadorilink_fs_platform::flush::sync_file(&file)?;
    drop(file);
    yadorilink_fs_platform::durable_dir::publish_durably(
        &tmp,
        &dir.join(RECORD_FILE),
        yadorilink_fs_platform::durable_dir::Replace::Yes,
    )?;
    Ok(())
}

fn new_holder_id() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests;
