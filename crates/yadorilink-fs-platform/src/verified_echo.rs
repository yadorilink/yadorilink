//! Files this device has just written and verified, remembered so that the watcher event the write
//! itself causes does not read them again.
//!
//! After a file is materialized, the watcher reports it, and local capture then asks whether the
//! bytes on disk still match the version the index holds. For a large file that is a second full
//! read and SHA-256 of bytes that were verified moments ago. This registry answers the question
//! without the read, and only when nothing could have changed the file since it was verified:
//!
//! * the entry is made only after the written bytes were checked, with the identity that was
//!   observed *before* that check (an edit between the observation and the check fails the check);
//! * the file's size, mode, modification time and change time (all inside the identity's metadata
//!   fingerprint), and its object identity, must be exactly what was recorded;
//! * the racy-clean rule, applied at the moment the identity was observed (before the bytes were
//!   read, which is what makes it sound): the modification and change times must be older than that
//!   moment by more than [`RACY_WINDOW`] (100 ms, ten times the kernel's coarsest clock tick; a
//!   volume that keeps whole-second timestamps gets no entry). Any edit made after that moment
//!   then carries a newer timestamp, whatever happens while the bytes are being read; an edit in
//!   the same timestamp tick as the observation could leave the fingerprint unchanged, so no entry
//!   is made in that case. A freshly written file is always that young, so [`settle_wait`] says how
//!   long to pause before observing it;
//! * only on a local filesystem the code knows ([`known_local_volume`]): timestamps kept by a
//!   server, whose clock this machine does not share, prove nothing about this machine's moments;
//! * only on Unix, where the change time is available through the standard library; elsewhere no
//!   entry is made (the change time cannot be shown to be available and aged);
//! * only for [`TRUST_LIFETIME`], and only while the wall clock has not gone back since the entry
//!   was made: the write's echo arrives within moments, and a clock that is set back would let a
//!   later edit be stamped with the very timestamps recorded.
//!
//! Known limit: a process that already holds the new file mapped shared and writable, with the
//! page faulted writable before the identity was observed, can change bytes through that mapping
//! without any timestamp moving until writeback. The echo then skips its read; the change is not
//! lost (the bytes differ from the index, and the next scan or any later event hashes the file),
//! only reported later than it would have been.
//!
//! Anything missing, different or unreadable is "not proven", which leaves the caller on its
//! ordinary read-and-hash path. The registry lives in memory: a restart only costs one read.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use yadorilink_replica_domain::ids::VersionHash;

use crate::fs_identity::{FileIdentity, IdentityComparison, TimestampGranularity};

/// How much older than the moment its identity was observed a file's timestamps must be for the
/// entry to be trusted: ten times the coarsest tick of the clock the kernel stamps files with
/// (10 ms at 100 Hz). A volume that keeps whole-second timestamps is excluded separately.
pub const RACY_WINDOW: Duration = Duration::from_millis(100);

/// How long an entry is used. The watcher reports a write within moments; a clock stepped back
/// later cannot revive an old entry.
pub const TRUST_LIFETIME: Duration = Duration::from_secs(60);

/// The most paths remembered at once; the oldest entry goes first.
const CAPACITY: usize = 4096;

struct Entry {
    version: VersionHash,
    identity: FileIdentity,
    serial: u64,
    created: Instant,
    /// The wall clock when the entry was made: a clock that is later found to be earlier means it
    /// was stepped back, and timestamps may collide with the recorded ones.
    noted_at: SystemTime,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<(String, String), Entry>,
    next_serial: u64,
}

/// A file that was just written and verified: where it is, and what was checked.
pub struct VerifiedWrite<'a> {
    pub group_id: &'a str,
    pub path: &'a str,
    pub version: VersionHash,
    /// The identity observed *before* the bytes were verified.
    pub identity: &'a FileIdentity,
    pub out_path: &'a Path,
}

/// See the module documentation.
#[derive(Default)]
pub struct VerifiedEchoes {
    inner: Mutex<Inner>,
}

/// Whether the file's timestamps look like whole seconds (both nanosecond fields zero), which is
/// what a volume that cannot keep finer ones shows. A file on a nanosecond volume has both fields
/// zero with probability 1e-18.
#[cfg(unix)]
fn whole_second_timestamps(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.mtime_nsec() == 0 && metadata.ctime_nsec() == 0
}

#[cfg(not(unix))]
fn whole_second_timestamps(_metadata: &std::fs::Metadata) -> bool {
    true
}

/// Whether `path` is on a filesystem known to be local to this machine (its timestamps come from
/// this machine's clock). Anything not recognised is `false`.
#[cfg(target_os = "linux")]
pub fn known_local_volume(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else { return false };
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c_path.as_ptr(), &mut fs) } != 0 {
        return false;
    }
    // ext2/3/4, xfs, btrfs, tmpfs, f2fs, zfs, overlayfs (its timestamps are the upper layer's)
    const LOCAL: [i64; 7] =
        [0xEF53, 0x5846_5342, 0x9123_683E, 0x0102_1994, 0xF2F5_2010, 0x2FC1_2FC1, 0x794C_7630];
    LOCAL.contains(&(fs.f_type as i64))
}

#[cfg(target_vendor = "apple")]
pub fn known_local_volume(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else { return false };
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c_path.as_ptr(), &mut fs) } != 0 {
        return false;
    }
    let name: Vec<u8> = fs.f_fstypename.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
    matches!(name.as_slice(), b"apfs" | b"hfs")
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
pub fn known_local_volume(_path: &Path) -> bool {
    false
}

/// The later of the modification and change times (the change time only where the platform has it).
fn newest_timestamp(metadata: &std::fs::Metadata) -> Option<SystemTime> {
    let modified = metadata.modified().ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.ctime() < 0 {
            return None;
        }
        let changed = SystemTime::UNIX_EPOCH
            + Duration::new(
                metadata.ctime() as u64,
                metadata.ctime_nsec().clamp(0, 999_999_999) as u32,
            );
        Some(modified.max(changed))
    }
    #[cfg(not(unix))]
    {
        Some(modified)
    }
}

/// How long to pause before observing the identity of the freshly written file at `out_path`, so
/// that its timestamps are older than the window when it is observed. `None`: no entry can be made
/// for this file (whole-second timestamps, a volume not known to be local, a platform without the
/// change time, not a regular file), so there is nothing to wait for. `Some(zero)`: observe now.
pub fn settle_wait(out_path: &Path) -> Option<Duration> {
    if !cfg!(unix) || !known_local_volume(out_path) {
        return None;
    }
    let metadata = std::fs::symlink_metadata(out_path).ok()?;
    if !metadata.is_file() || whole_second_timestamps(&metadata) {
        return None;
    }
    let ready = newest_timestamp(&metadata)?.checked_add(RACY_WINDOW)?;
    let wait = ready.duration_since(SystemTime::now()).unwrap_or(Duration::ZERO);
    // A timestamp in the future (a restored mtime, a clock that was ahead) would make the pause
    // arbitrarily long; the pause is only ever the window itself.
    (wait <= RACY_WINDOW).then_some(wait)
}

/// Whether the file's modification and change times are all older than `observed_at` by more
/// than `window`. A timestamp in the future counts as not older.
fn older_than(metadata: &std::fs::Metadata, observed_at: SystemTime, window: Duration) -> bool {
    let Some(cutoff) = observed_at.checked_sub(window) else { return false };
    newest_timestamp(metadata).is_some_and(|newest| newest < cutoff)
}

impl VerifiedEchoes {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remembers that the file at `write.out_path` was verified as `write.version`, with the
    /// identity that was observed before the verification. `observed_at` is the moment taken just
    /// before that identity was observed (not when the verification finished). Returns whether an
    /// entry was made; `false` means a rule above ruled it out (the file was too young at
    /// `observed_at`, or changed since), which is not an error.
    pub fn note(&self, write: VerifiedWrite<'_>, observed_at: SystemTime) -> bool {
        let VerifiedWrite { group_id, path, version, identity, out_path } = write;
        if !cfg!(unix) || !known_local_volume(out_path) {
            return false;
        }
        let Ok(metadata) = std::fs::symlink_metadata(out_path) else { return false };
        if !metadata.is_file()
            || whole_second_timestamps(&metadata)
            || !older_than(&metadata, observed_at, RACY_WINDOW)
        {
            self.forget(group_id, path);
            return false;
        }
        // The file must still be the object that was observed before the check. Its timestamps
        // were older than the window when it was observed, so any change since then moved them.
        let Ok(observed) = FileIdentity::observe_path(out_path) else { return false };
        if observed.metadata_fingerprint != identity.metadata_fingerprint {
            self.forget(group_id, path);
            return false;
        }
        let mut inner = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.next_serial += 1;
        let serial = inner.next_serial;
        if inner.entries.len() >= CAPACITY {
            if let Some(oldest) =
                inner.entries.iter().min_by_key(|(_, entry)| entry.serial).map(|(k, _)| k.clone())
            {
                inner.entries.remove(&oldest);
            }
        }
        inner.entries.insert(
            (group_id.to_owned(), path.to_owned()),
            Entry {
                version,
                identity: *identity,
                serial,
                created: Instant::now(),
                noted_at: SystemTime::now(),
            },
        );
        true
    }

    /// Whether the file at `out_path` is, untouched, the verified `version`: an entry exists for
    /// the path and version and is still within [`TRUST_LIFETIME`], and the file's identity and
    /// metadata fingerprint (size, mode, modification and change time) are exactly those
    /// recorded. Anything else is `false`.
    pub fn still_untouched(
        &self,
        group_id: &str,
        path: &str,
        version: &VersionHash,
        out_path: &Path,
        granularity: TimestampGranularity,
    ) -> bool {
        let recorded = {
            let inner = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            match inner.entries.get(&(group_id.to_owned(), path.to_owned())) {
                Some(entry)
                    if entry.version == *version
                        && entry.created.elapsed() < TRUST_LIFETIME
                        && SystemTime::now() >= entry.noted_at =>
                {
                    entry.identity
                }
                _ => return false,
            }
        };
        let Ok(observed) = FileIdentity::observe_path(out_path) else { return false };
        observed.metadata_fingerprint == recorded.metadata_fingerprint
            && observed.compare(&recorded, granularity) == IdentityComparison::SameObject
    }

    /// Drops the entry for a path (after the path was changed through another route).
    pub fn forget(&self, group_id: &str, path: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.entries.remove(&(group_id.to_owned(), path.to_owned()));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;

    fn version(byte: u8) -> VersionHash {
        VersionHash([byte; 32])
    }

    fn verified<'a>(
        path: &'a str,
        identity: &'a FileIdentity,
        out_path: &'a Path,
    ) -> VerifiedWrite<'a> {
        VerifiedWrite { group_id: "g", path, version: version(1), identity, out_path }
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        let mut file = std::fs::File::create(path).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    /// A moment far enough after the file's timestamps that the racy-clean rule passes.
    fn later() -> SystemTime {
        SystemTime::now() + Duration::from_secs(60)
    }

    fn noted(dir: &Path) -> (VerifiedEchoes, std::path::PathBuf, FileIdentity) {
        let path = dir.join("file.bin");
        write_file(&path, b"verified bytes");
        let identity = FileIdentity::observe_path(&path).unwrap();
        let echoes = VerifiedEchoes::new();
        assert!(echoes.note(verified("file.bin", &identity, &path), later()));
        (echoes, path, identity)
    }

    #[test]
    fn an_untouched_verified_file_is_recognised() {
        let dir = tempfile::tempdir().unwrap();
        let (echoes, path, _) = noted(dir.path());
        assert!(echoes.still_untouched(
            "g",
            "file.bin",
            &version(1),
            &path,
            TimestampGranularity::Fine
        ));
    }

    #[test]
    fn on_a_volume_with_coarse_birth_times_an_equal_identity_is_not_trusted() {
        // Same object by inode alone is not enough where the identity cannot be told apart from a
        // recycled one.
        let dir = tempfile::tempdir().unwrap();
        let (echoes, path, identity) = noted(dir.path());
        if identity.generation_or_usn.is_none() {
            assert!(!echoes.still_untouched(
                "g",
                "file.bin",
                &version(1),
                &path,
                TimestampGranularity::Coarse
            ));
        }
    }

    #[test]
    fn another_version_or_path_is_not_recognised() {
        let dir = tempfile::tempdir().unwrap();
        let (echoes, path, _) = noted(dir.path());
        for (group, name, v) in [("g", "file.bin", 2), ("g", "other.bin", 1), ("h", "file.bin", 1)]
        {
            assert!(!echoes.still_untouched(
                group,
                name,
                &version(v),
                &path,
                TimestampGranularity::Fine
            ));
        }
    }

    #[test]
    fn a_same_size_edit_with_the_old_modification_time_restored_is_caught() {
        // The edit leaves the size and (restored) modification time alone; the change time cannot be
        // restored, so the fingerprint moves.
        let dir = tempfile::tempdir().unwrap();
        let (echoes, path, _) = noted(dir.path());
        let before = std::fs::metadata(&path).unwrap().modified().unwrap();
        write_file(&path, b"VERIFIED BYTES");
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_modified(before).unwrap();
        assert!(!echoes.still_untouched(
            "g",
            "file.bin",
            &version(1),
            &path,
            TimestampGranularity::Fine
        ));
    }

    #[test]
    fn a_chmod_after_publication_is_caught() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (echoes, path, _) = noted(dir.path());
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(permissions.mode() ^ 0o100);
        std::fs::set_permissions(&path, permissions).unwrap();
        assert!(!echoes.still_untouched(
            "g",
            "file.bin",
            &version(1),
            &path,
            TimestampGranularity::Fine
        ));
    }

    #[test]
    fn a_replaced_file_is_caught() {
        let dir = tempfile::tempdir().unwrap();
        let (echoes, path, _) = noted(dir.path());
        std::fs::remove_file(&path).unwrap();
        write_file(&path, b"verified bytes");
        assert!(!echoes.still_untouched(
            "g",
            "file.bin",
            &version(1),
            &path,
            TimestampGranularity::Fine
        ));
    }

    #[test]
    fn a_missing_file_is_not_recognised() {
        let dir = tempfile::tempdir().unwrap();
        let (echoes, path, _) = noted(dir.path());
        std::fs::remove_file(&path).unwrap();
        assert!(!echoes.still_untouched(
            "g",
            "file.bin",
            &version(1),
            &path,
            TimestampGranularity::Fine
        ));
    }

    #[test]
    fn a_file_observed_within_the_window_of_its_timestamps_is_not_remembered() {
        // The file was written now and its identity observed now: an edit in the same timestamp tick
        // could leave the fingerprint unchanged, so nothing may be remembered.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        write_file(&path, b"verified bytes");
        let identity = FileIdentity::observe_path(&path).unwrap();
        let echoes = VerifiedEchoes::new();
        assert!(!echoes.note(verified("file.bin", &identity, &path), SystemTime::now()));
        assert!(!echoes.still_untouched(
            "g",
            "file.bin",
            &version(1),
            &path,
            TimestampGranularity::Fine
        ));
    }

    #[test]
    fn the_age_is_judged_at_the_observation_not_when_the_note_is_made() {
        // The identity was observed right after the write; the verification then took longer than the
        // window. An edit in the same tick as the observation, made while the bytes were being read,
        // would leave the fingerprint alone: the entry must not be made however late the note comes.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        write_file(&path, b"verified bytes");
        let identity = FileIdentity::observe_path(&path).unwrap();
        let observed_at = SystemTime::now();
        std::thread::sleep(RACY_WINDOW + Duration::from_millis(100));
        let echoes = VerifiedEchoes::new();
        assert!(!echoes.note(verified("file.bin", &identity, &path), observed_at));
    }

    #[test]
    fn after_the_settle_wait_a_fresh_file_is_remembered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        write_file(&path, b"verified bytes");
        let wait = settle_wait(&path).expect("a local file on a nanosecond volume");
        assert!(wait <= RACY_WINDOW + Duration::from_millis(50));
        std::thread::sleep(wait + Duration::from_millis(20));
        let observed_at = SystemTime::now();
        let identity = FileIdentity::observe_path(&path).unwrap();
        let echoes = VerifiedEchoes::new();
        assert!(echoes.note(verified("file.bin", &identity, &path), observed_at));
        assert!(echoes.still_untouched(
            "g",
            "file.bin",
            &version(1),
            &path,
            TimestampGranularity::Fine
        ));
    }

    #[test]
    fn a_file_changed_between_the_observation_and_the_note_is_not_remembered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        write_file(&path, b"verified bytes");
        let identity = FileIdentity::observe_path(&path).unwrap();
        write_file(&path, b"changed after the observation");
        let echoes = VerifiedEchoes::new();
        assert!(!echoes.note(verified("file.bin", &identity, &path), later()));
    }

    #[test]
    fn a_volume_with_whole_second_timestamps_is_recognised_by_its_zero_fractions() {
        // The predicate on a file of this volume (nanosecond timestamps in practice): not whole.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        write_file(&path, b"x");
        assert!(!whole_second_timestamps(&std::fs::metadata(&path).unwrap()));
    }

    #[test]
    fn a_wall_clock_that_went_back_since_the_note_invalidates_the_entry() {
        let dir = tempfile::tempdir().unwrap();
        let (echoes, path, _) = noted(dir.path());
        for entry in echoes.inner.lock().unwrap().entries.values_mut() {
            entry.noted_at = SystemTime::now() + Duration::from_secs(3600);
        }
        assert!(!echoes.still_untouched(
            "g",
            "file.bin",
            &version(1),
            &path,
            TimestampGranularity::Fine
        ));
    }

    #[test]
    fn a_file_dated_in_the_future_is_not_waited_for() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        write_file(&path, b"x");
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_modified(SystemTime::now() + Duration::from_secs(86_400)).unwrap();
        assert_eq!(settle_wait(&path), None);
    }

    #[test]
    fn an_entry_expires() {
        let dir = tempfile::tempdir().unwrap();
        let (echoes, path, _) = noted(dir.path());
        for entry in echoes.inner.lock().unwrap().entries.values_mut() {
            entry.created = Instant::now() - TRUST_LIFETIME - Duration::from_secs(1);
        }
        assert!(!echoes.still_untouched(
            "g",
            "file.bin",
            &version(1),
            &path,
            TimestampGranularity::Fine
        ));
    }

    #[test]
    fn the_registry_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.bin");
        write_file(&path, b"x");
        let identity = FileIdentity::observe_path(&path).unwrap();
        let echoes = VerifiedEchoes::new();
        for i in 0..(CAPACITY + 10) {
            assert!(echoes.note(verified(&format!("p{i}"), &identity, &path), later()));
        }
        assert!(echoes.inner.lock().unwrap().entries.len() <= CAPACITY);
        assert!(!echoes.still_untouched("g", "p0", &version(1), &path, TimestampGranularity::Fine));
    }
}
