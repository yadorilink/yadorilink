//! The file-
//! operation wrappers that stamp every tempdir mutation through the shared
//! `HarnessClock`, so no simulated write ever carries a kernel-stamped
//! real-wall-clock mtime.
//!
//! These are meant to be the *only* way a migrated scenario touches its
//! tempdir: `stamp-on-every-mutation` is enforced by construction here
//! rather than left as a per-call convention, where a forgotten stamp would
//! silently produce a real-clock mtime.
//!
//! Extracted from the retired network-fault scenario's `stamp_deterministic_
//! mtime` + `deliver_local_write`/`remove_file_if_present` helpers.
//!
//! `#![cfg(turmoil)]`-gated like every DST scenario file.

use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use super::clock::HarnessClock;

/// Stamps `path`'s on-disk mtime to `nanos` (nanoseconds since the Unix
/// epoch). `std::fs::File::set_times` is stable since Rust 1.75 and needs
/// no extra crate -- the same call the canonical `stamp_deterministic_
/// mtime` used.
fn stamp(path: &Path, nanos: i64) -> Result<(), String> {
    let modified = UNIX_EPOCH + Duration::from_nanos(nanos as u64);
    let file = std::fs::File::options().write(true).open(path).map_err(|e| e.to_string())?;
    file.set_times(std::fs::FileTimes::new().set_modified(modified)).map_err(|e| e.to_string())
}

/// Writes `content` to `path` (creating or truncating) and stamps its
/// mtime from `clock`. Returns the stamped mtime so a caller that also
/// records the write in an oracle can reuse the exact value.
pub fn write(clock: &HarnessClock, path: &Path, content: &[u8]) -> Result<i64, String> {
    std::fs::write(path, content).map_err(|e| e.to_string())?;
    let nanos = clock.next_mtime();
    stamp(path, nanos)?;
    Ok(nanos)
}

/// Appends `content` to `path` (creating it if absent) and re-stamps its
/// mtime from `clock`.
pub fn append(clock: &HarnessClock, path: &Path, content: &[u8]) -> Result<i64, String> {
    use std::io::Write as _;
    let mut file =
        std::fs::File::options().create(true).append(true).open(path).map_err(|e| e.to_string())?;
    file.write_all(content).map_err(|e| e.to_string())?;
    drop(file);
    let nanos = clock.next_mtime();
    stamp(path, nanos)?;
    Ok(nanos)
}

/// Truncates (or extends) `path` to `len` bytes and re-stamps its mtime.
pub fn truncate(clock: &HarnessClock, path: &Path, len: u64) -> Result<i64, String> {
    let file = std::fs::File::options().write(true).open(path).map_err(|e| e.to_string())?;
    file.set_len(len).map_err(|e| e.to_string())?;
    drop(file);
    let nanos = clock.next_mtime();
    stamp(path, nanos)?;
    Ok(nanos)
}

/// Renames `from` to `to` and stamps the destination's mtime from `clock`
/// (a rename does not itself update the moved file's mtime on most
/// filesystems, so the harness stamps it to keep the destination on the
/// synthetic timeline like any other mutation).
pub fn rename(clock: &HarnessClock, from: &Path, to: &Path) -> Result<i64, String> {
    std::fs::rename(from, to).map_err(|e| e.to_string())?;
    let nanos = clock.next_mtime();
    stamp(to, nanos)?;
    Ok(nanos)
}

/// Re-stamps `path`'s mtime from `clock` without changing its content --
/// the explicit set-mtime primitive the file-op wrapper list
/// names, for a scenario that touches a file's timestamp on its own.
pub fn set_mtime(clock: &HarnessClock, path: &Path) -> Result<i64, String> {
    let nanos = clock.next_mtime();
    stamp(path, nanos)?;
    Ok(nanos)
}

/// Removes `path` if present, tolerating a concurrent removal exactly as
/// the canonical `remove_file_if_present` did: a `NotFound` only means the
/// spawned session/debounce tasks sharing this simulated runtime won the
/// race, not a scenario error. A delete needs no stamp (there is no file
/// left to stamp; the tombstone's causal ordering is the version vector's
/// job, not the mtime's).
pub fn remove(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mtime_nanos(path: &Path) -> i64 {
        let modified = std::fs::metadata(path).unwrap().modified().unwrap();
        modified.duration_since(UNIX_EPOCH).unwrap().as_nanos() as i64
    }

    #[test]
    fn write_stamps_the_returned_mtime_onto_disk() {
        let dir = tempfile::tempdir().unwrap();
        let clock = HarnessClock::from_seed(7);
        let p = dir.path().join("a.txt");
        let stamped = write(&clock, &p, b"hello").unwrap();
        assert_eq!(mtime_nanos(&p), stamped);
        assert_eq!(std::fs::read(&p).unwrap(), b"hello");
    }

    #[test]
    fn successive_writes_stamp_strictly_increasing_mtimes() {
        let dir = tempfile::tempdir().unwrap();
        let clock = HarnessClock::from_seed(7);
        let p = dir.path().join("a.txt");
        let first = write(&clock, &p, b"one").unwrap();
        let second = write(&clock, &p, b"two").unwrap();
        assert!(second > first);
        assert_eq!(mtime_nanos(&p), second);
    }

    #[test]
    fn rename_stamps_the_destination() {
        let dir = tempfile::tempdir().unwrap();
        let clock = HarnessClock::from_seed(3);
        let from = dir.path().join("a.txt");
        let to = dir.path().join("b.txt");
        write(&clock, &from, b"data").unwrap();
        let stamped = rename(&clock, &from, &to).unwrap();
        assert!(!from.exists());
        assert_eq!(mtime_nanos(&to), stamped);
    }

    #[test]
    fn remove_tolerates_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        remove(&dir.path().join("never-existed.txt")).unwrap();
    }
}
