//! The one flush a batch of received files owes when its writers deferred
//! theirs (`Durability::DeferredToBatch`).
//!
//! The content of a received file is already durable in the block store, so
//! the file on disk is a projection that may be rebuilt. What the batch owes
//! before it forgets that the writes were in flight is that the projection is
//! on stable storage too; until then an intent stays open and startup repair
//! rebuilds a torn file from the blocks.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use yadorilink_fs_platform::flush::{self, Target};

/// How the batch is flushed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceivedFlushMode {
    /// `F_FULLFSYNC` (`sync_all`) of every file, concurrently, and one of every
    /// distinct parent directory. The same primitive the per-file path uses,
    /// only off the critical path and coalesced per directory.
    FullFsyncEach,
    /// `fsync(2)` of every file and directory, then a single `F_FULLFSYNC` that
    /// asks the drive to flush everything issued before it. Whether the
    /// filesystem makes that one call cover the other files is a property of the
    /// filesystem; this mode exists to be measured, not assumed.
    FsyncThenOneFullFsync,
}

/// What became of one file of the batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivedFlushOutcome {
    /// The file and its parent directory were flushed.
    Flushed,
    /// The file is no longer at its path (the user removed or moved it): there
    /// is nothing of ours to flush, and what became of it is capture's.
    Gone,
    /// The flush did not complete; the file's write must stay in flight.
    Failed(String),
}

#[cfg(any(test, feature = "test-support"))]
static TEST_FAIL_SUBSTRINGS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Test seam: until the returned guard drops, every flush of a path containing
/// `substring` fails. Guards of concurrent tests do not disturb each other.
#[cfg(any(test, feature = "test-support"))]
pub fn fail_received_flushes_of(substring: &str) -> FailReceivedFlushes {
    TEST_FAIL_SUBSTRINGS.lock().unwrap_or_else(|p| p.into_inner()).push(substring.to_owned());
    FailReceivedFlushes(substring.to_owned())
}

#[cfg(any(test, feature = "test-support"))]
pub struct FailReceivedFlushes(String);

#[cfg(any(test, feature = "test-support"))]
impl Drop for FailReceivedFlushes {
    fn drop(&mut self) {
        let mut needles = TEST_FAIL_SUBSTRINGS.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(at) = needles.iter().position(|n| *n == self.0) {
            needles.remove(at);
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
static TEST_FLUSH_LOG: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

/// Test seam: the paths (files and directories) whose flush primitive really ran
/// and succeeded under `root`, in order. It is recorded where the flush happens,
/// so a flush that was removed from the code is a flush that is missing here.
#[cfg(any(test, feature = "test-support"))]
pub fn completed_flushes_under(root: &Path) -> Vec<PathBuf> {
    let log = TEST_FLUSH_LOG.lock().unwrap_or_else(|p| p.into_inner());
    log.iter().filter(|path| path.starts_with(root)).cloned().collect()
}

/// `fsync` (mode 2) or `F_FULLFSYNC` (`sync_all`, mode 1) of `file`, which was opened at `path`.
fn flush_primitive(
    file: &fs::File,
    path: &Path,
    plain: bool,
    target: Target,
) -> std::io::Result<()> {
    let result = if plain { plain_fsync(file, target) } else { flush::sync(file, target) };
    #[cfg(any(test, feature = "test-support"))]
    if result.is_ok() {
        TEST_FLUSH_LOG.lock().unwrap_or_else(|p| p.into_inner()).push(path.to_path_buf());
    }
    #[cfg(not(any(test, feature = "test-support")))]
    let _ = path;
    result
}

fn injected_failure(_path: &Path) -> std::io::Result<()> {
    #[cfg(any(test, feature = "test-support"))]
    {
        let path = _path.to_string_lossy();
        let needles = TEST_FAIL_SUBSTRINGS.lock().unwrap_or_else(|p| p.into_inner());
        if needles.iter().any(|needle| path.contains(needle.as_str())) {
            return Err(std::io::Error::other("injected flush failure"));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn plain_fsync(file: &fs::File, target: Target) -> std::io::Result<()> {
    flush::fsync_plain(file, target)
}

#[cfg(not(unix))]
fn plain_fsync(file: &fs::File, target: Target) -> std::io::Result<()> {
    flush::sync(file, target)
}

/// `(device, inode)` of the object at `path`: what a received file was when it was
/// renamed in, to recognise it again at the barrier.
pub type ObjectKey = (u64, u64);

/// The key of the object at `path`, where the platform has one.
#[cfg(unix)]
pub fn object_key(path: &Path) -> Option<ObjectKey> {
    use std::os::unix::fs::MetadataExt;
    fs::symlink_metadata(path).ok().map(|meta| (meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
pub fn object_key(_path: &Path) -> Option<ObjectKey> {
    None
}

#[cfg(unix)]
fn key_of(file: &fs::File) -> Option<ObjectKey> {
    use std::os::unix::fs::MetadataExt;
    file.metadata().ok().map(|meta| (meta.dev(), meta.ino()))
}

#[cfg(not(unix))]
fn key_of(_file: &fs::File) -> Option<ObjectKey> {
    None
}

/// Opens `path` so that the flush primitive can run on it. A file is opened through
/// `open_for_flush` (Windows' `FlushFileBuffers` needs write access). Windows has no
/// directory flush at all, so a directory there is refused outright, never flushed in name
/// only; the batch that defers its flushes is Unix-only today, and this keeps that explicit.
fn open_for_received_flush(path: &Path, is_dir: bool) -> std::io::Result<fs::File> {
    if is_dir {
        #[cfg(windows)]
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Windows has no directory flush; a received batch is not flushed there",
        ));
        #[cfg(not(windows))]
        return fs::File::open(path);
    }
    flush::open_for_flush(path)
}

fn flush_one(
    path: &Path,
    plain: bool,
    is_dir: bool,
    expected: Option<ObjectKey>,
) -> std::io::Result<()> {
    injected_failure(path)?;
    let file = open_for_received_flush(path, is_dir)?;
    // A path that now names another object (the user moved the received file and
    // put something else there) must not be flushed in its place.
    if expected.is_some() && key_of(&file) != expected {
        return Err(std::io::Error::other("the object at this path is not the one received"));
    }
    let (op, target) = if is_dir {
        (crate::io_diag::Op::DirFsync, Target::Directory)
    } else {
        (crate::io_diag::Op::FileFsync, Target::File)
    };
    crate::io_diag::time(op, 0, || flush_primitive(&file, path, plain, target))
}

/// Runs `job(index)` for every index with `workers` threads.
fn for_each_concurrently(count: usize, workers: usize, job: impl Fn(usize) + Sync) {
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..workers.clamp(1, count.max(1)) {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= count {
                    break;
                }
                job(index);
            });
        }
    });
}

/// Flushes `files` (absolute paths of files that were renamed into place with
/// a deferred flush) and each distinct parent directory once, and answers per
/// file. Blocking; call it from a blocking thread.
pub fn flush_received_files(
    files: &[PathBuf],
    mode: ReceivedFlushMode,
    workers: usize,
) -> Vec<ReceivedFlushOutcome> {
    let keys = vec![None; files.len()];
    flush_received_objects(files, &keys, mode, workers)
}

/// [`flush_received_files`] that also checks each file is still the object
/// recorded in `keys` (same length as `files`); another object there is `Failed`.
pub fn flush_received_objects(
    files: &[PathBuf],
    keys: &[Option<ObjectKey>],
    mode: ReceivedFlushMode,
    workers: usize,
) -> Vec<ReceivedFlushOutcome> {
    let plain = mode == ReceivedFlushMode::FsyncThenOneFullFsync;
    let file_results: Vec<std::sync::Mutex<Option<std::io::Result<()>>>> =
        files.iter().map(|_| std::sync::Mutex::new(None)).collect();
    for_each_concurrently(files.len(), workers, |index| {
        let result = flush_one(&files[index], plain, false, keys[index]);
        *file_results[index].lock().unwrap_or_else(|p| p.into_inner()) = Some(result);
    });

    let mut dirs: Vec<PathBuf> = files
        .iter()
        .map(|file| match file.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        })
        .collect();
    dirs.sort();
    dirs.dedup();
    let dir_results: Vec<std::sync::Mutex<Option<std::io::Result<()>>>> =
        dirs.iter().map(|_| std::sync::Mutex::new(None)).collect();
    for_each_concurrently(dirs.len(), workers, |index| {
        let result = flush_one(&dirs[index], plain, true, None);
        *dir_results[index].lock().unwrap_or_else(|p| p.into_inner()) = Some(result);
    });

    // The one barrier of the second mode, once per backing device (a sync root
    // may contain a mounted volume): after every fsync(2) was issued, on a
    // directory of that device that can still be opened.
    let dir_devices: Vec<Option<u64>> = dirs.iter().map(|dir| device_of(dir)).collect();
    let mut barriers: std::collections::HashMap<u64, std::io::Result<()>> =
        std::collections::HashMap::new();
    if plain {
        for (dir, device) in dirs.iter().zip(&dir_devices) {
            let Some(device) = device else { continue };
            if barriers.contains_key(device) {
                continue;
            }
            let result = injected_failure(files.first().unwrap_or(dir)).and_then(|()| {
                let handle = open_for_received_flush(dir, true)?;
                crate::io_diag::time(crate::io_diag::Op::FileFsync, 0, || {
                    flush::sync_directory(&handle)
                })
            });
            barriers.insert(*device, result);
        }
    }

    files
        .iter()
        .enumerate()
        .map(|(index, file)| {
            let file_result =
                file_results[index].lock().unwrap_or_else(|p| p.into_inner()).take().unwrap();
            let gone = match file_result {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
                Err(e) => return ReceivedFlushOutcome::Failed(format!("{}: {e}", file.display())),
                Ok(()) => false,
            };
            // A file that is gone still left a rename (or its removal) in its
            // directory: that and the drive barrier must be durable too.
            let parent = match file.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
                _ => PathBuf::from("."),
            };
            let dir_index = dirs.binary_search(&parent).expect("every parent was collected");
            if let Some(Err(e)) =
                dir_results[dir_index].lock().unwrap_or_else(|p| p.into_inner()).as_ref()
            {
                return ReceivedFlushOutcome::Failed(format!("{}: {e}", parent.display()));
            }
            if let Some(Err(e)) = dir_devices[dir_index].and_then(|device| barriers.get(&device)) {
                return ReceivedFlushOutcome::Failed(format!("drive flush: {e}"));
            }
            // Still the received object at its path once everything was flushed: a
            // move meanwhile flushed the old directory, not the new one.
            if !gone && keys[index].is_some() && object_key(file) != keys[index] {
                return ReceivedFlushOutcome::Failed(format!(
                    "{}: moved while it was being flushed",
                    file.display()
                ));
            }
            if gone {
                ReceivedFlushOutcome::Gone
            } else {
                ReceivedFlushOutcome::Flushed
            }
        })
        .collect()
}

/// The device a directory lives on, when it can be read.
#[cfg(unix)]
fn device_of(dir: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(dir).ok().map(|meta| meta.dev())
}

#[cfg(not(unix))]
fn device_of(_dir: &Path) -> Option<u64> {
    Some(0)
}
