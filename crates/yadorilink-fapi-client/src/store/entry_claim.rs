//! Which credential entry an engine uses, decided by the operating system.
//!
//! Two engines of one process must not refresh one refresh token under different rotation
//! locks, so before an engine starts it claims its credential entry, and a second claim of the
//! same entry is refused. Whether two configurations name the same entry is not something
//! their spellings can answer: dot segments, symlinks, case aliases on a case-insensitive
//! volume and hard links all name one file under different strings, and every comparison of
//! strings added so far had another alias. So the claim is an exclusive advisory lock
//! (`flock`/`LockFileEx`, the mechanism of the rotation lock) that the filesystem itself
//! resolves:
//!
//! - A **keyring** entry has no file. It is identified by its scope, which
//!   [`Backend::scoped_keyring`] restricts to one lowercase spelling, so the literal scope is
//!   the identity.
//! - A **credential file** is claimed through a lock file `<credential file>.entry-lock` beside
//!   it (created if absent, empty, never the credential). The file's directory is resolved
//!   (dot segments, symlinked directories) and its name kept, so every spelling of one file
//!   maps to one lock file for the file's lifetime, also after a save renames a new file over
//!   it. On a case-insensitive volume case aliases of the lock file are one inode, so they
//!   contend too. A credential path that is itself a symlink is refused: a save would replace
//!   the symlink with a regular file and leave its target as another credential. On Unix, when the credential file exists it is also locked itself (opened read-only,
//!   so nothing is written), which catches a hard link to it. Windows cannot: a `LockFileEx`
//!   lock is mandatory there and would make the engine's own reads of the file fail.
//!
//! The locks are held for the life of the [`EntryClaim`]. A save replaces the credential file
//! by renaming a new one over it, so a lock on the file's inode only proves what it proved at
//! claim time; a hard link is undone by the first save anyway.

use std::fs::File;
use std::path::{Path, PathBuf};

use fs2::FileExt as _;

use super::{Backend, StoreError, StoreResult};

/// The claim of one credential entry, held while an engine uses it.
#[derive(Debug)]
pub enum EntryClaim {
    /// An OS keyring entry, named by its scope (`None`: the entry the desktop programs share).
    Keyring { scope: Option<String> },
    /// A credential file, held by OS locks.
    File(FileEntryLock),
}

/// The OS locks that make a credential file's claim exclusive.
#[derive(Debug)]
pub struct FileEntryLock {
    path: PathBuf,
    /// The lock file beside the credential file, and the credential file when it was locked
    /// too (Unix, file existed).
    held: Vec<PathBuf>,
    _locks: Vec<File>,
}

impl FileEntryLock {
    /// Whether `contended` (the path a failed claim reported in [`StoreError::EntryInUse`]) is
    /// one of the files this claim holds, as the operating system sees them (not by spelling).
    #[must_use]
    pub fn holds(&self, contended: &Path) -> bool {
        let Ok(contended) = same_file::Handle::from_path(contended) else { return false };
        self.held
            .iter()
            .any(|held| same_file::Handle::from_path(held).is_ok_and(|held| held == contended))
    }

    /// The credential file this claim is for, as the host named it.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn contended(e: &std::io::Error) -> bool {
    if e.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    // `fs2` reports a held `LockFileEx` as the raw ERROR_LOCK_VIOLATION on Windows.
    #[cfg(windows)]
    if e.raw_os_error() == Some(33) {
        return true;
    }
    false
}

/// Locks `file`, or says it is held.
fn lock(file: &File, path: &Path) -> StoreResult<()> {
    match file.try_lock_exclusive() {
        Ok(()) => Ok(()),
        Err(e) if contended(&e) => Err(StoreError::EntryInUse(path.to_path_buf())),
        Err(_) => Err(StoreError::UnresolvableCredentialPath(path.to_path_buf())),
    }
}

/// The claim's lock file suffix. Not `.lock`: a credential file named `credentials` would put
/// its claim on `credentials.lock`, the store's rotation lock, which the engine's own
/// sign-in and refresh must be able to take.
const ENTRY_LOCK_SUFFIX: &str = ".entry-lock";

fn lock_file_path(credential: &Path) -> StoreResult<PathBuf> {
    let name = credential
        .file_name()
        .ok_or_else(|| StoreError::UnresolvableCredentialPath(credential.to_path_buf()))?;
    let mut lock_name = name.to_os_string();
    lock_name.push(ENTRY_LOCK_SUFFIX);
    Ok(credential.with_file_name(lock_name))
}

#[cfg(unix)]
fn open_lock_file(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new().create(true).truncate(false).write(true).mode(0o600).open(path)
}

#[cfg(not(unix))]
fn open_lock_file(path: &Path) -> std::io::Result<File> {
    std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(path)
}

/// The credential file's directory resolved, its own name kept: the path a save replaces,
/// since a save renames a new file over the name it was given.
fn literal(path: &Path) -> StoreResult<PathBuf> {
    let unresolvable = || StoreError::UnresolvableCredentialPath(path.to_path_buf());
    let name = path.file_name().ok_or_else(unresolvable)?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    std::fs::canonicalize(parent).map(|parent| parent.join(name)).map_err(|_| unresolvable())
}

/// Whether `name` is the rotation lock's file name or ends in the claim lock suffix.
fn reserved_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == super::LOCK_FILE || lower.ends_with(ENTRY_LOCK_SUFFIX)
}

fn claim_file(path: &Path) -> StoreResult<FileEntryLock> {
    let unresolvable = || StoreError::UnresolvableCredentialPath(path.to_path_buf());
    let file = literal(path)?;
    // A save renames a new file over the name, which would replace a symlink with a regular
    // file and leave the target (a different name, possibly one that does not exist yet) as
    // another credential. A symlink is therefore not a credential path.
    if std::fs::symlink_metadata(&file).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(StoreError::CredentialFileIsSymlink(path.to_path_buf()));
    }
    // The store's own rotation lock file, or another claim's lock file, is never a credential:
    // holding it for the engine's life would starve the engine's own sign-in and refresh. The
    // names are compared ASCII-case-insensitively, with no probing of the volume: on a
    // case-insensitive one `Credentials.lock` is `credentials.lock`, and on a case-sensitive one
    // refusing it costs nothing.
    if file.file_name().is_some_and(|name| reserved_name(&name.to_string_lossy())) {
        return Err(StoreError::CredentialFileIsRotationLock(path.to_path_buf()));
    }
    let lock_path = lock_file_path(&file)?;
    let mut locks = Vec::new();
    // Only Unix adds the credential file itself below.
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut held = vec![lock_path.clone()];
    let sidecar = open_lock_file(&lock_path).map_err(|_| unresolvable())?;
    lock(&sidecar, &lock_path)?;
    locks.push(sidecar);
    // After the lock file is held, so a credential created in the meantime is seen.
    #[cfg(unix)]
    match File::open(&file) {
        Ok(opened) => {
            lock(&opened, &file)?;
            locks.push(opened);
            held.push(file);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(unresolvable()),
    }
    Ok(FileEntryLock { path: path.to_path_buf(), held, _locks: locks })
}

impl Backend {
    /// Claims the credential entry this backend names, for as long as the result is held.
    ///
    /// # Errors
    /// [`StoreError::EntryInUse`] when another claim (of this process or another) holds the same
    /// entry; [`StoreError::UnresolvableCredentialPath`] when the file's lock file cannot be
    /// created (its directory does not exist, or is not writable), which is refused rather than
    /// assumed to be a different entry; [`StoreError::InvalidKeyringScope`] for a scope that is
    /// not the canonical spelling.
    pub fn claim_entry(&self) -> StoreResult<EntryClaim> {
        match self {
            Backend::Keyring { scope } => {
                if let Some(scope) = scope {
                    // The field is public, so a scope may not have come through the constructor.
                    Backend::scoped_keyring(scope)?;
                }
                Ok(EntryClaim::Keyring { scope: scope.clone() })
            }
            Backend::File(path) => claim_file(path).map(EntryClaim::File),
        }
    }
}
