//! Process-lifetime exclusive locks on the daemon's *mutable data resources* —
//! the block-store root and the sync-state SQLite database.
//!
//! The config-directory lock ([`crate::app`]'s `DaemonInstanceLock`) only
//! guarantees a single daemon per *config directory*. But the block-store root
//! and the SQLite database path are independently overridable
//! (`YADORILINK_BLOCK_STORE` / `YADORILINK_SYNC_DB`), so two daemons started
//! with *distinct* config directories — each holding its own config-dir lock —
//! could still be pointed at the *same* store root and/or database. Two writers
//! over one block store or one SQLite index risks index/store corruption:
//! `SegmentBlockStore`'s internal locks are process-local and SQLite's WAL mode
//! happily lets both processes open the same file. These locks close that gap,
//! additively (the config-dir lock is untouched).
//!
//! Mechanism: an OS advisory exclusive lock (`flock`/`LockFileEx` via `fs2`),
//! applied in two layers together. First, a *sidecar* lock file whose location
//! is derived from the **canonicalized** resource path (both resources, all
//! platforms). Second (Linux/Android only, sync DB only), an additional
//! whole-file flock on the **live database inode itself**, to catch same-inode
//! aliases whose canonical path — and therefore sidecar path — differs (see
//! below). Like the config-dir lock, the OS releases the locks on process exit
//! (including SIGKILL/crash) and the lock files are left in place — acquisition
//! never parses PIDs or deletes "stale" files.
//!
//! ## What is caught
//!
//! By canonicalize + sidecar (all platforms):
//!
//! * the exact same path;
//! * `..`-relative aliases;
//! * symlinked parent directories;
//! * a symlink pointing directly at an *existing* database file (its full path
//!   canonicalizes to the real file);
//! * a **directory** bind mount of a parent: the sidecar is one real inode
//!   inside the shared directory, so both mount paths open it and conflict even
//!   though their canonical paths differ (handle identity).
//!
//! Additionally, by the live-inode flock (Linux/Android, sync DB only):
//!
//! * a **file** bind mount of the database file itself (same inode, different
//!   canonical path — hence a different sidecar);
//! * a **hard link** of the database file into another path/directory.
//!
//! ## What is NOT caught (known limitations)
//!
//! * On **macOS, the BSDs, and Windows**, the file-bind-mount and
//!   hard-link-of-DB-file cases are NOT caught — there is no live-inode flock
//!   there. This is deliberate, not an oversight: verification showed that on
//!   macOS a whole-file `flock` held on the SQLite file makes SQLite itself
//!   return `database is locked`, and on Windows `fs2`'s whole-file
//!   `LockFileEx` range overlaps the byte range SQLite locks — so locking the
//!   live DB inode is unsafe on those platforms. They get sidecar-only. (The
//!   block-store root has no equivalent gap on any platform: a directory cannot
//!   be hard-linked, and a directory bind mount is already caught by the
//!   sidecar's inode identity.)
//! * **NFS**, even on Linux: `flock` there is emulated via whole-file POSIX
//!   byte-range locks that can interact with SQLite's own POSIX locks, and
//!   SQLite is itself officially unsupported on NFS. Running the daemon's
//!   database on NFS is out of scope.
//! * **Concurrent-rename TOCTOU**: the lock is taken on the canonical path
//!   resolved at acquisition time; `SyncState`/`SegmentBlockStore` then open the
//!   originally-configured path. A hostile concurrent rename or symlink swap
//!   between those two steps could make them diverge. Out of threat model —
//!   this guards a cooperative env-override *misconfiguration*, not an attacker
//!   racing the filesystem.
//! * **Dangling symlink to a not-yet-created target**: when neither daemon's
//!   database exists yet, canonicalization falls back to canonical-parent +
//!   filename, so two daemons pointing distinct dangling symlinks at the same
//!   eventual target may both start until the file is created. Also out of
//!   threat model.

use std::path::{Path, PathBuf};

/// Lock file placed *inside* the block-store root. Ignored by the store itself:
/// `SegmentBlockStore`'s usage scan only counts 64-character hash filenames,
/// so this sidecar is never miscounted as a block.
const BLOCK_STORE_LOCK_FILE: &str = ".yadorilink-store.lock";

/// Process-lifetime ownership of one mutable data resource. Holding the
/// [`std::fs::File`] handles keeps the advisory lock(s); dropping the value
/// releases them (so a partially-acquired set rolls back automatically).
#[derive(Debug)]
pub(crate) struct ResourceLock {
    _sidecar: std::fs::File,
    /// (Linux/Android, sync DB only) A second whole-file flock held on the
    /// *live* database inode, so same-inode aliases (file bind mount, hard
    /// link) whose canonical path — and thus sidecar — differs are still
    /// caught. `None` for the block-store root (a directory, which cannot be
    /// hard-linked). Absent entirely on other platforms, where locking the live
    /// SQLite inode is unsafe (see the module doc).
    #[cfg(any(target_os = "linux", target_os = "android"))]
    _live_inode: Option<std::fs::File>,
}

impl ResourceLock {
    /// Lock the block-store root. The lock file lives inside the canonicalized
    /// root, so any alias resolving to (or bind-mounting) the same directory
    /// targets the same lock-file inode and conflicts.
    pub(crate) fn lock_block_store(root: &Path) -> anyhow::Result<Self> {
        let canonical = canonicalize_dir(root).map_err(|e| {
            anyhow::anyhow!("failed to resolve block-store root {}: {e}", root.display())
        })?;
        let lock_path = canonical.join(BLOCK_STORE_LOCK_FILE);
        let label = format!("block store {}", canonical.display());
        let sidecar = open_sidecar_file(&lock_path)?;
        take_exclusive_lock(&sidecar, &label, &lock_path)?;
        Ok(Self {
            _sidecar: sidecar,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            _live_inode: None,
        })
    }

    /// Lock the sync-state SQLite database. A sidecar lock file next to the
    /// canonicalized database path handles path/symlink/dir-bind-mount aliases
    /// on every platform; on Linux/Android an additional whole-file flock on
    /// the live database inode additionally catches same-inode file aliases
    /// (bind mount, hard link). See the module doc for the platform rationale.
    pub(crate) fn lock_sync_db(db_path: &Path) -> anyhow::Result<Self> {
        let canonical_db = canonicalize_file_target(db_path).map_err(|e| {
            anyhow::anyhow!("failed to resolve sync database {}: {e}", db_path.display())
        })?;
        let parent = canonical_db.parent().ok_or_else(|| {
            anyhow::anyhow!("sync database path {} has no parent directory", canonical_db.display())
        })?;
        let file_name = canonical_db.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            anyhow::anyhow!("sync database path {} has no file name", canonical_db.display())
        })?;
        let lock_path = parent.join(format!(".{file_name}.yadorilink-lock"));
        let label = format!("sync database {}", canonical_db.display());

        // Sidecar first (portable path-alias coverage).
        let sidecar = open_sidecar_file(&lock_path)?;
        take_exclusive_lock(&sidecar, &label, &lock_path)?;

        // Then the live-inode flock, where it is safe. If this conflicts the
        // sidecar handle above is dropped as we return `Err`, releasing it.
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let live_inode = Self::lock_live_inode(&canonical_db, &label)?;

        Ok(Self {
            _sidecar: sidecar,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            _live_inode: live_inode,
        })
    }

    /// Flock the live database inode if the database exists. Never creates it.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn lock_live_inode(canonical_db: &Path, label: &str) -> anyhow::Result<Option<std::fs::File>> {
        // Open the real database inode and flock the whole file. This
        // must NEVER create it: an absent database is how startup tells a
        // new install from a lost one (`refuse_lost_database`), and an
        // empty file made here would pass that check and let the first
        // idle sweep delete every surviving block. A database that does
        // not exist yet has no hard link or file bind mount to alias, so
        // the sidecar alone covers it. `truncate(false)` is load-bearing:
        // we must never truncate the live database. Verified not to
        // disturb SQLite's own WAL-mode locking on Linux local
        // filesystems, because `flock` and SQLite's POSIX `fcntl`
        // byte-range locks are independent there. We do NOT chmod the file.
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .truncate(false)
            .open(canonical_db)
        {
            Ok(live) => {
                take_exclusive_lock(&live, label, canonical_db)?;
                Ok(Some(live))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::anyhow!(
                "failed to open sync database {} for inode lock: {e}",
                canonical_db.display()
            )),
        }
    }

    /// Take the live-inode flock once the database has been created. A
    /// database that was absent at `lock_sync_db` time had no inode to lock
    /// then; without this the first session would not be protected against a
    /// hard-link or file-bind-mount alias of the file it just created.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) fn lock_created_live_inode(&mut self, db_path: &Path) -> anyhow::Result<()> {
        if self._live_inode.is_none() {
            let canonical_db = canonicalize_file_target(db_path).map_err(|e| {
                anyhow::anyhow!("failed to resolve sync database {}: {e}", db_path.display())
            })?;
            let label = format!("sync database {}", canonical_db.display());
            self._live_inode = Self::lock_live_inode(&canonical_db, &label)?;
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    pub(crate) fn lock_created_live_inode(&mut self, _db_path: &Path) -> anyhow::Result<()> {
        Ok(())
    }
}

/// The daemon's two data-resource locks, acquired together in a deterministic
/// order so distinct instances can never deadlock waiting on each other.
#[derive(Debug)]
pub(crate) struct DataResourceLocks {
    _block_store: ResourceLock,
    _sync_db: ResourceLock,
}

impl DataResourceLocks {
    /// Acquire the block-store lock then the sync-DB lock, in that fixed order
    /// (the caller already holds the config-dir lock, so the global order is
    /// config dir → block store → DB). On any conflict the already-acquired
    /// lock is dropped as this returns `Err`, so a losing daemon fails fast
    /// holding nothing — no store or database mutation has happened yet.
    pub(crate) fn acquire(block_store_root: &Path, sync_db_path: &Path) -> anyhow::Result<Self> {
        let block_store = ResourceLock::lock_block_store(block_store_root)?;
        let sync_db = ResourceLock::lock_sync_db(sync_db_path)?;
        Ok(Self { _block_store: block_store, _sync_db: sync_db })
    }

    /// Call after the sync database has been opened (and so created, on a
    /// new install) to extend the lock to the live inode.
    pub(crate) fn lock_created_sync_db(&mut self, sync_db_path: &Path) -> anyhow::Result<()> {
        self._sync_db.lock_created_live_inode(sync_db_path)
    }
}

/// Open (creating if needed, never truncating) a sidecar lock file at
/// `lock_path`, with `0o600` permissions on Unix. The sidecar is our own file,
/// so tightening its mode is safe (unlike the live database file, which we
/// never chmod).
fn open_sidecar_file(lock_path: &Path) -> anyhow::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)
        .map_err(|e| anyhow::anyhow!("failed to open lock file {}: {e}", lock_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(lock_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// Take a non-blocking exclusive OS lock on `file`, mapping contention to a
/// clear "already in use" error and any other failure to a lock-path error.
///
/// Compares against `fs2::lock_contended_error()`'s raw OS error rather than
/// `ErrorKind::WouldBlock`: on Windows, `try_lock_exclusive`'s real
/// contention error is `ERROR_LOCK_VIOLATION` (raw os error 33), which does
/// not map to `ErrorKind::WouldBlock` in std's Windows error-kind mapping
/// (unlike Unix's `EWOULDBLOCK`, which does) -- `fs2`'s own test suite
/// compares the same way for the same reason.
fn take_exclusive_lock(
    file: &std::fs::File,
    resource_label: &str,
    lock_path: &Path,
) -> anyhow::Result<()> {
    match fs2::FileExt::try_lock_exclusive(file) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
            anyhow::bail!("{resource_label} is already in use by another YadoriLink daemon")
        }
        Err(error) => {
            Err(anyhow::anyhow!("failed to acquire lock {}: {error}", lock_path.display()))
        }
    }
}

/// Create `dir` if needed and return its canonical path (resolving `..`,
/// symlinked components, and a symlink to the directory itself).
fn canonicalize_dir(dir: &Path) -> std::io::Result<PathBuf> {
    // Created durably where the volume offers it: a plain `create_dir_all` here would leave the
    // root's own entry unpublished, and the store's later creation trusts an existing root.
    yadorilink_fs_platform::durable_dir::create_dir_all_durably(dir)?;
    dir.canonicalize()
}

/// Resolve a *file* target to a canonical path stable across aliases. If the
/// file already exists (the common case — a prior daemon created it),
/// `canonicalize` resolves `..`, symlinked parents, and a symlink to the file
/// itself. If it does not exist yet, canonicalize the parent directory and
/// rejoin the final component so `..`/symlinked-parent aliases still collapse.
fn canonicalize_file_target(path: &Path) -> std::io::Result<PathBuf> {
    if let Ok(canonical) = path.canonicalize() {
        return Ok(canonical);
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    yadorilink_fs_platform::durable_dir::create_dir_all_durably(&parent)?;
    Ok(parent.canonicalize()?.join(file_name))
}

#[cfg(test)]
mod tests;
