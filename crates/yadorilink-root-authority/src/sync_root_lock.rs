//! Sync-root single-instance ownership: an OS-level advisory exclusive lock
//! proving no other process is concurrently treating this folder as a sync
//! root.
//!
//! Distinct from [`crate::root_identity`]: that module proves *this is the
//! right folder* (identity, corroborated against the index). This module
//! proves *nobody else is touching it right now* (mutual exclusion between
//! processes). The two are complementary, not overlapping — a folder can be
//! the right one and still be double-owned (two daemons pointed at the same
//! path), and holding this lock does nothing to prove which folder it is.
//!
//! # Why this is not held on `VerifiedRoot`
//!
//! `VerifiedRoot::open`/`verify` run on every scan, every materialization
//! repair pass, every peer-driven write — many times over one link's life,
//! inside a *single* daemon process. An OS `flock` conflicts between two
//! open file *descriptions* of the same file, even within one process, on
//! Linux and macOS (see the identical precedent already relied on by
//! `yadorilink-local-storage::resource_lock::take_exclusive_lock`). Acquiring and
//! releasing a fresh lock on every `VerifiedRoot` construction would
//! therefore make two concurrent in-process operations on the *same* root
//! serialize-or-fail against each other — not what this guards against, and
//! it would break ordinary same-process concurrency today (concurrent scans
//! and repairs over one link are routine).
//!
//! The lock this module provides is instead acquired *once*, when the
//! daemon starts actively managing a link, and held for as long as the
//! daemon keeps that link active — mirroring the config-directory lock
//! (`yadorilink-daemon::app::DaemonInstanceLock`) and the data-resource locks
//! (`yadorilink-local-storage::resource_lock::DataResourceLocks`), which are
//! likewise whole-process-lifetime locks rather than per-operation ones.
//!
//! # Mechanism
//!
//! A sidecar lock file at the top level of the root
//! ([`SYNC_ROOT_LOCK_FILE_NAME`], excluded from sync exactly like the
//! identity marker — see `local_change::is_excluded_from_sync`), held with a
//! non-blocking OS advisory exclusive lock (`flock`/`LockFileEx` via `fs2`)
//! for as long as the returned [`SyncRootLock`] is alive. The OS releases
//! the lock automatically when the holding process exits for any reason —
//! including `SIGKILL` and a hard crash — so the file left behind is never
//! read for "is this stale?"; a plain re-open-and-lock either succeeds
//! (nothing else holds it) or fails (something does), and that is the whole
//! answer.
//!
//! Deliberately, no PID is stored anywhere in this file, and none is read
//! back. A stored PID is not sufficient to tell "the process that held this
//! died" apart from "an unrelated process now has that PID" — PIDs are
//! reused, and a naive stale-lock reclaimer that trusts `kill(pid, 0)` can be
//! fooled by exactly that reuse into stepping on a live owner. What actually
//! answers "is the previous holder still alive" correctly is the *live OS
//! lock state itself*: the kernel tracks the lock against the open file
//! description, not a PID, and tears it down exactly when that description's
//! last reference (the process that opened it) goes away. That is a strictly
//! stronger and simpler signal than any PID bookkeeping this module could add
//! on top, so none is added.
//!
//! # What this assumes, and what happens when the assumption fails
//!
//! This mechanism assumes the underlying filesystem honours OS advisory
//! locking (`flock`/`fcntl`/`LockFileEx`) with real, exclusive,
//! cross-process semantics. Ordinary local filesystems on all three target
//! platforms (APFS, NTFS/ReFS, ext4/btrfs/xfs, ...) satisfy this.
//!
//! A sync root living on a network volume or removable media does not
//! necessarily satisfy it, and the failure mode is a silent fail-**open**,
//! not a refusal:
//!
//! * **NFS** delegates locking to `lockd`/NLM, and a mount using `nolock` (or
//!   talking to a server with no lock manager) grants every caller's lock
//!   request immediately regardless of who else holds it. There is no
//!   portable way to detect this from the client side in advance — the
//!   `try_lock_exclusive` call simply succeeds for two hosts at once.
//! * **SMB/CIFS**: whether an advisory lock taken by one client is honoured
//!   by the server against a *different* client mounting the same share
//!   depends on the server implementation and client mount options; some
//!   configurations only enforce it within one client's own processes.
//! * **Removable media (USB, exFAT/FAT32)** is single-host by construction,
//!   so cross-*process*-on-one-host exclusion still works normally (the
//!   local OS lock manager applies regardless of the filesystem format).
//!   What it cannot do is stop two *different* hosts each believing they own
//!   the volume after a silent unplug/replug from one of them — that
//!   scenario is `root_identity`'s job (the marker/token check), not this
//!   module's.
//!
//! In short: on local storage, and on one host's view of removable media,
//! this lock is correct and load-bearing. On genuinely shared network
//! storage it degrades to whatever that network filesystem's own
//! advisory-lock implementation actually provides, which this module has no
//! way to verify and does not attempt to — it fails closed on outright I/O
//! errors, but a lock request the server silently grants to two hosts at
//! once (the NFS `nolock` case above) is invisible to it by construction.
//! Design section 15's harder "genuine multi-process operation" case ("a
//! fenced lease checked immediately before every namespace mutation") is
//! what would be needed to close that gap; this module implements the
//! simpler single-owner refusal called for today, not that lease.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::error::RootAuthorityError;
use yadorilink_fs_platform::fs_identity::FileIdentity;
pub use yadorilink_fs_platform::reserved_namespace::wire_path_names_sync_root_lock;
pub use yadorilink_replica_domain::reserved_paths::SYNC_ROOT_LOCK_FILE_NAME;

static HELD_ROOT_IDENTITIES: OnceLock<Mutex<HashMap<PathBuf, FileIdentity>>> = OnceLock::new();

fn held_root_identities() -> &'static Mutex<HashMap<PathBuf, FileIdentity>> {
    HELD_ROOT_IDENTITIES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// On Unix, an inode cannot be recycled while this process still has the
/// original inode open. Every `expected` passed by this module was captured
/// from the live `_sidecar` handle and remains registered only for that
/// handle's lifetime. Consequently, an equal `(device, inode, kind)` from a
/// fresh path observation is conclusive in this narrower live-handle case,
/// even when the filesystem exposes neither an inode-generation counter nor
/// a fine birth-time clock (notably overlayfs).
///
/// This is intentionally local to `SyncRootLock`; general persisted identity
/// comparisons must continue to treat a bare Unix inode match as ambiguous,
/// because a closed/unlinked inode can be reused later.
#[cfg(unix)]
fn path_still_names_live_unix_handle(expected: FileIdentity, current: FileIdentity) -> bool {
    matches!(
        (
            expected.volume_identity,
            expected.object_id,
            current.volume_identity,
            current.object_id,
        ),
        (
            yadorilink_fs_platform::fs_identity::VolumeIdentity::Unix { device_id: expected_device },
            yadorilink_fs_platform::fs_identity::PlatformObjectId::Unix { inode: expected_inode },
            yadorilink_fs_platform::fs_identity::VolumeIdentity::Unix { device_id: current_device },
            yadorilink_fs_platform::fs_identity::PlatformObjectId::Unix { inode: current_inode },
        ) if expected_device == current_device
            && expected_inode == current_inode
            && expected.object_kind == current.object_kind
    )
}

fn verify_sidecar_identity(root: &Path, expected: FileIdentity) -> Result<(), RootAuthorityError> {
    let lock_path = root.join(SYNC_ROOT_LOCK_FILE_NAME);
    let current = FileIdentity::observe_path(&lock_path).map_err(|e| {
        RootAuthorityError::OwnershipLost(format!(
            "sync-root lock sidecar {} could not be re-observed: {e} -- this root's ownership can no longer be confirmed",
            lock_path.display()
        ))
    })?;
    // Cached, not the raw probe: this function is reached from
    // `RootLease::begin_operation`, which runs on essentially every local
    // capture, materialize, and hydration operation -- an uncached probe
    // here re-pays real file-create/stat/unlink I/O, inside the very sync
    // root the filesystem watcher is watching, on every single call. See
    // `cached_probe_birth_time_granularity`'s own doc for the cost.
    let granularity =
        yadorilink_fs_platform::fs_capabilities::cached_probe_birth_time_granularity(root);
    match expected.compare(&current, granularity) {
        yadorilink_fs_platform::fs_identity::IdentityComparison::SameObject => Ok(()),
        yadorilink_fs_platform::fs_identity::IdentityComparison::DefinitelyDifferent => {
            Err(RootAuthorityError::OwnershipLost(format!(
                "sync-root lock sidecar {} no longer names the object this process locked",
                lock_path.display()
            )))
        }
        yadorilink_fs_platform::fs_identity::IdentityComparison::Ambiguous(reason) => {
            #[cfg(unix)]
            if path_still_names_live_unix_handle(expected, current) {
                return Ok(());
            }
            Err(RootAuthorityError::OwnershipLost(format!(
                "sync-root lock sidecar {} cannot be conclusively re-verified ({reason:?})",
                lock_path.display()
            )))
        }
    }
}

/// Re-checks the process-lifetime root lock, when one is registered for
/// `root`.
pub fn verify_registered_root_ownership(root: &Path) -> Result<(), RootAuthorityError> {
    let canonical = root.canonicalize()?;
    let expected =
        held_root_identities().lock().unwrap_or_else(|p| p.into_inner()).get(&canonical).copied();
    match expected {
        Some(expected) => verify_sidecar_identity(&canonical, expected),
        None => Ok(()),
    }
}

/// Process-lifetime-scoped exclusive ownership of one sync root. Acquired
/// once (see the module doc for why this is not per-`VerifiedRoot`-call) and
/// held for as long as the daemon keeps this link active; dropping it
/// releases the underlying OS lock, at which point another process's
/// [`SyncRootLock::acquire`] for the same root succeeds.
#[derive(Debug)]
pub struct SyncRootLock {
    _sidecar: std::fs::File,
    /// The identity observed at the moment [`open_sidecar_file`] opened
    /// `_sidecar` — kept (not merely discarded after the open-time checks
    /// run) so a caller that later wants to confirm the held handle still
    /// names the same on-disk object it was granted the lock against has
    /// something to compare a fresh observation to (`FileIdentity::compare`
    /// against a re-observation of `_sidecar` via `FileIdentity::
    /// observe_handle`). Nothing in this module re-checks it today — the
    /// live OS lock on `_sidecar` is already this module's sole
    /// correctness signal (see the module doc) — but recording it here
    /// costs one field and means that check does not need a second, later
    /// open to become possible.
    sidecar_identity: FileIdentity,
    root: PathBuf,
}

impl SyncRootLock {
    /// Acquire exclusive ownership of `root`. Fails closed: any error
    /// resolving the path, opening the sidecar lock file, or finding it
    /// already held by a live owner is `Err` — never "probably fine".
    ///
    /// `root` must already exist (a link's root is created by the join/link
    /// flow before this runs); this deliberately does not create the
    /// directory itself, unlike the block-store root lock in
    /// `yadorilink-local-storage::resource_lock`, which owns a directory this crate
    /// never does.
    pub fn acquire(root: &Path) -> Result<Self, RootAuthorityError> {
        let canonical = root.canonicalize().map_err(|e| {
            RootAuthorityError::Io(io::Error::new(
                e.kind(),
                format!("failed to resolve sync root {}: {e}", root.display()),
            ))
        })?;
        let lock_path = canonical.join(SYNC_ROOT_LOCK_FILE_NAME);
        let (sidecar, sidecar_identity) = open_sidecar_file(&canonical, &lock_path)?;
        take_exclusive_lock(&sidecar, &canonical, &lock_path)?;
        {
            let mut held = held_root_identities().lock().unwrap_or_else(|p| p.into_inner());
            if held.contains_key(&canonical) {
                return Err(RootAuthorityError::CorruptState(format!(
                    "sync root {} already has a registered process owner",
                    canonical.display()
                )));
            }
            held.insert(canonical.clone(), sidecar_identity);
        }
        Ok(Self { _sidecar: sidecar, sidecar_identity, root: canonical })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The identity of the sidecar lock file as observed at acquisition
    /// time — see the field's own doc for why this is kept rather than
    /// discarded once the open-time checks pass.
    pub fn sidecar_identity(&self) -> FileIdentity {
        self.sidecar_identity
    }

    /// Re-verifies that the sidecar path still names the exact object this
    /// lock was granted against. The OS lock this module relies on is held against the open file
    /// *description* (effectively the inode), not the pathname. `flock`
    /// does not prevent `unlink` — a live holder's lock survives its own
    /// sidecar being unlinked out from under it, completely undetected by
    /// that holder. A second process can then `openat(O_CREAT)` the exact
    /// same pathname (which the kernel now treats as creating a BRAND NEW
    /// object, since the old inode is unlinked but still referenced by the
    /// first holder's open descriptor) and successfully take its own
    /// exclusive lock on that new object — two processes now both
    /// correctly believe they exclusively own this sync root, because each
    /// one's OS lock genuinely is uncontended on the specific inode it
    /// holds.
    ///
    /// This method is the fencing primitive `SyncRootLock`'s own struct
    /// doc already anticipated ("nothing in this module re-checks it
    /// today") but never wired up: it re-`observe_path`s the sidecar's
    /// pathname right now and compares the result against the identity
    /// captured at acquisition time. `SameObject` means the pathname still
    /// names what this handle's lock actually covers — safe to proceed.
    /// Anything else — `DefinitelyDifferent` (the common unlink-and-
    /// recreate case; a fresh object now sits at this name), an outright
    /// I/O error (the path is gone, or has become unreadable), or
    /// `Ambiguous` (this platform's identity probe cannot conclusively
    /// prove sameness right now) — fails closed, matching every other
    /// identity check in this crate that treats "cannot prove it's still
    /// the same object" the same as "proven different," never as
    /// "probably still fine."
    ///
    /// Callers are responsible for actually invoking this before a
    /// namespace-mutating operation for full protection — this method only
    /// provides the check itself.
    pub fn verify_still_owns(&self) -> Result<(), RootAuthorityError> {
        verify_sidecar_identity(&self.root, self.sidecar_identity)
    }

    /// The same check as [`Self::verify_still_owns`], detached from this
    /// lock so it can run where the lock itself cannot be borrowed.
    pub fn identity_check(&self) -> RootIdentityCheck {
        RootIdentityCheck { root: self.root.clone(), expected: self.sidecar_identity }
    }
}

/// [`SyncRootLock::verify_still_owns`] with its inputs copied out: the root
/// and the sidecar identity the lock was granted against. Verifying it
/// re-observes the sidecar exactly as the lock would.
#[derive(Debug, Clone)]
pub struct RootIdentityCheck {
    root: PathBuf,
    expected: FileIdentity,
}

impl RootIdentityCheck {
    pub fn verify(&self) -> Result<(), RootAuthorityError> {
        verify_sidecar_identity(&self.root, self.expected)
    }
}

impl Drop for SyncRootLock {
    fn drop(&mut self) {
        held_root_identities().lock().unwrap_or_else(|p| p.into_inner()).remove(&self.root);
    }
}

/// Removes `root`'s entry from the in-process ownership registry without
/// releasing its OS lock or dropping the handle that holds it — for tests
/// that deliberately simulate a *second, independent process* acquiring the
/// same root within a single test process. A real second process has its
/// own empty registry (a separate address space), so it is never blocked by
/// this process's registration; only a genuine same-process double
/// `acquire` is. This lets such a test exercise the OS/inode-level race
/// (`unlink` + recreate at the same pathname) that this registry is not the
/// mechanism for, without the registry's same-process guard masking it.
#[cfg(any(test, feature = "test-support"))]
pub fn forget_registered_root_for_test(root: &Path) {
    held_root_identities().lock().unwrap_or_else(|p| p.into_inner()).remove(root);
}

/// Open (creating if needed, never truncating — this is a lock file, not a
/// content file, so pre-existing bytes are never discarded just by opening
/// it) the sidecar lock file, with `0o600` permissions on Unix, and return
/// the [`FileIdentity`] of the object actually opened alongside it. A
/// process that can write inside `root` (any local user on a
/// single-user-writable directory, or a compromised peer's materialization
/// path) can otherwise plant a symlink at `<root>/.yadorilink-root.lock`
/// pointing anywhere on the filesystem — a naive open-by-path follows it,
/// and the OS lock this module exists to provide then locks an unrelated
/// file while [`SyncRootLock::acquire`] reports success. This function is
/// what closes that: it never follows a symlink already at the lock path,
/// and never accepts anything other than a plain regular file there, in
/// both cases refusing outright (`Err`) rather than falling back to
/// something else at the same name. Same discipline as every artefact this
/// crate creates or opens beside user content (`create_artefact`/
/// `open_child_no_follow`): resolved from an already-open parent-directory
/// handle rather than a second, independently-racy path lookup, and never
/// trusting a name's apparent kind without checking it. Unlike
/// `open_child_no_follow`, this never falls back to opening the symlink
/// entry itself when the name turns out to be one: that helper exists for
/// a caller that has already classified the name as a legitimate symlink
/// it wants a handle to; nothing at this sidecar's path is ever a
/// legitimate symlink, so any symlink found here is refused outright, with
/// no fallback branch to reach. # Platform asymmetry On Unix (Linux and
/// macOS; see the `cfg` below) this is fully directory-handle-relative:
/// `root` is opened once as a directory descriptor, and the sidecar is
/// created/opened through `openat` against that descriptor's file number
/// with `O_NOFOLLOW`, so a rename or replacement of `root` itself after
/// the caller resolved it cannot redirect where the sidecar lands, and a
/// symlink already at the sidecar's name is refused (`ELOOP`) rather than
/// followed — matching `ParentDirHandle::open`'s own directory-relative
/// discipline. On Windows there is no directory-handle-relative open
/// primitive at the Win32 level for this shape (`CreateFileW` has no
/// equivalent of `openat` against a parent descriptor). This function does
/// not pretend otherwise: the Windows path below opens `lock_path`
/// directly, by name, same as the pre-fix code did. What it does still
/// guarantee is the symlink refusal, using a mechanism Windows *does*
/// have: `FILE_FLAG_OPEN_REPARSE_POINT` (the same flag `fs_identity::
/// win_identity::query_path` already relies on for its own never-follow
/// contract) makes `CreateFileW` open a reparse point object itself —
/// whatever it is, a symlink (`IO_REPARSE_TAG_SYMLINK`), a mount point, or
/// any other reparse tag — instead of transparently resolving through it
/// to its target, and the `FILE_ATTRIBUTE_REPARSE_POINT` bit this function
/// then checks on the result is what turns "did not silently follow it"
/// into "refuses it outright", matching the Unix branch's refusal rather
/// than merely not-following.
fn open_sidecar_file(
    root: &Path,
    lock_path: &Path,
) -> Result<(std::fs::File, FileIdentity), RootAuthorityError> {
    let file = open_sidecar_file_platform(root, lock_path)?;
    let identity = FileIdentity::observe_handle(&file).map_err(|e| {
        RootAuthorityError::Io(io::Error::new(
            e.kind(),
            format!(
                "failed to observe identity of sync-root lock sidecar {}: {e}",
                lock_path.display()
            ),
        ))
    })?;
    if identity.object_kind != yadorilink_fs_platform::fs_identity::ObjectKind::RegularFile {
        return Err(RootAuthorityError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to use {} as the sync-root lock: it is not a plain regular file \
                 (found {:?}) — a symlink, directory, FIFO or other special file at this path \
                 is never a legitimate sync-root lock sidecar",
                lock_path.display(),
                identity.object_kind
            ),
        )));
    }
    Ok((file, identity))
}

/// Unix implementation of [`open_sidecar_file`]:
/// directory-handle-relative, never-follow. `O_RDWR` (not the
/// plain-open-existing case's `O_RDONLY`) because the lock file must be
/// creatable, and `fs2`'s `try_lock_exclusive` needs write access to the
/// descriptor regardless of whether this call created or merely opened it.
/// `O_CREAT` without `O_EXCL`: unlike `ParentDirHandle::
/// create_artefact`'s exclusive-create (which must never silently attach
/// to something already there), the sidecar's whole point is to be reused
/// across every acquisition of the same root — see the module doc's
/// "Mechanism" section on why a pre-existing, unlocked sidecar is acquired
/// with no special-casing. A directory, FIFO, socket or device node
/// already at the sidecar's name is not refused by `O_NOFOLLOW` (which
/// only ever refuses a *symlink*) — opening a directory with `O_RDWR`
/// already fails outright with `EISDIR` on both Linux and macOS before
/// this function's own regular-file check ever runs, and opening a FIFO
/// with `O_RDWR` never blocks (POSIX: only a FIFO opened `O_RDONLY`-only
/// or `O_WRONLY`-only can block waiting for the other end), so it is safe
/// to open here and is instead refused by [`open_sidecar_file`]'s own
/// `object_kind` check right after this function returns.
#[cfg(unix)]
fn open_sidecar_file_platform(
    root: &Path,
    lock_path: &Path,
) -> Result<std::fs::File, RootAuthorityError> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let dir = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY).open(root)?;

    // The lock file name is a fixed ASCII constant with no interior NUL, so
    // this conversion cannot fail — `expect` rather than threading a
    // fallible path through a name this module itself controls.
    let name_c = std::ffi::CString::new(std::ffi::OsStr::new(SYNC_ROOT_LOCK_FILE_NAME).as_bytes())
        .expect("SYNC_ROOT_LOCK_FILE_NAME has no interior NUL byte");
    let flags = libc::O_CREAT | libc::O_NOFOLLOW | libc::O_RDWR | libc::O_CLOEXEC;
    // SAFETY: `dir.as_raw_fd()` is a valid, open directory descriptor for
    // the duration of this call; `name_c` is a valid NUL-terminated string;
    // the variadic `mode` argument is required whenever `O_CREAT` is set
    // and is otherwise ignored (masked by the process umask on actual
    // creation).
    let fd =
        unsafe { libc::openat(dir.as_raw_fd(), name_c.as_ptr(), flags, 0o600 as libc::c_uint) };
    if fd < 0 {
        let err = io::Error::last_os_error();
        return Err(RootAuthorityError::Io(io::Error::new(
            err.kind(),
            format!("failed to open sync-root lock sidecar {}: {err}", lock_path.display()),
        )));
    }
    // SAFETY: `fd` was just returned by the successful `openat` call above,
    // is a valid open file descriptor, and is not used or closed anywhere
    // else — `File` takes sole ownership of it here.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    // `fchmod` on the already-open descriptor, not `std::fs::set_permissions`
    // on `lock_path`: the whole point of resolving through `dir`/`openat`
    // above is to never re-resolve the path after the symlink check has
    // already run, and a path-based `set_permissions` call here would
    // reopen exactly that TOCTOU window one line later.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

/// Windows implementation of [`open_sidecar_file`] — see that function's
/// "Platform asymmetry" doc for what this can and cannot guarantee
/// relative to the Unix branch above.
/// `custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)` is a stable
/// `std::os::windows::fs::OpenOptionsExt` call — no hand-declared
/// `CreateFileW` FFI needed for this half of the fix, unlike
/// `fs_identity:: win_identity`'s own reason for declaring it by hand
/// (this crate does not need `FileIdInfo`/`GetFileInformationByHandleEx`
/// here, only the one documented `dwFlagsAndAttributes` bit
/// `OpenOptionsExt::custom_flags` already exposes on stable).
#[cfg(windows)]
fn open_sidecar_file_platform(
    _root: &Path,
    lock_path: &Path,
) -> Result<std::fs::File, RootAuthorityError> {
    use std::os::windows::fs::OpenOptionsExt;

    /// `FILE_FLAG_OPEN_REPARSE_POINT` — identical value, and identical
    /// justification, as `fs_identity::win_identity`'s own private copy of
    /// this constant (that module's `mod win_identity` is private to
    /// `fs_identity.rs`, so this is a second declaration of the same
    /// documented Win32 constant rather than a shared one; see
    /// `fs_identity.rs`'s `FILE_FLAG_OPEN_REPARSE_POINT` for the identical
    /// value from the same Win32 header).
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(lock_path)?;

    // `CreateFileW` with `FILE_FLAG_OPEN_REPARSE_POINT` does not itself
    // refuse to open a reparse point — it only stops silently resolving
    // through one to its target. Refusing it outright is this check's job:
    // `FILE_ATTRIBUTE_REPARSE_POINT` is set on the returned metadata for a
    // symlink, junction, mount point or any other reparse tag, and never
    // for a plain file created by this same call.
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let attributes = file.metadata()?.file_attributes();
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(RootAuthorityError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "refusing to use {} as the sync-root lock: it is a reparse point (symlink, \
                 junction or mount point), not a plain file",
                lock_path.display()
            ),
        )));
    }
    Ok(file)
}

/// Take a non-blocking exclusive OS lock on `file`, mapping contention to a
/// clear "already in use" error and any other failure to a plain I/O error.
///
/// Compares against `fs2::lock_contended_error()`'s raw OS error rather than
/// `ErrorKind::WouldBlock`: on Windows, `try_lock_exclusive`'s real
/// contention error is `ERROR_LOCK_VIOLATION` (raw OS error 33), which does
/// not map to `ErrorKind::WouldBlock` in std's Windows error-kind mapping —
/// unlike Unix's `EWOULDBLOCK`, which does. Mirrors
/// `yadorilink-local-storage::resource_lock::take_exclusive_lock`'s identical
/// comparison, for the identical reason (that module's own comment cites
/// `fs2`'s test suite comparing the same way).
fn take_exclusive_lock(
    file: &std::fs::File,
    root: &Path,
    lock_path: &Path,
) -> Result<(), RootAuthorityError> {
    match fs2::FileExt::try_lock_exclusive(file) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
            Err(RootAuthorityError::Io(io::Error::new(
                error.kind(),
                format!(
                    "sync root {} is already in use by another YadoriLink process",
                    root.display()
                ),
            )))
        }
        Err(error) => Err(RootAuthorityError::Io(io::Error::new(
            error.kind(),
            format!("failed to acquire sync-root lock {}: {error}", lock_path.display()),
        ))),
    }
}

#[cfg(test)]
mod tests;
