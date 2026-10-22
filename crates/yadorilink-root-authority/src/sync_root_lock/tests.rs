#![cfg(test)]

use super::*;

/// The wire-path form must catch what the host form is not safe to be
/// used for: a peer path spelled with a different case, or an NTFS
/// alternate-data-stream suffix — mirroring `reserved_namespace`'s own
/// wire-path tests for the identical reasons (see
/// [`wire_path_names_sync_root_lock`]'s doc comment). It must also stay
/// top-level-only (unlike the versioned-artefact wire check, which
/// matches at any depth): a *nested* same-named path, on either
/// separator convention, is ordinary user content and must not match.
#[test]
fn wire_path_form_is_top_level_only_and_matches_case_and_ads_variants() {
    assert!(wire_path_names_sync_root_lock(".yadorilink-root.lock"));
    assert!(wire_path_names_sync_root_lock(".YADORILINK-ROOT.LOCK"));
    assert!(wire_path_names_sync_root_lock(".yadorilink-root.lock::$DATA"));
    assert!(!wire_path_names_sync_root_lock("notes.txt"));
    assert!(!wire_path_names_sync_root_lock("some/dir/.yadorilink-root.lock"));
    assert!(!wire_path_names_sync_root_lock("some\\dir\\.yadorilink-root.lock"));
    assert!(!wire_path_names_sync_root_lock("nested/.yadorilink-root.lock/inner.txt"));
}

/// A second acquisition of the same root, while the first is still
/// held, must be refused. Real `fs2` OS locks, not a mock: `flock`
/// conflicts between two open file descriptions of the same file even
/// within a single process (the same property
/// `yadorilink-daemon::resource_lock`'s equivalent tests rely on), so
/// this genuinely exercises the OS lock, not an in-process flag.
#[test]
fn a_second_acquisition_is_refused_while_the_first_is_held() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let _owner = SyncRootLock::acquire(&root).unwrap();

    let err = SyncRootLock::acquire(&root)
        .expect_err("a second holder of the same sync root must be rejected");
    assert!(err.to_string().contains("already in use"), "unexpected error: {err}");
}

/// Releasing (dropping) the lock makes the root acquirable again — the
/// ordinary "link stopped, then restarted" path within one daemon
/// process.
#[test]
fn releasing_the_lock_makes_the_root_acquirable_again() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();

    let owner = SyncRootLock::acquire(&root).unwrap();
    assert!(SyncRootLock::acquire(&root).is_err(), "must be exclusive while held");
    drop(owner);

    let _reacquired = SyncRootLock::acquire(&root)
        .expect("the root must be acquirable again once the prior owner released it");
}

/// A lock file left on disk with nothing holding its OS lock (the
/// steady state after any prior owner's process exited, cleanly or not
/// — the OS releases the lock but this module never deletes the lock
/// file itself) must be reacquired with no special-casing. Pins that
/// there is no stale-file logic to go wrong: an unlocked pre-existing
/// file is indistinguishable from a freshly created one.
#[test]
fn a_preexisting_but_unlocked_lock_file_is_acquired_normally() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    std::fs::write(root.join(SYNC_ROOT_LOCK_FILE_NAME), b"").unwrap();

    let _owner = SyncRootLock::acquire(&root)
        .expect("a lock file with nothing holding its OS lock must be acquired normally");
}

// The crash-recovery case (a genuine child process, SIGKILLed) lives in
// `tests/sync_root_lock_process.rs`: spawning from this process would let a
// forked child briefly share other tests' lock descriptors.

/// THE symlink-planting attack this fix exists for: a process that can
/// write inside the sync root plants a symlink at the sidecar's exact
/// name, pointing at some other file it wants locked (or, worse, at a
/// file it wants to be able to observe *whether* the daemon is holding
/// open). Before the fix, `open_sidecar_file` used a plain
/// `OpenOptions::open` by path, which follows a symlink transparently —
/// `SyncRootLock::acquire` would then lock `target.txt`, not the sidecar,
/// and report success while proving nothing about single-instance
/// ownership of `root`. Pins that this is refused outright, not
/// followed.
#[test]
fn a_symlink_planted_at_the_sidecar_path_is_refused_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let target = root.join("target.txt");
    std::fs::write(&target, b"unrelated content").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, root.join(SYNC_ROOT_LOCK_FILE_NAME)).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&target, root.join(SYNC_ROOT_LOCK_FILE_NAME)).unwrap();

    let err = SyncRootLock::acquire(&root)
        .expect_err("a symlink planted at the sidecar path must be refused, not followed");
    assert!(
        !err.to_string().contains("already in use"),
        "must be refused for being a symlink, not because the (unrelated) target happens \
         to look locked: {err}"
    );

    // The real proof this wasn't silently followed: the target file's
    // own bytes are untouched, and it is still an ordinary,
    // non-locked, plain file — nothing here ever opened or locked it.
    assert_eq!(std::fs::read(&target).unwrap(), b"unrelated content");
}

// A "directory at the sidecar path is refused" test was written and
// mutation-checked here, then dropped: `std::fs::OpenOptions::new().
// write(true).open(<a directory>)` already fails with `EISDIR` even on
// the pre-fix code (a plain path-based open with no `O_NOFOLLOW` at
// all), because Unix refuses to open a directory for writing regardless
// of symlink-following. That test was green before this fix and green
// after it — it exercises the OS's own directory-vs-file distinction,
// not anything this module's `open_sidecar_file` rewrite added, so it
// would not have caught a regression in the actual fix and is not kept.
// The FIFO test below is the real non-regular-file case: `O_NOFOLLOW`
// does not refuse a FIFO (only a symlink), so a FIFO opens successfully
// and only this module's own `object_kind` check afterward refuses it —
// confirmed by mutation (disabling that check turns the FIFO test red).

/// A FIFO at the sidecar's exact name is the other non-regular-file
/// case this module's `O_NOFOLLOW` open does not implicitly exclude
/// (`O_NOFOLLOW` only refuses a *symlink*; a FIFO opens successfully
/// with `O_RDWR`, per POSIX, without blocking) — it is
/// `open_sidecar_file`'s explicit `object_kind` check afterward that
/// must catch this one. Unix-only: FIFOs are not a concept at an
/// ordinary filesystem path on Windows (named pipes live in a separate
/// `\\.\pipe\` namespace), so there is nothing to plant there — see
/// `open_sidecar_file`'s own doc on the Windows-side residual this
/// module states plainly rather than pretending symmetric.
/// The happy path: nothing touched the sidecar since acquisition, so
/// `verify_still_owns` must succeed.
#[test]
fn verify_still_owns_succeeds_while_nothing_has_touched_the_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let owner = SyncRootLock::acquire(&root).unwrap();

    owner.verify_still_owns().expect("nothing changed -- must still confirm ownership");
}

/// Proves the real call
/// chain -- not just the pure caching decision
/// `granularity_cache_reprobes_on_a_different_volume_identity_but_not_
/// the_same_one` in `fs_capabilities.rs` already covers -- actually
/// stops re-probing. `RootLease::begin_operation` and every
/// `LinkOperation::reverify()` (i.e. every `RootCommitPermit::verify()`
/// along one operation's path) reach `verify_still_owns` repeatedly;
/// before this fix, each call paid a full uncached
/// `probe_birth_time_granularity` (real file-create/stat/unlink I/O).
/// Confirmed genuinely RED against the pre-fix code (temporarily
/// reverting `verify_sidecar_identity` to call the raw, uncached probe):
/// this test's second assertion then failed, the count having grown by
/// 2 instead of staying flat.
#[test]
fn repeated_verify_still_owns_calls_probe_at_most_once_per_volume() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let owner = SyncRootLock::acquire(&root).unwrap();

    owner.verify_still_owns().expect("first call must succeed");
    let count_after_first =
        yadorilink_fs_platform::fs_capabilities::probe_birth_time_granularity_call_count_for_test();

    owner.verify_still_owns().expect("second call must succeed");
    owner.verify_still_owns().expect("third call must succeed");
    let count_after_more =
        yadorilink_fs_platform::fs_capabilities::probe_birth_time_granularity_call_count_for_test();

    assert_eq!(
        count_after_more, count_after_first,
        "repeated verify_still_owns calls for the same volume must not trigger additional \
         real granularity probes -- only the first call (or a genuine cache miss on a \
         different volume) may"
    );
}

/// The double-acquisition hazard: `flock` is
/// bound to the open file description, not the pathname, so unlinking
/// the sidecar out from under a live holder does not affect that
/// holder's own lock at all -- but it DOES let a second `openat(
/// O_CREAT)` at the identical pathname create a brand-new object and
/// take its own, independently-uncontended exclusive lock on it. Both
/// processes then correctly believe they exclusively own the root.
/// `verify_still_owns` must detect this: after the unlink-and-recreate,
/// the ORIGINAL holder's re-check of the pathname must fail, since the
/// object now sitting there is not the one its lock actually covers.
#[test]
fn verify_still_owns_detects_an_unlink_and_recreate_of_the_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let owner = SyncRootLock::acquire(&root).unwrap();
    owner.verify_still_owns().expect("precondition: still fine immediately after acquiring");

    // Simulate a second process's exact sequence: unlink the sidecar
    // pathname (the first holder's lock is completely unaffected by
    // this -- it is bound to the now-unlinked inode, not the name),
    // then create and lock a fresh object at the same name.
    let lock_path = root.join(SYNC_ROOT_LOCK_FILE_NAME);
    std::fs::remove_file(&lock_path).unwrap();
    // A genuine second process has its own empty in-process registry,
    // so it is never blocked by this process's registration -- only a
    // real same-process double `acquire` is. Simulate that here so this
    // test still exercises the OS/inode-level race, not the unrelated
    // same-process guard.
    forget_registered_root_for_test(&root);
    let _second_holder = SyncRootLock::acquire(&root).expect(
        "a second acquisition after the unlink must succeed -- this IS the bug: the \
         kernel sees an entirely new, uncontended object at this pathname",
    );

    let err = owner.verify_still_owns().expect_err(
        "the original holder's re-check must detect that the pathname no longer names the \
         object its lock actually covers",
    );
    assert!(
        !err.to_string().contains("already in use"),
        "must fail as an identity mismatch, not a lock-contention error: {err}"
    );
}

#[cfg(unix)]
#[test]
fn a_fifo_at_the_sidecar_path_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let fifo_path = root.join(SYNC_ROOT_LOCK_FILE_NAME);
    let fifo_path_c = {
        use std::os::unix::ffi::OsStrExt;
        std::ffi::CString::new(fifo_path.as_os_str().as_bytes()).unwrap()
    };
    // SAFETY: `fifo_path_c` is a valid NUL-terminated string naming a
    // path inside a directory this test just created and owns; `0o600`
    // is an ordinary permission mode for `mkfifo(3)`.
    let ret = unsafe { libc::mkfifo(fifo_path_c.as_ptr(), 0o600) };
    assert_eq!(ret, 0, "mkfifo failed: {}", io::Error::last_os_error());

    let err = SyncRootLock::acquire(&root)
        .expect_err("a FIFO at the sidecar path must be refused, never treated as a lock");
    assert!(err.to_string().contains("not a plain regular file"), "unexpected error: {err}");
}
