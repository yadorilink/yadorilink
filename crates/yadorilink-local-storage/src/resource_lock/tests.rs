#![cfg(test)]

use super::*;

// --- block store ---------------------------------------------------------

#[test]
fn block_store_lock_rejects_second_holder_on_exact_path() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("blocks");
    let _owner = ResourceLock::lock_block_store(&root).unwrap();

    let err = ResourceLock::lock_block_store(&root)
        .expect_err("a second holder of the same block-store root must be rejected");
    assert!(err.to_string().contains("already in use"), "unexpected error: {err}");
}

#[test]
fn block_store_lock_rejects_dotdot_alias() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("blocks");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    let _owner = ResourceLock::lock_block_store(&root).unwrap();

    // `<root>/sub/..` is an alias of `<root>` that canonicalization must
    // collapse.
    let alias = root.join("sub").join("..");
    let err = ResourceLock::lock_block_store(&alias)
        .expect_err("a `..`-relative alias of the block-store root must be rejected");
    assert!(err.to_string().contains("already in use"), "unexpected error: {err}");
}

#[cfg(unix)]
#[test]
fn block_store_lock_rejects_symlinked_parent_alias() {
    let dir = tempfile::tempdir().unwrap();
    let real_parent = dir.path().join("real");
    let root = real_parent.join("blocks");
    let _owner = ResourceLock::lock_block_store(&root).unwrap();

    // A symlinked *parent* directory: `<link>/blocks` resolves to the same
    // real block-store root.
    let link_parent = dir.path().join("link");
    std::os::unix::fs::symlink(&real_parent, &link_parent).unwrap();
    let aliased_root = link_parent.join("blocks");

    let err = ResourceLock::lock_block_store(&aliased_root)
        .expect_err("a symlinked-parent alias of the block-store root must be rejected");
    assert!(err.to_string().contains("already in use"), "unexpected error: {err}");
}

// --- sync database -------------------------------------------------------

#[test]
fn sync_db_lock_rejects_second_holder_on_exact_path() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("sync-state.sqlite3");
    let _owner = ResourceLock::lock_sync_db(&db).unwrap();

    let err = ResourceLock::lock_sync_db(&db)
        .expect_err("a second holder of the same sync database must be rejected");
    assert!(err.to_string().contains("already in use"), "unexpected error: {err}");
}

#[test]
fn sync_db_lock_rejects_dotdot_alias() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("sub")).unwrap();
    let db = dir.path().join("sync-state.sqlite3");
    let _owner = ResourceLock::lock_sync_db(&db).unwrap();

    // `<dir>/sub/../sync-state.sqlite3` names the same database.
    let alias = dir.path().join("sub").join("..").join("sync-state.sqlite3");
    let err = ResourceLock::lock_sync_db(&alias)
        .expect_err("a `..`-relative alias of the sync database must be rejected");
    assert!(err.to_string().contains("already in use"), "unexpected error: {err}");
}

#[cfg(unix)]
#[test]
fn sync_db_lock_rejects_symlink_to_existing_db_file() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("sync-state.sqlite3");
    // The database already exists (a prior owner created it), so a symlink
    // pointing straight at the file resolves to the same real path.
    std::fs::write(&db, b"").unwrap();
    let _owner = ResourceLock::lock_sync_db(&db).unwrap();

    let db_link = dir.path().join("db-link.sqlite3");
    std::os::unix::fs::symlink(&db, &db_link).unwrap();
    let err = ResourceLock::lock_sync_db(&db_link)
        .expect_err("a symlink to the existing sync database file must be rejected");
    assert!(err.to_string().contains("already in use"), "unexpected error: {err}");
}

/// Live-inode flock coverage: a **hard link** of the database file has the
/// same inode but a different canonical path (and therefore a different
/// sidecar), so only the live-inode flock can catch it. Gated to the
/// platforms where that flock is applied (and verified safe against SQLite).
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn sync_db_lock_rejects_hard_link_via_live_inode_flock() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("sync-state.sqlite3");
    std::fs::write(&db, b"").unwrap();
    let _owner = ResourceLock::lock_sync_db(&db).unwrap();

    let hard = dir.path().join("aliased.sqlite3");
    std::fs::hard_link(&db, &hard).unwrap();
    // The two paths really are the same inode but distinct sidecars, so the
    // rejection can only come from the live-inode flock.
    let err = ResourceLock::lock_sync_db(&hard)
        .expect_err("a hard link to the same DB inode must be rejected by the live-inode flock");
    assert!(err.to_string().contains("already in use"), "unexpected error: {err}");
}

/// A database absent at lock time gets its inode lock once it is created, so
/// the first session is also protected against a hard-link alias.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn a_database_created_after_locking_gets_the_live_inode_lock() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("sync-state.sqlite3");
    let mut owner = ResourceLock::lock_sync_db(&db).unwrap();
    std::fs::write(&db, b"").unwrap();
    owner.lock_created_live_inode(&db).unwrap();

    let hard = dir.path().join("aliased.sqlite3");
    std::fs::hard_link(&db, &hard).unwrap();
    let err = ResourceLock::lock_sync_db(&hard)
        .expect_err("a hard link to the newly created DB inode must be rejected");
    assert!(err.to_string().contains("already in use"), "unexpected error: {err}");
}

/// The live-inode flock must roll back with the sidecar: after the owner
/// exits, a previously-rejected hard-link path must acquire cleanly
/// (nothing was left locked).
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn sync_db_hard_link_lock_releases_on_owner_exit() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("sync-state.sqlite3");
    std::fs::write(&db, b"").unwrap();
    let hard = dir.path().join("aliased.sqlite3");
    std::fs::hard_link(&db, &hard).unwrap();

    let owner = ResourceLock::lock_sync_db(&db).unwrap();
    assert!(ResourceLock::lock_sync_db(&hard).is_err());
    drop(owner);
    // Owner released both its sidecar and its live-inode flock.
    let _reacquire = ResourceLock::lock_sync_db(&hard)
        .expect("the live-inode flock must be released when the owner exits");
}

// --- no false positives + independence ----------------------------------

#[test]
fn distinct_block_store_and_db_do_not_collide_in_same_dir() {
    // A block-store lock and a sync-DB lock rooted in the SAME directory
    // are distinct resources and must both succeed.
    let dir = tempfile::tempdir().unwrap();
    let _store = ResourceLock::lock_block_store(&dir.path().join("blocks")).unwrap();
    let _db = ResourceLock::lock_sync_db(&dir.path().join("sync-state.sqlite3")).unwrap();
}

#[test]
fn genuinely_distinct_resources_all_start() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let _a =
        DataResourceLocks::acquire(&a.path().join("blocks"), &a.path().join("sync-state.sqlite3"))
            .unwrap();
    // Fully disjoint resources: no false positive, both instances "start".
    let _b =
        DataResourceLocks::acquire(&b.path().join("blocks"), &b.path().join("sync-state.sqlite3"))
            .expect("a daemon with genuinely distinct resources must acquire its locks");
}

// --- stale (unlocked) lock file -----------------------------------------

#[test]
fn stale_unlocked_lock_file_is_reacquired() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("blocks");
    // First owner acquires and then exits (drop releases the OS lock but
    // deliberately leaves the lock file on disk).
    drop(ResourceLock::lock_block_store(&root).unwrap());
    assert!(root.join(BLOCK_STORE_LOCK_FILE).exists(), "lock file should persist after drop");

    // A fresh owner must acquire the pre-existing but unlocked file fine —
    // no stale-PID logic, mirroring the config-dir lock.
    let _new_owner = ResourceLock::lock_block_store(&root)
        .expect("a stale (unlocked) lock file must be reacquired by a new owner");
}

// --- locking must not create the database -------------------------------

/// An absent database is how startup tells a new install from a lost one.
/// Locking it must not create an empty file that would pass that check.
#[test]
fn locking_a_missing_sync_db_does_not_create_it() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("sync-state.sqlite3");
    let _lock = ResourceLock::lock_sync_db(&db).unwrap();
    assert!(!db.exists(), "taking the lock must not create the database file");
}

// --- deterministic order + rollback -------------------------------------

#[test]
fn conflict_on_db_rolls_back_the_block_store_lock() {
    // Owner A holds distinct block store A + DB S.
    let a = tempfile::tempdir().unwrap();
    let shared_db = a.path().join("sync-state.sqlite3");
    let _owner_a = DataResourceLocks::acquire(&a.path().join("blocks"), &shared_db).unwrap();

    // Daemon B has a *distinct* block store but shares A's DB. Acquisition
    // order is block store (succeeds) then DB (conflicts) — B must fail and
    // release the block-store lock it briefly held.
    let b = tempfile::tempdir().unwrap();
    let b_store = b.path().join("blocks");
    let err = DataResourceLocks::acquire(&b_store, &shared_db)
        .expect_err("sharing A's database must make B fail");
    assert!(err.to_string().contains("already in use"), "unexpected error: {err}");

    // Rollback check: B's block-store lock was released on failure, so it is
    // freely acquirable now.
    let _reacquire = ResourceLock::lock_block_store(&b_store)
        .expect("the block-store lock must be rolled back when the DB lock conflicts");
}
