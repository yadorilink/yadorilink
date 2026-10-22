//! Sync-root lock behaviour that needs a genuine second OS process.
//!
//! These live in their own test binary on purpose. A process that holds a
//! sync-root lock (an `flock` on an open file description) and then spawns
//! a child lets that child briefly share the description between `fork`
//! and `exec` -- `O_CLOEXEC` only closes it at `exec`. If a spawning test
//! ran in the same process as the lock-releasing unit tests, a concurrent
//! spawn could make their re-acquire fail with "already in use". Keeping
//! every spawning test here, serialized by `SPAWN_GUARD`, means no
//! lock-holding test shares a process with a concurrent spawn.

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use yadorilink_root_authority::sync_root_lock::SyncRootLock;

static SPAWN_GUARD: Mutex<()> = Mutex::new(());

const HOLD_ENV: &str = "YADORILINK_TEST_HOLD_SYNC_ROOT_LOCK";
const ROOT_ENV: &str = "YADORILINK_TEST_SYNC_ROOT_LOCK_PATH";

/// Mechanism pin: a child between `fork` and `exec` shares the
/// parent's lock description, so releasing in the parent does not free the
/// root until the child has exec'd. This is why spawning tests must not
/// share a process with lock-releasing tests.
#[cfg(unix)]
#[test]
fn a_forked_child_shares_the_lock_until_it_execs() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;

    let _serial = SPAWN_GUARD.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();

    // Two handshakes pin the child inside its fork-to-exec window: it
    // reports "forked" on one pair, then waits for "go" on the other.
    let (mut forked_rx, forked_tx) = UnixStream::pair().unwrap();
    let (go_rx, mut go_tx) = UnixStream::pair().unwrap();
    go_rx.set_read_timeout(Some(Duration::from_secs(30))).unwrap();

    let owner = SyncRootLock::acquire(&root).unwrap();
    let mut command = std::process::Command::new("/bin/sh");
    command.args(["-c", "exit 0"]);
    // SAFETY: the hook only issues `write` and `read` on already-open
    // sockets, both async-signal-safe, and allocates nothing.
    unsafe {
        command.pre_exec(move || {
            let _ = (&forked_tx).write_all(b"f");
            let _ = (&go_rx).read(&mut [0u8; 1]);
            Ok(())
        });
    }
    // `spawn` returns only after the child has exec'd, so it runs on its own
    // thread while this one observes the fork-to-exec window.
    let spawner = std::thread::spawn(move || command.spawn().expect("spawning the child"));
    forked_rx.read_exact(&mut [0u8; 1]).expect("child reports it has forked");
    drop(owner);

    let during = SyncRootLock::acquire(&root);
    assert!(during.is_err(), "child still shares the description before exec");
    drop(during);

    go_tx.write_all(b"g").unwrap();
    spawner.join().unwrap().wait().unwrap();
    SyncRootLock::acquire(&root).expect("free again once the child has exec'd and exited");
}

/// THE crash-recovery case, driven with a genuine second OS process, not
/// a same-process `drop`: a real child process acquires the lock and
/// then is `SIGKILL`ed -- no graceful shutdown, no `Drop`. A new
/// acquisition afterward must still succeed, because the reclaim signal is
/// entirely OS-level, never a PID or stale-file check.
#[test]
fn a_lock_held_by_a_process_that_was_killed_is_reclaimable() {
    // Re-entry: under `HOLD_ENV` this function is the *child*. It takes the
    // lock and blocks so the parent can kill it while it holds the lock.
    if let Ok(root) = std::env::var(ROOT_ENV) {
        if std::env::var(HOLD_ENV).is_ok() {
            // The parent detects "the child holds the lock" by probing the same lock, so its
            // probe can briefly hold it. Retry (bounded) instead of failing on that window.
            let deadline = Instant::now() + Duration::from_secs(30);
            let _lock = loop {
                match SyncRootLock::acquire(Path::new(&root)) {
                    Ok(lock) => break lock,
                    Err(error) => {
                        assert!(
                            Instant::now() < deadline,
                            "child: never acquired the lock within the deadline: {error}"
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
            };
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        }
    }

    let _serial = SPAWN_GUARD.lock().unwrap_or_else(|p| p.into_inner());
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();

    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("a_lock_held_by_a_process_that_was_killed_is_reclaimable")
        .arg("--exact")
        .arg("--nocapture")
        .env(HOLD_ENV, "1")
        .env(ROOT_ENV, &root)
        .spawn()
        .expect("spawning the child holder process");

    // Poll for the child to have actually taken the lock; its startup time
    // is not bounded tightly enough for a fixed delay.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if SyncRootLock::acquire(&root).is_err() {
            break;
        }
        assert!(Instant::now() < deadline, "child never took the lock within the deadline");
        std::thread::sleep(Duration::from_millis(20));
    }

    child.kill().expect("killing the child holder");
    child.wait().expect("reaping the killed child");

    let _reacquired = SyncRootLock::acquire(&root).expect(
        "a lock left by a killed process must be reclaimable -- the daemon must not be \
         permanently unstartable after any prior crash",
    );
}
