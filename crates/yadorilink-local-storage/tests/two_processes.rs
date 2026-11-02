//! Two processes over one data area: the second is refused while the first holds it, the
//! first writer is untouched by the attempt, and after `kill -9` of the holder the next open
//! recovers cleanly with every acknowledged block intact.
//!
//! The test binary re-runs itself as the holder (`HOLDER_ENV` names the data area), so the
//! exclusion is proven between real processes, not between two handles of one.
#![cfg(unix)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use yadorilink_local_storage::resource_lock::DataResourceLocks;
use yadorilink_local_storage::{BlockStore, SegmentBlockStore};

const HOLDER_ENV: &str = "YADORILINK_TWO_PROCESSES_HOLDER_DIR";
const MINIMUM_ACKS: usize = 5;

fn paths(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    (dir.join("blocks"), dir.join("data").join("sync.sqlite3"), dir.join("acked"))
}

fn acked(path: &Path) -> Vec<(u64, String)> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    // A line torn by the kill is not an acknowledgement.
    text.lines()
        .filter_map(|line| {
            let (i, hash) = line.split_once(' ')?;
            if hash.len() != 64 {
                return None;
            }
            Some((i.parse().ok()?, hash.to_owned()))
        })
        .collect()
}

fn payload(i: u64) -> Vec<u8> {
    format!("two-process block {i} ").repeat(2048).into_bytes()
}

/// The holder: takes the locks, opens the store and writes blocks one after another, recording
/// each hash only after the store acknowledged it. Does nothing unless started by the test.
#[test]
fn holder_process() {
    let Some(dir) = std::env::var_os(HOLDER_ENV).map(PathBuf::from) else { return };
    let (blocks, db, ack_path) = paths(&dir);
    std::fs::create_dir_all(db.parent().unwrap()).unwrap();
    let _locks = DataResourceLocks::acquire(&blocks, &db).expect("the holder takes the locks");
    let store = SegmentBlockStore::open_process_locked(&blocks).expect("the holder opens");
    let mut ack = std::fs::OpenOptions::new().create(true).append(true).open(&ack_path).unwrap();
    for i in 0..u64::MAX {
        let hash = store.put(&payload(i)).expect("the holder's write is never disturbed");
        writeln!(ack, "{i} {hash}").unwrap();
        ack.sync_all().unwrap();
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn spawn_holder(dir: &Path) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "holder_process", "--nocapture", "--test-threads=1"])
        .env(HOLDER_ENV, dir)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

fn wait_for_acks(path: &Path, at_least: usize, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while acked(path).len() < at_least {
        assert!(child.try_wait().unwrap().is_none(), "the holder exited early");
        assert!(Instant::now() < deadline, "the holder wrote nothing in time");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_second_process_is_refused_and_a_killed_holder_leaves_a_clean_recovery() {
    if std::env::var_os(HOLDER_ENV).is_some() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let (blocks, db, ack_path) = paths(dir.path());
    std::fs::create_dir_all(db.parent().unwrap()).unwrap();

    let mut holder = spawn_holder(dir.path());
    wait_for_acks(&ack_path, MINIMUM_ACKS, &mut holder);

    // The attempt: refused, and it is only the lock that refuses (nothing is opened or recovered).
    for _ in 0..20 {
        let refused = DataResourceLocks::acquire(&blocks, &db).expect_err("the area is held");
        assert!(refused.to_string().contains("already in use"), "{refused}");
    }
    let after_attempts = acked(&ack_path).len();
    wait_for_acks(&ack_path, after_attempts + MINIMUM_ACKS, &mut holder);
    assert!(holder.try_wait().unwrap().is_none(), "the holder's writes survived the attempts");

    // kill -9: no unwinding, no release.
    holder.kill().unwrap();
    holder.wait().unwrap();

    let _locks = DataResourceLocks::acquire(&blocks, &db).expect("the kernel released the locks");
    let store = SegmentBlockStore::open_process_locked(&blocks).expect("recovery is clean");
    let acknowledged = acked(&ack_path);
    assert!(acknowledged.len() >= after_attempts + MINIMUM_ACKS);
    for (i, hash) in &acknowledged {
        let bytes = store.get(hash).unwrap_or_else(|e| panic!("acknowledged block {i} lost: {e}"));
        assert_eq!(bytes, payload(*i), "acknowledged block {i} changed");
    }
    let fresh = store.put(b"written after the takeover").unwrap();
    drop(store);
    let reopened = SegmentBlockStore::open_process_locked(&blocks).expect("a second recovery");
    assert_eq!(reopened.get(&fresh).unwrap(), b"written after the takeover");
}
