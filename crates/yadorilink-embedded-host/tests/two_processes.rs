//! The host's start over a data area another process holds: refused, without touching what that
//! process staged; and after `kill -9` of the holder, the next start recovers cleanly.
//!
//! The test binary re-runs itself as the holder (`HOLDER_ENV` names the data area), so the
//! exclusion is proven between real processes. The holder stages bytes past its committed end
//! (what a writer killed mid-write leaves) and then idles, so the contender's attempt
//! deterministically happens while those bytes are on disk.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use yadorilink_embedded_host::{EmbeddedHost, HostError, HostState};
use yadorilink_local_storage::resource_lock::DataResourceLocks;
use yadorilink_local_storage::{BlockStore, SegmentBlockStore};

mod support;
use support::{area, serialized};

const HOLDER_ENV: &str = "YADORILINK_HOST_TWO_PROCESSES_DIR";
const STAGED: usize = 64;

fn segment_of(blocks: &Path) -> PathBuf {
    std::fs::read_dir(blocks.join("segments"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "seg"))
        .expect("a segment")
}

/// The holder. Does nothing unless started by the test below.
#[test]
fn holder_process() {
    let Some(dir) = std::env::var_os(HOLDER_ENV).map(PathBuf::from) else { return };
    let blocks = dir.join("blocks");
    let db = dir.join("data/sync.sqlite3");
    let _locks = DataResourceLocks::acquire(&blocks, &db).expect("the holder takes the locks");
    let store = SegmentBlockStore::open_process_locked(&blocks).expect("the holder opens");
    store.put(b"a committed block").unwrap();
    let segment = segment_of(&blocks);
    let mut bytes = std::fs::read(&segment).unwrap();
    bytes.extend_from_slice(&[7u8; STAGED]);
    std::fs::write(&segment, &bytes).unwrap();
    std::fs::write(dir.join("ready"), b"").unwrap();
    std::thread::sleep(Duration::from_secs(120));
    drop(store);
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

#[test]
fn start_over_a_held_area_is_refused_untouched_and_recovers_after_kill() {
    if std::env::var_os(HOLDER_ENV).is_some() {
        return;
    }
    let _serial = serialized();
    let area = area();
    let root = area._dir.path().to_path_buf();
    // An engine has run over the area before, so its database exists: a missing database over
    // surviving blocks is a different, separately tested refusal.
    let host = EmbeddedHost::new(area.config.clone());
    host.start().unwrap();
    host.stop().unwrap();
    let mut holder = spawn_holder(&root);
    let deadline = Instant::now() + Duration::from_secs(60);
    while !root.join("ready").exists() {
        assert!(holder.try_wait().unwrap().is_none(), "the holder exited early");
        assert!(Instant::now() < deadline, "the holder never staged its bytes");
        std::thread::sleep(Duration::from_millis(20));
    }
    let segment = segment_of(&area.config.block_store_root);
    let staged = std::fs::read(&segment).unwrap();

    for _ in 0..3 {
        match host.start() {
            Err(HostError::Start(refusal)) => {
                assert!(refusal.to_string().contains("already in use"), "{refusal}");
            }
            other => panic!("the held area must refuse the start: {:?}", other.err()),
        }
        assert_eq!(host.state(), HostState::Stopped);
    }
    assert_eq!(std::fs::read(&segment).unwrap(), staged, "the holder's staged bytes were touched");

    holder.kill().unwrap();
    holder.wait().unwrap();

    host.start().expect("the kernel released the locks; the start recovers");
    host.stop().unwrap();
    let recovered = std::fs::read(&segment).unwrap();
    assert_eq!(recovered.len(), staged.len() - STAGED, "recovery cut exactly the staged tail");
    assert_eq!(recovered[..], staged[..recovered.len()], "the committed bytes are intact");
    let residue: Vec<_> = std::fs::read_dir(area.config.block_store_root.join("segments"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains("yadorilink-tmp"))
        .collect();
    assert!(residue.is_empty(), "temporary files left behind: {residue:?}");
}
