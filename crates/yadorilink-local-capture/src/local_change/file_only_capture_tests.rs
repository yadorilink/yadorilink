#![cfg(test)]
//! A file captured in the file-only mode is hashed, flushed and indexed without a single block
//! going into the store, and a policy that never asks for it changes nothing.
//!
//! What makes the mode safe is not in this file: it is the retention proof (a sync that replaces
//! the version reads it from the file into the store first) and the pin/lease rule of the policy
//! the daemon supplies. These tests pin the capture side: the bytes hashed are the ones a store
//! capture would have stored, the flush happens before the record commits, a file that cannot be
//! flushed falls back to the store, and a name swapped after the read captures nothing.

use std::sync::Arc;

use yadorilink_filesystem_sync::watcher::{FsChangeEvent, FsChangeKind};
use yadorilink_local_storage::{BlockStore, SegmentBlockStore};
use yadorilink_replica_domain::file::FileRecord;

use super::tests::{adopt_root, canonical_root, expect_file_changed};
use super::*;
use crate::ingest::{Ingest, IngestPolicy};
use crate::test_support::TestReplica;

const GROUP: &str = "group-1";
/// Several blocks, so a stored capture visibly differs from a hashed one.
const FILE_LEN: usize = 5_000_000;

struct Fixed(Ingest);
impl IngestPolicy for Fixed {
    fn ingest_for(&self, _: &str, _: &str, _: u64) -> Ingest {
        self.0
    }
}

struct Fixture {
    processor: LocalChangeProcessor,
    state: Arc<TestReplica>,
    store: Arc<SegmentBlockStore>,
    root: std::path::PathBuf,
    _store_dir: tempfile::TempDir,
    _root_dir: tempfile::TempDir,
}

fn fixture(policy: Option<Ingest>) -> Fixture {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let state = Arc::new(TestReplica::open_in_memory().unwrap());
    let root_dir = tempfile::tempdir().unwrap();
    let root = canonical_root(&root_dir);
    adopt_root(&state, GROUP, &root);
    let mut processor = LocalChangeProcessor::new(
        state.clone(),
        store.clone(),
        "device-a".into(),
        Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    );
    if let Some(mode) = policy {
        processor = processor.with_ingest_policy(Arc::new(Fixed(mode)));
    }
    Fixture { processor, state, store, root, _store_dir: store_dir, _root_dir: root_dir }
}

fn payload() -> Vec<u8> {
    (0..FILE_LEN).map(|i| (i.wrapping_mul(31) % 251) as u8).collect()
}

async fn capture(f: &Fixture, name: &str) -> LocalChangeOutcome {
    f.processor
        .process_event(
            GROUP,
            &f.root,
            &FsChangeEvent { path: f.root.join(name), kind: FsChangeKind::CreatedOrModified },
        )
        .await
        .unwrap()
}

fn hex_hashes(record: &FileRecord) -> Vec<String> {
    record.blocks.iter().map(|b| hex::encode(&b.hash)).collect()
}

fn blocks_in_store(f: &Fixture, record: &FileRecord) -> usize {
    f.store.present_blocks(&hex_hashes(record)).unwrap().into_iter().filter(|held| *held).count()
}

fn blocks_with_provenance(f: &Fixture, record: &FileRecord) -> usize {
    let hashes: Vec<Vec<u8>> = record.blocks.iter().map(|b| b.hash.clone()).collect();
    f.state.group_has_block_provenance_batch(GROUP, &hashes).unwrap().len()
}

/// A processor given no policy keeps every file in the store, with the group's provenance, as
/// before the mode existed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_policy_every_file_goes_into_the_store() {
    let f = fixture(None);
    std::fs::write(f.root.join("a.bin"), payload()).unwrap();

    let record = expect_file_changed(capture(&f, "a.bin").await);

    assert!(record.blocks.len() > 1);
    assert_eq!(blocks_in_store(&f, &record), record.blocks.len());
    assert_eq!(blocks_with_provenance(&f, &record), record.blocks.len());
}

/// A file-only capture indexes exactly the blocks a store capture of the same bytes does, puts none
/// of them into the store and records no provenance for them, and flushes the file and its new name.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_only_capture_hashes_without_storing_and_flushes_first() {
    let stored = fixture(Some(Ingest::Store));
    std::fs::write(stored.root.join("a.bin"), payload()).unwrap();
    let expected = expect_file_changed(capture(&stored, "a.bin").await);

    let f = fixture(Some(Ingest::FileOnly));
    std::fs::write(f.root.join("a.bin"), payload()).unwrap();
    let before = yadorilink_fs_platform::flush::counts();
    let record = expect_file_changed(capture(&f, "a.bin").await);
    let after = yadorilink_fs_platform::flush::counts();

    assert_eq!(record.blocks, expected.blocks, "the same bytes hash to the same block list");
    assert_eq!(record.size, expected.size);
    assert_eq!(blocks_in_store(&f, &record), 0, "no block was put into the store");
    assert_eq!(blocks_with_provenance(&f, &record), 0, "no provenance for blocks it never held");
    assert!(after.file_flushes > before.file_flushes, "the file was flushed before the commit");
    assert!(after.directory_syncs > before.directory_syncs, "its directory entry was flushed");
    assert!(f.state.get_file(GROUP, "a.bin").unwrap().is_some(), "the record is committed");
}

/// The reconciliation scan takes the same mode for a file it finds: the pooled staging is not
/// used, nothing is put into the store, and the record names the file.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_scan_captures_a_file_only_file_without_staging_its_blocks() {
    let f = fixture(Some(Ingest::FileOnly));
    std::fs::write(f.root.join("scanned.bin"), payload()).unwrap();

    let records = f.processor.reconcile_added_files(GROUP, &f.root).unwrap();

    let record = records.iter().find(|r| r.path == "scanned.bin").expect("the scan found the file");
    assert_eq!(blocks_in_store(&f, record), 0);
    assert_eq!(blocks_with_provenance(&f, record), 0);
    assert!(f.state.get_file(GROUP, "scanned.bin").unwrap().is_some());
}

/// Where a file's directory entry cannot be flushed (Windows), the policy's file-only choice is
/// not honoured: the file goes into the store, with provenance, and the record is the same.
#[cfg(not(unix))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_directory_flush_a_file_only_policy_stores_the_file() {
    let f = fixture(Some(Ingest::FileOnly));
    std::fs::write(f.root.join("a.bin"), payload()).unwrap();

    let record = expect_file_changed(capture(&f, "a.bin").await);

    assert_eq!(blocks_in_store(&f, &record), record.blocks.len());
    assert_eq!(blocks_with_provenance(&f, &record), record.blocks.len());
}

/// A file that cannot be flushed is not captured file-only: its blocks go into the store, with
/// provenance, and the record is the same.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_that_cannot_be_flushed_falls_back_to_the_store() {
    let f = fixture(Some(Ingest::FileOnly));
    let path = f.root.join("locked.bin");
    std::fs::write(&path, payload()).unwrap();
    crate::local_change::arm_flush_failure_hook(path.clone());

    let record = expect_file_changed(capture(&f, "locked.bin").await);
    crate::local_change::disarm_flush_failure_hook(&path);

    assert_eq!(blocks_in_store(&f, &record), record.blocks.len(), "the store holds the version");
    assert_eq!(blocks_with_provenance(&f, &record), record.blocks.len());
}

/// The name is swapped for another file after the read: nothing is captured from this pass, and
/// nothing about either file is indexed.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_name_swapped_after_the_read_captures_nothing() {
    let f = fixture(Some(Ingest::FileOnly));
    let path = f.root.join("swapped.bin");
    std::fs::write(&path, payload()).unwrap();
    let elsewhere = f.root.join("replacement.tmp");
    std::fs::write(&elsewhere, b"another file, put in place by a rename").unwrap();
    let (swap_to, swap_from) = (path.clone(), elsewhere.clone());
    crate::local_change::arm_content_read_race_hook(path.clone(), move || {
        std::fs::rename(&swap_from, &swap_to).unwrap();
        false
    });

    let outcome = capture(&f, "swapped.bin").await;
    crate::local_change::disarm_content_read_race_hook(&path);

    assert_eq!(outcome, LocalChangeOutcome::RetryLater, "left for a later pass");
    assert!(f.state.get_file(GROUP, "swapped.bin").unwrap().is_none(), "nothing indexed");
}

/// The file is written after it was read: the barrier does not turn a changed file into a record.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_written_after_the_read_is_not_captured_from_that_pass() {
    let f = fixture(Some(Ingest::FileOnly));
    let path = f.root.join("growing.bin");
    std::fs::write(&path, payload()).unwrap();
    let appended = path.clone();
    crate::local_change::arm_content_read_race_hook(path.clone(), move || {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new().append(true).open(&appended).unwrap();
        file.write_all(b"more bytes after the read").unwrap();
        false
    });

    let outcome = capture(&f, "growing.bin").await;
    crate::local_change::disarm_content_read_race_hook(&path);

    assert_eq!(outcome, LocalChangeOutcome::RetryLater);
    assert!(f.state.get_file(GROUP, "growing.bin").unwrap().is_none());
}

/// The barrier flushes the file it read, not whatever now stands under the name: a rename over the
/// name after the read is reported as a moved name, whatever the change times say.
#[cfg(unix)]
#[test]
fn the_barrier_notices_a_name_that_now_leads_to_another_file() {
    use super::record_builder::{flush_before_commit, Barrier};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let path = root.join("name.bin");
    std::fs::write(&path, b"the file that was read").unwrap();
    let read = std::fs::File::open(&path).unwrap();
    let read_metadata = read.metadata().unwrap();
    assert_eq!(flush_before_commit(&root, &path, &read_metadata), Barrier::Flushed);

    let other = root.join("other.tmp");
    std::fs::write(&other, b"another file").unwrap();
    std::fs::rename(&other, &path).unwrap();

    assert_eq!(flush_before_commit(&root, &path, &read_metadata), Barrier::NameMoved);
}

/// Every directory entry between the file and the folder's root is flushed, so a directory the user
/// has just made cannot disappear in a crash after the record that names its file has committed.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_barrier_flushes_the_directories_down_to_the_root() {
    let f = fixture(Some(Ingest::FileOnly));
    std::fs::create_dir_all(f.root.join("a/b")).unwrap();
    std::fs::write(f.root.join("a/b/deep.bin"), payload()).unwrap();
    let before = yadorilink_fs_platform::flush::counts();

    expect_file_changed(capture(&f, "a/b/deep.bin").await);
    let after = yadorilink_fs_platform::flush::counts();

    assert!(
        after.directory_syncs >= before.directory_syncs + 3,
        "a/b, a and the root were flushed: {before:?} -> {after:?}"
    );
}

/// A block limit lowered for one path is that path's alone: tests run in parallel in one binary,
/// and another file's capture must not be refused because of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_limit_set_for_one_path_does_not_refuse_another_file() {
    let f = fixture(Some(Ingest::FileOnly));
    std::fs::write(f.root.join("other.bin"), payload()).unwrap();
    super::record_builder::override_syncable_block_limit(Some((GROUP, "some-other-path.bin", 1)));
    let outcome = capture(&f, "other.bin").await;
    super::record_builder::override_syncable_block_limit(None);
    expect_file_changed(outcome);
}
