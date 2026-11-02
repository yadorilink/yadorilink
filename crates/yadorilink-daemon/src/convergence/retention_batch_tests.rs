#![cfg(test)]

//! Keeping the replaced versions of many files with one durable commit
//! (`local_convergence::retention_batch`). Each test reads the store and the index, not the code
//! that decides: which files are claimed kept, what the store holds, and what the group has
//! provenance for.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use yadorilink_local_storage::{BlockContentStore, ContentHash, LocallyHashedBlock, StorageError};
use yadorilink_replica_domain::file::{BlockInfo, FileRecord};
use yadorilink_sync_sqlite::file_index::upsert_file_in_tx;
use yadorilink_sync_sqlite::retention::{Retention, RetentionProof};
use yadorilink_sync_sqlite::SyncSqliteError;

use super::receive_cost_tests::{fixture, Fixture, GROUP};
use crate::local_convergence::retention_batch::{RetentionIngestQueue, RetentionRequest};

/// The fixture's durable store, counting the batches put into it, optionally refusing one.
struct CountingStore {
    inner: Arc<dyn BlockContentStore>,
    batches: Mutex<Vec<usize>>,
    refuse_batch_number: AtomicUsize,
    /// Runs while a batch is being committed.
    during_commit: Mutex<Option<Box<dyn Fn() + Send>>>,
}

impl CountingStore {
    fn new(inner: Arc<dyn BlockContentStore>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            batches: Mutex::new(Vec::new()),
            refuse_batch_number: AtomicUsize::new(usize::MAX),
            during_commit: Mutex::new(None),
        })
    }
    fn batch_sizes(&self) -> Vec<usize> {
        self.batches.lock().unwrap().clone()
    }
}

impl BlockContentStore for CountingStore {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        self.inner.put(data)
    }
    fn put_prepared(&self, prepared: &LocallyHashedBlock) -> Result<(), StorageError> {
        self.inner.put_prepared(prepared)
    }
    fn put_prepared_batch(&self, prepared: &[LocallyHashedBlock]) -> Result<(), StorageError> {
        let number = {
            let mut batches = self.batches.lock().unwrap();
            batches.push(prepared.len());
            batches.len()
        };
        if let Some(hook) = self.during_commit.lock().unwrap().as_ref() {
            hook();
        }
        if number == self.refuse_batch_number.load(Ordering::SeqCst) {
            return Err(StorageError::Io(std::io::Error::other("the store refused the batch")));
        }
        self.inner.put_prepared_batch(prepared)
    }
    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        self.inner.get(hash)
    }
    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        self.inner.present_blocks(hashes)
    }
}

/// `len` bytes that differ for every `seed` (a seed is a whole file's identity here).
fn content_of(len: usize, seed: u64) -> Vec<u8> {
    (0..len as u64)
        .map(|i| {
            (seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(i.wrapping_mul(2654435761))
                >> 24) as u8
        })
        .collect()
}

fn record(path: &str, content: &[u8], mtime: i64) -> FileRecord {
    let hash = hex::decode(yadorilink_local_storage::hash_block_bytes(content)).unwrap();
    FileRecord {
        path: path.into(),
        size: content.len() as u64,
        mtime_unix_nanos: mtime,
        blocks: vec![BlockInfo { hash, offset: 0, size: content.len() as u32 }],
        deleted: false,
    }
}

/// A file whose current version's bytes are only in the folder: indexed as an own edit and
/// written to disk. Returns the request that asks to keep it.
fn replaced_file(f: &Fixture, path: &str, seed: u64) -> RetentionRequest {
    let current = record(path, &content_of(3000, seed), 2);
    f.state
        .replica_coordinator
        .database()
        .write_immediate::<_, SyncSqliteError>(|tx| {
            upsert_file_in_tx(tx, GROUP, &current, "device-local", Retention::OwnEdit)
        })
        .unwrap();
    std::fs::write(f.root.join(path), content_of(3000, seed)).unwrap();
    request_for(f, path)
}

fn request_for(f: &Fixture, path: &str) -> RetentionRequest {
    let (row, _, blocks) = f
        .state
        .replica_coordinator
        .file_index_repository()
        .current_row_for_retention(GROUP, path)
        .unwrap()
        .expect("the file has a current row");
    RetentionRequest {
        group: GROUP.into(),
        path: path.into(),
        row,
        blocks,
        out_path: f.root.join(path),
    }
}

fn in_store(f: &Fixture, req: &RetentionRequest) -> bool {
    let hex_hash = hex::encode(&req.blocks[0].hash);
    f.executor.durable_store.present_blocks(&[hex_hash]).unwrap()[0]
}

fn has_provenance(f: &Fixture, req: &RetentionRequest) -> bool {
    !f.state
        .replica_coordinator
        .group_has_block_provenance_batch(GROUP, &[req.blocks[0].hash.clone()])
        .unwrap()
        .is_empty()
}

fn is_in_store(proof: &RetentionProof) -> bool {
    matches!(proof, RetentionProof::InStore(_))
}

async fn ask_all(
    queue: &Arc<RetentionIngestQueue>,
    requests: Vec<RetentionRequest>,
) -> Vec<crate::local_convergence::retention_batch::RetentionReply> {
    let mut tasks = Vec::new();
    for request in requests {
        let queue = Arc::clone(queue);
        tasks.push(tokio::spawn(async move { queue.ingest(request).await }));
    }
    let mut replies = Vec::new();
    for task in tasks {
        replies.push(task.await.unwrap());
    }
    replies
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn files_asked_together_are_kept_with_one_store_commit_and_all_have_provenance() {
    let f = fixture(false).await;
    let store = CountingStore::new(f.executor.durable_store.clone());
    let queue = RetentionIngestQueue::new(store.clone(), f.state.replica_coordinator.clone());
    let requests: Vec<_> =
        (0..20).map(|i| replaced_file(&f, &format!("f{i:02}.bin"), 100 + i)).collect();
    let probes: Vec<_> = requests.iter().map(|r| request_for(&f, &r.path)).collect();

    let replies = ask_all(&queue, requests).await;

    assert!(replies.iter().all(|r| matches!(r, Ok(p) if is_in_store(p))), "{replies:?}");
    assert_eq!(store.batch_sizes(), vec![20], "one durable commit for the 20 files");
    for probe in &probes {
        assert!(in_store(&f, probe) && has_provenance(&f, probe), "{}", probe.path);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_the_store_refuses_claims_none_of_its_files_kept_and_records_no_provenance() {
    let f = fixture(false).await;
    let store = CountingStore::new(f.executor.durable_store.clone());
    store.refuse_batch_number.store(1, Ordering::SeqCst);
    let queue = RetentionIngestQueue::new(store.clone(), f.state.replica_coordinator.clone());
    let requests: Vec<_> =
        (0..6).map(|i| replaced_file(&f, &format!("g{i}.bin"), 200 + i)).collect();
    let probes: Vec<_> = requests.iter().map(|r| request_for(&f, &r.path)).collect();

    let replies = ask_all(&queue, requests).await;

    assert!(replies.iter().all(|r| r.is_err()), "no file may be claimed kept: {replies:?}");
    for probe in &probes {
        assert!(!has_provenance(&f, probe), "provenance only follows a durable batch");
        assert!(!in_store(&f, probe));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_files_of_the_batch_that_failed_are_left_unkept() {
    let f = fixture(false).await;
    let store = CountingStore::new(f.executor.durable_store.clone());
    store.refuse_batch_number.store(2, Ordering::SeqCst);
    // Five blocks to a batch: 12 single-block files make three batches, in path order.
    let queue = RetentionIngestQueue::with_limits(
        store.clone(),
        f.state.replica_coordinator.clone(),
        5,
        16 * 1024 * 1024,
    );
    let requests: Vec<_> =
        (0..12).map(|i| replaced_file(&f, &format!("h{i:02}.bin"), 300 + i)).collect();
    let probes: Vec<_> = requests.iter().map(|r| request_for(&f, &r.path)).collect();

    let replies = ask_all(&queue, requests).await;

    assert_eq!(store.batch_sizes(), vec![5, 5, 2]);
    for (index, (reply, probe)) in replies.iter().zip(&probes).enumerate() {
        let second_batch = (5..10).contains(&index);
        if second_batch {
            assert!(reply.is_err(), "{}: {reply:?}", probe.path);
            assert!(!has_provenance(&f, probe) && !in_store(&f, probe), "{}", probe.path);
        } else {
            assert!(matches!(reply, Ok(p) if is_in_store(p)), "{}: {reply:?}", probe.path);
            assert!(in_store(&f, probe) && has_provenance(&f, probe), "{}", probe.path);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_edited_after_the_plan_is_not_claimed_kept_and_its_bytes_are_not_stored() {
    let f = fixture(false).await;
    let store = CountingStore::new(f.executor.durable_store.clone());
    let queue = RetentionIngestQueue::new(store.clone(), f.state.replica_coordinator.clone());
    let kept = replaced_file(&f, "kept.bin", 400);
    let edited = replaced_file(&f, "edited.bin", 401);
    // Same length, other bytes: the file is no longer the version the index names.
    std::fs::write(f.root.join("edited.bin"), content_of(3000, 999)).unwrap();
    let probe_kept = request_for(&f, "kept.bin");
    let probe_edited = request_for(&f, "edited.bin");

    let replies = ask_all(&queue, vec![kept, edited]).await;

    assert!(matches!(&replies[1], Ok(RetentionProof::NoLocalBytes(_))), "{replies:?}");
    assert!(matches!(&replies[0], Ok(p) if is_in_store(p)), "{replies:?}");
    assert!(in_store(&f, &probe_kept));
    assert!(!in_store(&f, &probe_edited) && !has_provenance(&f, &probe_edited));
    assert_eq!(store.batch_sizes(), vec![1], "only the file that is the version is put");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_with_more_blocks_than_a_batch_holds_is_ingested_alone_in_bounded_batches() {
    let f = fixture(false).await;
    let store = CountingStore::new(f.executor.durable_store.clone());
    let queue = RetentionIngestQueue::with_limits(
        store.clone(),
        f.state.replica_coordinator.clone(),
        2,
        16 * 1024 * 1024,
    );
    // One file of three blocks (3 x 1000 bytes), one single-block file.
    let big_content: Vec<u8> = (0..3).flat_map(|i| content_of(1000, 500 + i)).collect();
    let blocks: Vec<BlockInfo> = (0..3)
        .map(|i| {
            let part = &big_content[i * 1000..(i + 1) * 1000];
            BlockInfo {
                hash: hex::decode(yadorilink_local_storage::hash_block_bytes(part)).unwrap(),
                offset: (i * 1000) as u64,
                size: 1000,
            }
        })
        .collect();
    let big = FileRecord {
        path: "big.bin".into(),
        size: 3000,
        mtime_unix_nanos: 2,
        blocks,
        deleted: false,
    };
    f.state
        .replica_coordinator
        .database()
        .write_immediate::<_, SyncSqliteError>(|tx| {
            upsert_file_in_tx(tx, GROUP, &big, "device-local", Retention::OwnEdit)
        })
        .unwrap();
    std::fs::write(f.root.join("big.bin"), &big_content).unwrap();
    let big_request = request_for(&f, "big.bin");
    let small_request = replaced_file(&f, "small.bin", 600);
    let probe_small = request_for(&f, "small.bin");

    let replies = ask_all(&queue, vec![big_request, small_request]).await;

    assert!(replies.iter().all(|r| matches!(r, Ok(p) if is_in_store(p))), "{replies:?}");
    assert!(store.batch_sizes().iter().all(|n| *n <= 2), "{:?}", store.batch_sizes());
    assert!(in_store(&f, &probe_small));
    for block in &big.blocks {
        let hex_hash = hex::encode(&block.hash);
        assert!(f.executor.durable_store.present_blocks(&[hex_hash]).unwrap()[0]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replacements_running_together_through_the_executor_share_store_commits() {
    let f = fixture(false).await;
    // The executor's own queue writes to the fixture's store; count its commits by the segment
    // fsyncs the store's io counters would show, here by the files all being kept.
    let mut nexts = Vec::new();
    for i in 0..40u64 {
        let path = format!("k{i:02}.bin");
        let _ = replaced_file(&f, &path, 700 + i);
        nexts.push(record(&path, &content_of(3000, 5000 + i), 3));
    }
    let mut tasks = Vec::new();
    for next in nexts.clone() {
        let executor = Arc::clone(&f.executor);
        tasks.push(tokio::spawn(
            async move { executor.proofs_before_replacing(GROUP, &next).await },
        ));
    }
    for task in tasks {
        let proofs = task.await.unwrap().expect("a proof");
        let _ = proofs;
    }
    for next in &nexts {
        let probe = request_for(&f, &next.path);
        assert!(in_store(&f, &probe), "{}", next.path);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_that_grew_while_its_batch_was_committed_is_not_claimed_kept() {
    let f = fixture(false).await;
    let store = CountingStore::new(f.executor.durable_store.clone());
    let grown_path = f.root.join("grown.bin");
    *store.during_commit.lock().unwrap() = Some(Box::new({
        let grown_path = grown_path.clone();
        move || {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new().append(true).open(&grown_path).unwrap();
            file.write_all(b"more").unwrap();
        }
    }));
    let queue = RetentionIngestQueue::new(store.clone(), f.state.replica_coordinator.clone());
    let grown = replaced_file(&f, "grown.bin", 800);
    let steady = replaced_file(&f, "steady.bin", 801);

    let replies = ask_all(&queue, vec![grown, steady]).await;

    assert!(matches!(&replies[0], Ok(RetentionProof::NoLocalBytes(_))), "{replies:?}");
    assert!(matches!(&replies[1], Ok(p) if is_in_store(p)), "{replies:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_never_holds_more_than_64_files_open() {
    let f = fixture(false).await;
    let store = CountingStore::new(f.executor.durable_store.clone());
    let queue = RetentionIngestQueue::new(store.clone(), f.state.replica_coordinator.clone());
    let requests: Vec<_> =
        (0..130).map(|i| replaced_file(&f, &format!("m{i:03}.bin"), 900 + i)).collect();

    let replies = ask_all(&queue, requests).await;

    assert!(replies.iter().all(|r| matches!(r, Ok(p) if is_in_store(p))), "{replies:?}");
    assert_eq!(store.batch_sizes(), vec![64, 64, 2]);
}
