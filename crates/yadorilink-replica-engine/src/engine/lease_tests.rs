#![cfg(test)]

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{BlockHash, FolderGroupId, SyncPath};
use yadorilink_replica_domain::session_state::RootSetSummary;

use super::*;
use crate::error::ReplicaEngineError;
use crate::ports::{CustodyLeasePort, DurabilityEvidencePort, DurabilityRoot};

const GROUP: &str = "g";
const PATH: &str = "a.bin";
const REQUESTER: &str = "ondemand";
const TOKEN: [u8; 16] = [5; 16];

fn version() -> FileVersion {
    FileVersion::new(
        vec![VersionBlock { hash: BlockHash(vec![5; 32]), size: 4 }],
        4,
        FileMeta {
            mtime_unix_nanos: 0,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

struct Evidence {
    current: FileVersion,
    blocks_verify: AtomicBool,
}

impl DurabilityEvidencePort for Evidence {
    fn retention_policy(
        &self,
        _: &FolderGroupId,
    ) -> Result<Option<ReplicaRetentionPolicy>, ReplicaEngineError> {
        Ok(Some(ReplicaRetentionPolicy::Eager))
    }
    fn current_root(
        &self,
        _: &FolderGroupId,
        _: &SyncPath,
    ) -> Result<Option<DurabilityRoot>, ReplicaEngineError> {
        Ok(Some(DurabilityRoot { version: self.current.clone(), deleted: false }))
    }
    fn retained_roots(
        &self,
        _: &FolderGroupId,
        _: &SyncPath,
    ) -> Result<Vec<DurabilityRoot>, ReplicaEngineError> {
        Ok(Vec::new())
    }
    fn has_block_provenance(
        &self,
        _: &FolderGroupId,
        _: &BlockHash,
    ) -> Result<bool, ReplicaEngineError> {
        Ok(true)
    }
    fn verify_block(&self, _: &BlockHash) -> Result<(), ReplicaEngineError> {
        if self.blocks_verify.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(ReplicaEngineError::Storage("corrupt".into()))
        }
    }
    fn root_set_summary(&self, _: &FolderGroupId) -> Result<RootSetSummary, ReplicaEngineError> {
        Err(ReplicaEngineError::Storage("unused".into()))
    }
}

type LeaseKey = (String, String, String, [u8; 32]);

#[derive(Default)]
struct Leases {
    held: Mutex<HashSet<LeaseKey>>,
    fail_commit: AtomicBool,
    refuse: AtomicBool,
    guards: AtomicUsize,
}

struct Guard<'a>(&'a AtomicUsize);

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl CustodyLeasePort for Leases {
    fn begin_reference_write(&self) -> Box<dyn Send + '_> {
        self.guards.fetch_add(1, Ordering::SeqCst);
        Box::new(Guard(&self.guards))
    }
    fn acquire(&self, request: &CustodyLeaseRequest) -> Result<bool, ReplicaEngineError> {
        if self.fail_commit.load(Ordering::SeqCst) {
            return Err(ReplicaEngineError::Storage("disk full".into()));
        }
        if self.refuse.load(Ordering::SeqCst) {
            return Ok(false);
        }
        // The commit is the step GC must not be able to slip in front of.
        assert_eq!(self.guards.load(Ordering::SeqCst), 1, "lease committed outside the guard");
        self.held.lock().unwrap().insert((
            request.group_id.clone(),
            request.requester_device_id.clone(),
            request.path.clone(),
            request.version_hash,
        ));
        Ok(true)
    }
    fn release(
        &self,
        group_id: &str,
        requester: &str,
        path: &str,
        version_hash: &[u8; 32],
        _attempt_token: &[u8; 16],
    ) -> Result<bool, ReplicaEngineError> {
        Ok(self.held.lock().unwrap().remove(&(
            group_id.into(),
            requester.into(),
            path.into(),
            *version_hash,
        )))
    }
}

fn engine(verifies: bool) -> (PeerReplicaEngine, Arc<Leases>, Arc<Evidence>, DurableVersionQuery) {
    let current = version();
    let query = DurableVersionQuery {
        folder_group_id: GROUP.into(),
        file_path: PATH.into(),
        block_hashes: current.blocks.iter().map(|b| b.hash.0.clone()).collect(),
        for_handoff: false,
        version_hash: current.version_hash.as_bytes().to_vec(),
        block_sizes: current.blocks.iter().map(|b| b.size).collect(),
    };
    let evidence = Arc::new(Evidence { current, blocks_verify: AtomicBool::new(verifies) });
    let leases = Arc::new(Leases::default());
    let engine = PeerReplicaEngine::new(ReplicaEngineDependencies {
        durability: evidence.clone(),
        leases: leases.clone(),
    });
    (engine, leases, evidence, query)
}

/// A responder that cannot commit the lease row (a crash or a failed write
/// before the acknowledgement) never says present, so the requester has no
/// custody to reclaim against.
#[test]
fn a_lease_that_cannot_be_committed_is_never_acknowledged() {
    let (engine, leases, _, query) = engine(true);
    leases.fail_commit.store(true, Ordering::SeqCst);
    let answer = engine.acquire_custody_lease(REQUESTER, &query, 1, TOKEN);
    assert!(!answer.present);
    assert!(leases.held.lock().unwrap().is_empty());
}

/// The commit happened but the acknowledgement never arrived: the retry finds
/// the same lease and acknowledges, without a second one.
#[test]
fn a_retry_after_a_commit_without_an_acknowledgement_is_idempotent() {
    let (engine, leases, _, query) = engine(true);
    // The first attempt's lease committed; its acknowledgement was lost.
    assert!(engine.acquire_custody_lease(REQUESTER, &query, 1, TOKEN).present);
    assert!(engine.acquire_custody_lease(REQUESTER, &query, 1, TOKEN).present);
    assert_eq!(leases.held.lock().unwrap().len(), 1);
}

/// The guard that keeps GC out is released when the call returns, whatever
/// the answer was.
#[test]
fn the_reference_guard_is_released_on_every_outcome() {
    let (engine, leases, _, mut query) = engine(true);
    assert!(engine.acquire_custody_lease(REQUESTER, &query, 1, TOKEN).present);
    assert_eq!(leases.guards.load(Ordering::SeqCst), 0);
    query.version_hash = vec![0; 32];
    assert!(!engine.acquire_custody_lease(REQUESTER, &query, 1, TOKEN).present);
    assert_eq!(leases.guards.load(Ordering::SeqCst), 0);
}

/// Blocks that do not verify are not custody: no lease row is ever written.
#[test]
fn a_version_whose_blocks_do_not_verify_is_refused_and_leaves_no_lease() {
    let (engine, leases, _, query) = engine(false);
    assert!(!engine.acquire_custody_lease(REQUESTER, &query, 1, TOKEN).present);
    assert!(leases.held.lock().unwrap().is_empty());
}

/// A query for a version other than the current one is refused before any
/// lease is written.
#[test]
fn a_version_that_is_not_current_is_refused_without_a_lease() {
    let (engine, leases, _, mut query) = engine(true);
    query.version_hash = vec![0; 32];
    assert!(!engine.acquire_custody_lease(REQUESTER, &query, 1, TOKEN).present);
    assert!(leases.held.lock().unwrap().is_empty());
}

/// Release ends the lease, and a second release is not an error.
#[test]
fn release_ends_the_lease_and_can_be_repeated() {
    let (engine, leases, _, query) = engine(true);
    assert!(engine.acquire_custody_lease(REQUESTER, &query, 1, TOKEN).present);
    let hash: [u8; 32] = query.version_hash.clone().try_into().unwrap();
    engine.release_custody_lease(REQUESTER, GROUP, PATH, &hash, &TOKEN).unwrap();
    engine.release_custody_lease(REQUESTER, GROUP, PATH, &hash, &TOKEN).unwrap();
    assert!(leases.held.lock().unwrap().is_empty());
}

/// An acquire the lease store refuses to hold (its attempt was already released,
/// or the device is handing its leases off) is not acknowledged.
#[test]
fn an_acquire_the_lease_store_refuses_is_not_acknowledged() {
    let (engine, leases, _, query) = engine(true);
    leases.refuse.store(true, Ordering::SeqCst);
    assert!(!engine.acquire_custody_lease(REQUESTER, &query, 1, TOKEN).present);
    assert!(leases.held.lock().unwrap().is_empty());
}
