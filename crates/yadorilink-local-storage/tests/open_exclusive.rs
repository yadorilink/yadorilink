//! `SegmentBlockStore::open_exclusive` opens only under a live writer lease and refuses a
//! stale one before touching the store directory.

use std::sync::Arc;
use std::time::Duration;

use yadorilink_local_storage::{GroupCommitLimits, SegmentBlockStore, StorageError};
use yadorilink_root_authority::writer_lease::{FakeLeaseClock, WriterLease};

const TERM: Duration = Duration::from_secs(10);

#[test]
fn open_exclusive_needs_a_live_lease_and_refuses_a_stale_one_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let lease_dir = dir.path().join("lease");
    let store_dir = dir.path().join("blocks");
    let clock = FakeLeaseClock::new(1_000);

    let old = WriterLease::acquire(&lease_dir, TERM, clock.clone()).unwrap();
    SegmentBlockStore::open_exclusive(&store_dir, &old, GroupCommitLimits::default())
        .expect("a live lease opens the store");

    clock.advance(TERM);
    let _new = WriterLease::acquire(&lease_dir, TERM, Arc::clone(&clock) as _).unwrap();
    let untouched = dir.path().join("untouched");
    let err = SegmentBlockStore::open_exclusive(&untouched, &old, GroupCommitLimits::default())
        .err()
        .expect("stale refused");
    assert!(matches!(err, StorageError::WriterLease(_)), "{err}");
    assert!(!untouched.exists(), "a refused open must not create or recover anything");
}

/// A clock that reports the lease as live for its first `live_reads` reads and past its term
/// afterwards, so a lease can run out between two verifications of one open.
struct ExpiresAfter {
    reads: std::sync::atomic::AtomicU64,
    live_reads: u64,
}

impl yadorilink_root_authority::writer_lease::LeaseClock for ExpiresAfter {
    fn now_ms(&self) -> u64 {
        let read = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        if read <= self.live_reads {
            1_000
        } else {
            10_000_000
        }
    }
}

#[test]
fn a_lease_lost_during_the_open_stops_recovery_before_it_truncates() {
    let dir = tempfile::tempdir().unwrap();
    let store_dir = dir.path().join("blocks");
    {
        let store = SegmentBlockStore::new(&store_dir).unwrap();
        yadorilink_local_storage::BlockStore::put(&store, b"a committed block").unwrap();
    }
    // A tail past the committed end: recovery would truncate it.
    let segment = std::fs::read_dir(store_dir.join("segments"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "seg"))
        .expect("a segment");
    let mut bytes = std::fs::read(&segment).unwrap();
    bytes.extend_from_slice(&[7u8; 64]);
    std::fs::write(&segment, &bytes).unwrap();

    // Reads: acquire, the open's first verify, then the verify before recovery's first
    // destructive step, which finds the lease run out.
    let clock = Arc::new(ExpiresAfter { reads: 0.into(), live_reads: 2 });
    let lease = WriterLease::acquire(&dir.path().join("lease"), TERM, clock).unwrap();
    let err = SegmentBlockStore::open_exclusive(&store_dir, &lease, GroupCommitLimits::default())
        .err()
        .expect("refused");
    assert!(matches!(err, StorageError::WriterLease(_)), "{err}");
    assert_eq!(std::fs::read(&segment).unwrap(), bytes, "nothing was truncated");
}
