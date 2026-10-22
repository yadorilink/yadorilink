#![cfg(test)]

use super::*;

#[test]
fn begin_registers_an_active_transfer_with_zero_progress() {
    let tracker = TransferProgressTracker::new();
    let _guard = tracker.begin("group-1", "big.bin", 1000, 10);

    let snapshot = tracker.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].group_id, "group-1");
    assert_eq!(snapshot[0].path, "big.bin");
    assert_eq!(snapshot[0].bytes_done, 0);
    assert_eq!(snapshot[0].bytes_total, 1000);
    assert_eq!(snapshot[0].blocks_done, 0);
    assert_eq!(snapshot[0].blocks_total, 10);
}

/// progress advances as blocks land.
#[test]
fn record_block_done_advances_bytes_and_blocks_done() {
    let tracker = TransferProgressTracker::new();
    let _guard = tracker.begin("group-1", "big.bin", 300, 3);

    tracker.record_block_done("group-1", "big.bin", 100, "peer-a");
    tracker.record_block_done("group-1", "big.bin", 100, "peer-b");

    let snapshot = tracker.snapshot();
    assert_eq!(snapshot[0].bytes_done, 200);
    assert_eq!(snapshot[0].blocks_done, 2);
    assert_eq!(snapshot[0].source_peer, "peer-b");
    assert_eq!(tracker.transfer_bytes_total(), 200);
}

/// "completes at 100%" — once every block has landed and the
/// guard is dropped (as `hydrate_inner` does at the end of a
/// successful hydration), the transfer disappears from the active set
/// rather than lingering at 100%.
#[test]
fn dropping_the_guard_removes_the_active_transfer() {
    let tracker = TransferProgressTracker::new();
    {
        let _guard = tracker.begin("group-1", "big.bin", 300, 3);
        tracker.record_block_done("group-1", "big.bin", 300, "peer-a");
        assert_eq!(tracker.snapshot().len(), 1);
    }
    assert!(tracker.snapshot().is_empty());
}

/// the per-link rollup sums across every active transfer for
/// that link, and is absent (not zeroed) when the link has none.
#[test]
fn link_rollup_sums_across_active_transfers_for_the_same_link() {
    let tracker = TransferProgressTracker::new();
    let _guard_a = tracker.begin("group-1", "a.bin", 100, 1);
    let _guard_b = tracker.begin("group-1", "b.bin", 200, 2);
    let _guard_other = tracker.begin("group-2", "c.bin", 50, 1);

    tracker.record_block_done("group-1", "a.bin", 100, "peer-a");

    let rollup = tracker.link_rollup("group-1").unwrap();
    assert_eq!(rollup.bytes_done, 100);
    assert_eq!(rollup.bytes_total, 300);
    assert_eq!(rollup.blocks_done, 1);
    assert_eq!(rollup.blocks_total, 3);

    assert!(tracker.link_rollup("group-3").is_none());
}

#[test]
fn block_fetch_histogram_renders_openmetrics_with_bucket_counts() {
    let tracker = TransferProgressTracker::new();
    tracker.observe_block_fetch_seconds(0.02);
    tracker.observe_block_fetch_seconds(3.0);

    let rendered = tracker.render_block_fetch_histogram();
    assert!(rendered.contains("# TYPE yadorilink_block_fetch_seconds histogram"));
    assert!(rendered.contains("yadorilink_block_fetch_seconds_count 2"));
    assert!(rendered.contains("yadorilink_block_fetch_seconds_bucket{le=\"+Inf\"} 2"));
}
