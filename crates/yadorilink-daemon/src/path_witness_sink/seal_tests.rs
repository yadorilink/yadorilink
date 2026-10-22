#![cfg(test)]

use super::*;

/// A link dialled while the report is being assembled cannot be in it.
///
/// `flush` takes the watchers and then awaits them, and the driver is
/// still running throughout, so without the seal that link's watcher
/// would be pushed into a set nobody reads again -- and the file would
/// claim to describe every connection while omitting one. The sink
/// cannot prevent the dial, only notice it, and noticing is enough
/// because an inconclusive run is discarded rather than believed.
#[tokio::test]
async fn a_link_dialled_after_the_seal_makes_the_report_inconclusive() {
    let dir = tempfile::tempdir().expect("somewhere to write");
    let report = dir.path().join("paths.json");
    let sink = PathWitnessSink::new(report.clone(), 1);

    // Seal exactly as `flush` does, then let a dial arrive through the
    // same path the hook uses. The watcher is never built, which is the
    // other half of the contract: there is no point subscribing to a
    // connection whose evidence cannot reach the report.
    {
        let mut collected = sink.collected.lock().unwrap();
        collected.sealed = true;
    }
    sink.offer(|| unreachable!("a sealed sink must not subscribe to anything"));

    sink.flush().await;
    let written = std::fs::read_to_string(&report).expect("a report");
    assert!(written.contains("\"verdict\":\"inconclusive\""), "{written}");
    assert!(written.contains("went unwatched"), "{written}");
}

/// And the ordinary case is unaffected: nothing arrived late, so the
/// verdict comes from the witnesses themselves.
// The unsealed path is not tested here. A watcher needs a live
// connection, and a test that fakes one would be asserting against its
// own stub. It is covered where it actually happens instead:
// `a_daemon_writes_out_which_carrier_its_transfer_used` drives a real
// convergence through this sink, and a sink that refused every dial
// would produce an empty set, which `verdict_for` reports as "no
// connection was witnessed" and that gate fails on.

#[tokio::test]
async fn a_report_with_nothing_arriving_late_is_judged_on_its_witnesses() {
    let dir = tempfile::tempdir().expect("somewhere to write");
    let report = dir.path().join("paths.json");
    let sink = PathWitnessSink::new(report.clone(), 1);

    sink.flush().await;
    let written = std::fs::read_to_string(&report).expect("a report");
    assert!(!written.contains("went unwatched"), "{written}");
}
