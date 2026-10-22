#![cfg(test)]

use super::*;

fn witness(direct_tx: u64, direct_rx: u64, relay_rx: u64, incomplete: bool) -> PathWitness {
    PathWitness {
        direct_tx_bytes: direct_tx,
        direct_rx_bytes: direct_rx,
        relay_rx_bytes: relay_rx,
        incomplete,
        ..PathWitness::default()
    }
}

#[test]
fn a_direct_run_reports_the_total_it_actually_carried() {
    let set = [witness(8_192, 1024 * 1024 * 1024, 0, false)];
    let verdict = yadorilink_sync_substrate::verdict_for(&set, 1024 * 1024 * 1024);
    let report = render(&verdict, &set, 1024 * 1024 * 1024);
    assert!(report.contains("\"verdict\":\"direct\""), "{report}");
    assert!(report.contains("\"direct_bytes\":1073750016"), "{report}");
}

/// The reason has to survive into the file. A harness that is told only
/// "not_direct" cannot tell a relayed transfer from one that never
/// moved the payload, and those call for different responses.
#[test]
fn a_refused_run_carries_its_reason_into_the_file() {
    let set = [witness(4_096, 0, 999, false)];
    let verdict = yadorilink_sync_substrate::verdict_for(&set, 1);
    let report = render(&verdict, &set, 1);
    assert!(report.contains("\"verdict\":\"not_direct\""), "{report}");
    assert!(report.contains("999 bytes crossed a relay"), "{report}");
}

#[test]
fn an_inconclusive_run_is_not_reported_as_a_refusal() {
    let set = [witness(4_096, 0, 0, true)];
    let verdict = yadorilink_sync_substrate::verdict_for(&set, 1);
    assert!(render(&verdict, &set, 1).contains("\"verdict\":\"inconclusive\""));
}

/// Every connection is listed, so a refusal can be argued with.
#[test]
fn each_connection_appears_separately() {
    let set = [witness(1, 0, 0, false), witness(2, 0, 0, false)];
    let verdict = yadorilink_sync_substrate::verdict_for(&set, 1);
    let report = render(&verdict, &set, 1);
    assert_eq!(report.matches("\"direct_tx_bytes\"").count(), 2, "{report}");
}

#[test]
fn a_reason_containing_a_quote_does_not_break_the_file() {
    assert_eq!(json_string("a \"b\" c"), "\"a \\\"b\\\" c\"");
}
