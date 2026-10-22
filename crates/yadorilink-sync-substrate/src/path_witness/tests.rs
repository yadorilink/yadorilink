#![cfg(test)]

use super::*;

/// Gate: a relay path that carried bytes and then closed is still counted.
///
/// This is the false negative the whole module exists for. Reading the
/// connection's paths at the end would show one direct path and conclude
/// "direct only", labelling a mostly-relayed transfer as a direct-path
/// measurement.
#[test]
fn a_relay_path_that_closed_before_the_end_still_counts() {
    let mut acc = WitnessAccumulator::default();
    acc.opened(1, PathKind::Relay);
    acc.opened(2, PathKind::Direct);
    // The relay carried the first hundred megabytes, then went away.
    acc.closed(1, PathKind::Relay, PathBytes::new(100 * 1024 * 1024, 0));
    acc.still_open(2, PathKind::Direct, PathBytes::new(900 * 1024 * 1024, 0));

    let witness = acc.finish();
    assert_eq!(witness.relay_tx_bytes, 100 * 1024 * 1024);
    assert!(!witness.is_direct_only(), "a closed relay path must not vanish from the verdict");
    assert!(witness.rejection().unwrap().contains("relay path carried"));
}

/// Gate: the clean case is accepted, and says so.
#[test]
fn a_direct_only_connection_is_direct_only() {
    let mut acc = WitnessAccumulator::default();
    acc.opened(1, PathKind::Direct);
    acc.still_open(1, PathKind::Direct, PathBytes::new(1024 * 1024 * 1024, 0));

    let witness = acc.finish();
    assert!(witness.is_direct_only());
    assert_eq!(witness.rejection(), None);
    assert!(!witness.relay_path_opened, "no relay path should ever have opened");
}

/// Gate: a relay that opened but carried nothing does not invalidate.
///
/// Path validation traffic is not application data. Requiring that no relay
/// path ever opened would reject runs that were genuinely direct, so the
/// byte count decides and the open flag is reported alongside it.
#[test]
fn a_relay_path_that_carried_nothing_is_acceptable() {
    let mut acc = WitnessAccumulator::default();
    acc.opened(1, PathKind::Relay);
    acc.opened(2, PathKind::Direct);
    acc.closed(1, PathKind::Relay, PathBytes::default());
    acc.still_open(2, PathKind::Direct, PathBytes::new(4096, 0));

    let witness = acc.finish();
    assert!(witness.is_direct_only());
    assert!(witness.relay_path_opened, "and the fact it opened is still reported");
}

/// Gate: dropped events invalidate, rather than being tolerated.
///
/// After a gap the totals are a floor, not a measurement -- the missing
/// events could have been a relay path opening, carrying, and closing. A
/// snapshot cannot recover that, so the only honest verdict is that the run
/// produces no number.
#[test]
fn dropped_events_invalidate_the_run() {
    let mut acc = WitnessAccumulator::default();
    acc.opened(1, PathKind::Direct);
    acc.lagged();
    acc.still_open(1, PathKind::Direct, PathBytes::new(1024, 0));

    let witness = acc.finish();
    assert!(witness.incomplete);
    assert!(!witness.is_direct_only(), "an incomplete history cannot support the claim");
    assert!(witness.rejection().unwrap().contains("dropped"));
}

/// Gate: the transfer-end boundary is fixed before the pump is stopped.
///
/// Ordering, not arithmetic. Draining first leaves a window in which a
/// relay path closes after the pump has finished: its `Closed` reaches
/// nobody, and it is gone from a snapshot taken afterwards too -- a false
/// "direct only" with nothing marking it incomplete. A snapshot taken
/// first cannot miss a path that was open at the transfer's end, whatever
/// happens next.
///
/// Expressed here as the property the ordering has to deliver: bytes
/// observed at the boundary survive into the verdict even when the only
/// later news about that path never arrives.
#[test]
fn bytes_open_at_the_boundary_survive_a_close_that_is_never_observed() {
    let mut acc = WitnessAccumulator::default();
    acc.seed(0, PathKind::Relay);
    // The snapshot, taken at transfer end while the relay was still up.
    acc.still_open(0, PathKind::Relay, PathBytes::new(64 * 1024, 0));
    // Its `Closed` never arrives -- the pump had already stopped.

    let witness = acc.finish();
    assert_eq!(witness.relay_tx_bytes, 64 * 1024, "the boundary reading must stand alone");
    assert!(!witness.is_direct_only());
}

/// Gate: a path is counted once, however the verdict is reached.
///
/// Closing a connection emits `Closed` for every still-open path AND leaves
/// them in the list a snapshot reads. A verdict taken after close therefore
/// sees each path twice, and without this would report roughly double the
/// bytes -- a number that looks plausible and is simply wrong.
#[test]
fn a_path_is_counted_once_even_if_it_both_closes_and_appears_in_the_snapshot() {
    let mut acc = WitnessAccumulator::default();
    acc.opened(1, PathKind::Direct);
    acc.closed(1, PathKind::Direct, PathBytes::new(1_000, 0));
    // The same path, still listed by the post-close snapshot.
    acc.still_open(1, PathKind::Direct, PathBytes::new(1_000, 0));

    assert_eq!(acc.finish().direct_tx_bytes, 1_000, "the path must be counted exactly once");
}

/// Gate: a relay present before watching began is still reported as opened.
///
/// The initial path's `Opened` is emitted before any subscriber exists, so
/// it can never be observed -- and on a relay-mode dial that path is the
/// relay. Seeding from a subscription-time snapshot is the only way the
/// flag can ever be true for it.
#[test]
fn a_path_present_before_watching_began_is_seeded() {
    let mut acc = WitnessAccumulator::default();
    acc.seed(0, PathKind::Relay);
    acc.still_open(0, PathKind::Relay, PathBytes::new(4_096, 0));

    let witness = acc.finish();
    assert!(witness.relay_path_opened, "the initial path's kind must survive into the verdict");
    assert_eq!(witness.relay_tx_bytes, 4_096);
}

/// Gate: the defect this direction-awareness exists for.
///
/// A fetching node sends a small request and receives a large payload. If
/// the payload comes back over a relay while acknowledgements go direct,
/// a TX-only verdict sees "direct bytes present, relay bytes zero" and
/// calls it a direct transfer -- having measured the acknowledgements.
#[test]
fn a_payload_received_over_a_relay_is_not_a_direct_transfer() {
    let mut acc = WitnessAccumulator::default();
    acc.opened(1, PathKind::Direct);
    acc.opened(2, PathKind::Relay);
    // Requests and acks out the direct path; the gigabyte back over relay.
    acc.still_open(1, PathKind::Direct, PathBytes::new(8_192, 0));
    acc.still_open(2, PathKind::Relay, PathBytes::new(0, 1024 * 1024 * 1024));

    let witness = acc.finish();
    assert!(
        !witness.is_direct_only(),
        "the payload arrived over a relay; only the acks were direct"
    );
    assert!(witness.rejection().unwrap().contains("received"));
}

/// Gate: the fetching side's own clean case still passes.
///
/// The mirror of the test above -- otherwise counting RX could be
/// satisfied by rejecting everything.
#[test]
fn a_payload_received_over_a_direct_path_is_a_direct_transfer() {
    let mut acc = WitnessAccumulator::default();
    acc.opened(1, PathKind::Direct);
    acc.still_open(1, PathKind::Direct, PathBytes::new(8_192, 1024 * 1024 * 1024));

    let witness = acc.finish();
    assert!(witness.is_direct_only());
    assert_eq!(witness.direct_bytes(), 8_192 + 1024 * 1024 * 1024);
}

/// Gate: a payload-scale floor rejects a connection that only handshook.
///
/// `is_direct_only` alone is satisfied by path-validation traffic, which
/// is how a witness attached to the wrong connection passed while the
/// transfer went elsewhere.
#[test]
fn a_setup_only_connection_fails_a_payload_scale_floor() {
    let mut acc = WitnessAccumulator::default();
    acc.opened(1, PathKind::Direct);
    acc.still_open(1, PathKind::Direct, PathBytes::new(4_978, 0));

    let witness = acc.finish();
    assert!(witness.is_direct_only(), "it is direct, as far as it goes");
    assert!(
        !witness.carried_direct_payload(1024 * 1024 * 1024),
        "but it carried nothing like a gigabyte"
    );
}

fn witness(direct: u64, relay: u64, incomplete: bool) -> PathWitness {
    PathWitness {
        direct_tx_bytes: direct,
        relay_rx_bytes: relay,
        incomplete,
        ..PathWitness::default()
    }
}

/// Gate: a relay on any connection beats a gap on any other.
///
/// The defect this ordering exists for. Judging connections one at a
/// time and returning early let the first connection's lost events
/// report "inconclusive" before the second connection's relay bytes
/// were ever looked at -- so a real relay came back as a retry, and a
/// measurement that retries past a relay eventually reports success.
#[test]
fn a_relay_on_a_later_connection_is_not_masked_by_an_earlier_gap() {
    let set = [witness(4_096, 0, true), witness(0, 1024 * 1024 * 1024, false)];
    match verdict_for(&set, 0) {
        TransferVerdict::NotDirect(why) => assert!(why.contains("relay"), "{why}"),
        other => panic!("a relay must disprove the claim outright, got {other:?}"),
    }
}

/// Gate: with nothing against it, a gap is still inconclusive.
#[test]
fn a_gap_alone_is_the_absence_of_an_answer() {
    let set = [witness(4_096, 0, false), witness(8_192, 0, true)];
    assert!(matches!(verdict_for(&set, 0), TransferVerdict::Inconclusive(_)));
}

/// Gate: a payload split by a redial still satisfies the floor.
///
/// A path that drops mid-transfer is redialled, and the bytes divide
/// legitimately between connections. Requiring the whole volume from
/// each would reject a run that was correct throughout.
#[test]
fn a_payload_split_across_two_connections_still_meets_the_floor() {
    let half = 512 * 1024 * 1024;
    let set = [witness(half, 0, false), witness(half, 0, false)];
    assert_eq!(
        verdict_for(&set, 1024 * 1024 * 1024),
        TransferVerdict::Direct { direct_bytes: 1024 * 1024 * 1024 }
    );
}

/// Gate: falling short of the expected volume is a refusal, not a pass.
#[test]
fn a_direct_set_that_never_carried_the_payload_is_refused() {
    let set = [witness(4_978, 0, false)];
    match verdict_for(&set, 1024 * 1024 * 1024) {
        TransferVerdict::NotDirect(why) => assert!(why.contains("short of"), "{why}"),
        other => panic!("setup traffic is not a transfer, got {other:?}"),
    }
}

/// Gate: witnessing nothing is never a success.
#[test]
fn an_attempt_that_witnessed_no_connection_proves_nothing() {
    assert!(matches!(verdict_for(&[], 0), TransferVerdict::NotDirect(_)));
}

/// Gate: a connection that sent nothing is not a direct-path success.
#[test]
fn a_connection_that_carried_nothing_proves_nothing() {
    let witness = WitnessAccumulator::<u64>::default().finish();
    assert!(!witness.is_direct_only());
    assert!(witness.rejection().unwrap().contains("no direct path"));
}
