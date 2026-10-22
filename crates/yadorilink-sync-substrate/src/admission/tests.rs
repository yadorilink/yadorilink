#![cfg(test)]

use super::*;

#[test]
fn admit_none_refuses_every_peer_including_one_it_has_seen_before() {
    let peer = PeerId::from_bytes([7u8; 32]);
    assert!(!AdmitNone.admit(&peer));
    assert!(!AdmitNone.admit(&peer), "no policy may soften on a second look");
}

/// The property revocation depends on: the answer tracks the state the
/// predicate reads, rather than whatever it read the first time.
#[test]
fn a_predicate_over_live_state_stops_admitting_once_that_state_changes() {
    let revoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = revoked.clone();
    let policy = AdmitWhen::new(move |_| !seen.load(std::sync::atomic::Ordering::SeqCst));
    let peer = PeerId::from_bytes([3u8; 32]);

    assert!(policy.admit(&peer), "an un-revoked peer is admitted");
    revoked.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(!policy.admit(&peer), "a peer revoked after the node spawned must stop being admitted");
}

#[test]
fn a_predicate_distinguishes_peers_rather_than_answering_the_same_way_twice() {
    let allowed = PeerId::from_bytes([1u8; 32]);
    let policy = AdmitWhen::new(move |peer: &PeerId| peer.as_bytes()[0] == 1);
    assert!(policy.admit(&allowed));
    assert!(!policy.admit(&PeerId::from_bytes([2u8; 32])));
}
