use std::collections::HashSet;

use yadorilink_replica_domain::file::BlockInfo;

use super::{DeclineEvidence, PrefetchVerdict, ASK_ROUNDS};

fn block(n: u8) -> BlockInfo {
    BlockInfo { hash: vec![n; 32], offset: 0, size: 1 }
}

fn set(blocks: &[&BlockInfo]) -> HashSet<Vec<u8>> {
    blocks.iter().map(|b| b.hash.clone()).collect()
}

/// Declined by every holder on every one of the rounds: unobtainable. Any
/// round that did not end that way -- a holder not connected, or a miss
/// that was not an explicit "do not hold" -- leaves it unresolved.
#[test]
fn only_a_block_every_holder_declined_every_round_is_unobtainable() {
    let (gone, flaky) = (block(1), block(2));
    let asked = vec![gone.clone(), flaky.clone()];
    let mut evidence = DeclineEvidence::default();
    for round in 0..ASK_ROUNDS {
        let declined = if round == 1 { set(&[&gone]) } else { set(&[&gone, &flaky]) };
        evidence.record_round(&asked, &declined, true);
    }
    let verdict = evidence.verdict(&asked);
    assert_eq!(verdict.unobtainable, set(&[&gone]));
    assert_eq!(verdict.unresolved, set(&[&flaky]), "one unanswered round is enough to doubt");

    // The same answers while a holder was not connected prove nothing.
    let mut partial = DeclineEvidence::default();
    for _ in 0..ASK_ROUNDS {
        partial.record_round(&asked, &set(&[&gone, &flaky]), false);
    }
    let verdict = partial.verdict(&asked);
    assert!(verdict.unobtainable.is_empty(), "an offline holder might have it");
    assert_eq!(verdict.unresolved, set(&[&gone, &flaky]));
}

/// A run cut short (the stall deadline ends the re-asking early) has not
/// asked often enough: however unanimous the rounds it ran, the block is
/// unresolved, never unobtainable.
#[test]
fn fewer_declining_rounds_than_required_is_never_unobtainable() {
    let gone = block(1);
    for rounds in 1..ASK_ROUNDS {
        let mut evidence = DeclineEvidence::default();
        for _ in 0..rounds {
            evidence.record_round(std::slice::from_ref(&gone), &set(&[&gone]), true);
        }
        let verdict = evidence.verdict(std::slice::from_ref(&gone));
        assert!(verdict.unobtainable.is_empty(), "{rounds} round(s) must not be enough");
        assert_eq!(verdict.unresolved, set(&[&gone]));
    }
}

/// A block fetched in a later round is not reported at all; a block still
/// missing that was never asked for is unresolved, never unobtainable.
#[test]
fn the_verdict_covers_exactly_what_is_still_missing() {
    let (fetched, never_asked) = (block(1), block(2));
    let mut evidence = DeclineEvidence::default();
    evidence.record_round(std::slice::from_ref(&fetched), &HashSet::new(), true);
    let verdict = evidence.verdict(std::slice::from_ref(&never_asked));
    assert_eq!(
        verdict,
        PrefetchVerdict {
            unobtainable: HashSet::new(),
            unresolved: set(&[&never_asked]),
            offline: Vec::new(),
        }
    );
    assert_eq!(evidence.verdict(&[]), PrefetchVerdict::default());
}
