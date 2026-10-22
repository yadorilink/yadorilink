//! Author closure, the cutoff of a closed incarnation, and the local fence:
//! what a checkpoint commits about a closure, who refuses what above a cutoff,
//! and that the fence never reaches a root.

use ed25519_dalek::VerifyingKey;

use yadorilink_replica_domain::native_frontier::{AuthorState, NativeAuthorFrontierEntry};
use yadorilink_replica_domain::native_state::Dot;

use super::*;
use crate::native_checkpoint_install::{CheckpointError, InstalledCheckpoint};

// --- helpers ---------------------------------------------------------------

fn key_for(author: &AuthorId) -> Option<VerifyingKey> {
    let seed = match author.device.0.as_str() {
        "device-a" => 1,
        "device-b" => 2,
        "device-c" => 3,
        "device-d" => 4,
        _ => return None,
    };
    Some(device_key(seed).verifying_key())
}

fn environment(device: &str) -> crate::author_incarnation::IncarnationEnvironment {
    crate::author_incarnation::IncarnationEnvironment {
        device_id: DeviceId(device.into()),
        sidecar: None,
        machine_fingerprint: vec![7],
    }
}

fn seeded(c: &Connection) {
    for seed in 1..=4 {
        crate::dag_store::put_file_version(c, GROUP, &version(seed)).unwrap();
    }
}

fn seed_of(who: &AuthorId) -> u8 {
    match who.device.0.as_str() {
        "device-a" => 1,
        "device-b" => 2,
        "device-c" => 3,
        "device-d" => 4,
        other => panic!("no key for {other}"),
    }
}

/// `count` signed deltas of `who`, `f1`, `f2`, ... each putting its own path.
fn chain(who: &AuthorId, count: u64) -> Vec<NativeDelta> {
    let mut deltas: Vec<NativeDelta> = Vec::new();
    for seq in 1..=count {
        let prev = deltas.last().map(NativeDelta::delta_hash);
        let mut delta = put_delta(who, seq, prev, &format!("f{seq}"), 1);
        delta.sign(&device_key(seed_of(who)));
        deltas.push(delta);
    }
    deltas
}

fn admit(c: &Connection, delta: &NativeDelta) -> NativeAdmission {
    crate::native_admission::admit_native_delta(c, &group(), delta, &key_for).unwrap()
}

fn is_admitted(outcome: &NativeAdmission) -> bool {
    matches!(outcome, NativeAdmission::Admitted { .. })
}

fn entry_of(delta: &NativeDelta) -> NativeAuthorFrontierEntry {
    NativeAuthorFrontierEntry { seq: delta.seq, tip: delta.delta_hash() }
}

/// Closes `who` at the entry of `cutoff` (`None`: before its first delta), the way
/// an installed closure does.
fn close_at(c: &Connection, who: &AuthorId, cutoff: Option<&NativeDelta>) {
    native_closure::store_bundle_closure(c, &group(), &own_closure(who, cutoff), [7; 32], &Policy)
        .unwrap();
}

fn held_rows(c: &Connection) -> i64 {
    c.query_row("SELECT COUNT(*) FROM native_delta_holds WHERE group_id = ?1", [GROUP], |row| {
        row.get(0)
    })
    .unwrap()
}

fn frontier_seq(c: &Connection, who: &AuthorId) -> Option<u64> {
    crate::native_store::frontier_entry_get(c, &group(), who).unwrap().map(|entry| entry.seq.get())
}

/// A raw closure row, as a writer that bypasses the sweep would leave it.
fn raw_closure(c: &Connection, who: &AuthorId, cutoff: Option<&NativeDelta>) {
    let entry = cutoff.map(entry_of);
    c.execute(
        "INSERT INTO native_closed_authors (group_id, author, incarnation, \
         closed_at_unixtime, cutoff_seq, cutoff_tip) \
         VALUES (?1, ?2, ?3, 1, ?4, ?5)",
        rusqlite::params![
            GROUP,
            who.device.as_str(),
            who.incarnation.0.as_slice(),
            entry.map(|e| e.seq.get() as i64),
            entry.map(|e| e.tip.0.to_vec()),
        ],
    )
    .unwrap();
}

fn name_of(outcome: &Result<InstalledCheckpoint, CheckpointError>) -> &'static str {
    match outcome {
        Ok(_) => "Installed",
        Err(CheckpointError::NotEmpty) => "NotEmpty",
        Err(CheckpointError::RetiredAuthorLifted { .. }) => "RetiredAuthorLifted",
        Err(CheckpointError::ClosureFork { .. }) => "ClosureFork",
        Err(_) => "Other",
    }
}

// --- the author-state root commits the state -----------------------------------------------

/// Closes `source()`'s author `b` (which has a frontier entry and no live
/// head) and returns its sealed bundle.
fn bundle_closing_b() -> NativeBootstrap {
    let (c, _a, b) = source();
    close_author(&c, &group(), &b);
    built(&c)
}

fn state_of<'a>(bundle: &'a mut NativeBootstrap, who: &AuthorId) -> &'a mut AuthorState {
    &mut bundle.authors.iter_mut().find(|entry| &entry.author == who).unwrap().state
}

#[test]
fn the_author_state_root_differs_for_open_closed_cutoff_and_none_versus_some() {
    let root_of = |build: &dyn Fn(&Connection, &AuthorId)| {
        let c = conn();
        seeded(&c);
        let who = author("device-b");
        build(&c, &who);
        crate::native_store::author_state_root(&c, &group()).unwrap()
    };
    let installed = |count: u64| {
        move |c: &Connection, who: &AuthorId| {
            for delta in chain(who, count) {
                assert!(is_admitted(&admit(c, &delta)));
            }
        }
    };
    let open_at_two = root_of(&|c, who| installed(2)(c, who));
    let closed_at_two = root_of(&|c, who| {
        installed(2)(c, who);
        close_author(c, &group(), who);
    });
    let closed_at_one = root_of(&|c, who| {
        installed(1)(c, who);
        close_author(c, &group(), who);
    });
    let closed_without_an_entry = root_of(&|c, who| close_author(c, &group(), who));
    let roots = [open_at_two, closed_at_two, closed_at_one, closed_without_an_entry];
    for (i, left) in roots.iter().enumerate() {
        for (j, right) in roots.iter().enumerate().skip(i + 1) {
            assert_ne!(left, right, "author-state roots {i} and {j} must differ");
        }
    }
}

#[test]
fn a_bundle_carries_the_closure_of_an_author_with_no_frontier_entry() {
    let (c, _a, _b) = source();
    let never_seen = author("device-d");
    close_author(&c, &group(), &never_seen);

    let bundle = built(&c);

    let carried = bundle.authors.iter().find(|entry| entry.author == never_seen);
    assert_eq!(
        carried.map(|entry| entry.state),
        Some(AuthorState::Closed { frontier: None }),
        "the closure of an author with no frontier entry was dropped from the bundle \
         or given an invented entry"
    );
    verify_native_bootstrap(bundle, &group(), &Policy).unwrap();
}

#[test]
fn the_unforged_bundle_verifies() {
    verify_native_bootstrap(bundle_closing_b(), &group(), &Policy).unwrap();
}

#[test]
fn a_forged_open_or_closed_state_is_refused_either_way() {
    let b = author("device-b");
    let a = author("device-a");
    // Closed -> open at the same entry.
    let mut bundle = bundle_closing_b();
    let AuthorState::Closed { frontier: Some(entry) } = *state_of(&mut bundle, &b) else {
        panic!("b is closed at its entry")
    };
    *state_of(&mut bundle, &b) = AuthorState::Open(entry);
    assert!(verify_native_bootstrap(bundle, &group(), &Policy).is_err(), "closed forged open");
    // Open -> closed at the same entry.
    let mut bundle = bundle_closing_b();
    let AuthorState::Open(entry) = *state_of(&mut bundle, &a) else { panic!("a is open") };
    *state_of(&mut bundle, &a) = AuthorState::Closed { frontier: Some(entry) };
    assert!(verify_native_bootstrap(bundle, &group(), &Policy).is_err(), "open forged closed");
}

/// A forger who keeps everything else consistent still cannot move the cutoff:
/// the signed root does not match.
#[test]
fn a_forged_cutoff_is_refused() {
    type Forge = fn(&mut NativeAuthorFrontierEntry);
    let forges: [(&str, Forge); 2] = [
        ("a higher sequence", |entry| entry.seq = AuthorSeq(entry.seq.get() + 1)),
        ("another tip", |entry| entry.tip = DeltaHash([0xEE; 32])),
    ];
    for (what, forge) in forges {
        let mut bundle = bundle_closing_b();
        let AuthorState::Closed { frontier: Some(mut forged) } =
            *state_of(&mut bundle, &author("device-b"))
        else {
            panic!("b is closed at its entry")
        };
        forge(&mut forged);
        *state_of(&mut bundle, &author("device-b")) =
            AuthorState::Closed { frontier: Some(forged) };
        assert!(
            verify_native_bootstrap(bundle, &group(), &Policy).is_err(),
            "a cutoff with {what} was accepted"
        );
    }
}

#[test]
fn none_turned_into_some_and_some_into_none_are_refused() {
    // Some -> None: the closure drops the entry.
    let mut bundle = bundle_closing_b();
    *state_of(&mut bundle, &author("device-b")) = AuthorState::Closed { frontier: None };
    assert!(verify_native_bootstrap(bundle, &group(), &Policy).is_err(), "Some turned into None");

    // None -> Some: an author closed before its first delta gains an entry.
    let (c, _a, _b) = source();
    let never_seen = author("device-d");
    close_author(&c, &group(), &never_seen);
    let mut bundle = built(&c);
    *state_of(&mut bundle, &never_seen) = AuthorState::Closed {
        frontier: Some(NativeAuthorFrontierEntry { seq: AuthorSeq(1), tip: DeltaHash([0xCD; 32]) }),
    };
    assert!(verify_native_bootstrap(bundle, &group(), &Policy).is_err(), "None turned into Some");
}

#[test]
fn an_author_listed_twice_in_one_bundle_is_refused() {
    let mut bundle = bundle_closing_b();
    let again = bundle.authors[0].clone();
    bundle.authors.push(again);
    assert!(verify_native_bootstrap(bundle, &group(), &Policy).is_err());
}

#[test]
fn a_join_keeps_the_checkpoints_author_states() {
    let (c, _a, b) = source();
    let never_seen = author("device-d");
    close_author(&c, &group(), &b);
    close_author(&c, &group(), &never_seen);
    let bundle = built(&c);
    let hash = bundle.checkpoint.checkpoint_hash();
    let expected = bundle.author_states().unwrap();

    let joiner = conn();
    seeded(&joiner);
    join_bundle(bundle, &joiner).unwrap();

    assert_eq!(
        crate::native_checkpoint_frontier::checkpoint_coverage(&joiner, &group(), &hash.0)
            .unwrap()
            .states,
        expected
    );
    assert_eq!(roots_of(&joiner), roots_of(&c), "the joiner's roots are the sealer's");
    assert!(crate::native_store::is_closed(&joiner, &group(), &b).unwrap());
    assert!(crate::native_store::is_closed(&joiner, &group(), &never_seen).unwrap());
}

// --- admission above the cutoff -----------------------------------------------------------

#[test]
fn a_closed_incarnation_admits_up_to_its_cutoff_and_refuses_above_it() {
    let c = conn();
    seeded(&c);
    let b1 = author("device-b");
    let deltas = chain(&b1, 4);
    close_at(&c, &b1, Some(&deltas[1]));

    assert!(is_admitted(&admit(&c, &deltas[0])), "seq 1 is below the cutoff");
    assert!(is_admitted(&admit(&c, &deltas[1])), "seq 2 is the cutoff itself");
    let above = admit(&c, &deltas[2]);
    assert_eq!(
        above,
        NativeAdmission::AuthorClosed { author: b1.clone(), cutoff: Some(AuthorSeq(2)) }
    );
    assert_eq!(frontier_seq(&c, &b1), Some(2), "the cutoff does not move");
}

#[test]
fn a_gap_above_the_cutoff_is_refused_and_never_held() {
    let c = conn();
    seeded(&c);
    let b1 = author("device-b");
    let deltas = chain(&b1, 4);
    assert!(is_admitted(&admit(&c, &deltas[0])));
    close_at(&c, &b1, Some(&deltas[0]));

    let outcome = admit(&c, &deltas[3]);

    assert!(matches!(outcome, NativeAdmission::AuthorClosed { .. }), "{outcome:?}");
    assert_eq!(held_rows(&c), 0, "a refused delta is not parked");
}

/// A replica that was bootstrapped past the cutoff still answers a delayed
/// delta below it with the truncation verdict, not the cutoff refusal.
#[test]
fn a_replica_bootstrapped_past_the_cutoff_keeps_the_verdicts_at_or_below_it() {
    let sealer = conn();
    seeded(&sealer);
    let b1 = author("device-b");
    let deltas = chain(&b1, 4);
    for delta in &deltas[..2] {
        publish(&sealer, &b1, &device_key(2), delta.clone());
    }
    close_author(&sealer, &group(), &b1);
    let joiner = conn();
    seeded(&joiner);
    join_bundle(built(&sealer), &joiner).unwrap();

    let below = admit(&joiner, &deltas[0]);
    assert!(matches!(below, NativeAdmission::PriorHistoryTruncated { .. }), "{below:?}");
    let at = admit(&joiner, &deltas[1]);
    assert!(!matches!(at, NativeAdmission::AuthorClosed { .. }), "{at:?}");
    let above = admit(&joiner, &deltas[2]);
    assert!(matches!(above, NativeAdmission::AuthorClosed { .. }), "{above:?}");
}

#[test]
fn a_retirement_drops_the_held_deltas_above_its_cutoff_only() {
    let c = conn();
    seeded(&c);
    let b1 = author("device-b");
    let deltas = chain(&b1, 4);
    // Held for a predecessor: seq 2 and seq 4 wait on seq 1 and seq 3.
    assert!(matches!(admit(&c, &deltas[1]), NativeAdmission::Held { .. }));
    assert!(matches!(admit(&c, &deltas[3]), NativeAdmission::Held { .. }));
    assert_eq!(held_rows(&c), 2);

    close_at(&c, &b1, Some(&deltas[1]));

    assert_eq!(held_rows(&c), 1, "the hold above the cutoff is dropped, the one at it stays");
    let released = admit(&c, &deltas[0]);
    assert_eq!(
        released,
        NativeAdmission::Admitted {
            dot: Dot { author: b1.clone(), seq: AuthorSeq(1) },
            released: vec![Dot { author: b1.clone(), seq: AuthorSeq(2) }],
        }
    );
    assert_eq!(frontier_seq(&c, &b1), Some(2));
}

#[test]
fn a_retirement_before_the_first_delta_drops_every_hold_of_the_author() {
    let c = conn();
    seeded(&c);
    let b1 = author("device-b");
    let deltas = chain(&b1, 3);
    assert!(matches!(admit(&c, &deltas[1]), NativeAdmission::Held { .. }));
    assert_eq!(held_rows(&c), 1);

    close_at(&c, &b1, None);

    assert_eq!(held_rows(&c), 0);
    assert!(!is_admitted(&admit(&c, &deltas[0])));
}

/// The retirement row was written without the sweep: the release of a held
/// delta whose blocker lands is still refused, and its hold goes.
#[test]
fn a_held_delta_of_a_closed_incarnation_is_refused_when_its_blocker_releases_it() {
    let c = conn();
    seeded(&c);
    let b1 = author("device-b");
    let other = author("device-c");
    let blocker = {
        let mut delta = put_delta(&other, 1, None, "c", 2);
        delta.sign(&device_key(3));
        delta
    };
    let mut held = put_delta(&b1, 1, None, "b", 1);
    held.ops[0].removes = vec![HeadRef {
        dot: Dot { author: other.clone(), seq: AuthorSeq(1) },
        provenance: blocker.delta_hash(),
    }];
    held.sign(&device_key(2));
    assert!(matches!(admit(&c, &held), NativeAdmission::Held { .. }));
    raw_closure(&c, &b1, None);
    assert_eq!(held_rows(&c), 1, "the raw write did not sweep");

    let outcome = admit(&c, &blocker);

    assert_eq!(
        outcome,
        NativeAdmission::Admitted {
            dot: Dot { author: other.clone(), seq: AuthorSeq(1) },
            released: Vec::new(),
        },
        "the closed incarnation's delta must not be released"
    );
    assert_eq!(frontier_seq(&c, &b1), None);
    assert_eq!(held_rows(&c), 0, "the hold of a delta that can never be admitted is dropped");
}

/// A local install does not go through admission, and still cannot take a
/// delta of a closed incarnation.
#[test]
fn the_local_install_entry_refuses_a_closed_incarnation_too() {
    let c = conn();
    seeded(&c);
    let b1 = author("device-b");
    let deltas = chain(&b1, 2);
    crate::native_store::install_verified_delta(
        &c,
        &group(),
        &deltas[0],
        &device_key(2).verifying_key(),
    )
    .unwrap();
    close_at(&c, &b1, Some(&deltas[0]));

    let outcome = crate::native_store::install_verified_delta_inner(
        &c,
        &group(),
        &deltas[1],
        &device_key(2).verifying_key(),
    )
    .unwrap();

    assert!(
        matches!(outcome, crate::native_store::InstallOutcome::AuthorClosed { .. }),
        "{outcome:?}"
    );
    assert!(crate::native_store::install_verified_delta(
        &c,
        &group(),
        &deltas[1],
        &device_key(2).verifying_key()
    )
    .is_err());
    assert_eq!(frontier_seq(&c, &b1), Some(1));
}

// --- ahead of the cutoff ---------------------------------------------------------------------

/// `holder` joined a bundle in which `b1` is at seq 1 and then admitted
/// `b1/2`; the sealer closes `b1` at seq 1.
fn ahead_of_a_cutoff() -> (Connection, NativeBootstrap, AuthorId) {
    let b1 = author("device-b");
    let deltas = chain(&b1, 2);
    let sealer = conn();
    seeded(&sealer);
    publish(&sealer, &b1, &device_key(2), deltas[0].clone());
    let holder = conn();
    seeded(&holder);
    join_bundle(built(&sealer), &holder).unwrap();
    assert!(is_admitted(&admit(&holder, &deltas[1])));
    close_author(&sealer, &group(), &b1);
    (holder, built(&sealer), b1)
}

/// A replica that is ahead of a closure cutoff does not join the checkpoint that carries it:
/// only a rebootstrap replaces its state.
#[test]
fn a_replica_ahead_of_a_cutoff_does_not_take_the_checkpoint_by_a_join() {
    let (holder, bundle, b1) = ahead_of_a_cutoff();
    let checkpoint = bundle.checkpoint.checkpoint_hash();
    let before = (roots_of(&holder), crate::native_store::load_state(&holder, &group()).unwrap());

    let outcome = join_bundle(bundle, &holder);

    assert_eq!(name_of(&outcome), "NotEmpty", "{outcome:?}");
    let after = (roots_of(&holder), crate::native_store::load_state(&holder, &group()).unwrap());
    assert!(before == after, "a refused install must change nothing");
    assert!(!crate::native_store::is_closed(&holder, &group(), &b1).unwrap());
    assert_eq!(
        crate::native_checkpoint_frontier::checkpoint_coverage(&holder, &group(), &checkpoint.0)
            .unwrap(),
        crate::native_checkpoint_frontier::CheckpointCoverage::default()
    );
}

// --- the rotation closure ----------------------------------------------------------------

#[test]
fn a_rotation_closure_closes_the_incarnation_above_its_cutoff_without_closing_the_state() {
    let c = conn();
    seeded(&c);
    let b1 = author("device-b");
    let deltas = chain(&b1, 3);
    assert!(is_admitted(&admit(&c, &deltas[0])));
    rotation_closure_at(&c, &group(), &b1, Some(AuthorSeq(1)));

    assert!(!crate::native_store::is_closed(&c, &group(), &b1).unwrap());
    assert_eq!(
        admit(&c, &deltas[1]),
        NativeAdmission::AuthorClosed { author: b1.clone(), cutoff: Some(AuthorSeq(1)) }
    );
    assert!(matches!(admit(&c, &deltas[2]), NativeAdmission::AuthorClosed { .. }));
    assert!(matches!(admit(&c, &deltas[0]), NativeAdmission::Duplicate));
}

#[test]
fn a_rotation_closure_before_the_first_delta_refuses_the_first_delta() {
    let c = conn();
    seeded(&c);
    let b1 = author("device-b");
    rotation_closure_at(&c, &group(), &b1, None);
    let outcome = admit(&c, &chain(&b1, 1)[0]);
    assert_eq!(outcome, NativeAdmission::AuthorClosed { author: b1.clone(), cutoff: None });
    assert_eq!(frontier_seq(&c, &b1), None);
}

/// Storing the closure is invisible to the summary roots, the cache token that
/// keys them.
#[test]
fn a_rotation_closure_is_outside_every_root_digest_and_token() {
    let (c, _a, b) = source();
    let roots = roots_of(&c);
    let token = crate::native_summary_cache::state_token(&c, &group()).unwrap();
    let bundle = built(&c);

    rotation_closure_at(&c, &group(), &b, Some(AuthorSeq(1)));
    rotation_closure_at(&c, &group(), &author("device-d"), None);

    assert_eq!(roots_of(&c), roots);
    assert_eq!(crate::native_summary_cache::state_token(&c, &group()).unwrap(), token);
    let after = built(&c);
    assert_eq!(after.checkpoint, bundle.checkpoint);
    assert_eq!(after.authors, bundle.authors);
    assert!(after.closures.is_empty());
}

#[test]
fn closing_twice_is_idempotent_and_a_lower_cutoff_wins() {
    let c = conn();
    let b1 = author("device-b");
    rotation_closure_at(&c, &group(), &b1, Some(AuthorSeq(3)));
    rotation_closure_at(&c, &group(), &b1, Some(AuthorSeq(3)));
    assert_eq!(closure_rows(&c), 1);
    assert_eq!(unexported_rotation_cutoff(&c, &group(), &b1), Some(Some(AuthorSeq(3))));
    rotation_closure_at(&c, &group(), &b1, Some(AuthorSeq(2)));
    assert_eq!(cutoff_seq_of(&c, &b1), Some(Some(2)));
    rotation_closure_at(&c, &group(), &b1, None);
    assert_eq!(cutoff_seq_of(&c, &b1), Some(None));
    assert_eq!(closure_rows(&c), 3, "every verified closure is kept");
}

#[test]
fn a_rotation_closure_drops_the_held_deltas_above_it() {
    let c = conn();
    seeded(&c);
    let b1 = author("device-b");
    let deltas = chain(&b1, 3);
    assert!(is_admitted(&admit(&c, &deltas[0])));
    assert!(matches!(admit(&c, &deltas[2]), NativeAdmission::Held { .. }));
    rotation_closure_at(&c, &group(), &b1, Some(AuthorSeq(1)));
    assert_eq!(held_rows(&c), 0);
}

/// Rotation alone closes nothing: a replica restored from a backup rotates and
/// keeps receiving the deltas its previous incarnation wrote after the backup.
#[test]
fn a_plain_rotation_closes_nothing() {
    let c = conn();
    seeded(&c);
    let old =
        crate::author_incarnation::ensure_incarnation(&c, &environment("device-b")).unwrap().author;
    let deltas = chain(&old, 2);
    for delta in &deltas {
        publish(&c, &old, &device_key(2), delta.clone());
    }

    crate::author_incarnation::rotate_incarnation(
        &c,
        yadorilink_replica_domain::author::IncarnationMintReason::Restore,
    )
    .unwrap();
    assert_eq!(unexported_rotation_cutoff(&c, &group(), &old), None);
    assert!(!crate::native_store::is_closed(&c, &group(), &old).unwrap());
    assert_eq!(closure_rows(&c), 0);
}

/// The closure a bundle carries is the one the rotation signed: the row is
/// upgraded in place and the author closes.
#[test]
fn receiving_the_closure_inside_its_bundle_upgrades_the_rotation_row() {
    let b1 = author("device-b");
    let deltas = chain(&b1, 1);
    let sealer = conn();
    seeded(&sealer);
    publish(&sealer, &b1, &device_key(2), deltas[0].clone());
    close_author(&sealer, &group(), &b1);
    let holder = holder_with_rotation(&b1, Some(&deltas[0]));
    assert_eq!(unexported_rotation_cutoff(&holder, &group(), &b1), Some(Some(AuthorSeq(1))));

    join_bundle(built(&sealer), &holder).unwrap();

    assert_eq!(
        unexported_rotation_cutoff(&holder, &group(), &b1),
        None,
        "now carried with its bundle"
    );
    assert_eq!(closure_rows(&holder), 1);
    assert!(crate::native_store::is_closed(&holder, &group(), &b1).unwrap());
    assert_eq!(roots_of(&holder), roots_of(&sealer));
    let late = chain(&b1, 2).remove(1);
    assert!(matches!(admit(&holder, &late), NativeAdmission::AuthorClosed { .. }));
}

#[test]
fn delivering_the_closure_with_its_bundle_upgrades_a_rotation_row() {
    let c = conn();
    seeded(&c);
    let b1 = author("device-b");
    assert!(is_admitted(&admit(&c, &chain(&b1, 1)[0])));
    rotation_closure_at(&c, &group(), &b1, Some(AuthorSeq(1)));
    close_author(&c, &group(), &b1);
    assert_eq!(unexported_rotation_cutoff(&c, &group(), &b1), None);
    assert!(crate::native_store::is_closed(&c, &group(), &b1).unwrap());
}

/// The rotation cutoff is larger than the shared one: the lower cutoff wins, and the
/// rotation closure stays as the evidence of what this device signed.
#[test]
fn a_shared_cutoff_below_the_rotation_closure_wins_and_the_rotation_row_stays() {
    let (_ahead, bundle, b1) = ahead_of_a_cutoff();
    let holder = holder_with_rotation(&b1, Some(&chain(&b1, 2)[1]));

    let outcome = join_bundle(bundle, &holder);

    assert_eq!(name_of(&outcome), "Installed", "{outcome:?}");
    assert_eq!(unexported_rotation_cutoff(&holder, &group(), &b1), Some(Some(AuthorSeq(2))));
    assert!(crate::native_store::is_closed(&holder, &group(), &b1).unwrap());
    assert_eq!(cutoff_seq_of(&holder, &b1), Some(Some(1)));
}

// --- a join never keeps a closure the checkpoint disagrees with ----------------------------

/// A sealer that holds `who` through `count` deltas and, when `closed`, closes it.
fn sealer_holding(who: &AuthorId, count: u64, closed: bool) -> Connection {
    let sealer = conn();
    seeded(&sealer);
    for delta in chain(who, count) {
        publish(&sealer, who, &device_key(seed_of(who)), delta);
    }
    if closed {
        close_author(&sealer, &group(), who);
    }
    sealer
}

/// A replica that holds no native state of the group, only a rotation closure of `who` at
/// `cutoff` (`None`: before its first delta). The closures outlive a rebootstrap's clear,
/// so this is the replica a checkpoint is checked against.
fn holder_with_rotation(who: &AuthorId, cutoff: Option<&NativeDelta>) -> Connection {
    let holder = conn();
    seeded(&holder);
    native_closure::record_rotation_closure(&holder, &own_closure(who, cutoff)).unwrap();
    holder
}

/// The same with a closure that came inside a bundle.
fn holder_with_bundle_closure(who: &AuthorId, cutoff: Option<&NativeDelta>) -> Connection {
    let holder = conn();
    seeded(&holder);
    close_at(&holder, who, cutoff);
    holder
}

/// Everything a refused join must leave alone.
fn untouched(c: &Connection, who: &AuthorId) -> impl PartialEq + std::fmt::Debug {
    (
        roots_of(c),
        crate::native_store::load_state(c, &group()).unwrap(),
        crate::native_store::load_frontier(c, &group()).unwrap(),
        crate::native_closure::load_closed_authors(c, &group()).unwrap(),
        unexported_rotation_cutoff(c, &group(), who),
        crate::native_store::is_closed(c, &group(), who).unwrap(),
        held_rows(c),
    )
}

fn refused_and_untouched(
    bundle: NativeBootstrap,
    holder: &Connection,
    who: &AuthorId,
) -> CheckpointError {
    let before = untouched(holder, who);
    let refusal = join_bundle(bundle, holder).expect_err("the join must be refused");
    assert!(before == untouched(holder, who), "a refused join must change nothing");
    refusal
}

#[test]
fn a_bundle_cannot_lift_a_locally_retired_author_above_its_stored_cutoff() {
    let b1 = author("device-b");
    // No record for the author in the bundle, and it is further along there.
    let sealer = sealer_holding(&b1, 2, false);
    let holder = holder_with_bundle_closure(&b1, Some(&chain(&b1, 1)[0]));

    let refusal = refused_and_untouched(built(&sealer), &holder, &b1);

    assert!(
        matches!(&refusal, CheckpointError::RetiredAuthorLifted { author, cutoff: Some(1), target: 2 } if *author == b1),
        "{refusal:?}"
    );
}

#[test]
fn a_bundle_cannot_lift_a_locally_retired_author_with_a_later_cutoff_of_its_own() {
    let b1 = author("device-b");
    let sealer = sealer_holding(&b1, 2, true);
    let holder = holder_with_bundle_closure(&b1, Some(&chain(&b1, 1)[0]));

    let refusal = refused_and_untouched(built(&sealer), &holder, &b1);

    assert_eq!(name_of(&Err(refusal)), "RetiredAuthorLifted");
}

#[test]
fn a_bundle_that_matches_the_local_retirement_still_joins() {
    let b1 = author("device-b");
    let sealer = sealer_holding(&b1, 1, false);
    let holder = holder_with_bundle_closure(&b1, Some(&chain(&b1, 1)[0]));

    let outcome = join_bundle(built(&sealer), &holder);

    assert_eq!(name_of(&outcome), "Installed", "{outcome:?}");
    assert!(crate::native_store::is_closed(&holder, &group(), &b1).unwrap());
}

#[test]
fn a_bundle_cannot_lift_an_author_above_its_rotation_closure() {
    let b1 = author("device-b");
    let sealer = sealer_holding(&b1, 3, false);
    let holder = holder_with_rotation(&b1, Some(&chain(&b1, 1)[0]));

    let refusal = refused_and_untouched(built(&sealer), &holder, &b1);

    assert!(
        matches!(&refusal, CheckpointError::RetiredAuthorLifted { author, cutoff: Some(1), target: 3 } if *author == b1),
        "{refusal:?}"
    );
}

#[test]
fn a_bundle_closing_an_author_later_than_its_rotation_closure_is_refused_too() {
    let b1 = author("device-b");
    let sealer = sealer_holding(&b1, 3, true);
    let holder = holder_with_rotation(&b1, Some(&chain(&b1, 1)[0]));

    let refusal = refused_and_untouched(built(&sealer), &holder, &b1);

    assert_eq!(name_of(&Err(refusal)), "RetiredAuthorLifted");
    assert_eq!(unexported_rotation_cutoff(&holder, &group(), &b1), Some(Some(AuthorSeq(1))));
}

#[test]
fn a_rotation_closure_before_the_first_delta_refuses_any_bundle_entry_of_the_author() {
    let b1 = author("device-b");
    let sealer = sealer_holding(&b1, 1, false);
    let holder = holder_with_rotation(&b1, None);

    let refusal = refused_and_untouched(built(&sealer), &holder, &b1);

    assert!(
        matches!(&refusal, CheckpointError::RetiredAuthorLifted { author, cutoff: None, target: 1 } if *author == b1),
        "{refusal:?}"
    );
}

// --- held deltas that depend on a delta of a closed incarnation ---------------------------------

/// A delta of `who` that removes the dot of `dependency` (so it waits for it).
fn depending_on(
    who: &AuthorId,
    seq: u64,
    prev: Option<DeltaHash>,
    dependency: &NativeDelta,
) -> NativeDelta {
    let mut delta = put_delta(who, seq, prev, &format!("d{seq}"), 1);
    delta.ops[0].removes.push(HeadRef {
        dot: Dot { author: dependency.author.clone(), seq: dependency.seq },
        provenance: dependency.delta_hash(),
    });
    delta.sign(&device_key(seed_of(who)));
    delta
}

#[test]
fn a_fence_drops_the_held_deltas_of_others_that_wait_on_the_swept_range() {
    let c = conn();
    seeded(&c);
    let (b1, c1) = (author("device-b"), author("device-c"));
    let b = chain(&b1, 3);
    assert!(is_admitted(&admit(&c, &b[0])));
    let waiting = depending_on(&c1, 1, None, &b[2]);
    let behind_it = depending_on(&c1, 2, Some(waiting.delta_hash()), &b[0]);
    assert!(matches!(admit(&c, &waiting), NativeAdmission::Held { .. }));
    assert!(matches!(admit(&c, &behind_it), NativeAdmission::Held { .. }));
    let before = crate::native_closure::unservable_holds_dropped();

    rotation_closure_at(&c, &group(), &b1, Some(AuthorSeq(1)));

    assert_eq!(held_rows(&c), 0, "nothing can ever release these holds");
    assert!(crate::native_closure::unservable_holds_dropped() >= before + 2);
}

#[test]
fn a_retirement_drops_the_held_deltas_of_others_that_wait_on_the_swept_range() {
    let c = conn();
    seeded(&c);
    let (b1, c1) = (author("device-b"), author("device-c"));
    let b = chain(&b1, 3);
    assert!(is_admitted(&admit(&c, &b[0])));
    assert!(matches!(admit(&c, &depending_on(&c1, 1, None, &b[2])), NativeAdmission::Held { .. }));

    close_at(&c, &b1, Some(&b[0]));

    assert_eq!(held_rows(&c), 0);
}

#[test]
fn a_delta_waiting_below_the_cutoff_stays_held() {
    let c = conn();
    seeded(&c);
    let (b1, c1) = (author("device-b"), author("device-c"));
    let b = chain(&b1, 3);
    assert!(is_admitted(&admit(&c, &b[0])));
    assert!(matches!(admit(&c, &depending_on(&c1, 1, None, &b[1])), NativeAdmission::Held { .. }));

    rotation_closure_at(&c, &group(), &b1, Some(AuthorSeq(2)));

    assert_eq!(held_rows(&c), 1, "b1/2 can still arrive");
}

#[test]
fn a_delta_that_waits_on_a_closed_incarnations_range_is_refused_on_arrival() {
    let c = conn();
    seeded(&c);
    let (b1, c1) = (author("device-b"), author("device-c"));
    let b = chain(&b1, 3);
    assert!(is_admitted(&admit(&c, &b[0])));
    rotation_closure_at(&c, &group(), &b1, Some(AuthorSeq(1)));

    let outcome = admit(&c, &depending_on(&c1, 1, None, &b[2]));

    assert_eq!(
        outcome,
        NativeAdmission::UnservableDependency {
            dependency: Dot { author: b1.clone(), seq: AuthorSeq(3) }
        }
    );
    assert_eq!(held_rows(&c), 0);
    let allowed = admit(&c, &depending_on(&c1, 1, None, &b[0]));
    assert!(is_admitted(&allowed) || matches!(allowed, NativeAdmission::Held { .. }));
}

/// The closed author's hold goes through a release, not a sweep: a retirement
/// row written without one, then the predecessor of the held delta arrives.
#[test]
fn a_release_that_drops_a_closed_hold_drops_what_waited_on_it() {
    let c = conn();
    seeded(&c);
    let (b1, c1) = (author("device-b"), author("device-c"));
    let b = chain(&b1, 3);
    assert!(is_admitted(&admit(&c, &b[0])));
    assert!(matches!(admit(&c, &b[2]), NativeAdmission::Held { .. }));
    assert!(matches!(admit(&c, &depending_on(&c1, 1, None, &b[2])), NativeAdmission::Held { .. }));
    raw_closure(&c, &b1, Some(&b[1]));

    assert!(is_admitted(&admit(&c, &b[1])));

    assert_eq!(held_rows(&c), 0);
}

// --- the closure proof --------------------------------------------------------------------

use crate::native_closure::{self, ClosureOutcome};

/// The closure `who` signs itself at the position of `cutoff`.
fn own_closure_at(
    who: &AuthorId,
    cutoff: Option<NativeAuthorFrontierEntry>,
) -> SignedAuthorClosure {
    closure_signed(who, cutoff, seed_of(who), who.device.as_str(), seed_of(who))
}

fn own_closure(who: &AuthorId, cutoff: Option<&NativeDelta>) -> SignedAuthorClosure {
    own_closure_at(who, cutoff.map(entry_of))
}

/// A replica that received a closure inside a replacement bundle.
fn deliver(
    c: &Connection,
    closure: &SignedAuthorClosure,
) -> Result<ClosureOutcome, SyncSqliteError> {
    native_closure::store_bundle_closure(c, &group(), closure, [7; 32], &Policy)
}

fn closure_rows(c: &Connection) -> i64 {
    c.query_row("SELECT COUNT(*) FROM native_author_closure WHERE group_id = ?1", [GROUP], |row| {
        row.get(0)
    })
    .unwrap()
}

fn state_closed(c: &Connection, who: &AuthorId) -> bool {
    crate::native_store::is_closed(c, &group(), who).unwrap()
}

fn cutoff_seq_of(c: &Connection, who: &AuthorId) -> Option<Option<u64>> {
    native_closure::effective_closed_cutoff(c, &group(), who)
        .unwrap()
        .map(|cutoff| cutoff.seq.map(AuthorSeq::get))
}

/// A replica holding the first `count` deltas of `who`.
fn replica_holding(who: &AuthorId, count: u64) -> Connection {
    let c = conn();
    seeded(&c);
    for delta in chain(who, count) {
        assert!(is_admitted(&admit(&c, &delta)));
    }
    c
}

#[test]
fn closure_signed_by_another_device_is_refused() {
    let b1 = author("device-b");
    let deltas = chain(&b1, 3);
    // Device C signs a closure of B's incarnation with its own key and its own
    // authorization; and again with B's genuine authorization attached to a
    // signature that is not B's.
    for (what, forged) in [
        (
            "own key and own authorization",
            closure_signed(&b1, Some(entry_of(&deltas[1])), 3, "device-c", 3),
        ),
        (
            "B's authorization on C's signature",
            closure_signed(&b1, Some(entry_of(&deltas[1])), 3, "device-b", 2),
        ),
    ] {
        let c = replica_holding(&b1, 3);
        let refused = deliver(&c, &forged);
        assert!(matches!(refused, Err(SyncSqliteError::ClosureRefused(_))), "{what}: {refused:?}");
        assert_eq!(closure_rows(&c), 0, "{what}: a refused closure left a row");
        assert_eq!(cutoff_seq_of(&c, &b1), None, "{what}: the forged closure gates admission");
        assert!(!state_closed(&c, &b1), "{what}");
    }
}

#[test]
fn a_closure_for_another_group_or_with_a_forged_cutoff_is_refused() {
    let b1 = author("device-b");
    let deltas = chain(&b1, 3);
    let c = replica_holding(&b1, 3);
    let mut other_group = own_closure(&b1, Some(&deltas[1]));
    other_group.closure.group_id = FolderGroupId("elsewhere".into());
    assert!(matches!(deliver(&c, &other_group), Err(SyncSqliteError::ClosureRefused(_))));
    let mut moved = own_closure(&b1, Some(&deltas[1]));
    moved.closure.cutoff = Some(entry_of(&deltas[0]));
    assert!(matches!(deliver(&c, &moved), Err(SyncSqliteError::ClosureRefused(_))));
    assert_eq!(closure_rows(&c), 0);
}

#[test]
fn closure_lower_seq_wins_in_any_order() {
    let b1 = author("device-b");
    let deltas = chain(&b1, 6);
    let closures = [
        own_closure(&b1, Some(&deltas[4])),
        own_closure(&b1, Some(&deltas[1])),
        own_closure(&b1, None),
    ];
    let expected = [Some(5u64), Some(2), None];
    // Every order of any two or all three: the lowest cutoff wins, `None` lowest.
    for order in [
        vec![0, 1, 2],
        vec![0, 2, 1],
        vec![1, 0, 2],
        vec![1, 2, 0],
        vec![2, 0, 1],
        vec![2, 1, 0],
        vec![0, 1],
        vec![1, 0],
    ] {
        let c = conn();
        seeded(&c);
        for index in &order {
            deliver(&c, &closures[*index]).unwrap();
        }
        let lowest = order.iter().map(|index| expected[*index]).min().unwrap();
        assert_eq!(cutoff_seq_of(&c, &b1), Some(lowest), "order {order:?}");
        assert_eq!(closure_rows(&c), order.len() as i64, "every verified closure is kept");
        assert!(
            native_closure::needs_rebootstrap(&c, &group()).unwrap().is_empty(),
            "order {order:?}: no frontier is above any cutoff"
        );
    }
}

#[test]
fn closure_same_seq_same_tip_is_idempotent() {
    let b1 = author("device-b");
    let deltas = chain(&b1, 3);
    let c = replica_holding(&b1, 2);
    assert_eq!(deliver(&c, &own_closure(&b1, Some(&deltas[1]))).unwrap(), ClosureOutcome::Stored);
    assert_eq!(
        deliver(&c, &own_closure(&b1, Some(&deltas[1]))).unwrap(),
        ClosureOutcome::AlreadyHeld
    );
    assert_eq!(closure_rows(&c), 1);
    assert!(state_closed(&c, &b1), "the frontier is at the cutoff, so the author is closed");
}

#[test]
fn closure_same_seq_different_tip_is_a_closure_fork() {
    let b1 = author("device-b");
    let deltas = chain(&b1, 4);
    let c = replica_holding(&b1, 1);
    let fork_tip = NativeAuthorFrontierEntry { seq: AuthorSeq(2), tip: DeltaHash([0xAB; 32]) };
    assert_eq!(deliver(&c, &own_closure(&b1, Some(&deltas[1]))).unwrap(), ClosureOutcome::Stored);
    let second = deliver(&c, &own_closure_at(&b1, Some(fork_tip))).unwrap();
    assert_eq!(second, ClosureOutcome::Fork);
    // Neither is installed as the author's state, both rows are the evidence.
    assert_eq!(closure_rows(&c), 2);
    assert!(!state_closed(&c, &b1));
    let stands = native_closure::needs_rebootstrap(&c, &group()).unwrap();
    assert_eq!(stands.len(), 1, "{stands:?}");
    assert!(stands[0].fork, "{stands:?}");
    // The sequence up to the forked one is judged as before; above it nothing.
    assert!(is_admitted(&admit(&c, &deltas[1])) || frontier_seq(&c, &b1) == Some(2));
    assert!(matches!(admit(&c, &deltas[2]), NativeAdmission::AuthorClosed { .. }));
    assert!(matches!(admit(&c, &deltas[3]), NativeAdmission::AuthorClosed { .. }));
    assert_eq!(frontier_seq(&c, &b1), Some(2));
    assert!(!state_closed(&c, &b1), "a fork never closes the author");
}

#[test]
fn closure_fork_refuses_the_authors_deltas_above_the_seq() {
    let b1 = author("device-b");
    let deltas = chain(&b1, 4);
    let c = conn();
    seeded(&c);
    let tip_a = NativeAuthorFrontierEntry { seq: AuthorSeq(2), tip: DeltaHash([1; 32]) };
    let tip_b = NativeAuthorFrontierEntry { seq: AuthorSeq(2), tip: DeltaHash([2; 32]) };
    deliver(&c, &own_closure_at(&b1, Some(tip_a))).unwrap();
    assert_eq!(deliver(&c, &own_closure_at(&b1, Some(tip_b))).unwrap(), ClosureOutcome::Fork);
    assert_eq!(cutoff_seq_of(&c, &b1), Some(Some(2)));
    assert!(matches!(admit(&c, &deltas[2]), NativeAdmission::AuthorClosed { .. }));
    assert!(matches!(admit(&c, &deltas[3]), NativeAdmission::AuthorClosed { .. }));
}

#[test]
fn delta_at_the_cutoff_seq_with_another_hash_than_the_closure_tip_is_a_closure_fork() {
    let b1 = author("device-b");
    let deltas = chain(&b1, 2);
    let c = replica_holding(&b1, 1);
    // The closure names a different second delta than the one that arrives.
    let other = NativeAuthorFrontierEntry { seq: AuthorSeq(2), tip: DeltaHash([0xCD; 32]) };
    assert_eq!(deliver(&c, &own_closure_at(&b1, Some(other))).unwrap(), ClosureOutcome::Stored);
    let outcome = admit(&c, &deltas[1]);
    assert_eq!(outcome, NativeAdmission::ClosureFork { author: b1.clone(), seq: AuthorSeq(2) });
    assert_eq!(frontier_seq(&c, &b1), Some(1), "nothing was admitted");
}

#[test]
fn store_install_refuses_a_delta_above_the_closure_cutoff_without_admission() {
    let b1 = author("device-b");
    let deltas = chain(&b1, 6);
    let c = replica_holding(&b1, 3);
    deliver(&c, &own_closure(&b1, Some(&deltas[2]))).unwrap();
    // The store-level install, bypassing admission.
    let direct = crate::native_store::install_verified_delta(
        &c,
        &group(),
        &deltas[3],
        &device_key(seed_of(&b1)).verifying_key(),
    );
    assert!(direct.is_err(), "the store installed a delta above the cutoff: {direct:?}");
    assert_eq!(frontier_seq(&c, &b1), Some(3));
}

#[test]
fn admission_refuses_a_gap_above_the_cutoff_and_a_dependency_on_it() {
    let b1 = author("device-b");
    let deltas = chain(&b1, 6);
    let c = replica_holding(&b1, 3);
    deliver(&c, &own_closure(&b1, Some(&deltas[2]))).unwrap();
    // A gap above the cutoff is refused outright, never parked.
    assert!(matches!(admit(&c, &deltas[5]), NativeAdmission::AuthorClosed { .. }));
    assert_eq!(held_rows(&c), 0);
    // A delta that depends on a dot above the cutoff can never be admitted.
    let mut dependent = put_delta_of(&author("device-d"), 1, None, "dep");
    dependent.ops[0].removes.push(HeadRef {
        dot: Dot { author: b1.clone(), seq: AuthorSeq(5) },
        provenance: deltas[4].delta_hash(),
    });
    dependent.sign(&device_key(4));
    assert!(matches!(admit(&c, &dependent), NativeAdmission::UnservableDependency { .. }));
}

fn put_delta_of(who: &AuthorId, seq: u64, prev: Option<DeltaHash>, path: &str) -> NativeDelta {
    put_delta(who, seq, prev, path, 1)
}

#[test]
fn a_delayed_old_incarnation_delta_cannot_resurrect_a_file_at_a_third_replica() {
    let b1 = author("device-b");
    let key = device_key(seed_of(&b1));
    // B's old incarnation puts `f`, then removes it, and later (delayed) puts it again.
    let mut put = put_delta(&b1, 1, None, "f", 1);
    put.sign(&key);
    let mut remove = put_delta(&b1, 2, Some(put.delta_hash()), "g", 2);
    remove.ops.push(DeltaOp {
        path: SyncPath("f".into()),
        removes: vec![HeadRef {
            dot: Dot { author: b1.clone(), seq: AuthorSeq(1) },
            provenance: put.delta_hash(),
        }],
        put: None,
    });
    remove.sign(&key);
    let mut delayed = put_delta(&b1, 3, Some(remove.delta_hash()), "f", 3);
    delayed.sign(&key);

    // The third replica holds B's first two deltas and learns the closure.
    let third = conn();
    seeded(&third);
    assert!(is_admitted(&admit(&third, &put)));
    assert!(is_admitted(&admit(&third, &remove)));
    deliver(&third, &own_closure(&b1, Some(&remove))).unwrap();

    let outcome = admit(&third, &delayed);
    assert!(matches!(outcome, NativeAdmission::AuthorClosed { .. }), "{outcome:?}");
    let state = crate::native_store::load_state(&third, &group()).unwrap();
    assert!(!state.heads.contains_key(&SyncPath("f".into())), "the removed file came back");
}

#[test]
fn replica_above_a_closure_cutoff_must_rebootstrap() {
    let b1 = author("device-b");
    let deltas = chain(&b1, 7);
    let c = replica_holding(&b1, 5);
    assert_eq!(deliver(&c, &own_closure(&b1, Some(&deltas[2]))).unwrap(), ClosureOutcome::Stored);
    // It cannot be installed as the author's state: the replica is past it.
    assert!(!state_closed(&c, &b1));
    let needs = native_closure::needs_rebootstrap(&c, &group()).unwrap();
    assert_eq!(needs.len(), 1, "{needs:?}");
    assert_eq!(needs[0].author, b1);
    assert_eq!(needs[0].cutoff_seq, Some(AuthorSeq(3)));
    assert_eq!(needs[0].local_seq, Some(AuthorSeq(5)));
    assert!(!needs[0].fork);
    // The verified closure gates admission at once, and the derived answer is
    // the same on a second read: nothing in memory decides it.
    assert!(matches!(admit(&c, &deltas[5]), NativeAdmission::AuthorClosed { .. }));
    assert!(matches!(admit(&c, &deltas[6]), NativeAdmission::AuthorClosed { .. }));
    assert_eq!(native_closure::needs_rebootstrap(&c, &group()).unwrap(), needs);
    assert_eq!(frontier_seq(&c, &b1), Some(5));
}

#[test]
fn closure_with_local_a5_and_cutoff_a10_admits_a6_to_a10_and_refuses_a11() {
    let a = author("device-a");
    let deltas = chain(&a, 11);
    let c = replica_holding(&a, 5);
    deliver(&c, &own_closure(&a, Some(&deltas[9]))).unwrap();
    assert!(!state_closed(&c, &a), "below the cutoff the author stays open");
    assert_eq!(frontier_seq(&c, &a), Some(5), "the frontier is never advanced to the cutoff");
    assert!(native_closure::needs_rebootstrap(&c, &group()).unwrap().is_empty());
    for delta in &deltas[5..9] {
        assert!(is_admitted(&admit(&c, delta)));
        assert!(!state_closed(&c, &a));
    }
    assert!(is_admitted(&admit(&c, &deltas[9])));
    assert!(state_closed(&c, &a), "reaching the cutoff tip closes the author");
    assert!(matches!(admit(&c, &deltas[10]), NativeAdmission::AuthorClosed { .. }));
}

#[test]
fn closure_arriving_before_the_deltas_and_after_the_deltas_converge_to_the_same_state() {
    let a = author("device-a");
    let deltas = chain(&a, 3);
    let closure = own_closure(&a, Some(&deltas[2]));
    let before = conn();
    seeded(&before);
    deliver(&before, &closure).unwrap();
    for delta in &deltas {
        assert!(is_admitted(&admit(&before, delta)));
    }
    let after = replica_holding(&a, 3);
    deliver(&after, &closure).unwrap();
    for c in [&before, &after] {
        assert!(state_closed(c, &a));
        assert_eq!(frontier_seq(c, &a), Some(3));
        assert_eq!(cutoff_seq_of(c, &a), Some(Some(3)));
    }
    assert_eq!(
        crate::native_store::load_author_states(&before, &group()).unwrap(),
        crate::native_store::load_author_states(&after, &group()).unwrap()
    );
}

#[test]
fn held_delta_above_the_cutoff_is_dropped_when_the_closure_arrives() {
    let a = author("device-a");
    let deltas = chain(&a, 5);
    let c = replica_holding(&a, 1);
    assert!(matches!(admit(&c, &deltas[3]), NativeAdmission::Held { .. }));
    assert!(matches!(admit(&c, &deltas[2]), NativeAdmission::Held { .. }));
    assert_eq!(held_rows(&c), 2);
    deliver(&c, &own_closure(&a, Some(&deltas[1]))).unwrap();
    assert_eq!(held_rows(&c), 0, "holds above the cutoff can never be admitted");
}

#[test]
fn closure_before_the_first_delta_closes_an_empty_author_and_rebootstraps_a_non_empty_one() {
    let a = author("device-a");
    let empty = conn();
    seeded(&empty);
    deliver(&empty, &own_closure(&a, None)).unwrap();
    assert!(state_closed(&empty, &a));
    assert!(matches!(admit(&empty, &chain(&a, 1)[0]), NativeAdmission::AuthorClosed { .. }));

    let c = replica_holding(&a, 1);
    deliver(&c, &own_closure(&a, None)).unwrap();
    assert!(!state_closed(&c, &a));
    let needs = native_closure::needs_rebootstrap(&c, &group()).unwrap();
    assert_eq!(needs.len(), 1, "{needs:?}");
    assert_eq!(needs[0].cutoff_seq, None);
}

#[test]
fn author_closure_row_is_its_own_evidence_and_reverifies() {
    let b1 = author("device-b");
    let deltas = chain(&b1, 2);
    let c = replica_holding(&b1, 2);
    let closure = own_closure(&b1, Some(&deltas[1]));
    deliver(&c, &closure).unwrap();
    let rows = native_closure::all_closures(&c, &group()).unwrap();
    assert_eq!(rows, vec![closure.clone()]);
    rows[0].verify(GROUP, |id, head| Policy.resolve_authority_key(id, head)).unwrap();
}

#[test]
fn author_closure_is_in_no_root() {
    let b1 = author("device-b");
    let deltas = chain(&b1, 3);
    let c = replica_holding(&b1, 3);
    let root = |c: &Connection| {
        author_state_root(&crate::native_store::load_author_states(c, &group()).unwrap())
    };
    let before = root(&c);
    native_closure::record_rotation_closure(&c, &own_closure(&b1, Some(&deltas[2]))).unwrap();
    assert_eq!(closure_rows(&c), 1);
    assert_eq!(root(&c), before, "a gating-only closure changed the author-state root");
    assert!(!state_closed(&c, &b1), "a closure that is not exportable does not close the state");
    assert_eq!(cutoff_seq_of(&c, &b1), Some(Some(3)), "but it gates admission at once");
}

#[test]
fn a_closure_is_exported_only_with_its_replacement_checkpoint() {
    let b1 = author("device-b");
    let c = conn();
    seeded(&c);
    let key = device_key(seed_of(&b1));
    let mut previous = None;
    let mut last = None;
    for seq in 1..=2 {
        let mut delta = put_delta(&b1, seq, previous, &format!("f{seq}"), 1);
        delta.sign(&key);
        previous = Some(delta.delta_hash());
        publish(&c, &b1, &key, delta.clone());
        last = Some(delta);
    }
    native_closure::record_rotation_closure(&c, &own_closure(&b1, last.as_ref())).unwrap();

    // It gates local admission, but no outward path reads it.
    assert_eq!(cutoff_seq_of(&c, &b1), Some(Some(2)));
    assert!(native_closure::closures_for_export(&c, &group()).unwrap().is_empty());
    let bundle = built(&c);
    assert!(bundle.closures.is_empty(), "a bundle carried a closure without its replacement");
    assert!(!bundle.authors.iter().any(|entry| entry.state.is_closed()));

    // Sealing the replacement checkpoint makes it exportable, with that bundle.
    native_closure::mark_replacement_checkpoint(&c, &group(), &b1, [5; 32]).unwrap();
    assert_eq!(native_closure::closures_for_export(&c, &group()).unwrap().len(), 1);
    assert!(state_closed(&c, &b1));
    let bundle = built(&c);
    assert_eq!(bundle.closures.len(), 1);
    verify_native_bootstrap(bundle, &group(), &Policy).unwrap();
}

/// A sealer whose author `b` is closed by a closure it holds, and its sealed bundle.
fn sealed_bundle_closing_b() -> (Connection, NativeBootstrap, AuthorId) {
    let (c, _a, b) = source();
    let entry = crate::native_store::frontier_entry_get(&c, &group(), &b).unwrap().unwrap();
    deliver(&c, &own_closure_at(&b, Some(entry))).unwrap();
    let bundle = built(&c);
    (c, bundle, b)
}

#[test]
fn a_bundle_carries_the_closure_of_every_closed_author_and_installs_it() {
    let (_sealer, bundle, b) = sealed_bundle_closing_b();
    assert_eq!(bundle.closures.len(), 1);
    assert_eq!(bundle.closures[0].closure.author, b);
    let fresh = conn();
    join_bundle(bundle, &fresh).unwrap();
    assert!(state_closed(&fresh, &b));
    assert_eq!(closure_rows(&fresh), 1);
    let rows = native_closure::all_closures(&fresh, &group()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(cutoff_seq_of(&fresh, &b), Some(Some(1)));
}

#[test]
fn bundle_closed_state_without_closure_is_refused() {
    let (_sealer, mut bundle, _b) = sealed_bundle_closing_b();
    bundle.closures.clear();
    assert!(verify_native_bootstrap(bundle, &group(), &Policy).is_err());
}

#[test]
fn closure_cutoff_mismatch_is_refused() {
    let (_sealer, mut bundle, b) = sealed_bundle_closing_b();
    // A genuine, self-signed closure of b, but at another cutoff than the state's.
    bundle.closures[0] = own_closure_at(
        &b,
        Some(NativeAuthorFrontierEntry { seq: AuthorSeq(1), tip: DeltaHash([0x77; 32]) }),
    );
    assert!(verify_native_bootstrap(bundle, &group(), &Policy).is_err());
}

#[test]
fn sealer_cannot_close_another_device() {
    let (_sealer, mut bundle, b) = sealed_bundle_closing_b();
    let entry = bundle.closures[0].closure.cutoff;
    // The sealer's own key, with the authorization issued to the sealer's device.
    bundle.closures[0] = closure_signed(&b, entry, 201, "sealer-device", 201);
    assert!(verify_native_bootstrap(bundle.clone(), &group(), &Policy).is_err());
    // A closure for a device that is not closed in the bundle is refused too.
    let (_c, mut stray, _b) = sealed_bundle_closing_b();
    stray.closures.push(own_closure_at(&author("device-a"), None));
    assert!(verify_native_bootstrap(stray, &group(), &Policy).is_err());
}

#[test]
fn closure_fork_in_a_bundle_fails_verification() {
    let (_sealer, mut bundle, b) = sealed_bundle_closing_b();
    let entry = bundle.closures[0].closure.cutoff.unwrap();
    let other = NativeAuthorFrontierEntry { seq: entry.seq, tip: DeltaHash([0x55; 32]) };
    bundle.closures.push(own_closure_at(&b, Some(other)));
    assert!(verify_native_bootstrap(bundle, &group(), &Policy).is_err());
}

// --- a bundle is checked against the closures already known ------------------------------

#[test]
fn a_refused_join_stores_none_of_the_bundles_closures() {
    let (sealer, _bundle, b) = sealed_bundle_closing_b();
    // The holder is ahead of the sealer for an author the sealer has never seen.
    let holder = replica_holding(&author("device-c"), 1);

    let refusal = join_bundle(built(&sealer), &holder);

    assert_eq!(name_of(&refusal), "NotEmpty");
    assert_eq!(closure_rows(&holder), 0, "a closure was activated without its bundle");
    assert!(!state_closed(&holder, &b));
    assert_eq!(cutoff_seq_of(&holder, &b), None);
}

#[test]
fn a_bundle_closure_forking_a_held_closure_is_refused() {
    let b1 = author("device-b");
    let sealer = sealer_holding(&b1, 1, true);
    let holder = conn();
    seeded(&holder);
    let other_tip = NativeAuthorFrontierEntry { seq: AuthorSeq(1), tip: DeltaHash([0x31; 32]) };
    native_closure::record_rotation_closure(&holder, &own_closure_at(&b1, Some(other_tip)))
        .unwrap();

    let refusal = refused_and_untouched(built(&sealer), &holder, &b1);

    assert!(matches!(&refusal, CheckpointError::ClosureFork { author, seq: 1 } if *author == b1));
}

#[test]
fn a_target_forking_a_known_closure_is_refused() {
    let b1 = author("device-b");
    let sealer = sealer_holding(&b1, 1, false);
    let holder = conn();
    seeded(&holder);
    let other_tip = NativeAuthorFrontierEntry { seq: AuthorSeq(1), tip: DeltaHash([0x32; 32]) };
    native_closure::record_rotation_closure(&holder, &own_closure_at(&b1, Some(other_tip)))
        .unwrap();

    let refusal = refused_and_untouched(built(&sealer), &holder, &b1);

    assert!(matches!(&refusal, CheckpointError::ClosureFork { author, seq: 1 } if *author == b1));
}

#[test]
fn a_target_below_a_known_closure_installs_and_the_author_stays_open() {
    let b1 = author("device-b");
    let sealer = sealer_holding(&b1, 1, false);
    let holder = conn();
    seeded(&holder);
    let deltas = chain(&b1, 4);
    native_closure::record_rotation_closure(&holder, &own_closure(&b1, Some(&deltas[2]))).unwrap();

    let outcome = join_bundle(built(&sealer), &holder);

    assert_eq!(name_of(&outcome), "Installed", "{outcome:?}");
    assert!(!state_closed(&holder, &b1));
    assert_eq!(cutoff_seq_of(&holder, &b1), Some(Some(3)), "the closure still gates admission");
    assert!(is_admitted(&admit(&holder, &deltas[1])));
    assert!(is_admitted(&admit(&holder, &deltas[2])));
    assert!(matches!(admit(&holder, &deltas[3]), NativeAdmission::AuthorClosed { .. }));
}

#[test]
fn a_target_closed_at_a_known_closure_installs_closed() {
    let b1 = author("device-b");
    let sealer = sealer_holding(&b1, 2, true);
    let holder = conn();
    seeded(&holder);
    let deltas = chain(&b1, 2);
    native_closure::record_rotation_closure(&holder, &own_closure(&b1, Some(&deltas[1]))).unwrap();

    let outcome = join_bundle(built(&sealer), &holder);

    assert_eq!(name_of(&outcome), "Installed", "{outcome:?}");
    assert!(state_closed(&holder, &b1));
    assert_eq!(
        unexported_rotation_cutoff(&holder, &group(), &b1),
        None,
        "now carried with its bundle"
    );
}
