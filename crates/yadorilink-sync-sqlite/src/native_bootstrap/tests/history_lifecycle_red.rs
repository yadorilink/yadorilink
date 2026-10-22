//! Specifications for the history lifecycle (rebootstrap, retirement of a
//! rotated-away incarnation, and the commitment of a closure by the signed
//! roots). Every test here describes behaviour the store has today.
//!
//! Where the operation under test does not exist yet (the rebootstrap install)
//! the test calls a small stand-in defined in this file. A stand-in does what
//! the store does today, so the assertion that follows it observes today's
//! behaviour; when the real operation exists, the stand-in is replaced by it
//! and nothing else changes.

use ed25519_dalek::VerifyingKey;

use yadorilink_replica_domain::native_state::Dot;

use super::*;

// --- helpers ---------------------------------------------------------------

pub(super) fn seed_of(device: &str) -> u8 {
    match device {
        "device-a" => 1,
        "device-b" => 2,
        "device-c" => 3,
        "device-s" => 4,
        other => panic!("no test key for {other}"),
    }
}

fn key_for(author: &AuthorId) -> Option<VerifyingKey> {
    Some(device_key(seed_of(&author.device.0)).verifying_key())
}

pub(super) fn incarnation_of(device: &str, n: u8) -> AuthorId {
    AuthorId { device: DeviceId(device.into()), incarnation: IncarnationId([n; 16]) }
}

pub(super) fn seed_versions(c: &Connection) {
    for seed in 1..=6 {
        crate::dag_store::put_file_version(c, GROUP, &version(seed)).unwrap();
    }
}

pub(super) fn rem(who: &AuthorId, seq: u64, header: DeltaHash) -> HeadRef {
    HeadRef { dot: Dot { author: who.clone(), seq: AuthorSeq(seq) }, provenance: header }
}

pub(super) fn put_op(path: &str, v: u8, removes: Vec<HeadRef>) -> DeltaOp {
    DeltaOp {
        path: SyncPath(path.into()),
        removes,
        put: Some(DeltaPut { version: version(v).version_hash }),
    }
}

pub(super) fn remove_op(path: &str, removes: Vec<HeadRef>) -> DeltaOp {
    DeltaOp { path: SyncPath(path.into()), removes, put: None }
}

/// A delta signed by the test key of `who`'s device.
pub(super) fn signed(
    who: &AuthorId,
    seq: u64,
    prev: Option<DeltaHash>,
    ops: Vec<DeltaOp>,
) -> NativeDelta {
    let mut delta = NativeDelta {
        recursive_part: None,
        group_id: group(),
        author: who.clone(),
        seq: AuthorSeq(seq),
        prev,
        ops,
        signature: [0; 64],
    };
    delta.sign(&device_key(seed_of(&who.device.0)));
    delta
}

pub(super) fn admit(c: &Connection, delta: &NativeDelta) -> NativeAdmission {
    crate::native_admission::admit_native_delta(c, &group(), delta, &key_for).unwrap()
}

pub(super) fn dots_at(c: &Connection, path: &str) -> Vec<Dot> {
    let state = crate::native_store::load_state(c, &group()).unwrap();
    state
        .heads
        .get(&SyncPath(path.into()))
        .map(|heads| heads.keys().cloned().collect())
        .unwrap_or_default()
}

pub(super) fn frontier_seq(c: &Connection, who: &AuthorId) -> Option<u64> {
    crate::native_store::load_frontier(c, &group()).unwrap().get(who).map(|entry| entry.seq.get())
}

fn is_admitted(outcome: &NativeAdmission) -> bool {
    matches!(outcome, NativeAdmission::Admitted { .. })
}

// --- stand-ins for operations that do not exist yet ---------------------------

#[derive(Debug, PartialEq, Eq)]
pub(super) enum BlockedReason {
    LocalIntentUnavailable,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RebootstrapOutcome {
    Installed,
    Blocked(BlockedReason),
    Refused(String),
}

/// The rebootstrap entry point: moves `local` onto `target`, preserving every own
/// delta the target does not cover, and runs the whole machine: preserve, install,
/// the catch-up with no peer to drain, the replay of own intent and the end of the
/// freeze.
pub(super) fn rebootstrap_to_target(
    local: &Connection,
    target: NativeBootstrap,
) -> RebootstrapOutcome {
    let area = super::rebootstrap_preserve::private_tempdir();
    let root = tempfile::tempdir().unwrap();
    match super::rebootstrap_preserve::begin_with(local, target.clone(), area.path(), &mut |_| {
        Ok(())
    }) {
        Err(crate::native_rebootstrap::BeginError::Blocked(
            crate::native_rebootstrap::BlockedReason::LocalIntentUnavailable { .. },
        )) => return RebootstrapOutcome::Blocked(BlockedReason::LocalIntentUnavailable),
        Err(other) => panic!("preserving failed: {other:?}"),
        Ok(_) => {}
    }
    match super::rebootstrap_install::install(
        local,
        area.path(),
        &super::rebootstrap_install::FsRoot::new(root.path()),
    ) {
        Ok(_) => {
            let id = crate::native_rebootstrap::rebootstrap_status(local, &group())
                .unwrap()
                .expect("the rebootstrap")
                .recovery_id;
            super::rebootstrap_replay::complete_machine(
                local,
                area.path(),
                &id,
                &super::rebootstrap_preserve::Writer,
            );
            RebootstrapOutcome::Installed
        }
        Err(crate::native_rebootstrap_install::InstallError::BundleRefused(why)) => {
            RebootstrapOutcome::Refused(why)
        }
        Err(other) => panic!("installing failed: {other:?}"),
    }
}

/// Fences `old` on the replica: nothing of it above `cutoff` is admitted until
/// its retirement is installed. `None` is before-first-delta.
fn write_old_rotation_closure(local: &Connection, old: &AuthorId, cutoff: Option<AuthorSeq>) {
    rotation_closure_at(local, &group(), old, cutoff);
}

/// `Some(cutoff)` when `old` is fenced on the replica.
fn old_rotation_closure(local: &Connection, old: &AuthorId) -> Option<Option<AuthorSeq>> {
    unexported_rotation_cutoff(local, &group(), old)
}

/// Closes `old` at its current frontier entry, which must be the cutoff the
/// closure is expected to carry: `cutoff` is that entry's seq (`None`:
/// before-first-delta, no entry).
fn close_with_cutoff(local: &Connection, old: &AuthorId, cutoff: Option<AuthorSeq>) {
    close_author(local, &group(), old);
    let (_, entry) = crate::native_closure::load_closed_authors(local, &group())
        .unwrap()
        .into_iter()
        .find(|(author, _)| author == old)
        .expect("the closure was recorded");
    assert_eq!(entry.map(|entry| entry.seq), cutoff, "the closure's cutoff");
}

// --- the scenario ---------------------------------------------------------------

/// A sealer `S` that holds `B1/1` (x = v1) and its own `S/1` (y = v3), and the
/// device `B`, which also holds the undelivered `B1/2`.
pub(super) struct Scenario {
    pub(super) sealer: Connection,
    /// B's database: its own chain `B1/1`, `B1/2` (the second authorized,
    /// published, and never delivered to `S`).
    pub(super) b: Connection,
    pub(super) b1: AuthorId,
    pub(super) h1: DeltaHash,
    /// `B1/2`.
    pub(super) undelivered: NativeDelta,
}

pub(super) fn environment(device: &str) -> crate::author_incarnation::IncarnationEnvironment {
    crate::author_incarnation::IncarnationEnvironment {
        device_id: DeviceId(device.into()),
        sidecar: None,
        machine_fingerprint: vec![7],
    }
}

/// `second` builds the ops of B's second delta from B's author and the hash of
/// its first.
pub(super) fn scenario(second: impl Fn(&AuthorId, DeltaHash) -> Vec<DeltaOp>) -> Scenario {
    let b = conn();
    let b1 =
        crate::author_incarnation::ensure_incarnation(&b, &environment("device-b")).unwrap().author;
    let sealer = conn();
    seed_versions(&b);
    seed_versions(&sealer);

    let d1 = signed(&b1, 1, None, vec![put_op("x", 1, Vec::new())]);
    let h1 = d1.delta_hash();
    publish(&b, &b1, &device_key(2), d1.clone());
    publish(&sealer, &b1, &device_key(2), d1);
    let s = incarnation_of("device-s", 1);
    publish(&sealer, &s, &device_key(4), signed(&s, 1, None, vec![put_op("y", 3, Vec::new())]));

    let undelivered = signed(&b1, 2, Some(h1), second(&b1, h1));
    publish(&b, &b1, &device_key(2), undelivered.clone());
    Scenario { sealer, b, b1, h1, undelivered }
}

// --- local intent survives a rebootstrap -----------------------------------------------

/// The body of an uncovered own delta is gone (collected). Absence of the
/// head must not be read as a delete, so the target is not installable and
/// nothing is touched.
#[test]
fn a_target_that_does_not_cover_an_own_delta_without_its_body_is_not_installable() {
    let w = scenario(|b1, h1| vec![remove_op("x", vec![rem(b1, 1, h1)])]);
    w.b.execute("DELETE FROM native_delta_bodies WHERE group_id = ?1 AND seq = 2", [GROUP])
        .unwrap();
    let before = (roots_of(&w.b), crate::native_store::load_state(&w.b, &group()).unwrap());

    let outcome = rebootstrap_to_target(&w.b, built(&w.sealer));

    assert_eq!(
        outcome,
        RebootstrapOutcome::Blocked(BlockedReason::LocalIntentUnavailable),
        "a target that leaves an own delta without its body must not be installed"
    );
    let after = (roots_of(&w.b), crate::native_store::load_state(&w.b, &group()).unwrap());
    assert!(before == after, "a blocked rebootstrap must leave the replica untouched");
}

// --- the rotated-away incarnation is fenced, then retired ------------------------------

/// A replica that has installed the target (the sealer's `B1/1`), rotated
/// away from `B1`, and re-asserted the uncovered edit as `B2/1`.
struct Rebootstrapped {
    replica: Connection,
    b1: AuthorId,
    b2: AuthorId,
    h1: DeltaHash,
    reasserted: NativeDelta,
    /// `B1/2`, the delta of the old incarnation that arrives late.
    delayed: NativeDelta,
    sealer: Connection,
}

fn rebootstrapped() -> Rebootstrapped {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    // The installed state is the target's: join it into a replica holding
    // nothing, then move to a new incarnation.
    let replica = conn();
    seed_versions(&replica);
    let mut stale_identity =
        crate::author_incarnation::ensure_incarnation(&replica, &environment("device-b")).unwrap();
    assert_ne!(stale_identity.author, w.b1);
    join_bundle(built(&w.sealer), &replica).unwrap();
    stale_identity = crate::author_incarnation::rotate_incarnation(
        &replica,
        yadorilink_replica_domain::author::IncarnationMintReason::Restore,
    )
    .unwrap();
    let b2 = stale_identity.author;
    let reasserted = signed(&b2, 1, None, vec![put_op("x", 2, vec![rem(&w.b1, 1, w.h1)])]);
    publish(&replica, &b2, &device_key(2), reasserted.clone());
    Rebootstrapped {
        replica,
        b1: w.b1,
        b2,
        h1: w.h1,
        reasserted,
        delayed: w.undelivered,
        sealer: w.sealer,
    }
}

/// Rotation does not retire and the fence is not root state: both are
/// asserted on a replica that rotated after installing the target.
#[test]
fn rotation_fences_the_old_incarnation_at_its_cutoff_without_retiring_it() {
    let r = rebootstrapped();
    let cutoff = frontier_seq(&r.replica, &r.b1).map(AuthorSeq);
    assert_eq!(cutoff, Some(AuthorSeq(1)), "the installed target covers B1 up to seq 1");

    write_old_rotation_closure(&r.replica, &r.b1, cutoff);

    assert_ne!(
        crate::author_incarnation::current_author(&r.replica).unwrap(),
        r.b1,
        "the replica signs under the new incarnation"
    );
    assert!(
        !crate::native_store::is_closed(&r.replica, &group(), &r.b1).unwrap(),
        "rotation alone must not retire the old author"
    );
    assert_eq!(
        old_rotation_closure(&r.replica, &r.b1),
        Some(cutoff),
        "the old incarnation must be fenced at its cutoff until the retirement is installed"
    );
    let outcome = admit(&r.replica, &r.delayed);
    assert!(
        !is_admitted(&outcome),
        "a delayed delta of the fenced incarnation above the cutoff was admitted: {outcome:?}"
    );
}

/// The fence adds nothing to the roots: the rebootstrapped replica and a peer
/// that installed the same checkpoint agree.
#[test]
fn the_fence_does_not_change_the_summary_roots() {
    let r = rebootstrapped();
    let peer = conn();
    seed_versions(&peer);
    join_bundle(built(&r.sealer), &peer).unwrap();
    publish(&peer, &r.b2, &device_key(2), r.reasserted.clone());
    write_old_rotation_closure(&r.replica, &r.b1, Some(AuthorSeq(1)));
    assert_eq!(roots_of(&r.replica), roots_of(&peer), "the fence must stay outside every root");
    assert_eq!(
        old_rotation_closure(&r.replica, &r.b1),
        Some(Some(AuthorSeq(1))),
        "the fence must have been written"
    );
}

/// The retirement is installed (the retire checkpoint): the old incarnation
/// stays closed above the cutoff at the rebootstrapped replica.
#[test]
fn a_delayed_old_incarnation_delta_is_refused_after_the_retirement_is_installed() {
    let r = rebootstrapped();
    close_with_cutoff(&r.replica, &r.b1, Some(AuthorSeq(1)));

    let outcome = admit(&r.replica, &r.delayed);

    assert!(
        !is_admitted(&outcome),
        "a delayed delta of the retired incarnation above its cutoff was admitted: {outcome:?}"
    );
    assert_eq!(dots_at(&r.replica, "x"), vec![Dot { author: r.b2.clone(), seq: AuthorSeq(1) }]);
}

/// A third replica that installed the retire checkpoint refuses the delayed
/// delta, and a delete of the re-asserted file stays a delete when the
/// delayed delta is delivered again.
#[test]
fn a_delayed_old_incarnation_delta_cannot_resurrect_a_file_at_a_third_replica() {
    let r = rebootstrapped();
    // The sealer retires B1 at its cutoff and seals the retire checkpoint.
    close_with_cutoff(&r.sealer, &r.b1, Some(AuthorSeq(1)));
    let third = conn();
    seed_versions(&third);
    join_bundle(built(&r.sealer), &third).unwrap();
    assert!(crate::native_store::is_closed(&third, &group(), &r.b1).unwrap());
    assert!(is_admitted(&admit(&third, &r.reasserted)));

    let first = admit(&third, &r.delayed);
    assert!(
        !is_admitted(&first),
        "the third replica admitted a delayed delta of the retired incarnation: {first:?}"
    );

    // A user deletes the re-asserted file; the delayed delta arrives again.
    let user = incarnation_of("device-c", 1);
    let delete = signed(
        &user,
        1,
        None,
        vec![remove_op("x", vec![rem(&r.b2, 1, r.reasserted.delta_hash())])],
    );
    assert!(is_admitted(&admit(&third, &delete)));
    let again = admit(&third, &r.delayed);
    assert!(!is_admitted(&again), "the delayed delta was admitted after the delete: {again:?}");
    assert!(dots_at(&third, "x").is_empty(), "the deleted file must not come back");
}

// --- a retirement cutoff refuses everything above it -----------------------------------

/// `frontier = Some(F)`: everything above `F.seq` is refused, an exact
/// duplicate at or below it is a duplicate, and no frontier row has seq 0.
#[test]
fn a_real_cutoff_refuses_above_it_and_reports_duplicates_below_it() {
    let r = rebootstrapped();
    let c = conn();
    seed_versions(&c);
    let first = signed(&r.b1, 1, None, vec![put_op("x", 1, Vec::new())]);
    assert_eq!(first.delta_hash(), r.h1);
    assert!(is_admitted(&admit(&c, &first)), "B1/1 is admitted before the retirement");
    close_with_cutoff(&c, &r.b1, Some(AuthorSeq(1)));

    let above = admit(&c, &r.delayed);
    assert!(!is_admitted(&above), "B1/2 above the cutoff was admitted: {above:?}");
    assert_eq!(frontier_seq(&c, &r.b1), Some(1), "the cutoff must not move");

    assert!(matches!(admit(&c, &first), NativeAdmission::Duplicate));

    let frontier = crate::native_store::load_frontier(&c, &group()).unwrap();
    assert!(frontier.values().all(|entry| entry.seq.get() >= 1), "no frontier entry at seq 0");
}

/// `frontier = None`: the incarnation is closed before its first delta, so
/// even its seq 1 is refused.
#[test]
fn a_before_first_delta_retirement_refuses_the_first_delta() {
    let c = conn();
    seed_versions(&c);
    let never_seen = incarnation_of("device-c", 9);
    close_with_cutoff(&c, &never_seen, None);

    let first = signed(&never_seen, 1, None, vec![put_op("w", 4, Vec::new())]);
    let outcome = admit(&c, &first);

    assert!(
        !is_admitted(&outcome),
        "the first delta of a before-first-delta retired incarnation was admitted: {outcome:?}"
    );
    assert_eq!(frontier_seq(&c, &never_seen), None, "no frontier entry, in particular none at 0");
}

/// The same retirement travels with the checkpoint: a third replica that
/// installs it refuses the incarnation's first delta too.
#[test]
fn a_before_first_delta_retirement_travels_with_the_checkpoint() {
    let r = rebootstrapped();
    let never_seen = incarnation_of("device-c", 9);
    close_with_cutoff(&r.sealer, &never_seen, None);
    let third = conn();
    seed_versions(&third);
    join_bundle(built(&r.sealer), &third).unwrap();

    assert!(
        crate::native_store::is_closed(&third, &group(), &never_seen).unwrap(),
        "the retirement of an incarnation without a frontier entry was lost in the bundle"
    );
    let first = signed(&never_seen, 1, None, vec![put_op("w", 4, Vec::new())]);
    let outcome = admit(&third, &first);
    assert!(!is_admitted(&outcome), "B/1 of the retired incarnation was admitted: {outcome:?}");
}

// --- the signed root commits the retirement --------------------------------------------

/// The author-state root commits whether an author is closed: two replicas that
/// differ only in that must not share a root, nor a sealed checkpoint.
#[test]
fn the_author_state_root_commits_whether_an_author_is_closed() {
    let (c, a, _) = source();
    let open_root = crate::native_store::author_state_root(&c, &group()).unwrap();
    let open_sealed = crate::native_store::seal_checkpoint(&c, &group(), &sealer_key()).unwrap();
    close_author(&c, &group(), &a);
    let closed_root = crate::native_store::author_state_root(&c, &group()).unwrap();
    let closed_sealed = crate::native_store::seal_checkpoint(&c, &group(), &sealer_key()).unwrap();
    assert_ne!(open_root, closed_root, "the root is the same whether the author is open or closed");
    assert_ne!(
        open_sealed.author_state_root, closed_sealed.author_state_root,
        "the sealed checkpoint cannot tell them apart"
    );
}

/// A bundle that carries an author as open where the sealer signed it closed
/// must be refused.
#[test]
fn a_bundle_with_a_forged_author_state_is_refused() {
    let (c, a, _) = source();
    close_author(&c, &group(), &a);
    let mut bundle = built(&c);
    let state = bundle.authors.iter_mut().find(|entry| entry.author == a).unwrap();
    let AuthorState::Closed { frontier: Some(entry) } = state.state else {
        panic!("a is closed at its entry")
    };
    state.state = AuthorState::Open(entry);

    let verified = verify_native_bootstrap(bundle, &group(), &Policy);

    assert!(
        verified.is_err(),
        "a bundle that claims a different author state than the one sealed was accepted"
    );
}

// --- local intent is replayed causally, not compressed per path -------------------------

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use yadorilink_replica_domain::native_state::{HeadPayload, NativeState, RemoteOp};

/// A sealer whose target holds `x = A/1 (v1)`, and a device `B` that observed
/// only `A/1` and then edited offline. With `supersede`, the sealer also holds
/// `A/2` (v4, removing `A/1`), which `B` never saw.
pub(super) struct Offline {
    pub(super) sealer: Connection,
    pub(super) b: Connection,
    pub(super) b1: AuthorId,
    pub(super) a: AuthorId,
    pub(super) a1: DeltaHash,
}

pub(super) fn offline_base(supersede: bool) -> Offline {
    let b = conn();
    let b1 =
        crate::author_incarnation::ensure_incarnation(&b, &environment("device-b")).unwrap().author;
    let sealer = conn();
    seed_versions(&b);
    seed_versions(&sealer);
    let a = incarnation_of("device-a", 1);
    let a1 = signed(&a, 1, None, vec![put_op("x", 1, Vec::new())]);
    let a1_hash = a1.delta_hash();
    publish(&sealer, &a, &device_key(1), a1.clone());
    publish(&b, &a, &device_key(1), a1);
    if supersede {
        let a2 = signed(&a, 2, Some(a1_hash), vec![put_op("x", 4, vec![rem(&a, 1, a1_hash)])]);
        publish(&sealer, &a, &device_key(1), a2);
    }
    Offline { sealer, b, b1, a, a1: a1_hash }
}

/// Authors `ops` as `B1`'s next delta and returns its hash.
fn b_authors(o: &Offline, seq: u64, prev: Option<DeltaHash>, ops: Vec<DeltaOp>) -> DeltaHash {
    let delta = signed(&o.b1, seq, prev, ops);
    let hash = delta.delta_hash();
    publish(&o.b, &o.b1, &device_key(2), delta);
    hash
}

// --- local intent survives a rebootstrap -----------------------------------------------

/// B authored `x: v1 -> v2` (authorized, undelivered); the sealer's target
/// does not cover it. After the rebootstrap the edit is in the projection
/// exactly once.
#[test]
fn rebootstrap_preserves_an_authorized_but_undelivered_put_exactly_once() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let outcome = rebootstrap_to_target(&w.b, built(&w.sealer));
    assert_eq!(outcome, RebootstrapOutcome::Installed, "the target must be installed");
    assert_eq!(
        versions_at(&w.b, "x"),
        vec![version(2).version_hash],
        "the undelivered edit must be present exactly once after the rebootstrap"
    );
}

/// B deleted `x` (authorized, undelivered). No live head of B's remains to be
/// re-asserted, so the delete survives only if its intent is carried.
#[test]
fn rebootstrap_preserves_an_authorized_but_undelivered_delete() {
    let w = scenario(|b1, h1| vec![remove_op("x", vec![rem(b1, 1, h1)])]);
    let outcome = rebootstrap_to_target(&w.b, built(&w.sealer));
    assert_eq!(outcome, RebootstrapOutcome::Installed, "the target must be installed");
    assert!(
        versions_at(&w.b, "x").is_empty(),
        "the undelivered delete must be re-asserted: x is still live"
    );
}

/// B renamed `x` to `z`: a remove at the source and a put at the destination.
#[test]
fn rebootstrap_preserves_an_undelivered_rename_source_remove() {
    let w =
        scenario(|b1, h1| vec![remove_op("x", vec![rem(b1, 1, h1)]), put_op("z", 1, Vec::new())]);
    let outcome = rebootstrap_to_target(&w.b, built(&w.sealer));
    assert_eq!(outcome, RebootstrapOutcome::Installed, "the target must be installed");
    assert!(
        versions_at(&w.b, "x").is_empty(),
        "the rename's source-side remove must be re-asserted: x is still live"
    );
    assert_eq!(versions_at(&w.b, "z"), vec![version(1).version_hash]);
}

/// B put v2 over `A/1` and then deleted its own put. The final intent is that
/// `x` is gone. Replaying only the last operation per path drops the delete
/// (the head it removes does not exist in the target) and `A/1` comes back.
#[test]
fn rebootstrap_preserves_transitive_own_intent_edit_then_delete() {
    let o = offline_base(false);
    let h1 = b_authors(&o, 1, None, vec![put_op("x", 2, vec![rem(&o.a, 1, o.a1)])]);
    b_authors(&o, 2, Some(h1), vec![remove_op("x", vec![rem(&o.b1, 1, h1)])]);
    assert!(versions_at(&o.b, "x").is_empty(), "B's own state: x is deleted");

    let outcome = rebootstrap_to_target(&o.b, built(&o.sealer));

    assert_eq!(outcome, RebootstrapOutcome::Installed, "the target must be installed");
    assert!(
        versions_at(&o.b, "x").is_empty(),
        "the delete of B's own put must be replayed through the rewritten head: A/1 came back"
    );
    assert!(dots_at(&o.b, "x").is_empty());
}

/// Put, put over the put, delete: every step removes the previous own head.
#[test]
fn rebootstrap_preserves_transitive_own_intent_put_put_delete() {
    let o = offline_base(false);
    let h1 = b_authors(&o, 1, None, vec![put_op("x", 2, vec![rem(&o.a, 1, o.a1)])]);
    let h2 = b_authors(&o, 2, Some(h1), vec![put_op("x", 3, vec![rem(&o.b1, 1, h1)])]);
    b_authors(&o, 3, Some(h2), vec![remove_op("x", vec![rem(&o.b1, 2, h2)])]);

    let outcome = rebootstrap_to_target(&o.b, built(&o.sealer));

    assert_eq!(outcome, RebootstrapOutcome::Installed, "the target must be installed");
    assert!(
        versions_at(&o.b, "x").is_empty(),
        "put, put, delete must end with x absent: the intermediate put must be replayed so the \
         delete can remove it"
    );
}

/// B's first put removed `A/1`, but the target already superseded `A/1` with
/// `A/2`, which B never saw. The removal of the external head is moot; the
/// removal of B's own head is rewritten. Final: `A/2` and B's last put, as
/// concurrent heads, and nothing else.
#[test]
fn rebootstrap_replay_drops_removals_of_external_heads_that_are_not_live_in_the_target() {
    let o = offline_base(true);
    let h1 = b_authors(&o, 1, None, vec![put_op("x", 2, vec![rem(&o.a, 1, o.a1)])]);
    b_authors(&o, 2, Some(h1), vec![put_op("x", 3, vec![rem(&o.b1, 1, h1)])]);

    let outcome = rebootstrap_to_target(&o.b, built(&o.sealer));

    assert_eq!(outcome, RebootstrapOutcome::Installed, "the target must be installed");
    let mut expected = vec![version(3).version_hash, version(4).version_hash];
    expected.sort();
    assert_eq!(
        versions_at(&o.b, "x"),
        expected,
        "x must hold the target's A/2 and B's last put as concurrent heads, and no intermediate"
    );
}

// The reference replay the design specifies, over the plain state. It checks the
// design claim, not the store: the head map keeps a transitive delete working and
// the last-op-per-path compression does not.

#[derive(Clone)]
struct ModelOp {
    path: &'static str,
    removes: Vec<HeadRef>,
    put: Option<u8>,
}

fn model_hash(who: &AuthorId, seq: u64) -> DeltaHash {
    let mut bytes = [0u8; 32];
    bytes[0] = who.incarnation.0[0];
    bytes[1] = seq as u8;
    DeltaHash(bytes)
}

fn model_payload(v: u8, provenance: DeltaHash) -> HeadPayload {
    HeadPayload { version: version(v).version_hash, provenance }
}

fn model_target(a: &AuthorId) -> NativeState {
    let mut state = NativeState::new();
    let op = RemoteOp {
        path: SyncPath("x".into()),
        removes: Vec::new(),
        put: Some(model_payload(1, model_hash(a, 1))),
    };
    state.receive_verified(a, AuthorSeq(1), &[op]).unwrap();
    state
}

fn live_in(state: &NativeState, path: &str, removal: &HeadRef) -> bool {
    state
        .heads
        .get(&SyncPath(path.into()))
        .and_then(|heads| heads.get(&removal.dot))
        .is_some_and(|head| head.provenance == removal.provenance)
}

/// Replays every uncovered delta in order under `new`, rewriting removals of old
/// own heads through the head map and keeping removals of external heads that
/// are live in the target.
fn replay_with_head_map(
    target: &NativeState,
    old: &AuthorId,
    new: &AuthorId,
    deltas: &[(u64, Vec<ModelOp>)],
) -> NativeState {
    let mut state = target.clone();
    let mut map: BTreeMap<Dot, HeadRef> = BTreeMap::new();
    for (index, (old_seq, ops)) in deltas.iter().enumerate() {
        let new_seq = index as u64 + 1;
        let provenance = model_hash(new, new_seq);
        let remote: Vec<RemoteOp> = ops
            .iter()
            .map(|op| RemoteOp {
                path: SyncPath(op.path.into()),
                removes: op
                    .removes
                    .iter()
                    .filter_map(|removal| {
                        if removal.dot.author == *old {
                            map.get(&removal.dot).cloned()
                        } else {
                            live_in(target, op.path, removal).then(|| removal.clone())
                        }
                    })
                    .collect(),
                put: op.put.map(|v| model_payload(v, provenance)),
            })
            .collect();
        state.receive_verified(new, AuthorSeq(new_seq), &remote).unwrap();
        map.insert(
            Dot { author: old.clone(), seq: AuthorSeq(*old_seq) },
            HeadRef { dot: Dot { author: new.clone(), seq: AuthorSeq(new_seq) }, provenance },
        );
    }
    state
}

/// The compression the first design had: only the last op per path, its removes
/// filtered to the heads the target holds.
fn replay_last_op_only(
    target: &NativeState,
    new: &AuthorId,
    deltas: &[(u64, Vec<ModelOp>)],
) -> NativeState {
    let mut state = target.clone();
    let mut last: BTreeMap<&str, &ModelOp> = BTreeMap::new();
    for (_, ops) in deltas {
        for op in ops {
            last.insert(op.path, op);
        }
    }
    for (index, (path, op)) in last.into_iter().enumerate() {
        let seq = index as u64 + 1;
        let removes: Vec<_> =
            op.removes.iter().filter(|removal| live_in(target, path, removal)).cloned().collect();
        let put = op.put.map(|v| model_payload(v, model_hash(new, seq)));
        if put.is_none() && removes.is_empty() {
            continue;
        }
        let remote = RemoteOp { path: SyncPath(path.into()), removes, put };
        state.receive_verified(new, AuthorSeq(seq), &[remote]).unwrap();
    }
    state
}

#[test]
fn the_head_map_replay_keeps_a_transitive_delete_and_last_op_compression_loses_it() {
    let a = incarnation_of("device-a", 1);
    let (old, new) = (incarnation_of("device-b", 1), incarnation_of("device-b", 2));
    let x = SyncPath("x".into());
    let a1 = HeadRef {
        dot: Dot { author: a.clone(), seq: AuthorSeq(1) },
        provenance: model_hash(&a, 1),
    };
    let b1 = HeadRef {
        dot: Dot { author: old.clone(), seq: AuthorSeq(1) },
        provenance: model_hash(&old, 1),
    };
    let deltas = vec![
        (1, vec![ModelOp { path: "x", removes: vec![a1], put: Some(2) }]),
        (2, vec![ModelOp { path: "x", removes: vec![b1], put: None }]),
    ];
    let target = model_target(&a);

    let compressed = replay_last_op_only(&target, &new, &deltas);
    assert!(compressed.heads.contains_key(&x), "last-op compression resurrects A/1 (the flaw)");

    let replayed = replay_with_head_map(&target, &old, &new, &deltas);
    assert!(!replayed.heads.contains_key(&x), "the head-map replay must leave x deleted");
    replayed.check_invariants().unwrap();
}

// --- the exact target is durable before the root is first modified -----------------------

/// The recovery directories under `area`: `<group>/<rebootstrap-id>`.
pub(super) fn recovery_dirs(area: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for group_dir in fs::read_dir(area).into_iter().flatten().flatten() {
        for id_dir in fs::read_dir(group_dir.path()).into_iter().flatten().flatten() {
            if id_dir.path().is_dir() {
                found.push(id_dir.path());
            }
        }
    }
    found.sort();
    found
}

/// The rebootstrap up to the install transaction: the target and the local intent
/// are copied to the recovery area under `area`, the paths are held, the
/// originals that may not be re-authored leave `root`, and the process dies
/// before the install transaction commits.
fn run_until_quarantined(local: &Connection, target: &NativeBootstrap, root: &Path, area: &Path) {
    use super::rebootstrap_install::{install_with, FsRoot};
    super::rebootstrap_preserve::begin_with(local, target.clone(), area, &mut |_| Ok(())).unwrap();
    let crashed = install_with(
        local,
        area,
        &FsRoot::new(root),
        &super::rebootstrap_preserve::Writer,
        &mut |point| {
            use crate::native_rebootstrap_install::{InstallPoint, InstallStep};
            if point == InstallPoint::InTransaction(InstallStep::NativeStateCleared) {
                Err(crate::native_rebootstrap::Crash)
            } else {
                Ok(())
            }
        },
    );
    assert!(
        matches!(crashed, Err(crate::native_rebootstrap_install::InstallError::Crashed)),
        "{crashed:?}"
    );
}

/// The install of the stored target, from the recovery directory `dir` alone and
/// the replica's database: no bundle argument, no peer.
fn install_stored_target(local: &Connection, dir: &Path, root: &Path) -> RebootstrapOutcome {
    use super::rebootstrap_install::{install, FsRoot};
    let recovery_root = dir.parent().unwrap().parent().unwrap();
    match install(local, recovery_root, &FsRoot::new(root)) {
        Ok(_) => RebootstrapOutcome::Installed,
        Err(crate::native_rebootstrap_install::InstallError::BundleRefused(why)) => {
            RebootstrapOutcome::Refused(why)
        }
        Err(other) => RebootstrapOutcome::Refused(format!("{other:?}")),
    }
}

/// The restart with no peer to ask: the stored target is verified locally from the
/// recovery area alone, then installed.
fn resume_from_recovery_area(local: &Connection, area: &Path, root: &Path) -> RebootstrapOutcome {
    let Some(dir) = recovery_dirs(area).into_iter().next() else {
        return RebootstrapOutcome::Blocked(BlockedReason::LocalIntentUnavailable);
    };
    let stored = crate::native_rebootstrap_recovery::RecoveryArea::open_dir(&dir)
        .map_err(|e| e.to_string())
        .and_then(|a| {
            crate::native_rebootstrap::verify_target_in_area(&a, &group())
                .map(|_| ())
                .map_err(|e| e.to_string())
        });
    match stored {
        Ok(()) => install_stored_target(local, &dir, root),
        Err(refusal) => RebootstrapOutcome::Refused(refusal),
    }
}

/// The process dies after the originals were quarantined and the peer that
/// served the target is gone. The target must be resumable from the recovery
/// area: the exact bundle, fsynced and sha256-verified, was written before the
/// root was first modified.
#[test]
fn crash_after_quarantine_with_peer_gone_resumes_from_durable_target() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let root = tempfile::tempdir().unwrap();
    let area = super::rebootstrap_preserve::private_tempdir();
    fs::write(root.path().join("x"), [2]).unwrap();
    let target = built(&w.sealer);

    run_until_quarantined(&w.b, &target, root.path(), area.path());
    let Scenario { b, sealer, .. } = w;
    drop(sealer); // the peer is gone, and so is its bundle
    drop(target);

    let dirs = recovery_dirs(area.path());
    assert_eq!(dirs.len(), 1, "one recovery directory per rebootstrap; found {dirs:?}");
    let dir = &dirs[0];
    let bundle = fs::read(dir.join("target.bundle")).unwrap_or_else(|e| {
        panic!("the target bundle was not made durable before quarantine: {e}")
    });
    let recorded = fs::read_to_string(dir.join("target.bundle.sha256")).unwrap();
    assert_eq!(recorded.trim(), hex::encode(Sha256::digest(&bundle)), "recorded bundle digest");
    assert_eq!(
        resume_from_recovery_area(&b, area.path(), root.path()),
        RebootstrapOutcome::Installed,
        "with the peer gone the machine must install from the durable target"
    );
}

// --- Preserved means reconstructable from the recovery area alone ----------------------

/// The Preserving step: copies every version named by an uncovered own delta, the
/// exact delta bodies, the target and a manifest into `area`.
fn preserve_to_recovery(local: &Connection, _root: &Path, area: &Path, target: &NativeBootstrap) {
    super::rebootstrap_preserve::begin_with(local, target.clone(), area, &mut |_| Ok(())).unwrap();
}

/// B authored three uncovered deltas: two versions of `x` (the first is no
/// longer on disk) and one of `y`. After the replica database and the sync root
/// are lost, the recovery directory alone yields every version's bytes, every
/// delta body in order, and the removes of each op.
#[test]
fn preserved_is_reconstructable_from_the_recovery_area_alone() {
    let o = offline_base(false);
    let d1 = signed(&o.b1, 1, None, vec![put_op("x", 2, vec![rem(&o.a, 1, o.a1)])]);
    let h1 = d1.delta_hash();
    let d2 = signed(&o.b1, 2, Some(h1), vec![put_op("x", 3, vec![rem(&o.b1, 1, h1)])]);
    let d3 = signed(&o.b1, 3, Some(d2.delta_hash()), vec![put_op("y", 4, Vec::new())]);
    let deltas = [d1, d2, d3];
    for d in &deltas {
        publish(&o.b, &o.b1, &device_key(2), d.clone());
    }
    let root = tempfile::tempdir().unwrap();
    let area = super::rebootstrap_preserve::private_tempdir();
    fs::write(root.path().join("x"), [3]).unwrap();
    fs::write(root.path().join("y"), [4]).unwrap();

    preserve_to_recovery(&o.b, root.path(), area.path(), &built(&o.sealer));
    let Offline { b, .. } = o;
    drop(b); // the replica database is lost
    drop(root); // and so is the sync root

    let dirs = recovery_dirs(area.path());
    assert_eq!(dirs.len(), 1, "one recovery directory per rebootstrap; found {dirs:?}");
    let dir = &dirs[0];
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("manifest.json")).expect("manifest.json"))
            .expect("the manifest parses");
    let order: Vec<String> = manifest["delta_order"]
        .as_array()
        .expect("the manifest records the delta order")
        .iter()
        .map(|hash| hash.as_str().unwrap().to_string())
        .collect();
    let expected_order: Vec<String> =
        deltas.iter().map(|d| hex::encode(d.delta_hash().0)).collect();
    assert_eq!(order, expected_order, "the old delta ordering");
    assert!(manifest["target_checkpoint_hash"].is_string(), "the target checkpoint hash");
    assert!(dir.join("target.bundle").is_file(), "the target bundle reference");

    for delta in &deltas {
        let name = format!("deltas/{}.bin", hex::encode(delta.delta_hash().0));
        let bytes = fs::read(dir.join(&name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(bytes, delta.to_wire_bytes(), "{name} must hold the exact signed body");
        let decoded = NativeDelta::from_wire_bytes(&bytes).unwrap();
        assert!(decoded.ops == delta.ops, "{name}: ops, puts and removes survive the round trip");
    }
    for seed in [2u8, 3, 4] {
        let name = format!("versions/{}", hex::encode(version(seed).version_hash.0));
        let bytes = fs::read(dir.join(&name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            bytes,
            vec![seed],
            "{name} must hold the version's bytes, even when the path \
            now holds a later one"
        );
    }
    let items = manifest["items"].as_array().expect("the manifest classifies every item");
    assert!(
        items.iter().all(|item| item["reassertable"].is_boolean()),
        "every item carries its planning-time classification"
    );
}

// --- reassertability is a planning classification, not authorization -----------------

// --- the replay: its unit, its order, its attributes ------------------------------------
//
// The stand-ins below cut and order the preserved deltas the way a first
// implementation would. Each test then states what the replay must do instead.

use yadorilink_replica_domain::native_frontier::{NativeAuthorFrontier, NativeAuthorFrontierEntry};

// --- the durable target is verified locally ----------------------------------------------

/// A policy view that answers from material stored with the target: the authority key, and
/// the grants it recorded when the target was accepted.
struct StoredPolicy {
    writer: bool,
}

impl NativeSealPolicy for StoredPolicy {
    fn resolve_authority_key(
        &self,
        key_id: &[u8; 32],
        _head: &[u8; 32],
    ) -> Option<ed25519_dalek::VerifyingKey> {
        (*key_id == fingerprint_signing_key(&authority_key().verifying_key()))
            .then(|| authority_key().verifying_key())
    }

    fn writer_at_policy_point(
        &self,
        _device: &str,
        _signing_key_fingerprint: &[u8; 32],
        _point: &yadorilink_replica_domain::native_checkpoint_seal::SealPolicyPoint,
    ) -> bool {
        self.writer
    }
}

/// The restart with no peer and no authority: the target is re-verified from what
/// the recovery area stored, whatever the live policy says, then installed.
fn resume_verifying_locally(local: &Connection, area: &Path, root: &Path) -> RebootstrapOutcome {
    resume_from_recovery_area(local, area, root)
}

/// Before the root is first modified the area holds the exact bundle, the checkpoint
/// hash, the seal evidence, the public verification material and a local verification record
/// that says the target may be used for the destructive install. After a restart the target
/// is re-verified from that alone, with no peer and no authority online, and a target that
/// was accepted is not rejected because the policy moved on since.
#[test]
fn resume_after_quarantine_verifies_the_stored_target_locally_with_no_peer_and_no_authority() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let root = tempfile::tempdir().unwrap();
    let area = super::rebootstrap_preserve::private_tempdir();
    fs::write(root.path().join("x"), [2]).unwrap();
    let target = built(&w.sealer);
    let bytes = crate::native_bootstrap_codec::encode_recovery_bundle(&target).unwrap();

    run_until_quarantined(&w.b, &target, root.path(), area.path());
    let Scenario { sealer, b, .. } = w;
    drop(sealer);
    drop(target);

    // What the store can do today: the stored bytes verify under the stored material alone,
    // and do not verify under a policy that has moved on, so acceptance must be recorded.
    let decoded = crate::native_bootstrap_codec::decode_recovery_bundle(&bytes).unwrap();
    verify_native_bootstrap(decoded.clone(), &group(), &StoredPolicy { writer: true })
        .expect("the stored bytes verify from the stored material alone");
    assert!(
        verify_native_bootstrap(decoded, &group(), &StoredPolicy { writer: false }).is_err(),
        "verification always consults the policy it is given"
    );

    let dirs = recovery_dirs(area.path());
    assert_eq!(dirs.len(), 1, "one recovery directory per rebootstrap; found {dirs:?}");
    let dir = &dirs[0];
    assert!(
        dir.join("target.verification.json").is_file(),
        "no local verification record was made durable with the target"
    );
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("target.verification.json")).unwrap()).unwrap();
    assert_eq!(record["install_permitted"], true, "the record permits the destructive install");
    assert!(record["checkpoint_hash"].is_string(), "the record names the checkpoint");
    assert!(dir.join("verification-material").is_dir(), "the public verification material");

    assert_eq!(
        resume_verifying_locally(&b, area.path(), root.path()),
        RebootstrapOutcome::Installed,
        "with no peer and no authority the machine must return to Installing"
    );
    assert_eq!(
        resume_verifying_locally(&b, area.path(), root.path()),
        RebootstrapOutcome::Installed,
        "a target accepted before the quarantine is not invalidated by later policy state"
    );
}

// --- replayed attributes are recomputed --------------------------------------------------

// --- retiring needs a sealer ----------------------------------------------------------------

// --- which checkpoint is the target --------------------------------------------------------

struct TargetCandidate {
    checkpoint_id: [u8; 32],
    installed_at: i64,
    frontier: NativeAuthorFrontier,
}

fn entry(seq: u64, tip: u8) -> NativeAuthorFrontierEntry {
    NativeAuthorFrontierEntry { seq: AuthorSeq(seq), tip: DeltaHash([tip; 32]) }
}

/// The production rule over the test candidates. The adoption time is carried by
/// the test candidate only to show that it is not an input.
fn rebootstrap_target(
    candidates: &[TargetCandidate],
    own: &BTreeMap<AuthorId, Vec<DeltaHash>>,
) -> Option<[u8; 32]> {
    let candidates: Vec<crate::native_rebootstrap::TargetCandidate> = candidates
        .iter()
        .map(|c| crate::native_rebootstrap::TargetCandidate {
            checkpoint_id: c.checkpoint_id,
            frontier: c.frontier.clone(),
        })
        .collect();
    crate::native_rebootstrap::choose_rebootstrap_target(&candidates, own, &BTreeMap::new())
        .unwrap()
}

/// Superiority is frontier dominance. Two incomparable candidates are both valid targets;
/// the choice is a function of the set: not of the adoption time, not of the order seen.
#[test]
fn incomparable_candidates_are_chosen_by_own_intent_coverage_then_checkpoint_id() {
    let b1 = incarnation_of("device-b", 1);
    let (a, c) = (incarnation_of("device-a", 1), incarnation_of("device-c", 1));
    let chain: Vec<DeltaHash> = (1..=3).map(|i| DeltaHash([i; 32])).collect();
    let own = BTreeMap::from([(b1.clone(), chain)]);
    let frontier = |entries: &[(&AuthorId, NativeAuthorFrontierEntry)]| -> NativeAuthorFrontier {
        entries.iter().map(|(who, e)| ((*who).clone(), *e)).collect()
    };
    // Covers two of B's three deltas, and A.
    let covers_two = TargetCandidate {
        checkpoint_id: [1; 32],
        installed_at: 100,
        frontier: frontier(&[(&b1, entry(2, 2)), (&a, entry(4, 40))]),
    };
    // Covers one of B's deltas, and C: incomparable with the first. Adopted later.
    let covers_one = TargetCandidate {
        checkpoint_id: [9; 32],
        installed_at: 900,
        frontier: frontier(&[(&b1, entry(1, 1)), (&c, entry(4, 41))]),
    };
    // Strictly dominated by the first, and the greatest id.
    let dominated = TargetCandidate {
        checkpoint_id: [200; 32],
        installed_at: 950,
        frontier: frontier(&[(&b1, entry(1, 1)), (&a, entry(3, 30))]),
    };
    // Incomparable with `covers_two`, covers the same two deltas, smaller id.
    let twin = TargetCandidate {
        checkpoint_id: [0; 32],
        installed_at: 10,
        frontier: frontier(&[(&b1, entry(2, 2)), (&c, entry(5, 50))]),
    };

    let pick = |list: &[&TargetCandidate]| {
        let owned: Vec<TargetCandidate> = list
            .iter()
            .map(|c| TargetCandidate {
                checkpoint_id: c.checkpoint_id,
                installed_at: c.installed_at,
                frontier: c.frontier.clone(),
            })
            .collect();
        rebootstrap_target(&owned, &own)
    };
    assert_eq!(pick(&[&covers_two, &covers_one, &dominated]), Some([1; 32]));
    assert_eq!(
        pick(&[&dominated, &covers_one, &covers_two]),
        Some([1; 32]),
        "order is not an input"
    );
    assert_eq!(
        pick(&[&covers_one, &twin]),
        Some([0; 32]),
        "coverage decides before the checkpoint id and before the adoption time"
    );
    assert_eq!(pick(&[&covers_two, &twin]), Some([1; 32]), "equal coverage: the greatest id");
    assert_eq!(pick(&[&twin, &covers_two]), Some([1; 32]));
}

/// The target choice over test candidates with the preservation verdicts given.
fn choose_with(
    candidates: &[(u8, NativeAuthorFrontier)],
    own: &BTreeMap<AuthorId, Vec<DeltaHash>>,
    blocked: &[u8],
) -> Result<Option<[u8; 32]>, crate::native_rebootstrap::BlockedReason> {
    let list: Vec<crate::native_rebootstrap::TargetCandidate> = candidates
        .iter()
        .map(|(id, frontier)| crate::native_rebootstrap::TargetCandidate {
            checkpoint_id: [*id; 32],
            frontier: frontier.clone(),
        })
        .collect();
    let blocked = blocked
        .iter()
        .map(|id| {
            (
                [*id; 32],
                crate::native_rebootstrap::BlockedReason::LocalIntentUnavailable {
                    delta: DeltaHash([*id; 32]),
                },
            )
        })
        .collect();
    crate::native_rebootstrap::choose_rebootstrap_target(&list, own, &blocked)
}

fn frontier_of(entries: &[(&AuthorId, NativeAuthorFrontierEntry)]) -> NativeAuthorFrontier {
    entries.iter().map(|(who, e)| ((*who).clone(), *e)).collect()
}

/// A higher sequence is not dominance by itself: a checkpoint whose own-author position is
/// beyond the local chain, or on another branch of it, is incomparable with one that matches
/// the chain, and one that preservation refuses is never chosen over one it accepts.
#[test]
fn selector_keeps_lower_provable_candidate_when_higher_seq_candidate_forks() {
    let a = incarnation_of("device-b", 1);
    let chain: Vec<DeltaHash> = (1..=5).map(|i| DeltaHash([i; 32])).collect();
    let own = BTreeMap::from([(a.clone(), chain)]);
    // C1 matches the local chain at seq 5. C2 sealed independently: seq 7 on another branch.
    let c1 = (9u8, frontier_of(&[(&a, entry(5, 5))]));
    let c2 = (2u8, frontier_of(&[(&a, entry(7, 77))]));
    let both = [c1.clone(), c2.clone()];
    assert_eq!(
        choose_with(&both, &own, &[2]),
        Ok(Some([9; 32])),
        "the candidate preservation refuses is not chosen over the usable one"
    );
    assert_eq!(
        choose_with(&[c2.clone(), c1.clone()], &own, &[2]),
        Ok(Some([9; 32])),
        "order is not an input"
    );
    // Unrefused, the two are incomparable (equal coverage): the greatest id decides, not C2's
    // higher sequence, and not the order they arrive in.
    assert_eq!(choose_with(&both, &own, &[]), Ok(Some([9; 32])));
    assert_eq!(choose_with(&[c2, c1], &own, &[]), Ok(Some([9; 32])));
    // A candidate on the local chain, beyond what the other covers, does dominate it.
    let c3 = (3u8, frontier_of(&[(&a, entry(3, 3))]));
    let c4 = (4u8, frontier_of(&[(&a, entry(5, 5))]));
    assert_eq!(choose_with(&[c3, c4], &own, &[]), Ok(Some([4; 32])));
}

#[test]
fn plainly_ordered_candidates_choose_the_dominating_one_and_all_blocked_report_the_reason() {
    let (a, c) = (incarnation_of("device-a", 1), incarnation_of("device-c", 1));
    let own = BTreeMap::new();
    let low = (200u8, frontier_of(&[(&a, entry(3, 30))]));
    let high = (1u8, frontier_of(&[(&a, entry(4, 40)), (&c, entry(1, 1))]));
    assert_eq!(choose_with(&[low.clone(), high.clone()], &own, &[]), Ok(Some([1; 32])));
    assert_eq!(choose_with(&[high.clone(), low.clone()], &own, &[]), Ok(Some([1; 32])));
    // Every candidate refused: the reason of the one the rule would have chosen.
    assert_eq!(
        choose_with(&[low, high], &own, &[1, 200]),
        Err(crate::native_rebootstrap::BlockedReason::LocalIntentUnavailable {
            delta: DeltaHash([1; 32])
        })
    );
    assert_eq!(choose_with(&[], &own, &[]), Ok(None));
}

// --- the recovery area is local security state -------------------------------------------

#[cfg(unix)]
fn entries_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        out.push(path.clone());
        if path.is_dir() && !path.is_symlink() {
            entries_under(&path, out);
        }
    }
}

/// The recovery area holds the user's data outside the sync root: private to the user,
/// never reached through a symlink, never named by anything the manifest says, and not
/// hard-linked to the sync root.
#[cfg(unix)]
#[test]
fn recovery_area_is_private_and_rejects_symlinked_root_and_hostile_manifest_paths() {
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    use crate::native_rebootstrap_recovery::{Manifest, ManifestItem, RecoveryArea};

    let base = tempfile::tempdir().unwrap();
    let mut violations: Vec<String> = Vec::new();

    // Preserve a rebootstrap, then give its manifest a parent-relative path and an
    // absolute path: a delta cannot carry either, so only a forged manifest can.
    let absolute = base.path().join("absolute-escape");
    let hostile = ["../escaped.txt", absolute.to_str().unwrap()];
    let area_root = base.path().join("recovery");
    let o = offline_base(false);
    let delta = signed(&o.b1, 1, None, vec![put_op("d/ok.txt", 2, Vec::new())]);
    publish(&o.b, &o.b1, &device_key(2), delta.clone());
    let preserved = super::rebootstrap_preserve::begin_with(
        &o.b,
        built(&o.sealer),
        &area_root,
        &mut |_| Ok(()),
    )
    .unwrap();

    let mut entries = Vec::new();
    entries_under(&area_root, &mut entries);
    entries.push(area_root.clone());
    for entry in &entries {
        let meta = fs::symlink_metadata(entry).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        let want = if meta.is_dir() { 0o700 } else { 0o600 };
        if mode != want {
            violations.push(format!("{} is mode {mode:o}, want {want:o}", entry.display()));
        }
        if meta.is_file() && meta.nlink() != 1 {
            violations.push(format!("{} is hard linked", entry.display()));
        }
        if !meta.is_file() {
            continue;
        }
        let rel = entry.strip_prefix(&preserved.dir).unwrap().to_string_lossy().into_owned();
        let name = rel.rsplit('/').next().unwrap();
        let hex_name =
            |s: &str| s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        let fixed = [
            "manifest.json",
            "target.bundle",
            "target.bundle.sha256",
            "target.verification.json",
            "verification-material/policy-answers.json",
        ];
        let content_addressed = (rel.starts_with("versions/")
            && (hex_name(name) || name.strip_suffix(".record").is_some_and(hex_name)))
            || (rel.starts_with("deltas/") && name.strip_suffix(".bin").is_some_and(hex_name));
        if !content_addressed && !fixed.contains(&rel.as_str()) {
            violations.push(format!("{rel} is named by neither a fixed name nor content"));
        }
    }

    // A read refuses a manifest whose paths are not relative sync-root paths before
    // anything is handed back, and nothing a manifest says names a file.
    let area = RecoveryArea::open_dir(&preserved.dir).unwrap();
    let mut forged: Manifest = area.read_intent().unwrap().manifest;
    for bad in hostile.iter().copied().chain(["C:/Windows", "a//b", ""]) {
        let mut item: ManifestItem = forged.items[0].clone();
        item.path = bad.to_owned();
        forged.items = vec![item];
        if Manifest::from_bytes(&forged.to_bytes()).is_ok() {
            violations.push(format!("a manifest with the path {bad:?} was accepted"));
        }
        area.write_manifest(&forged).unwrap();
        if area.read_intent().is_ok() {
            violations.push(format!("an area whose manifest names {bad:?} was read"));
        }
    }
    for escaped in
        [base.path().join("escaped.txt"), absolute.clone(), area_root.join("escaped.txt")]
    {
        if escaped.exists() {
            violations
                .push(format!("a manifest path wrote {} outside the area", escaped.display()));
        }
    }

    // A recovery root that is itself a symlink is refused.
    let real = base.path().join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    let link = base.path().join("link");
    symlink(&real, &link).unwrap();
    let id = crate::native_rebootstrap_recovery::new_recovery_id();
    if RecoveryArea::create(&link, &group(), &id, &[]).is_ok() {
        violations.push("a recovery root that is a symlink was accepted".into());
    }
    if fs::read_dir(&real).unwrap().next().is_some() {
        violations.push("a symlinked root was written through".into());
    }

    assert!(violations.is_empty(), "recovery area violations:\n{}", violations.join("\n"));
}
