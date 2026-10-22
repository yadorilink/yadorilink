//! The rebootstrap freeze: from `Capturing` on, the group admits nothing but the one final
//! capture pass, through the single install funnel. Local edits, remote deltas and the
//! promotion of held deltas are refused there with a typed, retryable `GroupFrozen`; the
//! capture pass alone is let through, by a capability bound to the rebootstrap's recovery id
//! that is consumed in the transaction of the delta it authors.

use std::cell::Cell;

use crate::local_author::LocalAuthor;
use crate::native_authoring::author_op;
use crate::native_rebootstrap::{
    finish_rebootstrap, frozen_frontier_unchanged, group_frozen, rebootstrap_status,
    recover_after_restart, refuse_materialization_if_frozen, set_journal_for_test, BeginError,
    BlockedReason, CaptureAuthority, CaptureBarrier, Crash, Failpoint, FinalCapture,
    InstallAuthority, PreservationFailure, RebootstrapState, RestartOutcome,
};
use crate::native_rebootstrap_install::{InstallError, InstallPoint};
use crate::native_rebootstrap_recovery::RecoveryArea;
use crate::native_store::{self, Admission, InstallOutcome};
use yadorilink_replica_domain::local_op::Op;

use super::history_lifecycle_red::{
    admit, frontier_seq, incarnation_of, put_op, rem, scenario, signed, Scenario,
};
use super::rebootstrap_install::{install, install_with, FsRoot};
use super::rebootstrap_preserve::{
    begin_custom, begin_with, no_hook, private_tempdir, publish_past_the_freeze, Setup, Writer,
};
use super::*;

const RID: &str = "recovery-under-test";

fn put(path: &str, seed: u8) -> Op {
    Op::Put { path: SyncPath(path.into()), version: version(seed).version_hash }
}

/// B's own author on `w`, which is the current incarnation of the device.
fn local<'a>(
    w: &Scenario,
    key: &'a SigningKey,
    authority: Option<&'a CaptureAuthority>,
) -> LocalAuthor<'a> {
    LocalAuthor { author: w.b1.clone(), signing_key: key, capture: authority }
}

fn author_new(
    w: &Scenario,
    path: &str,
    seed: u8,
    authority: Option<&CaptureAuthority>,
) -> Result<(), SyncSqliteError> {
    let key = device_key(2);
    author_op(&w.b, &group(), &local(w, &key, authority), &put(path, seed)).map(|_| ())
}

fn authority_for(w: &Scenario, recovery_id: &str) -> CaptureAuthority {
    CaptureAuthority::for_test(&group(), &w.b1.device, recovery_id)
}

fn is_frozen<T: std::fmt::Debug>(outcome: Result<T, SyncSqliteError>) -> bool {
    matches!(outcome, Err(SyncSqliteError::GroupFrozen { .. }))
}

fn capture_high_seq(c: &Connection) -> Option<u64> {
    rebootstrap_status(c, &group()).unwrap().and_then(|s| s.capture_high_seq)
}

// --- the gate, state by state --------------------------------------------------------------

#[test]
fn capture_delta_installs_under_capturing_with_the_matching_authority() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    set_journal_for_test(&w.b, &group(), "capturing", RID);
    let authority = authority_for(&w, RID);

    author_new(&w, "captured.txt", 5, Some(&authority)).unwrap();

    assert_eq!(frontier_seq(&w.b, &w.b1), Some(3), "the capture delta was installed");
    assert_eq!(capture_high_seq(&w.b), Some(3), "and recorded on the journal with it");
}

#[test]
fn same_call_without_the_authority_is_group_frozen() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    for state in
        ["capturing", "preserving", "preserved", "quarantining", "catching_up", "replaying"]
    {
        set_journal_for_test(&w.b, &group(), state, RID);

        let outcome = author_new(&w, "edit.txt", 5, None);

        assert!(is_frozen(outcome), "{state}");
        assert_eq!(frontier_seq(&w.b, &w.b1), Some(2), "{state}: nothing was authored");
    }
}

#[test]
fn same_call_after_preserved_is_group_frozen() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    for state in ["preserving", "preserved", "quarantining", "catching_up", "replaying"] {
        set_journal_for_test(&w.b, &group(), state, RID);
        let authority = authority_for(&w, RID);

        let outcome = author_new(&w, "late.txt", 5, Some(&authority));

        assert!(is_frozen(outcome), "{state}: a capability kept past Capturing is refused");
        assert_eq!(frontier_seq(&w.b, &w.b1), Some(2), "{state}");
        assert_eq!(capture_high_seq(&w.b), None, "{state}: nothing was consumed");
    }
}

#[test]
fn capture_authority_for_another_recovery_id_is_refused() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    set_journal_for_test(&w.b, &group(), "capturing", RID);
    let superseded = authority_for(&w, "an-earlier-rebootstrap");

    let outcome = author_new(&w, "edit.txt", 5, Some(&superseded));

    assert!(is_frozen(outcome));
    assert_eq!(frontier_seq(&w.b, &w.b1), Some(2));
    assert_eq!(capture_high_seq(&w.b), None);
}

#[test]
fn the_authority_never_admits_a_remote_delta() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    set_journal_for_test(&w.b, &group(), "capturing", RID);
    let authority = authority_for(&w, RID);
    let a = incarnation_of("device-a", 1);
    let remote = signed(&a, 1, None, vec![put_op("remote", 4, Vec::new())]);

    let (outcome, _) = native_store::install_verified_delta_reporting(
        &w.b,
        &group(),
        &remote,
        &device_key(1).verifying_key(),
        Admission::RebootstrapCapture(&authority),
    )
    .unwrap();

    assert!(matches!(outcome, InstallOutcome::GroupFrozen), "{outcome:?}");
    assert_eq!(frontier_seq(&w.b, &a), None);
    assert_eq!(capture_high_seq(&w.b), None);
}

#[test]
fn a_blocked_rebootstrap_does_not_freeze_the_group() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    set_journal_for_test(&w.b, &group(), "blocked", RID);
    // `blocked` carries a reason in a real row; the gate reads the state alone.
    author_new(&w, "edit.txt", 5, None).unwrap();
    assert_eq!(frontier_seq(&w.b, &w.b1), Some(3));
}

// --- remote admission ----------------------------------------------------------------------

#[test]
fn remote_delta_during_the_freeze_is_group_frozen_and_nothing_is_lost() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let a = incarnation_of("device-a", 1);
    let remote = signed(&a, 1, None, vec![put_op("remote", 4, Vec::new())]);
    for state in ["capturing", "preserving", "preserved", "quarantining"] {
        set_journal_for_test(&w.b, &group(), state, RID);

        let verdict = admit(&w.b, &remote);

        assert_eq!(verdict, NativeAdmission::GroupFrozen, "{state}");
        assert_eq!(frontier_seq(&w.b, &a), None, "{state}: nothing was admitted");
        assert_eq!(
            crate::native_store::fetch_delta_body(&w.b, &group(), &a, AuthorSeq(1)).unwrap(),
            None,
            "{state}: nothing was stored"
        );
    }

    // Once the journal is gone the same delta is admitted: it was refused, not dropped.
    w.b.execute("DELETE FROM native_rebootstrap_journal", []).unwrap();
    assert!(matches!(admit(&w.b, &remote), NativeAdmission::Admitted { .. }));
    assert_eq!(frontier_seq(&w.b, &a), Some(1));
}

#[test]
fn a_frozen_refusal_is_no_equivocation_and_does_not_poison_a_later_delivery() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let a = incarnation_of("device-a", 1);
    let first = signed(&a, 1, None, vec![put_op("one", 4, Vec::new())]);
    let second = signed(&a, 2, Some(first.delta_hash()), vec![put_op("two", 5, Vec::new())]);
    set_journal_for_test(&w.b, &group(), "preserved", RID);
    assert_eq!(admit(&w.b, &first), NativeAdmission::GroupFrozen);
    assert_eq!(admit(&w.b, &first), NativeAdmission::GroupFrozen, "again, still just frozen");

    w.b.execute("DELETE FROM native_rebootstrap_journal", []).unwrap();

    assert!(matches!(admit(&w.b, &first), NativeAdmission::Admitted { .. }));
    assert!(matches!(admit(&w.b, &second), NativeAdmission::Admitted { .. }));
}

// --- the transaction of the capture --------------------------------------------------------

#[test]
fn the_capture_delta_and_its_consumption_commit_or_vanish_together() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    set_journal_for_test(&w.b, &group(), "capturing", RID);
    let authority = authority_for(&w, RID);

    // Failure after the delta insert, before the commit: neither exists afterwards.
    {
        let tx = w.b.unchecked_transaction().unwrap();
        let key = device_key(2);
        author_op(&tx, &group(), &local(&w, &key, Some(&authority)), &put("captured.txt", 5))
            .unwrap();
        assert_eq!(capture_high_seq(&tx), Some(3), "visible inside the transaction");
        drop(tx);
    }
    assert_eq!(frontier_seq(&w.b, &w.b1), Some(2), "the delta did not survive");
    assert_eq!(capture_high_seq(&w.b), None, "nor did its consumption");

    // And committed, both exist.
    {
        let tx = w.b.unchecked_transaction().unwrap();
        let key = device_key(2);
        author_op(&tx, &group(), &local(&w, &key, Some(&authority)), &put("captured.txt", 5))
            .unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(frontier_seq(&w.b, &w.b1), Some(3));
    assert_eq!(capture_high_seq(&w.b), Some(3));
}

// --- the machine ---------------------------------------------------------------------------

/// A final capture pass that authors `ops` the first time it runs and whatever of them the
/// index does not hold afterwards: it stands for the capture seam, which authors only what
/// still differs from the index.
struct PassOver<'a> {
    w: &'a Scenario,
    wanted: Vec<(&'static str, u8)>,
    runs: Cell<usize>,
    authored: Cell<usize>,
}

impl<'a> PassOver<'a> {
    fn new(w: &'a Scenario, wanted: Vec<(&'static str, u8)>) -> Self {
        Self { w, wanted, runs: Cell::new(0), authored: Cell::new(0) }
    }
}

impl FinalCapture for PassOver<'_> {
    fn capture(&self, authority: &std::sync::Arc<CaptureAuthority>) -> CaptureBarrier {
        self.runs.set(self.runs.get() + 1);
        for (path, seed) in &self.wanted {
            if !crate::native_store::load_state(&self.w.b, &group())
                .unwrap()
                .heads
                .contains_key(&SyncPath((*path).into()))
            {
                author_new(self.w, path, *seed, Some(&**authority)).unwrap();
                self.authored.set(self.authored.get() + 1);
            }
        }
        CaptureBarrier::Completed
    }
}

fn setup_with<'a>(pass: &'a dyn FinalCapture) -> Setup<'a> {
    Setup { final_capture: pass, ..Setup::default() }
}

#[test]
fn edit_on_disk_not_in_the_index_at_freeze_start_is_captured_and_preserved() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let root = private_tempdir();
    let pass = PassOver::new(&w, vec![("captured.txt", 5)]);

    let preserved =
        begin_custom(&w.b, built(&w.sealer), root.path(), &setup_with(&pass), &mut no_hook)
            .unwrap();

    assert_eq!(pass.runs.get(), 1);
    assert_eq!(pass.authored.get(), 1, "authored exactly once");
    let intent = RecoveryArea::open_dir(&preserved.dir).unwrap().read_intent().unwrap();
    assert_eq!(
        intent.deltas.len(),
        2,
        "the undelivered B/2 and the capture delta (B/1 is covered)"
    );
    let paths_of_captured: Vec<_> =
        intent.manifest.items.iter().filter(|item| item.path == "captured.txt").collect();
    assert_eq!(paths_of_captured.len(), 1, "the capture delta is in the plan once");
    assert!(paths_of_captured[0].reassertable);
    let status = rebootstrap_status(&w.b, &group()).unwrap().unwrap();
    assert_eq!(status.state, RebootstrapState::Preserved);
    assert_eq!(status.capture_high_seq, Some(3));
}

#[test]
fn edit_after_the_final_capture_is_not_authored() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let root = private_tempdir();
    let pass = PassOver::new(&w, vec![("captured.txt", 5)]);
    begin_custom(&w.b, built(&w.sealer), root.path(), &setup_with(&pass), &mut no_hook).unwrap();

    let late = author_new(&w, "late.txt", 6, None);

    assert!(is_frozen(late), "the gate is closed to everyone once the pass is over");
    assert_eq!(frontier_seq(&w.b, &w.b1), Some(3), "only the capture delta was authored");
    // Resuming the barrier does not run a second pass.
    begin_custom(&w.b, built(&w.sealer), root.path(), &setup_with(&pass), &mut no_hook).unwrap();
    assert_eq!(pass.runs.get(), 1);
}

#[test]
fn a_remote_delta_while_the_machine_holds_the_barrier_is_refused() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let root = private_tempdir();
    begin_with(&w.b, built(&w.sealer), root.path(), &mut no_hook).unwrap();
    let a = incarnation_of("device-a", 1);
    let remote = signed(&a, 1, None, vec![put_op("remote", 4, Vec::new())]);

    assert_eq!(admit(&w.b, &remote), NativeAdmission::GroupFrozen);
}

#[test]
fn crash_after_capture_resumes_with_no_second_capture_and_no_loss() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let root = private_tempdir();
    let pass = PassOver::new(&w, vec![("one.txt", 5), ("two.txt", 6)]);

    // The process dies once the pass's deltas are durable and the journal still says Capturing.
    let crashed = begin_custom(&w.b, built(&w.sealer), root.path(), &setup_with(&pass), &mut |p| {
        if p == Failpoint::AfterCapture {
            Err(Crash)
        } else {
            Ok(())
        }
    });
    assert!(matches!(crashed, Err(BeginError::Crashed)));
    assert_eq!(frontier_seq(&w.b, &w.b1), Some(4), "both capture deltas are durable");
    assert_eq!(capture_high_seq(&w.b), Some(4));
    let a = incarnation_of("device-a", 1);
    let remote = signed(&a, 1, None, vec![put_op("remote", 4, Vec::new())]);
    assert_eq!(admit(&w.b, &remote), NativeAdmission::GroupFrozen, "frozen until the restart");

    let restart = recover_after_restart(&w.b, root.path(), &group()).unwrap();
    assert!(matches!(restart, RestartOutcome::Abandoned { .. }), "{restart:?}");
    assert!(
        matches!(admit(&w.b, &remote), NativeAdmission::Admitted { .. }),
        "an abandoned rebootstrap no longer freezes the group"
    );

    // Starting again captures nothing twice, and the plan carries every capture delta once.
    let preserved =
        begin_custom(&w.b, built(&w.sealer), root.path(), &setup_with(&pass), &mut no_hook)
            .unwrap();
    assert_eq!(pass.runs.get(), 2);
    assert_eq!(pass.authored.get(), 2, "the committed deltas were not authored again");
    assert_eq!(frontier_seq(&w.b, &w.b1), Some(4));
    let intent = RecoveryArea::open_dir(&preserved.dir).unwrap().read_intent().unwrap();
    assert_eq!(intent.deltas.len(), 3, "the undelivered B/2 and the two capture deltas, each once");
}

#[test]
fn a_partial_final_capture_blocks_the_plan_and_releases_the_freeze() {
    struct Partial;
    impl FinalCapture for Partial {
        fn capture(&self, _: &std::sync::Arc<CaptureAuthority>) -> CaptureBarrier {
            CaptureBarrier::Partial { detail: "unreadable d/".into() }
        }
    }
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let root = private_tempdir();

    let outcome =
        begin_custom(&w.b, built(&w.sealer), root.path(), &setup_with(&Partial), &mut no_hook);

    assert!(matches!(
        outcome,
        Err(BeginError::Blocked(BlockedReason::PreservationFailed(
            PreservationFailure::CapturePartial { .. }
        )))
    ));
    author_new(&w, "edit.txt", 5, None).unwrap();
}

// --- what the gate honours, and where --------------------------------------------------------

/// A delta of another device, presented to the gate with `admission` while the journal is in
/// `state`.
fn remote_under(state: &str, admission: impl Fn(&Scenario) -> AdmissionKind) -> InstallOutcome {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    set_journal_for_test(&w.b, &group(), state, RID);
    let a = incarnation_of("device-a", 1);
    let remote = signed(&a, 1, None, vec![put_op("remote", 4, Vec::new())]);
    let kind = admission(&w);
    let (outcome, _) = native_store::install_verified_delta_reporting(
        &w.b,
        &group(),
        &remote,
        &device_key(1).verifying_key(),
        kind.as_admission(),
    )
    .unwrap();
    outcome
}

/// Owns the capability a test presents, so the borrow outlives the call.
enum AdmissionKind {
    Capture(CaptureAuthority),
    Install(InstallAuthority),
}

impl AdmissionKind {
    fn as_admission(&self) -> Admission<'_> {
        match self {
            Self::Capture(authority) => Admission::RebootstrapCapture(authority),
            Self::Install(authority) => Admission::RebootstrapInstall(authority),
        }
    }
}

fn install_marker(rid: &'static str) -> impl Fn(&Scenario) -> AdmissionKind {
    move |_| AdmissionKind::Install(InstallAuthority::for_test(&group(), rid))
}

#[test]
fn an_install_marker_passes_the_gate_in_quarantining_and_replaying_for_its_own_recovery_id() {
    for state in ["quarantining", "replaying"] {
        let outcome = remote_under(state, install_marker(RID));
        assert!(matches!(outcome, InstallOutcome::Installed(_)), "{state}: {outcome:?}");
    }
}

#[test]
fn an_install_marker_is_refused_in_capturing_preserving_preserved_and_catching_up() {
    for state in ["capturing", "preserving", "preserved", "catching_up"] {
        let outcome = remote_under(state, install_marker(RID));
        assert!(matches!(outcome, InstallOutcome::GroupFrozen), "{state}: {outcome:?}");
    }
}

#[test]
fn an_install_marker_for_another_recovery_id_is_refused() {
    for state in ["quarantining", "replaying"] {
        let outcome = remote_under(state, install_marker("an-earlier-rebootstrap"));
        assert!(matches!(outcome, InstallOutcome::GroupFrozen), "{state}: {outcome:?}");
    }
}

#[test]
fn a_capture_marker_is_refused_after_the_capture_pass_even_for_this_device() {
    for state in ["quarantining", "catching_up", "replaying"] {
        let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
        set_journal_for_test(&w.b, &group(), state, RID);
        let authority = authority_for(&w, RID);

        let outcome = author_new(&w, "edit.txt", 5, Some(&authority));

        assert!(is_frozen(outcome), "{state}");
        assert_eq!(frontier_seq(&w.b, &w.b1), Some(2), "{state}: nothing was authored");
    }
}

#[test]
fn a_capture_marker_never_admits_a_remote_delta_after_the_capture_pass() {
    for state in ["quarantining", "catching_up", "replaying"] {
        let outcome = remote_under(state, |_| {
            AdmissionKind::Capture(CaptureAuthority::for_test(
                &group(),
                &DeviceId("device-a".into()),
                RID,
            ))
        });
        assert!(matches!(outcome, InstallOutcome::GroupFrozen), "{state}: {outcome:?}");
    }
}

#[test]
fn from_preserved_on_local_authoring_and_remote_admission_are_both_closed() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let a = incarnation_of("device-a", 1);
    let remote = signed(&a, 1, None, vec![put_op("remote", 4, Vec::new())]);
    for state in ["preserved", "quarantining"] {
        set_journal_for_test(&w.b, &group(), state, RID);
        let authority = authority_for(&w, RID);

        assert!(is_frozen(author_new(&w, "edit.txt", 5, None)), "{state}: local");
        assert!(is_frozen(author_new(&w, "edit.txt", 5, Some(&authority))), "{state}: capture");
        assert_eq!(admit(&w.b, &remote), NativeAdmission::GroupFrozen, "{state}: remote");
    }
}

// --- the freeze refuses materialization --------------------------------------------------------

#[test]
fn frozen_group_refuses_materialization_and_authoring() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let fence = |c: &Connection, path: &str| {
        crate::materialized_generation::bump_mutation_fence(c, group().as_str(), path, "test", 1)
    };
    for state in
        ["capturing", "preserving", "preserved", "quarantining", "catching_up", "replaying"]
    {
        set_journal_for_test(&w.b, &group(), state, RID);
        for path in ["x", "d/other", "anywhere"] {
            assert!(is_frozen(fence(&w.b, path)), "{state}: a lane took the fence of {path}");
        }
        assert!(refuse_materialization_if_frozen(&w.b, group().as_str()).is_err(), "{state}");
        assert!(is_frozen(author_new(&w, "edit.txt", 5, None)), "{state}: authoring");
        // Another group is not frozen.
        assert!(!group_frozen(&w.b, "another-group").unwrap(), "{state}");
    }
    for state in ["planning", "blocked"] {
        set_journal_for_test(&w.b, &group(), state, RID);
        fence(&w.b, "x").unwrap();
        assert!(!group_frozen(&w.b, group().as_str()).unwrap(), "{state}");
    }
    w.b.execute("DELETE FROM native_rebootstrap_journal", []).unwrap();
    fence(&w.b, "x").unwrap();
}

// --- the freeze across a restart, and its end --------------------------------------------------

#[test]
fn freeze_survives_restart_and_ends_only_after_the_replay() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let recovery_root = private_tempdir();
    let sync_root = tempfile::tempdir().unwrap();
    let fs_root = FsRoot::new(sync_root.path());
    let a = incarnation_of("device-a", 1);
    let remote = signed(&a, 1, None, vec![put_op("remote", 4, Vec::new())]);
    let preserved = begin_with(&w.b, built(&w.sealer), recovery_root.path(), &mut no_hook).unwrap();
    assert!(group_frozen(&w.b, group().as_str()).unwrap(), "frozen at the barrier");

    // A restart at the barrier resumes it; the group is still frozen.
    let restart = recover_after_restart(&w.b, recovery_root.path(), &group()).unwrap();
    assert!(matches!(restart, RestartOutcome::Preserved(_)), "{restart:?}");
    assert!(group_frozen(&w.b, group().as_str()).unwrap());
    assert!(!finish_rebootstrap(&w.b, &group(), &preserved.recovery_id).unwrap(), "not installed");
    assert_eq!(admit(&w.b, &remote), NativeAdmission::GroupFrozen);

    // A crash inside the quarantine: still frozen after the restart.
    let crashed = install_with(&w.b, recovery_root.path(), &fs_root, &Writer, &mut |point| {
        if point == InstallPoint::AfterBeginQuarantine {
            Err(Crash)
        } else {
            Ok(())
        }
    });
    assert!(matches!(crashed, Err(InstallError::Crashed)), "{crashed:?}");
    let restart = recover_after_restart(&w.b, recovery_root.path(), &group()).unwrap();
    assert!(matches!(restart, RestartOutcome::Quarantining(_)), "{restart:?}");
    assert!(group_frozen(&w.b, group().as_str()).unwrap());
    assert!(!finish_rebootstrap(&w.b, &group(), &preserved.recovery_id).unwrap(), "not installed");

    // The install itself does not end it ...
    install(&w.b, recovery_root.path(), &fs_root).unwrap();
    let restart = recover_after_restart(&w.b, recovery_root.path(), &group()).unwrap();
    assert!(matches!(restart, RestartOutcome::CatchingUp(_)), "{restart:?}");
    assert!(group_frozen(&w.b, group().as_str()).unwrap(), "the install ended the freeze");
    assert!(
        !finish_rebootstrap(&w.b, &group(), &preserved.recovery_id).unwrap(),
        "the replay is not done"
    );

    // ... finishing the machine does.
    super::rebootstrap_replay::complete_machine(
        &w.b,
        recovery_root.path(),
        &preserved.recovery_id,
        &Writer,
    );
    assert!(!group_frozen(&w.b, group().as_str()).unwrap());
    assert_ne!(admit(&w.b, &remote), NativeAdmission::GroupFrozen);
}

#[test]
fn a_crash_at_every_step_of_the_machine_leaves_the_group_frozen_from_the_capture_on() {
    let points = [
        Failpoint::BeforeCapture,
        Failpoint::AfterCapture,
        Failpoint::AfterTargetDurable,
        Failpoint::AfterRecoveryItem(0),
        Failpoint::BeforeManifest,
        Failpoint::AfterManifest,
        Failpoint::AtPreserved,
    ];
    for point in points {
        let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
        let root = private_tempdir();

        let crashed = begin_with(&w.b, built(&w.sealer), root.path(), &mut |p| {
            if p == point {
                Err(Crash)
            } else {
                Ok(())
            }
        });

        assert!(matches!(crashed, Err(BeginError::Crashed)), "{point:?}: {crashed:?}");
        assert!(
            group_frozen(&w.b, group().as_str()).unwrap(),
            "{point:?}: not frozen at the crash"
        );
        assert!(is_frozen(author_new(&w, "edit.txt", 5, None)), "{point:?}");
        assert!(refuse_materialization_if_frozen(&w.b, group().as_str()).is_err(), "{point:?}");
        // Before the barrier a restart gives the attempt up and the old state is
        // authoritative again; from the barrier on the freeze stays.
        recover_after_restart(&w.b, root.path(), &group()).unwrap();
        let barrier_held = point == Failpoint::AtPreserved;
        assert_eq!(group_frozen(&w.b, group().as_str()).unwrap(), barrier_held, "{point:?}");
    }
}

#[test]
fn a_crash_at_every_install_point_leaves_the_group_frozen_and_the_install_resumes() {
    // The per-original steps are the quarantine's own and are crashed in its tests.
    let mut points = vec![InstallPoint::AfterBeginQuarantine];
    points.extend(
        [
            crate::native_rebootstrap_install::InstallStep::NativeStateCleared,
            crate::native_rebootstrap_install::InstallStep::TargetInstalled,
            crate::native_rebootstrap_install::InstallStep::ProjectionArmed,
            crate::native_rebootstrap_install::InstallStep::Rotated,
            crate::native_rebootstrap_install::InstallStep::Recorded,
        ]
        .map(InstallPoint::InTransaction),
    );
    points.push(InstallPoint::AfterCommit);
    for point in points {
        let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
        let recovery_root = private_tempdir();
        let sync_root = tempfile::tempdir().unwrap();
        let fs_root = FsRoot::new(sync_root.path());
        begin_with(&w.b, built(&w.sealer), recovery_root.path(), &mut no_hook).unwrap();

        let crashed = install_with(&w.b, recovery_root.path(), &fs_root, &Writer, &mut |p| {
            if p == point {
                Err(Crash)
            } else {
                Ok(())
            }
        });

        assert!(matches!(crashed, Err(InstallError::Crashed)), "{point:?}: {crashed:?}");
        assert!(group_frozen(&w.b, group().as_str()).unwrap(), "{point:?}: not frozen");
        let done = install(&w.b, recovery_root.path(), &fs_root).unwrap();
        assert!(group_frozen(&w.b, group().as_str()).unwrap(), "{point:?}: the install ended it");
        super::rebootstrap_replay::complete_machine(
            &w.b,
            recovery_root.path(),
            &done.recovery_id,
            &Writer,
        );
        assert!(!group_frozen(&w.b, group().as_str()).unwrap(), "{point:?}");
    }
}

// --- the protected set, re-checked when the install is about to destroy ----------------------

#[test]
fn the_install_recheck_covers_the_frontier_the_closures_the_manifest_and_the_capture_result() {
    let preserved_over = || {
        let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
        let root = private_tempdir();
        let preserved = begin_with(&w.b, built(&w.sealer), root.path(), &mut no_hook).unwrap();
        (w, preserved)
    };
    let unchanged = |w: &Scenario, digest: &[u8; 32]| {
        frozen_frontier_unchanged(&w.b, &group(), digest).unwrap()
    };

    let (w, p) = preserved_over();
    assert!(unchanged(&w, &p.manifest_sha256), "sanity: nothing moved");

    // (i) the author frontier: a delta written past the freeze.
    let (w, p) = preserved_over();
    let d3 = signed(&w.b1, 3, Some(w.undelivered.delta_hash()), vec![put_op("z", 5, Vec::new())]);
    publish_past_the_freeze(&w.b, &w.b1, &device_key(2), d3);
    assert!(!unchanged(&w, &p.manifest_sha256), "a delta past the freeze went unnoticed");

    // (ii) the closure rows: a fence written past the freeze.
    let (w, p) = preserved_over();
    let s = incarnation_of("device-s", 1);
    rotation_closure_at(&w.b, &group(), &s, None);
    assert!(!unchanged(&w, &p.manifest_sha256), "a closure past the freeze went unnoticed");

    // (iii) the preservation manifest: not the one the barrier recorded.
    let (w, _) = preserved_over();
    assert!(!unchanged(&w, &[0xab; 32]), "another manifest went unnoticed");

    // (iv) the capture result: the pass's high-water mark moved.
    let (w, p) = preserved_over();
    w.b.execute("UPDATE native_rebootstrap_journal SET capture_high_seq = 99", []).unwrap();
    assert!(!unchanged(&w, &p.manifest_sha256), "a changed capture result went unnoticed");

    // A journal that never recorded a barrier has nothing to compare.
    let (w, p) = preserved_over();
    w.b.execute("UPDATE native_rebootstrap_journal SET frozen_frontier_hash = NULL", []).unwrap();
    assert!(!unchanged(&w, &p.manifest_sha256));
}

/// An edit on disk after the capture pass is not part of what the barrier protects: it is not
/// authored, so the frontier does not move and the install goes on; it stays on disk for the
/// scan that follows the freeze.
#[test]
fn a_disk_edit_after_the_capture_pass_does_not_stop_the_install_and_stays_on_disk() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let recovery_root = private_tempdir();
    let sync_root = tempfile::tempdir().unwrap();
    let fs_root = FsRoot::new(sync_root.path());
    begin_with(&w.b, built(&w.sealer), recovery_root.path(), &mut no_hook).unwrap();
    std::fs::write(sync_root.path().join("edited-after-capture"), b"the user's edit").unwrap();
    assert!(is_frozen(author_new(&w, "edited-after-capture", 7, None)), "it cannot be authored");

    install(&w.b, recovery_root.path(), &fs_root).unwrap();

    assert_eq!(
        std::fs::read(sync_root.path().join("edited-after-capture")).unwrap(),
        b"the user's edit",
        "the install touched an edit it never protected"
    );
}
