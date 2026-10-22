//! The machine after the install: remote admission resumes, the bounded catch-up drains the
//! available tail, own intent is replayed unit by unit, and only then do materialization and
//! local authoring resume. The journal state and the replay rows are its durable record, so a
//! crash at every boundary resumes with no loss and no duplication.

use std::cell::Cell;
use std::fs;
use std::time::Duration;

use crate::local_author::LocalAuthor;
use crate::native_authoring::author_op;
use crate::native_rebootstrap::{
    finish_rebootstrap, group_frozen, rebootstrap_status, recover_after_restart,
    refuse_materialization_if_frozen, set_journal_for_test, BeginError, Crash, ReassertAuthority,
    Reassertability, RebootstrapState, RestartOutcome,
};
use crate::native_rebootstrap_install::{InstallError, InstallPoint};
use crate::native_rebootstrap_recovery::RecoveryArea;
use crate::native_rebootstrap_replay::{
    catch_up, outstanding_steps, replay_own_intent, retry_replay_unit, unreplayed_units,
    CatchUpEnd, CatchUpLimits, CatchUpPass, CatchUpReport, CatchUpSource, MachinePoint,
    ReplayContext, ReplayError, ReplayReport, RetryError, UnitImport,
};
use yadorilink_replica_domain::local_op::Op;

use super::history_lifecycle_red::{
    admit, dots_at, frontier_seq, incarnation_of, offline_base, put_op, rebootstrap_to_target, rem,
    remove_op, scenario, seed_versions, signed, RebootstrapOutcome, Scenario,
};
use super::rebootstrap_install::{install_with, FsRoot};
use super::rebootstrap_preserve::{
    begin_custom, begin_with, no_hook, private_tempdir, Setup, Viewer, Writer,
};
use super::*;

const RID: &str = "recovery-under-test";

// --- the harness ------------------------------------------------------------------------------

/// A rebootstrap that has begun and is installed: its areas and its id.
pub(super) struct Machine {
    pub(super) recovery_root: tempfile::TempDir,
    pub(super) _sync_root: tempfile::TempDir,
    pub(super) recovery_id: String,
}

/// Preserves and installs `target` on `local`, with `authority` answering both times.
pub(super) fn preserve_and_install(
    local: &Connection,
    target: NativeBootstrap,
    authority: &dyn ReassertAuthority,
) -> Machine {
    let recovery_root = private_tempdir();
    let sync_root = tempfile::tempdir().unwrap();
    let setup = Setup { authority, ..Setup::default() };
    let preserved =
        begin_custom(local, target, recovery_root.path(), &setup, &mut no_hook).unwrap();
    install_with(
        local,
        recovery_root.path(),
        &FsRoot::new(sync_root.path()),
        authority,
        &mut |_| Ok(()),
    )
    .unwrap();
    Machine { recovery_root, _sync_root: sync_root, recovery_id: preserved.recovery_id }
}

/// A catch-up with no connected peer: every pass obtains nothing.
pub(super) struct NoPeers;

impl CatchUpSource for NoPeers {
    fn pass(&mut self, _cap: Duration) -> Result<CatchUpPass, String> {
        Ok(CatchUpPass { obtained: 0 })
    }
}

pub(super) fn drain_with(
    local: &Connection,
    recovery_id: &str,
    source: &mut dyn CatchUpSource,
    limits: CatchUpLimits,
    hook: &mut dyn FnMut(MachinePoint) -> Result<(), Crash>,
) -> Result<CatchUpReport, ReplayError> {
    catch_up(local, &group(), recovery_id, source, limits, 2500, hook)
}

pub(super) fn replay_with(
    local: &Connection,
    recovery_root: &std::path::Path,
    recovery_id: &str,
    authority: &dyn ReassertAuthority,
    hook: &mut dyn FnMut(MachinePoint) -> Result<(), Crash>,
) -> Result<ReplayReport, ReplayError> {
    let author = crate::author_incarnation::current_author(local).unwrap();
    let key = device_key(device_seed(author.device.as_str()));
    let signer = LocalAuthor { author, signing_key: &key, capture: None };
    replay_own_intent(
        local,
        &ReplayContext { recovery_root, authority, author: &signer, now_unix: 3000 },
        &group(),
        recovery_id,
        hook,
    )
}

fn never(_: MachinePoint) -> Result<(), Crash> {
    Ok(())
}

/// The rest of the machine from an installed target: no peer to drain, replay as `authority`
/// says, end the freeze.
pub(super) fn complete_machine(
    local: &Connection,
    recovery_root: &std::path::Path,
    recovery_id: &str,
    authority: &dyn ReassertAuthority,
) -> ReplayReport {
    drain_with(local, recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never).unwrap();
    let report = replay_with(local, recovery_root, recovery_id, authority, &mut never).unwrap();
    assert!(finish_rebootstrap(local, &group(), recovery_id).unwrap(), "the machine finished");
    report
}

fn state_of(local: &Connection) -> RebootstrapState {
    rebootstrap_status(local, &group()).unwrap().expect("a rebootstrap").state
}

fn current(local: &Connection) -> AuthorId {
    crate::author_incarnation::current_author(local).unwrap()
}

/// The deltas `who` authored, in order.
fn authored_by(local: &Connection, who: &AuthorId) -> Vec<NativeDelta> {
    (1..)
        .map_while(|seq| {
            crate::native_store::fetch_delta_body(local, &group(), who, AuthorSeq(seq)).unwrap()
        })
        .map(|wire| NativeDelta::from_wire_bytes(&wire).unwrap())
        .collect()
}

fn outcomes(local: &Connection) -> Vec<Option<String>> {
    let mut stmt =
        local.prepare("SELECT outcome FROM native_rebootstrap_delta ORDER BY ordinal").unwrap();
    stmt.query_map([], |row| row.get(0)).unwrap().collect::<Result<_, _>>().unwrap()
}

/// Whether the group refuses a local edit of `path`.
fn local_put(local: &Connection, path: &str, seed: u8) -> Result<(), SyncSqliteError> {
    let author = current(local);
    let key = device_key(device_seed(author.device.as_str()));
    let signer = LocalAuthor { author, signing_key: &key, capture: None };
    let op = Op::Put { path: SyncPath(path.into()), version: version(seed).version_hash };
    author_op(local, &group(), &signer, &op).map(|_| ())
}

fn local_delete(local: &Connection, path: &str) -> Result<(), SyncSqliteError> {
    let author = current(local);
    let key = device_key(device_seed(author.device.as_str()));
    let signer = LocalAuthor { author, signing_key: &key, capture: None };
    let op = Op::Delete { path: SyncPath(path.into()) };
    author_op(local, &group(), &signer, &op).map(|_| ())
}

fn is_frozen<T: std::fmt::Debug>(outcome: Result<T, SyncSqliteError>) -> bool {
    matches!(outcome, Err(SyncSqliteError::GroupFrozen { .. }))
}

fn remote_delta() -> NativeDelta {
    signed(&incarnation_of("device-a", 1), 1, None, vec![put_op("remote", 4, Vec::new())])
}

/// A device that is a Writer until the flag is raised.
struct Revocable<'a>(&'a Cell<bool>);

impl ReassertAuthority for Revocable<'_> {
    fn classify(&self, _path: &SyncPath) -> Reassertability {
        if self.0.get() {
            Reassertability::NotWriter
        } else {
            Reassertability::Reassertable
        }
    }
}

/// B's own deltas past the covered `B1/1`: `x` over it, then `y`, then `z`, with no removal
/// between them, so each is a unit of its own.
fn three_units() -> Scenario {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let d3 = signed(&w.b1, 3, Some(w.undelivered.delta_hash()), vec![put_op("p", 5, Vec::new())]);
    publish(&w.b, &w.b1, &device_key(2), d3.clone());
    let d4 = signed(&w.b1, 4, Some(d3.delta_hash()), vec![put_op("q", 6, Vec::new())]);
    publish(&w.b, &w.b1, &device_key(2), d4);
    w
}

/// B's put of `x` over the covered `B1/1` and the delete that removes that put: one unit.
fn put_then_delete() -> Scenario {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let delete = signed(
        &w.b1,
        3,
        Some(w.undelivered.delta_hash()),
        vec![remove_op("x", vec![rem(&w.b1, 2, w.undelivered.delta_hash())])],
    );
    publish(&w.b, &w.b1, &device_key(2), delete);
    w
}

// --- the gate: admission resumes at CatchingUp, authoring and materialization at the end -------

#[test]
fn remote_admission_resumes_in_catching_up_while_materialization_and_authoring_stay_frozen() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    set_journal_for_test(&w.b, &group(), "catching_up", RID);

    assert!(
        matches!(admit(&w.b, &remote_delta()), NativeAdmission::Admitted { .. }),
        "remote admission is open"
    );
    assert!(is_frozen(local_put(&w.b, "edit", 5)), "local authoring stays frozen");
    assert!(
        is_frozen(crate::materialized_generation::bump_mutation_fence(
            &w.b,
            group().as_str(),
            "x",
            "test",
            1
        )),
        "materialization stays frozen"
    );
    assert!(group_frozen(&w.b, group().as_str()).unwrap());
}

#[test]
fn remote_admission_stays_closed_until_the_install_commits() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let recovery_root = private_tempdir();
    let sync_root = tempfile::tempdir().unwrap();
    begin_with(&w.b, built(&w.sealer), recovery_root.path(), &mut no_hook).unwrap();
    assert_eq!(admit(&w.b, &remote_delta()), NativeAdmission::GroupFrozen, "preserved");

    // The install crashes after the quarantine began: the root is being modified, remote
    // admission is still closed.
    let crashed = install_with(
        &w.b,
        recovery_root.path(),
        &FsRoot::new(sync_root.path()),
        &Writer,
        &mut |point| if point == InstallPoint::AfterBeginQuarantine { Err(Crash) } else { Ok(()) },
    );
    assert!(matches!(crashed, Err(InstallError::Crashed)), "{crashed:?}");
    assert_eq!(state_of(&w.b), RebootstrapState::Quarantining);
    assert_eq!(admit(&w.b, &remote_delta()), NativeAdmission::GroupFrozen, "quarantining");

    // The install itself commits and opens remote admission, and nothing else.
    install_with(&w.b, recovery_root.path(), &FsRoot::new(sync_root.path()), &Writer, &mut |_| {
        Ok(())
    })
    .unwrap();
    assert_eq!(state_of(&w.b), RebootstrapState::CatchingUp);
    assert!(matches!(admit(&w.b, &remote_delta()), NativeAdmission::Admitted { .. }));
    assert!(is_frozen(local_put(&w.b, "edit", 5)));
}

#[test]
fn local_authoring_and_materialization_resume_only_when_the_replay_is_done() {
    let w = three_units();
    let m = preserve_and_install(&w.b, built(&w.sealer), &Writer);
    let fence = |c: &Connection| {
        crate::materialized_generation::bump_mutation_fence(c, group().as_str(), "q", "test", 1)
    };
    assert!(is_frozen(local_put(&w.b, "edit", 5)), "catching up");

    drain_with(&w.b, &m.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never).unwrap();
    assert_eq!(state_of(&w.b), RebootstrapState::Replaying);
    assert!(is_frozen(local_put(&w.b, "edit", 5)), "replaying, nothing replayed yet");
    assert!(!finish_rebootstrap(&w.b, &group(), &m.recovery_id).unwrap(), "steps remain");
    assert!(group_frozen(&w.b, group().as_str()).unwrap());

    // The first unit is replayed: the rest still stands in the way.
    let mut stop_after_first = |point| {
        if point == MachinePoint::AfterUnit(0) {
            Err(Crash)
        } else {
            Ok(())
        }
    };
    let halted =
        replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &Writer, &mut stop_after_first);
    assert!(matches!(halted, Err(ReplayError::Crashed)), "{halted:?}");
    assert_eq!(outstanding_steps(&w.b, &group()).unwrap(), 2);
    assert!(is_frozen(local_put(&w.b, "edit", 5)), "one unit replayed, two to go");
    assert!(is_frozen(fence(&w.b)));
    assert!(!finish_rebootstrap(&w.b, &group(), &m.recovery_id).unwrap());

    replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &Writer, &mut never).unwrap();
    assert_eq!(outstanding_steps(&w.b, &group()).unwrap(), 0);
    assert!(is_frozen(local_put(&w.b, "edit", 5)), "replayed, not yet finished");
    assert!(finish_rebootstrap(&w.b, &group(), &m.recovery_id).unwrap());
    assert!(!group_frozen(&w.b, group().as_str()).unwrap());
    local_put(&w.b, "edit", 5).unwrap();
    fence(&w.b).unwrap();
}

#[test]
fn replay_runs_only_in_replaying_and_the_catch_up_only_in_catching_up() {
    let w = three_units();
    let m = preserve_and_install(&w.b, built(&w.sealer), &Writer);
    let early = replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &Writer, &mut never);
    assert!(matches!(early, Err(ReplayError::NotRunnable(_))), "{early:?}");
    assert_eq!(outstanding_steps(&w.b, &group()).unwrap(), 3, "nothing was authored");

    drain_with(&w.b, &m.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never).unwrap();
    let again =
        drain_with(&w.b, &m.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never)
            .unwrap();
    assert_eq!(again.end, CatchUpEnd::AlreadyOver, "a restart after the catch-up runs nothing");
}

// --- the bounded catch-up ----------------------------------------------------------------------

struct Advancing;

impl CatchUpSource for Advancing {
    fn pass(&mut self, _cap: Duration) -> Result<CatchUpPass, String> {
        Ok(CatchUpPass { obtained: 1 })
    }
}

struct Failing;

impl CatchUpSource for Failing {
    fn pass(&mut self, _cap: Duration) -> Result<CatchUpPass, String> {
        Err("peer unreachable".into())
    }
}

struct Slow(Duration);

impl CatchUpSource for Slow {
    fn pass(&mut self, _cap: Duration) -> Result<CatchUpPass, String> {
        std::thread::sleep(self.0);
        Ok(CatchUpPass { obtained: 1 })
    }
}

fn installed() -> (Scenario, Machine) {
    let w = three_units();
    let m = preserve_and_install(&w.b, built(&w.sealer), &Writer);
    (w, m)
}

#[test]
fn catch_up_is_bounded_while_peers_keep_advancing() {
    let (w, m) = installed();
    let limits = CatchUpLimits { max_passes: 3, ..CatchUpLimits::default() };
    let report = drain_with(&w.b, &m.recovery_id, &mut Advancing, limits, &mut never).unwrap();
    assert_eq!(report, CatchUpReport { passes: 3, end: CatchUpEnd::PassLimit });
    assert_eq!(state_of(&w.b), RebootstrapState::Replaying, "the machine goes on");
}

#[test]
fn catch_up_with_no_connected_peer_ends_at_once_and_goes_on_to_the_replay() {
    let (w, m) = installed();
    let report =
        drain_with(&w.b, &m.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never)
            .unwrap();
    assert_eq!(report, CatchUpReport { passes: 1, end: CatchUpEnd::Drained });
    assert_eq!(state_of(&w.b), RebootstrapState::Replaying);
}

#[test]
fn catch_up_ends_at_its_budget_however_far_the_peers_have_advanced() {
    let (w, m) = installed();
    let limits = CatchUpLimits {
        max_passes: 1_000,
        budget: Duration::from_millis(60),
        per_pass: Duration::from_millis(30),
    };
    let report =
        drain_with(&w.b, &m.recovery_id, &mut Slow(Duration::from_millis(25)), limits, &mut never)
            .unwrap();
    assert_eq!(report.end, CatchUpEnd::Budget, "{report:?}");
    assert!(report.passes < 1_000);
    assert_eq!(state_of(&w.b), RebootstrapState::Replaying);
}

#[test]
fn a_catch_up_source_that_fails_never_blocks_the_machine() {
    let (w, m) = installed();
    let report =
        drain_with(&w.b, &m.recovery_id, &mut Failing, CatchUpLimits::default(), &mut never)
            .unwrap();
    assert_eq!(report.end, CatchUpEnd::SourceFailed);
    assert_eq!(state_of(&w.b), RebootstrapState::Replaying);
}

/// Hands the replica the deltas the peers had, one per pass, through ordinary admission.
struct Tail<'a> {
    local: &'a Connection,
    deltas: Vec<NativeDelta>,
}

impl CatchUpSource for Tail<'_> {
    fn pass(&mut self, _cap: Duration) -> Result<CatchUpPass, String> {
        let Some(delta) = self.deltas.pop() else { return Ok(CatchUpPass { obtained: 0 }) };
        match admit(self.local, &delta) {
            NativeAdmission::Admitted { .. } => Ok(CatchUpPass { obtained: 1 }),
            other => Err(format!("{other:?}")),
        }
    }
}

/// The tail the target lacks arrives before the replay runs, so the replayed removal sees the
/// deletion: B put v2 over `A/1`, the peers' `A/2` already removed `A/1`.
#[test]
fn the_replay_runs_after_the_catch_up_and_sees_what_the_catch_up_obtained() {
    let o = offline_base(false);
    let h1 = {
        let d = signed(&o.b1, 1, None, vec![put_op("x", 2, vec![rem(&o.a, 1, o.a1)])]);
        let hash = d.delta_hash();
        publish(&o.b, &o.b1, &device_key(2), d);
        hash
    };
    let _ = h1;
    let a2 = signed(&o.a, 2, Some(o.a1), vec![put_op("x", 4, vec![rem(&o.a, 1, o.a1)])]);
    let m = preserve_and_install(&o.b, built(&o.sealer), &Writer);
    let mut tail = Tail { local: &o.b, deltas: vec![a2] };
    let report =
        drain_with(&o.b, &m.recovery_id, &mut tail, CatchUpLimits::default(), &mut never).unwrap();
    assert_eq!(report, CatchUpReport { passes: 2, end: CatchUpEnd::Drained });
    assert_eq!(versions_at(&o.b, "x"), vec![version(4).version_hash], "the tail was admitted");

    replay_with(&o.b, m.recovery_root.path(), &m.recovery_id, &Writer, &mut never).unwrap();

    let mut expected = vec![version(2).version_hash, version(4).version_hash];
    expected.sort();
    assert_eq!(versions_at(&o.b, "x"), expected, "A/2 and B's put stand side by side");
    let replayed = authored_by(&o.b, &current(&o.b));
    assert_eq!(replayed.len(), 1);
    assert!(
        replayed[0].ops[0].removes.is_empty(),
        "the removal of A/1 is dropped: the catch-up already removed it"
    );
}

/// The machine ends when the available tail is drained and the replay is done, even though the
/// replica never reaches the frontier it had before the freeze.
#[test]
fn catch_up_completes_without_reaching_the_old_frontier() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    // B knew a delta of device C that the target does not hold, and no peer can serve it now.
    let c = incarnation_of("device-c", 1);
    let known = signed(&c, 1, None, vec![put_op("tail", 6, Vec::new())]);
    assert!(matches!(admit(&w.b, &known), NativeAdmission::Admitted { .. }));
    assert_eq!(frontier_seq(&w.b, &c), Some(1));

    let m = preserve_and_install(&w.b, built(&w.sealer), &Writer);
    drain_with(&w.b, &m.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never).unwrap();
    replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &Writer, &mut never).unwrap();

    assert_eq!(frontier_seq(&w.b, &c), None, "the old frontier was not reached");
    assert!(
        finish_rebootstrap(&w.b, &group(), &m.recovery_id).unwrap(),
        "the machine ends anyway: the tail is drained and the replay is done"
    );
    assert!(!group_frozen(&w.b, group().as_str()).unwrap());
    assert_eq!(versions_at(&w.b, "x"), vec![version(2).version_hash]);
}

// --- crash at every boundary -------------------------------------------------------------------

/// What a finished rebootstrap leaves, independent of the incarnation's random id.
fn fingerprint(local: &Connection) -> (Vec<Vec<VersionHash>>, usize, Vec<Option<String>>) {
    let versions = ["x", "p", "q"].iter().map(|p| versions_at(local, p)).collect();
    (versions, authored_by(local, &current(local)).len(), outcomes(local))
}

/// Runs the machine with a crash at `catch_point` / `replay_point`, restarts and resumes.
fn run_crashing(point: MachinePoint) -> (Vec<Vec<VersionHash>>, usize) {
    let w = three_units();
    let m = preserve_and_install(&w.b, built(&w.sealer), &Writer);
    let at = |p: MachinePoint| {
        move |reached: MachinePoint| if reached == p { Err(Crash) } else { Ok(()) }
    };
    let crashed = match point {
        MachinePoint::AfterPass(_) | MachinePoint::BeforeReplaying => {
            drain_with(&w.b, &m.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut at(point))
                .map(|_| ())
        }
        _ => {
            drain_with(&w.b, &m.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never)
                .unwrap();
            replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &Writer, &mut at(point))
                .map(|_| ())
        }
    };
    assert!(matches!(crashed, Err(ReplayError::Crashed)), "{point:?}: {crashed:?}");

    // The restart: the journal says where the machine was.
    let restart = recover_after_restart(&w.b, m.recovery_root.path(), &group()).unwrap();
    match (&restart, state_of(&w.b)) {
        (RestartOutcome::CatchingUp(_), RebootstrapState::CatchingUp)
        | (RestartOutcome::Replaying(_), RebootstrapState::Replaying) => {}
        other => panic!("{point:?}: {other:?}"),
    }
    assert!(group_frozen(&w.b, group().as_str()).unwrap(), "{point:?}: still frozen");
    assert!(is_frozen(local_put(&w.b, "edit", 5)), "{point:?}: no local authoring");

    if matches!(restart, RestartOutcome::CatchingUp(_)) {
        drain_with(&w.b, &m.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never)
            .unwrap();
    }
    replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &Writer, &mut never).unwrap();
    assert!(finish_rebootstrap(&w.b, &group(), &m.recovery_id).unwrap(), "{point:?}");
    let (versions, count, rows) = fingerprint(&w.b);
    assert!(rows.iter().all(|r| r.as_deref() == Some("authored")), "{point:?}: {rows:?}");
    (versions, count)
}

#[test]
fn crash_in_each_phase_of_the_machine_resumes_to_the_uncrashed_result() {
    let baseline = {
        let w = three_units();
        let m = preserve_and_install(&w.b, built(&w.sealer), &Writer);
        complete_machine(&w.b, m.recovery_root.path(), &m.recovery_id, &Writer);
        let (versions, count, _) = fingerprint(&w.b);
        (versions, count)
    };
    assert_eq!(baseline.1, 3, "three own deltas, three new ones");
    let points = [
        MachinePoint::AfterPass(1),
        MachinePoint::BeforeReplaying,
        MachinePoint::BeforeUnit(0),
        MachinePoint::InUnit { unit: 0, ordinal: 0 },
        MachinePoint::AfterUnit(0),
        MachinePoint::BeforeUnit(1),
        MachinePoint::AfterUnit(1),
        MachinePoint::InUnit { unit: 2, ordinal: 2 },
        MachinePoint::AfterUnit(2),
    ];
    for point in points {
        assert_eq!(run_crashing(point), baseline, "{point:?}");
    }
}

#[test]
fn a_crash_right_after_the_install_commits_resumes_in_catching_up() {
    let w = three_units();
    let recovery_root = private_tempdir();
    let sync_root = tempfile::tempdir().unwrap();
    let preserved = begin_with(&w.b, built(&w.sealer), recovery_root.path(), &mut no_hook).unwrap();
    let crashed = install_with(
        &w.b,
        recovery_root.path(),
        &FsRoot::new(sync_root.path()),
        &Writer,
        &mut |point| if point == InstallPoint::AfterCommit { Err(Crash) } else { Ok(()) },
    );
    assert!(matches!(crashed, Err(InstallError::Crashed)), "{crashed:?}");

    let restart = recover_after_restart(&w.b, recovery_root.path(), &group()).unwrap();
    assert!(matches!(restart, RestartOutcome::CatchingUp(_)), "{restart:?}");
    complete_machine(&w.b, recovery_root.path(), &preserved.recovery_id, &Writer);
    assert_eq!(authored_by(&w.b, &current(&w.b)).len(), 3);
}

/// The cursor is the replay rows, written in the transaction that authors the delta: a unit
/// that committed is never authored again, and a unit that did not leaves nothing.
#[test]
fn the_cursor_is_durable_a_decided_unit_is_never_authored_again() {
    let w = three_units();
    let m = preserve_and_install(&w.b, built(&w.sealer), &Writer);
    drain_with(&w.b, &m.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never).unwrap();
    let new = current(&w.b);
    let mut stop = |point| if point == MachinePoint::AfterUnit(0) { Err(Crash) } else { Ok(()) };
    let halted = replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &Writer, &mut stop);
    assert!(matches!(halted, Err(ReplayError::Crashed)));
    assert_eq!(outcomes(&w.b), [Some("authored".into()), None, None]);
    assert_eq!(frontier_seq(&w.b, &new), Some(1));

    let rest =
        replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &Writer, &mut never).unwrap();

    assert_eq!(rest.authored, 2, "only the undecided units were authored");
    assert_eq!(frontier_seq(&w.b, &new), Some(3), "no unit was authored twice");
    let once = authored_by(&w.b, &new);
    assert_eq!(once.len(), 3);
    assert_eq!(dots_at(&w.b, "x").len(), 1);
}

#[test]
fn a_crash_inside_a_unit_leaves_no_part_of_it_and_the_resume_authors_all_of_it() {
    let w = put_then_delete();
    let m = preserve_and_install(&w.b, built(&w.sealer), &Writer);
    drain_with(&w.b, &m.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never).unwrap();
    let new = current(&w.b);
    let mut stop = |point| {
        if matches!(point, MachinePoint::InUnit { ordinal: 0, .. }) {
            Err(Crash)
        } else {
            Ok(())
        }
    };

    let halted = replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &Writer, &mut stop);

    assert!(matches!(halted, Err(ReplayError::Crashed)));
    assert_eq!(frontier_seq(&w.b, &new), None, "the put was rolled back with its unit");
    assert_eq!(outcomes(&w.b), [None, None]);

    replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &Writer, &mut never).unwrap();
    assert_eq!(frontier_seq(&w.b, &new), Some(2));
    assert!(versions_at(&w.b, "x").is_empty(), "the delete removes the put it was written over");
}

// --- authority ---------------------------------------------------------------------------------

/// The authority is asked again before each unit. A put and the delete that removes it are one
/// unit: a revocation after the first unit leaves the rest unreplayed, never half of one.
#[test]
fn revoked_between_units_never_splits_a_put_from_the_delete_that_removes_it() {
    // Unit 0 is the put and its delete; unit 1 is an unrelated put of y.
    let w = put_then_delete();
    let d4 = signed(&w.b1, 4, Some(w.undelivered.delta_hash()), vec![put_op("p", 5, Vec::new())]);
    // The chain: b1/3 (the delete) is the tip the next delta must follow.
    let tip = crate::native_store::delta_log_hash(&w.b, &group(), &w.b1, AuthorSeq(3)).unwrap();
    let d4 = {
        let mut d = d4;
        d.prev = tip;
        d.sign(&device_key(2));
        d
    };
    publish(&w.b, &w.b1, &device_key(2), d4);
    let revoked = Cell::new(false);
    let authority = Revocable(&revoked);
    let m = preserve_and_install(&w.b, built(&w.sealer), &authority);
    drain_with(&w.b, &m.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never).unwrap();
    let new = current(&w.b);

    // The grant is revoked after the first unit is committed.
    let mut hook = |point| {
        if point == MachinePoint::AfterUnit(0) {
            revoked.set(true);
        }
        Ok(())
    };
    let report =
        replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &authority, &mut hook).unwrap();

    assert_eq!(report.unreplayed_units, vec![1]);
    assert!(
        !versions_at(&w.b, "x").contains(&version(2).version_hash),
        "the put was authored and the delete that removes it was not"
    );
    assert_eq!(frontier_seq(&w.b, &new), Some(2), "the unit was authored whole");
    assert!(versions_at(&w.b, "p").is_empty(), "the unit after the revocation was not authored");
}

/// The authority is never asked inside a unit.
#[test]
fn a_revocation_inside_a_unit_does_not_split_it() {
    let w = put_then_delete();
    let revoked = Cell::new(false);
    let authority = Revocable(&revoked);
    let m = preserve_and_install(&w.b, built(&w.sealer), &authority);
    drain_with(&w.b, &m.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never).unwrap();
    let new = current(&w.b);
    let mut hook = |point| {
        if matches!(point, MachinePoint::InUnit { ordinal: 0, .. }) {
            revoked.set(true);
        }
        Ok(())
    };

    let report =
        replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &authority, &mut hook).unwrap();

    assert!(report.unreplayed_units.is_empty());
    assert_eq!(frontier_seq(&w.b, &new), Some(2), "both steps of the unit were authored");
}

/// B holds a Writer grant when `x`, `y` and `z` are planned and loses it after the first unit:
/// the rest stays in the recovery area, nothing is rolled back and the old incarnation stays
/// closed at the target's position.
#[test]
fn writer_revoked_between_preserved_and_reasserting() {
    let w = three_units();
    let revoked = Cell::new(false);
    let authority = Revocable(&revoked);
    let m = preserve_and_install(&w.b, built(&w.sealer), &authority);
    drain_with(&w.b, &m.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never).unwrap();
    let new = current(&w.b);
    let mut hook = |point| {
        if point == MachinePoint::AfterUnit(0) {
            revoked.set(true); // the grant is revoked after the first chunk
        }
        Ok(())
    };

    let report =
        replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &authority, &mut hook).unwrap();

    assert_eq!(
        frontier_seq(&w.b, &new),
        Some(1),
        "authored after the Writer grant was revoked: items past the first chunk must not be published"
    );
    assert_eq!(report.unreplayed_units, vec![1, 2], "the rest are kept, not authored");
    assert_eq!(versions_at(&w.b, "x"), vec![version(2).version_hash], "no rollback");
    assert!(versions_at(&w.b, "p").is_empty() && versions_at(&w.b, "q").is_empty());
    assert_eq!(
        unreplayed_units(&w.b, &group()).unwrap(),
        vec![(m.recovery_id.clone(), 1), (m.recovery_id.clone(), 2)]
    );
    assert_eq!(
        unexported_rotation_cutoff(&w.b, &group(), &w.b1),
        Some(Some(AuthorSeq(1))),
        "the old incarnation stays closed at the target's position until a replacement is sealed"
    );
}

#[test]
fn authority_is_rechecked_immediately_before_the_install_and_before_each_unit() {
    // Revoked between the barrier and the install: the originals leave the root, the intent is
    // not replayed, and the machine still ends.
    let w = three_units();
    let recovery_root = private_tempdir();
    let sync_root = tempfile::tempdir().unwrap();
    let revoked = Cell::new(false);
    let authority = Revocable(&revoked);
    let setup = Setup { authority: &authority, ..Setup::default() };
    fs::write(sync_root.path().join("p"), [5]).unwrap();
    let preserved =
        begin_custom(&w.b, built(&w.sealer), recovery_root.path(), &setup, &mut no_hook).unwrap();
    revoked.set(true);
    let fs_root = FsRoot::new(sync_root.path());
    install_with(&w.b, recovery_root.path(), &fs_root, &authority, &mut |_| Ok(())).unwrap();
    assert!(
        !sync_root.path().join("p").exists(),
        "the install asked again: the original of an intent that may not be replayed was quarantined"
    );
    let area = RecoveryArea::open_dir(&preserved_dir(&w.b, recovery_root.path())).unwrap();
    assert!(area.read_version(&version(5).version_hash).is_ok(), "and its copy is in the area");

    drain_with(&w.b, &preserved.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never)
        .unwrap();
    let report =
        replay_with(&w.b, recovery_root.path(), &preserved.recovery_id, &authority, &mut never)
            .unwrap();
    assert_eq!(report.authored, 0);
    assert_eq!(report.unreplayed_units, vec![0, 1, 2]);
    assert!(finish_rebootstrap(&w.b, &group(), &preserved.recovery_id).unwrap());
}

fn preserved_dir(local: &Connection, recovery_root: &std::path::Path) -> std::path::PathBuf {
    crate::native_rebootstrap::resume_preserved(local, recovery_root, &group()).unwrap().dir
}

/// One path for every role: a Writer replays, a Viewer replays nothing, a device revoked at the
/// last moment replays nothing; each ends the machine, installs the target's state and keeps
/// what it did not replay.
#[test]
fn rebootstrap_is_one_path_for_writer_viewer_and_revoked_roles() {
    for role in ["writer", "viewer", "revoked_before_install", "revoked_after_install"] {
        let w = three_units();
        let revoked = Cell::new(role == "revoked_before_install");
        let authority = Revocable(&revoked);
        let viewer_authority: &dyn ReassertAuthority =
            if role == "viewer" { &Viewer } else { &authority };
        let recovery_root = private_tempdir();
        let sync_root = tempfile::tempdir().unwrap();
        let begin = Setup {
            authority: if role == "viewer" { &Viewer } else { &Writer },
            ..Setup::default()
        };
        let preserved =
            begin_custom(&w.b, built(&w.sealer), recovery_root.path(), &begin, &mut no_hook)
                .unwrap();
        install_with(
            &w.b,
            recovery_root.path(),
            &FsRoot::new(sync_root.path()),
            viewer_authority,
            &mut |_| Ok(()),
        )
        .unwrap();
        if role == "revoked_after_install" {
            revoked.set(true);
        }
        let new = current(&w.b);
        let report = {
            drain_with(
                &w.b,
                &preserved.recovery_id,
                &mut NoPeers,
                CatchUpLimits::default(),
                &mut never,
            )
            .unwrap();
            replay_with(
                &w.b,
                recovery_root.path(),
                &preserved.recovery_id,
                viewer_authority,
                &mut never,
            )
            .unwrap()
        };
        assert!(finish_rebootstrap(&w.b, &group(), &preserved.recovery_id).unwrap(), "{role}");
        if role == "writer" {
            assert_eq!(report.authored, 3, "{role}");
            assert_eq!(versions_at(&w.b, "x"), vec![version(2).version_hash], "{role}");
            assert_eq!(frontier_seq(&w.b, &new), Some(3), "{role}");
            assert!(unreplayed_units(&w.b, &group()).unwrap().is_empty());
        } else {
            assert_eq!(report.authored, 0, "{role}: nothing is authored without authority");
            assert_eq!(frontier_seq(&w.b, &new), None, "{role}: no delta of the new incarnation");
            assert_eq!(
                versions_at(&w.b, "x"),
                vec![version(1).version_hash],
                "{role}: the target's"
            );
            assert_eq!(unreplayed_units(&w.b, &group()).unwrap().len(), 3, "{role}");
        }
    }
}

/// What a replay did not author is not lost: the units are recorded and the area that holds their
/// signed deltas and the copies of their versions outlives the end of the rebootstrap.
#[test]
fn an_unreplayed_unit_is_recorded_and_its_area_outlives_the_machine() {
    let w = three_units();
    let recovery_root = private_tempdir();
    let sync_root = tempfile::tempdir().unwrap();
    let setup = Setup { authority: &Viewer, ..Setup::default() };
    let preserved =
        begin_custom(&w.b, built(&w.sealer), recovery_root.path(), &setup, &mut no_hook).unwrap();
    install_with(&w.b, recovery_root.path(), &FsRoot::new(sync_root.path()), &Viewer, &mut |_| {
        Ok(())
    })
    .unwrap();

    complete_machine(&w.b, recovery_root.path(), &preserved.recovery_id, &Viewer);

    assert!(rebootstrap_status(&w.b, &group()).unwrap().is_none(), "the journal is gone");
    assert_eq!(unreplayed_units(&w.b, &group()).unwrap().len(), 3, "the record survives it");
    let area = RecoveryArea::open_dir(&preserved.dir).unwrap();
    assert!(area.read_delta(&w.undelivered.delta_hash()).is_ok(), "and so does the area");
}

// --- the replay itself -------------------------------------------------------------------------

/// The new delta is authored from the installed state: its removals are those of the old op that
/// are live in it, and its sequence, chain link, author and provenance are the new incarnation's.
#[test]
fn reasserted_delta_is_recomputed_from_installed_state() {
    for (superseded, live) in [(false, true), (true, false)] {
        let o = offline_base(superseded);
        let old = signed(&o.b1, 1, None, vec![put_op("x", 2, vec![rem(&o.a, 1, o.a1)])]);
        publish(&o.b, &o.b1, &device_key(2), old.clone());

        assert_eq!(rebootstrap_to_target(&o.b, built(&o.sealer)), RebootstrapOutcome::Installed);

        let new = current(&o.b);
        assert_ne!(new, o.b1);
        let replayed = authored_by(&o.b, &new);
        assert_eq!(replayed.len(), 1, "one old delta, one new delta");
        let delta = &replayed[0];
        assert_eq!(delta.author, new);
        assert_eq!((delta.seq, delta.prev), (AuthorSeq(1), None));
        assert_ne!(delta.delta_hash(), old.delta_hash());
        assert_eq!(delta.ops.len(), 1);
        assert_eq!(delta.ops[0].put.as_ref().map(|p| p.version), Some(version(2).version_hash));
        assert_eq!(
            delta.ops[0].removes,
            if live { vec![rem(&o.a, 1, o.a1)] } else { Vec::new() },
            "the removal of A/1 stays only while A/1 is live in the installed state"
        );
    }
}

/// An old delta that created the same dot at two paths replays as ONE new delta that creates one
/// new dot at both; the delete that followed removes one of them.
#[test]
fn multi_path_old_delta_reasserts_with_one_logical_new_mutation() {
    let sealer = conn();
    let b = conn();
    seed_versions(&sealer);
    seed_versions(&b);
    let b0 = crate::author_incarnation::ensure_incarnation(
        &b,
        &super::history_lifecycle_red::environment("device-b"),
    )
    .unwrap()
    .author;
    let a = incarnation_of("device-a", 1);
    let a1 = signed(&a, 1, None, vec![put_op("a", 1, Vec::new())]);
    let a2 = signed(&a, 2, Some(a1.delta_hash()), vec![put_op("b", 3, Vec::new())]);
    for c in [&sealer, &b] {
        publish(c, &a, &device_key(1), a1.clone());
        publish(c, &a, &device_key(1), a2.clone());
    }
    let d1 = signed(
        &b0,
        1,
        None,
        vec![
            put_op("a", 2, vec![rem(&a, 1, a1.delta_hash())]),
            put_op("b", 4, vec![rem(&a, 2, a2.delta_hash())]),
        ],
    );
    let h1 = d1.delta_hash();
    publish(&b, &b0, &device_key(2), d1);
    publish(
        &b,
        &b0,
        &device_key(2),
        signed(&b0, 2, Some(h1), vec![remove_op("a", vec![rem(&b0, 1, h1)])]),
    );

    assert_eq!(rebootstrap_to_target(&b, built(&sealer)), RebootstrapOutcome::Installed);

    let new = current(&b);
    assert_eq!(
        frontier_seq(&b, &new),
        Some(2),
        "two old deltas must replay as two new deltas, not one per path"
    );
    assert_eq!(
        dots_at(&b, "b"),
        vec![yadorilink_replica_domain::native_state::Dot {
            author: new.clone(),
            seq: AuthorSeq(1)
        }],
        "the old delta's one dot maps to one new dot at every path it created"
    );
    assert!(versions_at(&b, "a").is_empty(), "the later delete of `a` is kept");
    assert_eq!(versions_at(&b, "b"), vec![version(4).version_hash]);
}

/// A delta that removes several heads is replayed as one delta, and its head is the one a later
/// removal names.
#[test]
fn chained_replay_of_one_old_delta_maps_its_head_to_the_delta_that_carries_the_put() {
    let sealer = conn();
    let b = conn();
    seed_versions(&sealer);
    seed_versions(&b);
    let b0 = crate::author_incarnation::ensure_incarnation(
        &b,
        &super::history_lifecycle_red::environment("device-b"),
    )
    .unwrap()
    .author;
    let (a, c) = (incarnation_of("device-a", 1), incarnation_of("device-c", 1));
    let a1 = signed(&a, 1, None, vec![put_op("x", 1, Vec::new())]);
    let c1 = signed(&c, 1, None, vec![put_op("x", 3, Vec::new())]);
    for conn in [&sealer, &b] {
        publish(conn, &a, &device_key(1), a1.clone());
        publish(conn, &c, &device_key(3), c1.clone());
    }
    let d1 = signed(
        &b0,
        1,
        None,
        vec![put_op("x", 2, vec![rem(&a, 1, a1.delta_hash()), rem(&c, 1, c1.delta_hash())])],
    );
    let h1 = d1.delta_hash();
    publish(&b, &b0, &device_key(2), d1);
    publish(
        &b,
        &b0,
        &device_key(2),
        signed(&b0, 2, Some(h1), vec![remove_op("x", vec![rem(&b0, 1, h1)])]),
    );

    assert_eq!(rebootstrap_to_target(&b, built(&sealer)), RebootstrapOutcome::Installed);

    let new = current(&b);
    let replayed = authored_by(&b, &new);
    assert_eq!(replayed.len(), 2, "one new delta per old delta, however many heads it removes");
    assert_eq!(replayed[1].ops[0].removes.len(), 1);
    assert_eq!(
        replayed[1].ops[0].removes[0].provenance,
        replayed[0].delta_hash(),
        "the later delete names the delta that carries the put"
    );
    assert!(
        versions_at(&b, "x").is_empty(),
        "the later delete must remove the head the put made, and x came back as {:?}",
        versions_at(&b, "x")
    );
}

/// Replay order is the dependency graph, not the age of the incarnation: a delta of one
/// incarnation removes a head that a delta of another put, and the put replays first.
#[test]
fn cross_incarnation_remove_replays_after_the_delta_that_recreates_its_head() {
    let sealer = conn();
    let b = conn();
    seed_versions(&sealer);
    seed_versions(&b);
    crate::author_incarnation::ensure_incarnation(
        &b,
        &super::history_lifecycle_red::environment("device-b"),
    )
    .unwrap();
    let a = incarnation_of("device-a", 1);
    let a1 = signed(&a, 1, None, vec![put_op("x", 1, Vec::new())]);
    publish(&sealer, &a, &device_key(1), a1.clone());
    publish(&b, &a, &device_key(1), a1.clone());
    let (b1, b2) = (incarnation_of("device-b", 1), incarnation_of("device-b", 2));
    // `B1/1` is unrelated; `B2/1` puts x over the target's head; `B1/2`, written by the lineage
    // that kept B1 after B2 was minted, observed that put and deletes it.
    let first = signed(&b1, 1, None, vec![put_op("y", 5, Vec::new())]);
    publish(&b, &b1, &device_key(2), first.clone());
    let puts = signed(&b2, 1, None, vec![put_op("x", 2, vec![rem(&a, 1, a1.delta_hash())])]);
    publish(&b, &b2, &device_key(2), puts.clone());
    let deletes = signed(
        &b1,
        2,
        Some(first.delta_hash()),
        vec![remove_op("x", vec![rem(&b2, 1, puts.delta_hash())])],
    );
    publish(&b, &b1, &device_key(2), deletes);

    assert_eq!(rebootstrap_to_target(&b, built(&sealer)), RebootstrapOutcome::Installed);

    assert!(
        versions_at(&b, "x").is_empty(),
        "the delete replayed before the put it removes was dropped, and x holds {:?}",
        versions_at(&b, "x")
    );
    assert_eq!(versions_at(&b, "y"), vec![version(5).version_hash]);
}

/// Recursive operations are keyed by the device, not the incarnation, so the new incarnation
/// cannot reuse the old id. The residual parts are a FRESH operation, numbered from zero, with
/// the residual count.
#[test]
fn partially_uncovered_recursive_operation_uses_fresh_operation_identity() {
    use yadorilink_replica_domain::recursive_operation::RecursiveOperationId;
    use yadorilink_replica_domain::signed_delta::RecursivePart;
    let sealer = conn();
    let b = conn();
    seed_versions(&sealer);
    seed_versions(&b);
    let b0 = crate::author_incarnation::ensure_incarnation(
        &b,
        &super::history_lifecycle_red::environment("device-b"),
    )
    .unwrap()
    .author;
    let a = incarnation_of("device-a", 1);
    let mut prev = None;
    let mut heads = Vec::new();
    for index in 0..5u64 {
        let d = signed(&a, index + 1, prev, vec![put_op(&format!("d/f{index}"), 1, Vec::new())]);
        prev = Some(d.delta_hash());
        heads.push(d.delta_hash());
        publish(&sealer, &a, &device_key(1), d.clone());
        publish(&b, &a, &device_key(1), d);
    }
    let old_id = RecursiveOperationId([7; 16]);
    // The old operation had five parts; the target covers parts 0 and 1, so parts 2..=4 are the
    // residual.
    let mut prev = None;
    for index in 0..5u32 {
        let part = RecursivePart { operation_id: old_id, part_index: index, part_count: 5 };
        let ops = vec![remove_op(
            &format!("d/f{index}"),
            vec![rem(&a, u64::from(index) + 1, heads[index as usize])],
        )];
        let mut delta = signed(&b0, u64::from(index) + 1, prev, ops);
        delta.recursive_part = Some(part);
        delta.sign(&device_key(2));
        prev = Some(delta.delta_hash());
        publish(&b, &b0, &device_key(2), delta.clone());
        if index < 2 {
            publish(&sealer, &b0, &device_key(2), delta);
        }
    }

    assert_eq!(rebootstrap_to_target(&b, built(&sealer)), RebootstrapOutcome::Installed);

    let new = current(&b);
    let parts: Vec<RecursivePart> =
        authored_by(&b, &new).iter().filter_map(|d| d.recursive_part).collect();
    assert_eq!(parts.len(), 3, "every residual part is still a part of a recursive operation");
    assert_ne!(
        parts[0].operation_id, old_id,
        "the residual parts reused the old operation id, which is the same operation to every peer"
    );
    assert!(parts.iter().all(|p| p.operation_id == parts[0].operation_id));
    assert_eq!(parts.iter().map(|p| p.part_index).collect::<Vec<_>>(), [0, 1, 2]);
    assert!(parts.iter().all(|p| p.part_count == 3), "the count is the residual count");
    for index in 0..5 {
        assert!(versions_at(&b, &format!("d/f{index}")).is_empty(), "d/f{index} is deleted");
    }
}

// --- the freeze while own intent is replayed ---------------------------------------------------

/// The user edits `x` on disk while the replay window is open: nothing authors it (the group is
/// frozen) and nothing overwrites it (the materializer is frozen). It is on disk when the freeze
/// ends and authored then, once.
#[test]
fn user_edits_held_path_during_reassert() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let m = preserve_and_install(&w.b, built(&w.sealer), &Writer);
    let disk = tempfile::tempdir().unwrap();
    fs::write(disk.path().join("x"), [2]).unwrap();
    drain_with(&w.b, &m.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never).unwrap();
    assert_eq!(state_of(&w.b), RebootstrapState::Replaying);

    fs::write(disk.path().join("x"), [3]).unwrap(); // the user's edit under the freeze
    assert!(is_frozen(local_put(&w.b, "x", 3)), "the edit is not authored under the freeze");
    assert!(refuse_materialization_if_frozen(&w.b, group().as_str()).is_err());
    replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &Writer, &mut never).unwrap();
    assert_eq!(fs::read(disk.path().join("x")).unwrap(), [3], "nothing overwrote the edit");
    assert!(finish_rebootstrap(&w.b, &group(), &m.recovery_id).unwrap());

    // The scan after the freeze authors what differs between the disk and the index.
    assert_eq!(versions_at(&w.b, "x"), vec![version(2).version_hash], "the replayed put stands");
    local_put(&w.b, "x", 3).unwrap();
    assert!(versions_at(&w.b, "x").contains(&version(3).version_hash), "the edit was authored");
}

#[test]
fn user_deletes_held_path_during_reassert() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let m = preserve_and_install(&w.b, built(&w.sealer), &Writer);
    let disk = tempfile::tempdir().unwrap();
    fs::write(disk.path().join("x"), [2]).unwrap();
    drain_with(&w.b, &m.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never).unwrap();

    fs::remove_file(disk.path().join("x")).unwrap();
    let before = authored_by(&w.b, &current(&w.b)).len();
    let attempt = local_delete(&w.b, "x");
    assert!(attempt.is_err() || before == authored_by(&w.b, &current(&w.b)).len());
    assert_eq!(
        authored_by(&w.b, &current(&w.b)).len(),
        before,
        "the delete is not authored under the freeze: {attempt:?}"
    );
    replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &Writer, &mut never).unwrap();
    assert!(!disk.path().join("x").exists(), "the replayed put did not bring the file back");
    assert!(finish_rebootstrap(&w.b, &group(), &m.recovery_id).unwrap());

    local_delete(&w.b, "x").unwrap();
}

/// The process dies after the replay and before the freeze ends. The freeze survives the
/// restart, the resumed machine authors nothing twice, and only then does it end.
#[test]
fn crash_between_final_capture_and_hold_release() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let m = preserve_and_install(&w.b, built(&w.sealer), &Writer);
    let disk = tempfile::tempdir().unwrap();
    fs::write(disk.path().join("x"), [3]).unwrap();
    drain_with(&w.b, &m.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never).unwrap();
    replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &Writer, &mut never).unwrap();

    // The crash: the replay is done, the freeze is not ended.
    let restart = recover_after_restart(&w.b, m.recovery_root.path(), &group()).unwrap();
    assert!(matches!(restart, RestartOutcome::Replaying(_)), "{restart:?}");
    assert!(group_frozen(&w.b, group().as_str()).unwrap(), "the freeze survives the crash");
    let report =
        replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &Writer, &mut never).unwrap();
    assert_eq!(report, ReplayReport::default(), "the resumed replay authors nothing twice");
    assert!(finish_rebootstrap(&w.b, &group(), &m.recovery_id).unwrap());

    assert_eq!(dots_at(&w.b, "x").len(), 1, "the replayed put is there once");
    let before = authored_by(&w.b, &current(&w.b)).len();
    local_put(&w.b, "x", 3).unwrap();
    assert!(versions_at(&w.b, "x").contains(&version(3).version_hash));
    assert_eq!(
        authored_by(&w.b, &current(&w.b)).len(),
        before + 1,
        "the difference is authored at most once"
    );
}

// --- the entry rule and the replacement checkpoint ---------------------------------------------

/// A group a verified closure has put above a cutoff cannot continue incrementally, so it
/// rebootstraps without any peer having said it truncated; a group nothing forces does not.
#[test]
fn a_verified_closure_forces_the_rebootstrap_without_a_truncating_peer() {
    let w = scenario(|b1, h1| vec![put_op("x", 2, vec![rem(b1, 1, h1)])]);
    let a = incarnation_of("device-a", 1);
    let a1 = signed(&a, 1, None, vec![put_op("t1", 4, Vec::new())]);
    let a2 = signed(&a, 2, Some(a1.delta_hash()), vec![put_op("t2", 4, Vec::new())]);
    publish(&w.b, &a, &device_key(1), a1.clone());
    publish(&w.b, &a, &device_key(1), a2);
    let root = private_tempdir();
    let nobody = Setup { truncating: vec![], connected: vec![], ..Setup::default() };

    let unforced = begin_custom(&w.b, built(&w.sealer), root.path(), &nobody, &mut no_hook);
    assert!(matches!(unforced, Err(BeginError::NotLeavingIncremental)), "{unforced:?}");
    assert!(crate::native_closure::needs_rebootstrap(&w.b, &group()).unwrap().is_empty());

    // A verified closure of device A at its first delta: this replica stands above it.
    let closure = closure_signed(
        &a,
        Some(NativeAuthorFrontierEntry { seq: AuthorSeq(1), tip: a1.delta_hash() }),
        1,
        "device-a",
        1,
    );
    crate::native_closure::store_bundle_closure(&w.b, &group(), &closure, [7; 32], &Policy)
        .unwrap();
    assert_eq!(crate::native_closure::needs_rebootstrap(&w.b, &group()).unwrap().len(), 1);

    let forced = begin_custom(&w.b, built(&w.sealer), root.path(), &nobody, &mut no_hook);
    assert!(forced.is_ok(), "{forced:?}");
}

/// The replacement checkpoint holds the replayed own intent, so no closure may be marked for
/// export before the replay is over.
#[test]
fn a_replacement_checkpoint_cannot_be_marked_before_the_replay_is_done() {
    let w = three_units();
    let m = preserve_and_install(&w.b, built(&w.sealer), &Writer);
    let mark =
        || crate::native_closure::mark_replacement_checkpoint(&w.b, &group(), &w.b1, [9; 32]);
    assert!(matches!(mark(), Err(SyncSqliteError::GroupFrozen { .. })), "catching up");
    drain_with(&w.b, &m.recovery_id, &mut NoPeers, CatchUpLimits::default(), &mut never).unwrap();
    assert!(matches!(mark(), Err(SyncSqliteError::GroupFrozen { .. })), "replaying");
    assert!(crate::native_closure::closures_for_export(&w.b, &group()).unwrap().is_empty());

    replay_with(&w.b, m.recovery_root.path(), &m.recovery_id, &Writer, &mut never).unwrap();
    assert!(finish_rebootstrap(&w.b, &group(), &m.recovery_id).unwrap());

    mark().unwrap();
    assert_eq!(crate::native_closure::closures_for_export(&w.b, &group()).unwrap().len(), 1);
}

// --- retrying a held unit ----------------------------------------------------------------------

/// A rebootstrap that ended with every unit held, because this device was not a Writer.
fn held_machine(w: &Scenario) -> Machine {
    let m = preserve_and_install(&w.b, built(&w.sealer), &Viewer);
    complete_machine(&w.b, m.recovery_root.path(), &m.recovery_id, &Viewer);
    m
}

fn retry_with(
    local: &Connection,
    m: &Machine,
    unit: usize,
    authority: &dyn ReassertAuthority,
    hook: &mut dyn FnMut(MachinePoint) -> Result<(), Crash>,
) -> Result<ReplayReport, RetryError> {
    retry_importing(local, m, unit, authority, &mut |_, _| Ok(()), hook)
}

fn retry_importing(
    local: &Connection,
    m: &Machine,
    unit: usize,
    authority: &dyn ReassertAuthority,
    import: &mut UnitImport<'_>,
    hook: &mut dyn FnMut(MachinePoint) -> Result<(), Crash>,
) -> Result<ReplayReport, RetryError> {
    let author = crate::author_incarnation::current_author(local).unwrap();
    let key = device_key(device_seed(author.device.as_str()));
    let signer = LocalAuthor { author, signing_key: &key, capture: None };
    retry_replay_unit(
        local,
        &ReplayContext {
            recovery_root: m.recovery_root.path(),
            authority,
            author: &signer,
            now_unix: 4000,
        },
        &group(),
        &m.recovery_id,
        unit,
        import,
        hook,
    )
}

fn held(local: &Connection) -> usize {
    unreplayed_units(local, &group()).unwrap().len()
}

/// The held unit goes through the replay's unit scheduler: both steps, one transaction, the
/// delete mapped onto the put it removes, authored as the new incarnation, once.
#[test]
fn a_retried_unit_is_authored_once_by_the_replay_scheduler_and_resolved() {
    let w = put_then_delete();
    let m = held_machine(&w);
    let new = current(&w.b);
    assert_eq!(held(&w.b), 1);
    assert_eq!(frontier_seq(&w.b, &new), None);

    let report = retry_with(&w.b, &m, 0, &Writer, &mut never).unwrap();

    assert_eq!(report.authored, 2);
    assert_eq!(frontier_seq(&w.b, &new), Some(2), "both steps, as deltas of the new incarnation");
    assert!(versions_at(&w.b, "x").is_empty(), "the delete removes the put it was written over");
    assert_eq!(held(&w.b), 0, "the unit is resolved");
    assert!(
        matches!(retry_with(&w.b, &m, 0, &Writer, &mut never), Err(RetryError::NotHeld)),
        "a resolved unit is not retried"
    );
    assert_eq!(frontier_seq(&w.b, &new), Some(2), "and nothing is authored twice");
}

#[test]
fn a_retry_without_writer_authority_is_refused_and_touches_nothing() {
    let w = put_then_delete();
    let m = held_machine(&w);
    let new = current(&w.b);

    let refused = retry_with(&w.b, &m, 0, &Viewer, &mut never);

    assert!(matches!(refused, Err(RetryError::NotAWriter)), "{refused:?}");
    assert_eq!(held(&w.b), 1, "the unit stays held");
    assert_eq!(frontier_seq(&w.b, &new), None, "and nothing is authored");
}

#[test]
fn a_retry_is_refused_while_a_rebootstrap_runs() {
    let w = put_then_delete();
    let m = held_machine(&w);
    let new = current(&w.b);
    for state in ["planning", "preserved", "catching_up", "replaying"] {
        set_journal_for_test(&w.b, &group(), state, "another-recovery");

        let refused = retry_with(&w.b, &m, 0, &Writer, &mut never);

        assert!(matches!(refused, Err(RetryError::RebootstrapRunning)), "{state}: {refused:?}");
        assert_eq!(held(&w.b), 1, "{state}");
        assert_eq!(frontier_seq(&w.b, &new), None, "{state}");
    }
}

#[test]
fn an_unknown_unit_is_a_typed_error() {
    let w = put_then_delete();
    let m = held_machine(&w);
    assert!(matches!(retry_with(&w.b, &m, 7, &Writer, &mut never), Err(RetryError::NotHeld)));
    let other = Machine {
        recovery_root: private_tempdir(),
        _sync_root: tempfile::tempdir().unwrap(),
        recovery_id: "0".repeat(32),
    };
    assert!(matches!(retry_with(&w.b, &other, 0, &Writer, &mut never), Err(RetryError::NotHeld)));
    assert_eq!(held(&w.b), 1);
}

/// Authoring and resolving are one transaction: a crash at any point inside it leaves the unit
/// held and nothing authored, and the retry that follows authors it once.
#[test]
fn a_crash_between_authoring_and_resolving_never_authors_twice() {
    let w = put_then_delete();
    let m = held_machine(&w);
    let new = current(&w.b);
    for crash_at in [MachinePoint::InUnit { unit: 0, ordinal: 1 }, MachinePoint::BeforeResolve(0)] {
        let mut stop = |point| if point == crash_at { Err(Crash) } else { Ok(()) };

        let halted = retry_with(&w.b, &m, 0, &Writer, &mut stop);

        assert!(matches!(halted, Err(RetryError::Crashed)), "{crash_at:?}: {halted:?}");
        assert_eq!(held(&w.b), 1, "{crash_at:?}: still held");
        assert_eq!(frontier_seq(&w.b, &new), None, "{crash_at:?}: nothing was authored");
    }

    retry_with(&w.b, &m, 0, &Writer, &mut never).unwrap();

    assert_eq!(frontier_seq(&w.b, &new), Some(2), "authored once");
    assert_eq!(held(&w.b), 0);
}

/// The bytes of the unit's put versions are imported, each once, before anything is authored.
#[test]
fn a_retried_unit_imports_its_preserved_bytes_before_authoring() {
    let w = put_then_delete();
    let m = held_machine(&w);
    let new = current(&w.b);
    let imported = std::cell::RefCell::new(Vec::new());
    let mut import = |record: &yadorilink_replica_domain::file::FileVersion,
                      bytes: &mut dyn std::io::Read| {
        assert_eq!(frontier_seq(&w.b, &new), None, "nothing is authored yet");
        let mut read = Vec::new();
        bytes.read_to_end(&mut read).unwrap();
        imported.borrow_mut().push((record.version_hash, read));
        Ok(())
    };
    let mut seen_after_import = false;
    let mut hook = |point| {
        if point == MachinePoint::AfterImport(0) {
            seen_after_import = true;
            assert_eq!(imported.borrow().len(), 1, "imported before the point");
        }
        Ok(())
    };

    retry_importing(&w.b, &m, 0, &Writer, &mut import, &mut hook).unwrap();

    assert!(seen_after_import);
    assert_eq!(*imported.borrow(), vec![(version(2).version_hash, vec![2u8])]);
    assert_eq!(held(&w.b), 0);
}

/// An import that fails ends the retry with nothing authored and the unit held; the next retry
/// imports again and authors it.
#[test]
fn a_failed_import_authors_nothing_and_keeps_the_unit_held() {
    let w = put_then_delete();
    let m = held_machine(&w);
    let new = current(&w.b);

    let failed = retry_importing(
        &w.b,
        &m,
        0,
        &Writer,
        &mut |_, _| Err("the block store is full".into()),
        &mut never,
    );

    assert!(matches!(failed, Err(RetryError::Import(_))), "{failed:?}");
    assert_eq!(held(&w.b), 1);
    assert_eq!(frontier_seq(&w.b, &new), None);
    retry_with(&w.b, &m, 0, &Writer, &mut never).unwrap();
    assert_eq!(frontier_seq(&w.b, &new), Some(2));
    assert_eq!(held(&w.b), 0);
}

/// A crash after the import and before the authoring leaves the unit held; the retry that
/// follows imports again and authors once.
#[test]
fn a_crash_after_the_import_leaves_the_unit_held_and_the_next_retry_succeeds() {
    let w = put_then_delete();
    let m = held_machine(&w);
    let new = current(&w.b);
    let calls = Cell::new(0);
    let mut import = |_: &yadorilink_replica_domain::file::FileVersion,
                      _: &mut dyn std::io::Read| {
        calls.set(calls.get() + 1);
        Ok(())
    };
    let mut stop = |point| if point == MachinePoint::AfterImport(0) { Err(Crash) } else { Ok(()) };

    let halted = retry_importing(&w.b, &m, 0, &Writer, &mut import, &mut stop);

    assert!(matches!(halted, Err(RetryError::Crashed)), "{halted:?}");
    assert_eq!((calls.get(), held(&w.b), frontier_seq(&w.b, &new)), (1, 1, None));
    retry_importing(&w.b, &m, 0, &Writer, &mut import, &mut never).unwrap();
    assert_eq!((calls.get(), held(&w.b), frontier_seq(&w.b, &new)), (2, 0, Some(2)));
}

/// A preserved copy that no longer matches the manifest is never imported, and the unit is not
/// authored over it.
#[test]
fn a_preserved_copy_that_does_not_match_the_manifest_is_not_imported() {
    let w = put_then_delete();
    let m = held_machine(&w);
    let new = current(&w.b);
    let area =
        RecoveryArea::open_existing(m.recovery_root.path(), &group(), &m.recovery_id).unwrap();
    area.write_version(&version(2).version_hash, b"tampered").unwrap();
    let calls = Cell::new(0);

    let refused = retry_importing(
        &w.b,
        &m,
        0,
        &Writer,
        &mut |_, _| {
            calls.set(calls.get() + 1);
            Ok(())
        },
        &mut never,
    );

    assert!(matches!(refused, Err(RetryError::Blocked(_))), "{refused:?}");
    assert_eq!((calls.get(), held(&w.b), frontier_seq(&w.b, &new)), (0, 1, None));
}
