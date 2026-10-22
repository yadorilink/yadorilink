//! The one install: a checkpoint replaces a group's native state, never joins it,
//! and fresh join and rebootstrap are the same code.

use crate::native_checkpoint_install::{
    install_checkpoint, CheckpointError, InstallKind, RebootstrapBarrier,
};
use crate::native_rebootstrap::{rebootstrap_status, Crash, InstallAuthority, RebootstrapState};
use crate::native_rebootstrap_install::{InstallPoint, InstallStep};
use crate::native_rebootstrap_recovery::RecoveryArea;

use super::history_lifecycle_red::{scenario, Scenario};
use super::rebootstrap_install::{install_with, FsRoot};
use super::rebootstrap_preserve::{
    begin_custom, items_root_of, no_hook, private_tempdir, Setup, Writer,
};
use super::*;

fn fresh_kind() -> InstallKind<'static> {
    InstallKind::Fresh
}

fn install_fresh(
    source: &Connection,
    into: &Connection,
) -> Result<crate::native_checkpoint_install::InstalledCheckpoint, CheckpointError> {
    let verified = verify_native_bootstrap(built(source), &group(), &Policy).unwrap();
    let tx = into.unchecked_transaction().unwrap();
    let outcome = install_checkpoint(&tx, &group(), verified, fresh_kind(), &mut |_| Ok(()));
    if outcome.is_ok() {
        tx.commit().unwrap();
    }
    outcome
}

type Everything = (
    yadorilink_replica_domain::native_state::NativeState,
    yadorilink_replica_domain::native_frontier::NativeAuthorFrontier,
    Vec<[u8; 32]>,
    ([u8; 32], [u8; 32]),
);

fn everything(c: &Connection) -> Everything {
    (
        crate::native_store::load_state(c, &group()).unwrap(),
        crate::native_store::load_frontier(c, &group()).unwrap(),
        crate::native_store::stored_checkpoint_hashes(c, &group()),
        roots_of(c),
    )
}

// --- a checkpoint is never joined into state that is there ---------------------------------

#[test]
fn join_into_non_empty_state_is_refused_by_construction() {
    let (source, a, _b) = source();
    // The receiver holds state of the group, even history the source also has.
    let receiver = conn();
    for seed in 1..=4 {
        crate::dag_store::put_file_version(&receiver, GROUP, &version(seed)).unwrap();
    }
    publish(&receiver, &a, &device_key(1), put_delta(&a, 1, None, "x", 1));
    let before = everything(&receiver);

    let outcome = install_fresh(&source, &receiver);

    assert!(matches!(outcome, Err(CheckpointError::NotEmpty)), "{outcome:?}");
    assert!(everything(&receiver) == before, "a refused install must write nothing");
}

#[test]
fn a_checkpoint_that_forks_a_local_author_never_drops_the_local_head() {
    let (source, a, _b) = source();
    // The same author, the same seq, another delta: a join would read the local
    // head as observed and drop it.
    let receiver = conn();
    for seed in 1..=4 {
        crate::dag_store::put_file_version(&receiver, GROUP, &version(seed)).unwrap();
    }
    publish(&receiver, &a, &device_key(1), put_delta(&a, 1, None, "keepme", 3));
    let before = everything(&receiver);

    let outcome = install_fresh(&source, &receiver);

    assert!(matches!(outcome, Err(CheckpointError::NotEmpty)), "{outcome:?}");
    assert!(everything(&receiver) == before);
    assert_eq!(versions_at(&receiver, "keepme"), vec![version(3).version_hash]);
}

#[test]
fn a_replica_holding_only_a_frontier_entry_is_not_empty() {
    let (source, a, _b) = source();
    let receiver = conn();
    crate::native_store::install_frontier(
        &receiver,
        &group(),
        &std::collections::BTreeMap::from([(
            a.clone(),
            yadorilink_replica_domain::native_frontier::NativeAuthorFrontierEntry {
                seq: AuthorSeq(1),
                tip: DeltaHash([9; 32]),
            },
        )]),
    )
    .unwrap();

    let outcome = install_fresh(&source, &receiver);

    assert!(matches!(outcome, Err(CheckpointError::NotEmpty)), "{outcome:?}");
}

// --- one install for fresh join and rebootstrap ----------------------------------------------

/// A rebootstrap whose journal stands in `Quarantining`, the target stored beside it.
struct Quarantining {
    w: Scenario,
    recovery_root: tempfile::TempDir,
    preserved: crate::native_rebootstrap::Preserved,
}

fn quarantining(w: Scenario) -> Quarantining {
    let recovery_root = private_tempdir();
    let preserved =
        begin_custom(&w.b, built(&w.sealer), recovery_root.path(), &Setup::default(), &mut no_hook)
            .unwrap();
    Quarantining { w, recovery_root, preserved }
}

impl Quarantining {
    /// Drives the install to the quarantine and stops there, as a crash would.
    fn stop_in_quarantine(&self) {
        let root = tempfile::tempdir().unwrap();
        let fs_root = FsRoot::new(root.path());
        let crashed =
            install_with(&self.w.b, self.recovery_root.path(), &fs_root, &Writer, &mut |point| {
                if point == InstallPoint::AfterBeginQuarantine {
                    Err(Crash)
                } else {
                    Ok(())
                }
            });
        assert!(crashed.is_err());
        assert_eq!(
            rebootstrap_status(&self.w.b, &group()).unwrap().unwrap().state,
            RebootstrapState::Quarantining
        );
    }

    /// Calls the install directly with the marker `authority`.
    fn install_directly(
        &self,
        authority: &InstallAuthority,
    ) -> Result<crate::native_checkpoint_install::InstalledCheckpoint, CheckpointError> {
        let area = RecoveryArea::open_dir(&self.preserved.dir).unwrap();
        let manifest = area.read_intent().unwrap().manifest;
        let verified = crate::native_rebootstrap::verify_target_in_area(&area, &group()).unwrap();
        let items_root = items_root_of(self.recovery_root.path());
        let tx = self.w.b.unchecked_transaction().unwrap();
        let outcome = install_checkpoint(
            &tx,
            &group(),
            verified,
            InstallKind::Rebootstrap(RebootstrapBarrier {
                authority,
                manifest: &manifest,
                manifest_sha256: &self.preserved.manifest_sha256,
                items_root: &items_root,
                closure_key: None,
            }),
            &mut |_| Ok(()),
        );
        if outcome.is_ok() {
            tx.commit().unwrap();
        }
        outcome
    }
}

#[test]
fn fresh_join_and_rebootstrap_call_the_same_install() {
    use std::cell::RefCell;

    // Fresh join: the steps the one install reports.
    let (source, _a, _b) = source();
    let fresh = conn();
    let fresh_steps = RefCell::new(Vec::new());
    {
        let verified = verify_native_bootstrap(built(&source), &group(), &Policy).unwrap();
        let tx = fresh.unchecked_transaction().unwrap();
        install_checkpoint(&tx, &group(), verified, fresh_kind(), &mut |step| {
            fresh_steps.borrow_mut().push(step);
            Ok(())
        })
        .unwrap();
        tx.commit().unwrap();
    }

    // Rebootstrap: the same steps, through the same function, then its own.
    let q = quarantining(scenario(|b1, h1| {
        vec![super::history_lifecycle_red::put_op(
            "x",
            2,
            vec![super::history_lifecycle_red::rem(b1, 1, h1)],
        )]
    }));
    let rebootstrap_steps = RefCell::new(Vec::new());
    let root = tempfile::tempdir().unwrap();
    install_with(
        &q.w.b,
        q.recovery_root.path(),
        &FsRoot::new(root.path()),
        &Writer,
        &mut |point| {
            if let InstallPoint::InTransaction(step) = point {
                rebootstrap_steps.borrow_mut().push(step);
            }
            Ok(())
        },
    )
    .unwrap();

    let shared = [
        InstallStep::NativeStateCleared,
        InstallStep::TargetInstalled,
        InstallStep::ProjectionArmed,
    ];
    assert_eq!(fresh_steps.borrow().as_slice(), shared, "clear, install, arm: nothing else");
    assert_eq!(&rebootstrap_steps.borrow()[..3], shared);
    assert_eq!(
        &rebootstrap_steps.borrow()[3..],
        [InstallStep::Rotated, InstallStep::Recorded],
        "a rebootstrap adds the rotation and the journal record after the shared steps"
    );
    // The state both end in is the target's, whole.
    assert_eq!(heads_of_state(&fresh), heads_of_state(&source));
    assert_eq!(heads_of_state(&q.w.b), heads_of_state(&q.w.sealer));
}

fn heads_of_state(c: &Connection) -> yadorilink_replica_domain::native_state::NativeState {
    crate::native_store::load_state(c, &group()).unwrap()
}

// --- the marker of a rebootstrap install ---------------------------------------------------

fn a_conflict_scenario() -> Scenario {
    scenario(|b1, h1| {
        vec![super::history_lifecycle_red::put_op(
            "x",
            2,
            vec![super::history_lifecycle_red::rem(b1, 1, h1)],
        )]
    })
}

#[test]
fn the_rebootstrap_marker_is_honoured_only_for_its_recovery_id() {
    let q = quarantining(a_conflict_scenario());
    q.stop_in_quarantine();
    let before = everything(&q.w.b);
    let recovery_id = rebootstrap_status(&q.w.b, &group()).unwrap().unwrap().recovery_id;

    let other = InstallAuthority::for_test(&group(), "another-recovery");
    let refused = q.install_directly(&other);

    assert!(matches!(refused, Err(CheckpointError::NotInstallable(_))), "{refused:?}");
    assert!(everything(&q.w.b) == before, "a marker of another rebootstrap cleared state");

    let own = InstallAuthority::for_test(&group(), &recovery_id);
    q.install_directly(&own).expect("its own recovery id installs");
    assert!(everything(&q.w.b) != before);
}

#[test]
fn the_rebootstrap_marker_is_refused_before_the_quarantine() {
    let q = quarantining(a_conflict_scenario());
    // Preserved, not Quarantining: the barrier has not been crossed into the install.
    assert_eq!(
        rebootstrap_status(&q.w.b, &group()).unwrap().unwrap().state,
        RebootstrapState::Preserved
    );
    let before = everything(&q.w.b);
    let recovery_id = rebootstrap_status(&q.w.b, &group()).unwrap().unwrap().recovery_id;

    let refused = q.install_directly(&InstallAuthority::for_test(&group(), &recovery_id));

    assert!(matches!(refused, Err(CheckpointError::NotInstallable(_))), "{refused:?}");
    assert!(everything(&q.w.b) == before, "an install out of stage cleared state");
}

// --- an empty set-aside is cheap ---------------------------------------------------------------

#[test]
fn empty_set_aside_rebootstrap_is_cheap() {
    // The target covers everything B holds: there is nothing to set aside.
    let w = scenario(|b1, h1| {
        vec![super::history_lifecycle_red::put_op(
            "x",
            2,
            vec![super::history_lifecycle_red::rem(b1, 1, h1)],
        )]
    });
    publish(&w.sealer, &w.b1, &device_key(2), w.undelivered.clone());
    let q = quarantining(w);

    let area = RecoveryArea::open_dir(&q.preserved.dir).unwrap();
    let manifest = area.read_intent().unwrap().manifest;
    assert!(manifest.items.is_empty(), "no own change to preserve");
    assert!(manifest.deltas.is_empty());
    assert!(manifest.versions.is_empty());
    assert!(manifest.remote_only.is_empty(), "no remote-only item");

    let root = tempfile::tempdir().unwrap();
    let mut points = Vec::new();
    install_with(&q.w.b, q.recovery_root.path(), &FsRoot::new(root.path()), &Writer, &mut |p| {
        points.push(p);
        Ok(())
    })
    .unwrap();

    assert_eq!(
        points,
        vec![
            InstallPoint::AfterBeginQuarantine,
            InstallPoint::InTransaction(InstallStep::NativeStateCleared),
            InstallPoint::InTransaction(InstallStep::TargetInstalled),
            InstallPoint::InTransaction(InstallStep::ProjectionArmed),
            InstallPoint::InTransaction(InstallStep::Rotated),
            InstallPoint::InTransaction(InstallStep::Recorded),
            InstallPoint::AfterCommit,
        ],
        "no original is quarantined, nothing is removed from the root"
    );
    let quarantined: i64 =
        q.w.b
            .query_row("SELECT COUNT(*) FROM native_rebootstrap_quarantine", [], |r| r.get(0))
            .unwrap();
    let items: i64 =
        q.w.b.query_row("SELECT COUNT(*) FROM native_recovery_item", [], |r| r.get(0)).unwrap();
    assert_eq!((quarantined, items), (0, 0));
    assert_eq!(roots_of(&q.w.b), roots_of(&q.w.sealer));
}

// --- closures travel with the checkpoint that replaces what they close -------------------

#[test]
fn a_closure_the_checkpoint_carries_is_stored_bound_to_that_checkpoint() {
    let (sealer, _a, b) = source();
    close_author(&sealer, &group(), &b);
    let bundle = built(&sealer);
    let checkpoint_hash = bundle.checkpoint.checkpoint_hash().0;
    assert_eq!(bundle.closures.len(), 1, "the closed author's closure travels in the bundle");

    let fresh = conn();
    join_bundle(bundle, &fresh).unwrap();

    let bound: Vec<Vec<u8>> = fresh
        .prepare(
            "SELECT replacement_checkpoint_hash FROM native_author_closure WHERE group_id = ?1",
        )
        .unwrap()
        .query_map([GROUP], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(bound, vec![checkpoint_hash.to_vec()]);
    assert_eq!(crate::native_closure::closures_for_export(&fresh, &group()).unwrap().len(), 1);
    assert!(crate::native_store::is_closed(&fresh, &group(), &b).unwrap());
}
