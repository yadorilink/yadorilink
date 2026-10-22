//! The fast fault gate: seconds-scale meta-tests proving that a fault a test
//! names is a fault the test injected.
//!
//! Run with `cargo dst-gate` (or as part of `cargo dst-lane0`). Everything
//! here is pure or on the simulated clock; there is no wall-clock sleep and no
//! scenario stack. It holds three kinds of test:
//!
//! * the unit contract between the generator and the scheduler (a generated
//!   fault offset is nanoseconds at a round boundary);
//! * negative controls -- a fault that is deferred, never hit, or never
//!   scheduled must fail the gate, with the fault named in the message;
//! * positive controls -- one SQLite BUSY, one block-store EIO and one network
//!   drop, each on a call that really is reached, observed through the real
//!   decorator and credited by that decorator at the moment it decides.
//!
//! Credit comes from the injection seam (`FaultingChannel::scheduled`,
//! `FaultingBlockStore::scheduled`, `FaultingSyncState::scheduled`), never
//! from the test: `ScheduledInjectors::credit` is not callable from a test.
//! A decorator that is not bound to the seam (the `new` constructors) earns
//! nothing, which the "unbound decorator" controls below prove for all three.
//!
//! The lifecycle and the gate itself live in `fault_schedule.rs`.

use std::time::Duration;

use yadorilink_local_storage::BlockStore;

use super::case_ir::{DiskFault, Fault, NetFault, SimNanos, ROUND_NANOS};
use super::fault::{FaultDecision, FaultingChannel};
use super::fault_disk::{DiskDecision, DiskOp, FaultingBlockStore};
use super::fault_schedule::{run_schedule, FaultClass, FaultFate, FaultStage, ScheduledInjectors};
use super::fault_sqlite::FaultingSyncState;
use super::generator::{generate_case, generate_pairwise, validate_case};

fn sim<F: std::future::Future<Output = ()> + 'static>(f: impl FnOnce() -> F + 'static) {
    super::sim::block_on(1, f);
}

fn round(n: u64) -> Duration {
    Duration::from_nanos(n * ROUND_NANOS)
}

fn unexercised(failure: &super::fault_schedule::GateFailure) -> Vec<usize> {
    failure.unexercised.iter().map(|u| u.index).collect()
}

/// An in-memory index with one link, for the SQLite decorator.
fn index() -> (yadorilink_daemon::replica_coordinator::ReplicaCoordinator, tempfile::TempDir) {
    let root = tempfile::tempdir().unwrap();
    let state =
        yadorilink_daemon::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap();
    state.link_repository().add_link(&root.path().to_string_lossy(), "gate-group").unwrap();
    (state, root)
}

fn record(path: &str) -> yadorilink_replica_domain::file::FileRecord {
    yadorilink_replica_domain::file::FileRecord {
        path: path.to_string(),
        size: 0,
        mtime_unix_nanos: 0,
        blocks: Vec::new(),
        deleted: false,
    }
}

fn fate(injectors: &ScheduledInjectors, index: usize) -> FaultFate {
    injectors.fates()[index].2
}

// ---- the unit contract ------------------------------------------------

/// The generator draws fault times in logical rounds; the scheduler reads
/// nanoseconds. Every generated offset must therefore be a whole number of
/// rounds expressed in nanoseconds, and some must land after the first round
/// (the old bug put them all within the run's first instants).
#[test]
fn generated_fault_offsets_are_round_boundaries_in_nanoseconds() {
    let mut cases: Vec<_> = (0..300u64).map(generate_case).collect();
    cases.extend(generate_pairwise());
    let (mut faults, mut later_than_first_round) = (0, 0);
    for case in &cases {
        let violations = validate_case(case);
        assert!(violations.is_empty(), "seed {}: {violations:?}", case.seed);
        for (at, fault) in &case.fault_schedule {
            faults += 1;
            assert_eq!(
                at.as_nanos() % ROUND_NANOS,
                0,
                "seed {}: {fault:?} at {}ns is not on a round boundary; the generator and the \
                 scheduler disagree about the unit",
                case.seed,
                at.as_nanos()
            );
            if at.as_nanos() >= ROUND_NANOS {
                later_than_first_round += 1;
            }
        }
    }
    assert!(faults > 0, "the generators produced no faults to check");
    assert!(
        later_than_first_round > 0,
        "every generated fault fired in the first round: offsets are being read in the wrong unit"
    );
}

#[test]
fn a_round_converts_to_nanoseconds_in_one_place_and_serializes_as_a_bare_integer() {
    assert_eq!(SimNanos::from_round(0), SimNanos::ZERO);
    assert_eq!(SimNanos::from_round(3).as_nanos(), 3 * ROUND_NANOS);
    assert_eq!(SimNanos::from_round(3).round(), 3);
    // Corpus entries store the bare integer; the newtype must not change it.
    assert_eq!(serde_json::to_string(&SimNanos::from_round(2)).unwrap(), "2000000000");
    assert_eq!(serde_json::from_str::<SimNanos>("7000000000").unwrap(), SimNanos::from_round(7));
}

/// A fault at a round later than the first is inactive until that round, and
/// is credited only by a decision taken once its window is open.
#[test]
fn a_fault_at_a_later_round_is_not_active_or_credited_before_its_round() {
    sim(|| async {
        let spec = vec![(SimNanos::from_round(2), Fault::Net(NetFault::Drop))];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        let scheduler = tokio::spawn(run_schedule(spec, injectors.clone()));

        let mut channel = FaultingChannel::scheduled(&injectors);
        tokio::time::sleep(round(1)).await;
        let early = channel.decide(0);
        assert_eq!(early, FaultDecision::Deliver, "the round-2 drop was active in round 1");
        assert!(injectors.verify_gate().is_err(), "a fault that has not fired passed the gate");

        tokio::time::sleep(round(1) + Duration::from_millis(1)).await;
        scheduler.await.unwrap().unwrap();
        let late = channel.decide(0);
        assert_eq!(late, FaultDecision::Drop, "the round-2 drop never became active");
        injectors.assert_gate();
    });
}

// ---- negative controls ------------------------------------------------

/// The window opened, nothing was ever routed through the injector: the
/// classic "named but not exercised" green. The gate names the fault, the
/// stage reached, and the expected-vs-actual count.
#[test]
fn an_enabled_fault_that_no_operation_hit_fails_the_gate() {
    sim(|| async {
        let spec = vec![(SimNanos::from_round(1), Fault::Disk(DiskFault::Eio))];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        run_schedule(spec, injectors.clone()).await.unwrap();

        assert_eq!(fate(&injectors, 0), FaultFate::Stage(FaultStage::Enabled));
        let failure = injectors.verify_gate().expect_err("an un-hit fault passed the gate");
        let message = failure.to_string();
        assert!(message.contains("Eio"), "{message}");
        assert!(message.contains("Enabled"), "{message}");
        assert!(message.contains("expected injected >= 1, actual 0"), "{message}");
    });
}

/// The scheduler is only given part of the run: the late fault never opens.
#[test]
fn a_fault_the_run_ended_before_reaching_fails_the_gate() {
    sim(|| async {
        let spec = vec![(SimNanos::from_round(50), Fault::Net(NetFault::Drop))];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        let _scheduler = tokio::spawn(run_schedule(spec, injectors.clone()));
        tokio::time::sleep(round(3)).await;

        assert_eq!(fate(&injectors, 0), FaultFate::Stage(FaultStage::Specified));
        let message = injectors.verify_gate().unwrap_err().to_string();
        assert!(message.contains("Drop") && message.contains("still specified"), "{message}");
    });
}

/// A scheduler that is never started must not read as an empty, passing run.
#[test]
fn a_scheduler_that_never_ran_fails_the_gate() {
    let spec = vec![(SimNanos::from_round(1), Fault::Net(NetFault::Drop))];
    let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
    let message = injectors.verify_gate().unwrap_err().to_string();
    assert!(message.contains("Drop") && message.contains("still specified"), "{message}");
}

/// Crash, Restart, clock faults and FsyncFail have no seam here. Run
/// leniently they are `Deferred` -- a state of their own, never a pass.
#[test]
fn deferred_faults_are_a_distinct_terminal_state_and_fail_the_gate() {
    sim(|| async {
        let injectors = ScheduledInjectors::new();
        let schedule = vec![
            (SimNanos::from_nanos(1), Fault::Crash { device: 0 }),
            (SimNanos::from_nanos(2), Fault::Restart { device: 0 }),
            (SimNanos::from_nanos(3), Fault::ClockSkew { device: 0, delta_nanos: 5 }),
            (SimNanos::from_nanos(4), Fault::ClockJump { device: 0, to_unix_nanos: 5 }),
            (SimNanos::from_nanos(5), Fault::Disk(DiskFault::FsyncFail)),
        ];
        run_schedule(schedule, injectors.clone()).await.unwrap();

        for (_, label, fate) in injectors.fates() {
            assert_eq!(fate, FaultFate::Deferred, "{label}");
        }
        let failure = injectors.verify_gate().unwrap_err();
        assert_eq!(failure.unexercised.len(), 5);
        assert!(failure.to_string().contains("deferred"));
    });
}

/// A test spec that names an unsupported class is rejected before any run.
#[test]
fn a_spec_naming_an_unsupported_fault_fails_validation() {
    let spec = vec![
        (SimNanos::from_round(1), Fault::Net(NetFault::Drop)),
        (SimNanos::from_round(2), Fault::Crash { device: 0 }),
        (SimNanos::from_round(3), Fault::Disk(DiskFault::FsyncFail)),
    ];
    let err = ScheduledInjectors::validate_spec(&spec).unwrap_err();
    let indices: Vec<usize> = err.unsupported.iter().map(|(i, _, _)| *i).collect();
    assert_eq!(indices, vec![1, 2], "{err}");
    assert!(err.to_string().contains("Crash") && err.to_string().contains("FsyncFail"));
}

#[test]
fn every_supported_class_passes_spec_validation() {
    let spec: Vec<(SimNanos, Fault)> = [
        Fault::Net(NetFault::Drop),
        Fault::Net(NetFault::Duplicate),
        Fault::Net(NetFault::Reorder),
        Fault::Net(NetFault::Delay { millis: 5 }),
        Fault::Net(NetFault::Partition { device_a: 0, device_b: 1 }),
        Fault::Net(NetFault::Heal { device_a: 0, device_b: 1 }),
        Fault::Disk(DiskFault::Enospc),
        Fault::Disk(DiskFault::Eio),
        Fault::Disk(DiskFault::TornWrite),
        Fault::Disk(DiskFault::SlowIo { millis: 5 }),
        Fault::Disk(DiskFault::SqliteBusy),
        Fault::Disk(DiskFault::SqliteLocked),
    ]
    .into_iter()
    .map(|f| (SimNanos::ZERO, f))
    .collect();
    ScheduledInjectors::validate_spec(&spec).expect("a supported class was rejected");
}

// ---- positive controls ------------------------------------------------

/// One SQLite BUSY on a reached call: observed exactly, and credited.
#[test]
fn a_sqlite_busy_on_a_reached_call_is_injected_and_observed() {
    sim(|| async {
        let spec = vec![(SimNanos::from_round(1), Fault::Disk(DiskFault::SqliteBusy))];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        let scheduler = tokio::spawn(run_schedule(spec, injectors.clone()));
        tokio::time::sleep(round(1) + Duration::from_millis(1)).await;
        scheduler.await.unwrap().unwrap();

        let (state, _root) = index();
        let faulty = FaultingSyncState::scheduled(&state, &injectors);
        let err =
            faulty.upsert_file("gate-group", &record("a")).expect_err("BUSY was not injected");
        assert!(super::fault_sqlite::is_transient_sqlite_error(&err), "{err}");
        injectors.record_observed(FaultClass::SqliteBusy);
        assert_eq!(fate(&injectors, 0), FaultFate::Stage(FaultStage::Observed));
        injectors.assert_gate();
    });
}

/// One block-store EIO through the real decorator over a real store.
#[test]
fn a_block_store_eio_on_a_reached_put_is_injected_and_observed() {
    sim(|| async {
        let spec = vec![(SimNanos::from_round(1), Fault::Disk(DiskFault::Eio))];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        let scheduler = tokio::spawn(run_schedule(spec, injectors.clone()));
        let dir = tempfile::tempdir().unwrap();
        let inner = std::sync::Arc::new(
            yadorilink_local_storage::SegmentBlockStore::new(dir.path()).unwrap(),
        );

        // Before the window: the put succeeds and nothing is credited.
        let store = FaultingBlockStore::scheduled(inner, &injectors);
        store.put(b"before").expect("a put before the window must succeed");
        assert!(injectors.verify_gate().is_err());

        tokio::time::sleep(round(1) + Duration::from_millis(1)).await;
        scheduler.await.unwrap().unwrap();

        // The credit is the put's own: nothing else decides or notes.
        assert!(store.put(b"after").is_err(), "the EIO window was open but the put succeeded");
        injectors.record_observed(FaultClass::DiskEio);
        assert_eq!(fate(&injectors, 0), FaultFate::Stage(FaultStage::Observed));
        injectors.assert_gate();
    });
}

/// One network drop on a reached message.
#[test]
fn a_network_drop_on_a_reached_message_is_injected_and_observed() {
    sim(|| async {
        let spec = vec![(SimNanos::from_nanos(10), Fault::Net(NetFault::Drop))];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        run_schedule(spec, injectors.clone()).await.unwrap();

        let decision = FaultingChannel::scheduled(&injectors).decide(0);
        assert_eq!(decision, FaultDecision::Drop);
        injectors.record_observed(FaultClass::NetDrop);
        assert_eq!(fate(&injectors, 0), FaultFate::Stage(FaultStage::Observed));
        injectors.assert_gate();
    });
}

/// partition -> heal -> partition: traffic dropped by the second window must
/// not credit the first, which nothing ever hit.
#[test]
fn a_later_window_does_not_credit_a_closed_unexercised_one() {
    sim(|| async {
        let (a, b) = (0, 1);
        let spec = vec![
            (SimNanos::from_round(1), Fault::Net(NetFault::Partition { device_a: a, device_b: b })),
            (SimNanos::from_round(2), Fault::Net(NetFault::Heal { device_a: a, device_b: b })),
            (SimNanos::from_round(3), Fault::Net(NetFault::Partition { device_a: a, device_b: b })),
        ];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        run_schedule(spec, injectors.clone()).await.unwrap();

        // Traffic arrives only during the second partition.
        let now = (3 * ROUND_NANOS) as i64;
        assert_eq!(FaultingChannel::scheduled(&injectors).decide(now), FaultDecision::Drop);

        let failure = injectors.verify_gate().expect_err("the first partition was never hit");
        assert_eq!(unexercised(&failure), vec![0], "{failure}");
    });
}

/// `clear_all` closes the windows it resets: a decision in a later window of
/// the same class must not credit the earlier, closed, never-hit one.
#[test]
fn clear_all_closes_the_window_so_a_later_one_does_not_credit_it() {
    sim(|| async {
        let spec = vec![
            (SimNanos::from_round(1), Fault::Disk(DiskFault::Eio)),
            (SimNanos::from_round(3), Fault::Disk(DiskFault::Eio)),
        ];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        let scheduler = tokio::spawn(run_schedule(spec, injectors.clone()));

        tokio::time::sleep(round(2)).await;
        injectors.clear_all();
        tokio::time::sleep(round(2)).await;
        scheduler.await.unwrap().unwrap();
        assert_eq!(
            injectors.disk_plan().decide(DiskOp::Put, 1),
            DiskDecision::Eio,
            "the second window should be open"
        );
        let inner = tempfile::tempdir().unwrap();
        let store = FaultingBlockStore::scheduled(
            std::sync::Arc::new(
                yadorilink_local_storage::SegmentBlockStore::new(inner.path()).unwrap(),
            ),
            &injectors,
        );
        assert!(store.put(b"x").is_err());

        let failure = injectors.verify_gate().expect_err("the first window was never hit");
        assert_eq!(unexercised(&failure), vec![0], "{failure}");
    });
}

/// Positive control: a decision taken inside the window still credits it.
#[test]
fn a_decision_inside_a_window_before_clear_all_credits_it() {
    sim(|| async {
        let spec = vec![(SimNanos::from_round(1), Fault::Disk(DiskFault::Eio))];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        run_schedule(spec, injectors.clone()).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = FaultingBlockStore::scheduled(
            std::sync::Arc::new(
                yadorilink_local_storage::SegmentBlockStore::new(dir.path()).unwrap(),
            ),
            &injectors,
        );
        assert!(store.put(b"x").is_err());
        injectors.clear_all();
        injectors.assert_gate();
    });
}

/// Credit goes to the entry whose window is open when the seam decides. With
/// `Eio@r1, Eio@r3` and a reset at r2, both decisions are taken in window 1;
/// window 2 never got a decision of its own, so the gate must fail on it
/// however late anyone looks. (Before the seam credited at decision time, a
/// decision reported after r3 landed on window 2 and the gate was green.)
#[test]
fn n5_disk_decisions_in_window_one_do_not_credit_window_two() {
    sim(|| async {
        let spec = vec![
            (SimNanos::from_round(1), Fault::Disk(DiskFault::Eio)),
            (SimNanos::from_round(3), Fault::Disk(DiskFault::Eio)),
        ];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        let scheduler = tokio::spawn(run_schedule(spec, injectors.clone()));
        let dir = tempfile::tempdir().unwrap();
        let store = FaultingBlockStore::scheduled(
            std::sync::Arc::new(
                yadorilink_local_storage::SegmentBlockStore::new(dir.path()).unwrap(),
            ),
            &injectors,
        );

        tokio::time::sleep(round(1) + Duration::from_millis(1)).await;
        assert!(store.put(b"d1").is_err());
        assert!(store.put(b"d2").is_err());
        tokio::time::sleep(round(1)).await;
        injectors.clear_all();
        tokio::time::sleep(round(1) + Duration::from_millis(1)).await;
        scheduler.await.unwrap().unwrap();

        let failure = injectors.verify_gate().expect_err("window 2 had no decision of its own");
        assert_eq!(unexercised(&failure), vec![1], "{failure}");
    });
}

/// The same repro for the network seam.
#[test]
fn n5_net_decisions_in_window_one_do_not_credit_window_two() {
    sim(|| async {
        let spec = vec![
            (SimNanos::from_round(1), Fault::Net(NetFault::Drop)),
            (SimNanos::from_round(3), Fault::Net(NetFault::Drop)),
        ];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        let scheduler = tokio::spawn(run_schedule(spec, injectors.clone()));
        let mut channel = FaultingChannel::scheduled(&injectors);

        tokio::time::sleep(round(1) + Duration::from_millis(1)).await;
        assert_eq!(channel.decide(0), FaultDecision::Drop);
        assert_eq!(channel.decide(0), FaultDecision::Drop);
        tokio::time::sleep(round(1)).await;
        injectors.clear_all();
        tokio::time::sleep(round(1) + Duration::from_millis(1)).await;
        scheduler.await.unwrap().unwrap();

        let failure = injectors.verify_gate().expect_err("window 2 had no decision of its own");
        assert_eq!(unexercised(&failure), vec![1], "{failure}");
    });
}

/// The same repro for the index seam.
#[test]
fn n5_sqlite_decisions_in_window_one_do_not_credit_window_two() {
    sim(|| async {
        let spec = vec![
            (SimNanos::from_round(1), Fault::Disk(DiskFault::SqliteBusy)),
            (SimNanos::from_round(3), Fault::Disk(DiskFault::SqliteBusy)),
        ];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        let scheduler = tokio::spawn(run_schedule(spec, injectors.clone()));
        let (state, _root) = index();
        let faulty = FaultingSyncState::scheduled(&state, &injectors);

        tokio::time::sleep(round(1) + Duration::from_millis(1)).await;
        assert!(faulty.upsert_file("gate-group", &record("a")).is_err());
        assert!(faulty.upsert_file("gate-group", &record("b")).is_err());
        tokio::time::sleep(round(1)).await;
        injectors.clear_all();
        tokio::time::sleep(round(1) + Duration::from_millis(1)).await;
        scheduler.await.unwrap().unwrap();

        let failure = injectors.verify_gate().expect_err("window 2 had no decision of its own");
        assert_eq!(unexercised(&failure), vec![1], "{failure}");
    });
}

/// The sync `BlockStore` methods cannot sleep, so a slow-I/O window they pass
/// through is not an injected fault; only the async wrapper that applies the
/// delay earns the credit.
#[test]
fn slow_io_is_credited_only_where_the_delay_is_applied() {
    sim(|| async {
        let spec = vec![(SimNanos::ZERO, Fault::Disk(DiskFault::SlowIo { millis: 5 }))];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        run_schedule(spec, injectors.clone()).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = FaultingBlockStore::scheduled(
            std::sync::Arc::new(
                yadorilink_local_storage::SegmentBlockStore::new(dir.path()).unwrap(),
            ),
            &injectors,
        );
        store.put(b"sync").unwrap();
        assert!(injectors.verify_gate().is_err(), "a pass-through put was credited as slow");
        store.put_faulted(b"async").await.unwrap();
        injectors.assert_gate();
    });
}

// ---- unbound decorators: a seam that never reports earns nothing --------

/// The mutation the gate exists to catch: a decorator that applies the fault
/// but does not call the seam. The fault really is injected (the put fails),
/// yet the gate fails, because the credit is the seam's to give. Verified
/// against the real code by deleting the seam call in `FaultingBlockStore`.
#[test]
fn an_unbound_block_store_that_fails_a_put_earns_no_credit() {
    sim(|| async {
        let spec = vec![(SimNanos::from_round(1), Fault::Disk(DiskFault::Eio))];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        run_schedule(spec, injectors.clone()).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let inner = std::sync::Arc::new(
            yadorilink_local_storage::SegmentBlockStore::new(dir.path()).unwrap(),
        );
        let unbound = FaultingBlockStore::new(inner, injectors.disk_plan());
        assert!(unbound.put(b"x").is_err(), "the fault was injected");
        let failure = injectors.verify_gate().expect_err("an unreported injection passed");
        assert_eq!(unexercised(&failure), vec![0], "{failure}");
    });
}

#[test]
fn an_unbound_channel_that_drops_earns_no_credit() {
    sim(|| async {
        let spec = vec![(SimNanos::from_round(1), Fault::Net(NetFault::Drop))];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        run_schedule(spec, injectors.clone()).await.unwrap();
        assert_eq!(FaultingChannel::new(injectors.net_plan()).decide(0), FaultDecision::Drop);
        let failure = injectors.verify_gate().expect_err("an unreported injection passed");
        assert_eq!(unexercised(&failure), vec![0], "{failure}");
    });
}

#[test]
fn an_unbound_index_wrapper_that_fails_a_write_earns_no_credit() {
    sim(|| async {
        let spec = vec![(SimNanos::from_round(1), Fault::Disk(DiskFault::SqliteLocked))];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        run_schedule(spec, injectors.clone()).await.unwrap();
        let (state, _root) = index();
        let unbound = FaultingSyncState::new(&state, injectors.sqlite_plan());
        assert!(unbound.upsert_file("gate-group", &record("a")).is_err());
        let failure = injectors.verify_gate().expect_err("an unreported injection passed");
        assert_eq!(unexercised(&failure), vec![0], "{failure}");
    });
}

/// The carrier's credit comes from its own discard counter: no new discards,
/// no credit.
#[test]
fn a_carrier_partition_with_no_discards_earns_no_credit() {
    sim(|| async {
        let spec = vec![(
            SimNanos::from_round(1),
            Fault::Net(NetFault::Partition { device_a: 0, device_b: 1 }),
        )];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        run_schedule(spec, injectors.clone()).await.unwrap();
        injectors.credit_carrier_partition(7, 7);
        assert!(injectors.verify_gate().is_err());
        injectors.credit_carrier_partition(7, 9);
        injectors.assert_gate();
    });
}

/// Running a schedule that is not the spec the injectors were built from
/// fails instead of advancing the wrong ledger entries.
#[test]
fn running_a_different_schedule_than_the_spec_is_rejected() {
    sim(|| async {
        let spec = vec![(SimNanos::from_round(1), Fault::Disk(DiskFault::Eio))];
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        let other = vec![
            (SimNanos::from_round(1), Fault::Disk(DiskFault::Enospc)),
            (SimNanos::from_round(2), Fault::Disk(DiskFault::Eio)),
        ];
        let err = run_schedule(other, injectors.clone()).await.expect_err("mismatch ran");
        assert!(err.to_string().contains("differs from the spec"), "{err}");
    });
}

/// A run with no faults is a valid control and passes. A heal alone has
/// nothing to inject and also passes.
#[test]
fn a_run_with_no_faults_is_a_valid_control() {
    sim(|| async {
        let empty = ScheduledInjectors::new();
        run_schedule(Vec::new(), empty.clone()).await.unwrap();
        empty.assert_gate();

        let heal = ScheduledInjectors::new();
        run_schedule(
            vec![(SimNanos::ZERO, Fault::Net(NetFault::Heal { device_a: 0, device_b: 1 }))],
            heal.clone(),
        )
        .await
        .unwrap();
        heal.assert_gate();
    });
}
