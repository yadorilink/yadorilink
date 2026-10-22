//! The first fast boundary tests (one row per boundary of the boundary-test
//! table), each a small deterministic case on the real capture pipeline with
//! no wall-clock sleep, run by `cargo dst-gate` among the other gate tests.
//!
//! | Boundary | Invariant | Tests here |
//! |---|---|---|
//! | Core debounce: reply sent, requester cancelled | a local change is not lost | not duplicated: the daemon's `capture_local_change` tests (reply delivered/undelivered, cancelled, timed out, journal commit failing) |
//! | Core journal: stop or retry before/after persistence | an unfinished operation is never treated as complete | `journal_*` |
//! | Windows: folder ID check, then action | never operate on another group's folder | not duplicated: the Windows repository's folder-id tests |
//! | Apple File Provider: partial copy, then I/O failure | no leftover, an existing file is never deleted | not duplicated: the Apple repository's partial-copy tests |
//! | Sync model: swap order of write / delete / rename | only causally justified changes may disappear | `order_*` |
//!
//! Every test that claims a property also shows the check can fail: the
//! sync-model rows drop a class of watcher events and must see the
//! comparison fail, and the journal rows run a pipeline that clears the
//! journal early (treating the unfinished edit as complete) and must see the
//! no-loss oracle fail. A named fault must also have been injected: the
//! journal fault goes through [`ScheduledInjectors`]'s gate.

use super::boundary_device::{compare, Defect, Delivery, Device, GROUP};
use super::case_ir::{DiskFault, Fault, Op, SimNanos};
use super::directory_model::ExplicitModel;
use super::fault_schedule::{run_schedule, ScheduledInjectors};
use super::fault_sqlite::JournalFault;
use super::{check_no_silent_data_loss, WriteOracle};

fn sim<F: std::future::Future<Output = ()> + 'static>(f: impl FnOnce() -> F + 'static) {
    super::sim::block_on(1, f);
}

// ---- sync model: swap the order of write / delete / rename --------------

fn write(path: &str, content_id: u64) -> Op {
    Op::Write { path: path.to_string(), content_id }
}
fn delete(path: &str) -> Op {
    Op::Delete { path: path.to_string() }
}
fn rename(from: &str, to: &str) -> Op {
    Op::Rename { from: from.to_string(), to: to.to_string() }
}

fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = Vec::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let head = rest.remove(i);
        for mut tail in permutations(&rest) {
            tail.insert(0, head.clone());
            out.push(tail);
        }
    }
    out
}

/// The orderings under test: an indexed file `a` (content 1) and three
/// operations on the pair of names `a`/`b`.
fn order_cases() -> Vec<(&'static str, Vec<Op>)> {
    vec![
        ("edit a, delete a, rename a to b", vec![write("a", 2), delete("a"), rename("a", "b")]),
        ("edit a, rename a to b, write b", vec![write("a", 2), rename("a", "b"), write("b", 3)]),
        ("delete a, write a, rename a to b", vec![delete("a"), write("a", 4), rename("a", "b")]),
    ]
}

/// Runs the case in `order` on a fresh device holding an indexed `a`.
async fn run_order(order: &[Op], delivery: Delivery, defect: Defect) -> Result<(), String> {
    let device = Device::new();
    device.write_file("a", 1);
    let mut base = ExplicitModel::default();
    let base_op = write("a", 1);
    base.apply(&base_op).unwrap();
    device
        .flush_events(super::fs_events::decompose(&super::fs_events::FsOp::Create {
            path: "a".to_string(),
        }))
        .await;
    let model = device.run(base, order, delivery, defect).await;
    compare(&device, &model)
}

/// Every permutation of every case, delivered per operation and as one
/// debounce window: the index ends exactly where the model says. A change
/// the model does not justify (a file lost, a deleted file revived, other
/// content) fails the comparison.
#[test]
fn order_swaps_of_write_delete_rename_lose_nothing_the_model_keeps() {
    sim(|| async {
        let mut failures = Vec::new();
        for (name, ops) in order_cases() {
            for order in permutations(&ops) {
                for delivery in [Delivery::PerOp, Delivery::OneWindow] {
                    if let Err(problem) = run_order(&order, delivery, Defect::None).await {
                        failures
                            .push(format!("{name}: order {order:?} via {delivery:?}: {problem}"));
                    }
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    });
}

/// The check can fail: a pipeline that never sees removals leaves deleted
/// and renamed-away files live, and one that never sees creations loses
/// written and renamed-to files. Both must be caught in some ordering of
/// every case.
#[test]
fn order_swaps_detect_a_pipeline_that_drops_removals_or_creations() {
    sim(|| async {
        for defect in [Defect::DropRemovals, Defect::DropCreations] {
            for (name, ops) in order_cases() {
                let mut caught = false;
                for order in permutations(&ops) {
                    for delivery in [Delivery::PerOp, Delivery::OneWindow] {
                        caught |= run_order(&order, delivery, defect).await.is_err();
                    }
                }
                assert!(caught, "{name}: {defect:?} went unnoticed in every ordering");
            }
        }
    });
}

// ---- core journal: stop or retry before / after persistence -------------

fn journal_spec() -> Vec<(SimNanos, Fault)> {
    vec![(SimNanos::ZERO, Fault::Disk(DiskFault::SqliteBusy))]
}

fn handed_over(
    device: &Device,
    name: &str,
) -> Vec<(std::path::PathBuf, yadorilink_filesystem_sync::watcher::FsChangeKind, i64)> {
    vec![(
        device.root.join(name),
        yadorilink_filesystem_sync::watcher::FsChangeKind::CreatedOrModified,
        1,
    )]
}

fn journal_rows(device: &Device) -> usize {
    device.state.dirty_path_repository().list_dirty_paths(GROUP).unwrap().len()
}

fn live(device: &Device, name: &str) -> bool {
    device
        .state
        .file_index_repository()
        .get_file(GROUP, name)
        .unwrap()
        .is_some_and(|record| !record.deleted)
}

/// Before persistence: the journal write fails, so the edit is neither in the
/// journal nor in the index. It must stay owned (retained, the failure
/// visible) and never read as complete; a retry after the fault clears
/// persists it and the next re-drive captures it.
#[test]
fn journal_write_failing_before_persistence_keeps_the_edit_owed_until_a_retry_lands() {
    sim(|| async {
        let spec = journal_spec();
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        run_schedule(spec, injectors.clone()).await.unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let db = db_dir.path().join("index.db");
        let device = Device::over_file(&db);
        let fault = JournalFault::new(&db, &injectors);
        device.write_file("a.txt", 1);
        fault.engage();

        let handoff = device.processor.journal_handed_over_edits(
            GROUP,
            &device.root,
            &handed_over(&device, "a.txt"),
        );
        assert!(fault.observe(handoff).is_err(), "the journal fault did not refuse the write");
        assert_eq!(journal_rows(&device), 0);
        assert_eq!(device.processor.retained_handoff_count(), 1, "the edit lost its owner");
        assert!(!live(&device, "a.txt"), "an edit nobody persisted read as complete");

        // A retry while the fault holds fails again and keeps the edit.
        let retry = device.processor.retry_retained_handoffs(GROUP);
        assert!(fault.observe(retry).is_err());
        assert_eq!(device.processor.retained_handoff_count(), 1);

        fault.heal();
        device.processor.retry_retained_handoffs(GROUP).expect("retry after heal");
        assert_eq!((journal_rows(&device), device.processor.retained_handoff_count()), (1, 0));
        device.processor.redrive_dirty_journal(GROUP, &device.root).await.expect("re-drive");
        assert!(live(&device, "a.txt"), "the retried edit was never captured");
        assert_eq!(journal_rows(&device), 0, "a captured edit stays journaled");
        injectors.assert_gate();
    });
}

/// After persistence: the row is committed, the processor stops before it
/// captured anything, and a fresh process finishes the work, once. A second
/// re-drive changes nothing.
#[test]
fn journal_stop_after_persistence_is_finished_by_the_next_process_exactly_once() {
    sim(|| async {
        let db_dir = tempfile::tempdir().unwrap();
        let db = db_dir.path().join("index.db");
        let mut device = Device::over_file(&db);
        device.write_file("a.txt", 1);
        device
            .processor
            .journal_handed_over_edits(GROUP, &device.root, &handed_over(&device, "a.txt"))
            .expect("journal commit");
        assert_eq!(journal_rows(&device), 1);
        assert!(!live(&device, "a.txt"), "persisted but not yet captured must not read as done");

        device.restart_over_file(&db);
        assert_eq!(journal_rows(&device), 1, "the committed row did not survive the restart");
        device.processor.redrive_dirty_journal(GROUP, &device.root).await.expect("re-drive");
        assert!(live(&device, "a.txt"));
        assert_eq!(journal_rows(&device), 0);

        let settled = device.state.file_index_repository().list_files(GROUP).unwrap();
        device.processor.redrive_dirty_journal(GROUP, &device.root).await.expect("again");
        assert_eq!(
            device.state.file_index_repository().list_files(GROUP).unwrap(),
            settled,
            "a repeated re-drive authored something"
        );
    });
}

/// The oracle can fail: a pipeline that treats the unfinished edit as
/// complete (clears the journal row without capturing) loses the write, and
/// the no-silent-loss check says so.
#[test]
fn journal_a_pipeline_that_clears_an_unfinished_edit_is_caught_as_a_loss() {
    sim(|| async {
        let db_dir = tempfile::tempdir().unwrap();
        let db = db_dir.path().join("index.db");
        let device = Device::over_file(&db);
        device.write_file("a.txt", 1);
        device
            .processor
            .journal_handed_over_edits(GROUP, &device.root, &handed_over(&device, "a.txt"))
            .unwrap();
        // The defect: the row is cleared as if the edit had been captured.
        rusqlite::Connection::open(&db)
            .unwrap()
            .execute_batch("DELETE FROM local_dirty_paths;")
            .unwrap();
        device.processor.redrive_dirty_journal(GROUP, &device.root).await.unwrap();

        let oracle = WriteOracle::new();
        oracle.record_write("a.txt", &super::boundary_device::bytes_of(1));
        let violations = check_no_silent_data_loss(&oracle, &device.state, GROUP, &device.root);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert!(violations[0].detail.contains("never indexed"), "{violations:?}");
    });
}

/// The gate side: a journal fault that is named but whose write never ran
/// (or ran after the heal) fails the gate.
#[test]
fn journal_fault_that_never_refused_a_write_fails_the_gate() {
    sim(|| async {
        let spec = journal_spec();
        let injectors = ScheduledInjectors::for_spec(&spec).unwrap();
        run_schedule(spec, injectors.clone()).await.unwrap();
        let db_dir = tempfile::tempdir().unwrap();
        let db = db_dir.path().join("index.db");
        let device = Device::over_file(&db);
        let fault = JournalFault::new(&db, &injectors);
        device.write_file("a.txt", 1);
        fault.engage();
        fault.heal();
        let handoff = device.processor.journal_handed_over_edits(
            GROUP,
            &device.root,
            &handed_over(&device, "a.txt"),
        );
        assert!(fault.observe(handoff).is_ok());
        assert!(injectors.verify_gate().is_err(), "a fault that refused nothing passed the gate");
    });
}
