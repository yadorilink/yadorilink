//! Risk-oriented combinatorics for the capture boundary: when a boundary gets
//! pairwise rows and when it gets a triple.
//!
//! # The rule
//!
//! 1. A boundary gets **pairwise** rows by default: an orthogonal array over
//!    its factors, one invariant for every row (the capture boundary's L8 over
//!    source, entry, read fault and peer write is the model, in
//!    `yadorilink-local-capture`'s `pairwise_matrix_tests`). Do not repeat a
//!    pairwise matrix here, and do not add triples over factors an existing
//!    array already covers: an L8 whose fourth factor is the xor of the other
//!    three already meets every three-factor subset of its four factors.
//! 2. A **triple** is added only for a data-loss combination, and only after
//!    the third factor is shown to change the outcome: the two-factor row
//!    passes, and adding the third makes a different recovery path, or a
//!    different correct answer, necessary. "Shown" means a negative control
//!    in this file that fails when the third factor's path is removed.
//! 3. Each triple carries its negative control, and the total gate time is
//!    recorded in the change that adds it.
//!
//! # The matrix here
//!
//! Three factors the L8 does not have, over one data-loss scenario: the user
//! deletes an indexed file and the removal is handed to the journal.
//!
//! * A, the database refuses the journal write (the handed-over removal is
//!   retained in memory only).
//! * B, the process restarts before recovery (memory is gone; only what was
//!   committed, and the disk, remain).
//! * C, the object's provider state when its absence is observed: `Present`
//!   (a user delete) or `Evicting` (the provider is removing it, so the
//!   absence is an echo, not a delete).
//!
//! The expected answer is derived without the pipeline: the index tombstones
//! the file exactly when the object was `Present`. A alone or B alone leaves
//! a committed journal row or a retained handoff that recovery drains; A with
//! B leaves neither, so only the startup rescan can find the delete, and C
//! decides whether that rescan may act on it. Those are the interactions the
//! negative controls remove.
//!
//! # Ordered sequences over several deletes
//!
//! The second block (`Sequence`, below) orders the faults over more than one
//! file: a first removal reaches a healthy journal, the journal then refuses,
//! a further removal is handed to it, the watcher loses another outright, the
//! process may restart, and recovery runs. The oracle is the disk, and it also
//! fails when a file nobody deleted leaves the index. Gate time added: about
//! one second of the roughly twenty the gate spends in the simulation binary.

use super::boundary_device::{Device, GROUP};
use super::case_ir::{DiskFault, Fault, SimNanos};
use super::fault_schedule::{run_schedule, ScheduledInjectors};
use super::fault_sqlite::JournalFault;
use yadorilink_filesystem_sync::debounce::DebounceFlush;
use yadorilink_filesystem_sync::watcher::FsChangeKind;
use yadorilink_replica_domain::session_state::MaterializationState;

fn sim<F: std::future::Future<Output = ()> + 'static>(f: impl FnOnce() -> F + 'static) {
    super::sim::block_on(1, f);
}

#[derive(Clone, Copy, Debug)]
struct Cell {
    journal_fails: bool,
    restarts: bool,
    provider_state: MaterializationState,
}

fn cells() -> Vec<Cell> {
    let mut out = Vec::new();
    for journal_fails in [false, true] {
        for restarts in [false, true] {
            for provider_state in [MaterializationState::Present, MaterializationState::Evicting] {
                out.push(Cell { journal_fails, restarts, provider_state });
            }
        }
    }
    out
}

/// What the index must say, from the cell alone.
fn expect_tombstone(cell: Cell) -> bool {
    cell.provider_state == MaterializationState::Present
}

/// How recovery runs. `Full` is the product's: a restart is followed by the
/// startup rescan, and every run re-drives the journal. `NoRescan` is the
/// defect the negative controls use: a restart that recovers nothing but the
/// journal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Recovery {
    Full,
    NoRescan,
}

async fn run_cell(cell: Cell, recovery: Recovery) -> Result<(), String> {
    let spec: Vec<(SimNanos, Fault)> = if cell.journal_fails {
        vec![(SimNanos::ZERO, Fault::Disk(DiskFault::SqliteBusy))]
    } else {
        Vec::new()
    };
    let injectors = ScheduledInjectors::for_spec(&spec).map_err(|e| e.to_string())?;
    run_schedule(spec, injectors.clone()).await.map_err(|e| e.to_string())?;

    let db_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let db = db_dir.path().join("index.db");
    let mut device = Device::over_file(&db);
    let fault = JournalFault::new(&db, &injectors);

    // An indexed file, then the user deletes it.
    device.write_file("a.txt", 1);
    device
        .flush_events(super::fs_events::decompose(&super::fs_events::FsOp::Create {
            path: "a.txt".to_string(),
        }))
        .await;
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    device
        .state
        .set_materialization_state(GROUP, "a.txt", cell.provider_state, &permit)
        .map_err(|e| e.to_string())?;
    std::fs::remove_file(device.root.join("a.txt")).map_err(|e| e.to_string())?;

    // The removal is handed over to the journal; the database may refuse.
    if cell.journal_fails {
        fault.engage();
    }
    let handoff = device.processor.journal_handed_over_edits(
        GROUP,
        &device.root,
        &[(device.root.join("a.txt"), FsChangeKind::ObservedRemoval, 2)],
    );
    match (cell.journal_fails, fault.observe(handoff)) {
        (true, Ok(())) => return Err("the journal fault did not refuse the write".into()),
        (false, Err(e)) => return Err(format!("a healthy journal refused: {e}")),
        _ => {}
    }

    if cell.restarts {
        device.restart_over_file(&db);
    }
    fault.heal();
    if cell.restarts && recovery == Recovery::Full {
        device
            .processor
            .process_flush(GROUP, &device.root, DebounceFlush::RescanRequired)
            .await
            .map_err(|e| e.to_string())?;
    }
    device.processor.redrive_dirty_journal(GROUP, &device.root).await.map_err(|e| e.to_string())?;

    injectors.verify_gate().map_err(|e| e.to_string())?;
    let row =
        device.state.file_index_repository().get_file(GROUP, "a.txt").map_err(|e| e.to_string())?;
    let tombstoned = row.as_ref().is_some_and(|r| r.deleted);
    if tombstoned != expect_tombstone(cell) {
        return Err(format!(
            "expected tombstone={} but the index says {row:?}",
            expect_tombstone(cell)
        ));
    }
    Ok(())
}

/// Every cell converges to the answer the provider state alone dictates.
#[test]
fn journal_failure_restart_and_provider_state_never_change_what_is_deleted() {
    sim(|| async {
        let mut failures = Vec::new();
        for cell in cells() {
            if let Err(why) = run_cell(cell, Recovery::Full).await {
                failures.push(format!("{cell:?}: {why}"));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    });
}

/// The third factor matters: without the startup rescan, a restart after a
/// refused journal write loses the delete (the retained handoff died with the
/// process), while a restart over a committed row, or a refused write
/// without a restart, still recovers. So the A x B pair needs the rescan, and
/// only the triple with C says whether the rescan may act.
#[test]
fn the_triple_needs_the_startup_rescan_only_where_failure_and_restart_meet() {
    sim(|| async {
        for cell in cells() {
            let outcome = run_cell(cell, Recovery::NoRescan).await;
            let needs_rescan = cell.journal_fails && cell.restarts && expect_tombstone(cell);
            assert_eq!(
                outcome.is_err(),
                needs_rescan,
                "{cell:?} without the rescan: {outcome:?} (the rescan is needed exactly where a \
                 refused journal write meets a restart over a real delete)"
            );
        }
    });
}

// ---------------------------------------------------------------------------
// Ordered sequences over several deletes: the boundaries the single-file
// matrix above does not reach.
//
// One scenario family, one ordered fault sequence per row:
//
//   1. the user deletes some files; the first removal is journaled, the
//      journal then refuses (the fault window opens between two deletes);
//   2. the watcher loses a removal outright (no event, no journal row);
//   3. the process may restart (memory gone);
//   4. recovery runs (rescan after a restart or a lost event, retry of the
//      retained handoffs, re-drive of the journal).
//
// The oracle never reads the pipeline: the disk is the truth. After recovery
// the live index must be exactly the files still on disk, with the content
// they hold, and every removed path must be tombstoned. A file nobody
// deleted ("bystander") that went missing from the index is the "deleted
// someone else's file" failure; a removed file still live is the lost delete.
// ---------------------------------------------------------------------------

/// One ordered row. All files are written and indexed first; then, in this
/// order, `journaled` are removed and handed to a healthy journal, the
/// journal fault opens, `refused` are removed and handed to the refusing
/// journal, and `lost` are removed with no event at all.
struct Sequence {
    name: &'static str,
    files: &'static [&'static str],
    journaled: &'static [&'static str],
    refused: &'static [&'static str],
    lost: &'static [&'static str],
    restarts: bool,
}

/// Rows chosen from the boundaries `risk_matrix_gate`'s first matrix leaves
/// open: a second refusal while an earlier removal is already committed, a
/// removed subtree, and a removal the watcher never reported.
const SEQUENCES: &[Sequence] = &[
    Sequence {
        name: "refused second delete beside a committed first, bystander kept",
        files: &["a.txt", "b.txt", "c.txt"],
        journaled: &["a.txt"],
        refused: &["b.txt"],
        lost: &[],
        restarts: true,
    },
    Sequence {
        name: "the same without a restart",
        files: &["a.txt", "b.txt", "c.txt"],
        journaled: &["a.txt"],
        refused: &["b.txt"],
        lost: &[],
        restarts: false,
    },
    Sequence {
        name: "removed subtree refused, sibling subtree kept",
        files: &["d/x.txt", "d/y.txt", "e/z.txt"],
        journaled: &[],
        refused: &["d/x.txt", "d/y.txt"],
        lost: &[],
        restarts: true,
    },
    Sequence {
        name: "removal the watcher never reported, no restart",
        files: &["a.txt", "b.txt", "c.txt"],
        journaled: &[],
        refused: &[],
        lost: &["a.txt"],
        restarts: false,
    },
    Sequence {
        name: "lost removal beside a refused one, then a restart",
        files: &["a.txt", "b.txt", "c.txt"],
        journaled: &[],
        refused: &["b.txt"],
        lost: &["a.txt"],
        restarts: true,
    },
];

/// Every regular file under `root`, relative, with its bytes.
fn disk_files(root: &std::path::Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    fn walk(
        root: &std::path::Path,
        dir: &std::path::Path,
        out: &mut std::collections::BTreeMap<String, Vec<u8>>,
    ) {
        for entry in std::fs::read_dir(dir).expect("list") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                let rel = path.strip_prefix(root).expect("under root");
                out.insert(rel.to_string_lossy().replace('\\', "/"), std::fs::read(&path).unwrap());
            }
        }
    }
    let mut out = std::collections::BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// What recovery may do in a row. `Full` is the product's. The others are the
/// defects the negative controls use.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SeqRecovery {
    Full,
    /// No rescan: only the retained handoffs and the journal are drained.
    NoRescan,
    /// The journal is never re-driven (which also retries the retained
    /// handoffs): a process that gives up on what it owes.
    NoRedrive,
}

async fn run_sequence(row: &Sequence, recovery: SeqRecovery) -> Result<(), String> {
    let spec = vec![(SimNanos::ZERO, Fault::Disk(DiskFault::SqliteBusy))];
    let injectors = ScheduledInjectors::for_spec(&spec).map_err(|e| e.to_string())?;
    run_schedule(spec, injectors.clone()).await.map_err(|e| e.to_string())?;

    let db_dir = tempfile::tempdir().map_err(|e| e.to_string())?;
    let db = db_dir.path().join("index.db");
    let mut device = Device::over_file(&db);
    let fault = JournalFault::new(&db, &injectors);

    for (i, name) in row.files.iter().enumerate() {
        device.write_file(name, i as u64 + 1);
        device
            .flush_events(super::fs_events::decompose(&super::fs_events::FsOp::Create {
                path: (*name).to_string(),
            }))
            .await;
    }
    let removal = |name: &&str| {
        std::fs::remove_file(device.root.join(name)).map_err(|e| format!("remove {name}: {e}"))
    };
    let handoff = |names: &[&str]| {
        let edits: Vec<_> =
            names.iter().map(|n| (device.root.join(n), FsChangeKind::ObservedRemoval, 2)).collect();
        device.processor.journal_handed_over_edits(GROUP, &device.root, &edits)
    };

    // 1. The first removals reach a healthy journal.
    row.journaled.iter().try_for_each(removal)?;
    if !row.journaled.is_empty() {
        handoff(row.journaled).map_err(|e| format!("a healthy journal refused: {e}"))?;
    }
    // 2. The journal starts refusing; the next removals are handed over to it.
    fault.engage();
    row.refused.iter().try_for_each(removal)?;
    if !row.refused.is_empty() && fault.observe(handoff(row.refused)).is_ok() {
        return Err("the journal fault did not refuse the write".into());
    }
    // 3. The watcher loses a removal: nothing is handed over.
    row.lost.iter().try_for_each(removal)?;

    if row.restarts {
        device.restart_over_file(&db);
    }
    fault.heal();

    // 4. Recovery.
    let needs_rescan = row.restarts || !row.lost.is_empty();
    if needs_rescan && recovery != SeqRecovery::NoRescan {
        device
            .processor
            .process_flush(GROUP, &device.root, DebounceFlush::RescanRequired)
            .await
            .map_err(|e| e.to_string())?;
    }
    if recovery != SeqRecovery::NoRedrive {
        device
            .processor
            .redrive_dirty_journal(GROUP, &device.root)
            .await
            .map_err(|e| e.to_string())?;
    }

    if !row.refused.is_empty() {
        injectors.verify_gate().map_err(|e| e.to_string())?;
    }

    // The oracle: the disk, read directly.
    let on_disk = disk_files(&device.root);
    let mut problems = Vec::new();
    for name in row.files {
        let record = device.state.file_index_repository().get_file(GROUP, name).unwrap();
        let live = record.as_ref().is_some_and(|r| !r.deleted);
        match (on_disk.contains_key(*name), live) {
            (true, false) => problems.push(format!("{name} is on disk but not live: {record:?}")),
            (false, true) => problems.push(format!("{name} was deleted but is still live")),
            (false, false) if record.is_none() => {
                problems.push(format!("{name} was deleted and never tombstoned"));
            }
            _ => {}
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

/// Every row converges to the disk: each removed file tombstoned, each
/// bystander still live.
#[test]
fn ordered_delete_sequences_converge_to_the_disk_and_spare_bystanders() {
    sim(|| async {
        let mut failures = Vec::new();
        for row in SEQUENCES {
            if let Err(why) = run_sequence(row, SeqRecovery::Full).await {
                failures.push(format!("{}: {why}", row.name));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    });
}

/// Each recovery step is needed by exactly the rows that depend on it, so
/// the oracle can fail: without the rescan, a row whose removal only a rescan
/// can find loses it; without the re-drive, a removal only the journal or the
/// retained handoffs hold (no restart, nothing lost) is never found.
#[test]
fn ordered_delete_sequences_need_each_recovery_step_exactly_where_they_depend_on_it() {
    sim(|| async {
        for row in SEQUENCES {
            // Only a rescan can find a removal the process never held.
            let rescan_needed = row.restarts && !row.refused.is_empty() || !row.lost.is_empty();
            let without_rescan = run_sequence(row, SeqRecovery::NoRescan).await;
            assert_eq!(
                without_rescan.is_err(),
                rescan_needed,
                "{}: without the rescan: {without_rescan:?}",
                row.name
            );
            // What the journal holds, or the process retained, is drained only
            // by the re-drive; a row that restarts or lost a removal rescans,
            // and the rescan finds those removals without it.
            let redrive_needed = !row.restarts
                && row.lost.is_empty()
                && !(row.journaled.is_empty() && row.refused.is_empty());
            let without_redrive = run_sequence(row, SeqRecovery::NoRedrive).await;
            assert_eq!(
                without_redrive.is_err(),
                redrive_needed,
                "{}: without the re-drive: {without_redrive:?}",
                row.name
            );
        }
    });
}
