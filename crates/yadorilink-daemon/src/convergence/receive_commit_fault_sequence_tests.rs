#![cfg(all(test, unix))]
//! An ordered fault sequence on the database under a receive: one of the
//! writes the receive makes is refused (the transaction aborts and rolls
//! back, as a `SQLITE_BUSY` that outlasts its retries does), for one pass or
//! several, the process may be replaced or restarted while it is refused, and
//! the fault then clears. A refused write must not read as a finished one,
//! and the redo must be idempotent.
//!
//! The three refused writes are the three the receive makes around its bytes:
//! the pre-write commit that opens the intent, the record of the temp file the
//! write will create, and the commit that closes the write (the bytes are
//! already renamed into place when it is refused).
//!
//! Safety invariants, each read from the disk and the tables, not from the
//! code that decides them:
//!
//! * a row never claims `Present` for a path whose bytes are not the received
//!   ones, and an obligation is never settled unless the bytes are on disk;
//! * while the write is refused the path stays owed: its obligation is open;
//! * after the fault clears, with no new admission, the received bytes land,
//!   the obligation settles, the intent closes and no temp file is left;
//! * running the recovery again changes nothing.
//!
//! The fault is credited by effect against an identical control run: the
//! control (no trigger) lands the file in its first pass, so a faulted run
//! that does not stall was not faulted ([`a_trigger_that_refuses_nothing_...`]).
//! The refusal is an `ABORT` raised by a trigger inside the product's own
//! write transaction; the transaction rolls back and the caller sees an error.
//! A failure of the `COMMIT` statement itself cannot be produced without a seam
//! in the product and is not claimed.

use super::engine::{drive_obligations_once_for_test, ConvergenceEngine};
use super::receive_cost_tests::{content_of, fixture, Fixture, GROUP};

const MARKER: &str = "dst-injected-refusal";

#[derive(Clone, Copy, Debug)]
enum Refused {
    /// The commit that opens the write's intent.
    IntentOpen,
    /// The record of the temp file the write will create.
    TempRecord,
    /// The commit that closes the write, after the rename.
    WriteClose,
}

impl Refused {
    fn trigger(self) -> String {
        let (event, table) = match self {
            Self::IntentOpen => ("INSERT", "materialization_intents"),
            Self::TempRecord => ("INSERT", "materialization_tmp_files"),
            Self::WriteClose => ("DELETE", "materialization_intents"),
        };
        format!(
            "CREATE TRIGGER IF NOT EXISTS dst_refusal BEFORE {event} ON {table} \
             BEGIN SELECT RAISE(ABORT, '{MARKER}'); END;"
        )
    }
}

#[derive(Clone, Copy, Debug)]
enum Restart {
    /// The fault clears and the same engine retries.
    None,
    /// The engine is replaced while the fault holds.
    Engine,
    /// A start (temp removal and repair) runs while the fault holds, and again
    /// after it clears.
    Start,
}

fn sql(f: &Fixture, text: &str) {
    f.state
        .replica_coordinator
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute_batch(text)?;
            Ok(())
        })
        .unwrap();
}

fn let_backoff_elapse(f: &Fixture) {
    sql(f, "UPDATE projection_obligations SET next_attempt_at = 0");
}

fn open_obligation(f: &Fixture, name: &str) -> bool {
    f.state
        .replica_coordinator
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            Ok(yadorilink_sync_sqlite::projection_obligations::lookup_projection_obligation(
                conn, GROUP, name,
            )?
            .is_some_and(|row| row.state == "pending" || row.state == "claimed"))
        })
        .unwrap()
}

fn temp_files(f: &Fixture) -> Vec<String> {
    std::fs::read_dir(&f.root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".yadorilink-tmp."))
        .collect()
}

/// What a start does before it serves: removes the recorded temp files, then
/// repairs interrupted writes. A refused write makes the repair report an
/// error or nothing; either way it must not claim anything done.
fn start(f: &Fixture) {
    let _ = f.state.replica_coordinator.remove_recorded_temp_files(GROUP, &f.root);
    let _ = yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
        f.state.replica_coordinator.as_ref(),
        &*f.executor.store,
        &f.root,
        GROUP,
        yadorilink_filesystem_sync::materialization_repair::RepairMode::Startup,
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    );
}

async fn pass(engine: &ConvergenceEngine) {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        drive_obligations_once_for_test(engine, 128, 256),
    )
    .await
    .expect("one engine pass must not stall");
}

/// The consistency oracle: what the tables claim against what the disk holds.
fn consistent(f: &Fixture, name: &str, content: &[u8]) -> Result<(), String> {
    use yadorilink_replica_domain::session_state::MaterializationState;
    let bytes = f.read(name);
    let present = f.state.replica_coordinator.get_materialization_state(GROUP, name).ok().flatten()
        == Some(MaterializationState::Present);
    if present && bytes.as_deref() != Some(content) {
        return Err(format!(
            "{name} is Present but the disk holds {:?} bytes",
            bytes.map(|b| b.len())
        ));
    }
    if !open_obligation(f, name) && bytes.as_deref() != Some(content) {
        return Err(format!("{name} is settled but the disk does not hold its bytes"));
    }
    Ok(())
}

/// One cell. `faulted_passes` passes run under the refusal. `Err` names the
/// first invariant that broke; `Ok(stalled)` says whether the refusal held
/// the file back (it must when a fault was installed).
async fn run(
    refused: Option<Refused>,
    faulted_passes: usize,
    restart: Restart,
) -> Result<bool, String> {
    let f = fixture(false).await;
    let mut engine = ConvergenceEngine::new(f.state.clone());
    let content = content_of(5000, 9);
    f.admit("held.bin", &f.content_version(&content, 5));

    if let Some(refused) = refused {
        sql(&f, &refused.trigger());
    }
    let mut stalled = false;
    for n in 0..faulted_passes {
        let_backoff_elapse(&f);
        pass(&engine).await;
        stalled |= f.read("held.bin").as_deref() != Some(content.as_slice())
            || open_obligation(&f, "held.bin");
        consistent(&f, "held.bin", &content).map_err(|e| format!("faulted pass {n}: {e}"))?;
        if refused.is_some() && !open_obligation(&f, "held.bin") {
            return Err(format!("faulted pass {n}: the refused write was settled"));
        }
        match restart {
            Restart::None => {}
            Restart::Engine if n == 0 => engine = ConvergenceEngine::new(f.state.clone()),
            Restart::Engine => {}
            Restart::Start if n == 0 => {
                start(&f);
                engine = ConvergenceEngine::new(f.state.clone());
                consistent(&f, "held.bin", &content)
                    .map_err(|e| format!("start under fault: {e}"))?;
            }
            Restart::Start => {}
        }
    }

    // The fault clears. No admission, no event.
    sql(&f, "DROP TRIGGER IF EXISTS dst_refusal");
    if matches!(restart, Restart::Start) {
        start(&f);
    }
    // Wait on the state, not on a pass count: a pass may legitimately skip the
    // path (the group's guard held by a background task) and the next one
    // lands it. A real regression never lands and runs into the deadline.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let_backoff_elapse(&f);
        pass(&engine).await;
        if f.read("held.bin").as_deref() == Some(content.as_slice())
            && !open_obligation(&f, "held.bin")
        {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    if f.read("held.bin").as_deref() != Some(content.as_slice()) {
        return Err("the bytes never landed after the fault cleared".into());
    }
    if open_obligation(&f, "held.bin") {
        return Err("the bytes landed but the obligation stayed open".into());
    }
    if f.state.replica_coordinator.has_materialization_intent(GROUP, "held.bin").unwrap() {
        return Err("the write's intent is still open".into());
    }
    let leftovers = temp_files(&f);
    if !leftovers.is_empty() {
        return Err(format!("temp files left: {leftovers:?}"));
    }
    consistent(&f, "held.bin", &content)?;

    // Redo is idempotent.
    let before = (f.read("held.bin"), std::fs::read_dir(&f.root).unwrap().count());
    start(&f);
    pass(&engine).await;
    if (f.read("held.bin"), std::fs::read_dir(&f.root).unwrap().count()) != before {
        return Err("a second recovery changed the root".into());
    }
    Ok(stalled)
}

/// Every refused write x length of the fault x restart lands the file by
/// itself once the fault clears, and no state ever claimed it done early.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_receive_write_is_never_taken_for_done_and_is_redone_once() {
    // The gate runs the two extreme rows of each refused write (shortest fault
    // with no restart, longest fault with a start under it); the weekly
    // exploration (`DST_SEQUENCES` set) runs the whole product.
    let full = std::env::var_os("DST_SEQUENCES").is_some();
    let rows: Vec<(usize, Restart)> = if full {
        [1, 3]
            .into_iter()
            .flat_map(|n| [Restart::None, Restart::Engine, Restart::Start].map(|r| (n, r)))
            .collect()
    } else {
        vec![(1, Restart::None), (3, Restart::Start)]
    };
    let mut failures = Vec::new();
    for refused in [Refused::IntentOpen, Refused::TempRecord, Refused::WriteClose] {
        for &(faulted_passes, restart) in &rows {
            match run(Some(refused), faulted_passes, restart).await {
                Ok(true) => {}
                Ok(false) => failures.push(format!(
                    "{refused:?} x{faulted_passes} {restart:?}: the refusal never held the file back"
                )),
                Err(why) => failures.push(format!("{refused:?} x{faulted_passes} {restart:?}: {why}")),
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The control: with nothing refused the file lands in the first pass, so a
/// faulted run that stalls was stalled by the fault. And the gate can fail: a
/// run that names no refusal reports that nothing held the file back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_trigger_that_refuses_nothing_is_not_a_fault() {
    assert_eq!(run(None, 1, Restart::None).await, Ok(false), "the control must not stall");
}
