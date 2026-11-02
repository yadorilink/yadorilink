#![cfg(all(test, unix))]
//! A user delete made durable in the window between a received file's unflushed rename and the
//! batch barrier, followed by a power cut, must stand; a rename the cut lost must be rebuilt.
//!
//! After the cut the name is missing either way. What tells the two apart is only what the
//! write's intent durably recorded: that an object stood at the name when it opened (a rename
//! over an object cannot make the name vanish), or, for a new name, that its temp's directory
//! entry was flushed before the rename (the temp still there means the rename was lost, gone
//! means it was durable and the name was then removed).
//!
//! The product is not simulated: each case drives the real receive up to the window, applies the
//! physical outcome the model says the cut left, and runs the real startup repair.

use super::growing_file_projection_tests::{Harness, GROUP};
use super::receive_deferred_flush_tests::{
    closed, intent_open, startup, use_deferred, FULL_FLUSH_EACH,
};
use super::receive_window_concurrency_tests::{
    arm, driver, names, pin_concurrency, publish, put, reconcile, source,
};
use super::{OverlapProbe, ProbeSeam};

/// Where the receive is when the cut comes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Window {
    /// Renamed in without a flush, stopped before its commit: no marker, no proof.
    RenamedNotCommitted,
    /// Committed with the flush-pending marker, the barrier's flush failed: proof, marker.
    CommittedFlushPending,
}

/// What the power cut left at the name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fate {
    /// The user's delete reached stable storage (and with it the rename before it).
    UserDeleteDurable,
    /// The rename did not: the temp is still there, and a replaced object is back.
    RenameLost,
    /// Neither the rename nor the replaced object's own name (a file the user created that was
    /// never flushed) reached stable storage: the name is missing, the temp is still there.
    RenameAndReplacedObjectLost,
    /// Nothing was lost.
    NothingLost,
}

struct Case {
    h: Harness,
    name: String,
    old: Option<Vec<u8>>,
    new: Vec<u8>,
}

fn facts(h: &Harness, name: &str) -> Option<yadorilink_sync_sqlite::WriteRemovalFacts> {
    h.state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::write_removal_facts(conn, GROUP, name)
        })
        .unwrap()
}

async fn receive(window: Window, replacing: bool, tag: &str) -> Case {
    let h = Harness::new(false);
    pin_concurrency(&h, 4);
    use_deferred(&h, FULL_FLUSH_EACH);
    if window == Window::RenamedNotCommitted {
        // A power cut stops every task. Here the batch that flushes the renamed names would
        // otherwise be closed by its 20 ms timer on a task of its own: a flush that ran before
        // the test's "cut" makes the rename durable and releases the temp's ledger record, which
        // a lost rename cannot have done.
        h.convergence
            .completion_max_latency_override_ms
            .store(600_000, std::sync::atomic::Ordering::Relaxed);
    }
    let files = names(&format!("{tag}-"), 1);
    let name = files[0].clone();
    let mut old = None;
    if replacing {
        let content = format!("previous content of {name}").into_bytes();
        let version = source(&h, &format!("{tag}-old"), &content).await;
        publish(&h, &[put(&name, version)]);
        reconcile(&h, &files).await;
        h.convergence.drain_flush_barriers().await;
        assert!(closed(&h, &name), "the previous version is closed and durable");
        old = Some(content);
    }
    let new = format!("current content of {name}, different").into_bytes();
    let version = source(&h, &format!("{tag}-new"), &new).await;
    publish(&h, &[put(&name, version)]);
    match window {
        Window::RenamedNotCommitted => {
            let probe = OverlapProbe::new(ProbeSeam::BeforeCommit, 1, 30_000);
            probe.hold_until_released();
            arm(&h, &probe);
            let task = {
                let (convergence, files) = (h.convergence.clone(), files.clone());
                tokio::spawn(async move {
                    convergence
                        .reconcile_paths_directly(&driver(), GROUP, files.into_iter().collect())
                        .await
                })
            };
            let waited = std::time::Instant::now();
            while probe.in_flight() < 1 {
                assert!(waited.elapsed() < std::time::Duration::from_secs(30));
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            task.abort();
            let _ = task.await;
            *h.convergence.overlap_probe.lock().unwrap() = None;
        }
        Window::CommittedFlushPending => {
            let _fail = yadorilink_local_storage::fail_received_flushes_of(&format!("{tag}-"));
            let attempt = reconcile(&h, &files).await;
            assert!(attempt.is_settled(&name));
            let reports = h.convergence.drain_flush_barriers().await;
            assert_eq!(reports.iter().map(|r| r.failed).sum::<usize>(), 1, "{reports:?}");
        }
    }
    assert!(intent_open(&h, &name), "setup: the write is unsettled");
    assert_eq!(std::fs::read(h.path(&name)).unwrap(), new, "setup: renamed in");
    Case { h, name, old, new }
}

impl Case {
    fn cut(&self, fate: Fate) {
        let path = self.h.path(&self.name);
        match fate {
            Fate::NothingLost => {}
            Fate::UserDeleteDurable => std::fs::remove_file(&path).unwrap(),
            Fate::RenameLost | Fate::RenameAndReplacedObjectLost => {
                std::fs::remove_file(&path).unwrap();
                let witness = facts(&self.h, &self.name)
                    .and_then(|f| f.temp_witness)
                    .expect("a rename left unflushed is preceded by a recorded witness");
                std::fs::write(path.with_file_name(witness), &self.new).unwrap();
                if let (Fate::RenameLost, Some(old)) = (fate, &self.old) {
                    std::fs::write(&path, old).unwrap();
                }
            }
        }
    }
}

async fn run(window: Window, replacing: bool, fate: Fate) {
    let tag = format!("u{}{}{}", window as u8, replacing as u8, fate as u8);
    let case = receive(window, replacing, &tag).await;
    case.cut(fate);

    let report = startup(&case.h);

    let exists = case.h.path(&case.name).exists();
    let context = format!("{window:?} replacing={replacing} {fate:?}: {report:?}");
    match fate {
        Fate::UserDeleteDurable => {
            assert!(!exists, "the user's delete was undone: {context}");
            assert!(report.reconstructed.is_empty(), "{context}");
            assert!(
                case.h.state.is_path_dirty(GROUP, &case.name).unwrap(),
                "the removal is journaled so capture authors it: {context}"
            );
        }
        Fate::RenameLost | Fate::RenameAndReplacedObjectLost | Fate::NothingLost => {
            assert!(exists, "a file that was not removed is gone: {context}");
            assert!(!case.h.state.is_path_dirty(GROUP, &case.name).unwrap(), "{context}");
        }
    }
    // The control the matrix rests on: a file nobody removed ends up with the received bytes.
    if fate == Fate::NothingLost {
        assert_eq!(std::fs::read(case.h.path(&case.name)).unwrap(), case.new, "{context}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_file_the_user_deleted_before_its_commit_stays_deleted() {
    run(Window::RenamedNotCommitted, false, Fate::UserDeleteDurable).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_file_the_user_deleted_while_its_flush_was_owed_stays_deleted() {
    run(Window::CommittedFlushPending, false, Fate::UserDeleteDurable).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replaced_file_the_user_deleted_before_the_commit_stays_deleted() {
    run(Window::RenamedNotCommitted, true, Fate::UserDeleteDurable).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replaced_file_the_user_deleted_while_its_flush_was_owed_stays_deleted() {
    run(Window::CommittedFlushPending, true, Fate::UserDeleteDurable).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_name_whose_rename_was_lost_is_rebuilt() {
    run(Window::RenamedNotCommitted, false, Fate::RenameLost).await;
    run(Window::CommittedFlushPending, false, Fate::RenameLost).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replaced_file_whose_rename_was_lost_is_not_removed() {
    run(Window::RenamedNotCommitted, true, Fate::RenameLost).await;
    run(Window::CommittedFlushPending, true, Fate::RenameLost).await;
}

/// The object a rename replaces is not necessarily durable itself (a file the user created
/// moments ago): if the cut loses both, the name is missing and no one deleted it. The temp is
/// still there, which is what says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replaced_object_lost_with_the_rename_is_rebuilt_not_read_as_a_delete() {
    run(Window::RenamedNotCommitted, true, Fate::RenameAndReplacedObjectLost).await;
    run(Window::CommittedFlushPending, true, Fate::RenameAndReplacedObjectLost).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_nobody_removed_is_unchanged_by_the_rule() {
    for window in [Window::RenamedNotCommitted, Window::CommittedFlushPending] {
        for replacing in [false, true] {
            run(window, replacing, Fate::NothingLost).await;
        }
    }
}

/// Every rename left unflushed is preceded by a recorded witness, new name or replacement,
/// committed before the rename.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_intent_records_the_flushed_temp_name_before_the_rename() {
    for replacing in [false, true] {
        let tag = format!("rec{}", replacing as u8);
        let case = receive(Window::RenamedNotCommitted, replacing, &tag).await;
        let facts = facts(&case.h, &case.name).expect("an intent is open");
        let witness = facts.temp_witness.expect("the temp's flushed name is recorded");
        assert!(witness.starts_with(".yadorilink-tmp."), "{witness}");
        assert!(!case.h.path(&witness).exists(), "the rename moved the witnessed temp away");
    }
}

fn temps_beside(h: &Harness) -> Vec<String> {
    std::fs::read_dir(h.path(""))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".yadorilink-tmp."))
        .collect()
}

/// A temp whose flushed name was recorded is abandoned (a local edit landed at the name after the
/// barrier): the witness is withdrawn BEFORE the temp is removed, so a witness whose temp is gone
/// can only mean "renamed".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_abandoned_witnessed_temp_leaves_no_witness_behind() {
    let h = Harness::new(false);
    pin_concurrency(&h, 4);
    use_deferred(&h, FULL_FLUSH_EACH);
    let files = names("abandon-", 1);
    publish_one(&h, &files[0]).await;
    // The hook runs after barrier 1 recorded the witness and before the rename: a user write
    // lands at the name, so the receive publishes nothing and removes its temp.
    *h.convergence.between_assemble_and_persist_hook.lock().unwrap() =
        Some(Box::new(|out_path| std::fs::write(out_path, b"the user's own bytes").unwrap()));

    let _ = reconcile(&h, &files).await;

    assert_eq!(
        std::fs::read(h.path(&files[0])).unwrap(),
        b"the user's own bytes",
        "the user's bytes were left in place"
    );
    assert_eq!(temps_beside(&h), Vec::<String>::new(), "the abandoned temp was removed");
    if let Some(facts) = facts(&h, &files[0]) {
        assert_eq!(facts.temp_witness, None, "the witness outlived its temp: {facts:?}");
    }
}

async fn publish_one(h: &Harness, name: &str) -> Vec<u8> {
    let content = format!("content of {name}").into_bytes();
    let version = source(h, name, &content).await;
    publish(h, &[put(name, version)]);
    content
}

/// The batch that flushes the temps' names records them or refuses the renames: a temp whose
/// directory flush failed is not renamed and no witness is recorded for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_directory_flush_that_fails_stops_the_rename_and_records_nothing() {
    let h = Harness::new(false);
    pin_concurrency(&h, 4);
    use_deferred(&h, FULL_FLUSH_EACH);
    let files = names("noflush-", 1);
    publish_one(&h, &files[0]).await;
    let root = h.path("").to_string_lossy().trim_end_matches('/').to_owned();
    let _fail = yadorilink_local_storage::fail_received_flushes_of(&root);

    let _ = reconcile(&h, &files).await;

    assert!(!h.path(&files[0]).exists(), "a file whose temp name could not be flushed was renamed");
    if let Some(facts) = facts(&h, &files[0]) {
        assert_eq!(facts.temp_witness, None, "{facts:?}");
    }
}

/// The startup sweep keeps a temp an open intent names as its witness: whether it is still there
/// is the evidence the repair that follows decides by.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_startup_sweep_keeps_a_witnessed_temp_until_its_intent_is_gone() {
    let case = receive(Window::RenamedNotCommitted, false, "sweep").await;
    case.cut(Fate::RenameLost);
    let witness = facts(&case.h, &case.name).unwrap().temp_witness.unwrap();
    let temp = case.h.path(&witness);
    assert!(temp.exists(), "setup: the lost rename left its temp");
    let recorded = case.h.state.temp_ledger(GROUP).list().unwrap();
    assert!(
        recorded.iter().any(|r| std::path::Path::new(r) == temp),
        "setup: the unflushed rename's temp is still in the ledger: {recorded:?} (temp {temp:?})"
    );

    let removed = case.h.state.remove_recorded_temp_files(GROUP, &case.h.path("")).unwrap();
    assert!(!removed.contains(&temp), "the witnessed temp was swept before repair: {removed:?}");
    assert!(temp.exists());

    let report = startup(&case.h);
    // Repair rebuilt the file and closed the intent; now the temp is an ordinary stray.
    let intent_still_open = intent_open(&case.h, &case.name);
    let facts_after = facts(&case.h, &case.name);
    let temp_still_there = temp.exists();
    let removed = case.h.state.remove_recorded_temp_files(GROUP, &case.h.path("")).unwrap();
    assert!(
        removed.contains(&temp),
        "the sweep after repair removed {removed:?}; repair: {report:?}; intent still open: \
         {intent_still_open}; facts: {facts_after:?}; temp still on disk before the sweep: \
         {temp_still_there}"
    );
}

/// A second receive of a path whose first receive still owes its flush records its own witness:
/// with both renames lost the name is missing and that is no delete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_write_over_a_file_still_owed_its_flush_has_its_own_witness() {
    for fate in [Fate::UserDeleteDurable, Fate::RenameLost] {
        let tag = format!("twice{}", fate as u8);
        // The first receive: renamed in, committed, its barrier's flush failed.
        let mut case = receive(Window::CommittedFlushPending, false, &tag).await;
        // The second receive of the same path, stopped before its commit.
        let files = vec![case.name.clone()];
        let new = format!("second content of {}, different again", case.name).into_bytes();
        let version = source(&case.h, &format!("{tag}-second"), &new).await;
        publish(&case.h, &[put(&case.name, version)]);
        let probe = OverlapProbe::new(ProbeSeam::BeforeCommit, 1, 30_000);
        probe.hold_until_released();
        arm(&case.h, &probe);
        let task = {
            let (convergence, files) = (case.h.convergence.clone(), files.clone());
            tokio::spawn(async move {
                convergence
                    .reconcile_paths_directly(&driver(), GROUP, files.into_iter().collect())
                    .await
            })
        };
        let waited = std::time::Instant::now();
        while probe.in_flight() < 1 {
            assert!(waited.elapsed() < std::time::Duration::from_secs(30));
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        task.abort();
        let _ = task.await;
        *case.h.convergence.overlap_probe.lock().unwrap() = None;
        case.new = new;
        let facts_now = facts(&case.h, &case.name).expect("the second write's intent is open");
        assert!(facts_now.temp_witness.is_some(), "{facts_now:?}");

        case.cut(fate);
        let report = startup(&case.h);

        let exists = case.h.path(&case.name).exists();
        match fate {
            Fate::UserDeleteDurable => {
                assert!(!exists, "the user's delete was undone: {report:?}")
            }
            _ => assert!(exists, "a lost rename was read as a delete: {report:?}"),
        }
    }
}

/// A write whose fence moved between its open and barrier 1 (a capture, an edit) is refused by
/// the batch: nothing is renamed and no witness is recorded for it, because nothing says the
/// temp the witness would name is the one this intent's write renames.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_whose_fence_moved_before_barrier_one_is_not_renamed_and_not_witnessed() {
    let h = Harness::new(false);
    pin_concurrency(&h, 4);
    use_deferred(&h, FULL_FLUSH_EACH);
    let files = names("moved-", 1);
    publish_one(&h, &files[0]).await;
    let hold = super::received_flush_barrier::test_hold::hold_temp_flushes_under(
        h.path("").to_string_lossy().trim_end_matches('/'),
    );
    let task = {
        let (convergence, files) = (h.convergence.clone(), files.clone());
        tokio::spawn(async move {
            let _ = convergence
                .reconcile_paths_directly(&driver(), GROUP, files.into_iter().collect())
                .await;
        })
    };
    while hold.entered() == 0 {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    h.state.dag_bump_mutation_fence(GROUP, &files[0], "other_mutator").unwrap();
    drop(hold);
    task.await.unwrap();

    assert!(!h.path(&files[0]).exists(), "a write whose witness was refused was renamed");
    if let Some(facts) = facts(&h, &files[0]) {
        assert_eq!(facts.temp_witness, None, "{facts:?}");
    }
}

/// The temp can only vouch for the name if the directory it was in is there: a directory lost with
/// the cut (never flushed itself) makes every entry in it look gone, which is no delete. Two files
/// of the lost directory: rebuilding the first re-creates the (empty) directory, and the second
/// must not then read as removed by the user.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_parent_directory_is_not_read_as_the_users_delete() {
    let h = Harness::new(false);
    pin_concurrency(&h, 4);
    use_deferred(&h, FULL_FLUSH_EACH);
    let files = vec!["sub/a.txt".to_owned(), "sub/b.txt".to_owned()];
    let mut contents = Vec::new();
    for (i, name) in files.iter().enumerate() {
        let content = format!("content of {name}").into_bytes();
        let version = source(&h, &format!("parent{i}"), &content).await;
        publish(&h, &[put(name, version)]);
        contents.push(content);
    }
    let probe = OverlapProbe::new(ProbeSeam::BeforeCommit, 2, 30_000);
    probe.hold_until_released();
    arm(&h, &probe);
    let task = {
        let (convergence, files) = (h.convergence.clone(), files.clone());
        tokio::spawn(async move {
            convergence
                .reconcile_paths_directly(&driver(), GROUP, files.into_iter().collect())
                .await
        })
    };
    let waited = std::time::Instant::now();
    while probe.in_flight() < 2 {
        assert!(waited.elapsed() < std::time::Duration::from_secs(30));
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    task.abort();
    let _ = task.await;
    *h.convergence.overlap_probe.lock().unwrap() = None;
    for name in &files {
        assert!(facts(&h, name).and_then(|f| f.temp_witness).is_some(), "setup: {name} witnessed");
    }
    // The cut loses the directory itself, with the files and the temps that were in it.
    std::fs::remove_dir_all(h.path("sub")).unwrap();
    // Link start withdraws the witnesses whose directory is gone before anything can re-create
    // it, and then something does (a restore, a receive, a rebuild of another file): the
    // directory is back, empty, and the temps are not in it.
    let withdrawn = h.state.withdraw_witnesses_without_their_directory(GROUP, &h.path("")).unwrap();
    assert_eq!(withdrawn, 2);
    std::fs::create_dir(h.path("sub")).unwrap();

    let report = startup(&h);

    for (name, content) in files.iter().zip(&contents) {
        assert_eq!(
            std::fs::read(h.path(name)).ok().as_ref(),
            Some(content),
            "{name} was lost with its directory and read as a delete: {report:?}"
        );
    }
}
