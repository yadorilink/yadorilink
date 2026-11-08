#![cfg(all(test, unix))]
//! A name that is missing after a power cut while a received file's rename was left unflushed for
//! the batch barrier is rebuilt, whatever took it away.
//!
//! Until the barrier has flushed the directory, nothing durable says whether the name vanished
//! because the rename was lost with the cut or because the user deleted the file in the window
//! (a write lands only once its rename is on stable storage). A lost rename must not be read as a
//! delete, so both are rebuilt: a delete made in that window and lost to a power cut is
//! reverted. The file comes back; no bytes are lost. A delete after the write landed (a durable
//! per-file flush) stands, see `a_delete_after_a_per_file_flushed_write_stands_across_a_restart`.
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
    /// The rename did not: a replaced object is back.
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
    // Every missing name is rebuilt, a delete in the window included, and nothing is journaled
    // as the user's.
    assert!(exists, "a file that was not durably removed is gone: {context}");
    assert!(!case.h.state.is_path_dirty(GROUP, &case.name).unwrap(), "{context}");
    if fate == Fate::UserDeleteDurable || fate == Fate::RenameAndReplacedObjectLost {
        assert_eq!(std::fs::read(case.h.path(&case.name)).unwrap(), case.new, "{context}");
    }
    // The control the matrix rests on: a file nobody removed ends up with the received bytes.
    if fate == Fate::NothingLost {
        assert_eq!(std::fs::read(case.h.path(&case.name)).unwrap(), case.new, "{context}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_file_deleted_in_the_window_before_its_commit_is_rebuilt() {
    run(Window::RenamedNotCommitted, false, Fate::UserDeleteDurable).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_file_deleted_in_the_window_while_its_flush_was_owed_is_rebuilt() {
    run(Window::CommittedFlushPending, false, Fate::UserDeleteDurable).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replaced_file_deleted_in_the_window_before_the_commit_is_rebuilt() {
    run(Window::RenamedNotCommitted, true, Fate::UserDeleteDurable).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replaced_file_deleted_in_the_window_while_its_flush_was_owed_is_rebuilt() {
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
/// moments ago): if the cut loses both, the name is missing and no one deleted it.
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

/// A rename left unflushed does not land: the intent stays `prepared` until the proof turns it
/// `flush_pending`, so no cut can make a missing name the user's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unflushed_rename_is_never_marked_landed() {
    for replacing in [false, true] {
        let tag = format!("rec{}", replacing as u8);
        let case = receive(Window::RenamedNotCommitted, replacing, &tag).await;
        let landed = case
            .h
            .state
            .database()
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                yadorilink_sync_sqlite::write_landed_unproven(conn, GROUP, &case.name)
            })
            .unwrap();
        assert!(!landed, "replacing={replacing}");
        assert_eq!(
            super::receive_deferred_flush_tests::intent_phase(&case.h, &case.name).as_deref(),
            Some("prepared")
        );
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

/// A temp that went through barrier 1 is abandoned (a local edit landed at the name after the
/// barrier): the user's bytes stay and the temp is removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_abandoned_flushed_temp_is_removed_and_the_users_bytes_stay() {
    let h = Harness::new(false);
    pin_concurrency(&h, 4);
    use_deferred(&h, FULL_FLUSH_EACH);
    let files = names("abandon-", 1);
    publish_one(&h, &files[0]).await;
    // The hook runs after barrier 1 and before the rename: a user write
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
}

async fn publish_one(h: &Harness, name: &str) -> Vec<u8> {
    let content = format!("content of {name}").into_bytes();
    let version = source(h, name, &content).await;
    publish(h, &[put(name, version)]);
    content
}

/// A temp whose directory flush failed is not renamed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_directory_flush_that_fails_stops_the_rename() {
    let h = Harness::new(false);
    pin_concurrency(&h, 4);
    use_deferred(&h, FULL_FLUSH_EACH);
    let files = names("noflush-", 1);
    publish_one(&h, &files[0]).await;
    let root = h.path("").to_string_lossy().trim_end_matches('/').to_owned();
    let _fail = yadorilink_local_storage::fail_received_flushes_of(&root);

    let _ = reconcile(&h, &files).await;

    assert!(!h.path(&files[0]).exists(), "a file whose temp name could not be flushed was renamed");
}

/// A directory lost with the cut (never flushed itself) makes every entry in it look gone, which
/// is no delete. Two files of the lost directory: rebuilding the first re-creates the (empty)
/// directory, and the second must not then read as removed by the user.
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
    // The cut loses the directory itself, with the files and the temps that were in it.
    std::fs::remove_dir_all(h.path("sub")).unwrap();
    // Something re-creates the directory before repair runs (a restore, a receive): it is back,
    // empty.
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
