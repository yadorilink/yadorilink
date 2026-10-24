#![cfg(all(test, unix))]
//! The deferred receive flush (`YADORILINK_RECEIVE_DEFERRED_FSYNC`):
//! the files of a run are renamed in without their own flush, commit with their
//! write intent kept open, and are flushed together by one barrier that clears
//! the intents of the files that reached stable storage. A barrier that fails
//! keeps the intents, and startup repair rebuilds a torn file in place.

use std::sync::atomic::Ordering;

use yadorilink_fs_platform::fs_identity::FileIdentity;
use yadorilink_local_capture::LocalChangeOutcome;
use yadorilink_replica_domain::session_state::MaterializationState;

use super::growing_file_projection_tests::{Harness, GROUP};
use super::receive_window_concurrency_tests::{
    names, pin_concurrency, publish_new_files, reconcile,
};

pub(super) const FULL_FLUSH_EACH: u8 = 1;
pub(super) const SINGLE_BARRIER: u8 = 2;
const OFF: u8 = 3;

pub(super) fn use_deferred(h: &Harness, mode: u8) {
    h.convergence.deferred_flush_override.store(mode, Ordering::Relaxed);
}

pub(super) fn proven(h: &Harness, path: &str) -> bool {
    h.state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::materialized_generation::lookup_materialized_generation(
                conn, GROUP, path,
            )
        })
        .unwrap()
        .is_some()
}

pub(super) fn present(h: &Harness, path: &str) -> bool {
    h.state.get_materialization_state(GROUP, path).unwrap() == Some(MaterializationState::Present)
}

pub(super) fn intent_open(h: &Harness, path: &str) -> bool {
    h.state.has_materialization_intent(GROUP, path).unwrap()
}

/// The fence the open write intent is marked as waiting for, if it is marked.
fn marker(h: &Harness, path: &str) -> Option<i64> {
    h.state
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            Ok(conn
                .query_row(
                    "SELECT mutation_generation FROM materialization_intents \
                     WHERE group_id = ?1 AND path = ?2 AND kind = 'write'",
                    rusqlite::params![GROUP, path],
                    |r| r.get::<_, Option<i64>>(0),
                )
                .ok()
                .flatten())
        })
        .unwrap()
}

/// Closed as an ordinary durable write: proof, `Present`, no intent.
pub(super) fn closed(h: &Harness, path: &str) -> bool {
    proven(h, path) && present(h, path) && !intent_open(h, path)
}

/// Committed but waiting for the barrier: proof, `Present`, intent open and marked.
pub(super) fn flush_pending(h: &Harness, path: &str) -> bool {
    proven(h, path) && present(h, path) && intent_open(h, path) && marker(h, path).is_some()
}

pub(super) fn repair(
    h: &Harness,
    mode: yadorilink_filesystem_sync::materialization_repair::RepairMode,
) -> yadorilink_filesystem_sync::materialization_repair::MaterializationRepairReport {
    yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
        h.state.as_ref(),
        &*h.convergence.store,
        &h.path(""),
        GROUP,
        mode,
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    )
    .unwrap()
}

pub(super) fn startup(
    h: &Harness,
) -> yadorilink_filesystem_sync::materialization_repair::MaterializationRepairReport {
    repair(h, yadorilink_filesystem_sync::materialization_repair::RepairMode::Startup)
}

/// A file received under a failing barrier: proven and `Present`, its intent
/// still open and marked.
async fn received_with_failed_barrier(h: &Harness, prefix: &str) -> (String, Vec<u8>) {
    pin_concurrency(h, 4);
    use_deferred(h, FULL_FLUSH_EACH);
    let files = names(prefix, 1);
    let contents = publish_new_files(h, &files).await;
    let _fail = yadorilink_local_storage::fail_received_flushes_of(prefix);
    let attempt = reconcile(h, &files).await;
    assert!(attempt.is_settled(&files[0]));
    let reports = h.convergence.drain_flush_barriers().await;
    assert_eq!(reports.iter().map(|r| r.failed).sum::<usize>(), 1, "{reports:?}");
    assert!(flush_pending(h, &files[0]));
    let content = contents[&files[0]].clone();
    (files[0].clone(), content)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_run_is_flushed_by_one_barrier_that_then_clears_every_intent() {
    for mode in [FULL_FLUSH_EACH, SINGLE_BARRIER] {
        let h = Harness::new(false);
        pin_concurrency(&h, 8);
        use_deferred(&h, mode);
        let files = names(&format!("run{mode}-"), 6);
        let contents = publish_new_files(&h, &files).await;

        let attempt = reconcile(&h, &files).await;
        let reports = h.convergence.drain_flush_barriers().await;

        for name in &files {
            assert!(attempt.is_settled(name), "{name}");
            assert_eq!(&std::fs::read(h.path(name)).unwrap(), &contents[name]);
            assert!(closed(&h, name), "{name} is closed once the barrier ran");
        }
        assert_eq!(reports.len(), 1, "one barrier for the run: {reports:?}");
        assert_eq!((reports[0].flushed, reports[0].failed, reports[0].cleared), (6, 0, 6));
    }
}

/// A file the barrier could not flush keeps its intent (and so its protection),
/// and the files that were flushed are cleared.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_flush_keeps_that_files_intent_and_clears_the_others() {
    let h = Harness::new(false);
    pin_concurrency(&h, 8);
    use_deferred(&h, FULL_FLUSH_EACH);
    let mut files = names("good-", 3);
    files.extend(names("badflush-", 2));
    publish_new_files(&h, &files).await;
    let _fail = yadorilink_local_storage::fail_received_flushes_of("badflush-");

    let attempt = reconcile(&h, &files).await;
    let reports = h.convergence.drain_flush_barriers().await;

    assert!(files.iter().all(|name| attempt.is_settled(name)));
    assert_eq!((reports[0].flushed, reports[0].failed, reports[0].cleared), (3, 2, 3));
    for name in files.iter().filter(|n| n.starts_with("good-")) {
        assert!(closed(&h, name), "{name}");
    }
    for name in files.iter().filter(|n| n.starts_with("badflush-")) {
        assert!(flush_pending(&h, name), "{name} stays waiting for its flush");
    }
}

/// The intent is never cleared before the flush: when the single drive flush
/// fails, every file is still exactly waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_is_cleared_when_the_single_barrier_fails() {
    let h = Harness::new(false);
    pin_concurrency(&h, 8);
    use_deferred(&h, SINGLE_BARRIER);
    let files = names("onebarrier-", 4);
    publish_new_files(&h, &files).await;
    let _fail = yadorilink_local_storage::fail_received_flushes_of("onebarrier-");

    reconcile(&h, &files).await;
    let reports = h.convergence.drain_flush_barriers().await;

    assert_eq!((reports[0].flushed, reports[0].failed, reports[0].cleared), (0, 4, 0));
    assert!(files.iter().all(|name| flush_pending(&h, name)));
}

/// Startup repair finds the bytes intact and closes the intent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startup_closes_an_unflushed_file_whose_bytes_are_intact() {
    let h = Harness::new(false);
    let (name, content) = received_with_failed_barrier(&h, "intact-").await;

    let report = startup(&h);

    assert!(report.quarantined_dirty.is_empty(), "{report:?}");
    assert_eq!(std::fs::read(h.path(&name)).unwrap(), content);
    assert!(closed(&h, &name));
}

/// Same-size garbage under the object the proof recorded: a torn flush. Rebuilt
/// in place from the blocks, with no conflict copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startup_rebuilds_a_torn_file_in_place_without_a_conflict_copy() {
    let h = Harness::new(false);
    let (name, content) = received_with_failed_barrier(&h, "torn-").await;
    tear_in_place(&h, &name, content.len());
    // What a crash leaves: the data lost, the metadata the proof recorded.
    record_observed_identity_as_proof(&h, &name);

    let report = startup(&h);

    assert!(report.quarantined_dirty.is_empty(), "{report:?}");
    assert!(report.reconstructed.contains(&name), "{report:?}");
    assert_eq!(std::fs::read(h.path(&name)).unwrap(), content);
    assert!(closed(&h, &name));
    assert_eq!(conflict_copies(&h), 0);
}

/// Bytes the proof's object does not account for (a user edit after the file
/// was received) are not the lost flush's: they are quarantined as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startup_still_quarantines_bytes_that_the_proof_does_not_describe() {
    let h = Harness::new(false);
    let (name, content) = received_with_failed_barrier(&h, "edited-").await;
    tear_in_place(&h, &name, content.len());

    let report = startup(&h);

    assert_eq!(report.quarantined_dirty.len(), 1, "{report:?}");
    assert_eq!(std::fs::read(h.path(&name)).unwrap(), content);
    assert!(closed(&h, &name));
}

/// A file that is missing under the waiting intent is rebuilt, never read as an
/// offline delete.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startup_rebuilds_a_missing_file_under_a_waiting_intent() {
    let h = Harness::new(false);
    let (name, content) = received_with_failed_barrier(&h, "lost-").await;
    std::fs::remove_file(h.path(&name)).unwrap();

    let report = startup(&h);

    assert!(report.offline_deleted.is_empty(), "{report:?}");
    assert_eq!(std::fs::read(h.path(&name)).unwrap(), content);
    assert!(closed(&h, &name));
}

/// A live pass leaves a file whose barrier is still to run to that barrier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_live_repair_pass_leaves_a_waiting_file_to_its_barrier() {
    let h = Harness::new(false);
    let (name, _) = received_with_failed_barrier(&h, "live-").await;

    let report = repair(&h, yadorilink_filesystem_sync::materialization_repair::RepairMode::Live);

    assert!(report.reproven.is_empty() && report.reconstructed.is_empty(), "{report:?}");
    assert!(flush_pending(&h, &name), "the live pass did not clear the waiting intent");
}

/// With the knob off nothing is deferred: every file closes by itself, no
/// barrier exists, and no intent is ever marked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn with_the_knob_off_every_file_closes_durably_by_itself() {
    let h = Harness::new(false);
    pin_concurrency(&h, 8);
    use_deferred(&h, OFF);
    let files = names("off-", 4);
    publish_new_files(&h, &files).await;

    let attempt = reconcile(&h, &files).await;

    assert!(files.iter().all(|name| attempt.is_settled(name) && closed(&h, name)));
    assert!(h.convergence.drain_flush_barriers().await.is_empty());
}

#[test]
fn only_macos_defers_by_default_and_zero_opts_out() {
    use super::completion_window::parse_deferred_flush;
    use yadorilink_local_storage::ReceivedFlushMode::{FsyncThenOneFullFsync, FullFsyncEach};
    // Unset: the Apple default is the conservative mode (one F_FULLFSYNC per
    // file, off the critical path); every other platform keeps the per-file flush.
    let unset = if cfg!(target_vendor = "apple") { Some(FullFsyncEach) } else { None };
    assert_eq!(parse_deferred_flush(None), unset);
    // The opt-out, an empty value and anything unrecognised keep the per-file flush.
    assert_eq!(parse_deferred_flush(Some("0")), None);
    assert_eq!(parse_deferred_flush(Some("")), None);
    assert_eq!(parse_deferred_flush(Some("true")), None);
    if cfg!(unix) {
        assert_eq!(parse_deferred_flush(Some("1")), Some(FullFsyncEach));
        assert_eq!(parse_deferred_flush(Some(" 2 ")), Some(FsyncThenOneFullFsync));
    }
}

fn tear_in_place(h: &Harness, name: &str, len: usize) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().write(true).open(h.path(name)).unwrap();
    file.write_all(&vec![0xAB; len]).unwrap();
}

fn record_observed_identity_as_proof(h: &Harness, name: &str) {
    let identity = FileIdentity::observe_path(&h.path(name)).unwrap();
    h.state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute(
                "UPDATE path_materialized_generations \
                 SET filesystem_identity = ?3, metadata_fingerprint = ?4 \
                 WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![
                    GROUP,
                    name,
                    yadorilink_sync_sqlite::file_identity_codec::encode_file_identity(&identity),
                    identity.metadata_fingerprint.to_vec(),
                ],
            )?;
            Ok(())
        })
        .unwrap();
}

pub(super) fn conflict_copies(h: &Harness) -> usize {
    std::fs::read_dir(h.path(""))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains("conflict"))
        .count()
}

/// The deferred flush is for plain directory roots only: a provider root (or one
/// whose declaration cannot be read) never defers, whatever the knob says.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_root_never_defers_its_flush() {
    let h = Harness::new(false);
    use_deferred(&h, FULL_FLUSH_EACH);
    assert!(h.convergence.deferred_flush(GROUP).is_some(), "a plain root defers when asked");

    h.state
        .provider_repository()
        .declare_root(
            GROUP,
            yadorilink_replica_domain::session_state::ProviderKind::MacFileProvider,
            "P",
        )
        .unwrap();

    use_deferred(&h, FULL_FLUSH_EACH);
    assert!(h.convergence.deferred_flush(GROUP).is_none());
    use_deferred(&h, SINGLE_BARRIER);
    assert!(h.convergence.deferred_flush(GROUP).is_none());
}

/// Matching bytes are not stable bytes: startup repair flushes the file before it
/// clears the intent, and keeps the intent when it cannot.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startup_keeps_the_intent_when_the_matching_file_cannot_be_flushed() {
    let h = Harness::new(false);
    let (name, _) = received_with_failed_barrier(&h, "unflushable-").await;
    let fail = yadorilink_local_storage::fail_received_flushes_of("unflushable-");

    startup(&h);
    assert!(flush_pending(&h, &name) || intent_open(&h, &name), "the intent stays");

    drop(fail);
    startup(&h);
    assert!(closed(&h, &name));
}

// ---------------------------------------------------------------------------
// Audit of the unflushed window (deferred receive flush): a user's edit made while a
// received file's intent is still open is never overwritten, whichever way the
// edit was made and whichever step the process stopped at.
// ---------------------------------------------------------------------------

/// Every file of the root other than `keep` and the scratch sources, with its
/// bytes: where a quarantined edit ends up.
pub(super) fn side_files(h: &Harness, keep: &str) -> Vec<(String, Vec<u8>)> {
    std::fs::read_dir(h.path(""))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name != keep && !name.starts_with("zz-source-") && !name.starts_with('.'))
        .map(|name| {
            let bytes = std::fs::read(h.path(&name)).unwrap();
            (name, bytes)
        })
        .collect()
}

pub(super) fn edit_in_place_same_size(h: &Harness, name: &str, content: &[u8]) -> Vec<u8> {
    let edit = vec![b'U'; content.len()];
    std::fs::write(h.path(name), &edit).unwrap();
    edit
}

pub(super) fn edit_in_place_longer(h: &Harness, name: &str, content: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().append(true).open(h.path(name)).unwrap();
    file.write_all(b" plus the user's own lines").unwrap();
    let mut edit = content.to_vec();
    edit.extend_from_slice(b" plus the user's own lines");
    edit
}

pub(super) fn edit_by_atomic_replace(h: &Harness, name: &str, content: &[u8]) -> Vec<u8> {
    let edit = vec![b'R'; content.len()];
    let aside = h.path("user-editor.swp");
    std::fs::write(&aside, &edit).unwrap();
    std::fs::rename(&aside, h.path(name)).unwrap();
    edit
}

/// A user's edit made while the received file's intent waits for the barrier,
/// made in place (same size and longer) or by an editor's atomic replace, is
/// never read as the lost flush: startup keeps the user's exact bytes in a
/// conflict copy and rebuilds the received version at the name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn startup_keeps_the_exact_bytes_of_a_user_edit_made_in_the_unflushed_window() {
    type Edit = fn(&Harness, &str, &[u8]) -> Vec<u8>;
    let edits: [(&str, Edit); 3] = [
        ("same-size", edit_in_place_same_size),
        ("longer", edit_in_place_longer),
        ("atomic-replace", edit_by_atomic_replace),
    ];
    for (kind, edit) in edits {
        let h = Harness::new(false);
        let (name, content) = received_with_failed_barrier(&h, &format!("window-{kind}-")).await;
        let user_bytes = edit(&h, &name, &content);

        let report = startup(&h);

        assert_eq!(report.quarantined_dirty.len(), 1, "{kind}: {report:?}");
        assert_eq!(std::fs::read(h.path(&name)).unwrap(), content, "{kind}: received version");
        let kept: Vec<_> =
            side_files(&h, &name).into_iter().filter(|(_, bytes)| *bytes == user_bytes).collect();
        assert_eq!(kept.len(), 1, "{kind}: the user's bytes survive exactly once: {kept:?}");
        assert!(closed(&h, &name), "{kind}");
    }
}

/// A capture scan in the unflushed window picks the user's edit up as the local
/// change it is (an open intent does not hide a present file from capture); a
/// restart after that keeps the edit at the name and closes the intent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_user_edit_captured_in_the_unflushed_window_survives_a_restart() {
    let h = Harness::new(false);
    let (name, content) = received_with_failed_barrier(&h, "scanned-").await;
    let user_bytes = edit_in_place_same_size(&h, &name, &content);

    let scanned = h.scan();
    assert!(scanned.iter().any(|record| record.path == name), "the edit is captured: {scanned:?}");

    let report = startup(&h);

    assert!(report.quarantined_dirty.is_empty(), "{report:?}");
    assert_eq!(std::fs::read(h.path(&name)).unwrap(), user_bytes, "the edit stays at the name");
    assert!(side_files(&h, &name).is_empty());
    assert!(closed(&h, &name), "the intent no longer waits once the row is the edit's");
    assert!(h.scan().is_empty(), "nothing is authored twice");
}

/// Once the barrier closed the intent the file is an ordinary file: a user's
/// edit made afterwards survives a restart untouched and is then captured.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_edit_after_the_barrier_is_neither_repaired_nor_quarantined_by_startup() {
    let h = Harness::new(false);
    pin_concurrency(&h, 4);
    use_deferred(&h, FULL_FLUSH_EACH);
    let files = names("after-", 1);
    let contents = publish_new_files(&h, &files).await;
    assert!(reconcile(&h, &files).await.is_settled(&files[0]));
    h.convergence.drain_flush_barriers().await;
    assert!(closed(&h, &files[0]));
    let user_bytes = edit_in_place_longer(&h, &files[0], &contents[&files[0]]);

    let report = startup(&h);

    assert!(report.quarantined_dirty.is_empty() && report.reconstructed.is_empty(), "{report:?}");
    assert_eq!(std::fs::read(h.path(&files[0])).unwrap(), user_bytes);
    assert!(matches!(h.capture(&files[0]).await, LocalChangeOutcome::FileChanged(_)));
}

/// Step: every file flushed, the transaction that clears the intents fails.
/// The intents stay open and marked; startup finds the intact bytes and closes
/// them without a conflict copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_clear_after_a_good_flush_leaves_the_intents_for_startup_to_close() {
    let h = Harness::new(false);
    pin_concurrency(&h, 4);
    use_deferred(&h, FULL_FLUSH_EACH);
    let files = names("clearfail-", 3);
    let contents = publish_new_files(&h, &files).await;
    h.state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER poison_clear BEFORE DELETE ON materialization_intents \
                 BEGIN SELECT RAISE(ABORT, 'poisoned'); END;",
            )?;
            Ok(())
        })
        .unwrap();

    let attempt = reconcile(&h, &files).await;
    let reports = h.convergence.drain_flush_barriers().await;

    assert!(files.iter().all(|name| attempt.is_settled(name)));
    assert_eq!(reports.iter().map(|r| (r.flushed, r.cleared)).collect::<Vec<_>>(), [(3, 0)]);
    assert!(files.iter().all(|name| flush_pending(&h, name)), "nothing was cleared");
    h.state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute_batch("DROP TRIGGER poison_clear")?;
            Ok(())
        })
        .unwrap();

    let report = startup(&h);

    assert!(report.quarantined_dirty.is_empty(), "{report:?}");
    for name in &files {
        assert_eq!(std::fs::read(h.path(name)).unwrap(), contents[name]);
        assert!(closed(&h, name), "{name}");
    }
    assert_eq!(conflict_copies(&h), 0);
}

/// Step: renamed into place without its flush, stopped before the commit (so
/// no proof and no marker exist). Intact bytes are closed by startup; bytes a
/// torn flush left cannot be told from a user's edit without the proof, so
/// they are kept in a conflict copy and the received version is rebuilt: the
/// bytes at the name are never silently overwritten.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_between_the_unflushed_rename_and_the_commit_never_overwrites_the_bytes_at_the_name()
{
    use super::receive_window_concurrency_tests::{arm, driver};
    use super::OverlapProbe;
    for torn in [false, true] {
        let h = Harness::new(false);
        pin_concurrency(&h, 4);
        use_deferred(&h, FULL_FLUSH_EACH);
        let files = names(&format!("precommit{torn}-"), 1);
        let contents = publish_new_files(&h, &files).await;
        let probe = OverlapProbe::new(super::ProbeSeam::BeforeCommit, 1, 30_000);
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
            assert!(waited.elapsed() < std::time::Duration::from_secs(30), "{:?}", probe.events());
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        task.abort();
        let _ = task.await;
        *h.convergence.overlap_probe.lock().unwrap() = None;
        let name = &files[0];
        assert!(intent_open(&h, name) && marker(&h, name).is_none() && !proven(&h, name));
        let on_disk = if torn {
            tear_in_place(&h, name, contents[name].len());
            vec![0xAB; contents[name].len()]
        } else {
            contents[name].clone()
        };

        let report = startup(&h);

        assert!(report.offline_deleted.is_empty(), "{report:?}");
        assert_eq!(std::fs::read(h.path(name)).unwrap(), contents[name], "torn={torn}");
        assert!(closed(&h, name), "torn={torn}");
        let kept = side_files(&h, name);
        if torn {
            assert_eq!(kept.len(), 1, "{kept:?}");
            assert_eq!(kept[0].1, on_disk, "the bytes that were at the name are kept");
        } else {
            assert!(kept.is_empty(), "intact bytes need no copy: {kept:?}");
        }
    }
}
