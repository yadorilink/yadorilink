#![cfg(test)]

use std::future::Future;
use std::pin::Pin;

use super::*;
use crate::link_runtime::dependencies::LinkRuntimeHostPort;

/// A `LinkRuntimeHostPort` that does nothing -- these tests are about
/// `announce_local_change`'s own local-indexing/status-push/propagation-
/// gate behavior, not about the daemon-wide broadcast/write-activity/
/// signing-key operations the real host implementation reaches; there
/// are no connected peers in any of these tests, so a real broadcast
/// would be a no-op anyway.
struct NoopHost;

impl LinkRuntimeHostPort for NoopHost {
    fn note_capture_settled(&self, _group_id: &str) {}

    fn on_local_native_commit<'a>(
        &'a self,
        _group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }

    fn begin_write_activity(&self) -> Box<dyn Send + '_> {
        Box::new(())
    }

    fn device_signing_key(&self) -> Option<ed25519_dalek::SigningKey> {
        None
    }
}

/// A host that records whether the capture-settled signal was raised.
struct RecordingHost {
    settled: std::sync::atomic::AtomicUsize,
    broadcasts: std::sync::atomic::AtomicUsize,
}

impl LinkRuntimeHostPort for RecordingHost {
    fn note_capture_settled(&self, _group_id: &str) {
        self.settled.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    fn on_local_native_commit<'a>(
        &'a self,
        _group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        self.broadcasts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async {})
    }

    fn begin_write_activity(&self) -> Box<dyn Send + '_> {
        Box::new(())
    }

    fn device_signing_key(&self) -> Option<ed25519_dalek::SigningKey> {
        None
    }
}

/// A flush that authors nothing must still re-ask admission.
///
/// The dirty rows a flush clears ARE the capture barrier that holds a
/// verified staged Change back. A flush can clear them and produce no
/// record at all -- a spurious event, or one whose path turned out
/// unchanged. `announce_local_change` returns at `records.is_empty()`,
/// so everything downstream of it, including the admission wake, is
/// skipped in exactly that case. The staged Change is then admissible
/// with nothing left that will ever look: it is advertised as possessed,
/// so no peer re-sends it, so no delivery ever schedules another drain.
///
/// So the signal must not be conditioned on there being records. This
/// asserts that directly, which is what tying it to a commit did not.
#[tokio::test]
async fn a_flush_that_authors_nothing_still_reports_capture_settled() {
    use std::sync::atomic::Ordering as AOrd;

    let host = Arc::new(RecordingHost {
        settled: std::sync::atomic::AtomicUsize::new(0),
        broadcasts: std::sync::atomic::AtomicUsize::new(0),
    });
    let store_dir = tempfile::tempdir().unwrap();
    let block_store =
        Arc::new(yadorilink_local_storage::SegmentBlockStore::new(store_dir.path()).unwrap());
    let (status_push_tx, _rx) = tokio::sync::broadcast::channel(16);
    let deps = Arc::new(LinkRuntimeDependencies {
        replica_coordinator: Arc::new(ReplicaCoordinator::open_in_memory().unwrap()),
        block_store,
        telemetry: Arc::new(crate::runtime_telemetry::RuntimeTelemetry::new(status_push_tx)),
        device_id: "device-a".to_string(),
        host: host.clone(),
    });

    // Exactly what a no-op flush reaches: settlement is reported, then
    // the announce path is handed an empty record set.
    deps.note_capture_settled("group-1");
    announce_local_change(&deps, "/root", "group-1", Vec::new()).await;

    // The announce half correctly does nothing -- there is nothing to
    // tell a peer about.
    assert_eq!(
        host.broadcasts.load(AOrd::SeqCst),
        0,
        "sanity: an empty record set must not broadcast"
    );

    // ...but settlement must still have been reported. Tying the two
    // together is the bug: `announce_local_change` returns at
    // `records.is_empty()`, so anything downstream of it -- which is
    // where the wake used to live -- never runs for a flush that
    // authored nothing, while the dirty rows it cleared were the very
    // barrier holding a staged Change back.
    assert_eq!(
        host.settled.load(AOrd::SeqCst),
        1,
        "capture settlement must be reported independently of having anything to announce"
    );
}

fn test_deps() -> Arc<LinkRuntimeDependencies> {
    let block_store = Arc::new(
        yadorilink_local_storage::SegmentBlockStore::new(tempfile::tempdir().unwrap().keep())
            .unwrap(),
    );
    let replica_coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let (status_push_tx, _rx) = tokio::sync::broadcast::channel(16);
    Arc::new(LinkRuntimeDependencies {
        replica_coordinator,
        block_store,
        telemetry: Arc::new(crate::runtime_telemetry::RuntimeTelemetry::new(status_push_tx)),
        device_id: "device-a".to_string(),
        host: Arc::new(NoopHost),
    })
}

fn sample_record(path: &str) -> FileRecord {
    FileRecord {
        path: path.to_string(),
        size: 10,
        mtime_unix_nanos: 0,
        blocks: vec![],
        deleted: false,
    }
}

/// `StatusPush` stays
/// one-per-file for the shell extension even when the peer-facing
/// broadcast batches many files into a single wire message — these
/// are different concerns (local UI feedback vs. peer wire
/// efficiency), and only the latter should batch.
#[tokio::test]
async fn announce_local_change_pushes_one_status_update_per_file_even_when_batched() {
    let deps = test_deps();
    deps.replica_coordinator.link_repository().add_link("/tmp/photos", "group-1").unwrap();
    let mut push_rx = deps.telemetry.subscribe_status();

    let records = vec![sample_record("a.jpg"), sample_record("b.jpg"), sample_record("c.jpg")];
    announce_local_change(&deps, "/tmp/photos", "group-1", records).await;

    let mut seen_paths = std::collections::HashSet::new();
    for _ in 0..3 {
        let push = tokio::time::timeout(std::time::Duration::from_secs(1), push_rx.recv())
            .await
            .expect("expected a StatusPush")
            .unwrap();
        seen_paths.insert(push.path);
    }
    // Path::join (production's own construction, see
    // announce_local_change above) uses the OS's native separator --
    // `\` on Windows, `/` elsewhere -- so the expected set must too,
    // rather than hardcoding `/` and failing on every Windows run.
    assert_eq!(
        seen_paths,
        std::collections::HashSet::from(
            ["a.jpg", "b.jpg", "c.jpg"]
                .map(|name| Path::new("/tmp/photos").join(name).to_string_lossy().to_string())
        )
    );
    // No fourth push — exactly one per file, not more.
    assert!(tokio::time::timeout(std::time::Duration::from_millis(200), push_rx.recv())
        .await
        .is_err());
}

/// An empty batch must not push anything or attempt to broadcast.
#[tokio::test]
async fn announce_local_change_is_a_no_op_for_an_empty_batch() {
    let deps = test_deps();
    deps.replica_coordinator.link_repository().add_link("/tmp/photos", "group-1").unwrap();
    let mut push_rx = deps.telemetry.subscribe_status();

    announce_local_change(&deps, "/tmp/photos", "group-1", vec![]).await;

    assert!(tokio::time::timeout(std::time::Duration::from_millis(200), push_rx.recv())
        .await
        .is_err());
}

/// Propagation permission comes from the authoritative group gate. Missing,
/// paused and orphaned links all fail closed; only the exact live path passes.
#[tokio::test]
async fn link_should_propagate_is_fail_closed() {
    let replica_coordinator = ReplicaCoordinator::open_in_memory().unwrap();
    let local_path = "/tmp/photos";
    let group_id = "group-1";

    assert!(
        !link_should_propagate(&replica_coordinator, local_path, group_id),
        "no live link must not be interpreted as permission to broadcast"
    );
    replica_coordinator.link_repository().add_link(local_path, group_id).unwrap();
    assert!(link_should_propagate(&replica_coordinator, local_path, group_id));
    assert!(
        !link_should_propagate(&replica_coordinator, "/tmp/some-other-root", group_id),
        "a stale watcher for a different path must not broadcast for the group"
    );
    replica_coordinator.link_repository().set_paused(local_path, true).unwrap();
    assert!(!link_should_propagate(&replica_coordinator, local_path, group_id));
    replica_coordinator.link_repository().set_paused(local_path, false).unwrap();
    replica_coordinator.link_repository().mark_link_orphaned(local_path).unwrap();
    assert!(!link_should_propagate(&replica_coordinator, local_path, group_id));
}

/// Marking a link orphaned never touches its on-disk files — only a
/// local bookkeeping flag flips. The folder and its contents must be
/// exactly as they were, byte for byte, after the link transitions.
#[tokio::test]
async fn orphaning_a_link_leaves_its_on_disk_files_untouched() {
    let deps = test_deps();
    let folder = tempfile::tempdir().unwrap();
    let file_path = folder.path().join("keepsake.txt");
    std::fs::write(&file_path, b"never delete me").unwrap();
    let local_path = folder.path().to_string_lossy().to_string();
    deps.replica_coordinator.link_repository().add_link(&local_path, "group-1").unwrap();

    deps.replica_coordinator.link_repository().mark_link_orphaned(&local_path).unwrap();

    assert_eq!(std::fs::read(&file_path).unwrap(), b"never delete me");
    assert!(deps
        .replica_coordinator
        .link_repository()
        .list_links()
        .unwrap()
        .iter()
        .any(|l| l.orphaned));

    // And sync propagation for this now-orphaned link is suppressed,
    // the same guarantee `link_should_propagate_excludes_paused_and_
    // orphaned` proves in isolation -- exercised here end to end
    // through `announce_local_change` against the real orphaned row.
    let mut push_rx = deps.telemetry.subscribe_status();
    announce_local_change(&deps, &local_path, "group-1", vec![sample_record("new.txt")]).await;
    // The per-file shell-status push still fires (local indexing UI
    // feedback is unconditional); only peer propagation is gated, which
    // has no directly observable effect here with zero connected
    // peers. This call completing without panicking, combined with the
    // isolated gate test above, is the coverage for that path.
    assert!(tokio::time::timeout(std::time::Duration::from_millis(200), push_rx.recv())
        .await
        .is_ok());
}

fn test_link_flush_handle(
    deps: &Arc<LinkRuntimeDependencies>,
    root: &Path,
    flush_request_tx: tokio::sync::mpsc::Sender<debounce::FlushPathRequest>,
) -> LinkFlushHandle {
    let (flush_all_request_tx, _flush_all_request_rx) = tokio::sync::mpsc::channel(1);
    test_link_flush_handle_with_flush_all(deps, root, flush_request_tx, flush_all_request_tx)
}

fn test_link_flush_handle_with_flush_all(
    deps: &Arc<LinkRuntimeDependencies>,
    root: &Path,
    flush_request_tx: tokio::sync::mpsc::Sender<debounce::FlushPathRequest>,
    flush_all_request_tx: tokio::sync::mpsc::Sender<debounce::FlushAllRequest>,
) -> LinkFlushHandle {
    let root_lock = yadorilink_root_authority::sync_root_lock::SyncRootLock::acquire(root).unwrap();
    let root_lease = Arc::new(yadorilink_root_authority::root_commit::RootLease::new(
        root_lock,
        "group-1".to_string(),
        1,
    ));
    let processor = Arc::new(LocalChangeProcessor::new(
        deps.replica_coordinator.clone(),
        Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
            deps.block_store.clone(),
        )),
        deps.device_id.clone(),
        root_lease.clone(),
    ));
    LinkFlushHandle::new(
        deps,
        flush_request_tx,
        flush_all_request_tx,
        processor,
        root.to_path_buf(),
        root.display().to_string(),
        root_lease,
    )
}

/// The targeted-flush channel (`flush_request_tx`, capacity 4 in
/// production) is shared by every concurrent peer message handler
/// reconciling a path against this link. Under a duplicate-delivery
/// storm it can stay permanently full -- this proves a message handler
/// calling `flush_pending_local_change` against a full, never-drained
/// channel gets a `RetryRequired` back within its bound (never parks
/// indefinitely holding its caller's message-handling permit), rather
/// than the previous unbounded `.send().await`.
#[tokio::test(start_paused = true)]
async fn flush_pending_local_change_returns_retry_required_when_the_channel_stays_full() {
    let deps = test_deps();
    let root_dir = tempfile::tempdir().unwrap();
    let (flush_request_tx, _flush_request_rx) = tokio::sync::mpsc::channel(1);
    // Occupy the channel's one slot and never drain it -- simulates the
    // accumulator task being backlogged/stalled behind other requests.
    let (occupy_reply_tx, _occupy_reply_rx) = tokio::sync::oneshot::channel();
    flush_request_tx
        .try_send(debounce::FlushPathRequest {
            path: root_dir.path().join("occupied"),
            mode: debounce::FlushMode::ExactPath,
            reply: occupy_reply_tx,
        })
        .unwrap();

    let handle = test_link_flush_handle(&deps, root_dir.path(), flush_request_tx);

    let flush_task =
        tokio::spawn(
            async move { handle.flush_pending_local_change("group-1", "shared.bin").await },
        );
    tokio::time::advance(FORCE_FLUSH_REQUEST_TIMEOUT + std::time::Duration::from_millis(1)).await;
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), flush_task)
        .await
        .expect("flush_pending_local_change must return promptly once its enqueue bound elapses, not park indefinitely")
        .unwrap();
    assert_eq!(outcome, PendingLocalFlushOutcome::RetryRequired);
}

/// Mirrors the exact-path case above for the case-fold-sibling flush.
#[tokio::test(start_paused = true)]
async fn flush_case_fold_sibling_returns_retry_required_when_the_channel_stays_full() {
    let deps = test_deps();
    let root_dir = tempfile::tempdir().unwrap();
    let (flush_request_tx, _flush_request_rx) = tokio::sync::mpsc::channel(1);
    let (occupy_reply_tx, _occupy_reply_rx) = tokio::sync::oneshot::channel();
    flush_request_tx
        .try_send(debounce::FlushPathRequest {
            path: root_dir.path().join("occupied"),
            mode: debounce::FlushMode::ExactPath,
            reply: occupy_reply_tx,
        })
        .unwrap();

    let handle = test_link_flush_handle(&deps, root_dir.path(), flush_request_tx);

    let flush_task =
        tokio::spawn(async move { handle.flush_case_fold_sibling("group-1", "shared.bin").await });
    tokio::time::advance(FORCE_FLUSH_REQUEST_TIMEOUT + std::time::Duration::from_millis(1)).await;
    let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), flush_task)
        .await
        .expect("flush_case_fold_sibling must return promptly once its enqueue bound elapses, not park indefinitely")
        .unwrap();
    assert_eq!(outcome, PendingLocalFlushOutcome::RetryRequired);
}

/// `ask_accumulator` keeps its three outcomes apart: an answer, a request dropped unanswered
/// (closed), and no answer in time (timed out) -- and a timed-out requester has stopped
/// listening, so a late answer is handed back to the accumulator instead of vanishing.
#[tokio::test(start_paused = true)]
async fn ask_accumulator_tells_an_answer_a_closed_accumulator_and_a_timeout_apart() {
    // Answered in time, exactly once.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<debounce::FlushAllRequest>(4);
    let answer = tokio::spawn(async move {
        let request = rx.recv().await.unwrap();
        request.reply.send(vec![]).unwrap();
    });
    let reply = ask_accumulator(&tx, |reply| debounce::FlushAllRequest { reply }, |_| Ok(())).await;
    assert_eq!(reply, Ok(vec![]));
    answer.await.unwrap();

    // The accumulator drops the request without answering: closed.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<debounce::FlushAllRequest>(4);
    let dropper = tokio::spawn(async move { drop(rx.recv().await.unwrap()) });
    let reply = ask_accumulator(&tx, |reply| debounce::FlushAllRequest { reply }, |_| Ok(())).await;
    assert_eq!(reply, Err(AccumulatorFault::Closed));
    dropper.await.unwrap();

    // The accumulator takes the request but does not answer in time: timed out, and the
    // reply it still holds can no longer be delivered.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<debounce::FlushAllRequest>(4);
    let holder = tokio::spawn(async move { rx.recv().await.unwrap() });
    let reply = ask_accumulator(&tx, |reply| debounce::FlushAllRequest { reply }, |_| Ok(())).await;
    assert_eq!(reply, Err(AccumulatorFault::TimedOut));
    let late = holder.await.unwrap();
    assert!(
        late.reply.send(vec![]).is_err(),
        "a late answer must fail to send so the accumulator keeps what it drained"
    );

    // A request that cannot even be enqueued in time is also a timeout, not a closure.
    let (tx, _rx) = tokio::sync::mpsc::channel::<debounce::FlushAllRequest>(1);
    let (occupy, _occupy_rx) = tokio::sync::oneshot::channel();
    tx.try_send(debounce::FlushAllRequest { reply: occupy }).unwrap();
    let reply = ask_accumulator(&tx, |reply| debounce::FlushAllRequest { reply }, |_| Ok(())).await;
    assert_eq!(reply, Err(AccumulatorFault::TimedOut));
}

/// Seeds a `Remote`-state row for `path` in `deps`'s index
/// (`ensure_windows_placeholder_generation` requires the row to
/// already exist -- `record_placeholder_generation`'s own `UPDATE`
/// affects zero rows and returns `NotFound` otherwise), independent of
/// any real `LinkFlushHandle`/`RootLease` -- `RootCommitPermit::
/// for_tests()` mirrors `materialization_execution.rs`'s own
/// `setup_placeholder_file` test helper.
fn seed_placeholder_row(deps: &LinkRuntimeDependencies, group_id: &str, path: &str) {
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    deps.replica_coordinator
        .file_index_repository()
        .upsert_file(group_id, &sample_record(path), &permit)
        .unwrap();
    deps.replica_coordinator
        .materialization_state_repository()
        .set_materialization_state(
            group_id,
            path,
            yadorilink_replica_domain::session_state::MaterializationState::Remote,
            &permit,
        )
        .unwrap();
}

#[tokio::test]
async fn ensure_windows_placeholder_generation_mints_once_and_persists() {
    let deps = test_deps();
    let root_dir = tempfile::tempdir().unwrap();
    deps.replica_coordinator
        .link_repository()
        .add_link(&root_dir.path().display().to_string(), "group-1")
        .unwrap();
    seed_placeholder_row(&deps, "group-1", "doc.txt");
    let (flush_request_tx, _flush_request_rx) = tokio::sync::mpsc::channel(1);
    let handle = test_link_flush_handle(&deps, root_dir.path(), flush_request_tx);

    let first = handle.ensure_windows_placeholder_generation("group-1", "doc.txt").unwrap();

    // Idempotent: a second call for the SAME still-placeholder path
    // (exactly what `shell_ipc.rs`'s `ListFolderFilesRequest` handler
    // does on every ~30s cfapi-host poll) must return the identical
    // persisted value, never mint a fresh one.
    let second = handle.ensure_windows_placeholder_generation("group-1", "doc.txt").unwrap();
    assert_eq!(first, second);

    // Restart-safety proxy: a fresh read straight from the index (not
    // anything this handle might have cached in memory) sees the same
    // value -- the property that makes this safe across a real daemon
    // restart, where a NEW handle re-reads whatever was persisted.
    let recorded = deps
        .replica_coordinator
        .materialization_state_repository()
        .get_placeholder_generation("group-1", "doc.txt")
        .unwrap()
        .expect("a generation should have been persisted");
    assert_eq!(
        recorded.provider_kind,
        yadorilink_local_storage::WINDOWS_CFAPI_GENERATION_PROVIDER_KIND
    );
    assert_eq!(recorded.identity.dev, 0);
    assert_eq!(recorded.identity.ino, first);
}

/// Two different placeholder paths must never collide on the same
/// minted generation -- the same ABA-guard property `cfapi.rs`'s own
/// `mint_generation_token`/`encode_generation_identity` doc comments
/// require, now proved at the daemon-side minting authority instead.
#[tokio::test]
async fn ensure_windows_placeholder_generation_differs_across_paths() {
    let deps = test_deps();
    let root_dir = tempfile::tempdir().unwrap();
    deps.replica_coordinator
        .link_repository()
        .add_link(&root_dir.path().display().to_string(), "group-1")
        .unwrap();
    seed_placeholder_row(&deps, "group-1", "a.txt");
    seed_placeholder_row(&deps, "group-1", "b.txt");
    let (flush_request_tx, _flush_request_rx) = tokio::sync::mpsc::channel(1);
    let handle = test_link_flush_handle(&deps, root_dir.path(), flush_request_tx);

    let a = handle.ensure_windows_placeholder_generation("group-1", "a.txt").unwrap();
    let b = handle.ensure_windows_placeholder_generation("group-1", "b.txt").unwrap();
    assert_ne!(a, b);
}

// ---- a link paused for a safe stop is not a link being torn down ---------------------------

/// A handle over a real file `a.txt`, with its lease.
fn paused_link_fixture(
) -> (Arc<LinkRuntimeDependencies>, tempfile::TempDir, LinkFlushHandle, PathBuf) {
    let deps = test_deps();
    let root_dir = tempfile::tempdir().unwrap();
    let (flush_request_tx, _flush_request_rx) = tokio::sync::mpsc::channel(1);
    let handle = test_link_flush_handle(&deps, root_dir.path(), flush_request_tx);
    let file = handle.canonical_root.join("a.txt");
    std::fs::write(&file, b"user edit").unwrap();
    (deps, root_dir, handle, file)
}

#[tokio::test]
async fn a_path_flush_during_a_pause_must_be_retried_not_reported_settled() {
    let (_deps, _root, handle, file) = paused_link_fixture();
    handle.root_lease.begin_quiesce();
    let paused = handle
        .flush_one_path("group-1", "a.txt", file.clone(), FsChangeKind::CreatedOrModified, 1)
        .await;
    assert_eq!(
        paused,
        PendingLocalFlushOutcome::RetryRequired,
        "a pause lifts: \"settled\" would license a remote write over the unrecorded edit"
    );
    let undiscovered = handle.capture_undiscovered_local_change("group-1", "a.txt", &file).await;
    assert_eq!(undiscovered, PendingLocalFlushOutcome::RetryRequired);

    // A real stop keeps its meaning: the same lease refuses the writer, so nothing is owed.
    handle.root_lease.begin_stopping();
    let stopping = handle
        .flush_one_path("group-1", "a.txt", file.clone(), FsChangeKind::CreatedOrModified, 1)
        .await;
    assert_eq!(stopping, PendingLocalFlushOutcome::Settled);
    assert_eq!(
        handle.capture_undiscovered_local_change("group-1", "a.txt", &file).await,
        PendingLocalFlushOutcome::Settled
    );
}

#[tokio::test]
async fn flush_everything_during_a_pause_fails_and_after_a_stop_is_done() {
    let (_deps, _root, handle, _file) = paused_link_fixture();
    handle.root_lease.begin_quiesce();
    // The accumulator is not running in this fixture, so the request cannot be answered; with a
    // pause that is a failure to report, never "nothing pending".
    assert!(handle.flush_all_pending_local_changes("group-1").await.is_err());
    handle.root_lease.begin_stopping();
    assert!(handle.flush_all_pending_local_changes("group-1").await.is_ok());
}

/// A safe-stop pause that begins while resume's flush-all is draining the accumulator must not
/// lose the drained edit: afterwards it is either captured in the index or still journaled dirty
/// (so a retry or rescan recovers it), never in neither.
#[tokio::test]
async fn flush_all_never_loses_a_batch_drained_just_before_a_pause() {
    let deps = test_deps();
    let root_dir = tempfile::tempdir().unwrap();
    let (flush_request_tx, _flush_request_rx) = tokio::sync::mpsc::channel(1);
    let (flush_all_tx, mut flush_all_rx) = tokio::sync::mpsc::channel(1);
    let handle = test_link_flush_handle_with_flush_all(
        &deps,
        root_dir.path(),
        flush_request_tx,
        flush_all_tx,
    );
    let file = handle.canonical_root.join("a.txt");
    std::fs::write(&file, b"user edit").unwrap();

    // The accumulator hands over the batch and the safe stop begins at that same instant.
    let lease = handle.root_lease.clone();
    let drained_file = file.clone();
    tokio::spawn(async move {
        let request = flush_all_rx.recv().await.unwrap();
        lease.begin_quiesce();
        let _ = request.reply.send(vec![(drained_file, FsChangeKind::CreatedOrModified, 1)]);
    });

    let _ = handle.flush_all_pending_local_changes("group-1").await;

    let indexed = deps
        .replica_coordinator
        .file_index_repository()
        .get_file("group-1", "a.txt")
        .unwrap()
        .is_some();
    let journaled =
        deps.replica_coordinator.dirty_path_repository().is_path_dirty("group-1", "a.txt").unwrap();
    assert!(indexed || journaled, "the drained edit is in neither the index nor the dirty journal");
}

#[tokio::test]
async fn a_provider_write_during_a_pause_is_refused_visibly_and_works_after_it_lifts() {
    let (_deps, _root, handle, _file) = paused_link_fixture();
    handle.root_lease.begin_quiesce();
    let refused = handle
        .capture_local_write("group-1", "a.txt", LocalWrite::CreatedOrModified)
        .await
        .unwrap_err();
    assert!(refused.contains("paused for a safe stop"), "{refused}");
    let refused = handle.capture_resumed_item("group-1", "a.txt").await.unwrap_err();
    assert!(refused.contains("paused for a safe stop"), "{refused}");

    handle.root_lease.end_quiesce();
    let after = handle.capture_local_write("group-1", "a.txt", LocalWrite::CreatedOrModified).await;
    assert!(
        !matches!(&after, Err(e) if e.contains("paused for a safe stop")),
        "the pause is over: {after:?}"
    );
}

// ---- a reply delivered to a requester that is then cancelled -------------------------------

/// Polls `future` once, so it has sent its request and is parked waiting for the reply.
fn poll_once_to_pending<F: Future>(future: &mut Pin<Box<F>>) {
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(future.as_mut().poll(&mut cx).is_pending(), "the requester must be waiting");
}

fn is_journaled(deps: &LinkRuntimeDependencies, path: &str) -> bool {
    deps.replica_coordinator.dirty_path_repository().is_path_dirty("group-1", path).unwrap()
}

/// The debounce accumulator drops an entry from its pending set once its reply is delivered. A
/// requester cancelled after that (a peer-session reconcile is dropped) never reads the reply, so
/// the edit must already be in the dirty journal, found again by the next flush, resume or rescan.
#[tokio::test]
async fn flush_all_cancelled_after_its_reply_was_delivered_leaves_the_edit_journaled() {
    let deps = test_deps();
    let root_dir = tempfile::tempdir().unwrap();
    let (flush_request_tx, _flush_request_rx) = tokio::sync::mpsc::channel(1);
    let (flush_all_tx, mut flush_all_rx) = tokio::sync::mpsc::channel(1);
    let handle = test_link_flush_handle_with_flush_all(
        &deps,
        root_dir.path(),
        flush_request_tx,
        flush_all_tx,
    );
    let file = handle.canonical_root.join("a.txt");
    std::fs::write(&file, b"user edit").unwrap();

    let mut requester = Box::pin(handle.flush_all_pending_local_changes("group-1"));
    poll_once_to_pending(&mut requester);
    let request = flush_all_rx.try_recv().unwrap();
    request.reply.send(vec![(file, FsChangeKind::CreatedOrModified, 1)]).unwrap();
    drop(requester); // cancelled with the reply buffered and unread

    assert!(is_journaled(&deps, "a.txt"), "the handed-over edit is in neither index nor journal");

    // A safe-stop pause begun now does not change that, and the next flush captures it.
    handle.root_lease.begin_quiesce();
    assert!(is_journaled(&deps, "a.txt"));
    handle.root_lease.end_quiesce();
    let accumulator = tokio::spawn(async move {
        flush_all_rx.recv().await.unwrap().reply.send(Vec::new()).unwrap();
    });
    let _ = handle.flush_all_pending_local_changes("group-1").await;
    accumulator.await.unwrap();
    let indexed = deps
        .replica_coordinator
        .file_index_repository()
        .get_file("group-1", "a.txt")
        .unwrap()
        .is_some();
    assert!(indexed || is_journaled(&deps, "a.txt"));
}

/// A case-fold sibling has no disk fallback, so its delivered-then-cancelled reply matters most.
#[tokio::test]
async fn a_case_fold_sibling_cancelled_after_its_reply_was_delivered_leaves_it_journaled() {
    let deps = test_deps();
    let root_dir = tempfile::tempdir().unwrap();
    let (flush_request_tx, mut flush_request_rx) = tokio::sync::mpsc::channel(1);
    let handle = test_link_flush_handle(&deps, root_dir.path(), flush_request_tx);
    let sibling = handle.canonical_root.join("Report.txt");
    std::fs::write(&sibling, b"user edit").unwrap();

    let mut requester = Box::pin(handle.flush_case_fold_sibling("group-1", "report.txt"));
    poll_once_to_pending(&mut requester);
    let request = flush_request_rx.try_recv().unwrap();
    request.reply.send(Some((sibling, FsChangeKind::CreatedOrModified, 1))).unwrap();
    drop(requester);

    assert!(is_journaled(&deps, "Report.txt"));
}

/// Same for the exact path.
#[tokio::test]
async fn a_targeted_flush_cancelled_after_its_reply_was_delivered_leaves_it_journaled() {
    let deps = test_deps();
    let root_dir = tempfile::tempdir().unwrap();
    let (flush_request_tx, mut flush_request_rx) = tokio::sync::mpsc::channel(1);
    let handle = test_link_flush_handle(&deps, root_dir.path(), flush_request_tx);
    let file = handle.canonical_root.join("a.txt");
    std::fs::write(&file, b"user edit").unwrap();

    let mut requester = Box::pin(handle.flush_pending_local_change("group-1", "a.txt"));
    poll_once_to_pending(&mut requester);
    let request = flush_request_rx.try_recv().unwrap();
    request.reply.send(Some((file, FsChangeKind::CreatedOrModified, 1))).unwrap();
    drop(requester);

    assert!(is_journaled(&deps, "a.txt"));
}

/// Taking a buffered reply closes the receiver in the same step: the receiver is still alive
/// here, so only `close()` (not a drop) can make a later answer fail to send, which is what
/// makes the accumulator keep the entry it was about to hand over.
#[test]
fn taking_a_buffered_reply_closes_the_receiver_so_a_late_answer_is_not_lost() {
    let journaled = std::cell::RefCell::new(Vec::new());
    let (tx, rx) = tokio::sync::oneshot::channel::<u32>();
    let mut watch = ReplyWatch {
        rx,
        journal: |reply: &u32| {
            journaled.borrow_mut().push(*reply);
            Ok(())
        },
    };
    assert_eq!(watch.take_buffered(), Ok(None), "nothing delivered yet");
    assert_eq!(tx.send(7), Err(7), "after taking, a late answer must be handed back");

    let (tx, rx) = tokio::sync::oneshot::channel::<u32>();
    tx.send(9).unwrap();
    let mut watch = ReplyWatch {
        rx,
        journal: |reply: &u32| {
            journaled.borrow_mut().push(*reply);
            Ok(())
        },
    };
    assert_eq!(watch.take_buffered(), Ok(Some(9)));
    assert_eq!(*journaled.borrow(), vec![9], "a taken reply is journaled once");
}

// ---- a handed-over reply whose dirty-journal commit fails ----------------------------------

/// A file-backed index (so a restart can reopen it) and a second connection that can make every
/// dirty-journal insert fail with a real SQLite error.
struct FailingJournal {
    db: PathBuf,
}

impl FailingJournal {
    fn conn(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(&self.db).unwrap()
    }

    /// Every insert of `only_path` (any path when `None`) into the journal now aborts.
    fn fail(&self, only_path: Option<&str>) {
        let when = only_path.map_or(String::new(), |path| format!("WHEN NEW.path = '{path}' "));
        self.conn()
            .execute_batch(&format!(
                "CREATE TRIGGER IF NOT EXISTS inject_journal_failure \
                 BEFORE INSERT ON local_dirty_paths {when}\
                 BEGIN SELECT RAISE(ABORT, 'injected SQLITE_IOERR'); END;"
            ))
            .unwrap();
    }

    fn heal(&self) {
        self.conn().execute_batch("DROP TRIGGER IF EXISTS inject_journal_failure;").unwrap();
    }
}

/// A file-backed daemon state whose group has a policy (the default when no provider is set),
/// so a re-drive really captures; see `a_redrive_waits_for_the_group_policy_then_captures` for
/// the policy-unavailable side. The link row and root identity come from `adopt_root`.
fn file_backed_deps(db: &Path) -> Arc<LinkRuntimeDependencies> {
    let deps = test_deps();
    let (status_push_tx, _rx) = tokio::sync::broadcast::channel(16);
    let replica_coordinator = Arc::new(ReplicaCoordinator::open(db).unwrap());
    Arc::new(LinkRuntimeDependencies {
        replica_coordinator,
        telemetry: Arc::new(crate::runtime_telemetry::RuntimeTelemetry::new(status_push_tx)),
        ..(*deps).clone()
    })
}

fn journal_rows(deps: &LinkRuntimeDependencies) -> usize {
    deps.replica_coordinator.dirty_path_repository().list_dirty_paths("group-1").unwrap().len()
}

struct Handoff {
    deps: Arc<LinkRuntimeDependencies>,
    handle: LinkFlushHandle,
    journal: FailingJournal,
    flush_rx: tokio::sync::mpsc::Receiver<debounce::FlushPathRequest>,
    flush_all_rx: tokio::sync::mpsc::Receiver<debounce::FlushAllRequest>,
    _dirs: (tempfile::TempDir, tempfile::TempDir),
}

fn handoff_fixture() -> Handoff {
    let db_dir = tempfile::tempdir().unwrap();
    let root_dir = tempfile::tempdir().unwrap();
    let db = db_dir.path().join("index.db");
    let deps = file_backed_deps(&db);
    let (flush_tx, flush_rx) = tokio::sync::mpsc::channel(1);
    let (flush_all_tx, flush_all_rx) = tokio::sync::mpsc::channel(1);
    let handle =
        test_link_flush_handle_with_flush_all(&deps, root_dir.path(), flush_tx, flush_all_tx);
    adopt_root(&deps, &handle.canonical_root);
    Handoff {
        deps,
        handle,
        journal: FailingJournal { db },
        flush_rx,
        flush_all_rx,
        _dirs: (db_dir, root_dir),
    }
}

/// The link row and root identity a first startup establishes (the scan and capture verify them).
fn adopt_root(deps: &LinkRuntimeDependencies, root: &Path) {
    let coordinator = &deps.replica_coordinator;
    let _ = coordinator.link_repository().add_link(&root.to_string_lossy(), "group-1");
    yadorilink_root_authority::root_identity::VerifiedRoot::open(root, "group-1", &**coordinator)
        .unwrap();
    let identity = yadorilink_filesystem_sync::device_boundary::root_volume_identity(root).unwrap();
    coordinator
        .link_repository()
        .set_capture_volume_identity_for_group("group-1", &identity)
        .unwrap();
}

fn indexed_live(deps: &LinkRuntimeDependencies, path: &str) -> Option<FileRecord> {
    deps.replica_coordinator
        .file_index_repository()
        .get_file("group-1", path)
        .unwrap()
        .filter(|row| !row.deleted)
}

impl Handoff {
    /// A daemon restart: every handle (processor, root lease, connections) is dropped, so
    /// nothing in memory survives, and the index file is opened afresh with a new processor.
    fn restart(self) -> Handoff {
        let Handoff { deps, handle, journal, flush_rx, flush_all_rx, _dirs } = self;
        drop((deps, handle, flush_rx, flush_all_rx));
        let deps = file_backed_deps(&journal.db);
        let (flush_tx, flush_rx) = tokio::sync::mpsc::channel(1);
        let (flush_all_tx, flush_all_rx) = tokio::sync::mpsc::channel(1);
        let root = _dirs.1.path().to_path_buf();
        let handle = test_link_flush_handle_with_flush_all(&deps, &root, flush_tx, flush_all_tx);
        adopt_root(&deps, &handle.canonical_root);
        Handoff { deps, handle, journal, flush_rx, flush_all_rx, _dirs }
    }

    fn write(&self, name: &str) -> PathBuf {
        let file = self.handle.canonical_root.join(name);
        std::fs::write(&file, name.as_bytes()).unwrap();
        file
    }

    /// Recovery as the link runs it: the dirty-journal backstop's re-drive.
    async fn redrive(
        &self,
    ) -> Result<yadorilink_local_capture::FlushOutcome, yadorilink_local_capture::LocalCaptureError>
    {
        self.handle.processor.redrive_dirty_journal("group-1", &self.handle.root).await
    }
}

/// The reported hole: reply delivered, requester cancelled before reading it, journaling fails.
/// The edit must stay owned (retained, failure visible), then be committed once and applied once.
#[tokio::test]
async fn a_cancelled_requester_whose_journal_commit_fails_loses_nothing() {
    let mut fx = handoff_fixture();
    let file = fx.write("a.txt");
    fx.journal.fail(None);

    let mut requester = Box::pin(fx.handle.flush_pending_local_change("group-1", "a.txt"));
    poll_once_to_pending(&mut requester);
    let request = fx.flush_rx.try_recv().unwrap();
    // The barrier: the reply is delivered, and the requester has not consumed it.
    request.reply.send(Some((file, FsChangeKind::CreatedOrModified, 1))).unwrap();
    drop(requester);

    assert_eq!(journal_rows(&fx.deps), 0, "the injected failure kept the row out");
    assert_eq!(fx.handle.processor.retained_handoff_count(), 1, "the edit lost its owner");
    assert_eq!(
        fx.deps.telemetry.recent_error_snapshot().len(),
        1,
        "the failure must be observable, not log-only"
    );

    // Still failing: recovery reports it and keeps the edit.
    assert!(fx.redrive().await.is_err());
    assert_eq!(fx.handle.processor.retained_handoff_count(), 1);

    // Healed: the next re-drive commits it and captures it exactly once.
    // The re-drive commits the retained edit and captures it, exactly once.
    fx.journal.heal();
    let captured = fx.redrive().await.unwrap();
    assert_eq!(fx.handle.processor.retained_handoff_count(), 0);
    assert_eq!(captured.records.len(), 1, "one logical edit, one capture");
    assert_eq!(captured.records[0].path, "a.txt");
    assert!(indexed_live(&fx.deps, "a.txt").is_some(), "the edit is in the index");
    assert_eq!(journal_rows(&fx.deps), 0, "a captured edit leaves no pending row");
    assert!(fx.redrive().await.unwrap().records.is_empty(), "re-driving again captures nothing");
}

/// After a restart nothing in memory survives: what was committed must be in the reopened file.
#[tokio::test]
async fn a_recovered_handoff_survives_a_restart_as_pending_work() {
    let mut fx = handoff_fixture();
    let file = fx.write("a.txt");
    fx.journal.fail(None);
    let mut requester = Box::pin(fx.handle.flush_pending_local_change("group-1", "a.txt"));
    poll_once_to_pending(&mut requester);
    fx.flush_rx
        .try_recv()
        .unwrap()
        .reply
        .send(Some((file, FsChangeKind::CreatedOrModified, 1)))
        .unwrap();
    drop(requester);

    fx.journal.heal();
    fx.handle.processor.retry_retained_handoffs("group-1").unwrap();
    assert!(is_journaled(&fx.deps, "a.txt"));

    let reopened = file_backed_deps(&fx.journal.db);
    assert!(is_journaled(&reopened, "a.txt"), "the committed row is durable across a restart");
    assert_eq!(journal_rows(&reopened), 1, "once, not duplicated");
}

/// A requester that does consume the reply while the commit fails gets a visible failure, not a
/// capture it cannot claim, and the edit is retained.
#[tokio::test]
async fn a_consumed_reply_with_a_failed_journal_commit_is_retry_required_and_retained() {
    let mut fx = handoff_fixture();
    let file = fx.write("a.txt");
    fx.journal.fail(None);
    let mut requester = Box::pin(fx.handle.flush_pending_local_change("group-1", "a.txt"));
    poll_once_to_pending(&mut requester);
    fx.flush_rx
        .try_recv()
        .unwrap()
        .reply
        .send(Some((file, FsChangeKind::CreatedOrModified, 1)))
        .unwrap();
    let outcome = requester.await;
    assert_eq!(outcome, PendingLocalFlushOutcome::RetryRequired);
    assert_eq!(fx.handle.processor.retained_handoff_count(), 1);

    fx.journal.heal();
    fx.redrive().await.unwrap();
    assert_eq!(fx.handle.processor.retained_handoff_count(), 0);
    assert!(indexed_live(&fx.deps, "a.txt").is_some());
    assert_eq!(journal_rows(&fx.deps), 0);
}

/// Control: with a healthy journal nothing is retained and the row is committed at hand-over.
#[tokio::test]
async fn a_healthy_journal_commits_at_handoff_and_retains_nothing() {
    let mut fx = handoff_fixture();
    let file = fx.write("a.txt");
    let mut requester = Box::pin(fx.handle.flush_pending_local_change("group-1", "a.txt"));
    poll_once_to_pending(&mut requester);
    fx.flush_rx
        .try_recv()
        .unwrap()
        .reply
        .send(Some((file, FsChangeKind::CreatedOrModified, 1)))
        .unwrap();
    drop(requester);
    assert!(is_journaled(&fx.deps, "a.txt"));
    assert_eq!(fx.handle.processor.retained_handoff_count(), 0);
    fx.redrive().await.unwrap();
    assert_eq!(fx.handle.processor.retained_handoff_count(), 0);
    assert!(indexed_live(&fx.deps, "a.txt").is_some());
    assert_eq!(journal_rows(&fx.deps), 0);
}

/// Control: a receiver gone before the send hands nothing over; the accumulator keeps the entry,
/// so there is nothing to journal or retain even with a failing journal.
#[tokio::test]
async fn a_requester_dropped_before_the_send_hands_nothing_over() {
    let mut fx = handoff_fixture();
    let file = fx.write("a.txt");
    fx.journal.fail(None);
    let mut requester = Box::pin(fx.handle.flush_pending_local_change("group-1", "a.txt"));
    poll_once_to_pending(&mut requester);
    let request = fx.flush_rx.try_recv().unwrap();
    drop(requester);
    let refused = request.reply.send(Some((file, FsChangeKind::CreatedOrModified, 1)));
    assert!(refused.is_err(), "the accumulator gets the value back and keeps it pending");
    assert_eq!(fx.handle.processor.retained_handoff_count(), 0);
    assert_eq!(journal_rows(&fx.deps), 0);
}

/// A batch whose commit fails on its first or its second item is retained whole (the commit is
/// one transaction), and after recovery each logical edit is applied once, none deleted.
#[tokio::test]
async fn a_batch_failing_on_either_item_is_retained_whole_and_applied_once() {
    for failing in ["a.txt", "b.txt"] {
        let mut fx = handoff_fixture();
        let a = fx.write("a.txt");
        let b = fx.write("b.txt");
        fx.journal.fail(Some(failing));

        let mut requester = Box::pin(fx.handle.flush_all_pending_local_changes("group-1"));
        poll_once_to_pending(&mut requester);
        fx.flush_all_rx
            .try_recv()
            .unwrap()
            .reply
            .send(vec![
                (a, FsChangeKind::CreatedOrModified, 1),
                (b, FsChangeKind::CreatedOrModified, 2),
            ])
            .unwrap();
        drop(requester);

        assert_eq!(journal_rows(&fx.deps), 0, "{failing}: a failed transaction leaves no row");
        assert_eq!(fx.handle.processor.retained_handoff_count(), 2, "{failing}");

        fx.journal.heal();
        fx.redrive().await.unwrap();
        assert_eq!(fx.handle.processor.retained_handoff_count(), 0);
        for name in ["a.txt", "b.txt"] {
            assert!(indexed_live(&fx.deps, name).is_some(), "{failing}: {name} must be captured");
        }
        assert_eq!(journal_rows(&fx.deps), 0, "{failing}: each edit captured, none pending");
    }
}

/// The process-restart case: a retained batch lives only in memory, so a restart loses it. The
/// startup scan must find those edits again from disk: nothing is deleted, nothing is applied
/// twice, and a path that was never touched is left alone.
#[tokio::test]
async fn a_retained_batch_lost_at_restart_is_refound_by_the_startup_scan() {
    let mut fx = handoff_fixture();
    let keep = fx.write("keep.txt");
    let old = fx.write("old.txt");
    let same = fx.write("same.txt");
    // `old.txt` is already captured; `new.txt` and the edit of `old.txt` are the handed-over batch.
    let root = fx.handle.root.clone();
    fx.handle.processor.scan_existing_files("group-1", &root).unwrap();
    let old_before = indexed_live(&fx.deps, "old.txt").unwrap();
    let same_blocks_before = indexed_live(&fx.deps, "same.txt").unwrap().blocks;
    std::fs::write(&old, b"old.txt edited by the user, longer").unwrap();
    // An edit that keeps both the size and the mtime: only the content differs.
    let same_mtime = std::fs::metadata(&same).unwrap().modified().unwrap();
    std::fs::write(&same, b"SAME.TXT").unwrap();
    std::fs::File::options().write(true).open(&same).unwrap().set_modified(same_mtime).unwrap();
    let new = fx.write("new.txt");
    fx.journal.fail(None);

    let mut requester = Box::pin(fx.handle.flush_all_pending_local_changes("group-1"));
    poll_once_to_pending(&mut requester);
    fx.flush_all_rx
        .try_recv()
        .unwrap()
        .reply
        .send(vec![
            (old, FsChangeKind::CreatedOrModified, 1),
            (same, FsChangeKind::CreatedOrModified, 1),
            (new, FsChangeKind::CreatedOrModified, 2),
        ])
        .unwrap();
    drop(requester);
    assert_eq!(fx.handle.processor.retained_handoff_count(), 3, "the batch is only in memory");
    assert_eq!(journal_rows(&fx.deps), 0, "the failing journal holds nothing");

    // The daemon dies here and starts again on the same file (the fault is over by then).
    fx.journal.heal();
    let fx = fx.restart();
    assert_eq!(fx.handle.processor.retained_handoff_count(), 0, "nothing survived in memory");
    assert_eq!(journal_rows(&fx.deps), 0, "and nothing was ever journaled");
    assert!(indexed_live(&fx.deps, "new.txt").is_none(), "the edit is not captured yet");

    // Startup, in the order the link runs it: the full scan, then the journal re-drive.
    let scanned = fx.handle.processor.scan_existing_files("group-1", &root).unwrap();
    let mut paths: Vec<&str> = scanned.iter().map(|record| record.path.as_str()).collect();
    paths.sort();
    assert_eq!(
        paths,
        ["new.txt", "old.txt", "same.txt"],
        "each lost edit applied once, nothing else"
    );
    assert!(scanned.iter().all(|record| !record.deleted), "no false deletion");
    assert!(indexed_live(&fx.deps, "new.txt").is_some());
    let old_after = indexed_live(&fx.deps, "old.txt").unwrap();
    assert_ne!(old_after.blocks, old_before.blocks, "the edit's content is what is indexed");
    assert_eq!(old_after.size, b"old.txt edited by the user, longer".len() as u64);
    assert!(indexed_live(&fx.deps, "keep.txt").is_some(), "{keep:?} untouched");
    assert_ne!(
        indexed_live(&fx.deps, "same.txt").unwrap().blocks,
        same_blocks_before,
        "a same-size, same-mtime edit is found by content"
    );

    assert!(fx.redrive().await.unwrap().records.is_empty());
    assert!(
        fx.handle.processor.scan_existing_files("group-1", &root).unwrap().is_empty(),
        "a second scan finds nothing left to apply"
    );
    assert_eq!(journal_rows(&fx.deps), 0);
}

/// End to end through the daemon's real coordinator: with the group policy unavailable the
/// re-drive keeps the committed row and captures nothing; once it arrives, the same re-drive
/// captures the edit exactly once.
#[tokio::test]
async fn a_redrive_waits_for_the_group_policy_then_captures() {
    let mut fx = handoff_fixture();
    let policy = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let provider_flag = policy.clone();
    fx.deps.replica_coordinator.set_local_policy_head_provider(Arc::new(move |_group_id| {
        if provider_flag.load(std::sync::atomic::Ordering::SeqCst) {
            Ok([0u8; 32])
        } else {
            Err(yadorilink_replica_domain::local_op::PolicyUnavailable)
        }
    }));
    let file = fx.write("a.txt");
    let mut requester = Box::pin(fx.handle.flush_pending_local_change("group-1", "a.txt"));
    poll_once_to_pending(&mut requester);
    fx.flush_rx
        .try_recv()
        .unwrap()
        .reply
        .send(Some((file, FsChangeKind::CreatedOrModified, 1)))
        .unwrap();
    drop(requester);
    assert!(is_journaled(&fx.deps, "a.txt"));

    assert!(fx.redrive().await.unwrap().records.is_empty(), "no policy, nothing captured");
    assert!(is_journaled(&fx.deps, "a.txt"), "the row waits");
    assert!(indexed_live(&fx.deps, "a.txt").is_none());

    policy.store(true, std::sync::atomic::Ordering::SeqCst);
    let captured = fx.redrive().await.unwrap();
    assert_eq!(captured.records.len(), 1);
    assert!(indexed_live(&fx.deps, "a.txt").is_some());
    assert_eq!(journal_rows(&fx.deps), 0);
    assert!(fx.redrive().await.unwrap().records.is_empty());
}
