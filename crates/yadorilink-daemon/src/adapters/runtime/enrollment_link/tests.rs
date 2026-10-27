#![cfg(test)]

use super::*;
use crate::application::ports::{LinkRepositoryPort, LinkWatcherPort};
use crate::application::EnrollmentKind;
use yadorilink_replica_domain::session_state::LinkRowWrite;

fn test_state() -> Arc<DaemonState> {
    let store = Arc::new(
        yadorilink_local_storage::SegmentBlockStore::new(tempfile::tempdir().unwrap().keep())
            .unwrap(),
    );
    let sync_state =
        Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new("device-a".into(), sync_state, store);
    state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
    state
}

fn test_link_lifecycle(state: &Arc<DaemonState>) -> Arc<LinkLifecycleService> {
    let controller = Arc::new(LinkRuntimeController::new(state.clone()));
    Arc::new(LinkLifecycleService::new(
        Arc::new(super::super::link_lifecycle::DaemonLinkRepositoryAdapter::new(state.clone())),
        Arc::new(super::super::link_lifecycle::DaemonLinkWatcherAdapter::new(
            state.clone(),
            controller,
        )),
    ))
}

fn enrollment_link_spec(operation_id: &str, local_path: &str) -> EnrollmentLinkRequest {
    EnrollmentLinkRequest {
        operation_id: operation_id.to_string(),
        kind: EnrollmentKind::Create,
        device_id: "device-a".to_string(),
        group_id: "group-1".to_string(),
        absolute_path: std::path::PathBuf::from(local_path),
        on_demand: false,
        provider: None,
    }
}

/// When the journal row is `Prepared` or `CancelPending` at the time of
/// a `link()` failure, nothing was left committed (either the failure
/// happened before the atomic commit, or `link()`'s own rollback already
/// confirmed it undone) -- `classify_link_failure` must classify this as
/// `NotCommitted`.
#[tokio::test]
async fn classify_link_failure_returns_not_committed_for_a_prepared_row() {
    let state = test_state();
    // A second, unrelated live link on "group-1" forces `link()` to fail
    // deterministically at its very first preflight check, before it
    // ever touches the journal row -- the failure REASON is irrelevant
    // to `classify_link_failure`, only the row's own state at read-back
    // time matters.
    let other = tempfile::tempdir().unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&other.path().to_string_lossy(), "group-1")
        .unwrap();
    state
        .replica_coordinator
        .enrollment_repository()
        .try_insert_enrollment_operation(
            &yadorilink_replica_domain::session_state::EnrollmentOperation {
                operation_id: "op-1".to_string(),
                kind: yadorilink_replica_domain::session_state::EnrollmentKind::Create,
                group_id: Some("group-1".to_string()),
                group_name: None,
                device_id: "device-a".to_string(),
                local_path: "/home/alice/Photos".to_string(),
                storage_mode: "eager".to_string(),
                state: EnrollmentOperationState::Prepared,
                last_error: None,
                attempts: 0,
                created_at_unix: 1,
                updated_at_unix: 1,
            },
        )
        .unwrap();

    let result = classify_link_failure(
        &state,
        &test_link_lifecycle(&state),
        enrollment_link_spec("op-1", "/home/alice/Photos"),
    )
    .await;

    assert!(
        matches!(result, Err(EnrollmentLinkError::NotCommitted { .. })),
        "expected NotCommitted, got {result:?}"
    );
}

/// When the journal row is `LocalSetupPending` at the time of a
/// `link()` failure, the link/marker commit landed and either the
/// post-commit rollback never ran or it ran and failed -- either way
/// the link may still be fully committed, so `classify_link_failure`
/// must classify this as `CommitUncertain`, never `NotCommitted`.
/// Getting this wrong is exactly the bug this function exists to close:
/// treating a still-committed link as safely cancellable would delete
/// its remote authorization while the link stays live locally.
#[tokio::test]
async fn classify_link_failure_returns_commit_uncertain_for_a_local_setup_pending_row() {
    let state = test_state();
    let other = tempfile::tempdir().unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&other.path().to_string_lossy(), "group-1")
        .unwrap();
    state
        .replica_coordinator
        .enrollment_repository()
        .try_insert_enrollment_operation(
            &yadorilink_replica_domain::session_state::EnrollmentOperation {
                operation_id: "op-1".to_string(),
                kind: yadorilink_replica_domain::session_state::EnrollmentKind::Create,
                group_id: Some("group-1".to_string()),
                group_name: None,
                device_id: "device-a".to_string(),
                local_path: "/home/alice/Photos".to_string(),
                storage_mode: "eager".to_string(),
                state: EnrollmentOperationState::LocalSetupPending,
                last_error: None,
                attempts: 0,
                created_at_unix: 1,
                updated_at_unix: 1,
            },
        )
        .unwrap();

    let result = classify_link_failure(
        &state,
        &test_link_lifecycle(&state),
        enrollment_link_spec("op-1", "/home/alice/Photos"),
    )
    .await;

    assert!(
        matches!(result, Err(EnrollmentLinkError::CommitUncertain { .. })),
        "expected CommitUncertain, got {result:?}"
    );
}

/// A missing journal row (or a read failure) at classification time must
/// fail closed toward `CommitUncertain`, never `NotCommitted` -- there is
/// no way to positively confirm nothing was committed.
#[tokio::test]
async fn classify_link_failure_fails_closed_when_the_journal_row_is_missing() {
    let state = test_state();
    let other = tempfile::tempdir().unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&other.path().to_string_lossy(), "group-1")
        .unwrap();
    // No `enrollment_operations` row at all for "op-missing".

    let result = classify_link_failure(
        &state,
        &test_link_lifecycle(&state),
        enrollment_link_spec("op-missing", "/home/alice/Photos"),
    )
    .await;

    assert!(
        matches!(result, Err(EnrollmentLinkError::CommitUncertain { .. })),
        "expected CommitUncertain (fail closed), got {result:?}"
    );
}

/// `LinkLifecycleService::is_linked` -- the primitive `commit_plain`'s
/// own classification is built on, since a plain link has no
/// `enrollment_operations` journal row to read back the way
/// `classify_link_failure` does above.
#[tokio::test]
async fn is_linked_reports_true_only_for_a_genuinely_live_matching_path() {
    let state = test_state();
    let lifecycle = test_link_lifecycle(&state);
    let linked = tempfile::tempdir().unwrap();
    let linked_path = linked.path().to_string_lossy().to_string();
    state.replica_coordinator.link_repository().add_link(&linked_path, "group-1").unwrap();

    assert!(
        lifecycle.is_linked("group-1", &linked_path).unwrap(),
        "the exact (group, path) that was just linked must report true"
    );

    let elsewhere = tempfile::tempdir().unwrap();
    assert!(
        !lifecycle.is_linked("group-1", &elsewhere.path().to_string_lossy()).unwrap(),
        "a different path for the SAME group must report false"
    );
    assert!(
        !lifecycle.is_linked("group-2", &linked_path).unwrap(),
        "the same path under a DIFFERENT group must report false"
    );
}

/// Forwards every `LinkRepositoryPort` call to a real, working adapter
/// EXCEPT `undo_plain_link`, which always fails -- the one piece
/// `classify_link_failure`'s own tests above never needed to fake
/// (they vary journal-row state instead), but `commit_plain` has no
/// journal to read, so proving its classification right requires
/// actually reaching "commit landed, watcher failed, rollback ALSO
/// failed" for real, not asserting it from a stub.
struct RemoveLinkAlwaysFails {
    inner: super::super::link_lifecycle::DaemonLinkRepositoryAdapter,
}

impl LinkRepositoryPort for RemoveLinkAlwaysFails {
    fn preflight_headroom_override_bytes(&self) -> Option<u64> {
        self.inner.preflight_headroom_override_bytes()
    }
    fn state_dir(&self) -> std::path::PathBuf {
        self.inner.state_dir()
    }
    fn live_link_paths_for_group(
        &self,
        group_id: &str,
    ) -> Result<Vec<String>, crate::sync_error::SyncError> {
        self.inner.live_link_paths_for_group(group_id)
    }
    fn live_link_keys_for_group(
        &self,
        group_id: &str,
    ) -> Result<Vec<String>, crate::sync_error::SyncError> {
        self.inner.live_link_keys_for_group(group_id)
    }
    fn list_link_paths_and_groups(
        &self,
    ) -> Result<Vec<(String, String)>, crate::sync_error::SyncError> {
        self.inner.list_link_paths_and_groups()
    }
    fn commit_plain_link(
        &self,
        local_path: &str,
        group_id: &str,
    ) -> Result<LinkRowWrite, crate::sync_error::SyncError> {
        self.inner.commit_plain_link(local_path, group_id)
    }
    fn commit_provider_link_plain(
        &self,
        local_path: &str,
        group_id: &str,
        provider: &crate::application::ports::ProviderLinkTarget,
    ) -> Result<LinkRowWrite, crate::sync_error::SyncError> {
        self.inner.commit_provider_link_plain(local_path, group_id, provider)
    }
    fn commit_link_with_pending_enrollment(
        &self,
        local_path: &str,
        group_id: &str,
        marker: &PendingEnrollmentLinkCommand,
        provider: Option<&crate::application::ports::ProviderLinkTarget>,
    ) -> Result<LinkRowWrite, crate::sync_error::SyncError> {
        self.inner.commit_link_with_pending_enrollment(local_path, group_id, marker, provider)
    }
    fn undo_plain_link(
        &self,
        _local_path: &str,
        _group_id: &str,
        _write: &LinkRowWrite,
    ) -> Result<&'static str, crate::sync_error::SyncError> {
        Err(std::io::Error::other("simulated undo_plain_link failure").into())
    }
    fn rollback_local_setup_to_cancel_pending(
        &self,
        local_path: &str,
        group_id: &str,
        write: &LinkRowWrite,
        operation_id: &str,
        detail: &str,
    ) -> Result<&'static str, crate::sync_error::SyncError> {
        self.inner.rollback_local_setup_to_cancel_pending(
            local_path,
            group_id,
            write,
            operation_id,
            detail,
        )
    }
    fn mark_enrollment_activation_pending(
        &self,
        operation_id: &str,
    ) -> Result<bool, crate::sync_error::SyncError> {
        self.inner.mark_enrollment_activation_pending(operation_id)
    }
    fn mark_link_orphaned(&self, local_path: &str) -> Result<(), crate::sync_error::SyncError> {
        self.inner.mark_link_orphaned(local_path)
    }
}

/// A `LinkWatcherPort` whose `start` always fails -- forces `link()`
/// past the commit and into its post-commit rollback path.
struct WatcherStartAlwaysFails;

impl LinkWatcherPort for WatcherStartAlwaysFails {
    fn is_ready(&self, _local_path: &str) -> bool {
        false
    }
    fn is_registered(&self, _local_path: &str) -> bool {
        false
    }
    fn start<'a>(
        &'a self,
        _local_path: &'a str,
        _group_id: &'a str,
        _on_demand: bool,
    ) -> BoxFuture<'a, Result<(), crate::error::DaemonError>> {
        Box::pin(async move {
            Err(crate::error::DaemonError::Config("simulated watcher start failure".to_string()))
        })
    }
    fn stop<'a>(&'a self, _local_path: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {})
    }
}

/// Exercises `commit_plain`'s REAL classification logic end to end,
/// through the actual `LinkLifecycleService::link()` call chain --
/// commit succeeds, the watcher fails, the rollback ALSO fails -- the
/// exact failure shape `commit_plain`'s own doc comment describes.
/// `link()` itself returns only a plain `Err` with no structure a
/// caller could classify from; this proves `commit_plain`'s `is_linked`
/// re-check correctly sees the link row still genuinely present and
/// classifies it `CommitUncertain`, never `NotCommitted` (which would
/// let the caller safely cancel the coordination-plane authorization
/// for a link that is actually still live).
#[tokio::test]
async fn commit_plain_classifies_a_genuinely_uncommittable_rollback_failure_as_commit_uncertain() {
    let state = test_state();
    let repository = RemoveLinkAlwaysFails {
        inner: super::super::link_lifecycle::DaemonLinkRepositoryAdapter::new(state.clone()),
    };
    let lifecycle = Arc::new(LinkLifecycleService::new(
        Arc::new(repository),
        Arc::new(WatcherStartAlwaysFails),
    ));
    let controller = Arc::new(LinkRuntimeController::new(state.clone()));
    let adapter = DaemonEnrollmentLinkAdapter::new(state.clone(), lifecycle, controller);

    let dir = tempfile::tempdir().unwrap();
    let local_path = dir.path().to_path_buf();
    let local_path_str = local_path.to_string_lossy().to_string();

    let result = adapter.commit_plain("group-1", &local_path, false, None).await;

    assert!(
        matches!(result, Err(EnrollmentLinkError::CommitUncertain { .. })),
        "expected CommitUncertain (the commit landed, only post-commit setup and its own \
         rollback failed), got {result:?}"
    );
    // The proof this test actually exercises the real classification,
    // not a stub: the link row genuinely IS still present.
    assert!(
        state
            .replica_coordinator
            .link_repository()
            .live_link_paths_for_group("group-1")
            .unwrap()
            .iter()
            .any(|p| p == &local_path_str),
        "the link row must genuinely still exist -- this is what makes CommitUncertain correct"
    );
}

// --- Re-linking a folder that is already linked and watched ---------------
//
// A second `share join G --path P` (or `yadorilink link P G`) for a folder
// that is already linked to G and running must leave that first link exactly
// as it was. The watcher refuses a second start for a path it already holds,
// so if the second call gets as far as committing and starting, its own
// failure rollback is what destroys the first link: the row (and with it the
// adopted root token) disappears while the first watcher keeps running, and
// every later capture then fails closed on "no previously-adopted root
// token".

const RELINK_GROUP: &str = "group-1";

/// A canonical folder with one file in it, so the adoption path (a marker on
/// disk, a token in the row) is the one production takes.
fn relink_root() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), b"first").unwrap();
    let path = dir.path().canonicalize().unwrap().to_string_lossy().to_string();
    (dir, path)
}

fn plain_link_command(local_path: &str) -> LinkCommand {
    LinkCommand {
        local_path: local_path.to_string(),
        group_id: RELINK_GROUP.to_string(),
        on_demand: false,
        pending_enrollment: None,
        provider: None,
    }
}

fn insert_prepared_join_operation(state: &Arc<DaemonState>, operation_id: &str, local_path: &str) {
    state
        .replica_coordinator
        .enrollment_repository()
        .try_insert_enrollment_operation(
            &yadorilink_replica_domain::session_state::EnrollmentOperation {
                operation_id: operation_id.to_string(),
                kind: yadorilink_replica_domain::session_state::EnrollmentKind::Join,
                group_id: Some(RELINK_GROUP.to_string()),
                group_name: None,
                device_id: "device-a".to_string(),
                local_path: local_path.to_string(),
                storage_mode: "eager".to_string(),
                state: EnrollmentOperationState::Prepared,
                last_error: None,
                attempts: 0,
                created_at_unix: 1,
                updated_at_unix: 1,
            },
        )
        .unwrap();
}

/// Links `local_path` for real and waits for its first scan, returning the
/// root token the start adopted.
async fn link_and_await_ready(
    state: &Arc<DaemonState>,
    lifecycle: &LinkLifecycleService,
    local_path: &str,
) -> String {
    // A local policy head lets live captures commit, so the capture check in
    // `assert_first_link_survives` observes the real admission path.
    state
        .replica_coordinator
        .set_local_policy_head_provider(std::sync::Arc::new(|_group_id| Ok([0u8; 32])));
    assert!(lifecycle.link(plain_link_command(local_path)).await.is_ok(), "the first link");
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        state.replica_coordinator.wait_group_ready(RELINK_GROUP),
    )
    .await
    .expect("the initial scan must finish")
    .expect("the initial scan must succeed");
    state
        .replica_coordinator
        .link_repository()
        .link_root_token_for_group(RELINK_GROUP)
        .unwrap()
        .expect("starting the first link must adopt a root token")
}

/// Everything that makes the first link still usable: its row, its token,
/// the on-disk identity check every capture runs, and an actual capture.
async fn assert_first_link_survives(
    state: &Arc<DaemonState>,
    dir: &std::path::Path,
    local_path: &str,
    token: &str,
) {
    assert_eq!(
        state
            .replica_coordinator
            .link_repository()
            .live_link_paths_for_group(RELINK_GROUP)
            .unwrap(),
        vec![local_path.to_string()],
        "the original link row must survive a repeated link of the same folder"
    );
    assert_eq!(
        state
            .replica_coordinator
            .link_repository()
            .link_root_token_for_group(RELINK_GROUP)
            .unwrap()
            .as_deref(),
        Some(token),
        "the adopted root token must be unchanged"
    );
    yadorilink_root_authority::root_identity::VerifiedRoot::verify(
        dir,
        RELINK_GROUP,
        state.replica_coordinator.as_ref(),
    )
    .expect("the root must still verify against its adopted token");

    std::fs::write(dir.join("b.txt"), b"second").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let captured = state
            .replica_coordinator
            .file_index_repository()
            .get_file(RELINK_GROUP, "b.txt")
            .unwrap()
            .is_some_and(|record| !record.deleted);
        if captured {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the still-running watcher must capture a new file after the repeated link"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// The enrollment re-join shape (`share join` on a folder already linked to
/// the group), driven straight through `LinkLifecycleService::link`.
// Multi-threaded: the live watcher's flush uses `block_in_place`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
// apple-cfg: ios-explicit the iOS host never runs the file watcher, and the simulator's kqueue
// backend does not deliver this test's event in time
#[cfg_attr(target_os = "ios", ignore = "the file watcher is not used on iOS")]
async fn an_enrollment_relink_of_a_running_link_leaves_the_first_link_intact() {
    let state = test_state();
    let lifecycle = test_link_lifecycle(&state);
    let (dir, local_path) = relink_root();
    let token = link_and_await_ready(&state, &lifecycle, &local_path).await;

    insert_prepared_join_operation(&state, "op-rejoin", &local_path);
    let mut command = plain_link_command(&local_path);
    command.pending_enrollment = Some(PendingEnrollmentLinkCommand {
        operation_id: "op-rejoin".to_string(),
        kind: EnrollmentKind::Join,
        device_id: "device-a".to_string(),
    });
    let result = lifecycle.link(command).await;

    assert!(result.is_ok(), "re-linking an already-running link must be a no-op, got {result:?}");
    assert!(
        state
            .replica_coordinator
            .enrollment_repository()
            .list_pending_enrollments()
            .unwrap()
            .is_empty(),
        "a no-op re-link must not leave a pending-enrollment marker behind"
    );
    assert_first_link_survives(&state, dir.path(), &local_path, &token).await;
}

/// The plain re-link while the first link's watcher is still starting: the
/// second call must not commit anything, so it has nothing to roll back.
#[tokio::test]
async fn a_plain_relink_while_the_first_watcher_is_starting_leaves_its_row_intact() {
    let state = test_state();
    let lifecycle = test_link_lifecycle(&state);
    let (_dir, local_path) = relink_root();
    state.replica_coordinator.link_repository().add_link(&local_path, RELINK_GROUP).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .set_link_root_token_for_group(RELINK_GROUP, "0123456789abcdef0123456789abcdef")
        .unwrap();
    // The first link's start is in flight: its slot is reserved `Starting`.
    let starting =
        crate::link_registry::LinkRegistry::reserve_starting(&state.links, local_path.clone())
            .unwrap();

    let _ = lifecycle.link(plain_link_command(&local_path)).await;

    assert_eq!(
        state
            .replica_coordinator
            .link_repository()
            .live_link_paths_for_group(RELINK_GROUP)
            .unwrap(),
        vec![local_path.clone()],
        "the first link's row must survive a re-link racing its start"
    );
    assert_eq!(
        state
            .replica_coordinator
            .link_repository()
            .link_root_token_for_group(RELINK_GROUP)
            .unwrap()
            .as_deref(),
        Some("0123456789abcdef0123456789abcdef"),
        "the first link's root token must survive"
    );
    drop(starting);
}

/// Just enough coordination plane for a same-account join: prepare succeeds,
/// activation reports the membership already active (the server resolves a
/// re-join by (group, device), whatever operation id it carries), and cancel
/// confirms.
struct AlreadyMemberCoordination;

impl crate::application::ports::EnrollmentCoordination for AlreadyMemberCoordination {
    fn is_configured(&self) -> bool {
        true
    }
    fn prepare_create<'a>(
        &'a self,
        _operation_id: &'a str,
        _group_name: &'a str,
        _device_id: &'a str,
        _storage_mode: &'a str,
    ) -> BoxFuture<'a, crate::application::model::EnrollmentPrepareResult> {
        unreachable!("create is not part of these tests")
    }
    fn prepare_join<'a>(
        &'a self,
        _operation_id: &'a str,
        group_id: &'a str,
        _device_id: &'a str,
        _storage_mode: &'a str,
    ) -> BoxFuture<'a, crate::application::model::EnrollmentPrepareResult> {
        let group_id = group_id.to_string();
        Box::pin(async move {
            crate::application::model::EnrollmentPrepareResult::Prepared { group_id }
        })
    }
    fn activate_create<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
    ) -> BoxFuture<'a, crate::application::model::EnrollmentActivationResult> {
        unreachable!("create is not part of these tests")
    }
    fn activate_join<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
        _device_id: &'a str,
    ) -> BoxFuture<'a, crate::application::model::EnrollmentActivationResult> {
        Box::pin(async { crate::application::model::EnrollmentActivationResult::AlreadyActive })
    }
    fn cancel_create<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
    ) -> BoxFuture<'a, crate::application::model::EnrollmentCancellationResult> {
        unreachable!("create is not part of these tests")
    }
    fn cancel_join<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
        _device_id: &'a str,
    ) -> BoxFuture<'a, crate::application::model::EnrollmentCancellationResult> {
        Box::pin(async { crate::application::model::EnrollmentCancellationResult::Confirmed })
    }
    fn prepare_invite_accept<'a>(
        &'a self,
        _operation_id: &'a str,
        _code: &'a str,
        _device_id: &'a str,
        _storage_mode: &'a str,
    ) -> BoxFuture<'a, crate::application::model::EnrollmentPrepareResult> {
        unreachable!("invites are not part of these tests")
    }
    fn activate_invite_accept<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
        _device_id: &'a str,
    ) -> BoxFuture<'a, crate::application::model::EnrollmentActivationResult> {
        unreachable!("invites are not part of these tests")
    }
    fn cancel_invite_accept<'a>(
        &'a self,
        _group_id: &'a str,
        _operation_id: &'a str,
        _device_id: &'a str,
    ) -> BoxFuture<'a, crate::application::model::EnrollmentCancellationResult> {
        unreachable!("invites are not part of these tests")
    }
    fn mint_invite<'a>(
        &'a self,
        _group_id: &'a str,
        _role: Option<&'a str>,
        _ttl_secs: Option<u64>,
        _requires_approval: bool,
    ) -> BoxFuture<
        'a,
        Result<crate::application::model::MintedInvite, crate::application::model::MintInviteError>,
    > {
        unreachable!("invites are not part of these tests")
    }
}

/// The whole `share join` path the CLI drives, against a folder this device
/// already links to the group and watches: it must succeed as a no-op, keep
/// the first link usable, and leave no enrollment bookkeeping behind.
// Multi-threaded: the live watcher's flush uses `block_in_place`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
// apple-cfg: ios-explicit the iOS host never runs the file watcher, and the simulator's kqueue
// backend does not deliver this test's event in time
#[cfg_attr(target_os = "ios", ignore = "the file watcher is not used on iOS")]
async fn a_repeated_share_join_of_a_linked_folder_succeeds_without_touching_it() {
    let state = test_state();
    let lifecycle = test_link_lifecycle(&state);
    let (dir, local_path) = relink_root();
    let token = link_and_await_ready(&state, &lifecycle, &local_path).await;

    let controller = Arc::new(LinkRuntimeController::new(state.clone()));
    let service = crate::application::EnrollmentService::new(
        "device-a".to_string(),
        Arc::new(crate::adapters::persistence::enrollment::SyncStateEnrollmentRepository::new(
            state.replica_coordinator.clone(),
        )),
        Arc::new(AlreadyMemberCoordination),
        Arc::new(DaemonEnrollmentLinkAdapter::new(state.clone(), lifecycle.clone(), controller)),
    );
    let outcome = service
        .join_and_link(crate::application::JoinAndLinkCommand {
            group_id: RELINK_GROUP.to_string(),
            group_name: "Photos".to_string(),
            absolute_path: std::path::PathBuf::from(&local_path),
            on_demand: false,
            provider: None,
        })
        .await;

    let outcome =
        outcome.unwrap_or_else(|e| panic!("a repeated join of a linked folder must succeed: {e}"));
    assert!(outcome.already_linked, "the outcome must say the folder was already linked");
    assert!(
        state
            .replica_coordinator
            .enrollment_repository()
            .scan_all_enrollment_operations()
            .unwrap()
            .valid
            .is_empty(),
        "the re-join's own enrollment operation must be settled, not left open"
    );
    assert_first_link_survives(&state, dir.path(), &local_path, &token).await;
}

/// A folder whose link row already exists but whose runtime is NOT running
/// (a retry after an earlier failed start, or an orphaned link being linked
/// again) is re-linked by updating that row. If the start then fails, the
/// rollback must put the row back as it was -- not delete it, which would
/// throw away its adopted root token.
#[tokio::test]
async fn a_failed_relink_restores_the_existing_row_instead_of_deleting_it() {
    let state = test_state();
    let (_dir, local_path) = relink_root();
    let links = state.replica_coordinator.link_repository();
    links.add_link(&local_path, RELINK_GROUP).unwrap();
    links.set_link_root_token_for_group(RELINK_GROUP, "0123456789abcdef0123456789abcdef").unwrap();
    links.mark_link_orphaned(&local_path).unwrap();
    let lifecycle = LinkLifecycleService::new(
        Arc::new(super::super::link_lifecycle::DaemonLinkRepositoryAdapter::new(state.clone())),
        Arc::new(WatcherStartAlwaysFails),
    );

    let result = lifecycle.link(plain_link_command(&local_path)).await;

    assert!(result.is_err(), "the start failed, so the link must be reported failed");
    let row = links
        .list_links()
        .unwrap()
        .into_iter()
        .find(|l| l.key() == local_path)
        .expect("the existing row must survive the failed re-link");
    assert!(row.orphaned, "the row must be restored to its prior (orphaned) state");
    assert_eq!(
        links.link_root_tokens_for_group_unchecked_for_test(RELINK_GROUP).unwrap(),
        vec![Some("0123456789abcdef0123456789abcdef".to_string())],
        "the row's root token must survive"
    );
}

/// The enrollment form of the same rollback: the existing row is restored,
/// while this attempt's own marker is dropped and its journal row returned to
/// `CancelPending` so the coordination side is still cancelled.
#[tokio::test]
async fn a_failed_enrollment_relink_restores_the_row_and_cancels_only_its_own_operation() {
    let state = test_state();
    let (_dir, local_path) = relink_root();
    let links = state.replica_coordinator.link_repository();
    links.add_link(&local_path, RELINK_GROUP).unwrap();
    links.set_link_root_token_for_group(RELINK_GROUP, "0123456789abcdef0123456789abcdef").unwrap();
    insert_prepared_join_operation(&state, "op-retry", &local_path);
    let lifecycle = LinkLifecycleService::new(
        Arc::new(super::super::link_lifecycle::DaemonLinkRepositoryAdapter::new(state.clone())),
        Arc::new(WatcherStartAlwaysFails),
    );
    let mut command = plain_link_command(&local_path);
    command.pending_enrollment = Some(PendingEnrollmentLinkCommand {
        operation_id: "op-retry".to_string(),
        kind: EnrollmentKind::Join,
        device_id: "device-a".to_string(),
    });

    assert!(lifecycle.link(command).await.is_err());

    assert_eq!(
        links.live_link_paths_for_group(RELINK_GROUP).unwrap(),
        vec![local_path.clone()],
        "the row that existed before this attempt must survive its rollback"
    );
    assert_eq!(
        links.link_root_token_for_group(RELINK_GROUP).unwrap().as_deref(),
        Some("0123456789abcdef0123456789abcdef")
    );
    let enrollment = state.replica_coordinator.enrollment_repository();
    assert!(enrollment.list_pending_enrollments().unwrap().is_empty(), "the marker is dropped");
    assert_eq!(
        enrollment.get_enrollment_operation("op-retry").unwrap().unwrap().state,
        EnrollmentOperationState::CancelPending
    );
}

/// A row this attempt inserted is still removed by the rollback, as before.
#[tokio::test]
async fn a_failed_first_link_still_removes_the_row_it_inserted() {
    let state = test_state();
    let (_dir, local_path) = relink_root();
    let lifecycle = LinkLifecycleService::new(
        Arc::new(super::super::link_lifecycle::DaemonLinkRepositoryAdapter::new(state.clone())),
        Arc::new(WatcherStartAlwaysFails),
    );

    assert!(lifecycle.link(plain_link_command(&local_path)).await.is_err());

    assert!(state.replica_coordinator.link_repository().list_links().unwrap().is_empty());
}

/// A watcher double that holds a path the way the real registry does (one
/// runtime per path, a second start refused) and lets a test put the two
/// starts of concurrent `link()` calls in a chosen order: the first start
/// parks until a second start has taken the path (or a short timeout runs
/// out, which is what happens when the second call cannot get that far).
#[derive(Default)]
struct RacingWatcher {
    held: std::sync::Mutex<std::collections::HashSet<String>>,
    starts: std::sync::atomic::AtomicUsize,
    first_start_entered: tokio::sync::Notify,
    second_start_reserved: tokio::sync::Notify,
}

impl RacingWatcher {
    fn reserve(&self, local_path: &str) -> Result<(), crate::error::DaemonError> {
        if self.held.lock().unwrap().insert(local_path.to_string()) {
            Ok(())
        } else {
            Err(crate::error::DaemonError::Config(
                "a watch is already starting or running".to_string(),
            ))
        }
    }
}

impl LinkWatcherPort for RacingWatcher {
    fn is_ready(&self, local_path: &str) -> bool {
        self.held.lock().unwrap().contains(local_path)
    }
    fn is_registered(&self, local_path: &str) -> bool {
        self.held.lock().unwrap().contains(local_path)
    }
    fn start<'a>(
        &'a self,
        local_path: &'a str,
        _group_id: &'a str,
        _on_demand: bool,
    ) -> BoxFuture<'a, Result<(), crate::error::DaemonError>> {
        Box::pin(async move {
            let order = self.starts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if order == 0 {
                let second = self.second_start_reserved.notified();
                self.first_start_entered.notify_one();
                let _ = tokio::time::timeout(std::time::Duration::from_millis(500), second).await;
                self.reserve(local_path)
            } else {
                let reserved = self.reserve(local_path);
                self.second_start_reserved.notify_one();
                reserved
            }
        })
    }
    fn stop<'a>(&'a self, local_path: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.held.lock().unwrap().remove(local_path);
        })
    }
}

/// Two `link` calls for the same new folder at once (the CLI and the desktop
/// app, or a double submit). The first commits the row, and before its
/// runtime takes the path the second call passes the already-linked check,
/// commits over the same row and starts first. Whatever order they land in,
/// the folder must end up linked with a runtime AND a row: the losing call
/// must never delete the row the winning call's runtime depends on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_concurrent_links_of_one_new_folder_never_delete_the_row_the_winner_runs_on() {
    let state = test_state();
    let (_dir, local_path) = relink_root();
    let watcher = Arc::new(RacingWatcher::default());
    let lifecycle = Arc::new(LinkLifecycleService::new(
        Arc::new(super::super::link_lifecycle::DaemonLinkRepositoryAdapter::new(state.clone())),
        watcher.clone(),
    ));

    let first_entered = watcher.first_start_entered.notified();
    let first = tokio::spawn({
        let lifecycle = lifecycle.clone();
        let command = plain_link_command(&local_path);
        async move { lifecycle.link(command).await }
    });
    first_entered.await;
    let second = tokio::spawn({
        let lifecycle = lifecycle.clone();
        let command = plain_link_command(&local_path);
        async move { lifecycle.link(command).await }
    });
    let first = first.await.unwrap();
    let second = second.await.unwrap();

    assert!(
        first.is_ok() || second.is_ok(),
        "one of the two calls must link the folder: {first:?} / {second:?}"
    );
    assert!(watcher.is_registered(&local_path), "a runtime holds the folder");
    assert_eq!(
        state
            .replica_coordinator
            .link_repository()
            .live_link_paths_for_group(RELINK_GROUP)
            .unwrap(),
        vec![local_path.clone()],
        "the row the running link depends on must survive the losing call \
         (first: {first:?}, second: {second:?})"
    );
}

/// A folder around the recovery area, or inside it, is refused at link time: the
/// area holds the user's files outside every synced folder and must never be
/// read back as new ones.
#[tokio::test]
async fn a_link_that_contains_or_lies_within_the_recovery_area_is_refused() {
    let _env = crate::test_support::CONFIG_ENV_MUTEX.lock().await;
    let base = tempfile::tempdir().unwrap();
    let base_path = base.path().canonicalize().unwrap();
    let state_dir = base_path.join("state");
    std::fs::create_dir_all(state_dir.join("recovery").join("inside")).unwrap();
    std::env::set_var("YADORILINK_CONFIG_DIR", &state_dir);

    let state = test_state();
    let lifecycle = LinkLifecycleService::new(
        Arc::new(super::super::link_lifecycle::DaemonLinkRepositoryAdapter::new(state.clone())),
        Arc::new(WatcherStartAlwaysFails),
    );
    let around = lifecycle.link(plain_link_command(&base_path.to_string_lossy())).await;
    let within = lifecycle
        .link(plain_link_command(&state_dir.join("recovery").join("inside").to_string_lossy()))
        .await;
    let (_other_dir, other_path) = relink_root();
    let elsewhere = lifecycle.link(plain_link_command(&other_path)).await;
    std::env::remove_var("YADORILINK_CONFIG_DIR");

    for (name, outcome) in [("around", around), ("within", within)] {
        assert!(
            matches!(&outcome, Err(crate::error::DaemonError::PathNotAllowed(why)) if why.contains("recovery area")),
            "{name}: {outcome:?}"
        );
    }
    assert!(
        !matches!(&elsewhere, Err(crate::error::DaemonError::PathNotAllowed(why)) if why.contains("recovery area")),
        "an unrelated folder was refused for the recovery area: {elsewhere:?}"
    );
    assert!(state.replica_coordinator.link_repository().list_links().unwrap().is_empty());
}

#[test]
fn the_recovery_area_overlap_check_compares_resolved_and_folded_paths() {
    use crate::device_config::link_overlaps_recovery_area as overlaps;
    use std::path::Path;
    let recovery = Path::new("/nonexistent-root/State/recovery");
    assert!(overlaps(Path::new("/nonexistent-root/state/RECOVERY/x"), recovery), "inside, folded");
    assert!(overlaps(Path::new("/nonexistent-root"), recovery), "around");
    assert!(overlaps(recovery, recovery), "the same folder");
    assert!(!overlaps(Path::new("/nonexistent-root/state/recovery2"), recovery), "a sibling");
    assert!(!overlaps(Path::new("/nonexistent-root/state/documents"), recovery));
}
