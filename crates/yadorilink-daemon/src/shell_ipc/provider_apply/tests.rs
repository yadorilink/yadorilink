#![cfg(test)]

//! `ProviderApplyChange` over the shell connection's message handling: who may ask, ingest, the
//! replay path that never ingests, KEEP_LOCAL, cancellation, error mapping, and one writer per
//! domain across processes (the OS lock).

use std::time::Duration;

use tokio::sync::mpsc;
use yadorilink_ipc_proto::shellipc::{ProviderContentSource, ProviderItemMetadata};

use crate::daemon_state::DaemonState;
use crate::provider_handoff::HandoffRoot;
use crate::shell_ipc::provider_materialize::Delivery;
use crate::shell_ipc::provider_tests::{domain_state, handshake, send, state_with_root};

use yadorilink_local_storage::BlockContentStore;

use super::*;

const GROUP_ID: &str = "group-1";

struct Fx {
    state: Arc<DaemonState>,
    root: String,
    root_id: Vec<u8>,
    context: Arc<ShellContext>,
    requests: MaterializeRequests,
    handshakes: Arc<Handshakes>,
    tx: Reply,
    rx: mpsc::UnboundedReceiver<Delivery>,
    host: mpsc::UnboundedSender<ShellIpcMessage>,
    _host_rx: mpsc::UnboundedReceiver<ShellIpcMessage>,
    dir: tempfile::TempDir,
}

fn sha(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

impl Fx {
    async fn new() -> Self {
        Self::new_with(true).await
    }

    /// The embedding app's view: the root is declared and nothing else has happened. The OS has
    /// registered no domain, no extension has said hello and no host connection is attached.
    async fn app_only() -> Self {
        Self::new_with(false).await
    }

    async fn new_with(os_evidence: bool) -> Self {
        let (state, root) = state_with_root();
        state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
        // This device is a writer of the group's verified policy.
        state.authority.replace_group_policy_states(std::collections::HashMap::from([(
            GROUP_ID.to_string(),
            crate::test_support::sync_stack_fixture::fixture_group_policy_granting(&[(
                "device-a",
                ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key(),
            )]),
        )]));
        let root_id = hex::decode(&root).unwrap();
        if os_evidence {
            send(&state, domain_state(&root_id, true)).await;
            send(&state, handshake(&root_id)).await;
        }
        let dir = tempfile::tempdir().unwrap();
        let handoff = HandoffRoot::open_with_lifetime(dir.path(), Duration::from_secs(60)).unwrap();
        let context =
            Arc::new(ShellContext::from_state(state.clone()).with_handoff_root(Some(handoff)));
        let (host, host_rx) = mpsc::unbounded_channel();
        let (tx, rx) = mpsc::unbounded_channel();
        let handshakes = Arc::new(Handshakes::default());
        if os_evidence {
            assert!(context.provider_host.try_attach(host.clone()));
            handshakes.note(&root_id);
        }
        Self {
            state,
            root,
            root_id,
            context,
            requests: MaterializeRequests::default(),
            handshakes,
            tx,
            rx,
            host,
            _host_rx: host_rx,
            dir,
        }
    }

    fn repo(&self) -> &yadorilink_sync_sqlite::provider::ProviderRepository {
        self.state.replica_coordinator.provider_repository()
    }

    fn ingest_dir(&self) -> std::path::PathBuf {
        self.context.handoff.get().unwrap().ingest_dir().to_path_buf()
    }

    fn put_ingest(&self, name: &str, bytes: &[u8]) -> ProviderContentSource {
        std::fs::write(self.ingest_dir().join(name), bytes).unwrap();
        ProviderContentSource {
            ingest_name: name.into(),
            size: bytes.len() as u64,
            sha256: sha(bytes),
        }
    }

    fn create(
        &self,
        seq: u64,
        name: &str,
        content: Option<ProviderContentSource>,
    ) -> ProviderApplyChangeRequest {
        ProviderApplyChangeRequest {
            request_id: format!("req-{seq}").into_bytes(),
            session_id: vec![1; 16],
            operation_seq: seq,
            root_id: self.root_id.clone(),
            kind: ProviderChangeKind::Create as i32,
            name: Some(name.into()),
            entry_kind: WireEntryKind::File as i32,
            content,
            metadata: Some(ProviderItemMetadata::default()),
            ..Default::default()
        }
    }

    fn send(&self, request: ProviderApplyChangeRequest) {
        let message =
            ShellIpcMessage { payload: Some(Payload::ProviderApplyChangeRequest(request)) };
        assert!(apply_message(&self.context, &self.requests, &self.handshakes, &self.tx, &message));
    }

    async fn response(&mut self) -> ProviderApplyChangeResponse {
        let delivery = tokio::time::timeout(Duration::from_secs(10), self.rx.recv())
            .await
            .expect("no response within 10 s (a slow machine, or the reply was never sent)")
            .expect("the response channel closed before a reply");
        if let Some(written) = delivery.written {
            let _ = written.send(true);
        }
        match delivery.message.payload {
            Some(Payload::ProviderApplyChangeResponse(response)) => response,
            other => panic!("expected a response, got {other:?}"),
        }
    }

    async fn ask(&mut self, request: ProviderApplyChangeRequest) -> ProviderApplyChangeResponse {
        self.send(request);
        self.response().await
    }
}

fn failure(response: &ProviderApplyChangeResponse) -> ProviderApplyFailure {
    ProviderApplyFailure::try_from(response.failure).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_create_ingests_the_copy_commits_and_removes_it() {
    let mut fx = Fx::new().await;
    let source = fx.put_ingest("copy-1", b"hello provider");
    let response = fx.ask(fx.create(1, "a.txt", Some(source))).await;
    assert!(response.ok, "{response:?}");
    assert_eq!(response.outcome, ProviderApplyOutcome::Applied as i32);
    // The committed change is followed up (published to peers): a peer cannot be sent a delta that
    // is not published, and nothing else would publish it until the next reconnect.
    assert_eq!(fx.context.writer.follow_ups(), 1, "a committed provider change must be published");
    let item = response.item.unwrap();
    assert_eq!(item.name, "a.txt");
    assert_eq!(item.size, 14);
    assert!(item.current);
    assert!(!fx.ingest_dir().join("copy-1").exists(), "the spent copy is removed");
    let path =
        fx.repo().path_for_item(&fx.root, &<[u8; 16]>::try_from(item.item_id.as_slice()).unwrap());
    assert_eq!(path.unwrap().map(|(p, _)| p).as_deref(), Some("a.txt"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replay_is_answered_from_the_record_without_reading_anything() {
    let mut fx = Fx::new().await;
    let source = fx.put_ingest("copy-1", b"once");
    let first = fx.ask(fx.create(1, "a.txt", Some(source.clone()))).await;
    assert!(first.ok);
    // The copy is gone: a replay that tried to ingest again would fail.
    let mut again = fx.create(1, "a.txt", Some(source.clone()));
    again.request_id = b"another-attempt".to_vec();
    let replay = fx.ask(again).await;
    assert!(replay.ok, "{replay:?}");
    assert_eq!(replay.outcome, ProviderApplyOutcome::Applied as i32, "a replay keeps its outcome");
    assert!(replay.replayed && !first.replayed);
    assert_eq!(replay.item, first.item);
    // The same identity with other fields is a different change.
    let mut other = fx.create(1, "b.txt", Some(source));
    other.request_id = b"third".to_vec();
    assert_eq!(failure(&fx.ask(other).await), ProviderApplyFailure::OperationMismatch);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_late_replay_of_an_expired_operation_is_stale() {
    let mut fx = Fx::new().await;
    let first = fx.ask(fx.create(1, "a.txt", None)).await;
    assert!(first.ok, "{first:?}");
    fx.state
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            tx.execute("DELETE FROM provider_apply_log", [])?;
            Ok(())
        })
        .unwrap();
    let mut late = fx.create(1, "a.txt", None);
    late.request_id = b"late".to_vec();
    assert_eq!(failure(&fx.ask(late).await), ProviderApplyFailure::StaleOperation);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_a_handshaken_connection_with_an_attached_host_may_write() {
    let mut fx = Fx::new().await;
    // A connection that never sent the extension handshake for the root.
    let stray = Arc::new(Handshakes::default());
    let message = ShellIpcMessage {
        payload: Some(Payload::ProviderApplyChangeRequest(fx.create(1, "a.txt", None))),
    };
    assert!(apply_message(&fx.context, &fx.requests, &stray, &fx.tx, &message));
    assert_eq!(failure(&fx.response().await), ProviderApplyFailure::NotReady);

    // No host app attached.
    assert!(fx.context.provider_host.detach(&fx.host));
    let response = fx.ask(fx.create(2, "a.txt", None)).await;
    assert_eq!(failure(&response), ProviderApplyFailure::NotReady);
    assert_eq!(fx.repo().pending_items(&fx.root).unwrap().len(), 0, "nothing was authored");
}

/// The operating system's registration of the root is gone (the host reports its domain removed or
/// missing): the placeholders vanishing with it are not the person deleting them. A delete that
/// reaches the daemon from that root is refused and the item survives; once the host reports the
/// root registered again, the same delete is the person's and is applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delete_from_a_root_the_host_reports_lost_is_refused_and_the_item_survives() {
    use yadorilink_ipc_proto::shellipc::{DomainEvidence, ProviderDomainState};
    let mut fx = Fx::new().await;
    let source = fx.put_ingest("copy-1", b"the only copy another device keeps");
    let created = fx.ask(fx.create(1, "keep.bin", Some(source))).await;
    assert!(created.ok, "{created:?}");
    let item = created.item.unwrap();
    let root_id = fx.root_id.clone();
    let delete = |seq: u64| ProviderApplyChangeRequest {
        base_version_hash: item.content_version.clone(),
        request_id: format!("delete-{seq}").into_bytes(),
        session_id: vec![1; 16],
        operation_seq: seq,
        root_id: root_id.clone(),
        kind: ProviderChangeKind::Delete as i32,
        item_id: item.item_id.clone(),
        ..Default::default()
    };
    async fn report(fx: &Fx, evidence: DomainEvidence) {
        let message = ShellIpcMessage {
            payload: Some(Payload::ProviderDomainState(ProviderDomainState {
                root_id: fx.root_id.clone(),
                evidence: evidence as i32,
                preserved_location: String::new(),
                last_acked_namespace_revision: 0,
            })),
        };
        crate::shell_ipc::provider_channel_message(&fx.context, &fx.host, &message).await;
    }

    // The registration is lost (a raw reading from the host, before any verdict is reached).
    report(&fx, DomainEvidence::Absent).await;
    let refused = fx.ask(delete(2)).await;
    assert_eq!(failure(&refused), ProviderApplyFailure::NotReady, "{refused:?}");
    assert_eq!(
        fx.repo().list_children(&fx.root, "").unwrap().len(),
        1,
        "a delete from a root the OS no longer has registered was applied"
    );
    assert_eq!(fx.context.writer.follow_ups(), 1, "only the create was published");

    // A reading that proves nothing came back does not lift the refusal.
    report(&fx, DomainEvidence::Unknown).await;
    report(&fx, DomainEvidence::NotRegistered).await;
    assert_eq!(failure(&fx.ask(delete(4)).await), ProviderApplyFailure::NotReady);
    assert_eq!(fx.repo().list_children(&fx.root, "").unwrap().len(), 1);

    // Registered again: the same request is the person's and goes through.
    report(&fx, DomainEvidence::Registered).await;
    assert!(fx.ask(delete(3)).await.ok);
    assert_eq!(fx.repo().list_children(&fx.root, "").unwrap().len(), 0);
}

/// A delete that passed the first look is stopped at the commit point when the registration is
/// reported lost in between (the copy of the bytes is read in that time).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_loss_reported_before_the_commit_point_stops_the_delete() {
    let mut fx = Fx::new().await;
    let source = fx.put_ingest("copy-1", b"bytes");
    let created = fx.ask(fx.create(1, "keep.bin", Some(source))).await;
    let item = created.item.unwrap();
    let delete = ProviderApplyChangeRequest {
        base_version_hash: item.content_version.clone(),
        request_id: b"delete-in-flight".to_vec(),
        session_id: vec![1; 16],
        operation_seq: 2,
        root_id: fx.root_id.clone(),
        kind: ProviderChangeKind::Delete as i32,
        item_id: item.item_id.clone(),
        ..Default::default()
    };
    let (context, root) = (fx.context.clone(), fx.root.clone());
    set_point(
        "before_commit_point",
        &delete.request_id,
        Arc::new(move || context.provider_host.note_domain_lost(&root, true)),
    );
    fx.send(delete);
    let response = fx.response().await;
    assert!(!response.ok, "{response:?}");
    assert_eq!(fx.repo().list_children(&fx.root, "").unwrap().len(), 1, "the delete committed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_copy_that_does_not_match_its_declaration_is_rejected_and_nothing_is_authored() {
    let mut fx = Fx::new().await;
    let mut source = fx.put_ingest("copy-1", b"declared one thing");
    source.sha256 = sha(b"another thing");
    let response = fx.ask(fx.create(1, "a.txt", Some(source))).await;
    assert_eq!(failure(&response), ProviderApplyFailure::IngestUnstable);
    let mut missing = fx.create(
        2,
        "b.txt",
        Some(ProviderContentSource { ingest_name: "nope".into(), size: 1, sha256: sha(b"x") }),
    );
    missing.request_id = b"m".to_vec();
    assert_eq!(failure(&fx.ask(missing).await), ProviderApplyFailure::IngestUnstable);
    let mut traversal = fx.create(
        3,
        "c.txt",
        Some(ProviderContentSource { ingest_name: "../x".into(), size: 1, sha256: sha(b"x") }),
    );
    traversal.request_id = b"t".to_vec();
    assert_eq!(failure(&fx.ask(traversal).await), ProviderApplyFailure::IngestRejected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_modify_of_a_retired_item_keeps_the_local_bytes_under_a_conflict_copy_name() {
    let mut fx = Fx::new().await;
    let source = fx.put_ingest("copy-1", b"first");
    let created = fx.ask(fx.create(1, "doc.txt", Some(source))).await;
    let item = created.item.unwrap();
    let id = <[u8; 16]>::try_from(item.item_id.as_slice()).unwrap();
    assert!(fx.repo().retire_item(&fx.root, &id).unwrap());
    let source = fx.put_ingest("copy-2", b"edited after retirement");
    let response = fx
        .ask(ProviderApplyChangeRequest {
            request_id: b"edit".to_vec(),
            session_id: vec![1; 16],
            operation_seq: 2,
            root_id: fx.root_id.clone(),
            kind: ProviderChangeKind::Modify as i32,
            item_id: id.to_vec(),
            base_version_hash: item.content_version.clone(),
            base_generation: Some(u64::from_be_bytes(
                item.content_version[32..].try_into().unwrap(),
            )),
            content: Some(source),
            ..Default::default()
        })
        .await;
    // The bytes are kept durably as a conflict-named file; nothing is left for the OS to re-send.
    assert!(response.ok, "{response:?}");
    assert_eq!(response.outcome, ProviderApplyOutcome::Concurrent as i32);
    let kept = response.item.unwrap();
    assert!(kept.name.starts_with("doc"), "{}", kept.name);
    assert_ne!(kept.name, "doc.txt");
}

fn cancel_message(id: &[u8]) -> ShellIpcMessage {
    ShellIpcMessage {
        payload: Some(Payload::ProviderApplyCancel(ProviderApplyCancel {
            request_id: id.to_vec(),
        })),
    }
}

fn set_point(name: &'static str, id: &[u8], hook: Arc<dyn Fn() + Send + Sync>) {
    POINT_HOOKS
        .lock()
        .unwrap()
        .get_or_insert_with(Default::default)
        .insert((name, id.to_vec()), hook);
}

/// A cancel that arrives before the commit point wins: CANCELLED, once, and nothing is authored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_before_the_commit_point_answers_cancelled_and_authors_nothing() {
    let mut fx = Fx::new().await;
    let mut request = fx.create(1, "a.txt", None);
    request.request_id = b"cancel-before".to_vec();
    let id = request.request_id.clone();
    {
        let (context, requests, handshakes, tx) =
            (fx.context.clone(), fx.requests.clone(), fx.handshakes.clone(), fx.tx.clone());
        let cancel = cancel_message(&id);
        set_point(
            "before_commit_point",
            &id,
            Arc::new(move || {
                assert!(apply_message(&context, &requests, &handshakes, &tx, &cancel));
            }),
        );
    }
    fx.send(request);
    let response = fx.response().await;
    assert_eq!(failure(&response), ProviderApplyFailure::Cancelled);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(fx.rx.try_recv().is_err(), "a second answer");
    assert_eq!(
        fx.repo().list_children(&fx.root, "").unwrap().len(),
        0,
        "a cancelled change was authored"
    );
}

/// A cancel that arrives AT the commit point (the change may commit) is ignored: the response is
/// the real outcome and the change is committed. The OS is never told a committed change failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_at_the_commit_point_never_hides_a_committed_change() {
    let mut fx = Fx::new().await;
    let mut request = fx.create(1, "a.txt", None);
    request.request_id = b"cancel-at".to_vec();
    let id = request.request_id.clone();
    {
        let (context, requests, handshakes, tx) =
            (fx.context.clone(), fx.requests.clone(), fx.handshakes.clone(), fx.tx.clone());
        let cancel = cancel_message(&id);
        set_point(
            "at_commit_point",
            &id,
            Arc::new(move || {
                assert!(apply_message(&context, &requests, &handshakes, &tx, &cancel));
            }),
        );
    }
    fx.send(request);
    let response = fx.response().await;
    assert!(response.ok, "{response:?}");
    assert_eq!(fx.repo().list_children(&fx.root, "").unwrap().len(), 1, "the change is committed");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(fx.rx.try_recv().is_err(), "a second answer");
}

#[test]
fn a_full_database_maps_to_low_disk_and_other_database_errors_to_retry() {
    let full = rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_FULL),
        Some("database or disk is full".into()),
    );
    assert_eq!(map_error(full.into(), &None).code, ProviderApplyFailure::LowDisk);
    let busy = rusqlite::Error::InvalidQuery;
    assert_eq!(map_error(busy.into(), &None).code, ProviderApplyFailure::Retry);
    assert_eq!(
        map_ingest(IngestError::LowDisk("no space".into())).code,
        ProviderApplyFailure::LowDisk
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_writers_cannot_author_for_one_domain_directory() {
    let fx = Fx::new().await;
    let dir = fx.dir.path().join("domains-shared");
    let first = crate::provider_writer::ProviderWriter::new(fx.state.clone());
    let lease = first.lease(&fx.root, "group-1", &dir).unwrap();
    // Another writer of the same directory (here a second instance; across processes it is the
    // same OS lock) is refused while the first lease lives.
    let second = crate::provider_writer::ProviderWriter::new(fx.state.clone());
    assert!(second.lease(&fx.root, "group-1", &dir).is_err());
    drop(lease);
    drop(first);
    assert!(second.lease(&fx.root, "group-1", &dir).is_ok());
}

/// A device that is not a writer of the group's verified policy (a Viewer, or simply not
/// granted) is refused before anything is read or committed: its change would be rejected by
/// every peer, so success here would be a lie. A granted writer still succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_device_that_is_not_a_writer_is_refused_before_anything_is_read_or_committed() {
    use crate::test_support::sync_stack_fixture::fixture_group_policy_granting;
    let mut fx = Fx::new().await;
    let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key();
    let mine = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
    let state = fx.state.clone();
    let install = |granted: &[(&str, ed25519_dalek::VerifyingKey)]| {
        state.authority.replace_group_policy_states(std::collections::HashMap::from([(
            "group-1".to_string(),
            fixture_group_policy_granting(granted),
        )]));
    };

    install(&[("someone-else", other)]);
    let source = fx.put_ingest("copy-1", b"viewer bytes");
    let response = fx.ask(fx.create(1, "a.txt", Some(source))).await;
    assert_eq!(failure(&response), ProviderApplyFailure::NotAuthorized, "{response:?}");
    assert_eq!(fx.repo().list_children(&fx.root, "").unwrap().len(), 0, "a viewer authored");
    assert!(fx.ingest_dir().join("copy-1").exists(), "the copy was consumed for a refused change");

    install(&[("device-a", mine)]);
    let mut again = fx.create(2, "a.txt", None);
    again.request_id = b"granted".to_vec();
    assert!(fx.ask(again).await.ok);
}

/// A symlinked domain path is refused (it could split the lock between two directories), and a
/// path retargeted after the lock was taken is refused on the next request.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_symlinked_or_retargeted_domain_path_cannot_split_the_lock() {
    let fx = Fx::new().await;
    let base = fx.dir.path().join("domains-links");
    std::fs::create_dir(&base).unwrap();
    let elsewhere = fx.dir.path().join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();

    // The domain directory itself is a symlink: refused, nothing locked.
    let linked = base.join("linked");
    std::os::unix::fs::symlink(&elsewhere, &linked).unwrap();
    let writer = crate::provider_writer::ProviderWriter::new(fx.state.clone());
    assert!(writer.lease(&fx.root, "group-1", &linked).is_err());
    assert!(
        !elsewhere.join(".yadorilink-root.lock").exists(),
        "a lock was taken through a symlink"
    );

    // A real directory is locked with mode 0700; retargeting it afterwards is refused.
    let real = base.join("real");
    writer.lease(&fx.root, "group-1", &real).unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&real).unwrap().permissions().mode() & 0o777, 0o700);
    }
    std::fs::rename(&real, base.join("moved")).unwrap();
    std::os::unix::fs::symlink(&elsewhere, &real).unwrap();
    assert!(writer.lease(&fx.root, "group-1", &real).is_err());
}

fn declared_root(fx: &Fx) -> yadorilink_sync_sqlite::provider::ProviderRoot {
    fx.repo()
        .list_declared_roots()
        .unwrap()
        .into_iter()
        .find(|r| r.root_id == fx.root)
        .expect("the declared root")
}

/// The projector rebuilds the rows of an install and, once the build verifies, marks the
/// namespace queryable: not before the install is recorded, and never cleared by later lag.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_projector_builds_the_namespace_and_readiness_is_set_once() {
    let mut fx = Fx::new().await;
    let source = fx.put_ingest("copy-1", b"hello");
    assert!(fx.ask(fx.create(1, "a.txt", Some(source))).await.ok);
    // What an install leaves: heads and versions, no rows, every path armed.
    fx.state
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            tx.execute("DELETE FROM files", [])?;
            tx.execute("UPDATE provider_roots SET install_done = 0, namespace_ready = 0", [])?;
            yadorilink_sync_sqlite::projection_obligations::bump_projection_obligations_for_touched_paths(
                tx, "group-1", &["a.txt"], 1,
            )?;
            Ok(())
        })
        .unwrap();

    // Not installed: the rows are rebuilt, but an empty-or-partial namespace is not "queryable".
    let tick = crate::provider_projector::tick_root(&fx.state, &declared_root(&fx), 100);
    assert_eq!((tick.projected, tick.became_ready), (1, false));
    assert!(!declared_root(&fx).namespace_ready);

    fx.repo().mark_install_done(&fx.root).unwrap();
    let tick = crate::provider_projector::tick_root(&fx.state, &declared_root(&fx), 100);
    assert!(tick.became_ready);
    assert!(declared_root(&fx).namespace_ready);

    // Later lag (an armed obligation nobody projected yet, a restart) never clears it.
    fx.state
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            yadorilink_sync_sqlite::projection_obligations::bump_projection_obligations_for_touched_paths(
                tx, "group-1", &["a.txt"], 2,
            )?;
            Ok(())
        })
        .unwrap();
    let tick = crate::provider_projector::tick_root(&fx.state, &declared_root(&fx), 0);
    assert_eq!(tick.projected, 0);
    assert!(declared_root(&fx).namespace_ready, "lag cleared readiness");
}

struct NoEnvironment;

impl crate::provider_eager::EagerEnvironment for NoEnvironment {
    fn low_disk(&self, _dir: &std::path::Path, _bytes: u64) -> bool {
        false
    }
    fn peers_available(&self, _group_id: &str) -> bool {
        true
    }
}

/// An item the user created or edited on this device is already on the OS: once the host lists it
/// as materialized, the Eager driver settles it and never offers it as a download, so it cannot
/// hold one of the host's two download slots.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_authored_item_is_settled_by_the_eager_driver_and_never_offered() {
    use yadorilink_ipc_proto::shellipc::{
        NextProviderDownloadsRequest, ProviderMaterializedItem, ProviderMaterializedReport,
    };
    let mut fx = Fx::new().await;
    fx.repo().mark_install_done(&fx.root).unwrap();
    fx.repo().set_namespace_ready(&fx.root, true).unwrap();
    let source = fx.put_ingest("copy-1", b"hello provider");
    let created = fx.ask(fx.create(1, "a.txt", Some(source))).await;
    assert!(created.ok, "{created:?}");
    let item = created.item.unwrap().item_id;

    // The host reports what the OS holds, in a report that began after the daemon's evidence.
    let latest = fx.repo().latest_evidence_seq(&fx.root).unwrap().unwrap();
    let ack = fx.context.membership.apply(
        &ProviderMaterializedReport {
            root_id: fx.root_id.clone(),
            reporter_epoch: 1,
            report_seq: 1,
            full: true,
            observed_after_seq: latest,
            upserts: vec![ProviderMaterializedItem { item_id: item.clone() }],
            removed: Vec::new(),
            more: false,
        },
        latest,
    );
    assert!(!ack.needs_full);

    let driver = crate::provider_eager::EagerDriver::new(
        Arc::new(NoEnvironment),
        crate::provider_eager::EagerConfig::default(),
    );
    let staging = tempfile::tempdir().unwrap();
    let inputs = crate::provider_eager::EagerInputs {
        coordinator: &fx.state.replica_coordinator,
        membership: &fx.context.membership,
        staging_dir: Some(staging.path()),
        host_attached: true,
    };
    let ask = |exclude: Vec<Vec<u8>>| {
        driver.next_downloads(
            &inputs,
            &NextProviderDownloadsRequest {
                root_id: fx.root_id.clone(),
                exclude_item_ids: exclude,
                max: 2,
                request_id: Vec::new(),
            },
        )
    };
    let offered = ask(Vec::new());
    assert_eq!(offered.state, yadorilink_ipc_proto::shellipc::DriverState::Done as i32);
    assert!(offered.downloads.is_empty(), "an authored item was offered for download");
    let settled = ask(vec![item.clone()]);
    assert_eq!(settled.settled_item_ids, vec![item], "an authored item was left outstanding");
}

// ---- enumeration over the connection ----

async fn ask_children(
    fx: &Fx,
    parent: &[u8],
    token: &[u8],
    limit: u32,
) -> yadorilink_ipc_proto::shellipc::EnumerateChildrenResponse {
    use yadorilink_ipc_proto::shellipc::EnumerateChildrenRequest;
    let message = ShellIpcMessage {
        payload: Some(Payload::EnumerateChildrenRequest(EnumerateChildrenRequest {
            root_id: fx.root_id.clone(),
            parent_item_id: parent.to_vec(),
            page_token: token.to_vec(),
            limit,
        })),
    };
    match super::super::provider_enumerate::answer(&fx.context, &fx.handshakes, &message)
        .await
        .and_then(|m| m.payload)
    {
        Some(Payload::EnumerateChildrenResponse(response)) => response,
        other => panic!("expected an enumeration response, got {other:?}"),
    }
}

fn enumerate_failure(code: i32) -> yadorilink_ipc_proto::shellipc::EnumerateFailure {
    yadorilink_ipc_proto::shellipc::EnumerateFailure::try_from(code).unwrap()
}

/// The OS is told, per item and by the engine, whether it may drop its own copy ("Remove
/// Download"): a file the user keeps on this device is not allowed, and an item is judged at the
/// moment it is served, so an unpin takes effect at the next read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_wire_item_carries_the_engines_eviction_permission() {
    let mut fx = Fx::new().await;
    for (seq, name) in ["free", "kept"].into_iter().enumerate() {
        let mut request = fx.create(seq as u64 + 1, name, None);
        request.request_id = format!("req-{name}").into_bytes();
        assert!(fx.ask(request).await.ok);
    }
    fx.repo().set_namespace_ready(&fx.root, true).unwrap();
    let permissions = |page: yadorilink_ipc_proto::shellipc::EnumerateChildrenResponse| {
        assert!(page.ok, "{}", page.error);
        page.items.into_iter().map(|i| (i.name, i.eviction_allowed)).collect::<Vec<_>>()
    };
    let pins = fx.state.replica_coordinator.retention_rules();
    assert_eq!(
        permissions(ask_children(&fx, &[], &[], 10).await),
        [("free".to_string(), true), ("kept".to_string(), true)]
    );
    pins.pin("group-1", "kept").unwrap();
    assert_eq!(
        permissions(ask_children(&fx, &[], &[], 10).await),
        [("free".to_string(), true), ("kept".to_string(), false)]
    );
    pins.unpin("group-1", "kept").unwrap();
    assert!(permissions(ask_children(&fx, &[], &[], 10).await).iter().all(|(_, ok)| *ok));
}

/// The wire item reports what the engine holds of it (not what the OS holds): bytes here, bytes
/// not here, a fetch in progress, and nothing for a row the engine has no state for.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_wire_item_carries_the_engines_local_state() {
    use yadorilink_ipc_proto::shellipc::LocalTransition;
    let mut fx = Fx::new().await;
    let names = ["away", "busy", "here"];
    for (seq, name) in names.into_iter().enumerate() {
        let mut request = fx.create(seq as u64 + 1, name, None);
        request.request_id = format!("req-{name}").into_bytes();
        assert!(fx.ask(request).await.ok);
    }
    fx.repo().set_namespace_ready(&fx.root, true).unwrap();
    for (name, state) in [("away", "remote"), ("busy", "hydrating"), ("here", "present")] {
        fx.state
            .replica_coordinator
            .database()
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                tx.execute(
                    "UPDATE files SET materialization_state = ?3 \
                     WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
                    rusqlite::params!["group-1", name, state],
                )?;
                Ok(())
            })
            .unwrap();
    }
    let page = ask_children(&fx, &[], &[], 10).await;
    assert!(page.ok, "{}", page.error);
    let states: std::collections::BTreeMap<_, _> =
        page.items.into_iter().map(|i| (i.name, i.local_state)).collect();
    let away = states["away"].expect("a row with a state is reported");
    assert!(!away.local_object_present && !away.current_content_present);
    assert_eq!(away.transition(), LocalTransition::None);
    let busy = states["busy"].expect("hydrating is reported");
    assert!(!busy.current_content_present);
    assert_eq!(busy.transition(), LocalTransition::Hydrating);
    let here = states["here"].expect("present is reported");
    assert!(here.local_object_present && here.current_content_present);
    assert_eq!(here.transition(), LocalTransition::None);
}

/// Pinning or unpinning is not just retention state: the OS already holds the item with its old
/// permission, so the engine republishes it (a new served token) and owes the OS a signal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pin_or_unpin_republishes_the_item_to_the_os() {
    use crate::adapters::runtime::materialization::DaemonMaterializationAdapter;
    use crate::application::ports::MaterializationPort;
    let mut fx = Fx::new().await;
    for (seq, name) in ["free", "kept"].into_iter().enumerate() {
        let mut request = fx.create(seq as u64 + 1, name, None);
        request.request_id = format!("req-{name}").into_bytes();
        assert!(fx.ask(request).await.ok);
    }
    fx.repo().set_namespace_ready(&fx.root, true).unwrap();
    let served = |page: yadorilink_ipc_proto::shellipc::EnumerateChildrenResponse| {
        page.items
            .into_iter()
            .map(|i| (i.name, (i.metadata_version, i.eviction_allowed)))
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let before = served(ask_children(&fx, &[], &[], 10).await);
    let owed = |fx: &Fx| fx.repo().unannounced_changes(&fx.root).unwrap();
    if let Some(changes) = owed(&fx) {
        fx.repo().mark_announced(&fx.root, changes).unwrap();
    }
    let adapter = DaemonMaterializationAdapter::new(fx.state.clone());

    adapter.set_rule("group-1", "kept", crate::application::ports::RuleChoice::Keep).await.unwrap();
    let pinned = served(ask_children(&fx, &[], &[], 10).await);
    assert_ne!(pinned["kept"].0, before["kept"].0, "the OS was not given a new token for the pin");
    assert!(!pinned["kept"].1 && pinned["free"].1);
    assert_eq!(pinned["free"].0, before["free"].0, "an unrelated item was republished");
    assert!(owed(&fx).is_some(), "the OS is owed a signal for the pin");
    if let Some(changes) = owed(&fx) {
        fx.repo().mark_announced(&fx.root, changes).unwrap();
    }

    adapter
        .set_rule("group-1", "kept", crate::application::ports::RuleChoice::Default)
        .await
        .unwrap();
    let unpinned = served(ask_children(&fx, &[], &[], 10).await);
    assert_ne!(
        unpinned["kept"].0, pinned["kept"].0,
        "the OS was not given a new token for the unpin"
    );
    assert!(unpinned["kept"].1);
    assert!(owed(&fx).is_some(), "the OS is owed a signal for the unpin");
}

/// Until the namespace is verified queryable the answer is NOT_READY, never an empty folder; once
/// it is, a never-opened folder lists its children page by page with a cursor tied to the folder.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enumeration_waits_for_readiness_then_pages_by_cursor() {
    use yadorilink_ipc_proto::shellipc::EnumerateFailure;
    let mut fx = Fx::new().await;
    for (seq, name) in ["a", "b", "c"].into_iter().enumerate() {
        let mut request = fx.create(seq as u64 + 1, name, None);
        request.request_id = format!("req-{name}").into_bytes();
        assert!(fx.ask(request).await.ok);
    }
    // The state an install leaves for the OS: rows projected, nothing exposed.
    fx.state
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            tx.execute("DELETE FROM provider_items", [])?;
            tx.execute("DELETE FROM provider_change_events", [])?;
            tx.execute("UPDATE provider_roots SET namespace_ready = 0", [])?;
            Ok(())
        })
        .unwrap();

    let early = ask_children(&fx, &[], &[], 10).await;
    assert!(!early.ok);
    assert_eq!(enumerate_failure(early.failure), EnumerateFailure::NotReady);
    assert!(early.items.is_empty());

    fx.repo().set_namespace_ready(&fx.root, true).unwrap();
    let first = ask_children(&fx, &[], &[], 2).await;
    assert!(first.ok, "{first:?}");
    assert_eq!(first.items.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["a", "b"]);
    assert!(!first.next_page_token.is_empty());
    let second = ask_children(&fx, &[], &first.next_page_token, 2).await;
    assert_eq!(second.items.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(), ["c"]);
    assert!(second.next_page_token.is_empty());
    assert_eq!(second.anchor, first.anchor, "every page repeats the first page's anchor");

    // A cursor of another folder is refused, not misread.
    let foreign = ask_children(&fx, &first.items[0].item_id, &first.next_page_token, 2).await;
    assert_eq!(enumerate_failure(foreign.failure), EnumerateFailure::TokenInvalid);

    // item(for:) serves one item in the shown view; a connection with no handshake gets nothing.
    use yadorilink_ipc_proto::shellipc::ProviderItemRequest;
    let lookup = ShellIpcMessage {
        payload: Some(Payload::ProviderItemRequest(ProviderItemRequest {
            root_id: fx.root_id.clone(),
            item_id: first.items[0].item_id.clone(),
        })),
    };
    let found = super::super::provider_enumerate::answer(&fx.context, &fx.handshakes, &lookup)
        .await
        .and_then(|m| m.payload);
    let Some(Payload::ProviderItemResponse(found)) = found else { panic!("no lookup answer") };
    assert!(found.ok);
    assert_eq!(found.item.unwrap().name, "a");
    let stray = Arc::new(Handshakes::default());
    let denied = super::super::provider_enumerate::answer(&fx.context, &stray, &lookup)
        .await
        .and_then(|m| m.payload);
    let Some(Payload::ProviderItemResponse(denied)) = denied else { panic!("no answer") };
    assert_eq!(enumerate_failure(denied.failure), EnumerateFailure::NotReady);
}

async fn through(fx: &Fx, payload: Payload) -> Payload {
    super::super::provider_enumerate::answer(
        &fx.context,
        &fx.handshakes,
        &ShellIpcMessage { payload: Some(payload) },
    )
    .await
    .and_then(|m| m.payload)
    .expect("an answer")
}

/// The change feed and the working-set walk over the connection: a peer's create after the
/// listing arrives through the working-set scope; an anchor outside the range is ANCHOR_EXPIRED;
/// the walk pages by a cursor bound to the root and its last page repeats the first page's anchor.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changes_and_the_working_set_walk_over_the_connection() {
    use yadorilink_ipc_proto::shellipc::{
        ChangeScope, EnumerateChangesRequest, EnumerateFailure, EnumerateWorkingSetRequest,
    };
    let mut fx = Fx::new().await;
    for (seq, name) in ["a", "b", "c"].into_iter().enumerate() {
        let mut request = fx.create(seq as u64 + 1, name, None);
        request.request_id = format!("req-{name}").into_bytes();
        assert!(fx.ask(request).await.ok);
    }
    fx.state
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
            tx.execute("DELETE FROM provider_items", [])?;
            tx.execute("DELETE FROM provider_change_events", [])?;
            tx.execute("DELETE FROM provider_enumerated_parents", [])?;
            tx.execute("UPDATE provider_roots SET namespace_revision = 0", [])?;
            Ok(())
        })
        .unwrap();
    fx.repo().set_namespace_ready(&fx.root, true).unwrap();
    let listing = ask_children(&fx, &[], &[], 10).await;
    assert!(listing.ok);

    // `a` is deleted (through the write path here; a peer's delete arrives the same way): the
    // working-set scope is told it is gone.
    let a_item = listing.items.iter().find(|i| i.name == "a").unwrap();
    let a_id = a_item.item_id.clone();
    let delete = ProviderApplyChangeRequest {
        base_version_hash: a_item.content_version.clone(),
        request_id: b"delete-a".to_vec(),
        session_id: vec![1; 16],
        operation_seq: 10,
        root_id: fx.root_id.clone(),
        kind: ProviderChangeKind::Delete as i32,
        item_id: a_id.clone(),
        ..Default::default()
    };
    assert!(fx.ask(delete).await.ok);
    let Payload::EnumerateChangesResponse(changed) = through(
        &fx,
        Payload::EnumerateChangesRequest(EnumerateChangesRequest {
            root_id: fx.root_id.clone(),
            scope: ChangeScope::WorkingSet as i32,
            parent_item_id: Vec::new(),
            since_anchor: listing.anchor,
            limit: 0,
        }),
    )
    .await
    else {
        panic!("not a changes response")
    };
    assert!(changed.ok, "{changed:?}");
    assert_eq!(changed.removed_item_ids, [a_id]);
    assert!(changed.upserts.is_empty() && !changed.more);

    // An anchor from the future (a restored database on the OS's side) is expired.
    let Payload::EnumerateChangesResponse(expired) = through(
        &fx,
        Payload::EnumerateChangesRequest(EnumerateChangesRequest {
            root_id: fx.root_id.clone(),
            scope: ChangeScope::WorkingSet as i32,
            parent_item_id: Vec::new(),
            since_anchor: changed.next_anchor + 100,
            limit: 0,
        }),
    )
    .await
    else {
        panic!("not a changes response")
    };
    assert_eq!(enumerate_failure(expired.failure), EnumerateFailure::AnchorExpired);
    assert!(!expired.ok && expired.upserts.is_empty() && expired.removed_item_ids.is_empty());

    // An anchor the retention sweep passed is expired too: the OS enumerates in full instead of
    // being handed a partial list. The newest anchor still answers.
    fx.repo().prune_change_events(&fx.root, 0, i64::MAX).unwrap();
    for (since, expect_ok) in [(listing.anchor, false), (changed.next_anchor, true)] {
        let Payload::EnumerateChangesResponse(answer) = through(
            &fx,
            Payload::EnumerateChangesRequest(EnumerateChangesRequest {
                root_id: fx.root_id.clone(),
                scope: ChangeScope::WorkingSet as i32,
                parent_item_id: Vec::new(),
                since_anchor: since,
                limit: 0,
            }),
        )
        .await
        else {
            panic!("not a changes response")
        };
        assert_eq!(answer.ok, expect_ok, "{answer:?}");
        if !expect_ok {
            assert_eq!(enumerate_failure(answer.failure), EnumerateFailure::AnchorExpired);
            assert!(answer.upserts.is_empty() && answer.removed_item_ids.is_empty());
        }
    }

    // The walk: pages by cursor, every page repeats the first page's anchor.
    let mut names = Vec::new();
    let mut token = Vec::new();
    let mut first_anchor = None;
    loop {
        let Payload::EnumerateWorkingSetResponse(page) = through(
            &fx,
            Payload::EnumerateWorkingSetRequest(EnumerateWorkingSetRequest {
                root_id: fx.root_id.clone(),
                page_token: token.clone(),
                limit: 2,
            }),
        )
        .await
        else {
            panic!("not a working-set response")
        };
        assert!(page.ok, "{page:?}");
        assert_eq!(*first_anchor.get_or_insert(page.anchor), page.anchor);
        names.extend(page.items.iter().map(|i| i.name.clone()));
        if page.next_page_token.is_empty() {
            break;
        }
        token = page.next_page_token;
    }
    names.sort();
    assert_eq!(names, ["b", "c"]);
}

// ---- generations over the connection ----

fn generation_of(version: &[u8]) -> u64 {
    assert_eq!(version.len(), 40, "an item version is the hash and the generation");
    u64::from_be_bytes(version[32..].try_into().unwrap())
}

/// The item versions the OS holds carry the generation; an edit that names none is a STALE_VIEW
/// and authors nothing; one that names the current generation is applied; the same operation
/// identity with another view is a different operation (OPERATION_MISMATCH).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_edit_names_the_generation_it_saw_and_the_view_is_part_of_the_operation() {
    let mut fx = Fx::new().await;
    let source = fx.put_ingest("copy-1", b"first");
    let created = fx.ask(fx.create(1, "doc.txt", Some(source))).await;
    let item = created.item.unwrap();
    let generation = generation_of(&item.content_version);
    assert_eq!(generation_of(&item.metadata_version), generation);

    let edit = |fx: &Fx, seq: u64, bytes: &[u8], base_generation: Option<u64>| {
        let source = fx.put_ingest(&format!("edit-{seq}"), bytes);
        ProviderApplyChangeRequest {
            request_id: format!("edit-{seq}-{base_generation:?}").into_bytes(),
            session_id: vec![1; 16],
            operation_seq: seq,
            root_id: fx.root_id.clone(),
            kind: ProviderChangeKind::Modify as i32,
            item_id: item.item_id.clone(),
            // The identifier the daemon sent, with the generation the OS claims to have seen;
            // none at all is an absent base.
            base_version_hash: base_generation.map_or_else(Vec::new, |g| {
                let mut id = item.content_version[..32].to_vec();
                id.extend_from_slice(&g.to_be_bytes());
                id
            }),
            content: Some(source),
            ..Default::default()
        }
    };
    let unknown = fx.ask(edit(&fx, 2, b"unknown view", None)).await;
    // An edit on an unknown or old view is never refused with its bytes dropped: canonical stays
    // and the bytes become a conflict copy beside it.
    assert!(unknown.ok, "{unknown:?}");
    assert_eq!(unknown.outcome, ProviderApplyOutcome::Concurrent as i32);
    let stale = fx.ask(edit(&fx, 3, b"old view", Some(generation + 7))).await;
    assert!(stale.ok, "{stale:?}");
    assert_eq!(stale.outcome, ProviderApplyOutcome::Concurrent as i32);
    let children = fx.repo().list_children(&fx.root, "").unwrap();
    assert_eq!(children.len(), 3, "doc.txt and the two conflict copies");

    let applied = fx.ask(edit(&fx, 4, b"current view", Some(generation))).await;
    assert!(applied.ok, "{applied:?}");
    let new_generation = generation_of(&applied.item.unwrap().content_version);
    assert!(new_generation > generation, "an edit did not advance the item generation");

    // The same identity (session, operation) with a different view is another operation.
    let mut same_identity = edit(&fx, 4, b"current view", Some(generation + 1));
    same_identity.request_id = b"retry-other-view".to_vec();
    assert_eq!(
        failure(&fx.ask(same_identity).await),
        ProviderApplyFailure::OperationMismatch,
        "a retry with a different view replayed"
    );
}

/// The base is exactly the 40-byte identifier the daemon emitted: any other length is INVALID_BASE,
/// and a separately named generation must agree with the one inside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_base_is_exactly_the_emitted_version_identifier() {
    let mut fx = Fx::new().await;
    let source = fx.put_ingest("copy-1", b"first");
    let created = fx.ask(fx.create(1, "doc.txt", Some(source))).await;
    let item = created.item.unwrap();
    let mut seq = 1;
    let mut edit = |fx: &Fx, base: Vec<u8>, named: Option<u64>| {
        seq += 1;
        let source = fx.put_ingest(&format!("e-{seq}"), b"second");
        ProviderApplyChangeRequest {
            request_id: format!("e-{seq}").into_bytes(),
            session_id: vec![1; 16],
            operation_seq: seq,
            root_id: fx.root_id.clone(),
            kind: ProviderChangeKind::Modify as i32,
            item_id: item.item_id.clone(),
            base_version_hash: base,
            base_generation: named,
            content: Some(source),
            ..Default::default()
        }
    };
    for bad in [vec![7u8; 1], item.content_version[..32].to_vec(), vec![7u8; 41]] {
        let response = fx.ask(edit(&fx, bad, None)).await;
        assert_eq!(failure(&response), ProviderApplyFailure::InvalidBase, "{response:?}");
    }
    let generation = generation_of(&item.content_version);
    let disagree = fx.ask(edit(&fx, item.content_version.clone(), Some(generation + 1))).await;
    assert_eq!(failure(&disagree), ProviderApplyFailure::InvalidBase);
    let agree = fx.ask(edit(&fx, item.content_version.clone(), Some(generation))).await;
    assert!(agree.ok, "{agree:?}");
}

/// An edit based on the token the daemon issued is applied and answers the next token; the next
/// edit names that one. A LATE callback that still names the old token is a stale view and the
/// canonical version stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_applied_edit_hands_back_the_token_the_next_one_must_echo() {
    let mut fx = Fx::new().await;
    let source = fx.put_ingest("copy-1", b"A");
    let created = fx.ask(fx.create(1, "doc.txt", Some(source))).await;
    let token_a = created.item.unwrap();
    let edit = |fx: &Fx, seq: u64, bytes: &[u8], base: &[u8]| {
        let source = fx.put_ingest(&format!("edit-{seq}"), bytes);
        ProviderApplyChangeRequest {
            request_id: format!("edit-{seq}").into_bytes(),
            session_id: vec![1; 16],
            operation_seq: seq,
            root_id: fx.root_id.clone(),
            kind: ProviderChangeKind::Modify as i32,
            item_id: token_a.item_id.clone(),
            base_version_hash: base.to_vec(),
            content: Some(source),
            ..Default::default()
        }
    };
    // A@g -> B@(g+1).
    let b = fx.ask(edit(&fx, 2, b"B", &token_a.content_version)).await;
    assert!(b.ok, "{b:?}");
    let token_b = b.item.unwrap().content_version;
    assert_eq!(generation_of(&token_b), generation_of(&token_a.content_version) + 1);
    // A late callback naming A@g: stale, nothing authored.
    let late = fx.ask(edit(&fx, 3, b"late A", &token_a.content_version)).await;
    assert!(late.ok, "{late:?}");
    assert_eq!(late.outcome, ProviderApplyOutcome::Concurrent as i32);
    assert_eq!(
        fx.repo().list_children(&fx.root, "").unwrap().len(),
        2,
        "the late bytes are a conflict copy"
    );
    // B@(g+1) -> C@(g+2).
    let c = fx.ask(edit(&fx, 4, b"C", &token_b)).await;
    assert!(c.ok, "{c:?}");
    assert_eq!(generation_of(&c.item.unwrap().content_version), generation_of(&token_b) + 1);
}

/// A lost response to a stale edit, replayed: the answer keeps the stored CONFLICT outcome
/// (marked as a replay), so the extension refetches the canonical content instead of leaving stale
/// local bytes under the canonical token; no second copy is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replayed_conflict_keeps_its_conflict_outcome() {
    let mut fx = Fx::new().await;
    let source = fx.put_ingest("copy-1", b"A");
    let created = fx.ask(fx.create(1, "doc.txt", Some(source))).await;
    let token_a = created.item.unwrap();
    let edit = |fx: &Fx, request: &[u8], staged: &str| {
        let source = fx.put_ingest(staged, b"stale bytes");
        ProviderApplyChangeRequest {
            request_id: request.to_vec(),
            session_id: vec![1; 16],
            operation_seq: 9,
            root_id: fx.root_id.clone(),
            kind: ProviderChangeKind::Modify as i32,
            item_id: token_a.item_id.clone(),
            base_version_hash: vec![0u8; 40],
            content: Some(source),
            ..Default::default()
        }
    };
    let first = fx.ask(edit(&fx, b"first", "e-1")).await;
    assert_eq!(first.outcome, ProviderApplyOutcome::Concurrent as i32, "{first:?}");
    let before = fx.repo().list_children(&fx.root, "").unwrap().len();
    // The response was lost: the OS retries the same operation (a new attempt, restaged bytes).
    let replay = fx.ask(edit(&fx, b"second", "e-2")).await;
    assert!(replay.ok && replay.replayed, "{replay:?}");
    assert_eq!(replay.outcome, ProviderApplyOutcome::Concurrent as i32, "the conflict was lost");
    assert_eq!(fx.repo().list_children(&fx.root, "").unwrap().len(), before, "a second copy");
}

/// A retry of an undecided operation whose own upload is gone reuses the upload journaled for
/// the operation, and the journal is cleared when the operation is decided.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retry_reuses_the_journaled_upload() {
    let mut fx = Fx::new().await;
    let kept = fx.put_ingest("journaled-copy", b"journaled bytes");
    fx.repo().journal_pending_ingest(&fx.root, &[1; 16], 1, "journaled-copy", 1).unwrap();
    // The retry names an upload that no longer exists but carries the same bytes' digest.
    let gone = ProviderContentSource { ingest_name: "restaged-copy".into(), ..kept };
    let response = fx.ask(fx.create(1, "a.txt", Some(gone))).await;
    assert!(response.ok, "{response:?}");
    assert_eq!(fx.repo().pending_ingest_name(&fx.root, &[1; 16], 1).unwrap(), None);
    assert!(!fx.ingest_dir().join("journaled-copy").exists(), "a spent upload was left behind");
}

/// (Y1) The upload is journaled BEFORE any refusal: a request refused for its base still has its
/// upload journaled and on disk; the age sweep never removes it, even after a restart and a month;
/// retries of the undecided operation accumulate no staged files (N refused retries, one retained).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_upload_stays_journaled_and_retries_keep_one_copy() {
    let mut fx = Fx::new().await;
    let first = fx.put_ingest("retry-0", b"user bytes");
    let refused = |fx: &Fx, source: ProviderContentSource, id: &str| {
        let mut request = fx.create(7, "a.txt", Some(source));
        request.request_id = id.as_bytes().to_vec();
        // A malformed base: refused before anything is ingested.
        request.kind = ProviderChangeKind::Modify as i32;
        request.item_id = vec![1; 16];
        request.base_version_hash = vec![9; 7];
        request
    };
    let response = fx.ask(refused(&fx, first.clone(), "r0")).await;
    assert_eq!(failure(&response), ProviderApplyFailure::InvalidBase, "{response:?}");
    assert_eq!(
        fx.repo().pending_ingest_name(&fx.root, &[1; 16], 7).unwrap(),
        Some("retry-0".to_owned()),
        "a refused upload was not journaled"
    );
    for n in 1..6 {
        let source = fx.put_ingest(&format!("retry-{n}"), b"user bytes");
        let response = fx.ask(refused(&fx, source, &format!("r{n}"))).await;
        assert_eq!(failure(&response), ProviderApplyFailure::InvalidBase);
    }
    let files: Vec<_> = std::fs::read_dir(fx.ingest_dir()).unwrap().flatten().collect();
    assert_eq!(files.len(), 1, "retries accumulated staged files: {files:?}");
    assert_eq!(fx.repo().undecided_uploads(i64::MAX / 2).unwrap().0, 1);

    // A restart and a month later: the journaled upload is still there.
    let names = fx.repo().pending_ingest_names().unwrap();
    let handoff =
        crate::provider_handoff::HandoffRoot::open(fx.ingest_dir().parent().unwrap()).unwrap();
    handoff.sweep_ingest_at(
        Some(&names),
        std::time::SystemTime::now() + std::time::Duration::from_secs(30 * 24 * 3600),
    );
    assert!(fx.ingest_dir().join("retry-0").exists(), "a journaled upload was aged out");
}

/// (AA1) A journaled upload is replaced by the retry's copy only when the journaled one fails its
/// declared digest and the fresh one passes; a copy is never discarded unverified.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bad_journaled_upload_is_replaced_by_a_verified_retry_copy() {
    for damage in ["same size, other bytes", "truncated", "missing"] {
        let mut fx = Fx::new().await;
        let valid = b"the user's valid bytes";
        let fresh = fx.put_ingest("fresh", valid);
        match damage {
            "same size, other bytes" => {
                std::fs::write(fx.ingest_dir().join("old"), vec![b'x'; valid.len()]).unwrap()
            }
            "truncated" => std::fs::write(fx.ingest_dir().join("old"), &valid[..5]).unwrap(),
            _ => {}
        }
        fx.repo().journal_pending_ingest(&fx.root, &[1; 16], 1, "old", 1).unwrap();
        let response = fx.ask(fx.create(1, "a.txt", Some(fresh))).await;
        assert!(response.ok, "{damage}: {response:?}");
        assert_eq!(fx.repo().pending_ingest_name(&fx.root, &[1; 16], 1).unwrap(), None);
        assert!(!fx.ingest_dir().join("old").exists(), "{damage}: the bad copy was left");
    }
}

/// (AA1) The journaled copy verifies: the retry's copy is redundant and removed, and the journaled
/// bytes are the ones used. When NEITHER verifies both are kept, the journal keeps the first, and the
/// retry is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_verified_journaled_upload_makes_the_retry_redundant_and_two_bad_copies_are_both_kept() {
    let mut fx = Fx::new().await;
    let valid = b"valid bytes of the operation";
    // The journaled copy is good; the retry's copy is garbage of the declared size.
    let declared = fx.put_ingest("old", valid);
    fx.repo().journal_pending_ingest(&fx.root, &[1; 16], 1, "old", 1).unwrap();
    std::fs::write(fx.ingest_dir().join("fresh"), vec![b'z'; valid.len()]).unwrap();
    let retry = ProviderContentSource { ingest_name: "fresh".into(), ..declared.clone() };
    let response = fx.ask(fx.create(1, "a.txt", Some(retry))).await;
    assert!(response.ok, "{response:?}");

    // Neither copy verifies.
    let mut fx = Fx::new().await;
    let declared = fx.put_ingest("old", valid);
    std::fs::write(fx.ingest_dir().join("old"), vec![b'y'; valid.len()]).unwrap();
    fx.repo().journal_pending_ingest(&fx.root, &[1; 16], 1, "old", 1).unwrap();
    std::fs::write(fx.ingest_dir().join("fresh"), vec![b'z'; valid.len()]).unwrap();
    let retry = ProviderContentSource { ingest_name: "fresh".into(), ..declared };
    let response = fx.ask(fx.create(1, "a.txt", Some(retry))).await;
    assert!(!response.ok);
    assert!(fx.ingest_dir().join("old").exists() && fx.ingest_dir().join("fresh").exists());
    assert_eq!(
        fx.repo().pending_ingest_name(&fx.root, &[1; 16], 1).unwrap(),
        Some("old".to_owned())
    );
}

/// (Z1, combined) A rebootstrap between the first refused transaction and the second, then a sweep a
/// month later: the upload file and its journal row both survive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rebootstrap_then_a_late_sweep_keeps_the_upload_and_its_row() {
    let fx = Fx::new().await;
    fx.put_ingest("undecided", b"bytes awaiting a decision");
    fx.repo().journal_pending_ingest(&fx.root, &[1; 16], 3, "undecided", 1).unwrap();
    fx.repo().rebootstrap_root(GROUP_ID).unwrap();
    let names = fx.repo().pending_ingest_names().unwrap();
    assert!(names.contains("undecided"), "the journal row died with the root");
    let handoff =
        crate::provider_handoff::HandoffRoot::open(fx.ingest_dir().parent().unwrap()).unwrap();
    handoff.sweep_ingest_at(
        Some(&names),
        std::time::SystemTime::now() + std::time::Duration::from_secs(30 * 24 * 3600),
    );
    assert!(fx.ingest_dir().join("undecided").exists(), "the upload was swept");
}

/// The writer check sits AT the commit point: a device granted when the request arrived but
/// demoted to a Viewer before it commits is refused there, and nothing is authored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_viewer_demoted_before_the_commit_point_is_refused_there() {
    use crate::test_support::sync_stack_fixture::fixture_group_policy_granting;
    let mut fx = Fx::new().await;
    let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key();
    let mine = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
    let state = fx.state.clone();
    state.authority.replace_group_policy_states(std::collections::HashMap::from([(
        "group-1".to_string(),
        fixture_group_policy_granting(&[("device-a", mine)]),
    )]));
    let mut request = fx.create(1, "a.txt", None);
    request.request_id = b"demoted".to_vec();
    {
        let state = state.clone();
        set_point(
            "before_commit_point",
            &request.request_id.clone(),
            Arc::new(move || {
                state.authority.replace_group_policy_states(std::collections::HashMap::from([(
                    "group-1".to_string(),
                    fixture_group_policy_granting(&[("someone-else", other)]),
                )]));
            }),
        );
    }
    fx.send(request);
    let response = fx.response().await;
    assert_eq!(failure(&response), ProviderApplyFailure::NotAuthorized, "{response:?}");
    assert_eq!(
        fx.repo().list_children(&fx.root, "").unwrap().len(),
        0,
        "a demoted device authored"
    );
}

// ---- the embedding app's own path ------------------------------------------------------------

impl Fx {
    async fn app(&self, request: ProviderApplyChangeRequest) -> ProviderApplyChangeResponse {
        apply_for_app(&self.context, &request).await
    }

    fn modify(&self, seq: u64, item: &ProviderAppliedItem) -> ProviderApplyChangeRequest {
        ProviderApplyChangeRequest {
            request_id: format!("app-{seq}").into_bytes(),
            session_id: vec![2; 16],
            operation_seq: seq,
            root_id: self.root_id.clone(),
            kind: ProviderChangeKind::Modify as i32,
            item_id: item.item_id.clone(),
            base_version_hash: item.content_version.clone(),
            base_generation: Some(generation_of(&item.content_version)),
            parent_generation: Some(item.parent_generation),
            ..Default::default()
        }
    }
}

/// No socket, no handshake, no attached host, no registered domain: the owner of the engine writes
/// a file, a folder, a new version, a rename and move, and a delete, every one durable and visible
/// to the same readers the extension uses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_app_creates_modifies_renames_moves_and_deletes_without_any_os_evidence() {
    let fx = Fx::app_only().await;
    assert!(!fx.context.provider_host.host_connected());
    assert_eq!(
        declared_root(&fx).readiness(),
        Readiness::NotReady(
            yadorilink_replica_domain::session_state::NotReady::DomainNotRegistered
        ),
        "the setup must have no OS evidence at all"
    );

    // A folder, then a file in it.
    let mut folder = fx.create(1, "Trip", None);
    folder.entry_kind = WireEntryKind::Directory as i32;
    folder.session_id = vec![2; 16];
    let folder = fx.app(folder).await;
    assert!(folder.ok, "{folder:?}");
    let folder = folder.item.unwrap();
    assert_eq!(folder.entry_kind, WireEntryKind::Directory as i32);

    let source = fx.put_ingest("up-1", b"photo bytes");
    let mut create = fx.create(2, "p.jpg", Some(source));
    create.session_id = vec![2; 16];
    create.parent_item_id = Some(folder.item_id.clone());
    let created = fx.app(create).await;
    assert!(created.ok, "{created:?}");
    assert_eq!(created.outcome, ProviderApplyOutcome::Applied as i32);
    let file = created.item.unwrap();
    assert_eq!((file.name.as_str(), file.size), ("p.jpg", 11));
    assert!(!fx.ingest_dir().join("up-1").exists(), "the spent copy is removed once committed");
    assert_eq!(fx.context.writer.follow_ups(), 2, "committed changes are published to peers");

    // A new version of the same file.
    let source = fx.put_ingest("up-2", b"retouched");
    let mut edit = fx.modify(3, &file);
    edit.content = Some(source);
    let edited = fx.app(edit).await;
    assert!(edited.ok, "{edited:?}");
    let file = edited.item.unwrap();
    assert_eq!(file.size, 9);

    // Rename and move to the root in one request.
    let mut rename = fx.modify(4, &file);
    rename.name = Some("cover.jpg".into());
    rename.parent_item_id = Some(Vec::new());
    let renamed = fx.app(rename).await;
    assert!(renamed.ok, "{renamed:?}");
    let file = renamed.item.unwrap();
    assert_eq!(file.name, "cover.jpg");
    assert!(file.parent_item_id.is_empty(), "moved to the root");
    let id = <[u8; 16]>::try_from(file.item_id.as_slice()).unwrap();
    assert_eq!(
        fx.repo().path_for_item(&fx.root, &id).unwrap().map(|(p, _)| p).as_deref(),
        Some("cover.jpg")
    );

    // Delete.
    let mut delete = fx.modify(5, &file);
    delete.kind = ProviderChangeKind::Delete as i32;
    let deleted = fx.app(delete).await;
    assert!(deleted.ok, "{deleted:?}");
    assert_eq!(fx.repo().path_for_item(&fx.root, &id).unwrap().map(|(_, live)| live), Some(false));
}

/// A lost response is answered with the stored outcome: nothing is read again (the staged copy is
/// gone) and nothing is authored twice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_app_retry_after_a_lost_response_returns_the_stored_outcome() {
    let fx = Fx::app_only().await;
    let source = fx.put_ingest("up-1", b"once only");
    let mut first = fx.create(1, "a.txt", Some(source.clone()));
    first.session_id = vec![2; 16];
    let first = fx.app(first.clone()).await;
    assert!(first.ok && !first.replayed, "{first:?}");
    let count = fx.repo().list_children(&fx.root, "").unwrap().len();

    let mut retry = fx.create(1, "a.txt", Some(source));
    retry.session_id = vec![2; 16];
    retry.request_id = b"retry".to_vec();
    let again = fx.app(retry).await;
    assert!(again.ok && again.replayed, "{again:?}");
    assert_eq!(again.item, first.item);
    assert_eq!(fx.repo().list_children(&fx.root, "").unwrap().len(), count);
}

/// Conflicts are the engine's decision, never the app's: a stale view of an item authored at the
/// same time keeps both versions, and a retired item answers KEEP_LOCAL with a name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_app_edit_on_a_stale_view_keeps_both_and_a_retired_item_names_a_copy() {
    let fx = Fx::app_only().await;
    let source = fx.put_ingest("up-1", b"v1");
    let mut create = fx.create(1, "doc.txt", Some(source));
    create.session_id = vec![2; 16];
    let doc = fx.app(create).await.item.unwrap();

    // Another edit lands first; the app's edit names the old version.
    let source = fx.put_ingest("up-2", b"v2 from elsewhere");
    let mut other = fx.modify(2, &doc);
    other.content = Some(source);
    assert!(fx.app(other).await.ok);
    let source = fx.put_ingest("up-3", b"v2 from the phone");
    let mut stale = fx.modify(3, &doc);
    stale.content = Some(source);
    let stale = fx.app(stale).await;
    assert!(stale.ok, "{stale:?}");
    assert_eq!(stale.outcome, ProviderApplyOutcome::Concurrent as i32);
    assert_eq!(fx.repo().list_children(&fx.root, "").unwrap().len(), 2, "both versions are kept");

    // A request that carries nothing but the version it saw, when that is no longer the current
    // version, authors nothing: STALE_VIEW, refresh and retry.
    let before = fx.repo().list_children(&fx.root, "").unwrap().len();
    let touch = fx.app(fx.modify(10, &doc)).await;
    assert_eq!(failure(&touch), ProviderApplyFailure::StaleView, "{touch:?}");
    assert_eq!(fx.repo().list_children(&fx.root, "").unwrap().len(), before);

    // A pure rename or move acts on the item's identity, not on a view: it applies, into a
    // folder named by its stable id.
    let mut dir = fx.create(11, "B", None);
    dir.entry_kind = WireEntryKind::Directory as i32;
    dir.session_id = vec![2; 16];
    let dir_b = fx.app(dir).await.item.unwrap();
    let mut mv = fx.modify(12, &doc);
    mv.parent_item_id = Some(dir_b.item_id.clone());
    mv.name = Some("moved.txt".into());
    let moved = fx.app(mv).await;
    assert!(moved.ok, "{moved:?}");
    let moved = moved.item.unwrap();
    assert_eq!((moved.name.as_str(), &moved.parent_item_id), ("moved.txt", &dir_b.item_id));

    // A retired item: the bytes are kept as a new item under a suggested name.
    let id = <[u8; 16]>::try_from(doc.item_id.as_slice()).unwrap();
    assert!(fx.repo().retire_item(&fx.root, &id).unwrap());
    let source = fx.put_ingest("up-4", b"after retirement");
    let mut late = fx.modify(5, &doc);
    late.content = Some(source);
    let late = fx.app(late).await;
    assert!(late.ok, "{late:?}");
    assert_eq!(late.outcome, ProviderApplyOutcome::Concurrent as i32);
}

/// A reader (or any device that is not a writer of the group) is refused with a typed refusal,
/// before the staged file is read; the staged file stays for the app to discard.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_app_write_by_a_reader_is_refused_not_authorized() {
    use crate::test_support::sync_stack_fixture::fixture_group_policy_granting;
    let fx = Fx::app_only().await;
    let other = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]).verifying_key();
    fx.state.authority.replace_group_policy_states(std::collections::HashMap::from([(
        "group-1".to_string(),
        fixture_group_policy_granting(&[("someone-else", other)]),
    )]));
    let source = fx.put_ingest("up-1", b"not allowed");
    let mut create = fx.create(1, "a.txt", Some(source));
    create.session_id = vec![2; 16];
    let response = fx.app(create).await;
    assert_eq!(failure(&response), ProviderApplyFailure::NotAuthorized, "{response:?}");
    assert_eq!(fx.repo().list_children(&fx.root, "").unwrap().len(), 0);
    assert!(fx.ingest_dir().join("up-1").exists());
}

/// A publish-only root takes new files and nothing else from this device: a modify (contents,
/// rename, move) and a delete are refused `PublishOnly` before anything is recorded, and clearing
/// the flag lets the same change through as a fresh operation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_publish_only_root_takes_creates_and_refuses_modify_and_delete() {
    let fx = Fx::app_only().await;
    let mut create = fx.create(1, "a.txt", Some(fx.put_ingest("up-1", b"first")));
    create.session_id = vec![2; 16];
    let item = fx.app(create).await.item.expect("created");

    assert!(fx.repo().set_publish_only(&fx.root, true).unwrap());
    let mut more = fx.create(2, "b.txt", Some(fx.put_ingest("up-2", b"second")));
    more.session_id = vec![2; 16];
    assert!(fx.app(more).await.ok, "a create is allowed");

    let mut rename = fx.modify(3, &item);
    rename.name = Some("renamed.txt".into());
    assert_eq!(failure(&fx.app(rename).await), ProviderApplyFailure::PublishOnly);
    let mut edit = fx.modify(4, &item);
    edit.content = Some(fx.put_ingest("up-3", b"changed"));
    assert_eq!(failure(&fx.app(edit).await), ProviderApplyFailure::PublishOnly);
    assert!(fx.ingest_dir().join("up-3").exists(), "the staged copy is kept");
    let mut delete = fx.modify(5, &item);
    delete.kind = ProviderChangeKind::Delete as i32;
    assert_eq!(failure(&fx.app(delete).await), ProviderApplyFailure::PublishOnly);
    assert_eq!(fx.repo().list_children(&fx.root, "").unwrap().len(), 2, "nothing changed");

    // The refusal recorded nothing, not even the journal row of the staged copy.
    assert_eq!(fx.repo().pending_ingest_name(&fx.root, &[2; 16], 4).unwrap(), None);

    // The same identity succeeds once the flag is cleared.
    assert!(fx.repo().set_publish_only(&fx.root, false).unwrap());
    let mut delete = fx.modify(5, &item);
    delete.kind = ProviderChangeKind::Delete as i32;
    let deleted = fx.app(delete).await;
    assert!(deleted.ok, "{deleted:?}");
}

/// A change that committed before the flag was set still answers with its stored outcome when it
/// is asked about again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replay_of_a_committed_change_survives_the_flag() {
    let fx = Fx::app_only().await;
    let mut create = fx.create(1, "a.txt", Some(fx.put_ingest("up-1", b"first")));
    create.session_id = vec![2; 16];
    let item = fx.app(create).await.item.expect("created");
    let mut delete = fx.modify(2, &item);
    delete.kind = ProviderChangeKind::Delete as i32;
    let done = fx.app(delete.clone()).await;
    assert!(done.ok, "{done:?}");

    assert!(fx.repo().set_publish_only(&fx.root, true).unwrap());
    let again = fx.app(delete).await;
    assert!(again.ok && again.replayed, "{again:?}");
}

/// A root that reported an error of its own is not written to, even by the app.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_app_write_to_a_root_with_an_error_is_not_ready() {
    let fx = Fx::app_only().await;
    fx.repo().record_provider_error(&fx.root, "domain invalid").unwrap();
    let mut create = fx.create(1, "a.txt", None);
    create.session_id = vec![2; 16];
    assert_eq!(failure(&fx.app(create).await), ProviderApplyFailure::NotReady);
    assert_eq!(fx.repo().list_children(&fx.root, "").unwrap().len(), 0);
}

/// A file too big for the volume is refused with LOW_DISK before it is read; the staged copy is
/// kept, so nothing is lost and the same operation succeeds once there is room.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_app_write_that_cannot_fit_is_refused_low_disk_before_reading() {
    let fx = Fx::app_only().await;
    fx.state.enable_disk_headroom_enforcement();
    let mut source = fx.put_ingest("up-1", b"small but declared huge");
    // Declared far beyond any volume: the check is on the declared size, before any read.
    source.size = u64::MAX / 4;
    let mut create = fx.create(1, "huge.bin", Some(source));
    create.session_id = vec![2; 16];
    let response = fx.app(create).await;
    assert_eq!(failure(&response), ProviderApplyFailure::LowDisk, "{response:?}");
    assert!(fx.ingest_dir().join("up-1").exists(), "the staged copy is kept");
    assert_eq!(fx.repo().list_children(&fx.root, "").unwrap().len(), 0);
}

// ---- restore: an earlier version, a deleted item ---------------------------------------------

impl Fx {
    /// The retained versions of `path`, newest first (what the history listing reads).
    fn versions(&self, path: &str) -> Vec<yadorilink_replica_domain::session_state::VersionRecord> {
        self.state.replica_coordinator.sqlite().dag_list_versions(GROUP_ID, path).unwrap()
    }

    /// A file `a.txt` with two versions, "first" then "second, longer". Returns the item the last
    /// write left.
    async fn file_with_two_versions(&self) -> ProviderAppliedItem {
        let mut create = self.create(1, "a.txt", Some(self.put_ingest("up-1", b"first")));
        create.session_id = vec![2; 16];
        let item = self.app(create).await.item.expect("created");
        let mut edit = self.modify(2, &item);
        edit.content = Some(self.put_ingest("up-2", b"second, longer"));
        self.app(edit).await.item.expect("edited")
    }

    fn restore_request(
        &self,
        mut request: ProviderApplyChangeRequest,
        path: &str,
        version_hash: &VersionHash,
    ) -> ProviderApplyChangeRequest {
        request.restore_from = Some(yadorilink_ipc_proto::shellipc::ProviderRestoreSource {
            path: path.into(),
            version_hash: version_hash.0.to_vec(),
        });
        request
    }
}

/// An earlier version comes back as one ordinary new write over the live item: the content is the
/// old one, the item and its place are unchanged, the old version stays in the history, and the
/// same operation asked again is a replay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restore_authors_an_earlier_version_as_a_new_write() {
    let fx = Fx::app_only().await;
    let file = fx.file_with_two_versions().await;
    assert_eq!(file.size, 14);
    let first = fx
        .versions("a.txt")
        .into_iter()
        .find(|v| v.state == yadorilink_replica_domain::session_state::VersionState::Superseded)
        .expect("the first version is retained");
    assert_eq!(first.size, 5);

    let restore = fx.restore_request(fx.modify(3, &file), "a.txt", &first.version_hash);
    let restored = fx.app(restore.clone()).await;
    assert!(restored.ok && !restored.replayed, "{restored:?}");
    let item = restored.item.clone().unwrap();
    assert_eq!((item.item_id.clone(), item.name.as_str(), item.size), (file.item_id, "a.txt", 5));
    assert!(item.current);
    let versions = fx.versions("a.txt");
    let current = versions
        .iter()
        .find(|v| v.state == yadorilink_replica_domain::session_state::VersionState::Current)
        .unwrap();
    assert_eq!((current.size, &current.blocks), (5, &first.blocks), "the old bytes are current");
    assert!(versions.iter().any(|v| v.size == 14), "the version that was replaced stays");
    assert_eq!(fx.repo().list_children(&fx.root, "").unwrap().len(), 1, "no copy was made");

    let mut again = restore;
    again.request_id = b"retry".to_vec();
    let replay = fx.app(again).await;
    assert!(replay.ok && replay.replayed, "{replay:?}");
    assert_eq!(replay.item, restored.item);
}

/// A deleted file comes back with a create under its name and parent; asked twice under another
/// identity it is the same file (the create adopts what is already there).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deleted_file_is_restored_by_a_create() {
    let fx = Fx::app_only().await;
    let file = fx.file_with_two_versions().await;
    let mut delete = fx.modify(3, &file);
    delete.kind = ProviderChangeKind::Delete as i32;
    assert!(fx.app(delete).await.ok);
    let trashed = fx
        .state
        .replica_coordinator
        .file_index_repository()
        .list_trashed(GROUP_ID)
        .unwrap()
        .into_iter()
        .find(|t| t.path == "a.txt")
        .expect("the deleted file is listed");
    let last = fx.versions("a.txt").into_iter().find(|v| v.version_seq == trashed.version_seq);
    let last = last.expect("the trashed version is retained");
    assert_eq!(last.size, 14, "the last content before the delete");

    let restore = fx.restore_request(fx.create(4, "a.txt", None), "a.txt", &last.version_hash);
    let mut restore = restore;
    restore.session_id = vec![2; 16];
    let restored = fx.app(restore).await;
    assert!(restored.ok, "{restored:?}");
    let item = restored.item.unwrap();
    assert_eq!((item.name.as_str(), item.size), ("a.txt", 14));
    assert!(item.current);
    assert!(
        fx.state
            .replica_coordinator
            .file_index_repository()
            .list_trashed(GROUP_ID)
            .unwrap()
            .iter()
            .all(|t| t.path != "a.txt"),
        "the file is not in the trash any more"
    );
}

/// A deleted folder comes back as a folder; the files that were in it are brought back after it,
/// each under the folder's new item.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deleted_folder_is_restored_before_what_was_in_it() {
    let fx = Fx::app_only().await;
    let mut folder = fx.create(1, "Trip", None);
    folder.entry_kind = WireEntryKind::Directory as i32;
    folder.session_id = vec![2; 16];
    let folder = fx.app(folder).await.item.unwrap();
    let mut file = fx.create(2, "p.jpg", Some(fx.put_ingest("up-1", b"photo")));
    file.session_id = vec![2; 16];
    file.parent_item_id = Some(folder.item_id.clone());
    assert!(fx.app(file).await.ok);
    // Delete the folder with what is in it.
    // A folder is deleted on its current token, which a file added below it moved.
    let folder_id = <[u8; 16]>::try_from(folder.item_id.as_slice()).unwrap();
    let (shown, _) = fx.repo().lookup_item(&fx.root, &folder_id).unwrap().expect("listed");
    let mut token = shown.content_version.0.to_vec();
    token.extend_from_slice(&shown.generation.to_be_bytes());
    let mut delete = fx.modify(3, &folder);
    delete.kind = ProviderChangeKind::Delete as i32;
    delete.recursive = true;
    delete.base_version_hash = token;
    delete.base_generation = Some(shown.generation);
    let deleted = fx.app(delete).await;
    assert!(deleted.ok, "{deleted:?}");
    let hash_of = |path: &str| {
        let trashed = fx
            .state
            .replica_coordinator
            .file_index_repository()
            .list_trashed(GROUP_ID)
            .unwrap()
            .into_iter()
            .find(|t| t.path == path)
            .unwrap_or_else(|| panic!("{path} is in the trash"));
        fx.versions(path).into_iter().find(|v| v.version_seq == trashed.version_seq).unwrap()
    };

    // The file first: its folder is gone, so it cannot come back yet and nothing is kept.
    let mut orphan = fx.restore_request(
        fx.create(4, "p.jpg", None),
        "Trip/p.jpg",
        &hash_of("Trip/p.jpg").version_hash,
    );
    orphan.session_id = vec![2; 16];
    orphan.parent_item_id = Some(folder.item_id.clone());
    let refused = fx.app(orphan).await;
    assert!(!refused.ok, "{refused:?}");

    let mut dir =
        fx.restore_request(fx.create(5, "Trip", None), "Trip", &hash_of("Trip").version_hash);
    dir.session_id = vec![2; 16];
    dir.entry_kind = WireEntryKind::Directory as i32;
    let dir = fx.app(dir).await;
    assert!(dir.ok, "{dir:?}");
    let dir = dir.item.unwrap();
    assert_eq!(dir.entry_kind, WireEntryKind::Directory as i32);

    let mut child = fx.restore_request(
        fx.create(6, "p.jpg", None),
        "Trip/p.jpg",
        &hash_of("Trip/p.jpg").version_hash,
    );
    child.session_id = vec![2; 16];
    child.parent_item_id = Some(dir.item_id.clone());
    let child = fx.app(child).await;
    assert!(child.ok, "{child:?}");
    assert_eq!(child.item.unwrap().size, 5);
}

/// A restore that cannot be done changes nothing and keeps nothing: an unknown version, a taken
/// name, bytes that no device holds, a request that also carries bytes, a symlink.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_restore_changes_nothing_and_keeps_no_copy() {
    let fx = Fx::app_only().await;
    let file = fx.file_with_two_versions().await;
    let first = fx
        .versions("a.txt")
        .into_iter()
        .find(|v| v.state == yadorilink_replica_domain::session_state::VersionState::Superseded)
        .unwrap();
    let children = || fx.repo().list_children(&fx.root, "").unwrap().len();

    // A version this device does not retain.
    let unknown = fx.restore_request(fx.modify(3, &file), "a.txt", &VersionHash([0xEE; 32]));
    let refused = fx.app(unknown).await;
    assert_eq!(failure(&refused), ProviderApplyFailure::VersionUnavailable, "{refused:?}");

    // A modify on a view that is not the current one: stale, nothing authored, no copy.
    let mut stale = fx.restore_request(fx.modify(30, &file), "a.txt", &first.version_hash);
    let mut token = vec![0xAB; 32];
    token.extend_from_slice(&generation_of(&file.content_version).to_be_bytes());
    stale.base_version_hash = token;
    let refused = fx.app(stale).await;
    assert_eq!(failure(&refused), ProviderApplyFailure::StaleView, "{refused:?}");
    assert_eq!(children(), 1, "a stale restore keeps no copy");

    // A create over a name that is taken by other content: a collision, and no conflict copy.
    let mut taken = fx.restore_request(fx.create(4, "a.txt", None), "a.txt", &first.version_hash);
    taken.session_id = vec![2; 16];
    let refused = fx.app(taken).await;
    assert_eq!(failure(&refused), ProviderApplyFailure::NameCollision, "{refused:?}");
    assert_eq!(children(), 1, "a refused restore keeps no conflict copy");

    // Bytes and a version together are not a request.
    let mut both = fx.restore_request(fx.modify(5, &file), "a.txt", &first.version_hash);
    both.content = Some(fx.put_ingest("up-3", b"x"));
    let refused = fx.app(both).await;
    assert_eq!(failure(&refused), ProviderApplyFailure::IngestRejected, "{refused:?}");

    // A modify must be for the live item at the path of the version.
    let elsewhere = fx.restore_request(fx.modify(6, &file), "other.txt", &first.version_hash);
    assert_eq!(failure(&fx.app(elsewhere).await), ProviderApplyFailure::NotFound);

    // The old bytes are gone from this device and no peer is connected.
    for block in &first.blocks {
        fx.state.block_store.delete(&hex::encode(&block.hash)).unwrap();
    }
    let lost = fx.restore_request(fx.modify(7, &file), "a.txt", &first.version_hash);
    let refused = fx.app(lost).await;
    assert_eq!(failure(&refused), ProviderApplyFailure::VersionUnavailable, "{refused:?}");
    let current = fx
        .versions("a.txt")
        .into_iter()
        .find(|v| v.state == yadorilink_replica_domain::session_state::VersionState::Current)
        .unwrap();
    assert_eq!(current.size, 14, "nothing was authored");
}

/// The File Provider extension never restores: the request is for the embedding app.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_extension_cannot_ask_for_a_restore() {
    let mut fx = Fx::new().await;
    let source = fx.put_ingest("copy-1", b"hello");
    let created = fx.ask(fx.create(1, "a.txt", Some(source))).await;
    let item = created.item.unwrap();
    let hash = fx.versions("a.txt")[0].version_hash;
    let mut request = fx.restore_request(fx.modify(2, &item), "a.txt", &hash);
    request.session_id = vec![1; 16];
    let response = fx.ask(request).await;
    assert_eq!(failure(&response), ProviderApplyFailure::NotFound, "{response:?}");
}

// ---- conflict copies of a provider folder -----------------------------------------------------

impl Fx {
    /// The daemon-side applier the resolution commits through, as the provider side installs it.
    fn install_applier(&self) {
        let context = self.context.clone();
        self.state.set_provider_applier(Arc::new(move |request| {
            let context = context.clone();
            Box::pin(async move { apply_for_app(&context, &request).await })
        }));
    }

    /// `a.txt` holding "mine" and a conflict copy of it holding "theirs". Returns the copy's path.
    async fn file_with_a_conflict_copy(&self) -> String {
        let mut create = self.create(1, "a.txt", Some(self.put_ingest("up-1", b"mine")));
        create.session_id = vec![2; 16];
        assert!(self.app(create).await.ok);
        let copy = yadorilink_replica_domain::conflict::conflict_copy_path(
            "a.txt",
            1_700_000_000_000_000_000,
            "dev-b",
            &[0xab; 32],
        );
        let mut create = self.create(2, &copy, Some(self.put_ingest("up-2", b"theirs")));
        create.session_id = vec![2; 16];
        assert!(self.app(create).await.ok);
        copy
    }

    fn current_size(&self, path: &str) -> Option<u64> {
        self.versions(path)
            .into_iter()
            .find(|v| v.state == yadorilink_replica_domain::session_state::VersionState::Current)
            .map(|v| v.size)
    }
}

/// Keep this writes the copy's content over the original as a new version: the original keeps its
/// item and its old version, and the copy is left as it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keep_this_restores_the_copy_over_the_original_in_a_provider_folder() {
    use crate::conflict_resolution::{resolve_conflict, ConflictChoice};
    let fx = Fx::app_only().await;
    fx.install_applier();
    let copy = fx.file_with_a_conflict_copy().await;
    let before = fx.repo().item_for_path(&fx.root, "a.txt").unwrap().unwrap();
    assert_eq!(fx.current_size("a.txt"), Some(4));

    let kept =
        resolve_conflict(&fx.state, GROUP_ID, &copy, ConflictChoice::KeepThis).await.unwrap();
    assert_eq!(kept, std::path::PathBuf::from("a.txt"));
    assert_eq!(fx.current_size("a.txt"), Some(6), "the copy's bytes are the original's now");
    assert!(fx.versions("a.txt").iter().any(|v| v.size == 4), "the replaced version stays");
    assert_eq!(fx.repo().item_for_path(&fx.root, "a.txt").unwrap(), Some(before));
    assert!(fx.repo().item_for_path(&fx.root, &copy).unwrap().is_some(), "the copy is untouched");
    // The OS does not hold the copy's bytes: the new version is left to be announced and fetched
    // (as a change from a peer is), not published as if the OS had written it.
    let pending: Vec<_> =
        fx.repo().pending_items(&fx.root).unwrap().into_iter().map(|p| p.item_id).collect();
    assert!(pending.contains(&before), "the original awaits its announcement to the OS");
}

/// Restoring an earlier version of an item itself stays published at once (the app's own write).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restore_of_the_items_own_version_is_still_published_at_once() {
    let fx = Fx::app_only().await;
    let file = fx.file_with_two_versions().await;
    let first = fx
        .versions("a.txt")
        .into_iter()
        .find(|v| v.state == yadorilink_replica_domain::session_state::VersionState::Superseded)
        .unwrap();
    let restore = fx.restore_request(fx.modify(3, &file), "a.txt", &first.version_hash);
    assert!(fx.app(restore).await.ok);
    let item = fx.repo().item_for_path(&fx.root, "a.txt").unwrap().unwrap();
    assert!(!fx.repo().pending_items(&fx.root).unwrap().iter().any(|p| p.item_id == item));
}

/// Keep both renames the copy to the first free "other version" name, the same names a plain
/// folder gives, and never onto a name that is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keep_both_renames_the_copy_to_the_first_free_other_version_name() {
    use crate::conflict_resolution::{resolve_conflict, ConflictChoice};
    let fx = Fx::app_only().await;
    fx.install_applier();
    let copy = fx.file_with_a_conflict_copy().await;
    let item = fx.repo().item_for_path(&fx.root, &copy).unwrap().unwrap();

    let kept =
        resolve_conflict(&fx.state, GROUP_ID, &copy, ConflictChoice::KeepBoth).await.unwrap();
    assert_eq!(kept, std::path::PathBuf::from("a (other version).txt"));
    assert_eq!(fx.repo().item_for_path(&fx.root, "a (other version).txt").unwrap(), Some(item));
    assert!(fx.repo().item_for_path(&fx.root, &copy).unwrap().is_none(), "the copy was renamed");
    assert_eq!(fx.current_size("a.txt"), Some(4), "the original is unchanged");

    // A second copy takes the next name.
    let second = yadorilink_replica_domain::conflict::conflict_copy_path(
        "a.txt",
        1_700_000_100_000_000_000,
        "dev-c",
        &[0xcd; 32],
    );
    let mut create = fx.create(3, &second, Some(fx.put_ingest("up-3", b"third")));
    create.session_id = vec![2; 16];
    assert!(fx.app(create).await.ok);
    let kept =
        resolve_conflict(&fx.state, GROUP_ID, &second, ConflictChoice::KeepBoth).await.unwrap();
    assert_eq!(kept, std::path::PathBuf::from("a (other version 2).txt"));
}

/// A copy whose original is not a shown item is not offered a resolution at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_copy_without_a_shown_original_is_not_resolvable() {
    use crate::conflict_resolution::resolvable_in_folder;
    let fx = Fx::app_only().await;
    fx.install_applier();
    let copy = fx.file_with_a_conflict_copy().await;
    assert!(resolvable_in_folder(&fx.state.replica_coordinator, GROUP_ID, &copy));
    let original = fx.repo().item_for_path(&fx.root, "a.txt").unwrap().unwrap();
    fx.repo().retire_item(&fx.root, &original).unwrap();
    assert!(!resolvable_in_folder(&fx.state.replica_coordinator, GROUP_ID, &copy));
}

/// Resolutions share one session of the root: many of them never run into the root's bound on
/// sessions, and each one still commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn many_resolutions_use_one_session_of_the_root() {
    use crate::conflict_resolution::{resolve_conflict, ConflictChoice};
    let fx = Fx::app_only().await;
    fx.install_applier();
    fx.file_with_a_conflict_copy().await;
    for n in 0..70u8 {
        let copy = yadorilink_replica_domain::conflict::conflict_copy_path(
            "a.txt",
            1_700_000_200_000_000_000 + i64::from(n),
            "dev-d",
            &[n; 32],
        );
        let mut create =
            fx.create(10 + u64::from(n), &copy, Some(fx.put_ingest(&format!("m-{n}"), b"x")));
        create.session_id = vec![2; 16];
        assert!(fx.app(create).await.ok);
        resolve_conflict(&fx.state, GROUP_ID, &copy, ConflictChoice::KeepBoth).await.unwrap();
    }
}

/// An original that changes between the moment Keep this reads its view and the commit is not
/// overwritten: the change is refused as stale, nothing is written, and the copy stays a conflict.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keep_this_does_not_overwrite_an_original_that_changed_before_the_commit() {
    use crate::conflict_resolution::{resolve_conflict, ConflictChoice, ResolveConflictError};
    let fx = Fx::app_only().await;
    let copy = fx.file_with_a_conflict_copy().await;
    let item = fx.repo().item_for_path(&fx.root, "a.txt").unwrap().unwrap();
    // The applier edits the original first (an edit arriving after the view was read), then
    // commits the resolution request unchanged.
    let edit = {
        let mut edit = fx.create(0, "unused", None);
        edit.kind = ProviderChangeKind::Modify as i32;
        edit.session_id = vec![3; 16];
        edit.operation_seq = 1;
        edit.item_id = item.to_vec();
        edit.name = None;
        edit.content = Some(fx.put_ingest("up-edit", b"edited meanwhile"));
        let view = fx.versions("a.txt");
        let current = view.iter().find(|v| v.size == 4).unwrap();
        let mut base = current.version_hash.0.to_vec();
        base.extend_from_slice(
            &fx.repo().live_item_generation(&fx.root, &item).unwrap().unwrap().to_be_bytes(),
        );
        edit.base_version_hash = base;
        edit.base_generation = fx.repo().live_item_generation(&fx.root, &item).unwrap();
        edit
    };
    let context = fx.context.clone();
    let edited = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let edited_in = edited.clone();
    fx.state.set_provider_applier(Arc::new(move |request| {
        let (context, edit, edited) = (context.clone(), edit.clone(), edited_in.clone());
        Box::pin(async move {
            if !edited.swap(true, std::sync::atomic::Ordering::SeqCst) {
                assert!(apply_for_app(&context, &edit).await.ok, "the edit lands first");
            }
            apply_for_app(&context, &request).await
        })
    }));

    let refused =
        resolve_conflict(&fx.state, GROUP_ID, &copy, ConflictChoice::KeepThis).await.unwrap_err();
    assert!(matches!(refused, ResolveConflictError::UnrecordedLocalChanges(_)), "{refused:?}");
    assert_eq!(
        fx.current_size("a.txt"),
        Some(16),
        "the edit stands, the copy did not overwrite it"
    );
    assert!(fx.repo().item_for_path(&fx.root, &copy).unwrap().is_some(), "the copy is still there");
}

// --- ingest op: step order and the cut between the store barrier and the record -------------

fn ingest_op(fx: &Fx, seq: u64) -> IngestOp {
    IngestOp::new(GROUP_ID, &fx.root, &[1; 16], seq)
}

use crate::write_op::StepEvent::{IngestApplied, IngestJournaled, IngestStoreDurable};

/// The bytes are durable in the store before the ingest is recorded as done, and the journal row
/// is cleared by that record and not before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ingest_makes_the_store_durable_before_it_is_recorded_and_clears_the_journal_with_it() {
    let mut fx = Fx::new().await;
    let source = fx.put_ingest("trace-copy", b"traced bytes");
    let mut request = fx.create(11, "t.txt", Some(source));
    request.request_id = b"trace-order".to_vec();
    let id = request.request_id.clone();
    let seen = Arc::new(Mutex::new(None));
    {
        // At the commit point the store barrier is behind us and the record is not yet written.
        let (op, repo_root, repo, seen) = (
            ingest_op(&fx, 11),
            fx.root.clone(),
            fx.state.replica_coordinator.clone(),
            seen.clone(),
        );
        set_point(
            "at_commit_point",
            &id,
            Arc::new(move || {
                let journaled = repo
                    .provider_repository()
                    .pending_ingest_name(&repo_root, &[1; 16], 11)
                    .unwrap()
                    .is_some();
                *seen.lock().unwrap() = Some((op.steps(), journaled));
            }),
        );
    }
    let response = fx.ask(request).await;
    assert!(response.ok, "{response:?}");
    let (before_record, journal_held) = seen.lock().unwrap().take().unwrap();
    assert_eq!(before_record, vec![IngestJournaled, IngestStoreDurable]);
    assert!(journal_held, "the journal row was cleared before the record");
    assert_eq!(
        ingest_op(&fx, 11).steps(),
        vec![IngestJournaled, IngestStoreDurable, IngestApplied]
    );
    assert_eq!(fx.repo().pending_ingest_name(&fx.root, &[1; 16], 11).unwrap(), None);
}

/// Cut between the store barrier and the record: the blocks are durable, nothing is authored and
/// the journaled upload is still there. The retry of the same operation applies it, and a further
/// replay is answered from the record without ingesting again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cut_between_the_store_barrier_and_the_record_is_finished_by_the_retry() {
    let mut fx = Fx::new().await;
    let source = fx.put_ingest("cut-copy", b"cut bytes");
    let mut first = fx.create(12, "c.txt", Some(source.clone()));
    first.request_id = b"cut-1".to_vec();
    {
        let (context, requests, handshakes, tx) =
            (fx.context.clone(), fx.requests.clone(), fx.handshakes.clone(), fx.tx.clone());
        let cancel = cancel_message(&first.request_id);
        set_point(
            "before_commit_point",
            &first.request_id,
            Arc::new(move || {
                assert!(apply_message(&context, &requests, &handshakes, &tx, &cancel));
            }),
        );
    }
    let response = fx.ask(first).await;
    assert_eq!(failure(&response), ProviderApplyFailure::Cancelled);
    assert_eq!(
        ingest_op(&fx, 12).steps(),
        vec![IngestJournaled, IngestStoreDurable],
        "the cut state is store-durable, not applied"
    );
    assert_eq!(fx.repo().list_children(&fx.root, "").unwrap().len(), 0);
    // The blocks are already readable from the store: the barrier is behind the cut.
    assert_eq!(
        fx.context.writer.store().get(&hex::encode(sha(b"cut bytes"))).unwrap(),
        b"cut bytes"
    );
    assert_eq!(
        fx.repo().pending_ingest_name(&fx.root, &[1; 16], 12).unwrap(),
        Some("cut-copy".to_owned()),
        "the journal must outlive the cut"
    );
    assert!(fx.ingest_dir().join("cut-copy").exists(), "the upload must outlive the cut");

    // The retry (same identity, a new request id) finishes it.
    let mut retry = fx.create(12, "c.txt", Some(source.clone()));
    retry.request_id = b"cut-2".to_vec();
    let response = fx.ask(retry).await;
    assert!(response.ok, "{response:?}");
    assert_eq!(fx.repo().list_children(&fx.root, "").unwrap().len(), 1);
    assert_eq!(fx.repo().pending_ingest_name(&fx.root, &[1; 16], 12).unwrap(), None);
    let steps = ingest_op(&fx, 12).steps();
    assert_eq!(steps.last(), Some(&IngestApplied));
    assert_eq!(steps.iter().filter(|s| **s == IngestApplied).count(), 1);

    // A replay after the record: answered from it, nothing journaled, stored or applied again.
    let recorded = steps.len();
    fx.put_ingest("cut-copy", b"cut bytes");
    let mut replay = fx.create(12, "c.txt", Some(source));
    replay.request_id = b"cut-3".to_vec();
    let response = fx.ask(replay).await;
    assert!(response.ok, "{response:?}");
    // The replay re-journals its own upload (before the replay check) and clears it again; it
    // stores and applies nothing.
    let after = ingest_op(&fx, 12).steps();
    assert_eq!(after[recorded..], [IngestJournaled]);
    assert_eq!(fx.repo().pending_ingest_name(&fx.root, &[1; 16], 12).unwrap(), None);
}
