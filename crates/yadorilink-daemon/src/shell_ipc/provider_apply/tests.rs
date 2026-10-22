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
        send(&state, domain_state(&root_id, true)).await;
        send(&state, handshake(&root_id)).await;
        let dir = tempfile::tempdir().unwrap();
        let handoff = HandoffRoot::open_with_lifetime(dir.path(), Duration::from_secs(60)).unwrap();
        let context =
            Arc::new(ShellContext::from_state(state.clone()).with_handoff_root(Some(handoff)));
        let (host, host_rx) = mpsc::unbounded_channel();
        assert!(context.provider_host.try_attach(host.clone()));
        let (tx, rx) = mpsc::unbounded_channel();
        let handshakes = Arc::new(Handshakes::default());
        handshakes.note(&root_id);
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
            .expect("no response")
            .expect("closed");
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
    let pins = fx.state.replica_coordinator.pinned_item_repository();
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

    adapter.pin("group-1", "kept").await.unwrap();
    let pinned = served(ask_children(&fx, &[], &[], 10).await);
    assert_ne!(pinned["kept"].0, before["kept"].0, "the OS was not given a new token for the pin");
    assert!(!pinned["kept"].1 && pinned["free"].1);
    assert_eq!(pinned["free"].0, before["free"].0, "an unrelated item was republished");
    assert!(owed(&fx).is_some(), "the OS is owed a signal for the pin");
    if let Some(changes) = owed(&fx) {
        fx.repo().mark_announced(&fx.root, changes).unwrap();
    }

    adapter.unpin("group-1", "kept").unwrap();
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
