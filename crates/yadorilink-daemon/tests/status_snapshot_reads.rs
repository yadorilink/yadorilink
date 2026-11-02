//! A status read does not wait on the ledger: with a write transaction held, with every pooled
//! connection checked out, over the real control transport. The facts a request is answered from
//! are collected by the status builder, never by the request.

mod support;

use std::sync::{mpsc, Arc};
use std::time::Duration;

use support::control_socket_client as control;
use support::{ensure_device_signing_key, open_file_backed_replica_coordinator};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{ListLinksRequest, StatusRequest};
use yadorilink_local_storage::SegmentBlockStore;

const GROUP: &str = "snapshot-reads-group";
/// A request slower than this fails the test; a passing run never gets near it.
const NEVER: Duration = Duration::from_secs(20);

struct Daemon {
    state: Arc<DaemonState>,
    _store_dir: tempfile::TempDir,
    _index_dir: tempfile::TempDir,
    _root: tempfile::TempDir,
}

fn new_daemon() -> Daemon {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let state = yadorilink_daemon::test_support::isolated_daemon_state(
        "device-a".to_string(),
        Arc::new(sync_state),
        store,
    );
    ensure_device_signing_key(&state);
    let root = tempfile::tempdir().unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&root.path().to_string_lossy(), GROUP)
        .unwrap();
    Daemon { state, _store_dir: store_dir, _index_dir: index_dir, _root: root }
}

async fn answers(socket: &control::ControlSocketHandle) {
    for payload in
        [ReqPayload::Status(StatusRequest {}), ReqPayload::ListLinks(ListLinksRequest {})]
    {
        let asked = std::time::Instant::now();
        let response = control::send(socket, payload).await;
        // A read that blocks a thread defeats an async timeout, so the wait is measured. A
        // pass takes milliseconds; the slowest wait a ledger read has (a connection checkout)
        // is 30 s.
        assert!(asked.elapsed() < NEVER, "a read waited {:?} on a held ledger", asked.elapsed());
        assert!(
            !matches!(response.payload, Some(RespPayload::Error(_))),
            "a read failed: {:?}",
            response.payload
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_are_answered_while_a_write_transaction_is_held() {
    let daemon = new_daemon();
    let socket = control::start(daemon.state.clone()).await;
    answers(&socket).await; // the first build

    let (inside_tx, inside_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let state = daemon.state.clone();
    let writer = std::thread::spawn(move || {
        state
            .replica_coordinator
            .database()
            .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                let tx = conn.transaction()?;
                tx.execute("UPDATE links SET paused = paused WHERE 1 = 1", [])?;
                inside_tx.send(()).unwrap();
                release_rx.recv().unwrap(); // parked inside the transaction
                tx.commit()?;
                Ok(())
            })
            .unwrap();
    });
    tokio::task::spawn_blocking(move || inside_rx.recv().unwrap()).await.unwrap();

    answers(&socket).await;

    release_tx.send(()).unwrap();
    writer.join().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reads_are_answered_while_every_pooled_connection_is_checked_out() {
    let daemon = new_daemon();
    let socket = control::start(daemon.state.clone()).await;
    answers(&socket).await; // the first build

    // The request path owns no read of the ledger: with the pool empty, a read that tried to
    // check a connection out would wait for it.
    let database = daemon.state.replica_coordinator.database();
    let pool = database.pool_for_test();
    let held: Vec<_> = (0..pool.max_size()).map(|_| pool.get().unwrap()).collect();

    answers(&socket).await;

    drop(held);
}
