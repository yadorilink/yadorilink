//! A file deleted from disk while the daemon was stopped must settle, on a
//! device that has no peer.
//!
//! The sibling scenario to `local_import_restart_convergence`, one step
//! further along: the folder is imported and quiet, then the daemon stops,
//! then a file is removed from the folder by something that is not this
//! daemon -- another process, a file manager, a user at a shell. On the
//! next start the reconciliation scan is the only thing that can notice,
//! and it emits an offline-deletion tombstone.
//!
//! What the device has to end up with is a consistent trio for that path:
//! the DAG resolves it to absent, nothing is still owed for it, and its
//! actual-state record says absent rather than still naming the content
//! that used to be there. Any two of those without the third is a path
//! that either never goes quiet or claims to hold bytes that are gone --
//! and with no peer to ask, nothing else will ever correct it.
//!
//! Deliberately single-device, for the same reason the import test is: a
//! peer is precisely the thing being proven unnecessary.

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use support::{ensure_device_signing_key, install_bootstrap_policy};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_engine::conflict::{resolve_path_heads, PathResolution};
use yadorilink_sync_sqlite::materialized_generation::MaterializedObjectKind;

const GROUP_ID: &str = "offline-delete-no-peer-group";
const FILE_COUNT: usize = 4;
/// The one file removed from disk while the daemon is stopped.
const DELETED_PATH: &str = "file00002.bin";
const SETTLE_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

struct Device {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    store_dir: tempfile::TempDir,
    _db_dir: tempfile::TempDir,
    db_path: PathBuf,
}

fn new_device(device_id: &str) -> Device {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let db_dir = tempfile::tempdir().unwrap();
    let db_path = db_dir.path().join("index.db");
    let sync_state = Arc::new(ReplicaCoordinator::open(&db_path).unwrap());
    let state = DaemonState::new(device_id.to_string(), sync_state, store);
    ensure_device_signing_key(&state);
    // A linked group is fail-closed without a verified policy snapshot:
    // local DAG emission is withheld entirely, so neither the import nor
    // the deletion under test would ever reach history.
    install_bootstrap_policy(&state, &[GROUP_ID.to_string()]);
    Device {
        device_id: device_id.to_string(),
        state,
        root: tempfile::tempdir().unwrap(),
        store_dir,
        _db_dir: db_dir,
        db_path,
    }
}

fn count(conn: &rusqlite::Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get(0)).unwrap()
}

fn pending_obligations(conn: &rusqlite::Connection) -> i64 {
    count(conn, "SELECT COUNT(*) FROM projection_obligations")
}

fn materialized_proofs(conn: &rusqlite::Connection) -> i64 {
    count(conn, "SELECT COUNT(*) FROM path_materialized_generations")
}

fn dag_backed(conn: &rusqlite::Connection) -> bool {
    count(conn, "SELECT COUNT(*) FROM native_heads") > 0
}

fn current_rows(conn: &rusqlite::Connection) -> i64 {
    count(conn, "SELECT COUNT(*) FROM files WHERE state = 'current' AND version_seq > 0")
}

/// Whether this volume can confirm that a regular file it observed twice
/// is the same object both times -- the property that decides whether
/// identity revalidation can ever authorize settling a present path
/// without doing physical work. A property of the volume, not of the code
/// under test, so it gates rather than asserts. See the identical helper
/// in `local_import_restart_convergence` for the full reasoning.
fn can_confirm_repeated_observation(dir: &std::path::Path) -> bool {
    use yadorilink_fs_platform::fs_capabilities::probe_birth_time_granularity;
    use yadorilink_fs_platform::fs_identity::{FileIdentity, IdentityComparison};
    let probe = dir.join(".yadorilink-identity-probe");
    if std::fs::write(&probe, b"probe").is_err() {
        return false;
    }
    let granularity = probe_birth_time_granularity(dir);
    let confirmable = match (FileIdentity::observe_path(&probe), FileIdentity::observe_path(&probe))
    {
        (Ok(first), Ok(second)) => {
            matches!(first.compare(&second, granularity), IdentityComparison::SameObject)
        }
        _ => false,
    };
    let _ = std::fs::remove_file(&probe);
    confirmable
}

async fn wait_for_scan(conn: &rusqlite::Connection, what: &str) {
    let deadline = tokio::time::Instant::now() + SETTLE_TIMEOUT;
    loop {
        if current_rows(conn) >= FILE_COUNT as i64 {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "{what}: the folder scan did not index all {FILE_COUNT} files within \
                 {SETTLE_TIMEOUT:?} (current_rows={})",
                current_rows(conn)
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_import(conn: &rusqlite::Connection, what: &str) {
    let deadline = tokio::time::Instant::now() + SETTLE_TIMEOUT;
    loop {
        if dag_backed(conn) && current_rows(conn) >= FILE_COUNT as i64 {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "{what}: import did not finish within {SETTLE_TIMEOUT:?} \
                 (dag_backed={} current_rows={})",
                dag_backed(conn),
                current_rows(conn)
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_proofs(conn: &rusqlite::Connection, what: &str) {
    let deadline = tokio::time::Instant::now() + SETTLE_TIMEOUT;
    loop {
        if materialized_proofs(conn) >= FILE_COUNT as i64 {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "{what}: the import recorded {} actual-state proof(s) for {FILE_COUNT} imported \
                 path(s) within {SETTLE_TIMEOUT:?}",
                materialized_proofs(conn)
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_quiet(conn: &rusqlite::Connection, what: &str) {
    let deadline = tokio::time::Instant::now() + SETTLE_TIMEOUT;
    loop {
        let outstanding = pending_obligations(conn);
        if outstanding == 0 {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "{what}: {outstanding} projection obligation(s) never closed within \
                 {SETTLE_TIMEOUT:?} on a device with no peer. breakdown: [{}]",
                obligation_breakdown(conn)
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// `path/origin/state=attempts` for every outstanding obligation -- the
/// only useful thing to print when a no-peer device refuses to go quiet.
fn obligation_breakdown(conn: &rusqlite::Connection) -> String {
    let mut stmt = conn
        .prepare(
            "SELECT path, origin, state, attempt_count FROM projection_obligations ORDER BY path",
        )
        .unwrap();
    let rows = stmt
        .query_map([], |row| {
            Ok(format!(
                "{}/{}/{}={}",
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?
            ))
        })
        .unwrap();
    rows.map(|r| r.unwrap()).collect::<Vec<_>>().join(" ")
}

/// Stops the link runtime, the way a daemon shutdown does. `stop` awaits
/// any in-flight scan to genuine completion before releasing the root
/// lock, so after this returns nothing is still looking at the folder --
/// which is what makes the deletion below a genuinely offline one.
async fn stop_link(device: &Device, local_path: &str) {
    LinkRuntimeController::new(device.state.clone()).stop(local_path).await;
}

/// Brings the device back up over the same on-disk index and block store:
/// reopen through the production open path, restore the signing key and
/// policy (neither of which `DaemonState` persists), and start the link
/// again. Starting the link is what runs the full reconciliation scan.
async fn start_link(device: Device, local_path: &str, group_id: &str) -> Device {
    let signing_key = device.state.device_signing_key().expect("signing key was set");
    drop(device.state);
    let sync_state = {
        let mut attempts = 0;
        loop {
            match ReplicaCoordinator::open(&device.db_path) {
                Ok(coordinator) => break Arc::new(coordinator),
                Err(_) if attempts < 10 => {
                    attempts += 1;
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(error) => panic!("reopening the index database failed: {error}"),
            }
        }
    };
    let restarted = DaemonState::new(
        device.device_id.clone(),
        sync_state,
        Arc::new(SegmentBlockStore::new(device.store_dir.path()).unwrap()),
    );
    restarted.set_device_signing_key(signing_key);
    install_bootstrap_policy(&restarted, &[group_id.to_string()]);
    let device = Device { state: restarted, ..device };
    // The retry covers the previous generation's root-lock sidecar still
    // being released; the placeholder-backend override is what the other
    // restart harnesses apply here too.
    let mut attempts = 0;
    loop {
        device.state.set_test_on_demand_allowed(true);
        match LinkRuntimeController::new(device.state.clone())
            .start(local_path.to_string(), group_id.to_string())
        {
            Ok(()) => break,
            Err(_) if attempts < 20 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(error) => panic!("restarting the link runtime failed: {error}"),
        }
    }
    device
}

async fn restart(device: Device, local_path: &str, group_id: &str) -> Device {
    stop_link(&device, local_path).await;
    start_link(device, local_path, group_id).await
}

/// How the DAG currently resolves `path`, and how many present heads it
/// has. A generation-11 delete leaves no head, so an empty head set alone
/// does not tell "deleted" from "never existed"; [`removed_by_history`]
/// does.
fn dag_resolution(device: &Device, group_id: &str, path: &str) -> (PathResolution, usize) {
    let heads = support::native_path_heads(&device.state, group_id, path);
    let resolution = resolve_path_heads(path, &heads);
    (resolution, heads.len())
}

/// The version `path`'s single present head lands.
fn shown_version(device: &Device, group_id: &str, path: &str) -> [u8; 32] {
    let heads = support::native_path_heads(&device.state, group_id, path);
    assert_eq!(heads.len(), 1, "one head at {path}: {heads:?}");
    heads[0].content.as_ref().expect("a present head lands content").version_hash
}

/// Whether a held delta removed `path`'s head and put nothing there.
fn removed_by_history(device: &Device, group_id: &str, path: &str, _shown: &[u8; 32]) -> bool {
    support::native_path_removed(&device.state, group_id, path)
}

/// A file removed from the folder while the daemon was stopped has to
/// settle on the next start, on a device with no peer and no prospect of
/// one.
///
/// Three things have to agree afterwards, and the test asserts all three
/// because any two of them can be true while the third is not:
///
/// 1. the DAG resolves the path to absent -- the scan noticed and emitted
///    a real, signed deletion rather than leaving a live file in history
///    that peers would one day re-hydrate;
/// 2. nothing is still owed for the path -- its projection obligation is
///    closed, not retrying forever against a peer that will never exist;
/// 3. the path's actual-state record says absent -- not still naming the
///    content that used to be there, which is a claim about disk that
///    stopped being true the moment the file was removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_deleted_while_stopped_settles_without_a_peer() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    support::ensure_isolated_config_dir();
    let group_id = GROUP_ID;

    let mut device = new_device("offline-delete-no-peer-a");
    for i in 0..FILE_COUNT {
        let path = device.root.path().join(format!("file{i:05}.bin"));
        std::fs::write(&path, format!("payload for file {i}").repeat(4)).unwrap();
    }
    let local_path = device.root.path().to_string_lossy().to_string();

    if !can_confirm_repeated_observation(device.root.path()) {
        eprintln!(
            "skipping: this volume cannot confirm that a regular file observed twice is the same \
             object, so the import can never settle in the first place and the deletion under \
             test would be vetoed by its still-unsettled obligation"
        );
        return;
    }

    device
        .state
        .replica_coordinator
        .link_repository()
        .add_link(&local_path, group_id)
        .expect("linking the folder must succeed");
    LinkRuntimeController::new(device.state.clone())
        .start(local_path.clone(), group_id.to_string())
        .expect("starting the link runtime for a fresh, pre-populated root");

    // Stage 1: get the folder imported, hydrated and fully quiet, so the
    // deletion below is the only thing left to settle. The first start
    // scans into the index; a restart is what gets those rows into history.
    {
        let poll_conn = rusqlite::Connection::open(&device.db_path).unwrap();
        wait_for_scan(&poll_conn, "first run").await;
    }
    device = restart(device, &local_path, group_id).await;
    {
        let poll_conn = rusqlite::Connection::open(&device.db_path).unwrap();
        wait_for_import(&poll_conn, "after import restart").await;
        wait_for_proofs(&poll_conn, "after import restart").await;
        wait_for_quiet(&poll_conn, "after import restart").await;
    }

    let deleted = device.root.path().join(DELETED_PATH);
    assert!(deleted.exists(), "sanity: the path to be deleted must exist after the import");
    let (before, before_heads) = dag_resolution(&device, group_id, DELETED_PATH);
    assert!(
        matches!(before, PathResolution::Present { .. }) && before_heads > 0,
        "sanity: the path must resolve to present content before it is deleted, got \
         {before:?} over {before_heads} head(s)"
    );
    let shown = shown_version(&device, group_id, DELETED_PATH);

    // Stage 2: stop, delete from disk behind the daemon's back, start.
    // `stop` has already awaited the in-flight scan, so nothing is
    // watching the folder while the file goes away -- the deletion can
    // only be discovered by the reconciliation scan the next start runs.
    stop_link(&device, &local_path).await;
    std::fs::remove_file(&deleted).unwrap();
    device = start_link(device, &local_path, group_id).await;

    let poll_conn = rusqlite::Connection::open(&device.db_path).unwrap();
    // Give the scan and everything downstream of it the full settle
    // budget before judging. Polls the same trio the assertions below
    // check, so a device that does settle costs a poll interval rather
    // than the whole timeout.
    let deadline = tokio::time::Instant::now() + SETTLE_TIMEOUT;
    loop {
        let (resolution, heads) = dag_resolution(&device, group_id, DELETED_PATH);
        let obligation = device
            .state
            .replica_coordinator
            .sqlite()
            .dag_lookup_projection_obligation(group_id, DELETED_PATH)
            .unwrap();
        let basis = device
            .state
            .replica_coordinator
            .sqlite()
            .dag_lookup_materialized_generation(group_id, DELETED_PATH)
            .unwrap();
        let settled = heads == 0
            && removed_by_history(&device, group_id, DELETED_PATH, &shown)
            && resolution == PathResolution::Absent
            && obligation.is_none()
            && basis.as_ref().map(|b| b.object_kind) == Some(MaterializedObjectKind::Absent);
        if settled || tokio::time::Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }

    assert!(!deleted.exists(), "sanity: the deleted file must not have been re-created");

    let (resolution, heads) = dag_resolution(&device, group_id, DELETED_PATH);
    assert_eq!(heads, 0, "the deletion superseded the only head at {DELETED_PATH}");
    assert!(
        removed_by_history(&device, group_id, DELETED_PATH, &shown),
        "an admitted change must have removed the version the path held -- a headless path \
         with no removal is a path that was never written, not a deleted one"
    );
    assert_eq!(
        resolution,
        PathResolution::Absent,
        "the reconciliation scan must have emitted an offline-deletion tombstone for a file \
         removed from disk while the daemon was stopped: the DAG still resolves {DELETED_PATH} \
         to present content over {heads} head(s), so a peer would treat it as a live file and \
         re-hydrate it"
    );

    // Asserted before the obligation below, because it is the thing the
    // obligation's closure depends on: with no usable actual-state record
    // saying "absent", there is nothing for a no-peer device to close the
    // obligation against, so the obligation failing is downstream of this.
    let basis = device
        .state
        .replica_coordinator
        .sqlite()
        .dag_lookup_materialized_generation(group_id, DELETED_PATH)
        .unwrap();
    assert_eq!(
        basis.as_ref().map(|b| b.object_kind),
        Some(MaterializedObjectKind::Absent),
        "the actual-state record for {DELETED_PATH} must say the path is absent. `None` here is \
         not the same answer: absence is a first-class generation, and `None` means no usable \
         record at all -- so nothing can conclude the path is already in its desired state \
         without asking a peer that does not exist. got {basis:?}"
    );

    let obligation = device
        .state
        .replica_coordinator
        .sqlite()
        .dag_lookup_projection_obligation(group_id, DELETED_PATH)
        .unwrap();
    assert!(
        obligation.is_none(),
        "the projection obligation the deletion opened for {DELETED_PATH} never closed on a \
         device with no peer, for a path whose desired state (absent) already matches its own \
         disk: {obligation:?}. all outstanding: [{}]",
        obligation_breakdown(&poll_conn)
    );

    LinkRuntimeController::new(device.state.clone()).stop(&local_path).await;
}
