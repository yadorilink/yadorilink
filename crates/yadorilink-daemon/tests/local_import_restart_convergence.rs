//! A device that imported a folder and has no peer must reach a settled
//! state, and stay settled across a restart.
//!
//! Nothing about an already-imported, already-on-disk folder needs a peer.
//! The content is present, it is correct, and this device authored every
//! change describing it. So once the import finishes there is no work
//! left, and the projection obligations the import created must be closed
//! -- by this device, from what it can see on its own disk.
//!
//! When they are not, the failure is invisible and permanent. Obligations
//! stay `pending` forever, every engine tick claims a few, fails them for
//! want of a peer that will never exist, and pushes them to the back of a
//! queue ordered by when they were last touched. Nothing errors. The
//! folder is perfectly correct on disk the whole time. It simply never
//! goes quiet, and on a large folder a single path can wait tens of
//! minutes for a retry that cannot succeed.
//!
//! Deliberately single-device: no peer, no coordination plane, no policy
//! admission. A peer is the thing being proven unnecessary, so introducing
//! one would defeat the test.

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use support::{ensure_device_signing_key, install_bootstrap_policy};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

const GROUP_ID: &str = "local-import-restart-group";
const FILE_COUNT: usize = 100;
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
    // local DAG emission is withheld entirely, so the import under test
    // would never run at all.
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

/// Waits for the folder scan to land every file in the index. Says
/// nothing about history; the import is a separate stage.
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

/// Whether this volume can confirm that a regular file it observed twice
/// is the same object both times.
///
/// Asks the question directly rather than inferring it from birth-time
/// granularity. Granularity is not the deciding input: a generation
/// counter is checked first and is a counter, not a clock reading, so a
/// volume with a coarse birth clock still confirms if it has one --
/// measured on this project's own ext4, which reports `Coarse` and
/// confirms anyway. A volume with neither a generation counter nor a fine
/// birth clock has nothing that excludes inode reuse, and there
/// revalidation is inconclusive for every regular file no matter what
/// proof exists, so nothing can be settled as already-materialized.
///
/// That is a property of the volume, not of the code under test, which is
/// why this gates rather than asserts.
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

/// Paths whose actual-state proof names a different version than the one
/// the native state currently resolves them to.
///
/// The number that matters, and the one a "did it settle" check cannot
/// see. A proof and a live head are supposed to be two records of a
/// single decision; if they name different versions, something derived
/// the same logical value twice and got two answers. The obligation then
/// cannot close -- but worse, it could later be closed by some other
/// mechanism while the disagreement is still there, so the settled count
/// alone is not evidence that this is right.
fn proofs_disagreeing_with_the_live_head(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM native_heads h \
         LEFT JOIN path_materialized_generations g \
           ON g.group_id = h.group_id AND g.path = h.path \
         WHERE g.version_hash IS NULL OR g.version_hash != h.version",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

/// Waits for the import to have recorded a proof per path.
async fn wait_for_proofs(conn: &rusqlite::Connection, what: &str) {
    let deadline = tokio::time::Instant::now() + SETTLE_TIMEOUT;
    loop {
        if materialized_proofs(conn) >= FILE_COUNT as i64 {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            panic!(
                "{what}: the import recorded {} actual-state proof(s) for {FILE_COUNT} imported \
                 path(s) within {SETTLE_TIMEOUT:?}. Content this device already holds, wrote \
                 into history itself, and can see on its own disk has no record saying so -- so \
                 nothing can ever conclude the paths are already materialized",
                materialized_proofs(conn)
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Waits for the import itself to finish -- the group is DAG-backed and
/// every file has a current index row. Says nothing about obligations;
/// that is what the test asserts afterwards.
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

/// Waits for the device to go quiet, and reports what it was still
/// carrying if it never does.
async fn wait_for_quiet(conn: &rusqlite::Connection, what: &str) {
    let deadline = tokio::time::Instant::now() + SETTLE_TIMEOUT;
    loop {
        let outstanding = pending_obligations(conn);
        if outstanding == 0 {
            return;
        }
        if tokio::time::Instant::now() > deadline {
            let attempts: i64 = conn
                .query_row(
                    "SELECT COALESCE(MAX(attempt_count), 0) FROM projection_obligations",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let origins: String = {
                let mut stmt = conn
                    .prepare(
                        "SELECT origin, state, COUNT(*) FROM projection_obligations \
                         GROUP BY origin, state",
                    )
                    .unwrap();
                let rows = stmt
                    .query_map([], |row| {
                        Ok(format!(
                            "{}/{}={}",
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?
                        ))
                    })
                    .unwrap();
                rows.map(|r| r.unwrap()).collect::<Vec<_>>().join(" ")
            };
            panic!(
                "{what}: {outstanding} projection obligation(s) never closed within \
                 {SETTLE_TIMEOUT:?} on a device with no peer, for content already correct on \
                 its own disk. max attempt_count={attempts}, breakdown: [{origins}], \
                 path_materialized_generations={}, and {} path(s) whose proof names a \
                 different version than the DAG resolves them to",
                materialized_proofs(conn),
                proofs_disagreeing_with_the_live_head(conn),
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Restarts the device the way the daemon actually restarts: stop the
/// link runtime, drop the state, reopen the index through the production
/// open path, and start the link again.
async fn restart(device: Device, local_path: &str, group_id: &str) -> Device {
    LinkRuntimeController::new(device.state.clone()).stop(local_path).await;
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
    // Resume watching the link, the way real startup does. The
    // placeholder-backend override is what the shared restart harness
    // applies here too -- harmless for an eager link, and required for the
    // link runtime to come back up at all. The retry covers the previous
    // generation's root-lock sidecar still being released.
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

/// Import a folder on a device that has no peer and never will, then
/// restart it. Once the import has happened the device must settle: no
/// outstanding projection obligations, and an actual-state proof for
/// every path it imported. It must still be settled after another
/// restart.
///
/// The scan and the import are two separate stages here, and which one a
/// given startup runs depends on what the other has already finished --
/// on a fresh link the first start scans into the file index and the
/// import only runs on a later start, once there are unbound rows for it
/// to find. That ordering is itself part of what this test pins: whatever
/// sequence of starts gets the content into history, the device has to end
/// up quiet.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_imported_folder_settles_without_a_peer_and_stays_settled_across_a_restart() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    support::ensure_isolated_config_dir();
    let group_id = GROUP_ID;

    let mut device = new_device("local-import-restart-a");
    for i in 0..FILE_COUNT {
        let path = device.root.path().join(format!("file{i:05}.bin"));
        std::fs::write(&path, format!("payload for file {i}").repeat(4)).unwrap();
    }
    // Judged before any daemon or watcher exists: the probe writes a temporary
    // file into the watched root, and a running watcher would index it.
    let can_confirm = can_confirm_repeated_observation(device.root.path());
    let local_path = device.root.path().to_string_lossy().to_string();

    device
        .state
        .replica_coordinator
        .link_repository()
        .add_link(&local_path, group_id)
        .expect("linking the folder must succeed");
    LinkRuntimeController::new(device.state.clone())
        .start(local_path.clone(), group_id.to_string())
        .expect("starting the link runtime for a fresh, pre-populated root");

    // The first start scans the folder into the file index.
    {
        let poll_conn = rusqlite::Connection::open(&device.db_path).unwrap();
        wait_for_scan(&poll_conn, "first run").await;
    }

    // A restart is what gets the scanned rows into history.
    device = restart(device, &local_path, group_id).await;
    let poll_conn = rusqlite::Connection::open(&device.db_path).unwrap();
    wait_for_import(&poll_conn, "after import restart").await;

    // The import must leave an actual-state proof for every path it
    // imported. This is the half that is purely this device's own doing,
    // so it holds everywhere.
    wait_for_proofs(&poll_conn, "after import restart").await;
    assert_eq!(
        materialized_proofs(&poll_conn),
        FILE_COUNT as i64,
        "the import must leave an actual-state proof for every path it imported -- without one \
         this device has no way to conclude that content it wrote itself is already in place"
    );

    // Closing the obligation additionally requires confirming, against
    // disk, that the object the proof describes is still the object that
    // is there. A volume with nothing that excludes inode reuse -- no
    // generation counter and no fine birth clock -- cannot confirm that
    // for any regular file, so skip the closure half there rather than
    // assert something the volume cannot support.
    if can_confirm {
        wait_for_quiet(&poll_conn, "after import restart").await;
    } else {
        eprintln!(
            "skipping the obligation-closure half: this volume cannot confirm that a regular \
             file observed twice is the same object, so disk identity revalidation is \
             inconclusive for every path and zero-work closure cannot succeed regardless of \
             the proof"
        );
    }
    // Every path's proof must name the version that path actually resolves
    // to. Checked here rather than as soon as the proofs appear, because
    // the divergence is introduced by work that runs after that: the proof
    // is right when written and only stops agreeing once something else
    // derives the same version a second way.
    //
    // Checked separately from whether anything settled, because a
    // disagreement is the real defect and "it settled" can become true for
    // other reasons -- leaving a proof and a live head permanently naming
    // different versions with nothing reporting it.
    assert_eq!(
        proofs_disagreeing_with_the_live_head(&poll_conn),
        0,
        "some paths' actual-state proof names a different version than the DAG resolves them \
         to: the version was derived twice, once from the index and once from disk, and the \
         two answers disagree"
    );
    drop(poll_conn);

    // And it must stay settled, not re-open the same work on every boot.
    device = restart(device, &local_path, group_id).await;
    let poll_conn = rusqlite::Connection::open(&device.db_path).unwrap();
    if can_confirm {
        wait_for_quiet(&poll_conn, "after second restart").await;
    }
    assert_eq!(
        current_rows(&poll_conn),
        FILE_COUNT as i64,
        "the restart must not have lost or duplicated index rows"
    );
    assert_eq!(
        materialized_proofs(&poll_conn),
        FILE_COUNT as i64,
        "the proofs must survive the restart rather than being rebuilt or dropped"
    );

    LinkRuntimeController::new(device.state.clone()).stop(&local_path).await;
}
