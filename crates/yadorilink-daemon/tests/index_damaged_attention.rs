//! A stored file record whose block list cannot be read back marks only its own folder: that
//! folder claims neither protection nor availability and says why, the others are untouched, and
//! the mark goes when the record reads back.

mod support;

use std::sync::Arc;

use support::control_socket_client as control;
use support::{ensure_device_signing_key, open_file_backed_replica_coordinator};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    FetchAvailability, GroupDurabilityStatus, StatusRequest, StatusResponse,
};
use yadorilink_local_storage::SegmentBlockStore;

const DAMAGED: &str = "damaged-group";
const CLEAN: &str = "clean-group";

struct Daemon {
    state: Arc<DaemonState>,
    _dirs: Vec<tempfile::TempDir>,
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
    let mut dirs = vec![store_dir, index_dir];
    for group in [DAMAGED, CLEAN] {
        let root = tempfile::tempdir().unwrap();
        state
            .replica_coordinator
            .link_repository()
            .add_link(&root.path().to_string_lossy(), group)
            .unwrap();
        state
            .replica_coordinator
            .file_index_repository()
            .ensure_bootstrap_row_for_metadata(group, "photo.jpg")
            .unwrap();
        dirs.push(root);
    }
    Daemon { state, _dirs: dirs }
}

fn set_block_list(daemon: &Daemon, group: &str, blocks_json: &str) {
    daemon
        .state
        .replica_coordinator
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            conn.execute(
                "UPDATE files SET blocks_json = ?1 WHERE group_id = ?2 AND path = 'photo.jpg'",
                rusqlite::params![blocks_json, group],
            )?;
            Ok(())
        })
        .unwrap();
    // The write went around the request dispatchers; say it has finished.
    daemon.state.telemetry.command_completed();
}

async fn status(socket: &control::ControlSocketHandle) -> StatusResponse {
    let response = control::send(socket, ReqPayload::Status(StatusRequest {})).await;
    let Some(RespPayload::Status(status)) = response.payload else {
        panic!("not a status: {:?}", response.payload)
    };
    status
}

fn link<'a>(
    status: &'a StatusResponse,
    group: &str,
) -> &'a yadorilink_ipc_proto::daemonctl::LinkStatus {
    status.links.iter().find(|l| l.group_id == group).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_damaged_record_marks_its_own_folder_and_the_mark_goes_when_it_is_repaired() {
    let daemon = new_daemon();
    // Damaged before the first status: the audit's first pass runs to the end of the table when
    // the builder first collects. (Damage that comes later waits for the next step; the audit's
    // own tests cover that.)
    set_block_list(&daemon, DAMAGED, "[{\"hash\"");
    let socket = control::start(daemon.state.clone()).await;

    let damaged = status(&socket).await;
    let folder = link(&damaged, DAMAGED);
    assert_eq!(folder.index_damaged_path, "photo.jpg");
    assert_eq!(folder.durability_status(), GroupDurabilityStatus::Unknown);
    assert_eq!(folder.fetch_availability(), FetchAvailability::Unknown);
    let reasons = &damaged.attention_reasons;
    assert!(reasons.contains(&format!("index_damaged:{DAMAGED}")), "{reasons:?}");
    // One item for the damage, not the unknowns that follow from it.
    assert!(!reasons.contains(&format!("durability_unknown:{DAMAGED}")), "{reasons:?}");
    // The other folder is untouched, and the status as a whole still answers.
    assert_eq!(link(&damaged, CLEAN).index_damaged_path, "");
    assert!(!reasons.contains(&format!("index_damaged:{CLEAN}")), "{reasons:?}");

    set_block_list(&daemon, DAMAGED, "[]");
    let repaired = status(&socket).await;
    assert_eq!(link(&repaired, DAMAGED).index_damaged_path, "");
    assert!(!repaired.attention_reasons.iter().any(|r| r.starts_with("index_damaged")));
}
