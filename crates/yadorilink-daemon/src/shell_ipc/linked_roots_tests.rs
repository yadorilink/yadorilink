#![cfg(test)]

//! `ListLinkedRootsResponse` feeds the Finder extension's monitored directories:
//! a link-table read failure must never look like a confirmed empty set.

use std::sync::Arc;

use yadorilink_ipc_proto::shellipc::{ListLinkedRootsRequest, ListLinkedRootsResponse};
use yadorilink_local_storage::SegmentBlockStore;

use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;

use super::*;

fn test_state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    DaemonState::new("device-a".into(), sync_state, store)
}

async fn list_roots(state: &Arc<DaemonState>) -> ListLinkedRootsResponse {
    let response = handle_message(
        &ShellContext::from_state(state.clone()),
        ShellIpcMessage {
            payload: Some(Payload::ListLinkedRootsRequest(ListLinkedRootsRequest {})),
        },
    )
    .await
    .expect("a ListLinkedRootsRequest always gets a response");
    let Some(Payload::ListLinkedRootsResponse(r)) = response.payload else {
        panic!("expected a ListLinkedRootsResponse");
    };
    r
}

fn execute(state: &Arc<DaemonState>, sql: &str) {
    let database = state.replica_coordinator.database();
    database.pool_for_test().get().unwrap().execute_batch(sql).unwrap();
}

#[tokio::test]
async fn no_links_is_a_confirmed_empty_snapshot() {
    let r = list_roots(&test_state()).await;
    assert!(r.local_paths.is_empty());
    assert!(r.snapshot_available);
}

#[tokio::test]
async fn every_live_folder_link_is_listed_and_an_orphan_is_not() {
    let state = test_state();
    let links = state.replica_coordinator.link_repository();
    links.add_link("/Users/x/Documents/Work", "group-1").unwrap();
    links.add_link("/Volumes/Data/Photos", "group-2").unwrap();
    links.add_link("/tmp/orphan", "group-3").unwrap();
    execute(&state, "UPDATE links SET orphaned = 1 WHERE local_path = '/tmp/orphan'");

    let r = list_roots(&state).await;

    assert!(r.snapshot_available);
    let mut paths = r.local_paths;
    paths.sort();
    assert_eq!(paths, ["/Users/x/Documents/Work", "/Volumes/Data/Photos"]);
}

#[tokio::test]
async fn a_link_table_read_failure_is_not_a_confirmed_empty_snapshot() {
    let state = test_state();
    state.replica_coordinator.link_repository().add_link("/Users/x/Work", "group-1").unwrap();
    execute(&state, "DROP TABLE links");

    let r = list_roots(&state).await;

    assert!(r.local_paths.is_empty());
    assert!(!r.snapshot_available, "an unreadable link table is unknown, not empty");
}
