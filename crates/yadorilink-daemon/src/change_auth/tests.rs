#![cfg(test)]

use std::sync::Arc;

use crate::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;

use super::*;

fn test_state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    DaemonState::new("device-a".into(), sync_state, store)
}

/// A cached `false` must be honored without re-resolving group policy --
/// a fresh (uncached) resolution of this never-touched bootstrap group
/// would say it is fine, so an empty result here can only come from the
/// cache actually being consulted.
#[tokio::test]
async fn effective_servable_groups_short_circuits_on_a_cached_result() {
    let state = test_state();
    let raw_groups: HashSet<String> = HashSet::from(["group-x".to_string()]);
    let cache: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());
    cache.lock().unwrap().insert("group-x".to_string(), false);

    let result = effective_servable_groups(state, "device-b", &raw_groups, &cache);
    assert!(result.is_empty());
}

/// A resolution miss populates the cache with its outcome, so a group
/// shared by many peers in one netmap-update pass is resolved once, not
/// once per peer sharing it. (Only an answer every peer would get is kept: see the next test.)
#[tokio::test]
async fn effective_servable_groups_populates_the_validation_cache_on_a_miss() {
    let state = test_state();
    state.mark_group_policy_stale("group-y");
    let raw_groups: HashSet<String> = HashSet::from(["group-y".to_string()]);
    let cache: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());

    let result = effective_servable_groups(state, "device-b", &raw_groups, &cache);
    assert!(result.is_empty());
    assert_eq!(cache.lock().unwrap().get("group-y").copied(), Some(false));
}

/// For a group with no verified policy yet, whether it may be served depends on which OTHER peers
/// name it, so one peer's answer must not be handed to another through the pass's shared cache.
#[tokio::test]
async fn one_peers_answer_for_an_unresolved_group_is_not_handed_to_another() {
    let state = test_state();
    let group: HashSet<String> = HashSet::from(["group-z".to_string()]);
    // device-a is already the group's only writer; device-b is newly listed.
    state.replace_peer_netmap_metadata("device-a", Some([1; 32]), &group, &group);
    let cache: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());

    // device-b is judged first: another peer names the group and nothing has resolved it.
    let for_b = effective_servable_groups(state.clone(), "device-b", &group, &cache);
    assert!(for_b.is_empty(), "sanity: device-a's authorization introduces the group");

    // device-a, judged as if it had none, must not inherit device-b's refusal.
    let for_a = effective_servable_groups(state, "device-a", &group, &cache);
    assert_eq!(for_a, group, "device-a was withdrawn by device-b's cached answer");
}
