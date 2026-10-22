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

    let result = effective_servable_groups(state, &raw_groups, &cache);
    assert!(result.is_empty());
}

/// A resolution miss populates the cache with its outcome, so a group
/// shared by many peers in one netmap-update pass is resolved once, not
/// once per peer sharing it.
#[tokio::test]
async fn effective_servable_groups_populates_the_validation_cache_on_a_miss() {
    let state = test_state();
    let raw_groups: HashSet<String> = HashSet::from(["group-y".to_string()]);
    let cache: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());

    let result = effective_servable_groups(state, &raw_groups, &cache);
    assert_eq!(result, raw_groups);
    assert_eq!(cache.lock().unwrap().get("group-y").copied(), Some(true));
}
