#![cfg(test)]

use std::collections::HashMap;
use std::sync::Arc;

use yadorilink_fs_platform::ignore_patterns::IgnoreRulesStore;
use yadorilink_local_storage::SegmentBlockStore;

use super::types::IGNORE_SET_REFRESH_INTERVAL;
use super::LocalConvergenceExecutor;
use crate::replica_coordinator::ReplicaCoordinator;

const GROUP: &str = "ignore-set-liveness-group";

/// The executor alone. The ignore-set cache is its own state and no part of
/// this test reaches the wire, so there is no session here: the version of
/// this fixture that built one only did so because the cache used to live
/// behind a session accessor.
fn harness() -> (Arc<LocalConvergenceExecutor>, IgnoreRulesStore) {
    let root = tempfile::tempdir().unwrap();
    let state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    state.link_repository().add_link(&root.path().to_string_lossy(), GROUP).unwrap();
    let store: Arc<dyn yadorilink_peer_session::ports::BlockContentStore> =
        Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let ports = crate::test_support::peer_session_fixture::ExecutorPorts::permissive();
    let rules = IgnoreRulesStore::new(tempfile::tempdir().unwrap().keep());
    let convergence = LocalConvergenceExecutor::new(
        state,
        "device-a".to_string(),
        ports.root_commit_authority_provider.clone(),
        ports.pending_local_change_flush.clone(),
        HashMap::from([(GROUP.to_string(), root.path().to_path_buf())]),
        store,
        ports.block_write_activity_provider.clone(),
        super::HeadroomPolicy::disabled(),
        rules.clone(),
    );
    // Held for the test's length: the link's root must exist.
    std::mem::forget(root);
    (convergence, rules)
}

/// GREEN: once the cached entry ages past `IGNORE_SET_REFRESH_INTERVAL`,
/// an ignore-rules edit written after session construction takes
/// effect without reconstructing the session.
#[test]
fn a_stale_cached_entry_reloads_and_picks_up_an_ignore_rules_edit() {
    let (convergence, rules) = harness();

    assert!(
        !convergence.is_locally_ignored(GROUP, "secret.txt"),
        "sanity: nothing is ignored before any rules exist"
    );

    rules.write(GROUP, "secret.txt\n").unwrap();

    // Still within the freshness window -- the edit must not be visible
    // yet, or this test would not be exercising the reload path at all.
    assert!(
        !convergence.is_locally_ignored(GROUP, "secret.txt"),
        "an edit must not appear before the cached entry goes stale"
    );

    convergence.rewind_ignore_set_cache_for_tests(
        GROUP,
        IGNORE_SET_REFRESH_INTERVAL + std::time::Duration::from_secs(1),
    );

    assert!(
        convergence.is_locally_ignored(GROUP, "secret.txt"),
        "an ignore-rules edit must take effect once the cached entry goes stale, \
         without rebuilding the session"
    );
}

/// Rules that can no longer be read keep the set already in force: falling back to the defaults
/// would let paths the rules excluded be projected.
#[test]
fn unreadable_rules_keep_the_previous_set_in_force() {
    let (convergence, rules) = harness();
    rules.write(GROUP, "secret.txt\n").unwrap();
    convergence.rewind_ignore_set_cache_for_tests(
        GROUP,
        IGNORE_SET_REFRESH_INTERVAL + std::time::Duration::from_secs(1),
    );
    assert!(convergence.is_locally_ignored(GROUP, "secret.txt"));

    std::fs::write(rules.path(GROUP), "ok\nbad//line\n").unwrap();
    convergence.rewind_ignore_set_cache_for_tests(
        GROUP,
        IGNORE_SET_REFRESH_INTERVAL + std::time::Duration::from_secs(1),
    );

    assert!(
        convergence.is_locally_ignored(GROUP, "secret.txt"),
        "an unusable rules file must not widen what is projected"
    );
}
