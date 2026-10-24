//! Waits until a device's own local capture has nothing pending or in flight.
//!
//! On Windows a directory cannot be renamed or removed while any file below it is open, and the
//! daemon opens files transiently (for one, while it hashes the echo of a write). A test that
//! renames or removes a directory right after an index wait would race those opens, so every such
//! test calls [`wait_quiescent`] first.
//!
//! A barrier file is written and waited on until it is captured, which proves the watcher has
//! delivered every earlier event to the debounce accumulator (the channel is ordered). The
//! barrier is then removed and its deletion captured the same way, so it leaves no row that
//! postdates the caller's next step. Finally the accumulator is drained into the index and the
//! dirty journal must be empty.

use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_replica_domain::session_state::VersionState;

use super::wait_until_with_context;

const QUIESCENCE_TIMEOUT: Duration = Duration::from_secs(90);

/// Waits until the link of `group_id` rooted at `root` has captured everything the operating
/// system reported so far and holds nothing pending.
#[allow(dead_code)]
pub async fn wait_quiescent(root: &Path, state: &DaemonState, group_id: &str) {
    static BARRIERS: AtomicU32 = AtomicU32::new(0);
    let barrier = format!("watcher-barrier-{}.txt", BARRIERS.fetch_add(1, Ordering::Relaxed));
    let live = || {
        state
            .replica_coordinator
            .sqlite()
            .dag_list_versions(group_id, &barrier)
            .unwrap_or_default()
            .iter()
            .any(|v| v.state == VersionState::Current && !v.deleted)
    };

    std::fs::write(root.join(&barrier), "b").unwrap();
    wait_until_with_context(&live, QUIESCENCE_TIMEOUT, || format!("{barrier} was never captured"))
        .await;
    std::fs::remove_file(root.join(&barrier)).unwrap();
    wait_until_with_context(
        || !live(),
        QUIESCENCE_TIMEOUT,
        || format!("the removal of {barrier} was never captured"),
    )
    .await;
    yadorilink_daemon::test_support::drain_pending_local_changes(state, group_id).await.unwrap();
    // A batch the executor already took is journaled until it is captured.
    wait_until_with_context(
        || {
            state
                .replica_coordinator
                .dirty_path_repository()
                .list_dirty_paths(group_id)
                .is_ok_and(|dirty| dirty.is_empty())
        },
        QUIESCENCE_TIMEOUT,
        || "capture still pending".to_string(),
    )
    .await;
}
