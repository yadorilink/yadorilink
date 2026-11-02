//! Publishes the native deltas a refused flush left pending.
//!
//! A native delta is sent to a peer only once a checkpoint from the coordination plane
//! covers it (`native_checkpoint_flush`). A flush runs when the plane connection is
//! (re)established, when the verified policy advances and after every local commit; one the
//! plane refuses or does not answer leaves the deltas pending, and none of those moments
//! has to come again. The plane connection can outlive a short outage (it need not drop
//! while the network is cut), and the device may make no further edit. The deltas then stay
//! local for good: the peers never learn of them, neither a concurrent edit of the same
//! path (no conflict copy is ever made) nor a plain change.
//!
//! A refused flush therefore arms this task ([`DaemonState::publication_retry`]), which
//! flushes every group again after [`INITIAL_DELAY`] and doubles the delay up to
//! [`MAX_DELAY`] while any group is still refused. Nothing runs while nothing was refused.

use std::sync::Arc;
use std::time::Duration;

use crate::daemon_state::DaemonState;

/// The delay before the first retry of a refused flush.
pub(crate) const INITIAL_DELAY: Duration = Duration::from_secs(1);

/// The longest delay between two retries: the time a device that was cut off waits, at most, to
/// publish after the network returns. A retry costs one local read and one request.
pub(crate) const MAX_DELAY: Duration = Duration::from_secs(15);

/// Runs for the life of the daemon.
pub(crate) async fn run(state: Arc<DaemonState>) {
    let mut delay = INITIAL_DELAY;
    loop {
        state.publication_retry.notified().await;
        loop {
            tokio::time::sleep(delay).await;
            if !retry_once(&state).await {
                delay = INITIAL_DELAY;
                break;
            }
            delay = (delay * 2).min(MAX_DELAY);
        }
    }
}

/// Flushes every active group once; whether any flush was refused again.
async fn retry_once(state: &DaemonState) -> bool {
    let Ok(links) = state.replica_coordinator.link_repository().list_links() else {
        return true;
    };
    let mut groups: Vec<String> = links
        .into_iter()
        .filter(|link| !link.paused && !link.orphaned)
        .map(|link| link.group_id)
        .collect();
    groups.sort();
    groups.dedup();
    let mut again = false;
    for group in groups {
        again |= state.flush_group_publication(&group).await;
    }
    again
}

#[cfg(test)]
mod tests;
