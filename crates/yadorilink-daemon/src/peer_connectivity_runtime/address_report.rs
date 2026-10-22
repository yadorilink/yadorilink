//! Publishes this device's iroh address to the coordination plane.
//!
//! The address comes from the iroh endpoint itself: iroh gathers direct
//! addresses, learns its home relay, traverses NATs and picks paths, and
//! announces every change through its address lookup, which lands in
//! [`PeerConnectivityRuntime::local_substrate_reachability`](super::PeerConnectivityRuntime).
//! This device only forwards that snapshot to the plane, so peers that are
//! not on the same network can find it. Nothing here discovers addresses of
//! its own.

use std::time::Duration;

use tokio::sync::watch;

use crate::coordination_client::{self, SubstrateReachability};

/// First delay after a failed report, doubling to [`REPORT_RETRY_MAX`].
/// Small enough that a momentary blip costs almost nothing, bounded so a
/// plane that is down does not become a busy loop.
const REPORT_RETRY_MIN: Duration = Duration::from_secs(1);
/// Ceiling for that backoff. Not a heartbeat: reached only while reports are
/// FAILING, and abandoned the moment one succeeds.
const REPORT_RETRY_MAX: Duration = Duration::from_secs(60);

/// Reports this device's iroh address to the coordination plane whenever it
/// changes, for as long as `address` has a sender.
///
/// Nothing is reported until the endpoint has published an address once:
/// "not yet known" is not the claim "reachable nowhere", and the plane keeps
/// what it has until it is told something.
pub async fn report_own_address(
    coordination_addr: String,
    auth: yadorilink_fapi_client::CoordinationAuth,
    device_id: String,
    mut address: watch::Receiver<Option<SubstrateReachability>>,
) {
    let mut retry_delay = REPORT_RETRY_MIN;
    loop {
        let current = address.borrow_and_update().clone();
        let Some(current) = current else {
            if address.changed().await.is_err() {
                return;
            }
            continue;
        };
        let published = coordination_client::report_endpoint(
            &coordination_addr,
            &auth,
            device_id.clone(),
            &current,
        )
        .await;

        // A failed report is not a lost one. The plane is the only way a peer
        // off this network learns where this device answers, and an address
        // that never changes again produces no further wake -- so a single
        // coordination blip would otherwise leave this device unreachable.
        //
        // What is retried is the LATEST address, never a queue of historical
        // ones: if the address moves while retrying, the newer snapshot
        // replaces the pending one and the older is never sent.
        if !published {
            retry_delay = (retry_delay * 2).min(REPORT_RETRY_MAX);
            tokio::select! {
                // A newer snapshot supersedes what failed; send it at once --
                // the backoff is for a plane that is failing, not for state
                // that has moved on.
                changed = address.changed() => {
                    if changed.is_err() { return; }
                    retry_delay = REPORT_RETRY_MIN;
                }
                () = tokio::time::sleep(retry_delay) => {}
            }
            continue;
        }
        // Published. Back to waiting on the endpoint -- this must not become
        // a heartbeat once the plane is healthy.
        retry_delay = REPORT_RETRY_MIN;
        if address.changed().await.is_err() {
            return;
        }
    }
}
