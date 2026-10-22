//! Production custody confirmer: acquires the responder's durable custody
//! lease via `DaemonState::acquire_custody_lease_via_peer`. The
//! eviction sweep is synchronous, so this bridges to the async query with
//! `block_in_place`, guarded the same way as every other `block_in_place`
//! call site in this crate (see `confirms_present`'s doc comment for why
//! this one can't share the crate's `run_blocking_sweep_offloaded` helper).
//! Holds a weak reference so it never keeps the daemon alive.
//!
//! Lives here, not in `durability_service.rs`, so that module never depends
//! on `DaemonState` -- this is the one adapter allowed to know both sides.

use std::sync::Weak;

use yadorilink_replica_domain::file::VersionBlock;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_engine::custody::CustodyStamp;
use yadorilink_sync_sqlite::remote_custody_hold::HoldKey;

use crate::daemon_state::DaemonState;
use crate::durability_service::CustodyConfirmer;

pub(crate) struct P2pCustodyConfirmer {
    state: Weak<DaemonState>,
}

impl P2pCustodyConfirmer {
    pub(crate) fn new(state: &std::sync::Arc<DaemonState>) -> Self {
        Self { state: std::sync::Arc::downgrade(state) }
    }
}

impl CustodyConfirmer for P2pCustodyConfirmer {
    // The caller, `yadorilink_replica_engine::custody::verify_reclaim_custody`, is
    // reachable now that `REMOTE_CUSTODY_LEASES_SUPPORTED` is `true`. A non-multi-thread
    // runtime fails closed to `None` below (no confirmation, no reclaim).
    // `block_in_place` panics if called on a current-thread tokio runtime,
    // so the offload path below can only be taken when a *multi-threaded*
    // runtime is actually current -- the same guard used at every other
    // `block_in_place` call site in this crate (see
    // `daemon_state::run_blocking_sweep_offloaded`'s doc comment for the
    // full list). This site can't reuse that shared helper: the helper's
    // non-offloaded branch just runs the same synchronous closure inline,
    // but there is no synchronous implementation of a peer query to fall
    // back to here -- `confirms_present` must return synchronously, and the
    // only way to answer it inline on a non-multi-thread runtime would be
    // another blocking call (e.g. a bare `block_on`), which panics for the
    // same reason `block_in_place` does. So the non-multi-thread branch
    // can't do the work at all, and fails closed: `None` is "no custody", so nothing is
    // evicted from the working tree's blocks. The sync-over-async bridge is a
    // known limitation; replacing it does not change the fail-closed outcome.
    fn confirms_present(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        let state = self.state.upgrade()?;
        let group_id = group_id.to_string();
        let path = path.to_string();
        let version_hash = *version_hash;
        let blocks = blocks.to_vec();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(move || {
                    tokio::runtime::Handle::current().block_on(async move {
                        state
                            .acquire_custody_lease_via_peer(&group_id, &path, version_hash, &blocks)
                            .await
                    })
                })
            }
            _ => {
                tracing::error!(
                    group_id,
                    path,
                    "P2pCustodyConfirmer::confirms_present called off a non-multi-thread tokio \
                     runtime; this should be unreachable today -- block_in_place would panic \
                     here, so reporting no custody confirmation instead of blocking"
                );
                None
            }
        }
    }

    fn confirmation_still_valid(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        stamp: &CustodyStamp,
    ) -> bool {
        let Some(state) = self.state.upgrade() else {
            return false;
        };
        // The lease must still be one this device records as granted: a stamp
        // whose hold was released (or never recorded) backs nothing.
        let hold = HoldKey {
            group_id: group_id.to_string(),
            path: path.to_string(),
            version_hash: version_hash.0,
            peer_id: stamp.peer_id().to_string(),
        };
        let granted = state
            .replica_coordinator
            .remote_custody_hold_repository()
            .is_granted(&hold)
            .unwrap_or(false);
        granted
            && state.authority.membership_generation() == stamp.membership_generation()
            && state.peer_may_hold_custody(stamp.peer_id(), group_id)
    }
}
