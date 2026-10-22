//! This crate's entire contribution to peer-applied mutation
//! ("ApplyPeerChange"). The actual mutation logic -- `materialize`,
//! `hydrate`, `hold`, and the rest of what happens when a peer's change is
//! applied -- lives in
//! `yadorilink_peer_session::peer_session::PeerSyncSession`, a different
//! crate this one depends on (never the reverse). What this crate DOES own
//! is the authority lookup `PeerSyncSession` calls through its injected
//! `RootCommitAuthorityProvider` seam: resolving a `group_id` to the SAME
//! per-link `RootLease` every other subsystem touching that link
//! (local-change capture, periodic/startup repair, the disk-reconcile
//! backstop) admits through, not a second independent one.
//! `PeerSyncSession` fails closed (`SyncError::NotFound`) when this
//! returns `None` -- no live link, no provider installed, or (in
//! production) the link is only `Starting`, not yet `Ready` -- never a
//! permissive fallback. Lives at the crate's top level, a sibling of
//! `link_runtime` rather than inside it: unlike that module tree's own
//! operations, this impl is `DaemonState`'s own (it needs the daemon-wide
//! link table and runtime registry directly, not a narrowed per-link
//! bundle), so it stays out of `link_runtime`'s own DaemonState-free
//! module tree.

use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_root_authority::root_commit::RootLease;

use crate::daemon_state::DaemonState;

impl yadorilink_peer_session::peer_session::RootCommitAuthorityProvider for DaemonState {
    /// Mirrors `capture_local_change::LinkFlushHandle`'s own lookup:
    /// resolves `group_id` to the SAME `RootLease` this link's
    /// `LocalChangeProcessor` and targeted flush/backstop paths already
    /// admit through, not a second independent one — a peer-applied
    /// mutation for a group this device is not actively linked (or
    /// watching) for gets no lease at all, and
    /// `PeerSyncSession::root_lease_for` turns that into a hard error
    /// rather than silently permitting the write.
    fn root_lease_for(&self, group_id: &str) -> Option<Arc<RootLease>> {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(lease) = self
            .test_root_commit_authorities
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(group_id)
        {
            return Some(lease.clone());
        }
        let local_path = match self.replica_coordinator.link_repository().list_links() {
            Ok(links) => links
                .into_iter()
                .find(|l| l.group_id == group_id)
                .and_then(|l| l.folder_path().map(str::to_string)),
            Err(e) => {
                tracing::warn!(error = %e, group_id, "failed to look up this group's local link");
                None
            }
        };
        let local_path = local_path?;
        self.links.runtime(&local_path).map(|runtime| runtime.root_lease().clone())
    }
}

#[cfg(any(test, feature = "test-support"))]
impl DaemonState {
    /// Registers an always-valid, `SyncRootLock`-less `RootLease` for
    /// `group_id`, consulted by `root_lease_for` before its normal
    /// `link_runtimes` lookup -- see `DaemonState::test_root_commit_
    /// authorities`'s own doc comment for why this exists. Call after
    /// `sync_state.add_link(...)` in a unit test that needs `hydration::
    /// hydrate_inner`/`evict`/`preflight_disk_pressure` (or any other
    /// caller of `root_lease_for`) to succeed without paying for a real
    /// `start_link_watch`.
    pub fn install_test_root_commit_authority(&self, group_id: &str) {
        self.test_root_commit_authorities
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(group_id.to_string(), Arc::new(RootLease::for_tests()));
    }

    /// Overrides the answer `adapters::build_application_services` wires
    /// into `ReplicaRoleService`'s `OnDemandCapabilityPort` for
    /// this daemon instance, in place of the real, unconditionally-`false`
    /// per-root decision of `provider_gate` (a plain root never allows it) -- see
    /// `test_on_demand_allowed`'s own doc comment for why a daemon integration
    /// test needs a per-daemon override. Call before `control_context::ControlContext::
    /// from_state`/`control_socket::unix_transport::serve` build this
    /// instance's `ApplicationServices` -- the override is read once, at
    /// that composition-root call, not polled per-request.
    pub fn set_test_on_demand_allowed(&self, connected: bool) {
        *self.test_on_demand_allowed.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some(connected);
    }
}

impl DaemonState {
    /// Same lookup as `RootCommitAuthorityProvider::root_lease_for` above,
    /// for this crate's own internal callers (the periodic GC/capacity-
    /// eviction/hydration sweeps in `gc.rs`/`hydration.rs`, and the
    /// per-link periodic repair pass in the daemon's own `LinkRuntimeController`) that are not a
    /// `PeerSyncSession` and so have no `root_lease_for` of their own to
    /// call. Fails closed with a real error (never a permissive fallback)
    /// when this device is not actively linked/watching `group_id` right
    /// now.
    pub(crate) fn root_lease_for(&self, group_id: &str) -> Result<Arc<RootLease>, SyncError> {
        use yadorilink_peer_session::peer_session::RootCommitAuthorityProvider;
        RootCommitAuthorityProvider::root_lease_for(self, group_id).ok_or_else(|| {
            SyncError::NotFound(format!(
                "no live root-commit authority for group {group_id} (no established link, or \
                 not actively watching)"
            ))
        })
    }
}
