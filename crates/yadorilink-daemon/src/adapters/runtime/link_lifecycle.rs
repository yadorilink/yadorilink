//! `SyncState`/`LinkRuntimeController`-backed [`LinkRepositoryPort`]/
//! [`LinkWatcherPort`].

use std::sync::Arc;

use crate::sync_error::SyncError;
use yadorilink_replica_domain::session_state::LinkRowWrite;

use crate::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use crate::application::ports::{
    BoxFuture, LinkRepositoryPort, LinkWatcherPort, PendingEnrollmentLinkCommand,
};
use crate::application::EnrollmentKind;
use crate::daemon_state::DaemonState;
use crate::error::DaemonError;

pub(crate) struct DaemonLinkRepositoryAdapter {
    state: Arc<DaemonState>,
}

impl DaemonLinkRepositoryAdapter {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl LinkRepositoryPort for DaemonLinkRepositoryAdapter {
    fn preflight_headroom_override_bytes(&self) -> Option<u64> {
        self.state.link_preflight_headroom_override()
    }

    fn live_link_paths_for_group(&self, group_id: &str) -> Result<Vec<String>, SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .live_link_paths_for_group(group_id)
            .map_err(SyncError::from)
    }

    fn live_link_keys_for_group(&self, group_id: &str) -> Result<Vec<String>, SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .live_link_key_vec_for_group(group_id)
            .map_err(SyncError::from)
    }

    fn list_link_paths_and_groups(&self) -> Result<Vec<(String, String)>, SyncError> {
        Ok(self
            .state
            .replica_coordinator
            .link_repository()
            .list_links()
            .map_err(SyncError::from)?
            .into_iter()
            .filter_map(|l| l.folder_path().map(|p| (p.to_string(), l.group_id.clone())))
            .collect())
    }

    fn commit_plain_link(
        &self,
        local_path: &str,
        group_id: &str,
    ) -> Result<LinkRowWrite, SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .add_link(local_path, group_id)
            .map_err(SyncError::from)
    }

    fn commit_link_with_pending_enrollment(
        &self,
        local_path: &str,
        group_id: &str,
        marker: &PendingEnrollmentLinkCommand,
        provider: Option<&crate::application::ports::ProviderLinkTarget>,
    ) -> Result<LinkRowWrite, SyncError> {
        let kind = match marker.kind {
            EnrollmentKind::Create => {
                yadorilink_replica_domain::session_state::EnrollmentKind::Create
            }
            EnrollmentKind::Join => yadorilink_replica_domain::session_state::EnrollmentKind::Join,
        };
        self.state
            .replica_coordinator
            .enrollment_repository()
            .add_link_with_pending_enrollment_and_begin_setup(
                local_path,
                group_id,
                &yadorilink_replica_domain::session_state::PendingEnrollment {
                    operation_id: marker.operation_id.clone(),
                    kind,
                    group_id: group_id.to_string(),
                    device_id: marker.device_id.clone(),
                    local_path: local_path.to_string(),
                },
                crate::daemon_state::now_unix(),
                provider
                    .map(|target| yadorilink_sync_sqlite::provider::ProviderLinkSpec {
                        kind: target.kind,
                        display_name: target.display_name.clone(),
                        empty_owner: target.empty_owner,
                        on_demand: target.on_demand,
                        creation_digest: target.creation_digest.clone(),
                    })
                    .as_ref(),
            )
            .map_err(SyncError::from)
    }

    fn undo_plain_link(
        &self,
        local_path: &str,
        group_id: &str,
        write: &LinkRowWrite,
    ) -> Result<&'static str, SyncError> {
        let undone = self
            .state
            .replica_coordinator
            .link_repository()
            .undo_link_row(local_path, group_id, write)
            .map_err(SyncError::from)?;
        // A row this attempt inserted is gone again: drop any custody
        // confirmation cached for its group, as `remove_link` does, so a
        // stale one can't be reused by a later relink. A restored row is
        // the earlier link, still live -- its cache entry stays valid.
        if matches!(write, LinkRowWrite::Inserted) {
            self.state.durability().clear_custody_confirmation(group_id);
        }
        Ok(undone)
    }

    fn rollback_local_setup_to_cancel_pending(
        &self,
        local_path: &str,
        group_id: &str,
        write: &LinkRowWrite,
        operation_id: &str,
        detail: &str,
    ) -> Result<&'static str, SyncError> {
        self.state
            .replica_coordinator
            .enrollment_repository()
            .rollback_local_setup_undoing_link_write(
                local_path,
                group_id,
                write,
                operation_id,
                detail,
                crate::daemon_state::now_unix(),
            )
            .map_err(SyncError::from)
    }

    fn mark_enrollment_activation_pending(&self, operation_id: &str) -> Result<bool, SyncError> {
        self.state
            .replica_coordinator
            .enrollment_repository()
            .mark_enrollment_activation_pending(operation_id, crate::daemon_state::now_unix())
            .map_err(SyncError::from)
    }

    fn mark_link_orphaned(&self, local_path: &str) -> Result<(), SyncError> {
        self.state
            .replica_coordinator
            .link_repository()
            .mark_link_orphaned(local_path)
            .map_err(SyncError::from)
    }
}

pub(crate) struct DaemonLinkWatcherAdapter {
    state: Arc<DaemonState>,
    controller: Arc<LinkRuntimeController>,
}

impl DaemonLinkWatcherAdapter {
    pub(crate) fn new(state: Arc<DaemonState>, controller: Arc<LinkRuntimeController>) -> Self {
        Self { state, controller }
    }
}

impl LinkWatcherPort for DaemonLinkWatcherAdapter {
    fn is_ready(&self, local_path: &str) -> bool {
        self.controller.is_ready(local_path)
    }

    fn is_registered(&self, local_path: &str) -> bool {
        self.state.links.has_entry(local_path)
    }

    fn start<'a>(
        &'a self,
        local_path: &'a str,
        group_id: &'a str,
        on_demand: bool,
    ) -> BoxFuture<'a, Result<(), DaemonError>> {
        Box::pin(async move {
            if on_demand {
                if !self.state.root_allows_on_demand(group_id) {
                    return Err(DaemonError::Config(
                        crate::provider_gate::ON_DEMAND_REFUSAL.to_string(),
                    ));
                }
                self.state
                    .replica_coordinator
                    .link_repository()
                    .set_materialization_policy(
                        local_path,
                        yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand,
                    )
                    .map_err(SyncError::from)?;
            }
            // Retention is a fixed built-in policy (10 versions / 30 days)
            // applied to every link, so there is nothing per-link to
            // configure here.
            self.controller.start(local_path.to_string(), group_id.to_string())?;
            // A new group here is what makes the next reconcile round productive.
            self.state.native_replication.wake_reconcile();
            Ok(())
        })
    }

    fn stop<'a>(&'a self, local_path: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(self.controller.stop(local_path))
    }
}

#[cfg(test)]
mod wake_tests {
    use super::*;
    use crate::application::{LinkCommand, LinkLifecycleService};

    /// Linking a folder wakes the native reconcile loops: the new group is what makes the next
    /// round productive.
    #[tokio::test]
    async fn linking_a_folder_wakes_the_reconcile_loops() {
        let store = Arc::new(
            yadorilink_local_storage::SegmentBlockStore::new(tempfile::tempdir().unwrap().keep())
                .unwrap(),
        );
        let sync_state =
            Arc::new(crate::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap());
        let state = DaemonState::new("device-a".into(), sync_state, store);
        state.set_device_signing_key(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
        let controller = Arc::new(LinkRuntimeController::new(state.clone()));
        let service = LinkLifecycleService::new(
            Arc::new(DaemonLinkRepositoryAdapter::new(state.clone())),
            Arc::new(DaemonLinkWatcherAdapter::new(state.clone(), controller)),
        );
        let wake = state.native_replication.subscribe_wake_for_test();
        assert!(!wake.has_changed().unwrap());
        let dir = tempfile::tempdir().unwrap();
        service
            .link(LinkCommand {
                local_path: dir.path().to_string_lossy().to_string(),
                group_id: "group-1".to_string(),
                on_demand: false,
                pending_enrollment: None,
                provider: None,
            })
            .await
            .unwrap();
        assert!(wake.has_changed().unwrap());
    }
}
