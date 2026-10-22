//! HTTP-backed [`RoleLossCoordination`].

use std::sync::Arc;

use crate::application::model::{RoleLossCommitOutcome, RoleLossCompensationOutcome};
use crate::application::ports::{BoxFuture, RoleLossCoordination};
use crate::daemon_state::DaemonState;

const NOT_CONFIGURED_DETAIL: &str = "local device identity is unavailable";

pub(crate) struct HttpRoleLossCoordination {
    state: Arc<DaemonState>,
}

impl HttpRoleLossCoordination {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl RoleLossCoordination for HttpRoleLossCoordination {
    fn is_configured(&self) -> bool {
        self.state.coordination_client_config().is_some()
    }

    fn commit_handoff_role_loss<'a>(
        &'a self,
        group_id: &'a str,
        source_device_id: &'a str,
        target_device_id: &'a str,
        lease_id: Option<&'a str>,
        action: &'a str,
        operation_id: &'a str,
    ) -> BoxFuture<'a, RoleLossCommitOutcome> {
        Box::pin(async move {
            let Some(config) = self.state.coordination_client_config().cloned() else {
                return RoleLossCommitOutcome::Ambiguous(NOT_CONFIGURED_DETAIL.to_string());
            };
            crate::coordination_client::commit_handoff_role_loss(
                &config.addr,
                &config.auth,
                crate::coordination_client::RoleLossCommitRequest {
                    group_id,
                    source_device_id,
                    target_device_id,
                    lease_id,
                    action,
                    operation_id,
                },
            )
            .await
        })
    }

    fn set_storage_mode<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
        mode: &'a str,
    ) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let Some(config) = self.state.coordination_client_config().cloned() else {
                return Err(NOT_CONFIGURED_DETAIL.to_string());
            };
            crate::coordination_client::set_storage_mode(
                &config.addr,
                &config.auth,
                group_id,
                device_id,
                mode,
            )
            .await
        })
    }

    fn compensate_handoff_role_loss<'a>(
        &'a self,
        group_id: &'a str,
        source_device_id: &'a str,
        target_device_id: &'a str,
        lease_id: &'a str,
        expected_membership_generation: Option<i64>,
    ) -> BoxFuture<'a, Result<RoleLossCompensationOutcome, String>> {
        Box::pin(async move {
            let Some(config) = self.state.coordination_client_config().cloned() else {
                return Err(NOT_CONFIGURED_DETAIL.to_string());
            };
            crate::coordination_client::compensate_handoff_role_loss(
                &config.addr,
                &config.auth,
                group_id,
                source_device_id,
                target_device_id,
                lease_id,
                expected_membership_generation,
            )
            .await
        })
    }
}
