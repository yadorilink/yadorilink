//! HTTP-backed [`MembershipCoordination`] -- the coordination-plane request
//! building this crate's `coordination_client` module already implemented;
//! this adapter is the seam that lets `application` reach it without
//! depending on `crate::coordination_client`/`reqwest` directly.

use std::sync::Arc;

use yadorilink_replica_domain::session_state::MembershipCommitMode;

use crate::application::model::{
    HandoffCommitResult, MembershipCommitOutcome, MembershipCommitResult,
    MembershipOperationLookup, MembershipRemoteCommand,
};
use crate::application::ports::{BoxFuture, MembershipCoordination};
use crate::coordination_client::{RoleLossCommitOutcome, SendAuthorized};
use crate::daemon_state::{CoordinationClientConfig, DaemonState};

const NOT_CONFIGURED_DETAIL: &str = "local device identity is unavailable";

pub(crate) struct HttpMembershipCoordination {
    state: Arc<DaemonState>,
}

impl HttpMembershipCoordination {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    fn config(&self) -> Option<CoordinationClientConfig> {
        self.state.coordination_client_config().cloned()
    }
}

fn classify_status(status: reqwest::StatusCode, detail: String) -> MembershipCommitOutcome {
    if status == reqwest::StatusCode::CONFLICT {
        MembershipCommitOutcome::Conflict(detail)
    } else if status.is_client_error() {
        MembershipCommitOutcome::DefinitelyRejected(detail)
    } else {
        MembershipCommitOutcome::Ambiguous(detail)
    }
}

async fn classify_plain_remove_device(
    config: &CoordinationClientConfig,
    device_id: &str,
    operation_id: &str,
) -> MembershipCommitOutcome {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Body<'a> {
        operation_id: &'a str,
    }
    let response = match reqwest::Client::new()
        .delete(format!("{}/devices/{device_id}", config.addr))
        .json(&Body { operation_id })
        .send_authorized(&config.auth)
        .await
    {
        Ok(response) => response,
        Err(e) => {
            return MembershipCommitOutcome::Ambiguous(format!(
                "could not confirm the coordination-plane device removal: {e}"
            ));
        }
    };
    if response.status().is_success() {
        return MembershipCommitOutcome::Committed(MembershipCommitResult::NONE);
    }
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    classify_status(status, format!("remove device returned HTTP {status}: {text}"))
}

async fn classify_plain_revoke(
    config: &CoordinationClientConfig,
    group_id: &str,
    device_id: &str,
    operation_id: &str,
) -> MembershipCommitOutcome {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Body<'a> {
        device_id: &'a str,
        operation_id: &'a str,
    }
    let response = match reqwest::Client::new()
        .post(format!("{}/shares/groups/{group_id}/revoke", config.addr))
        .json(&Body { device_id, operation_id })
        .send_authorized(&config.auth)
        .await
    {
        Ok(response) => response,
        Err(e) => {
            return MembershipCommitOutcome::Ambiguous(format!(
                "could not confirm the coordination-plane revoke: {e}"
            ));
        }
    };
    if response.status().is_success() {
        return MembershipCommitOutcome::Committed(MembershipCommitResult::NONE);
    }
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    classify_status(status, format!("revoke device returned HTTP {status}: {text}"))
}

async fn commit_multi_group_removal(
    config: &CoordinationClientConfig,
    device_id: &str,
    command: &MembershipRemoteCommand,
    operation_id: &str,
) -> MembershipCommitOutcome {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct GroupEntry<'a> {
        group_id: &'a str,
        target_device_id: &'a str,
        lease_id: &'a str,
    }
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Body<'a> {
        groups: Vec<GroupEntry<'a>>,
        operation_id: &'a str,
    }
    let groups: Vec<GroupEntry> = command
        .group_ids
        .iter()
        .zip(command.target_device_ids.iter())
        .zip(command.lease_ids.iter())
        .map(|((group_id, target_device_id), lease_id)| GroupEntry {
            group_id,
            target_device_id,
            lease_id: lease_id.as_deref().unwrap_or_default(),
        })
        .collect();
    let response = match reqwest::Client::new()
        .post(format!("{}/devices/{device_id}/handoff-remove", config.addr))
        .json(&Body { groups, operation_id })
        .send_authorized(&config.auth)
        .await
    {
        Ok(response) => response,
        Err(e) => {
            return MembershipCommitOutcome::Ambiguous(format!(
                "could not confirm the coordination-plane lease-bound removal: {e}"
            ));
        }
    };
    if response.status().is_success() {
        return MembershipCommitOutcome::Committed(MembershipCommitResult::NONE);
    }
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    classify_status(status, format!("lease-bound device removal returned HTTP {status}: {text}"))
}

impl MembershipCoordination for HttpMembershipCoordination {
    fn is_configured(&self) -> bool {
        self.state.coordination_client_config().is_some()
    }

    fn fetch_eager_groups<'a>(
        &'a self,
        device_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<String>, String>> {
        Box::pin(async move {
            #[derive(serde::Deserialize)]
            struct Resp {
                #[serde(rename = "groupIds")]
                group_ids: Vec<String>,
            }
            let Some(config) = self.config() else {
                return Err(NOT_CONFIGURED_DETAIL.to_string());
            };
            let response = reqwest::Client::new()
                .get(format!("{}/devices/{device_id}/eager-groups", config.addr))
                .send_authorized(&config.auth)
                .await
                .map_err(|e| e.to_string())?;
            if !response.status().is_success() {
                return Err(format!("enumerate eager groups returned HTTP {}", response.status()));
            }
            response.json::<Resp>().await.map(|body| body.group_ids).map_err(|e| e.to_string())
        })
    }

    fn dispatch<'a>(
        &'a self,
        command: &'a MembershipRemoteCommand,
        operation_id: &'a str,
    ) -> BoxFuture<'a, MembershipCommitOutcome> {
        Box::pin(async move {
            let Some(config) = self.config() else {
                return MembershipCommitOutcome::Ambiguous(NOT_CONFIGURED_DETAIL.to_string());
            };
            match command.commit_mode {
                MembershipCommitMode::PlainRevoke => {
                    classify_plain_revoke(
                        &config,
                        &command.group_ids[0],
                        &command.removed_device_id,
                        operation_id,
                    )
                    .await
                }
                MembershipCommitMode::GuardedRevoke => {
                    match crate::coordination_client::commit_handoff_role_loss(
                        &config.addr,
                        &config.auth,
                        crate::coordination_client::RoleLossCommitRequest {
                            group_id: &command.group_ids[0],
                            source_device_id: &command.removed_device_id,
                            target_device_id: command.target_device_ids[0].as_str(),
                            lease_id: command.lease_ids[0].as_deref(),
                            action: "revoke",
                            operation_id,
                        },
                    )
                    .await
                    {
                        RoleLossCommitOutcome::Committed(result) => {
                            MembershipCommitOutcome::Committed(MembershipCommitResult {
                                handoff: Some(HandoffCommitResult {
                                    target_device_id: result.target_device_id,
                                    membership_generation: result.membership_generation,
                                    lease_id: result.lease_id,
                                }),
                            })
                        }
                        RoleLossCommitOutcome::DefinitelyRejected(detail) => {
                            MembershipCommitOutcome::DefinitelyRejected(detail)
                        }
                        RoleLossCommitOutcome::Conflict(detail) => {
                            MembershipCommitOutcome::Conflict(detail)
                        }
                        RoleLossCommitOutcome::Ambiguous(detail) => {
                            MembershipCommitOutcome::Ambiguous(detail)
                        }
                    }
                }
                MembershipCommitMode::PlainRemoveDevice => {
                    classify_plain_remove_device(&config, &command.removed_device_id, operation_id)
                        .await
                }
                MembershipCommitMode::HandoffRemoveDevice => {
                    commit_multi_group_removal(
                        &config,
                        &command.removed_device_id,
                        command,
                        operation_id,
                    )
                    .await
                }
            }
        })
    }

    fn query_operation<'a>(
        &'a self,
        operation_id: &'a str,
    ) -> BoxFuture<'a, Result<MembershipOperationLookup, String>> {
        Box::pin(async move {
            let Some(config) = self.config() else {
                return Err(NOT_CONFIGURED_DETAIL.to_string());
            };
            crate::coordination_client::query_membership_operation(
                &config.addr,
                &config.auth,
                operation_id,
            )
            .await
        })
    }

    fn resolve_edge<'a>(
        &'a self,
        edge_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<(String, String)>, String>> {
        Box::pin(async move {
            let Some(config) = self.config() else {
                return Err(NOT_CONFIGURED_DETAIL.to_string());
            };
            crate::coordination_client::resolve_edge(&config.addr, &config.auth, edge_id).await
        })
    }

    fn fetch_edge_state<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>, String>> {
        Box::pin(async move {
            let Some(config) = self.config() else {
                return Err(NOT_CONFIGURED_DETAIL.to_string());
            };
            crate::coordination_client::fetch_edge_state(
                &config.addr,
                &config.auth,
                group_id,
                device_id,
            )
            .await
        })
    }

    fn record_force_override_audit<'a>(
        &'a self,
        local_device_id: &'a str,
        target_device_id: &'a str,
        group_ids: &'a [String],
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            #[derive(serde::Serialize)]
            #[serde(rename_all = "camelCase")]
            struct Body<'a> {
                device_id: &'a str,
                action: &'a str,
                group_ids: &'a [String],
            }
            let Some(config) = self.config() else { return };
            let action = format!("membership removal (excluded_device_id={target_device_id})");
            let request = reqwest::Client::new()
                .post(format!("{}/audit/force-override", config.addr))
                .json(&Body { device_id: local_device_id, action: &action, group_ids })
                .send_authorized(&config.auth);
            if tokio::time::timeout(std::time::Duration::from_secs(5), request).await.is_err() {
                tracing::warn!(target_device_id, "force-override audit request timed out");
            }
        })
    }
}
