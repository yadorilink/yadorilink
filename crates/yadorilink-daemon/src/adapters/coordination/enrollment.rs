//! HTTP-backed [`EnrollmentCoordination`] -- the only place `application`'s
//! enrollment saga reaches the coordination plane, via
//! `crate::coordination_client`'s own prepare/activate/cancel calls.
//! Resolves the coordination address/token live from `DaemonState` on
//! every call (never cached), matching every other coordination-client
//! caller in this crate -- see `CoordinationClientConfig`'s own doc
//! comment for when it is (and isn't) set.

use std::sync::Arc;

use crate::application::model::{
    EnrollmentActivationResult, EnrollmentCancellationResult, EnrollmentPrepareResult,
};
use crate::application::ports::{BoxFuture, EnrollmentCoordination};
use crate::coordination_client::{
    self, ActivateOutcome, EnrollmentCancelOutcome, EnrollmentPrepareOutcome,
};
use crate::daemon_state::DaemonState;

pub(crate) struct HttpEnrollmentCoordination {
    state: Arc<DaemonState>,
}

impl HttpEnrollmentCoordination {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

const NOT_CONFIGURED_DETAIL: &str = "coordination-plane address/access token not configured";

impl EnrollmentCoordination for HttpEnrollmentCoordination {
    fn is_configured(&self) -> bool {
        self.state.coordination_client_config().is_some()
    }

    fn prepare_create<'a>(
        &'a self,
        operation_id: &'a str,
        group_name: &'a str,
        device_id: &'a str,
        storage_mode: &'a str,
    ) -> BoxFuture<'a, EnrollmentPrepareResult> {
        Box::pin(async move {
            let Some(config) = self.state.coordination_client_config() else {
                return EnrollmentPrepareResult::Ambiguous {
                    detail: NOT_CONFIGURED_DETAIL.to_string(),
                };
            };
            let outcome = coordination_client::prepare_create(
                &config.addr,
                &config.auth,
                operation_id,
                group_name,
                device_id,
                storage_mode,
            )
            .await;
            prepare_result(outcome)
        })
    }

    fn prepare_join<'a>(
        &'a self,
        operation_id: &'a str,
        group_id: &'a str,
        device_id: &'a str,
        storage_mode: &'a str,
    ) -> BoxFuture<'a, EnrollmentPrepareResult> {
        Box::pin(async move {
            let Some(config) = self.state.coordination_client_config() else {
                return EnrollmentPrepareResult::Ambiguous {
                    detail: NOT_CONFIGURED_DETAIL.to_string(),
                };
            };
            let outcome = coordination_client::prepare_join(
                &config.addr,
                &config.auth,
                operation_id,
                group_id,
                device_id,
                storage_mode,
            )
            .await;
            prepare_result(outcome)
        })
    }

    fn activate_create<'a>(
        &'a self,
        group_id: &'a str,
        operation_id: &'a str,
    ) -> BoxFuture<'a, EnrollmentActivationResult> {
        Box::pin(async move {
            let Some(config) = self.state.coordination_client_config() else {
                return EnrollmentActivationResult::TransientFailure {
                    detail: NOT_CONFIGURED_DETAIL.to_string(),
                };
            };
            let outcome = coordination_client::activate_create(
                &config.addr,
                &config.auth,
                group_id,
                operation_id,
            )
            .await;
            activation_result(outcome)
        })
    }

    fn activate_join<'a>(
        &'a self,
        group_id: &'a str,
        operation_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, EnrollmentActivationResult> {
        Box::pin(async move {
            let Some(config) = self.state.coordination_client_config() else {
                return EnrollmentActivationResult::TransientFailure {
                    detail: NOT_CONFIGURED_DETAIL.to_string(),
                };
            };
            let outcome = coordination_client::activate_join(
                &config.addr,
                &config.auth,
                group_id,
                operation_id,
                device_id,
            )
            .await;
            activation_result(outcome)
        })
    }

    fn cancel_create<'a>(
        &'a self,
        group_id: &'a str,
        operation_id: &'a str,
    ) -> BoxFuture<'a, EnrollmentCancellationResult> {
        Box::pin(async move {
            let Some(config) = self.state.coordination_client_config() else {
                return EnrollmentCancellationResult::Ambiguous {
                    detail: NOT_CONFIGURED_DETAIL.to_string(),
                };
            };
            let outcome = coordination_client::cancel_create_classified(
                &config.addr,
                &config.auth,
                group_id,
                operation_id,
            )
            .await;
            cancellation_result(outcome)
        })
    }

    fn cancel_join<'a>(
        &'a self,
        group_id: &'a str,
        operation_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, EnrollmentCancellationResult> {
        Box::pin(async move {
            let Some(config) = self.state.coordination_client_config() else {
                return EnrollmentCancellationResult::Ambiguous {
                    detail: NOT_CONFIGURED_DETAIL.to_string(),
                };
            };
            let outcome = coordination_client::cancel_join_classified(
                &config.addr,
                &config.auth,
                group_id,
                operation_id,
                device_id,
            )
            .await;
            cancellation_result(outcome)
        })
    }

    fn prepare_invite_accept<'a>(
        &'a self,
        operation_id: &'a str,
        code: &'a str,
        device_id: &'a str,
        storage_mode: &'a str,
    ) -> BoxFuture<'a, EnrollmentPrepareResult> {
        Box::pin(async move {
            let Some(config) = self.state.coordination_client_config() else {
                return EnrollmentPrepareResult::Ambiguous {
                    detail: NOT_CONFIGURED_DETAIL.to_string(),
                };
            };
            let outcome = coordination_client::prepare_invite_accept(
                &config.addr,
                &config.auth,
                operation_id,
                code,
                device_id,
                storage_mode,
            )
            .await;
            prepare_result(outcome)
        })
    }

    fn activate_invite_accept<'a>(
        &'a self,
        group_id: &'a str,
        operation_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, EnrollmentActivationResult> {
        Box::pin(async move {
            let Some(config) = self.state.coordination_client_config() else {
                return EnrollmentActivationResult::TransientFailure {
                    detail: NOT_CONFIGURED_DETAIL.to_string(),
                };
            };
            let outcome = coordination_client::activate_invite_accept(
                &config.addr,
                &config.auth,
                group_id,
                operation_id,
                device_id,
            )
            .await;
            activation_result(outcome)
        })
    }

    fn cancel_invite_accept<'a>(
        &'a self,
        group_id: &'a str,
        operation_id: &'a str,
        device_id: &'a str,
    ) -> BoxFuture<'a, EnrollmentCancellationResult> {
        Box::pin(async move {
            let Some(config) = self.state.coordination_client_config() else {
                return EnrollmentCancellationResult::Ambiguous {
                    detail: NOT_CONFIGURED_DETAIL.to_string(),
                };
            };
            let outcome = coordination_client::cancel_invite_accept_classified(
                &config.addr,
                &config.auth,
                group_id,
                operation_id,
                device_id,
            )
            .await;
            cancellation_result(outcome)
        })
    }

    fn mint_invite<'a>(
        &'a self,
        group_id: &'a str,
        role: Option<&'a str>,
        ttl_secs: Option<u64>,
        requires_approval: bool,
    ) -> BoxFuture<
        'a,
        Result<crate::application::model::MintedInvite, crate::application::model::MintInviteError>,
    > {
        Box::pin(async move {
            let Some(config) = self.state.coordination_client_config() else {
                return Err(crate::application::model::MintInviteError::Rejected(
                    NOT_CONFIGURED_DETAIL.to_string(),
                ));
            };
            coordination_client::mint_invite(
                &config.addr,
                &config.auth,
                group_id,
                &self.state.device_id,
                role,
                ttl_secs,
                requires_approval,
            )
            .await
        })
    }
}

fn prepare_result(outcome: EnrollmentPrepareOutcome) -> EnrollmentPrepareResult {
    match outcome {
        EnrollmentPrepareOutcome::Prepared { group_id } => {
            EnrollmentPrepareResult::Prepared { group_id }
        }
        EnrollmentPrepareOutcome::DefinitelyRejected(detail) => {
            EnrollmentPrepareResult::DefinitelyRejected { detail }
        }
        EnrollmentPrepareOutcome::TermsConsentRequired(detail) => {
            EnrollmentPrepareResult::TermsConsentRequired { detail }
        }
        EnrollmentPrepareOutcome::InviteRefused { reason, detail } => {
            EnrollmentPrepareResult::InviteRefused { reason, detail }
        }
        EnrollmentPrepareOutcome::Conflict(detail) => EnrollmentPrepareResult::Conflict { detail },
        EnrollmentPrepareOutcome::Ambiguous(detail) => {
            EnrollmentPrepareResult::Ambiguous { detail }
        }
    }
}

fn activation_result(outcome: ActivateOutcome) -> EnrollmentActivationResult {
    match outcome {
        ActivateOutcome::Success => EnrollmentActivationResult::Activated,
        ActivateOutcome::AlreadyActive => EnrollmentActivationResult::AlreadyActive,
        ActivateOutcome::AwaitingApproval => EnrollmentActivationResult::AwaitingApproval,
        ActivateOutcome::Deleted => EnrollmentActivationResult::Deleted,
        ActivateOutcome::TransientFailure => EnrollmentActivationResult::TransientFailure {
            detail: "activation call did not return a clear terminal answer".to_string(),
        },
    }
}

fn cancellation_result(outcome: EnrollmentCancelOutcome) -> EnrollmentCancellationResult {
    match outcome {
        EnrollmentCancelOutcome::Confirmed => EnrollmentCancellationResult::Confirmed,
        EnrollmentCancelOutcome::Conflict(detail) => {
            EnrollmentCancellationResult::Conflict { detail }
        }
        EnrollmentCancelOutcome::Ambiguous(detail) => {
            EnrollmentCancellationResult::Ambiguous { detail }
        }
    }
}
