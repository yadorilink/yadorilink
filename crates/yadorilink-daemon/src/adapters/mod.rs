//! Concrete implementations of `application`'s ports, plus the composition
//! root (`build_application_services`) that wires them together from a real
//! `Arc<DaemonState>`. Deliberately a SIBLING of `application`, not nested
//! under it: `application` owns the port TRAITS; it must never appear to
//! own their implementations too, or the dependency direction this whole
//! module tree exists to enforce (`application` -> ports only, adapters ->
//! application + concrete infrastructure) would be backwards for anyone
//! reading the tree alone.
//!
//! `app.rs` calls this once per daemon and shares the result between the
//! recovery job and the control socket's `ControlContext`.

pub mod block_store_ports;
mod coordination;
mod persistence;
pub(crate) mod query;
pub mod runtime;

use std::sync::Arc;

use crate::application::{
    ApplicationServices, EnrollmentRecoveryService, EnrollmentService, LinkLifecycleService,
    ReplicaMembershipService, ReplicaRoleService, VersionRestoreService,
};
use crate::daemon_state::DaemonState;
use crate::queries::link_status::LinkStatusQueryService;
use crate::queries::QueryServices;

pub(crate) fn build_application_services(state: Arc<DaemonState>) -> Arc<ApplicationServices> {
    let controller =
        Arc::new(runtime::link_runtime_controller::LinkRuntimeController::new(state.clone()));

    let link_lifecycle = Arc::new(LinkLifecycleService::new(
        Arc::new(runtime::link_lifecycle::DaemonLinkRepositoryAdapter::new(state.clone())),
        Arc::new(runtime::link_lifecycle::DaemonLinkWatcherAdapter::new(
            state.clone(),
            controller.clone(),
        )),
    ));

    let enrollment_repository =
        Arc::new(persistence::enrollment::SyncStateEnrollmentRepository::new(
            state.replica_coordinator.clone(),
        ));
    let enrollment_coordination =
        Arc::new(coordination::enrollment::HttpEnrollmentCoordination::new(state.clone()));
    let enrollment_link = Arc::new(runtime::enrollment_link::DaemonEnrollmentLinkAdapter::new(
        state.clone(),
        link_lifecycle.clone(),
        controller.clone(),
    ));
    let enrollment_attempts =
        Arc::new(runtime::enrollment_attempts::DaemonEnrollmentAttemptTracker::new(state.clone()));

    let enrollment = Arc::new(EnrollmentService::new(
        state.device_id.clone(),
        enrollment_repository.clone(),
        enrollment_coordination.clone(),
        enrollment_link.clone(),
    ));
    let enrollment_recovery = Arc::new(EnrollmentRecoveryService::new(
        enrollment_repository,
        enrollment_coordination,
        enrollment_link,
        enrollment_attempts,
    ));

    let materialization =
        Arc::new(runtime::materialization::DaemonMaterializationAdapter::new(state.clone()));

    let membership_repository =
        Arc::new(persistence::membership::SyncStateMembershipRepository::new(state.clone()));
    let membership_coordination =
        Arc::new(coordination::membership::HttpMembershipCoordination::new(state.clone()));
    let handoff_tickets =
        Arc::new(runtime::handoff_ticket::DaemonHandoffTicketAdapter::new(state.clone()));
    let replica_readiness =
        Arc::new(runtime::replica_readiness::DaemonReplicaReadinessAdapter::new(state.clone()));
    let membership = Arc::new(ReplicaMembershipService::new(
        state.device_id.clone(),
        membership_repository,
        membership_coordination,
        handoff_tickets,
        replica_readiness,
    ));

    let group_admin =
        Arc::new(coordination::group_admin::HttpGroupAdministration::new(state.clone()));

    let replica_role_repository =
        Arc::new(persistence::replica_role::SyncStateReplicaRoleRepository::new(state.clone()));
    let role_loss_journal =
        Arc::new(runtime::role_loss_journal::DaemonRoleLossJournal::new(state.clone()));
    let handoff_readiness =
        Arc::new(runtime::handoff_readiness::DaemonHandoffReadinessAdapter::new(state.clone()));
    let role_loss_coordination =
        Arc::new(coordination::role_loss::HttpRoleLossCoordination::new(state.clone()));
    let link_runtime =
        Arc::new(runtime::link_watch::DaemonLinkRuntimeAdapter::new(controller.clone()));
    let on_demand_capability = Arc::new(
        runtime::on_demand_capability::DaemonOnDemandCapabilityAdapter::new(state.clone()),
    );
    let custody_handoff =
        Arc::new(runtime::custody_handoff::DaemonCustodyLeaseHandoffAdapter::new(state.clone()));
    let replica_role = Arc::new(ReplicaRoleService::new(
        state.device_id.clone(),
        replica_role_repository,
        role_loss_journal,
        handoff_readiness,
        role_loss_coordination,
        link_runtime,
        on_demand_capability,
        custody_handoff,
    ));

    let pause_resume = Arc::new(runtime::runtime_control::DaemonPauseResumeAdapter::new(
        state.clone(),
        controller.clone(),
    ));
    let gc = Arc::new(runtime::runtime_control::DaemonGcAdapter::new(state.clone()));
    let preserved = Arc::new(runtime::preserved::DaemonPreservedAdapter::new(state.clone()));
    let lifecycle = Arc::new(runtime::runtime_control::DaemonLifecycleAdapter::new(state.clone()));
    let durability = Arc::new(runtime::handoff::DaemonDurabilityCommandAdapter::new(state.clone()));
    let handoff = Arc::new(runtime::handoff::DaemonHandoffCommandAdapter::new(state.clone()));
    let version_restore = Arc::new(VersionRestoreService::new(Arc::new(
        runtime::version_restore::DaemonVersionRestoreAdapter::new(state.clone()),
    )));
    let governance = Arc::new(runtime::governance::DaemonGovernanceCommandAdapter::new(
        state.governance_config.clone(),
        state.rate_limiters.clone(),
        state.block_store.clone(),
    ));
    let reporting =
        Arc::new(runtime::reporting::DaemonReportingCommandAdapter::new(state.reporting.clone()));
    let update = Arc::new(runtime::update::DaemonUpdateCommandAdapter::new(state.clone()));

    let send_transfer = Arc::new(crate::send_transfer::SendTransferService::new(state.clone()));
    let nas_admin = Arc::new(crate::nas_admin_bridge::NasAdminSessions::new(&state));
    let rewind = Arc::new(crate::rewind::RewindService::new(state.clone()));

    Arc::new(ApplicationServices {
        enrollment,
        enrollment_recovery,
        materialization,
        membership,
        group_admin,
        replica_role,
        pause_resume,
        gc,
        preserved,
        lifecycle,
        durability,
        handoff,
        version_restore,
        governance,
        reporting,
        update,
        link_lifecycle,
        send_transfer,
        nas_admin,
        rewind,
    })
}

pub(crate) fn build_query_services(state: Arc<DaemonState>) -> Arc<QueryServices> {
    let health = Arc::new(crate::queries::health::HealthQueryService::new(
        state.telemetry.clone(),
        state.peer_connectivity.clone(),
    ));
    let diagnostics = Arc::new(crate::queries::diagnostics::DiagnosticsQueryService::new(
        state.telemetry.clone(),
        state.replica_coordinator.clone(),
        state.device_id.clone(),
        state.links.clone(),
    ));
    let update_status = Arc::new(crate::queries::update_status::UpdateStatusQueryService::new(
        state.update_manager.clone(),
    ));
    let link_status_reader =
        Arc::new(query::link_status::DaemonLinkStatusReader::new(state.clone()));
    let link_status = Arc::new(LinkStatusQueryService::new(link_status_reader));
    let runtime_status = Arc::new(crate::queries::runtime_status::RuntimeStatusQueryService::new(
        link_status.clone(),
        update_status.clone(),
        state.peer_connectivity.clone(),
        state.telemetry.clone(),
        state.governance_config.clone(),
        state.block_store.clone(),
        state.gc.clone(),
        state.rate_limiters.clone(),
        state.replica_coordinator.clone(),
    ));
    let linked_path = Arc::new(crate::queries::linked_path::LinkedPathResolver::new(
        state.replica_coordinator.clone(),
    ));
    let file_history = Arc::new(crate::queries::file_history::FileHistoryQueryService::new(
        state.replica_coordinator.clone(),
        linked_path.clone(),
    ));
    let governance = Arc::new(crate::queries::governance::GovernanceQueryService::new(
        state.governance_config.clone(),
    ));
    let reporting =
        Arc::new(crate::queries::reporting::ReportingQueryService::new(state.reporting.clone()));
    let coordination_config =
        Arc::new(query::recovery::DaemonCoordinationConfig::new(state.clone()));
    let recovery = Arc::new(crate::queries::recovery::RecoveryQueryService::new(
        state.replica_coordinator.clone(),
        coordination_config,
    ));

    let diagnostics_bundle =
        Arc::new(crate::queries::diagnostics_bundle::DiagnosticsBundleQueryService::new(
            Arc::new(query::diagnostics_bundle::DaemonRuntimeDiagnostics::new(
                state.clone(),
                link_status.clone(),
                runtime_status.clone(),
                state.governance_config.clone(),
            )),
            Arc::new(query::diagnostics_bundle::DaemonHealthDiagnostics::new(health.clone())),
            Arc::new(query::diagnostics_bundle::DaemonUpdateDiagnostics::new(
                update_status.clone(),
            )),
            Arc::new(query::diagnostics_bundle::DaemonConfigurationDiagnostics::new(
                update_status.clone(),
            )),
            Arc::new(query::diagnostics_bundle::DaemonLogDiagnostics::new(state.reporting.clone())),
        ));

    let handoff_readiness =
        Arc::new(crate::queries::handoff_readiness::HandoffReadinessQueryService::new(Arc::new(
            query::handoff_readiness::DaemonHandoffReadinessReader::new(state.clone()),
        )));

    let inbox = Arc::new(crate::send_transfer::InboxQueries::new(state.clone()));

    let rewind = Arc::new(crate::rewind::RewindQueries::new(state.clone()));

    Arc::new(QueryServices {
        link_status,
        health,
        diagnostics,
        runtime_status,
        linked_path,
        file_history,
        governance,
        reporting,
        recovery,
        diagnostics_bundle,
        handoff_readiness,
        update_status,
        inbox,
        rewind,
    })
}

#[cfg(test)]
mod ports_reachability;
