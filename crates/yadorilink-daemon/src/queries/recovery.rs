//! `ListRecoveryOperations`/`ShowRecoveryOperation`'s read model --
//! strictly read-only, per `crate::recovery`'s own doc
//! comment. Depends on the coordination-plane address/token only through
//! `CoordinationConfigPort`, never on `DaemonState` or
//! `crate::coordination_client`'s concrete types directly, so this service
//! doesn't need to know how (or whether) a real daemon obtains that config.

use std::sync::Arc;

use crate::recovery::{RecoveryInventory, RecoveryOperationKey};
use crate::sync_error::SyncError;

use crate::recovery_diagnosis::StableDiagnosisOutcome;
use crate::recovery_evidence::WorkerEvidenceSource;
use crate::replica_coordinator::ReplicaCoordinator;

/// A source of this device's coordination-plane address + credential --
/// `None` when it isn't configured, matching
/// `DaemonState::coordination_client_config`'s own contract.
pub(crate) trait CoordinationConfigPort: Send + Sync {
    fn coordination_client_config(
        &self,
    ) -> Option<(String, yadorilink_fapi_client::CoordinationAuth)>;
}

pub(crate) enum DiagnoseOutcome {
    CoordinationNotConfigured,
    Diagnosis(Box<StableDiagnosisOutcome>),
}

pub(crate) struct RecoveryQueryService {
    // `crate::recovery::inventory` reads the three recovery journals off
    // `ReplicaCoordinator` directly -- `list()` below needs no other field.
    replica_coordinator: Arc<ReplicaCoordinator>,
    config: Arc<dyn CoordinationConfigPort>,
}

impl RecoveryQueryService {
    pub(crate) fn new(
        replica_coordinator: Arc<ReplicaCoordinator>,
        config: Arc<dyn CoordinationConfigPort>,
    ) -> Self {
        Self { replica_coordinator, config }
    }

    pub(crate) fn list(&self) -> Result<RecoveryInventory, SyncError> {
        crate::recovery::inventory(self.replica_coordinator.as_ref())
    }

    pub(crate) async fn diagnose(
        &self,
        key: &RecoveryOperationKey,
    ) -> Result<DiagnoseOutcome, SyncError> {
        let Some((addr, auth)) = self.config.coordination_client_config() else {
            return Ok(DiagnoseOutcome::CoordinationNotConfigured);
        };
        let source = WorkerEvidenceSource::new(&addr, &auth);
        let outcome =
            crate::recovery_diagnosis::diagnose_stable(&self.replica_coordinator, &source, key)
                .await?;
        Ok(DiagnoseOutcome::Diagnosis(Box::new(outcome)))
    }
}
