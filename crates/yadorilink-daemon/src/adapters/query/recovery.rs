//! `CoordinationConfigPort` backed by a real `DaemonState` -- kept as an
//! adapter (rather than narrowing `RecoveryQueryService` directly to
//! `CoordinationClientConfig`) since the underlying getter reads from
//! `DaemonState`'s own `OnceCell`, set post-construction by
//! `set_coordination_client_config`, not a plain field a query service
//! could hold an `Arc` clone of.

use std::sync::Arc;

use crate::daemon_state::DaemonState;
use crate::queries::recovery::CoordinationConfigPort;

pub(crate) struct DaemonCoordinationConfig {
    state: Arc<DaemonState>,
}

impl DaemonCoordinationConfig {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }
}

impl CoordinationConfigPort for DaemonCoordinationConfig {
    fn coordination_client_config(
        &self,
    ) -> Option<(String, yadorilink_fapi_client::CoordinationAuth)> {
        self.state
            .coordination_client_config()
            .map(|config| (config.addr.clone(), config.auth.clone()))
    }
}
