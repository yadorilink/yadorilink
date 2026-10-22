//! `LimitsShow`'s read model -- just a load of the persisted governance
//! config. Returns `ResourceGovernanceConfig` directly (already a plain
//! domain type, not protobuf) rather than a redundant wrapper view.

use std::sync::Arc;

use crate::governance_config::{GovernanceConfigStore, ResourceGovernanceConfig};

pub(crate) struct GovernanceQueryService {
    governance: Arc<GovernanceConfigStore>,
}

impl GovernanceQueryService {
    pub(crate) fn new(governance: Arc<GovernanceConfigStore>) -> Self {
        Self { governance }
    }

    pub(crate) fn limits(&self) -> ResourceGovernanceConfig {
        self.governance.load_or_default()
    }
}
