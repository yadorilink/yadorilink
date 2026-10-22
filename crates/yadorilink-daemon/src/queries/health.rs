//! `Health`'s read model -- task liveness and connected-peer count. See
//! `crate::queries::link_status`'s own doc comment for this module tree's
//! shape/rationale; this slice's dependencies (`RuntimeTelemetry`,
//! `PeerConnectivityRuntime`) are already narrow owner components, so its
//! port implementation needs no `DaemonState` strangler step at all.

use std::sync::Arc;

use crate::peer_connectivity_runtime::PeerConnectivityRuntime;
use crate::runtime_telemetry::RuntimeTelemetry;

#[derive(Debug, Clone)]
pub(crate) struct TaskLivenessView {
    pub(crate) name: String,
    pub(crate) alive: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct HealthView {
    pub(crate) tasks: Vec<TaskLivenessView>,
    pub(crate) connected_peer_count: u32,
}

pub(crate) struct HealthQueryService {
    telemetry: Arc<RuntimeTelemetry>,
    peers: Arc<PeerConnectivityRuntime>,
}

impl HealthQueryService {
    pub(crate) fn new(
        telemetry: Arc<RuntimeTelemetry>,
        peers: Arc<PeerConnectivityRuntime>,
    ) -> Self {
        Self { telemetry, peers }
    }

    pub(crate) fn snapshot(&self) -> HealthView {
        let tasks = self
            .telemetry
            .task_snapshot()
            .into_iter()
            .map(|entry| TaskLivenessView { name: entry.name, alive: entry.alive })
            .collect();
        HealthView { tasks, connected_peer_count: self.peers.connected_peer_count() }
    }
}
