//! `DaemonState`/query-service-backed implementations of
//! `crate::queries::diagnostics_bundle`'s ports. Each adapter reuses an
//! already-landed query service rather than re-deriving its data a second
//! way -- `RuntimeDiagnostics` reuses `LinkStatusQueryService`/
//! `RuntimeStatusQueryService::volumes_free_space`/`GovernanceQueryService`,
//! `ConfigurationDiagnostics` reuses the same `UpdateStatusQueryService`
//! snapshot `UpdateDiagnostics` does (its `install_source` field), and
//! `LogDiagnostics` reads the same error-candidate store
//! `reporting_ipc::generate_last_error_report` already reads.

use std::sync::Arc;

use crate::daemon_state::DaemonState;
use crate::governance_config::GovernanceConfigStore;
use crate::queries::diagnostics_bundle::{
    ConfigurationDiagnosticsPort, ConfigurationDiagnosticsSnapshot, DiagnosticsLinkView,
    HealthDiagnosticsPort, HealthDiagnosticsSnapshot, LogDiagnosticsPort, LogDiagnosticsSnapshot,
    RecentErrorLogEntry, RuntimeDiagnosticsPort, RuntimeDiagnosticsSnapshot, TaskHealthView,
    UpdateDiagnosticsPort, UpdateDiagnosticsSnapshot,
};
use crate::queries::health::HealthQueryService;
use crate::queries::link_status::LinkStatusQueryService;
use crate::queries::runtime_status::RuntimeStatusQueryService;
use crate::queries::update_status::UpdateStatusQueryService;
use crate::reporting::ReportingStorage;

/// How many recent error candidates to summarize -- matches
/// `diagnostics_ipc`'s previous `RECENT_ERRORS_SAMPLE_LIMIT`. A bounded
/// sample, not the full set: a diagnostics bundle is a support artifact,
/// not a full audit log.
const RECENT_ERRORS_SAMPLE_LIMIT: usize = 5;

/// Worst-case classification across a set of volume states (using the
/// same `"ok" | "low" | "critical"` convention `VolumeSpaceView::state`
/// already produces) -- `"unknown"` when there's nothing to classify.
fn worst_volume_state<'a>(states: impl Iterator<Item = &'a str>) -> &'static str {
    let mut saw_any = false;
    let mut worst = "ok";
    for state in states {
        saw_any = true;
        if state == "critical" {
            return "critical";
        }
        if state == "low" {
            worst = "low";
        }
    }
    if !saw_any {
        return "unknown";
    }
    worst
}

pub(crate) struct DaemonRuntimeDiagnostics {
    state: Arc<DaemonState>,
    link_status: Arc<LinkStatusQueryService>,
    runtime_status: Arc<RuntimeStatusQueryService>,
    governance: Arc<GovernanceConfigStore>,
}

impl DaemonRuntimeDiagnostics {
    pub(crate) fn new(
        state: Arc<DaemonState>,
        link_status: Arc<LinkStatusQueryService>,
        runtime_status: Arc<RuntimeStatusQueryService>,
        governance: Arc<GovernanceConfigStore>,
    ) -> Self {
        Self { state, link_status, runtime_status, governance }
    }
}

impl RuntimeDiagnosticsPort for DaemonRuntimeDiagnostics {
    fn snapshot(&self) -> RuntimeDiagnosticsSnapshot {
        let links = self.link_status.list_links().unwrap_or_else(|error| {
            tracing::warn!(%error, "diagnostics snapshot could not enumerate links");
            Vec::new()
        });
        let volumes = self.runtime_status.volumes_free_space(&links);
        let disk_state = worst_volume_state(volumes.iter().map(|v| v.state.as_str()));

        let governance = self.governance.load_or_default();
        let limits_state = if governance.upload_limit_bytes_per_sec == 0
            && governance.download_limit_bytes_per_sec == 0
        {
            "unlimited"
        } else {
            "limited"
        };

        let diagnostics_links = links
            .iter()
            .map(|link| {
                let state_label = if link.degraded.is_some() {
                    "degraded"
                } else if link.paused {
                    "paused"
                } else if link.conflict_count > 0 {
                    "conflict"
                } else {
                    "synced"
                };
                DiagnosticsLinkView { state_label }
            })
            .collect();

        RuntimeDiagnosticsSnapshot {
            uptime: self.state.uptime(),
            links: diagnostics_links,
            disk_state,
            limits_state,
        }
    }
}

pub(crate) struct DaemonHealthDiagnostics {
    health: Arc<HealthQueryService>,
}

impl DaemonHealthDiagnostics {
    pub(crate) fn new(health: Arc<HealthQueryService>) -> Self {
        Self { health }
    }
}

impl HealthDiagnosticsPort for DaemonHealthDiagnostics {
    fn snapshot(&self) -> HealthDiagnosticsSnapshot {
        let health = self.health.snapshot();
        let tasks = health
            .tasks
            .into_iter()
            .map(|t| TaskHealthView { name: t.name, alive: t.alive })
            .collect();
        HealthDiagnosticsSnapshot { tasks }
    }
}

pub(crate) struct DaemonUpdateDiagnostics {
    update_status: Arc<UpdateStatusQueryService>,
}

impl DaemonUpdateDiagnostics {
    pub(crate) fn new(update_status: Arc<UpdateStatusQueryService>) -> Self {
        Self { update_status }
    }
}

impl UpdateDiagnosticsPort for DaemonUpdateDiagnostics {
    fn snapshot(&self) -> UpdateDiagnosticsSnapshot {
        let view = self.update_status.snapshot();
        UpdateDiagnosticsSnapshot {
            state: view.state,
            channel: view.channel,
            available_version: view.available_version,
            mandatory: view.mandatory,
            holdback_reason: view.holdback_reason,
        }
    }
}

pub(crate) struct DaemonConfigurationDiagnostics {
    update_status: Arc<UpdateStatusQueryService>,
}

impl DaemonConfigurationDiagnostics {
    pub(crate) fn new(update_status: Arc<UpdateStatusQueryService>) -> Self {
        Self { update_status }
    }
}

impl ConfigurationDiagnosticsPort for DaemonConfigurationDiagnostics {
    fn snapshot(&self) -> ConfigurationDiagnosticsSnapshot {
        ConfigurationDiagnosticsSnapshot {
            install_channel: self.update_status.snapshot().install_source,
        }
    }
}

pub(crate) struct DaemonLogDiagnostics {
    reporting: Arc<ReportingStorage>,
}

impl DaemonLogDiagnostics {
    pub(crate) fn new(reporting: Arc<ReportingStorage>) -> Self {
        Self { reporting }
    }
}

impl LogDiagnosticsPort for DaemonLogDiagnostics {
    fn snapshot(&self) -> LogDiagnosticsSnapshot {
        let candidates = self.reporting.error_candidates();
        let Ok(metas) = candidates.list() else {
            return LogDiagnosticsSnapshot { recent_errors: Vec::new() };
        };
        let recent_errors = metas
            .into_iter()
            .rev() // newest first -- `list()` returns oldest-first
            .take(RECENT_ERRORS_SAMPLE_LIMIT)
            .filter_map(|meta| {
                let envelope = candidates.show(&meta.report_id).ok().flatten()?;
                let yadorilink_reporting::schema::ReportPayload::Error(err) = envelope.payload
                else {
                    return None;
                };
                Some(RecentErrorLogEntry {
                    category: err.error_category,
                    timestamp: envelope.generated_at,
                    context: err.subsystem,
                })
            })
            .collect();
        LogDiagnosticsSnapshot { recent_errors }
    }
}
