//! `DiagnosticsBundle`'s read model -- composes narrow ports (each backed
//! by an already-landed query service, not `DaemonState` directly) into
//! the single snapshot `diagnostics_ipc` encodes onto the wire.
//!
//! Every port mirrors the pre-existing `assemble_bundle_sync`'s own
//! silent-degrade-on-error behavior exactly: a sub-collection that can't
//! be read contributes an empty/default value, never an `Err` that fails
//! the whole bundle -- every underlying reader here is already infallible
//! in practice (the query services it wraps default on error themselves).
//! The bounded-timeout fallback in `diagnostics_ipc.rs` remains the ONLY
//! thing that ever produces a `"daemon-partial"` bundle; nothing in this
//! module's `Result`-free signatures could produce one on its own, which
//! is what makes `build()` safe to call directly from a `spawn_blocking`
//! worker with no `?` short-circuit to reason about.

use std::sync::Arc;
use std::time::Duration;

pub(crate) struct DiagnosticsLinkView {
    pub(crate) state_label: &'static str,
}

pub(crate) struct RuntimeDiagnosticsSnapshot {
    pub(crate) uptime: Duration,
    pub(crate) links: Vec<DiagnosticsLinkView>,
    pub(crate) disk_state: &'static str,
    pub(crate) limits_state: &'static str,
}

pub(crate) trait RuntimeDiagnosticsPort: Send + Sync {
    fn snapshot(&self) -> RuntimeDiagnosticsSnapshot;
}

pub(crate) struct TaskHealthView {
    pub(crate) name: String,
    pub(crate) alive: bool,
}

pub(crate) struct HealthDiagnosticsSnapshot {
    pub(crate) tasks: Vec<TaskHealthView>,
}

pub(crate) trait HealthDiagnosticsPort: Send + Sync {
    fn snapshot(&self) -> HealthDiagnosticsSnapshot;
}

#[derive(Default)]
pub(crate) struct UpdateDiagnosticsSnapshot {
    pub(crate) state: String,
    pub(crate) channel: String,
    pub(crate) available_version: String,
    pub(crate) mandatory: bool,
    pub(crate) holdback_reason: String,
}

pub(crate) trait UpdateDiagnosticsPort: Send + Sync {
    fn snapshot(&self) -> UpdateDiagnosticsSnapshot;
}

pub(crate) struct ConfigurationDiagnosticsSnapshot {
    pub(crate) install_channel: String,
}

pub(crate) trait ConfigurationDiagnosticsPort: Send + Sync {
    fn snapshot(&self) -> ConfigurationDiagnosticsSnapshot;
}

pub(crate) struct RecentErrorLogEntry {
    pub(crate) category: String,
    pub(crate) timestamp: String,
    pub(crate) context: String,
}

pub(crate) struct LogDiagnosticsSnapshot {
    pub(crate) recent_errors: Vec<RecentErrorLogEntry>,
}

pub(crate) trait LogDiagnosticsPort: Send + Sync {
    fn snapshot(&self) -> LogDiagnosticsSnapshot;
}

pub(crate) struct DiagnosticsBundleSnapshot {
    pub(crate) generated_at_unix: i64,
    pub(crate) runtime: RuntimeDiagnosticsSnapshot,
    pub(crate) health: HealthDiagnosticsSnapshot,
    pub(crate) update: UpdateDiagnosticsSnapshot,
    pub(crate) configuration: ConfigurationDiagnosticsSnapshot,
    pub(crate) logs: LogDiagnosticsSnapshot,
}

pub(crate) struct DiagnosticsBundleQueryService {
    runtime: Arc<dyn RuntimeDiagnosticsPort>,
    health: Arc<dyn HealthDiagnosticsPort>,
    update: Arc<dyn UpdateDiagnosticsPort>,
    configuration: Arc<dyn ConfigurationDiagnosticsPort>,
    logs: Arc<dyn LogDiagnosticsPort>,
}

impl DiagnosticsBundleQueryService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        runtime: Arc<dyn RuntimeDiagnosticsPort>,
        health: Arc<dyn HealthDiagnosticsPort>,
        update: Arc<dyn UpdateDiagnosticsPort>,
        configuration: Arc<dyn ConfigurationDiagnosticsPort>,
        logs: Arc<dyn LogDiagnosticsPort>,
    ) -> Self {
        Self { runtime, health, update, configuration, logs }
    }

    /// `generated_at_unix` is caller-supplied rather than read from the
    /// system clock here -- keeps this service, like every other query
    /// service in this module tree, free of hidden non-determinism.
    pub(crate) fn build(&self, generated_at_unix: i64) -> DiagnosticsBundleSnapshot {
        DiagnosticsBundleSnapshot {
            generated_at_unix,
            runtime: self.runtime.snapshot(),
            health: self.health.snapshot(),
            update: self.update.snapshot(),
            configuration: self.configuration.snapshot(),
            logs: self.logs.snapshot(),
        }
    }
}
