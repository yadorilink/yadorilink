//! The composition root's own output type: `application`/`queries`, built
//! exactly once (in production, by `app.rs`, the sole composition root;
//! in tests -- both this crate's own unit tests and the integration test
//! binaries under `tests/`, which link against this crate as an ordinary
//! dependency and so never see `#[cfg(test)]` -- by
//! `ControlContext::from_state`) and handed down through every
//! connection. Deliberately has NO `Arc<DaemonState>` field --
//! `handle_request`'s match arms all go through `application`/`queries`
//! now, and any future one that would need `DaemonState` directly is a
//! signal to add a narrow port/query instead, not to widen this struct
//! back out.
//!
//! `pub`, not `pub(crate)`: `control_socket::unix_transport::serve`/
//! `windows_transport::serve` are themselves `pub` (every integration
//! test under `tests/` calls them directly), so their `Arc<ControlContext>`
//! parameter must be constructible from outside this crate too.

use std::sync::Arc;

use crate::application::ApplicationServices;
use crate::queries::QueryServices;

pub struct ControlContext {
    pub(crate) application: Arc<ApplicationServices>,
    pub(crate) queries: Arc<QueryServices>,
    /// The engine's state directory: the settings and recovery records `status` and the
    /// settings verbs read live under it.
    pub(crate) config_dir: std::path::PathBuf,
    /// The provider roots' lines of `status`, filled in by the shell side.
    pub(crate) provider_status: Arc<crate::provider_status::ProviderStatusSource>,
    /// Frees the local copy of a provider folder's file; installed by the shell side.
    pub(crate) provider_evict: Arc<crate::provider_evict::ProviderEvictSlot>,
    /// Automatic space management; installed by the shell side.
    pub(crate) auto_reclaim: Arc<crate::provider_auto_reclaim::AutoReclaimSlot>,
    /// Who this daemon is, for `identify`.
    #[cfg(feature = "process-model")]
    pub(crate) identity: Arc<crate::identity::RuntimeIdentity>,
    /// What a status collects from, and the builder that serves `Status` and `ListLinks`.
    pub(crate) status_sources: Arc<crate::status_report::StatusSources>,
    pub(crate) status_hub: Arc<crate::status_facts::StatusHub>,
    /// Whether peer traffic may flow on the connection the host reports.
    pub(crate) network_policy: Arc<crate::network_policy::NetworkPolicy>,
}

impl ControlContext {
    pub(crate) fn new(
        application: Arc<ApplicationServices>,
        queries: Arc<QueryServices>,
        config_dir: std::path::PathBuf,
        network_policy: Arc<crate::network_policy::NetworkPolicy>,
    ) -> Self {
        let provider_status: Arc<crate::provider_status::ProviderStatusSource> = Arc::default();
        let auto_reclaim: Arc<crate::provider_auto_reclaim::AutoReclaimSlot> = Arc::default();
        let status_sources = Arc::new(crate::status_report::StatusSources {
            queries: queries.clone(),
            application: application.clone(),
            provider_status: provider_status.clone(),
            auto_reclaim: auto_reclaim.clone(),
            config_dir: config_dir.clone(),
            network_policy: network_policy.clone(),
            last_synced: Default::default(),
        });
        let status_hub = Arc::new(crate::status_facts::StatusHub::new(
            status_sources.clone(),
            queries.runtime_status.telemetry(),
        ));
        Self {
            application,
            queries,
            config_dir,
            provider_status,
            provider_evict: Arc::default(),
            auto_reclaim,
            status_sources,
            status_hub,
            network_policy,
            #[cfg(feature = "process-model")]
            identity: Arc::new(crate::identity::RuntimeIdentity::detect(None, None)),
        }
    }

    /// Replaces the identity `identify` reports; the composition root passes the one it gated the
    /// start with, tests pass a chosen layout.
    #[cfg(feature = "process-model")]
    #[must_use]
    pub fn with_identity(mut self, identity: Arc<crate::identity::RuntimeIdentity>) -> Self {
        self.identity = identity;
        self
    }

    /// Builds both from a real `Arc<DaemonState>`, matching the exact
    /// composition `crate::adapters::build_application_services`/
    /// `build_query_services` (and, in production, `app.rs`) perform. Not
    /// used by `app.rs` itself, which already holds the two `Arc`s
    /// separately -- this exists for test call sites that only have a
    /// `DaemonState` to start from.
    pub fn from_state(state: Arc<crate::daemon_state::DaemonState>) -> Self {
        let application = crate::adapters::build_application_services(state.clone());
        let config_dir = state.config_dir().to_path_buf();
        let network_policy = state.network_policy.clone();
        let queries = crate::adapters::build_query_services(state);
        Self::new(application, queries, config_dir, network_policy)
    }
}
