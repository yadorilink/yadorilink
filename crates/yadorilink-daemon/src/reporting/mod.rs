//! OSS usage/error reporting local storage. This module owns everything
//! under `<config_dir>/reporting/` — aggregate usage counters and the
//! bounded unsent-report queue directly, plus consent/config state and
//! bounded error-candidate persistence by re-using
//! `yadorilink_reporting::local_store` (those two have no daemon-specific
//! coupling, so `yadorilink-cli` uses the same storage directly instead of
//! reaching into this crate). Submodules: - `counters`:
//! `<config_dir>/reporting/counters.json`. - `queue`:
//! `<config_dir>/reporting/queue/`, built on
//! `yadorilink_reporting::local_store::entry_store`. - `hooks`:
//! severe-error/panic capture, writing into
//! `yadorilink_reporting::local_store::error_candidates`.
//! `ReportingStorage` below is the facade that bundles all four stores
//! together and is the type `DaemonState`'s IPC dispatch will actually
//! hold — its `note_*`/`*_best_effort` methods are the infallible surface
//! arbitrary daemon call sites (a command handler, a sync-state
//! transition, an error path) are meant to call directly, ensuring
//! reliability by construction: there is no `Result` for such a call site
//! to mishandle. The individual stores' own `Result`-returning methods
//! remain available (via
//! `ReportingStorage::{consent,queue,error_candidates}` accessors) for
//! reporting-specific code (future CLI/IPC handlers in sections 3/4) that
//! legitimately needs to see and report a failure.

pub mod counters;
pub mod hooks;
pub mod queue;

// Re-exported so existing `crate::reporting::time::...` call sites
// elsewhere in this crate (e.g. `diagnostics_ipc.rs`) keep working
// unchanged now that the dependency-free RFC 3339 helpers live in
// `yadorilink-reporting::local_store` alongside the other storage that
// moved there.
pub(crate) use yadorilink_reporting::local_store::time;

use std::collections::BTreeMap;
use std::path::PathBuf;

use yadorilink_reporting::consent::ConsentState;
use yadorilink_reporting::local_store::{
    consent_store::ConsentStore, error_candidates::ErrorCandidateStore,
};
use yadorilink_reporting::redact::RedactionSummary;
use yadorilink_reporting::schema::ReportEnvelope;

use counters::ReportingCounters;
use queue::QueueStore;

/// `<config_dir>/reporting` — a sibling of `device.json`/the block store,
/// never inside a linked/synced folder.
pub fn reporting_dir() -> PathBuf {
    crate::device_config::config_dir().join("reporting")
}

pub struct ReportingStorage {
    consent: ConsentStore,
    counters: ReportingCounters,
    error_candidates: ErrorCandidateStore,
    queue: QueueStore,
}

impl ReportingStorage {
    /// Opens (without eagerly writing anything — see `consent_store`'s
    /// doc comment) reporting storage rooted at the daemon's normal
    /// config directory.
    pub fn open_default() -> Self {
        Self::open(reporting_dir())
    }

    pub fn open(reporting_dir: impl Into<PathBuf>) -> Self {
        let dir = reporting_dir.into();
        ReportingStorage {
            consent: ConsentStore::new(&dir),
            counters: ReportingCounters::open(&dir),
            error_candidates: ErrorCandidateStore::new(&dir),
            queue: QueueStore::new(&dir),
        }
    }

    pub fn consent(&self) -> &ConsentStore {
        &self.consent
    }

    pub fn counters(&self) -> &ReportingCounters {
        &self.counters
    }

    pub fn error_candidates(&self) -> &ErrorCandidateStore {
        &self.error_candidates
    }

    pub fn queue(&self) -> &QueueStore {
        &self.queue
    }

    // -- Infallible, "safe for any call site" surface --------

    /// Best-effort consent read: reporting-disabled default on any
    /// storage failure, for call sites that just need to decide "is
    /// reporting on" without caring why a read might have failed.
    pub fn consent_or_default(&self) -> ConsentState {
        self.consent.load_or_default()
    }

    pub fn note_command_category(&self, category: &str) {
        self.counters.increment_command_category(category);
    }

    pub fn note_sync_state(&self, state: &str) {
        self.counters.record_sync_state(state);
    }

    pub fn note_error_category(&self, category: &str) {
        self.counters.record_error_category(category);
    }

    pub fn note_transfer_bytes(&self, bytes: u64) {
        self.counters.record_transfer_bytes(bytes);
    }

    pub fn note_latency_millis(&self, millis: u64) {
        self.counters.record_latency_millis(millis);
    }

    pub fn note_peer_count(&self, count: u32) {
        self.counters.record_peer_count(count);
    }

    pub fn note_linked_folders(&self, total: u32, policy_counts: BTreeMap<String, u32>) {
        self.counters.record_linked_folder_counts(total, policy_counts);
    }

    pub fn note_feature_flags(&self, flags: Vec<String>) {
        self.counters.record_feature_flags(flags);
    }

    /// Persists a severe-error candidate for later user review. Never
    /// propagates a failure: returns `None` (and logs a warning) instead
    /// of an `Err`, so a real error-hook call site (not yet
    /// wired) can call this from inside its own error-handling path
    /// without needing a nested `Result` of its own.
    pub fn record_error_candidate_best_effort(&self, envelope: ReportEnvelope) -> Option<String> {
        match self.error_candidates.create_candidate(envelope) {
            Ok(meta) => Some(meta.report_id),
            Err(e) => {
                tracing::warn!(error = %e, "reporting: failed to persist error candidate");
                None
            }
        }
    }

    /// Like `record_error_candidate_best_effort`, but also
    /// persists the redaction summary produced when the candidate's
    /// payload was built, so a later `yadorilink report error --preview`
    /// can show it (see `error_candidates.rs`'s module doc comment).
    pub fn record_error_candidate_with_summary_best_effort(
        &self,
        envelope: ReportEnvelope,
        summary: &RedactionSummary,
    ) -> Option<String> {
        match self.error_candidates.create_candidate_with_summary(envelope, summary) {
            Ok(meta) => Some(meta.report_id),
            Err(e) => {
                tracing::warn!(error = %e, "reporting: failed to persist error candidate");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests;
