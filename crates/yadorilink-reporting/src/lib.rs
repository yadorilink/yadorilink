//! Shared report schema, redaction, consent, and queue types for
//! YadoriLink's opt-in OSS usage/error reporting, plus the
//! `local_store` module's plain filesystem-JSON persistence for the
//! consent state and error-candidate store. The optional HTTPS
//! submission client is a separate concern layered on top of
//! `schema::ReportEnvelope`.
//!
//! `schema`, `consent`, `queue`, `redact`, and `builder` deliberately
//! depend on nothing daemon/CLI-specific (no `tokio`, no filesystem
//! access, no clock): every function there is a pure transformation
//! over caller-supplied data, which is what makes the privacy
//! properties in `redact` and `schema::ReportEnvelope::validate`
//! testable in isolation. `local_store` and `metrics_config` are the
//! exceptions among the non-`submission` modules — they do real
//! filesystem I/O — but they have no daemon-specific coupling either,
//! which is why they live here rather than in `yadorilink-daemon`: both
//! the CLI and the daemon can use them directly. `metrics_config` is the
//! persisted opt-in toggle for the daemon's `/metrics` endpoint, which the
//! CLI writes and the daemon reads at startup. The on-disk submission
//! *queue* and usage *counters* still live in `yadorilink-daemon`
//! (they're entangled with daemon-specific counting and scheduling),
//! reusing `local_store::entry_store` as their storage engine.
//!
//! `submission` is the other exception: it's the optional HTTPS
//! submission client, so it necessarily depends on a
//! minimal-feature `tokio` + `reqwest` for real async I/O — but it's
//! still self-contained, taking only a `&ReportEnvelope` and a plain
//! `Option<&str>` endpoint, with no daemon/CLI/sync/auth types reachable
//! from it.

pub mod builder;
pub mod consent;
pub mod diagnostics;
pub mod local_store;
pub mod metrics_config;
pub mod queue;
pub mod redact;
pub mod schema;
pub mod submission;

pub use builder::{
    build_error_envelope, build_usage_envelope, ErrorPayloadBuilder, ReportEnvironment,
    UsagePayloadBuilder,
};
pub use consent::ConsentState;
pub use diagnostics::{
    diagnostics_summary_count, redact_diagnostics_text, redact_diagnostics_value,
};
pub use local_store::{consent_store::ConsentStore, error_candidates::ErrorCandidateStore};
pub use queue::{QueuedReportMetadata, RetentionPolicy, SubmissionReceipt};
pub use redact::{redact, redact_lines, RedactionCategory, RedactionSummary};
pub use schema::{
    ErrorPayload, OsFamily, ReportEnvelope, ReportPayload, ReportType, UsagePayload,
    ValidationError, MAX_REPORT_BYTES, SCHEMA_VERSION,
};
pub use submission::{SubmissionClient, SubmissionConfig, SubmissionError};
