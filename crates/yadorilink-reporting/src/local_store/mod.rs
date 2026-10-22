//! Plain filesystem-JSON persistence for the parts of reporting storage
//! that have no daemon-specific coupling: consent/config state and the
//! bounded error-candidate store, plus the small dependency-free helpers
//! they share (`entry_store`'s bounded-directory engine, `time`'s RFC
//! 3339 formatting, and the `ReportingStorageError` type). Everything
//! here depends only on `std`, `serde`/`serde_json`, and this crate's own
//! pure types (`ConsentState`, `ReportEnvelope`, `QueuedReportMetadata`,
//! `RetentionPolicy`, ...) — no `tokio` runtime state, no daemon-only
//! types, nothing that would tie it to running inside `yadorilink-daemon`.
//! That's what makes it safe for `yadorilink-cli` to use directly instead
//! of reaching into the daemon crate for logic that isn't actually
//! daemon-specific.
//!
//! The on-disk submission *queue* and usage *counters* stay owned by
//! `yadorilink-daemon` (`crates/yadorilink-daemon/src/reporting/queue.rs`
//! and `counters.rs`) — they're entangled with daemon-specific counting
//! and scheduling, even though `queue.rs` reuses `entry_store` from here
//! as its storage engine.
//!
//! Submodules:
//! - `error`: `ReportingStorageError`/`ReportingResult`. Deliberately
//!   never converted into a daemon or CLI error type by a `From` impl —
//!   callers that aren't reporting-specific are expected to log and
//!   ignore a failure, or use one of the infallible best-effort wrappers
//!   the owning crate provides on top.
//! - `time`: dependency-free RFC 3339 formatting.
//! - `entry_store`: shared bounded-directory-of-JSON-files engine behind
//!   `consent_store`/`error_candidates` here and `queue.rs` in the daemon
//!   crate.
//! - `consent_store`: `<config_dir>/reporting/consent.json`.
//! - `error_candidates`: `<config_dir>/reporting/error-candidates/`.
//! - `environment`: builds the `ReportEnvironment` every generated report
//!   needs from this process's own build/platform constants plus the
//!   caller-supplied consent state.

pub mod consent_store;
pub mod entry_store;
pub mod environment;
pub mod error;
pub mod error_candidates;
pub mod time;
