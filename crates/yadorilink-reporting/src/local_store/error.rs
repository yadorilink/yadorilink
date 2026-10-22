//! reporting storage gets its own error type, deliberately kept
//! separate from `crate::error::DaemonError`. Nothing in this crate ever
//! converts a `ReportingStorageError` into a `DaemonError` (there is no
//! `From` impl and there must never be one) — that's what structurally
//! guarantees a reporting-storage failure can't be `?`-propagated into an
//! unrelated daemon operation (sync reconciliation, daemon startup, auth,
//! ordinary CLI/IPC handling). Call sites that aren't themselves
//! reporting-specific code are expected to log-and-ignore
//! (`ReportingStorageError` implements `std::fmt::Display` via
//! `thiserror` for exactly that), or better, to use one of the infallible
//! best-effort wrappers on `ReportingStorage`/`ReportingCounters` that
//! never hand back a `Result` at all.

#[derive(Debug, thiserror::Error)]
pub enum ReportingStorageError {
    #[error("reporting storage io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("reporting storage json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("reporting storage entry not found: {0}")]
    NotFound(String),

    #[error("invalid report id: {0}")]
    InvalidEntryId(String),
}

pub type ReportingResult<T> = Result<T, ReportingStorageError>;
