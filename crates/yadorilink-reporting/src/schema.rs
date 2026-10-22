//! Versioned report envelope and payload types shared by the CLI, daemon,
//! and (eventually) an HTTPS submission client. Construction is
//! allowlist-first by design: every field here is a specific, typed,
//! coarse-grained value a caller must explicitly set — there is no path
//! that serializes an internal struct (sync state, auth, device, peer,
//! file index) directly into a report.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Bumped whenever the envelope or a payload's field set changes in a way
/// that could affect how a maintainer or endpoint interprets a report.
pub const SCHEMA_VERSION: u32 = 1;

/// Reports must stay small: they're previewed inline in a terminal and
/// bounded in a local queue. This is enforced by `validate`, not by
/// the type system, since payload content is data, not shape.
pub const MAX_REPORT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportType {
    Usage,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    Macos,
    Windows,
    Linux,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportEnvelope {
    pub schema_version: u32,
    pub report_type: ReportType,
    /// RFC 3339 timestamp. Callers supply this (rather than the schema
    /// stamping it internally) so it can be produced from a single,
    /// injectable clock source at the call site — keeps this crate free
    /// of any direct time-source dependency.
    pub generated_at: String,
    pub yadorilink_version: String,
    pub os_family: OsFamily,
    /// Coarse, e.g. "14.x", "11", "24.04" — never a full build/kernel
    /// string, which can be identifying on its own.
    pub os_version_bucket: String,
    pub arch: String,
    pub install_channel: Option<String>,
    /// Present only once the user has opted in (`ConsentState::opt_in`
    /// creates it); absent on every report generated before that.
    pub anonymous_reporter_id: Option<String>,
    pub payload: ReportPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReportPayload {
    Usage(UsagePayload),
    Error(ErrorPayload),
}

/// Aggregate, coarse-grained counts only. No file paths, folder names,
/// group IDs, peer IDs, or command arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsagePayload {
    pub enabled_feature_flags: Vec<String>,
    pub linked_folder_count: u32,
    /// e.g. "eager" -> 3, "on-demand" -> 1 — never the folder paths
    /// themselves.
    pub linked_folder_policy_counts: BTreeMap<String, u32>,
    /// e.g. "link" -> 4, "status" -> 12 — the command's category, never
    /// its arguments.
    pub command_category_counts: BTreeMap<String, u32>,
    /// A bucket label, e.g. "<1h", "1h-1d", "1d-7d", ">7d" — never an
    /// exact duration or start timestamp.
    pub daemon_uptime_bucket: String,
    pub sync_state_counts: BTreeMap<String, u32>,
    pub error_category_counts: BTreeMap<String, u32>,
    pub transfer_size_bucket_counts: BTreeMap<String, u32>,
    pub latency_bucket_counts: BTreeMap<String, u32>,
    /// A bucket label, e.g. "0", "1-2", "3-5", "6+" — never an exact
    /// peer count tied to a specific group.
    pub peer_count_bucket: String,
}

/// A candidate error report. Sanitized/redacted before it ever reaches
/// this struct; the redactor in `redact.rs` is also re-applied to every
/// string field here as a denylist safety pass, since a caller-provided
/// log line or backtrace is exactly the kind of free-text field most
/// likely to accidentally carry a path or token through.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorPayload {
    pub error_category: String,
    pub subsystem: String,
    pub sanitized_log_lines: Vec<String>,
    pub redacted_backtrace: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    #[error("report schema_version {found} is not the supported version {expected}")]
    UnsupportedSchemaVersion { found: u32, expected: u32 },
    #[error("report payload does not match report_type")]
    PayloadTypeMismatch,
    #[error("report exceeds the maximum size of {max} bytes (was {actual})")]
    TooLarge { max: usize, actual: usize },
    #[error("required field `{field}` is empty")]
    MissingField { field: &'static str },
}

impl ReportEnvelope {
    /// Validates schema version, payload/type consistency, required
    /// fields, and overall serialized size. Does not perform redaction —
    /// callers are expected to have already run `redact::redact_payload`
    /// (or equivalent) on any free-text fields before calling this.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ValidationError::UnsupportedSchemaVersion {
                found: self.schema_version,
                expected: SCHEMA_VERSION,
            });
        }
        match (&self.report_type, &self.payload) {
            (ReportType::Usage, ReportPayload::Usage(_)) => {}
            (ReportType::Error, ReportPayload::Error(_)) => {}
            _ => return Err(ValidationError::PayloadTypeMismatch),
        }
        if self.yadorilink_version.is_empty() {
            return Err(ValidationError::MissingField { field: "yadorilink_version" });
        }
        if self.generated_at.is_empty() {
            return Err(ValidationError::MissingField { field: "generated_at" });
        }
        if let ReportPayload::Error(err) = &self.payload {
            if err.error_category.is_empty() {
                return Err(ValidationError::MissingField { field: "error_category" });
            }
        }
        let serialized =
            serde_json::to_vec(self).expect("ReportEnvelope always serializes to JSON");
        if serialized.len() > MAX_REPORT_BYTES {
            return Err(ValidationError::TooLarge {
                max: MAX_REPORT_BYTES,
                actual: serialized.len(),
            });
        }
        Ok(())
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("ReportEnvelope always serializes to JSON")
    }

    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

#[cfg(test)]
mod tests;
