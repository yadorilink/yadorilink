//! Allowlist-based construction helpers. `UsagePayload`/
//! `ErrorPayload` already structurally forbid serializing arbitrary
//! internal state (they have no field that could hold a raw struct) —
//! these builders are the ergonomic layer on top: a fluent surface with
//! only the specific setters that correspond to allowed fields, so a
//! call site building a report reads as "here are the coarse facts I'm
//! choosing to report," not "here's my internal state, minus what I
//! remembered to strip out."

use crate::redact::{redact, redact_lines, RedactionSummary};
use crate::schema::{
    ErrorPayload, OsFamily, ReportEnvelope, ReportPayload, ReportType, UsagePayload, SCHEMA_VERSION,
};

#[derive(Debug, Clone, Default)]
pub struct UsagePayloadBuilder {
    payload: UsagePayload,
}

impl UsagePayloadBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enabled_feature_flags(mut self, flags: Vec<String>) -> Self {
        self.payload.enabled_feature_flags = flags;
        self
    }

    pub fn linked_folder_count(mut self, count: u32) -> Self {
        self.payload.linked_folder_count = count;
        self
    }

    pub fn linked_folder_policy_count(mut self, policy: impl Into<String>, count: u32) -> Self {
        self.payload.linked_folder_policy_counts.insert(policy.into(), count);
        self
    }

    pub fn command_category_count(mut self, category: impl Into<String>, count: u32) -> Self {
        self.payload.command_category_counts.insert(category.into(), count);
        self
    }

    pub fn daemon_uptime_bucket(mut self, bucket: impl Into<String>) -> Self {
        self.payload.daemon_uptime_bucket = bucket.into();
        self
    }

    pub fn sync_state_count(mut self, state: impl Into<String>, count: u32) -> Self {
        self.payload.sync_state_counts.insert(state.into(), count);
        self
    }

    pub fn error_category_count(mut self, category: impl Into<String>, count: u32) -> Self {
        self.payload.error_category_counts.insert(category.into(), count);
        self
    }

    pub fn transfer_size_bucket_count(mut self, bucket: impl Into<String>, count: u32) -> Self {
        self.payload.transfer_size_bucket_counts.insert(bucket.into(), count);
        self
    }

    pub fn latency_bucket_count(mut self, bucket: impl Into<String>, count: u32) -> Self {
        self.payload.latency_bucket_counts.insert(bucket.into(), count);
        self
    }

    pub fn peer_count_bucket(mut self, bucket: impl Into<String>) -> Self {
        self.payload.peer_count_bucket = bucket.into();
        self
    }

    pub fn build(self) -> UsagePayload {
        self.payload
    }
}

#[derive(Debug, Clone, Default)]
pub struct ErrorPayloadBuilder {
    category: String,
    subsystem: String,
    log_lines: Vec<String>,
    backtrace: Option<String>,
}

impl ErrorPayloadBuilder {
    pub fn new(category: impl Into<String>, subsystem: impl Into<String>) -> Self {
        ErrorPayloadBuilder {
            category: category.into(),
            subsystem: subsystem.into(),
            ..Default::default()
        }
    }

    pub fn log_lines(mut self, lines: Vec<String>) -> Self {
        self.log_lines = lines;
        self
    }

    pub fn backtrace(mut self, backtrace: impl Into<String>) -> Self {
        self.backtrace = Some(backtrace.into());
        self
    }

    /// Runs the denylist safety pass over every free-text field
    /// before producing the final payload — the one place in this
    /// builder where raw caller-supplied text (log lines, a backtrace)
    /// is unavoidable, and therefore the one place redaction is
    /// mandatory rather than optional.
    pub fn build(self) -> (ErrorPayload, RedactionSummary) {
        let (sanitized_log_lines, log_summary) = redact_lines(&self.log_lines);
        let (redacted_backtrace, backtrace_summary) = match self.backtrace {
            Some(bt) => {
                let (redacted, summary) = redact(&bt);
                (Some(redacted), summary)
            }
            None => (None, RedactionSummary::default()),
        };
        let mut merged = log_summary;
        for (category, count) in backtrace_summary.categories {
            match merged.categories.iter_mut().find(|(c, _)| *c == category) {
                Some((_, existing)) => *existing += count,
                None => merged.categories.push((category, count)),
            }
        }
        (
            ErrorPayload {
                error_category: self.category,
                subsystem: self.subsystem,
                sanitized_log_lines,
                redacted_backtrace,
            },
            merged,
        )
    }
}

/// Environment facts every envelope needs, gathered once at the call
/// site (typically the daemon or CLI's own `std::env::consts`/version
/// constant) and threaded through here rather than read directly by
/// this crate, so this crate stays free of any platform-detection
/// dependency of its own.
#[derive(Debug, Clone)]
pub struct ReportEnvironment {
    pub generated_at: String,
    pub yadorilink_version: String,
    pub os_family: OsFamily,
    pub os_version_bucket: String,
    pub arch: String,
    pub install_channel: Option<String>,
    pub anonymous_reporter_id: Option<String>,
}

pub fn build_usage_envelope(env: ReportEnvironment, payload: UsagePayload) -> ReportEnvelope {
    ReportEnvelope {
        schema_version: SCHEMA_VERSION,
        report_type: ReportType::Usage,
        generated_at: env.generated_at,
        yadorilink_version: env.yadorilink_version,
        os_family: env.os_family,
        os_version_bucket: env.os_version_bucket,
        arch: env.arch,
        install_channel: env.install_channel,
        anonymous_reporter_id: env.anonymous_reporter_id,
        payload: ReportPayload::Usage(payload),
    }
}

/// Returns the envelope plus the redaction summary produced while
/// building the error payload, so a caller (e.g. the CLI's `--preview`)
/// can show the user what was stripped.
pub fn build_error_envelope(
    env: ReportEnvironment,
    builder: ErrorPayloadBuilder,
) -> (ReportEnvelope, RedactionSummary) {
    let (payload, summary) = builder.build();
    let envelope = ReportEnvelope {
        schema_version: SCHEMA_VERSION,
        report_type: ReportType::Error,
        generated_at: env.generated_at,
        yadorilink_version: env.yadorilink_version,
        os_family: env.os_family,
        os_version_bucket: env.os_version_bucket,
        arch: env.arch,
        install_channel: env.install_channel,
        anonymous_reporter_id: env.anonymous_reporter_id,
        payload: ReportPayload::Error(payload),
    };
    (envelope, summary)
}

#[cfg(test)]
mod tests;
