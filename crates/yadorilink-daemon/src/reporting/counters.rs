//! Daemon-owned aggregate usage counters, persisted to
//! `<config_dir>/reporting/counters.json`. This module owns the
//! storage/aggregation layer only — actually incrementing these from real
//! call sites in the daemon's own `LinkRuntimeController`/`peer_orchestrator.rs`/etc. happens
//! elsewhere, as part of wiring reporting IPC dispatch into
//! yadorilink-daemon. Every mutation method here is deliberately
//! infallible (`-> `), not `-> ReportingResult<>`: this is the API a
//! future call site deep in an unrelated sync/command path will call
//! directly, so a reporting storage failure structurally *cannot* be
//! `?`-propagated into it — the signature doesn't offer an `Err` to
//! propagate. Persistence failures are logged (`tracing::warn!`) and
//! otherwise swallowed; the in-memory counters keep accumulating either
//! way, so a transient disk failure only risks losing counts on an
//! unclean shutdown, never a lost or failed sync/command.
//!
//! Flush policy: every mutation flushes the full counters state to disk
//! immediately, rather than batching/periodic flush. This is deliberate,
//! not an oversight: each increment corresponds to one discrete,
//! human-scale event (one CLI command finishing, one sync-state
//! transition, one completed transfer, one error) — not a hot per-byte or
//! per-packet path — so the write volume this produces is comparable to,
//! e.g., the credential store's occasional writes, not a bottleneck.
//! Flush-on-write
//! also means a killed-without-warning daemon never loses more than the
//! single most recent event, which matters more for a feature whose whole
//! point is "give maintainers an accurate signal" than shaving a few
//! syscalls off an already-infrequent code path.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use yadorilink_reporting::builder::UsagePayloadBuilder;
use yadorilink_reporting::local_store::error::ReportingResult;
use yadorilink_reporting::schema::UsagePayload;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
struct CountersState {
    enabled_feature_flags: Vec<String>,
    linked_folder_count: u32,
    linked_folder_policy_counts: BTreeMap<String, u32>,
    command_category_counts: BTreeMap<String, u32>,
    sync_state_counts: BTreeMap<String, u32>,
    error_category_counts: BTreeMap<String, u32>,
    transfer_size_bucket_counts: BTreeMap<String, u32>,
    latency_bucket_counts: BTreeMap<String, u32>,
    peer_count_bucket_counts: BTreeMap<String, u32>,
}

/// Coarse performance buckets — see `schema.rs`'s doc comments for the
/// two bucket shapes it gives as examples (uptime, peer count); the
/// transfer-size/latency bucket edges below are this module's own
/// reasoned choices, not specified elsewhere.
fn bucket_transfer_size(bytes: u64) -> &'static str {
    const MB: u64 = 1024 * 1024;
    match bytes {
        0..=999_999 => "<1MB",
        b if b < 10 * MB => "1-10MB",
        b if b < 100 * MB => "10-100MB",
        b if b < 1024 * MB => "100MB-1GB",
        _ => ">1GB",
    }
}

fn bucket_latency(millis: u64) -> &'static str {
    match millis {
        0..=99 => "<100ms",
        100..=499 => "100-500ms",
        500..=1999 => "500ms-2s",
        2000..=9999 => "2-10s",
        _ => ">10s",
    }
}

/// Matches the example bucket labels in `UsagePayload::peer_count_bucket`'s
/// doc comment exactly ("0", "1-2", "3-5", "6+").
fn bucket_peer_count(count: u32) -> &'static str {
    match count {
        0 => "0",
        1..=2 => "1-2",
        3..=5 => "3-5",
        _ => "6+",
    }
}

/// Matches the example bucket labels in `UsagePayload::daemon_uptime_bucket`'s
/// doc comment exactly ("<1h", "1h-1d", "1d-7d", ">7d").
fn bucket_uptime(secs: u64) -> &'static str {
    const HOUR: u64 = 3600;
    const DAY: u64 = 24 * HOUR;
    match secs {
        0..=3599 => "<1h",
        s if s < DAY => "1h-1d",
        s if s < 7 * DAY => "1d-7d",
        _ => ">7d",
    }
}

pub struct ReportingCounters {
    path: PathBuf,
    state: Mutex<CountersState>,
    started_at: Instant,
}

impl ReportingCounters {
    /// Loads persisted counters (best-effort — a missing or unreadable
    /// file just starts from zero rather than failing daemon startup)
    /// and starts the in-process uptime clock.
    pub fn open(reporting_dir: impl Into<PathBuf>) -> Self {
        let path = reporting_dir.into().join("counters.json");
        let state = match Self::load(&path) {
            Ok(state) => state,
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "reporting: failed to load counters; starting from zero");
                CountersState::default()
            }
        };
        ReportingCounters { path, state: Mutex::new(state), started_at: Instant::now() }
    }

    fn load(path: &std::path::Path) -> ReportingResult<CountersState> {
        match std::fs::read_to_string(path) {
            Ok(contents) => Ok(serde_json::from_str(&contents)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CountersState::default()),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&self, state: &CountersState) -> ReportingResult<()> {
        if let Some(parent) = self.path.parent() {
            yadorilink_fs_platform::durable_dir::create_dir_all_durably(parent)?;
        }
        let json = serde_json::to_string_pretty(state)?;
        let tmp_path = self.path.with_extension("json.tmp");
        std::fs::write(&tmp_path, json)?;
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    /// Locks, mutates via `f`, and best-effort flushes — the one place
    /// every infallible public method below funnels through, so the
    /// "log and never propagate" behavior only needs to be written once.
    fn mutate(&self, f: impl FnOnce(&mut CountersState)) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut state);
        if let Err(e) = self.save(&state) {
            tracing::warn!(error = %e, path = %self.path.display(), "reporting: failed to persist counters; in-memory count still updated");
        }
    }

    pub fn record_feature_flags(&self, flags: Vec<String>) {
        self.mutate(|s| s.enabled_feature_flags = flags);
    }

    pub fn record_linked_folder_counts(&self, total: u32, policy_counts: BTreeMap<String, u32>) {
        self.mutate(|s| {
            s.linked_folder_count = total;
            s.linked_folder_policy_counts = policy_counts;
        });
    }

    pub fn increment_command_category(&self, category: &str) {
        self.mutate(|s| *s.command_category_counts.entry(category.to_string()).or_insert(0) += 1);
    }

    pub fn record_sync_state(&self, state_name: &str) {
        self.mutate(|s| *s.sync_state_counts.entry(state_name.to_string()).or_insert(0) += 1);
    }

    pub fn record_error_category(&self, category: &str) {
        self.mutate(|s| *s.error_category_counts.entry(category.to_string()).or_insert(0) += 1);
    }

    pub fn record_transfer_bytes(&self, bytes: u64) {
        let bucket = bucket_transfer_size(bytes);
        self.mutate(|s| *s.transfer_size_bucket_counts.entry(bucket.to_string()).or_insert(0) += 1);
    }

    pub fn record_latency_millis(&self, millis: u64) {
        let bucket = bucket_latency(millis);
        self.mutate(|s| *s.latency_bucket_counts.entry(bucket.to_string()).or_insert(0) += 1);
    }

    pub fn record_peer_count(&self, count: u32) {
        let bucket = bucket_peer_count(count);
        self.mutate(|s| *s.peer_count_bucket_counts.entry(bucket.to_string()).or_insert(0) += 1);
    }

    /// Clears every counter. Counters reset after successful
    /// export/submission unless the user chooses otherwise; the actual
    /// reset-on-export policy decision lives with the daemon's IPC/CLI
    /// wiring — this is the primitive it calls.
    pub fn reset(&self) {
        self.mutate(|s| *s = CountersState::default());
    }

    /// The current process's uptime bucket — computed fresh each call
    /// from `started_at` rather than persisted, since "uptime" resets
    /// with every daemon restart by definition.
    fn current_uptime_bucket(&self) -> &'static str {
        bucket_uptime(self.started_at.elapsed().as_secs())
    }

    /// The bucket with the single largest count, i.e. "what's the current
    /// peer-count bucket most likely representative of recent activity" —
    /// `UsagePayload::peer_count_bucket` is a single label, not a
    /// distribution, so this collapses the accumulated histogram down to
    /// one representative bucket for the payload. Ties resolve to the
    /// larger bucket, since that's the more actionable signal for
    /// maintainers ("some users do have several peers") and BTreeMap
    /// iteration order already sorts bucket labels a fixed way, so this
    /// stays deterministic.
    fn representative_peer_count_bucket(&self, counts: &BTreeMap<String, u32>) -> String {
        counts
            .iter()
            .max_by_key(|(_, count)| **count)
            .map(|(bucket, _)| bucket.clone())
            .unwrap_or_else(|| "0".to_string())
    }

    /// Builds a `UsagePayload` from the current in-memory counters via
    /// `UsagePayloadBuilder` — read-only, does not reset anything.
    pub fn to_usage_payload(&self) -> UsagePayload {
        let state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let peer_bucket = self.representative_peer_count_bucket(&state.peer_count_bucket_counts);
        let mut builder = UsagePayloadBuilder::new()
            .enabled_feature_flags(state.enabled_feature_flags.clone())
            .linked_folder_count(state.linked_folder_count)
            .daemon_uptime_bucket(self.current_uptime_bucket())
            .peer_count_bucket(peer_bucket);
        for (policy, count) in &state.linked_folder_policy_counts {
            builder = builder.linked_folder_policy_count(policy.clone(), *count);
        }
        for (category, count) in &state.command_category_counts {
            builder = builder.command_category_count(category.clone(), *count);
        }
        for (sync_state, count) in &state.sync_state_counts {
            builder = builder.sync_state_count(sync_state.clone(), *count);
        }
        for (category, count) in &state.error_category_counts {
            builder = builder.error_category_count(category.clone(), *count);
        }
        for (bucket, count) in &state.transfer_size_bucket_counts {
            builder = builder.transfer_size_bucket_count(bucket.clone(), *count);
        }
        for (bucket, count) in &state.latency_bucket_counts {
            builder = builder.latency_bucket_count(bucket.clone(), *count);
        }
        builder.build()
    }
}

#[cfg(test)]
mod tests;
