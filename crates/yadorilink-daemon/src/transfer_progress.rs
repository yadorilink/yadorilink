//! Lightweight, additive per-active-transfer progress state
//! keyed by `(group_id, path)` — bytes/blocks done vs total, source peer,
//! and a started-at timestamp — plus the cumulative counters/histogram the
//! `/metrics` endpoint (section 3) renders from the exact same observation
//! point. This module owns bookkeeping only; the actual hook sites are
//! `yadorilink-daemon::hydration`'s multi-session block dispatcher, the one
//! place a whole file's total block/byte count and every successful fetch
//! already converge (see `hydration.rs`'s own doc comments), so this is a
//! pure observation add-on, not a restructuring of that dispatch logic.
//!
//! Mirrors this crate's other bounded/RAII-guarded in-memory state
//! (`connection_trace::ConnectionTraceLog`'s bounded ring buffer,
//! `daemon_state::BroadcastGuard`/`WriteActivityGuard`'s "can't forget to
//! release" RAII pattern): an active transfer is torn down automatically
//! when its `TransferProgressGuard` drops — including via
//! `hydrate_with_timeout`'s outer `tokio::time::timeout` cancelling the
//! whole future mid-flight — so a crashed or timed-out hydration can never
//! leak a stale "in progress" entry forever.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// One in-flight file transfer's progress: bytes_done / bytes_total,
/// blocks_done / blocks_total, source_peer, started_at.
/// Every field here is a count, a project-internal device id, or a
/// sync-relative file path already known to both peers over an
/// authenticated session — never raw content, so this is safe to surface
/// verbatim over the control socket the way `LinkStatus`
/// already surfaces `local_path`/`group_id`.
#[derive(Debug, Clone)]
pub struct ActiveTransferProgress {
    pub group_id: String,
    pub path: String,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub blocks_done: u64,
    pub blocks_total: u64,
    /// The most recent peer a block was actually fetched from — a
    /// multi-peer dispatch can pull blocks for the same file
    /// from several candidates, so this is "most recently active source,"
    /// not "the only source."
    pub source_peer: String,
    pub started_at_unix: i64,
}

/// An overall per-link rollup (sum across active transfers) for a
/// headline percent, plus a best-effort ETA derived from the
/// average throughput observed since the earliest active transfer in this
/// link started — deliberately simple (a cumulative average, not a
/// windowed/decaying rate estimator): a simple derived estimate,
/// best-effort, and every value here is explicitly labelled as such by
/// the CLI, not asserted as precise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkProgressRollup {
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub blocks_done: u64,
    pub blocks_total: u64,
    /// `None` when there's not yet enough signal (no bytes moved, or no
    /// active transfer) to derive a rate from.
    pub eta_seconds: Option<u64>,
}

struct Entry {
    path: String,
    bytes_done: u64,
    bytes_total: u64,
    blocks_done: u64,
    blocks_total: u64,
    source_peer: String,
    started_at_unix: i64,
}

/// Prometheus-style cumulative histogram buckets for block-fetch latency
/// (`yadorilink_block_fetch_seconds`) — the standard default bucket
/// boundaries (seconds), fine enough to distinguish a healthy LAN
/// round trip from a slow/lossy one without being a per-request trace of
/// anything content-identifying (it's purely a duration).
const HISTOGRAM_BUCKETS_SECONDS: &[f64] =
    &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

struct Histogram {
    /// Cumulative counts: `bucket_counts[i]` is the number of observations
    /// `<= HISTOGRAM_BUCKETS_SECONDS[i]`, matching OpenMetrics/Prometheus's
    /// own cumulative-histogram convention.
    bucket_counts: Vec<AtomicU64>,
    count: AtomicU64,
    /// Sum of all observed durations in microseconds (integer, so this
    /// stays lock-free) — rendered back out as seconds.
    sum_micros: AtomicU64,
}

impl Histogram {
    fn new() -> Self {
        Self {
            bucket_counts: HISTOGRAM_BUCKETS_SECONDS.iter().map(|_| AtomicU64::new(0)).collect(),
            count: AtomicU64::new(0),
            sum_micros: AtomicU64::new(0),
        }
    }

    fn observe(&self, seconds: f64) {
        for (bucket, count) in HISTOGRAM_BUCKETS_SECONDS.iter().zip(self.bucket_counts.iter()) {
            if seconds <= *bucket {
                count.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        let micros = (seconds * 1_000_000.0).round().clamp(0.0, u64::MAX as f64) as u64;
        self.sum_micros.fetch_add(micros, Ordering::Relaxed);
    }

    /// Renders this histogram as OpenMetrics text lines for metric family
    /// `name` — manual text rendering, with no metrics-framework dependency
    /// added for this one family.
    fn render_openmetrics(&self, name: &str) -> String {
        let mut out = format!("# TYPE {name} histogram\n");
        let mut cumulative = 0u64;
        for (bucket, count) in HISTOGRAM_BUCKETS_SECONDS.iter().zip(self.bucket_counts.iter()) {
            cumulative = count.load(Ordering::Relaxed);
            out += &format!("{name}_bucket{{le=\"{bucket}\"}} {cumulative}\n");
        }
        let total = self.count.load(Ordering::Relaxed);
        // `+Inf` bucket always equals the total observation count.
        out += &format!("{name}_bucket{{le=\"+Inf\"}} {}\n", total.max(cumulative));
        let sum_seconds = self.sum_micros.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        out += &format!("{name}_sum {sum_seconds}\n");
        out += &format!("{name}_count {total}\n");
        out
    }
}

struct Inner {
    active: Mutex<HashMap<(String, String), Entry>>,
    /// Monotonic, never-decreasing total of every byte actually written to
    /// the block store from a fetched block
    /// (`yadorilink_transfer_bytes_total` — a counter, unlike `bytes_done`
    /// above which resets to nothing once a transfer's entry is torn down).
    transfer_bytes_total: AtomicU64,
    block_fetch_seconds: Histogram,
}

/// Cheap-to-clone (`Arc`-backed) handle so it can be handed into
/// `hydration.rs`'s per-lane spawned worker tasks directly.
#[derive(Clone)]
pub struct TransferProgressTracker(Arc<Inner>);

impl Default for TransferProgressTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl TransferProgressTracker {
    pub fn new() -> Self {
        Self(Arc::new(Inner {
            active: Mutex::new(HashMap::new()),
            transfer_bytes_total: AtomicU64::new(0),
            block_fetch_seconds: Histogram::new(),
        }))
    }

    /// Registers a new active transfer and returns an RAII guard that
    /// removes it once dropped — see this module's doc comment for why
    /// that's what makes cleanup automatic even on a cancelled/timed-out
    /// hydration.
    pub fn begin(
        &self,
        group_id: impl Into<String>,
        path: impl Into<String>,
        bytes_total: u64,
        blocks_total: u64,
    ) -> TransferProgressGuard {
        let group_id = group_id.into();
        let path = path.into();
        let key = (group_id.clone(), path.clone());
        self.0.active.lock().unwrap_or_else(|p| p.into_inner()).insert(
            key.clone(),
            Entry {
                path,
                bytes_done: 0,
                bytes_total,
                blocks_done: 0,
                blocks_total,
                source_peer: String::new(),
                started_at_unix: now_unix(),
            },
        );
        TransferProgressGuard { tracker: self.clone(), key: Some(key) }
    }

    /// Records one more successfully-fetched-and-stored block for the
    /// `(group_id, path)` transfer — a no-op if that transfer's guard has
    /// already been dropped (a late/racing update after teardown).
    pub fn record_block_done(&self, group_id: &str, path: &str, bytes: u64, peer_id: &str) {
        let key = (group_id.to_string(), path.to_string());
        if let Some(entry) = self.0.active.lock().unwrap_or_else(|p| p.into_inner()).get_mut(&key) {
            entry.bytes_done = entry.bytes_done.saturating_add(bytes);
            entry.blocks_done = entry.blocks_done.saturating_add(1);
            entry.source_peer = peer_id.to_string();
        }
        self.0.transfer_bytes_total.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Records one block-fetch round trip's duration
    /// (`yadorilink_block_fetch_seconds`), whatever its outcome (found,
    /// not-found, or timed out) — `hydration.rs`'s dispatcher is the
    /// single choke point every block fetch already passes through.
    pub fn observe_block_fetch_seconds(&self, seconds: f64) {
        self.0.block_fetch_seconds.observe(seconds);
    }

    fn remove(&self, key: &(String, String)) {
        self.0.active.lock().unwrap_or_else(|p| p.into_inner()).remove(key);
    }

    /// Every currently-active transfer, for `yadorilink status`
    /// and the `/metrics` active-transfers gauge.
    pub fn snapshot(&self) -> Vec<ActiveTransferProgress> {
        self.0
            .active
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|((group_id, _), entry)| ActiveTransferProgress {
                group_id: group_id.clone(),
                path: entry.path.clone(),
                bytes_done: entry.bytes_done,
                bytes_total: entry.bytes_total,
                blocks_done: entry.blocks_done,
                blocks_total: entry.blocks_total,
                source_peer: entry.source_peer.clone(),
                started_at_unix: entry.started_at_unix,
            })
            .collect()
    }

    /// the per-link rollup — `None` when `group_id` has no
    /// currently-active transfer at all (distinct from "0% done," which is
    /// a real, just-started transfer).
    pub fn link_rollup(&self, group_id: &str) -> Option<LinkProgressRollup> {
        let active = self.0.active.lock().unwrap_or_else(|p| p.into_inner());
        let mut bytes_done = 0u64;
        let mut bytes_total = 0u64;
        let mut blocks_done = 0u64;
        let mut blocks_total = 0u64;
        let mut earliest_start: Option<i64> = None;
        let mut found = false;
        for ((g, _), entry) in active.iter() {
            if g != group_id {
                continue;
            }
            found = true;
            bytes_done = bytes_done.saturating_add(entry.bytes_done);
            bytes_total = bytes_total.saturating_add(entry.bytes_total);
            blocks_done = blocks_done.saturating_add(entry.blocks_done);
            blocks_total = blocks_total.saturating_add(entry.blocks_total);
            earliest_start = Some(
                earliest_start.map_or(entry.started_at_unix, |e| e.min(entry.started_at_unix)),
            );
        }
        if !found {
            return None;
        }
        let elapsed = earliest_start.map(|s| (now_unix() - s).max(0) as u64).unwrap_or(0);
        let eta_seconds = if bytes_done > 0 && elapsed > 0 && bytes_total > bytes_done {
            let rate = bytes_done as f64 / elapsed as f64; // best-effort, cumulative-average rate
            if rate > 0.0 {
                Some(((bytes_total - bytes_done) as f64 / rate).round() as u64)
            } else {
                None
            }
        } else {
            None
        };
        Some(LinkProgressRollup { bytes_done, bytes_total, blocks_done, blocks_total, eta_seconds })
    }

    pub fn active_transfer_count(&self) -> usize {
        self.0.active.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn transfer_bytes_total(&self) -> u64 {
        self.0.transfer_bytes_total.load(Ordering::Relaxed)
    }

    pub fn render_block_fetch_histogram(&self) -> String {
        self.0.block_fetch_seconds.render_openmetrics("yadorilink_block_fetch_seconds")
    }
}

/// RAII handle for one active transfer's lifetime — dropping it (however
/// that happens: normal completion, an early `?`-propagated error, or the
/// whole future being cancelled by `hydrate_with_timeout`'s outer
/// `tokio::time::timeout`) removes the corresponding entry, the same
/// "can't forget to release" guarantee `daemon_state::BroadcastGuard` gives
/// its own counter.
pub struct TransferProgressGuard {
    tracker: TransferProgressTracker,
    key: Option<(String, String)>,
}

impl Drop for TransferProgressGuard {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.tracker.remove(&key);
        }
    }
}

#[cfg(test)]
mod tests;
