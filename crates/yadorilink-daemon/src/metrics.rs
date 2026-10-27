//! The daemon's opt-in Prometheus/OpenMetrics `/metrics` endpoint —
//! manual, no-framework text rendering that reaches directly into the same
//! shared `DaemonState` the control socket's `status` handler already
//! reads, rather than a parallel bookkeeping path.
//!
//! Metric families: `yadorilink_transfer_bytes_total` (counter),
//! `yadorilink_active_transfers` (gauge), `yadorilink_active_peers` (gauge),
//! `yadorilink_sync_errors_total{category}` (counter),
//! `yadorilink_block_fetch_seconds` (histogram),
//! `yadorilink_replication_deltas_total{outcome}` (counter: admitted, duplicate, held,
//! rejected), `yadorilink_replication_served_bytes_total` and
//! `yadorilink_replication_served_messages_total` (counters). Every label/value here is a
//! count or a bounded-cardinality category string — the test
//! (`tests::privacy_safe_metrics_never_contain_content_paths_keys_tokens_or_ips`)
//! asserts none of them ever carries content, a file name, an absolute
//! path, a key, a token, or a peer IP.

use std::sync::Arc;

use crate::daemon_state::DaemonState;

#[derive(Clone)]
pub struct DaemonMetrics {
    state: Arc<DaemonState>,
}

impl DaemonMetrics {
    pub fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    pub fn render_openmetrics(&self) -> String {
        let active_transfers = self.state.telemetry.active_transfer_count();
        let active_peers = self.state.peer_connectivity.connected_peer_count();
        let transfer_bytes_total = self.state.telemetry.transfer_bytes_total();

        let mut out = String::new();
        out += "# TYPE yadorilink_transfer_bytes_total counter\n";
        out += &format!("yadorilink_transfer_bytes_total {transfer_bytes_total}\n");
        out += "# TYPE yadorilink_active_transfers gauge\n";
        out += &format!("yadorilink_active_transfers {active_transfers}\n");
        out += "# TYPE yadorilink_active_peers gauge\n";
        out += &format!("yadorilink_active_peers {active_peers}\n");

        let counts = self.state.telemetry.replication_counters().snapshot();
        out += "# TYPE yadorilink_replication_deltas_total counter\n";
        for (outcome, count) in [
            ("admitted", counts.deltas_admitted),
            ("duplicate", counts.deltas_duplicate),
            ("held", counts.deltas_held),
            ("rejected", counts.deltas_rejected),
        ] {
            out +=
                &format!("yadorilink_replication_deltas_total{{outcome=\"{outcome}\"}} {count}\n");
        }
        out += "# TYPE yadorilink_replication_served_bytes_total counter\n";
        out += &format!("yadorilink_replication_served_bytes_total {}\n", counts.served_bytes);
        out += "# TYPE yadorilink_replication_served_messages_total counter\n";
        out +=
            &format!("yadorilink_replication_served_messages_total {}\n", counts.served_messages);

        out += "# TYPE yadorilink_sync_errors_total counter\n";
        let mut category_counts = self.state.telemetry.recent_error_category_counts();
        // Deterministic ordering — cosmetic only (a `HashMap` iteration
        // order would still be a valid OpenMetrics document), but makes
        // the endpoint's output byte-stable for a fixed set of categories,
        // which is nicer for anything diffing scrape output.
        category_counts.sort_by_key(|(category, _)| *category);
        for (category, count) in category_counts {
            out += &format!("yadorilink_sync_errors_total{{category=\"{category}\"}} {count}\n");
        }

        out += &self.state.telemetry.render_block_fetch_histogram();
        out
    }
}

#[cfg(test)]
mod tests;
