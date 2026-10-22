use yadorilink_peer_session::PeerSessionError;

use super::types::*;

impl super::LocalConvergenceExecutor {
    pub(crate) fn headroom_override_bytes(&self) -> Option<u64> {
        *self.headroom_override_bytes.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Sets this executor's disk-headroom reserve override. Test-only:
    /// production preflights against the governance config's value.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_headroom_override_bytes_for_tests(&self, headroom_bytes: Option<u64>) {
        *self.headroom_override_bytes.lock().unwrap_or_else(|p| p.into_inner()) = headroom_bytes;
    }

    /// Turns the materialize-time disk-headroom preflight on or off for this
    /// executor. Test-only: production decides this once, at construction.
    #[cfg(any(test, feature = "test-support"))]
    pub fn set_headroom_enforced_for_tests(&self, enforced: bool) {
        self.headroom_enforced.store(enforced, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn headroom_enforced(&self) -> bool {
        self.headroom_enforced.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl super::LocalConvergenceExecutor {
    /// Flushes `hashes` (deduplicated by the caller already, if it
    /// matters) in ONE `record_group_block_provenance` call. `Ok(())` on
    /// an empty slice without touching the database at all. `call_timer`
    /// is `Some` only when this flush is part of the `reconcile_group_
    /// paths` call chain -- when given, this records the writer_gate
    /// wait/hold split for exactly this one write, from a narrow
    /// before/after diff of `yadorilink_sqlite_runtime::writer_gate_stats`'s
    /// own gate-wait counter (see `ReconcileCallTimer::add_sqlite_write`'s
    /// own doc comment for why this narrow a window is trustworthy).
    pub(crate) async fn flush_provenance_hashes(
        &self,
        group_id: &str,
        hashes: Vec<Vec<u8>>,
        call_timer: Option<&crate::local_convergence::call_timer::ReconcileCallTimer>,
    ) -> Result<(), PeerSessionError> {
        if hashes.is_empty() {
            return Ok(());
        }
        let index_state = self.state.clone();
        let provenance_group_id = group_id.to_string();
        let provenance_started = std::time::Instant::now();
        let gate_before = yadorilink_sqlite_runtime::writer_gate_stats::stats().1;
        let flush_result = spawn_blocking(move || {
            index_state.record_group_block_provenance(&provenance_group_id, &hashes)
        })
        .await;
        let provenance_elapsed = provenance_started.elapsed();
        if let Some(timer) = call_timer {
            let gate_wait =
                yadorilink_sqlite_runtime::writer_gate_stats::stats().1.saturating_sub(gate_before);
            timer.add_provenance_flush(provenance_elapsed);
            timer.add_sqlite_write(provenance_elapsed, gate_wait);
        }
        match flush_result {
            Ok(inner) => inner,
            Err(join_err) => Err(PeerSessionError::from(std::io::Error::other(format!(
                "block provenance batch write task panicked: {join_err}"
            )))),
        }
    }
}
