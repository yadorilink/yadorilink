//! `GovernanceConfigStore`/`RateLimiters`/`BlockStore`-backed
//! [`GovernanceCommandPort`] -- persists the new limits then immediately
//! applies them to the running daemon's shared rate-limiter buckets and
//! block-store headroom override, as one atomic operation. Holds these
//! three narrow `Arc`s directly (no `Arc<DaemonState>` strangler needed --
//! unlike `resume_link`/handoff, "set limits" was never deeply entangled
//! with the rest of `DaemonState`).

use std::sync::Arc;

use yadorilink_local_storage::BlockStore;
use yadorilink_peer_session::rate_limiter::RateLimiters;

use crate::application::ports::{GovernanceCommandPort, GovernanceLimits};
use crate::governance_config::GovernanceConfigStore;

pub(crate) struct DaemonGovernanceCommandAdapter {
    governance_config: Arc<GovernanceConfigStore>,
    rate_limiters: Arc<RateLimiters>,
    block_store: Arc<dyn BlockStore + Send + Sync>,
}

impl DaemonGovernanceCommandAdapter {
    pub(crate) fn new(
        governance_config: Arc<GovernanceConfigStore>,
        rate_limiters: Arc<RateLimiters>,
        block_store: Arc<dyn BlockStore + Send + Sync>,
    ) -> Self {
        Self { governance_config, rate_limiters, block_store }
    }
}

impl GovernanceCommandPort for DaemonGovernanceCommandAdapter {
    fn set_limits(
        &self,
        upload_bytes_per_sec: u64,
        download_bytes_per_sec: u64,
    ) -> std::io::Result<GovernanceLimits> {
        let config =
            self.governance_config.set_limits(upload_bytes_per_sec, download_bytes_per_sec)?;
        // Apply immediately to the running daemon's shared buckets, not
        // just persist to disk -- a `limits set` takes effect without a
        // restart.
        self.rate_limiters.upload.set_rate_bytes_per_sec(config.upload_limit_bytes_per_sec);
        self.rate_limiters.download.set_rate_bytes_per_sec(config.download_limit_bytes_per_sec);
        self.block_store.set_headroom_override_bytes(config.headroom_override_bytes);
        Ok(GovernanceLimits {
            upload_bytes_per_sec: config.upload_limit_bytes_per_sec,
            download_bytes_per_sec: config.download_limit_bytes_per_sec,
        })
    }
}
