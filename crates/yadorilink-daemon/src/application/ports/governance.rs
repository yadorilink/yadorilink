//! What the `LimitsSet` control command needs to change the persisted resource
//! limits AND apply them to the running daemon's shared rate-limiter/
//! headroom state as one atomic operation -- never split into a
//! persist-then-apply pair the caller sequences itself, so a caller can
//! never observe "persisted but not yet applied" or apply a config that
//! failed to persist.

/// Application-owned mirror of `crate::governance_config::
/// ResourceGovernanceConfig` -- kept distinct so `application` never
/// names that daemon-local config-file type in a port signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GovernanceLimits {
    pub(crate) upload_bytes_per_sec: u64,
    pub(crate) download_bytes_per_sec: u64,
}

pub(crate) trait GovernanceCommandPort: Send + Sync {
    /// Persists the new limits, then immediately applies them to the
    /// running daemon's shared upload/download rate-limiter buckets --
    /// `Err` means persistence itself failed, in which case nothing is
    /// applied (a limit change either fully takes effect or not at all).
    fn set_limits(
        &self,
        upload_bytes_per_sec: u64,
        download_bytes_per_sec: u64,
    ) -> std::io::Result<GovernanceLimits>;
}
