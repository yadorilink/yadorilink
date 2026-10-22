//! On-disk persistence for the daemon's resource-governance configuration
//! (global upload/download rate limits, disk-space headroom override) —
//! mirrors `reporting::consent_store::ConsentStore`'s pattern exactly (a
//! small, independent JSON file under the config directory,
//! `#[serde(default)]` + a hand-written `Default` impl so an old/missing
//! file always resolves to the documented default rather than a
//! deserialization error, tempfile-then-rename writes).
//!
//! Living in its own file (rather than being bolted onto
//! `device_config::DeviceConfig`, which has no `#[serde(default)]` today
//! and would hard-fail deserialization on any new required field) means an
//! existing install with no `resource_governance.json` at all — the normal
//! case for every device that predates this feature — loads the safe,
//! spec-mandated default (`0`/unlimited rates, no headroom override)
//! without any migration step, providing version-safe defaulting for
//! existing installs.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Global transfer rate limits and disk-space headroom override. `0` for
/// either rate means unlimited (the default) — a bucket at rate `0` is
/// bypassed entirely, so an unconfigured install imposes no throttling.
/// `headroom_override_bytes` `None` means "use the default `max(1 GiB,
/// 5%)` formula"; `Some(_)` is an explicit override.
// Unlike `reporting::ConsentState` (which needs a hand-written `Default`
// impl because one of its fields defaults to `true`), every field here
// genuinely defaults to Rust's own zero-value default (`0`/`None`) — the
// spec-mandated default ("`0` = unlimited... default `0`", "no headroom
// override") happens to coincide exactly with `#[derive(Default)]`, so a
// hand-written impl would just be redundant (and clippy agrees).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourceGovernanceConfig {
    pub upload_limit_bytes_per_sec: u64,
    pub download_limit_bytes_per_sec: u64,
    pub headroom_override_bytes: Option<u64>,
}

pub struct GovernanceConfigStore {
    path: PathBuf,
}

impl GovernanceConfigStore {
    pub fn new(config_dir: impl AsRef<Path>) -> Self {
        GovernanceConfigStore { path: config_dir.as_ref().join("resource_governance.json") }
    }

    /// Reads the persisted config, or the documented default if no file
    /// has ever been written — deliberately does **not** write anything
    /// to disk, so simply loading can never turn a fresh install into
    /// one with a governance config file on disk.
    pub fn load(&self) -> std::io::Result<ResourceGovernanceConfig> {
        match std::fs::read_to_string(&self.path) {
            Ok(contents) => serde_json::from_str(&contents)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(ResourceGovernanceConfig::default())
            }
            Err(e) => Err(e),
        }
    }

    /// Best-effort read for call sites that must never fail (e.g. daemon
    /// startup): falls back to the safe default and logs a warning rather
    /// than propagating.
    pub fn load_or_default(&self) -> ResourceGovernanceConfig {
        match self.load() {
            Ok(config) => config,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %self.path.display(),
                    "resource-governance: failed to load config; using defaults (unlimited rates, default headroom)"
                );
                ResourceGovernanceConfig::default()
            }
        }
    }

    /// Writes `config` to disk, creating the config directory if needed.
    /// Writes to a temp file and renames over the target so a crash
    /// mid-write can't leave a half-written, unparseable config file behind.
    pub fn save(&self, config: &ResourceGovernanceConfig) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(config)?;
        let tmp_path = self.path.with_extension("json.tmp");
        std::fs::write(&tmp_path, json)?;
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    /// `yadorilink limits set --up <RATE> --down <RATE>` persists both
    /// rates in one write (rather than two separate round trips that
    /// could interleave with a concurrent read).
    pub fn set_limits(
        &self,
        upload_bytes_per_sec: u64,
        download_bytes_per_sec: u64,
    ) -> std::io::Result<ResourceGovernanceConfig> {
        let mut config = self.load_or_default();
        config.upload_limit_bytes_per_sec = upload_bytes_per_sec;
        config.download_limit_bytes_per_sec = download_bytes_per_sec;
        self.save(&config)?;
        Ok(config)
    }

    pub fn set_headroom_override_bytes(
        &self,
        headroom_bytes: Option<u64>,
    ) -> std::io::Result<ResourceGovernanceConfig> {
        let mut config = self.load_or_default();
        config.headroom_override_bytes = headroom_bytes;
        self.save(&config)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests;
