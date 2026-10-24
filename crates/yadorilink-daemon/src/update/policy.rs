//! On-disk persistence for the daemon's update policy and last-known
//! update-attempt state — mirrors
//! `governance_config::GovernanceConfigStore`'s exact pattern (a small,
//! independent JSON file under the config directory, `#[serde(default)]`
//! plus a hand-written `Default` so an old/missing file always resolves
//! to a safe default rather than a deserialization error, tempfile-then-
//! rename writes so a crash mid-write never leaves a half-written,
//! unparseable file behind).
//!
//! Living in its own file (not bolted onto `device_config::DeviceConfig`)
//! means an existing install with no `update_policy.json` at all — every
//! device that existed before this update-policy feature shipped —
//! loads the documented safe default (checks enabled, `Idle` state) with no migration step, the same
//! "version-safe defaulting for existing installs" property
//! `GovernanceConfigStore`'s own doc comment calls out.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One state per update attempt, persisted so a restart after crash can
/// tell what was in flight. `Idle` is the steady state between checks;
/// `UpToDate` means the most recent check found nothing newer;
/// `HeldBack`/`KillSwitched` mean an applicable-looking newer version
/// exists but isn't currently installable (rollout holdback or a
/// manifest kill-switch entry) — tracked as distinct states (not folded
/// into `Available`) so `yadorilink update status`/`yadorilink status`
/// can say *why* nothing is happening.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateState {
    #[default]
    Idle,
    Checking,
    Available,
    HeldBack,
    KillSwitched,
    Failed,
    UpToDate,
}

impl UpdateState {
    pub fn as_str(&self) -> &'static str {
        match self {
            UpdateState::Idle => "idle",
            UpdateState::Checking => "checking",
            UpdateState::Available => "available",
            UpdateState::HeldBack => "held_back",
            UpdateState::KillSwitched => "kill_switched",
            UpdateState::Failed => "failed",
            UpdateState::UpToDate => "up_to_date",
        }
    }
}

/// A coarse, stable category for the last update-attempt failure — never
/// the raw error text — matching `CliError::report_category`'s
/// established convention in this workspace.
pub type ErrorCategory = String;

/// The error category of a check refused because the manifest had expired.
pub const EXPIRED_CATEGORY: &str = "update_manifest_expired";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdatePolicy {
    pub channel: String,
    pub automatic_checks_enabled: bool,
    /// Unix seconds; `None` means "never checked".
    pub last_check_unix: Option<i64>,
    /// Unix seconds of the last check that fetched and accepted a manifest (or found the channel
    /// empty); `None` means "never succeeded". Unlike `last_check_unix` a failed check leaves it.
    #[serde(default)]
    pub last_success_unix: Option<i64>,
    /// `expires_at` of the manifest the last check saw, kept also when that manifest was refused
    /// as expired; `None` before the first manifest or for a channel with none.
    #[serde(default)]
    pub manifest_expires_at: Option<String>,
    pub last_error_category: Option<ErrorCategory>,
    pub last_error_message: Option<String>,
    pub state: UpdateState,
    pub available_version: Option<String>,
    pub available_release_notes_url: Option<String>,
    pub mandatory: bool,
    /// The newest matching release's `minimum_supported_version`, as the last successful check
    /// saw it; `None` when that check found nothing newer. This is the one cutover marker: whether
    /// an update is *required* is derived from it against the version running now
    /// ([`Self::update_required`]), never remembered as a verdict, so an updated build stops
    /// reporting it without waiting for the next check. Only a parseable version is recorded.
    #[serde(default)]
    pub minimum_supported_version: Option<String>,
    pub holdback_reason: Option<String>,
    /// A stable value in `0..100`, generated once and persisted forever
    /// (never re-rolled), used only locally to decide staged-rollout
    /// eligibility (`manifest::LocalContext::rollout_bucket`) — never
    /// sent in any update-check request (see
    /// the update privacy rule).
    pub rollout_bucket: u8,
    /// The account's
    /// stable beta cohort, or `None` for a non-tester. Populated by the
    /// client (desktop/CLI) from the coordination plane's `GET /account/beta`
    /// and persisted here; the daemon reads it only to derive a *stable*
    /// rollout bucket for a tester (see `effective_rollout_bucket`), so a
    /// cohort maps consistently onto the manifest's rollout percentage
    /// release-over-release rather than being re-bucketed each release. Like
    /// `rollout_bucket`, it is never sent in an update-check request.
    #[serde(default)]
    pub beta_cohort: Option<String>,
}

/// A deterministic, platform- and release-stable `0..100` bucket for a beta
/// cohort. FNV-1a over the cohort bytes (implemented inline so the mapping
/// never depends on an unstable `std` hash) taken mod 100, so every install
/// in the same cohort maps to the same bucket, release-over-release. This is
/// what makes a staged rollout target *real, stable cohorts* rather than an
/// opaque per-install hash bucket.
fn cohort_rollout_bucket(cohort: &str) -> u8 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in cohort.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (hash % 100) as u8
}

impl UpdatePolicy {
    /// The last check refused the channel manifest because it had expired.
    pub fn manifest_expired(&self) -> bool {
        self.last_error_category.as_deref() == Some(EXPIRED_CATEGORY)
    }

    /// Whether `running` is below the signed minimum supported version, i.e. this device can no
    /// longer sync with devices on the current protocol generation until it updates. Equal to the
    /// minimum is supported. A missing or unparseable minimum requires nothing. While the
    /// channel manifest is expired the recorded minimum cannot be confirmed, so nothing is
    /// required: the status reads "cannot confirm update", never "update required".
    pub fn update_required(&self, running: &semver::Version) -> bool {
        if self.manifest_expired() {
            return false;
        }
        self.minimum_supported_version
            .as_deref()
            .and_then(|raw| super::manifest::parse_semver(raw).ok())
            .is_some_and(|minimum| *running < minimum)
    }

    /// The rollout bucket the update check should use. A beta tester's bucket
    /// is a stable function of their cohort, so all of a tester's installs
    /// (and every install in that cohort) fall inside or outside a given
    /// rollout percentage together, consistently across releases. A
    /// non-tester keeps the ordinary per-install `rollout_bucket`, so
    /// non-tester behavior is entirely unchanged.
    pub fn effective_rollout_bucket(&self) -> u8 {
        match &self.beta_cohort {
            Some(cohort) => cohort_rollout_bucket(cohort),
            None => self.rollout_bucket,
        }
    }
}

impl Default for UpdatePolicy {
    fn default() -> Self {
        UpdatePolicy {
            // Public beta builds default to the `beta` channel. This
            // crate has no separate beta/production build flag today,
            // so `beta` is this crate's default for every install
            // until release packaging introduces one.
            channel: "beta".to_string(),
            automatic_checks_enabled: true,
            last_check_unix: None,
            last_success_unix: None,
            manifest_expires_at: None,
            last_error_category: None,
            last_error_message: None,
            state: UpdateState::Idle,
            available_version: None,
            available_release_notes_url: None,
            mandatory: false,
            minimum_supported_version: None,
            holdback_reason: None,
            rollout_bucket: 0,
            beta_cohort: None,
        }
    }
}

pub struct UpdatePolicyStore {
    path: PathBuf,
}

impl UpdatePolicyStore {
    pub fn new(config_dir: impl AsRef<Path>) -> Self {
        UpdatePolicyStore { path: config_dir.as_ref().join("update_policy.json") }
    }

    /// Reads the persisted policy, or the documented default if no file
    /// has ever been written. Deliberately does **not** write anything to
    /// disk, so simply loading (or `load_or_default`) can never turn a
    /// fresh install into one with an update-policy file on disk.
    pub fn load(&self) -> std::io::Result<UpdatePolicy> {
        match std::fs::read_to_string(&self.path) {
            Ok(contents) => serde_json::from_str(&contents)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UpdatePolicy {
                rollout_bucket: fresh_rollout_bucket(),
                ..UpdatePolicy::default()
            }),
            Err(e) => Err(e),
        }
    }

    pub fn load_or_default(&self) -> UpdatePolicy {
        match self.load() {
            Ok(policy) => policy,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %self.path.display(),
                    "update-policy: failed to load config; using defaults"
                );
                UpdatePolicy { rollout_bucket: fresh_rollout_bucket(), ..UpdatePolicy::default() }
            }
        }
    }

    /// Writes to a temp file and renames over the target, matching
    /// `GovernanceConfigStore::save`'s crash-safety discipline.
    pub fn save(&self, policy: &UpdatePolicy) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(policy)?;
        let tmp_path = self.path.with_extension("json.tmp");
        std::fs::write(&tmp_path, json)?;
        std::fs::rename(&tmp_path, &self.path)?;
        Ok(())
    }

    /// Loads the current policy (assigning a fresh `rollout_bucket` the
    /// very first time, so it's persisted from that point on), applies
    /// `mutate`, saves, and returns the resulting policy — the standard
    /// read-modify-write shape every control-socket update-policy handler
    /// uses.
    pub fn update(&self, mutate: impl FnOnce(&mut UpdatePolicy)) -> std::io::Result<UpdatePolicy> {
        let mut policy = self.load_or_default();
        mutate(&mut policy);
        self.save(&policy)?;
        Ok(policy)
    }
}

fn fresh_rollout_bucket() -> u8 {
    rand::random_range(0..100)
}

#[cfg(test)]
mod tests;
