// apple-cfg-file: macos-only self-update of the macOS app; iOS updates through the App Store
//! Orchestrates the update check on top of `manifest` and `policy`.
//!
//! v1 ships manual updates: the daemon only discovers (signed manifest ->
//! `manifest::verify_and_parse` -> `manifest::select_applicable`) and
//! reports that a newer version exists; the user downloads and installs
//! it from the official download page. Nothing is downloaded or installed
//! by the daemon.

use std::path::Path;
use std::time::Duration;

use super::install_source;
use super::manifest::{self, Applicability, LocalContext};
use super::policy::{UpdatePolicy, UpdatePolicyStore, UpdateState};
use super::replay::{AcceptedGeneration, ReplayError, ReplayStore};
use super::trust::TrustStore;

#[derive(Debug, Clone, thiserror::Error)]
pub enum UpdateError {
    #[error("failed to fetch update manifest: {0}")]
    Fetch(String),
    #[error("update manifest rejected: {0}")]
    Manifest(#[from] manifest::ManifestError),
    #[error("update manifest refused as a replay: {0}")]
    Replay(#[from] ReplayError),
    #[error("failed to persist update policy: {0}")]
    Policy(String),
}

impl From<std::io::Error> for UpdateError {
    fn from(e: std::io::Error) -> Self {
        UpdateError::Policy(e.to_string())
    }
}

impl UpdateError {
    /// A coarse, stable category — never the raw message — matching this
    /// workspace's `CliError::report_category` convention, stored in
    /// `UpdatePolicy::last_error_category`.
    pub fn category(&self) -> &'static str {
        match self {
            UpdateError::Fetch(_) => "update_manifest_fetch_failed",
            UpdateError::Manifest(manifest::ManifestError::Expired { .. }) => {
                super::policy::EXPIRED_CATEGORY
            }
            UpdateError::Manifest(_) => "update_manifest_invalid",
            UpdateError::Replay(_) => "update_manifest_replayed",
            UpdateError::Policy(_) => "update_policy_persist_failed",
        }
    }
}

/// Which rule `UpdateManager::check_version` applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionCheckKind {
    /// An online install of a pinned version (`self-update --version`): refused when the live
    /// manifest withdraws, kill-switches or floors it.
    PinnedInstall,
    /// An appcast item the app is about to hand to Sparkle: must be exactly what the verified
    /// manifest serves to this install.
    AppcastItem,
}

/// How long a verified manifest answers [`UpdateManager::verified_entry`] after it was verified:
/// longer than the periodic check interval plus its jitter and retries, so a daemon whose checks
/// keep failing stops vouching for an entry rather than vouching from old data.
const VERIFIED_MAX_AGE_SECS: i64 = 12 * 3600;

#[derive(Debug, Clone)]
struct VerifiedManifest {
    channel: String,
    at_unix: i64,
    /// `None`: the channel had no manifest when last asked.
    manifest: Option<manifest::UpdateManifest>,
}

/// Why the daemon cannot say whether an item is covered. Distinct from a refusal: nothing is
/// known to be wrong, so an app shows "cannot confirm", never "update required".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CannotConfirm {
    /// No manifest was verified since the daemon started (or since the channel changed).
    NotChecked,
    /// The last verified manifest is older than the daemon is willing to vouch for.
    Stale,
    /// The last verified manifest has expired.
    Expired { expires_at: String },
    /// The channel has no manifest.
    NoManifest,
}

impl std::fmt::Display for CannotConfirm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotChecked => f.write_str("the update manifest has not been verified yet"),
            Self::Stale => f.write_str("the last verified update manifest is too old to rely on"),
            Self::Expired { expires_at } => {
                write!(f, "the verified update manifest expired at {expires_at}")
            }
            Self::NoManifest => f.write_str("the channel has no update manifest"),
        }
    }
}

impl CannotConfirm {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotChecked => "not_checked",
            Self::Stale => "stale",
            Self::Expired { .. } => "manifest_expired",
            Self::NoManifest => "no_manifest",
        }
    }
}

#[derive(Debug, Clone)]
pub enum EntryRefusal {
    CannotConfirm(CannotConfirm),
    Refused(manifest::VersionRefusal),
}

/// The verified `app_bundle` entry for this install, as the app caches it.
#[derive(Debug, Clone)]
pub struct VerifiedEntry {
    pub entry: manifest::ReleaseEntry,
    pub file: String,
    pub generated_at: String,
    pub expires_at: String,
    /// This build is below the entry's `minimum_supported_version`.
    pub update_required: bool,
}

#[derive(Debug, Clone)]
pub struct VerifiedEntryAnswer {
    /// Present whenever a fresh, unexpired verified manifest has an entry for this install,
    /// also when the item is refused.
    pub entry: Option<VerifiedEntry>,
    pub verdict: Result<(), EntryRefusal>,
}

impl VerifiedEntryAnswer {
    fn cannot_confirm(why: CannotConfirm) -> Self {
        Self { entry: None, verdict: Err(EntryRefusal::CannotConfirm(why)) }
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum VersionCheckError {
    #[error("the channel manifest could not be verified: {0}")]
    Unverifiable(UpdateError),
    #[error("the channel has no manifest")]
    NoManifest,
    #[error("{0}")]
    Refused(manifest::VersionRefusal),
}

/// This install's coarse platform identity — never anything more
/// identifying (device id, account id) — 's `LocalContext` plus the
/// install-source distinction from `install_source`.
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub platform: String,
    pub arch: String,
    pub install_source: String,
}

impl PlatformInfo {
    /// `declared_install_source` is the install source an image declares for itself (the
    /// desktop daemon's `YADORILINK_INSTALL_SOURCE`); only `container` is honoured.
    pub fn detect(declared_install_source: Option<&str>) -> Self {
        // apple-cfg: ios-explicit iOS is its own platform: its updates come from the App Store
        let platform = if cfg!(target_os = "ios") {
            "ios"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "windows") {
            "windows"
        } else {
            "linux"
        }
        .to_string();
        let arch = std::env::consts::ARCH.to_string();
        // The app bundle layout and the container marker say nothing on iOS: the App Store is
        // the only way an iOS install exists, so it is not refined.
        let install_source = if cfg!(target_os = "ios") {
            install_source::InstallSource::AppStore.as_str().to_string()
        } else {
            let exe = install_source::running_exe();
            install_source::refine(detect_install_source(), &exe, declared_install_source)
        };
        PlatformInfo { platform, arch, install_source }
    }
}

#[cfg(windows)]
fn detect_install_source() -> String {
    let exe = install_source::running_exe();
    match install_source::detect_windows_install_source(&exe) {
        install_source::InstallSource::MicrosoftStore => {
            install_source::InstallSource::MicrosoftStore.as_str().to_string()
        }
        // The Store's MSIX path is a structural signal checked first and
        // takes precedence; only a non-Store install can also be a WinGet
        // one (see `install_source::detect_package_manager_marker`'s doc
        // comment on why WinGet needs its own installer-written marker).
        // The Windows detection never yields it.
        install_source::InstallSource::AppStore => {
            install_source::InstallSource::AppStore.as_str().to_string()
        }
        install_source::InstallSource::Standalone => {
            install_source::detect_package_manager_marker()
                .unwrap_or_else(|| install_source::InstallSource::Standalone.as_str().to_string())
        }
    }
}

// iOS never asks: `PlatformInfo::detect` answers `app_store` without detection.
#[cfg(target_os = "ios")]
fn detect_install_source() -> String {
    install_source::InstallSource::AppStore.as_str().to_string()
}

#[cfg(target_os = "macos")]
fn detect_install_source() -> String {
    install_source::detect_macos_install_source()
}

#[cfg(target_os = "linux")]
fn detect_install_source() -> String {
    let exe = install_source::running_exe();
    install_source::detect_linux_install_source(install_source_runner(), &exe)
}

#[cfg(all(target_os = "linux", not(test)))]
fn install_source_runner() -> &'static dyn install_source::CommandRunner {
    &install_source::SystemCommandRunner
}

/// A test binary runs many tests in one process, some holding sync-root OS locks. A child
/// process spawned meanwhile shares every open lock until it execs, which can make another
/// test's release-then-reacquire fail with "already in use". So a test binary never spawns the
/// package-manager probe; the detection logic itself is tested through its injectable runner.
#[cfg(all(target_os = "linux", test))]
fn install_source_runner() -> &'static dyn install_source::CommandRunner {
    &tests::NoSpawnRunner
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux", target_os = "ios")))]
fn detect_install_source() -> String {
    "standalone".to_string()
}

/// A manifest fetch follows at most this many redirects, and only to an
/// `https` URL -- see the `redirect::Policy::custom` closure in
/// `UpdateManager::new`.
const MAX_DOWNLOAD_REDIRECTS: usize = 5;

pub struct UpdateManager {
    pub policy: UpdatePolicyStore,
    trust: TrustStore,
    replay: ReplayStore,
    /// The newest manifest this process verified, for [`UpdateManager::verified_entry`], which
    /// answers from it without touching the network or the replay floor.
    verified: std::sync::Mutex<Option<VerifiedManifest>>,
    http: reqwest::Client,
    manifest_url: String,
    current_version: semver::Version,
    platform_info: PlatformInfo,
    /// Substitutes the pinned production `manifest::TRUSTED_KEYS` trust
    /// root for `check_now`'s verification step. Never set outside a test
    /// binary: a real daemon must only ever trust the one pinned root.
    /// Exists so an integration test can exercise the exact `check_now`
    /// path (real HTTP fetch, real `manifest::verify_and_parse_with_keys`
    /// call) against a manifest signed with a throwaway test key, instead
    /// of stopping short at `manifest::verify_and_parse_with_keys` alone.
    /// Only this crate's own `#[cfg(test)]` code uses it, so it is not
    /// gated on `test-support` (unlike sibling overrides in this crate
    /// that other crates' tests do need to reach).
    #[cfg(test)]
    trusted_keys_override: Option<Vec<manifest::TrustedKey>>,
    /// Test-only fixed clock (Unix seconds) for the manifest expiry check.
    #[cfg(test)]
    now_override: Option<i64>,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl UpdateManager {
    /// `manifest_url` is overridable through the tuning's `update_manifest_url` (the desktop
    /// daemon maps `YADORILINK_UPDATE_MANIFEST_URL` into it) so this is testable
    /// against a local mock server without touching production config.
    /// The built-in default points at the coordination Worker's own
    /// `/updates/:channel/manifest.json` route (R2-backed, see
    /// the coordination service), served from this
    /// Worker's one configured production route
    /// (the coordination service's `routes` entry) -- not a
    /// placeholder domain.
    pub fn new(
        config_dir: impl AsRef<Path>,
        current_version: semver::Version,
        tuning: &crate::engine_tuning::EngineTuning,
    ) -> Self {
        let manifest_url = tuning.update_manifest_url.clone().unwrap_or_else(|| {
            "https://control.yadori.link/updates/beta/manifest.json".to_string()
        });
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent(format!("yadorilink-daemon/{current_version}"))
            // Defense in depth: a manifest/artifact fetch must
            // never be redirected off HTTPS (a downgrade a hostile or
            // compromised host could otherwise use to serve an
            // arbitrary plaintext response) and must never chase an
            // unbounded redirect chain.
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= MAX_DOWNLOAD_REDIRECTS {
                    return attempt.error(format!(
                        "exceeded {MAX_DOWNLOAD_REDIRECTS} redirects while fetching an update resource"
                    ));
                }
                if attempt.url().scheme() != "https" {
                    let url = attempt.url().clone();
                    return attempt.error(format!("refusing to follow a redirect to a non-https URL: {url}"));
                }
                attempt.follow()
            }))
            .build()
            .expect("reqwest client construction with only timeout/user-agent/redirect set cannot fail");
        UpdateManager {
            policy: UpdatePolicyStore::new(config_dir.as_ref()),
            trust: TrustStore::new(config_dir.as_ref()),
            replay: ReplayStore::new(config_dir.as_ref()),
            verified: std::sync::Mutex::new(None),
            http,
            manifest_url,
            current_version,
            platform_info: PlatformInfo::detect(tuning.install_source.as_deref()),
            #[cfg(test)]
            trusted_keys_override: None,
            #[cfg(test)]
            now_override: None,
        }
    }

    /// Test-only: the clock `check_now` judges manifest expiry against.
    #[cfg(test)]
    pub fn set_now_for_test(&mut self, now_unix: i64) {
        self.now_override = Some(now_unix);
    }

    fn now(&self) -> i64 {
        #[cfg(test)]
        if let Some(now) = self.now_override {
            return now;
        }
        now_unix()
    }

    /// Test-only: `check_now` verifies against `keys` instead of the
    /// pinned production `manifest::TRUSTED_KEYS`, so a test can exercise
    /// the real `check_now` path against a manifest signed with a
    /// throwaway key (see `manifest::test_support`).
    #[cfg(test)]
    pub fn set_trusted_keys_for_test(&mut self, keys: Vec<manifest::TrustedKey>) {
        self.trusted_keys_override = Some(keys);
    }

    pub fn current_version(&self) -> &semver::Version {
        &self.current_version
    }

    pub fn platform_info(&self) -> &PlatformInfo {
        &self.platform_info
    }

    fn local_context(&self, policy: &UpdatePolicy) -> LocalContext {
        LocalContext {
            current_version: self.current_version.clone(),
            channel: policy.channel.clone(),
            platform: self.platform_info.platform.clone(),
            arch: self.platform_info.arch.clone(),
            install_source: self.platform_info.install_source.clone(),
            // A beta tester's
            // bucket is derived from their stable cohort so a staged rollout
            // targets whole cohorts consistently across releases; a non-tester
            // keeps the ordinary per-install bucket unchanged.
            rollout_bucket: policy.effective_rollout_bucket(),
            state_schema_version: u32::try_from(yadorilink_sqlite_runtime::SCHEMA_VERSION)
                .unwrap_or(0),
        }
    }

    /// Fetches and verifies the manifest, decides
    /// applicability, and persists the resulting state — never downloads
    /// or installs anything itself. Callable both from the periodic
    /// scheduler and directly from `yadorilink update check`.
    pub async fn check_now(&self) -> Result<Applicability, UpdateError> {
        let _ = self.policy.update(|p| p.state = UpdateState::Checking);
        let result = self.check_now_inner().await;
        match &result {
            Ok((applicability, expires_at)) => {
                self.record_applicability(applicability, expires_at.as_deref())?;
            }
            Err(e) => {
                self.policy.update(|p| {
                    p.state = UpdateState::Failed;
                    p.last_error_category = Some(e.category().to_string());
                    p.last_error_message = Some(e.to_string());
                    p.last_check_unix = Some(self.now());
                    if let UpdateError::Manifest(manifest::ManifestError::Expired { expires_at }) =
                        e
                    {
                        p.manifest_expires_at = Some(expires_at.clone());
                    }
                })?;
            }
        }
        result.map(|(applicability, _)| applicability)
    }

    /// The applicability, plus the `expires_at` of the manifest it came from (`None` for a
    /// channel with no manifest).
    async fn check_now_inner(&self) -> Result<(Applicability, Option<String>), UpdateError> {
        let policy = self.policy.load_or_default();
        match self.fetch_verified_manifest(&policy).await? {
            // A channel nothing has been released on yet has no manifest: there is nothing to
            // update to, which is not a failed check.
            None => Ok((Applicability::UpToDate, None)),
            Some(manifest) => Ok((
                manifest::select_applicable(&manifest, &self.local_context(&policy)),
                Some(manifest.expires_at.clone()),
            )),
        }
    }

    /// Fetches the channel manifest and returns it only once its signature verifies under the
    /// persisted trust chain and the replay floor accepts it. `None` means the channel has no
    /// manifest (404). Every other failure is an error: nothing unverified is ever returned.
    async fn fetch_verified_manifest(
        &self,
        policy: &UpdatePolicy,
    ) -> Result<Option<manifest::UpdateManifest>, UpdateError> {
        let response = self
            .http
            .get(&self.manifest_url)
            .query(&self.update_check_query(policy))
            .send()
            .await
            .map_err(|e| UpdateError::Fetch(e.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            self.remember_verified(&policy.channel, None);
            return Ok(None);
        }
        let response =
            response.error_for_status().map_err(|e| UpdateError::Fetch(e.to_string()))?;
        let body = response.text().await.map_err(|e| UpdateError::Fetch(e.to_string()))?;
        let envelope = manifest::parse_envelope(&body)?;
        #[cfg(test)]
        let genesis: &[manifest::TrustedKey] = match &self.trusted_keys_override {
            Some(keys) => keys,
            None => manifest::TRUSTED_KEYS,
        };
        #[cfg(not(test))]
        let genesis: &[manifest::TrustedKey] = manifest::TRUSTED_KEYS;
        // The persisted chain (plus any verified extension the server offers)
        // decides which keys are trusted; a revoked key stays revoked even if
        // a later response omits the chain.
        let state = self
            .trust
            .sync(genesis, &envelope.trust_chain)
            .map_err(manifest::ManifestError::from)?;
        let manifest = manifest::verify_envelope(&envelope, &state)?;
        // Freshness before the floor: an expired manifest is not acted on, so it must not move
        // the replay floor either. Only update checks stop; nothing else reads this result.
        manifest::check_not_expired(&manifest, self.now())?;
        manifest::check_not_future_dated(&manifest, self.now())?;
        // Only a manifest that verified may move the replay floor, and it is stored before the
        // manifest is acted on.
        self.accept_and_remember(&policy.channel, &manifest, &body)?;
        Ok(Some(manifest))
    }

    fn remember_verified(&self, channel: &str, manifest: Option<manifest::UpdateManifest>) {
        *self.verified.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(VerifiedManifest { channel: channel.into(), at_unix: self.now(), manifest });
    }

    /// Moves the replay floor and records the manifest under one lock, so concurrent checks
    /// cannot leave the cache older than the floor: whoever accepts last also remembers last.
    fn accept_and_remember(
        &self,
        channel: &str,
        manifest: &manifest::UpdateManifest,
        body: &str,
    ) -> Result<(), ReplayError> {
        let mut cache = self.verified.lock().unwrap_or_else(|e| e.into_inner());
        self.replay.accept(channel, &manifest.generated_at, body)?;
        *cache = Some(VerifiedManifest {
            channel: channel.into(),
            at_unix: self.now(),
            manifest: Some(manifest.clone()),
        });
        Ok(())
    }

    /// Whether `item` is covered by the `app_bundle` entry of the manifest this daemon last
    /// verified, and that entry. Reads only what an earlier check verified: no network, and the
    /// replay floor is never touched. Fails closed: with no fresh, unexpired verified manifest
    /// for the current channel the answer is `CannotConfirm`, never "allowed".
    pub fn verified_entry(
        &self,
        item: &manifest::AppcastItem,
        phase: manifest::AppcastPhase,
    ) -> VerifiedEntryAnswer {
        let policy = self.policy.load_or_default();
        let cached = self.verified.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let Some(cached) = cached.filter(|c| c.channel == policy.channel) else {
            return VerifiedEntryAnswer::cannot_confirm(CannotConfirm::NotChecked);
        };
        let now = self.now();
        if now.saturating_sub(cached.at_unix) > VERIFIED_MAX_AGE_SECS || now < cached.at_unix {
            return VerifiedEntryAnswer::cannot_confirm(CannotConfirm::Stale);
        }
        let Some(doc) = cached.manifest else {
            return VerifiedEntryAnswer::cannot_confirm(CannotConfirm::NoManifest);
        };
        if let Err(manifest::ManifestError::Expired { expires_at }) =
            manifest::check_not_expired(&doc, now)
        {
            return VerifiedEntryAnswer::cannot_confirm(CannotConfirm::Expired { expires_at });
        }
        let ctx = self.local_context(&policy);
        let Some(entry) = doc
            .releases
            .iter()
            .find(|e| {
                e.channel == ctx.channel
                    && e.platform == ctx.platform
                    && e.arch == ctx.arch
                    && e.install_source == ctx.install_source
            })
            .cloned()
        else {
            return VerifiedEntryAnswer {
                entry: None,
                verdict: Err(EntryRefusal::Refused(manifest::VersionRefusal::NotOffered)),
            };
        };
        let verdict =
            manifest::check_appcast_entry(&doc, &ctx, item, phase).map_err(EntryRefusal::Refused);
        let update_required = manifest::parse_semver(&entry.minimum_supported_version)
            .is_ok_and(|minimum| self.current_version < minimum);
        VerifiedEntryAnswer {
            entry: Some(VerifiedEntry {
                file: entry.artifact_file().to_string(),
                generated_at: doc.generated_at.clone(),
                expires_at: doc.expires_at.clone(),
                update_required,
                entry,
            }),
            verdict,
        }
    }

    /// The newest manifest generation this install accepted for its channel, for status.
    pub fn accepted_generation(&self) -> Option<AcceptedGeneration> {
        self.replay.accepted(&self.policy.load_or_default().channel)
    }

    /// Judges one specific version against the live, verified, replay-protected channel
    /// manifest. Fails closed: a manifest that cannot be fetched or verified, or a channel
    /// with none, refuses.
    pub async fn check_version(
        &self,
        kind: VersionCheckKind,
        version: &str,
    ) -> Result<(), VersionCheckError> {
        let policy = self.policy.load_or_default();
        let manifest = self
            .fetch_verified_manifest(&policy)
            .await
            .map_err(VersionCheckError::Unverifiable)?
            .ok_or(VersionCheckError::NoManifest)?;
        let ctx = self.local_context(&policy);
        match kind {
            VersionCheckKind::PinnedInstall => {
                manifest::check_pinned_install(&manifest, &ctx, version)
            }
            VersionCheckKind::AppcastItem => manifest::check_appcast_item(&manifest, &ctx, version),
        }
        .map_err(VersionCheckError::Refused)
    }

    /// Update privacy:
    /// the *exact* and *only* fields an update-check request carries —
    /// current version, platform, architecture, channel, install source,
    /// and manifest schema version (spec "Update check uses coarse
    /// metadata only"). Deliberately returns a fixed-shape array (not an
    /// extensible map some other call site could accidentally widen) so
    /// there is exactly one place in this codebase that decides what an
    /// update check ever sends — no device id, account id, folder path,
    /// peer address, key, or token is ever constructed as part of this
    /// request.
    fn update_check_query(&self, policy: &UpdatePolicy) -> [(&'static str, String); 6] {
        [
            ("schema_version", manifest::MANIFEST_SCHEMA_VERSION.to_string()),
            ("current_version", self.current_version.to_string()),
            ("platform", self.platform_info.platform.clone()),
            ("arch", self.platform_info.arch.clone()),
            ("channel", policy.channel.clone()),
            ("install_source", self.platform_info.install_source.clone()),
        ]
    }

    fn record_applicability(
        &self,
        applicability: &Applicability,
        expires_at: Option<&str>,
    ) -> Result<(), UpdateError> {
        self.policy.update(|p| {
            p.last_check_unix = Some(self.now());
            p.last_success_unix = p.last_check_unix;
            p.manifest_expires_at = expires_at.map(str::to_owned);
            p.last_error_category = None;
            p.last_error_message = None;
            match applicability {
                Applicability::UpToDate => {
                    p.state = UpdateState::UpToDate;
                    p.available_version = None;
                    p.available_release_notes_url = None;
                    p.mandatory = false;
                    p.minimum_supported_version = None;
                    p.holdback_reason = None;
                }
                Applicability::Available { entry, version, mandatory } => {
                    p.state = UpdateState::Available;
                    p.available_version = Some(version.to_string());
                    p.available_release_notes_url = Some(entry.release_notes_url.clone());
                    p.mandatory = *mandatory;
                    p.minimum_supported_version = recorded_minimum(entry);
                    p.holdback_reason = None;
                }
                Applicability::HeldBack { entry, version, reason } => {
                    p.state = UpdateState::HeldBack;
                    p.available_version = Some(version.to_string());
                    p.available_release_notes_url = Some(entry.release_notes_url.clone());
                    p.mandatory = false;
                    p.minimum_supported_version = recorded_minimum(entry);
                    p.holdback_reason = Some(reason.clone());
                }
                Applicability::StateIncompatible { entry, version, refusal } => {
                    p.state = UpdateState::HeldBack;
                    p.available_version = Some(version.to_string());
                    p.available_release_notes_url = Some(entry.release_notes_url.clone());
                    p.mandatory = false;
                    p.minimum_supported_version = recorded_minimum(entry);
                    p.holdback_reason = Some(refusal.message());
                }
                Applicability::KillSwitched { entry, version } => {
                    p.state = UpdateState::KillSwitched;
                    p.available_version = Some(version.to_string());
                    p.available_release_notes_url = Some(entry.release_notes_url.clone());
                    p.mandatory = false;
                    // A withdrawn release still states where the floor is: a device below it
                    // cannot sync with the current generation whether or not it can update.
                    p.minimum_supported_version = recorded_minimum(entry);
                    p.holdback_reason =
                        Some("this release was withdrawn by the publisher (kill switch)".into());
                }
            }
        })?;
        Ok(())
    }
}

/// The release's minimum supported version, kept only when it is a version the client can compare.
fn recorded_minimum(entry: &manifest::ReleaseEntry) -> Option<String> {
    manifest::parse_semver(&entry.minimum_supported_version)
        .is_ok()
        .then(|| entry.minimum_supported_version.clone())
}

/// applies a `yadorilink update config` change, leaving any
/// field the caller passed `None` for unchanged.
pub fn apply_config(
    store: &UpdatePolicyStore,
    automatic_checks_enabled: Option<bool>,
) -> std::io::Result<UpdatePolicy> {
    store.update(|p| {
        if let Some(enabled) = automatic_checks_enabled {
            p.automatic_checks_enabled = enabled;
        }
    })
}

#[cfg(test)]
mod tests;
