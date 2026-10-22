//! The signed update manifest — data structures, strict parsing,
//! semantic-version comparison/applicability, and Ed25519 signature
//! verification against a pinned trust root.
//!
//! The manifest signature protects metadata (rollout, minimum supported
//! version, artifact URL/checksum) end-to-end over HTTPS *and* against a
//! compromised hosting/CDN — verified here, before anything is
//! downloaded. `verify::verify_artifact` (sibling module) separately
//! verifies the downloaded artifact's checksum and platform publisher
//! signature; neither check substitutes for the other.
//!
//! Every fallible step in this module is fail-closed by construction: a
//! parse error, an unknown signing key, an invalid signature, or an
//! unsupported schema version returns a distinct `ManifestError` variant
//! and never produces an `UpdateManifest` a caller could act on. Nothing
//! here downloads or installs anything — this module only ever decides
//! *whether* an update is applicable.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::trust::{self, SignedTrustRecord, TrustError, TrustState};

/// Bumped whenever the manifest schema's field set changes in a way that
/// could change how a daemon interprets it. A manifest declaring any
/// other value is rejected outright (rejecting unsupported
/// schema versions) rather than best-effort parsed, since a future
/// schema change might repurpose a field this version would otherwise
/// silently misinterpret.
pub const MANIFEST_SCHEMA_VERSION: u32 = 2;

/// One pinned release-signing public key, identified by a stable
/// `key_id` so keys can be rotated without breaking older clients that
/// still only trust the previous one.
#[derive(Clone)]
pub struct TrustedKey {
    pub key_id: &'static str,
    pub public_key_hex: &'static str,
}

/// Pinned update-manifest trust root (the genesis key set). Rotation and
/// revocation do not edit this list: they are signed trust records chained to
/// it (see `update::trust`), so the compiled-in key stays the root for the
/// life of the product line even after it stops signing.
///
/// Ordinary developer builds pin a known development key so update fixtures
/// remain usable. A build with `enforce-release-trust-root` instead requires
/// the release key id and public key at compile time. This makes it impossible
/// for a release binary to silently fall back to the forgeable development
/// key; the matching private key remains exclusively offline or in an HSM.
/// Fail-closed applies regardless of which key is pinned here: an
/// unknown `key_id` or a signature that does not verify under the exact
/// key listed is always rejected, never treated as "trust on first use."
/// The `key_id` of the development/beta placeholder trust root. A real release
/// build must not ship with this pinned. It is a named constant, and the pinned
/// key below references it, purely for readability -- the release gate below
/// never relies on this label, since a `key_id` can be renamed without
/// changing which private key can forge a manifest (see
/// `is_placeholder_public_key`).
pub const PLACEHOLDER_TRUST_ROOT_KEY_ID: &str = "yadorilink-beta-dev-2026";

#[cfg(not(feature = "enforce-release-trust-root"))]
pub const TRUSTED_KEYS: &[TrustedKey] = &[TrustedKey {
    key_id: PLACEHOLDER_TRUST_ROOT_KEY_ID,
    public_key_hex: "00e033f866c263139ff4afd165e75bae3cfca67eb32399dddd6e33a3251af1e3",
}];

#[cfg(feature = "enforce-release-trust-root")]
pub const TRUSTED_KEYS: &[TrustedKey] = &[TrustedKey {
    key_id: env!(
        "YADORILINK_RELEASE_MANIFEST_KEY_ID",
        "release builds require YADORILINK_RELEASE_MANIFEST_KEY_ID"
    ),
    public_key_hex: env!(
        "YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX",
        "release builds require YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX"
    ),
}];

/// The placeholder keypair's actual PUBLIC KEY BYTES (lowercase hex). The
/// release gate below detects the placeholder by this key MATERIAL, not by
/// `PLACEHOLDER_TRUST_ROOT_KEY_ID`: a `key_id` is only a label, so a build
/// that renamed it (or otherwise pinned this exact public key under a
/// different id) would still trust a key whose private half is not secret,
/// and must still be caught.
const PLACEHOLDER_TRUST_ROOT_PUBLIC_KEY_HEX: &str =
    "00e033f866c263139ff4afd165e75bae3cfca67eb32399dddd6e33a3251af1e3";

/// Whether the given `key_id` is the known development/beta placeholder's
/// usual label. Informational/logging only -- the release gate itself never
/// relies on this; see `is_placeholder_public_key` for the check that
/// actually matters.
pub fn key_id_is_placeholder(key_id: &str) -> bool {
    key_id == PLACEHOLDER_TRUST_ROOT_KEY_ID
}

/// Whether `public_key_hex` IS the placeholder keypair's public key bytes,
/// compared case-insensitively (and trimmed) so encoding differences can't
/// evade detection. This is what the release gate actually keys off, rather
/// than a `key_id` label.
pub(crate) fn is_placeholder_public_key(public_key_hex: &str) -> bool {
    public_key_hex.trim().eq_ignore_ascii_case(PLACEHOLDER_TRUST_ROOT_PUBLIC_KEY_HEX)
}

/// Whether `trusted_keys` configures at least one REAL trusted key: not
/// empty, and not made up entirely of blank/whitespace or placeholder key
/// material. An empty or placeholder-only trusted-key set is exactly as
/// forgeable as shipping no signature check at all, so it is never accepted
/// as a valid production trust root.
/// Pure release-gate logic: is `trusted_keys` safe to enforce as a real
/// release's trust root? Rejects if the placeholder key's MATERIAL is present
/// under any `key_id`, if no key is configured, or if an id/public key is
/// malformed. Validating the Ed25519 point here prevents a release that builds
/// successfully but can never verify any update manifest.
fn release_gate_result(trusted_keys: &[TrustedKey]) -> Result<(), String> {
    if trusted_keys.iter().any(|k| is_placeholder_public_key(k.public_key_hex)) {
        return Err(format!(
            "trust root pins the placeholder public key '{PLACEHOLDER_TRUST_ROOT_PUBLIC_KEY_HEX}' \
             (its matching private key is not secret, so anyone can forge a manifest that \
             passes this check); replace it with a real offline/HSM-generated release key \
             before serving updates"
        ));
    }
    if trusted_keys.is_empty() {
        return Err("trust root configures no trusted key; at least one real release-signing key \
             must be pinned before serving updates"
            .to_string());
    }
    let mut key_ids = std::collections::HashSet::new();
    for key in trusted_keys {
        if key.key_id.trim().is_empty() {
            return Err("trust root contains a blank key id".to_string());
        }
        if !key_ids.insert(key.key_id) {
            return Err(format!("trust root contains duplicate key id '{}'", key.key_id));
        }
        let bytes = hex::decode(key.public_key_hex.trim())
            .map_err(|_| format!("trust root key '{}' is not valid hex", key.key_id))?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            format!(
                "trust root key '{}' must decode to exactly 32 bytes, got {}",
                key.key_id,
                v.len()
            )
        })?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| {
            format!("trust root key '{}' is not a valid Ed25519 public key", key.key_id)
        })?;
    }
    Ok(())
}

/// Combines `release_gate_result` with the local/dev opt-out: when
/// `dev_override` is `true` the gate is skipped entirely, for a build that is
/// explicitly acknowledging it is not producing a real release artifact.
fn evaluate_release_gate(trusted_keys: &[TrustedKey], dev_override: bool) -> Result<(), String> {
    if dev_override {
        return Ok(());
    }
    release_gate_result(trusted_keys)
}

/// Env var name for the release gate's local/dev opt-out below. Meant only
/// for a developer's own machine, or a CI run that is not producing a real
/// release artifact -- an actual release job must never set this, since
/// setting it disables the one check that stops a forgeable trust root from
/// shipping.
pub const ALLOW_PLACEHOLDER_TRUST_ROOT_ENV: &str = "YADORILINK_ALLOW_PLACEHOLDER_TRUST_ROOT";

/// The value the opt-out env var must hold EXACTLY (after trimming
/// surrounding whitespace) to bypass the gate: the single character `1`.
/// Deliberately strict so an accidental `=0`, `=false`, empty, or
/// present-but-blank value in release CI does NOT silently disable the gate
/// (fail-closed): only a deliberate `=1` opts out.
const ALLOW_PLACEHOLDER_TRUST_ROOT_VALUE: &str = "1";

/// Pure predicate for the opt-out value, split from the env read so it is
/// testable without mutating the process environment (which would race with
/// any other test in this binary reading the same var). A missing value
/// (`None`), or any value other than `1` (including `0`, `false`, empty, or
/// blank/whitespace), does NOT bypass the gate.
fn dev_override_value_enabled(raw: Option<&str>) -> bool {
    raw.map(|v| v.trim() == ALLOW_PLACEHOLDER_TRUST_ROOT_VALUE).unwrap_or(false)
}

/// Whether the opt-out env var is set to exactly the required value. Thin
/// wrapper over `dev_override_value_enabled` that supplies the live env.
fn dev_override_enabled() -> bool {
    dev_override_value_enabled(std::env::var(ALLOW_PLACEHOLDER_TRUST_ROOT_ENV).ok().as_deref())
}

/// The release gate: rejects a build that still pins the forgeable
/// development/beta placeholder root (or configures no real trusted key),
/// unless the local/dev opt-out `YADORILINK_ALLOW_PLACEHOLDER_TRUST_ROOT=1`
/// is set. Developer builds intentionally retain the placeholder for fixtures;
/// release builds replace it at compile time. The gate is wired as a
/// release-only startup tripwire behind the
/// `enforce-release-trust-root` cargo feature (see the daemon's `run`
/// startup path). **Release builds MUST enable that feature and provide the
/// compile-time key id/public key variables**. Missing variables fail the
/// build; rejected key material prevents daemon startup.
///
/// This replaces an earlier opt-IN scheme keyed on
/// `YADORILINK_ENFORCE_RELEASE_TRUST_ROOT`: under that scheme, a release job
/// that simply forgot to set the variable shipped the forgeable placeholder
/// root with nothing failing to catch it. Tying enforcement to a release
/// build feature (fail-closed) instead means the failure mode of "forgetting
/// to flip something" now points the safe way.
pub fn enforce_release_trust_root_gate() -> Result<(), String> {
    evaluate_release_gate(TRUSTED_KEYS, dev_override_enabled())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest envelope is malformed: {0}")]
    MalformedEnvelope(String),
    #[error("manifest signed by unknown key id: {0}")]
    UnknownKey(String),
    #[error("manifest signed by revoked key id: {0}")]
    RevokedKey(String),
    #[error("update trust chain rejected: {0}")]
    Trust(#[from] TrustError),
    #[error("pinned trust root key is invalid")]
    InvalidTrustRoot,
    #[error("manifest signature encoding is invalid")]
    InvalidSignatureEncoding,
    #[error("manifest signature verification failed")]
    SignatureVerificationFailed,
    #[error("manifest body is malformed: {0}")]
    MalformedBody(String),
    #[error("manifest schema version {found} is not supported (expected {expected})")]
    UnsupportedSchemaVersion { found: u32, expected: u32 },
}

/// One release entry within a manifest — the manifest field list plus
/// this file's own `rollout_percentage`/`kill_switch`/`mandatory`
/// controls. Scoped to exactly one (channel, platform, arch,
/// install_source) combination; a manifest lists one entry per
/// applicable combination, matching `LinkStatus`'s established
/// "string-typed enum" convention (`channel`/`platform`/`install_source`
/// are plain strings here too, validated by comparison against the local
/// context rather than a closed proto/Rust enum, so a manifest can name a
/// future channel/platform without every already-deployed client needing
/// a code change first — an unrecognized value simply never matches any
/// local context and is harmlessly ignored, never misinterpreted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseEntry {
    pub channel: String,
    pub platform: String,
    pub arch: String,
    pub install_source: String,
    pub version: String,
    pub minimum_supported_version: String,
    /// 0-100. Interpreted as "this install is eligible once its pinned
    /// rollout bucket falls below this percentage" — see
    /// `rollout_selected`.
    #[serde(default)]
    pub rollout_percentage: u8,
    /// Kill switch: when set, this entry is never installed
    /// (automatically or manually) regardless of rollout/mandatory
    /// status — the release-operations equivalent of a fail-closed
    /// override for a bad release still being staged out.
    #[serde(default)]
    pub kill_switch: bool,
    /// Explicit mandatory flag — reserved for security/
    /// protocol-compatibility fixes, to guard against abuse. A version
    /// below `minimum_supported_version` is *also* treated as mandatory
    /// regardless of this flag — see `select_applicable`.
    #[serde(default)]
    pub mandatory: bool,
    pub artifact_url: String,
    /// Lowercase hex-encoded SHA-256, matching this repo's existing
    /// `.github/release/generate-release-checksums.py` sidecar convention.
    pub artifact_sha256: String,
    /// Signed (covered by the manifest signature exactly like every
    /// other field here) expected artifact size in bytes. Consulted by
    /// `manager::UpdateManager`'s download path to reject a response
    /// whose `Content-Length` exceeds this and to bound the download
    /// while it streams to disk, so a misconfigured or compromised
    /// signing key -- or a hostile host serving the artifact URL -- can
    /// never make a client stream an unbounded response to disk.
    pub artifact_size: u64,
    /// Expected platform publisher identity substring (e.g. a Developer
    /// ID Installer common name on macOS, or an Authenticode signer
    /// subject on Windows) — consulted by `verify::verify_artifact`.
    /// Empty means "no specific identity pinned for this entry" (`verify`
    /// still requires *a* valid platform signature; it simply can't also
    /// check *whose*).
    #[serde(default)]
    pub artifact_publisher_identity: String,
    #[serde(default)]
    pub release_notes_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub schema_version: u32,
    pub generated_at: String,
    pub releases: Vec<ReleaseEntry>,
    /// Versions the publisher withdrew from this channel (a yank repoints the entry to an older
    /// good version, which would otherwise make the bad one look like any old release). Absent
    /// in manifests that withdraw nothing, and ignored by clients that predate it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withdrawn_versions: Vec<String>,
}

/// The wire format actually fetched over HTTPS: the exact signed bytes
/// (`manifest_json`) carried alongside their signature, rather than a
/// manifest struct that gets re-serialized before verifying — mirrors
/// this workspace's existing `report_json`/`GenerateUsageReportResponse`
/// convention of signing/verifying literal bytes, never a
/// re-serialization that could differ byte-for-byte from what was
/// actually signed (a `serde_json` round-trip is not guaranteed to
/// reproduce identical bytes, e.g. key ordering or float formatting).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifestEnvelope {
    pub key_id: String,
    pub manifest_json: String,
    /// Standard base64 (not URL-safe) encoding of the raw 64-byte Ed25519
    /// signature.
    pub signature_base64: String,
    /// The append-only chain of signed trust records (see `update::trust`)
    /// that extends the client's compiled-in key set. Outside the manifest
    /// signature on purpose: every record carries its own signature, and
    /// the chain is checked before the manifest signer is looked up.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trust_chain: Vec<SignedTrustRecord>,
}

/// Verifies `envelope_json` (the raw bytes fetched from the manifest URL)
/// against the compiled-in trust root extended by the envelope's own trust
/// chain, with nothing persisted. Real clients use `UpdateManager`, which
/// persists the chain so revocations survive a stripped chain.
pub fn verify_and_parse(envelope_json: &str) -> Result<UpdateManifest, ManifestError> {
    verify_and_parse_with_keys(envelope_json, TRUSTED_KEYS)
}

/// `verify_and_parse` over an explicit genesis key set, so tests can use a
/// throwaway keypair instead of the pinned production trust root.
pub fn verify_and_parse_with_keys(
    envelope_json: &str,
    trusted_keys: &[TrustedKey],
) -> Result<UpdateManifest, ManifestError> {
    let envelope = parse_envelope(envelope_json)?;
    let state = TrustState::replay(trusted_keys, &envelope.trust_chain)?;
    verify_envelope(&envelope, &state)
}

pub fn parse_envelope(envelope_json: &str) -> Result<SignedManifestEnvelope, ManifestError> {
    serde_json::from_str(envelope_json).map_err(|e| ManifestError::MalformedEnvelope(e.to_string()))
}

/// Verifies a parsed envelope against `state` and, only if the signature
/// verifies, parses and returns the signed `UpdateManifest` body. Fails
/// closed on every error path: an unrecognized or revoked `key_id`, invalid
/// base64/signature encoding, a signature that doesn't verify, or a manifest
/// body with an unsupported `schema_version` or that doesn't parse.
pub fn verify_envelope(
    envelope: &SignedManifestEnvelope,
    state: &TrustState,
) -> Result<UpdateManifest, ManifestError> {
    let public_key_hex = match state.active_public_key(&envelope.key_id) {
        Some(hex) => hex,
        None if state.is_revoked(&envelope.key_id) => {
            return Err(ManifestError::RevokedKey(envelope.key_id.clone()));
        }
        None => return Err(ManifestError::UnknownKey(envelope.key_id.clone())),
    };
    let verifying_key =
        trust::decode_verifying_key(public_key_hex).ok_or(ManifestError::InvalidTrustRoot)?;

    use base64::Engine;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(&envelope.signature_base64)
        .map_err(|_| ManifestError::InvalidSignatureEncoding)?;
    let signature_bytes: [u8; 64] =
        signature_bytes.try_into().map_err(|_| ManifestError::InvalidSignatureEncoding)?;
    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key
        .verify(envelope.manifest_json.as_bytes(), &signature)
        .map_err(|_| ManifestError::SignatureVerificationFailed)?;

    let manifest: UpdateManifest = serde_json::from_str(&envelope.manifest_json)
        .map_err(|e| ManifestError::MalformedBody(e.to_string()))?;
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(ManifestError::UnsupportedSchemaVersion {
            found: manifest.schema_version,
            expected: MANIFEST_SCHEMA_VERSION,
        });
    }
    Ok(manifest)
}

/// This installation's coarse identity for manifest-entry matching
/// — deliberately nothing more identifying than this (see
/// update privacy rule): no device id, no
/// account id.
#[derive(Debug, Clone)]
pub struct LocalContext {
    pub current_version: semver::Version,
    pub channel: String,
    pub platform: String,
    pub arch: String,
    pub install_source: String,
    /// A stable value in `0..100`, persisted per-install (never derived
    /// from any identifier sent to a server) so repeated checks against
    /// the same rollout percentage give a consistent held-back/eligible
    /// answer instead of flapping — see `policy::UpdatePolicy::rollout_bucket`.
    pub rollout_bucket: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Applicability {
    /// No release entry names a version newer than `current_version` for
    /// this exact (channel, platform, arch, install_source) — includes
    /// the case where the only newer-looking entries are malformed or
    /// are a downgrade/equal version, both of which are simply excluded
    /// from consideration rather than erroring the whole check.
    UpToDate,
    /// An applicable, installable update (rollout-selected or mandatory,
    /// and not kill-switched).
    Available { entry: ReleaseEntry, version: semver::Version, mandatory: bool },
    /// A newer version exists but staged rollout hasn't selected this
    /// install yet.
    HeldBack { entry: ReleaseEntry, version: semver::Version, reason: String },
    /// A newer version exists but its manifest entry is kill-switched —
    /// never installed, automatically or manually, until the kill switch
    /// is cleared in a later manifest.
    KillSwitched { entry: ReleaseEntry, version: semver::Version },
}

/// Selects the best applicable release entry for `ctx` out of an already
/// signature-verified `manifest`, or reports why none is currently
/// installable. Never selects a version `<=` `ctx.current_version`
/// (downgrade and minimum-version protection requirement) —
/// an entry whose `version`
/// fails to parse as semver, or that doesn't match the local
/// channel/platform/arch/install_source, is excluded from consideration
/// entirely rather than causing an error.
pub fn select_applicable(manifest: &UpdateManifest, ctx: &LocalContext) -> Applicability {
    let mut best: Option<(ReleaseEntry, semver::Version)> = None;
    for entry in &manifest.releases {
        if entry.channel != ctx.channel
            || entry.platform != ctx.platform
            || entry.arch != ctx.arch
            || entry.install_source != ctx.install_source
        {
            continue;
        }
        let Ok(version) = parse_semver(&entry.version) else { continue };
        if version <= ctx.current_version {
            continue; // downgrade or already-current: never selectable
        }
        let better = match &best {
            Some((_, best_version)) => version > *best_version,
            None => true,
        };
        if better {
            best = Some((entry.clone(), version));
        }
    }

    let Some((entry, version)) = best else { return Applicability::UpToDate };

    if entry.kill_switch {
        return Applicability::KillSwitched { entry, version };
    }

    let mandatory = is_mandatory(&entry, ctx);

    if !mandatory && !rollout_selected(ctx.rollout_bucket, entry.rollout_percentage) {
        let reason = format!(
            "staged rollout at {}%; this install's bucket ({}) is not yet selected",
            entry.rollout_percentage, ctx.rollout_bucket
        );
        return Applicability::HeldBack { entry, version, reason };
    }

    Applicability::Available { entry, version, mandatory }
}

/// Mandatory by the explicit flag, or because this install is below the entry's minimum.
fn is_mandatory(entry: &ReleaseEntry, ctx: &LocalContext) -> bool {
    let min_supported = parse_semver(&entry.minimum_supported_version).ok();
    entry.mandatory || min_supported.is_some_and(|min| ctx.current_version < min)
}

/// Why a specific version may not be installed or offered, judged against the live, verified
/// channel manifest. Every variant is a refusal; there is no "unknown, proceed".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VersionRefusal {
    #[error("version {0} is not a valid version")]
    InvalidVersion(String),
    #[error("version {0} was withdrawn by the publisher")]
    Withdrawn(String),
    #[error("version {0} was withdrawn by the publisher (kill switch)")]
    KillSwitched(String),
    #[error("version {version} is below the minimum supported version {minimum}")]
    BelowMinimum { version: String, minimum: String },
    #[error("the channel manifest has no release for this install")]
    NotOffered,
    #[error("version {version} is not the version the channel manifest serves ({served})")]
    NotServed { version: String, served: String },
    #[error("version {0} is not yet rolled out to this install")]
    HeldBack(String),
}

fn matching_entries<'a>(
    manifest: &'a UpdateManifest,
    ctx: &'a LocalContext,
) -> impl Iterator<Item = &'a ReleaseEntry> {
    manifest.releases.iter().filter(move |e| {
        e.channel == ctx.channel
            && e.platform == ctx.platform
            && e.arch == ctx.arch
            && e.install_source == ctx.install_source
    })
}

fn is_withdrawn(manifest: &UpdateManifest, version: &semver::Version) -> bool {
    manifest.withdrawn_versions.iter().any(|w| parse_semver(w).ok().as_ref() == Some(version))
}

/// An online install of one pinned version (`self-update --version X`): the per-version
/// snapshot proves integrity but is immutable, so it cannot carry a later withdrawal. The live
/// manifest can, and a pinned install must not bypass it. Refuses a version the publisher
/// withdrew, kill-switched, or that is below the channel minimum; the caller must also refuse
/// when no verified live manifest could be obtained.
pub fn check_pinned_install(
    manifest: &UpdateManifest,
    ctx: &LocalContext,
    version: &str,
) -> Result<(), VersionRefusal> {
    let wanted =
        parse_semver(version).map_err(|_| VersionRefusal::InvalidVersion(version.into()))?;
    if is_withdrawn(manifest, &wanted) {
        return Err(VersionRefusal::Withdrawn(wanted.to_string()));
    }
    for entry in matching_entries(manifest, ctx) {
        if entry.kill_switch && parse_semver(&entry.version).ok().as_ref() == Some(&wanted) {
            return Err(VersionRefusal::KillSwitched(wanted.to_string()));
        }
        if let Ok(min) = parse_semver(&entry.minimum_supported_version) {
            if wanted < min {
                return Err(VersionRefusal::BelowMinimum {
                    version: wanted.to_string(),
                    minimum: min.to_string(),
                });
            }
        }
    }
    Ok(())
}

/// The app's check before Sparkle proceeds with an appcast item: the item's version must equal
/// the version the verified manifest serves for this install (not newer, not older), must not
/// be withdrawn or kill-switched, and must be rolled out to this install. A stale or replayed
/// appcast therefore cannot offer a withdrawn or superseded release.
pub fn check_appcast_item(
    manifest: &UpdateManifest,
    ctx: &LocalContext,
    item_version: &str,
) -> Result<(), VersionRefusal> {
    let item = parse_semver(item_version)
        .map_err(|_| VersionRefusal::InvalidVersion(item_version.into()))?;
    if is_withdrawn(manifest, &item) {
        return Err(VersionRefusal::Withdrawn(item.to_string()));
    }
    let Some(entry) = matching_entries(manifest, ctx).next() else {
        return Err(VersionRefusal::NotOffered);
    };
    if parse_semver(&entry.version).ok().as_ref() != Some(&item) {
        return Err(VersionRefusal::NotServed {
            version: item.to_string(),
            served: entry.version.clone(),
        });
    }
    if entry.kill_switch {
        return Err(VersionRefusal::KillSwitched(item.to_string()));
    }
    if !is_mandatory(entry, ctx) && !rollout_selected(ctx.rollout_bucket, entry.rollout_percentage)
    {
        return Err(VersionRefusal::HeldBack(item.to_string()));
    }
    Ok(())
}

/// Tolerates a leading `v` (e.g. `v1.2.3`) since that's a common release
/// tag convention, but otherwise requires strict semver (rejecting malformed versions).
/// `pub(crate)` so `manager` can re-derive a clean, filesystem-safe
/// version string from an already-selected entry's `version` field
/// without ever trusting a raw string straight from the manifest (see
/// `manager::artifact_filename`).
pub(crate) fn parse_semver(raw: &str) -> Result<semver::Version, semver::Error> {
    semver::Version::parse(raw.strip_prefix('v').unwrap_or(raw))
}

fn rollout_selected(bucket: u8, rollout_percentage: u8) -> bool {
    u32::from(bucket) < u32::from(rollout_percentage.min(100))
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests;
