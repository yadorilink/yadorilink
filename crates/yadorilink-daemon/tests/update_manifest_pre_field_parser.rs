//! Compatibility proof for the additive `withdrawn_versions` manifest field (schema stays 2).
//!
//! A client that predates the field must still verify and parse a signed envelope whose body
//! carries it, and must pick the same release as before. The old parser is pinned here as a
//! verbatim snapshot of the wire types and the verify path of `update/manifest.rs` as it was
//! before the field was added (git blob `45abd727a48fe21c9ec5acda8b994e540ce26fae`, the parent
//! of the commit that introduced the field). It is a snapshot, not a live copy: do not edit
//! it to follow the current types.
//!
//! What this does NOT prove: an old client ignores the field, so it cannot refuse a withdrawn
//! pinned version. Old clients keep the kill-switch and minimum-version policy only.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use yadorilink_daemon::update::manifest::{self, ReleaseEntry, SignedManifestEnvelope, TrustedKey};

/// Pre-field wire types (snapshot).
mod pre_field {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct OldReleaseEntry {
        pub channel: String,
        pub platform: String,
        pub arch: String,
        pub install_source: String,
        pub version: String,
        pub minimum_supported_version: String,
        #[serde(default)]
        pub rollout_percentage: u8,
        #[serde(default)]
        pub kill_switch: bool,
        #[serde(default)]
        pub mandatory: bool,
        pub artifact_url: String,
        pub artifact_sha256: String,
        pub artifact_size: u64,
        #[serde(default)]
        pub artifact_publisher_identity: String,
        #[serde(default)]
        pub release_notes_url: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct OldUpdateManifest {
        pub schema_version: u32,
        pub generated_at: String,
        pub releases: Vec<OldReleaseEntry>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct OldEnvelope {
        pub key_id: String,
        pub manifest_json: String,
        pub signature_base64: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub trust_chain: Vec<serde_json::Value>,
    }

    /// The old verify path: signature over the literal `manifest_json` bytes, then parse, then
    /// the schema check.
    pub fn verify_envelope(
        envelope_json: &str,
        key: &VerifyingKey,
        expected_schema: u32,
    ) -> Result<OldUpdateManifest, String> {
        let envelope: OldEnvelope =
            serde_json::from_str(envelope_json).map_err(|e| format!("envelope: {e}"))?;
        let sig = base64::engine::general_purpose::STANDARD
            .decode(&envelope.signature_base64)
            .map_err(|e| e.to_string())?;
        let sig: [u8; 64] = sig.try_into().map_err(|_| "signature length".to_string())?;
        key.verify(envelope.manifest_json.as_bytes(), &Signature::from_bytes(&sig))
            .map_err(|_| "signature".to_string())?;
        let m: OldUpdateManifest =
            serde_json::from_str(&envelope.manifest_json).map_err(|e| format!("body: {e}"))?;
        if m.schema_version != expected_schema {
            return Err("schema".into());
        }
        Ok(m)
    }
}

fn entry(version: &str, install_source: &str, kill: bool) -> ReleaseEntry {
    ReleaseEntry {
        channel: "beta".into(),
        platform: "linux".into(),
        arch: "x86_64".into(),
        install_source: install_source.into(),
        version: version.into(),
        minimum_supported_version: "0.1.0".into(),
        rollout_percentage: 100,
        kill_switch: kill,
        mandatory: false,
        artifact_url: format!("https://yadori.link/dl/{version}/yadorilink-{version}.zip"),
        artifact_sha256: "0".repeat(64),
        artifact_size: 1024,
        artifact_publisher_identity: String::new(),
        release_notes_url: String::new(),
    }
}

fn signed_envelope(key: &SigningKey, withdrawn: &[&str]) -> (String, String) {
    let m = manifest::UpdateManifest {
        schema_version: manifest::MANIFEST_SCHEMA_VERSION,
        generated_at: "2026-10-21T00:00:00Z".into(),
        withdrawn_versions: withdrawn.iter().map(|s| s.to_string()).collect(),
        releases: vec![entry("0.2.0", "script", false), entry("0.2.0", "app_bundle", true)],
    };
    let manifest_json = serde_json::to_string_pretty(&m).unwrap();
    let sig = key.sign(manifest_json.as_bytes());
    let env = SignedManifestEnvelope {
        key_id: "pre-field-fixture".into(),
        manifest_json: manifest_json.clone(),
        signature_base64: base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()),
        trust_chain: Vec::new(),
    };
    (serde_json::to_string(&env).unwrap(), manifest_json)
}

#[test]
fn a_pre_field_client_accepts_a_body_with_withdrawn_versions_and_selects_the_same_release() {
    let mut seed = [0u8; 32];
    rand::fill(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    let (without, _) = signed_envelope(&key, &[]);
    let (with, body) = signed_envelope(&key, &["0.1.5", "0.1.6"]);
    assert!(body.contains("withdrawn_versions"), "the body must carry the new field");

    let old_without = pre_field::verify_envelope(&without, &key.verifying_key(), 2).unwrap();
    let old_with = pre_field::verify_envelope(&with, &key.verifying_key(), 2)
        .expect("a schema-2 body with withdrawn_versions must not be rejected by the old parser");
    // The old parser sees exactly the entries it saw before; the field changes nothing it reads.
    assert_eq!(old_with.releases, old_without.releases);
    let pick = |m: &pre_field::OldUpdateManifest, src: &str| {
        m.releases
            .iter()
            .find(|r| r.install_source == src && r.platform == "linux" && r.arch == "x86_64")
            .map(|r| (r.version.clone(), r.kill_switch))
    };
    assert_eq!(pick(&old_with, "script"), Some(("0.2.0".into(), false)));
    assert_eq!(pick(&old_with, "app_bundle"), Some(("0.2.0".into(), true)));

    // The current client reads the same envelope and sees the list.
    let trusted = [TrustedKey {
        key_id: "pre-field-fixture",
        public_key_hex: Box::leak(hex::encode(key.verifying_key().to_bytes()).into_boxed_str()),
    }];
    let current = manifest::verify_and_parse_with_keys(&with, &trusted).unwrap();
    assert_eq!(current.withdrawn_versions, vec!["0.1.5".to_string(), "0.1.6".to_string()]);
}

#[test]
fn the_signature_covers_the_literal_body_including_the_field() {
    let mut seed = [0u8; 32];
    rand::fill(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    let (with, _) = signed_envelope(&key, &["0.1.5"]);
    // Dropping the field after signing breaks the signature in the old parser too.
    let mut env: pre_field::OldEnvelope = serde_json::from_str(&with).unwrap();
    env.manifest_json = env.manifest_json.replace("withdrawn_versions", "withdrawn_versionz");
    let tampered = serde_json::to_string(&env).unwrap();
    assert_eq!(
        pre_field::verify_envelope(&tampered, &key.verifying_key(), 2).unwrap_err(),
        "signature"
    );
}
