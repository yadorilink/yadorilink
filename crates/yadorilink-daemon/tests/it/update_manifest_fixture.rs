//! Proves a current-schema signed manifest verifies through the production
//! `manifest::verify_and_parse_with_keys` path, and that each failure cause is
//! distinguishable: a signature failure and a schema mismatch are different
//! errors, so a tamper test cannot pass for the wrong reason.
//!
//! The envelope is generated at test time and signed with a freshly generated
//! throwaway Ed25519 key, the same way `yadorilink-sign-manifest sign` builds
//! an envelope (sign the exact `manifest_json` bytes, base64 the signature).
//! The verifier is given that key as its genesis trust set through the public
//! `verify_and_parse_with_keys` API; the pinned production trust root is not
//! involved and nothing is added to production code.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use yadorilink_daemon::update::manifest::{
    self, ManifestError, ReleaseEntry, SignedManifestEnvelope, TrustedKey, UpdateManifest,
};

const KEY_ID: &str = "throwaway-fixture-key";

fn release(platform: &str, arch: &str, url: &str) -> ReleaseEntry {
    ReleaseEntry {
        channel: "beta".into(),
        platform: platform.into(),
        arch: arch.into(),
        install_source: "standalone".into(),
        version: "0.2.0".into(),
        minimum_supported_version: "0.1.0".into(),
        rollout_percentage: 100,
        kill_switch: false,
        mandatory: false,
        artifact_url: url.into(),
        artifact_sha256: "0".repeat(64),
        artifact_size: 1024,
        artifact_publisher_identity: String::new(),
        release_notes_url: "https://updates.yadorilink.example/beta/0.2.0/notes.html".into(),
        state_schema_version: None,
        state_schema_min_readable: None,
        sparkle_build: None,
    }
}

fn manifest_with_schema(schema_version: u32) -> UpdateManifest {
    UpdateManifest {
        schema_version,
        generated_at: "2026-07-04T00:00:00Z".into(),
        expires_at: "2099-01-01T00:00:00Z".into(),
        withdrawn_versions: Vec::new(),
        releases: vec![
            release("macos", "aarch64", "https://updates.yadorilink.example/beta/a.pkg"),
            release("windows", "x86_64", "https://updates.yadorilink.example/beta/b.exe"),
        ],
    }
}

struct Fixture {
    key: SigningKey,
    trusted: Vec<TrustedKey>,
}

impl Fixture {
    fn new() -> Self {
        let mut seed = [0u8; 32];
        rand::fill(&mut seed);
        let key = SigningKey::from_bytes(&seed);
        // `TrustedKey` holds `&'static str`; leaking a few bytes in a test is fine.
        let trusted = vec![TrustedKey {
            key_id: KEY_ID,
            public_key_hex: Box::leak(hex::encode(key.verifying_key().to_bytes()).into_boxed_str()),
        }];
        Self { key, trusted }
    }

    fn sign(&self, manifest: &UpdateManifest) -> SignedManifestEnvelope {
        let manifest_json = serde_json::to_string_pretty(manifest).unwrap();
        let signature = self.key.sign(manifest_json.as_bytes());
        SignedManifestEnvelope {
            key_id: KEY_ID.into(),
            manifest_json,
            signature_base64: base64::engine::general_purpose::STANDARD
                .encode(signature.to_bytes()),
            trust_chain: Vec::new(),
        }
    }

    fn verify(&self, envelope: &SignedManifestEnvelope) -> Result<UpdateManifest, ManifestError> {
        manifest::verify_and_parse_with_keys(
            &serde_json::to_string(envelope).unwrap(),
            &self.trusted,
        )
    }
}

#[test]
fn current_schema_manifest_signed_by_a_trusted_key_verifies() {
    let fixture = Fixture::new();
    let envelope = fixture.sign(&manifest_with_schema(manifest::MANIFEST_SCHEMA_VERSION));
    let manifest = fixture.verify(&envelope).expect("a current-schema signed manifest verifies");
    assert_eq!(manifest.schema_version, manifest::MANIFEST_SCHEMA_VERSION);
    assert_eq!(manifest.releases.len(), 2);
    assert!(manifest.releases.iter().any(|r| r.platform == "macos" && r.version == "0.2.0"));
    assert!(manifest.releases.iter().any(|r| r.platform == "windows" && r.version == "0.2.0"));
}

/// Changing the signed body after signing fails on the signature, and on the
/// signature specifically: the tampered body is still a current-schema manifest.
#[test]
fn tampering_the_body_after_signing_fails_the_signature_check() {
    let fixture = Fixture::new();
    let mut envelope = fixture.sign(&manifest_with_schema(manifest::MANIFEST_SCHEMA_VERSION));
    assert!(envelope.manifest_json.contains("0.2.0"));
    envelope.manifest_json = envelope.manifest_json.replace("0.2.0", "9.9.9");
    let tampered: UpdateManifest = serde_json::from_str(&envelope.manifest_json).unwrap();
    assert_eq!(tampered.schema_version, manifest::MANIFEST_SCHEMA_VERSION);
    assert!(matches!(fixture.verify(&envelope), Err(ManifestError::SignatureVerificationFailed)));
}

/// A signature from a different key under the trusted id fails the signature check; an id the
/// verifier does not trust is refused as an unknown key.
#[test]
fn a_signature_from_the_wrong_key_fails_the_signature_check() {
    let fixture = Fixture::new();
    let other = Fixture::new();
    let envelope = other.sign(&manifest_with_schema(manifest::MANIFEST_SCHEMA_VERSION));
    assert!(matches!(fixture.verify(&envelope), Err(ManifestError::SignatureVerificationFailed)));
    let mut renamed = envelope;
    renamed.key_id = "some-other-id".into();
    assert!(matches!(fixture.verify(&renamed), Err(ManifestError::UnknownKey(_))));
}

/// A correctly signed body at another schema version fails with a schema error, not a signature
/// error: the two causes are distinguishable.
#[test]
fn a_schema_mismatched_body_fails_with_a_schema_error() {
    let fixture = Fixture::new();
    let envelope = fixture.sign(&manifest_with_schema(manifest::MANIFEST_SCHEMA_VERSION - 1));
    match fixture.verify(&envelope) {
        Err(ManifestError::UnsupportedSchemaVersion { found, expected }) => {
            assert_eq!(found, manifest::MANIFEST_SCHEMA_VERSION - 1);
            assert_eq!(expected, manifest::MANIFEST_SCHEMA_VERSION);
        }
        other => panic!("expected UnsupportedSchemaVersion, got {other:?}"),
    }
}
