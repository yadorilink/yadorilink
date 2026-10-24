#![cfg(test)]

use super::test_support::*;
use super::*;

fn sample_entry(version: &str) -> ReleaseEntry {
    ReleaseEntry {
        channel: "beta".into(),
        platform: "macos".into(),
        arch: "aarch64".into(),
        install_source: "standalone".into(),
        version: version.into(),
        minimum_supported_version: "0.1.0".into(),
        rollout_percentage: 100,
        kill_switch: false,
        mandatory: false,
        artifact_url: "https://example.invalid/yadorilink-x.pkg".into(),
        artifact_sha256: "0".repeat(64),
        artifact_size: 1024,
        artifact_publisher_identity: String::new(),
        release_notes_url: "https://example.invalid/notes".into(),
        state_schema_version: None,
        state_schema_min_readable: None,
        sparkle_build: None,
    }
}

fn sample_manifest(entries: Vec<ReleaseEntry>) -> UpdateManifest {
    UpdateManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        generated_at: "2026-07-01T00:00:00Z".into(),
        expires_at: "2099-01-01T00:00:00Z".into(),
        withdrawn_versions: Vec::new(),
        releases: entries,
    }
}

fn sample_ctx() -> LocalContext {
    LocalContext {
        current_version: semver::Version::parse("0.1.0").unwrap(),
        channel: "beta".into(),
        platform: "macos".into(),
        arch: "aarch64".into(),
        install_source: "standalone".into(),
        rollout_bucket: 0,
        state_schema_version: 10,
    }
}

/// A validly-signed manifest with a newer, fully-rolled-out entry is
/// selected as available.
#[test]
fn valid_manifest_selects_an_applicable_update() {
    let manifest = sample_manifest(vec![sample_entry("0.2.0")]);
    let envelope = sign_manifest(&manifest);
    let keys = trusted_keys_hex(&test_trusted_keys());

    let parsed =
        verify_and_parse_with_keys(&serde_json::to_string(&envelope).unwrap(), &keys).unwrap();
    assert_eq!(parsed, manifest);

    match select_applicable(&parsed, &sample_ctx()) {
        Applicability::Available { version, mandatory, .. } => {
            assert_eq!(version, semver::Version::parse("0.2.0").unwrap());
            assert!(!mandatory);
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

/// A tampered payload (one changed byte) fails signature
/// verification and is never parsed into a usable manifest — this is
/// the fail-closed "tampered manifest is genuinely rejected" proof.
#[test]
fn tampered_manifest_body_fails_signature_verification() {
    let manifest = sample_manifest(vec![sample_entry("0.2.0")]);
    let mut envelope = sign_manifest(&manifest);
    // Flip the version an attacker most wants to control, without
    // re-signing (they don't have the private key).
    envelope.manifest_json = envelope.manifest_json.replace("0.2.0", "9.9.9");
    let keys = trusted_keys_hex(&test_trusted_keys());

    let result = verify_and_parse_with_keys(&serde_json::to_string(&envelope).unwrap(), &keys);
    assert_eq!(result, Err(ManifestError::SignatureVerificationFailed));
}

/// A manifest "signed" under a key id this build doesn't recognize is
/// rejected outright — never falls back to trusting it anyway.
#[test]
fn unknown_signing_key_is_rejected() {
    let manifest = sample_manifest(vec![sample_entry("0.2.0")]);
    let mut envelope = sign_manifest(&manifest);
    envelope.key_id = "some-other-key".into();
    let keys = trusted_keys_hex(&test_trusted_keys());

    let result = verify_and_parse_with_keys(&serde_json::to_string(&envelope).unwrap(), &keys);
    assert_eq!(result, Err(ManifestError::UnknownKey("some-other-key".into())));
}

/// `key_id_is_placeholder` checks the LABEL only, and is never what the
/// release gate relies on -- see the tests below, which detect the
/// placeholder by key MATERIAL instead, so a renamed `key_id` can't be
/// used to sneak the placeholder past the gate. Tests the mechanism, not
/// the current pinned state, so it keeps passing once a real key ships.
#[test]
fn key_id_is_placeholder_checks_the_label_only() {
    assert!(key_id_is_placeholder(PLACEHOLDER_TRUST_ROOT_KEY_ID));
    assert!(!key_id_is_placeholder("yadorilink-release-2026"));
}

/// The core bypass this gate closes: the placeholder public key, pinned
/// under a `key_id` that no longer looks like the placeholder's usual
/// label, must still be detected and rejected -- a naive `key_id`-only
/// check would miss this entirely.
#[test]
fn release_gate_rejects_placeholder_key_material_under_any_key_id() {
    let renamed_but_still_placeholder = &[TrustedKey {
        key_id: "yadorilink-release-2026", // looks legitimate
        public_key_hex: PLACEHOLDER_TRUST_ROOT_PUBLIC_KEY_HEX,
    }];
    assert!(release_gate_result(renamed_but_still_placeholder).is_err());
}

/// An empty trusted-key set is exactly as forgeable as no signature
/// check at all, so it must never pass the gate.
#[test]
fn release_gate_rejects_an_empty_trusted_key_set() {
    assert!(release_gate_result(&[]).is_err());
}

/// A trusted-key set containing only blank/whitespace key material is
/// also never a real trust root, even though the list itself is
/// non-empty.
#[test]
fn release_gate_rejects_a_blank_trusted_key_set() {
    let blank = &[TrustedKey { key_id: "blank", public_key_hex: "   " }];
    assert!(release_gate_result(blank).is_err());
}

#[test]
fn release_gate_rejects_malformed_public_key_and_duplicate_id() {
    let malformed = &[TrustedKey { key_id: "release", public_key_hex: "abcd" }];
    assert!(release_gate_result(malformed).is_err());

    let duplicate = &[
        TrustedKey {
            key_id: "release",
            public_key_hex: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        },
        TrustedKey {
            key_id: "release",
            public_key_hex: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        },
    ];
    assert!(release_gate_result(duplicate).is_err());
}

/// A real, non-placeholder configured key is accepted.
#[test]
fn release_gate_accepts_a_real_configured_root() {
    // Distinct from the placeholder's public key material, but still a
    // syntactically valid 32-byte hex string.
    const REAL_TEST_ROOT_PUBLIC_KEY_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    let real = &[TrustedKey {
        key_id: "yadorilink-release-2026",
        public_key_hex: REAL_TEST_ROOT_PUBLIC_KEY_HEX,
    }];
    assert!(release_gate_result(real).is_ok());
}

/// The local/dev opt-out, when explicitly enabled, bypasses the gate even
/// for a placeholder root -- but that override never changes
/// `release_gate_result` itself, only `evaluate_release_gate`'s handling
/// of it.
#[test]
fn release_gate_dev_override_bypasses_a_placeholder_root() {
    let placeholder = &[TrustedKey {
        key_id: PLACEHOLDER_TRUST_ROOT_KEY_ID,
        public_key_hex: PLACEHOLDER_TRUST_ROOT_PUBLIC_KEY_HEX,
    }];
    assert!(evaluate_release_gate(placeholder, false).is_err());
    assert!(evaluate_release_gate(placeholder, true).is_ok());
}

/// The opt-out value must be EXACTLY `1` (after trimming): only that
/// bypasses the gate. This is the fail-closed half of the fix -- an
/// accidental `=0`, `=false`, empty, or blank value left in release CI
/// must NOT disable the gate.
#[test]
fn dev_override_requires_exactly_one() {
    assert!(dev_override_value_enabled(Some("1")));
    assert!(dev_override_value_enabled(Some(" 1 "))); // surrounding whitespace trimmed
}

#[test]
fn dev_override_rejects_zero_false_empty_and_missing() {
    // The exact accidental values that must NOT fail the gate open.
    assert!(!dev_override_value_enabled(Some("0")));
    assert!(!dev_override_value_enabled(Some("false")));
    assert!(!dev_override_value_enabled(Some("true")));
    assert!(!dev_override_value_enabled(Some(""))); // present-but-empty
    assert!(!dev_override_value_enabled(Some("   "))); // present-but-blank
    assert!(!dev_override_value_enabled(Some("11")));
    assert!(!dev_override_value_enabled(None)); // unset
}

/// The release gate a real release pipeline actually runs
/// (`enforce_release_trust_root_gate`) reads the live pinned
/// `TRUSTED_KEYS` and the opt-out value it is given. This asserts the composed
/// function agrees with its parts, so it is stable regardless of how this test
/// binary happens to be invoked.
#[test]
fn enforce_gate_composes_live_trust_root_and_live_override() {
    assert_eq!(
        enforce_release_trust_root_gate(None),
        evaluate_release_gate(TRUSTED_KEYS, dev_override_value_enabled(None))
    );
}

/// The schema-version half of "invalid manifest is rejected".
#[test]
fn unsupported_schema_version_is_rejected() {
    let mut manifest = sample_manifest(vec![sample_entry("0.2.0")]);
    manifest.schema_version = 999;
    let envelope = sign_manifest(&manifest);
    let keys = trusted_keys_hex(&test_trusted_keys());

    let result = verify_and_parse_with_keys(&serde_json::to_string(&envelope).unwrap(), &keys);
    assert_eq!(
        result,
        Err(ManifestError::UnsupportedSchemaVersion {
            found: 999,
            expected: MANIFEST_SCHEMA_VERSION
        })
    );
}

/// Signs `manifest_json` verbatim with the test key.
fn sign_body(manifest_json: String) -> SignedManifestEnvelope {
    use base64::Engine;
    use ed25519_dalek::Signer;
    let signature = test_signing_key().sign(manifest_json.as_bytes());
    SignedManifestEnvelope {
        key_id: TEST_KEY_ID.to_string(),
        manifest_json,
        signature_base64: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
        trust_chain: Vec::new(),
    }
}

fn verify_body(manifest_json: String) -> Result<UpdateManifest, ManifestError> {
    let keys = trusted_keys_hex(&test_trusted_keys());
    let envelope = sign_body(manifest_json);
    verify_and_parse_with_keys(&serde_json::to_string(&envelope).unwrap(), &keys)
}

/// A signed body without `expires_at` is malformed: stripping the field cannot dodge the check.
#[test]
fn a_body_without_expires_at_is_malformed() {
    let mut body: serde_json::Value =
        serde_json::to_value(sample_manifest(vec![sample_entry("0.2.0")])).unwrap();
    body.as_object_mut().unwrap().remove("expires_at");
    let result = verify_body(serde_json::to_string(&body).unwrap());
    assert!(matches!(result, Err(ManifestError::MalformedBody(_))), "{result:?}");
}

/// `expires_at` must be strictly after `generated_at`, and both must be strict timestamps.
#[test]
fn an_expiry_that_is_not_after_generation_or_not_a_timestamp_is_malformed() {
    for bad in ["2026-07-01T00:00:00Z", "2026-06-30T23:59:59Z", "tomorrow", "2026-09-01", ""] {
        let mut m = sample_manifest(vec![sample_entry("0.2.0")]);
        m.expires_at = bad.into();
        let result = verify_body(serde_json::to_string(&m).unwrap());
        assert!(matches!(result, Err(ManifestError::MalformedBody(_))), "{bad}: {result:?}");
    }
}

/// Expired means `now > expires_at`; the boundary second itself is still valid.
#[test]
fn expiry_is_judged_against_the_clock_with_no_allowance() {
    let mut m = sample_manifest(vec![sample_entry("0.2.0")]);
    m.expires_at = "2026-09-01T00:00:00Z".into();
    let at = chrono::NaiveDate::from_ymd_opt(2026, 9, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap()
        .and_utc()
        .timestamp();
    assert_eq!(check_not_expired(&m, at - 1), Ok(()));
    assert_eq!(check_not_expired(&m, at), Ok(()));
    assert_eq!(
        check_not_expired(&m, at + 1),
        Err(ManifestError::Expired { expires_at: "2026-09-01T00:00:00Z".into() })
    );
}

/// An entry offering a version lower than (or equal to) the running
/// version is never selected, even though it's otherwise a perfectly
/// well-formed, validly-signed, applicable-platform entry.
#[test]
fn downgrade_entry_is_never_selected() {
    let manifest = sample_manifest(vec![sample_entry("0.0.9"), sample_entry("0.1.0")]);
    let mut ctx = sample_ctx();
    ctx.current_version = semver::Version::parse("0.1.0").unwrap();
    assert_eq!(select_applicable(&manifest, &ctx), Applicability::UpToDate);
}

/// A malformed version string in one entry doesn't error the whole
/// selection — it's simply excluded, and a valid newer entry
/// elsewhere in the same manifest is still selected.
#[test]
fn malformed_version_entry_is_skipped_not_fatal() {
    let mut bad = sample_entry("not-a-version");
    bad.rollout_percentage = 100;
    let manifest = sample_manifest(vec![bad, sample_entry("0.3.0")]);
    match select_applicable(&manifest, &sample_ctx()) {
        Applicability::Available { version, .. } => {
            assert_eq!(version, semver::Version::parse("0.3.0").unwrap())
        }
        other => panic!("expected Available for the well-formed entry, got {other:?}"),
    }
}

/// A rollout percentage of 0 never selects any install (bucket is
/// always `>= 0`), and is reported as held back rather than available.
#[test]
fn rollout_holdback_prevents_selection() {
    let mut entry = sample_entry("0.5.0");
    entry.rollout_percentage = 0;
    let manifest = sample_manifest(vec![entry]);
    match select_applicable(&manifest, &sample_ctx()) {
        Applicability::HeldBack { version, .. } => {
            assert_eq!(version, semver::Version::parse("0.5.0").unwrap())
        }
        other => panic!("expected HeldBack, got {other:?}"),
    }
}

/// The mirror case: full rollout (100%) always selects, regardless of
/// this install's particular bucket value.
#[test]
fn full_rollout_always_selects() {
    let entry = sample_entry("0.5.0"); // rollout_percentage: 100
    let manifest = sample_manifest(vec![entry]);
    let mut ctx = sample_ctx();
    ctx.rollout_bucket = 99;
    assert!(matches!(select_applicable(&manifest, &ctx), Applicability::Available { .. }));
}

/// An entry marked `kill_switch: true` is reported distinctly and is
/// never treated as installable even though it's otherwise a valid,
/// newer, fully rolled-out entry.
#[test]
fn kill_switch_entry_is_never_available() {
    let mut entry = sample_entry("0.9.0");
    entry.kill_switch = true;
    let manifest = sample_manifest(vec![entry]);
    match select_applicable(&manifest, &sample_ctx()) {
        Applicability::KillSwitched { version, .. } => {
            assert_eq!(version, semver::Version::parse("0.9.0").unwrap())
        }
        other => panic!("expected KillSwitched, got {other:?}"),
    }
}

/// A version below `minimum_supported_version` is mandatory even
/// without the explicit `mandatory` flag, and bypasses rollout
/// holdback (a mandatory security fix must not be gated behind a
/// staged percentage).
#[test]
fn below_minimum_supported_version_is_mandatory_and_bypasses_rollout() {
    let mut entry = sample_entry("0.5.0");
    entry.minimum_supported_version = "0.2.0".into();
    entry.rollout_percentage = 0; // would otherwise hold back
    let manifest = sample_manifest(vec![entry]);
    let mut ctx = sample_ctx();
    ctx.current_version = semver::Version::parse("0.1.0").unwrap(); // below minimum
    match select_applicable(&manifest, &ctx) {
        Applicability::Available { mandatory, .. } => assert!(mandatory),
        other => panic!("expected mandatory Available, got {other:?}"),
    }
}

/// Entries for a non-matching channel/platform/arch/install_source
/// are never selected, even if they're a validly-signed newer
/// version.
#[test]
fn non_matching_platform_entry_is_ignored() {
    let mut entry = sample_entry("0.9.0");
    entry.platform = "windows".into();
    let manifest = sample_manifest(vec![entry]);
    assert_eq!(select_applicable(&manifest, &sample_ctx()), Applicability::UpToDate);
}

/// Each install_source sees only its own entries: an `app_bundle` install never gets a `script`
/// artifact and vice versa, so adding per-source entries needs no schema change.
#[test]
fn every_install_source_sees_only_its_own_entries() {
    let sources = ["script", "app_bundle", "microsoft_store", "container", "homebrew", "apt"];
    let entries: Vec<ReleaseEntry> = sources
        .iter()
        .map(|source| {
            let mut entry = sample_entry("0.2.0");
            entry.install_source = (*source).into();
            entry.artifact_url = format!("https://example.invalid/{source}");
            entry
        })
        .collect();
    let manifest = sample_manifest(entries);
    for source in sources {
        let ctx = LocalContext { install_source: source.into(), ..sample_ctx() };
        match select_applicable(&manifest, &ctx) {
            Applicability::Available { entry, .. } => {
                assert_eq!(entry.install_source, source);
                assert!(entry.artifact_url.ends_with(source), "{source}: {}", entry.artifact_url);
            }
            other => panic!("{source}: expected Available, got {other:?}"),
        }
    }
    let ctx = LocalContext { install_source: "winget".into(), ..sample_ctx() };
    assert_eq!(select_applicable(&manifest, &ctx), Applicability::UpToDate);
}

/// The release gate requires the shipped version to equal the tag. This pins
/// why: under the update comparator a beta sorts below its release, so a
/// beta tag over a 0.1.0 build never notifies, while betas order among
/// themselves and below the final release.
#[test]
fn prerelease_versions_order_under_the_update_comparator() {
    let v = |s: &str| parse_semver(s).unwrap();
    assert!(v("0.1.0-beta.2") > v("0.1.0-beta.1"));
    assert!(v("0.1.0-beta.10") > v("0.1.0-beta.2"));
    assert!(v("0.1.0") > v("0.1.0-beta.2"));
    assert!(v("v0.1.0-beta.2") > v("0.1.0-beta.1"));
    assert!(!(v("0.1.0-beta.1") > v("0.1.0")));
}

// ---- version checks against the live manifest (pinned installs, appcast items) ----

#[test]
fn a_pinned_install_of_a_killed_version_is_refused() {
    let mut entry = sample_entry("0.3.0");
    entry.kill_switch = true;
    let m = sample_manifest(vec![entry]);
    assert_eq!(
        check_pinned_install(&m, &sample_ctx(), "0.3.0"),
        Err(VersionRefusal::KillSwitched("0.3.0".into()))
    );
    // Another version on the same channel is unaffected by that entry's kill switch.
    assert_eq!(check_pinned_install(&m, &sample_ctx(), "0.2.0"), Ok(()));
}

#[test]
fn a_pinned_install_of_a_yanked_version_is_refused_even_though_no_entry_names_it() {
    let mut m = sample_manifest(vec![sample_entry("0.2.0")]);
    m.withdrawn_versions = vec!["0.3.0".into()];
    assert_eq!(
        check_pinned_install(&m, &sample_ctx(), "v0.3.0"),
        Err(VersionRefusal::Withdrawn("0.3.0".into()))
    );
}

#[test]
fn a_pinned_install_below_the_minimum_is_refused_and_a_bad_version_too() {
    let mut entry = sample_entry("0.4.0");
    entry.minimum_supported_version = "0.3.0".into();
    let m = sample_manifest(vec![entry]);
    assert!(matches!(
        check_pinned_install(&m, &sample_ctx(), "0.2.9"),
        Err(VersionRefusal::BelowMinimum { .. })
    ));
    assert_eq!(check_pinned_install(&m, &sample_ctx(), "0.3.0"), Ok(()));
    assert!(matches!(
        check_pinned_install(&m, &sample_ctx(), "latest"),
        Err(VersionRefusal::InvalidVersion(_))
    ));
}

#[test]
fn an_appcast_item_must_be_exactly_the_served_version() {
    let m = sample_manifest(vec![sample_entry("0.3.0")]);
    assert_eq!(check_appcast_item(&m, &sample_ctx(), "0.3.0"), Ok(()));
    // Newer (appcast ahead of the manifest) and older (stale or replayed appcast) both stop.
    for item in ["0.4.0", "0.2.0"] {
        assert!(
            matches!(
                check_appcast_item(&m, &sample_ctx(), item),
                Err(VersionRefusal::NotServed { .. })
            ),
            "{item}"
        );
    }
}

#[test]
fn an_appcast_item_for_a_withdrawn_killed_or_unrolled_version_is_refused() {
    let mut killed = sample_entry("0.3.0");
    killed.kill_switch = true;
    assert_eq!(
        check_appcast_item(&sample_manifest(vec![killed]), &sample_ctx(), "0.3.0"),
        Err(VersionRefusal::KillSwitched("0.3.0".into()))
    );

    let mut withdrawn = sample_manifest(vec![sample_entry("0.3.0")]);
    withdrawn.withdrawn_versions = vec!["0.3.0".into()];
    assert_eq!(
        check_appcast_item(&withdrawn, &sample_ctx(), "0.3.0"),
        Err(VersionRefusal::Withdrawn("0.3.0".into()))
    );

    let mut staged = sample_entry("0.3.0");
    staged.rollout_percentage = 10;
    let mut ctx = sample_ctx();
    ctx.rollout_bucket = 50;
    assert_eq!(
        check_appcast_item(&sample_manifest(vec![staged.clone()]), &ctx, "0.3.0"),
        Err(VersionRefusal::HeldBack("0.3.0".into()))
    );
    // Below the minimum the update is mandatory, so rollout does not hold it back.
    staged.minimum_supported_version = "0.2.0".into();
    ctx.current_version = semver::Version::parse("0.1.0").unwrap();
    assert_eq!(check_appcast_item(&sample_manifest(vec![staged]), &ctx, "0.3.0"), Ok(()));
}

#[test]
fn no_entry_for_this_install_offers_nothing() {
    let mut other = sample_entry("0.3.0");
    other.platform = "windows".into();
    assert_eq!(
        check_appcast_item(&sample_manifest(vec![other]), &sample_ctx(), "0.3.0"),
        Err(VersionRefusal::NotOffered)
    );
}

#[test]
fn withdrawn_versions_is_optional_on_the_wire() {
    let m = sample_manifest(vec![sample_entry("0.2.0")]);
    let json = serde_json::to_string(&m).unwrap();
    assert!(!json.contains("withdrawn_versions"));
    let parsed: UpdateManifest = serde_json::from_str(&json).unwrap();
    assert!(parsed.withdrawn_versions.is_empty());
}

fn declaring(version: &str, writes: u32, min: Option<u32>) -> ReleaseEntry {
    ReleaseEntry {
        state_schema_version: Some(writes),
        state_schema_min_readable: min,
        sparkle_build: None,
        ..sample_entry(version)
    }
}

/// The context's data is stamped 10. A release whose engine cannot read that is never offered,
/// whichever path asks, and the refusal says why.
#[test]
fn a_release_whose_engine_cannot_read_the_data_on_disk_is_refused_on_every_path() {
    let ctx = sample_ctx();
    for (entry, expected) in [
        // A downgrade across a schema change.
        (
            declaring("0.2.0", 9, None),
            StateRefusal::NewerThanReadable { on_disk: 10, newest_readable: 9 },
        ),
        // A gap the engine no longer reads.
        (
            declaring("0.2.0", 12, Some(11)),
            StateRefusal::OlderThanReadable { on_disk: 10, oldest_readable: 11 },
        ),
        // A declaration that contradicts itself.
        (declaring("0.2.0", 10, Some(11)), StateRefusal::Undeclarable),
    ] {
        let manifest = sample_manifest(vec![entry]);
        match select_applicable(&manifest, &ctx) {
            Applicability::StateIncompatible { refusal, .. } => assert_eq!(refusal, expected),
            other => panic!("expected StateIncompatible, got {other:?}"),
        }
        for refused in [
            check_pinned_install(&manifest, &ctx, "0.2.0").unwrap_err(),
            check_appcast_item(&manifest, &ctx, "0.2.0").unwrap_err(),
        ] {
            assert_eq!(
                refused,
                VersionRefusal::StateIncompatible { version: "0.2.0".into(), refusal: expected }
            );
        }
    }
}

#[test]
fn a_release_that_reads_the_data_on_disk_or_declares_nothing_is_offered() {
    let ctx = sample_ctx();
    for entry in
        [declaring("0.2.0", 10, None), declaring("0.2.0", 11, Some(10)), sample_entry("0.2.0")]
    {
        let manifest = sample_manifest(vec![entry]);
        assert!(matches!(select_applicable(&manifest, &ctx), Applicability::Available { .. }));
        check_pinned_install(&manifest, &ctx, "0.2.0").unwrap();
        check_appcast_item(&manifest, &ctx, "0.2.0").unwrap();
    }
}

#[test]
fn the_state_declaration_survives_signing_and_older_entries_still_parse() {
    let manifest = sample_manifest(vec![declaring("0.2.0", 11, Some(10))]);
    let json = serde_json::to_string(&manifest).unwrap();
    assert_eq!(serde_json::from_str::<UpdateManifest>(&json).unwrap(), manifest);
    let without = serde_json::to_string(&sample_manifest(vec![sample_entry("0.2.0")])).unwrap();
    assert!(!without.contains("state_schema"));
    assert_eq!(
        serde_json::from_str::<UpdateManifest>(&without).unwrap().releases[0].state_schema_version,
        None
    );
}

#[test]
fn a_manifest_generated_far_in_the_future_is_refused_but_small_skew_is_not() {
    let m = sample_manifest(vec![sample_entry("0.2.0")]);
    let generated = chrono::NaiveDateTime::parse_from_str(&m.generated_at, "%Y-%m-%dT%H:%M:%SZ")
        .unwrap()
        .and_utc()
        .timestamp();
    assert_eq!(check_not_future_dated(&m, generated), Ok(()));
    assert_eq!(check_not_future_dated(&m, generated - MAX_FUTURE_SKEW_SECS), Ok(()));
    assert!(matches!(
        check_not_future_dated(&m, generated - MAX_FUTURE_SKEW_SECS - 1),
        Err(ManifestError::FutureDated { .. })
    ));
}

#[test]
fn the_artifact_file_is_the_last_segment_of_the_url() {
    let mut e = sample_entry("1.0.0");
    e.artifact_url = "https://yadori.link/dl/1.0.0/YadoriLink-1.0.0.dmg".into();
    assert_eq!(e.artifact_file(), "YadoriLink-1.0.0.dmg");
}

/// A manifest written before `sparkle_build` existed still parses, and the field is left out of
/// what is written when absent, so existing signed bytes do not change.
#[test]
fn sparkle_build_is_additive_in_the_manifest() {
    let e = sample_entry("1.0.0");
    let json = serde_json::to_string(&e).unwrap();
    assert!(!json.contains("sparkle_build"));
    let back: ReleaseEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.sparkle_build, None);
    let with = ReleaseEntry { sparkle_build: Some(7), ..e };
    let back: ReleaseEntry = serde_json::from_str(&serde_json::to_string(&with).unwrap()).unwrap();
    assert_eq!(back.sparkle_build, Some(7));
}

/// An appcast item is covered only by the served entry's exact version, build, whole URL and
/// length (and, once downloaded, sha256); every other field is its own typed refusal, and a
/// required field left out is refused, not skipped.
#[test]
fn an_appcast_item_that_differs_from_the_served_entry_is_refused_by_field() {
    use AppcastPhase::{Downloaded, Enclosure};
    let ctx = sample_ctx();
    let url = "https://example.invalid/dl/0.2.0/YadoriLink-0.2.0.dmg";
    let served = ReleaseEntry {
        sparkle_build: Some(42),
        artifact_url: url.into(),
        artifact_size: 1024,
        ..sample_entry("0.2.0")
    };
    let manifest = sample_manifest(vec![served]);
    let item = AppcastItem {
        version: "0.2.0".into(),
        sparkle_build: 42,
        channel: Some("beta".into()),
        url: url.into(),
        length: 1024,
        sha256: None,
    };
    let with_sha = AppcastItem { sha256: Some("0".repeat(64)), ..item.clone() };
    assert_eq!(check_appcast_entry(&manifest, &ctx, &item, Enclosure), Ok(()));
    assert_eq!(check_appcast_entry(&manifest, &ctx, &with_sha, Downloaded), Ok(()));
    let code = |item: AppcastItem, phase| {
        check_appcast_entry(&manifest, &ctx, &item, phase).unwrap_err().code()
    };
    assert_eq!(
        code(AppcastItem { sparkle_build: 41, ..item.clone() }, Enclosure),
        "build_mismatch"
    );
    assert_eq!(code(AppcastItem { sparkle_build: 0, ..item.clone() }, Enclosure), "build_missing");
    assert_eq!(code(AppcastItem { url: String::new(), ..item.clone() }, Enclosure), "url_missing");
    // The same file name on another host, scheme or path is not the served URL.
    for other in [
        "https://evil.invalid/dl/0.2.0/YadoriLink-0.2.0.dmg",
        "http://example.invalid/dl/0.2.0/YadoriLink-0.2.0.dmg",
        "https://example.invalid/other/YadoriLink-0.2.0.dmg",
        "YadoriLink-0.2.0.dmg",
    ] {
        assert_eq!(
            code(AppcastItem { url: other.into(), ..item.clone() }, Enclosure),
            "url_mismatch"
        );
    }
    assert_eq!(code(AppcastItem { length: 0, ..item.clone() }, Enclosure), "length_missing");
    assert_eq!(code(AppcastItem { length: 1025, ..item.clone() }, Enclosure), "length_mismatch");
    assert_eq!(
        code(AppcastItem { channel: Some("stable".into()), ..item.clone() }, Enclosure),
        "channel_mismatch"
    );
    // The digest: required after the download, compared whenever it is given.
    assert_eq!(code(item.clone(), Downloaded), "sha256_missing");
    assert_eq!(
        code(AppcastItem { sha256: Some(String::new()), ..item.clone() }, Downloaded),
        "sha256_missing"
    );
    assert_eq!(
        code(AppcastItem { sha256: Some("1".repeat(64)), ..item.clone() }, Downloaded),
        "sha256_mismatch"
    );
    assert_eq!(
        code(AppcastItem { sha256: Some("1".repeat(64)), ..item.clone() }, Enclosure),
        "sha256_mismatch"
    );
    let undeclared = sample_manifest(vec![sample_entry("0.2.0")]);
    assert_eq!(
        check_appcast_entry(&undeclared, &ctx, &item, Enclosure).unwrap_err().code(),
        "build_not_declared"
    );
}
