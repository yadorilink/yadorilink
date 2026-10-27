#![cfg(test)]

use super::*;

/// Answers every probe with "not available" and counts them, so a test can see that detection
/// went through the runner instead of spawning a process.
#[cfg(target_os = "linux")]
pub(super) struct NoSpawnRunner;

#[cfg(target_os = "linux")]
static REFUSED_PROBES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(target_os = "linux")]
impl install_source::CommandRunner for NoSpawnRunner {
    fn run(&self, _program: &str, _args: &[&str]) -> std::io::Result<std::process::Output> {
        REFUSED_PROBES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }
}

/// Building a manager (every daemon state does) must not spawn a process from a test binary: a
/// child shares the process's sync-root locks until it execs.
#[cfg(target_os = "linux")]
#[test]
fn platform_detection_spawns_no_process_in_a_test_binary() {
    let before = REFUSED_PROBES.load(std::sync::atomic::Ordering::SeqCst);
    let info = PlatformInfo::detect(None);
    assert!(REFUSED_PROBES.load(std::sync::atomic::Ordering::SeqCst) > before);
    assert_eq!(info.install_source, "standalone");
}

/// An iOS build is its own platform and an App Store install, whatever its bundle path looks like.
// apple-cfg: ios-explicit the iOS platform string and install source
#[cfg(target_os = "ios")]
#[test]
fn an_ios_build_reports_the_app_store_as_its_install_source() {
    let info = PlatformInfo::detect(None);
    assert_eq!(info.platform, "ios");
    assert_eq!(info.install_source, "app_store");
}

fn manager(config_dir: &Path) -> UpdateManager {
    UpdateManager::new(
        config_dir,
        semver::Version::parse("0.1.0").unwrap(),
        &crate::engine_tuning::EngineTuning::default(),
    )
}

/// A manager that fetches its manifest from `manifest_url`.
fn manager_at(config_dir: &Path, manifest_url: &str) -> UpdateManager {
    UpdateManager::new(
        config_dir,
        semver::Version::parse("0.1.0").unwrap(),
        &crate::engine_tuning::EngineTuning {
            update_manifest_url: Some(manifest_url.to_owned()),
            ..crate::engine_tuning::EngineTuning::default()
        },
    )
}

/// Update Privacy requirement / spec "Update check uses coarse
/// metadata only": exercises the *real* HTTP request
/// `check_now` sends (via a real local mock server, not just a code
/// inspection) and asserts its query string carries exactly the six
/// documented coarse fields — schema_version, current_version,
/// platform, arch, channel, install_source — and nothing else: no
/// device id, account id, folder path, peer address, key, or token.
#[tokio::test]
async fn update_check_request_sends_only_the_documented_coarse_fields() {
    use std::collections::BTreeSet;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/manifest.json"))
        // The response body doesn't matter for this test -- an
        // invalid/unsigned body just makes `check_now` return an
        // error, which is fine; only the *request* is under test.
        .respond_with(ResponseTemplate::new(200).set_body_string("not a valid manifest"))
        .mount(&server)
        .await;
    let manifest_url = format!("{}/manifest.json", server.uri());

    let dir = tempfile::tempdir().unwrap();
    let manager = manager_at(dir.path(), &manifest_url);
    let _ = manager.check_now().await;

    let requests = server.received_requests().await.expect("request recording must be enabled");
    assert_eq!(requests.len(), 1, "expected exactly one manifest fetch");
    let query_keys: BTreeSet<String> =
        requests[0].url.query_pairs().map(|(k, _)| k.into_owned()).collect();
    let expected: BTreeSet<String> =
        ["schema_version", "current_version", "platform", "arch", "channel", "install_source"]
            .into_iter()
            .map(String::from)
            .collect();
    assert_eq!(
        query_keys, expected,
        "update-check request must carry exactly the documented coarse fields and nothing else"
    );
}

/// Builds a `ReleaseEntry` that matches `mgr`'s own detected platform
/// context (channel/platform/arch/install_source), so `select_applicable`
/// actually considers it, with the given rollout/kill-switch knobs.
fn matching_entry(
    mgr: &UpdateManager,
    version: &str,
    rollout: u8,
    kill_switch: bool,
) -> manifest::ReleaseEntry {
    manifest::ReleaseEntry {
        channel: "beta".into(),
        platform: mgr.platform_info().platform.clone(),
        arch: mgr.platform_info().arch.clone(),
        install_source: mgr.platform_info().install_source.clone(),
        version: version.into(),
        minimum_supported_version: "0.1.0".into(),
        rollout_percentage: rollout,
        kill_switch,
        mandatory: false,
        artifact_url: "https://example.invalid/yadorilink-update".into(),
        artifact_sha256: "0".repeat(64),
        artifact_size: 1024,
        artifact_publisher_identity: String::new(),
        release_notes_url: "https://example.invalid/notes".into(),
        state_schema_version: None,
        state_schema_min_readable: None,
        sparkle_build: None,
    }
}

async fn serve_envelope_and_check(
    envelope_json: String,
    config_dir: &Path,
) -> Result<Applicability, UpdateError> {
    serve_envelope_and_check_at(envelope_json, config_dir, None).await
}

/// As [`serve_envelope_and_check`], with the manager's clock fixed at `now` (Unix seconds).
async fn serve_envelope_and_check_at(
    envelope_json: String,
    config_dir: &Path,
    now: Option<i64>,
) -> Result<Applicability, UpdateError> {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/manifest.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(envelope_json))
        .mount(&server)
        .await;
    let manifest_url = format!("{}/manifest.json", server.uri());
    let mut mgr = manager_at(config_dir, &manifest_url);
    mgr.set_trusted_keys_for_test(manifest::test_support::trusted_keys_hex(
        &manifest::test_support::test_trusted_keys(),
    ));
    if let Some(now) = now {
        mgr.set_now_for_test(now);
    }
    let result = mgr.check_now().await;
    result
}

/// End-to-end: a real `UpdateManager` fetches a real signed manifest
/// envelope from a real local HTTP server and reaches `Available` for
/// a fully-rolled-out release newer than its current version — the
/// same `manifest::verify_and_parse` path a production daemon runs,
/// exercised through `check_now`, not a unit-level call into
/// `select_applicable` alone.
#[tokio::test]
async fn a_running_daemon_discovers_verifies_and_applies_a_signed_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let entry = matching_entry(&mgr, "9.9.9", 100, false);
    let doc = manifest::UpdateManifest {
        schema_version: manifest::MANIFEST_SCHEMA_VERSION,
        generated_at: "2026-07-01T00:00:00Z".into(),
        expires_at: "2099-01-01T00:00:00Z".into(),
        withdrawn_versions: Vec::new(),
        releases: vec![entry],
    };
    let envelope = manifest::test_support::sign_manifest(&doc);
    let envelope_json = serde_json::to_string(&envelope).unwrap();

    let result = serve_envelope_and_check(envelope_json, dir.path()).await;
    match result {
        Ok(Applicability::Available { version, .. }) => {
            assert_eq!(version, semver::Version::parse("9.9.9").unwrap());
        }
        other => panic!("expected a verified Available update, got {other:?}"),
    }
}

/// Same end-to-end path, but the entry's rollout hasn't selected this
/// install (0%): `check_now` must report `HeldBack`, not silently
/// install and not error out.
#[tokio::test]
async fn a_running_daemon_holds_back_an_update_outside_its_rollout_percentage() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let entry = matching_entry(&mgr, "9.9.9", 0, false);
    let doc = manifest::UpdateManifest {
        schema_version: manifest::MANIFEST_SCHEMA_VERSION,
        generated_at: "2026-07-01T00:00:00Z".into(),
        expires_at: "2099-01-01T00:00:00Z".into(),
        withdrawn_versions: Vec::new(),
        releases: vec![entry],
    };
    let envelope = manifest::test_support::sign_manifest(&doc);
    let envelope_json = serde_json::to_string(&envelope).unwrap();

    let result = serve_envelope_and_check(envelope_json, dir.path()).await;
    assert!(
        matches!(result, Ok(Applicability::HeldBack { .. })),
        "expected HeldBack for a 0% rollout, got {result:?}"
    );
}

/// Same end-to-end path, but the served envelope's signature no
/// longer matches its body (simulating a tampered or corrupted
/// response, or an operator's `resign` step being skipped after an
/// edit): `check_now` must fail closed, never fall back to an
/// unverified manifest and never report an update as available.
#[tokio::test]
async fn a_running_daemon_rejects_a_tampered_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let entry = matching_entry(&mgr, "9.9.9", 100, false);
    let doc = manifest::UpdateManifest {
        schema_version: manifest::MANIFEST_SCHEMA_VERSION,
        generated_at: "2026-07-01T00:00:00Z".into(),
        expires_at: "2099-01-01T00:00:00Z".into(),
        withdrawn_versions: Vec::new(),
        releases: vec![entry],
    };
    let mut envelope = manifest::test_support::sign_manifest(&doc);
    // Mutate the signed body after signing without re-signing --
    // the signature on the wire no longer matches these bytes.
    envelope.manifest_json = envelope.manifest_json.replace("9.9.9", "9.9.8");
    let envelope_json = serde_json::to_string(&envelope).unwrap();

    let result = serve_envelope_and_check(envelope_json, dir.path()).await;
    assert!(
        matches!(
            result,
            Err(UpdateError::Manifest(manifest::ManifestError::SignatureVerificationFailed))
        ),
        "expected signature verification to fail (not some unrelated error), got {result:?}"
    );
}

/// Serves `status` for every manifest request, runs `check_now`, and returns
/// its result with the persisted policy.
async fn serve_status_and_check(
    status: u16,
    config_dir: &Path,
) -> (Result<Applicability, UpdateError>, UpdatePolicy) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/manifest.json"))
        .respond_with(ResponseTemplate::new(status))
        .mount(&server)
        .await;
    let manifest_url = format!("{}/manifest.json", server.uri());
    let mgr = manager_at(config_dir, &manifest_url);
    let result = mgr.check_now().await;
    (result, mgr.policy.load_or_default())
}

/// Before any release publishes a manifest for a channel the server answers
/// 404. That is "nothing to update to", not a failed check: it must not leave
/// an error category for `status` to raise attention about.
#[tokio::test]
async fn a_channel_with_no_published_manifest_is_up_to_date_not_failed() {
    let dir = tempfile::tempdir().unwrap();
    let (result, policy) = serve_status_and_check(404, dir.path()).await;
    assert!(matches!(result, Ok(Applicability::UpToDate)), "{result:?}");
    assert_eq!(policy.state, UpdateState::UpToDate);
    assert_eq!(policy.last_error_category, None);
    assert!(policy.last_check_unix.is_some());
}

/// Only 404 means "no manifest yet"; a server error is still a failed check.
#[tokio::test]
async fn a_server_error_while_fetching_the_manifest_is_still_a_failure() {
    let dir = tempfile::tempdir().unwrap();
    let (result, policy) = serve_status_and_check(500, dir.path()).await;
    assert!(matches!(result, Err(UpdateError::Fetch(_))), "{result:?}");
    assert_eq!(policy.state, UpdateState::Failed);
    assert_eq!(policy.last_error_category.as_deref(), Some("update_manifest_fetch_failed"));
}

/// Rotation and revocation through the real `check_now` path: the trust
/// chain a response carries is persisted, so a later response that omits it
/// (or an attacker-signed manifest from a revoked key) cannot undo it.
#[tokio::test]
async fn trust_chain_from_a_response_is_persisted_and_revocation_sticks() {
    use manifest::test_support::{numbered_key, sign_manifest_as, sign_record, test_signing_key};

    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    // Each response is a new publish, so each carries a newer generated_at (the replay floor
    // refuses an equal one with different bytes).
    let generation = std::cell::Cell::new(0u32);
    let next_doc = || {
        generation.set(generation.get() + 1);
        manifest::UpdateManifest {
            schema_version: manifest::MANIFEST_SCHEMA_VERSION,
            generated_at: format!("2026-07-01T00:00:{:02}Z", generation.get()),
            expires_at: "2099-01-01T00:00:00Z".into(),
            withdrawn_versions: Vec::new(),
            releases: vec![matching_entry(&mgr, "9.9.9", 100, false)],
        }
    };
    let old = test_signing_key();
    let next = numbered_key(42);
    let announce =
        sign_record(&old, manifest::test_support::TEST_KEY_ID, 1, &[("next", &next)], &[]);
    let retire = sign_record(&next, "next", 2, &[], &[manifest::test_support::TEST_KEY_ID]);
    let serve = |env: manifest::SignedManifestEnvelope| {
        serve_envelope_and_check(serde_json::to_string(&env).unwrap(), dir.path())
    };
    let by_old = |chain: Vec<_>| {
        sign_manifest_as(&old, manifest::test_support::TEST_KEY_ID, &next_doc(), chain)
    };
    let by_next = |chain: Vec<_>| sign_manifest_as(&next, "next", &next_doc(), chain);

    // Without the announcement the next key is unknown.
    assert!(matches!(
        serve(by_next(vec![])).await,
        Err(UpdateError::Manifest(manifest::ManifestError::UnknownKey(_)))
    ));
    // With it, both keys verify; the announcement is persisted.
    assert!(matches!(
        serve(by_next(vec![announce.clone()])).await,
        Ok(Applicability::Available { .. })
    ));
    assert!(matches!(serve(by_old(vec![])).await, Ok(Applicability::Available { .. })));
    assert!(matches!(serve(by_next(vec![])).await, Ok(Applicability::Available { .. })));
    // Retire the old key: its valid signatures are now refused, including on
    // a response that carries no chain.
    assert!(matches!(
        serve(by_next(vec![announce.clone(), retire.clone()])).await,
        Ok(Applicability::Available { .. })
    ));
    for chain in [vec![], vec![announce], vec![retire]] {
        let err = serve(by_old(chain)).await.unwrap_err();
        assert!(
            matches!(
                err,
                UpdateError::Manifest(manifest::ManifestError::RevokedKey(_))
                    | UpdateError::Manifest(manifest::ManifestError::Trust(_))
            ),
            "unexpected {err:?}"
        );
    }
    assert!(matches!(serve(by_next(vec![])).await, Ok(Applicability::Available { .. })));
}

/// Runs a real check against a signed manifest whose only entry (matching this install) has the
/// given `version`, `minimum_supported_version` and `mandatory` flag, and returns the persisted
/// policy plus the version the manager runs.
async fn check_against_entry(
    version: &str,
    minimum: &str,
    mandatory: bool,
    config_dir: &Path,
) -> (UpdatePolicy, semver::Version) {
    let mgr = manager(config_dir);
    let mut entry = matching_entry(&mgr, version, 100, false);
    entry.minimum_supported_version = minimum.into();
    entry.mandatory = mandatory;
    let doc = manifest::UpdateManifest {
        schema_version: manifest::MANIFEST_SCHEMA_VERSION,
        generated_at: "2026-07-01T00:00:00Z".into(),
        expires_at: "2099-01-01T00:00:00Z".into(),
        withdrawn_versions: Vec::new(),
        releases: vec![entry],
    };
    let envelope = serde_json::to_string(&manifest::test_support::sign_manifest(&doc)).unwrap();
    serve_envelope_and_check(envelope, config_dir).await.expect("the check succeeds");
    (mgr.policy.load_or_default(), mgr.current_version().clone())
}

/// A client below the signed minimum reports "update required"; one exactly at it does not.
#[tokio::test]
async fn a_client_below_the_manifest_minimum_is_told_an_update_is_required() {
    let dir = tempfile::tempdir().unwrap();
    let (policy, current) = check_against_entry("9.9.9", "5.0.0", false, dir.path()).await;
    assert!(policy.update_required(&current), "0.1.0 is below the minimum 5.0.0");

    let dir = tempfile::tempdir().unwrap();
    let (policy, current) = check_against_entry("9.9.9", "0.1.0", false, dir.path()).await;
    assert!(!policy.update_required(&current), "current == minimum is supported");
}

/// `mandatory` is not a cutover signal: an entry marked mandatory with a minimum the client meets
/// does not make "update required".
#[tokio::test]
async fn the_mandatory_flag_alone_is_not_a_cutover() {
    let dir = tempfile::tempdir().unwrap();
    let (policy, current) = check_against_entry("9.9.9", "0.1.0", true, dir.path()).await;
    assert!(policy.mandatory);
    assert!(!policy.update_required(&current));
}

/// Once the client is up to date the recorded minimum is cleared, so nothing stale remains.
#[tokio::test]
async fn an_up_to_date_check_clears_the_recorded_minimum() {
    let dir = tempfile::tempdir().unwrap();
    {
        check_against_entry("9.9.9", "5.0.0", false, dir.path()).await;
    }
    // `serve_status_and_check` takes the env lock itself.
    // The same install, now reporting a 404 (nothing newer is published).
    let (_, policy) = serve_status_and_check(404, dir.path()).await;
    assert_eq!(policy.minimum_supported_version, None);
}

// ---- replay protection and live version checks, through the real fetch path ----

fn doc_at(mgr: &UpdateManager, generated_at: &str) -> manifest::UpdateManifest {
    manifest::UpdateManifest {
        schema_version: manifest::MANIFEST_SCHEMA_VERSION,
        generated_at: generated_at.into(),
        expires_at: "2099-01-01T00:00:00Z".into(),
        withdrawn_versions: Vec::new(),
        releases: vec![matching_entry(mgr, "9.9.9", 100, false)],
    }
}

async fn serve_doc(
    doc: &manifest::UpdateManifest,
    dir: &Path,
) -> Result<Applicability, UpdateError> {
    let envelope = manifest::test_support::sign_manifest(doc);
    serve_envelope_and_check(serde_json::to_string(&envelope).unwrap(), dir).await
}

#[tokio::test]
async fn an_older_signed_manifest_is_refused_after_a_newer_one_even_across_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let new = doc_at(&mgr, "2026-10-19T00:00:10Z");
    let old = doc_at(&mgr, "2026-10-19T00:00:05Z");
    assert!(serve_doc(&new, dir.path()).await.is_ok());
    // Each helper call builds a fresh manager over the same directory: a restart.
    let err = serve_doc(&old, dir.path()).await.unwrap_err();
    assert!(matches!(err, UpdateError::Replay(_)), "{err:?}");
    assert_eq!(err.category(), "update_manifest_replayed");
    assert_eq!(
        manager(dir.path()).accepted_generation().unwrap().generated_at,
        "2026-10-19T00:00:10Z"
    );
}

#[tokio::test]
async fn an_equal_generated_at_is_accepted_for_the_same_bytes_only() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let doc = doc_at(&mgr, "2026-10-19T00:00:10Z");
    assert!(serve_doc(&doc, dir.path()).await.is_ok());
    assert!(serve_doc(&doc, dir.path()).await.is_ok(), "the same bytes are a republish");
    let mut other = doc_at(&mgr, "2026-10-19T00:00:10Z");
    other.releases[0].kill_switch = true;
    let err = serve_doc(&other, dir.path()).await.unwrap_err();
    assert!(matches!(err, UpdateError::Replay(_)), "{err:?}");
}

#[tokio::test]
async fn a_manifest_that_fails_verification_does_not_move_the_floor() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let mut envelope = manifest::test_support::sign_manifest(&doc_at(&mgr, "2999-01-01T00:00:00Z"));
    envelope.signature_base64 = "AAAA".into();
    let result =
        serve_envelope_and_check(serde_json::to_string(&envelope).unwrap(), dir.path()).await;
    assert!(result.is_err());
    assert!(manager(dir.path()).accepted_generation().is_none());
}

async fn check_version_against(
    doc: Option<&manifest::UpdateManifest>,
    kind: VersionCheckKind,
    version: &str,
    dir: &Path,
) -> Result<(), VersionCheckError> {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let response = match doc {
        Some(doc) => ResponseTemplate::new(200).set_body_string(
            serde_json::to_string(&manifest::test_support::sign_manifest(doc)).unwrap(),
        ),
        None => ResponseTemplate::new(404),
    };
    Mock::given(method("GET"))
        .and(path("/manifest.json"))
        .respond_with(response)
        .mount(&server)
        .await;
    let manifest_url = format!("{}/manifest.json", server.uri());
    let mut mgr = manager_at(dir, &manifest_url);
    mgr.set_trusted_keys_for_test(manifest::test_support::trusted_keys_hex(
        &manifest::test_support::test_trusted_keys(),
    ));
    let result = mgr.check_version(kind, version).await;
    result
}

#[tokio::test]
async fn a_pinned_install_of_a_killed_version_is_refused_by_the_live_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let mut doc = doc_at(&mgr, "2026-10-19T00:00:10Z");
    doc.releases[0].kill_switch = true;
    let result =
        check_version_against(Some(&doc), VersionCheckKind::PinnedInstall, "9.9.9", dir.path())
            .await;
    assert!(matches!(
        result,
        Err(VersionCheckError::Refused(manifest::VersionRefusal::KillSwitched(_)))
    ));
    let ok =
        check_version_against(Some(&doc), VersionCheckKind::PinnedInstall, "9.9.8", dir.path())
            .await;
    assert!(ok.is_ok(), "{ok:?}");
}

#[tokio::test]
async fn a_version_check_fails_closed_without_a_verified_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let none =
        check_version_against(None, VersionCheckKind::AppcastItem, "9.9.9", dir.path()).await;
    assert!(matches!(none, Err(VersionCheckError::NoManifest)));

    // Unverifiable: served under a key this client does not trust.
    let mgr = manager(dir.path());
    let mut bad = manifest::test_support::sign_manifest(&doc_at(&mgr, "2026-10-19T00:00:10Z"));
    bad.key_id = "unknown".into();
    let unverifiable = {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/manifest.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(serde_json::to_string(&bad).unwrap()),
            )
            .mount(&server)
            .await;
        let manifest_url = format!("{}/manifest.json", server.uri());
        let mut m = manager_at(dir.path(), &manifest_url);
        m.set_trusted_keys_for_test(manifest::test_support::trusted_keys_hex(
            &manifest::test_support::test_trusted_keys(),
        ));
        let r = m.check_version(VersionCheckKind::PinnedInstall, "9.9.9").await;
        r
    };
    assert!(matches!(unverifiable, Err(VersionCheckError::Unverifiable(_))));
}

#[tokio::test]
async fn an_appcast_item_ahead_of_the_manifest_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let doc = doc_at(&mgr, "2026-10-19T00:00:10Z");
    let ahead =
        check_version_against(Some(&doc), VersionCheckKind::AppcastItem, "10.0.0", dir.path())
            .await;
    assert!(matches!(
        ahead,
        Err(VersionCheckError::Refused(manifest::VersionRefusal::NotServed { .. }))
    ));
    let served =
        check_version_against(Some(&doc), VersionCheckKind::AppcastItem, "9.9.9", dir.path()).await;
    assert!(served.is_ok(), "{served:?}");
}

// ---- manifest freshness (expiry), through the real fetch path ----

fn unix_at(date: &str) -> i64 {
    chrono::NaiveDateTime::parse_from_str(date, "%Y-%m-%dT%H:%M:%SZ").unwrap().and_utc().timestamp()
}

fn doc_expiring(
    mgr: &UpdateManager,
    generated_at: &str,
    expires_at: &str,
) -> manifest::UpdateManifest {
    manifest::UpdateManifest { expires_at: expires_at.into(), ..doc_at(mgr, generated_at) }
}

async fn serve_doc_at(
    doc: &manifest::UpdateManifest,
    dir: &Path,
    now: i64,
) -> Result<Applicability, UpdateError> {
    let envelope = manifest::test_support::sign_manifest(doc);
    serve_envelope_and_check_at(serde_json::to_string(&envelope).unwrap(), dir, Some(now)).await
}

fn floor_bytes(dir: &Path) -> Option<Vec<u8>> {
    std::fs::read(dir.join("update_replay_floor.json")).ok()
}

#[tokio::test]
async fn an_expired_manifest_offers_nothing_and_leaves_the_replay_floor_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let good = doc_expiring(&mgr, "2026-10-19T00:00:10Z", "2026-12-18T00:00:10Z");
    assert!(serve_doc_at(&good, dir.path(), unix_at("2026-10-20T00:00:00Z")).await.is_ok());
    let before = floor_bytes(dir.path()).expect("the accepted manifest stored a floor");

    // A newer manifest, but past its expiry: refused before the floor can move.
    let stale = doc_expiring(&mgr, "2026-10-19T00:00:20Z", "2026-10-20T00:00:20Z");
    let err = serve_doc_at(&stale, dir.path(), unix_at("2026-10-21T00:00:00Z")).await.unwrap_err();
    assert!(
        matches!(err, UpdateError::Manifest(manifest::ManifestError::Expired { .. })),
        "{err:?}"
    );
    assert_eq!(err.category(), "update_manifest_expired");
    assert_eq!(floor_bytes(dir.path()), Some(before));

    let policy = UpdatePolicyStore::new(dir.path()).load_or_default();
    assert_eq!(policy.state, UpdateState::Failed);
    assert!(policy.manifest_expired());
    assert_eq!(policy.manifest_expires_at.as_deref(), Some("2026-10-20T00:00:20Z"));
}

#[tokio::test]
async fn a_manifest_is_accepted_through_its_expiry_second_and_refused_after() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let doc = doc_expiring(&mgr, "2026-10-19T00:00:10Z", "2026-12-18T00:00:10Z");
    let last_valid = unix_at("2026-12-18T00:00:10Z");
    assert!(serve_doc_at(&doc, dir.path(), last_valid).await.is_ok());
    assert!(floor_bytes(dir.path()).is_some());
    let err = serve_doc_at(&doc, dir.path(), last_valid + 1).await.unwrap_err();
    assert_eq!(err.category(), "update_manifest_expired");
}

#[tokio::test]
async fn a_failed_check_keeps_the_last_successful_check_time() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let doc = doc_expiring(&mgr, "2026-10-19T00:00:10Z", "2026-10-25T00:00:10Z");
    let ok_at = unix_at("2026-10-20T00:00:00Z");
    assert!(serve_doc_at(&doc, dir.path(), ok_at).await.is_ok());
    let policy = UpdatePolicyStore::new(dir.path()).load_or_default();
    assert_eq!(policy.last_success_unix, policy.last_check_unix);
    assert_eq!(policy.manifest_expires_at.as_deref(), Some("2026-10-25T00:00:10Z"));
    assert!(!policy.manifest_expired());

    let later = unix_at("2026-11-20T00:00:00Z");
    assert!(serve_doc_at(&doc, dir.path(), later).await.is_err());
    let policy = UpdatePolicyStore::new(dir.path()).load_or_default();
    assert_eq!(policy.last_success_unix, Some(ok_at));
    assert_eq!(policy.last_check_unix, Some(later));
    assert!(policy.manifest_expired());
}

#[tokio::test]
async fn a_far_future_manifest_is_refused_and_cannot_set_the_replay_floor() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let now = unix_at("2026-10-20T00:00:00Z");
    let poisoned = doc_expiring(&mgr, "2999-01-01T00:00:00Z", "2999-03-02T00:00:00Z");
    let err = serve_doc_at(&poisoned, dir.path(), now).await.unwrap_err();
    assert!(matches!(err, UpdateError::Manifest(manifest::ManifestError::FutureDated { .. })));
    assert_eq!(floor_bytes(dir.path()), None);

    // A correctly stamped manifest is still accepted afterwards.
    let good = doc_expiring(&mgr, "2026-10-19T00:00:10Z", "2026-12-18T00:00:10Z");
    assert!(serve_doc_at(&good, dir.path(), now).await.is_ok());
}

#[tokio::test]
async fn an_expired_manifest_stops_reporting_update_required_until_a_check_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let running = mgr.current_version().clone();
    let mut doc = doc_expiring(&mgr, "2026-10-19T00:00:10Z", "2026-10-25T00:00:10Z");
    let mut entry = matching_entry(&mgr, "999.0.0", 100, false);
    entry.minimum_supported_version = "999.0.0".into();
    doc.releases = vec![entry];
    assert!(serve_doc_at(&doc, dir.path(), unix_at("2026-10-20T00:00:00Z")).await.is_ok());
    let policy = UpdatePolicyStore::new(dir.path()).load_or_default();
    assert!(policy.update_required(&running));

    assert!(serve_doc_at(&doc, dir.path(), unix_at("2026-11-20T00:00:00Z")).await.is_err());
    let policy = UpdatePolicyStore::new(dir.path()).load_or_default();
    assert!(policy.manifest_expired());
    assert!(!policy.update_required(&running), "cannot confirm, not required");

    let fresh = doc_expiring(&mgr, "2026-11-19T00:00:10Z", "2027-01-18T00:00:10Z");
    let fresh = manifest::UpdateManifest { releases: doc.releases.clone(), ..fresh };
    assert!(serve_doc_at(&fresh, dir.path(), unix_at("2026-11-20T00:00:00Z")).await.is_ok());
    assert!(UpdatePolicyStore::new(dir.path()).load_or_default().update_required(&running));
}

/// A deliberate rollback is a new manifest with a higher generated_at that serves the older
/// release; the older manifest itself stays refused.
#[tokio::test]
async fn a_rollback_is_a_newer_manifest_not_an_older_one() {
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let now = unix_at("2026-10-20T00:00:00Z");
    let older = doc_expiring(&mgr, "2026-10-19T00:00:10Z", "2026-12-18T00:00:10Z");
    let newer = doc_expiring(&mgr, "2026-10-19T00:00:20Z", "2026-12-18T00:00:20Z");
    assert!(serve_doc_at(&newer, dir.path(), now).await.is_ok());
    let err = serve_doc_at(&older, dir.path(), now).await.unwrap_err();
    assert_eq!(err.category(), "update_manifest_replayed");
    let rolled_back = doc_expiring(&mgr, "2026-10-19T00:00:30Z", "2026-12-18T00:00:30Z");
    assert!(serve_doc_at(&rolled_back, dir.path(), now).await.is_ok());
}

// ---- the verified entry, as the app asks for it ----

const ENTRY_URL: &str = "https://example.invalid/yadorilink-update";
use manifest::AppcastPhase::{Downloaded, Enclosure};

fn item() -> manifest::AppcastItem {
    manifest::AppcastItem {
        version: "9.9.9".into(),
        sparkle_build: 42,
        channel: Some("beta".into()),
        url: ENTRY_URL.into(),
        length: 1024,
        sha256: Some("0".repeat(64)),
    }
}

fn doc_with_build(mgr: &UpdateManager) -> manifest::UpdateManifest {
    let mut doc = doc_at(mgr, "2026-10-19T00:00:10Z");
    doc.releases[0].sparkle_build = Some(42);
    doc
}

/// A manager that verified `doc` (or saw a 404 for `None`) through a real check at `now`. The
/// server is gone afterwards, so any later network request would fail.
async fn verified_manager(
    doc: Option<&manifest::UpdateManifest>,
    dir: &Path,
    now: i64,
) -> UpdateManager {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let response = match doc {
        Some(doc) => ResponseTemplate::new(200).set_body_string(
            serde_json::to_string(&manifest::test_support::sign_manifest(doc)).unwrap(),
        ),
        None => ResponseTemplate::new(404),
    };
    Mock::given(method("GET"))
        .and(path("/manifest.json"))
        .respond_with(response)
        .mount(&server)
        .await;
    let manifest_url = format!("{}/manifest.json", server.uri());
    let mut mgr = manager_at(dir, &manifest_url);
    mgr.set_trusted_keys_for_test(manifest::test_support::trusted_keys_hex(
        &manifest::test_support::test_trusted_keys(),
    ));
    mgr.set_now_for_test(now);
    let _ = mgr.check_now().await;
    mgr
}

fn code(answer: &VerifiedEntryAnswer) -> &'static str {
    match answer.verdict.as_ref().unwrap_err() {
        EntryRefusal::CannotConfirm(why) => why.code(),
        EntryRefusal::Refused(r) => r.code(),
    }
}

const NOW: &str = "2026-10-20T00:00:00Z";

#[tokio::test]
async fn an_item_equal_to_the_verified_entry_is_allowed_and_the_entry_is_returned() {
    let dir = tempfile::tempdir().unwrap();
    let doc = doc_with_build(&manager(dir.path()));
    let mgr = verified_manager(Some(&doc), dir.path(), unix_at(NOW)).await;
    let answer = mgr.verified_entry(&item(), Downloaded);
    assert!(answer.verdict.is_ok(), "{:?}", answer.verdict);
    let entry = answer.entry.expect("the verified entry is returned");
    assert_eq!(entry.entry.version, "9.9.9");
    assert_eq!(entry.entry.sparkle_build, Some(42));
    assert_eq!(entry.file, "yadorilink-update");
    assert_eq!(entry.entry.artifact_sha256, "0".repeat(64));
    assert_eq!(entry.expires_at, "2099-01-01T00:00:00Z");
    assert!(!entry.update_required);

    // Before the download there is no digest, and the daemon's own channel is authoritative.
    let enclosure = manifest::AppcastItem { channel: None, sha256: None, ..item() };
    assert!(mgr.verified_entry(&enclosure, Enclosure).verdict.is_ok());
    // After it, the digest is required: an item without one is refused, not skipped.
    let answer = mgr.verified_entry(&enclosure, Downloaded);
    assert_eq!(code(&answer), "sha256_missing");
}

#[tokio::test]
async fn any_field_mismatch_is_refused_with_its_own_reason_and_still_returns_the_entry() {
    let dir = tempfile::tempdir().unwrap();
    let doc = doc_with_build(&manager(dir.path()));
    let mgr = verified_manager(Some(&doc), dir.path(), unix_at(NOW)).await;
    let cases: [(manifest::AppcastItem, &str); 10] = [
        (manifest::AppcastItem { version: "9.9.8".into(), ..item() }, "version_mismatch"),
        (manifest::AppcastItem { version: "nine".into(), ..item() }, "invalid_version"),
        (manifest::AppcastItem { sparkle_build: 43, ..item() }, "build_mismatch"),
        (manifest::AppcastItem { sparkle_build: 0, ..item() }, "build_missing"),
        (
            manifest::AppcastItem {
                url: "https://evil.invalid/yadorilink-update".into(),
                ..item()
            },
            "url_mismatch",
        ),
        (manifest::AppcastItem { url: String::new(), ..item() }, "url_missing"),
        (manifest::AppcastItem { length: 1, ..item() }, "length_mismatch"),
        (manifest::AppcastItem { length: 0, ..item() }, "length_missing"),
        (manifest::AppcastItem { sha256: Some("1".repeat(64)), ..item() }, "sha256_mismatch"),
        (manifest::AppcastItem { channel: Some("stable".into()), ..item() }, "channel_mismatch"),
    ];
    for (wrong, expected) in cases {
        let answer = mgr.verified_entry(&wrong, Downloaded);
        assert_eq!(code(&answer), expected, "{wrong:?}");
        assert!(matches!(answer.verdict, Err(EntryRefusal::Refused(_))));
        // The invalid-version and channel cases do not depend on the entry; the entry is still
        // the verified one.
        assert_eq!(answer.entry.expect("entry").entry.version, "9.9.9");
    }
}

#[tokio::test]
async fn a_withdrawn_or_killed_or_undeclared_entry_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut doc = doc_with_build(&manager(dir.path()));
    doc.withdrawn_versions = vec!["9.9.9".into()];
    let mgr = verified_manager(Some(&doc), dir.path(), unix_at(NOW)).await;
    assert_eq!(code(&mgr.verified_entry(&item(), Downloaded)), "withdrawn");

    let dir = tempfile::tempdir().unwrap();
    let mut doc = doc_with_build(&manager(dir.path()));
    doc.releases[0].kill_switch = true;
    let mgr = verified_manager(Some(&doc), dir.path(), unix_at(NOW)).await;
    assert_eq!(code(&mgr.verified_entry(&item(), Downloaded)), "kill_switched");

    let dir = tempfile::tempdir().unwrap();
    let mut doc = doc_with_build(&manager(dir.path()));
    doc.releases[0].sparkle_build = None;
    let mgr = verified_manager(Some(&doc), dir.path(), unix_at(NOW)).await;
    assert_eq!(code(&mgr.verified_entry(&item(), Downloaded)), "build_not_declared");
}

#[tokio::test]
async fn without_a_fresh_verified_manifest_the_answer_is_cannot_confirm() {
    let confirm = |a: &VerifiedEntryAnswer| {
        assert!(a.entry.is_none(), "nothing is returned that was not confirmed");
        assert!(matches!(a.verdict, Err(EntryRefusal::CannotConfirm(_))));
        code(a)
    };

    // Nothing verified since start.
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(confirm(&manager(dir.path()).verified_entry(&item(), Downloaded)), "not_checked");

    // The channel has no manifest.
    let dir = tempfile::tempdir().unwrap();
    let mgr = verified_manager(None, dir.path(), unix_at(NOW)).await;
    assert_eq!(confirm(&mgr.verified_entry(&item(), Downloaded)), "no_manifest");

    // Stale, then expired.
    let dir = tempfile::tempdir().unwrap();
    let mut doc = doc_with_build(&manager(dir.path()));
    doc.expires_at = "2026-10-25T00:00:10Z".into();
    let mut mgr = verified_manager(Some(&doc), dir.path(), unix_at(NOW)).await;
    mgr.set_now_for_test(unix_at(NOW) + VERIFIED_MAX_AGE_SECS);
    assert!(mgr.verified_entry(&item(), Downloaded).verdict.is_ok());
    mgr.set_now_for_test(unix_at(NOW) + VERIFIED_MAX_AGE_SECS + 1);
    assert_eq!(confirm(&mgr.verified_entry(&item(), Downloaded)), "stale");
    // Expired while still fresh by age.
    let dir = tempfile::tempdir().unwrap();
    let mut doc = doc_with_build(&manager(dir.path()));
    doc.expires_at = "2026-10-20T01:00:00Z".into();
    let mut mgr = verified_manager(Some(&doc), dir.path(), unix_at(NOW)).await;
    mgr.set_now_for_test(unix_at("2026-10-20T01:00:01Z"));
    assert_eq!(confirm(&mgr.verified_entry(&item(), Downloaded)), "manifest_expired");

    // A clock that went backwards past the verification does not make the entry fresh again.
    mgr.set_now_for_test(unix_at(NOW) - 1);
    assert_eq!(confirm(&mgr.verified_entry(&item(), Downloaded)), "stale");
}

#[tokio::test]
async fn asking_for_the_entry_does_not_move_the_replay_floor() {
    let dir = tempfile::tempdir().unwrap();
    let doc = doc_with_build(&manager(dir.path()));
    let mgr = verified_manager(Some(&doc), dir.path(), unix_at(NOW)).await;
    let floor = floor_bytes(dir.path()).expect("the verified manifest stored a floor");
    let policy = std::fs::read(dir.path().join("update_policy.json")).ok();
    for wrong in [item(), manifest::AppcastItem { sparkle_build: 7, ..item() }] {
        let _ = mgr.verified_entry(&wrong, Downloaded);
    }
    assert_eq!(floor_bytes(dir.path()), Some(floor));
    assert_eq!(std::fs::read(dir.path().join("update_policy.json")).ok(), policy);
}

#[tokio::test]
async fn switching_channel_makes_the_verified_manifest_not_apply() {
    let dir = tempfile::tempdir().unwrap();
    let doc = doc_with_build(&manager(dir.path()));
    let mgr = verified_manager(Some(&doc), dir.path(), unix_at(NOW)).await;
    assert!(mgr.verified_entry(&item(), Downloaded).verdict.is_ok());
    mgr.policy.update(|p| p.channel = "stable".into()).unwrap();
    let answer = mgr.verified_entry(&item(), Downloaded);
    assert!(answer.entry.is_none());
    assert_eq!(code(&answer), "not_checked");
}

/// A check that was accepted earlier can finish after a newer one: the floor refuses it and the
/// cache keeps the newer manifest, so a withdrawal in the newer one is never lost.
#[tokio::test]
async fn an_older_generation_finishing_late_cannot_replace_the_newer_cached_one() {
    let dir = tempfile::tempdir().unwrap();
    let mut mgr = manager(dir.path());
    mgr.set_now_for_test(unix_at(NOW));
    let old = doc_with_build(&mgr);
    let mut newer =
        manifest::UpdateManifest { generated_at: "2026-10-19T00:00:20Z".into(), ..old.clone() };
    newer.withdrawn_versions = vec!["9.9.9".into()];
    mgr.accept_and_remember("beta", &newer, "newer-body").unwrap();
    assert!(mgr.accept_and_remember("beta", &old, "older-body").is_err());
    assert_eq!(code(&mgr.verified_entry(&item(), Downloaded)), "withdrawn");
}

/// A fresh process on the same config dir, as after a daemon restart.
fn restarted(dir: &Path, now: i64) -> UpdateManager {
    let mut mgr = manager(dir);
    mgr.set_trusted_keys_for_test(manifest::test_support::trusted_keys_hex(
        &manifest::test_support::test_trusted_keys(),
    ));
    mgr.set_now_for_test(now);
    mgr
}

#[tokio::test]
async fn a_restarted_daemon_answers_from_the_persisted_verified_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let doc = doc_with_build(&manager(dir.path()));
    let _ = verified_manager(Some(&doc), dir.path(), unix_at(NOW)).await;

    let mgr = restarted(dir.path(), unix_at(NOW) + 60);
    let answer = mgr.verified_entry(&item(), Downloaded);
    assert!(answer.verdict.is_ok(), "{:?}", answer.verdict);
    assert_eq!(answer.entry.expect("entry").entry.version, "9.9.9");

    // The age is the original verification's: it does not restart with the daemon.
    let mgr = restarted(dir.path(), unix_at(NOW) + VERIFIED_MAX_AGE_SECS + 1);
    assert_eq!(code(&mgr.verified_entry(&item(), Downloaded)), "stale");
}

#[tokio::test]
async fn a_persisted_manifest_that_no_longer_verifies_or_matches_the_floor_is_not_used() {
    let dir = tempfile::tempdir().unwrap();
    let doc = doc_with_build(&manager(dir.path()));
    let _ = verified_manager(Some(&doc), dir.path(), unix_at(NOW)).await;
    let file = dir.path().join(PERSISTED_VERIFIED_FILE);
    let good = std::fs::read_to_string(&file).unwrap();

    // Different signed bytes than the replay floor accepted.
    let mut record: serde_json::Value = serde_json::from_str(&good).unwrap();
    record["envelope"] = format!("{} ", record["envelope"].as_str().unwrap()).into();
    std::fs::write(&file, record.to_string()).unwrap();
    let mgr = restarted(dir.path(), unix_at(NOW));
    assert_eq!(code(&mgr.verified_entry(&item(), Downloaded)), "not_checked");

    // Damaged file.
    std::fs::write(&file, "not json").unwrap();
    let mgr = restarted(dir.path(), unix_at(NOW));
    assert_eq!(code(&mgr.verified_entry(&item(), Downloaded)), "not_checked");

    // Verified by the production root only: the throwaway test key is not trusted.
    std::fs::write(&file, good).unwrap();
    let mut mgr = restarted(dir.path(), unix_at(NOW));
    mgr.set_trusted_keys_for_test(vec![]);
    assert_eq!(code(&mgr.verified_entry(&item(), Downloaded)), "not_checked");
}

#[tokio::test]
async fn a_channel_without_a_manifest_forgets_the_persisted_one() {
    let dir = tempfile::tempdir().unwrap();
    let doc = doc_with_build(&manager(dir.path()));
    let _ = verified_manager(Some(&doc), dir.path(), unix_at(NOW)).await;
    let file = dir.path().join(PERSISTED_VERIFIED_FILE);
    let stale = std::fs::read_to_string(&file).unwrap();
    let _ = verified_manager(None, dir.path(), unix_at(NOW)).await;
    // Failure injection: the removal of the cache file failed, so the old file is still there.
    std::fs::write(&file, &stale).unwrap();
    let mgr = restarted(dir.path(), unix_at(NOW));
    assert_eq!(code(&mgr.verified_entry(&item(), Downloaded)), "not_checked");

    // The same signed manifest served again is usable again after a restart.
    let _ = verified_manager(Some(&doc), dir.path(), unix_at(NOW)).await;
    let mgr = restarted(dir.path(), unix_at(NOW));
    assert!(mgr.verified_entry(&item(), Downloaded).verdict.is_ok());
}
