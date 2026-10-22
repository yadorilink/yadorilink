#![cfg(test)]

use super::*;

/// `YADORILINK_UPDATE_MANIFEST_URL` is a process-global env var —
/// every test in this module that touches it holds this mutex for
/// its whole body, mirroring `daemon_state.rs`'s own
/// `CONFIG_ENV_MUTEX` precedent for `YADORILINK_CONFIG_DIR`.
static MANIFEST_URL_ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
    let info = PlatformInfo::detect();
    assert!(REFUSED_PROBES.load(std::sync::atomic::Ordering::SeqCst) > before);
    assert_eq!(info.install_source, "standalone");
}

fn manager(config_dir: &Path) -> UpdateManager {
    UpdateManager::new(config_dir, semver::Version::parse("0.1.0").unwrap())
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

    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/manifest.json"))
        // The response body doesn't matter for this test -- an
        // invalid/unsigned body just makes `check_now` return an
        // error, which is fine; only the *request* is under test.
        .respond_with(ResponseTemplate::new(200).set_body_string("not a valid manifest"))
        .mount(&server)
        .await;
    std::env::set_var("YADORILINK_UPDATE_MANIFEST_URL", format!("{}/manifest.json", server.uri()));

    let dir = tempfile::tempdir().unwrap();
    let manager = manager(dir.path());
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

    std::env::remove_var("YADORILINK_UPDATE_MANIFEST_URL");
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
    }
}

async fn serve_envelope_and_check(
    envelope_json: String,
    config_dir: &Path,
) -> Result<Applicability, UpdateError> {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/manifest.json"))
        .respond_with(ResponseTemplate::new(200).set_body_string(envelope_json))
        .mount(&server)
        .await;
    std::env::set_var("YADORILINK_UPDATE_MANIFEST_URL", format!("{}/manifest.json", server.uri()));
    let mut mgr = manager(config_dir);
    mgr.set_trusted_keys_for_test(manifest::test_support::trusted_keys_hex(
        &manifest::test_support::test_trusted_keys(),
    ));
    let result = mgr.check_now().await;
    std::env::remove_var("YADORILINK_UPDATE_MANIFEST_URL");
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
    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let entry = matching_entry(&mgr, "9.9.9", 100, false);
    let doc = manifest::UpdateManifest {
        schema_version: manifest::MANIFEST_SCHEMA_VERSION,
        generated_at: "2026-07-01T00:00:00Z".into(),
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
    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let entry = matching_entry(&mgr, "9.9.9", 0, false);
    let doc = manifest::UpdateManifest {
        schema_version: manifest::MANIFEST_SCHEMA_VERSION,
        generated_at: "2026-07-01T00:00:00Z".into(),
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
    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
    let dir = tempfile::tempdir().unwrap();
    let mgr = manager(dir.path());
    let entry = matching_entry(&mgr, "9.9.9", 100, false);
    let doc = manifest::UpdateManifest {
        schema_version: manifest::MANIFEST_SCHEMA_VERSION,
        generated_at: "2026-07-01T00:00:00Z".into(),
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

    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/manifest.json"))
        .respond_with(ResponseTemplate::new(status))
        .mount(&server)
        .await;
    std::env::set_var("YADORILINK_UPDATE_MANIFEST_URL", format!("{}/manifest.json", server.uri()));
    let mgr = manager(config_dir);
    let result = mgr.check_now().await;
    std::env::remove_var("YADORILINK_UPDATE_MANIFEST_URL");
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

    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
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
    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;

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
    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
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
        let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
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
    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
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
    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
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
    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
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
    std::env::set_var("YADORILINK_UPDATE_MANIFEST_URL", format!("{}/manifest.json", server.uri()));
    let mut mgr = manager(dir);
    mgr.set_trusted_keys_for_test(manifest::test_support::trusted_keys_hex(
        &manifest::test_support::test_trusted_keys(),
    ));
    let result = mgr.check_version(kind, version).await;
    std::env::remove_var("YADORILINK_UPDATE_MANIFEST_URL");
    result
}

#[tokio::test]
async fn a_pinned_install_of_a_killed_version_is_refused_by_the_live_manifest() {
    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
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
    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
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
        std::env::set_var(
            "YADORILINK_UPDATE_MANIFEST_URL",
            format!("{}/manifest.json", server.uri()),
        );
        let mut m = manager(dir.path());
        m.set_trusted_keys_for_test(manifest::test_support::trusted_keys_hex(
            &manifest::test_support::test_trusted_keys(),
        ));
        let r = m.check_version(VersionCheckKind::PinnedInstall, "9.9.9").await;
        std::env::remove_var("YADORILINK_UPDATE_MANIFEST_URL");
        r
    };
    assert!(matches!(unverifiable, Err(VersionCheckError::Unverifiable(_))));
}

#[tokio::test]
async fn an_appcast_item_ahead_of_the_manifest_is_refused() {
    let _guard = MANIFEST_URL_ENV_MUTEX.lock().await;
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
