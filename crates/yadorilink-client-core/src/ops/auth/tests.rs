#![cfg(test)]

use super::*;

/// `login` on a machine that already holds a credential must not quietly
/// enrol a second identity. Re-enrolling mints a new `client_id` and leaves
/// the old one live, so the two would both be authorized and only one of
/// them reachable from this machine.
#[tokio::test]
async fn login_on_an_enrolled_installation_refuses_rather_than_enrolling_twice() {
    let server = step_up_server().await;
    let dir = tempfile::tempdir().expect("temp dir");
    let _guard = crate::coordination::http_client::COORDINATION_ADDR_ENV_LOCK.lock().await;
    std::env::remove_var(crate::coordination::http_client::AUTH_SERVER_ADDR_VAR);
    std::env::set_var("YADORILINK_CREDENTIAL_STORE", "file");
    std::env::set_var("YADORILINK_CREDENTIAL_FILE", dir.path().join("credentials.json"));

    let store = credential_store::open().expect("store");
    let lock = store.lock(std::time::Duration::from_secs(5)).await.expect("lock");
    store
        .save(
            &lock,
            &yadorilink_fapi_client::store::Credentials::new(
                server.uri(),
                "ylk-AAAAAAAAAAAAAAAAAAAAAA",
                Es256Key::generate().to_jwk_json(),
                "rt-1",
            ),
        )
        .expect("save");
    drop(lock);

    let mut events = Vec::new();
    let result =
        login(false, None, &crate::ops::daemon::default_launch(), |event| events.push(event)).await;
    std::env::remove_var("YADORILINK_CREDENTIAL_FILE");
    std::env::remove_var("YADORILINK_CREDENTIAL_STORE");

    let error = result.expect_err("a refusal");
    assert_eq!(error.hint(), Some(Hint::AlreadyEnrolled), "the refusal carries the remedy");
    let CoreError::Hinted { error: inner, .. } = error else { panic!("hinted: {error:?}") };
    let CoreError::AuthFailed(message) = *inner else { panic!("a refusal, got {inner:?}") };
    assert!(message.starts_with("this installation is already enrolled. Re-enrolling mints"));
    assert!(!message.contains("yadorilink "), "client-core names no CLI command: {message}");
    assert!(events.is_empty(), "a refused login reports no progress, got {events:?}");
}

fn tombstone(client_id: &str, first: bool) -> SignOutResponse {
    SignOutResponse { client_id: client_id.to_owned(), first_revocation: first, grants_revoked: 1 }
}

/// The outcome that must never happen: the revocation did not land and the
/// credential was deleted anyway. That is the original bug -- "sign out"
/// meaning local deletion -- with a network call in front of it, and from
/// the terminal it looks identical to success.
#[test]
fn an_unreachable_server_keeps_the_credential_and_says_the_session_is_live() {
    let verdict = sign_out_verdict(
        SignOutAttempt::Failed(CoreError::CoordinationPlaneUnreachable(
            "connection refused".to_owned(),
        )),
        "ylk-AAAAAAAAAAAAAAAAAAAAAA",
    );
    let message = match verdict {
        SignOutVerdict::KeepCredential(CoreError::AuthFailed(message)) => message,
        other => panic!("a failed revocation must keep the credential, got {other:?}"),
    };
    assert!(message.contains("NOT"), "the message must say nothing was removed: {message}");
    assert!(
        message.contains("remove this device from another one"),
        "the message must name the remedy: {message}"
    );
}

/// A server that reports revoking a DIFFERENT installation has not
/// answered the question that was asked, and answering it wrongly here
/// would destroy the only credential able to ask again.
#[test]
fn a_tombstone_naming_another_installation_keeps_the_credential() {
    let verdict = sign_out_verdict(
        SignOutAttempt::Tombstone(tombstone("ylk-SOMEONEELSE", true)),
        "ylk-AAAAAAAAAAAAAAAAAAAAAA",
    );
    assert!(
        matches!(verdict, SignOutVerdict::KeepCredential(_)),
        "a mismatched tombstone must not clear the store, got {verdict:?}"
    );
}

/// The confirmed revocation, and the 401 whose independent confirmation
/// came back `Revoked`. Both are established revocations, so both earn
/// the local clear.
#[test]
fn a_confirmed_tombstone_or_an_independently_confirmed_revocation_clears_the_store() {
    let us = "ylk-AAAAAAAAAAAAAAAAAAAAAA";
    assert!(matches!(
        sign_out_verdict(SignOutAttempt::Tombstone(tombstone(us, true)), us),
        SignOutVerdict::Clear(SignOutKind::Revoked { grants_revoked: 1 })
    ));
    assert!(matches!(
        sign_out_verdict(SignOutAttempt::Tombstone(tombstone(us, false)), us),
        SignOutVerdict::Clear(SignOutKind::AlreadyRevoked)
    ));
    assert!(matches!(
        sign_out_verdict(
            SignOutAttempt::Denied401 {
                detail: "token not found".to_owned(),
                confirmed: Confirmed::Revoked,
            },
            us,
        ),
        SignOutVerdict::Clear(SignOutKind::ConfirmedRevokedAfterRejection)
    ));
}

/// THE FIX'S OWN TEST. A 401 alone used to be treated as proof of
/// revocation; it no longer is. When the independent check comes back
/// `Alive` -- the Authorization Server just issued this installation a
/// fresh token -- the credential must be kept, because deleting it would
/// be exactly the "revocation failed and the credential was deleted
/// anyway" bug this whole module exists to avoid, one layer further down.
#[test]
fn a_401_that_is_independently_confirmed_alive_keeps_the_credential() {
    let us = "ylk-AAAAAAAAAAAAAAAAAAAAAA";
    let verdict = sign_out_verdict(
        SignOutAttempt::Denied401 {
            detail: "invalid_dpop_proof".to_owned(),
            confirmed: Confirmed::Alive,
        },
        us,
    );
    let message = match verdict {
        SignOutVerdict::KeepCredential(CoreError::AuthFailed(message)) => message,
        other => panic!("a live registration must keep the credential, got {other:?}"),
    };
    assert!(message.contains("NOT"), "the message must say nothing was removed: {message}");
    assert!(
        message.contains("confirmed still active"),
        "the message must say why this is not treated as a revocation: {message}"
    );
}

/// A 401 that could not be confirmed either way -- the refresh itself hit
/// a transport error -- must not default to either outcome. Guessing
/// `Revoked` risks the original bug; guessing `Alive` would block a
/// legitimate sign-out on a flaky network forever.
#[test]
fn a_401_that_cannot_be_confirmed_either_way_keeps_the_credential() {
    let us = "ylk-AAAAAAAAAAAAAAAAAAAAAA";
    let verdict = sign_out_verdict(
        SignOutAttempt::Denied401 {
            detail: "token not found".to_owned(),
            confirmed: Confirmed::Unknown("connection refused".to_owned()),
        },
        us,
    );
    assert!(
        matches!(verdict, SignOutVerdict::KeepCredential(_)),
        "an unconfirmed 401 must not clear the store, got {verdict:?}"
    );
}

/// `forget-local-credentials` on a machine with no credential is
/// `NotLoggedIn` too -- it is a different operation from sign-out, not a
/// weaker version of it, but it has the same precondition.
#[tokio::test]
async fn forgetting_local_credentials_with_nothing_stored_reports_not_logged_in() {
    let dir = tempfile::tempdir().expect("temp dir");
    let _guard = crate::coordination::http_client::COORDINATION_ADDR_ENV_LOCK.lock().await;
    std::env::set_var("YADORILINK_CREDENTIAL_STORE", "file");
    std::env::set_var("YADORILINK_CREDENTIAL_FILE", dir.path().join("credentials.json"));
    let result = forget_local_credentials().await;
    std::env::remove_var("YADORILINK_CREDENTIAL_FILE");
    std::env::remove_var("YADORILINK_CREDENTIAL_STORE");

    assert!(matches!(result, Err(CoreError::NotLoggedIn)), "expected NotLoggedIn, got {result:?}");
}

/// Signing out on a machine with no credential is `NotLoggedIn`, not a
/// cheerful no-op. The pre-cutover version read a legacy refresh token and
/// reported the same thing; the shape survives, the credential it reads
/// does not.
#[tokio::test]
async fn logout_with_nothing_stored_reports_not_logged_in() {
    let dir = tempfile::tempdir().expect("temp dir");
    let _guard = crate::coordination::http_client::COORDINATION_ADDR_ENV_LOCK.lock().await;
    std::env::set_var("YADORILINK_CREDENTIAL_STORE", "file");
    std::env::set_var("YADORILINK_CREDENTIAL_FILE", dir.path().join("credentials.json"));
    let result = sign_out().await;
    std::env::remove_var("YADORILINK_CREDENTIAL_FILE");
    std::env::remove_var("YADORILINK_CREDENTIAL_STORE");

    assert!(matches!(result, Err(CoreError::NotLoggedIn)), "expected NotLoggedIn, got {result:?}");
}

/// The full refusal text for a sign-out that could not reach the server,
/// pinned because every front end shows it verbatim.
#[test]
fn an_unreachable_server_refusal_is_pinned_verbatim() {
    let verdict = sign_out_verdict(
        SignOutAttempt::Failed(CoreError::CoordinationPlaneUnreachable(
            "connection refused".to_owned(),
        )),
        "ylk-AAAAAAAAAAAAAAAAAAAAAA",
    );
    let SignOutVerdict::KeepCredential(error) = verdict else {
        panic!("a failed revocation must keep the credential");
    };
    assert_eq!(
        error.to_string(),
        "authentication failed: could not revoke this computer's access (could not reach the \
         coordination plane: connection refused). Your credentials were NOT removed, because \
         deleting them would leave this computer signed in on the server with no way to sign it \
         out from here. Try again when you are online, or remove this device from another one."
    );
}

mod device_key_mirrors {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    use yadorilink_transport::{KeyringDelete, TransportError};

    use super::super::delete_device_key_mirrors_in;

    fn fake<'a>(
        refuse: Option<&'static str>,
        seen: &'a RefCell<Vec<PathBuf>>,
    ) -> impl Fn(&Path) -> Result<KeyringDelete, TransportError> + 'a {
        move |path| {
            seen.borrow_mut().push(path.to_path_buf());
            match refuse {
                Some(name) if path.to_string_lossy().contains(name) => {
                    Err(TransportError::Io(std::io::Error::other("keyring locked")))
                }
                _ => Ok(KeyringDelete::NotFound),
            }
        }
    }

    pub(super) fn delete_in_with_ok(dir: &Path, seen: &RefCell<Vec<PathBuf>>) -> Option<String> {
        delete_device_key_mirrors_in(dir, &fake(None, seen))
    }

    #[test]
    fn the_live_and_every_retired_key_copy_is_deleted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("retired-devices/dev-1")).unwrap();
        let seen = RefCell::new(Vec::new());
        assert_eq!(delete_device_key_mirrors_in(dir.path(), &fake(None, &seen)), None);
        let seen = seen.into_inner();
        assert!(seen.contains(&dir.path().join("signing_key")));
        assert!(seen.contains(&dir.path().join("retired-devices/dev-1/signing_key")));
    }

    #[test]
    fn a_failed_delete_becomes_a_warning_naming_the_way_to_finish() {
        let dir = tempfile::tempdir().unwrap();
        let seen = RefCell::new(Vec::new());
        let warning =
            delete_device_key_mirrors_in(dir.path(), &fake(Some("signing_key"), &seen)).unwrap();
        assert!(warning.contains("keyring locked"), "{warning}");
        assert!(!warning.contains("yadorilink "), "client-core names no CLI command: {warning}");
        assert!(
            warning.starts_with("the device key's copy in the OS credential store could not be removed and may still be there: ")
                && warning.ends_with("keyring locked"),
            "{warning}"
        );
    }
}

#[test]
fn an_unreadable_retired_directory_is_reported_not_skipped() {
    let dir = tempfile::tempdir().unwrap();
    // A file where the directory should be: listing it fails with something other than NotFound.
    std::fs::write(dir.path().join("retired-devices"), b"x").unwrap();
    let seen = std::cell::RefCell::new(Vec::new());
    let warning = device_key_mirrors::delete_in_with_ok(dir.path(), &seen);
    assert!(warning.unwrap().contains("retired-devices"));
}

#[test]
fn a_superseded_401_is_a_denial_to_confirm_like_any_other_401() {
    let detail = denied_401_detail(CoreError::DeviceSuperseded).expect("a denial");
    assert!(detail.contains("replaced"), "{detail}");
    assert!(denied_401_detail(CoreError::AuthFailed("x".into())).is_ok());
    assert!(denied_401_detail(CoreError::Forbidden("x".into())).is_err());

    let verdict =
        sign_out_verdict(SignOutAttempt::Denied401 { detail, confirmed: Confirmed::Revoked }, "us");
    assert!(matches!(verdict, SignOutVerdict::Clear(SignOutKind::ConfirmedRevokedAfterRejection)));
}

#[test]
fn account_deletion_clears_the_credential_only_on_account_level_evidence() {
    let denied = |confirmed, account_deleted| DeletionProbe::Denied401 {
        detail: "gone".into(),
        confirmed,
        account_deleted,
    };
    assert!(deletion_completion_verdict(denied(Confirmed::Revoked, Some(true))).is_ok());

    // Registration revoked (a sign-out elsewhere) while the account is active: keep.
    assert!(matches!(
        deletion_completion_verdict(denied(Confirmed::Revoked, Some(false))),
        Err(CoreError::InvalidInput(_))
    ));
    // The server could not be asked about the account: keep.
    assert!(deletion_completion_verdict(denied(Confirmed::Revoked, None)).is_err());

    // In the grace period the account still answers: keep.
    assert!(matches!(
        deletion_completion_verdict(DeletionProbe::StillExists),
        Err(CoreError::InvalidInput(_))
    ));
    assert!(deletion_completion_verdict(denied(Confirmed::Alive, None)).is_err());
    assert!(
        deletion_completion_verdict(denied(Confirmed::Unknown("offline".into()), None)).is_err()
    );
    assert!(
        deletion_completion_verdict(DeletionProbe::Failed(CoreError::Other("x".into()))).is_err()
    );
}

/// A step-up is a login by an existing registration: with nothing enrolled
/// there is nobody to sign in again, and it must not enrol anyone.
#[tokio::test]
async fn reauthenticating_with_nothing_enrolled_reports_not_logged_in_and_enrols_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let _guard = crate::coordination::http_client::COORDINATION_ADDR_ENV_LOCK.lock().await;
    std::env::set_var("YADORILINK_CREDENTIAL_STORE", "file");
    std::env::set_var("YADORILINK_CREDENTIAL_FILE", dir.path().join("credentials.json"));

    let mut events = Vec::new();
    let result = reauthenticate(false, |event| events.push(event)).await;
    let stored = credential_store::installation();
    std::env::remove_var("YADORILINK_CREDENTIAL_FILE");
    std::env::remove_var("YADORILINK_CREDENTIAL_STORE");

    assert!(matches!(result, Err(CoreError::NotLoggedIn)), "{result:?}");
    assert!(events.is_empty());
    assert!(stored.expect("store").is_none());
}

/// An Authorization Server that serves the device-code step-up.
async fn step_up_server() -> wiremock::MockServer {
    step_up_server_claiming(None).await
}

/// As [`step_up_server`], reporting `claimed_issuer` as its issuer when given (its endpoints
/// stay at its own address).
async fn step_up_server_claiming(claimed_issuer: Option<&str>) -> wiremock::MockServer {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    let own = server.uri();
    let issuer = claimed_issuer.map_or_else(|| own.clone(), str::to_owned);
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/auth"),
            "token_endpoint": format!("{issuer}/token"),
            "pushed_authorization_request_endpoint": format!("{issuer}/request"),
            "userinfo_endpoint": format!("{issuer}/me"),
            "registration_endpoint": format!("{issuer}/reg"),
            "device_authorization_endpoint": format!("{issuer}/device/auth"),
            "require_pushed_authorization_requests": true,
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["private_key_jwt"],
            "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
            "dpop_signing_alg_values_supported": ["ES256"],
            "grant_types_supported": [
                "authorization_code", "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code"
            ],
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/device/auth"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code": "dc-1", "user_code": "BCDF-GHJK-LMNP",
            "verification_uri": format!("{issuer}/device"), "expires_in": 600, "interval": 1,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "at-up", "token_type": "DPoP", "expires_in": 300,
            "refresh_token": "rt-up", "scope": "openid offline_access",
        })))
        .mount(&server)
        .await;
    server
}

/// The step-up discovers OAuth endpoints at the Authorization Server named by
/// the stored issuer, not at the coordination API address.
#[tokio::test]
async fn reauthenticating_talks_to_the_authorization_server_not_the_coordination_address() {
    let server = step_up_server().await;
    let issuer = server.uri();

    let dir = tempfile::tempdir().expect("temp dir");
    let _guard = crate::coordination::http_client::COORDINATION_ADDR_ENV_LOCK.lock().await;
    std::env::set_var("YADORILINK_CREDENTIAL_STORE", "file");
    std::env::set_var("YADORILINK_CREDENTIAL_FILE", dir.path().join("credentials.json"));
    // A different, unreachable address for the coordination API.
    std::env::set_var("YADORILINK_COORDINATION_ADDR", "http://127.0.0.1:1");
    std::env::remove_var(crate::coordination::http_client::AUTH_SERVER_ADDR_VAR);

    let store = credential_store::open().expect("store");
    let key_jwk = Es256Key::generate().to_jwk_json();
    let lock = store.lock(std::time::Duration::from_secs(5)).await.expect("lock");
    store
        .save(
            &lock,
            &yadorilink_fapi_client::store::Credentials::new(
                issuer.clone(),
                "ylk-AAAAAAAAAAAAAAAAAAAAAA",
                key_jwk.clone(),
                "rt-original",
            ),
        )
        .expect("save");
    drop(lock);

    let mut events = Vec::new();
    let result = reauthenticate(true, |event| events.push(event)).await;
    let after = credential_store::installation();
    for var in [
        "YADORILINK_CREDENTIAL_FILE",
        "YADORILINK_CREDENTIAL_STORE",
        "YADORILINK_COORDINATION_ADDR",
    ] {
        std::env::remove_var(var);
    }

    result.expect("the step-up must reach the authorization server");
    let after = after.expect("store").expect("still enrolled");
    assert_eq!(after.client_id(), "ylk-AAAAAAAAAAAAAAAAAAAAAA");
    assert_eq!(after.issuer(), issuer);
    assert_eq!(after.client_key_jwk(), key_jwk);
    assert_eq!(after.refresh_token(), "rt-up");
    assert!(matches!(events.last(), Some(LoginEvent::SignedIn { .. })), "{events:?}");
}

/// The step-up over a named state directory uses the host's settings and leaves the process
/// environment out of it: the credential file and the Authorization Server come from the
/// arguments (the process's own credential variables are not set).
#[tokio::test]
async fn reauthenticating_in_a_directory_uses_the_hosts_settings() {
    // The stored issuer names a host nothing listens on; the settings name the live
    // Authorization Server, which reports that issuer. Only dialing the settings' address
    // reaches it.
    let stored_issuer = "https://issuer.example.test".to_owned();
    let server = step_up_server_claiming(Some(&stored_issuer)).await;
    let override_addr = server.uri();
    assert_ne!(override_addr, stored_issuer);
    let dir = tempfile::tempdir().expect("temp dir");
    let settings = credential_store::CredentialSettings {
        backend: yadorilink_fapi_client::store::Backend::File(dir.path().join("credentials.json")),
        key_mirror: yadorilink_transport::KeyMirror::Disabled,
        auth_server_addr: Some(override_addr),
        coordination_addr: None,
        host_name: None,
    };
    let store = credential_store::open_in(dir.path(), &settings).expect("store");
    let key_jwk = Es256Key::generate().to_jwk_json();
    let lock = store.lock(std::time::Duration::from_secs(5)).await.expect("lock");
    store
        .save(
            &lock,
            &yadorilink_fapi_client::store::Credentials::new(
                stored_issuer,
                "ylk-AAAAAAAAAAAAAAAAAAAAAA",
                key_jwk,
                "rt-original",
            ),
        )
        .expect("save");
    drop(lock);

    let mut events = Vec::new();
    reauthenticate_in(dir.path(), &settings, true, |event| events.push(event))
        .await
        .expect("the step-up must reach the configured authorization server");
    let after = credential_store::installation_in(dir.path(), &settings)
        .expect("store")
        .expect("still enrolled");
    assert_eq!(after.refresh_token(), "rt-up");
    assert!(matches!(events.last(), Some(LoginEvent::SignedIn { .. })), "{events:?}");
}

/// Every host differs, so a purpose that read the wrong source cannot pass by coincidence.
const COORDINATION: &str = "https://Coord.Example.test:8443/api";

fn save_issuer(dir: &std::path::Path, settings: &credential_store::CredentialSettings) {
    let store = credential_store::open_in(dir, settings).expect("store");
    let runtime = tokio::runtime::Builder::new_current_thread().build().expect("runtime");
    runtime.block_on(async {
        let lock = store.lock(std::time::Duration::from_secs(5)).await.expect("lock");
        store
            .save(
                &lock,
                &yadorilink_fapi_client::store::Credentials::new(
                    "https://issuer.example.test",
                    "ylk-AAAAAAAAAAAAAAAAAAAAAA",
                    Es256Key::generate().to_jwk_json(),
                    "rt",
                ),
            )
            .expect("save");
    });
}

#[test]
fn the_trusted_sign_in_origins_are_per_purpose_and_differ_when_the_servers_do() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut settings = credential_store::CredentialSettings {
        backend: yadorilink_fapi_client::store::Backend::File(dir.path().join("credentials.json")),
        key_mirror: yadorilink_transport::KeyMirror::Disabled,
        auth_server_addr: Some("https://Auth.Example.test:9443/x".to_owned()),
        coordination_addr: None,
        host_name: None,
    };
    let origins = |settings: &credential_store::CredentialSettings| {
        let origins =
            trusted_sign_in_origins_for(dir.path(), settings, COORDINATION).expect("origins");
        (origins.approve_device, origins.authorization)
    };
    let pair = |approve: &str, authorization: &str| {
        (Some(approve.to_owned()), Some(authorization.to_owned()))
    };

    // Fresh with a separate Authorization Server: the approval page is the coordination
    // service's (enrolment is dialed there), every OAuth page the server's; ports count.
    assert_eq!(
        origins(&settings),
        pair("https://coord.example.test:8443", "https://auth.example.test:9443")
    );

    // Fresh without one: discovery runs against the coordination service, so both are it.
    settings.auth_server_addr = None;
    assert_eq!(
        origins(&settings),
        pair("https://coord.example.test:8443", "https://coord.example.test:8443")
    );

    // Signed in (re-authentication): OAuth pages are where the stored issuer says; with a
    // configured server that one wins over the issuer.
    save_issuer(dir.path(), &settings);
    assert_eq!(
        origins(&settings),
        pair("https://coord.example.test:8443", "https://issuer.example.test")
    );
    settings.auth_server_addr = Some("https://auth.example.test".to_owned());
    assert_eq!(
        origins(&settings),
        pair("https://coord.example.test:8443", "https://auth.example.test")
    );

    // An address with no origin is no origin: nothing is trusted for that purpose.
    let none = trusted_sign_in_origins_for(dir.path(), &settings, "not a url").expect("origins");
    assert_eq!(none.approve_device, None);
    assert_eq!(none.authorization.as_deref(), Some("https://auth.example.test"));
}

#[test]
fn an_unreadable_credential_store_is_an_error_not_the_coordination_fallback() {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("credentials.json");
    std::fs::write(&path, b"{ this is not a credential store").expect("write");
    let settings = credential_store::CredentialSettings {
        backend: yadorilink_fapi_client::store::Backend::File(path),
        key_mirror: yadorilink_transport::KeyMirror::Disabled,
        auth_server_addr: None,
        coordination_addr: None,
        host_name: None,
    };
    assert!(trusted_sign_in_origins_for(dir.path(), &settings, COORDINATION).is_err());
}

async fn enrolled_in(
    dir: &std::path::Path,
    issuer: &str,
) -> (credential_store::CredentialSettings, String) {
    let settings = credential_store::CredentialSettings {
        backend: yadorilink_fapi_client::store::Backend::File(dir.join("credentials.json")),
        key_mirror: yadorilink_transport::KeyMirror::Disabled,
        auth_server_addr: Some(issuer.to_owned()),
        coordination_addr: None,
        host_name: None,
    };
    let store = credential_store::open_in(dir, &settings).expect("store");
    let key_jwk = Es256Key::generate().to_jwk_json();
    let lock = store.lock(std::time::Duration::from_secs(5)).await.expect("lock");
    store
        .save(
            &lock,
            &yadorilink_fapi_client::store::Credentials::new(
                issuer,
                "ylk-AAAAAAAAAAAAAAAAAAAAAA",
                key_jwk.clone(),
                "rt-original",
            ),
        )
        .expect("save");
    drop(lock);
    (settings, key_jwk)
}

/// After a change of the Terms the server refuses every refresh with `invalid_grant`. `login` on
/// the enrolled installation then signs in again AS THE SAME INSTALLATION (identity, key and
/// device kept) instead of telling the person to sign out, which would revoke it.
#[tokio::test]
async fn login_on_an_installation_whose_refresh_is_refused_signs_in_again_as_itself() {
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, ResponseTemplate};
    let server = step_up_server().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(
            ResponseTemplate::new(400).set_body_json(serde_json::json!({"error": "invalid_grant"})),
        )
        .with_priority(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().expect("temp dir");
    let (settings, key_jwk) = enrolled_in(dir.path(), &server.uri()).await;

    let mut events = Vec::new();
    login_in(dir.path(), &settings, true, |e| events.push(e))
        .await
        .expect("a refused refresh is answered by signing in again");

    let after = credential_store::installation_in(dir.path(), &settings)
        .expect("store")
        .expect("still enrolled");
    assert_eq!(after.client_id(), "ylk-AAAAAAAAAAAAAAAAAAAAAA", "no new identity was enrolled");
    assert_eq!(after.client_key_jwk(), key_jwk);
    assert_eq!(after.refresh_token(), "rt-up");
    assert!(matches!(events.last(), Some(LoginEvent::SignedIn { .. })), "{events:?}");
}

/// A session that still refreshes is not "signed out": `login` keeps refusing to enrol twice.
#[tokio::test]
async fn login_on_a_working_installation_still_refuses() {
    let server = step_up_server().await;
    let dir = tempfile::tempdir().expect("temp dir");
    let (settings, _) = enrolled_in(dir.path(), &server.uri()).await;
    let error = login_in(dir.path(), &settings, true, |_| {}).await.expect_err("a refusal");
    assert_eq!(error.hint(), Some(Hint::AlreadyEnrolled));
}

/// A server that cannot be asked is not "already enrolled": the person keeps the real reason and
/// is not pointed at signing out. Discovery succeeds here, so the refresh itself is what fails.
#[tokio::test]
async fn login_on_an_enrolled_installation_whose_refresh_cannot_be_answered_reports_that() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    for status in [429u16, 503] {
        let server = step_up_server().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(status))
            .with_priority(1)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().expect("temp dir");
        let (settings, _) = enrolled_in(dir.path(), &server.uri()).await;
        let error = login_in(dir.path(), &settings, true, |_| {}).await.expect_err("an error");
        assert!(matches!(error, CoreError::CoordinationPlaneUnreachable(_)), "{status}: {error:?}");
    }
}

/// The same when the token endpoint cannot be reached at all after a successful discovery.
#[tokio::test]
async fn login_on_an_enrolled_installation_whose_token_endpoint_is_down_reports_that() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let issuer = format!("http://{addr}");
    let discovery = serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/auth"),
        "token_endpoint": format!("{issuer}/token"),
        "pushed_authorization_request_endpoint": format!("{issuer}/request"),
        "userinfo_endpoint": format!("{issuer}/me"),
        "registration_endpoint": format!("{issuer}/reg"),
        "require_pushed_authorization_requests": true,
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
    })
    .to_string();
    tokio::spawn(async move {
        // Answers the discovery request, then every other connection is dropped unanswered.
        let mut served = false;
        while let Ok((mut stream, _)) = listener.accept().await {
            if served {
                drop(stream);
                continue;
            }
            served = true;
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{discovery}",
                discovery.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });
    let dir = tempfile::tempdir().expect("temp dir");
    let (settings, _) = enrolled_in(dir.path(), &issuer).await;
    let error = login_in(dir.path(), &settings, true, |_| {}).await.expect_err("an error");
    assert!(matches!(error, CoreError::CoordinationPlaneUnreachable(_)), "{error:?}");
}

// ---- sign-in with a pairing code ------------------------------------------------------------

mod pairing {
    use std::sync::{Arc, Mutex};

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::*;
    use crate::error::DesktopError;

    const CLIENT_ID: &str = "ylk-PAIREDPAIREDPAIREDAA";

    /// What the mock service saw, for the assertions.
    #[derive(Default)]
    struct Seen {
        start_bodies: Vec<serde_json::Value>,
        par_state: Option<String>,
        par_redirect: Option<String>,
        register_bodies: Vec<serde_json::Value>,
    }

    /// Where the resumed authorization request ends.
    #[derive(Clone, Copy)]
    enum Ends {
        /// At the registered redirect URI, with the pushed state.
        Redirect,
        /// At the identity provider: the pairing handoff ran out.
        IdentityProvider,
        /// At the registered redirect URI with another login's state.
        WrongState,
    }

    /// A service that answers the pairing flow end to end: discovery, `/bootstrap/start` and
    /// `/bootstrap/poll`, the pushed request, an authorization endpoint that redirects through
    /// an interaction page which only answers a request carrying its cookie, and the token
    /// endpoint.
    async fn service(start: ResponseTemplate, ends: Ends) -> (MockServer, Arc<Mutex<Seen>>) {
        let server = MockServer::start().await;
        let issuer = server.uri();
        let seen = Arc::new(Mutex::new(Seen::default()));

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/auth"),
                "token_endpoint": format!("{issuer}/token"),
                "pushed_authorization_request_endpoint": format!("{issuer}/request"),
                "require_pushed_authorization_requests": true,
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["private_key_jwt"],
                "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
                "dpop_signing_alg_values_supported": ["ES256"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
            })))
            .mount(&server)
            .await;

        let recorder = seen.clone();
        Mock::given(method("POST"))
            .and(path("/bootstrap/start"))
            .respond_with(move |request: &Request| {
                recorder
                    .lock()
                    .expect("lock")
                    .start_bodies
                    .push(request.body_json().expect("JSON"));
                start.clone()
            })
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/bootstrap/poll"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "client_id": CLIENT_ID })),
            )
            .mount(&server)
            .await;

        let recorder = seen.clone();
        Mock::given(method("POST"))
            .and(path("/request"))
            .respond_with(move |request: &Request| {
                let form: std::collections::HashMap<String, String> =
                    url::form_urlencoded::parse(&request.body).into_owned().collect();
                let mut seen = recorder.lock().expect("lock");
                seen.par_state = form.get("state").cloned();
                seen.par_redirect = form.get("redirect_uri").cloned();
                ResponseTemplate::new(201).set_body_json(
                    serde_json::json!({ "request_uri": "urn:par:1", "expires_in": 60 }),
                )
            })
            .mount(&server)
            .await;

        // authorize -> interaction (cookie set) -> resume (cookie required) -> the end.
        Mock::given(method("GET"))
            .and(path("/auth"))
            .respond_with(
                ResponseTemplate::new(303)
                    .insert_header("location", format!("{issuer}/interaction/u1").as_str())
                    .insert_header("set-cookie", "_interaction=abc; path=/interaction; httponly"),
            )
            .mount(&server)
            .await;
        let target = issuer.clone();
        Mock::given(method("GET"))
            .and(path("/interaction/u1"))
            .respond_with(move |request: &Request| {
                if request.headers.get("cookie").and_then(|c| c.to_str().ok())
                    == Some("_interaction=abc")
                {
                    ResponseTemplate::new(303)
                        .insert_header("location", format!("{target}/resume").as_str())
                } else {
                    ResponseTemplate::new(400)
                }
            })
            .mount(&server)
            .await;
        let recorder = seen.clone();
        let issuer_for_end = issuer.clone();
        Mock::given(method("GET"))
            .and(path("/resume"))
            .respond_with(move |_: &Request| {
                let seen = recorder.lock().expect("lock");
                let redirect = seen.par_redirect.clone().expect("a pushed request came first");
                let state = seen.par_state.clone().expect("a state");
                let location = match ends {
                    Ends::Redirect => format!(
                        "{redirect}?code=the-code&state={state}&iss={}",
                        url::form_urlencoded::byte_serialize(issuer_for_end.as_bytes())
                            .collect::<String>()
                    ),
                    Ends::WrongState => format!(
                        "{redirect}?code=the-code&state=another&iss={}",
                        url::form_urlencoded::byte_serialize(issuer_for_end.as_bytes())
                            .collect::<String>()
                    ),
                    Ends::IdentityProvider => {
                        "https://accounts.google.com/o/oauth2/v2/auth?state=secret".to_owned()
                    }
                };
                ResponseTemplate::new(303).insert_header("location", location.as_str())
            })
            .mount(&server)
            .await;

        // The server rotates the refresh token on every refresh, as the real one does.
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(|request: &Request| {
                let refreshing = url::form_urlencoded::parse(&request.body)
                    .any(|(k, v)| k == "grant_type" && v == "refresh_token");
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "access_token": "at-paired", "token_type": "DPoP", "expires_in": 300,
                    "refresh_token": if refreshing { "rt-rotated" } else { "rt-paired" },
                    "scope": "openid offline_access",
                }))
            })
            .mount(&server)
            .await;
        // The device registration that ends every first sign-in.
        let recorder = seen.clone();
        Mock::given(method("POST"))
            .and(path("/devices/register"))
            .respond_with(move |request: &Request| {
                recorder
                    .lock()
                    .expect("lock")
                    .register_bodies
                    .push(request.body_json().expect("JSON"));
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "deviceId": "dev-paired" }))
            })
            .mount(&server)
            .await;
        (server, seen)
    }

    fn started() -> ResponseTemplate {
        ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "bootstrap_handle": "h".repeat(64), "expires_in": 600, "poll_interval_seconds": 5,
        }))
    }

    fn settings_for(
        dir: &std::path::Path,
        server: &MockServer,
    ) -> credential_store::CredentialSettings {
        credential_store::CredentialSettings {
            backend: yadorilink_fapi_client::store::Backend::File(dir.join("credentials.json")),
            key_mirror: yadorilink_transport::KeyMirror::Disabled,
            auth_server_addr: None,
            coordination_addr: Some(server.uri()),
            host_name: Some("nas".to_owned()),
        }
    }

    fn code() -> PairingCode {
        PairingCode::parse("bcdf ghjk lmnp").expect("a code")
    }

    #[tokio::test]
    async fn a_code_enrols_and_signs_in_with_no_browser_and_two_events() {
        let (server, seen) = service(started(), Ends::Redirect).await;
        let dir = tempfile::tempdir().expect("dir");
        let settings = settings_for(dir.path(), &server);

        let mut events = Vec::new();
        login_with_pairing_code_in(dir.path(), &settings, code(), |e| events.push(e))
            .await
            .expect("signed in");

        assert_eq!(
            events,
            vec![
                LoginEvent::Enrolling,
                LoginEvent::SignedIn { client_id: CLIENT_ID.to_owned() },
                LoginEvent::DeviceRegistered { device_name: "nas".to_owned() },
            ]
        );
        // Signing in ends with the device registered and its identity on disk.
        let device = crate::coordination::device_config::load_in(dir.path()).expect("device.json");
        assert_eq!(device.device_id, "dev-paired");
        let stored = credential_store::installation_in(dir.path(), &settings)
            .expect("store")
            .expect("enrolled");
        assert_eq!(stored.client_id(), CLIENT_ID);
        // Registering refreshed the session once; the server rotated the token.
        assert_eq!(stored.refresh_token(), "rt-rotated");
        assert_eq!(stored.issuer(), server.uri());
        let seen = seen.lock().expect("lock");
        assert_eq!(seen.register_bodies.len(), 1);
        assert_eq!(seen.register_bodies[0]["deviceName"], "nas");
        assert_eq!(seen.start_bodies.len(), 1);
        assert_eq!(seen.start_bodies[0]["pairing_code"], "BCDFGHJKLMNP");
    }

    #[tokio::test]
    async fn a_refused_code_is_the_typed_refusal_and_stores_nothing() {
        let refused = ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant", "error_description": "the pairing code is invalid or has expired",
        }));
        let (server, _) = service(refused, Ends::Redirect).await;
        let dir = tempfile::tempdir().expect("dir");
        let settings = settings_for(dir.path(), &server);

        let mut events = Vec::new();
        let error = login_with_pairing_code_in(dir.path(), &settings, code(), |e| events.push(e))
            .await
            .expect_err("refused");

        assert!(matches!(error, CoreError::PairingCodeRefused), "{error:?}");
        assert_eq!(
            error.to_string(),
            "The code is invalid, expired or already used: create a new code on the web page"
        );
        assert!(!error.to_string().contains("BCDF"));
        assert!(credential_store::installation_in(dir.path(), &settings).expect("store").is_none());
        assert_eq!(events, vec![LoginEvent::Enrolling]);
        let desktop = DesktopError::from(error);
        assert!(matches!(
            desktop,
            DesktopError::Refused { reason: crate::error::RefusalReason::PairingCodeInvalid, .. }
        ));
    }

    #[tokio::test]
    async fn the_abuse_budget_is_a_rate_limit_that_names_the_wait() {
        let limited = ResponseTemplate::new(429)
            .insert_header("retry-after", "42")
            .set_body_json(serde_json::json!({ "error": "rate_limited" }));
        let (server, _) = service(limited, Ends::Redirect).await;
        let dir = tempfile::tempdir().expect("dir");
        let settings = settings_for(dir.path(), &server);

        let error = login_with_pairing_code_in(dir.path(), &settings, code(), |_| {})
            .await
            .expect_err("limited");

        let CoreError::LimitExceeded {
            message,
            kind: crate::error::LimitKind::RateLimited { retry_after_secs: Some(42) },
        } = &error
        else {
            panic!("a rate limit, got {error:?}")
        };
        assert!(message.contains("42 seconds"), "{message}");
        assert!(matches!(
            DesktopError::from(error),
            DesktopError::Network {
                kind: crate::error::NetworkErrorKind::RateLimited { retry_after_secs: Some(42) },
                ..
            }
        ));
    }

    #[tokio::test]
    async fn a_handoff_that_ran_out_sends_the_sign_in_to_the_identity_provider_and_writes_nothing()
    {
        let (server, _) = service(started(), Ends::IdentityProvider).await;
        let dir = tempfile::tempdir().expect("dir");
        let settings = settings_for(dir.path(), &server);

        let error = login_with_pairing_code_in(dir.path(), &settings, code(), |_| {})
            .await
            .expect_err("needs a browser");

        let CoreError::AuthFailed(message) = &error else { panic!("{error:?}") };
        assert!(message.contains("create a new code"), "{message}");
        assert!(message.contains("accounts.google.com"), "{message}");
        assert!(!message.contains("secret"), "the address' state must not be reported: {message}");
        assert!(credential_store::installation_in(dir.path(), &settings).expect("store").is_none());
    }

    #[tokio::test]
    async fn a_redirect_with_another_logins_state_is_refused() {
        let (server, _) = service(started(), Ends::WrongState).await;
        let dir = tempfile::tempdir().expect("dir");
        let settings = settings_for(dir.path(), &server);

        let error = login_with_pairing_code_in(dir.path(), &settings, code(), |_| {})
            .await
            .expect_err("state mismatch");

        assert!(matches!(error, CoreError::AuthFailed(_)), "{error:?}");
        assert!(credential_store::installation_in(dir.path(), &settings).expect("store").is_none());
    }

    #[tokio::test]
    async fn an_enrolled_installation_refuses_before_the_code_is_sent() {
        let (server, seen) = service(started(), Ends::Redirect).await;
        let dir = tempfile::tempdir().expect("dir");
        let settings = settings_for(dir.path(), &server);
        login_with_pairing_code_in(dir.path(), &settings, code(), |_| {}).await.expect("first");

        let error = login_with_pairing_code_in(dir.path(), &settings, code(), |_| {})
            .await
            .expect_err("already enrolled");

        assert_eq!(error.hint(), Some(Hint::AlreadyEnrolled));
        assert_eq!(
            seen.lock().expect("lock").start_bodies.len(),
            1,
            "the second code was not sent"
        );
    }
}

/// The registration that ends a first sign-in is skipped when the directory already holds a
/// device: signing in again must not mint a second identity.
#[tokio::test]
async fn a_sign_in_over_an_existing_device_registers_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let settings = credential_store::CredentialSettings::from_env(dir.path()).expect("settings");
    crate::coordination::device_config::save_in(
        dir.path(),
        &crate::coordination::device_config::DeviceConfig {
            device_id: "dev-1".to_owned(),
            coordination_addr: settings.coordination_addr(),
            signing_public_key: "k".to_owned(),
            config_version: crate::coordination::device_config::CONFIG_VERSION,
        },
    )
    .expect("device.json");
    let mut events = Vec::new();
    register_this_device(dir.path(), &settings, &mut |event| events.push(event))
        .await
        .expect("nothing to register");
    assert!(events.is_empty(), "no device was registered: {events:?}");
}

/// A `device.json` that cannot be read is not "no device": registering over it would create a
/// second identity, so the sign-in's last step reports the problem instead.
#[tokio::test]
async fn a_sign_in_over_an_unreadable_device_file_registers_nothing() {
    let dir = tempfile::tempdir().expect("dir");
    let settings = credential_store::CredentialSettings::from_env(dir.path()).expect("settings");
    std::fs::write(dir.path().join("device.json"), "not json").expect("device.json");
    let mut events = Vec::new();
    register_this_device(dir.path(), &settings, &mut |event| events.push(event))
        .await
        .expect_err("an unreadable device file is an error");
    assert!(events.is_empty(), "{events:?}");
}

#[test]
fn a_chosen_device_name_replaces_the_machines_own() {
    let dir = tempfile::tempdir().expect("dir");
    let base = credential_store::CredentialSettings::from_env(dir.path()).expect("settings");
    assert_eq!(
        named(base.clone(), Some("  my-nas ".to_owned())).host_name.as_deref(),
        Some("my-nas")
    );
    assert_eq!(named(base.clone(), Some("  ".to_owned())).host_name, base.host_name);
    assert_eq!(named(base.clone(), None).host_name, base.host_name);
}
