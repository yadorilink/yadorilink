#![cfg(test)]

use super::*;

/// `login` on a machine that already holds a credential must not quietly
/// enrol a second identity. Re-enrolling mints a new `client_id` and leaves
/// the old one live, so the two would both be authorized and only one of
/// them reachable from this machine.
#[tokio::test]
async fn login_on_an_enrolled_installation_refuses_rather_than_enrolling_twice() {
    let dir = tempfile::tempdir().expect("temp dir");
    let _guard = crate::coordination::http_client::COORDINATION_ADDR_ENV_LOCK.lock().await;
    std::env::set_var("YADORILINK_CREDENTIAL_STORE", "file");
    std::env::set_var("YADORILINK_CREDENTIAL_FILE", dir.path().join("credentials.json"));

    let store = credential_store::open().expect("store");
    let lock = store.lock(std::time::Duration::from_secs(5)).await.expect("lock");
    store
        .save(
            &lock,
            &yadorilink_fapi_client::store::Credentials::new(
                "https://as.test",
                "ylk-AAAAAAAAAAAAAAAAAAAAAA",
                Es256Key::generate().to_jwk_json(),
                "rt-1",
            ),
        )
        .expect("save");
    drop(lock);

    let mut events = Vec::new();
    let result = login(false, |event| events.push(event)).await;
    std::env::remove_var("YADORILINK_CREDENTIAL_FILE");
    std::env::remove_var("YADORILINK_CREDENTIAL_STORE");

    let message = match result {
        Err(CoreError::AuthFailed(message)) => message,
        other => panic!("expected a refusal, got {other:?}"),
    };
    assert!(message.contains("already enrolled"), "{message}");
    assert!(message.contains("logout"), "the refusal must name the remedy: {message}");
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
