#![cfg(test)]

use super::*;

fn response(access_token: &str, expires_in: u64) -> TokenResponse {
    TokenResponse::assembled(access_token, Duration::from_secs(expires_in), "rt-unused")
}

fn manager() -> CredentialManager {
    // No network is reached: every assertion below is about the cache's
    // own arithmetic, which is the part that decides whether a five-minute
    // token is ever presented after it died.
    let dir = tempfile::tempdir().expect("temp dir");
    let store = Arc::new(CredentialStore::with_backend(
        crate::store::Backend::File(dir.path().join("credentials.json")),
        dir.path(),
    ));
    // Leaked on purpose: the directory must outlive the store in a test
    // that never touches the filesystem again.
    std::mem::forget(dir);
    CredentialManager {
        client: FapiClient::from_metadata(
            reqwest::Client::new(),
            url::Url::parse("https://as.test").expect("a valid base URL"),
            crate::Metadata::deployed_profile("https://as.test"),
            "ylk-test",
            Es256Key::generate(),
            Es256Key::generate(),
        )
        .expect("the deployed profile is accepted"),
        store,
        refreshing: tokio::sync::Mutex::new(()),
        cached: std::sync::Mutex::new(None),
        refresh_skew: DEFAULT_REFRESH_SKEW,
        lock_timeout: DEFAULT_LOCK_TIMEOUT,
        detach: Arc::new(run_inline),
    }
}

#[test]
fn a_token_inside_its_lifetime_is_served_from_the_cache() {
    let manager = manager();
    manager.seed(&response("at-1", 300));
    assert_eq!(manager.fresh_enough().as_deref(), Some("at-1"));
}

/// The whole point of the skew: a token with thirty seconds left is not
/// good enough, because the request it would be attached to still has to
/// travel and be answered.
#[test]
fn a_token_inside_the_refresh_skew_is_not_served_even_though_it_has_not_expired() {
    let manager = manager();
    manager.seed(&response("at-1", 30));
    assert_eq!(manager.fresh_enough(), None);
}

// There is no test here for a response with no lifetime. There used to be
// one, asserting that an absent `expires_in` was treated as sixty seconds;
// that fallback is gone, and the case it covered is now
// `tests/token_response_contract.rs::
// a_token_response_with_no_lifetime_is_refused_rather_than_assumed`, where
// it belongs -- a response with no lifetime never reaches the cache,
// because it never becomes a `TokenResponse`.

#[test]
fn an_empty_cache_is_not_a_token() {
    assert_eq!(manager().fresh_enough(), None);
}

#[test]
fn debug_renders_no_credential() {
    let manager = manager();
    manager.seed(&response("secret-access-token", 300));
    let rendered = format!("{manager:?}");
    assert!(!rendered.contains("secret-access-token"), "the access token reached Debug");
}

/// The canonical door writes the credential and seeds the cache as one
/// step, so the login that just happened cannot end with only half of it
/// recorded.
///
/// Before [`CredentialManager::establish`] the call site did this by hand,
/// in four statements: build a `Credentials` literal, `store.save` it,
/// `with_client`, `seed`. Two call sites spelled it, which is two chances
/// to stop after the third statement -- a store holding a refresh token for
/// a process whose manager has no cached token and will refresh on its very
/// first request, or a seeded manager over a store that was never written,
/// which authenticates until the process exits and is not enrolled
/// afterwards.
#[tokio::test]
async fn establishing_a_login_writes_the_credential_and_seeds_the_cache_together() {
    let (client, store, dir) = parts();
    let tokens = TokenResponse::assembled("at-fresh", Duration::from_secs(300), "rt-1");

    let manager = CredentialManager::establish(client, "{\"kty\":\"EC\"}", &tokens, store)
        .await
        .expect("the credential is complete, so the store accepts it");

    assert_eq!(
        manager.fresh_enough().as_deref(),
        Some("at-fresh"),
        "the access token just issued is not in the cache, so the first request after a \
         login would spend a refresh token to obtain a token it was already handed"
    );
    let stored = manager.store.load().expect("load").expect("the store is enrolled");
    assert_eq!(stored.refresh_token(), "rt-1");
    drop(dir);
}

/// `establish` takes the client, not an issuer and a client id, so the
/// stored credential cannot name a different registration from the one the
/// token was issued to.
///
/// The hand-spelled literal took all four members as separate expressions.
/// Three of them came from the client and one -- `client_id` -- came from
/// the enrolment result that preceded it. They agreed because the same
/// value had been passed to `discover` a few lines earlier, which is
/// agreement by the author remembering, not by construction. A credential
/// naming a `client_id` the client key does not authenticate says
/// `invalid_client` at the next refresh, on a machine that logged in
/// successfully.
#[tokio::test]
async fn an_established_credential_names_the_client_the_token_was_issued_to() {
    let (client, store, dir) = parts();
    let issuer = client.metadata().issuer.clone();
    let client_id = client.client_id().to_owned();
    let tokens = TokenResponse::assembled("at-fresh", Duration::from_secs(300), "rt-1");

    let manager = CredentialManager::establish(client, "{\"kty\":\"EC\"}", &tokens, store)
        .await
        .expect("the credential is complete");

    let stored = manager.store.load().expect("load").expect("enrolled");
    assert_eq!(stored.client_id(), client_id);
    assert_eq!(stored.issuer(), issuer);
    drop(dir);
}

/// A `logout`/`login` while this process runs registers a new client and
/// stores its refresh token. Refreshing with the old client identity would
/// be a 401 `invalid_client` at the server; it is refused locally,
/// and without any network round trip (the base URL here is unreachable).
#[tokio::test]
async fn a_refresh_after_the_stored_installation_changed_is_refused_before_it_is_sent() {
    let (client, store, dir) = parts();
    let tokens = TokenResponse::assembled("at-1", Duration::from_secs(300), "rt-1");
    let issuer = client.metadata().issuer.clone();
    let manager = CredentialManager::establish(client, "{\"kty\":\"EC\"}", &tokens, store.clone())
        .await
        .expect("enrolled");

    let lock = store.lock(DEFAULT_LOCK_TIMEOUT).await.expect("lock");
    store
        .save(&lock, &Credentials::new(issuer, "ylk-after-relogin", "{\"kty\":\"EC\"}", "rt-2"))
        .expect("a second login replaces the installation");
    drop(lock);

    match manager.force_refresh().await {
        Err(Error::InstallationChanged { running, stored }) => {
            assert_eq!(running, "ylk-test");
            assert_eq!(stored, "ylk-after-relogin");
        }
        other => panic!("expected InstallationChanged, got {other:?}"),
    }
    drop(dir);
}

/// The pieces `manager()` assembles, handed back separately so a test can
/// drive the canonical constructor rather than the struct literal.
fn parts() -> (FapiClient, Arc<CredentialStore>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let store = Arc::new(CredentialStore::with_backend(
        crate::store::Backend::File(dir.path().join("credentials.json")),
        dir.path(),
    ));
    let client = FapiClient::from_metadata(
        reqwest::Client::new(),
        url::Url::parse("https://as.test").expect("a valid base URL"),
        crate::Metadata::deployed_profile("https://as.test"),
        "ylk-test",
        Es256Key::generate(),
        Es256Key::generate(),
    )
    .expect("the deployed profile is accepted");
    (client, store, dir)
}
