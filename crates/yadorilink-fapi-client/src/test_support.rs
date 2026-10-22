//! One offline credential, for tests that need *a* credential and not *this*
//! credential.
//!
//! # Why this is not a backdoor
//!
//! Dozens of daemon and CLI tests point a subsystem at a fake coordination
//! server and need a [`CoordinationAuth`] to hand it. They used to write
//! `CoordinationAuth::legacy_session("test")`, which is exactly the
//! bare-string constructor the cutover deleted. Nothing replaced it with a
//! looser one.
//!
//! It is behind the `test-support` feature, which nothing in the product
//! enables, and the credential it builds authenticates against nothing: the
//! issuer is `https://as.test`, the client key is generated per call, and the
//! access token is a fixed string that no server ever issued.
//!
//! # This module is now where the construction seams live
//!
//! `CredentialManager::with_client` and `CredentialManager::seed` used to be
//! public. Together they are the assembly line for a manager holding a token no
//! server ever issued, and therefore for a [`CoordinationAuth`] that signs real
//! DPoP proofs over it -- so they are `pub(crate)` now, and [`manager_over`]
//! below is the only way to reach them from outside this crate.
//!
//! That does not make this module a privileged door. The input `seed` needs is
//! a [`TokenResponse`], whose fields are private and whose only origin outside
//! this crate is a checked response from the Authorization Server; a caller
//! holding one has already been issued a real token, and had no need of a
//! shortcut. What the move buys is that the seams are now behind a feature
//! flag no product target enables, so the assembly line cannot be reconstructed
//! by a future call site that has a `TokenResponse` in hand and reaches for the
//! nearest constructor instead of [`CredentialManager::establish`].
//!
//! # What it deliberately does not do
//!
//! It never touches the filesystem. The store it builds is a path under the
//! temp directory that is never read and never written, because the seeded
//! token is valid for an hour and [`CredentialManager::access_token`] therefore
//! answers from its cache without reaching the store or the network. A test
//! that wants rotation behaviour wants a real store and should build one.

use std::sync::Arc;

use url::Url;

use crate::client::{FapiClient, TokenResponse};
use crate::coordination::CoordinationAuth;
use crate::discovery::Metadata;
use crate::key::Es256Key;
use crate::manager::CredentialManager;
use crate::store::{Backend, CredentialStore};

/// The access token [`offline_manager`] seeds. Exposed so a test can assert it
/// did *not* reach a log line or a `Debug` rendering.
pub const OFFLINE_ACCESS_TOKEN: &str = "offline-test-access-token";

/// The issuer the offline credential claims, and therefore the origin its DPoP
/// proofs sign `htu` against.
pub const OFFLINE_ISSUER: &str = "https://as.test";

/// A credential manager holding one seeded access token, valid for an hour.
///
/// Reaches no network and no filesystem, so it is usable from a test with no
/// server, no temp directory and no runtime beyond the one `#[tokio::test]`
/// already provides.
#[must_use]
pub fn offline_manager() -> CredentialManager {
    // The deployed profile, not a three-member minimum. `from_metadata` runs
    // the same profile check discovery does, so a fixture that advertised less
    // than the product requires would not build a client at all -- which is
    // the intended relationship between the two.
    let metadata: Metadata = Metadata::deployed_profile(OFFLINE_ISSUER);

    let client = FapiClient::from_metadata(
        reqwest::Client::new(),
        Url::parse(OFFLINE_ISSUER).expect("a valid base URL"),
        metadata,
        "ylk-offline-test",
        Es256Key::generate(),
        Es256Key::generate(),
    )
    .expect("the deployed profile is one this client accepts");

    // Never read and never written: the seeded token below is fresh for an
    // hour, so no refresh is attempted and nothing opens this path.
    let store = CredentialStore::with_backend(
        Backend::File(std::env::temp_dir().join("yadorilink-offline-test-credentials.json")),
        &std::env::temp_dir(),
    );

    let manager = CredentialManager::with_client(client, Arc::new(store));
    // `TokenResponse`'s fields are private and its only public origin is a
    // checked server response, so this fixture goes through the crate-internal
    // constructor rather than a struct literal. The refresh token it carries is
    // never used: `seed` puts the access token in the cache and touches nothing
    // else, and the token is fresh for an hour.
    manager.seed(&TokenResponse::assembled(
        OFFLINE_ACCESS_TOKEN,
        std::time::Duration::from_secs(3600),
        "offline-test-refresh-token",
    ));
    manager
}

/// A [`CoordinationAuth`] over [`offline_manager`].
#[must_use]
pub fn offline_auth() -> CoordinationAuth {
    CoordinationAuth::new(Arc::new(offline_manager())).expect("the offline issuer is a valid URL")
}

/// A manager over an already-built client, holding no token: the `pub(crate)`
/// [`CredentialManager::with_client`], reachable only from a target that has
/// enabled this crate's `test-support` feature.
///
/// For the tests that drive the store and the refresh clock directly -- the
/// five-minute boundary proof and the cross-process rotation proof -- which
/// need a manager over a client they built themselves and a store they can
/// inspect, and which deliberately do *not* want
/// [`CredentialManager::establish`] because they are asserting what happens
/// when the store is written by someone else.
///
/// Product code uses [`CredentialManager::establish`],
/// [`CredentialManager::restore`] or [`CredentialManager::from_credentials`].
#[must_use]
pub fn manager_over(client: FapiClient, store: Arc<CredentialStore>) -> CredentialManager {
    CredentialManager::with_client(client, store)
}
