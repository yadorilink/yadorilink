//! The product's OAuth credential manager, and the one credential store in
//! this workspace.
//!
//! It drives the four primitives FAPI 2.0 requires:
//!
//! * `private_key_jwt` client authentication ([`assertion`]),
//! * pushed authorization requests ([`FapiClient::push_authorization_request`]),
//! * PKCE with S256 ([`Pkce`]),
//! * DPoP sender-constrained access tokens ([`dpop`]).
//!
//! and the three things a product needs on top of them:
//!
//! * **enrolment** -- [`open_enrolment`] / [`complete_enrolment`] mint this
//!   installation's own `client_id` through the server's bootstrap
//!   transaction, so a shipped binary is not one principal shared by every
//!   user. It runs BEFORE any client exists and ends in a registration, which
//!   is why it is not the device grant;
//! * **headless login** -- the RFC 8628 device grant
//!   ([`FapiClient::request_device_authorization`]), for an already-enrolled
//!   installation on a host with no browser;
//! * **staying authenticated** -- [`CredentialManager`] caches the access
//!   token in memory and refreshes it before it dies. The token's lifetime is
//!   five minutes, so this is the difference between a demonstration and a
//!   daemon.
//!
//! [`store`] holds the durable half: the `client_id`, the client private key
//! and the refresh token, behind a cross-process lock, in either the OS
//! keyring or an owner-only file. The access token is never persisted and the
//! DPoP key is generated per process.
//!
//! ## Three facts that are easy to get wrong, and are therefore encoded here
//!
//! **The issuer is not the socket.** An Authorization Server's issuer is
//! configuration. It emits issuer-absolute URLs and validates DPoP `htu`
//! against issuer-derived URLs, regardless of which address a client connected
//! to and regardless of the `Host` header sent. So every `htu` and the client
//! assertion's `aud` come from the discovery document, never from the request
//! URL, and [`FapiClient::to_local`] exists to map the server's own absolute
//! URLs back onto the socket.
//!
//! **Assertions and proofs are single-use.** `jti` is replay-detected on both,
//! so each is minted per request and neither is ever cached. [`store`] and
//! [`CredentialManager`] cache other things -- the credential and the access
//! token -- and it is worth keeping the distinction sharp: a cached token is a
//! saved round trip, while a cached assertion is a request that fails.
//!
//! **Only the access token is sender-constrained.** The server records the
//! DPoP key's thumbprint next to the access token, and a request proving a
//! different key is refused. The refresh token carries no such binding:
//! `oidc-provider` 9.12.0 copies `jkt` onto a refresh token only for a client
//! authenticating with `none` (`lib/helpers/set_rt_bindings.js`), so for a
//! `private_key_jwt` client every refresh-token record has an empty `cnf_jkt`.
//!
//! So the two credentials rest on different defences -- the refresh token on
//! client authentication, the access token on DPoP -- and presenting the
//! refresh token with a brand new DPoP key succeeds, returning an access token
//! bound to that new key. Losing the DPoP key therefore does NOT end a session
//! while the refresh token and the client key are still held; the client key is
//! what has to be protected for that. Asserted by
//! `a_refresh_token_is_protected_by_client_authentication_and_not_by_the_dpop_key`
//! so a later change that starts binding refresh tokens is noticed.
//!
//! ## This is a profile client, not a tolerant one
//!
//! There is exactly one Authorization Server on the other end of this crate,
//! and this repository owns its configuration. So the server is treated as a
//! fixed profile to be checked, never as an unknown peer to be accommodated,
//! and both halves of that check refuse rather than degrade.
//!
//! **Discovery.** [`Metadata::unmet_profile_requirements`] requires the
//! document to advertise PAR *and* to require it, PKCE S256, `private_key_jwt`,
//! ES256 for client assertions, ES256 for DPoP, and the `authorization_code`
//! and `refresh_token` grants; the device grant is optional but must be
//! advertised on both halves or neither. An absent list is a failure, not an
//! unknown. The check runs in [`FapiClient::from_metadata`], which is the only
//! way to build a client, so there is no lower-level seam that skips it.
//! `tests/server_profile.rs` holds one test per capability.
//!
//! **Token responses.** A 200 is not a credential. [`TokenResponse`] exists
//! only for a response that is `DPoP`-typed, carries a non-zero `expires_in`,
//! and carries a refresh token -- a *rotated* one on the refresh leg, where
//! returning the token just presented means the stored credential is spent. Its
//! fields are private and it has no public constructor, so an unchecked token
//! response is not a value any caller can hold. Nothing guesses a lifetime and
//! nothing warns-and-continues; `tests/token_response_contract.rs` pins each
//! refusal.
//!
//! ## What this crate does not do
//!
//! It does not drive the authorization endpoint. Getting from a pushed request
//! to an authorization code involves a user agent and whatever the server puts
//! in front of it; [`FapiClient::authorization_endpoint_url`] hands back the
//! URL and the flow resumes at
//! [`FapiClient::exchange_authorization_code`].
//!
//! It does not verify a JWS. The access tokens are opaque, and the `id_token`
//! is not consumed.
//!
//! It does not implement a DPoP nonce retry loop. No server response observed
//! against this Authorization Server has carried a `DPoP-Nonce` header, so
//! that path would be untested code. A 401 that carries one surfaces to the
//! caller rather than being swallowed.

mod assertion;
mod bootstrap;
mod client;
mod coordination;
mod device_grant;
mod discovery;
mod dpop;
mod error;
mod jws;
mod key;
mod manager;
mod pkce;
pub mod store;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

// `client_assertion` and `ASSERTION_TYPE` sign and shape a `private_key_jwt`
// assertion outside `FapiClient`, which is otherwise the only thing in this
// crate that can produce one. Nothing in the product calls the free function
// -- it exists for `tests/coordination_wire_contract.rs`, which crafts its own
// token-endpoint requests to test the Authorization Server's client
// authentication rather than going through a `FapiClient` at all -- so it is
// behind `test-support` rather than a plain product-facing export.
#[cfg(any(test, feature = "test-support"))]
pub use assertion::{client_assertion, ASSERTION_TYPE};
pub use bootstrap::{
    complete_enrolment, open_enrolment, poll_enrolment, EnrolmentPoll, EnrolmentRequest,
    PendingEnrolment, Registration, BOOTSTRAP_POLL_PATH, BOOTSTRAP_START_PATH,
};
pub use client::{AuthorizationRequest, FapiClient, PushedAuthorizationResponse, TokenResponse};
pub use coordination::{CoordinationAuth, RegistrationStatus, Reload, RequestAuthorization};
pub use device_grant::{DeviceAuthorization, DevicePoll, DEVICE_CODE_GRANT};
pub use discovery::Metadata;
// Same reasoning as `client_assertion` above: no product call site mints a
// DPoP proof outside `FapiClient::dpop_proof_for_test`'s callers or
// `CoordinationAuth`, which is where every real request's proof is minted
// from the request that is actually being sent. This free function exists so
// `tests/coordination_wire_contract.rs` can forge a proof signed by a key the
// resource server does not expect, which is exactly the adversarial case a
// product code path must never need to construct.
#[cfg(any(test, feature = "test-support"))]
pub use dpop::dpop_proof;
pub use error::{Error, OauthError, Result};
pub use key::{Es256Key, PublicJwk};
pub use manager::{CredentialManager, Detach, DEFAULT_LOCK_TIMEOUT, DEFAULT_REFRESH_SKEW};
pub use pkce::Pkce;
pub use store::{Backend, CredentialStore, Credentials, StoreError};
