//! The credential an authenticated Coordination API request is made with.
//!
//! # Why this type exists rather than a `&str`
//!
//! Before this module, both clients of the Coordination API passed a token
//! around as a string: the CLI's `http_client` took `Option<&str>` and called
//! `bearer_auth`, and the daemon captured one `access_token: String` at startup
//! and cloned it into every subsystem. Two things are wrong with that shape and
//! only one of them is about types.
//!
//! The first is arithmetic. An access token on this plane lives **five
//! minutes** (the coordination service). A value
//! captured at startup is a daemon that is authenticated until its first coffee
//! break. A token therefore cannot be a value a subsystem *holds*; it has to be
//! something it *asks for*, and the asking is what refreshes it.
//!
//! The second is that a token alone is not a credential. The Coordination API
//! is a DPoP resource server
//! (the coordination service): it wants
//! `Authorization: DPoP <token>` **and** a proof signed by the key that token
//! was issued against, bound to this request's method and URL and to this
//! token. A caller holding only the token cannot construct a request that will
//! be accepted, and -- more to the point -- a caller holding only the token
//! *looks* like it can.
//!
//! # The type-level property, stated exactly
//!
//! [`CoordinationAuth`] is a newtype over an `Arc<CredentialManager>` and a
//! parsed issuer. It is **not an enum**: there is no second plane, no
//! `Option`, and no variant that carries a bare token. The only constructor is
//! [`CoordinationAuth::new`], which takes an `Arc<CredentialManager>`, and the
//! only way to obtain a `CredentialManager` is over a [`crate::FapiClient`]
//! bound to this installation's registered `client_id` and its ES256 client
//! key. There is no constructor anywhere in this workspace that takes an access
//! token.
//!
//! So "an authenticated Coordination request built from a string" is not a
//! state the program can enter, and it is not a state a test can fabricate
//! either: the legacy `sessions`-table plane used to be expressible as
//! `Plane::LegacySession(String)` and that variant, its constructor, its
//! `is_legacy` predicate and the `Bearer` branch of [`Self::authorize`] have all
//! been deleted along with the Worker's `authorizeLegacySession`.
//!
//! ## The shortcut that had to be closed for that to be true
//!
//! Deleting `LegacySession(String)` was not sufficient, and the gap is worth
//! recording because it was reachable with only this crate's ordinary public
//! API and no unsafe, no test feature and no second plane:
//!
//! ```text
//! FapiClient::from_metadata(/* three hand-written members */)   // infallible
//!   -> CredentialManager::with_client(client, store)            // public
//!   -> manager.seed(&TokenResponse { access_token: "anything", .. })
//!   -> CoordinationAuth::new(Arc::new(manager))                 // authenticated
//! ```
//!
//! Every step was public, `TokenResponse`'s fields were all `pub`, and the
//! result was a `CoordinationAuth` that would sign real DPoP proofs over a
//! bare string a caller chose. The enum was gone; the state was still
//! reachable, one level down.
//!
//! Both rungs are now removed rather than discouraged.
//! [`crate::FapiClient::from_metadata`] returns a `Result` and applies the same
//! profile check discovery does, so a client cannot exist over a document
//! nobody vetted; and [`crate::TokenResponse`] has private fields and no public
//! constructor, so the only way to obtain one is a checked response from that
//! server. `seed` and `with_client` stay public and are no longer a shortcut,
//! because their arguments can no longer be fabricated.
//!
//! # One proof per request, and why nothing here is cached
//!
//! A DPoP proof's `jti` is replay-detected server-side, and the Authorization
//! Server and the Resource Server deliberately share one replay namespace
//! (`resource.ts::spendProofJti`). So a proof is minted per request and never
//! reused -- not across a retry, not across a redirect. The access token is
//! cached, by [`CredentialManager`], which is the one place that knows when it
//! dies.
//!
//! # `htu` comes from the issuer, never from the socket
//!
//! The resource server builds the `htu` it expects as
//! `new URL(new URL(request.url).pathname, AS_ISSUER)` -- the request's path
//! against the *configured* issuer origin, never the incoming `Host`. It has to:
//! comparing against a caller-supplied origin would let the caller choose what
//! its own proof is checked against. So this module mints `htu` the same way,
//! from the discovery document's issuer and the request's path, and a client
//! dialing `http://127.0.0.1:8787` still signs `https://<issuer>/devices/register`.

use std::sync::Arc;

use url::Url;

use crate::error::{Error, Result};
use crate::manager::CredentialManager;

/// The two headers that authenticate one Coordination API request.
///
/// Produced only by [`CoordinationAuth::authorize`]; the fields are private so
/// there is no way to assemble a plausible-looking pair by hand. Both are
/// always present: a request on this plane without a proof is a request the
/// resource server refuses, so "no proof" is not a representable state here
/// either.
#[derive(Clone)]
pub struct RequestAuthorization {
    authorization: String,
    dpop: String,
}

impl RequestAuthorization {
    /// The `Authorization` header value -- always `DPoP <token>`.
    #[must_use]
    pub fn authorization(&self) -> &str {
        &self.authorization
    }

    /// The `DPoP` header value: this request's proof, minted for it alone.
    #[must_use]
    pub fn dpop(&self) -> &str {
        &self.dpop
    }

    /// Attach both headers to a request under construction.
    pub fn apply(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        request
            .header(reqwest::header::AUTHORIZATION, &self.authorization)
            .header("DPoP", &self.dpop)
    }
}

impl std::fmt::Debug for RequestAuthorization {
    /// Renders the scheme and nothing else. Both fields are credentials: the
    /// `Authorization` value carries the access token verbatim, and a proof is
    /// a single-use bearer of possession for as long as its `iat` window lasts.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestAuthorization")
            .field("scheme", &self.authorization.split(' ').next().unwrap_or(""))
            .finish()
    }
}

/// What a [`CoordinationAuth`] holds. Private, and there is one of it: the
/// shape that used to be an enum with a legacy arm is now a single struct, so
/// the deleted plane cannot be reintroduced by adding a variant without that
/// showing up as a change to this type rather than as a new call site.
struct Current {
    manager: Arc<CredentialManager>,
    issuer: Url,
}

/// Asked, with the running `client_id`, for the manager over whatever
/// installation the store holds NOW. `Ok(None)` means there is nothing newer
/// to follow: the store is empty, or it still holds the running installation.
pub type Reload = Arc<
    dyn Fn(
            String,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Option<Arc<CredentialManager>>>> + Send>,
        > + Send
        + Sync,
>;

struct Inner {
    current: std::sync::RwLock<Arc<Current>>,
    reload: Option<Reload>,
    /// Serializes reloads, so concurrent failures swap once.
    reloading: tokio::sync::Mutex<()>,
}

/// A credential that can authenticate Coordination API requests.
///
/// Cheap to clone -- an `Arc` over the one manager, which is how every
/// subsystem in a process ends up refreshing through the same cache and the
/// same cross-process rotation lock rather than racing to rotate the stored
/// refresh token.
#[derive(Clone)]
pub struct CoordinationAuth(Arc<Inner>);

impl CoordinationAuth {
    /// Every request gets a live token and a fresh proof from this manager.
    ///
    /// The issuer is taken from the manager's discovery document, because that
    /// is what the resource server checks `htu` against. This is the only
    /// constructor, and its one argument is the manager: there is no way to
    /// build this value from an access token.
    pub fn new(manager: Arc<CredentialManager>) -> Result<Self> {
        Ok(Self(Arc::new(Inner {
            current: std::sync::RwLock::new(Arc::new(Current::over(manager)?)),
            reload: None,
            reloading: tokio::sync::Mutex::new(()),
        })))
    }

    /// Like [`Self::new`], for a long-running process whose credential store
    /// can be replaced under it (sign out, sign in on the CLI).
    ///
    /// The manager is fixed to one installation, so when it reports that the
    /// store no longer holds that installation (`NotEnrolled` or
    /// `InstallationChanged`), or the server answers a request 401, `reload` is
    /// asked for a manager over the installation the store holds now. The
    /// handle every subsystem already holds is updated in place; nothing
    /// restarts.
    pub fn reloading(manager: Arc<CredentialManager>, reload: Reload) -> Result<Self> {
        Ok(Self(Arc::new(Inner {
            current: std::sync::RwLock::new(Arc::new(Current::over(manager)?)),
            reload: Some(reload),
            reloading: tokio::sync::Mutex::new(()),
        })))
    }

    fn current(&self) -> Arc<Current> {
        Arc::clone(&self.0.current.read().unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    /// Swap to the installation the store holds now, if it is a different one
    /// from `failed`, the snapshot whose use just failed. `Ok(true)` when the
    /// caller should retry: either this call swapped, or a concurrent one
    /// already had.
    async fn follow_store(&self, failed: &Arc<Current>) -> Result<bool> {
        let Some(reload) = self.0.reload.as_ref() else { return Ok(false) };
        let _serialized = self.0.reloading.lock().await;
        if !Arc::ptr_eq(&self.current(), failed) {
            return Ok(true);
        }
        let running = failed.manager.client().client_id().to_owned();
        let Some(manager) = reload(running).await? else { return Ok(false) };
        let next = Arc::new(Current::over(manager)?);
        *self.0.current.write().unwrap_or_else(std::sync::PoisonError::into_inner) = next;
        Ok(true)
    }

    /// The OAuth client registration this credential authenticates as.
    #[must_use]
    pub fn client_id(&self) -> String {
        self.current().manager.client().client_id().to_owned()
    }

    /// Mint the headers for one request.
    ///
    /// `url` is the address actually being dialed; only its path is used, and
    /// the `htu` that is signed is that path against the issuer. `method` must
    /// be the exact uppercase HTTP method the request is sent with -- the
    /// resource server compares it byte-for-byte against the proof's `htm`.
    ///
    /// This may refresh, and therefore may take a network round trip and the
    /// cross-process rotation lock. That is the point: this is the only moment
    /// in a request's life where "is this installation still authenticated?" is
    /// a question that can be answered.
    ///
    /// Public for the one product caller that is not built through
    /// [`CoordinationAuth::execute`]: a WebSocket upgrade authenticates once at
    /// the handshake, over a `tungstenite` request rather than a
    /// [`reqwest::RequestBuilder`], so there is no built request for `execute`
    /// to derive `htm`/`htu` from. Every HTTP call goes through `execute`
    /// instead, which derives both from the request it actually sends rather
    /// than trusting a caller to state them separately.
    pub async fn authorize(&self, method: &str, url: &str) -> Result<RequestAuthorization> {
        let mut current = self.current();
        let access_token = match current.manager.access_token().await {
            Err(Error::NotEnrolled | Error::InstallationChanged { .. })
                if self.follow_store(&current).await? =>
            {
                current = self.current();
                current.manager.access_token().await?
            }
            other => other?,
        };
        let htu = htu_for(&current.issuer, url)?;
        let proof = current.manager.client().dpop_proof(method, &htu, Some(&access_token))?;
        Ok(RequestAuthorization { authorization: format!("DPoP {access_token}"), dpop: proof })
    }

    /// Authenticate and send one Coordination API request.
    ///
    /// This is the canonical way to reach the Coordination API: `htm` and
    /// `htu` are read off the request AFTER it is built, from `build_split`'s
    /// own `Method` and `Url`, rather than from a second `method`/`url` pair a
    /// caller states alongside the builder. The two used to be able to
    /// disagree -- [`CoordinationAuth::authorize_request`], which this
    /// replaces, took a builder and a method/URL pair as three independent
    /// arguments, so a proof could be minted for a different call than the one
    /// that was actually sent. That is not a hypothetical: it is exactly the
    /// shape of bug a DPoP `htm`/`htu` mismatch produces, and it is refused by
    /// the server as a 401 that reads exactly like an expired token.
    pub async fn execute(&self, request: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        let (client, built) = request.build_split();
        let built = built.map_err(Error::Http)?;

        // A 401 can mean the store now holds a different installation than
        // the one whose token was just presented (the cached token outlives a
        // sign out / sign in by up to its lifetime). Follow the store and send
        // once more; a 401 that is about anything else comes back unchanged.
        let used = self.current();
        let retry = built.try_clone();
        let response = self.send_once(&client, built).await?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            if let Some(retry) = retry {
                if self.follow_store(&used).await? {
                    return self.send_once(&client, retry).await;
                }
            }
        }
        Ok(response)
    }

    async fn send_once(
        &self,
        client: &reqwest::Client,
        mut built: reqwest::Request,
    ) -> Result<reqwest::Response> {
        let headers = self.authorize(built.method().as_str(), built.url().as_str()).await?;
        built.headers_mut().insert(
            reqwest::header::AUTHORIZATION,
            reqwest::header::HeaderValue::from_str(headers.authorization()).map_err(|_| {
                Error::InvalidHeaderValue("the access token is not a valid header value".into())
            })?,
        );
        // Not optional: every authenticated request on this plane carries a
        // proof, so there is no branch here for a missing one.
        built.headers_mut().insert(
            "dpop",
            reqwest::header::HeaderValue::from_str(headers.dpop()).map_err(|_| {
                Error::InvalidHeaderValue("the DPoP proof is not a valid header value".into())
            })?,
        );
        Ok(client.execute(built).await?)
    }

    /// Ask the Authorization Server directly whether this registration still
    /// works, by forcing a refresh.
    ///
    /// This exists for exactly one caller: a Sign Out whose `POST
    /// /devices/sign-out` came back 401. That 401 alone proves nothing --
    /// `http_client::error_from_body` maps every 401 this plane can produce,
    /// DPoP mismatches and other authentication bugs included, onto the same
    /// shape a genuine revocation produces, and clearing the local credential
    /// on the strength of a generic 401 is the very failure mode Sign Out
    /// exists to avoid. Forcing a
    /// refresh gives an answer that does not depend on guessing what the 401
    /// meant:
    ///
    /// * the server issues a fresh token -- the registration is alive, and
    ///   the 401 was something else;
    /// * the server refuses `private_key_jwt` client authentication itself
    ///   with `invalid_client` -- this installation's `Client` row is gone,
    ///   which is the ONLY kill boundary this architecture has, so the
    ///   registration is
    ///   confirmed revoked;
    /// * the server refuses with `invalid_grant` -- THIS grant or refresh
    ///   token is dead, which is not the same fact. `invalid_grant` is also
    ///   what the reuse defence produces when it revokes one grant without
    ///   touching the client registration at all
    ///   (`revocation.ts::revokeByGrantId`), and it is what an ordinary
    ///   expired or already-rotated refresh token produces too. Treating it
    ///   as a confirmed client revocation would clear a local credential
    ///   whose registration is still live on the server -- an orphaned
    ///   `Client` row with nothing left able to revoke it, which is exactly
    ///   the kind of state this workspace does not leave lying around. So
    ///   `invalid_grant` settles nothing on its own and is reported as
    ///   [`RegistrationStatus::Unknown`];
    /// * anything else -- a transport failure, a different server error --
    ///   settles nothing either, and is reported the same way.
    pub async fn confirm_registration_status(&self) -> RegistrationStatus {
        match self.current().manager.force_refresh().await {
            Ok(_) => RegistrationStatus::Alive,
            Err(Error::Response { parsed: Some(oauth), .. }) if oauth.error == "invalid_client" => {
                RegistrationStatus::Revoked
            }
            Err(other) => RegistrationStatus::Unknown(other),
        }
    }
}

/// The answer to [`CoordinationAuth::confirm_registration_status`].
#[derive(Debug)]
pub enum RegistrationStatus {
    /// A fresh refresh succeeded: this installation's registration is live.
    Alive,
    /// The Authorization Server refused `private_key_jwt` client
    /// authentication itself with `invalid_client`: this installation's
    /// client registration is confirmed gone. `invalid_grant` does NOT reach
    /// this variant -- see [`CoordinationAuth::confirm_registration_status`].
    Revoked,
    /// Neither `Alive` nor `Revoked` could be established: an `invalid_grant`
    /// refusal (which the client registration can survive), a transport
    /// failure, or anything else the two confirmed cases do not cover.
    /// Carries the error rather than discarding it, because a caller that
    /// cannot settle the question needs to say why, not just that it could
    /// not.
    Unknown(Error),
}

impl std::fmt::Debug for CoordinationAuth {
    /// Names the client registration and the issuer. No credential is
    /// rendered: not the access token, not the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoordinationAuth")
            .field("client_id", &self.current().manager.client().client_id())
            .field("issuer", &self.current().issuer.as_str())
            .finish()
    }
}

impl Current {
    fn over(manager: Arc<CredentialManager>) -> Result<Self> {
        let issuer = Url::parse(&manager.client().metadata().issuer)?;
        Ok(Self { manager, issuer })
    }
}

/// The `htu` for a request: the request's path, against the issuer's origin.
///
/// Query and fragment are excluded from `htu` by RFC 9449 §4.2, and the server
/// strips them before comparing, so they are dropped here rather than signed.
fn htu_for(issuer: &Url, url: &str) -> Result<String> {
    let requested = Url::parse(url)?;
    let mut htu = issuer.clone();
    htu.set_path(requested.path());
    htu.set_query(None);
    htu.set_fragment(None);
    Ok(htu.into())
}

#[cfg(test)]
mod tests;
