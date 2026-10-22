//! The FAPI 2.0 client: discovery, PAR, token, refresh, and a
//! DPoP-protected GET.

use std::time::Duration;

use reqwest::StatusCode;
use url::Url;

use crate::assertion::{client_assertion, ASSERTION_TYPE};
use crate::discovery::Metadata;
use crate::dpop::dpop_proof;
use crate::error::{Error, Result};
use crate::key::Es256Key;
use crate::pkce::Pkce;

/// Refuses a socket that is neither `https://` nor loopback.
///
/// Shared with `bootstrap.rs`, which dials a `base_url` of its own before any
/// [`FapiClient`] exists to check it: a fresh installation has no issuer to
/// compare against yet either, so the same "https or loopback" floor is the
/// only check available at that point too, and it is the same property for
/// the same reason -- this crate never sends a credential-bearing request to
/// an origin that is neither the deployment's own https endpoint nor a
/// developer's own machine.
pub(crate) fn ensure_trusted_socket(base_url: &Url) -> Result<()> {
    if base_url.scheme() == "https" || is_loopback(base_url) {
        return Ok(());
    }
    Err(Error::UntrustedSocket(base_url.as_str().to_owned()))
}

/// Whether `url`'s host is a loopback address: `localhost`, `127.0.0.0/8`, or
/// `::1`. Mirrors `yadorilink-cli`'s `is_loopback_host`, which exists for the
/// same reason on the *coordination* address rather than the auth-server one;
/// duplicated rather than shared across the crate boundary because it is four
/// lines over a type each crate already depends on for an unrelated reason.
pub(crate) fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// A successful pushed authorization request (RFC 9126).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PushedAuthorizationResponse {
    pub request_uri: String,
    pub expires_in: u64,
}

/// A token endpoint response, as it arrived on the wire and before anything
/// has been checked about it.
///
/// Private, and every member is optional, because this type's only job is to
/// get the bytes into Rust so `TokenResponse::accept` can refuse them. Making
/// `access_token` mandatory here would move that refusal into serde, where it
/// arrives as a parse error that names no requirement.
#[derive(serde::Deserialize)]
struct RawTokenResponse {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
}

/// A token response that has been checked against this deployment's profile.
///
/// # Why the fields are private
///
/// Every value of this type is a usable credential: a DPoP-typed access token
/// with a real lifetime and a refresh token to succeed it. That is a property
/// of the *type*, not of the code path that happened to produce it, and it only
/// stays one while `TokenResponse::accept` is the only way to make one. A
/// public field set would let a caller assemble a credential that no server
/// ever issued, and a `pub` `token_type: String` would let one exist that the
/// server said was a `Bearer`.
///
/// `access_token` is opaque: this Authorization Server issues a random
/// identifier and keeps the sender constraint server-side, so the client can
/// neither read nor validate it. `token_type` is not kept at all -- it is
/// checked and discarded, because after the check there is only one value it
/// could have.
#[derive(Clone)]
pub struct TokenResponse {
    access_token: String,
    expires_in: Duration,
    refresh_token: String,
    scope: Option<String>,
    id_token: Option<String>,
}

/// The `token_type` this deployment issues, and the `Authorization` scheme its
/// resource server requires.
const DPOP_TOKEN_TYPE: &str = "DPoP";

impl std::fmt::Debug for TokenResponse {
    /// Renders the shape and none of the secrets. This value is two live
    /// credentials; a derived `Debug` would put both into the first log line
    /// that formatted a token response.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("token_type", &DPOP_TOKEN_TYPE)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .field("has_id_token", &self.id_token.is_some())
            .finish_non_exhaustive()
    }
}

impl TokenResponse {
    /// Check a wire response against the profile, or say which requirement it
    /// failed.
    ///
    /// `spent_refresh_token` is the refresh token that was *presented* on this
    /// request, and is `Some` exactly for a refresh. Rotation is measured
    /// against it rather than against the credential store: another process may
    /// have rotated the store since, and reading the store here would turn that
    /// ordinary race into a bogus "the server did not rotate".
    fn accept(
        raw: RawTokenResponse,
        step: &'static str,
        spent_refresh_token: Option<&str>,
    ) -> Result<Self> {
        let unusable = |requirement: String| Error::UnusableTokenResponse { step, requirement };

        let access_token = raw
            .access_token
            .filter(|token| !token.is_empty())
            .ok_or_else(|| unusable("access_token: absent, so this is not a credential".into()))?;

        // RFC 6749 section 7.1 makes `token_type` case-insensitive. Absent is
        // not "probably DPoP": it is a server that did not say the token is
        // sender-constrained, and this client has no other way to find out.
        match raw.token_type.as_deref() {
            Some(kind) if kind.eq_ignore_ascii_case(DPOP_TOKEN_TYPE) => {}
            other => {
                return Err(unusable(format!(
                    "token_type: expected `{DPOP_TOKEN_TYPE}`, got {}; a token that is not \
                     sender-constrained is not a credential this client will present",
                    other.map_or_else(|| "nothing".to_owned(), |kind| format!("`{kind}`"))
                )))
            }
        }

        // No assumed lifetime. Guessing is a claim about how long a credential
        // lives made by the party that does not issue it, and the guess that
        // existed here was only ever a way to tolerate an incomplete response.
        let expires_in = match raw.expires_in {
            Some(0) | None => {
                return Err(unusable(format!(
                    "expires_in: {}; this client will not guess a credential's lifetime",
                    if raw.expires_in.is_some() { "zero" } else { "absent" }
                )))
            }
            Some(seconds) => Duration::from_secs(seconds),
        };

        const NO_REFRESH_TOKEN: &str =
            "refresh_token: absent; this client only ever requests `offline_access`, and a grant \
             with no refresh token is a session that ends at the next expiry";
        let refresh_token = raw
            .refresh_token
            .filter(|token| !token.is_empty())
            .ok_or_else(|| unusable(NO_REFRESH_TOKEN.into()))?;

        // Rotation, on the one step where it is observable. This server rotates
        // on every refresh, so a repeat of the presented token means the store
        // now holds a spent credential -- the state that used to be reported as
        // success.
        if spent_refresh_token.is_some_and(|spent| spent == refresh_token) {
            return Err(unusable(
                "refresh_token: the server returned the refresh token that was just presented; \
                 this server rotates on every refresh, so the stored credential is now spent"
                    .into(),
            ));
        }

        Ok(Self {
            access_token,
            expires_in,
            refresh_token,
            scope: raw.scope,
            id_token: raw.id_token,
        })
    }

    /// A response assembled without a server, for this crate's own tests and
    /// for `test_support`'s offline credential.
    ///
    /// Crate-internal on purpose. The guarantee this type carries is that no
    /// caller *outside* the crate can hold a credential that no Authorization
    /// Server issued; a fixture inside it is not a way around
    /// `TokenResponse::accept`, because nothing it builds ever reaches a real
    /// server.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn assembled(access_token: &str, expires_in: Duration, refresh_token: &str) -> Self {
        Self {
            access_token: access_token.to_owned(),
            expires_in,
            refresh_token: refresh_token.to_owned(),
            scope: None,
            id_token: None,
        }
    }

    /// The opaque access token, to be presented as `Authorization: DPoP <t>`.
    #[must_use]
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    /// How long the access token lives. Checked to be non-zero.
    #[must_use]
    pub fn expires_in(&self) -> Duration {
        self.expires_in
    }

    /// The refresh token that succeeds the one this response was obtained with.
    #[must_use]
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    #[must_use]
    pub fn scope(&self) -> Option<&str> {
        self.scope.as_deref()
    }

    #[must_use]
    pub fn id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }
}

/// The authorization-request parameters this client pushes.
///
/// `response_type` and `code_challenge_method` are not settable: FAPI 2.0
/// permits only `code` and only `S256`, so offering the choice would only be a
/// way to produce an invalid request.
#[derive(Debug)]
pub struct AuthorizationRequest<'a> {
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub state: &'a str,
    /// `Some("consent")` is required to be granted `offline_access`, and
    /// therefore to receive a refresh token at all. Without it the token
    /// response arrives with a 200 and simply no `refresh_token`.
    pub prompt: Option<&'a str>,
    pub pkce: &'a Pkce,
}

/// A FAPI 2.0 client bound to one Authorization Server, one registered client
/// id, one client key and one DPoP key.
///
/// The DPoP key is held for the life of the value: the sender constraint is
/// re-proved at every refresh, not carried over from the previous token, so a
/// client that discards the key can no longer refresh.
pub struct FapiClient {
    http: reqwest::Client,
    /// The socket actually dialed. Frequently NOT the issuer -- a local
    /// `wrangler dev` listens on `127.0.0.1` while the issuer stays
    /// `https://...`.
    base_url: Url,
    metadata: Metadata,
    client_id: String,
    client_key: Es256Key,
    dpop_key: Es256Key,
}

impl std::fmt::Debug for FapiClient {
    /// Renders what identifies the client and nothing that authenticates it.
    /// `Es256Key`'s own `Debug` already refuses the private scalar; this keeps
    /// a derived `Debug` from ever being added over the top of it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FapiClient")
            .field("client_id", &self.client_id)
            .field("issuer", &self.metadata.issuer)
            .field("base_url", &self.base_url.as_str())
            .field("dpop_jkt", &self.dpop_key.jkt())
            .finish_non_exhaustive()
    }
}

impl FapiClient {
    /// Fetch the server's metadata and build a client from it.
    ///
    /// `base_url` is the socket to dial. Every subsequent request is sent
    /// there, while every `htu` and the assertion audience come from the
    /// metadata -- which is the only correct arrangement, because the server
    /// discards the request's `Host` header and validates against its own
    /// configured issuer.
    pub async fn discover(
        http: reqwest::Client,
        base_url: &str,
        client_id: impl Into<String>,
        client_key: Es256Key,
        dpop_key: Es256Key,
    ) -> Result<Self> {
        let base_url = Url::parse(base_url)?;
        // Before anything is sent, including the discovery request itself: a
        // socket that is neither `https://` nor loopback cannot be this
        // deployment's real issuer (which speaks https) and is not a
        // supported local-development override either. Refusing here is what
        // stops a misconfigured or attacker-controlled `base_url` from ever
        // receiving so much as an unauthenticated GET, let alone the
        // refresh-token, client-assertion or DPoP-bearing requests that follow
        // once a client exists over it.
        ensure_trusted_socket(&base_url)?;
        let well_known = base_url.join("/.well-known/openid-configuration")?;

        let response = http.get(well_known).send().await?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            return Err(Error::response("discovery", status.as_u16(), body));
        }
        let metadata: Metadata = serde_json::from_str(&body)?;

        Self::from_metadata(http, base_url, metadata, client_id, client_key, dpop_key)
    }

    /// Build a client from metadata that has already been fetched.
    ///
    /// One discovery document per process is enough: an enrolment flow reads
    /// it to find the device-authorization endpoint and then wants a client
    /// over the same document, and fetching it twice would let the two halves
    /// of one login disagree about the issuer.
    ///
    /// The profile check runs here rather than only in
    /// [`FapiClient::discover`]. `Metadata`'s fields are public and it is
    /// `Deserialize`, so a caller can hand one in that no server ever sent;
    /// checking only on the fetch path would make the gate advisory and leave
    /// this constructor as the way around it. The cost is that the check runs
    /// twice for a discovery, which is a list comparison over a document
    /// already in memory.
    pub fn from_metadata(
        http: reqwest::Client,
        base_url: Url,
        metadata: Metadata,
        client_id: impl Into<String>,
        client_key: Es256Key,
        dpop_key: Es256Key,
    ) -> Result<Self> {
        // Reported here rather than left to the caller: a check that nothing
        // calls at construction lets every mismatch surface as the opaque 400
        // several requests later that the check exists to prevent.
        let unmet = metadata.unmet_profile_requirements();
        if !unmet.is_empty() {
            return Err(Error::UnsupportedServer(unmet));
        }
        // The second half of the socket check, now that the issuer is known.
        // `ensure_trusted_socket` already refused anything that is neither
        // `https://` nor loopback; this refuses the one shape that check
        // cannot see on its own -- an `https://` socket that is simply a
        // DIFFERENT origin than the issuer it claims to be discovery for. A
        // loopback socket is exempt, which is what lets a local `wrangler dev`
        // dial `http://127.0.0.1:8787` while the issuer stays the deployed
        // `https://` hostname; every other socket must be the issuer's own
        // origin or this constructor -- the one place a [`FapiClient`] can be
        // built -- refuses before returning one that could send a refresh
        // token, a client assertion or a DPoP proof anywhere else.
        ensure_trusted_socket(&base_url)?;
        if !is_loopback(&base_url) {
            let issuer_url = Url::parse(&metadata.issuer)?;
            if issuer_url.origin() != base_url.origin() {
                return Err(Error::UntrustedIssuerMismatch {
                    socket: base_url.origin().ascii_serialization(),
                    issuer: metadata.issuer.clone(),
                });
            }
        }
        Ok(Self { http, base_url, metadata, client_id: client_id.into(), client_key, dpop_key })
    }

    #[must_use]
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The RFC 7638 thumbprint of the DPoP key -- the sender constraint the
    /// server records against every token this client obtains.
    #[must_use]
    pub fn dpop_jkt(&self) -> String {
        self.dpop_key.jkt()
    }

    /// The underlying HTTP client, for the legs this crate deliberately does
    /// not own (see `authorization_endpoint_url`).
    #[must_use]
    pub fn http(&self) -> &reqwest::Client {
        &self.http
    }

    /// Map an issuer-absolute URL the server emitted onto the socket this
    /// client is really talking to.
    ///
    /// The server's `Location` headers are inconsistent by nature: some are
    /// relative, some are absolute against the issuer. Neither points at the
    /// socket, because the issuer is configuration.
    pub fn to_local(&self, url: &str) -> Result<Url> {
        if let Some(rest) = url.strip_prefix(&self.metadata.issuer) {
            return Ok(self.base_url.join(rest)?);
        }
        if url.starts_with('/') {
            return Ok(self.base_url.join(url)?);
        }
        Err(Error::NotUnderIssuer { url: url.to_owned(), issuer: self.metadata.issuer.clone() })
    }

    /// One fresh `private_key_jwt` assertion, audienced at the issuer.
    ///
    /// `pub(crate)`: every product request that needs one is built inside this
    /// module (PAR, the token endpoint) or `device_grant.rs`, and nothing
    /// outside the crate has ever called it -- an assertion minted with no
    /// request to attach it to is exactly the reassembled-credential shape
    /// `crate::coordination` documents closing.
    pub(crate) fn client_assertion(&self) -> Result<String> {
        client_assertion(&self.client_key, &self.client_id, &self.metadata.issuer)
    }

    /// One fresh DPoP proof for `htm` + `htu`, where `htu` must already be the
    /// issuer-derived endpoint URL.
    ///
    /// `pub(crate)`: every real request's proof is minted by
    /// [`crate::CoordinationAuth::execute`] (or, for the one product caller
    /// that is not an HTTP request, [`crate::CoordinationAuth::authorize`])
    /// from the request actually being sent. [`Self::dpop_proof_for_test`] is
    /// the one sanctioned way around that, for tests that need to prove the
    /// resource server rejects a proof this client's own key signed over the
    /// WRONG claims.
    pub(crate) fn dpop_proof(
        &self,
        htm: &str,
        htu: &str,
        access_token: Option<&str>,
    ) -> Result<String> {
        dpop_proof(&self.dpop_key, htm, htu, access_token)
    }

    /// Sign a DPoP proof with this client's own key over caller-chosen claims.
    ///
    /// Exists only for adversarial resource-server tests
    /// (`tests/coordination_wire_contract.rs`) that need a proof carrying the
    /// right key and the WRONG `htm`/`htu`/`ath` -- a case no product code path
    /// can construct, because [`crate::CoordinationAuth::execute`] derives
    /// every claim from the request it is actually sending.
    #[cfg(any(test, feature = "test-support"))]
    pub fn dpop_proof_for_test(
        &self,
        htm: &str,
        htu: &str,
        access_token: Option<&str>,
    ) -> Result<String> {
        self.dpop_proof(htm, htu, access_token)
    }

    /// Push an authorization request (RFC 9126).
    ///
    /// The DPoP proof sent here is what pins the grant's `dpop_jkt`: the token
    /// request later must prove possession of the *same* key or the grant is
    /// refused.
    pub async fn push_authorization_request(
        &self,
        request: &AuthorizationRequest<'_>,
    ) -> Result<PushedAuthorizationResponse> {
        let endpoint = self
            .metadata
            .pushed_authorization_request_endpoint
            .as_deref()
            .ok_or(Error::MissingMetadata("pushed_authorization_request_endpoint"))?;

        let mut form = vec![
            ("client_id", self.client_id.as_str()),
            ("client_assertion_type", ASSERTION_TYPE),
            ("response_type", "code"),
            ("redirect_uri", request.redirect_uri),
            ("scope", request.scope),
            ("state", request.state),
            ("code_challenge", request.pkce.challenge()),
            ("code_challenge_method", "S256"),
        ];
        if let Some(prompt) = request.prompt {
            form.push(("prompt", prompt));
        }
        let assertion = self.client_assertion()?;
        form.push(("client_assertion", &assertion));

        let response = self
            .http
            .post(self.to_local(endpoint)?)
            .header("DPoP", self.dpop_proof("POST", endpoint, None)?)
            .form(&form)
            .send()
            .await?;

        // RFC 9126 specifies 201 for a successful push.
        Self::decode(
            response,
            "pushed authorization request",
            &[StatusCode::CREATED, StatusCode::OK],
        )
        .await
    }

    /// The URL a user agent visits to authorize the pushed request.
    ///
    /// Returned rather than fetched. Driving the authorization endpoint is the
    /// user agent's job, and what happens between it and the redirect back is
    /// server-specific (an identity provider, a consent screen, cookies). This
    /// crate deliberately stops at the boundary: it hands back the URL and
    /// resumes once the caller has an authorization code.
    pub fn authorization_endpoint_url(&self, request_uri: &str) -> Result<Url> {
        let mut url = self.to_local(&self.metadata.authorization_endpoint)?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("request_uri", request_uri);
        Ok(url)
    }

    /// Exchange an authorization code for tokens.
    ///
    /// `redirect_uri` and `pkce` must be the ones pushed at PAR.
    pub async fn exchange_authorization_code(
        &self,
        code: &str,
        redirect_uri: &str,
        pkce: &Pkce,
    ) -> Result<TokenResponse> {
        let assertion = self.client_assertion()?;
        self.token_request(
            "authorization code exchange",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri),
                ("code_verifier", pkce.verifier()),
                ("client_id", &self.client_id),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &assertion),
            ],
            None,
        )
        .await
    }

    /// Exchange a refresh token for a new access token.
    ///
    /// The server rotates: the response carries a *new* refresh token and the
    /// one just spent is dead. A caller that keeps the old one and replays it
    /// takes the whole grant down. A response that does *not* rotate is refused
    /// here rather than returned, because by then the presented token is spent
    /// and the session is over -- reporting success would only postpone the
    /// failure by one access-token lifetime.
    ///
    /// The sender constraint is re-proved here, not inherited, which is why the
    /// DPoP key has to outlive the access token it first obtained.
    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenResponse> {
        let assertion = self.client_assertion()?;
        self.token_request(
            "refresh",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", &self.client_id),
                ("client_assertion_type", ASSERTION_TYPE),
                ("client_assertion", &assertion),
            ],
            Some(refresh_token),
        )
        .await
    }

    async fn token_request(
        &self,
        step: &'static str,
        form: &[(&str, &str)],
        spent_refresh_token: Option<&str>,
    ) -> Result<TokenResponse> {
        let endpoint = self.metadata.token_endpoint.clone();
        let response = self
            .http
            .post(self.to_local(&endpoint)?)
            .header("DPoP", self.dpop_proof("POST", &endpoint, None)?)
            .form(form)
            .send()
            .await?;
        let raw: RawTokenResponse = Self::decode(response, step, &[StatusCode::OK]).await?;
        TokenResponse::accept(raw, step, spent_refresh_token)
    }

    /// The device grant's own token leg, which reads a 200 body this same way.
    pub(crate) fn accept_token_body(body: &str, step: &'static str) -> Result<TokenResponse> {
        TokenResponse::accept(serde_json::from_str(body)?, step, None)
    }

    /// A GET against a DPoP-protected resource.
    ///
    /// `endpoint` is the issuer-derived URL; the request itself goes to the
    /// socket. The proof carries `ath`, binding it to this specific token, and
    /// the `Authorization` scheme is `DPoP`, not `Bearer` -- presenting the
    /// same token as a Bearer is refused.
    ///
    /// The response is returned whatever its status, so a caller can assert on
    /// a refusal instead of only on success.
    pub async fn protected_get(
        &self,
        endpoint: &str,
        access_token: &str,
    ) -> Result<reqwest::Response> {
        Ok(self
            .http
            .get(self.to_local(endpoint)?)
            .header("Authorization", format!("DPoP {access_token}"))
            .header("DPoP", self.dpop_proof("GET", endpoint, Some(access_token))?)
            .send()
            .await?)
    }

    async fn decode<T: serde::de::DeserializeOwned>(
        response: reqwest::Response,
        step: &'static str,
        accepted: &[StatusCode],
    ) -> Result<T> {
        let status = response.status();
        let body = response.text().await?;
        if !accepted.contains(&status) {
            return Err(Error::response(step, status.as_u16(), body));
        }
        Ok(serde_json::from_str(&body)?)
    }
}
