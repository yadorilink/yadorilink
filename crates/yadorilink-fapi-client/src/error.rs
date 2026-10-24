//! Errors this client can produce.

use std::fmt;

/// An OAuth 2.0 / OpenID Connect error response body, as returned by the
/// Authorization Server. Kept whole rather than flattened into a message, so a
/// caller can branch on `error` (for example `invalid_dpop_proof` versus
/// `invalid_client`, which otherwise look identical in a log line).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct OauthError {
    pub error: String,
    #[serde(default)]
    pub error_description: Option<String>,
}

impl fmt::Display for OauthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.error_description {
            Some(detail) => write!(f, "{}: {detail}", self.error),
            None => write!(f, "{}", self.error),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP transport failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),

    #[error("could not parse JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// The key material on disk (or handed in) is not a usable ES256 key.
    #[error("invalid ES256 key: {0}")]
    Key(String),

    /// The Authorization Server answered with a status this step does not
    /// accept. `body` is retained verbatim because FAPI error bodies are
    /// deliberately terse and the status alone rarely identifies the cause.
    #[error("{step} returned HTTP {status}: {body}")]
    Response { step: &'static str, status: u16, body: String, parsed: Option<OauthError> },

    /// A discovery document that does not carry an endpoint this client needs.
    #[error("the Authorization Server's metadata has no `{0}`")]
    MissingMetadata(&'static str),

    /// The token endpoint answered 200 with something that is not a usable
    /// credential on this deployment's profile: not DPoP-typed, with no real
    /// lifetime, or -- the expensive one -- a refresh that did not rotate.
    ///
    /// Distinct from [`Error::Response`], which is the server *refusing*. This
    /// is the server succeeding and handing back a session that is already
    /// broken; the difference matters because only one of the two is worth
    /// retrying, and neither is worth continuing from.
    ///
    /// `requirement` begins with the response member it is about, so a caller
    /// and a test can tell `expires_in` from `refresh_token` without parsing
    /// prose.
    #[error("the {step} response is not a usable credential -- {requirement}")]
    UnusableTokenResponse { step: &'static str, requirement: String },

    /// An absolute URL the server emitted did not start with the issuer, so it
    /// cannot be mapped back onto the socket this client is really dialing.
    #[error("`{url}` is not under the issuer `{issuer}`")]
    NotUnderIssuer { url: String, issuer: String },

    /// The server's advertised capabilities and this client's do not overlap.
    /// Reported at construction rather than as an opaque refusal several
    /// requests later.
    #[error("this client cannot use this Authorization Server: {}", .0.join("; "))]
    UnsupportedServer(Vec<String>),

    /// The credential store holds nothing, so this installation has never
    /// enrolled. Distinct from a damaged store, which is [`Error::Store`]:
    /// this one is answered by logging in, and that one is not.
    #[error("this installation is not enrolled; run `yadorilink login` first")]
    NotEnrolled,

    /// The store now names a different installation (`client_id`) than the
    /// one this process authenticates as -- a `logout`/`login` registered a
    /// new client while this process kept running. Presenting the new
    /// installation's refresh token with the old client's identity can only
    /// end in `invalid_client`, so the refresh is refused before it is sent.
    #[error(
        "the stored sign-in belongs to installation {stored:?}, but this process authenticates \
         as {running:?}; the sign-in changed after it started, so restart it"
    )]
    InstallationChanged { running: String, stored: String },

    /// The stored credential belongs to a different Authorization Server than
    /// the one being dialed. Without this the failure is an `invalid_client`
    /// that names neither issuer.
    #[error(
        "the stored credential was issued by `{stored}` but this server is `{discovered}`; \
         enrol against one of them rather than mixing deployments"
    )]
    IssuerMismatch { stored: String, discovered: String },

    /// A registration completed but produced something this client refuses to
    /// hold.
    #[error("client registration: {0}")]
    Registration(String),

    /// A [`crate::Reload`] could not build a manager over the credential the
    /// store holds now.
    #[error("could not follow the credential store to a new sign-in: {0}")]
    Reload(String),

    /// The device code's own `expires_in` elapsed while polling.
    #[error("the device authorization expired before it was approved")]
    DeviceAuthorizationExpired,

    /// The credential store refused.
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),

    /// The socket a caller asked this crate to dial is neither `https://` nor
    /// loopback. Refused before anything -- including discovery -- is sent to
    /// it: a non-loopback `http://` socket cannot be a real deployment's
    /// issuer, which always speaks https, and is not a supported
    /// local-development override either.
    #[error(
        "refusing to dial `{0}`: only an https:// socket or a loopback http:// socket may \
         receive a client credential"
    )]
    UntrustedSocket(String),

    /// The socket actually dialed is `https://` but a different origin than
    /// the issuer discovery reported. A loopback socket is allowed to diverge
    /// from the issuer (a local `wrangler dev`); a non-loopback one is not --
    /// the issuer is the only non-loopback origin this client will ever send a
    /// refresh token, a client assertion or a DPoP proof to.
    #[error(
        "`{socket}` is not the issuer `{issuer}` and is not a loopback socket; refusing to send \
         a credential to it"
    )]
    UntrustedIssuerMismatch { socket: String, issuer: String },

    /// A minted credential (the access token or a DPoP proof) contains bytes
    /// `http::HeaderValue` refuses. Neither is expected in practice -- the
    /// access token is server-issued opaque ASCII and a proof is base64url --
    /// but [`CoordinationAuth::execute`](crate::CoordinationAuth::execute)
    /// checks anyway rather than let a malformed value panic inside `reqwest`.
    #[error("{0}")]
    InvalidHeaderValue(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub(crate) fn response(step: &'static str, status: u16, body: String) -> Self {
        let parsed = serde_json::from_str::<OauthError>(&body).ok();
        Error::Response { step, status, body, parsed }
    }

    /// The OAuth `error` code, when the server sent a structured error body.
    #[must_use]
    pub fn oauth_error(&self) -> Option<&str> {
        match self {
            Error::Response { parsed, .. } => parsed.as_ref().map(|e| e.error.as_str()),
            _ => None,
        }
    }

    /// Whether the Authorization Server refused a refresh or a grant with
    /// `invalid_grant` (HTTP 400). This installation's grant is not usable now:
    /// a revoked or reused refresh token, or an account that has not accepted
    /// the current Terms. It says nothing about the client registration, and
    /// the stored credential is kept.
    #[must_use]
    pub fn is_invalid_grant(&self) -> bool {
        matches!(self, Error::Response { status: 400, .. })
            && self.oauth_error() == Some("invalid_grant")
    }

    /// The HTTP status, when the failure came from a response rather than the
    /// transport.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Response { status, .. } => Some(*status),
            _ => None,
        }
    }
}
