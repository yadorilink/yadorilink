//! The Authorization Server's metadata document (RFC 8414).
//!
//! Only the members this client actually uses are modelled. Everything else in
//! the document is ignored rather than rejected, so the server can advertise
//! more without breaking the client.
//!
//! # This is a profile requirement, not a capability negotiation
//!
//! This client talks to exactly one Authorization Server: the one configured in
//! the coordination service. Its discovery document is
//! not an unknown quantity to be probed and accommodated -- it is a fixed
//! profile this repository owns. So [`Metadata::unmet_profile_requirements`]
//! asks "does this server match the profile?", never "what can this server do
//! that I might also be able to do?".
//!
//! The difference shows up on the *absent* member. A negotiating client treats
//! an empty `code_challenge_methods_supported` as "unknown, probably fine"; a
//! profile client treats it as a server that has not said it will accept an
//! S256 challenge. Every capability below is a defence -- PAR keeps the
//! authorization request out of a browser-visible URL, PKCE binds the code to
//! the requester, `private_key_jwt` is the only client credential that exists
//! here, DPoP is the access token's only sender constraint -- and a defence
//! that is "probably" present is one this client will not rely on.

/// The subset of `/.well-known/openid-configuration` this client reads.
///
/// Every absolute URL here is **issuer-derived**: the server builds them from
/// its own configuration and knows nothing about the socket a client dialed.
/// They are the source of truth for DPoP `htu` and for the assertion audience;
/// the socket is only ever a transport detail.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// RFC 9126. Required by the profile, so this is `Option` only because the
    /// member can be absent on the wire -- a document without it never becomes
    /// a client.
    #[serde(default)]
    pub pushed_authorization_request_endpoint: Option<String>,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    /// RFC 8628. Absent until the deployment has `AS_DEVICE_SECRET` set and
    /// migration 0016 applied. This is the one capability the profile treats as
    /// optional, because a deployment without the device grant is a correct
    /// deployment; what the profile requires is that it be advertised
    /// coherently -- endpoint and grant type together, or neither.
    #[serde(default)]
    pub device_authorization_endpoint: Option<String>,
    /// RFC 7591. Present once the registration feature is enabled. This client
    /// never posts to it directly -- it is unsatisfiable without an Initial
    /// Access Token that never leaves the Worker -- but its presence is how a
    /// client can tell a deployment that supports enrolment from one that does
    /// not.
    #[serde(default)]
    pub registration_endpoint: Option<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    pub dpop_signing_alg_values_supported: Vec<String>,
}

/// The grant type identifier for the authorization-code flow.
const AUTHORIZATION_CODE_GRANT: &str = "authorization_code";
/// The grant type identifier for refresh. Without it every session this client
/// establishes is one access-token lifetime long.
const REFRESH_TOKEN_GRANT: &str = "refresh_token";

impl Metadata {
    /// Whether the server offers the RFC 8628 device grant.
    ///
    /// Reads one member because [`Metadata::unmet_profile_requirements`] has
    /// already established that the endpoint and the grant type agree -- a
    /// document where they disagree never becomes a [`crate::FapiClient`], so
    /// there is no state here for a second check to disambiguate.
    #[must_use]
    pub fn supports_device_grant(&self) -> bool {
        self.device_authorization_endpoint.is_some()
    }

    /// Everything the profile requires that this document does not carry.
    ///
    /// Empty means the server is the one this client was written against. Each
    /// entry is written as `member: why`, where `member` is the discovery
    /// document's own member name -- that name is the stable identifier, and
    /// `tests/server_profile.rs` pins one test per capability against it, so a
    /// server that quietly stops advertising one is caught by name.
    ///
    /// Called by [`crate::FapiClient::discover`] *and* by
    /// [`crate::FapiClient::from_metadata`]: `Metadata`'s fields are public, so
    /// checking only on the fetch path would leave the gate advisory.
    #[must_use]
    pub fn unmet_profile_requirements(&self) -> Vec<String> {
        let mut unmet = Vec::new();

        if self.pushed_authorization_request_endpoint.as_ref().is_none_or(|e| e.trim().is_empty()) {
            unmet.push(
                "pushed_authorization_request_endpoint: this client sends every authorization \
                 request through PAR, and the server advertises no endpoint to send it to"
                    .to_owned(),
            );
        }
        if !self.require_pushed_authorization_requests {
            unmet.push(
                "require_pushed_authorization_requests: the server does not require PAR, so an \
                 authorization request can still be carried in a browser-visible URL"
                    .to_owned(),
            );
        }

        self.require_advertised(
            &mut unmet,
            "code_challenge_methods_supported",
            &self.code_challenge_methods_supported,
            "S256",
            "this client binds every authorization code with PKCE S256",
        );
        // These three are EXACT matches, not "contains": there is exactly one
        // Authorization Server this client talks to, it authenticates with
        // exactly one method and signs exactly one algorithm on each of these
        // two surfaces, and a document advertising anything wider is not
        // describing looser compatibility this client can ignore -- it is
        // describing a resource server (or, for the assertion algorithm, a
        // token endpoint) that would accept a credential this client never
        // signs, which is a real widening of what a captured credential could
        // be replayed as, not a cosmetic difference in the document.
        self.require_exact(
            &mut unmet,
            "token_endpoint_auth_methods_supported",
            &self.token_endpoint_auth_methods_supported,
            &["private_key_jwt"],
            "this client holds an ES256 key and no client secret, and no other method exists to \
             fall back to",
        );
        self.require_exact(
            &mut unmet,
            "token_endpoint_auth_signing_alg_values_supported",
            &self.token_endpoint_auth_signing_alg_values_supported,
            &["ES256"],
            "this client signs its client assertions with ES256 and nothing else, so a server \
             accepting a second algorithm accepts a client assertion this client will never \
             produce -- from somewhere else",
        );
        self.require_exact(
            &mut unmet,
            "dpop_signing_alg_values_supported",
            &self.dpop_signing_alg_values_supported,
            &["ES256"],
            "DPoP is the access token's only sender constraint and this client's proofs are \
             ES256 and nothing else; a resource server that also verifies Ed25519 or EdDSA \
             proofs is a wider attack surface than the profile this client was checked against",
        );
        self.require_advertised(
            &mut unmet,
            "grant_types_supported",
            &self.grant_types_supported,
            AUTHORIZATION_CODE_GRANT,
            "this client enrols over the authorization-code flow",
        );
        self.require_advertised(
            &mut unmet,
            "grant_types_supported",
            &self.grant_types_supported,
            REFRESH_TOKEN_GRANT,
            "without it every session is one access-token lifetime long",
        );

        // The device grant is optional; advertising half of it is not. An
        // endpoint with no grant type is a door the token endpoint refuses to
        // open, and a grant type with no endpoint is a flow with nowhere to
        // start -- both of which are discovered at the point of use, after the
        // user has been asked to do something.
        let endpoint = self.device_authorization_endpoint.is_some();
        let grant = self.grant_types_supported.iter().any(|g| g == crate::DEVICE_CODE_GRANT);
        if endpoint != grant {
            unmet.push(format!(
                "device_authorization_endpoint: the device grant is advertised on one half only \
                 (endpoint {}, `{}` in grant_types_supported {}); a deployment either offers it \
                 or does not",
                if endpoint { "present" } else { "absent" },
                crate::DEVICE_CODE_GRANT,
                if grant { "present" } else { "absent" },
            ));
        }

        unmet
    }

    /// One "the server must advertise `value` in `member`" requirement.
    ///
    /// An empty list fails exactly like a list of the wrong values: both are a
    /// server that has not said it will accept what this client sends.
    fn require_advertised(
        &self,
        unmet: &mut Vec<String>,
        member: &'static str,
        advertised: &[String],
        value: &str,
        why: &str,
    ) {
        if !advertised.iter().any(|entry| entry == value) {
            unmet.push(format!(
                "{member}: `{value}` is not advertised (the server offers {advertised:?}); {why}"
            ));
        }
    }

    /// One "the server must advertise EXACTLY `expected` in `member`, no
    /// more and no fewer" requirement.
    ///
    /// Stricter than [`Self::require_advertised`] on purpose, for the members
    /// where a WIDER document is itself the failure this client cares about:
    /// this is a fixed profile against one deployment, not a capability
    /// negotiation, so "the server also accepts something else" is not slack
    /// to tolerate, it is a resource or token endpoint validating a
    /// credential shape wider than the one this client was checked against.
    /// Compared as a set: order and duplicates in the document do not matter,
    /// membership does.
    fn require_exact(
        &self,
        unmet: &mut Vec<String>,
        member: &'static str,
        advertised: &[String],
        expected: &[&str],
        why: &str,
    ) {
        let advertised_set: std::collections::BTreeSet<&str> =
            advertised.iter().map(String::as_str).collect();
        let expected_set: std::collections::BTreeSet<&str> = expected.iter().copied().collect();
        if advertised_set != expected_set {
            unmet.push(format!(
                "{member}: expected exactly {expected:?}, the server advertises {advertised:?}; \
                 {why}"
            ));
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Metadata {
    /// The deployed server's discovery document, for the fixtures that need a
    /// client without a server behind it.
    ///
    /// Not a lenient stand-in: it is the profile
    /// [`Metadata::unmet_profile_requirements`] demands, so a fixture cannot
    /// accidentally become the one place a client exists over a document the
    /// product would refuse.
    pub(crate) fn deployed_profile(issuer: &str) -> Self {
        serde_json::from_value(serde_json::json!({
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
        }))
        .expect("the deployed profile parses")
    }
}

#[cfg(test)]
mod tests;
