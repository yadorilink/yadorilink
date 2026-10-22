//! The RFC 8628 device authorization grant -- enrolment on a host with no
//! browser.
//!
//! # Why the product needs it
//!
//! The authorization-code flow needs a user agent on the same machine and a
//! loopback listener to catch the redirect. A headless Linux host has neither.
//! The device grant moves the browser leg to whatever device the user already
//! has one on, and leaves this process polling.
//!
//! # The three things this server does that the RFC does not describe
//!
//! 1. **`POST /device/auth` is client-authenticated.** `private_key_jwt` with
//!    the installation's ES256 key, exactly like the token endpoint. RFC 8628
//!    describes a public client sending only `client_id`; this deployment
//!    registers confidential clients, so an unauthenticated device
//!    authorization request is refused.
//! 2. **No DPoP proof at `/device/auth`.** The library adds `dpop_jkt` to the
//!    parameter allow-list for the authorization and PAR endpoints only, so
//!    the device-authorization request pins no key and a proof sent there
//!    would be ignored. The sender constraint is established at `/token`, on
//!    whichever key signs the proof there.
//! 3. **`interval` and `slow_down` are YadoriLink's, not the library's.**
//!    `oidc-provider` 9.12.0 implements neither; the Worker wraps the endpoint
//!    to supply `interval` and to answer `slow_down`. A client that ignores
//!    `slow_down` therefore gets it from a real rate decision, not from a
//!    library default, and RFC 8628 section 3.5's "add five seconds" is the
//!    correct response.
//!
//! # `offline_access` without `prompt=consent`
//!
//! The authorization-code flow only receives a refresh token when the pushed
//! request carried `prompt=consent` (measured against the deployed server). The
//! device flow does not: `prompt` is not in the device endpoints' parameter
//! allow-list at all, and `check_scope.js` only strips `offline_access` over a
//! missing consent prompt when `prompt` is a parameter of that endpoint. So
//! the scope alone is enough here, and sending `prompt` would be rejected as
//! an unknown parameter rather than helping.

use std::time::Duration;

use crate::client::{FapiClient, TokenResponse};
use crate::error::{Error, Result};

/// The grant type identifier, and the value that appears in
/// `grant_types_supported` when the deployment has the feature on.
pub const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// What the server hands back from `POST /device/auth`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct DeviceAuthorization {
    /// Presented at the token endpoint. A credential: it is what the polling
    /// process holds, and anyone else holding it can deny the enrolment by
    /// consuming its poll slot.
    pub device_code: String,
    /// Shown to the user. Twelve characters from a twenty-character alphabet;
    /// the entropy is what stands in for the rate limiter this deployment has
    /// no Durable Object to build.
    pub user_code: String,
    pub verification_uri: String,
    /// The URI with the code already in it (RFC 8628 section 3.3.1). When the
    /// server sends it, it is what [`DeviceAuthorization::instructions`]
    /// prints, so nobody has to type the code.
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    /// Seconds between polls. RFC 8628 defaults it to 5 when absent.
    #[serde(default)]
    pub interval: Option<u64>,
}

impl DeviceAuthorization {
    /// What to show the user. With `verification_uri_complete`: one link that
    /// already carries the code, plus the code to compare against the page
    /// it opens. Without it: the bare verification URI and the code to type.
    #[must_use]
    pub fn instructions(&self) -> String {
        match &self.verification_uri_complete {
            Some(complete) => format!(
                "To finish signing in, open this link on any device (your phone is fine) and \
                 check that the code shown there matches:\n\n  {complete}\n\n  Code: {}\n",
                self.user_code
            ),
            None => format!(
                "To finish signing in, open {} on any device and enter this code:\n\n    {}\n",
                self.verification_uri, self.user_code
            ),
        }
    }

    #[must_use]
    pub fn poll_interval(&self) -> Duration {
        // RFC 8628 section 3.2: absent means five seconds.
        Duration::from_secs(self.interval.unwrap_or(5).max(1))
    }
}

/// One poll's outcome.
#[derive(Debug)]
pub enum DevicePoll {
    /// The user has not finished yet. Keep the interval.
    Pending,
    /// Polled too fast. RFC 8628 section 3.5: add five seconds, permanently.
    SlowDown,
    /// Done.
    Granted(Box<TokenResponse>),
}

impl FapiClient {
    /// Begin a device authorization.
    ///
    /// `scope` must include `offline_access` to receive a refresh token, and
    /// `openid` to receive a subject.
    pub async fn request_device_authorization(&self, scope: &str) -> Result<DeviceAuthorization> {
        let endpoint = self
            .metadata()
            .device_authorization_endpoint
            .clone()
            .ok_or(Error::MissingMetadata("device_authorization_endpoint"))?;

        let assertion = self.client_assertion()?;
        let form = [
            ("client_id", self.client_id()),
            ("scope", scope),
            ("client_assertion_type", crate::assertion::ASSERTION_TYPE),
            ("client_assertion", &assertion),
        ];

        let response = self.http().post(self.to_local(&endpoint)?).form(&form).send().await?;
        let status = response.status();
        let body = response.text().await?;
        if status != reqwest::StatusCode::OK {
            return Err(Error::response("device authorization", status.as_u16(), body));
        }
        Ok(serde_json::from_str(&body)?)
    }

    /// Present the device code once.
    ///
    /// The three RFC 8628 pending states are outcomes rather than errors,
    /// because a polling loop has to distinguish them; everything else --
    /// `expired_token`, `access_denied`, a refused client -- is an error,
    /// because none of them is improved by polling again.
    pub async fn poll_device_authorization(&self, device_code: &str) -> Result<DevicePoll> {
        let endpoint = self.metadata().token_endpoint.clone();
        let assertion = self.client_assertion()?;
        let form = [
            ("grant_type", DEVICE_CODE_GRANT),
            ("device_code", device_code),
            ("client_id", self.client_id()),
            ("client_assertion_type", crate::assertion::ASSERTION_TYPE),
            ("client_assertion", &assertion),
        ];

        let response = self
            .http()
            .post(self.to_local(&endpoint)?)
            // The registration sets `dpop_bound_access_tokens`, so this proof
            // is mandatory rather than optional, and the key that signs it is
            // the key the issued access token is bound to.
            .header("DPoP", self.dpop_proof("POST", &endpoint, None)?)
            .form(&form)
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await?;
        if status == reqwest::StatusCode::OK {
            // The same profile check the other two token legs run. A device
            // grant is how a headless host enrols, so a response with no
            // refresh token here is an installation that can never refresh --
            // discovered now rather than at the first expiry.
            return Ok(DevicePoll::Granted(Box::new(FapiClient::accept_token_body(
                &body,
                "device token",
            )?)));
        }

        let error = Error::response("device token", status.as_u16(), body);
        match error.oauth_error() {
            Some("authorization_pending") => Ok(DevicePoll::Pending),
            Some("slow_down") => Ok(DevicePoll::SlowDown),
            _ => Err(error),
        }
    }

    /// Poll to completion.
    ///
    /// Stops at the server's own `expires_in` rather than polling forever, and
    /// widens the interval by five seconds on every `slow_down` and keeps it
    /// widened, which is what RFC 8628 section 3.5 specifies -- a client that
    /// narrows back is the reason the server has to answer `slow_down` twice.
    pub async fn complete_device_authorization(
        &self,
        authorization: &DeviceAuthorization,
    ) -> Result<TokenResponse> {
        let deadline =
            std::time::Instant::now() + Duration::from_secs(authorization.expires_in.max(1));
        let mut interval = authorization.poll_interval();

        loop {
            tokio::time::sleep(interval).await;
            if std::time::Instant::now() >= deadline {
                return Err(Error::DeviceAuthorizationExpired);
            }
            match self.poll_device_authorization(&authorization.device_code).await? {
                DevicePoll::Granted(tokens) => return Ok(*tokens),
                DevicePoll::Pending => {}
                DevicePoll::SlowDown => interval += Duration::from_secs(5),
            }
        }
    }
}

#[cfg(test)]
mod tests;
