//! The authorization endpoint without a person at a browser.
//!
//! An enrolment opened with a pairing code (`crate::bootstrap`) leaves the
//! server holding the account's sign-in for the freshly registered client for a
//! short while, so the authorization request that follows finishes by itself:
//! the endpoint redirects to an interaction page, the page redirects back to
//! resume the request, and that redirects to the client's registered redirect
//! URI with a code. A browser would follow those redirects; this does the same,
//! and nothing more.
//!
//! What it deliberately does NOT do: it never renders or submits a page, never
//! talks to anything but the issuer's own socket, and gives up the moment the
//! server asks for a person (a page, or a redirect to an identity provider --
//! what happens when the handoff has run out). The redirect URI is never
//! dialed: its query is the result.

use std::time::Duration;

use url::Url;

use crate::client::FapiClient;
use crate::error::{Error, Result};

/// More redirects than the server's flow has (it uses three), fewer than a loop.
const MAX_HOPS: usize = 8;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HOP_TIMEOUT: Duration = Duration::from_secs(30);

/// The cookies a browser would keep between the hops: name and value, scoped
/// by path. One origin only, so no domain handling.
#[derive(Default)]
struct Jar {
    cookies: Vec<(String, String, String)>,
}

impl Jar {
    fn absorb(&mut self, headers: &reqwest::header::HeaderMap) {
        for line in headers.get_all(reqwest::header::SET_COOKIE) {
            let Ok(line) = line.to_str() else { continue };
            let mut parts = line.split(';').map(str::trim);
            let Some((name, value)) = parts.next().and_then(|pair| pair.split_once('=')) else {
                continue;
            };
            let mut path = "/".to_owned();
            let mut expired = value.is_empty();
            for attribute in parts {
                let lower = attribute.to_ascii_lowercase();
                if let Some(p) = lower.strip_prefix("path=") {
                    // Original case: paths are case sensitive.
                    path = attribute[attribute.len() - p.len()..].to_owned();
                } else if let Some(age) = lower.strip_prefix("max-age=") {
                    expired |= age.trim().parse::<i64>().is_ok_and(|age| age <= 0);
                }
            }
            self.cookies.retain(|(n, _, p)| !(n == name && *p == path));
            if !expired {
                self.cookies.push((name.to_owned(), value.to_owned(), path));
            }
        }
    }

    fn header_for(&self, request_path: &str) -> Option<String> {
        let pairs: Vec<String> = self
            .cookies
            .iter()
            .filter(|(_, _, path)| request_path.starts_with(path.as_str()))
            .map(|(name, value, _)| format!("{name}={value}"))
            .collect();
        (!pairs.is_empty()).then(|| pairs.join("; "))
    }
}

impl FapiClient {
    /// Follows the authorization request `request_uri` (pushed with
    /// [`FapiClient::push_authorization_request`]) to the redirect it ends in,
    /// without a browser, and returns that redirect's URL. The caller checks
    /// its `state` and `iss` and takes the `code`, exactly as it does for a
    /// redirect a browser delivered.
    ///
    /// # Errors
    /// [`Error::BrowserRequired`] when the server wants a person (it showed a
    /// page, or sent the request to an identity provider), which is what an
    /// expired pairing handoff looks like.
    pub async fn authorize_without_browser(
        &self,
        request_uri: &str,
        redirect_uri: &str,
    ) -> Result<Url> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(HOP_TIMEOUT)
            .build()?;
        let mut jar = Jar::default();
        let mut url = self.authorization_endpoint_url(request_uri)?;

        for _ in 0..MAX_HOPS {
            let mut request = http.get(url.clone());
            if let Some(cookie) = jar.header_for(url.path()) {
                request = request.header(reqwest::header::COOKIE, cookie);
            }
            let response = request.send().await?;
            jar.absorb(response.headers());

            let status = response.status();
            if !status.is_redirection() {
                return Err(Error::BrowserRequired(format!(
                    "the server answered HTTP {} instead of finishing the sign-in",
                    status.as_u16()
                )));
            }
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| {
                    Error::BrowserRequired("the server redirected to nowhere".to_owned())
                })?
                .to_owned();

            if let Some(rest) = location.strip_prefix(redirect_uri) {
                if rest.is_empty() || rest.starts_with('?') {
                    return Ok(Url::parse(&location)?);
                }
            }
            url = match self.to_local(&location) {
                Ok(local) => local,
                // Only the host is reported: the rest of the address can carry state.
                Err(_) => {
                    let host = Url::parse(&location)
                        .ok()
                        .and_then(|other| other.host_str().map(str::to_owned))
                        .unwrap_or_else(|| "another site".to_owned());
                    return Err(Error::BrowserRequired(format!(
                        "the sign-in was sent to {host}, which needs a person"
                    )));
                }
            };
        }
        Err(Error::BrowserRequired("the sign-in redirected too many times".to_owned()))
    }
}

#[cfg(test)]
mod tests;
