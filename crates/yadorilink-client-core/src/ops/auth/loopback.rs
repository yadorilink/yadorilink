//! The loopback redirect a native OAuth client receives its authorization code
//! on (RFC 8252 §7.3).
//!
//! # Why this is written out rather than pulled in
//!
//! It is one accept, one request line, one reply. A web framework here would
//! be a dependency, a TLS stack and a router in exchange for parsing a query
//! string, and it would still have to be told all the things below that
//! actually matter.
//!
//! # What actually matters, and is therefore enforced here
//!
//! **It listens on the loopback interface only.** `127.0.0.1`, never
//! `0.0.0.0`: the authorization code arrives in a URL, and a listener on a
//! routable interface is a listener anything on the network can deliver a code
//! to -- or read one from, by being first to connect.
//!
//! **The port comes from the kernel.** Bound as port 0 and read back, so the
//! registered redirect URI names a port this process actually holds. A chosen
//! port is one a second `login`, or an unrelated program, may already have.
//!
//! **`state` is checked here, before the code is used.** The redirect is an
//! endpoint an attacker can drive: anything can open `http://127.0.0.1:<port>/
//! callback?code=...` on this machine. Checking `state` is what ties the code
//! that arrives to the authorization request this process actually made, so a
//! code injected by something else is refused rather than exchanged.
//!
//! **It answers exactly one request and then stops.** The listener is dropped
//! the moment it has an answer, so there is no port left open behind a finished
//! login.
//!
//! **It never echoes what it received.** The page says what happened in this
//! module's own words. Reflecting a query parameter into HTML on a page a
//! browser is already looking at is a cross-site scripting hole in a login
//! flow.

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use url::Url;

use crate::error::CoreError;

/// The path the redirect lands on. Part of the registered redirect URI, so it
/// is fixed for the life of a registration.
const CALLBACK_PATH: &str = "/cli/callback";

/// A bound loopback listener and the redirect URI that names it.
pub struct Listener {
    listener: TcpListener,
    redirect_uri: String,
}

impl Listener {
    /// Bind `127.0.0.1:0` and read back the port the kernel assigned.
    pub async fn bind() -> Result<Self, CoreError> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.map_err(|e| {
            CoreError::AuthFailed(format!(
                "could not open a loopback port to receive the sign-in redirect on: {e}"
            ))
        })?;
        let port = listener
            .local_addr()
            .map_err(|e| CoreError::AuthFailed(format!("the loopback port has no address: {e}")))?
            .port();
        Ok(Self { listener, redirect_uri: format!("http://127.0.0.1:{port}{CALLBACK_PATH}") })
    }

    /// The URI to register, and to push at PAR. The same string both times, by
    /// construction: the server compares them byte for byte.
    #[must_use]
    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    /// Wait for the browser to arrive, and return the authorization code.
    ///
    /// Consumes the listener: a login receives exactly one code, and a port
    /// still accepting connections after that is a port accepting a second one.
    pub async fn wait_for_code(
        self,
        expected_state: &str,
        expected_issuer: &str,
        timeout: Duration,
    ) -> Result<String, CoreError> {
        // Requests that are not the redirect -- a browser's `/favicon.ico`, a
        // port scanner, a stray `curl` -- are answered and ignored rather than
        // ending the login, but the overall wait is still bounded.
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let accepted = tokio::time::timeout_at(deadline, self.listener.accept()).await;
            let (stream, _) = match accepted {
                Err(_) => {
                    return Err(CoreError::AuthFailed(format!(
                        "no sign-in arrived within {} seconds. Run `yadorilink login` again and \
                         open the link it prints.",
                        timeout.as_secs()
                    )))
                }
                Ok(Ok(accepted)) => accepted,
                Ok(Err(e)) => {
                    return Err(CoreError::AuthFailed(format!(
                        "the loopback listener failed while waiting for the sign-in: {e}"
                    )))
                }
            };

            match self.serve_one(stream, expected_state, expected_issuer).await {
                Outcome::Code(code) => return Ok(code),
                Outcome::Refused(reason) => return Err(CoreError::AuthFailed(reason)),
                Outcome::NotTheRedirect => {}
            }
        }
    }

    async fn serve_one(
        &self,
        stream: TcpStream,
        expected_state: &str,
        expected_issuer: &str,
    ) -> Outcome {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        // Only the request line is read. The headers and any body are not
        // needed and reading them would mean trusting a length this process has
        // no reason to trust.
        if reader.read_line(&mut request_line).await.is_err() {
            return Outcome::NotTheRedirect;
        }

        let target = request_line.split_whitespace().nth(1).unwrap_or_default().to_owned();
        // A request target is origin-form (`/path?query`), so it is joined onto
        // a base rather than parsed as an absolute URL.
        let Ok(url) = Url::options()
            .base_url(Some(&Url::parse("http://127.0.0.1").expect("a literal base URL")))
            .parse(&target)
        else {
            reply(&mut reader, 400, "Not the sign-in redirect.").await;
            return Outcome::NotTheRedirect;
        };

        if url.path() != CALLBACK_PATH {
            reply(&mut reader, 404, "Not the sign-in redirect.").await;
            return Outcome::NotTheRedirect;
        }

        let mut code = None;
        let mut state = None;
        let mut error = None;
        let mut iss = None;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "code" => code = Some(value.into_owned()),
                "state" => state = Some(value.into_owned()),
                "error" => error = Some(value.into_owned()),
                "iss" => iss = Some(value.into_owned()),
                _ => {}
            }
        }

        // The state check comes FIRST, before the error is read and before the
        // code is touched. A redirect this process did not start says nothing
        // about this process's login, including when it says it failed.
        if state.as_deref() != Some(expected_state) {
            reply(&mut reader, 400, "This sign-in did not come from the login you started.").await;
            return Outcome::Refused(
                "the sign-in that came back does not match the one this command started; \
                 nothing was written to the credential store"
                    .to_owned(),
            );
        }

        // `iss` next, before the error/code are trusted: FAPI 2.0 Final
        // requires the Authorization Server to return an `iss` response
        // parameter and the client to verify it against the issuer this
        // login actually discovered against, precisely because `state`
        // alone does not rule out a mix-up attack -- a malicious or
        // misconfigured second Authorization Server that also happens to
        // learn this process's `state` value could otherwise redirect here
        // with its OWN code/error and be trusted as if it were the real
        // issuer. `oidc-provider` sends this unconditionally on every
        // authorization response; a redirect missing it, or naming a
        // different issuer, is refused the same way an unmatched `state` is.
        match iss.as_deref() {
            Some(actual) if actual == expected_issuer => {}
            Some(_) | None => {
                reply(&mut reader, 400, "This sign-in did not come from the expected server.")
                    .await;
                return Outcome::Refused(
                    "the sign-in's `iss` did not match the issuer this login discovered against; \
                     nothing was written to the credential store"
                        .to_owned(),
                );
            }
        }

        if let Some(error) = error {
            reply(&mut reader, 200, "You were not signed in. You can close this page.").await;
            // The server's own code, which is a fixed OAuth vocabulary, not
            // free text it chose: `access_denied`, `invalid_scope` and so on.
            return Outcome::Refused(format!(
                "the Authorization Server refused the sign-in ({error}); \
                 nothing was written to the credential store"
            ));
        }

        match code {
            Some(code) if !code.is_empty() => {
                reply(
                    &mut reader,
                    200,
                    "Signed in. You can close this page and go back to the terminal.",
                )
                .await;
                Outcome::Code(code)
            }
            _ => {
                reply(&mut reader, 400, "The sign-in did not complete.").await;
                Outcome::Refused(
                    "the sign-in came back with no authorization code; nothing was written to \
                     the credential store"
                        .to_owned(),
                )
            }
        }
    }
}

enum Outcome {
    Code(String),
    Refused(String),
    NotTheRedirect,
}

/// A complete, minimal HTTP/1.1 response. `message` is one of this module's own
/// literals -- nothing from the request reaches it.
async fn reply(reader: &mut BufReader<TcpStream>, status: u16, message: &str) {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Bad Request",
    };
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>YadoriLink</title></head><body><p>{message}</p></body></html>"
    );
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         content-type: text/html; charset=utf-8\r\n\
         content-length: {}\r\n\
         cache-control: no-store\r\n\
         connection: close\r\n\r\n{body}",
        body.len()
    );
    // A browser that has already gone away is not a failure of the login: the
    // code, if there was one, has been read.
    let _ = reader.get_mut().write_all(response.as_bytes()).await;
    let _ = reader.get_mut().shutdown().await;
}

/// 256 bits of `state`, which is the CSRF value tying the redirect to the
/// request this process pushed.
#[must_use]
pub fn random_state() -> String {
    yadorilink_fapi_client::Pkce::generate().verifier().to_owned()
}

#[cfg(test)]
mod tests;
