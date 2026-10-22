//! Fresh-install enrolment: how an installation holding NO credential of any
//! kind obtains a `client_id`.
//!
//! # The cycle this breaks
//!
//! Enrolment used to be one request, `POST /bootstrap/client`, gated on a
//! Google ID token the installation had to already hold. A shipped binary
//! cannot obtain one -- Google's desktop client type needs a secret at the code
//! exchange, and the Worker deliberately never returns the ID token it verifies
//! -- so that gate asked the installation to prove an identity it had no way to
//! get. The fix is not a different credential in the same request; it is to
//! move the identity leg off the installation entirely:
//!
//! ```text
//!   1. this process generates its ES256 client key
//!   2. POST /bootstrap/start { public JWK, loopback redirect URIs }
//!        -> a high-entropy handle and an approval URL
//!   3. a HUMAN opens the approval URL and signs in at the upstream, in a
//!      browser, on the server's side of the wire
//!   4. the server performs the RFC 7591 registration for the key from step 1
//!   5. POST /bootstrap/poll { handle } -> the registration, exactly once
//! ```
//!
//! # This is not RFC 8628, and the difference is not cosmetic
//!
//! A device grant logs an EXISTING client in: every device authorization is
//! made by an authenticated `client_id`, and what it yields is a token. This
//! runs BEFORE any client exists -- there is nothing to authenticate the
//! request with, because the whole point is that the caller has no identity yet
//! -- and what it yields is a REGISTRATION. They share a shape (open, poll,
//! approve in a browser) and share nothing else. RFC 8628 stays what it is here:
//! the headless LOGIN path ([`crate::DeviceAuthorization`]), for an installation
//! that has already been through this module.
//!
//! # What this process supplies, and what it cannot
//!
//! The **public** half of a freshly generated client key, and its loopback
//! redirect URIs. Everything else -- the authentication method, both signature
//! algorithms, the grant types, `dpop_bound_access_tokens` -- is server-fixed
//! and the policy overwrites whatever the body said, so there is nothing to
//! negotiate and this module does not offer a way to try.
//!
//! Nothing later in the flow can substitute a key: the approval leg and the
//! poll have no field to carry one, and the server registers the key captured
//! when the transaction opened. This module could not offer a second key even
//! if a caller asked it to.
//!
//! # One enrolment, one identity
//!
//! Every completed transaction mints a new `client_id` from fresh randomness.
//! Re-enrolling after a revocation is a *new* identity, never a repair of the
//! old one, so a caller must persist what
//! comes back rather than assume it can re-derive it.

use std::fmt;
use std::time::Duration;

use url::Url;

use crate::client::ensure_trusted_socket;
use crate::error::{Error, Result};
use crate::jws::{jti, now_secs};
use crate::key::Es256Key;

/// Where an installation opens a transaction.
pub const BOOTSTRAP_START_PATH: &str = "/bootstrap/start";

/// Where an installation collects its `client_id`.
pub const BOOTSTRAP_POLL_PATH: &str = "/bootstrap/poll";

/// The code the poll answers with for everything that is not a completed
/// enrolment: unknown handle, pending, expired, already redeemed, malformed.
///
/// Named here because the distinction a caller needs -- "keep waiting" versus
/// "this failed" -- is exactly this one string, and the server deliberately
/// gives it no finer answer: a poll that distinguished "unknown" from "pending"
/// would tell a stranger whether a guessed handle exists.
const AUTHORIZATION_PENDING: &str = "authorization_pending";

/// What a fresh installation asks to be registered as.
#[derive(Debug)]
pub struct EnrolmentRequest<'a> {
    /// The loopback URIs this installation will receive its redirect on. The
    /// port is the one field a native application genuinely has to choose at
    /// run time, which is why it is the one field the server does not fix.
    pub redirect_uris: &'a [String],
    /// A display label, shown to the human on the approval page. Not an
    /// identifier, and not trusted as one.
    pub client_name: Option<&'a str>,
}

/// An open transaction: what the installation holds while a human approves it.
///
/// The handle is a bearer secret -- whoever holds it collects the registration
/// -- so it is deliberately not reachable as a `&str` and not printed by
/// [`fmt::Debug`]. It exists to be handed back to [`poll_enrolment`], which is
/// in this module, so there is no reason for it to leave.
///
/// `transport_base` and `canonical_issuer` are fixed HERE, at open time, and
/// neither [`poll_enrolment`] nor [`complete_enrolment`] takes a `base_url`
/// argument of its own. That is load-bearing rather than tidiness: a poll
/// used to take its own `base_url`, independently of the one `open_enrolment`
/// had already validated, which meant a caller -- by a bug, a stale variable,
/// a misconfigured override read a second time -- could open a transaction
/// against the real Authorization Server and then poll a DIFFERENT socket
/// with the resulting handle and a valid, correctly-keyed proof. A poll
/// endpoint under an attacker's control cannot forge that proof itself (it
/// does not hold the private key), but it can RELAY the handle and proof it
/// just received on to the real server and consume the one-shot registration
/// before the legitimate installation's own next poll does -- a denial of
/// service that needs no key at all, only a socket the caller was persuaded
/// to dial. Fixing both values at open time and refusing to accept them again
/// removes the argument that would let that relay happen.
pub struct PendingEnrolment {
    handle: String,
    /// The URL a human must open to approve this enrolment. It carries a
    /// DIFFERENT secret from the handle, so printing it -- which is the whole
    /// point of it -- does not print the value the registration is collected
    /// with.
    pub approval_uri: String,
    /// How long the transaction lives. The server's number, not a local guess:
    /// polling past it can only ever return "pending".
    pub expires_in: Duration,
    /// How long to wait between polls, as the server advises.
    pub poll_interval: Duration,
    /// The socket [`open_enrolment`] actually dialed, already checked by
    /// [`ensure_trusted_socket`]. Every later request in this transaction's
    /// life goes here and nowhere else.
    transport_base: Url,
    /// This deployment's issuer, read from its own discovery document at open
    /// time. What a poll proof's `htu` is signed against, and what the server
    /// checks it against -- never the socket, for the same reason `htu` is
    /// never the socket for a DPoP proof (`crate::coordination`).
    canonical_issuer: String,
}

impl fmt::Debug for PendingEnrolment {
    /// Every field but the handle, which is redacted rather than omitted so a
    /// reader of a log line can see that one was held.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingEnrolment")
            .field("handle", &"<redacted>")
            .field("approval_uri", &self.approval_uri)
            .field("expires_in", &self.expires_in)
            .field("poll_interval", &self.poll_interval)
            .field("transport_base", &self.transport_base.as_str())
            .field("canonical_issuer", &self.canonical_issuer)
            .finish()
    }
}

/// What the server registered.
///
/// The full metadata is kept as well as the field this client reads, because
/// the server is the authority on what the registration says and a later
/// surface (a "your devices" list) should read the server's words rather than
/// this crate's model of them.
#[derive(Debug, Clone)]
pub struct Registration {
    pub client_id: String,
    pub metadata: serde_json::Value,
}

/// What one poll found.
#[derive(Debug)]
pub enum EnrolmentPoll {
    /// The human has not finished approving. Indistinguishable, by design, from
    /// a handle that never existed or has already been redeemed.
    Pending,
    /// The registration, which this handle will never produce again.
    Registered(Registration),
}

#[derive(serde::Deserialize)]
struct StartResponse {
    bootstrap_handle: String,
    approval_uri: String,
    expires_in: u64,
    poll_interval_seconds: u64,
}

/// Open a transaction: send the public key, receive a handle and a link for a
/// human.
///
/// The key is generated by the caller and only its public half is sent. The
/// private half never leaves the process except through
/// [`Es256Key::to_jwk_json`] into the credential store, which is the caller's
/// own later step: persisting a credential and obtaining one are separate
/// concerns, and an enrolment that succeeded but could not be saved has to be
/// visible as exactly that.
///
/// This request carries no credential, and cannot: the caller has no identity
/// yet. What it creates is a short-lived row that grants nothing until a human
/// has signed in.
pub async fn open_enrolment(
    http: &reqwest::Client,
    base_url: &str,
    client_key: &Es256Key,
    request: &EnrolmentRequest<'_>,
) -> Result<PendingEnrolment> {
    let base_url = Url::parse(base_url)?;
    // No issuer is known yet -- this is the transaction that will eventually
    // produce a registration, not a request against one -- so this is the
    // weaker, pre-discovery half of the check `FapiClient::discover` applies:
    // the socket has to be https or loopback before it receives so much as
    // this installation's public key.
    ensure_trusted_socket(&base_url)?;

    // The issuer this transaction's poll proofs will be signed against, fixed
    // here alongside the socket. Read from the deployment's own discovery
    // document rather than assumed to be `base_url` itself: a local override
    // dials a loopback socket while the issuer stays the deployed hostname,
    // exactly the split every DPoP proof in this crate already respects.
    let canonical_issuer = discover_issuer(http, &base_url).await?;

    let endpoint = base_url.join(BOOTSTRAP_START_PATH)?;

    let body = serde_json::json!({
        // A JWK *set*, because RFC 7591 registers `jwks`, and with the public
        // half only: the server refuses a key carrying private parameters, and
        // rightly.
        "jwks": { "keys": [client_key.public_jwk()] },
        "redirect_uris": request.redirect_uris,
        "client_name": request.client_name,
    });

    let response = http.post(endpoint).json(&body).send().await?;
    let status = response.status();
    let text = response.text().await?;
    if status != reqwest::StatusCode::CREATED {
        return Err(Error::response("opening a bootstrap transaction", status.as_u16(), text));
    }

    let started: StartResponse = serde_json::from_str(&text)?;
    // A transaction with no life left is not an enrolment in progress, it is a
    // loop that will only ever print "still waiting". Better to say so here
    // than after ten minutes of polling.
    if started.expires_in == 0 {
        return Err(Error::Registration(
            "the server opened a bootstrap transaction that had already expired".to_owned(),
        ));
    }

    Ok(PendingEnrolment {
        handle: started.bootstrap_handle,
        approval_uri: started.approval_uri,
        expires_in: Duration::from_secs(started.expires_in),
        // Zero would busy-loop against the server; one second is the floor RFC
        // 8628 uses for the same advisory field, for the same reason.
        poll_interval: Duration::from_secs(started.poll_interval_seconds.max(1)),
        transport_base: base_url,
        canonical_issuer,
    })
}

/// The `issuer` field alone, off this deployment's own discovery document.
///
/// A full [`crate::Metadata`] fetch and profile check is not what this needs
/// -- there is no client yet for a profile to apply to, and no endpoint here
/// is chosen from the document. Only the issuer identifier is read, and only
/// to bind a poll proof's `htu` to it.
async fn discover_issuer(http: &reqwest::Client, base_url: &Url) -> Result<String> {
    #[derive(serde::Deserialize)]
    struct IssuerOnly {
        issuer: String,
    }

    let well_known = base_url.join("/.well-known/openid-configuration")?;
    let response = http.get(well_known).send().await?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        return Err(Error::response("bootstrap discovery", status.as_u16(), text));
    }
    let doc: IssuerOnly = serde_json::from_str(&text)?;
    if doc.issuer.is_empty() {
        return Err(Error::MissingMetadata("issuer"));
    }
    Ok(doc.issuer)
}

/// One signed proof that whoever is polling `handle` holds the private half
/// of the key captured at `/bootstrap/start`.
///
/// Shaped like a DPoP proof -- an ES256 JWS whose protected header carries the
/// public key, so the server can verify it without having seen the key before
/// -- and, since a review of the first version of this proof found it worth
/// having, now carrying `htm`/`htu` exactly as a DPoP proof does: `htm` is
/// always `POST` and `htu` is the ISSUER-derived poll endpoint, never the
/// socket. That binds the proof to one operation at one deployment rather
/// than to bare possession of the key: a proof minted here verifies at no
/// endpoint but this deployment's own `/bootstrap/poll`, so a relay that
/// forwards a captured handle-and-proof pair to a different Authorization
/// Server -- or a different endpoint of this one -- gets a proof that fails
/// its own `htu` check there. `bootstrap_handle` additionally stops a proof
/// minted while polling one transaction from meaning anything against a
/// different one the same key happens to be trying to redeem, and `jti` is
/// what stops the exact same proof from being replayed against this one --
/// the server spends it in the same replay store a DPoP proof's `jti` is
/// spent in.
fn poll_proof(client_key: &Es256Key, htu: &str, handle: &str) -> Result<String> {
    let claims = serde_json::json!({
        "htm": "POST",
        "htu": htu,
        "iat": now_secs(),
        "jti": jti(),
        "bootstrap_handle": handle,
    });
    client_key.sign_compact(
        &serde_json::json!({
            "alg": "ES256",
            "typ": "bootstrap-poll+jwt",
            "jwk": client_key.public_jwk(),
        }),
        &claims,
    )
}

/// Ask once whether the transaction has been approved.
///
/// A 200 is the registration and the row behind it is gone: the server answers
/// a successful poll with a `DELETE ... RETURNING`, so this handle will report
/// [`EnrolmentPoll::Pending`] forever afterwards. That is why the caller has to
/// persist what comes back -- there is no second chance to ask for it.
///
/// `client_key` must be the same key [`open_enrolment`] sent to
/// `/bootstrap/start`: the server collects the registration only for a poll
/// that proves possession of the key the transaction was opened with, so
/// stealing the handle alone -- from a log line, a shared clipboard, a process
/// listing -- is not enough to collect a registration that belongs to someone
/// else's key.
///
/// Takes no `base_url` of its own: `pending` already carries the socket and
/// the issuer [`open_enrolment`] validated, and reusing them is what makes it
/// impossible for a poll to be aimed anywhere its own transaction was not
/// opened against. See [`PendingEnrolment`]'s own documentation for why that
/// is a security property and not a convenience.
pub async fn poll_enrolment(
    http: &reqwest::Client,
    pending: &PendingEnrolment,
    client_key: &Es256Key,
) -> Result<EnrolmentPoll> {
    let endpoint = pending.transport_base.join(BOOTSTRAP_POLL_PATH)?;
    let htu = format!("{}{BOOTSTRAP_POLL_PATH}", pending.canonical_issuer);
    let proof = poll_proof(client_key, &htu, &pending.handle)?;
    let response = http
        .post(endpoint)
        .json(&serde_json::json!({ "bootstrap_handle": pending.handle, "proof": proof }))
        .send()
        .await?;
    let status = response.status();
    let text = response.text().await?;

    if status == reqwest::StatusCode::OK {
        return Ok(EnrolmentPoll::Registered(registration_from(&text)?));
    }

    let refusal = Error::response("polling a bootstrap transaction", status.as_u16(), text);
    if refusal.oauth_error() == Some(AUTHORIZATION_PENDING) {
        return Ok(EnrolmentPoll::Pending);
    }
    Err(refusal)
}

/// Poll until the enrolment completes, the transaction expires, or the server
/// refuses.
///
/// `sleep` is a parameter rather than `tokio::time::sleep` so a test can run the
/// whole loop, including its deadline, without waiting: the loop's termination
/// is the property worth asserting and it is not assertable against a real
/// clock in reasonable time.
pub async fn complete_enrolment<S, F>(
    http: &reqwest::Client,
    pending: &PendingEnrolment,
    client_key: &Es256Key,
    mut sleep: S,
) -> Result<Registration>
where
    S: FnMut(Duration) -> F,
    F: std::future::Future<Output = ()>,
{
    // The server's own deadline, converted to a number of attempts. A
    // wall-clock deadline would be the obvious shape and is the wrong one here:
    // the sleep is injected, so wall-clock time does not advance in a test and
    // the loop would never end.
    let interval = pending.poll_interval.max(Duration::from_secs(1));
    let attempts = pending.expires_in.as_secs().div_ceil(interval.as_secs()).max(1);

    for attempt in 0..attempts {
        if attempt > 0 {
            sleep(interval).await;
        }
        match poll_enrolment(http, pending, client_key).await? {
            EnrolmentPoll::Registered(registration) => return Ok(registration),
            EnrolmentPoll::Pending => {}
        }
    }

    Err(Error::Registration(format!(
        "the enrolment was not approved within {} seconds; open the link again and approve it \
         on the machine you are setting up",
        pending.expires_in.as_secs()
    )))
}

/// The registration response, checked.
fn registration_from(text: &str) -> Result<Registration> {
    let metadata: serde_json::Value = serde_json::from_str(text)?;
    let client_id = metadata
        .get("client_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::MissingMetadata("client_id"))?
        .to_owned();

    // The architecture says a client secret does not exist for this client, and
    // the server asserts it twice. A third check here costs nothing and makes
    // the claim true of what this process holds, not only of what the server
    // believes it sent.
    if metadata.get("client_secret").is_some() {
        return Err(Error::Registration(
            "the server issued a client secret for a client that authenticates with a key; \
             refusing to store it"
                .to_owned(),
        ));
    }

    // The whole point of moving the identity leg into the browser is that no
    // upstream artefact reaches this process. A registration response carrying
    // one means the server regressed, and accepting it quietly is how it would
    // stay that way.
    for forbidden in ["id_token", "access_token", "refresh_token"] {
        if metadata.get(forbidden).is_some() {
            return Err(Error::Registration(format!(
                "the enrolment response carried `{forbidden}`; an upstream credential must \
                 never reach this process, so the registration is refused rather than stored"
            )));
        }
    }

    Ok(Registration { client_id, metadata })
}

#[cfg(test)]
mod tests;
