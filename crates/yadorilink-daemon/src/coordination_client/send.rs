//! The Track Send calls of the coordination client: same-account send grants, cross-account
//! one-shot Send links, and consuming a grant.

use serde::{Deserialize, Serialize};

use super::imp::decode_signing_key;
use super::send_code::SendLinkCode;
use super::{CoordinationAuth, SendAuthorized, SubstrateReachability};

/// A Track Send rendezvous grant from `POST /send/authorization` --
/// the coordination service's `routes/send.ts`, backed by the `send_authorizations`
/// table (see that migration's own doc comment for what this primitive is
/// and, deliberately, is not: never an extension of folder-group/ACL
/// membership). Names the exact sender+receiver pair it authorizes and
/// carries ONLY the receiver's own Track Send connect material -- its
/// signing key (= iroh endpoint id) and where its iroh endpoint answers --
/// never any other same-account device's key or address.
#[derive(Debug, Clone)]
pub struct SendAuthorizationGrant {
    pub grant_id: String,
    /// Presented alongside `grant_id` at consume time, never alone -- see
    /// `consume_send_authorization`'s own doc comment for why a leaked or
    /// logged grant id must not be independently consumable.
    pub nonce: String,
    pub expires_at_unix: i64,
    pub receiver_device_id: String,
    pub receiver_signing_key: [u8; 32],
    /// Empty when the receiver's iroh endpoint has not published an
    /// address yet; the dial then relies on what the endpoint's own lookup
    /// knows.
    pub receiver_reachability: SubstrateReachability,
}

/// A freshly minted cross-account Send link (`POST /send/links`).
#[derive(Clone)]
pub struct CreatedSendLink {
    pub link_id: String,
    /// Shown once, with the secret half that exists only on the sender's and recipient's devices;
    /// the service keeps a lookup id, a hash of a token derived from the secret, and ciphertext.
    pub code: String,
    pub expires_at_unix: i64,
}

impl std::fmt::Debug for CreatedSendLink {
    /// Names no part of the code: it unlocks the link's file list.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedSendLink")
            .field("link_id", &self.link_id)
            .field("code", &"..")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

/// The sender's view of a link (`GET /send/links/:id`).
#[derive(Debug, Clone)]
pub struct SendLinkStatus {
    /// `open`, `redeemed`, `granted`, `cancelled` or `expired`.
    pub state: String,
    pub receiver_device_name: Option<String>,
}

/// What a signed-in holder of a code may see of a link before redeeming it
/// (`POST /send/links/preview`).
#[derive(Debug, Clone)]
pub struct SendLinkPreview {
    pub sender_name: String,
    /// (name, size in bytes) of each file the link carries; empty when the sender attached none.
    pub files: Vec<(String, u64)>,
    pub expires_at_unix: i64,
}

/// Why a send-link call to the coordination plane failed, as a kind a caller can branch on
/// without reading the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendLinkCallKind {
    /// The service could not be reached.
    Unreachable,
    /// 401 or 403: this device's sign-in is not accepted.
    SignInRequired,
    /// 404: for a redeem, the service's one uniform refusal (unknown, expired, used or
    /// cancelled); for another call, the link is not one of this account's.
    NotFound,
    /// The service has Send links switched off (a 404 carrying the code `send_links_disabled`).
    FeatureDisabled,
    /// 409: the lookup id or link id is already in use (the caller mints a fresh code).
    Conflict,
    /// The link is valid but its sealed file list does not open with the code (altered, or
    /// sealed for another link): no list can be shown.
    PreviewUnverified,
    Other,
}

/// A failed send-link call: its kind plus the text for a details view.
#[derive(Debug, Clone)]
pub struct SendLinkCallError {
    pub kind: SendLinkCallKind,
    pub message: String,
}

impl std::fmt::Display for SendLinkCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Requests a Track Send rendezvous grant naming `receiver_device_id` as
/// the exact (and only) device this call authorizes `sender_device_id`
/// to reach -- `POST /send/authorization`. Unlike most calls in this
/// module, this surfaces its failure to the caller: `SendTransferService`
/// needs to tell a user-initiated `yadorilink send` apart a real
/// rejection (receiver removed, not on this account, budget exceeded)
/// from a transient outage, and a silently-swallowed `None` cannot do
/// that.
pub async fn request_send_authorization(
    addr: &str,
    auth: &CoordinationAuth,
    sender_device_id: &str,
    receiver_device_id: &str,
) -> Result<SendAuthorizationGrant, String> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Body<'a> {
        sender_device_id: &'a str,
        receiver_device_id: &'a str,
    }
    post_send_grant(
        auth,
        &format!("{addr}/send/authorization"),
        &Body { sender_device_id, receiver_device_id },
    )
    .await
}

/// Posts a grant request (same-account `POST /send/authorization`, or a
/// redeemed link's `POST /send/links/:id/authorization`) and parses the
/// grant both answer with.
async fn post_send_grant(
    auth: &CoordinationAuth,
    url: &str,
    body: &impl Serialize,
) -> Result<SendAuthorizationGrant, String> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ReceiverBody {
        device_id: String,
        signing_public_key_base64: String,
        #[serde(default)]
        substrate_reachability: Option<super::WireSubstrateReachability>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Resp {
        grant_id: String,
        nonce: String,
        expires_at: i64,
        receiver: ReceiverBody,
    }
    let resp = reqwest::Client::new()
        .post(url)
        .json(body)
        .send_authorized(auth)
        .await
        .map_err(|e| format!("could not reach the coordination plane: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!(
            "coordination plane refused the send-authorization request ({status}): {text}"
        ));
    }
    let parsed: Resp =
        resp.json().await.map_err(|e| format!("unparseable send-authorization response: {e}"))?;
    let receiver_signing_key = decode_signing_key(&parsed.receiver.signing_public_key_base64)
        .ok_or_else(|| {
            "send-authorization response carried an unparseable receiver signing key".to_string()
        })?;
    Ok(SendAuthorizationGrant {
        grant_id: parsed.grant_id,
        nonce: parsed.nonce,
        expires_at_unix: parsed.expires_at,
        receiver_device_id: parsed.receiver.device_id,
        receiver_signing_key,
        receiver_reachability: parsed
            .receiver
            .substrate_reachability
            .map(Into::into)
            .unwrap_or_default(),
    })
}

/// The pair-bound grant for a redeemed cross-account Send link --
/// `POST /send/links/:id/authorization`. Issued once per link.
pub async fn request_send_link_authorization(
    addr: &str,
    auth: &CoordinationAuth,
    link_id: &str,
    sender_device_id: &str,
) -> Result<SendAuthorizationGrant, String> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Body<'a> {
        sender_device_id: &'a str,
    }
    post_send_grant(
        auth,
        &format!("{addr}/send/links/{link_id}/authorization"),
        &Body { sender_device_id },
    )
    .await
}

/// Mints a one-use expiring cross-account Send link -- `POST /send/links`. The code is made here,
/// on the sender's device, and shown once; the service receives only its lookup id, a hash of the
/// token derived from the code's secret half, and the file list sealed under a key derived from the
/// same secret.
pub async fn create_send_link(
    addr: &str,
    auth: &CoordinationAuth,
    sender_device_id: &str,
    ttl_seconds: Option<u32>,
    files: &[(String, u64)],
) -> Result<CreatedSendLink, SendLinkCallError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Body<'a> {
        sender_device_id: &'a str,
        link_id: &'a str,
        lookup_id: &'a str,
        token_hash: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        ttl_seconds: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        preview_blob: Option<&'a str>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Resp {
        link_id: String,
        expires_at: i64,
    }
    // A 40-bit lookup id collides rarely; a collision is answered with a fresh code.
    const ATTEMPTS: usize = 4;
    for attempt in 1..=ATTEMPTS {
        let code = SendLinkCode::mint();
        let link_id = uuid::Uuid::new_v4().to_string();
        let preview_blob =
            if files.is_empty() {
                None
            } else {
                Some(code.seal_preview(&link_id, files).map_err(|message| SendLinkCallError {
                    kind: SendLinkCallKind::Other,
                    message,
                })?)
            };
        let token_hash = code.token_hash_hex();
        let result = send_link_request(
            reqwest::Client::new().post(format!("{addr}/send/links")).json(&Body {
                sender_device_id,
                link_id: &link_id,
                lookup_id: code.lookup_id(),
                token_hash: &token_hash,
                ttl_seconds,
                preview_blob: preview_blob.as_deref(),
            }),
            auth,
            "create the send link",
        )
        .await;
        let resp = match result {
            Err(e) if e.kind == SendLinkCallKind::Conflict && attempt < ATTEMPTS => continue,
            other => other?,
        };
        let parsed: Resp = resp.json().await.map_err(|e| SendLinkCallError {
            kind: SendLinkCallKind::Other,
            message: format!("unparseable send-link response: {e}"),
        })?;
        // The preview is sealed to the id this device chose, so the id the service answers with
        // must be that one: a different id would hand the sender a link no preview opens for.
        if parsed.link_id != link_id {
            return Err(SendLinkCallError {
                kind: SendLinkCallKind::Other,
                message: "the service answered with a different send-link id than the one created"
                    .to_string(),
            });
        }
        return Ok(CreatedSendLink {
            link_id,
            code: code.display(),
            expires_at_unix: parsed.expires_at,
        });
    }
    unreachable!("the last attempt returns")
}

/// The refusal for text that is not a code: the same one the service gives an unknown code, so a
/// mistyped code is never told apart from a dead link.
fn not_a_code() -> SendLinkCallError {
    SendLinkCallError {
        kind: SendLinkCallKind::NotFound,
        message: "send link is invalid, expired, or already used".to_string(),
    }
}

/// Redeems a code with one of this account's devices --
/// `POST /send/links/redeem`. Returns the link id. Every failure (unknown,
/// expired, used, cancelled) is the service's one uniform refusal.
pub async fn redeem_send_link(
    addr: &str,
    auth: &CoordinationAuth,
    code: &str,
    receiver_device_id: &str,
) -> Result<String, SendLinkCallError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Body<'a> {
        lookup_id: &'a str,
        token: &'a str,
        receiver_device_id: &'a str,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Resp {
        link_id: String,
    }
    let code = SendLinkCode::parse(code).ok_or_else(not_a_code)?;
    let token = code.token_hex();
    let resp = send_link_request(
        reqwest::Client::new().post(format!("{addr}/send/links/redeem")).json(&Body {
            lookup_id: code.lookup_id(),
            token: &token,
            receiver_device_id,
        }),
        auth,
        "redeem the send link",
    )
    .await?;
    let parsed: Resp = resp.json().await.map_err(|e| SendLinkCallError {
        kind: SendLinkCallKind::Other,
        message: format!("unparseable send-link response: {e}"),
    })?;
    Ok(parsed.link_id)
}

/// What a link carries and who sends it, before redeeming --
/// `POST /send/links/preview`. Reads only; the service refuses every link that is not open
/// alike (`NotFound`).
pub async fn preview_send_link(
    addr: &str,
    auth: &CoordinationAuth,
    code: &str,
) -> Result<SendLinkPreview, SendLinkCallError> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Body<'a> {
        lookup_id: &'a str,
        token: &'a str,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Resp {
        link_id: String,
        sender_name: String,
        expires_at: i64,
        #[serde(default)]
        preview_blob: Option<String>,
    }
    let code = SendLinkCode::parse(code).ok_or_else(not_a_code)?;
    let token = code.token_hex();
    let resp = send_link_request(
        reqwest::Client::new()
            .post(format!("{addr}/send/links/preview"))
            .json(&Body { lookup_id: code.lookup_id(), token: &token }),
        auth,
        "read the send link",
    )
    .await?;
    let parsed: Resp = resp.json().await.map_err(|e| SendLinkCallError {
        kind: SendLinkCallKind::Other,
        message: format!("unparseable send-link response: {e}"),
    })?;
    // No list attached is a link that carries none. A list that does not open (altered, or sealed
    // for another link) is not "no files": it is said so, and the link itself stays redeemable.
    let files = match parsed.preview_blob {
        None => Vec::new(),
        Some(blob) => {
            code.open_preview(&parsed.link_id, &blob).ok_or_else(|| SendLinkCallError {
                kind: SendLinkCallKind::PreviewUnverified,
                message: "the list of files in this link could not be verified and may have been \
                      altered; the link itself is still valid"
                    .to_string(),
            })?
        }
    };
    Ok(SendLinkPreview {
        sender_name: parsed.sender_name,
        files,
        expires_at_unix: parsed.expires_at,
    })
}

/// The sender's view of a link -- `GET /send/links/:id`.
pub async fn send_link_status(
    addr: &str,
    auth: &CoordinationAuth,
    link_id: &str,
) -> Result<SendLinkStatus, SendLinkCallError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Resp {
        state: String,
        #[serde(default)]
        receiver_device_name: Option<String>,
    }
    let resp = send_link_request(
        reqwest::Client::new().get(format!("{addr}/send/links/{link_id}")),
        auth,
        "read the send link",
    )
    .await?;
    let parsed: Resp = resp.json().await.map_err(|e| SendLinkCallError {
        kind: SendLinkCallKind::Other,
        message: format!("unparseable send-link response: {e}"),
    })?;
    Ok(SendLinkStatus { state: parsed.state, receiver_device_name: parsed.receiver_device_name })
}

/// Cancels a link and revokes its unconsumed grant -- `DELETE /send/links/:id`.
pub async fn cancel_send_link(
    addr: &str,
    auth: &CoordinationAuth,
    link_id: &str,
) -> Result<(), SendLinkCallError> {
    send_link_request(
        reqwest::Client::new().delete(format!("{addr}/send/links/{link_id}")),
        auth,
        "cancel the send link",
    )
    .await
    .map(|_| ())
}

/// Whether a 404 body is the service's "Send links are switched off" answer, which an
/// unknown link's plain 404 is not.
fn is_send_links_disabled(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("code").and_then(|c| c.as_str().map(str::to_owned)))
        .is_some_and(|code| code == "send_links_disabled")
}

async fn send_link_request(
    request: reqwest::RequestBuilder,
    auth: &CoordinationAuth,
    what: &str,
) -> Result<reqwest::Response, SendLinkCallError> {
    let resp = request.send_authorized(auth).await.map_err(|e| SendLinkCallError {
        kind: SendLinkCallKind::Unreachable,
        message: format!("could not reach the coordination plane: {e}"),
    })?;
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    let kind = match status.as_u16() {
        401 | 403 => SendLinkCallKind::SignInRequired,
        404 if is_send_links_disabled(&text) => SendLinkCallKind::FeatureDisabled,
        404 => SendLinkCallKind::NotFound,
        409 => SendLinkCallKind::Conflict,
        _ => SendLinkCallKind::Other,
    };
    Err(SendLinkCallError { kind, message: format!("could not {what} ({status}): {text}") })
}

/// Atomically consumes a grant -- `POST /send/authorization/:grantId/consume`
/// -- naming the exact sender identity this device's own Track Send
/// handshake just authenticated (never a value merely claimed in the application-
/// layer offer that presented `grant_id`/`nonce`; see
/// `yadorilink-send`'s `handle_offer`, which is what calls this). Only
/// the first consume of a grant succeeds -- see
/// `consumeSendAuthorization`'s own doc comment on the
/// Worker side for why a SECOND call with the exact same arguments
/// (a replay, or an honest retry after this device never saw the first
/// response) reliably fails rather than reliably succeeding twice: only
/// the first to actually commit gets a receiver's `Ok`, and a caller
/// that legitimately needs to retry a transient failure does so by
/// requesting a fresh grant, not by re-presenting a consumed one.
pub async fn consume_send_authorization(
    addr: &str,
    auth: &CoordinationAuth,
    grant_id: &str,
    nonce: &str,
    sender_device_id: &str,
    receiver_device_id: &str,
) -> Result<(), String> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Body<'a> {
        nonce: &'a str,
        sender_device_id: &'a str,
        receiver_device_id: &'a str,
    }
    let url = format!("{addr}/send/authorization/{grant_id}/consume");
    let body = Body { nonce, sender_device_id, receiver_device_id };
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&body)
        .send_authorized(auth)
        .await
        .map_err(|e| format!("could not reach the coordination plane: {e}"))?;
    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        return Err(format!(
            "send authorization is invalid, expired, or already used ({status}): {text}"
        ));
    }
    // The response also names the sender; this device already knows who
    // it is from the authenticated connection, so the body is not read.
    Ok(())
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The credential every call in this module takes, wrapping the opaque token these mock
    /// servers expect to see as `Authorization: Bearer`.
    fn test_auth() -> yadorilink_fapi_client::CoordinationAuth {
        yadorilink_fapi_client::test_support::offline_auth()
    }

    /// A create answer that names the link id the request carried, as the service does.
    fn created_answer(expires_at: i64) -> impl Fn(&wiremock::Request) -> ResponseTemplate {
        move |request: &wiremock::Request| {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "linkId": body["linkId"], "expiresAt": expires_at }),
            )
        }
    }

    #[tokio::test]
    async fn a_send_link_goes_from_created_to_redeemed_to_a_pair_bound_grant() {
        use super::{
            cancel_send_link, create_send_link, redeem_send_link, request_send_link_authorization,
            send_link_status,
        };
        use base64::Engine as _;
        use wiremock::matchers::body_json;
        let key = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/send/links"))
            .respond_with(created_answer(1234))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/send/links/redeem"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "linkId": "link-1" })),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/send/links/link-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "linkId": "link-1", "state": "redeemed", "expiresAt": 1234,
                "receiverDeviceName": "Bob laptop"
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/send/links/link-1/authorization"))
            .and(body_json(serde_json::json!({ "senderDeviceId": "dev-a" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "grantId": "g1", "nonce": "n1", "expiresAt": 99,
                "receiver": { "deviceId": "dev-b", "signingPublicKeyBase64": key }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/send/links/link-1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "cancelled": true })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let (addr, auth) = (server.uri(), test_auth());

        let link = create_send_link(&addr, &auth, "dev-a", Some(600), &[]).await.unwrap();
        assert!(!link.link_id.is_empty());
        assert_eq!(redeem_send_link(&addr, &auth, &link.code, "dev-b").await.unwrap(), "link-1");
        // The service saw the lookup id and a hash of the token, and the redeem presented the
        // token itself; neither request carried the secret half of the code.
        let sent = server.received_requests().await.unwrap();
        let body_of = |suffix: &str| -> serde_json::Value {
            let request = sent.iter().find(|r| r.url.path() == suffix).unwrap();
            serde_json::from_slice(&request.body).unwrap()
        };
        let (created, redeemed) = (body_of("/send/links"), body_of("/send/links/redeem"));
        let code = super::SendLinkCode::parse(&link.code).unwrap();
        assert_eq!(created["linkId"], link.link_id.as_str(), "the id sent is the id kept");
        assert_eq!(created["lookupId"], code.lookup_id());
        assert_eq!(created["tokenHash"], code.token_hash_hex());
        assert_eq!(created["ttlSeconds"], 600);
        assert!(created.get("previewBlob").is_none() && created.get("files").is_none());
        assert_eq!(redeemed["lookupId"], code.lookup_id());
        assert_eq!(redeemed["token"], code.token_hex());
        let secret = &link.code.replace('-', "")[8..];
        for request in &sent {
            assert!(!String::from_utf8_lossy(&request.body).contains(secret));
            assert!(!request.url.as_str().contains(secret));
        }
        let status = send_link_status(&addr, &auth, "link-1").await.unwrap();
        assert_eq!(status.state, "redeemed");
        assert_eq!(status.receiver_device_name.as_deref(), Some("Bob laptop"));
        let grant = request_send_link_authorization(&addr, &auth, "link-1", "dev-a").await.unwrap();
        assert_eq!(
            (grant.grant_id.as_str(), grant.nonce.as_str(), grant.receiver_device_id.as_str()),
            ("g1", "n1", "dev-b")
        );
        assert_eq!(grant.receiver_signing_key, [9u8; 32]);
        cancel_send_link(&addr, &auth, "link-1").await.unwrap();
    }

    #[tokio::test]
    async fn a_preview_opens_the_sealed_list_and_the_service_never_sees_a_name() {
        use super::{create_send_link, preview_send_link};
        use wiremock::matchers::body_json;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/send/links"))
            .respond_with(created_answer(9))
            .mount(&server)
            .await;
        let (addr, auth) = (server.uri(), test_auth());
        let files = vec![("a.txt".to_string(), 5), ("dir/secret-name.pdf".to_string(), 7)];
        let link = create_send_link(&addr, &auth, "dev-a", None, &files).await.unwrap();
        let code = super::SendLinkCode::parse(&link.code).unwrap();
        let created: serde_json::Value = {
            let sent = server.received_requests().await.unwrap();
            serde_json::from_slice(&sent[0].body).unwrap()
        };
        let sent_text = created.to_string();
        assert!(!sent_text.contains("a.txt") && !sent_text.contains("secret-name"));
        assert!(created.get("files").is_none());
        let (link_id, blob) = (
            created["linkId"].as_str().unwrap().to_string(),
            created["previewBlob"].as_str().unwrap().to_string(),
        );

        let body = serde_json::json!({ "lookupId": code.lookup_id(), "token": code.token_hex() });
        Mock::given(method("POST"))
            .and(path("/send/links/preview"))
            .and(body_json(body))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "linkId": link_id, "senderName": "Kai's Mac", "expiresAt": 1_800_000_000,
                "previewBlob": blob
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/send/links/preview"))
            .respond_with(ResponseTemplate::new(404).set_body_json(
                serde_json::json!({ "error": "send link is invalid, expired, or already used" }),
            ))
            .mount(&server)
            .await;

        let preview = preview_send_link(&addr, &auth, &link.code).await.unwrap();
        assert_eq!(preview.sender_name, "Kai's Mac");
        assert_eq!(preview.files, files);
        assert_eq!(preview.expires_at_unix, 1_800_000_000);
        // A typed variant of the same code still opens it.
        let typed = link.code.to_lowercase().replace('-', " ");
        assert_eq!(preview_send_link(&addr, &auth, &typed).await.unwrap().files, files);
        // Another code, and text that is not a code, are the uniform refusal.
        let other = super::SendLinkCode::mint().display();
        for bad in [other.as_str(), "X", ""] {
            let refused = preview_send_link(&addr, &auth, bad).await.unwrap_err();
            assert_eq!(refused.kind, super::SendLinkCallKind::NotFound);
        }
        // Nothing of the code's secret half ever went over the wire.
        let secret = &link.code.replace('-', "")[8..];
        for request in server.received_requests().await.unwrap() {
            assert!(!String::from_utf8_lossy(&request.body).contains(secret));
        }
    }

    #[tokio::test]
    async fn a_taken_lookup_id_is_answered_with_a_fresh_code() {
        use super::create_send_link;
        use wiremock::matchers::any;
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(409).set_body_json(serde_json::json!({ "error": "in use" })),
            )
            .up_to_n_times(2)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(any()).respond_with(created_answer(9)).with_priority(2).mount(&server).await;
        let (addr, auth) = (server.uri(), test_auth());
        create_send_link(&addr, &auth, "dev-a", None, &[]).await.unwrap();
        let sent = server.received_requests().await.unwrap();
        let ids: std::collections::BTreeSet<_> = sent
            .iter()
            .map(|r| {
                serde_json::from_slice::<serde_json::Value>(&r.body).unwrap()["lookupId"]
                    .to_string()
            })
            .collect();
        assert_eq!(sent.len(), 3);
        assert_eq!(ids.len(), 3, "each attempt mints a fresh code");
        // A service that keeps answering 409 gives up after a few attempts.
        server.reset().await;
        Mock::given(any()).respond_with(ResponseTemplate::new(409)).mount(&server).await;
        let err = create_send_link(&addr, &auth, "dev-a", None, &[]).await.unwrap_err();
        assert_eq!(err.kind, super::SendLinkCallKind::Conflict);
    }

    #[tokio::test]
    async fn a_preview_that_does_not_open_is_said_to_be_unverified_not_empty() {
        use super::{create_send_link, preview_send_link};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/send/links"))
            .respond_with(created_answer(9))
            .mount(&server)
            .await;
        let (addr, auth) = (server.uri(), test_auth());
        let files = vec![("a.txt".to_string(), 5)];
        let link = create_send_link(&addr, &auth, "dev-a", None, &files).await.unwrap();
        let created: serde_json::Value = {
            let sent = server.received_requests().await.unwrap();
            serde_json::from_slice(&sent[0].body).unwrap()
        };
        let (link_id, blob) = (
            created["linkId"].as_str().unwrap().to_string(),
            created["previewBlob"].as_str().unwrap().to_string(),
        );
        // Served under another link id (replay) or altered: not a list, and not "no files" either.
        let mut altered = blob.clone();
        altered.replace_range(10..11, if &blob[10..11] == "A" { "B" } else { "A" });
        for (id, served) in
            [("other-link".to_string(), Some(blob.clone())), (link_id.clone(), Some(altered))]
        {
            server.reset().await;
            let mut body = serde_json::json!({ "linkId": id, "senderName": "Kai", "expiresAt": 9 });
            if let Some(blob) = served {
                body["previewBlob"] = blob.into();
            }
            Mock::given(method("POST"))
                .and(path("/send/links/preview"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&server)
                .await;
            let refused = preview_send_link(&addr, &auth, &link.code).await.unwrap_err();
            assert_eq!(refused.kind, super::SendLinkCallKind::PreviewUnverified);
            assert!(refused.message.contains("could not be verified"), "{}", refused.message);
        }
        // A link that carries no list says so plainly.
        server.reset().await;
        Mock::given(method("POST"))
            .and(path("/send/links/preview"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({ "linkId": link_id, "senderName": "Kai", "expiresAt": 9 }),
            ))
            .mount(&server)
            .await;
        let preview = preview_send_link(&addr, &auth, &link.code).await.unwrap();
        assert_eq!(preview.sender_name, "Kai");
        assert!(preview.files.is_empty());
    }

    #[tokio::test]
    async fn a_created_link_under_another_id_than_the_one_sealed_is_refused() {
        use super::create_send_link;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/send/links"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "linkId": "someone-elses-id", "expiresAt": 9
            })))
            .mount(&server)
            .await;
        let (addr, auth) = (server.uri(), test_auth());
        let refused = create_send_link(&addr, &auth, "dev-a", None, &[("a".to_string(), 1)])
            .await
            .unwrap_err();
        assert!(refused.message.contains("different send-link id"), "{}", refused.message);
    }

    #[tokio::test]
    async fn a_service_with_send_links_off_is_told_apart_from_an_unknown_link() {
        use super::{preview_send_link, send_link_status};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/send/links/preview"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": "send links are not available", "code": "send_links_disabled"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/send/links/link-1"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": "send link not found"
            })))
            .mount(&server)
            .await;
        let (addr, auth) = (server.uri(), test_auth());
        let off = preview_send_link(&addr, &auth, &super::SendLinkCode::mint().display())
            .await
            .unwrap_err();
        assert_eq!(off.kind, super::SendLinkCallKind::FeatureDisabled);
        let unknown = send_link_status(&addr, &auth, "link-1").await.unwrap_err();
        assert_eq!(unknown.kind, super::SendLinkCallKind::NotFound);
    }

    #[tokio::test]
    async fn refused_send_link_calls_surface_the_service_refusal() {
        use super::{redeem_send_link, request_send_link_authorization};
        let server = MockServer::start().await;
        // Reused, expired, cancelled and unknown codes all look like this.
        Mock::given(method("POST"))
            .and(path("/send/links/redeem"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": "send link is invalid, expired, or already used"
            })))
            .mount(&server)
            .await;
        // A second grant request for the same link, or one before redeem.
        Mock::given(method("POST"))
            .and(path("/send/links/link-1/authorization"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let (addr, auth) = (server.uri(), test_auth());
        let err = redeem_send_link(&addr, &auth, &super::SendLinkCode::mint().display(), "dev-b")
            .await
            .unwrap_err();
        assert!(err.message.contains("404") && err.message.contains("already used"), "{err}");
        // The uniform refusal is typed, so a front end never reads the text.
        assert_eq!(err.kind, super::SendLinkCallKind::NotFound);
        assert!(request_send_link_authorization(&addr, &auth, "link-1", "dev-a").await.is_err());
    }
}
