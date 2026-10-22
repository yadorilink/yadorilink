//! Round-trips this workspace's real client code against a real, locally
//! running deployment -- the Authorization Server and the Coordination API,
//! served from one origin by the same composition root the hosted service runs.
//!
//! # What this closes that nothing else can
//!
//! Every other test of these code paths asserts against something a human
//! wrote: either the Rust request struct is built and inspected directly (never
//! becoming JSON at all), or it is sent to a mock HTTP server whose canned
//! response is itself a hand-written guess at what the service sends. Both
//! sides of that arrangement can drift together without any test going red -- a
//! request struct that serializes `refresh_token` where the service reads
//! `refreshToken` still passes a mock that was written to expect
//! `refresh_token`, and the service keeps answering `204` either way.
//!
//! The case worth being precise about is co-drift, not a lone edit. Changing a
//! request struct by itself usually does trip whichever mock-based test pins
//! the old key -- and then the author updates that test to agree with the
//! struct, because it looks like the test is the thing that is out of date. Two
//! hand-written descriptions of the same JSON now agree with each other and
//! disagree with the service, every existing gate is green again, and only a
//! real round trip can still tell.
//!
//! # There is no shortcut in here
//!
//! The credential every request below carries was obtained the way a fresh
//! installation obtains one, in this order and with no step skipped:
//!
//! ```text
//!   generate an ES256 key
//!     -> POST /bootstrap/start                        (no credential at all)
//!     -> a human approves in a browser
//!     -> the browser authenticates at the upstream
//!     -> RFC 7591 registration, for the key that opened the transaction
//!     -> POST /bootstrap/poll                         -> client_id
//!     -> PAR -> authorize -> interaction -> upstream -> code
//!     -> POST /token, private_key_jwt + DPoP          -> access + refresh
//!     -> CoordinationAuth
//! ```
//!
//! That matters beyond tidiness. The previous version of this file signed in
//! through `POST /auth/google/device/*` and presented the resulting `sessions`
//! row as `Authorization: Bearer`, which is a plane that no longer exists on
//! either side of the wire. A harness that kept it would be the reason the
//! legacy plane could not be deleted.
//!
//! The only thing the harness stands in for is Google, which a local run
//! genuinely cannot reach; the seam is outbound-only and lives in
//! the test-only entry point of the coordination service, which is never
//! bundled into a deploy. The harness plays the USER AGENT for the two browser legs --
//! a cookie jar and a redirect chain -- and every byte it sends is one a
//! browser would send.
//!
//! # Inert without a service
//!
//! Every test returns immediately unless `YADORILINK_WIRE_CONTRACT_ADDR` names
//! a running deployment, so an ordinary `cargo test` run compiles them and
//! skips them. Each one announces itself with [`RAN_MARKER`] the moment it has
//! an address and before it does any work, which is what makes a skipped run
//! distinguishable from a real one -- libtest's own summary is not (see that
//! constant).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Once};

use base64::Engine as _;
use tokio::sync::Mutex;
use yadorilink_cli::commands::{device, share};
use yadorilink_client_core::coordination::{credential_store, http_client};
use yadorilink_client_core::ops::{account, devices, shares};
use yadorilink_client_core::CoreError;
use yadorilink_daemon::coordination_client::{ActivateOutcome, EnrollmentPrepareOutcome};
use yadorilink_fapi_client::{
    client_assertion, complete_enrolment, open_enrolment, poll_enrolment, AuthorizationRequest,
    CoordinationAuth, CredentialManager, EnrolmentPoll, EnrolmentRequest, Es256Key, FapiClient,
    Pkce, ASSERTION_TYPE,
};

/// Prefix of the line every test prints once it has a service address in hand,
/// and before it does any work.
///
/// It exists because libtest cannot distinguish a test that ran from one that
/// skipped itself: the skip below is a plain `return`, which libtest counts as
/// a pass, so `test result: ok. 7 passed` is the identical line whether all
/// seven round-tripped against a real service or all seven found no address and
/// did nothing. Counting these markers instead measures executions, which is
/// the thing worth asserting.
const RAN_MARKER: &str = "wire-contract: ran";

/// Serializes the whole file. Every test enrols, which replaces the
/// process-wide credential store's contents, and several point
/// `YADORILINK_CONFIG_DIR` at their own directory -- both are process globals.
/// The contract script also passes `--test-threads=1`; this lock keeps a
/// hand-run `cargo test` of this file correct too.
static WORLD: Mutex<()> = Mutex::const_new(());

static STORE: Once = Once::new();

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn unique(prefix: &str) -> String {
    let n = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_nanos();
    format!("{prefix}-{nanos}-{n}")
}

fn worker_addr() -> Option<String> {
    match std::env::var("YADORILINK_WIRE_CONTRACT_ADDR") {
        Ok(addr) if !addr.is_empty() => Some(addr),
        _ => None,
    }
}

macro_rules! worker_addr_or_skip {
    ($test:literal) => {
        match worker_addr() {
            Some(addr) => {
                // The marker only proves `YADORILINK_WIRE_CONTRACT_ADDR` was
                // set -- the real request traffic is driven by
                // `coordination_addr`, which reads its own env var. The
                // launching script sets both to the same value, but nothing
                // enforced that agreement: a stray leftover service bound to
                // the default address would let every test print this marker
                // while silently talking to the wrong server.
                assert_eq!(
                    yadorilink_client_core::coordination::http_client::coordination_addr(),
                    addr,
                    "YADORILINK_COORDINATION_ADDR must resolve to the same address as \
                     YADORILINK_WIRE_CONTRACT_ADDR, or every request below silently targets \
                     the wrong service"
                );
                // Emitted before any request, so a marker means "this test
                // reached the service", never "this test finished". The leading
                // newline closes libtest's own unterminated `test <name> ... `
                // prefix, which under `--nocapture` would otherwise share this
                // line and hide it from a line-anchored search.
                println!("\n{} {}", RAN_MARKER, $test);
                addr
            }
            None => return,
        }
    };
}

/// Points the shared credential store at a file this test binary owns.
///
/// Not a shortcut around the code under test: the file backend is a supported
/// backend rather than a test double, selected the same way a headless Linux
/// host selects it. What it buys is that a contract run does not overwrite the
/// developer's real credential, and that it works on a CI host whose kernel
/// keyring a container cannot reach.
///
/// The path is fixed for the life of the binary and is NOT derived from
/// `YADORILINK_CONFIG_DIR`, which several tests repoint at their own directory:
/// a credential that moved every time the config directory moved would make
/// "enrolled" depend on which test ran last.
fn use_a_file_credential_store() {
    STORE.call_once(|| {
        let dir = tempfile::tempdir().expect("a temporary credential directory");
        std::env::set_var("YADORILINK_CREDENTIAL_STORE", "file");
        std::env::set_var("YADORILINK_CREDENTIAL_FILE", dir.path().join("credentials.json"));
        // Held for the life of the process; the directory must outlive every
        // test that reads through it.
        std::mem::forget(dir);
    });
}

/// Points `device.json` and the generated device signing key at a fresh
/// directory. The returned handle must stay alive for as long as the test needs
/// the registered device's files.
fn fresh_config_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("a temporary config directory");
    std::env::set_var("YADORILINK_CONFIG_DIR", dir.path());
    dir
}

// --- the user agent ----------------------------------------------------------

/// A browser: a cookie jar, and no automatic redirect following.
///
/// Redirects are followed by hand because the `Location` headers ARE the
/// protocol here -- the upstream's authorization URL, the relay's routing
/// decision and the authorization code all appear in one and nowhere else.
fn browser() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("a reqwest client")
}

/// The authorization code the harness hands back where Google would have.
///
/// It carries the subject to authenticate as and the `nonce` this attempt asked
/// for, read off the redirect the Worker just issued. Carrying the nonce is
/// what makes the Worker's nonce check a real check: forget it and production
/// code refuses the login.
fn upstream_code(upstream: &url::Url, subject: &str) -> String {
    let nonce = upstream.query_pairs().find(|(k, _)| k == "nonce").map(|(_, v)| v.into_owned());
    let payload = serde_json::json!({ "sub": subject, "nonce": nonce });
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string())
}

fn location(response: &reqwest::Response) -> String {
    response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("a {} carried no Location header", response.status()))
        .to_owned()
}

/// Follows one 303 and returns where it pointed, resolved against `addr`.
async fn hop(client: &reqwest::Client, addr: &str, target: &str) -> (reqwest::Response, String) {
    let url = url::Url::parse(addr).expect("the address is a URL").join(target).expect("a URL");
    let response = client.get(url).send().await.expect("the request reaches the service");
    let next = if response.status().is_redirection() { location(&response) } else { String::new() };
    (response, next)
}

/// Drives the upstream round trip: read the redirect the Worker issued, answer
/// as the upstream would, and follow the relay to wherever it forwards.
async fn return_from_upstream(
    client: &reqwest::Client,
    addr: &str,
    at_upstream: &str,
    subject: &str,
) -> reqwest::Response {
    let upstream = url::Url::parse(at_upstream).expect("the upstream URL");
    assert_eq!(
        upstream.origin().ascii_serialization(),
        "https://accounts.google.com",
        "the browser must be sent to the upstream, not somewhere this Worker invented"
    );
    let state = upstream
        .query_pairs()
        .find(|(k, _)| k == "state")
        .map(|(_, v)| v.into_owned())
        .expect("the upstream request carries a state");

    let back = format!(
        "/interaction/callback?state={}&code={}",
        urlencoding(&state),
        urlencoding(&upstream_code(&upstream, subject))
    );
    let (relay, forwarded) = hop(client, addr, &back).await;
    assert_eq!(relay.status(), 303, "the registered redirect URI relays");
    let (finished, _) = hop(client, addr, &forwarded).await;
    finished
}

/// Minimal percent-encoding for the two values this file puts in a query
/// string. Both are base64url or hex, so only `=` and `+` can appear; encoding
/// the whole reserved set anyway keeps this correct if either format changes.
fn urlencoding(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// --- the whole enrolment and login ------------------------------------------

/// The redirect URI a real installation registers. Never dialled here: the
/// harness intercepts the final 303 rather than running a listener, which is
/// what a browser would deliver to.
const REDIRECT_URI: &str = "http://127.0.0.1:51789/cli/callback";

const LOGIN_SCOPE: &str = "openid offline_access";

struct Enrolled {
    auth: CoordinationAuth,
    client_id: String,
    /// Every body the installation's own half of the flow received, so a test
    /// can assert what did NOT reach it.
    installation_saw: Vec<String>,
}

/// What a completed bootstrap transaction leaves an installation holding.
struct Registered {
    client_key: Es256Key,
    client_id: String,
    /// Every body the installation's own half of the flow received, so a test
    /// can assert what did NOT reach it.
    installation_saw: Vec<String>,
}

/// Runs the bootstrap transaction: an installation with no credential of any
/// kind ends up holding a `client_id` for the key it generated.
///
/// This is the ONLY way a client registration comes into existence here, and
/// deliberately so. The repository used to carry two scripts that emitted an
/// `INSERT ... INTO auth_oidc_record` for a hand-written `Client` row, which
/// registered a key of the operator's choosing with no approval and no upstream
/// identity; every test and gate that leaned on one was testing a client the
/// product can never produce.
async fn register_a_client(addr: &str, subject: &str, client_name: &str) -> Registered {
    let http = reqwest::Client::new();
    let client_key = Es256Key::generate();
    let redirect_uris = vec![REDIRECT_URI.to_owned()];
    let mut saw = Vec::new();

    // 1. Open the transaction. No credential of any kind on this request.
    let pending = open_enrolment(
        &http,
        addr,
        &client_key,
        &EnrolmentRequest { redirect_uris: &redirect_uris, client_name: Some(client_name) },
    )
    .await
    .expect("opening a bootstrap transaction");
    saw.push(pending.approval_uri.clone());

    // 2. The human's browser: the interstitial, the approval, the upstream.
    let browser = browser();
    let page =
        browser.get(&pending.approval_uri).send().await.expect("the approval page is reachable");
    assert_eq!(page.status(), 200, "the approval page should render a form");
    let page_html = page.text().await.expect("the approval page has a body");
    assert!(page_html.contains("<form"), "approval must be a POST, not a link: {page_html}");

    let approve_url =
        url::Url::parse(addr).expect("a URL").join("/bootstrap/approve").expect("a URL");
    let submitted = browser
        .post(approve_url)
        .header("content-type", "application/x-www-form-urlencoded")
        .body("")
        .send()
        .await
        .expect("approving is reachable");
    assert_eq!(submitted.status(), 303, "approval sends the browser upstream");
    let at_upstream = location(&submitted);

    let finished = return_from_upstream(&browser, addr, &at_upstream, subject).await;
    let finished_status = finished.status();
    let finished_html = finished.text().await.expect("a body");
    assert_eq!(finished_status, 200, "the enrolment should complete: {finished_html}");

    // 3. Collect the registration. Exactly once -- this handle will never
    //    produce it again.
    let registration = complete_enrolment(&http, &pending, &client_key, tokio::time::sleep)
        .await
        .expect("collecting the registration");
    saw.push(registration.metadata.to_string());

    let second =
        poll_enrolment(&http, &pending, &client_key).await.expect("a second poll is answered");
    assert!(
        matches!(second, EnrolmentPoll::Pending),
        "a redeemed handle must never produce the registration again, got {second:?}"
    );

    Registered { client_key, client_id: registration.client_id, installation_saw: saw }
}

/// Drives one authorization leg to a code, through the browser hops a human
/// would make.
///
/// ONE-BROWSER-CEREMONY AWARE. `register_a_client` (above) already signs
/// this human in through the upstream once, as part of approving the
/// enrolment -- so this client's very FIRST login, right after registering,
/// finds a live identity handoff and the interaction finishes directly with
/// no second upstream visit at all (`interaction.ts`'s own header has the
/// mechanism). The path is therefore either:
///
///   authorize -> interaction -> [resumes the authorization directly]
///                             -> redirect, or
///   authorize -> interaction -> upstream -> callback -> redirect
///
/// and this function detects which one it got by checking `at_upstream`'s
/// origin rather than assuming either shape -- a login for a client whose
/// handoff has already been spent (a second login, tested elsewhere) still
/// takes the second path, and this function must not break that case.
///
/// Returns the code out of the final `Location`, having checked that it was
/// delivered to the registered redirect URI and echoed the state.
async fn authorization_code(
    addr: &str,
    client: &FapiClient,
    request_uri: &str,
    state: &str,
    subject: &str,
) -> String {
    let browser = browser();
    let authorize = client.authorization_endpoint_url(request_uri).expect("the authorization URL");
    let (started, interaction) = hop(&browser, addr, authorize.as_str()).await;
    assert_eq!(started.status(), 303, "authorize sends the browser to its interaction");
    let (entry, at_upstream) = hop(&browser, addr, &interaction).await;
    assert_eq!(entry.status(), 303, "the interaction redirects onward");

    let bypassed_the_upstream = url::Url::parse(&at_upstream)
        .ok()
        .map(|url| url.origin().ascii_serialization() != "https://accounts.google.com")
        .unwrap_or(false);

    let (completed, redirected) = if bypassed_the_upstream {
        // A live identity handoff: `at_upstream` is not the upstream at all,
        // it is already the redirect resuming the authorization request.
        hop(&browser, addr, &at_upstream).await
    } else {
        let resumed = return_from_upstream(&browser, addr, &at_upstream, subject).await;
        assert_eq!(resumed.status(), 303, "the callback resumes the authorization");
        hop(&browser, addr, &location(&resumed)).await
    };
    assert_eq!(completed.status(), 303, "the resumed authorization redirects to the client");

    let landed = url::Url::parse(&redirected).expect("the redirect is absolute");
    assert_eq!(
        landed.origin().ascii_serialization(),
        url::Url::parse(REDIRECT_URI).expect("a URL").origin().ascii_serialization(),
        "the code must be delivered to the registered redirect URI"
    );
    assert_eq!(
        landed.query_pairs().find(|(k, _)| k == "state").map(|(_, v)| v.into_owned()).as_deref(),
        Some(state),
        "the redirect must echo the state this login pushed"
    );
    landed
        .query_pairs()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.into_owned())
        .expect("the redirect carries an authorization code")
}

/// Enrols a fresh installation and signs it in, exactly as `yadorilink login`
/// does, and leaves the credential in the process-wide store so the CLI's own
/// commands find it.
async fn enrol_and_sign_in(addr: &str, subject: &str) -> Enrolled {
    use_a_file_credential_store();
    credential_store::clear().await.ok();

    let registered = register_a_client(addr, subject, "wire-contract").await;

    // Log in as the client that was just registered.
    let client_key_jwk = registered.client_key.to_jwk_json();
    let client = FapiClient::discover(
        reqwest::Client::new(),
        addr,
        registered.client_id.clone(),
        registered.client_key,
        Es256Key::generate(),
    )
    .await
    .expect("discovery, including this client's profile check");

    let pkce = Pkce::generate();
    let state = unique("wire-contract-state");
    let pushed = client
        .push_authorization_request(&AuthorizationRequest {
            redirect_uri: REDIRECT_URI,
            scope: LOGIN_SCOPE,
            state: &state,
            prompt: Some("consent"),
            pkce: &pkce,
        })
        .await
        .expect("the pushed authorization request");

    let code = authorization_code(addr, &client, &pushed.request_uri, &state, subject).await;

    let tokens = client
        .exchange_authorization_code(&code, REDIRECT_URI, &pkce)
        .await
        .expect("the authorization code exchange");

    // One write, with everything in it, through the shipped store -- and
    // through the same one call the shipped `yadorilink login` makes. This
    // harness used to spell the four statements `login` spelled, which meant
    // the wire contract proved a sequence that existed only here. There is
    // now one door and both go through it.
    let store = Arc::new(credential_store::open().expect("the credential store"));
    let manager = CredentialManager::establish(client, client_key_jwk, &tokens, store)
        .await
        .expect("recording the completed login");
    let auth = CoordinationAuth::new(Arc::new(manager)).expect("a coordination credential");

    Enrolled {
        auth,
        client_id: registered.client_id,
        installation_saw: registered.installation_saw,
    }
}

/// Registers a device for the enrolled installation and returns its id.
async fn register_a_device(label: &str) -> (String, tempfile::TempDir) {
    let config_dir = fresh_config_dir();
    let device_id =
        devices::register_device(unique(label)).await.expect("device registration should succeed");
    assert!(!device_id.is_empty(), "the service should assign a device id");
    (device_id, config_dir)
}

/// Creates an active folder group through the daemon's own two-phase enrollment
/// calls and returns `(group_id, group_name)`.
async fn create_an_active_group(
    addr: &str,
    auth: &CoordinationAuth,
    device_id: &str,
) -> (String, String) {
    let operation_id = unique("create-operation");
    let name = unique("wire-contract-group");
    let prepared = yadorilink_daemon::coordination_client::prepare_create(
        addr,
        auth,
        &operation_id,
        &name,
        device_id,
        "eager",
    )
    .await;
    let group_id = match prepared {
        EnrollmentPrepareOutcome::Prepared { group_id } => group_id,
        other => panic!("create prepare should return a group id, got {other:?}"),
    };
    let activated = yadorilink_daemon::coordination_client::activate_create(
        addr,
        auth,
        &group_id,
        &operation_id,
    )
    .await;
    assert!(
        matches!(activated, ActivateOutcome::Success | ActivateOutcome::AlreadyActive),
        "create activate should confirm the group, got {activated:?}"
    );
    (group_id, name)
}

// --- 1. enrolment, on the real wire -----------------------------------------

/// The whole of `yadorilink login`, against a deployment that has never seen
/// this installation.
///
/// This is the test the rest of the file rests on: every credential below comes
/// from this path, so if the transaction's shape ever stops matching the
/// Worker's, nothing else in this file can pass either.
#[tokio::test]
async fn a_fresh_installation_enrols_and_obtains_a_dpop_credential() {
    let addr = worker_addr_or_skip!("a_fresh_installation_enrols_and_obtains_a_dpop_credential");
    let _world = WORLD.lock().await;

    let subject = unique("wire-contract-subject");
    let enrolled = enrol_and_sign_in(&addr, &subject).await;

    assert!(
        enrolled.client_id.starts_with("ylk-"),
        "the server mints the client id: {}",
        enrolled.client_id
    );

    // The credential works on the Coordination API, which is the only proof
    // that the token, the DPoP binding and the resource server agree.
    account::deletion_status().await.expect("the enrolled credential should be usable");

    // And nothing the upstream issued reached the installation's half of the
    // flow. The approval link and the registration are everything it saw.
    //
    // The two checks are deliberately different in kind. A VALUE the upstream
    // chose -- its access token, the Google subject -- can appear anywhere, so
    // it is searched for as a substring. A credential MEMBER cannot be searched
    // for that way: `id_token_signed_response_alg` is ordinary registered
    // metadata and contains the substring, so a substring search here reports a
    // leak that is not one. Names are therefore checked as JSON members.
    for body in &enrolled.installation_saw {
        assert!(
            !body.contains("ya29."),
            "an upstream access token reached the installation: {body}"
        );
        assert!(!body.contains(&subject), "the upstream subject reached the installation: {body}");

        if let Ok(serde_json::Value::Object(members)) =
            serde_json::from_str::<serde_json::Value>(body)
        {
            for forbidden in ["id_token", "access_token", "refresh_token"] {
                assert!(
                    !members.contains_key(forbidden),
                    "`{forbidden}` reached the installation: {body}"
                );
            }
        }
    }
}

// --- 2. the surviving operations --------------------------------------------

/// Device registration and listing.
#[tokio::test]
async fn device_registration_and_listing_round_trip() {
    let addr = worker_addr_or_skip!("device_registration_and_listing_round_trip");
    let _world = WORLD.lock().await;

    let enrolled = enrol_and_sign_in(&addr, &unique("wire-contract-subject")).await;
    let (_device_id, _config_dir) = register_a_device("wire-contract-device").await;

    device::list().await.expect("listing devices should succeed");

    // The daemon reads the same listing through its own types, with
    // `signedOut` required: a missing or renamed key fails the whole listing,
    // so one live key coming back is a real assertion about the response.
    let keys =
        yadorilink_daemon::coordination_client::list_account_device_keys(&addr, &enrolled.auth)
            .await
            .expect("the daemon's device listing should parse");
    assert_eq!(keys.len(), 1, "the registered, signed-in device is listed as not signed out");
}

/// Folder-group enrollment plus every share listing the CLI reads.
#[tokio::test]
async fn folder_group_enrollment_and_share_listings_round_trip() {
    let addr = worker_addr_or_skip!("folder_group_enrollment_and_share_listings_round_trip");
    let _world = WORLD.lock().await;

    let enrolled = enrol_and_sign_in(&addr, &unique("wire-contract-subject")).await;
    let (device_id, _config_dir) = register_a_device("wire-contract-owner-device").await;
    let (group_id, group_name) = create_an_active_group(&addr, &enrolled.auth, &device_id).await;

    let groups = shares::list_groups().await.expect("listing folder groups should succeed");
    assert!(
        groups.iter().any(|group| group.group_id == group_id && group.name == group_name),
        "the created group should appear in the owner's listing"
    );

    let resolved =
        yadorilink_client_core::ops::shares::resolve_group_id(&enrolled.auth, &group_name)
            .await
            .expect("resolving a group by name should succeed");
    assert_eq!(resolved, group_id, "name resolution should find the same group");

    share::list_shares().await.expect("listing shares should succeed");
    share::list_joinable().await.expect("listing joinable groups should succeed");
    share::members(group_name.clone()).await.expect("listing members should succeed");

    // The daemon reads the same `/shares` listing through its own types. A
    // renamed key there fails deserialization rather than merely returning
    // nothing, so both calls below are real assertions about the response.
    let state = yadorilink_daemon::coordination_client::fetch_edge_state(
        &addr,
        &enrolled.auth,
        &group_id,
        &device_id,
    )
    .await
    .expect("reading the edge state should succeed");
    assert_eq!(
        state.as_deref(),
        Some("active"),
        "the creating device's own edge should be reported active"
    );

    yadorilink_daemon::coordination_client::resolve_edge(&addr, &enrolled.auth, "no-such-edge")
        .await
        .expect("resolving an unknown edge should still parse the listing");
}

/// The account surface the desktop app's account screen drives.
#[tokio::test]
async fn account_lifecycle_round_trips() {
    let addr = worker_addr_or_skip!("account_lifecycle_round_trips");
    let _world = WORLD.lock().await;

    enrol_and_sign_in(&addr, &unique("wire-contract-subject")).await;

    let status =
        account::deletion_status().await.expect("reading the deletion status should succeed");
    assert_eq!(status.state, "active", "a fresh account should start active");

    let requested = account::request_deletion().await.expect("requesting deletion should succeed");
    assert!(
        !requested.confirmation_token.is_empty(),
        "the service should return a confirmation token to quote back"
    );

    let confirmed = account::confirm_deletion(requested.confirmation_token)
        .await
        .expect("confirming deletion should succeed");
    assert_eq!(confirmed.state, "grace", "confirming should open the grace window");
    assert!(
        confirmed.grace_expires_at_unix.is_some(),
        "the grace state should carry its expiry, so the app can count it down"
    );

    let cancelled = account::cancel_deletion().await.expect("cancelling deletion should succeed");
    assert_eq!(cancelled.state, "active", "cancelling should restore the account");

    let export = account::export_account().await.expect("exporting the account should succeed");
    assert!(export.is_object(), "the export should be a JSON document, got {export}");
}

// --- 3. what the resource server must refuse --------------------------------

/// The four refusals that say the Coordination API is sender-constrained rather
/// than merely token-gated.
///
/// Each is sent by hand rather than through a client function, deliberately:
/// there is no shipped code that can produce any of them, which is the point --
/// these assert what happens when something OTHER than this workspace's client
/// speaks to the deployment.
#[tokio::test]
async fn the_coordination_api_refuses_every_credential_but_a_live_dpop_proof() {
    let addr =
        worker_addr_or_skip!("the_coordination_api_refuses_every_credential_but_a_live_dpop_proof");
    let _world = WORLD.lock().await;

    let enrolled = enrol_and_sign_in(&addr, &unique("wire-contract-subject")).await;
    let target = format!("{addr}/shares/groups");
    let http = reqwest::Client::new();

    // The control: the real credential works, so every refusal below is about
    // the thing it changed and not about the route being broken.
    let authorization =
        enrolled.auth.authorize("GET", &target).await.expect("the credential authorizes a request");
    let ok = http
        .get(&target)
        .header("authorization", authorization.authorization())
        .header("dpop", authorization.dpop())
        .send()
        .await
        .expect("the request reaches the service");
    assert_eq!(ok.status(), 200, "the live credential must be accepted");

    let access_token = authorization
        .authorization()
        .strip_prefix("DPoP ")
        .expect("the credential is presented as DPoP")
        .to_owned();

    // (a) The same token, presented as Bearer. This is the whole legacy plane
    //     in one request: if it is ever accepted, the DPoP binding buys nothing.
    let bearer = http
        .get(&target)
        .header("authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .expect("the request reaches the service");
    assert_eq!(bearer.status(), 401, "a Bearer-shaped credential must be refused");
    let challenge = bearer
        .headers()
        .get("www-authenticate")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    assert!(
        challenge.to_ascii_lowercase().contains("dpop"),
        "the refusal must say which scheme the resource wants, got {challenge:?}"
    );

    // (b) The right token, no proof at all.
    let unproved = http
        .get(&target)
        .header("authorization", format!("DPoP {access_token}"))
        .send()
        .await
        .expect("the request reaches the service");
    assert_eq!(unproved.status(), 401, "a DPoP token with no proof must be refused");

    // (c) The right token, a well-formed proof signed by a DIFFERENT key. The
    //     token is bound to a thumbprint, and this is the request that proves
    //     the server checks it rather than merely checking a proof exists.
    let stranger = yadorilink_fapi_client::dpop_proof(
        &Es256Key::generate(),
        "GET",
        &target,
        Some(&access_token),
    )
    .expect("a proof signed by another key");
    let wrong_key = http
        .get(&target)
        .header("authorization", format!("DPoP {access_token}"))
        .header("dpop", stranger)
        .send()
        .await
        .expect("the request reaches the service");
    assert_eq!(wrong_key.status(), 401, "a proof signed by another key must be refused");

    // (d) The proof that just worked, sent again. `jti` is replay-detected, so
    //     a captured proof must not authorize a second request.
    let replayed = http
        .get(&target)
        .header("authorization", authorization.authorization())
        .header("dpop", authorization.dpop())
        .send()
        .await
        .expect("the request reaches the service");
    assert_eq!(replayed.status(), 401, "a replayed proof must be refused");
}

/// A second device joining an existing group, and being granted access.
#[tokio::test]
async fn joining_and_granting_a_second_device_round_trips() {
    let addr = worker_addr_or_skip!("joining_and_granting_a_second_device_round_trips");
    let _world = WORLD.lock().await;

    // The same upstream subject throughout: both enrolments land on the SAME
    // account, because the account is keyed on the subject and not on the
    // installation.
    let subject = unique("wire-contract-subject");
    let enrolled = enrol_and_sign_in(&addr, &subject).await;
    let (owner_device_id, _owner_config) = register_a_device("wire-contract-owner-device").await;
    let (group_id, group_name) =
        create_an_active_group(&addr, &enrolled.auth, &owner_device_id).await;

    // A second device is a second INSTALLATION. One OAuth client registration
    // owns one device row for life, so the only way this account gets another
    // device is another enrolment -- which is exactly what a second computer
    // does. Re-enrolling also repoints the process-wide credential store, so
    // everything after this acts as the second installation.
    let second_installation = enrol_and_sign_in(&addr, &subject).await;
    assert_ne!(
        second_installation.client_id, enrolled.client_id,
        "re-enrolling must mint a new client id rather than reuse the first"
    );
    let (second_device_id, _second_config) = register_a_device("wire-contract-second-device").await;
    assert_ne!(second_device_id, owner_device_id);

    share::grant(group_name.clone(), second_device_id.clone(), Some("editor".to_string()))
        .await
        .expect("granting a second device access should succeed");

    let join_operation = unique("join-operation");
    let prepared = yadorilink_daemon::coordination_client::prepare_join(
        &addr,
        &second_installation.auth,
        &join_operation,
        &group_id,
        &second_device_id,
        "on-demand",
    )
    .await;
    assert!(
        matches!(prepared, EnrollmentPrepareOutcome::Prepared { .. }),
        "join prepare should be accepted, got {prepared:?}"
    );

    let activated = yadorilink_daemon::coordination_client::activate_join(
        &addr,
        &second_installation.auth,
        &group_id,
        &join_operation,
        &second_device_id,
    )
    .await;
    assert!(
        matches!(activated, ActivateOutcome::Success | ActivateOutcome::AlreadyActive),
        "join activate should confirm the membership, got {activated:?}"
    );

    let state = yadorilink_daemon::coordination_client::fetch_edge_state(
        &addr,
        &second_installation.auth,
        &group_id,
        &second_device_id,
    )
    .await
    .expect("reading the joined device's edge state should succeed");
    assert_eq!(
        state.as_deref(),
        Some("active"),
        "the joined device's edge should be reported active"
    );
}

/// Accepting an invite issued by another account.
#[tokio::test]
async fn cross_account_invite_accept_round_trips() {
    let addr = worker_addr_or_skip!("cross_account_invite_accept_round_trips");
    let _world = WORLD.lock().await;

    let owner = enrol_and_sign_in(&addr, &unique("wire-contract-owner-subject")).await;
    let (owner_device_id, _owner_config) = register_a_device("wire-contract-owner-device").await;
    let (group_id, _group_name) =
        create_an_active_group(&addr, &owner.auth, &owner_device_id).await;

    // Minting is setup, not the shape under test: the CLI mints through the
    // local daemon rather than over HTTP, so there is no shipped client
    // function here to drive. It still goes out through the CLI's own HTTP
    // client so a broken route surfaces as a failure rather than as a
    // hand-rolled request that happens to work.
    let minted: serde_json::Value = http_client::post_json(
        &format!("/shares/groups/{group_id}/invites"),
        &serde_json::json!({ "mintingDeviceId": owner_device_id, "role": "editor" }),
        &owner.auth,
    )
    .await
    .expect("minting a cross-account invite should succeed");
    let code =
        minted["code"].as_str().expect("a minted invite should carry its one-use code").to_string();

    let recipient = enrol_and_sign_in(&addr, &unique("wire-contract-recipient-subject")).await;
    let (recipient_device_id, _recipient_config) =
        register_a_device("wire-contract-recipient-device").await;

    let operation_id = unique("invite-accept-operation");
    let prepared = yadorilink_daemon::coordination_client::prepare_invite_accept(
        &addr,
        &recipient.auth,
        &operation_id,
        &code,
        &recipient_device_id,
        "on-demand",
    )
    .await;
    let accepted_group_id = match prepared {
        EnrollmentPrepareOutcome::Prepared { group_id } => group_id,
        other => panic!("invite-accept prepare should name the group, got {other:?}"),
    };
    assert_eq!(
        accepted_group_id, group_id,
        "the accepted invite should name the group it was minted for"
    );

    let activated = yadorilink_daemon::coordination_client::activate_invite_accept(
        &addr,
        &recipient.auth,
        &accepted_group_id,
        &operation_id,
        &recipient_device_id,
    )
    .await;
    assert!(
        matches!(activated, ActivateOutcome::Success | ActivateOutcome::AlreadyActive),
        "invite-accept activate should confirm the membership, got {activated:?}"
    );
}

/// Signing out revokes the installation on the DEPLOYMENT, not just locally.
///
/// The local half -- the store is empty afterwards -- proves only that the CLI
/// forgot. The half that matters is that the credential it forgot is dead on
/// the server, so the credential is SAVED before signing out and put back
/// afterwards, and the same question is asked with it again. A sign-out that
/// only deleted a file passes the first assertion and fails the second.
#[tokio::test]
async fn signing_out_revokes_the_installation_on_the_server() {
    let addr = worker_addr_or_skip!("signing_out_revokes_the_installation_on_the_server");
    let _world = WORLD.lock().await;

    enrol_and_sign_in(&addr, &unique("wire-contract-subject")).await;
    account::deletion_status().await.expect("the credential should work before signing out");

    // The exact bytes an attacker would have copied off this machine.
    let stolen = credential_store::open()
        .expect("the credential store")
        .load()
        .expect("reading the credential")
        .expect("an enrolled installation has a credential");

    yadorilink_cli::commands::auth::logout(true).await.expect("signing out should succeed");

    match account::deletion_status().await {
        Err(CoreError::NotLoggedIn) => {}
        Err(other) => panic!("expected NotLoggedIn after signing out, got {other:?}"),
        Ok(status) => {
            panic!("a signed-out installation still reached the account (state {})", status.state)
        }
    }

    // Put the copy back. Everything the installation held is present again --
    // client id, client key, refresh token -- and none of it works, because
    // what ended the session was a tombstone on the server rather than the
    // absence of a file here.
    let store = credential_store::open().expect("the credential store");
    let lock = store.lock(std::time::Duration::from_secs(5)).await.expect("lock");
    store.save(&lock, &stolen).expect("restoring");
    // Released before the call: refreshing takes this same lock.
    drop(lock);
    match account::deletion_status().await {
        Err(CoreError::AuthFailed(_)) => {}
        Err(CoreError::NotLoggedIn) => {
            panic!("the restored credential was not even loadable; this test proved nothing")
        }
        Err(other) => panic!("expected the restored credential to be refused, got {other:?}"),
        Ok(status) => panic!(
            "a revoked installation's saved credential still reached the account (state {})",
            status.state
        ),
    }
    credential_store::clear().await.ok();
}

/// `forget-local-credentials` is the local-only operation, and it is NOT
/// sign-out.
///
/// The distinction is the whole point of giving it a separate name: after it,
/// the installation is still authorized on the server, which is exactly why it
/// must not be what the "Sign Out" button does.
#[tokio::test]
async fn forgetting_local_credentials_does_not_revoke_anything() {
    let addr = worker_addr_or_skip!("forgetting_local_credentials_does_not_revoke_anything");
    let _world = WORLD.lock().await;

    enrol_and_sign_in(&addr, &unique("wire-contract-subject")).await;
    let kept = credential_store::open()
        .expect("the credential store")
        .load()
        .expect("reading the credential")
        .expect("an enrolled installation has a credential");

    yadorilink_cli::commands::auth::forget_local_credentials()
        .await
        .expect("forgetting local credentials should succeed");
    assert!(
        matches!(account::deletion_status().await, Err(CoreError::NotLoggedIn)),
        "the local store should be empty afterwards"
    );

    // Still authorized on the server. This is the fact that makes it a
    // different operation from Sign Out rather than a synonym for it.
    let store = credential_store::open().expect("the credential store");
    let lock = store.lock(std::time::Duration::from_secs(5)).await.expect("lock");
    store.save(&lock, &kept).expect("restoring");
    // Released before the call: refreshing takes this same lock.
    drop(lock);
    account::deletion_status()
        .await
        .expect("forgetting local credentials must not have revoked the installation");

    // Leave nothing live behind.
    yadorilink_cli::commands::auth::logout(true).await.expect("signing out at the end");
}

// --- 4. the FAPI 2.0 negatives, against this deployment ----------------------
//
// These used to live in `yadorilink-fapi-client/tests/{vertical_flow,negatives}
// .rs` and ran against `auth-as-spike/`, a second Authorization Server with its
// own oidc-provider, its own D1 adapter, its own migrations and a fixed-account
// auto-login. Every one of them needed a client registration that existed
// because a script had written the row -- which is the shortcut this product
// must not have, so the server that offered it is deleted and the assertions
// moved here, onto the one deployment and the one way of obtaining a client.
//
// The cost of the move is visible and worth naming: the negatives now need a
// browser approval and an upstream identity before they can start, because
// that is what it takes to hold a client_id. That is not friction to design
// around; it is the property being asserted everywhere else in this file.

/// A pushed authorization request whose client assertion is supplied by the
/// caller, so exactly one thing about it can be wrong.
///
/// Everything else -- the DPoP proof, the PKCE challenge, the form -- is what
/// the server accepts, which is what makes a refusal attributable to the
/// assertion rather than to the request around it.
async fn par_with_assertion(
    client: &FapiClient,
    assertion: &str,
    pkce: &Pkce,
    state: &str,
) -> reqwest::Response {
    let endpoint = client
        .metadata()
        .pushed_authorization_request_endpoint
        .clone()
        .expect("the server advertises a PAR endpoint");

    client
        .http()
        .post(client.to_local(&endpoint).expect("local PAR URL"))
        .header(
            "DPoP",
            client.dpop_proof_for_test("POST", &endpoint, None).expect("a fresh DPoP proof"),
        )
        .form(&[
            ("client_id", client.client_id()),
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", assertion),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("scope", LOGIN_SCOPE),
            ("prompt", "consent"),
            ("state", state),
            ("code_challenge", pkce.challenge()),
            ("code_challenge_method", "S256"),
        ])
        .send()
        .await
        .expect("PAR")
}

/// A GET at a protected resource with a caller-supplied `DPoP` header, or none
/// at all.
async fn protected_get_with(
    client: &FapiClient,
    endpoint: &str,
    scheme: &str,
    access_token: &str,
    proof: Option<&str>,
) -> reqwest::Response {
    let mut request = client
        .http()
        .get(client.to_local(endpoint).expect("local resource URL"))
        .header("Authorization", format!("{scheme} {access_token}"));
    if let Some(proof) = proof {
        request = request.header("DPoP", proof);
    }
    request.send().await.expect("protected GET")
}

/// Print a response -- including the challenge, which is where a resource
/// server says *how* it wants to be talked to -- and reduce it to
/// `(status, body)`.
async fn outcome(label: &str, response: reqwest::Response) -> (u16, String) {
    let status = response.status().as_u16();
    let challenge =
        response.headers().get("www-authenticate").and_then(|v| v.to_str().ok()).map(str::to_owned);
    let body = response.text().await.unwrap_or_default();
    println!("  {label}\n    -> {status} {body}");
    if let Some(challenge) = challenge {
        println!("       www-authenticate: {challenge}");
    }
    (status, body)
}

/// The OAuth `error` code out of an error body, or the body itself if it is not
/// one. The status alone does not identify the cause, and the codes are what
/// the profile actually specifies.
fn error_code(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
        .unwrap_or_else(|| body.to_owned())
}

/// A complete grant for an already-registered client: PAR, the browser legs,
/// and the code exchange.
async fn fresh_grant(
    addr: &str,
    client: &FapiClient,
    subject: &str,
) -> yadorilink_fapi_client::TokenResponse {
    let pkce = Pkce::generate();
    let state = unique("negatives-state");
    let pushed = client
        .push_authorization_request(&AuthorizationRequest {
            redirect_uri: REDIRECT_URI,
            scope: LOGIN_SCOPE,
            state: &state,
            prompt: Some("consent"),
            pkce: &pkce,
        })
        .await
        .expect("PAR");
    let code = authorization_code(addr, client, &pushed.request_uri, &state, subject).await;
    client.exchange_authorization_code(&code, REDIRECT_URI, &pkce).await.expect("code exchange")
}

/// Everything this deployment must refuse, each wrong in exactly one way.
///
/// One test rather than fourteen because every case needs a registered client,
/// and a registration costs a whole bootstrap transaction with two browser
/// round trips. Each section announces itself and asserts its own refusal code,
/// so a failure names the leg that broke.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one test by design (see above): each refusal case is a short section \
              sharing one registered client"
)]
async fn the_authorization_server_refuses_every_request_that_is_wrong_in_exactly_one_way() {
    let addr = worker_addr_or_skip!(
        "the_authorization_server_refuses_every_request_that_is_wrong_in_exactly_one_way"
    );
    let _world = WORLD.lock().await;
    use_a_file_credential_store();
    credential_store::clear().await.ok();

    let subject = unique("negatives-subject");
    let registered = register_a_client(&addr, &subject, "wire-contract-negatives").await;
    let client_key_jwk = registered.client_key.to_jwk_json();
    let client = FapiClient::discover(
        reqwest::Client::new(),
        &addr,
        registered.client_id.clone(),
        registered.client_key,
        Es256Key::generate(),
    )
    .await
    .expect("discovery");

    let issuer = client.metadata().issuer.clone();
    let token_endpoint = client.metadata().token_endpoint.clone();
    let userinfo = client
        .metadata()
        .userinfo_endpoint
        .clone()
        .expect("the server advertises a protected resource");

    println!("\n  socket {addr}\n  issuer {issuer}");
    assert!(
        client.metadata().unmet_profile_requirements().is_empty(),
        "the live server does not match the profile this client requires: {:?}",
        client.metadata().unmet_profile_requirements()
    );
    // THE ISSUER IS THE SOCKET HERE, AND THAT COSTS ONE THING. Against the
    // deleted prototype these two differed, which made C4 below (a proof bound
    // to another URL) also prove that `htu` is derived from the CONFIGURED
    // issuer rather than from whatever the client dialled. This harness
    // overrides `AS_ISSUER` to the address it listens on -- deliberately, so
    // that no translation layer sits between the client and the server and can
    // hide a mismatch -- so the
    // two are indistinguishable and C4 proves only the narrower claim: a proof
    // for one PATH is not spendable at another.
    //
    // The origin half is proved where it can be: the coordination service
    // auth-resource-server.test.ts`, "refuses a proof whose htu names a
    // different origin, however convincing the Host header", where the issuer
    // and the request URL are set independently. Asserting the inequality here
    // instead would fail the run and prove nothing; stating it is the honest
    // version.
    assert_eq!(
        issuer, addr,
        "this harness sets AS_ISSUER to its own socket; if that ever changes, \
         the note above about what C4 covers has to change with it"
    );

    let registered_key = || Es256Key::from_jwk_json(&client_key_jwk).expect("the client key");

    // === A. private_key_jwt client authentication ===========================
    println!("\n=== A. client authentication ===");

    // A1. The assertion is well-formed, correctly audienced, and carries the
    // registered `kid` -- only the signing key is wrong. That is what makes
    // this a test of signature verification rather than of parsing.
    let foreign_key = match registered_key().kid() {
        Some(kid) => Es256Key::generate().with_kid(kid),
        None => Es256Key::generate(),
    };
    let forged =
        client_assertion(&foreign_key, client.client_id(), &issuer).expect("signing cannot fail");
    let (status, body) = outcome(
        "A1 PAR, assertion signed by a key the client never registered",
        par_with_assertion(&client, &forged, &Pkce::generate(), &unique("a1")).await,
    )
    .await;
    assert_eq!(status, 401, "an unregistered key must not authenticate the client");
    assert_eq!(error_code(&body), "invalid_client");

    // A2. The registered key, but addressed to somebody else. This is what
    // stops an assertion captured by one relying party from being spent here.
    const FOREIGN_AUDIENCE: &str = "https://attacker.example";
    let misaddressed = client_assertion(&registered_key(), client.client_id(), FOREIGN_AUDIENCE)
        .expect("signing cannot fail");
    let (status, body) = outcome(
        &format!("A2 PAR, assertion addressed to {FOREIGN_AUDIENCE}"),
        par_with_assertion(&client, &misaddressed, &Pkce::generate(), &unique("a2")).await,
    )
    .await;
    assert_eq!(status, 401, "an assertion for another audience must not authenticate here");
    assert_eq!(error_code(&body), "invalid_client");

    // A3. One assertion, presented twice. The first presentation must be
    // accepted, or the second proves nothing: a replay test whose control leg
    // fails is indistinguishable from a broken request.
    let replayed = client_assertion(&registered_key(), client.client_id(), &issuer)
        .expect("signing cannot fail");
    let (status, body) = outcome(
        "A3a PAR, one freshly minted assertion (control: must be accepted)",
        par_with_assertion(&client, &replayed, &Pkce::generate(), &unique("a3a")).await,
    )
    .await;
    assert_eq!(status, 201, "the control leg of the replay case must succeed: {body}");

    let (status, body) = outcome(
        "A3b PAR, the SAME assertion again (same jti, fresh PKCE, fresh DPoP proof)",
        par_with_assertion(&client, &replayed, &Pkce::generate(), &unique("a3b")).await,
    )
    .await;
    assert_eq!(status, 401, "a replayed assertion jti must be refused sequentially too");
    assert_eq!(error_code(&body), "invalid_client");

    // === B. authorization code replay =======================================
    println!("\n=== B. authorization codes ===");
    let first = fresh_grant(&addr, &client, &subject).await;
    println!("  B1 first redemption of the code -> access_token {}", first.access_token());

    // The code is spent inside `fresh_grant`; re-running the exchange with it
    // needs the code itself, so this leg re-drives PAR and keeps the code.
    let pkce = Pkce::generate();
    let state = unique("negatives-replay");
    let pushed = client
        .push_authorization_request(&AuthorizationRequest {
            redirect_uri: REDIRECT_URI,
            scope: LOGIN_SCOPE,
            state: &state,
            prompt: Some("consent"),
            pkce: &pkce,
        })
        .await
        .expect("PAR");
    let code = authorization_code(&addr, &client, &pushed.request_uri, &state, &subject).await;
    let honest = client
        .exchange_authorization_code(&code, REDIRECT_URI, &pkce)
        .await
        .expect("the first redemption of a code must succeed");

    let err = client
        .exchange_authorization_code(&code, REDIRECT_URI, &pkce)
        .await
        .expect_err("a redeemed authorization code must not be redeemable again");
    println!("  B2 the SAME code redeemed a second time -> {err}");
    assert_eq!(err.status(), Some(400));
    assert_eq!(err.oauth_error(), Some("invalid_grant"));

    // Detecting the replay only helps if it also costs the attacker the tokens.
    // Observed rather than assumed: the access token the honest redemption
    // produced is checked after the replay.
    let (status, body) = outcome(
        "B3 the honest access token, after the code was replayed",
        client.protected_get(&userinfo, honest.access_token()).await.expect("protected GET"),
    )
    .await;
    println!(
        "     (a 401 here means replaying the code tore the whole grant down; \
         a 200 means only the replay was refused)"
    );
    assert!(
        status == 401 || status == 200,
        "unexpected status {status} at the protected resource: {body}"
    );

    // === C. DPoP sender constraint ==========================================
    // A grant of its own: section B may have revoked the previous one.
    println!("\n=== C. DPoP sender constraint ===");
    let tokens = fresh_grant(&addr, &client, &subject).await;
    println!("  dpop jkt {}", client.dpop_jkt());

    // C0. The control. Everything below differs from this by one field.
    let (status, body) = outcome(
        "C0 control: correct key, correct htm/htu, correct ath",
        client.protected_get(&userinfo, tokens.access_token()).await.expect("protected GET"),
    )
    .await;
    assert_eq!(
        status, 200,
        "the control leg must succeed or nothing below is attributable: {body}"
    );

    // C1. No proof at all, presented the way a bearer-token client would.
    let (status, body) = outcome(
        "C1 no DPoP header, Authorization: Bearer",
        protected_get_with(&client, &userinfo, "Bearer", tokens.access_token(), None).await,
    )
    .await;
    assert_eq!(status, 401, "a sender-constrained token must be useless as a bearer token");
    println!("     error {}", error_code(&body));

    // C2. No proof, but the right scheme -- so the refusal cannot be explained
    // by the server simply not recognising `Bearer`.
    //
    // The status here is 400 `invalid_request`, not 401. That is a real
    // difference from C1 and worth stating rather than smoothing over: RFC 9449
    // section 7.1 describes a resource server answering an unauthenticated
    // request with 401 and a `DPoP` challenge, and this server does exactly that
    // when the scheme is `Bearer` (C1). Presenting the `DPoP` scheme with no
    // proof is instead treated as a malformed request. Both refuse; the token
    // buys nothing either way. A client must therefore not branch on 401 alone
    // to decide "this token needs a proof".
    let (status, body) = outcome(
        "C2 no DPoP header, Authorization: DPoP",
        protected_get_with(&client, &userinfo, "DPoP", tokens.access_token(), None).await,
    )
    .await;
    assert!(
        (400..500).contains(&status),
        "the DPoP scheme without a proof must not be enough, got {status}: {body}"
    );
    assert_ne!(status, 200);
    println!("     error {}", error_code(&body));

    // C3. A correctly shaped, freshly minted, correctly `ath`'d proof -- signed
    // by a different key. The only difference from C0 is the private key, so
    // the refusal is attributable to possession and not to a missing header.
    let impostor = FapiClient::discover(
        reqwest::Client::new(),
        &addr,
        registered.client_id.clone(),
        registered_key(),
        Es256Key::generate(),
    )
    .await
    .expect("discovery");
    assert_ne!(impostor.dpop_jkt(), client.dpop_jkt());
    let (status, body) = outcome(
        &format!("C3 a valid proof signed by a different key (jkt {})", impostor.dpop_jkt()),
        impostor.protected_get(&userinfo, tokens.access_token()).await.expect("protected GET"),
    )
    .await;
    assert_eq!(status, 401, "a stolen access token plus a freshly minted proof must not be enough");
    println!("     error {}", error_code(&body));

    // C4. The right key and the right `ath`, bound to a different URL. A proof
    // captured at one endpoint must not be spendable at another.
    let wrong_htu = client
        .dpop_proof_for_test("GET", &token_endpoint, Some(tokens.access_token()))
        .expect("a proof for the wrong endpoint");
    let (status, body) = outcome(
        &format!("C4 proof with htu = {token_endpoint}, presented at {userinfo}"),
        protected_get_with(&client, &userinfo, "DPoP", tokens.access_token(), Some(&wrong_htu))
            .await,
    )
    .await;
    assert_eq!(status, 401, "a proof bound to another URL must be refused");
    println!("     error {}", error_code(&body));

    // C5. The right key, the right URL, the wrong method.
    let wrong_htm = client
        .dpop_proof_for_test("POST", &userinfo, Some(tokens.access_token()))
        .expect("a proof for the wrong method");
    let (status, body) = outcome(
        "C5 proof with htm = POST, presented on a GET",
        protected_get_with(&client, &userinfo, "DPoP", tokens.access_token(), Some(&wrong_htm))
            .await,
    )
    .await;
    assert_eq!(status, 401, "a proof bound to another method must be refused");
    println!("     error {}", error_code(&body));

    // === D. refresh rotation ================================================
    println!("\n=== D. refresh token rotation ===");
    let spent = tokens.refresh_token().to_owned();

    let rotated = client.refresh(&spent).await.expect("the first refresh must succeed");
    let next = rotated.refresh_token().to_owned();
    println!("  D1 refresh -> 200, a different refresh token");
    assert_ne!(next, spent, "the spent refresh token must not be reissued");

    // D2. Use the successor. A rotated-away token is still accepted while its
    // successor is unused and the rotation is recent (a client that crashed
    // before storing the successor), so the replay below is only "wrong in
    // exactly one way" after the successor has been used.
    let confirmed = client.refresh(&next).await.expect("the successor must be redeemable");
    println!("  D2 refresh with the successor -> 200, the successor is now confirmed");
    let (status, body) = outcome(
        "D2 control: the newest access token, before any replay",
        client.protected_get(&userinfo, confirmed.access_token()).await.expect("protected GET"),
    )
    .await;
    assert_eq!(status, 200, "the control leg must succeed or D4 proves nothing: {body}");

    let err = client
        .refresh(&spent)
        .await
        .expect_err("a rotated-away refresh token whose successor was used must not be redeemable");
    println!("  D3 the OLD refresh token, after its successor was used -> {err}");
    assert_eq!(err.status(), Some(400));
    assert_eq!(err.oauth_error(), Some("invalid_grant"));

    // A replay past a confirmed successor is reuse, and reuse revokes the grant.
    let (status, body) = outcome(
        "D4 the newest access token, after the old refresh token was replayed",
        client.protected_get(&userinfo, confirmed.access_token()).await.expect("protected GET"),
    )
    .await;
    assert_eq!(status, 401, "refresh token reuse must tear the grant down: {body}");

    println!("\n=== every negative refused ===\n");
    credential_store::clear().await.ok();
}

/// What the refresh token is, and is not, protected by.
///
/// The access token is sender-constrained: the server records the DPoP key's
/// thumbprint next to it, and a request proving a different key is refused.
/// The refresh token is not. `oidc-provider` 9.12.0 copies `jkt` onto a refresh
/// token only when the client authenticates with `none`, so for a
/// `private_key_jwt` client the refresh token carries no key binding at all.
///
/// The consequence is the whole point of writing this down: presenting the
/// refresh token with a BRAND NEW DPoP key succeeds, and returns an access
/// token bound to that new key. So the two credentials rest on different
/// defences -- the refresh token on client authentication, the access token on
/// DPoP -- and losing the DPoP key does not end a session while the refresh
/// token and the client key are still held. The revocation lifecycle is
/// built on top of this measurement; a later change that quietly starts
/// binding refresh tokens must be noticed rather than assumed.
#[tokio::test]
async fn a_refresh_token_is_protected_by_client_authentication_and_not_by_the_dpop_key() {
    let addr = worker_addr_or_skip!(
        "a_refresh_token_is_protected_by_client_authentication_and_not_by_the_dpop_key"
    );
    let _world = WORLD.lock().await;
    use_a_file_credential_store();
    credential_store::clear().await.ok();

    let subject = unique("refresh-binding-subject");
    let registered = register_a_client(&addr, &subject, "wire-contract-refresh-binding").await;
    let client_key_jwk = registered.client_key.to_jwk_json();
    let client = FapiClient::discover(
        reqwest::Client::new(),
        &addr,
        registered.client_id.clone(),
        registered.client_key,
        Es256Key::generate(),
    )
    .await
    .expect("discovery");

    let tokens = fresh_grant(&addr, &client, &subject).await;

    // A second session: the same registered client key, a DPoP key the first
    // session never had, and the refresh token the first session holds.
    let stranger = FapiClient::discover(
        reqwest::Client::new(),
        &addr,
        registered.client_id.clone(),
        Es256Key::from_jwk_json(&client_key_jwk).expect("the client key"),
        Es256Key::generate(),
    )
    .await
    .expect("discovery");
    assert_ne!(
        stranger.dpop_jkt(),
        client.dpop_jkt(),
        "the second session must hold a different DPoP key or this proves nothing"
    );

    let rotated = stranger
        .refresh(tokens.refresh_token())
        .await
        .expect("a refresh token is not bound to the DPoP key that obtained it");

    let userinfo = client.metadata().userinfo_endpoint.clone().expect("a protected resource");
    let response =
        stranger.protected_get(&userinfo, rotated.access_token()).await.expect("protected GET");
    assert_eq!(
        response.status().as_u16(),
        200,
        "the access token from that refresh is bound to the NEW key"
    );

    let refused = client.protected_get(&userinfo, rotated.access_token()).await.expect("GET");
    assert_eq!(
        refused.status().as_u16(),
        401,
        "and it is NOT bound to the key of the session that held the refresh token"
    );

    credential_store::clear().await.ok();
}
