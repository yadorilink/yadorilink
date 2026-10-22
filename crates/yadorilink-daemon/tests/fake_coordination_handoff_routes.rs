//! Route-level tests for `FakeCoordination`'s three handoff endpoints.
//!
//! These exist because the handoff routes are the only ones this fake
//! answers from test-supplied canned data rather than from its own state,
//! which makes two things easy to get wrong and impossible to notice from a
//! scenario test:
//!
//! 1. **Prefix shadowing.** `/handoff/lease` is a strict prefix of
//!    `/handoff/lease/{leaseId}/release`. Matching lease first silently
//!    answers every release call as a lease request -- a scenario test would
//!    see a plausible response and a wrong request count, not an error.
//! 2. **The unconfigured default.** Before these routes were parsed at all,
//!    they fell through to this fake's blanket `204`, and every test that
//!    does not opt in must keep seeing exactly that. A regression here would
//!    change behaviour for test binaries that never mention handoff.
//!
//! Driven over a raw socket rather than an HTTP client: integration tests
//! link only against this crate and its dev-dependencies, and the crate's
//! `reqwest` is a regular dependency, so it is not nameable from here. A
//! hand-written request is also a closer match to what is being tested --
//! this fake parses request lines itself.

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use support::fake_coordination::{FakeCoordination, HandoffRoute};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Sends `POST <path>` with a JSON body and returns `(status_code, body)`.
async fn post(addr: &str, path: &str, body: &str) -> (u16, String) {
    let host = addr.trim_start_matches("http://");
    let mut stream = TcpStream::connect(host).await.expect("the fake must be listening");
    let request = format!(
        "POST {path} HTTP/1.1\r\nhost: {host}\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("unparseable response: {text}"));
    let body = text.split("\r\n\r\n").nth(1).unwrap_or_default().to_string();
    (status, body)
}

/// The default every test that does not opt in depends on.
#[tokio::test]
async fn an_unconfigured_handoff_route_answers_the_blanket_204() {
    let fake = FakeCoordination::start().await;

    for path in [
        "/shares/groups/g1/handoff/lease",
        "/shares/groups/g1/handoff/commit",
        "/shares/groups/g1/handoff/lease/lease-1/release",
    ] {
        let (status, body) = post(&fake.addr(), path, "{}").await;
        assert_eq!(status, 204, "{path} must fall through to the blanket 204 until configured");
        assert!(body.is_empty(), "a 204 carries no body, got {body:?}");
    }
}

/// A route the fake does not parse at all must be untouched by the handoff
/// parser -- the blanket fallback's semantics are not being changed.
#[tokio::test]
async fn an_unrelated_route_is_unaffected_by_the_handoff_parser() {
    let fake = FakeCoordination::start().await;

    let (status, _) = post(&fake.addr(), "/shares/groups/g1/something-else", "{}").await;
    assert_eq!(status, 204);
    assert_eq!(
        fake.handoff_request_count(HandoffRoute::Lease)
            + fake.handoff_request_count(HandoffRoute::Commit)
            + fake.handoff_request_count(HandoffRoute::Release),
        0,
        "a non-handoff path must not be recorded as a handoff request"
    );
}

#[tokio::test]
async fn a_configured_response_is_served_with_its_status_and_body() {
    let fake = FakeCoordination::start().await;
    fake.set_handoff_lease_response(
        "g1",
        200,
        serde_json::json!({ "leaseId": "lease-1", "ttlSeconds": 900 }),
    );

    let (status, body) = post(&fake.addr(), "/shares/groups/g1/handoff/lease", "{}").await;
    assert_eq!(status, 200);
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("a JSON body");
    assert_eq!(parsed["leaseId"], "lease-1");
    assert_eq!(parsed["ttlSeconds"], 900);
}

/// Configuration is per group: another group must still see the default.
#[tokio::test]
async fn a_configured_response_does_not_leak_to_another_group() {
    let fake = FakeCoordination::start().await;
    fake.set_handoff_lease_response("g1", 200, serde_json::json!({ "leaseId": "only-g1" }));

    let (status, _) = post(&fake.addr(), "/shares/groups/g2/handoff/lease", "{}").await;
    assert_eq!(status, 204, "g2 was never configured and must keep the default");
}

/// The prefix-shadowing trap: `/handoff/lease` is a prefix of the release
/// path, so a release call must not be answered as a lease request.
#[tokio::test]
async fn a_release_call_is_not_swallowed_by_the_lease_route() {
    let fake = FakeCoordination::start().await;
    fake.set_handoff_lease_response("g1", 200, serde_json::json!({ "leaseId": "wrong" }));
    fake.set_handoff_release_response("g1", 204, serde_json::Value::Null);

    let (status, _) =
        post(&fake.addr(), "/shares/groups/g1/handoff/lease/lease-7/release", "{}").await;

    assert_eq!(status, 204, "the release route's own configuration must be the one used");
    assert_eq!(
        fake.handoff_request_count(HandoffRoute::Lease),
        0,
        "a release call must never be recorded as a lease request"
    );
    assert_eq!(fake.handoff_request_count(HandoffRoute::Release), 1);
    assert_eq!(
        fake.handoff_requests()[0].lease_id.as_deref(),
        Some("lease-7"),
        "the lease id must be extracted from the path"
    );
}

#[tokio::test]
async fn request_counts_distinguish_the_three_routes_and_record_bodies() {
    let fake = FakeCoordination::start().await;

    post(&fake.addr(), "/shares/groups/g1/handoff/lease", r#"{"who":"n"}"#).await;
    post(&fake.addr(), "/shares/groups/g1/handoff/lease", r#"{"who":"n"}"#).await;
    post(&fake.addr(), "/shares/groups/g1/handoff/commit", r#"{"leaseId":"l1"}"#).await;

    assert_eq!(fake.handoff_request_count(HandoffRoute::Lease), 2);
    assert_eq!(fake.handoff_request_count(HandoffRoute::Commit), 1);
    assert_eq!(fake.handoff_request_count(HandoffRoute::Release), 0);

    let commit = fake
        .handoff_requests()
        .into_iter()
        .find(|r| r.route == HandoffRoute::Commit)
        .expect("the commit request was recorded");
    assert_eq!(commit.group_id, "g1");
    assert_eq!(commit.body, r#"{"leaseId":"l1"}"#, "the raw body is kept for assertions");
}

/// The hook must run while the request is in flight, not after the response
/// -- that ordering is the whole reason it exists, since the guard it
/// exercises re-reads state only after this call returns.
#[tokio::test]
async fn the_lease_hook_runs_before_the_response_is_written() {
    let fake = FakeCoordination::start().await;
    let fired = Arc::new(AtomicUsize::new(0));
    let hook_fired = fired.clone();
    fake.on_handoff_lease(move || {
        hook_fired.fetch_add(1, Ordering::SeqCst);
    });
    fake.set_handoff_lease_response("g1", 200, serde_json::json!({ "leaseId": "l1" }));

    let (status, _) = post(&fake.addr(), "/shares/groups/g1/handoff/lease", "{}").await;

    assert_eq!(status, 200);
    assert_eq!(
        fired.load(Ordering::SeqCst),
        1,
        "the response arrived, so the hook must already have run exactly once"
    );
}

/// The hook is scoped to the lease route: a commit or release must not fire
/// it, or a test injecting a state change would corrupt unrelated steps.
#[tokio::test]
async fn the_lease_hook_does_not_fire_for_commit_or_release() {
    let fake = FakeCoordination::start().await;
    let fired = Arc::new(AtomicUsize::new(0));
    let hook_fired = fired.clone();
    fake.on_handoff_lease(move || {
        hook_fired.fetch_add(1, Ordering::SeqCst);
    });

    post(&fake.addr(), "/shares/groups/g1/handoff/commit", "{}").await;
    post(&fake.addr(), "/shares/groups/g1/handoff/lease/l1/release", "{}").await;

    assert_eq!(fired.load(Ordering::SeqCst), 0);
}
