//! Opt-in remote administration behind a reverse proxy / authenticated tunnel:
//! it adds nothing to what is bound, admits exactly one extra Host and its
//! https Origin, and keeps every existing guard.
//!
//! No daemon is running here: a request that gets past authentication reaches
//! the control-socket client and answers 503 (daemon unavailable), which is
//! what these tests treat as "admitted"; 401/403 mean refused.

use std::path::Path;

use yadorilink_http_api::{HttpApiConfig, RemoteAdminConfig, RemoteBoundary};

fn config(dir: &Path, remote: Option<RemoteAdminConfig>) -> HttpApiConfig {
    HttpApiConfig {
        #[cfg(unix)]
        control_socket_path: dir.join("daemon.sock"),
        #[cfg(windows)]
        control_pipe_name: format!("yadorilink-remote-admin-test-{}", std::process::id()),
        token_path: dir.join("http-api-token"),
        port_path: dir.join("http-api-port"),
        port: 0,
        extra_allowed_origins: Vec::new(),
        remote,
    }
}

fn proxy(host: &str) -> RemoteAdminConfig {
    RemoteAdminConfig { public_host: host.into(), boundary: RemoteBoundary::TrustedProxy }
}

#[tokio::test]
async fn trusted_proxy_binds_nothing_new_and_admits_only_the_named_host() {
    let dir = tempfile::tempdir().unwrap();
    let handle = yadorilink_http_api::bind(&config(dir.path(), Some(proxy("nas.example.net"))))
        .await
        .unwrap();
    assert!(handle.bound_addrs().iter().all(|a| a.ip().is_loopback()));
    let (port, token) = (handle.port, handle.token.clone());
    tokio::spawn(yadorilink_http_api::run(handle));
    let c = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/api/status");
    let get = |host: &'static str, origin: Option<&'static str>, bearer: bool| {
        let mut r = c.get(&url).header("Host", host);
        if let Some(o) = origin {
            r = r.header("Origin", o);
        }
        if bearer {
            r = r.bearer_auth(&token);
        }
        async move { r.send().await.unwrap().status().as_u16() }
    };
    assert_eq!(get("nas.example.net", Some("https://nas.example.net"), true).await, 503);
    assert_eq!(get("nas.example.net", None, false).await, 401, "token still required");
    assert_eq!(get("nas.example.net", Some("https://evil.example"), true).await, 403);
    assert_eq!(get("nas.example.net", Some("http://nas.example.net"), true).await, 403);
    assert_eq!(get("evil.example", None, true).await, 403);
    assert_eq!(get("nas.example.net.evil.example", None, true).await, 403);
}

#[tokio::test]
async fn without_the_opt_in_the_public_name_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let handle = yadorilink_http_api::bind(&config(dir.path(), None)).await.unwrap();
    let (port, token) = (handle.port, handle.token.clone());
    tokio::spawn(yadorilink_http_api::run(handle));
    let r = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/api/status"))
        .header("Host", "nas.example.net")
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}
