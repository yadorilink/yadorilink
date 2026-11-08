//! Real daemon + real HTTP server + real HTTP client, end to end -- mirrors
//! this workspace's existing daemon-integration-test convention (see e.g.
//! `crates/yadorilink-cli/tests/materialization.rs`'s `start_daemon()`):
//! build a real `DaemonState`, spawn the real
//! `control_socket::unix_transport::serve` on it, then drive it through a
//! real client. Here, the "client" is this crate's own HTTP adapter, driven
//! in turn by a real `reqwest::Client` (and, for the `Host`-header tests, a
//! raw `TcpStream` -- see `forged_host_header_is_rejected`'s doc comment for
//! why reqwest itself isn't a reliable enough tool for that one assertion).
//!
//! Unix-only, same reason `materialization.rs` is: this drives the daemon
//! over `unix_transport::serve` directly rather than exercising the
//! Windows named-pipe transport (covered by `yadorilink-daemon`'s own
//! transport tests).
#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_http_api::HttpApiConfig;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::{FileRecord, RecordKind};

/// Tests in this file share `YADORILINK_CONTROL_SOCKET` (a process-global
/// env var `start()` sets, same as `materialization.rs`'s identical
/// `start_daemon()`) and the daemon's governance-config file under the
/// process-global config directory, so they must not run concurrently with
/// each other.
static TEST_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct TestServer {
    _dir: tempfile::TempDir,
    state: Arc<DaemonState>,
    port: u16,
    token: String,
    client: reqwest::Client,
    /// A clone of this run's `AppState::sse_slots`, taken before `run`
    /// consumed the `HttpApiHandle` -- see
    /// `HttpApiHandle::sse_slots_for_test`'s own doc comment.
    sse_slots: std::sync::Arc<tokio::sync::Semaphore>,
    /// A clone of this run's connection-admission semaphore, taken the same
    /// way -- see `HttpApiHandle::conn_slots_for_test`'s own doc comment.
    conn_slots: std::sync::Arc<tokio::sync::Semaphore>,
    /// Where the daemon would offer a device-authorized stream.
    peer: yadorilink_http_api::PeerStreams,
}

impl TestServer {
    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

async fn start() -> TestServer {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(dir.path().join("blocks")).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open(dir.path().join("sync.sqlite3")).unwrap());
    let state = DaemonState::new("device-under-test".into(), sync_state, store);

    let socket_path = dir.path().join("daemon.sock");
    std::env::set_var("YADORILINK_CONTROL_SOCKET", &socket_path);

    let serve_path = socket_path.clone();
    let serve_context = std::sync::Arc::new(
        yadorilink_daemon::control_context::ControlContext::from_state(state.clone()),
    );
    tokio::spawn(async move {
        let _ =
            yadorilink_daemon::control_socket::unix_transport::serve(&serve_path, serve_context)
                .await;
    });
    yadorilink_daemon::control_socket::unix_transport::wait_until_bound(&socket_path).await;

    let config = HttpApiConfig {
        control_socket_path: socket_path,
        token_path: dir.path().join("http-api-token"),
        port_path: dir.path().join("http-api-port"),
        port: 0,
        extra_allowed_origins: Vec::new(),
        remote: None,
    };
    let handle = yadorilink_http_api::bind(&config).await.expect("http api bind");
    let port = handle.port;
    let token = handle.token.clone();
    let sse_slots = handle.sse_slots_for_test();
    let conn_slots = handle.conn_slots_for_test();
    let peer = handle.peer_streams();
    tokio::spawn(yadorilink_http_api::run(handle));
    tokio::time::sleep(Duration::from_millis(50)).await;

    TestServer {
        _dir: dir,
        state,
        port,
        token,
        client: reqwest::Client::new(),
        sse_slots,
        conn_slots,
        peer,
    }
}

/// Adds a link and indexes one hydrated file under it, the same fixture
/// shape `materialization.rs`'s own tests use (empty `blocks` list, real
/// content written straight to disk). This crate's tests never install a
/// live root-commit authority, since `materialization`/`versions` only ever
/// need a path that resolves and has *some* materialized content, never a
/// live peer/session. A `Hydrated` stamp on its own is a
/// combination production can no longer produce, so the fixture seeds the
/// pair the one way a writer produces it: `seed_prior_cycle_proof`, the
/// single commit that publishes the proof and stamps the claim together.
fn seed_linked_file(state: &DaemonState, folder: &std::path::Path, content: &[u8]) {
    std::fs::create_dir_all(folder).unwrap();
    state
        .replica_coordinator
        .link_repository()
        .add_link(&folder.to_string_lossy(), "group-1")
        .unwrap();
    std::fs::write(folder.join("notes.txt"), content).unwrap();
    state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: "notes.txt".into(),
                size: content.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    yadorilink_daemon::test_support::seed_prior_cycle_proof(
        &state.replica_coordinator,
        "group-1",
        "notes.txt",
        &folder.join("notes.txt"),
        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
    );
}

// ---------------------------------------------------------------------
// Security properties -- each tried against the real running server, not
// asserted from reading the source.
// ---------------------------------------------------------------------

#[tokio::test]
async fn request_without_a_token_is_rejected() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;

    let resp = ts.client.get(ts.url("/api/status")).send().await.unwrap();
    assert_eq!(resp.status(), 401);
}

/// `add_security_headers` (`security.rs`) is documented as running on
/// *every* response, including one an earlier layer already rejected --
/// this pins that claim down for the 401 case specifically, rather than
/// leaving it as an unverified doc comment (`lib.rs`'s own `build_router`
/// doc comment).
#[tokio::test]
async fn security_headers_are_present_on_a_401_response() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;

    let resp = ts.client.get(ts.url("/api/status")).send().await.unwrap();
    assert_eq!(resp.status(), 401);
    assert_eq!(
        resp.headers().get(reqwest::header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff",
        "even a rejected (401) response must carry X-Content-Type-Options: nosniff"
    );
    assert_eq!(
        resp.headers().get(reqwest::header::CACHE_CONTROL).unwrap(),
        "no-store",
        "even a rejected (401) response must carry Cache-Control: no-store"
    );
}

#[tokio::test]
async fn request_with_the_wrong_token_is_rejected() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;

    let resp = ts
        .client
        .get(ts.url("/api/status"))
        .bearer_auth("not-the-real-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn request_with_the_correct_token_succeeds() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;

    let resp = ts.client.get(ts.url("/api/status")).bearer_auth(&ts.token).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.get("links").is_some());
    assert!(body.get("peers").is_some());
    assert!(body.get("overall_state").is_some());
}

/// The appliance summary shows disk capacity next to free space, so the
/// block-store volume carries its size.
#[tokio::test]
async fn status_reports_the_disk_capacity_of_the_block_store_volume() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;

    let resp = ts.client.get(ts.url("/api/status")).bearer_auth(&ts.token).send().await.unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let volume = body["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["path"] == "<block store>")
        .expect("the block store volume");
    let total = volume["total_bytes"].as_u64().unwrap();
    assert!(total > 0 && total >= volume["available_bytes"].as_u64().unwrap());
}

#[tokio::test]
async fn a_forged_cross_origin_request_is_rejected() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;

    let resp = ts
        .client
        .get(ts.url("/api/status"))
        .bearer_auth(&ts.token)
        .header(reqwest::header::ORIGIN, "http://evil.example")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // The adapter's own origin is accepted (same request, only the Origin
    // header differs).
    let resp = ts
        .client
        .get(ts.url("/api/status"))
        .bearer_auth(&ts.token)
        .header(reqwest::header::ORIGIN, ts.origin())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

/// `reqwest`/`hyper` compute their own `Host` header from the request URI
/// and are not a reliable way to send an arbitrary forged one (whether an
/// explicitly-set `Host` header even survives is a `hyper`-internal
/// implementation detail this test shouldn't depend on). A raw
/// `TcpStream` with a hand-written HTTP/1.1 request line gives full,
/// unambiguous control over exactly what's on the wire, which is what a
/// real DNS-rebinding attacker's browser would also send verbatim (the
/// browser sets `Host` from the request URL; it is not something
/// attacker-controlled JS can override -- see `security.rs`'s doc
/// comment).
async fn raw_get(port: u16, path: &str, host_header: &str, token: &str) -> String {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    // Read until the header block is complete (`\r\n\r\n`) instead of to EOF:
    // this server keeps the connection open (`Connection: close` on the
    // client side doesn't force the server to also close its half), so
    // reading to EOF would just hang until this function's own timeout.
    let mut buf = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), async {
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break; // peer closed
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        std::io::Result::Ok(())
    })
    .await;
    let mut text = String::from_utf8_lossy(&buf).to_string();
    match read {
        Ok(Ok(())) => {}
        Ok(Err(e)) => text.push_str(&format!("\n[raw_get: read error: {e}]")),
        Err(_) => text.push_str("\n[raw_get: timed out waiting for a response]"),
    }
    text
}

#[tokio::test]
async fn a_forged_host_header_is_rejected() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;

    let response = raw_get(ts.port, "/api/status", "evil.example:9999", &ts.token).await;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "a Host header naming a domain other than this adapter's own loopback address must be \
         rejected (this is the DNS-rebinding defense); got: {response}"
    );

    let response =
        raw_get(ts.port, "/api/status", &format!("127.0.0.1:{}", ts.port), &ts.token).await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "the adapter's own Host:port must be accepted; got: {response}"
    );
}

#[tokio::test]
async fn bind_only_ever_uses_loopback_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let config = HttpApiConfig {
        control_socket_path: dir.path().join("daemon.sock"),
        token_path: dir.path().join("http-api-token"),
        port_path: dir.path().join("http-api-port"),
        port: 0,
        extra_allowed_origins: Vec::new(),
        remote: None,
    };
    let handle = yadorilink_http_api::bind(&config).await.unwrap();
    let addrs = handle.bound_addrs();
    assert!(!addrs.is_empty(), "must bind at least one address");
    for addr in addrs {
        assert!(addr.ip().is_loopback(), "must never bind a non-loopback address, got {addr}");
    }
}

// ---------------------------------------------------------------------
// Functional coverage of the read-only and mutating endpoints.
// ---------------------------------------------------------------------

#[tokio::test]
async fn links_and_pause_resume_round_trip() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let folder = ts._dir.path().join("shared");
    seed_linked_file(&ts.state, &folder, b"hello world");
    let local_path = folder.to_string_lossy().to_string();

    let links: serde_json::Value = ts
        .client
        .get(ts.url("/api/links"))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let links = links["links"].as_array().unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0]["local_path"], local_path);
    assert_eq!(links[0]["paused"], false);

    let resp = ts
        .client
        .post(ts.url("/api/pause"))
        .bearer_auth(&ts.token)
        .json(&serde_json::json!({ "path": local_path }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let links: serde_json::Value = ts
        .client
        .get(ts.url("/api/links"))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(links["links"][0]["paused"], true);

    let resp = ts
        .client
        .post(ts.url("/api/resume"))
        .bearer_auth(&ts.token)
        .json(&serde_json::json!({ "path": local_path }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let links: serde_json::Value = ts
        .client
        .get(ts.url("/api/links"))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(links["links"][0]["paused"], false);
}

#[tokio::test]
async fn materialization_and_versions_round_trip() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let folder = ts._dir.path().join("shared");
    seed_linked_file(&ts.state, &folder, b"hello world");
    let file_path = folder.join("notes.txt").to_string_lossy().to_string();

    let m: serde_json::Value = ts
        .client
        .get(ts.url(&format!("/api/materialization?path={}", urlencoding_lite(&file_path))))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(m["known"], true);

    let versions: serde_json::Value = ts
        .client
        .get(ts.url(&format!("/api/versions?path={}", urlencoding_lite(&file_path))))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let versions = versions["versions"].as_array().unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0]["size"], 11);
    assert_eq!(versions[0]["kind"], "ENTRY_KIND_FILE");
}

#[tokio::test]
async fn missing_path_query_param_is_a_bad_request() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;

    let resp = ts.client.get(ts.url("/api/versions")).bearer_auth(&ts.token).send().await.unwrap();
    assert_eq!(resp.status(), 400);

    let resp =
        ts.client.get(ts.url("/api/materialization")).bearer_auth(&ts.token).send().await.unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn mutating_an_unlinked_path_is_a_client_error_not_a_server_error() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;

    let resp = ts
        .client
        .post(ts.url("/api/evict"))
        .bearer_auth(&ts.token)
        .json(&serde_json::json!({ "path": "/nowhere/linked.txt" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].is_string());
}

#[tokio::test]
async fn conflicts_endpoint_is_empty_for_a_healthy_folder() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let folder = ts._dir.path().join("shared");
    seed_linked_file(&ts.state, &folder, b"hello world");

    let conflicts: serde_json::Value = ts
        .client
        .get(ts.url("/api/conflicts"))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(conflicts["conflicts"].as_array().unwrap().len(), 0);
}

/// `/api/conflicts` must forward the daemon's real per-file `ListConflicts`
/// IPC, not a per-link aggregate -- an earlier version of this endpoint
/// mistakenly claimed no such per-file IPC existed and projected
/// `LinkStatus.conflict_count` instead; this seeds an actual live
/// conflicted-copy file (a path matching
/// `yadorilink_replica_domain::conflict::is_conflict_copy_path`'s naming
/// convention, the same predicate `list_live_conflict_copies`'s SQL
/// pre-filter is re-validated against) and asserts the real per-file detail
/// comes back.
#[tokio::test]
async fn conflicts_endpoint_returns_real_per_file_detail() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let folder = ts._dir.path().join("shared");
    seed_linked_file(&ts.state, &folder, b"hello world");

    let conflict_content = b"conflicting content";
    let conflict_path = "notes (conflicted copy, 2026-01-01-000000, device-b).txt";
    ts.state
        .replica_coordinator
        .file_index_repository()
        .upsert_file(
            "group-1",
            &FileRecord {
                path: conflict_path.into(),
                size: conflict_content.len() as u64,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    let conflicts: serde_json::Value = ts
        .client
        .get(ts.url("/api/conflicts"))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows = conflicts["conflicts"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "expected exactly the one seeded conflicted-copy file: {conflicts}");
    assert_eq!(rows[0]["path"], conflict_path);
    assert_eq!(rows[0]["absolute_path"], folder.join(conflict_path).to_string_lossy().to_string());
    assert_eq!(rows[0]["local_path"], folder.to_string_lossy().to_string());
    assert_eq!(rows[0]["size"], conflict_content.len());
    assert_eq!(rows[0]["kind"], "ENTRY_KIND_FILE");
    // Why the copy is kept, the same reason the CLI and apps show.
    assert_eq!(rows[0]["reason"], "CONFLICT_REASON_CONCURRENT_EDIT");
    // No compaction is waiting on it.
}

/// Seeds a live explicit-directory row at `path`: a canonical `size=0`,
/// `mtime=0`, block-less row whose `record_kind` is `Directory`.
fn seed_directory_row(state: &DaemonState, path: &str) {
    let files = state.replica_coordinator.file_index_repository();
    let permit = yadorilink_root_authority::root_commit::RootCommitPermit::for_tests();
    files
        .upsert_file(
            "group-1",
            &FileRecord {
                path: path.into(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: vec![],
                deleted: false,
            },
            &permit,
        )
        .unwrap();
    files.set_record_kind("group-1", path, RecordKind::Directory, &permit).unwrap();
}

/// `/api/versions` and `/api/conflicts` name each row's entry kind, so a
/// client can show an explicit directory as a folder instead of a zero-byte
/// file. Reads only: nothing here needs a live root-commit authority, which
/// this fixture does not run.
#[tokio::test]
async fn versions_and_conflicts_report_each_entry_kind() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let folder = ts._dir.path().join("shared");
    seed_linked_file(&ts.state, &folder, b"hello world");
    seed_directory_row(&ts.state, "album");
    let conflict_dir = "album (conflicted copy, 2026-01-01-000000, device-b)";
    seed_directory_row(&ts.state, conflict_dir);

    let versions_of = |rel: &str| {
        let url = ts.url(&format!(
            "/api/versions?path={}",
            urlencoding_lite(&folder.join(rel).to_string_lossy())
        ));
        let req = ts.client.get(url).bearer_auth(&ts.token);
        async move { req.send().await.unwrap().json::<serde_json::Value>().await.unwrap() }
    };

    let file_versions = versions_of("notes.txt").await;
    let file_versions = file_versions["versions"].as_array().unwrap();
    assert_eq!(file_versions.len(), 1, "{file_versions:?}");
    assert_eq!(file_versions[0]["kind"], "ENTRY_KIND_FILE");

    let dir_versions = versions_of("album").await;
    let dir_versions = dir_versions["versions"].as_array().unwrap();
    assert_eq!(dir_versions.len(), 1, "{dir_versions:?}");
    assert_eq!(dir_versions[0]["kind"], "ENTRY_KIND_DIRECTORY");

    let conflicts: serde_json::Value = ts
        .client
        .get(ts.url("/api/conflicts"))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows = conflicts["conflicts"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "expected only the seeded conflict-copy directory: {conflicts}");
    assert_eq!(rows[0]["path"], conflict_dir);
    assert_eq!(rows[0]["kind"], "ENTRY_KIND_DIRECTORY");
}

#[tokio::test]
async fn connections_endpoint_returns_the_peer_list() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;

    let resp: serde_json::Value = ts
        .client
        .get(ts.url("/api/connections"))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // No coordination plane configured in this fixture, so an empty (but
    // present, correctly-shaped) peer list.
    assert!(resp["connections"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn events_stream_emits_a_status_frame() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;

    let resp = ts
        .client
        .get(ts.url("/api/events"))
        .bearer_auth(&ts.token)
        .header(reqwest::header::ORIGIN, ts.origin())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get(reqwest::header::CONTENT_TYPE).unwrap(), "text/event-stream");

    use futures_util::StreamExt;
    let mut stream = resp.bytes_stream();
    let chunk = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .expect("first SSE frame within 5s")
        .expect("stream not closed")
        .expect("no transport error");
    let text = String::from_utf8_lossy(&chunk).to_string();
    assert!(text.contains("event: status"), "expected a status frame, got: {text}");
    assert!(
        text.contains("\"overall_state\""),
        "status frame should carry the status JSON, got: {text}"
    );
}

/// A `/api/events` poller must stop polling the control socket once its
/// client disconnects, even when the daemon is idle and so the poll loop
/// never had a reason to call `tx.send` (the only place a `tx.closed()`-less
/// version of this loop would ever notice a dropped receiver). Verified here
/// via `AppState::sse_slots`'s permit count rather than by measuring process
/// CPU usage after many opened-then-closed connections -- both measure the
/// same underlying fact (whether poller tasks pile up unboundedly), but
/// reading a semaphore is far faster and gives a precise, tight timing
/// window (see the assertion below).
#[tokio::test]
async fn events_stream_poller_is_cleaned_up_on_client_disconnect() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let baseline = ts.sse_slots.available_permits();

    {
        let resp =
            ts.client.get(ts.url("/api/events")).bearer_auth(&ts.token).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        use futures_util::StreamExt;
        let mut stream = resp.bytes_stream();
        // Read the first frame to confirm the poller task actually started
        // (and therefore actually holds a permit) before checking it below.
        let _first_frame = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("first SSE frame within 5s")
            .expect("stream not closed")
            .expect("no transport error");
        assert_eq!(
            ts.sse_slots.available_permits(),
            baseline - 1,
            "an open /api/events stream must hold exactly one sse_slots permit"
        );
        // `resp`/`stream` are dropped at the end of this block, closing the
        // underlying connection -- the same thing a browser tab close, page
        // reload, or the bundled Web UI's own reconnect loop does.
    }

    // The server-side poller notices the disconnect via `tx.closed()` and
    // exits promptly (measured release time after a real disconnect is
    // ~12ms); poll for up to a few hundred milliseconds rather than
    // asserting immediately, since the notification is asynchronous. This
    // window is deliberately tight -- `POLL_INTERVAL` (`events.rs`) is 2s,
    // and this daemon test fixture's auto-updater independently flips
    // `update.state` a few seconds after startup, which reaches `tx.send`
    // and would let even a `tx.closed()`-less poller exit and release its
    // permit within a several-second window, passing this assertion for a
    // reason unrelated to the fix under test. Staying well under both of
    // those keeps this test discriminating: a poller that never checks
    // `tx.closed()` genuinely cannot release its permit this fast.
    let recovered = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            if ts.sse_slots.available_permits() == baseline {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(
        recovered.is_ok(),
        "the /api/events poller must exit and release its slot within 500ms of the client \
         disconnecting instead of polling the control socket forever -- available_permits \
         stuck at {}, baseline {}",
        ts.sse_slots.available_permits(),
        baseline
    );
}

/// `/api/events` must reject a connection attempt once `sse_slots` is
/// exhausted, rather than serving it uncapped.
#[tokio::test]
async fn events_stream_is_capped_at_max_concurrent_streams() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let cap = ts.sse_slots.available_permits();

    // Acquire every slot directly (bypassing HTTP entirely) rather than
    // opening `cap` real connections -- exercises the same rejection path
    // deterministically without depending on how many concurrent
    // connections this test process can actually open in time.
    let mut held = Vec::new();
    for _ in 0..cap {
        held.push(ts.sse_slots.clone().try_acquire_owned().unwrap());
    }

    let resp = ts.client.get(ts.url("/api/events")).bearer_auth(&ts.token).send().await.unwrap();
    assert_eq!(resp.status(), 503, "a full sse_slots must reject a new stream, not queue it");

    drop(held);
}

/// An `/api/events` stream must keep delivering frames well past
/// `conn_limit`'s connection-level idle timeout (60s): its own poller
/// writes a fresh `status` frame at least every `POLL_INTERVAL` (2s)
/// whenever the underlying snapshot changed since the last poll
/// (`handlers::events`), and even when it doesn't, axum's own
/// `KeepAlive::default()` (also wired in `handlers::events::events`) writes
/// a comment frame at least every 15s regardless -- both are ordinary
/// writes on the connection, so both reset the same rolling idle deadline
/// that governs every other connection. Verified here by staying connected
/// for a real, elapsed-time-measured window comfortably longer than that
/// 60s timeout and confirming frames keep arriving throughout, not merely
/// that the initial connection succeeded.
#[tokio::test]
async fn events_stream_survives_well_past_the_connection_idle_timeout() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;

    let resp = ts.client.get(ts.url("/api/events")).bearer_auth(&ts.token).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    use futures_util::StreamExt;
    let mut stream = resp.bytes_stream();
    let started = std::time::Instant::now();
    let mut frame_count = 0usize;
    // `conn_limit::CONNECTION_IDLE_TIMEOUT` is 60s; stay connected for
    // comfortably longer than that, reading whatever frames arrive (status
    // updates or keep-alive comments), and confirm the stream is still
    // alive and delivering data at the very end.
    while started.elapsed() < Duration::from_secs(70) {
        match tokio::time::timeout(Duration::from_secs(20), stream.next()).await {
            Ok(Some(Ok(_chunk))) => frame_count += 1,
            Ok(Some(Err(e))) => {
                panic!("transport error after {:?} connected: {e}", started.elapsed())
            }
            Ok(None) => panic!(
                "stream closed after only {:?}, well before the 60s idle timeout should even \
                 be reachable for a stream that keeps writing",
                started.elapsed()
            ),
            Err(_) => panic!(
                "no frame (status update or keep-alive comment) arrived within 20s -- axum's \
                 own KeepAlive::default() should have written a comment frame by 15s at the \
                 latest even on a perfectly idle daemon"
            ),
        }
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(70),
        "expected to stay connected for the full 70s window (comfortably past the 60s idle \
         timeout), only lasted {elapsed:?}"
    );
    assert!(frame_count > 0, "expected at least one frame delivered over the 70s window");
}

/// When the best-effort `[::1]` bind fails
/// (simulated here by squatting it first, standing in for another local
/// process), this adapter must NOT treat `localhost`/`[::1]` as its own
/// identity -- `localhost` resolves to `[::1]` first on many systems, so
/// trusting that hostname while not actually owning `[::1]` means whatever
/// IS answering there gets treated as same-origin by this adapter's own
/// Origin check, and shares the same `localStorage` bucket (keyed by
/// origin string, not by which process currently answers there) the
/// bundled Web UI persists its bearer token into.
#[tokio::test]
async fn partial_v6_bind_does_not_trust_localhost_identity() {
    // Hard-codes the same port across the `[::1]` and `127.0.0.1` binds
    // below -- under concurrent test execution, a different concurrently
    // running test could otherwise grab that port on `127.0.0.1` first
    // (Linux shares the ephemeral port range across address families), so
    // this needs the same serialization every other daemon-backed test in
    // this file takes.
    let _guard = TEST_MUTEX.lock().await;
    let squatter = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let port = squatter.local_addr().unwrap().port();

    let dir = tempfile::tempdir().unwrap();
    let config = HttpApiConfig {
        control_socket_path: dir.path().join("daemon.sock"),
        token_path: dir.path().join("http-api-token"),
        port_path: dir.path().join("http-api-port"),
        port,
        extra_allowed_origins: Vec::new(),
        remote: None,
    };
    let handle = yadorilink_http_api::bind(&config)
        .await
        .expect("the mandatory 127.0.0.1 bind must still succeed even though [::1] is squatted");
    assert_eq!(handle.port, port, "must bind the exact requested port on 127.0.0.1");
    tokio::spawn(yadorilink_http_api::run(handle));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let response = raw_get(port, "/", &format!("localhost:{port}"), "").await;
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "must not trust the `localhost` hostname when this process could not confirm it owns \
         [::1] (a squatting process could be the one actually answering there); got: {response}"
    );

    let response = raw_get(port, "/", &format!("127.0.0.1:{port}"), "").await;
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "the 127.0.0.1 identity this process actually does own must still work; got: {response}"
    );

    drop(squatter);
}

/// RFC 7235: the `Authorization` auth-scheme token ("Bearer") is compared
/// case-insensitively.
#[tokio::test]
async fn bearer_scheme_is_case_insensitive() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let resp = ts
        .client
        .get(ts.url("/api/status"))
        .header(reqwest::header::AUTHORIZATION, format!("bearer {}", ts.token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "the Bearer scheme token must match case-insensitively");
}

// ---------------------------------------------------------------------
// Connection-level resource bounds.
//
// `conn_limit::LimitedIo` tracks one rolling idle deadline per connection
// (`conn_limit::CONNECTION_IDLE_TIMEOUT`, 60s -- twice `lib.rs::REQUEST_TIMEOUT`),
// reset by every successful read *or* write and never permanently disarmed
// by any of them -- see that module's own doc comment for why a one-shot
// disarm (the shape of an earlier version of this mechanism) is unsound
// against an adversary who controls every byte on the connection. Every
// test below issues a real concurrent request to prove the adapter
// actually recovers, not just that a permit counter changes, and every
// timing-sensitive assertion carries both a lower bound (rules out passing
// for an unrelated, faster reason) and an upper bound (proves the recovery
// is actually bounded).
// ---------------------------------------------------------------------

/// Every byte-level shape of "never lets this adapter finish responding"
/// connection that this adapter's connection-slot budget must still recover
/// from, all bounded by the exact same mechanism now
/// (`conn_limit::LimitedIo`'s single rolling idle timeout): before the
/// connection-admission gate (`conn_limit::ConnLimitedListener`) existed at
/// all, this adapter accepted every one of these and spawned a
/// permanently-live per-connection task for each, with no cap and no auth
/// check ever having a chance to run (auth only runs once a full request
/// has been parsed, which none of these connections ever provide). The four
/// shapes flooded together here:
///
/// - sends nothing at all;
/// - sends a single arbitrary byte (`G`) and nothing more;
/// - sends a complete, well-formed request line and one full header, but
///   never the blank line that would terminate the header block, so no
///   request is ever dispatched;
/// - sends exactly the fixed 24-byte HTTP/2 client preface (RFC 9113
///   section 3.4) and nothing else -- a legal start to an HTTP/2 connection
///   via prior knowledge, incomplete on its own (no SETTINGS frame follows,
///   so hyper-util's h2 codec has nothing to respond to yet).
///
/// None of these ever provokes this adapter into writing a byte back
/// (unlike the SETTINGS-completing variant covered by its own test below),
/// so every one of them is bounded purely by "no read or write since
/// accept" -- the simplest case for the rolling idle timeout.
#[tokio::test]
async fn silent_connections_of_every_shape_are_bounded_and_recover() {
    const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let cap = ts.conn_slots.available_permits();

    // Open well more than `cap` raw connections split evenly across the
    // four shapes above. These all succeed at the TCP level regardless of
    // this adapter's own admission gate (the OS accept backlog absorbs
    // them), so a successful `connect()` here proves nothing by itself --
    // the actual bound this test proves is on the server side, below.
    let flood_count = cap + 20;
    let mut flood = Vec::with_capacity(flood_count);
    for i in 0..flood_count {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", ts.port)).await.expect(
            "the OS backlog accepts the TCP handshake regardless of whether this \
             adapter is actively serving the connection yet",
        );
        match i % 4 {
            0 => {
                // Sends nothing at all.
            }
            1 => {
                stream
                    .write_all(b"G")
                    .await
                    .expect("a single-byte write on a fresh socket always succeeds");
            }
            2 => {
                let partial =
                    format!("GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n", ts.port);
                stream
                    .write_all(partial.as_bytes())
                    .await
                    .expect("writing a partial header block on a fresh socket always succeeds");
            }
            _ => {
                stream
                    .write_all(H2_PREFACE)
                    .await
                    .expect("writing the bare h2 preface on a fresh socket always succeeds");
            }
        }
        flood.push(stream);
    }

    // Give the accept loop a moment to admit everything it's willing to
    // admit from the backlog and for the bytes above to actually reach this
    // adapter.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        ts.conn_slots.available_permits(),
        0,
        "a flood of {flood_count} connections spanning every silent shape (cap {cap}) must \
         saturate, never exceed, this adapter's connection-slot budget"
    );

    // Even with every connection-slot held, this adapter is not permanently
    // wedged: a legitimate authenticated request, issued while the flood is
    // still holding every slot, eventually succeeds once a flooding
    // connection's own rolling idle deadline reclaims its slot.
    let started = std::time::Instant::now();
    let resp = tokio::time::timeout(
        Duration::from_secs(75),
        ts.client.get(ts.url("/api/status")).bearer_auth(&ts.token).send(),
    )
    .await
    .expect(
        "an authenticated request must eventually succeed once a flooding connection's idle \
         timeout reclaims its connection slot -- this adapter must recover from every one of \
         these shapes, not stay wedged forever",
    )
    .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(resp.status(), 200, "/api/status must still work correctly once a slot frees up");
    assert!(
        elapsed >= Duration::from_secs(45),
        "expected the connection-level idle timeout (60s) to actually govern recovery here, \
         not some other, faster mechanism; recovered after only {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(75),
        "expected recovery comfortably bounded well under a previously measured 150s+ hang for \
         a connection whose protective deadline never re-armed; took {elapsed:?}"
    );

    drop(flood);
}

/// The connection-level idle timeout must bound a connection even once it
/// has provoked this adapter into writing a byte back -- not just the
/// purely-silent shapes above. A connection that opens with exactly the
/// fixed 24-byte HTTP/2 client preface (RFC 9113 section 3.4) *plus* one
/// well-formed, empty SETTINGS frame (9 bytes: a 3-byte zero length, a
/// 1-byte SETTINGS frame type, a 1-byte zero flags field, and a 4-byte zero
/// stream id -- 33 bytes total) is a completely ordinary, legal way for an
/// HTTP/2 connection to sit idle: this workspace enables hyper-util's
/// `http2` cargo feature workspace-wide (pulled in transitively by
/// `igd-next`, confirmed via `cargo tree -e features -i hyper-util`,
/// nothing to do with this crate's own needs -- see `Cargo.lock`), so
/// hyper-util's `auto::Builder` serves this connection via HTTP/2 prior
/// knowledge and its h2 codec unconditionally writes an initial SETTINGS
/// frame back as part of the handshake, once the client's own preface and
/// SETTINGS frame have both been read -- before anything resembling a real
/// request exists. A mechanism that grants any kind of permanent exemption
/// once a connection has produced *a* write is exactly what this shape is
/// designed to defeat: this write happens purely from ordinary protocol
/// bookkeeping, with the connection going on to do nothing else ever again.
/// Under the rolling idle timeout this is no different from any other
/// connection that goes quiet after some activity -- its deadline was reset
/// by that read/write pair, then elapses on schedule since nothing follows.
#[tokio::test]
async fn an_http2_preface_plus_settings_then_silent_connection_is_bounded_and_recovers() {
    const H2_PREFACE_PLUS_EMPTY_SETTINGS: &[u8] = &[
        // 24-byte HTTP/2 client connection preface (RFC 9113 section 3.4).
        b'P', b'R', b'I', b' ', b'*', b' ', b'H', b'T', b'T', b'P', b'/', b'2', b'.', b'0', b'\r',
        b'\n', b'\r', b'\n', b'S', b'M', b'\r', b'\n', b'\r', b'\n',
        // A well-formed, empty SETTINGS frame: 3-byte length (0), 1-byte
        // type (0x04 == SETTINGS), 1-byte flags (0), 4-byte stream id (0).
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(H2_PREFACE_PLUS_EMPTY_SETTINGS.len(), 33);

    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let cap = ts.conn_slots.available_permits();

    let flood_count = cap + 5;
    let mut flood = Vec::with_capacity(flood_count);
    for _ in 0..flood_count {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", ts.port)).await.expect(
            "the OS backlog accepts the TCP handshake regardless of whether this \
             adapter is actively serving the connection yet",
        );
        stream
            .write_all(H2_PREFACE_PLUS_EMPTY_SETTINGS)
            .await
            .expect("writing the 33-byte preface+SETTINGS on a fresh socket always succeeds");
        flood.push(stream);
    }

    // Give hyper-util's auto-detector time to read the full preface and
    // SETTINGS frame, and the h2 codec time to write its own automatic
    // initial SETTINGS frame back in response.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        ts.conn_slots.available_permits(),
        0,
        "a flood of {flood_count} preface+SETTINGS-then-silent connections (cap {cap}) must \
         saturate this adapter's connection-slot budget"
    );

    let started = std::time::Instant::now();
    let resp = tokio::time::timeout(
        Duration::from_secs(75),
        ts.client.get(ts.url("/api/status")).bearer_auth(&ts.token).send(),
    )
    .await
    .expect(
        "an authenticated request must eventually succeed once the rolling idle timeout \
         reclaims a slot held by a connection that completed a legal h2 handshake and then \
         went silent -- a connection must never be able to earn a permanent exemption just by \
         provoking one write back from this adapter",
    )
    .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(resp.status(), 200, "/api/status must still work correctly once a slot frees up");
    assert!(
        elapsed >= Duration::from_secs(45),
        "expected the connection-level idle timeout (60s) to actually govern recovery here, \
         not some other, faster mechanism; recovered after only {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(75),
        "expected recovery comfortably bounded well under a previously measured 150s+ hang with \
         zero recovery for this exact shape; took {elapsed:?}"
    );

    drop(flood);
}

/// Reads a raw HTTP/1.1 response's status line and headers off `stream`
/// (stopping at the blank line that terminates the header block), then
/// reads exactly `Content-Length` further bytes of body -- mirrors what a
/// real HTTP/1.1 keep-alive client does after issuing one request, without
/// closing or otherwise touching the connection afterward. Returns the
/// still-open stream so the caller can then leave it idle.
async fn read_one_keepalive_response(stream: &mut tokio::net::TcpStream) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("response headers within 5s")
            .expect("no transport error while reading response headers");
        assert!(n > 0, "connection closed before a complete response was received");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
    };
    let header_text = String::from_utf8_lossy(&buf[..header_end]).to_string();
    assert!(
        header_text.starts_with("HTTP/1.1 200"),
        "expected a 200 status line, got: {header_text}"
    );
    let content_length: usize = header_text
        .split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length").then(|| value.trim().parse().unwrap())
        })
        .expect("a JSON response must carry Content-Length");

    let mut body_read = buf.len() - header_end;
    while body_read < content_length {
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("response body within 5s")
            .expect("no transport error while reading response body");
        assert!(n > 0, "connection closed before the full response body was received");
        body_read += n;
    }
}

/// The other shape that must be bounded with zero protocol trickery at all:
/// one ordinary, fully authenticated `GET /api/status` request completed
/// over an HTTP/1.1 keep-alive connection, followed by silence forever --
/// exactly what a real browser tab does between dashboard refreshes. A
/// mechanism that treats "this adapter has produced a real response" as a
/// permanent exemption from any further timeout is defeated by this shape
/// trivially, since it requires no adversarial behavior whatsoever; the
/// rolling idle timeout instead treats that response write the same as any
/// other activity -- it resets the deadline, which then elapses on
/// schedule because nothing follows.
#[tokio::test]
async fn a_completed_keepalive_request_then_idle_connection_is_bounded_and_recovers() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let baseline = ts.conn_slots.available_permits();

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", ts.port)).await.unwrap();
    let request = format!(
        "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\n\r\n",
        ts.port, ts.token
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    read_one_keepalive_response(&mut stream).await;

    assert_eq!(
        ts.conn_slots.available_permits(),
        baseline - 1,
        "the completed request's own connection must still hold its connection slot \
         immediately after the response, before any idle timeout has had a chance to fire"
    );

    // Send nothing further -- exactly what a browser does between requests
    // on a keep-alive connection it intends to reuse later.
    let started = std::time::Instant::now();
    let recovered = tokio::time::timeout(Duration::from_secs(75), async {
        loop {
            if ts.conn_slots.available_permits() == baseline {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let elapsed = started.elapsed();
    assert!(
        recovered.is_ok(),
        "a connection that completed one ordinary authenticated request and then went idle \
         forever over keep-alive must still have its connection slot reclaimed once the \
         connection-level idle timeout elapses -- available_permits stuck at {}, baseline {}",
        ts.conn_slots.available_permits(),
        baseline,
    );
    assert!(
        elapsed >= Duration::from_secs(45),
        "expected the connection-level idle timeout (60s) to actually govern recovery here, \
         not some other, faster mechanism; recovered after only {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(75),
        "expected recovery comfortably bounded well under a previously measured 150s+ hang with \
         zero recovery for this exact shape; took {elapsed:?}"
    );

    drop(stream);
}

/// A minimal HTTP-API-only fixture (no real daemon) whose control socket is
/// answered by a listener that accepts every connection and then holds it
/// open forever without ever reading or writing anything back -- stands in
/// for a daemon whose control-socket accept loop is wedged (deadlocked,
/// overwhelmed, ...) rather than simply absent or refusing the connection
/// outright, which is what specifically exercises `control_client.rs`'s own
/// read-side timeout instead of an immediate `connect()` failure.
struct HangingControlServer {
    _dir: tempfile::TempDir,
    port: u16,
    token: String,
    client: reqwest::Client,
}

impl HangingControlServer {
    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }
}

async fn start_with_hanging_control_socket() -> HangingControlServer {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("daemon.sock");

    let hang_listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = hang_listener.accept().await {
            // Accepted and never touched again: no read, no write, ever --
            // held here only so dropping it (which would close the socket
            // and unblock the client with a different error than the one
            // this test means to exercise) doesn't happen while this task
            // is still running.
            held.push(stream);
        }
    });

    let config = HttpApiConfig {
        control_socket_path: socket_path,
        token_path: dir.path().join("http-api-token"),
        port_path: dir.path().join("http-api-port"),
        port: 0,
        extra_allowed_origins: Vec::new(),
        remote: None,
    };
    let handle = yadorilink_http_api::bind(&config).await.expect("http api bind");
    let port = handle.port;
    let token = handle.token.clone();
    tokio::spawn(yadorilink_http_api::run(handle));
    tokio::time::sleep(Duration::from_millis(50)).await;

    HangingControlServer { _dir: dir, port, token, client: reqwest::Client::new() }
}

/// The control-socket round trip's own timeout (`control_client.rs`'s 5s
/// `REQUEST_TIMEOUT`) is the *documented* failure path for a hung daemon --
/// a caller should see this adapter's own `503 DaemonUnavailable` JSON
/// response, not the raw TCP connection being reset out from under a fully
/// authenticated, in-flight request. This specifically guards against a
/// connection-level idle timeout that races and wins against that 5s
/// figure (or against `lib.rs::REQUEST_TIMEOUT`'s 30s figure): if the
/// connection-level deadline fires first, the caller observes a transport
/// error instead of ever seeing the JSON body this adapter means to send,
/// which is indistinguishable from this adapter having crashed.
#[tokio::test]
async fn control_socket_hang_yields_service_unavailable_not_a_connection_reset() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start_with_hanging_control_socket().await;

    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(8),
        ts.client.get(ts.url("/api/status")).bearer_auth(&ts.token).send(),
    )
    .await
    .expect(
        "a response -- successful or not -- must arrive within 8s; control_client.rs's own \
         REQUEST_TIMEOUT is 5s",
    );
    let elapsed = started.elapsed();

    let resp = result.unwrap_or_else(|e| {
        panic!(
            "expected a proper HTTP response (503 DaemonUnavailable) even though the control \
             socket never replies, not a transport-level failure -- got a transport error \
             instead: {e} (elapsed {elapsed:?})"
        )
    });
    assert_eq!(
        resp.status(),
        503,
        "a hung control-socket connection must surface as this adapter's documented \
         DaemonUnavailable response, not any other status"
    );
    assert!(
        elapsed >= Duration::from_secs(4),
        "expected control_client.rs's own 5s REQUEST_TIMEOUT to actually govern this response, \
         not some faster unrelated mechanism; only took {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(8),
        "expected the 503 within a bound tied to control_client.rs's 5s REQUEST_TIMEOUT, took \
         {elapsed:?}"
    );
}

/// Percent-encodes just the handful of bytes these tests' fixture paths can
/// contain (they're always plain temp-dir paths) -- avoids pulling in a
/// dedicated URL-encoding crate for this one test-only need.
fn urlencoding_lite(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[tokio::test]
async fn bind_records_the_bound_port_and_nothing_secret() {
    let dir = tempfile::tempdir().unwrap();
    let config = HttpApiConfig {
        control_socket_path: dir.path().join("daemon.sock"),
        token_path: dir.path().join("http-api-token"),
        port_path: dir.path().join("http-api-port"),
        port: 0,
        extra_allowed_origins: Vec::new(),
        remote: None,
    };
    let handle = yadorilink_http_api::bind(&config).await.unwrap();
    let recorded = std::fs::read_to_string(&config.port_path).expect("port file written");
    assert_eq!(recorded.lines().next(), Some(handle.port.to_string().as_str()));
    assert!(!recorded.contains(&handle.token), "the port file must never hold the token");
}

/// A request whose `Host` names another port -- what a browser sends through
/// `ssh -L <other>:127.0.0.1:<port>` -- is still refused, and the refusal
/// says why, so the operator can fix the tunnel instead of guessing.
#[tokio::test]
async fn a_tunnel_on_another_local_port_is_refused_with_a_hint() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let other = ts.port.wrapping_add(1).max(1);

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", ts.port)).await.unwrap();
    let request = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{other}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if String::from_utf8_lossy(&buf).contains("same port") {
                break;
            }
        }
        std::io::Result::Ok(())
    })
    .await;
    let response = String::from_utf8_lossy(&buf);
    assert!(
        response.starts_with("HTTP/1.1 403"),
        "a mismatched Host must stay refused: {response}"
    );
    assert!(
        response.contains("http://127.0.0.1:<port>/")
            && response.contains("same port on both sides"),
        "the refusal must say how to open the dashboard: {response}"
    );
}

#[tokio::test]
async fn the_port_file_goes_away_when_the_dashboard_stops() {
    let dir = tempfile::tempdir().unwrap();
    let config = HttpApiConfig {
        control_socket_path: dir.path().join("daemon.sock"),
        token_path: dir.path().join("http-api-token"),
        port_path: dir.path().join("http-api-port"),
        port: 0,
        extra_allowed_origins: Vec::new(),
        remote: None,
    };
    let handle = yadorilink_http_api::bind(&config).await.unwrap();
    let port = handle.port;
    let task = tokio::spawn(yadorilink_http_api::run(handle));
    // A response proves `run` is serving, so its guard exists.
    let page = reqwest::get(format!("http://127.0.0.1:{port}/")).await.unwrap();
    assert_eq!(page.status(), 200);
    assert!(config.port_path.exists(), "written while listening");
    task.abort();
    let _ = task.await;
    assert!(!config.port_path.exists(), "a stopped dashboard must not leave its port behind");
}

// ---------------------------------------------------------------------
// Folder state, timed pause, linking and the update check.
// ---------------------------------------------------------------------

async fn post_json(ts: &TestServer, path: &str, body: serde_json::Value) -> reqwest::Response {
    ts.client.post(ts.url(path)).bearer_auth(&ts.token).json(&body).send().await.unwrap()
}

/// The two product dimensions reach the page exactly as the daemon derived
/// them (the protocol's own names), together with their device lists.
#[tokio::test]
async fn links_carry_the_daemon_derived_availability_and_protection() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let folder = ts._dir.path().join("shared");
    seed_linked_file(&ts.state, &folder, b"hello world");

    let status: serde_json::Value = ts
        .client
        .get(ts.url("/api/status"))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let link = &status["links"][0];
    assert!(link["availability"].as_str().unwrap().starts_with("PRODUCT_AVAILABILITY_"), "{link}");
    assert!(link["protection"].as_str().unwrap().starts_with("DATA_PROTECTION_"), "{link}");
    for list in [
        "availability_reachable_device_ids",
        "availability_offline_device_ids",
        "protection_device_ids",
    ] {
        assert!(link[list].is_array(), "{list} missing: {link}");
    }
    assert_eq!(link["paused_until_unix"], 0);
    assert!(link["durability_evidence"].as_str().unwrap().starts_with("DURABILITY_EVIDENCE_"));
}

#[tokio::test]
async fn a_timed_pause_reports_its_deadline_and_an_unknown_length_is_refused() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let folder = ts._dir.path().join("shared");
    seed_linked_file(&ts.state, &folder, b"hello world");
    let local_path = folder.to_string_lossy().to_string();

    let resp = post_json(
        &ts,
        "/api/pause",
        serde_json::json!({ "path": local_path, "duration": "PAUSE_DURATION_FOREVER" }),
    )
    .await;
    assert_eq!(resp.status(), 400);

    let resp = post_json(
        &ts,
        "/api/pause",
        serde_json::json!({ "path": local_path, "duration": "PAUSE_DURATION_TWO_HOURS" }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let links: serde_json::Value = ts
        .client
        .get(ts.url("/api/links"))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let until = links["links"][0]["paused_until_unix"].as_i64().unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    assert!(until > now + 7000 && until <= now + 7300, "until={until} now={now}");
}

#[tokio::test]
async fn the_link_preflight_reports_the_folder_risks() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let folder = ts._dir.path().join("photos");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.jpg"), b"x").unwrap();

    let resp = post_json(
        &ts,
        "/api/link/preflight",
        serde_json::json!({ "path": folder.to_string_lossy() }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["resolved_path"],
        std::fs::canonicalize(&folder).unwrap().to_string_lossy().to_string()
    );
    let warnings = body["warnings"].as_array().unwrap();
    assert!(warnings.iter().any(|w| w.as_str().unwrap().contains("not empty")), "{body}");
    assert!(body["prohibitions"].as_array().unwrap().is_empty());
}

/// The page cannot skip the acknowledgement: the daemon refuses an
/// unacknowledged risky folder whatever sent the request.
#[tokio::test]
async fn an_unacknowledged_risky_link_or_invite_is_refused_by_the_daemon() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let folder = ts._dir.path().join("photos");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(folder.join("a.jpg"), b"x").unwrap();
    let path = folder.to_string_lossy().to_string();

    for (route, body) in [
        ("/api/link", serde_json::json!({ "path": path, "group_id": "group-1" })),
        ("/api/share/create", serde_json::json!({ "path": path, "group_name": "Photos" })),
        ("/api/share/join", serde_json::json!({ "path": path, "group_id": "group-1" })),
        ("/api/invite/accept", serde_json::json!({ "path": path, "code": "abc123" })),
    ] {
        let resp = post_json(&ts, route, body).await;
        assert_eq!(resp.status(), 400, "{route}");
        let error: serde_json::Value = resp.json().await.unwrap();
        assert!(
            error["error"].as_str().unwrap().contains("needs its risks acknowledged"),
            "{route}: {error}"
        );
    }
    assert!(ts.state.replica_coordinator.link_repository().list_links().unwrap().is_empty());

    // Acknowledged, the request gets past the gate to the enrollment, which
    // stops here only because this test daemon has no account identity.
    let resp = post_json(
        &ts,
        "/api/invite/accept",
        serde_json::json!({ "path": path, "code": "abc123", "acknowledge_risks": true }),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let error: serde_json::Value = resp.json().await.unwrap();
    assert!(!error["error"].as_str().unwrap().contains("needs its risks acknowledged"), "{error}");
}

/// Every new state-changing route keeps the adapter's barriers: the bearer
/// header, the Origin check, and a JSON body (a cross-site form post cannot
/// produce one), and none of them answers a `GET`.
#[tokio::test]
async fn the_new_routes_need_the_token_same_origin_and_a_json_post() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let routes = [
        "/api/update/check",
        "/api/link/preflight",
        "/api/link",
        "/api/unlink",
        "/api/conflicts/resolve",
        "/api/trash/restore",
        "/api/share/invite",
        "/api/share/delete",
        "/api/retained/free",
        "/api/share/revoke",
        "/api/transfers/cancel",
        "/api/transfers/retry",
        "/api/devices/remove",
        "/api/preserved/action",
        "/api/share/create",
        "/api/share/join",
        "/api/invite/accept",
    ];
    for route in routes {
        let resp = ts.client.post(ts.url(route)).json(&serde_json::json!({})).send().await.unwrap();
        assert_eq!(resp.status(), 401, "{route} without a token");

        let resp = ts
            .client
            .post(ts.url(route))
            .bearer_auth(&ts.token)
            .header(reqwest::header::ORIGIN, "http://evil.example")
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "{route} cross-origin");

        let resp = ts.client.get(ts.url(route)).bearer_auth(&ts.token).send().await.unwrap();
        assert_eq!(resp.status(), 405, "{route} as a GET");
    }
    // A form-encoded body is not accepted where a JSON one is expected.
    for route in &routes[1..] {
        let resp = ts
            .client
            .post(ts.url(route))
            .bearer_auth(&ts.token)
            .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body("path=%2Ftmp")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 415, "{route} with a form body");
    }
}

fn port_file_config(dir: &std::path::Path) -> HttpApiConfig {
    HttpApiConfig {
        control_socket_path: dir.join("daemon.sock"),
        token_path: dir.join("http-api-token"),
        port_path: dir.join("http-api-port"),
        port: 0,
        extra_allowed_origins: Vec::new(),
        remote: None,
    }
}

#[tokio::test]
async fn an_old_guard_keeps_a_newer_daemons_file_on_the_same_port() {
    let dir = tempfile::tempdir().unwrap();
    let config = port_file_config(dir.path());
    let handle = yadorilink_http_api::bind(&config).await.unwrap();
    let port = handle.port;
    let task = tokio::spawn(yadorilink_http_api::run(handle));
    let page = reqwest::get(format!("http://127.0.0.1:{port}/")).await.unwrap();
    assert_eq!(page.status(), 200);
    // A newer daemon bound the same port and wrote its own file: same port,
    // different run.
    let newer = format!("{port}\n");
    std::fs::write(&config.port_path, &newer).unwrap();
    task.abort();
    let _ = task.await;
    assert_eq!(std::fs::read_to_string(&config.port_path).unwrap(), newer);
}

#[cfg(unix)]
#[tokio::test]
async fn the_port_file_is_replaced_atomically_and_stays_owner_only() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let config = port_file_config(dir.path());
    std::fs::write(&config.port_path, "stale").unwrap();
    let before = std::fs::metadata(&config.port_path).unwrap().ino();
    let handle = yadorilink_http_api::bind(&config).await.unwrap();
    let meta = std::fs::metadata(&config.port_path).unwrap();
    assert_ne!(meta.ino(), before, "renamed into place, not truncated in place");
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    let text = std::fs::read_to_string(&config.port_path).unwrap();
    assert_eq!(text.lines().next(), Some(handle.port.to_string().as_str()));
    let mut names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert!(!names.iter().any(|n| n.ends_with(".tmp")), "no temp file left: {names:?}");
}

/// The session secret the test dialler sends with its streams, and the bearer
/// value the page would present for it.
const PEER_SECRET: [u8; 32] = [9u8; 32];

fn peer_bearer() -> String {
    format!("Authorization: Bearer {}\r\n", hex::encode(PEER_SECRET))
}

/// Sends one raw request over a device-authorized stream (what the daemon
/// hands the adapter after the device connection is authorized) and returns
/// the whole response.
async fn peer_request(peer: &yadorilink_http_api::PeerStreams, request: &str) -> String {
    let (mut client, server) = tokio::io::duplex(64 * 1024);
    assert!(peer.offer(Box::new(server), PEER_SECRET), "the dashboard takes the stream");
    client.write_all(request.as_bytes()).await.unwrap();
    // Headers, then exactly `Content-Length` body bytes: the server may keep
    // the stream open after answering.
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(end) = response.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&response[..end]).to_ascii_lowercase();
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if response.len() >= end + 4 + length {
                    return;
                }
            }
            let n = client.read(&mut chunk).await.unwrap();
            if n == 0 {
                return;
            }
            response.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .expect("response in time");
    String::from_utf8_lossy(&response).into_owned()
}

/// The managing device's browser talks to a loopback port of its own, which
/// the adapter cannot know. It does not have this run's token; it has the
/// session secret its dialler sent with the stream.
#[tokio::test]
async fn a_device_authorized_stream_takes_the_session_secret_on_any_loopback_port() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    for host in ["127.0.0.1:54321", "localhost:49152", "[::1]:60000"] {
        let response = peer_request(
            &ts.peer,
            &format!(
                "GET /api/status HTTP/1.1\r\nHost: {host}\r\n{}Connection: close\r\n\r\n",
                peer_bearer()
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200"), "{host}: {response}");
    }
    let page = peer_request(
        &ts.peer,
        "GET / HTTP/1.1\r\nHost: 127.0.0.1:54321\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
}

/// Being a device-authorized stream is not enough: another program on the
/// managing computer can reach the loopback listener too. It has no session
/// secret, so the API refuses it -- without one, with a wrong one, with this
/// run's TCP token (a different credential), and with a forged `Origin`
/// whatever else it sends.
#[tokio::test]
async fn a_device_authorized_stream_without_the_session_secret_gets_no_api() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let host = "127.0.0.1:54321";
    let wrong = format!("Authorization: Bearer {}\r\n", "0".repeat(64));
    let tcp_token = format!("Authorization: Bearer {}\r\n", ts.token);
    for auth in ["", wrong.as_str(), tcp_token.as_str()] {
        let response = peer_request(
            &ts.peer,
            &format!("GET /api/status HTTP/1.1\r\nHost: {host}\r\n{auth}Connection: close\r\n\r\n"),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 401"), "{auth:?}: {response}");
    }
    // The forged Origin is refused even when the secret is right, and when it is not.
    for auth in [peer_bearer(), wrong.clone(), String::new()] {
        let response = peer_request(
            &ts.peer,
            &format!(
                "GET /api/status HTTP/1.1\r\nHost: {host}\r\nOrigin: http://evil.example\r\n{auth}Connection: close\r\n\r\n"
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 403"), "{auth:?}: {response}");
    }
    // The shell page holds nothing and needs no secret, as on the TCP listener.
    let page = peer_request(
        &ts.peer,
        &format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
}

/// Each stream carries its own dialler's secret: one session's secret does not
/// open another session's stream.
#[tokio::test]
async fn each_device_stream_checks_its_own_session_secret() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let host = "127.0.0.1:54321";
    let other: [u8; 32] = [3u8; 32];
    let request = |secret: &[u8; 32]| {
        format!(
            "GET /api/status HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            hex::encode(secret)
        )
    };
    for (stream_secret, presented, ok) in [
        (PEER_SECRET, PEER_SECRET, true),
        (other, other, true),
        (PEER_SECRET, other, false),
        (other, PEER_SECRET, false),
    ] {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        assert!(ts.peer.offer(Box::new(server), stream_secret));
        client.write_all(request(&presented).as_bytes()).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), client.read_to_end(&mut response))
            .await
            .expect("response in time")
            .unwrap();
        let response = String::from_utf8_lossy(&response).into_owned();
        let expected = if ok { "HTTP/1.1 200" } else { "HTTP/1.1 401" };
        assert!(response.starts_with(expected), "{ok}: {response}");
    }
}

/// DNS rebinding stays closed on the device path: a page whose name merely
/// resolves to loopback sends its own name in `Host`.
#[tokio::test]
async fn a_device_authorized_stream_still_refuses_a_non_loopback_host() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    for host in ["evil.example:54321", "192.168.1.20:8484", "127.0.0.1.evil.example", ""] {
        let response = peer_request(
            &ts.peer,
            &format!("GET /api/status HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 403") || response.starts_with("HTTP/1.1 400"),
            "{host:?}: {response}"
        );
    }
}

/// `Origin` is what keeps other pages in the
/// managing device's browser out: it must be this page's own, and a
/// state-changing request must carry it.
#[tokio::test]
async fn a_device_authorized_stream_refuses_foreign_origins_and_originless_changes() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let host = "127.0.0.1:54321";
    let refused = [
        format!("GET /api/status HTTP/1.1\r\nHost: {host}\r\nOrigin: http://evil.example\r\nConnection: close\r\n\r\n"),
        format!("GET /api/status HTTP/1.1\r\nHost: {host}\r\nOrigin: http://127.0.0.1:1\r\nConnection: close\r\n\r\n"),
        format!("GET /api/status HTTP/1.1\r\nHost: {host}\r\nOrigin: null\r\nConnection: close\r\n\r\n"),
        format!("POST /api/pause HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"),
    ];
    for request in &refused {
        let response = peer_request(&ts.peer, request).await;
        assert!(response.starts_with("HTTP/1.1 403"), "{request}: {response}");
    }
    let body = r#"{"path":"/not/linked"}"#;
    let own = format!(
        "POST /api/pause HTTP/1.1\r\nHost: {host}\r\nOrigin: http://{host}\r\n{}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        peer_bearer(),
        body.len()
    );
    let response = peer_request(&ts.peer, &own).await;
    assert!(
        !response.starts_with("HTTP/1.1 403") && !response.starts_with("HTTP/1.1 401"),
        "a same-origin change reaches its handler: {response}"
    );
}

/// The TCP listener keeps every rule it had: the device path widens nothing
/// for other local processes.
#[tokio::test]
async fn the_tcp_listener_still_needs_the_token_and_its_own_port() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let resp = ts.client.get(ts.url("/api/status")).send().await.unwrap();
    assert_eq!(resp.status(), 401);
    let other = ts.port.wrapping_add(1).max(1);
    let response = raw_get(ts.port, "/api/status", &format!("127.0.0.1:{other}"), &ts.token).await;
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
}

/// A stopped dashboard takes no more streams, so the daemon reports the
/// service as unavailable instead of handing them anywhere.
#[tokio::test]
async fn peer_streams_report_the_dashboard_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let config = HttpApiConfig {
        control_socket_path: dir.path().join("daemon.sock"),
        token_path: dir.path().join("http-api-token"),
        port_path: dir.path().join("http-api-port"),
        port: 0,
        extra_allowed_origins: Vec::new(),
        remote: None,
    };
    let handle = yadorilink_http_api::bind(&config).await.unwrap();
    let port = handle.port;
    let peer = handle.peer_streams();
    let task = tokio::spawn(yadorilink_http_api::run(handle));
    let page = reqwest::get(format!("http://127.0.0.1:{port}/")).await.unwrap();
    assert_eq!(page.status(), 200);
    assert!(peer.is_serving());
    task.abort();
    let _ = task.await;
    assert!(!peer.is_serving(), "a stopped dashboard must not look available");
    let (_client, server) = tokio::io::duplex(64);
    assert!(
        !peer.offer(Box::new(server), PEER_SECRET),
        "nothing takes a stream after the dashboard stopped"
    );
}

/// Stopping the dashboard ends the device streams it was already serving,
/// not only the queue: a keep-alive stream does not outlive it.
#[tokio::test]
async fn a_stopped_dashboard_ends_the_streams_it_was_serving() {
    let dir = tempfile::tempdir().unwrap();
    let config = HttpApiConfig {
        control_socket_path: dir.path().join("daemon.sock"),
        token_path: dir.path().join("http-api-token"),
        port_path: dir.path().join("http-api-port"),
        port: 0,
        extra_allowed_origins: Vec::new(),
        remote: None,
    };
    let handle = yadorilink_http_api::bind(&config).await.unwrap();
    let peer = handle.peer_streams();
    let task = tokio::spawn(yadorilink_http_api::run(handle));

    let (mut client, server) = tokio::io::duplex(64 * 1024);
    assert!(peer.offer(Box::new(server), PEER_SECRET));
    client.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:54321\r\n\r\n").await.unwrap();
    let mut chunk = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(10), client.read(&mut chunk))
        .await
        .expect("a response in time")
        .unwrap();
    assert!(String::from_utf8_lossy(&chunk[..n]).starts_with("HTTP/1.1 200"));

    task.abort();
    let _ = task.await;
    let ended = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match client.read(&mut chunk).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    })
    .await;
    assert!(ended.is_ok(), "the kept-alive stream ends with the dashboard");
}

/// Every state-changing route, including ones added later, sits behind the
/// device path's Origin rule: without `Origin` it is refused before its
/// handler runs.
#[tokio::test]
async fn every_state_changing_route_needs_origin_on_a_device_authorized_stream() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    for path in [
        "/api/pause",
        "/api/resume",
        "/api/unlink",
        "/api/conflicts/resolve",
        "/api/trash/restore",
        "/api/share/invite",
        "/api/share/delete",
        "/api/retained/free",
        "/api/share/revoke",
        "/api/transfers/cancel",
        "/api/transfers/retry",
        "/api/devices/remove",
        "/api/preserved/action",
        "/api/evict",
        "/api/restore",
        "/api/update/check",
        "/api/link/preflight",
        "/api/link",
        "/api/share/create",
        "/api/share/join",
        "/api/invite/accept",
    ] {
        let response = peer_request(
            &ts.peer,
            &format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:54321\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            ),
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 403"), "{path}: {response}");
    }
}

#[tokio::test]
async fn unlink_is_refused_for_a_wrong_group_and_for_the_last_complete_copy() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let folder = ts._dir.path().join("shared");
    seed_linked_file(&ts.state, &folder, b"hello world");
    let local_path = folder.to_string_lossy().to_string();

    let resp = post_json(
        &ts,
        "/api/unlink",
        serde_json::json!({ "path": local_path, "group_id": "some-other-group" }),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("different group"), "{body}");

    // The seeded folder is this account's only complete copy: the daemon's
    // own guard refuses, and the page cannot override it.
    let resp = post_json(&ts, "/api/unlink", serde_json::json!({ "path": local_path })).await;
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("complete copy"), "{body}");
    let links: serde_json::Value = ts
        .client
        .get(ts.url("/api/links"))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(links["links"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn resolving_a_conflict_needs_a_known_resolution_and_a_real_conflict_copy() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let folder = ts._dir.path().join("shared");
    seed_linked_file(&ts.state, &folder, b"hello world");
    let copy = folder.join("notes.txt").to_string_lossy().to_string();

    let resp = post_json(
        &ts,
        "/api/conflicts/resolve",
        serde_json::json!({ "path": copy, "resolution": "delete_everything" }),
    )
    .await;
    assert_eq!(resp.status(), 400);

    // An ordinary file is not a conflict copy: the daemon refuses.
    let resp = post_json(
        &ts,
        "/api/conflicts/resolve",
        serde_json::json!({ "path": copy, "resolution": "keep_this" }),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].is_string(), "{body}");
}

#[tokio::test]
async fn trash_lists_and_restore_refuses_what_is_not_trashed() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let folder = ts._dir.path().join("shared");
    seed_linked_file(&ts.state, &folder, b"hello world");

    let trash: serde_json::Value = ts
        .client
        .get(ts.url("/api/trash"))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(trash["files"].as_array().unwrap().is_empty());

    let path = folder.join("notes.txt").to_string_lossy().to_string();
    for whole in [false, true] {
        let resp = post_json(
            &ts,
            "/api/trash/restore",
            serde_json::json!({ "path": path, "whole_operation": whole }),
        )
        .await;
        assert_eq!(resp.status(), 400, "whole_operation={whole}");
    }
}

#[tokio::test]
async fn invite_and_device_removal_need_their_ids() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let resp = post_json(&ts, "/api/share/invite", serde_json::json!({ "group_id": "" })).await;
    assert_eq!(resp.status(), 400);
    let resp = post_json(&ts, "/api/devices/remove", serde_json::json!({ "device_id": "" })).await;
    assert_eq!(resp.status(), 400);
    let resp = post_json(&ts, "/api/share/delete", serde_json::json!({ "group_id": "" })).await;
    assert_eq!(resp.status(), 400);
    for body in [
        serde_json::json!({ "group_id": "", "device_id": "d" }),
        serde_json::json!({ "group_id": "g", "device_id": "" }),
    ] {
        let resp = post_json(&ts, "/api/share/revoke", body).await;
        assert_eq!(resp.status(), 400);
    }
    let resp = post_json(
        &ts,
        "/api/share/revoke",
        serde_json::json!({ "group_id": "g", "device_id": "d" }),
    )
    .await;
    assert!(resp.status().is_client_error(), "{}", resp.status());
    // Listing members needs the coordination plane too.
    let resp = ts.client.get(ts.url("/api/shares")).bearer_auth(&ts.token).send().await.unwrap();
    assert!(resp.status().is_client_error(), "{}", resp.status());
    for (path, body) in [
        ("/api/transfers/cancel", serde_json::json!({ "transfer_id": "" })),
        ("/api/transfers/retry", serde_json::json!({ "transfer_id": "" })),
        ("/api/transfers/retry", serde_json::json!({ "transfer_id": "t" })),
        ("/api/transfers/retry", serde_json::json!({ "transfer_id": "t", "direction": "any" })),
    ] {
        assert_eq!(post_json(&ts, path, body).await.status(), 400, "{path}");
    }
    // An unknown id is the daemon's refusal, not a server error.
    let resp =
        post_json(&ts, "/api/transfers/cancel", serde_json::json!({ "transfer_id": "nope" })).await;
    assert!(resp.status().is_client_error(), "{}", resp.status());
    // Without coordination access the daemon refuses rather than the adapter failing.
    let resp = post_json(&ts, "/api/share/delete", serde_json::json!({ "group_id": "g" })).await;
    assert!(resp.status().is_client_error(), "{}", resp.status());
    // Without coordination access the daemon refuses rather than the adapter failing.
    let resp =
        post_json(&ts, "/api/devices/remove", serde_json::json!({ "device_id": "nope" })).await;
    assert!(resp.status().is_client_error(), "{}", resp.status());
}

#[tokio::test]
async fn preserved_items_list_empty_and_actions_validate() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let list: serde_json::Value = ts
        .client
        .get(ts.url("/api/preserved"))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(list["items"].as_array().unwrap().is_empty());

    let resp = post_json(
        &ts,
        "/api/preserved/action",
        serde_json::json!({ "group_id": "g", "item_id": "i", "action": "explode" }),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let resp = post_json(
        &ts,
        "/api/preserved/action",
        serde_json::json!({ "group_id": "g", "item_id": "missing", "action": "discard" }),
    )
    .await;
    assert!(resp.status().is_client_error(), "{}", resp.status());
}

#[tokio::test]
async fn the_device_list_needs_the_account_and_the_token() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let resp = ts.client.get(ts.url("/api/devices")).send().await.unwrap();
    assert_eq!(resp.status(), 401);
    // The test daemon has no coordination service: the daemon says so.
    let resp = ts.client.get(ts.url("/api/devices")).bearer_auth(&ts.token).send().await.unwrap();
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("coordination"), "{body}");
}

#[tokio::test]
async fn transfers_list_is_refused_without_coordination_not_a_server_error() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    // Track Send needs the coordination plane; the page ignores the refusal and shows no card.
    let resp = ts.client.get(ts.url("/api/transfers")).bearer_auth(&ts.token).send().await.unwrap();
    assert!(resp.status().is_client_error(), "{}", resp.status());
}

#[tokio::test]
async fn retained_originals_list_empty_and_release_validates() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let list: serde_json::Value = ts
        .client
        .get(ts.url("/api/retained"))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list, serde_json::json!({ "items": [] }));
    let resp = post_json(&ts, "/api/retained/free", serde_json::json!({ "group_id": "" })).await;
    assert_eq!(resp.status(), 400);
    // A group with nothing kept releases nothing, and is not an error.
    let resp = post_json(&ts, "/api/retained/free", serde_json::json!({ "group_id": "g" })).await;
    assert!(resp.status().is_success() || resp.status().is_client_error(), "{}", resp.status());
}

// ---------------------------------------------------------------------
// Success paths through a real watcher. The daemon crate covers these end
// to end through its control socket; these cover the adapter in front of it
// (request validation, the daemon's answer mapped to JSON).
// ---------------------------------------------------------------------

/// Polls `condition` every 50 ms for up to 30 s.
async fn wait_until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !condition() {
        assert!(std::time::Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn current_size(state: &DaemonState, group: &str, path: &str) -> Option<u64> {
    use yadorilink_replica_domain::session_state::VersionState;
    state
        .replica_coordinator
        .sqlite()
        .dag_list_versions(group, path)
        .unwrap_or_default()
        .iter()
        .find(|v| v.state == VersionState::Current && !v.deleted)
        .map(|v| v.size)
}

/// Waits until capture has recorded everything on disk at `path`: a current
/// version of the disk's size and the path no longer journaled dirty.
async fn wait_recorded(state: &DaemonState, group: &str, folder: &std::path::Path, path: &str) {
    wait_until(path, || {
        let dirty = state
            .replica_coordinator
            .dirty_path_repository()
            .is_path_dirty(group, path)
            .unwrap_or(true);
        let disk = std::fs::metadata(folder.join(path)).map(|m| m.len()).ok();
        !dirty && disk.is_some() && current_size(state, group, path) == disk
    })
    .await;
}

/// A watched folder holding `plan.txt` ("mine") and a conflicted copy of it
/// ("theirs!"), both captured. Returns the folder and the copy's name.
async fn watched_conflict(ts: &TestServer, group: &str) -> (std::path::PathBuf, &'static str) {
    const COPY: &str = "plan (conflicted copy, 2026-01-01-000000, device-b).txt";
    let folder = ts._dir.path().join("watched");
    std::fs::create_dir_all(&folder).unwrap();
    yadorilink_daemon::test_support::watch_link(&ts.state, &folder.to_string_lossy(), group);
    std::fs::write(folder.join("plan.txt"), "mine").unwrap();
    std::fs::write(folder.join(COPY), "theirs!").unwrap();
    wait_recorded(&ts.state, group, &folder, "plan.txt").await;
    wait_recorded(&ts.state, group, &folder, COPY).await;
    // Events reach the watcher in order, so a file created now is captured only
    // after the echo of everything written before it: Keep this refuses while
    // an earlier write is still journaled.
    std::fs::write(folder.join("barrier.txt"), "b").unwrap();
    wait_recorded(&ts.state, group, &folder, "barrier.txt").await;
    (folder, COPY)
}

#[tokio::test(flavor = "multi_thread")]
async fn resolving_a_conflict_keep_this_replaces_the_original() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let (folder, copy) = watched_conflict(&ts, "http-keep-this").await;
    let resp = post_json(
        &ts,
        "/api/conflicts/resolve",
        serde_json::json!({ "path": folder.join(copy), "resolution": "keep_this" }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["kept_path"], folder.join("plan.txt").to_string_lossy().to_string());
    assert_eq!(std::fs::read_to_string(folder.join("plan.txt")).unwrap(), "theirs!");
    assert_eq!(std::fs::read_to_string(folder.join(copy)).unwrap(), "theirs!", "the copy stays");
}

#[tokio::test(flavor = "multi_thread")]
async fn resolving_a_conflict_keep_both_moves_the_copy_to_its_own_name() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let (folder, copy) = watched_conflict(&ts, "http-keep-both").await;
    let resp = post_json(
        &ts,
        "/api/conflicts/resolve",
        serde_json::json!({ "path": folder.join(copy), "resolution": "keep_both" }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let kept = std::path::PathBuf::from(body["kept_path"].as_str().unwrap());
    assert_eq!(kept, folder.join("plan (other version).txt"));
    assert_eq!(std::fs::read_to_string(&kept).unwrap(), "theirs!");
    assert_eq!(std::fs::read_to_string(folder.join("plan.txt")).unwrap(), "mine");
    assert!(!folder.join(copy).exists(), "the copy moved");
}

#[tokio::test(flavor = "multi_thread")]
async fn resolving_a_conflict_the_daemon_refuses_answers_its_reason() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let (folder, copy) = watched_conflict(&ts, "http-keep-refused").await;
    // Capture of the original is held, so the edit stays unrecorded however long
    // the request takes: the daemon must refuse, changing nothing.
    ts.state
        .replica_coordinator
        .paused_item_repository()
        .pause("http-keep-refused", "plan.txt")
        .unwrap();
    std::fs::write(folder.join("plan.txt"), "edited after the listing").unwrap();
    let resp = post_json(
        &ts,
        "/api/conflicts/resolve",
        serde_json::json!({ "path": folder.join(copy), "resolution": "keep_this" }),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("not synced yet"), "{body}");
    assert_eq!(
        std::fs::read_to_string(folder.join("plan.txt")).unwrap(),
        "edited after the listing"
    );
    assert_eq!(std::fs::read_to_string(folder.join(copy)).unwrap(), "theirs!");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deleted_file_is_listed_in_the_trash_and_restores() {
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let group = "http-trash";
    let folder = ts._dir.path().join("watched");
    std::fs::create_dir_all(&folder).unwrap();
    yadorilink_daemon::test_support::watch_link(&ts.state, &folder.to_string_lossy(), group);
    std::fs::write(folder.join("gone.txt"), "bring me back").unwrap();
    wait_recorded(&ts.state, group, &folder, "gone.txt").await;
    std::fs::remove_file(folder.join("gone.txt")).unwrap();
    wait_until("the delete to be captured", || {
        current_size(&ts.state, group, "gone.txt").is_none()
    })
    .await;

    let trash: serde_json::Value = ts
        .client
        .get(ts.url("/api/trash"))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let files = trash["files"].as_array().unwrap();
    assert_eq!(files.len(), 1, "{trash}");
    assert_eq!(files[0]["path"], "gone.txt");
    let absolute = files[0]["absolute_path"].as_str().unwrap().to_string();
    assert_eq!(absolute, folder.join("gone.txt").to_string_lossy().to_string());

    let resp = post_json(
        &ts,
        "/api/trash/restore",
        serde_json::json!({ "path": absolute, "whole_operation": false }),
    )
    .await;
    assert_eq!(resp.status(), 200, "{}", resp.text().await.unwrap());
    wait_until("the file to be back", || folder.join("gone.txt").exists()).await;
    assert_eq!(std::fs::read_to_string(folder.join("gone.txt")).unwrap(), "bring me back");
}

// --- the account-level success paths, over a stand-in coordination plane ---

async fn plane(ts: &TestServer) -> wiremock::MockServer {
    let server = wiremock::MockServer::start().await;
    yadorilink_daemon::test_support::use_coordination(&ts.state, &server.uri());
    server
}

#[tokio::test(flavor = "multi_thread")]
async fn the_device_list_and_the_folder_members_come_from_the_account() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let plane = plane(&ts).await;
    Mock::given(method("GET"))
        .and(path("/devices"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "devices": [
            { "deviceId": "device-under-test", "deviceName": "NAS", "online": false,
              "signingPublicKeyBase64": "", "signedOut": false },
            { "deviceId": "laptop", "deviceName": "Laptop", "online": true,
              "signingPublicKeyBase64": "", "signedOut": false },
            { "deviceId": "old", "deviceName": "Old", "online": false,
              "signingPublicKeyBase64": "", "signedOut": true },
        ] })))
        .mount(&plane)
        .await;
    Mock::given(method("GET"))
        .and(path("/shares"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "edges": [
            { "edgeId": "e1", "groupId": "g1", "deviceId": "laptop", "state": "active" },
            { "edgeId": "e2", "groupId": "g1", "deviceId": "phone", "state": "pending_approval" },
        ] })))
        .mount(&plane)
        .await;

    let devices: serde_json::Value = ts
        .client
        .get(ts.url("/api/devices"))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows = devices["devices"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "a signed-out device is not listed: {devices}");
    assert_eq!(rows[0]["device_name"], "NAS");
    assert_eq!(rows[0]["is_this_device"], true);
    assert_eq!(rows[0]["online"], true, "this device is always shown online");
    assert_eq!(rows[1]["device_id"], "laptop");
    assert_eq!(rows[1]["is_this_device"], false);

    let shares: serde_json::Value = ts
        .client
        .get(ts.url("/api/shares"))
        .bearer_auth(&ts.token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let edges = shares["edges"].as_array().unwrap();
    assert_eq!(edges.len(), 2, "{shares}");
    assert_eq!(edges[1]["state"], "pending_approval");
    assert_eq!(edges[0]["device_id"], "laptop");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invite_is_minted_and_its_code_returned() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let plane = plane(&ts).await;
    Mock::given(method("POST"))
        .and(path("/shares/groups/g1/invites"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "code": "ABC-123", "inviteId": "i1", "groupId": "g1", "role": "viewer",
            "expiresAtUnix": 4102444800i64, "requiresApproval": true,
        })))
        .mount(&plane)
        .await;
    let resp = post_json(
        &ts,
        "/api/share/invite",
        serde_json::json!({ "group_id": "g1", "role": "viewer", "requires_approval": true }),
    )
    .await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["code"], "ABC-123");
    assert_eq!(body["requires_approval"], true);
    let sent = plane.received_requests().await.unwrap();
    let sent: serde_json::Value = serde_json::from_slice(&sent[0].body).unwrap();
    assert_eq!(sent["role"], "viewer");
    assert_eq!(sent["mintingDeviceId"], "device-under-test");
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_folder_group_reaches_the_plane_and_a_refusal_comes_back_verbatim() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let plane = plane(&ts).await;
    Mock::given(method("DELETE"))
        .and(path("/shares/groups/g-ok"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&plane)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/shares/groups/g-shared"))
        .respond_with(
            ResponseTemplate::new(409).set_body_string("acknowledge cross-account members"),
        )
        .mount(&plane)
        .await;
    let resp = post_json(&ts, "/api/share/delete", serde_json::json!({ "group_id": "g-ok" })).await;
    assert_eq!(resp.status(), 200);
    let resp =
        post_json(&ts, "/api/share/delete", serde_json::json!({ "group_id": "g-shared" })).await;
    assert!(resp.status().is_client_error(), "{}", resp.status());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap().contains("acknowledge cross-account members"),
        "{body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn removing_a_device_that_holds_no_folder_alone_commits_and_answers_ok() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let plane = plane(&ts).await;
    // The device is the only complete copy of no folder, so nothing needs handing off.
    Mock::given(method("GET"))
        .and(path("/devices/laptop/eager-groups"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "groupIds": [] })),
        )
        .mount(&plane)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/devices/laptop"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&plane)
        .await;
    let resp =
        post_json(&ts, "/api/devices/remove", serde_json::json!({ "device_id": "laptop" })).await;
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body, serde_json::json!({ "ok": true, "handoffs": [] }));
    let removed = plane
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.method.as_str() == "DELETE")
        .count();
    assert_eq!(removed, 1, "the plane was asked to remove the device once");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_revoke_that_would_leave_the_member_s_data_without_another_copy_is_refused() {
    use wiremock::matchers::any;
    use wiremock::{Mock, ResponseTemplate};
    let _guard = TEST_MUTEX.lock().await;
    let ts = start().await;
    let plane = plane(&ts).await;
    Mock::given(any()).respond_with(ResponseTemplate::new(404)).mount(&plane).await;
    let resp = post_json(
        &ts,
        "/api/share/revoke",
        serde_json::json!({ "group_id": "g1", "device_id": "laptop" }),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["error"].as_str().unwrap().contains("another complete copy is not ready"),
        "{body}"
    );
    let revoked = plane
        .received_requests()
        .await
        .unwrap()
        .iter()
        .any(|r| r.url.path().ends_with("/revoke") || r.method.as_str() == "DELETE");
    assert!(!revoked, "nothing was committed on the plane");
}
