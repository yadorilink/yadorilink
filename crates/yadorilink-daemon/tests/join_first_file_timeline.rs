//! Measurement harness: per-milestone timeline from a receiver joining a
//! share to its first materialized file, with a small and a larger source
//! tree.
//!
//! The receiver joins through the daemon's real control path: a
//! `JoinAndLinkCommand` over the daemon's unix control socket runs
//! `EnrollmentService::join_and_link` (coordination prepare, durable
//! enrollment, local link commit, activation) against the in-process
//! coordination fake, exactly as `yadorilink share join` does. The sender is
//! linked, paired and verified idle (native deltas published, none pending,
//! delta count stable) BEFORE the join starts, so the measured window is the
//! receiver's alone. The timeline is keyed by the receiver's device id, so
//! the sender's identical milestones never feed it.
//!
//! Not a pass/fail latency gate: it only prints the timeline. Ignored by
//! default; run it with
//!
//! ```text
//! YADORILINK_JOIN_TIMELINE_FILES=1,10,1000 YADORILINK_JOIN_TIMELINE_RUNS=3 \
//!   cargo test -p yadorilink-daemon --test join_first_file_timeline \
//!   -- --ignored --nocapture
//! ```
//!
//! Scenario C (peer becomes available after the join): set
//! `YADORILINK_JOIN_TIMELINE_AVAIL_DELAY_MS=0,500,...`. The pairing is severed
//! after the sender is idle, the receiver joins with no peer, and the pairing
//! is re-established that many ms after the join returns; the extra
//! `JOIN_TIMELINE_C` line reports availability event -> first/all files on disk.
//!
//! Limits: both daemons share one process and are paired directly (the
//! stand-in for a netmap push), so peer discovery, relay and NAT traversal
//! are not exercised, and coordination is an in-process fake that answers
//! join prepare/activate instantly.

#![cfg(unix)]

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use support::real_entry_names;
use tokio::net::UnixStream;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::control_context::ControlContext;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_fs_platform::join_timeline;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::{
    join_and_link_command_response, DaemonControlRequest, DaemonControlResponse,
    JoinAndLinkCommandRequest,
};
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_local_storage::SegmentBlockStore;

fn env_list(name: &str, default: &[usize]) -> Vec<usize> {
    std::env::var(name)
        .ok()
        .map(|v| v.split(',').filter_map(|s| s.trim().parse().ok()).collect())
        .filter(|v: &Vec<usize>| !v.is_empty())
        .unwrap_or_else(|| default.to_vec())
}

struct Run {
    files: usize,
    sender_heads: i64,
    sender_idle: bool,
    sender_idle_wait: Duration,
    first_on_disk: Option<Duration>,
    all_on_disk: Option<Duration>,
    timeline: Option<join_timeline::Finished>,
}

/// (native heads, pending-publication deltas) for the sender: heads are one
/// per captured path, so the scan is complete when they reach the file count.
fn sender_counts(state: &Arc<DaemonState>, group_id: &str) -> (i64, usize) {
    let db = state.replica_coordinator.database();
    let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_string());
    let device = state.device_id.clone();
    let logged = db
        .read(|conn| {
            Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(
                conn.query_row(
                    "SELECT COUNT(*) FROM native_heads WHERE group_id = ?1",
                    [group_id],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap_or(-1),
            )
        })
        .unwrap_or(-1);
    let pending = db
        .read(|conn| {
            yadorilink_sync_sqlite::native_publication::pending_native_deltas_for_device(
                conn, &group, &device,
            )
        })
        .map(|p| p.len())
        .unwrap_or(usize::MAX);
    (logged, pending)
}

/// Waits until the sender's capture and publication are finished: a head
/// exists for every file, no delta is pending publication, and the counts have
/// not moved for a full second. Returns (heads, idle, waited).
async fn wait_sender_idle(
    state: &Arc<DaemonState>,
    group_id: &str,
    files: usize,
) -> (i64, bool, Duration) {
    let started = Instant::now();
    let mut last = (-2, usize::MAX);
    let mut stable_since = Instant::now();
    while started.elapsed() < Duration::from_secs(180) {
        let now = sender_counts(state, group_id);
        if now.1 > 0 && now.1 != usize::MAX {
            // What production does after every local commit.
            state.flush_pending_native_checkpoint_for_group_for_test(group_id).await;
        }
        if now != last {
            last = now;
            stable_since = Instant::now();
        } else if now.0 >= files as i64
            && now.1 == 0
            && stable_since.elapsed() >= Duration::from_secs(1)
        {
            return (now.0, true, started.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    (last.0, false, started.elapsed())
}

async fn join_over_control_socket(
    socket: &std::path::Path,
    group_id: &str,
    local_path: &str,
) -> Result<(), String> {
    let mut stream = UnixStream::connect(socket).await.map_err(|e| e.to_string())?;
    write_message(
        &mut stream,
        &DaemonControlRequest {
            payload: Some(ReqPayload::JoinAndLinkCommand(JoinAndLinkCommandRequest {
                group_id: group_id.to_string(),
                group_name: group_id.to_string(),
                local_path: local_path.to_string(),
                on_demand: false,
                acknowledge_risks: true,
                provider_display_name: String::new(),
                request_token: String::new(),
            })),
            protocol_version: yadorilink_ipc_proto::daemonctl::CONTROL_PROTOCOL_VERSION,
        },
    )
    .await
    .map_err(|e| e.to_string())?;
    let response: DaemonControlResponse = read_message(&mut stream)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "control socket closed without a response".to_string())?;
    match response.payload {
        Some(RespPayload::JoinAndLinkCommand(r)) => match r.result {
            Some(join_and_link_command_response::Result::Outcome(_)) => Ok(()),
            Some(join_and_link_command_response::Result::Error(e)) => Err(format!("{e:?}")),
            None => Err("empty join result".into()),
        },
        other => Err(format!("unexpected response {other:?}")),
    }
}

/// `avail_delay`: scenario C. After the sender is verified idle the pairing is
/// severed (as custody_evict_e2e does), the receiver joins while the peer is
/// unavailable, and the pairing is re-established `avail_delay` after the join
/// command returns. The returned `Duration` is the availability event's
/// offset from the join start.
async fn one_join(files: usize, run: usize, avail_delay: Option<Duration>) -> (Run, Duration) {
    let device_a_id = format!("device-a-{files}-{run}");
    let device_b_id = format!("device-b-{files}-{run}");
    let group_id = format!("join-timeline-{files}-{run}");

    let make_state = |device_id: &str| {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        let state = DaemonState::new(device_id.to_string(), sync_state, store);
        support::ensure_device_signing_key(&state);
        (state, store_dir)
    };
    let (state_a, _store_dir_a) = make_state(&device_a_id);
    let (state_b, _store_dir_b) = make_state(&device_b_id);
    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();
    let control_dir = tempfile::tempdir().unwrap();

    for i in 0..files {
        std::fs::write(
            root_a.path().join(format!("file-{i:04}.txt")),
            format!("content of file {i}"),
        )
        .unwrap();
    }
    let local_path_a = root_a.path().to_string_lossy().to_string();
    state_a.replica_coordinator.link_repository().add_link(&local_path_a, &group_id).unwrap();
    LinkRuntimeController::new(state_a.clone())
        .start(local_path_a.clone(), group_id.clone())
        .unwrap();

    // Both peers online before the join: pair them now (this also installs
    // the group's bootstrap policy on both and publishes the sender's pending
    // deltas), then wait for the sender to be provably idle.
    let (handles, link) = support::connect_two_daemons_with_link_keeper_dials(
        &state_a,
        &device_a_id,
        &state_b,
        &device_b_id,
        std::slice::from_ref(&group_id),
    )
    .await;
    let (sender_heads, sender_idle, sender_idle_wait) =
        wait_sender_idle(&state_a, &group_id, files).await;

    let mut handles: Vec<_> = handles.into_iter().collect();
    let mut link = Some(link);
    if avail_delay.is_some() {
        // The peer drops off before the receiver joins.
        support::sever_reconciliation(&state_a, &state_b).await;
        for handle in &handles {
            handle.abort();
        }
        drop(link.take());
        state_a.peers.remove(&device_b_id);
        state_b.peers.remove(&device_a_id);
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // The receiver's daemon serves the real control protocol.
    let socket = control_dir.path().join("daemon.sock");
    let (serve_path, serve_state) = (socket.clone(), state_b.clone());
    let server = tokio::spawn(async move {
        let _ = yadorilink_daemon::control_socket::unix_transport::serve(
            &serve_path,
            Arc::new(ControlContext::from_state(serve_state)),
        )
        .await;
    });
    yadorilink_daemon::control_socket::unix_transport::wait_until_bound(&socket).await;

    let local_path_b = root_b.path().to_string_lossy().to_string();
    let joined = Instant::now();
    let join_result = join_over_control_socket(&socket, &group_id, &local_path_b).await;
    let join_returned = joined.elapsed();
    if let Err(error) = &join_result {
        panic!("join command failed: {error}");
    }

    let mut avail_at = Duration::ZERO;
    if let Some(delay) = avail_delay {
        let target = join_returned + delay;
        tokio::time::sleep(target.saturating_sub(joined.elapsed())).await;
        avail_at = joined.elapsed();
        let (h, l) = support::connect_two_daemons_with_link_keeper_dials(
            &state_a,
            &device_a_id,
            &state_b,
            &device_b_id,
            std::slice::from_ref(&group_id),
        )
        .await;
        handles.extend(h);
        link = Some(l);
        println!("JOIN_TIMELINE availability_event_ms={:.0}", avail_at.as_secs_f64() * 1000.0);
    }

    let mut first_on_disk = None;
    let mut all_on_disk = None;
    while joined.elapsed() < Duration::from_secs(180) {
        let n = real_entry_names(root_b.path()).len();
        if n > 0 && first_on_disk.is_none() {
            first_on_disk = Some(joined.elapsed());
        }
        if n >= files {
            all_on_disk = Some(joined.elapsed());
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The commit that settles the first file lands just after its bytes do.
    let settled = Instant::now();
    while join_timeline::peek_complete(&device_b_id, &group_id) == Some(false)
        && settled.elapsed() < Duration::from_secs(3)
    {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let timeline = join_timeline::take_finished_or_partial(&device_b_id, &group_id);
    println!(
        "JOIN_TIMELINE join_command_returned_ms={:.0} attempt={:?}",
        join_returned.as_secs_f64() * 1000.0,
        timeline.as_ref().map(|t| t.attempt)
    );

    server.abort();
    for handle in handles {
        handle.abort();
    }
    drop(link);
    LinkRuntimeController::new(state_a).stop(&local_path_a).await;
    LinkRuntimeController::new(state_b).stop(&local_path_b).await;
    (
        Run {
            files,
            sender_heads,
            sender_idle,
            sender_idle_wait,
            first_on_disk,
            all_on_disk,
            timeline,
        },
        avail_at,
    )
}

fn ms(d: Option<Duration>) -> String {
    d.map(|d| format!("{:.0}", d.as_secs_f64() * 1000.0)).unwrap_or_else(|| "-".into())
}

#[ignore = "measurement harness -- run locally with --ignored --nocapture"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn join_to_first_file_timeline() {
    support::start_coordination_server().await;
    if std::env::var_os("RUST_LOG").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .try_init();
    }
    let counts = env_list("YADORILINK_JOIN_TIMELINE_FILES", &[1, 10, 1000]);
    let runs = env_list("YADORILINK_JOIN_TIMELINE_RUNS", &[3])[0];
    let names: Vec<&str> = join_timeline::milestones().iter().map(|m| m.name()).collect();
    println!("JOIN_TIMELINE milestones(ms from join): {}", names.join(","));
    // Scenario C: ms after the join command returns at which the peer becomes
    // available. Empty/unset keeps the peer-online baseline.
    let delays: Vec<Option<Duration>> =
        match std::env::var("YADORILINK_JOIN_TIMELINE_AVAIL_DELAY_MS") {
            Ok(_) => env_list("YADORILINK_JOIN_TIMELINE_AVAIL_DELAY_MS", &[])
                .into_iter()
                .map(|d| Some(Duration::from_millis(d as u64)))
                .collect(),
            Err(_) => vec![None],
        };
    for &files in &counts {
        for &delay in &delays {
            for run in 0..runs {
                let (r, avail_at) = one_join(files, run, delay).await;
                if let Some(delay) = delay {
                    let after = |t: Option<Duration>| ms(t.map(|t| t.saturating_sub(avail_at)));
                    println!(
                    "JOIN_TIMELINE_C files={} delay_ms={} run={} avail_ms={:.0} avail_to_first_on_disk_ms={} avail_to_all_on_disk_ms={}",
                    files,
                    delay.as_millis(),
                    run,
                    avail_at.as_secs_f64() * 1000.0,
                    after(r.first_on_disk),
                    after(r.all_on_disk),
                );
                }
                let cols: Vec<String> = match &r.timeline {
                    Some(f) => f.offsets.iter().map(|o| ms(*o)).collect(),
                    None => vec!["-".into(); join_timeline::MILESTONES],
                };
                println!(
                "JOIN_TIMELINE files={} run={} {} | rounds_before_first_file={} first_on_disk_ms={} all_on_disk_ms={} sender_idle_at_join={} sender_heads={} sender_idle_wait_ms={:.0}",
                r.files,
                run,
                cols.join(","),
                r.timeline.as_ref().map(|f| f.reconcile_rounds).unwrap_or(0),
                ms(r.first_on_disk),
                ms(r.all_on_disk),
                r.sender_idle,
                r.sender_heads,
                r.sender_idle_wait.as_secs_f64() * 1000.0,
            );
                assert!(r.sender_idle, "sender never became idle for files={files}");
                assert!(r.all_on_disk.is_some(), "receiver never converged for files={files}");
                assert!(
                    r.timeline.as_ref().is_some_and(|f| !f.ambiguous),
                    "ambiguous or missing timeline for files={files}: not data"
                );
            }
        }
    }
}
