//! Idle/resource variants of `idle_resource_baseline.rs` with a peer in the
//! picture: peer online and quiescent, peer offline, On-Demand metadata-only,
//! and a deterministic network-transition loop (sever and re-pair). Two real
//! daemons (the production composition of `native_e2e_support`) share this
//! process, so every number is for both together. Results and the re-run
//! commands live in `docs/IDLE_RESOURCE_BASELINE.md`.
//!
//! `YADORILINK_IDLE_FILES` (default 300), `YADORILINK_IDLE_SECS` (default 20),
//! `YADORILINK_IDLE_CYCLES` (transition loop, default 10).
//! Gates are catastrophic-only (see `idle_sampler::Gates`); metrics are the
//! baseline.

#![cfg(unix)]

mod idle_sampler;
mod native_e2e_support;
mod support;

use std::time::{Duration, Instant};

use idle_sampler::{env_num, idle_window, report, snapshot, Gates};
use native_e2e_support::*;
use yadorilink_daemon::daemon_state::DaemonState;

const GROUP: &str = "idle-variants-group";

fn indexed(state: &DaemonState) -> usize {
    state
        .replica_coordinator
        .file_index_repository()
        .list_files(GROUP)
        .map(|f| f.len())
        .unwrap_or(0)
}

fn populate(node: &TopologyNode, files: usize) {
    for i in 0..files {
        std::fs::write(node.root.path().join(format!("file-{i:05}.txt")), format!("content {i}"))
            .unwrap();
    }
}

async fn until(what: &str, secs: u64, cond: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !cond() {
        assert!(Instant::now() < deadline, "{what}: not reached in {secs}s");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

struct Pair {
    a: TopologyNode,
    b: TopologyNode,
    files: usize,
}

/// A has `files` files and is paired with B; waits until B holds all of them
/// (content when eager, index rows when on-demand) and everything settled.
async fn converged_pair(on_demand: bool) -> Pair {
    idle_sampler::init_log_counter();
    let files: usize = env_num("YADORILINK_IDLE_FILES", 300);
    let a = new_node("idle-a");
    populate(&a, files);
    link_eager(&a, GROUP);
    let b = new_node("idle-b");
    if on_demand {
        support::topology::link_on_demand(&b, GROUP);
    } else {
        link_eager(&b, GROUP);
    }
    pair(&a, &b, GROUP).await;
    let converge = 120 + files as u64 / 20;
    until("B indexed", converge, || indexed(&b.state) >= files).await;
    if !on_demand {
        until("B materialized", converge, || {
            support::real_entry_names(b.root.path()).len() >= files
        })
        .await;
    }
    // Let follow-up passes finish.
    tokio::time::sleep(Duration::from_secs(10)).await;
    Pair { a, b, files }
}

async fn sample(label: &str, p: &Pair) {
    let (ia, ib) = (indexed(&p.a.state), indexed(&p.b.state));
    let s0 = snapshot();
    tokio::time::sleep(idle_window()).await;
    let s1 = snapshot();
    report(label, p.files, &s0, &s1, &Gates::default());
    assert_eq!((ia, ib), (indexed(&p.a.state), indexed(&p.b.state)), "{label}: index changed");
}

#[ignore = "timed resource check -- run with --ignored (see docs/IDLE_RESOURCE_BASELINE.md)"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_online_quiescent_stays_idle() {
    let p = converged_pair(false).await;
    sample("peer-online", &p).await;
}

#[ignore = "timed resource check -- run with --ignored (see docs/IDLE_RESOURCE_BASELINE.md)"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_offline_stays_idle() {
    let p = converged_pair(false).await;
    partition(&p.a, &p.b).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    sample("peer-offline", &p).await;
}

#[ignore = "timed resource check -- run with --ignored (see docs/IDLE_RESOURCE_BASELINE.md)"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_demand_metadata_only_stays_idle() {
    let p = converged_pair(true).await;
    sample("on-demand", &p).await;
}

/// The deterministic part of sleep/wake and network changes: the link drops
/// and comes back N times. Process resources must not grow with N, and the
/// replicas must still agree afterwards. Radio/route changes, OS sleep and
/// wake clocks need a real device (see the doc).
#[ignore = "timed resource check -- run with --ignored (see docs/IDLE_RESOURCE_BASELINE.md)"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn network_transition_loop_does_not_grow() {
    let p = converged_pair(false).await;
    let cycles: usize = env_num("YADORILINK_IDLE_CYCLES", 10);
    // Each cycle ends both sessions (closing the pairing link, as a dropped
    // connection does) and starts new ones on the same endpoints. `partition`
    // is deliberately not used: it rebuilds the substrate endpoint, which the
    // daemon never does (one stack per process; the call is test-only) and
    // which leaks 2 UDP sockets + 1 route socket per endpoint in this harness.
    let s0 = snapshot();
    for _ in 0..cycles {
        let ([ta, tb], link) = support::connect_two_daemons_with_link(
            &p.a.state,
            &p.a.device_id,
            &p.b.state,
            &p.b.device_id,
            std::slice::from_ref(&GROUP.to_string()),
        )
        .await;
        grant_writers(&[&p.a, &p.b], GROUP);
        tokio::time::sleep(Duration::from_secs(1)).await;
        link.close();
        let _ = tokio::join!(ta, tb);
    }
    tokio::time::sleep(Duration::from_secs(10)).await;
    let s1 = snapshot();
    println!("idle-baseline: transition cycles={cycles}");
    report("transition-loop", p.files, &s0, &s1, &Gates::default());
    // Still converged and live: a new file crosses.
    write(&p.a, "after-loop.txt", b"after");
    until("post-loop file", 60, || p.b.root.path().join("after-loop.txt").exists()).await;
    // And idle again.
    tokio::time::sleep(Duration::from_secs(5)).await;
    sample("after-transition-loop", &p).await;
}
