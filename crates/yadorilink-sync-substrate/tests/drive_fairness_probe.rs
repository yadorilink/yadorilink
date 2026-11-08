//! What the QUIC connection driver's per-pass datagram limit protects, measured on loopback in one process:
//! `PROBE_BULK` connections each pull large blocks from one server while one more connection (`PROBE_PING=sep`) or one
//! of the bulk connections (`PROBE_PING=same`) carries a 8-byte ping-pong every 20 ms. Prints the ping round-trip
//! percentiles, the bulk throughput and the process CPU seconds.
//!
//! Ignored by default; run explicitly:
//! `PROBE_BULK=4 PROBE_PING=sep PROBE_SECS=10 cargo test --release -p yadorilink-sync-substrate --features test-support --test drive_fairness_probe -- --ignored --nocapture`

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use yadorilink_sync_substrate::testing::SharedAddressBook;
use yadorilink_sync_substrate::{NetworkConfig, SubstrateNode};

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Process CPU seconds (Linux: utime + stime of /proc/self/stat, 100 ticks per second).
fn cpu_seconds() -> f64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let after_comm = stat.rsplit_once(')').map(|(_, rest)| rest).unwrap_or("");
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let tick = |i: usize| fields.get(i).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);
    (tick(11) + tick(12)) / 100.0
}

/// Answers every stream of one inbound connection: byte 0 gets a block, byte 1 gets the 8 bytes sent after it.
async fn serve_connection(inbound: yadorilink_sync_substrate::PeerLink, block_bytes: usize) {
    while let Ok(stream) = inbound.accept_stream().await {
        tokio::spawn(answer(stream.into_raw_for_test(), block_bytes));
    }
}

async fn answer(
    (mut send, mut recv): (iroh::endpoint::SendStream, iroh::endpoint::RecvStream),
    block_bytes: usize,
) {
    let mut kind = [0u8; 1];
    if recv.read_exact(&mut kind).await.is_err() {
        return;
    }
    if kind[0] == 0 {
        let block = vec![0x5au8; block_bytes];
        let _ = send.write_all(&block).await;
    } else {
        let mut ping = [0u8; 8];
        if recv.read_exact(&mut ping).await.is_ok() {
            let _ = send.write_all(&ping).await;
        }
    }
    let _ = send.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement, run on request"]
async fn ping_during_bulk() {
    let bulk = env_u64("PROBE_BULK", 4) as usize;
    let secs = env_u64("PROBE_SECS", 10);
    let block_bytes = env_u64("PROBE_BLOCK_BYTES", 8_000_000) as usize;
    let same = std::env::var("PROBE_PING").map(|v| v == "same").unwrap_or(false);

    let book = SharedAddressBook::default();
    let spawn = |secret: iroh::SecretKey| {
        let book = book.clone();
        async move {
            SubstrateNode::spawn(
                secret,
                NetworkConfig::direct_only().with_directory(Arc::new(book.clone())),
                Arc::new(yadorilink_sync_substrate::AdmitAnyAuthenticated),
            )
            .await
            .expect("node starts")
        }
    };
    let (server, mut server_in) = spawn(iroh::SecretKey::generate()).await;

    // Each client is a node of its own; the server answers byte 0 with a block and byte 1 with an echo.
    let mut links = Vec::new();
    for _ in 0..bulk + 1 {
        let (client, _client_in) = spawn(iroh::SecretKey::generate()).await;
        let link = client.connect(server.peer_id()).await.expect("connect");
        let inbound = server_in.recv().await.expect("inbound link");
        tokio::spawn(serve_connection(inbound, block_bytes));
        links.push((client, link));
    }

    let moved = Arc::new(AtomicU64::new(0));
    let stop = Instant::now() + Duration::from_secs(secs);
    let cpu0 = cpu_seconds();
    let started = Instant::now();
    let mut tasks = Vec::new();
    for (_, link) in links.iter().take(bulk) {
        for _ in 0..2 {
            let link = link.clone();
            let moved = moved.clone();
            tasks.push(tokio::spawn(async move {
                while Instant::now() < stop {
                    let (mut send, mut recv) = link.open_raw_stream_for_test().await.expect("open");
                    send.write_all(&[0u8]).await.unwrap();
                    let mut block = vec![0u8; block_bytes];
                    recv.read_exact(&mut block).await.unwrap();
                    moved.fetch_add(block_bytes as u64, Ordering::Relaxed);
                }
            }));
        }
    }
    let ping_link = if same { links[0].1.clone() } else { links[bulk].1.clone() };
    let ping = tokio::spawn(async move {
        let mut rtts = Vec::new();
        while Instant::now() < stop {
            let t = Instant::now();
            let (mut send, mut recv) = ping_link.open_raw_stream_for_test().await.expect("open");
            send.write_all(&[1u8]).await.unwrap();
            send.write_all(&[7u8; 8]).await.unwrap();
            let mut echo = [0u8; 8];
            recv.read_exact(&mut echo).await.unwrap();
            rtts.push(t.elapsed().as_secs_f64() * 1e3);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        rtts
    });
    let mut rtts = ping.await.unwrap();
    for task in tasks {
        task.await.unwrap();
    }
    let wall = started.elapsed().as_secs_f64();
    let cpu = cpu_seconds() - cpu0;
    rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let q = |p: f64| rtts[((rtts.len() as f64 - 1.0) * p) as usize];
    println!(
        "RESULT bulk={bulk} ping={} pings={} rtt_ms p50={:.2} p90={:.2} p99={:.2} max={:.2} | bulk {:.1} MB/s | cpu {:.1} s over {:.1} s",
        if same { "same" } else { "sep" },
        rtts.len(),
        q(0.5),
        q(0.9),
        q(0.99),
        rtts[rtts.len() - 1],
        moved.load(Ordering::Relaxed) as f64 / wall / 1e6,
        cpu,
        wall
    );
}
