//! Raw stream throughput of the substrate on loopback: the same shape as a block transfer (many
//! concurrent streams, each carrying one block of a fixed size), with no store, hashing or file
//! writes on either side. Used to tell a transport limit from an application limit.
//!
//! Ignored by default; run explicitly:
//! `PROBE_BLOCKS=430 PROBE_BLOCK_BYTES=2500000 PROBE_STREAMS=8 PROBE_STREAM_WINDOW=1250000 \
//!  PROBE_GSO=1 cargo test -p yadorilink-sync-substrate --test throughput_probe -- --ignored --nocapture`

use std::sync::Arc;
use std::time::Instant;

use yadorilink_sync_substrate::testing::SharedAddressBook;
use yadorilink_sync_substrate::{NetworkConfig, SubstrateNode};

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement, run on request"]
async fn raw_stream_throughput() {
    let blocks = env_u64("PROBE_BLOCKS", 430);
    let block_bytes = env_u64("PROBE_BLOCK_BYTES", 2_500_000) as usize;
    let streams = env_u64("PROBE_STREAMS", 8) as usize;
    let stream_window = env_u64("PROBE_STREAM_WINDOW", 0);
    let conn_window = env_u64("PROBE_CONN_WINDOW", 0);
    let send_window = env_u64("PROBE_SEND_WINDOW", 0);
    let gso = env_u64("PROBE_GSO", 1) == 1;

    let mut builder = iroh::endpoint::QuicTransportConfig::builder();
    if stream_window > 0 {
        builder =
            builder.stream_receive_window(iroh::endpoint::VarInt::from_u64(stream_window).unwrap());
    }
    if conn_window > 0 {
        builder = builder.receive_window(iroh::endpoint::VarInt::from_u64(conn_window).unwrap());
    }
    if send_window > 0 {
        builder = builder.send_window(send_window);
    }
    builder = builder.enable_segmentation_offload(gso);
    let transport = builder.build();

    let book = SharedAddressBook::default();
    let spawn = |secret: iroh::SecretKey| {
        let book = book.clone();
        let transport = transport.clone();
        async move {
            SubstrateNode::spawn(
                secret,
                NetworkConfig::direct_only()
                    .with_directory(Arc::new(book.clone()))
                    .with_quic_transport_config(transport),
                Arc::new(yadorilink_sync_substrate::AdmitAnyAuthenticated),
            )
            .await
            .expect("node starts")
        }
    };
    let (server, mut server_in) = spawn(iroh::SecretKey::generate()).await;
    let (client, _client_in) = spawn(iroh::SecretKey::generate()).await;

    let link_client = client.connect(server.peer_id()).await.expect("connect");
    let link_server = server_in.recv().await.expect("inbound link");

    // The server answers every stream with one block of `block_bytes`.
    let serve = tokio::spawn(async move {
        while let Ok(inbound) = link_server.accept_stream().await {
            tokio::spawn(async move {
                let (mut send, mut recv) = inbound.into_raw_for_test();
                let mut request = [0u8; 4];
                if recv.read_exact(&mut request).await.is_err() {
                    return;
                }
                let block = vec![0x5au8; block_bytes];
                let _ = send.write_all(&block).await;
                let _ = send.finish();
            });
        }
    });

    // Warm up the connection so the path is settled before it is recorded and timed.
    for _ in 0..2 {
        let (mut send, mut recv) = link_client.open_raw_stream_for_test().await.expect("open");
        send.write_all(&0u32.to_le_bytes()).await.unwrap();
        let mut sink = vec![0u8; block_bytes];
        recv.read_exact(&mut sink).await.unwrap();
    }
    println!("PATHS {:?}", link_client.path_summary_for_test());

    let gate = Arc::new(tokio::sync::Semaphore::new(streams));
    let started = Instant::now();
    let mut tasks = Vec::new();
    for index in 0..blocks {
        let permit = gate.clone().acquire_owned().await.unwrap();
        let link = link_client.clone();
        tasks.push(tokio::spawn(async move {
            let (mut send, mut recv) = link.open_raw_stream_for_test().await.expect("open");
            send.write_all(&(index as u32).to_le_bytes()).await.unwrap();
            let mut block = vec![0u8; block_bytes];
            recv.read_exact(&mut block).await.unwrap();
            drop(permit);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    let elapsed = started.elapsed().as_secs_f64();
    let total = blocks as f64 * block_bytes as f64;
    println!(
        "RESULT streams={streams} block={block_bytes} blocks={blocks} stream_window={stream_window} \
         conn_window={conn_window} send_window={send_window} gso={gso} -> {:.2} s, {:.1} MB/s",
        elapsed,
        total / elapsed / 1e6
    );
    println!("PATHS_AFTER {:?}", link_client.path_summary_for_test());
    println!("STATS {}", link_client.stats_summary_for_test());
    serve.abort();
}
