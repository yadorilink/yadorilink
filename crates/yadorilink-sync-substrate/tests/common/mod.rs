//! Shared harness for the substrate gate tests.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yadorilink_sync_substrate::testing::SharedAddressBook;
use yadorilink_sync_substrate::{Lane, LaneStream, NetworkConfig, PeerLink, SubstrateNode};

/// A node that publishes into, and resolves out of, `book`.
///
/// Two nodes sharing one book can find each other by endpoint id alone, which
/// is how they are dialled now -- addresses are no longer passed to `connect`.
/// A node given its own private book can still be dialled by anything that has
/// already learnt where it is, and by nothing else.
// Used by `substrate_gates` only; `in_process_relay` compiles this module too.
#[allow(dead_code)]
pub async fn spawn_node_in(
    secret: iroh::SecretKey,
    book: &SharedAddressBook,
) -> (SubstrateNode, tokio::sync::mpsc::Receiver<PeerLink>) {
    SubstrateNode::spawn(
        secret,
        NetworkConfig::direct_only().with_directory(Arc::new(book.clone())),
        std::sync::Arc::new(yadorilink_sync_substrate::AdmitAnyAuthenticated),
    )
    .await
    .expect("substrate starts")
}

/// Echo every byte of every stream the peer opens, on every lane.
pub fn serve_echo(link: PeerLink) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok(lane) = link.accept_lane().await {
            tokio::spawn(async move {
                let (mut send, mut recv) = lane.split();
                let _ = tokio::io::copy(&mut recv, &mut send).await;
                let _ = send.finish();
            });
        }
    })
}

/// Echo the service lane; hold block streams open without
/// ever reading a byte, standing in for a receiver whose storage writer is
/// blocked.
// Used by `substrate_gates` only; `in_process_relay` compiles this module too.
#[allow(dead_code)]
pub fn serve_with_stalled_block_lane(link: PeerLink) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok(lane) = link.accept_lane().await {
            match lane.lane() {
                Lane::Service => {
                    tokio::spawn(async move {
                        let (mut send, mut recv) = lane.split();
                        let _ = tokio::io::copy(&mut recv, &mut send).await;
                    });
                }
                Lane::Block => {
                    tokio::spawn(async move {
                        let _held = lane;
                        std::future::pending::<()>().await;
                    });
                }
            }
        }
    })
}

/// Write `payload` and require it back verbatim.
pub async fn round_trip(lane: &mut LaneStream, payload: &[u8]) {
    lane.write_all(payload).await.expect("write request");
    let mut response = vec![0u8; payload.len()];
    lane.read_exact(&mut response).await.expect("read response");
    assert_eq!(response, payload, "echo mismatch on {} lane", lane.lane());
}
