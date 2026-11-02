#![cfg(windows)]
//! On Windows a large file goes through the block store by design (the capture barrier has no
//! directory flush there): the sender keeps every block of it in its store, and the receiver gets
//! the file, with the engine's default settings.

use crate::native_e2e_support::*;

const GROUP: &str = "windows-store-path-group";
const LARGE: usize = 5 * 1024 * 1024;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_large_file_is_copied_into_the_senders_store_by_default() {
    crate::support::ensure_isolated_config_dir();
    let sender = device_fast("ws-sender", GROUP);
    let receiver = device_fast("ws-receiver", GROUP);
    pair(&sender, &receiver, GROUP).await;
    let bytes: Vec<u8> = (0..LARGE as u64)
        .map(|i| (i.wrapping_mul(2_654_435_761).rotate_left(13) >> 7) as u8)
        .collect();
    write(&sender, "large.bin", &bytes);
    converge_to(&[&sender, &receiver], &[("large.bin", &bytes)], "the file reaches the receiver")
        .await;

    for (name, node) in [("sender", &sender), ("receiver", &receiver)] {
        let record = node
            .state
            .replica_coordinator
            .file_index_repository()
            .get_file(GROUP, "large.bin")
            .unwrap()
            .expect("a record");
        let hashes: Vec<String> = record.blocks.iter().map(|b| hex::encode(&b.hash)).collect();
        let held = node.state.block_store.present_blocks(&hashes).unwrap();
        assert!(
            hashes.len() > 1 && held.iter().all(|held| *held),
            "{name}: every block of a large file is in the store on Windows ({}/{})",
            held.iter().filter(|held| **held).count(),
            hashes.len()
        );
    }
}
