#![cfg(unix)]
//! Two real daemons, the sender serving blocks from its files and capturing large files as a hash
//! only: what the sender's block store holds, and what a pin or a custody lease changes about it.
//!
//! The store is read directly (`present_blocks` over the blocks the sender's own record lists), so
//! these tests say what is in it, not what the engine claims.

use std::time::Duration;

use crate::native_e2e_support::*;
use crate::support;

const GROUP: &str = "file-only-e2e-group";
/// Over the 4 MiB floor of the file-only policy, so it spans several blocks.
const LARGE: usize = 5 * 1024 * 1024;

fn setup() {
    support::ensure_isolated_config_dir();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
}

/// A sender that serves from its files, and an ordinary receiver, paired.
async fn sender_and_receiver() -> (TopologyNode, TopologyNode) {
    let sender = device_fast_with(
        "fo-sender",
        GROUP,
        support::NodeFeatures { serves_from_files: true, ..Default::default() },
    );
    let receiver = device_fast("fo-receiver", GROUP);
    pair(&sender, &receiver, GROUP).await;
    (sender, receiver)
}

/// Bytes that differ per `seed` and do not repeat, so no two files share a block.
fn payload(seed: u8) -> Vec<u8> {
    (0..LARGE as u64)
        .map(|i| (i.wrapping_mul(2_654_435_761).rotate_left(13) >> 7) as u8 ^ seed)
        .collect()
}

/// How many of the blocks the node's current record of `path` lists are in its block store, and
/// how many it lists.
fn blocks_in_store(node: &TopologyNode, path: &str) -> (usize, usize) {
    let record = node
        .state
        .replica_coordinator
        .file_index_repository()
        .get_file(GROUP, path)
        .unwrap()
        .unwrap_or_else(|| panic!("{path}: no record"));
    let hashes: Vec<String> = record.blocks.iter().map(|b| hex::encode(&b.hash)).collect();
    let held = node.state.block_store.present_blocks(&hashes).unwrap();
    (held.iter().filter(|held| **held).count(), hashes.len())
}

/// The block hashes of the sender's current record of `path`.
fn recorded_blocks(node: &TopologyNode, path: &str) -> Vec<Vec<u8>> {
    node.state
        .replica_coordinator
        .file_index_repository()
        .get_file(GROUP, path)
        .unwrap()
        .filter(|record| !record.deleted)
        .map(|record| record.blocks.into_iter().map(|block| block.hash).collect())
        .unwrap_or_default()
}

/// Waits until the sender's current record of `path` lists other blocks than `before`: the sender
/// has captured a different version. (The size is no evidence: edits here keep the length.)
async fn sender_records_other_than(node: &TopologyNode, path: &str, before: &[Vec<u8>]) {
    let deadline = std::time::Instant::now() + CONVERGE;
    while recorded_blocks(node, path) == before {
        assert!(std::time::Instant::now() < deadline, "{path}: the sender never captured the edit");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A large file nothing keeps is not copied into the sender's store, and still reaches the
/// receiver (served from the file); a large file under a pinned folder is copied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_large_file_is_not_copied_into_the_senders_store_unless_it_is_pinned() {
    setup();
    let (sender, receiver) = sender_and_receiver().await;
    sender.state.replica_coordinator.pinned_item_repository().pin(GROUP, "pinned").unwrap();
    let plain = payload(1);
    let kept = payload(2);

    write(&sender, "plain.bin", &plain);
    write(&sender, "pinned/kept.bin", &kept);

    converge_to(
        &[&sender, &receiver],
        &[("plain.bin", &plain), ("pinned/kept.bin", &kept)],
        "both files reach the receiver, served from the sender's files",
    )
    .await;
    let (held, listed) = blocks_in_store(&sender, "plain.bin");
    assert!(
        listed > 1 && held == 0,
        "an unpinned large file stays out of the store: {held}/{listed}"
    );
    let (held, listed) = blocks_in_store(&sender, "pinned/kept.bin");
    assert!(listed > 1 && held == listed, "a pinned file is in the store: {held}/{listed}");
}

/// A pin taken after the version was captured as a hash only brings it into the store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pin_taken_later_brings_the_captured_version_into_the_store() {
    setup();
    let (sender, receiver) = sender_and_receiver().await;
    let bytes = payload(3);
    write(&sender, "later.bin", &bytes);
    converge_to(&[&sender, &receiver], &[("later.bin", &bytes)], "the file reaches the receiver")
        .await;
    assert_eq!(blocks_in_store(&sender, "later.bin").0, 0, "fixture: captured as a hash only");

    let pending =
        yadorilink_daemon::test_support::pin_item(&sender.state, GROUP, "later.bin").await.unwrap();
    assert_eq!(pending, None, "everything beneath the pin is in the store");

    let (held, listed) = blocks_in_store(&sender, "later.bin");
    assert!(
        held == listed && listed > 1,
        "the pin brought the version into the store: {held}/{listed}"
    );
}

/// A custody lease is granted only with the current versions in the store; a file that changes
/// while it is asked for ends with its new version in the store and the lease granted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_ends_with_the_changed_file_in_the_store_and_is_granted() {
    setup();
    let (sender, receiver) = sender_and_receiver().await;
    // The receiver is a full replica the sender may hand its history to.
    sender.state.authority.set_peer_group_full_replica(&receiver.device_id, GROUP, true);
    receiver.state.authority.set_peer_group_full_replica(&sender.device_id, GROUP, true);
    let first = payload(4);
    write(&sender, "leased.bin", &first);
    converge_to(&[&sender, &receiver], &[("leased.bin", &first)], "the first version arrives")
        .await;
    assert_eq!(blocks_in_store(&sender, "leased.bin").0, 0, "fixture: captured as a hash only");

    // The plane the pairing used answers the lease request.
    let plane = support::checkpoint_fake_of(&sender.state).expect("the pairing made a plane");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    plane.set_handoff_lease_response(
        GROUP,
        200,
        serde_json::json!({ "leaseId": "lease-e2e", "expiresAt": now + 900, "ttlSeconds": 900 }),
    );

    // The user changes the file just as the lease is asked for.
    let before = recorded_blocks(&sender, "leased.bin");
    let second = payload(5);
    write(&sender, "leased.bin", &second);
    let deadline = std::time::Instant::now() + CONVERGE;
    let granted = loop {
        if let Some(grant) = sender.state.request_handoff_lease(GROUP).await {
            break grant;
        }
        assert!(std::time::Instant::now() < deadline, "the lease was never granted");
        tokio::time::sleep(Duration::from_millis(500)).await;
    };

    assert_eq!(granted.0.lease_id, "lease-e2e");
    sender_records_other_than(&sender, "leased.bin", &before).await;
    let (held, listed) = blocks_in_store(&sender, "leased.bin");
    assert!(
        held == listed && listed > 1,
        "the version the lease promises is in the store: {held}/{listed}"
    );
    converge_to(&[&sender, &receiver], &[("leased.bin", &second)], "the receiver has the new one")
        .await;
}

/// The version an own edit replaces is not in the store and is not required to be: the edit is
/// captured and reaches the receiver.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_own_edit_proceeds_when_the_version_it_replaces_is_not_in_the_store() {
    setup();
    let (sender, receiver) = sender_and_receiver().await;
    let first = payload(6);
    write(&sender, "edited.bin", &first);
    converge_to(&[&sender, &receiver], &[("edited.bin", &first)], "the first version arrives")
        .await;
    let old = sender
        .state
        .replica_coordinator
        .file_index_repository()
        .get_file(GROUP, "edited.bin")
        .unwrap()
        .unwrap();
    assert_eq!(blocks_in_store(&sender, "edited.bin").0, 0, "fixture: not in the store");

    let second = payload(7);
    write(&sender, "edited.bin", &second);

    converge_to(&[&sender, &receiver], &[("edited.bin", &second)], "the edit reaches the receiver")
        .await;
    let hashes: Vec<String> = old.blocks.iter().map(|b| hex::encode(&b.hash)).collect();
    let held = sender.state.block_store.present_blocks(&hashes).unwrap();
    assert!(
        held.iter().all(|held| !held),
        "the replaced version of an own edit is not kept, and was not asked to be"
    );
}

/// The lease request is made while a file differs from its record, at a fixed point: after the
/// device has attested the group ready and before the current versions are read into the store.
/// The request is declined with `changing_retry`, the group is asked to capture into the store,
/// and once the edit has been captured (into the store) the same request is granted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_declined_for_a_changing_file_is_granted_once_the_capture_has_landed() {
    setup();
    let (sender, receiver) = sender_and_receiver().await;
    sender.state.authority.set_peer_group_full_replica(&receiver.device_id, GROUP, true);
    receiver.state.authority.set_peer_group_full_replica(&sender.device_id, GROUP, true);
    let first = payload(8);
    write(&sender, "changing.bin", &first);
    converge_to(&[&sender, &receiver], &[("changing.bin", &first)], "the first version arrives")
        .await;
    assert_eq!(blocks_in_store(&sender, "changing.bin").0, 0, "fixture: captured as a hash only");
    let plane = support::checkpoint_fake_of(&sender.state).expect("the pairing made a plane");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
        as i64;
    plane.set_handoff_lease_response(
        GROUP,
        200,
        serde_json::json!({ "leaseId": "lease-retry", "expiresAt": now + 900, "ttlSeconds": 900 }),
    );

    // At the fixed point the user's editor saves the file: the file is no longer its record.
    let before = recorded_blocks(&sender, "changing.bin");
    let second = payload(9);
    let edited = sender.root.path().join("changing.bin");
    let bytes = second.clone();
    yadorilink_daemon::test_support::on_next_lease_request(&sender.state, move || {
        std::fs::write(&edited, &bytes).unwrap();
    });

    let declined =
        yadorilink_daemon::test_support::request_lease_with_reason(&sender.state, GROUP).await;
    assert_eq!(declined, Err(Some("changing_retry")), "not a silent no");
    assert!(
        yadorilink_daemon::test_support::store_mode_requested(&sender.state, GROUP),
        "the group is asked to capture into the store while the retry is pending"
    );

    // The capture of the edit lands, into the store.
    sender_records_other_than(&sender, "changing.bin", &before).await;
    let (held, listed) = blocks_in_store(&sender, "changing.bin");
    assert!(held == listed && listed > 1, "captured in store mode: {held}/{listed}");

    let deadline = std::time::Instant::now() + CONVERGE;
    let granted = loop {
        match yadorilink_daemon::test_support::request_lease_with_reason(&sender.state, GROUP).await
        {
            Ok(lease) => break lease,
            Err(reason) => {
                // The receiver must hold the new version before the sender can attest the group.
                assert!(reason.is_none() || reason == Some("changing_retry"), "{reason:?}");
                assert!(
                    std::time::Instant::now() < deadline,
                    "the retried lease was never granted (last refusal {reason:?})"
                );
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
    };
    assert_eq!(granted, "lease-retry");
    converge_to(
        &[&sender, &receiver],
        &[("changing.bin", &second)],
        "the receiver has the new one",
    )
    .await;
}

/// How many of `hashes` the node's block store holds.
fn held_of(node: &TopologyNode, hashes: &[Vec<u8>]) -> usize {
    let hex: Vec<String> = hashes.iter().map(hex::encode).collect();
    node.state.block_store.present_blocks(&hex).unwrap().into_iter().filter(|held| *held).count()
}

/// A device whose receive keeps large received files out of its block store (single-pass receive)
/// still stores the blocks of a path it pinned: after a pin on B, A edits and B receives, the new
/// version is in B's store; and when B then edits the file itself, the received version is still
/// there. A path nobody pinned is received without a store copy, as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pinned_path_received_in_single_pass_is_kept_when_the_receiver_edits_it() {
    setup();
    let a = device_fast("fo-a", GROUP);
    let b = device_fast_with(
        "fo-b",
        GROUP,
        support::NodeFeatures { single_pass_receive: true, ..Default::default() },
    );
    pair(&a, &b, GROUP).await;
    let (doc_v1, plain_v1) = (payload(10), payload(11));
    write(&a, "doc.bin", &doc_v1);
    write(&a, "plain.bin", &plain_v1);
    converge_to(
        &[&a, &b],
        &[("doc.bin", &doc_v1), ("plain.bin", &plain_v1)],
        "the first versions arrive on B",
    )
    .await;
    assert_eq!(
        held_of(&b, &recorded_blocks(&b, "plain.bin")),
        0,
        "fixture: a large file B received is held by its file alone (single-pass receive)"
    );

    // B pins one of them; then A edits both.
    let pending =
        yadorilink_daemon::test_support::pin_item(&b.state, GROUP, "doc.bin").await.unwrap();
    assert_eq!(pending, None, "the pin found nothing pending");
    let (doc_v2, plain_v2) = (payload(12), payload(13));
    write(&a, "doc.bin", &doc_v2);
    write(&a, "plain.bin", &plain_v2);
    converge_to(&[&a, &b], &[("doc.bin", &doc_v2), ("plain.bin", &plain_v2)], "the edits reach B")
        .await;

    let doc_blocks = recorded_blocks(&b, "doc.bin");
    assert!(doc_blocks.len() > 1);
    assert_eq!(
        held_of(&b, &doc_blocks),
        doc_blocks.len(),
        "the pinned path's version is in B's store"
    );
    assert_eq!(held_of(&b, &recorded_blocks(&b, "plain.bin")), 0, "an unpinned path stays out");

    // B edits the pinned file itself: the version it received is kept.
    let doc_v3 = payload(14);
    write(&b, "doc.bin", &doc_v3);
    converge_to(&[&a, &b], &[("doc.bin", &doc_v3), ("plain.bin", &plain_v2)], "B's edit reaches A")
        .await;
    assert_eq!(
        held_of(&b, &doc_blocks),
        doc_blocks.len(),
        "the received version survives the receiver's own edit"
    );
}

/// Three devices write different large content to one path at the same time, none having seen
/// the others' version. Every version is held by its device's file alone (no store copy), yet the
/// devices converge: one version stays at the path and the other two are kept at conflict-copy
/// paths, each served by its author.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_large_writes_on_three_devices_converge() {
    setup();
    let features = support::NodeFeatures { serves_from_files: true, single_pass_receive: true };
    let a = device_fast_with("cc-a", GROUP, features);
    let b = device_fast_with("cc-b", GROUP, features);
    let c = device_fast_with("cc-c", GROUP, features);
    pair(&a, &b, GROUP).await;
    pair(&b, &c, GROUP).await;
    pair(&a, &c, GROUP).await;
    let versions = [payload(21), payload(22), payload(23)];
    write(&a, "doc.bin", &versions[0]);
    write(&b, "doc.bin", &versions[1]);
    write(&c, "doc.bin", &versions[2]);

    let tree =
        converge_where(&[&a, &b, &c], "the three versions are all kept everywhere", |tree| {
            let files: Vec<&Vec<u8>> = tree
                .iter()
                .filter(|(name, _)| !name.ends_with('/'))
                .map(|(_, bytes)| bytes)
                .collect();
            files.len() == 3 && versions.iter().all(|v| files.contains(&v))
        })
        .await;
    assert_eq!(tree.len(), 3, "the path and two conflict copies: {:?}", tree.keys());
}

/// While a contested version is not in the store, no fork runs: the path stays contested and no
/// copy path appears anywhere, across several passes. Once the versions are settled the fork runs
/// and the devices converge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fork_waits_for_an_unsettled_version_and_runs_once_it_is_settled() {
    struct Release(Vec<String>);
    impl Drop for Release {
        fn drop(&mut self) {
            for device in &self.0 {
                yadorilink_daemon::test_support::hold_contest_settling(device, false);
            }
        }
    }
    setup();
    let features = support::NodeFeatures { serves_from_files: true, single_pass_receive: true };
    let a = device_fast_with("hold-a", GROUP, features);
    let b = device_fast_with("hold-b", GROUP, features);
    let c = device_fast_with("hold-c", GROUP, features);
    pair(&a, &b, GROUP).await;
    pair(&b, &c, GROUP).await;
    pair(&a, &c, GROUP).await;
    let nodes = [&a, &b, &c];
    let held = Release(nodes.iter().map(|n| n.state.device_id.clone()).collect());
    for device in &held.0 {
        yadorilink_daemon::test_support::hold_contest_settling(device, true);
    }
    let versions = [payload(31), payload(32), payload(33)];
    for (node, version) in nodes.iter().zip(&versions) {
        write(node, "doc.bin", version);
    }
    let copy_paths = |node: &TopologyNode| -> Vec<String> {
        node.state
            .replica_coordinator
            .file_index_repository()
            .list_live_files_under(GROUP, "")
            .unwrap()
            .into_iter()
            .filter(|path| path.contains("(conflicted copy"))
            .collect()
    };

    // Long enough for several passes (the wait doubles from 2 s): the versions stay unsettled.
    let until = std::time::Instant::now() + Duration::from_secs(9);
    while std::time::Instant::now() < until {
        for node in nodes {
            assert!(
                copy_paths(node).is_empty(),
                "{}: a fork ran while a contested version was not in the store: {:?}",
                node.device_id,
                copy_paths(node)
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // The gate was exercised: the contest reached the candidate table of some device, and is
    // still waiting there for its fork.
    let waiting: u64 = nodes
        .iter()
        .map(|node| {
            read(node, |conn| yadorilink_sync_sqlite::native_contest_candidates::count(conn, GROUP))
        })
        .sum();
    assert!(waiting > 0, "no contest was waiting for a fork: the hold proved nothing");

    drop(held);
    converge_where(&nodes, "once settled the three versions are all kept", |tree| {
        let files: Vec<&Vec<u8>> =
            tree.iter().filter(|(name, _)| !name.ends_with('/')).map(|(_, bytes)| bytes).collect();
        files.len() == 3 && versions.iter().all(|v| files.contains(&v))
    })
    .await;
}
