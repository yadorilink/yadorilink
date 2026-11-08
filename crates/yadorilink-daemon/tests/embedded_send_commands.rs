//! The embedded host's Send commands (`EngineCommands`) between two devices of different
//! accounts that share no folder: a sender creates a link and lists it, the recipient previews
//! and redeems it, the sender's offer goes out under the link, and the recipient receives the
//! bytes. The sender's link list and the link -> transfer record survive a restart (a fresh
//! command set over the same state directory). The fake coordination models the link state
//! machine only; the Worker's own tests cover account scoping.

mod support;

use std::sync::Arc;
use std::time::Duration;

use support::fake_coordination::FakeCoordination;
use support::topology::{new_node, spawn_orchestrator, TopologyNode};
use support::{register_with_fake, wait_until_with_context};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::embedded_host::{CommandErrorKind, EngineCommands};
use yadorilink_ipc_proto::daemonctl::{ApplicationErrorCode, SendLinkState};

/// The nodes of one test process share one state directory (the harness has a single
/// process-wide one), and with it the sender's link list file: the tests take turns.
static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn start_send_transfer(node: &TopologyNode) -> tempfile::TempDir {
    let config_dir = tempfile::tempdir().unwrap();
    let state = node.state.clone();
    let dir = config_dir.path().to_path_buf();
    tokio::spawn(async move {
        let _ = yadorilink_daemon::send_transfer::run(state, dir).await;
    });
    config_dir
}

async fn wait_for_send_service(state: &Arc<DaemonState>) {
    wait_until_with_context(
        || state.send_service().is_some(),
        Duration::from_secs(30),
        || "Track Send service never became ready".to_string(),
    )
    .await;
}

fn report_endpoint(fake: &FakeCoordination, node: &TopologyNode) {
    tokio::spawn(yadorilink_daemon::peer_connectivity_runtime::report_own_address(
        fake.addr(),
        yadorilink_fapi_client::test_support::offline_auth(),
        node.device_id.clone(),
        node.state.peer_connectivity.local_substrate_reachability.clone(),
    ));
}

async fn stand_up() -> (
    FakeCoordination,
    TopologyNode,
    TopologyNode,
    [tokio::runtime::Runtime; 2],
    [tempfile::TempDir; 2],
) {
    support::ensure_isolated_config_dir();
    let fake = FakeCoordination::start().await;
    let a = new_node("emb-a");
    let b = new_node("emb-b");
    for node in [&a, &b] {
        register_with_fake(&fake, &node.state, &node.device_id, &[]).await;
    }
    let runtimes = [spawn_orchestrator(fake.addr(), &a), spawn_orchestrator(fake.addr(), &b)];
    let dirs = [start_send_transfer(&a), start_send_transfer(&b)];
    wait_for_send_service(&a.state).await;
    wait_for_send_service(&b.state).await;
    for node in [&a, &b] {
        report_endpoint(&fake, node);
        wait_until_with_context(
            || {
                fake.substrate_reachability_of(&node.device_id)
                    .is_some_and(|(direct, _)| !direct.is_empty())
            },
            Duration::from_secs(30),
            || format!("{} never published an iroh address", node.device_id),
        )
        .await;
    }
    (fake, a, b, runtimes, dirs)
}

/// Polls the recipient's inbox until the transfer reads `status`.
async fn wait_for_inbox_status(
    recipient: &EngineCommands,
    transfer_id: &str,
    status: &str,
) -> yadorilink_ipc_proto::daemonctl::InboxTransfer {
    for _ in 0..300 {
        if let Some(entry) =
            recipient.list_inbox().unwrap().into_iter().find(|t| t.transfer_id == transfer_id)
        {
            if entry.status == status {
                return entry;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the transfer never read {status}: {:?}", recipient.list_inbox().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_goes_from_created_to_received_and_the_sender_keeps_its_record() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let (fake, a, b, runtimes, _dirs) = stand_up().await;
    let sender = EngineCommands::for_state_for_test(a.state.clone());
    let recipient = EngineCommands::for_state_for_test(b.state.clone());

    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("gift.txt");
    std::fs::write(&file, b"from an iPhone").unwrap();
    let sources = vec![file.to_string_lossy().into_owned()];

    let link = sender.create_send_link(3600, &sources).await.unwrap();
    assert_eq!(
        sender.send_link_status(&link.link_id).await.unwrap().state,
        SendLinkState::Waiting as i32
    );
    let listed = sender.list_send_links().await.unwrap();
    let mine = listed.iter().find(|l| l.link_id == link.link_id).expect("listed");
    assert_eq!(mine.file_count, 1);
    assert_eq!(mine.status.state, SendLinkState::Waiting as i32);

    // The recipient sees what the link carries before redeeming it.
    let preview = recipient.preview_send_link(&link.code).await.unwrap();
    assert_eq!(preview.files.len(), 1);
    assert_eq!(preview.files[0].name, "gift.txt");
    // The service saw neither the name nor the secret half of the code: only ciphertext and hashes.
    let secret = link.code.replace('-', "")[8..].to_string();
    let bodies = fake.send_link_request_bodies().join("\n");
    assert!(!bodies.is_empty());
    assert!(!bodies.contains("gift"), "a file name reached the service: {bodies}");
    assert!(!bodies.to_uppercase().contains(&secret), "the code's secret reached the service");
    // Redeeming is the one consent: the offer that arrives under the link is received by the engine
    // itself into the folder named at redeem, with no receive call.
    let dest = tempfile::tempdir().unwrap();
    let dest_path = dest.path().to_string_lossy().into_owned();
    assert_eq!(recipient.redeem_send_link(&link.code, "", &dest_path).await.unwrap(), link.link_id);
    assert_eq!(
        sender.send_link_status(&link.link_id).await.unwrap().state,
        SendLinkState::Redeemed as i32
    );

    let offered = sender.send_to_link(&link.link_id, &sources).await.unwrap();
    let entry = wait_for_inbox_status(&recipient, &offered.transfer_id, "completed").await;
    assert_eq!(entry.link_id, link.link_id);
    assert_eq!(entry.received_bytes, entry.total_size);
    assert_eq!((entry.files_done, entry.files_total), (1, 1));
    assert_eq!(entry.destination_dir, dest_path);
    assert_eq!(std::fs::read(dest.path().join("gift.txt")).unwrap(), b"from an iPhone");

    // The sender learns the recipient has everything.
    let mut done = false;
    for _ in 0..100 {
        if sender.send_link_status(&link.link_id).await.unwrap().state == SendLinkState::Done as i32
        {
            done = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(done, "the link never read as done");
    assert_eq!(sender.list_sent_transfers().unwrap().len(), 1);

    // A restart keeps the list and which transfer the link started: a fresh command set over
    // the same state directory reads the link as done, with its transfer.
    let restarted = EngineCommands::for_state_for_test(a.state.clone());
    let after = restarted.list_send_links().await.unwrap();
    let kept = after.iter().find(|l| l.link_id == link.link_id).expect("still listed");
    assert_eq!(kept.status.state, SendLinkState::Done as i32);
    assert_eq!(kept.status.transfer_id, offered.transfer_id);

    // The link was one-use.
    assert!(recipient.redeem_send_link(&link.code, "", "").await.is_err());
    for runtime in runtimes {
        runtime.shutdown_background();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusals_are_typed_and_a_cancelled_link_reads_cancelled() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let (_fake, a, b, runtimes, _dirs) = stand_up().await;
    let sender = EngineCommands::for_state_for_test(a.state.clone());
    let recipient = EngineCommands::for_state_for_test(b.state.clone());

    let code_of = |e: yadorilink_daemon::embedded_host::CommandError| match e.kind() {
        CommandErrorKind::Refused(code) => code,
        other => panic!("not a typed refusal: {other:?}"),
    };
    let unknown = recipient.preview_send_link("NOPE-NOPE").await.unwrap_err();
    assert_eq!(code_of(unknown), ApplicationErrorCode::SendLinkInvalid);

    let link = sender.create_send_link(3600, &[]).await.unwrap();
    sender.cancel_send_link(&link.link_id).await.unwrap();
    assert_eq!(
        sender.send_link_status(&link.link_id).await.unwrap().state,
        SendLinkState::Cancelled as i32
    );
    let redeemed = recipient.redeem_send_link(&link.code, "", "").await.unwrap_err();
    assert_eq!(code_of(redeemed), ApplicationErrorCode::SendLinkInvalid);

    // Sending under a cancelled link names why.
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("x.txt");
    std::fs::write(&file, b"x").unwrap();
    let refused = sender
        .send_to_link(&link.link_id, &[file.to_string_lossy().into_owned()])
        .await
        .unwrap_err();
    assert_eq!(code_of(refused), ApplicationErrorCode::SendLinkCancelled);
    for runtime in runtimes {
        runtime.shutdown_background();
    }
}

/// A receive the engine's stop cuts off is recorded as failed with the interrupted reason
/// (not left in progress, not cancelled), and receiving it again fetches only what is missing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stop_interrupts_a_receive_cleanly_and_it_resumes() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let (_fake, a, b, runtimes, _dirs) = stand_up().await;
    let sender = EngineCommands::for_state_for_test(a.state.clone());
    let recipient = EngineCommands::for_state_for_test(b.state.clone());

    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("big.bin");
    let content: Vec<u8> = (0..1_048_576u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&file, &content).unwrap();
    let sources = vec![file.to_string_lossy().into_owned()];
    let link = sender.create_send_link(3600, &sources).await.unwrap();
    let dest = tempfile::tempdir().unwrap();
    let dest_path = dest.path().to_string_lossy().into_owned();
    recipient.redeem_send_link(&link.code, "", &dest_path).await.unwrap();

    // The engine's own receive of the redeemed link's offer parks after two chunks have landed,
    // as a process cut off mid-transfer would.
    let service = b.state.send_service().unwrap();
    let parked = service.test_abort_after_n_chunks(2);
    let offered = sender.send_to_link(&link.link_id, &sources).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), parked.notified()).await.expect("parked");
    let during = wait_for_inbox_status(&recipient, &offered.transfer_id, "in_progress").await;
    assert!(during.received_bytes > 0 && during.received_bytes < during.total_size);
    // Two chunks of one file landed: the file is not done, and the offer holds one.
    assert_eq!((during.files_done, during.files_total), (0, 1));

    service.interrupt_receives(Duration::from_secs(10)).await;
    let entry = recipient.list_inbox().unwrap().into_iter().next().unwrap();
    assert_eq!(entry.status, "failed");
    assert_eq!(entry.failure, "interrupted");

    // Receiving again resumes and completes it.
    let received =
        recipient.receive_transfer(&offered.transfer_id, Some(&dest_path)).await.unwrap();
    assert_eq!(received.files_received, vec!["big.bin".to_string()]);
    assert_eq!(std::fs::read(dest.path().join("big.bin")).unwrap(), content);
    for runtime in runtimes {
        runtime.shutdown_background();
    }
}

/// The sender's engine is killed mid-transfer: after it starts again the link reads interrupted
/// (not transferring forever), the transfer is stopped for good (the link's grant is spent: no
/// resume, only a new link) and the receiver is told so when it comes back to pull.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sender_engine_that_restarted_mid_transfer_reads_interrupted() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let (_fake, a, b, runtimes, _dirs) = stand_up().await;
    let sender = EngineCommands::for_state_for_test(a.state.clone());
    let recipient = EngineCommands::for_state_for_test(b.state.clone());

    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("big.bin");
    let content: Vec<u8> = (0..1_048_576u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&file, &content).unwrap();
    let sources = vec![file.to_string_lossy().into_owned()];
    let link = sender.create_send_link(3600, &sources).await.unwrap();
    let dest = tempfile::tempdir().unwrap();
    let dest_path = dest.path().to_string_lossy().into_owned();
    recipient.redeem_send_link(&link.code, "", &dest_path).await.unwrap();

    let service = b.state.send_service().unwrap();
    let parked = service.test_abort_after_n_chunks(2);
    let offered = sender.send_to_link(&link.link_id, &sources).await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), parked.notified()).await.expect("parked");
    let during = wait_for_inbox_status(&recipient, &offered.transfer_id, "in_progress").await;
    assert!(during.received_bytes > 0 && during.received_bytes < during.total_size);
    assert_eq!(
        sender.send_link_status(&link.link_id).await.unwrap().state,
        SendLinkState::Transferring as i32,
        "while the sender's engine is alive and sending, the link is going"
    );

    // A command set with no memory of the send is a sender engine that started again.
    let restarted = EngineCommands::for_state_for_test(a.state.clone());
    assert_eq!(
        restarted.send_link_status(&link.link_id).await.unwrap().state,
        SendLinkState::Interrupted as i32
    );
    assert_eq!(restarted.list_sent_transfers().unwrap()[0].status, "canceled");

    service.interrupt_receives(Duration::from_secs(10)).await;
    recipient
        .receive_transfer(&offered.transfer_id, Some(&dest_path))
        .await
        .expect_err("the sender stopped the transfer; there is no resume");
    for runtime in runtimes {
        runtime.shutdown_background();
    }
}

/// An offer under a link this device did not redeem, like any unsolicited offer, waits in the
/// inbox for an explicit receive and is not received by itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_offer_under_a_link_this_device_did_not_redeem_waits_for_an_explicit_receive() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let (fake, a, b, runtimes, _dirs) = stand_up().await;
    let sender = EngineCommands::for_state_for_test(a.state.clone());
    let recipient = EngineCommands::for_state_for_test(b.state.clone());

    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("unasked.txt");
    std::fs::write(&file, b"nobody agreed to this").unwrap();
    let sources = vec![file.to_string_lossy().into_owned()];
    let link = sender.create_send_link(3600, &sources).await.unwrap();
    // Redeemed at the service on the recipient's behalf, without the recipient's engine being
    // told: the same position as a device that lost its record of the redeem.
    yadorilink_daemon::coordination_client::redeem_send_link(
        &fake.addr(),
        &yadorilink_fapi_client::test_support::offline_auth(),
        &link.code,
        &b.device_id,
    )
    .await
    .unwrap();
    let offered = sender.send_to_link(&link.link_id, &sources).await.unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;
    let inbox = recipient.list_inbox().unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].transfer_id, offered.transfer_id);
    assert_eq!(inbox[0].status, "pending");
    assert_eq!(inbox[0].link_id, link.link_id, "the entry names its link even when it waits");
    for runtime in runtimes {
        runtime.shutdown_background();
    }
}

/// Makes a link, redeems it onto the second device and returns what a send needs.
async fn redeemed_link(
    a: &TopologyNode,
    b: &TopologyNode,
) -> (EngineCommands, EngineCommands, String, Vec<String>, tempfile::TempDir) {
    let sender = EngineCommands::for_state_for_test(a.state.clone());
    let recipient = EngineCommands::for_state_for_test(b.state.clone());
    let src = tempfile::tempdir().unwrap();
    let file = src.path().join("late.txt");
    std::fs::write(&file, b"grant push arrives late").unwrap();
    let sources = vec![file.to_string_lossy().into_owned()];
    let link = sender.create_send_link(3600, &sources).await.unwrap();
    recipient.redeem_send_link(&link.code, "", "").await.unwrap();
    (sender, recipient, link.link_id, sources, src)
}

/// The grant reaches the receiver by a push that is independent of the sender's own grant
/// response. When the sender dials first, the receiver does not admit it yet; the send must
/// still get through once the push lands, not stay "transferring" with nothing delivered
/// (the stuck Mac live check).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grant_push_that_lands_after_the_sender_dialed_still_delivers() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let (fake, a, b, runtimes, _dirs) = stand_up().await;
    let (sender, recipient, link_id, sources, _src) = redeemed_link(&a, &b).await;

    fake.hold_send_authorization_pushes();
    let send = tokio::spawn({
        let link_id = link_id.clone();
        async move { sender.send_to_link(&link_id, &sources).await }
    });
    wait_until_with_context(
        || fake.held_send_authorization_pushes() == 1,
        Duration::from_secs(30),
        || "the sender never asked for its grant".to_string(),
    )
    .await;
    // The sender has the grant and is dialing; the receiver has not been told.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!send.is_finished(), "the offer cannot have been accepted without the push");
    fake.release_send_authorization_pushes();

    let offered = send.await.unwrap().expect("the offer is accepted once the receiver admits it");
    let inbox = recipient.list_inbox().unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].transfer_id, offered.transfer_id);
    for runtime in runtimes {
        runtime.shutdown_background();
    }
}

/// A send that cannot get in fails with a typed, visible error, and the link then reads
/// interrupted instead of transferring.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_send_the_receiver_never_admits_ends_interrupted_not_transferring() {
    let _turn = ONE_AT_A_TIME.lock().await;
    let (fake, a, b, runtimes, _dirs) = stand_up().await;
    let (sender, recipient, link_id, sources, _src) = redeemed_link(&a, &b).await;
    a.state.send_service().unwrap().set_offer_admission_window(Duration::from_secs(2));

    fake.hold_send_authorization_pushes();
    let err = sender.send_to_link(&link_id, &sources).await.expect_err("nobody admitted it");
    assert!(matches!(
        err.kind(),
        CommandErrorKind::Refused(ApplicationErrorCode::SendPeerUnreachable)
    ));
    assert_eq!(
        sender.send_link_status(&link_id).await.unwrap().state,
        SendLinkState::Interrupted as i32
    );
    assert!(recipient.list_inbox().unwrap().is_empty());
    for runtime in runtimes {
        runtime.shutdown_background();
    }
}
