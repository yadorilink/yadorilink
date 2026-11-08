//! A concurrent edit of one file while one device is away converges by itself once the device is
//! back: both ends end with the same tree, the file and one conflicted copy holding the two
//! versions, and no head of the path stays contested. Whichever device the tie-break makes the
//! loser, and whether the away device was only cut off or its daemon was down and its edit made
//! on the disk while nothing was watching, no one has to act.

use crate::native_e2e_support;
use crate::support;

use std::time::Duration;

use native_e2e_support::device_fast as device;
use native_e2e_support::*;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;

const GROUP: &str = "conflict-loser-offline-group";
const FILE: &str = "shared.txt";
const AWAY_EDIT: &[u8] = b"edited while away";
const HOME_EDIT: &[u8] = b"edited at home, and longer";

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

/// `away_is_a`: which of the two devices is the one that is away. `daemon_down`: the away device's
/// daemon is stopped for the whole time and its edit lands on the disk meanwhile; otherwise it is
/// running and only cut off from the other.
async fn run(away_is_a: bool, daemon_down: bool) {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    setup();
    let tag =
        format!("{}{}", if away_is_a { "a" } else { "b" }, if daemon_down { "d" } else { "p" });
    let a = device(&format!("clo-a-{tag}"), GROUP);
    let b = device(&format!("clo-b-{tag}"), GROUP);
    pair(&a, &b, GROUP).await;
    write(&a, FILE, b"base");
    converge_to(&[&a, &b], &[(FILE, b"base")], "the base file").await;

    partition(&a, &b).await;
    let (away, home) = if away_is_a { (a, b) } else { (b, a) };
    write(&home, FILE, HOME_EDIT);
    captured(&home, GROUP).await;
    let away = if daemon_down {
        support::topology::shutdown_substrate(&away).await;
        LinkRuntimeController::new(away.state.clone())
            .stop(&away.root.path().to_string_lossy())
            .await;
        write(&away, FILE, AWAY_EDIT);
        // The device starts again with nothing to reach.
        support::topology::restart_node(away).await
    } else {
        write(&away, FILE, AWAY_EDIT);
        away
    };
    // A restarted device has its group policy again only once it reaches a peer, so its edit
    // is captured after the two meet.
    if !daemon_down {
        captured(&away, GROUP).await;
    }
    // Time passes with the two apart; neither has seen the other's edit.
    tokio::time::sleep(Duration::from_millis(500)).await;

    pair(&away, &home, GROUP).await;
    let settled = converge_where(&[&away, &home], "the edits of the two devices", |tree| {
        let copies = conflict_copies(tree);
        copies.len() == 1
            && tree.len() == 2
            && tree.values().any(|v| v == AWAY_EDIT)
            && tree.values().any(|v| v == HOME_EDIT)
    })
    .await;
    assert_eq!(settled.len(), 2, "{settled:?}");

    // No head of the path is left contested on either end, and nothing is still open.
    for node in [&away, &home] {
        for path in settled.keys() {
            assert_eq!(live_head_ids(node, GROUP, path).len(), 1, "{} {path}", node.device_id);
        }
        assert_eq!(live_head_ids(node, GROUP, FILE).len(), 1, "{}", node.device_id);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn loser_cut_off_a_converges_without_action() {
    run(true, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn loser_cut_off_b_converges_without_action() {
    run(false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn daemon_down_a_converges_without_action() {
    run(true, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn daemon_down_b_converges_without_action() {
    run(false, true).await;
}
