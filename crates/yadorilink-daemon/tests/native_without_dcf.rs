//! Normal operation needs no DCF: the replica schema holds no DCF change or
//! history table, and native capture, sync, conflict, restart, removal and a
//! fresh joiner still converge without one appearing. A hidden dependency on
//! DCF state shows up as a failure here instead of as a silently populated
//! table.

mod native_e2e_support;
mod support;

use native_e2e_support::*;

const GROUP: &str = "native-without-dcf";

/// The DCF change graph, its retained objects and the HistoryBase state.
/// (`file_versions` is the content-version store native shares, and
/// `author_own_ahead` belongs to the author identity every authoring checks.)
const DCF_TABLES: &[&str] = &[
    "admitted_changes",
    "author_chain_state",
    "change_store",
    "dcf_admission_holds",
    "dcf_admission_node_waits",
    "dcf_change_dots",
    "dcf_namespace_roots",
    "dcf_path_basis",
    "dcf_path_effects",
    "dcf_path_heads",
    "dcf_pending_retries",
    "dcf_retired_subtrees",
    "dcf_retry_dependencies",
    "dcf_unsettled_changes",
    "group_heads",
    "recursive_operation_parts",
    "recursive_operations",
    "rejected_changes",
    "change_authorization",
    "change_checkpoint_snapshots",
    "change_checkpoints",
    "change_parents",
    "dag_retention_roots",
    "group_history_bases",
    "history_base_author_state",
    "history_base_carried_authors",
    "history_base_meta",
    "history_base_path_heads",
    "published_evidence",
    "verified_change_objects",
    "verified_change_parents",
    "verified_change_version_refs",
    "verified_change_versions",
    "verified_checkpoints",
];

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

/// The DCF tables or views present on `node`. The replica schema creates
/// none, so any present one was created by something that depends on it.
fn dcf_state_present(node: &TopologyNode) -> Vec<String> {
    read(node, |conn| {
        let mut back = Vec::new();
        for table in DCF_TABLES {
            let exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type IN ('table', 'view') \
                 AND name = ?1)",
                [table],
                |r| r.get(0),
            )?;
            if exists {
                back.push((*table).to_owned());
            }
        }
        Ok(back)
    })
}

async fn native_pair(a: &TopologyNode, b: &TopologyNode) {
    pair(a, b, GROUP).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn native_operation_leaves_no_dcf_state() {
    setup();
    let a = device("nodcf-a", GROUP);
    let b = device("nodcf-b", GROUP);
    assert!(!DCF_TABLES.is_empty(), "the guard must cover real tables");
    native_pair(&a, &b).await;

    // Capture, sync, materialize.
    write(&a, "doc.txt", b"one");
    write(&a, "dir/nested.txt", b"nested");
    converge_to(&[&a, &b], &[("doc.txt", b"one"), ("dir/nested.txt", b"nested")], "create").await;

    // The rest needs a conflict winner to replace the loser's original and a
    // removal to reach the peer, which a platform without durable namespace
    // changes holds back; the create-and-sync half above still has to leave
    // no DCF state there.
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the conflict winner replacing the original and removals reaching the peer",
    ) {
        for node in [&a, &b] {
            assert_eq!(
                dcf_state_present(node),
                Vec::<String>::new(),
                "{} holds DCF state",
                node.device_id
            );
        }
        return;
    }

    // Concurrent edits keep both versions, one as a copy, on both.
    partition(&a, &b).await;
    write(&a, "doc.txt", b"from a");
    write(&b, "doc.txt", b"from b");
    captured(&a, GROUP).await;
    captured(&b, GROUP).await;
    native_pair(&a, &b).await;
    let tree = converge_where(&[&a, &b], "both versions kept", |tree| {
        let contents: Vec<&Vec<u8>> = tree.values().collect();
        contents.contains(&&b"from a".to_vec()) && contents.contains(&&b"from b".to_vec())
    })
    .await;
    assert_eq!(conflict_copies(&tree).len(), 1, "{:?}", tree.keys().collect::<Vec<_>>());
    converge_state(&[&a, &b], GROUP, "one native state").await;

    // A restart keeps the state, and the device keeps writing.
    let b = restart(b, &[&a], GROUP).await;
    write(&b, "after-restart.txt", b"after");
    let copy = conflict_copies(&tree).remove(0);
    let winner = tree["doc.txt"].clone();
    converge_to(
        &[&a, &b],
        &[
            ("doc.txt", &winner),
            (&copy, &tree[&copy]),
            ("dir/nested.txt", b"nested"),
            ("after-restart.txt", b"after"),
        ],
        "after restart",
    )
    .await;

    // Removals and a recursive removal.
    remove(&a, "after-restart.txt");
    remove(&a, "dir");
    converge_to(&[&a, &b], &[("doc.txt", &winner), (&copy, &tree[&copy])], "removals").await;
    converge_state(&[&a, &b], GROUP, "one native state after removals").await;

    // The writes that happened left no DCF state behind.
    for node in [&a, &b] {
        assert_eq!(
            dcf_state_present(node),
            Vec::<String>::new(),
            "{} holds DCF state",
            node.device_id
        );
    }
}

/// A folder that already holds files when it is linked is imported without
/// any DCF row, and the files reach a peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn importing_a_populated_folder_leaves_no_dcf_state() {
    setup();
    let a = new_node("nodcf-import-a");
    assert!(!DCF_TABLES.is_empty(), "the guard must cover real tables");
    write(&a, "old.txt", b"was here before the link");
    write(&a, "dir/nested.txt", b"nested");
    link_eager(&a, GROUP);
    let b = device("nodcf-import-b", GROUP);
    native_pair(&a, &b).await;
    converge_to(
        &[&a, &b],
        &[("old.txt", b"was here before the link"), ("dir/nested.txt", b"nested")],
        "the pre-existing files reach the peer",
    )
    .await;
    for node in [&a, &b] {
        assert_eq!(
            dcf_state_present(node),
            Vec::<String>::new(),
            "{} holds DCF state",
            node.device_id
        );
    }
}
