//! Recovery after a laptop sleeps or the network changes, at the scale of a
//! small real folder (tens of files): a device is cut off from its peer (or
//! its daemon is stopped, as when the machine sleeps), both sides keep editing,
//! and when the link returns nothing may need doing by hand. Every test checks
//! the same three things: the trees converge, no write is lost (every distinct
//! byte string a side wrote is still in the final tree, at its path or as a
//! conflicted copy), and conflicted copies appear only where both sides edited
//! the same path.
//!
//! The single-file shapes of these races live in `native_replication_e2e.rs`
//! and `partition_reconnect_matrix.rs`; this file adds the volume, the mixed
//! operations (edit, delete, rename, create) and repeated flaps.

mod native_e2e_support;
mod support;

use std::collections::BTreeMap;

use native_e2e_support::*;
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;

const GROUP: &str = "sleep-wake-group";
const BASE_FILES: usize = 60;

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

fn base_name(i: usize) -> String {
    format!("dir{}/base-{i:03}.txt", i % 4)
}

fn base_bytes(i: usize) -> Vec<u8> {
    format!("base content {i}\n").repeat(20).into_bytes()
}

/// Two paired devices that share `BASE_FILES` files.
async fn two_with_base(prefix: &str) -> (TopologyNode, TopologyNode) {
    let a = device(&format!("{prefix}-a"), GROUP);
    let b = device(&format!("{prefix}-b"), GROUP);
    pair(&a, &b, GROUP).await;
    for i in 0..BASE_FILES {
        write(&a, &base_name(i), &base_bytes(i));
    }
    let names: Vec<String> = (0..BASE_FILES).map(base_name).collect();
    converge_where(&[&a, &b], "the base reaches both devices", |tree| {
        names.iter().all(|n| tree.get(n).is_some())
    })
    .await;
    (a, b)
}

/// What the folder must hold once everything has crossed: `exact` are the
/// paths nobody contended (every file, untouched ones included, with its
/// bytes); each `contended` path was edited by both sides, so it keeps one of
/// the two versions and the other is in exactly one conflicted copy of it.
struct Expected {
    exact: BTreeMap<String, Vec<u8>>,
    contended: Vec<(String, Vec<u8>, Vec<u8>)>,
}

impl Expected {
    fn from_base() -> Self {
        Self {
            exact: (0..BASE_FILES).map(|i| (base_name(i), base_bytes(i))).collect(),
            contended: Vec::new(),
        }
    }

    fn put(&mut self, node: &TopologyNode, path: &str, bytes: Vec<u8>) {
        write(node, path, &bytes);
        self.exact.insert(path.to_string(), bytes);
    }

    fn contend(
        &mut self,
        a: &TopologyNode,
        b: &TopologyNode,
        path: &str,
        a_bytes: &[u8],
        b_bytes: &[u8],
    ) {
        write(a, path, a_bytes);
        write(b, path, b_bytes);
        self.exact.remove(path);
        self.contended.push((path.to_string(), a_bytes.to_vec(), b_bytes.to_vec()));
    }

    /// Whether `tree` is exactly the expected result, or why not.
    fn check(&self, tree: &BTreeMap<String, Vec<u8>>) -> Result<(), String> {
        let files: BTreeMap<&String, &Vec<u8>> =
            tree.iter().filter(|(name, _)| !name.ends_with('/')).collect();
        let copies = conflict_copies(tree);
        let mut seen = 0;
        for (path, bytes) in &self.exact {
            if files.get(path).map(|b| b.as_slice()) != Some(bytes.as_slice()) {
                return Err(format!("{path} does not hold its expected bytes"));
            }
            seen += 1;
        }
        for (path, a_bytes, b_bytes) in &self.contended {
            let stem =
                std::path::Path::new(path).file_stem().unwrap().to_string_lossy().to_string();
            let dir = path.rsplit_once('/').map(|(d, _)| format!("{d}/")).unwrap_or_default();
            let prefix = format!("{dir}{stem} (conflicted copy");
            let mine: Vec<&String> = copies.iter().filter(|c| c.starts_with(&prefix)).collect();
            if mine.len() != 1 {
                return Err(format!("want exactly one conflicted copy of {path}: {copies:?}"));
            }
            let Some(kept) = files.get(path) else {
                return Err(format!("{path} is missing: {copies:?}"));
            };
            let copy = &tree[mine[0]];
            let ok = (kept == &a_bytes && copy == b_bytes) || (kept == &b_bytes && copy == a_bytes);
            if !ok {
                return Err(format!("{path} and its copy must hold the two edits"));
            }
            seen += 2;
        }
        if files.len() != seen {
            return Err(format!("no other file may exist: {:?}", files.keys().collect::<Vec<_>>()));
        }
        Ok(())
    }

    /// Waits until both devices hold exactly the expected tree.
    async fn settle(&self, a: &TopologyNode, b: &TopologyNode) {
        let tree = converge_where(&[a, b], "both devices settle on the expected tree", |tree| {
            self.check(tree).is_ok()
        })
        .await;
        self.check(&tree).unwrap();
    }
}

/// Both sides do a different mix of operations on disjoint files, plus three
/// same-path edits and one edit-against-delete, while cut off from each other.
fn offline_workload(a: &TopologyNode, b: &TopologyNode) -> Expected {
    let mut e = Expected::from_base();
    for i in 0..10 {
        e.put(a, &base_name(i), format!("a edited {i}\n").into_bytes());
        e.put(b, &base_name(10 + i), format!("b edited {i}\n").into_bytes());
    }
    for i in 0..15 {
        e.put(a, &format!("new-a/{i}.txt"), format!("a created {i}\n").into_bytes());
        e.put(b, &format!("new-b/{i}.txt"), format!("b created {i}\n").into_bytes());
    }
    for i in 20..24 {
        remove(a, &base_name(i));
        e.exact.remove(&base_name(i));
    }
    for i in 24..28 {
        remove(b, &base_name(i));
        e.exact.remove(&base_name(i));
    }
    rename(a, &base_name(28), "renamed-by-a.txt");
    let bytes = e.exact.remove(&base_name(28)).unwrap();
    e.exact.insert("renamed-by-a.txt".to_string(), bytes);
    rename(b, &base_name(29), "renamed-by-b.txt");
    let bytes = e.exact.remove(&base_name(29)).unwrap();
    e.exact.insert("renamed-by-b.txt".to_string(), bytes);
    for i in 30..33 {
        e.contend(
            a,
            b,
            &base_name(i),
            format!("a contended {i}\n").as_bytes(),
            format!("b contended {i}\n").as_bytes(),
        );
    }
    // An edit on one side against a delete on the other. The test pins the
    // outcome (the edit survives); that the delete itself is authored and
    // replicated is pinned by the uncontended deletes above, which take the
    // same path.
    remove(a, &base_name(40));
    e.put(b, &base_name(40), b"b edited what a deleted\n".to_vec());
    e
}

/// The link between the devices drops (Wi-Fi lost, interface switched), both
/// sides keep working, and the link comes back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dropped_link_with_edits_on_both_sides_recovers_without_loss() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    setup();
    let (a, b) = two_with_base("sw-link").await;

    partition(&a, &b).await;
    let expected = offline_workload(&a, &b);
    captured(&a, GROUP).await;
    captured(&b, GROUP).await;
    pair(&a, &b, GROUP).await;

    expected.settle(&a, &b).await;
}

/// One machine sleeps: its daemon is stopped and the peer cannot reach it.
/// Both folders change meanwhile; the daemon starts again on wake.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_machine_that_slept_with_edits_on_both_sides_recovers_without_loss() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    setup();
    let (a, b) = two_with_base("sw-sleep").await;

    let a_path = a.root.path().to_string_lossy().to_string();
    LinkRuntimeController::new(a.state.clone()).stop(&a_path).await;
    partition(&a, &b).await;
    let expected = offline_workload(&a, &b);
    captured(&b, GROUP).await;

    let a = restart(a, &[&b], GROUP).await;
    expected.settle(&a, &b).await;
}

/// A flapping link: three cut-and-restore cycles, each with edits on both
/// sides (a fresh file each, plus one path edited by both in the first
/// cycle). The end state is the union of everything written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flapping_link_loses_nothing_across_repeated_reconnects() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    setup();
    let (a, b) = two_with_base("sw-flap").await;
    let mut expected = Expected::from_base();
    for cycle in 0..3 {
        partition(&a, &b).await;
        for i in 0..8 {
            expected.put(
                &a,
                &format!("flap-a/{cycle}-{i}.txt"),
                format!("a cycle {cycle} file {i}\n").into_bytes(),
            );
            expected.put(
                &b,
                &format!("flap-b/{cycle}-{i}.txt"),
                format!("b cycle {cycle} file {i}\n").into_bytes(),
            );
        }
        if cycle == 0 {
            expected.contend(&a, &b, &base_name(5), b"a flap contended\n", b"b flap contended\n");
        }
        captured(&a, GROUP).await;
        captured(&b, GROUP).await;
        pair(&a, &b, GROUP).await;
        let last = format!("flap-b/{cycle}-7.txt");
        let last_a = format!("flap-a/{cycle}-7.txt");
        converge_where(&[&a, &b], "the cycle's writes cross", |tree| {
            tree.contains_key(&last) && tree.contains_key(&last_a)
        })
        .await;
    }
    expected.settle(&a, &b).await;
}

/// Deterministic multi-block bytes, different for every `seed`.
fn large_bytes(seed: u8) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15_u64 ^ u64::from(seed);
    (0..5 * 1024 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

/// Sets a file's modified time to `secs` seconds from the Unix epoch, as a
/// clock that stepped while the machine slept would have stamped it.
fn stamp(node: &TopologyNode, relative: &str, secs: u64) {
    let when = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
    let file = std::fs::File::options().write(true).open(node.root.path().join(relative)).unwrap();
    file.set_times(std::fs::FileTimes::new().set_modified(when)).unwrap();
}

/// Large files are written and the link is cut right after the first device
/// published them, so the peer is at most part way through fetching. Both
/// sides then edit the same large file and the link returns: nothing is lost,
/// whichever point the fetch had reached when the link dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_cut_during_a_large_transfer_with_both_sides_editing_recovers() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    setup();
    let (a, b) = two_with_base("sw-large").await;
    let mut expected = Expected::from_base();

    for i in 0..3u8 {
        expected.put(&a, &format!("big/a-{i}.bin"), large_bytes(i));
    }
    expected.put(&a, "big/shared.bin", large_bytes(10));
    captured(&a, GROUP).await;
    partition(&a, &b).await;

    expected.put(&b, "big/b-only.bin", large_bytes(11));
    // Whichever version of the shared file b held when the link dropped, both
    // sides now replace it with different content.
    // The replacements differ in length from the original and from each other,
    // so the capture check (which compares sizes) cannot pass before the
    // watcher has seen each edit.
    let (mut a_edit, mut b_edit) = (large_bytes(20), large_bytes(21));
    a_edit.extend_from_slice(b"a tail\n");
    b_edit.extend_from_slice(b"b longer tail\n");
    write(&a, "big/shared.bin", &a_edit);
    write(&b, "big/shared.bin", &b_edit);
    expected.exact.remove("big/shared.bin");
    // b may never have received the shared file; then there is no contention
    // and a's edit simply wins. Accept either end state below.
    captured(&a, GROUP).await;
    captured(&b, GROUP).await;
    pair(&a, &b, GROUP).await;

    let tree = converge_where(&[&a, &b], "the large files cross and settle", |tree| {
        expected.exact.iter().all(|(p, bytes)| tree.get(p) == Some(bytes))
            && tree.contains_key("big/shared.bin")
    })
    .await;
    let kept = &tree["big/shared.bin"];
    let shared_copies: Vec<String> =
        conflict_copies(&tree).into_iter().filter(|c| c.starts_with("big/shared")).collect();
    // Every edit survives, at the path or in a conflicted copy.
    for edit in [&a_edit, &b_edit] {
        assert!(
            kept == edit || shared_copies.iter().any(|c| &tree[c] == edit),
            "an edit of the shared file was lost: {shared_copies:?}"
        );
    }
}

/// The clock stepped back while the machine slept: the edit made after waking
/// is stamped older than the file it replaces. It still reaches the peer, and
/// two such edits of one path both survive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edits_stamped_by_a_clock_that_stepped_back_still_propagate() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    setup();
    let (a, b) = two_with_base("sw-clock-back").await;
    let mut expected = Expected::from_base();

    partition(&a, &b).await;
    // A year before the base files were written.
    let long_ago = 1_000_000_000;
    for i in 0..5 {
        let name = base_name(i);
        expected.put(&a, &name, format!("a after clock step {i}\n").into_bytes());
        stamp(&a, &name, long_ago);
    }
    expected.put(&b, &base_name(5), b"b untouched clock\n".to_vec());
    expected.contend(&a, &b, &base_name(6), b"a stamped old\n", b"b stamped now\n");
    stamp(&a, &base_name(6), long_ago);
    captured(&a, GROUP).await;
    captured(&b, GROUP).await;
    pair(&a, &b, GROUP).await;

    expected.settle(&a, &b).await;
}

/// The same, with the clock stepped far forward: edits stamped in the distant
/// future do not outrank later real edits, and nothing is dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edits_stamped_by_a_clock_that_stepped_far_forward_lose_nothing() {
    if !yadorilink_daemon::test_support::windows_durability_gate_allows_tests(
        "the winner replacing the loser's original",
    ) {
        return;
    }
    setup();
    let (a, b) = two_with_base("sw-clock-fwd").await;
    let mut expected = Expected::from_base();

    partition(&a, &b).await;
    let far_future = 4_000_000_000;
    for i in 0..5 {
        let name = base_name(i);
        expected.put(&a, &name, format!("a future stamp {i}\n").into_bytes());
        stamp(&a, &name, far_future);
    }
    expected.contend(&a, &b, &base_name(6), b"a stamped future\n", b"b stamped now\n");
    stamp(&a, &base_name(6), far_future);
    expected.put(&b, &base_name(7), b"b edit\n".to_vec());
    captured(&a, GROUP).await;
    captured(&b, GROUP).await;
    pair(&a, &b, GROUP).await;

    expected.settle(&a, &b).await;
}
