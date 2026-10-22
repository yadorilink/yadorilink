//! Large-tree convergence gate: a seeded, deterministic tree of many small files across nested
//! directories plus a few large files is synced between two or three real daemons, mutated
//! (rename, delete, modify, create, a directory move) and must end with the same content on every
//! device, nothing stuck, and bounded resources.
//!
//! This is a manual / periodic gate, NOT a per-PR check: it is `#[ignore]`d and run through
//! `cargo large-tree-gate [--files N]` (see `docs/TESTING.md`). The default size is small enough
//! for about a minute on a developer machine; `--files 100000` is the promotion tier.
//!
//! The daemons are the production composition the other native end-to-end tests use
//! (`native_e2e_support`): real file-backed SQLite, the real watcher and capture, native signed
//! deltas over the loopback reconciliation stack, real block store and materialization. They share
//! this process, so peak RSS is one number for all of them.
//!
//! Knobs (environment; the xtask sets them from its flags):
//! - `LARGE_TREE_FILES`      small files in the initial tree (default 1500)
//! - `LARGE_TREE_SEED`       the seed everything is derived from (default 1)
//! - `LARGE_TREE_DEVICES`    2 or 3 (default 3)
//! - `LARGE_TREE_LARGE_FILES` / `LARGE_TREE_LARGE_BYTES` the large files (default 3 x 6 MiB)
//! - `LARGE_TREE_CONVERGE_SECS` the wait for each convergence (default scales with the size)
//! - `LARGE_TREE_MAX_WALL_SECS`, `LARGE_TREE_MAX_RSS_MB` the resource thresholds
//! - `LARGE_TREE_REPORT`     a file to append the JSON metrics line to
//! - `LARGE_TREE_FAULT=skip-rename` the negative control: the apply side skips one rename, so the
//!   gate must fail (`cargo large-tree-gate --self-check` runs it)
//!
//! Set `TMPDIR` to a roomy volume for large sizes: every device keeps its folder, block store and
//! database there.
#![cfg(unix)]

mod native_e2e_support;
mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, Instant};

use native_e2e_support::*;
use sha2::{Digest, Sha256};
use support::control_socket_client;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::StatusRequest;

const GROUP: &str = "large-tree-gate-group";
const MARKER: &str = "LARGE_TREE_GATE_FAIL";

type Hash = [u8; 32];

fn env_num<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn fail(message: String) -> ! {
    panic!("{MARKER}: {message}");
}

// --- Deterministic generation -----------------------------------------------------

/// SplitMix64: a small, fixed generator so a seed names the same tree on every machine.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// `len` bytes that depend only on `(seed, tag)`; every file gets its own tag, so no two differ
/// by accident of generation.
fn content(seed: u64, tag: u64, len: usize) -> Vec<u8> {
    let mut rng = Rng(seed ^ tag.wrapping_mul(0xD1B5_4A32_D192_ED03));
    let mut out = Vec::with_capacity(len + 8);
    while out.len() < len {
        out.extend_from_slice(&rng.next().to_le_bytes());
    }
    out.truncate(len);
    out
}

fn hash_of(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

fn short(hash: &Hash) -> String {
    hash.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// What every device must hold, by relative path.
type Oracle = BTreeMap<String, Hash>;

fn put(node: &TopologyNode, oracle: &mut Oracle, relative: &str, bytes: &[u8]) {
    write(node, relative, bytes);
    oracle.insert(relative.to_owned(), hash_of(bytes));
}

struct Plan {
    files: usize,
    seed: u64,
    large_files: usize,
    large_bytes: usize,
}

/// Writes the initial tree into `node`'s folder and returns the oracle. Directories form a random
/// recursive tree (broad near the root) with a few deep chains; sizes are mostly small with a
/// medium tail, so block transfer is exercised without the run becoming bandwidth-bound.
fn populate(node: &TopologyNode, plan: &Plan) -> Oracle {
    let mut rng = Rng(plan.seed);
    let dir_count = (plan.files / 25).max(4);
    let mut dirs: Vec<String> = vec![String::new()];
    let mut depth: Vec<usize> = vec![0];
    for i in 1..=dir_count {
        let parent = if i % 97 == 0 { i - 1 } else { rng.below(i) };
        let parent = if depth[parent] >= 12 { 0 } else { parent };
        let relative = if dirs[parent].is_empty() {
            format!("d{i:05}")
        } else {
            format!("{}/d{i:05}", dirs[parent])
        };
        std::fs::create_dir_all(node.root.path().join(&relative)).unwrap();
        dirs.push(relative);
        depth.push(depth[parent] + 1);
    }
    let mut oracle = Oracle::new();
    for idx in 0..plan.files {
        let dir = &dirs[rng.below(dirs.len())];
        let size =
            if rng.below(20) == 0 { 8_192 + rng.below(56_000) } else { 1 + rng.below(1_500) };
        let relative =
            if dir.is_empty() { format!("f{idx:06}.dat") } else { format!("{dir}/f{idx:06}.dat") };
        put(node, &mut oracle, &relative, &content(plan.seed, (idx as u64) << 8, size));
    }
    for k in 0..plan.large_files {
        let tag = (1u64 << 40) + k as u64;
        put(
            node,
            &mut oracle,
            &format!("large/big{k}.bin"),
            &content(plan.seed, tag, plan.large_bytes),
        );
    }
    for j in 0..moved_tree_size(plan) {
        let tag = (2u64 << 40) + j as u64;
        put(
            node,
            &mut oracle,
            &format!("moved-tree/sub/m{j:03}.dat"),
            &content(plan.seed, tag, 200 + j),
        );
    }
    oracle
}

fn moved_tree_size(plan: &Plan) -> usize {
    (plan.files / 50).clamp(5, 60)
}

// --- Reading a device's folder ----------------------------------------------------

/// Every real file under `root` (relative path) and every real directory.
fn walk(root: &Path) -> (Vec<String>, BTreeSet<String>) {
    let mut files = Vec::new();
    let mut dirs = BTreeSet::new();
    let mut stack = vec![String::new()];
    while let Some(relative) = stack.pop() {
        let dir = if relative.is_empty() { root.to_path_buf() } else { root.join(&relative) };
        for name in support::real_entry_names(&dir) {
            let child =
                if relative.is_empty() { name.clone() } else { format!("{relative}/{name}") };
            if root.join(&child).is_dir() {
                dirs.insert(child.clone());
                stack.push(child);
            } else {
                files.push(child);
            }
        }
    }
    (files, dirs)
}

fn manifest(root: &Path) -> Oracle {
    walk(root)
        .0
        .into_iter()
        .filter_map(|path| std::fs::read(root.join(&path)).ok().map(|b| (path, hash_of(&b))))
        .collect()
}

/// The first differences between a device and the oracle, for the failure message.
fn first_differences(actual: &Oracle, expected: &Oracle) -> String {
    const LIMIT: usize = 12;
    let missing: Vec<&String> = expected.keys().filter(|p| !actual.contains_key(*p)).collect();
    let extra: Vec<&String> = actual.keys().filter(|p| !expected.contains_key(*p)).collect();
    let changed: Vec<String> = expected
        .iter()
        .filter_map(|(p, h)| match actual.get(p) {
            Some(a) if a != h => Some(format!("{p} (expected {}, found {})", short(h), short(a))),
            _ => None,
        })
        .collect();
    format!(
        "{} missing, first {:?}; {} unexpected, first {:?}; {} content mismatches, first {:?}",
        missing.len(),
        &missing[..missing.len().min(LIMIT)],
        extra.len(),
        &extra[..extra.len().min(LIMIT)],
        changed.len(),
        &changed[..changed.len().min(LIMIT)],
    )
}

/// Waits until every device holds exactly `oracle`. The cheap file-name walk gates the content
/// hashing, so a large tree is not re-read on every poll while files are still arriving.
async fn await_tree(
    nodes: &[&TopologyNode],
    oracle: &Oracle,
    timeout: Duration,
    what: &str,
) -> Duration {
    let started = Instant::now();
    let expected_names: BTreeSet<&String> = oracle.keys().collect();
    loop {
        let names_match = nodes.iter().all(|node| {
            let (files, _) = walk(node.root.path());
            files.len() == expected_names.len() && files.iter().all(|f| expected_names.contains(f))
        });
        if names_match && nodes.iter().all(|node| &manifest(node.root.path()) == oracle) {
            return started.elapsed();
        }
        if started.elapsed() > timeout {
            let report: Vec<String> = nodes
                .iter()
                .map(|node| {
                    format!(
                        "{}: {} [{}]",
                        node.device_id,
                        first_differences(&manifest(node.root.path()), oracle),
                        counters(node)
                    )
                })
                .collect();
            fail(format!(
                "{what}: no convergence in {timeout:?}; first differing paths: {}",
                report.join(" | ")
            ));
        }
        tokio::time::sleep(Duration::from_millis(1_000)).await;
    }
}

// --- Stuck state ------------------------------------------------------------------

struct Counters {
    dirty: i64,
    held: i64,
    open_writes: i64,
}

fn read_counters(node: &TopologyNode) -> Counters {
    read(node, |conn| {
        let count = |sql: &str| conn.query_row(sql, [], |row| row.get::<_, i64>(0));
        Ok(Counters {
            dirty: count("SELECT COUNT(*) FROM local_dirty_paths")?,
            held: count("SELECT COUNT(*) FROM native_delta_holds")?,
            open_writes: count("SELECT COUNT(*) FROM materialization_intents")?,
        })
    })
}

fn counters(node: &TopologyNode) -> String {
    let c = read_counters(node);
    format!("dirty {} held {} open_writes {}", c.dirty, c.held, c.open_writes)
}

async fn attention(handle: &control_socket_client::ControlSocketHandle) -> Vec<String> {
    match control_socket_client::send(handle, ReqPayload::Status(StatusRequest {})).await.payload {
        // Durability is a statement about replica count and custody evidence, which this fixture
        // (no coordination-declared full replica, no custody sweep) leaves "at risk" by
        // construction. It says nothing about whether the tree converged or is stuck.
        Some(RespPayload::Status(status)) => status
            .attention_reasons
            .into_iter()
            .filter(|reason| !reason.starts_with("durability_"))
            .collect(),
        other => fail(format!("the control socket did not answer Status: {other:?}")),
    }
}

/// Everything that must be quiet: no dirty rows, held deltas or open writes, no attention item.
async fn stuck_state(
    nodes: &[&TopologyNode],
    handles: &[control_socket_client::ControlSocketHandle],
) -> Vec<String> {
    let mut problems = Vec::new();
    for (node, handle) in nodes.iter().zip(handles) {
        let c = read_counters(node);
        if c.dirty + c.held + c.open_writes > 0 {
            problems.push(format!("{}: {}", node.device_id, counters(node)));
        }
        let reasons = attention(handle).await;
        if !reasons.is_empty() {
            problems.push(format!("{}: attention items {reasons:?}", node.device_id));
        }
    }
    problems
}

/// Status settles: no dirty rows, no held deltas, no open writes, no attention item, and the
/// native roots agree. Waits, then requires all of it, and the content oracle, to still hold
/// after an idle pause.
async fn assert_settled(nodes: &[&TopologyNode], oracle: &Oracle, timeout: Duration, what: &str) {
    // One control socket per device for the whole call; a handle's server outlives its drop.
    let mut handles = Vec::new();
    for node in nodes {
        handles.push(control_socket_client::start(node.state.clone()).await);
    }
    let started = Instant::now();
    loop {
        let problems = stuck_state(nodes, &handles).await;
        if problems.is_empty() {
            break;
        }
        if started.elapsed() > timeout {
            fail(format!("{what}: stuck state after {timeout:?}: {}", problems.join(" | ")));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    converge_state(nodes, GROUP, what).await;
    let roots: Vec<String> = nodes.iter().map(|n| native_roots(n)).collect();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let problems = stuck_state(nodes, &handles).await;
    if !problems.is_empty() {
        fail(format!("{what}: stuck state appeared while idle: {}", problems.join(" | ")));
    }
    for (node, before) in nodes.iter().zip(&roots) {
        if &native_roots(node) != before {
            fail(format!("{what}: {} was still changing while idle", node.device_id));
        }
        let actual = manifest(node.root.path());
        if &actual != oracle {
            fail(format!(
                "{what}: {} changed on disk while idle; first differing paths: {}",
                node.device_id,
                first_differences(&actual, oracle)
            ));
        }
    }
}

fn native_roots(node: &TopologyNode) -> String {
    format!(
        "{:?}",
        read(node, |conn| yadorilink_sync_sqlite::native_replication::summary_roots(
            conn,
            &yadorilink_replica_domain::ids::FolderGroupId(GROUP.to_owned())
        ))
    )
}

fn all<'a>(
    a: &'a TopologyNode,
    b: &'a TopologyNode,
    c: &'a Option<TopologyNode>,
) -> Vec<&'a TopologyNode> {
    let mut nodes = vec![a, b];
    nodes.extend(c.iter());
    nodes
}

// --- Mutations ---------------------------------------------------------------------

/// Applies the seeded mutation batches and updates `oracle`. Deletes, renames and the directory
/// move are applied on the first device; edits and creations on the second; the third (if any)
/// edits a large file. The three sets are disjoint, so the expected result is unambiguous.
fn mutate(nodes: &[&TopologyNode], plan: &Plan, oracle: &mut Oracle) {
    let (a, b) = (nodes[0], nodes[1]);
    let editor_of_large = nodes.get(2).copied().unwrap_or(b);
    let mut rng = Rng(plan.seed ^ 0xA5A5_A5A5);
    let mut candidates: Vec<String> = oracle
        .keys()
        .filter(|p| !p.starts_with("large/") && !p.starts_with("moved-tree/"))
        .cloned()
        .collect();
    for i in (1..candidates.len()).rev() {
        candidates.swap(i, rng.below(i + 1));
    }
    let k = (plan.files / 25).max(3).min(candidates.len() / 3);
    let (deletes, rest) = candidates.split_at(k);
    let (renames, rest) = rest.split_at(k);
    let modifies = &rest[..k];

    for path in deletes {
        remove(a, path);
        oracle.remove(path);
    }
    let skip_one_rename = std::env::var("LARGE_TREE_FAULT").as_deref() == Ok("skip-rename");
    for (n, path) in renames.iter().enumerate() {
        let target = format!("renamed/l{}/m{}/{}", n % 7, n % 13, path.replace('/', "_"));
        std::fs::create_dir_all(a.root.path().join(&target).parent().unwrap()).unwrap();
        if skip_one_rename && n == 0 {
            println!("LARGE_TREE_FAULT_APPLIED skipped rename {path} -> {target}");
        } else {
            rename(a, path, &target);
        }
        let hash = oracle.remove(path).unwrap();
        oracle.insert(target, hash);
    }
    // A whole directory moves, and keeps its files.
    std::fs::create_dir_all(a.root.path().join("archive")).unwrap();
    rename(a, "moved-tree", "archive/moved-tree-renamed");
    let moved: Vec<String> =
        oracle.keys().filter(|p| p.starts_with("moved-tree/")).cloned().collect();
    for path in moved {
        let hash = oracle.remove(&path).unwrap();
        oracle.insert(path.replacen("moved-tree/", "archive/moved-tree-renamed/", 1), hash);
    }

    for (n, path) in modifies.iter().enumerate() {
        let bytes = content(plan.seed, ((n as u64) << 8) | 1 | (1 << 50), 100 + (n % 900));
        put(b, oracle, path, &bytes);
    }
    for n in 0..k {
        let relative = format!("created/c{}/c{}/n{n:06}.dat", n % 5, n % 11);
        let bytes = content(plan.seed, (3u64 << 40) + n as u64, 50 + (n % 700));
        put(b, oracle, &relative, &bytes);
    }

    if plan.large_files > 0 {
        let path = "large/big0.bin";
        let mut bytes = std::fs::read(editor_of_large.root.path().join(path)).unwrap();
        bytes.extend_from_slice(&content(plan.seed, 4u64 << 40, 1 << 20));
        put(editor_of_large, oracle, path, &bytes);
    }
}

// --- Resources ---------------------------------------------------------------------

fn peak_rss_bytes() -> u64 {
    // SAFETY: `getrusage` fills the struct it is given; zeroed is a valid initial value.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    let raw = usage.ru_maxrss as u64;
    if cfg!(target_os = "macos") {
        raw
    } else {
        raw * 1024
    }
}

fn dir_bytes(dir: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            match entry.metadata() {
                Ok(m) if m.is_dir() => stack.push(entry.path()),
                Ok(m) => total += m.len(),
                Err(_) => {}
            }
        }
    }
    total
}

fn db_bytes(node: &TopologyNode) -> u64 {
    read(node, |conn| {
        let pages: i64 = conn.pragma_query_value(None, "page_count", |r| r.get(0))?;
        let size: i64 = conn.pragma_query_value(None, "page_size", |r| r.get(0))?;
        Ok((pages * size) as u64)
    })
}

fn commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned())
}

#[ignore = "large-tree convergence gate: manual / periodic, run with `cargo large-tree-gate`"]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn large_tree_converges_across_real_daemons() {
    support::ensure_isolated_config_dir();
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();

    let plan = Plan {
        files: env_num("LARGE_TREE_FILES", 1_500),
        seed: env_num("LARGE_TREE_SEED", 1),
        large_files: env_num("LARGE_TREE_LARGE_FILES", 3),
        large_bytes: env_num("LARGE_TREE_LARGE_BYTES", 6 << 20),
    };
    let devices: usize = env_num("LARGE_TREE_DEVICES", 3).clamp(2, 3);
    let converge =
        Duration::from_secs(env_num("LARGE_TREE_CONVERGE_SECS", 300 + (plan.files as u64) / 10));
    let max_wall =
        Duration::from_secs(env_num("LARGE_TREE_MAX_WALL_SECS", 600 + (plan.files as u64) / 16));
    let max_rss = env_num::<u64>("LARGE_TREE_MAX_RSS_MB", 6_144 + (plan.files as u64) / 16) << 20;
    let started = Instant::now();

    // Device A is populated before it is linked, so the first scan carries the whole tree.
    let a = new_node("ltg-a");
    let mut oracle = populate(&a, &plan);
    let generated = started.elapsed();
    link_eager(&a, GROUP);
    let b = device("ltg-b", GROUP);
    let mut c = (devices == 3).then(|| device("ltg-c", GROUP));

    pair(&a, &b, GROUP).await;
    if let Some(c) = &c {
        pair(&a, c, GROUP).await;
        pair(&b, c, GROUP).await;
    }
    let mut phases: Vec<(&str, f64)> = vec![("generate", generated.as_secs_f64())];

    let initial = await_tree(&all(&a, &b, &c), &oracle, converge, "initial tree").await;
    phases.push(("initial_sync", initial.as_secs_f64()));
    assert_settled(&all(&a, &b, &c), &oracle, converge, "after the initial sync").await;

    // An ordinary restart of the third device in the middle of the run: it comes back from its own
    // database and folder and must still agree.
    if let Some(node) = c.take() {
        let restart_started = Instant::now();
        c = Some(restart(node, &[&a, &b], GROUP).await);
        await_tree(&all(&a, &b, &c), &oracle, converge, "after restarting a device").await;
        phases.push(("restart_recovery", restart_started.elapsed().as_secs_f64()));
    }

    let mutate_started = Instant::now();
    mutate(&all(&a, &b, &c), &plan, &mut oracle);
    await_tree(&all(&a, &b, &c), &oracle, converge, "after the mutation batches").await;
    phases.push(("mutation_sync", mutate_started.elapsed().as_secs_f64()));
    assert_settled(&all(&a, &b, &c), &oracle, converge, "after the mutations").await;

    // The directory sets must agree between devices too (empty directories included).
    let dirs: Vec<BTreeSet<String>> =
        all(&a, &b, &c).iter().map(|n| walk(n.root.path()).1).collect();
    for (i, d) in dirs.iter().enumerate().skip(1) {
        if d != &dirs[0] {
            let diff: Vec<&String> = d.symmetric_difference(&dirs[0]).take(12).collect();
            fail(format!("directory sets differ between device 0 and {i}: first {diff:?}"));
        }
    }

    // Metrics and thresholds.
    let wall = started.elapsed();
    let rss = peak_rss_bytes();
    let nodes = all(&a, &b, &c);
    let report = serde_json::json!({
        "gate": "large-tree",
        "commit": commit(),
        "host": format!("{}-{} cpus={}", std::env::consts::OS, std::env::consts::ARCH,
            std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0)),
        "files": plan.files, "seed": plan.seed, "devices": devices,
        "large_files": plan.large_files, "large_bytes": plan.large_bytes,
        "final_files": oracle.len(),
        "wall_secs": wall.as_secs_f64(),
        "phases_secs": phases.iter().map(|(n, s)| serde_json::json!({ *n: s })).collect::<Vec<_>>(),
        "peak_rss_mb": rss >> 20,
        "db_bytes": nodes.iter().map(|n| db_bytes(n)).collect::<Vec<_>>(),
        "block_store_bytes": nodes.iter().map(|n| dir_bytes(n.store_root())).collect::<Vec<_>>(),
        "max_wall_secs": max_wall.as_secs(), "max_rss_mb": max_rss >> 20,
    });
    println!("LARGE_TREE_GATE_REPORT {report}");
    if let Ok(path) = std::env::var("LARGE_TREE_REPORT") {
        use std::io::Write as _;
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{report}");
        }
    }
    if wall > max_wall {
        fail(format!("wall time {wall:?} exceeds the threshold {max_wall:?}"));
    }
    if rss > max_rss {
        fail(format!("peak RSS {} MB exceeds the threshold {} MB", rss >> 20, max_rss >> 20));
    }
}
