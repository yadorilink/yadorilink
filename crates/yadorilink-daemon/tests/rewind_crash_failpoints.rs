//! Folder Rewind crashed at every journal boundary, and raced by a concurrent
//! edit, on a real two-device topology: a Full replica that is always on
//! ("the NAS") and an On-Demand laptop that previews and executes the rewind,
//! gathering the historical bytes from the NAS.
//!
//! The crash is the daemon's own failpoint convention: the rewind stops at a
//! [`RewindPoint`] (or mid-gathering) without any destructor running, so the
//! journal row stays exactly as the process left it, and the laptop is then
//! restarted from its on-disk store and index (`restart_node`, which runs the
//! startup settle of unfinished runs, decided from the row alone).
//!
//! After every crash the test checks, against an oracle the test builds from
//! the corpus itself (never from the product's index):
//! - the journal row: `failed` / `interrupted` when nothing was committed,
//!   `needs_replan` when a chunk was, `done` after the last one;
//! - no change was authored twice: the laptop authored exactly one op per
//!   path the rewind changes, over the crashed run and the fresh one;
//! - both devices hold exactly the committed chunks' effect, no more and no
//!   less, the NAS through ordinary sync;
//! - a fresh preview and execute from the current state ends at the exact
//!   target tree on both devices, and is a fixed point.

// The corpus uses POSIX modes and symlinks; there is nothing to run elsewhere.
#![cfg(unix)]

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use support::fake_coordination::FakeCoordination;
use support::topology::{
    advertise_substrate_endpoints, fully_connected, link_eager, link_on_demand, new_node,
    restart_node, shutdown_substrate, spawn_orchestrator, TopologyHandles, TopologyNode,
};
use support::{register_with_fake, wait_until_progress, wait_until_with_context};
use yadorilink_daemon::change_policy::WriterRole;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::rewind::{
    begin_rewind, execute_rewind, prepare_rewind, preview_rewind, RewindExecuteRequest, RewindHook,
    RewindPoint,
};
use yadorilink_replica_domain::rewind::{
    RewindFailureKind, RewindPathAction, RewindPlan, RewindRun, RewindRunState,
};
use yadorilink_sync_sqlite::rewind_commit::rewind_chunks;

const GROUP: &str = "rewind-crash-group";

/// One entry of a folder, as the test sees it on disk and in its oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Dir,
    File { content: String, exec: bool },
    Symlink(String),
}

type Tree = BTreeMap<String, Node>;

/// Every entry under `root`, skipping the daemon's own reserved names.
fn disk_tree(root: &Path) -> Tree {
    fn walk(root: &Path, dir: &Path, out: &mut Tree) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if yadorilink_fs_platform::reserved_namespace::is_reserved_component(&entry.file_name())
                || name == yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME
                || name == yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME
                || name.contains(".yadorilink-tmp.")
            {
                continue;
            }
            let path = entry.path();
            let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
            if meta.file_type().is_symlink() {
                let target = std::fs::read_link(&path).unwrap_or_default();
                out.insert(rel, Node::Symlink(target.to_string_lossy().into_owned()));
            } else if meta.is_dir() {
                out.insert(rel, Node::Dir);
                walk(root, &path, out);
            } else if meta.is_file() {
                let content = std::fs::read_to_string(&path).unwrap_or_default();
                let exec = meta.permissions().mode() & 0o100 != 0;
                out.insert(rel, Node::File { content, exec });
            }
        }
    }
    let mut out = Tree::new();
    walk(root, root, &mut out);
    out
}

/// What the index says one live path is: kind, size, owner-exec bit and
/// symlink target. Compared with the oracle on a device whose disk holds
/// placeholders.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Indexed {
    Dir,
    File { size: u64, exec: bool },
    Symlink(String),
}

fn indexed_view(tree: &Tree) -> BTreeMap<String, Indexed> {
    tree.iter()
        .map(|(path, node)| {
            let indexed = match node {
                Node::Dir => Indexed::Dir,
                Node::File { content, exec } => {
                    Indexed::File { size: content.len() as u64, exec: *exec }
                }
                Node::Symlink(target) => Indexed::Symlink(target.clone()),
            };
            (path.clone(), indexed)
        })
        .collect()
}

fn index_tree(state: &DaemonState) -> BTreeMap<String, Indexed> {
    let database = state.replica_coordinator.database();
    let conn = database.pool_for_test().get().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT path, record_kind, size, unix_mode, symlink_target FROM files \
             WHERE group_id = ?1 AND state = 'current' AND deleted = 0 ORDER BY path",
        )
        .unwrap();
    let rows = stmt
        .query_map([GROUP], |r| {
            let path: String = r.get(0)?;
            let kind: String = r.get(1)?;
            let size: i64 = r.get(2)?;
            let mode: i64 = r.get(3)?;
            let target: Option<Vec<u8>> = r.get(4)?;
            let indexed = match kind.as_str() {
                "directory" | "dir" => Indexed::Dir,
                "symlink" => Indexed::Symlink(
                    String::from_utf8_lossy(&target.unwrap_or_default()).into_owned(),
                ),
                _ => Indexed::File { size: size as u64, exec: mode >= 0 && mode & 0o100 != 0 },
            };
            Ok((path, indexed))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    rows
}

/// The corpus, written on the NAS's disk (captured by its real watcher) and
/// mirrored into the oracle by the same call.
struct Corpus<'a> {
    root: &'a Path,
    model: Tree,
}

impl<'a> Corpus<'a> {
    fn new(root: &'a Path) -> Self {
        Corpus { root, model: Tree::new() }
    }

    fn parents(&mut self, rel: &str) {
        let mut at = String::new();
        let parts: Vec<&str> = rel.split('/').collect();
        for part in &parts[..parts.len() - 1] {
            if !at.is_empty() {
                at.push('/');
            }
            at.push_str(part);
            self.model.insert(at.clone(), Node::Dir);
        }
        std::fs::create_dir_all(self.root.join(rel).parent().unwrap()).unwrap();
    }

    fn write(&mut self, rel: &str, content: &str, exec: bool) {
        self.parents(rel);
        let path = self.root.join(rel);
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            std::fs::remove_file(&path).unwrap();
        }
        std::fs::write(&path, content).unwrap();
        let mode = if exec { 0o755 } else { 0o644 };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        self.model.insert(rel.into(), Node::File { content: content.into(), exec });
    }

    fn symlink(&mut self, rel: &str, target: &str) {
        self.parents(rel);
        let path = self.root.join(rel);
        if std::fs::symlink_metadata(&path).is_ok() {
            std::fs::remove_file(&path).unwrap();
        }
        std::os::unix::fs::symlink(target, &path).unwrap();
        self.model.insert(rel.into(), Node::Symlink(target.into()));
    }

    /// Changes only the mode of a regular file: its bytes stay.
    fn chmod(&mut self, rel: &str, exec: bool) {
        let mode = if exec { 0o755 } else { 0o644 };
        std::fs::set_permissions(self.root.join(rel), std::fs::Permissions::from_mode(mode))
            .unwrap();
        match self.model.get_mut(rel) {
            Some(Node::File { exec: model_exec, .. }) => *model_exec = exec,
            other => panic!("{rel} is not a regular file in the corpus: {other:?}"),
        }
    }

    fn remove(&mut self, rel: &str) {
        std::fs::remove_file(self.root.join(rel)).unwrap();
        assert!(self.model.remove(rel).is_some(), "{rel} was not in the corpus");
    }

    fn remove_dir(&mut self, rel: &str) {
        std::fs::remove_dir_all(self.root.join(rel)).unwrap();
        let below = format!("{rel}/");
        self.model.retain(|path, _| path != rel && !path.starts_with(&below));
    }

    fn rename(&mut self, from: &str, to: &str) {
        self.parents(to);
        std::fs::rename(self.root.join(from), self.root.join(to)).unwrap();
        let node = self.model.remove(from).unwrap();
        self.model.insert(to.into(), node);
    }
}

/// The state at the target: 1000 entries -- nested regular files three
/// levels deep, executable scripts, plain notes and relative symlinks.
fn write_original(corpus: &mut Corpus<'_>) {
    for a in 0..10 {
        for b in 0..10 {
            for f in 0..8 {
                let rel = format!("docs/a{a}/b{b}/f{f}.txt");
                corpus.write(&rel, &format!("original {rel}"), false);
            }
        }
    }
    for i in 0..30 {
        corpus.write(&format!("bin/tool{i}.sh"), &format!("#!/bin/sh\necho tool {i}\n"), true);
    }
    for i in 0..60 {
        corpus.write(&format!("notes/n{i}.txt"), &format!("note {i} as it was"), false);
    }
    for i in 0..20 {
        corpus.symlink(&format!("links/l{i}"), &format!("../notes/n{i}.txt"));
    }
}

/// A mass edit after the target touching every kind of change: overwrite,
/// delete, rename, a whole nested directory deleted, new nested
/// directories, executable scripts overwritten, deleted and renamed (the
/// rewind brings them back executable), symlinks created, deleted and
/// moved. More than one chunk of work.
///
/// No path changes kind (file to symlink or back): on an On-Demand device
/// without a placeholder provider, as here, the projection leaves the
/// object of the old kind on disk by design, which says nothing about a
/// rewind. Some paths change only their metadata (a chmod, a symlink
/// retarget): a device that received such a change keeps the metadata of
/// the version it replaced in its history, so the rewind sees them.
fn write_mass_edit(corpus: &mut Corpus<'_>) {
    for a in 0..9 {
        for b in 0..10 {
            let dir = format!("docs/a{a}/b{b}");
            corpus.write(&format!("{dir}/f0.txt"), "ENCRYPTED 0", false);
            corpus.write(&format!("{dir}/f1.txt"), "ENCRYPTED 1", false);
            corpus.write(&format!("{dir}/f4.txt"), "ENCRYPTED 4", false);
            corpus.remove(&format!("{dir}/f2.txt"));
            corpus.rename(&format!("{dir}/f3.txt"), &format!("{dir}/f3.txt.locked"));
            corpus.rename(&format!("{dir}/f5.txt"), &format!("{dir}/f5.txt.locked"));
        }
    }
    corpus.remove_dir("docs/a9");
    for r in 0..12 {
        for x in 0..12 {
            corpus.write(&format!("ransom/r{r:02}/x{x:02}.txt"), "pay up", false);
        }
    }
    for i in 0..10 {
        corpus.write(&format!("bin/tool{i}.sh"), "#!/bin/sh\necho ENCRYPTED\n", true);
    }
    for i in 10..15 {
        corpus.remove(&format!("bin/tool{i}.sh"));
    }
    for i in 15..20 {
        corpus.rename(&format!("bin/tool{i}.sh"), &format!("bin/tool{i}.sh.locked"));
    }
    for i in 30..50 {
        corpus.write(&format!("notes/n{i}.txt"), &format!("note {i} ENCRYPTED"), false);
    }
    for i in 0..5 {
        corpus.symlink(&format!("links/new{i}"), "../notes/n59.txt");
    }
    for i in 5..10 {
        corpus.remove(&format!("links/l{i}"));
    }
    for i in 15..20 {
        corpus.symlink(&format!("links/l{i}"), "../notes/n59.txt");
    }
    for i in 20..25 {
        corpus.chmod(&format!("bin/tool{i}.sh"), false);
    }
    for i in 50..55 {
        corpus.chmod(&format!("notes/n{i}.txt"), true);
    }
    for i in 10..15 {
        corpus.rename(&format!("links/l{i}"), &format!("links/moved/l{i}"));
    }
}

/// Paths whose entry differs between two trees (added, removed or changed).
fn changed_paths(a: &Tree, b: &Tree) -> BTreeSet<String> {
    a.keys().chain(b.keys()).filter(|path| a.get(*path) != b.get(*path)).cloned().collect()
}

/// `post` with the rewind applied to exactly `paths`: each takes its value
/// at the target (or is absent if it did not exist then).
fn apply(post: &Tree, target: &Tree, paths: &BTreeSet<String>) -> Tree {
    let mut out = post.clone();
    for path in paths {
        match target.get(path) {
            Some(node) => out.insert(path.clone(), node.clone()),
            None => out.remove(path),
        };
    }
    out
}

fn diff(actual: &Tree, expected: &Tree) -> String {
    let paths = changed_paths(actual, expected);
    let shown: Vec<String> = paths
        .iter()
        .take(12)
        .map(|p| format!("{p}: actual {:?} expected {:?}", actual.get(p), expected.get(p)))
        .collect();
    format!("{} paths differ; first: {shown:#?}", paths.len())
}

fn index_differing(
    actual: &BTreeMap<String, Indexed>,
    expected: &BTreeMap<String, Indexed>,
) -> usize {
    actual
        .keys()
        .chain(expected.keys())
        .filter(|p| actual.get(*p) != expected.get(*p))
        .collect::<BTreeSet<_>>()
        .len()
}

fn index_diff(actual: &BTreeMap<String, Indexed>, expected: &BTreeMap<String, Indexed>) -> String {
    let paths: BTreeSet<&String> = actual
        .keys()
        .chain(expected.keys())
        .filter(|p| actual.get(*p) != expected.get(*p))
        .collect();
    let shown: Vec<String> = paths
        .iter()
        .take(12)
        .map(|p| format!("{p}: actual {:?} expected {:?}", actual.get(*p), expected.get(*p)))
        .collect();
    format!("{} paths differ; first: {shown:#?}", paths.len())
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
}

/// The NAS (Full, always on) and the laptop (On-Demand) sharing the group.
struct Mesh {
    fake: FakeCoordination,
    nas: TopologyNode,
    laptop: Option<TopologyNode>,
    handles: TopologyHandles,
}

impl Mesh {
    async fn start() -> Self {
        init_tracing();
        support::ensure_isolated_config_dir();
        let fake = FakeCoordination::start().await;
        fake.enable_signed_policy();
        let (nas, laptop) = (new_node("rewind-nas"), new_node("rewind-laptop"));
        for node in [&nas, &laptop] {
            register_with_fake(&fake, &node.state, &node.device_id, &[GROUP]).await;
            fake.grant_role(&node.device_id, GROUP, WriterRole::Editor);
        }
        link_eager(&nas, GROUP);
        link_on_demand(&laptop, GROUP);
        fake.set_full_replica(&nas.device_id, GROUP, true);
        let mut handles = TopologyHandles::new();
        handles.insert(nas.device_id.clone(), spawn_orchestrator(fake.addr(), &nas));
        handles.insert(laptop.device_id.clone(), spawn_orchestrator(fake.addr(), &laptop));
        let mesh = Mesh { fake, nas, laptop: Some(laptop), handles };
        mesh.connect().await;
        mesh
    }

    fn laptop(&self) -> &TopologyNode {
        self.laptop.as_ref().unwrap()
    }

    async fn connect(&self) {
        advertise_substrate_endpoints(&[&self.nas, self.laptop()]).await;
        let (nas, laptop) = (&self.nas, self.laptop());
        wait_until_with_context(
            || {
                fully_connected(&nas.state, &laptop.device_id)
                    && fully_connected(&laptop.state, &nas.device_id)
            },
            Duration::from_secs(60),
            || "the NAS and the laptop never connected".to_string(),
        )
        .await;
    }

    /// The laptop's process is gone (its run was stopped without any
    /// destructor); it starts again from its on-disk store and index.
    async fn restart_laptop(&mut self) {
        let laptop = self.laptop.take().unwrap();
        shutdown_substrate(&laptop).await;
        self.handles.take_and_shutdown(&laptop.device_id).await;
        let laptop = restart_node(laptop).await;
        register_with_fake(&self.fake, &laptop.state, &laptop.device_id, &[GROUP]).await;
        self.handles
            .insert(laptop.device_id.clone(), spawn_orchestrator(self.fake.addr(), &laptop));
        self.laptop = Some(laptop);
        self.connect().await;
    }

    /// The laptop leaves the mesh: its substrate and orchestrator are gone,
    /// and the NAS has no peer for the group.
    async fn take_laptop_offline(&mut self) {
        let laptop = self.laptop.as_ref().unwrap();
        shutdown_substrate(laptop).await;
        let id = laptop.device_id.clone();
        self.handles.take_and_shutdown(&id).await;
        let nas = self.nas.state.clone();
        wait_until_with_context(
            || !fully_connected(&nas, &id),
            Duration::from_secs(60),
            || "the NAS still has a session with the laptop".to_string(),
        )
        .await;
    }

    /// The laptop, taken offline before, starts again and rejoins.
    async fn bring_laptop_back(&mut self) {
        let laptop = restart_node(self.laptop.take().unwrap()).await;
        register_with_fake(&self.fake, &laptop.state, &laptop.device_id, &[GROUP]).await;
        self.handles
            .insert(laptop.device_id.clone(), spawn_orchestrator(self.fake.addr(), &laptop));
        self.laptop = Some(laptop);
        self.connect().await;
    }
}

/// How long a wait may go without getting closer before it is a stall, and the total it may take
/// while it does: `timeout` is the first, a convergence that keeps progressing is not cut off by
/// it (a busy machine makes the same convergence several times slower).
const PROGRESS_CAP_FACTOR: u32 = 6;

async fn wait_disk(node: &TopologyNode, expected: &Tree, what: &str, timeout: Duration) {
    let root = node.root.path().to_path_buf();
    wait_until_progress(
        || changed_paths(&disk_tree(&root), expected).len(),
        timeout,
        timeout * PROGRESS_CAP_FACTOR,
        || format!("{}: {what}: {}", node.device_id, diff(&disk_tree(&root), expected)),
    )
    .await;
}

async fn wait_index(node: &TopologyNode, expected: &Tree, what: &str, timeout: Duration) {
    let expected = indexed_view(expected);
    wait_until_progress(
        || index_differing(&index_tree(&node.state), &expected),
        timeout,
        timeout * PROGRESS_CAP_FACTOR,
        || {
            format!(
                "{}: {what}: {}",
                node.device_id,
                index_diff(&index_tree(&node.state), &expected)
            )
        },
    )
    .await;
}

/// What the laptop shows: the index always, and on disk every entry that is
/// there must be the oracle's (an On-Demand device may leave a file as a
/// placeholder whose bytes are not local).
async fn wait_laptop(mesh: &Mesh, expected: &Tree, what: &str, timeout: Duration) {
    let laptop = mesh.laptop();
    wait_index(laptop, expected, what, timeout).await;
    // Content identity, not only size: once the NAS's disk is the oracle,
    // every live path's version on the laptop is the NAS's.
    if disk_tree(mesh.nas.root.path()) == *expected {
        wait_until_with_context(
            || version_hashes(&laptop.state) == version_hashes(&mesh.nas.state),
            timeout,
            || format!("{what}: the laptop's versions are not the NAS's"),
        )
        .await;
    }
    let root = laptop.root.path().to_path_buf();
    wait_until_with_context(
        || laptop_disk_agrees(&disk_tree(&root), expected).is_ok(),
        timeout,
        || format!("{what}: {}", laptop_disk_agrees(&disk_tree(&root), expected).unwrap_err()),
    )
    .await;
    let files = |tree: &Tree| tree.values().filter(|n| matches!(n, Node::File { .. })).count();
    eprintln!(
        "{what}: the laptop agrees ({} of {} regular files hydrated on disk)",
        files(&disk_tree(&root)),
        files(expected)
    );
}

/// Every live path's current version hash.
fn version_hashes(
    state: &DaemonState,
) -> BTreeMap<String, yadorilink_replica_domain::ids::VersionHash> {
    let index = state.replica_coordinator.file_index_repository();
    current_rows(state)
        .into_iter()
        .filter(|(_, (_, deleted, _, _))| !deleted)
        .map(|(path, (seq, ..))| {
            let hash = index.get_version(GROUP, &path, seq).unwrap().unwrap().version_hash;
            (path, hash)
        })
        .collect()
}

/// Every directory and symlink of the oracle is on the laptop's disk and
/// nothing is there the oracle lacks; a regular file's bytes, when present,
/// are the oracle's. An On-Demand folder's files belong to the platform
/// placeholder provider, which these tests have none of: a file the laptop
/// has not hydrated is left off the disk, so the index is what is checked
/// for those.
fn laptop_disk_agrees(disk: &Tree, expected: &Tree) -> Result<(), String> {
    let mut bad = Vec::new();
    for path in disk.keys().chain(expected.keys()).collect::<BTreeSet<_>>() {
        let ok = match (disk.get(path), expected.get(path)) {
            (None, Some(Node::File { .. })) => true,
            (Some(Node::File { content, exec }), Some(Node::File { content: want, exec: x })) => {
                exec == x && content == want
            }
            (Some(a), Some(b)) => a == b,
            _ => false,
        };
        if !ok {
            bad.push(format!(
                "{path}: disk {:?} expected {:?}",
                disk.get(path),
                expected.get(path)
            ));
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} laptop entries disagree; first: {:#?}",
            bad.len(),
            &bad[..bad.len().min(12)]
        ))
    }
}

/// How many ops `device` authored, per path.
fn ops_by(state: &DaemonState, device: &str) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for delta in support::native_deltas(state, GROUP) {
        if delta.author.device.as_str() != device {
            continue;
        }
        for op in &delta.ops {
            *out.entry(op.path.as_str().to_string()).or_insert(0) += 1;
        }
    }
    out
}

fn latest_run(node: &TopologyNode) -> RewindRun {
    node.state.replica_coordinator.rewind_run_repository().latest_run(GROUP).unwrap().unwrap()
}

/// A target strictly between what was admitted before and what comes after.
async fn target_now() -> i64 {
    tokio::time::sleep(Duration::from_millis(50)).await;
    let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        as i64;
    tokio::time::sleep(Duration::from_millis(50)).await;
    at
}

fn actionable(plan_counts: &yadorilink_replica_domain::rewind::RewindActionCounts) -> u64 {
    plan_counts.create + plan_counts.replace + plan_counts.delete
}

/// Previews on `node` at `target` until the plan acts on exactly `expected`
/// paths with nothing unavailable, and returns the request approving it.
/// The prepared plan is checked again by its paths ([`plan_paths`]).
async fn approve(
    node: &TopologyNode,
    target: i64,
    expected: &BTreeSet<String>,
) -> RewindExecuteRequest {
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        let preview =
            preview_rewind(node.state.clone(), GROUP.into(), target, false).await.unwrap();
        let listed: BTreeSet<String> = preview
            .entries
            .iter()
            .filter(|e| e.action != RewindPathAction::Unchanged)
            .map(|e| e.path.clone())
            .collect();
        if actionable(&preview.counts) == expected.len() as u64
            && preview.counts.unavailable == 0
            // A listing cut at its frame budget is checked by count here;
            // the caller checks the prepared plan's paths.
            && (preview.listing_truncated || listed == *expected)
        {
            return RewindExecuteRequest {
                group_id: GROUP.into(),
                target_unix_nanos: target,
                plan_id: preview.plan_id,
            };
        }
        if Instant::now() > deadline {
            let missing: Vec<_> = expected.difference(&listed).take(20).collect();
            let extra: Vec<_> = listed.difference(expected).take(20).collect();
            panic!(
                "{}: the plan never settled on the {} expected paths: {:?}; not in the plan: \
                 {missing:?}; not expected: {extra:?}",
                node.device_id,
                expected.len(),
                preview.counts
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn plan_paths(plan: &RewindPlan) -> BTreeSet<String> {
    plan.entries
        .iter()
        .filter(|e| {
            matches!(
                e.action,
                RewindPathAction::Create { .. }
                    | RewindPathAction::Replace { .. }
                    | RewindPathAction::Delete
            )
        })
        .map(|e| e.path.clone())
        .collect()
}

/// The scenario up to an approved rewind: the corpus at the target, the
/// mass edit after it, both devices settled on it.
struct Setup {
    target: i64,
    original: Tree,
    post: Tree,
    changed: BTreeSet<String>,
}

async fn set_up(mesh: &Mesh) -> Setup {
    let started = Instant::now();
    let mut corpus = Corpus::new(mesh.nas.root.path());
    write_original(&mut corpus);
    let original = corpus.model.clone();
    wait_index(&mesh.nas, &original, "the NAS never indexed the corpus", Duration::from_secs(300))
        .await;
    wait_index(
        mesh.laptop(),
        &original,
        "the laptop never got the corpus",
        Duration::from_secs(300),
    )
    .await;
    let target = target_now().await;
    write_mass_edit(&mut corpus);
    let post = corpus.model.clone();
    wait_index(&mesh.nas, &post, "the NAS never indexed the mass edit", Duration::from_secs(300))
        .await;
    wait_laptop(mesh, &post, "the laptop never got the mass edit", Duration::from_secs(300)).await;
    let changed = changed_paths(&original, &post);
    eprintln!(
        "corpus: {} entries at the target, {} after the mass edit, {} changed; set up in {:?}",
        original.len(),
        post.len(),
        changed.len(),
        started.elapsed()
    );
    Setup { target, original, post, changed }
}

/// Everything after the crash and the restart: the journal row, nothing
/// authored twice, both devices at exactly the committed effect, then a
/// fresh preview and execute to the exact target, a fixed point.
async fn after_restart(
    mesh: &Mesh,
    setup: &Setup,
    committed: &BTreeSet<String>,
    expect_state: RewindRunState,
    ops_at_crash: &BTreeMap<String, usize>,
) {
    let laptop = mesh.laptop();
    let laptop_id = laptop.device_id.clone();
    let run = latest_run(laptop);
    assert_eq!(run.state, expect_state, "the journal after restart: {run:?}");
    match expect_state {
        RewindRunState::Failed => {
            assert_eq!(run.failure_kind, Some(RewindFailureKind::Interrupted), "{run:?}");
            assert_eq!(run.chunks_done, 0);
        }
        RewindRunState::NeedsReplan => {
            assert!(run.chunks_done > 0);
            assert_eq!(run.failure_kind, None);
            assert_eq!(
                run.message(),
                "Rewind was interrupted. Review the current state and preview again."
            );
        }
        RewindRunState::Done => assert_eq!(run.chunks_done, run.chunks_total),
        other => panic!("not an ending state: {other:?}"),
    }

    // Exactly the committed chunks' effect, on both devices; the NAS gets it
    // through ordinary sync.
    let at_commit = apply(&setup.post, &setup.original, committed);
    wait_disk(&mesh.nas, &at_commit, "NAS after the restart", Duration::from_secs(300)).await;
    wait_laptop(mesh, &at_commit, "laptop after the restart", Duration::from_secs(300)).await;
    // ...and it stays there: nothing resumes the run on its own.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(disk_tree(mesh.nas.root.path()), at_commit, "the NAS moved past the commit");
    assert_eq!(&ops_by(&laptop.state, &laptop_id), ops_at_crash, "the restart authored something");
    assert_eq!(latest_run(laptop).run_id, run.run_id, "no run started on its own");

    // A fresh preview from the current state: what is left, no more.
    let rest: BTreeSet<String> = setup.changed.difference(committed).cloned().collect();
    let request = approve(laptop, setup.target, &rest).await;
    let started = Instant::now();
    let prepared = prepare_rewind(laptop.state.clone(), request).await.unwrap();
    assert_eq!(plan_paths(prepared.plan()), rest, "the fresh plan is exactly what is left");
    assert_eq!(
        execute_rewind(laptop.state.clone(), prepared, None).await,
        Some(RewindRunState::Done)
    );
    wait_disk(&mesh.nas, &setup.original, "NAS after the fresh rewind", Duration::from_secs(300))
        .await;
    wait_laptop(mesh, &setup.original, "laptop after the fresh rewind", Duration::from_secs(300))
        .await;
    eprintln!("fresh rewind of {} paths converged in {:?}", rest.len(), started.elapsed());

    // Nothing authored twice: one op per changed path over both runs.
    let ops = ops_by(&laptop.state, &laptop_id);
    let twice: Vec<_> = ops.iter().filter(|(_, n)| **n != 1).collect();
    assert!(twice.is_empty(), "paths the laptop authored other than once: {twice:?}");
    assert_eq!(ops.keys().cloned().collect::<BTreeSet<_>>(), setup.changed);
    approve(laptop, setup.target, &BTreeSet::new()).await;
}

/// The paths of chunks `0..n` of `plan`.
fn first_chunks(plan: &RewindPlan, n: usize) -> BTreeSet<String> {
    rewind_chunks(plan).into_iter().take(n).flatten().map(|e| e.path).collect()
}

/// Runs a prepared rewind on the laptop with a hook that crashes at
/// `crash_at`, after `at_crash` (run in the hook, on the executing thread).
async fn crash_execute(
    mesh: &Mesh,
    setup: &Setup,
    crash_at: RewindPoint,
    at_crash: impl Fn() + Send + Sync + 'static,
) -> (RewindPlan, BTreeMap<String, usize>) {
    let laptop = mesh.laptop();
    let request = approve(laptop, setup.target, &setup.changed).await;
    let prepared = prepare_rewind(laptop.state.clone(), request).await.unwrap();
    let plan = prepared.plan().clone();
    assert_eq!(plan_paths(&plan), setup.changed, "the plan is the oracle's change set");
    assert_eq!(rewind_chunks(&plan).len(), 2, "the corpus makes two chunks");
    let hook: RewindHook = Arc::new(move |point| {
        if point == crash_at {
            at_crash();
            false
        } else {
            true
        }
    });
    assert_eq!(execute_rewind(laptop.state.clone(), prepared, Some(hook)).await, None);
    let ops = ops_by(&laptop.state, &laptop.device_id);
    (plan, ops)
}

/// Before the gathering of historical bytes completes: nothing was
/// changed; the run ends failed / interrupted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_before_prefetch_completes() {
    let mut mesh = Mesh::start().await;
    let setup = set_up(&mesh).await;
    let laptop = mesh.laptop();
    let request = approve(laptop, setup.target, &setup.changed).await;
    let begun = begin_rewind(laptop.state.clone(), request).await.unwrap();
    assert_eq!(latest_run(laptop).state, RewindRunState::Planned);
    // The gathering runs on a runtime of its own, standing for the process:
    // it is polled until it is under way, then the runtime is torn down
    // with the gathering itself never dropped (no destructor runs, as in a
    // crash) and every task it started cancelled.
    let process =
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let (polled, was_pending) = tokio::sync::oneshot::channel();
    process.spawn(async move {
        let mut gathering = std::mem::ManuallyDrop::new(Box::pin(begun.prefetch()));
        let pending =
            tokio::time::timeout(Duration::from_millis(5), gathering.as_mut()).await.is_err();
        let _ = polled.send(pending);
        std::future::pending::<()>().await;
    });
    assert!(was_pending.await.unwrap(), "the gathering finished before the crash point");
    tokio::task::spawn_blocking(move || process.shutdown_timeout(Duration::from_secs(10)))
        .await
        .unwrap();
    assert_eq!(latest_run(laptop).state, RewindRunState::Planned);
    let ops = ops_by(&laptop.state, &laptop.device_id);
    assert!(ops.is_empty(), "nothing authored before the first chunk");

    mesh.restart_laptop().await;
    after_restart(&mesh, &setup, &BTreeSet::new(), RewindRunState::Failed, &ops).await;
    mesh.handles.shutdown();
}

/// Every byte gathered, before the first chunk: nothing was changed; the
/// run ends failed / interrupted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_prefetch_before_first_commit() {
    let mut mesh = Mesh::start().await;
    let setup = set_up(&mesh).await;
    let laptop_state = mesh.laptop().state.clone();
    let (_, ops) = crash_execute(&mesh, &setup, RewindPoint::BeforeChunk(0), move || {
        let run = laptop_state
            .replica_coordinator
            .rewind_run_repository()
            .latest_run(GROUP)
            .unwrap()
            .unwrap();
        assert_eq!(run.state, RewindRunState::Prefetched);
    })
    .await;
    assert!(ops.is_empty(), "nothing authored before the first chunk");

    mesh.restart_laptop().await;
    after_restart(&mesh, &setup, &BTreeSet::new(), RewindRunState::Failed, &ops).await;
    mesh.handles.shutdown();
}

/// The process dies inside the first chunk's transaction, after its changes
/// are authored and before the journal row advances: the chunk is entirely
/// absent (no signed op, nothing on either disk or index, no journal
/// progress), and a fresh preview and execute reaches the target.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_inside_the_chunk_transaction() {
    let mut mesh = Mesh::start().await;
    let setup = set_up(&mesh).await;
    let laptop = mesh.laptop();
    let request = approve(laptop, setup.target, &setup.changed).await;
    let prepared = prepare_rewind(laptop.state.clone(), request).await.unwrap();
    yadorilink_sync_sqlite::rewind_commit::abort_chunk_in_tx_for_test(
        &latest_run(laptop).run_id,
        0,
    );
    assert_eq!(
        execute_rewind(laptop.state.clone(), prepared, None).await,
        Some(RewindRunState::Failed)
    );
    let ops = ops_by(&laptop.state, &laptop.device_id);
    assert!(ops.is_empty(), "the aborted chunk left {} signed changes", ops.len());
    let run = latest_run(laptop);
    assert_eq!((run.chunks_done, run.restored, run.deleted), (0, 0, 0), "{run:?}");

    mesh.restart_laptop().await;
    after_restart(&mesh, &setup, &BTreeSet::new(), RewindRunState::Failed, &ops).await;
    mesh.handles.shutdown();
}

/// The first chunk's signed changes and journal advance committed, and the
/// process dies before anything announced them: neither publication nor
/// the projection was woken. The restart publishes and projects them as
/// ordinary changes; the run needs a new preview.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_signed_change_before_materialization() {
    let mut mesh = Mesh::start().await;
    let setup = set_up(&mesh).await;
    let nas_root = mesh.nas.root.path().to_path_buf();
    let post = setup.post.clone();
    let nas_untouched = Arc::new(Mutex::new(None));
    let seen = nas_untouched.clone();
    let (plan, ops) = crash_execute(&mesh, &setup, RewindPoint::AfterChunk(0), move || {
        *seen.lock().unwrap() = Some(disk_tree(&nas_root) == post);
    })
    .await;
    let committed = first_chunks(&plan, 1);
    assert_eq!(ops.keys().cloned().collect::<BTreeSet<_>>(), committed);
    assert_eq!(
        *nas_untouched.lock().unwrap(),
        Some(true),
        "the NAS had nothing of the chunk at the crash point"
    );
    let run = latest_run(mesh.laptop());
    assert_eq!((run.state, run.chunks_done), (RewindRunState::Committing, 1));
    // Not announced: while the old process lingers, the NAS receives none of
    // the chunk's signed changes (only a published change is ever sent).
    tokio::time::sleep(Duration::from_secs(3)).await;
    let laptop_id = mesh.laptop().device_id.clone();
    assert!(
        ops_by(&mesh.nas.state, &laptop_id).is_empty(),
        "the chunk reached the NAS before its commit was announced"
    );

    mesh.restart_laptop().await;
    after_restart(&mesh, &setup, &committed, RewindRunState::NeedsReplan, &ops).await;
    mesh.handles.shutdown();
}

/// The first chunk is on both disks (materialized here, synced there), and
/// the process dies before the next chunk's journal advance.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_materialization_before_journal_advance() {
    let mut mesh = Mesh::start().await;
    let setup = set_up(&mesh).await;
    let laptop = mesh.laptop();
    let request = approve(laptop, setup.target, &setup.changed).await;
    let prepared = prepare_rewind(laptop.state.clone(), request).await.unwrap();
    let plan = prepared.plan().clone();
    let committed = first_chunks(&plan, 1);
    let at_commit = apply(&setup.post, &setup.original, &committed);
    let nas_root = mesh.nas.root.path().to_path_buf();
    let laptop_state = laptop.state.clone();
    let expected_index = indexed_view(&at_commit);
    let hook: RewindHook = Arc::new(move |point| {
        if point != RewindPoint::BeforeChunk(1) {
            return true;
        }
        support::wait_until_progress_blocking(
            || {
                changed_paths(&disk_tree(&nas_root), &at_commit).len()
                    + index_differing(&index_tree(&laptop_state), &expected_index)
            },
            Duration::from_secs(300),
            Duration::from_secs(1800),
            || {
                format!(
                    "the first chunk never materialized: {}; {}",
                    diff(&disk_tree(&nas_root), &at_commit),
                    index_diff(&index_tree(&laptop_state), &expected_index)
                )
            },
        );
        false
    });
    assert_eq!(execute_rewind(laptop.state.clone(), prepared, Some(hook)).await, None);
    let ops = ops_by(&laptop.state, &laptop.device_id);
    assert_eq!(ops.keys().cloned().collect::<BTreeSet<_>>(), committed);
    assert_eq!(latest_run(laptop).chunks_done, 1);

    mesh.restart_laptop().await;
    after_restart(&mesh, &setup, &committed, RewindRunState::NeedsReplan, &ops).await;
    mesh.handles.shutdown();
}

/// Between chunks, the first one announced and its materialization in
/// flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_between_chunks() {
    let mut mesh = Mesh::start().await;
    let setup = set_up(&mesh).await;
    let (plan, ops) = crash_execute(&mesh, &setup, RewindPoint::BeforeChunk(1), || {}).await;
    let committed = first_chunks(&plan, 1);
    assert_eq!(ops.keys().cloned().collect::<BTreeSet<_>>(), committed);

    mesh.restart_laptop().await;
    after_restart(&mesh, &setup, &committed, RewindRunState::NeedsReplan, &ops).await;
    mesh.handles.shutdown();
}

/// After the final chunk committed (the row is `done` in the same
/// transaction), before anything announced it or the run's own wrap-up ran.
/// The restart leaves the row `done`, publishes and projects the changes,
/// and a fresh preview finds nothing left.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crash_after_final_chunk_before_wrap_up() {
    let mut mesh = Mesh::start().await;
    let setup = set_up(&mesh).await;
    let (plan, ops) = crash_execute(&mesh, &setup, RewindPoint::AfterChunk(1), || {}).await;
    let committed = first_chunks(&plan, 2);
    assert_eq!(committed, setup.changed);
    assert_eq!(ops.keys().cloned().collect::<BTreeSet<_>>(), committed);
    assert_eq!(latest_run(mesh.laptop()).state, RewindRunState::Done);

    mesh.restart_laptop().await;
    after_restart(&mesh, &setup, &committed, RewindRunState::Done, &ops).await;
    mesh.handles.shutdown();
}

/// While the laptop executes, a person on the NAS edits a path the first
/// (already committed, not yet announced) chunk restored, and a path the
/// second chunk would remove. The second chunk stops on the changed path
/// (the run needs a new preview); the rewind never wins: the second edit is
/// kept as it is, and the first is concurrent with the rewind's own change
/// and follows ordinary conflict semantics -- both devices converge on the
/// same tree and the edit's bytes are not lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_concurrent_edit_on_the_other_device_stops_the_chunk_and_is_kept() {
    let mesh = Mesh::start().await;
    let setup = set_up(&mesh).await;
    let laptop = mesh.laptop();
    let request = approve(laptop, setup.target, &setup.changed).await;
    let prepared = prepare_rewind(laptop.state.clone(), request).await.unwrap();
    let chunks = rewind_chunks(prepared.plan());
    assert_eq!(chunks.len(), 2);
    let restored = chunks[0]
        .iter()
        .find(|e| matches!(e.action, RewindPathAction::Replace { .. }) && e.path.ends_with(".txt"))
        .unwrap()
        .path
        .clone();
    let removed = chunks[1]
        .iter()
        .find(|e| e.action == RewindPathAction::Delete && e.path.ends_with(".locked"))
        .unwrap()
        .path
        .clone();
    eprintln!("concurrent edits: {restored} (restored by chunk 0), {removed} (removed by chunk 1)");

    let nas_root = mesh.nas.root.path().to_path_buf();
    let nas_id = mesh.nas.device_id.clone();
    let laptop_state = laptop.state.clone();
    let (r1, r2) = (restored.clone(), removed.clone());
    let hook: RewindHook = Arc::new(move |point| {
        if point != RewindPoint::AfterChunk(0) {
            return true;
        }
        let seq_before = |path: &str| nas_head_seq(&laptop_state, &nas_id, path);
        let (b1, b2) = (seq_before(&r1), seq_before(&r2));
        std::fs::write(nas_root.join(&r1), "the NAS edited this during the rewind").unwrap();
        std::fs::write(nas_root.join(&r2), "the NAS kept this during the rewind").unwrap();
        support::wait_until_progress_blocking(
            || {
                usize::from(nas_head_seq(&laptop_state, &nas_id, &r1) <= b1)
                    + usize::from(nas_head_seq(&laptop_state, &nas_id, &r2) <= b2)
            },
            Duration::from_secs(300),
            Duration::from_secs(900),
            || {
                format!(
                    "the laptop never admitted the NAS's edits (seq now {} and {}, before {b1} and {b2})",
                    nas_head_seq(&laptop_state, &nas_id, &r1),
                    nas_head_seq(&laptop_state, &nas_id, &r2)
                )
            },
        );
        true
    });
    let ended = execute_rewind(laptop.state.clone(), prepared, Some(hook)).await;
    assert_eq!(ended, Some(RewindRunState::NeedsReplan));
    let run = latest_run(laptop);
    assert_eq!((run.chunks_done, run.failure_kind), (1, None));
    let ops = ops_by(&laptop.state, &laptop.device_id);
    assert!(!ops.contains_key(&removed), "the stopped chunk authored nothing");

    // Both devices settle on the same tree.
    support::wait_until_progress(
        || {
            let (nas, lap) = (disk_tree(mesh.nas.root.path()), index_tree(&laptop.state));
            index_differing(&lap, &indexed_view(&nas))
                + usize::from(laptop_disk_agrees(&disk_tree(laptop.root.path()), &nas).is_err())
        },
        Duration::from_secs(300),
        Duration::from_secs(1800),
        || {
            let (nas, lap) = (disk_tree(mesh.nas.root.path()), index_tree(&laptop.state));
            format!("the devices never converged: {}", index_diff(&lap, &indexed_view(&nas)))
        },
    )
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let nas = disk_tree(mesh.nas.root.path());
    assert_eq!(
        nas.get(&removed),
        Some(&Node::File { content: "the NAS kept this during the rewind".into(), exec: false }),
        "the rewind never wins over a concurrent edit"
    );
    let kept: Vec<&String> = nas
        .iter()
        .filter(|(_, node)| {
            matches!(node, Node::File { content, .. } if content == "the NAS edited this during the rewind")
        })
        .map(|(path, _)| path)
        .collect();
    assert!(
        !kept.is_empty(),
        "the concurrent edit to {restored} was lost: {:?}",
        nas.get(&restored)
    );
    eprintln!(
        "{restored} after the race: {:?}; the edit's bytes are at {kept:?}",
        nas.get(&restored)
    );
    mesh.handles.shutdown();
}

/// The highest seq of a live head `author` holds at `path` on `state`.
fn nas_head_seq(state: &DaemonState, author: &str, path: &str) -> i64 {
    let database = state.replica_coordinator.database();
    let conn = database.pool_for_test().get().unwrap();
    conn.query_row(
        "SELECT coalesce(max(seq), 0) FROM native_heads \
         WHERE group_id = ?1 AND path = ?2 AND author = ?3",
        [GROUP, path, author],
        |r| r.get(0),
    )
    .unwrap()
}

/// How long a 10 000-file mass-edit rewind takes on the NAS, with the
/// laptop online and with no peer at all. Timing only; run by hand:
/// `YL_REWIND_10K=1 cargo test ... --test rewind_crash_failpoints rewind_10k -- --ignored --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "timing run; minutes long"]
async fn rewind_10k_mass_edit_timing() {
    for peer_online in [true, false] {
        let mut mesh = Mesh::start().await;
        let started = Instant::now();
        let mut corpus = Corpus::new(mesh.nas.root.path());
        for i in 0..10_000 {
            corpus.write(
                &format!("big/d{:03}/f{i:05}.txt", i / 100),
                &format!("original {i}"),
                false,
            );
        }
        let original = corpus.model.clone();
        wait_index(&mesh.nas, &original, "the NAS never indexed 10k", Duration::from_secs(1800))
            .await;
        wait_index(mesh.laptop(), &original, "the laptop never got 10k", Duration::from_secs(1800))
            .await;
        let indexed = started.elapsed();
        let target = target_now().await;
        for i in 0..10_000 {
            corpus.write(
                &format!("big/d{:03}/f{i:05}.txt", i / 100),
                &format!("ENCRYPTED {i}"),
                false,
            );
        }
        let post = corpus.model.clone();
        wait_index(
            &mesh.nas,
            &post,
            "the NAS never indexed the 10k edit",
            Duration::from_secs(1800),
        )
        .await;
        wait_index(
            mesh.laptop(),
            &post,
            "the laptop never got the 10k edit",
            Duration::from_secs(1800),
        )
        .await;
        if !peer_online {
            mesh.take_laptop_offline().await;
        }

        let t0 = Instant::now();
        let changed = changed_paths(&original, &post);
        assert_eq!(changed.len(), 10_000);
        let request = approve(&mesh.nas, target, &changed).await;
        let previewed = t0.elapsed();
        let prepared = prepare_rewind(mesh.nas.state.clone(), request).await.unwrap();
        assert_eq!(plan_paths(prepared.plan()), changed);
        let prepared_at = t0.elapsed();
        let chunks = latest_run(&mesh.nas).chunks_total;
        assert_eq!(
            execute_rewind(mesh.nas.state.clone(), prepared, None).await,
            Some(RewindRunState::Done)
        );
        let committed_at = t0.elapsed();
        wait_disk(
            &mesh.nas,
            &original,
            "the NAS never materialized 10k",
            Duration::from_secs(3600),
        )
        .await;
        let materialized_at = t0.elapsed();
        let peer_at = if peer_online {
            wait_index(
                mesh.laptop(),
                &original,
                "the laptop never converged",
                Duration::from_secs(3600),
            )
            .await;
            Some(t0.elapsed())
        } else {
            None
        };
        eprintln!(
            "REWIND-10K peer_online={peer_online}: set-up {indexed:?}; preview {previewed:?}; \
             prepared {prepared_at:?}; {chunks} chunks committed {committed_at:?}; NAS disk \
             {materialized_at:?} ({:.1} paths/s after commit); laptop index {peer_at:?}",
            10_000.0 / (materialized_at - committed_at).as_secs_f64()
        );
        mesh.handles.shutdown();
    }
}

/// Each path's current row: (seq, deleted, admitted at, whether it names a
/// native head).
fn current_rows(state: &DaemonState) -> BTreeMap<String, (i64, bool, i64, bool)> {
    let database = state.replica_coordinator.database();
    let conn = database.pool_for_test().get().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT path, version_seq, deleted, coalesce(admitted_at_unix_nanos, 0), \
                    native_authoring_identity IS NOT NULL \
             FROM files WHERE group_id = ?1 AND state = 'current'",
        )
        .unwrap();
    let rows = stmt
        .query_map([GROUP], |r| {
            Ok((r.get::<_, String>(0)?, (r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    rows
}

/// A rewind executed with no peer online -- on the NAS, which holds every
/// historical byte, while the laptop is away -- goes through the ordinary
/// path: each changed path gets exactly one signed op of the NAS's, its new
/// current row is a version row naming a native head and is exactly the
/// historical version (or a tombstone), and the projection, not the rewind,
/// writes the disk and publishes its proof. When the laptop comes back,
/// ordinary sync brings it to the same tree, and nothing is left to do on
/// either device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rewind_with_no_peer_online_uses_the_ordinary_path_and_the_peer_converges_later() {
    let mut mesh = Mesh::start().await;
    let setup = set_up(&mesh).await;
    mesh.take_laptop_offline().await;
    let nas_id = mesh.nas.device_id.clone();
    let ops_before = ops_by(&mesh.nas.state, &nas_id);
    let rows_before = current_rows(&mesh.nas.state);
    let started_at =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
            as i64;

    let request = approve(&mesh.nas, setup.target, &setup.changed).await;
    let started = Instant::now();
    let prepared = prepare_rewind(mesh.nas.state.clone(), request).await.unwrap();
    let plan = prepared.plan().clone();
    assert_eq!(plan_paths(&plan), setup.changed);
    // Right after the first chunk's commit, before it is announced: the
    // rewind itself has written nothing to the disk.
    let nas_root = mesh.nas.root.path().to_path_buf();
    let post = setup.post.clone();
    let disk_at_commit = Arc::new(Mutex::new(None));
    let seen = disk_at_commit.clone();
    let rows_at_commit = Arc::new(Mutex::new(None));
    let rows_seen = rows_at_commit.clone();
    let nas_state = mesh.nas.state.clone();
    let hook: RewindHook = Arc::new(move |point| {
        if point == RewindPoint::AfterChunk(0) {
            *seen.lock().unwrap() = Some(changed_paths(&disk_tree(&nas_root), &post).len());
            *rows_seen.lock().unwrap() = Some(current_rows(&nas_state));
        }
        true
    });
    assert_eq!(
        execute_rewind(mesh.nas.state.clone(), prepared, Some(hook)).await,
        Some(RewindRunState::Done)
    );
    assert_eq!(
        *disk_at_commit.lock().unwrap(),
        Some(0),
        "the commit wrote the disk itself instead of leaving it to the projection"
    );
    assert_eq!(
        rows_at_commit.lock().unwrap().as_ref(),
        Some(&rows_before),
        "the commit wrote index rows itself instead of leaving them to the projection"
    );
    let committed = started.elapsed();
    wait_disk(&mesh.nas, &setup.original, "NAS after the offline rewind", Duration::from_secs(600))
        .await;
    eprintln!(
        "offline rewind of {} paths: committed in {committed:?}, on the NAS disk in {:?}",
        setup.changed.len(),
        started.elapsed()
    );

    // One signed op per changed path, none elsewhere.
    let ops_after = ops_by(&mesh.nas.state, &nas_id);
    let authored: BTreeMap<&String, usize> = ops_after
        .iter()
        .map(|(path, n)| (path, n - ops_before.get(path).copied().unwrap_or(0)))
        .filter(|(_, n)| *n > 0)
        .collect();
    assert!(authored.values().all(|n| *n == 1), "authored more than once: {authored:?}");
    assert_eq!(authored.keys().map(|p| (*p).clone()).collect::<BTreeSet<_>>(), setup.changed);

    // Each changed path's current row is a new, native-authored version row:
    // the historical version itself, or a tombstone; the projection's proof
    // names it.
    let rows_after = current_rows(&mesh.nas.state);
    let index = mesh.nas.state.replica_coordinator.file_index_repository();
    let sqlite = mesh.nas.state.replica_coordinator.sqlite();
    for entry in &plan.entries {
        if !setup.changed.contains(&entry.path) {
            continue;
        }
        let (seq, deleted, admitted, native) = rows_after[&entry.path];
        let (seq_before, ..) = rows_before[&entry.path];
        assert!(seq > seq_before, "{}: no new version row", entry.path);
        assert!(admitted >= started_at, "{}: row not admitted by the rewind", entry.path);
        assert!(native, "{}: row names no native head", entry.path);
        let restored = match &entry.action {
            RewindPathAction::Create { version_hash, .. } => Some(*version_hash),
            RewindPathAction::Replace { to_version_hash, .. } => Some(*to_version_hash),
            RewindPathAction::Delete => None,
            other => panic!("{}: not actionable: {other:?}", entry.path),
        };
        assert_eq!(deleted, restored.is_none(), "{}", entry.path);
        if let Some(hash) = restored {
            let row = index.get_version(GROUP, &entry.path, seq).unwrap().unwrap();
            assert_eq!(row.version_hash, hash, "{}: not the historical version", entry.path);
            assert!(
                sqlite.dag_usable_proof_names_current_version(GROUP, &entry.path).unwrap(),
                "{}: no projection proof names the restored version",
                entry.path
            );
        }
    }
    approve(&mesh.nas, setup.target, &BTreeSet::new()).await;

    // The laptop comes back: ordinary sync, nothing authored by it.
    mesh.bring_laptop_back().await;
    wait_laptop(&mesh, &setup.original, "laptop after it came back", Duration::from_secs(300))
        .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(disk_tree(mesh.nas.root.path()), setup.original);
    let laptop = mesh.laptop();
    assert!(ops_by(&laptop.state, &laptop.device_id).is_empty(), "the laptop authored something");
    approve(laptop, setup.target, &BTreeSet::new()).await;
    mesh.handles.shutdown();
}
