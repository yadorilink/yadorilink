//! Reference model of explicit replicated state for directory-shaped `Case`
//! workloads, independent of the product's capture and materialization.
//!
//! `reference_model.rs` predicts per-path winners for flat files and has no
//! notion of a tree. This model replays `Case` ops as the explicit-entry
//! semantics say they replicate:
//!
//! * `Mkdir` puts an explicit Directory (and one for each missing
//!   ancestor: the user's `mkdir -p` created those too).
//! * `Write` / `Edit` put a File; a missing parent directory is put as an
//!   explicit Directory, since the writing tool created it on the user's
//!   behalf.
//! * `Delete` / `Rmdir` delete exactly one entry. A directory delete is not
//!   a prefix tombstone.
//! * `RmTree` deletes every entry the device observed at or under the path
//!   (observed-remove): a finite set of point deletes.
//! * `RenameTree` deletes each observed entry at its old path and puts it
//!   at its new one. Directories have no identity that travels.
//! * `Rename` / `Move` of a file are delete-plus-put.
//!
//! A *structural* directory, one that exists only to hold descendants, is
//! never an entry here; it is derived by [`ExplicitModel::expected_tree`].
//!
//! [`concurrent_heads`] turns a common base plus concurrent per-device op
//! lists into the per-path live heads of the merged history, which is what
//! `project` and the projection oracles in `namespace_oracle.rs` consume.

#![cfg(turmoil)]
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};

use sha2::{Digest, Sha256};
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_engine::conflict::{PathHead, PathHeadContent};

use super::case_ir::Op;
use super::namespace_oracle::{proper_ancestors, ExplicitHeads};

/// One explicit entry. Symlinks are absent because the `Case` IR has no op
/// that creates one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelEntry {
    Directory,
    File { content_id: u64 },
}

/// One replicated point effect of an op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Put { path: String, entry: ModelEntry },
    Delete { path: String },
}

/// What a path should physically be once the explicit state is projected,
/// for a state with at most one head per path (no concurrency, so no shape
/// conflict and no copy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedNode {
    ExplicitDirectory,
    StructuralDirectory,
    File { content_id: u64 },
}

/// Explicit state as one device sees it after applying ops sequentially.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExplicitModel {
    entries: BTreeMap<String, ModelEntry>,
}

fn is_under(path: &str, dir: &str) -> bool {
    path.len() > dir.len() + 1 && path.starts_with(dir) && path.as_bytes()[dir.len()] == b'/'
}

impl ExplicitModel {
    /// A model whose only entries are the given explicit directories (and
    /// their ancestors).
    pub fn with_directories<'a>(dirs: impl IntoIterator<Item = &'a str>) -> Self {
        let mut model = Self::default();
        for dir in dirs {
            model.apply(&Op::Mkdir { path: dir.to_string() }).expect("seed directory");
        }
        model
    }

    pub fn entries(&self) -> &BTreeMap<String, ModelEntry> {
        &self.entries
    }

    fn put(&mut self, path: &str, entry: ModelEntry, effects: &mut Vec<Effect>) {
        self.entries.insert(path.to_string(), entry);
        effects.push(Effect::Put { path: path.to_string(), entry });
    }

    fn delete(&mut self, path: &str, effects: &mut Vec<Effect>) {
        self.entries.remove(path);
        effects.push(Effect::Delete { path: path.to_string() });
    }

    /// Puts an explicit Directory at every missing ancestor of `path`,
    /// shallowest first. Fails if an ancestor is a File.
    fn ensure_parents(&mut self, path: &str, effects: &mut Vec<Effect>) -> Result<(), String> {
        let mut missing: Vec<String> = Vec::new();
        for ancestor in proper_ancestors(path) {
            match self.entries.get(ancestor) {
                Some(ModelEntry::Directory) => break,
                Some(ModelEntry::File { .. }) => {
                    return Err(format!("`{path}` would sit under file `{ancestor}`"));
                }
                None => missing.push(ancestor.to_string()),
            }
        }
        for ancestor in missing.iter().rev() {
            self.put(ancestor, ModelEntry::Directory, effects);
        }
        Ok(())
    }

    /// Every entry at or under `path`, sorted.
    pub fn observed_subtree(&self, path: &str) -> Vec<String> {
        self.entries.keys().filter(|p| *p == path || is_under(p, path)).cloned().collect()
    }

    /// Applies `op`, returning its replicated point effects in order, or why
    /// the op is not well-formed against this state.
    pub fn apply(&mut self, op: &Op) -> Result<Vec<Effect>, String> {
        let mut effects = Vec::new();
        match op {
            Op::Write { path, content_id } | Op::Edit { path, content_id } => {
                if self.entries.get(path) == Some(&ModelEntry::Directory) {
                    return Err(format!("write over directory `{path}`"));
                }
                self.ensure_parents(path, &mut effects)?;
                self.put(path, ModelEntry::File { content_id: *content_id }, &mut effects);
            }
            Op::Delete { path } => match self.entries.get(path) {
                Some(ModelEntry::File { .. }) => self.delete(path, &mut effects),
                other => return Err(format!("delete of `{path}`, which is {other:?}")),
            },
            Op::Rename { from, to } | Op::Move { from, to } => {
                let Some(entry @ ModelEntry::File { .. }) = self.entries.get(from).copied() else {
                    return Err(format!("file rename of non-file `{from}`"));
                };
                if self.entries.contains_key(to) {
                    return Err(format!("rename onto existing `{to}`"));
                }
                self.ensure_parents(to, &mut effects)?;
                self.delete(from, &mut effects);
                self.put(to, entry, &mut effects);
            }
            Op::Mkdir { path } => {
                if self.entries.contains_key(path) {
                    return Err(format!("mkdir of existing `{path}`"));
                }
                self.ensure_parents(path, &mut effects)?;
                self.put(path, ModelEntry::Directory, &mut effects);
            }
            Op::Rmdir { path } => {
                if self.entries.get(path) != Some(&ModelEntry::Directory) {
                    return Err(format!("rmdir of non-directory `{path}`"));
                }
                if self.observed_subtree(path).len() > 1 {
                    return Err(format!("rmdir of non-empty `{path}`"));
                }
                self.delete(path, &mut effects);
            }
            Op::RmTree { path } => {
                if self.entries.get(path) != Some(&ModelEntry::Directory) {
                    return Err(format!("rm -rf of non-directory `{path}`"));
                }
                // Deepest first, the order a recursive unlink runs in; the
                // replicated meaning is the set, not the order.
                for p in self.observed_subtree(path).into_iter().rev() {
                    self.delete(&p, &mut effects);
                }
            }
            Op::RenameTree { from, to } => {
                if self.entries.get(from) != Some(&ModelEntry::Directory) {
                    return Err(format!("directory rename of non-directory `{from}`"));
                }
                if self.entries.contains_key(to) || to == from || is_under(to, from) {
                    return Err(format!("directory rename `{from}` → `{to}` is not well-formed"));
                }
                self.ensure_parents(to, &mut effects)?;
                let moved: Vec<(String, ModelEntry)> = self
                    .observed_subtree(from)
                    .into_iter()
                    .map(|p| {
                        let entry = self.entries[&p];
                        (p, entry)
                    })
                    .collect();
                for (p, _) in moved.iter().rev() {
                    self.delete(p, &mut effects);
                }
                for (p, entry) in &moved {
                    let new_path = format!("{to}{}", &p[from.len()..]);
                    self.put(&new_path, *entry, &mut effects);
                }
            }
            Op::Chmod { path, .. } => {
                if !matches!(self.entries.get(path), Some(ModelEntry::File { .. })) {
                    return Err(format!("chmod of non-file `{path}`"));
                }
            }
            Op::ConflictingConcurrent { .. } => {}
        }
        Ok(effects)
    }

    /// The physical tree this state projects to, derived here without
    /// `project`: every explicit entry at its own path, plus a structural
    /// directory at every proper ancestor that is not itself explicit.
    pub fn expected_tree(&self) -> BTreeMap<String, ExpectedNode> {
        let mut out: BTreeMap<String, ExpectedNode> = BTreeMap::new();
        for (path, entry) in &self.entries {
            for ancestor in proper_ancestors(path) {
                if !self.entries.contains_key(ancestor) {
                    out.insert(ancestor.to_string(), ExpectedNode::StructuralDirectory);
                }
            }
            out.insert(
                path.clone(),
                match entry {
                    ModelEntry::Directory => ExpectedNode::ExplicitDirectory,
                    ModelEntry::File { content_id } => {
                        ExpectedNode::File { content_id: *content_id }
                    }
                },
            );
        }
        out
    }

    /// This state as `project` input: one head per entry, all from one
    /// change.
    pub fn heads(&self) -> ExplicitHeads {
        self.entries
            .iter()
            .map(|(path, entry)| (path.clone(), vec![head_for(BASE_DEVICE, 1, Some(*entry))]))
            .collect()
    }
}

/// The device name a base state's heads carry.
pub const BASE_DEVICE: &str = "base";

/// The version hash the model gives an entry. Every explicit directory
/// shares one version, as directories whose only metadata is the same mode
/// do, so identical concurrent `mkdir`s collapse instead of conflicting.
pub fn version_of(entry: ModelEntry) -> [u8; 32] {
    let tag = match entry {
        ModelEntry::Directory => "directory".to_string(),
        ModelEntry::File { content_id } => format!("file:{content_id}"),
    };
    Sha256::digest(tag.as_bytes()).into()
}

/// The kind of every version [`version_of`] can produce for `entries`.
pub fn kinds_for<'a>(
    entries: impl IntoIterator<Item = &'a ModelEntry>,
) -> HashMap<[u8; 32], RecordKind> {
    let mut kinds = HashMap::new();
    kinds.insert(version_of(ModelEntry::Directory), RecordKind::Directory);
    for entry in entries {
        if let ModelEntry::File { .. } = entry {
            kinds.insert(version_of(*entry), RecordKind::File);
        }
    }
    kinds
}

fn head_for(device: &str, lamport: u64, entry: Option<ModelEntry>) -> PathHead {
    let change_hash: [u8; 32] = Sha256::digest(format!("change:{device}:{lamport}")).into();
    PathHead {
        change_hash,
        rank: lamport,
        device_id: device.to_string(),
        naming_device_id: device.to_string(),
        content: entry
            .map(|e| PathHeadContent { version_hash: version_of(e), mtime_unix_nanos: 0 }),
    }
}

/// The merged explicit state after each device applies its ops to its own
/// copy of `base`, with no device having seen any other's: per path, the
/// base head if no device touched it, otherwise one head per device that
/// did (its net effect), all concurrent. Also returns every version kind
/// the heads use.
pub fn concurrent_heads(
    base: &ExplicitModel,
    sides: &[(&str, Vec<Op>)],
) -> Result<(ExplicitHeads, HashMap<[u8; 32], RecordKind>), String> {
    let mut touched: BTreeMap<String, Vec<(usize, Option<ModelEntry>)>> = BTreeMap::new();
    let mut all_entries: Vec<ModelEntry> = base.entries.values().copied().collect();
    for (index, (device, ops)) in sides.iter().enumerate() {
        let mut view = base.clone();
        let mut net: BTreeMap<String, Option<ModelEntry>> = BTreeMap::new();
        for op in ops {
            for effect in view.apply(op).map_err(|e| format!("device {device}: {e}"))? {
                match effect {
                    Effect::Put { path, entry } => {
                        all_entries.push(entry);
                        net.insert(path, Some(entry));
                    }
                    Effect::Delete { path } => {
                        net.insert(path, None);
                    }
                }
            }
        }
        for (path, entry) in net {
            touched.entry(path).or_default().push((index, entry));
        }
    }
    let mut heads = base.heads();
    for (path, effects) in touched {
        let side_heads =
            effects.into_iter().map(|(index, entry)| head_for(sides[index].0, 2, entry)).collect();
        heads.insert(path, side_heads);
    }
    Ok((heads, kinds_for(&all_entries)))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::super::clock::HarnessClock;
    use super::super::generator::generate_directory_case;
    use super::super::namespace_oracle::{
        check_disk_against_projection, check_projection, check_projection_purity, disk_tree,
        sha256_hex, ExpectedLeaf, NamespaceViolation,
    };
    use super::super::namespace_oracle::{
        project, DirectoryNode, PhysicalNode, PlacedEntry, Placement,
    };
    use super::super::op_applier::apply_op;
    use super::*;

    fn w(path: &str, content_id: u64) -> Op {
        Op::Write { path: path.into(), content_id }
    }

    fn project_and_check(
        heads: &ExplicitHeads,
        kinds: &HashMap<[u8; 32], RecordKind>,
    ) -> BTreeMap<String, PhysicalNode> {
        let kind_of = |v: &[u8; 32]| kinds.get(v).copied();
        let tree = project(heads, kind_of).expect("every model version has a kind");
        let mut violations: Vec<NamespaceViolation> =
            check_projection(heads, &kind_of, tree.nodes());
        violations.extend(check_projection_purity(heads, &kind_of));
        assert!(violations.is_empty(), "{violations:#?}");
        tree.nodes().clone()
    }

    fn file_at(content_id: u64, source: &str, placement: Placement) -> PhysicalNode {
        PhysicalNode::Entry(PlacedEntry {
            kind: RecordKind::File,
            version_hash: version_of(ModelEntry::File { content_id }),
            source: source.into(),
            placement,
        })
    }

    fn explicit_dir() -> PhysicalNode {
        PhysicalNode::Directory(DirectoryNode::Explicit {
            version_hash: version_of(ModelEntry::Directory),
        })
    }

    const STRUCTURAL: PhysicalNode = PhysicalNode::Directory(DirectoryNode::Structural);

    #[test]
    fn rm_tree_is_a_set_of_point_deletes_of_what_was_observed() {
        let mut model = ExplicitModel::with_directories(["a/b"]);
        model.apply(&w("a/b/f", 1)).unwrap();
        model.apply(&w("a/g", 2)).unwrap();
        let effects = model.apply(&Op::RmTree { path: "a".into() }).unwrap();
        let deleted: BTreeSet<String> = effects
            .iter()
            .map(|e| match e {
                Effect::Delete { path } => path.clone(),
                Effect::Put { .. } => panic!("rm -rf puts nothing: {e:?}"),
            })
            .collect();
        assert_eq!(deleted, ["a", "a/b", "a/b/f", "a/g"].map(String::from).into());
        assert!(model.entries().is_empty());
        assert!(model.expected_tree().is_empty(), "nothing left, not even an empty `a`");
    }

    #[test]
    fn a_sequential_state_projects_to_the_models_own_tree() {
        let mut model = ExplicitModel::with_directories(["docs", "empty"]);
        model.apply(&w("docs/a.txt", 1)).unwrap();
        model.apply(&Op::RenameTree { from: "docs".into(), to: "new/docs".into() }).unwrap();
        let heads = model.heads();
        let tree = project_and_check(&heads, &kinds_for(model.entries().values()));
        let expected = model.expected_tree();
        assert_eq!(
            tree.keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>(),
            "projection and model disagree on which paths exist"
        );
        for (path, want) in &expected {
            let got = &tree[path];
            let ok = match want {
                ExpectedNode::ExplicitDirectory => got == &explicit_dir(),
                ExpectedNode::StructuralDirectory => got == &STRUCTURAL,
                ExpectedNode::File { content_id } => {
                    got == &file_at(*content_id, path, Placement::AtPath)
                }
            };
            assert!(ok, "{path}: model wants {want:?}, projection has {got:?}");
        }
    }

    /// `rm -rf a` on one device while the other writes `a/new`: the write
    /// survives, and so does `a`, now only as its container.
    #[test]
    fn rm_tree_against_a_concurrent_child_keeps_child_and_container() {
        let mut base = ExplicitModel::with_directories(["a"]);
        base.apply(&w("a/old", 1)).unwrap();
        let (heads, kinds) = concurrent_heads(
            &base,
            &[("dev-a", vec![Op::RmTree { path: "a".into() }]), ("dev-b", vec![w("a/new", 2)])],
        )
        .unwrap();
        let tree = project_and_check(&heads, &kinds);
        assert_eq!(tree.get("a"), Some(&STRUCTURAL));
        assert_eq!(tree.get("a/new"), Some(&file_at(2, "a/new", Placement::AtPath)));
        assert_eq!(tree.get("a/old"), None);
        assert_eq!(tree.len(), 2, "{tree:#?}");
    }

    /// An edit racing `rm -rf` of its directory keeps the edit: content
    /// beats a concurrent tombstone, and the directory stays structural.
    #[test]
    fn rm_tree_against_a_concurrent_edit_keeps_the_edit() {
        let mut base = ExplicitModel::with_directories(["a"]);
        base.apply(&w("a/f", 1)).unwrap();
        let (heads, kinds) = concurrent_heads(
            &base,
            &[
                ("dev-a", vec![Op::RmTree { path: "a".into() }]),
                ("dev-b", vec![Op::Edit { path: "a/f".into(), content_id: 2 }]),
            ],
        )
        .unwrap();
        let tree = project_and_check(&heads, &kinds);
        assert_eq!(tree.get("a"), Some(&STRUCTURAL));
        assert_eq!(tree.get("a/f"), Some(&file_at(2, "a/f", Placement::AtPath)));
    }

    /// Renaming `a` to `b` while the other device creates `a/new`: the moved
    /// entries land under `b`, the concurrent child stays under `a`.
    #[test]
    fn rename_tree_against_a_concurrent_child_leaves_the_child_behind() {
        let mut base = ExplicitModel::with_directories(["a"]);
        base.apply(&w("a/moved", 1)).unwrap();
        let (heads, kinds) = concurrent_heads(
            &base,
            &[
                ("dev-a", vec![Op::RenameTree { from: "a".into(), to: "b".into() }]),
                ("dev-b", vec![w("a/new", 2)]),
            ],
        )
        .unwrap();
        let tree = project_and_check(&heads, &kinds);
        assert_eq!(tree.get("b"), Some(&explicit_dir()));
        assert_eq!(tree.get("b/moved"), Some(&file_at(1, "b/moved", Placement::AtPath)));
        assert_eq!(tree.get("a"), Some(&STRUCTURAL));
        assert_eq!(tree.get("a/new"), Some(&file_at(2, "a/new", Placement::AtPath)));
        assert_eq!(tree.get("a/moved"), None);
    }

    /// File `a` against directory `a` holding `a/x`: the directory wins the
    /// path, the file is kept beside it, nothing is lost.
    #[test]
    fn file_against_a_directory_with_a_child_keeps_both() {
        let (heads, kinds) = concurrent_heads(
            &ExplicitModel::default(),
            &[("dev-a", vec![w("a", 1)]), ("dev-b", vec![w("a/x", 2)])],
        )
        .unwrap();
        let tree = project_and_check(&heads, &kinds);
        assert_eq!(tree.get("a"), Some(&explicit_dir()));
        assert_eq!(tree.get("a/x"), Some(&file_at(2, "a/x", Placement::AtPath)));
        let beside: Vec<&PhysicalNode> =
            tree.iter().filter(|(p, _)| p.starts_with("a (")).map(|(_, n)| n).collect();
        assert_eq!(beside, vec![&file_at(1, "a", Placement::ConflictCopy)], "{tree:#?}");
    }

    /// Two devices `mkdir` the same path: one explicit directory, no copy.
    #[test]
    fn identical_concurrent_mkdir_collapses() {
        let (heads, kinds) = concurrent_heads(
            &ExplicitModel::default(),
            &[
                ("dev-a", vec![Op::Mkdir { path: "d".into() }]),
                ("dev-b", vec![Op::Mkdir { path: "d".into() }]),
            ],
        )
        .unwrap();
        let tree = project_and_check(&heads, &kinds);
        assert_eq!(tree.len(), 1, "{tree:#?}");
        assert_eq!(tree.get("d"), Some(&explicit_dir()));
    }

    /// The whole stack on a real filesystem, for generated directory
    /// workloads replayed on one device in their global order: the applier
    /// produces exactly the tree the model projects to, and every disk
    /// oracle agrees (no leftover, no kind mismatch, right bytes).
    #[test]
    fn generated_directory_workloads_replayed_on_disk_match_the_projection() {
        const SEEDS: u64 = 60;
        for seed in 0..SEEDS {
            let case = generate_directory_case(seed);
            let root = tempfile::tempdir().unwrap();
            let mut model = ExplicitModel::with_directories(["dir_a", "dir_b"]);
            for dir in ["dir_a", "dir_b"] {
                std::fs::create_dir(root.path().join(dir)).unwrap();
            }
            let clock = HarnessClock::from_seed(seed);
            let mut ordered: Vec<(u64, usize, &Op)> = case
                .workload
                .iter()
                .flat_map(|tl| tl.ops.iter().map(move |(ts, op)| (*ts, tl.device_index, op)))
                .collect();
            ordered.sort_by_key(|(ts, dev, _)| (*ts, *dev));
            for (_, _, op) in ordered {
                model.apply(op).unwrap_or_else(|e| panic!("seed {seed}: {e}"));
                apply_op(&clock, root.path(), op, &case.content_table).unwrap();
            }

            let heads = model.heads();
            let kinds = kinds_for(model.entries().values());
            let tree = project_and_check(&heads, &kinds);
            let bytes_of = |id: u64| case.content_table.get(id).cloned().unwrap();
            let expected_leaf = |e: &PlacedEntry| {
                model.entries().iter().find_map(|(_, entry)| match entry {
                    ModelEntry::File { content_id } if version_of(*entry) == e.version_hash => {
                        Some(ExpectedLeaf::FileSha256(sha256_hex(&bytes_of(*content_id))))
                    }
                    _ => None,
                })
            };
            let on_disk = disk_tree(root.path());
            // Every directory here came from a replayed op the model saw, so
            // every one has a known origin: any the projection does not
            // want is a leftover.
            let (violations, extra) =
                check_disk_against_projection(0, &on_disk, &tree, &|_| true, expected_leaf);
            assert!(violations.is_empty(), "seed {seed}: {violations:#?}");
            assert!(extra.retained.is_empty(), "seed {seed}: nothing untracked was written");
            let disk_kinds: BTreeMap<&String, bool> =
                on_disk.iter().map(|(p, n)| (p, n.is_directory())).collect();
            let expected_tree = model.expected_tree();
            let model_kinds: BTreeMap<&String, bool> = expected_tree
                .iter()
                .map(|(p, n)| (p, !matches!(n, ExpectedNode::File { .. })))
                .collect();
            assert_eq!(disk_kinds, model_kinds, "seed {seed}");
        }
    }
}
