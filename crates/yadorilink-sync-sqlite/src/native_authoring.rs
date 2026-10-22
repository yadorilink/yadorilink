//! Authors a native `NativeDelta` for each local mutation (or one multi-op
//! delta for a bulk-captured run of them) and installs it via
//! `native_store::install_verified_delta`, under the device's own author.
//!
//! This runs inside the *same transaction* as the `files` row write
//! (`file_index::commit_local_mutation_in_tx` propagates this function's
//! `Result` with `?`, exactly like every other step of that commit) --
//! deliberately, not caught and swallowed: this crate's crash-sweep tests
//! assert every write step commits fully or not at all, and an authoring
//! failure silently absorbed mid-transaction while the rest of the
//! transaction still commits would violate that invariant. A failure here
//! therefore refuses the local mutation too.
//!
//! Scope: `Op::Put` (an ordinary edit/create), `Op::Delete`, and a
//! single-file `Op::Move` (the single-head rename: remove at the source, put
//! at the destination).
//!
//! A conflict copy is an ordinary entry at its own path, authored like any
//! other: the op a user's edit of it produces targets that path and
//! supersedes exactly the heads of the content the capture showed there.

use rusqlite::Connection;

use yadorilink_replica_domain::ids::{AuthorSeq, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::native_fork::VersionInfo;
use yadorilink_replica_domain::native_state::{
    DeltaHash, Dot, HeadPayload, NativeCaptureWitness, NativeState, PathEdit,
};
use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, HeadRef, NativeDelta};

use crate::error::SyncSqliteError;
use crate::local_author::LocalAuthor;
use crate::native_store;

/// The most ops one bulk-captured delta carries: a batch of local mutations at
/// distinct paths is signed as one delta of at most this many ops. The same
/// bound the initial import and the startup reconcile cut their chunks by, far
/// inside the decode limit on ops per delta.
pub const BULK_DELTA_MAX_OPS: usize = yadorilink_replica_domain::local_op::IMPORT_BATCH_OP_LIMIT;

/// The most bytes (estimated, never under the encoded size) the ops of one
/// bulk-captured delta may take on the wire: the bound the import and reconcile
/// chunks already share. A delta travels in one `DeltaBatch` entry beside its
/// proof under a per-item budget of a few MiB, so a batch of long paths is
/// signed as several deltas instead of one that could not be delivered.
pub const BULK_DELTA_MAX_BYTES: usize = yadorilink_replica_domain::local_op::MAX_CHANGE_OP_BYTES;

/// The native heads one authored mutation put, by the logical path
/// each landed at: what a `files` row produced by that mutation shows.
#[derive(Debug, Default, Clone)]
pub struct AuthoredPuts {
    puts: std::collections::BTreeMap<
        SyncPath,
        yadorilink_replica_domain::native_plan::NativeRowIdentity,
    >,
    /// The live heads at every path an authored delta touched, as the installs left them: the
    /// state each install computed and wrote, so what the transaction holds at those paths now.
    installed: std::collections::BTreeMap<SyncPath, crate::native_store::PathHeadsMap>,
    /// The obligation each touched path holds as the arming of its last delta left it.
    armed: std::collections::BTreeMap<String, crate::projection_obligations::ArmedObligation>,
}

impl AuthoredPuts {
    /// The head the mutation put at `path`, when it put one.
    pub fn put_at(
        &self,
        path: &SyncPath,
    ) -> Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity> {
        self.puts.get(path)
    }

    /// The live heads at `path` as the authoring left them, when a delta touched it.
    pub(crate) fn installed_heads_at(
        &self,
        path: &SyncPath,
    ) -> Option<&crate::native_store::PathHeadsMap> {
        self.installed.get(path)
    }

    /// The obligation at `path` as the arming of the last delta that touched it left it.
    pub(crate) fn armed_obligation_at(
        &self,
        path: &str,
    ) -> Option<&crate::projection_obligations::ArmedObligation> {
        self.armed.get(path)
    }

    /// Adds another part's puts.
    pub fn extend(&mut self, other: AuthoredPuts) {
        self.puts.extend(other.puts);
        self.installed.extend(other.installed);
        self.armed.extend(other.armed);
    }
}

/// Authors a delta for `op` as `author`, inside `tx`. See the module doc for
/// scope and the atomicity contract.
pub fn author_op(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    op: &Op,
) -> Result<AuthoredPuts, SyncSqliteError> {
    author_op_witnessed(tx, group_id, author, op, None)
}

/// [`author_op`] for a mutation captured earlier under `witness`: the
/// heads it supersedes are those of the content it displayed that the
/// capture saw (see [`NativeCaptureWitness::shown_class`]).
pub fn author_op_witnessed(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    op: &Op,
    witness: Option<&NativeCaptureWitness>,
) -> Result<AuthoredPuts, SyncSqliteError> {
    let shown = shown_versions(tx, group_id, &author.author, std::slice::from_ref(op), &[witness])?
        .remove(0);
    author_op_shown(tx, group_id, author, op, &shown)
}

/// One mutation of a bulk capture: the op and the witness its capture
/// recorded.
pub struct BulkOp<'a> {
    pub op: &'a Op,
    pub witness: Option<&'a NativeCaptureWitness>,
}

/// Every path whose rows or heads authoring `item` reads or edits.
fn bulk_touched_paths<'a>(item: &'a BulkOp<'a>) -> Vec<&'a SyncPath> {
    let mut paths = op_paths(item.op);
    if let Some(witness) = item.witness {
        paths.push(&witness.path);
    }
    paths
}

/// Cuts `items` (in order) into the runs a bulk capture signs as one delta
/// each: consecutive mutations that touch pairwise unrelated paths -- no
/// shared path, and no path under another (a file and the directory it would
/// live in) -- at most [`BULK_DELTA_MAX_OPS`] of them. A mutation that touches
/// a path an earlier one of the run touches starts a new run, so per-path
/// ordering is exactly that of authoring them one by one. Each run is a
/// complete, independent edit set: it depends on no later run.
pub fn bulk_groups(items: &[BulkOp<'_>]) -> Vec<std::ops::Range<usize>> {
    let mut groups = Vec::new();
    let mut start = 0;
    let mut touched: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        let paths = bulk_touched_paths(item);
        let related = index - start >= BULK_DELTA_MAX_OPS
            || paths.iter().any(|path| paths_related(&touched, path.as_str()));
        if related {
            groups.push(start..index);
            start = index;
            touched.clear();
        }
        touched.extend(paths.iter().map(|path| path.as_str()));
    }
    if start < items.len() {
        groups.push(start..items.len());
    }
    groups
}

/// Whether `path` is, is under, or is above a path of `touched`.
fn paths_related(touched: &std::collections::BTreeSet<&str>, path: &str) -> bool {
    if touched.contains(path) {
        return true;
    }
    let mut ancestor = path;
    while let Some(slash) = ancestor.rfind('/') {
        ancestor = &ancestor[..slash];
        if touched.contains(ancestor) {
            return true;
        }
    }
    let below = format!("{path}/");
    touched.range::<&str, _>(below.as_str()..).next().is_some_and(|next| next.starts_with(&below))
}

/// The bytes an op for `edit` is estimated to take on the wire. A removal
/// names its head exactly (a length-prefixed device id, the incarnation, the
/// sequence and the header hash), so its size depends on the device id's
/// length: the op is charged for the longest names it could carry, never the
/// first ones met.
fn estimated_edit_bytes(edit: &PathEdit) -> usize {
    use yadorilink_replica_domain::signed_delta::MAX_REMOVES_PER_OP;
    /// What naming a head takes: 4 (length) + device id + 16 + 8 + 32.
    fn named_head_bytes(dot: &Dot) -> usize {
        60 + dot.author.device.0.len()
    }
    let mut sizes: Vec<usize> = edit.observed.iter().map(named_head_bytes).collect();
    sizes.sort_unstable_by(|a, b| b.cmp(a));
    let removes: usize = sizes.into_iter().take(MAX_REMOVES_PER_OP).sum();
    // The path (length-prefixed), the counts and the put.
    edit.path.as_str().len() + 64 + removes
}

/// Authors one bulk capture run (see [`bulk_groups`]) as a single multi-op
/// delta: every mutation's edits are computed against the same pre-state and
/// signed together. A run whose ops would exceed
/// [`BULK_DELTA_MAX_BYTES`] is signed as consecutive deltas, a mutation's own
/// edits (a move's removal and put) never split across them. One mutation is
/// signed exactly as [`author_op_witnessed`] signs it.
pub fn author_bulk_group(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    items: &[BulkOp<'_>],
) -> Result<AuthoredPuts, SyncSqliteError> {
    if items.is_empty() {
        return Ok(AuthoredPuts::default());
    }
    let ops: Vec<Op> = items.iter().map(|item| item.op.clone()).collect();
    let witnesses: Vec<Option<&NativeCaptureWitness>> =
        items.iter().map(|item| item.witness).collect();
    let shown = shown_versions(tx, group_id, &author.author, &ops, &witnesses)?;
    let state = native_store::load_heads_at_paths(tx, group_id, &paths_of_ops(&ops))?;
    let mut per_op: Vec<Vec<PathEdit>> = Vec::with_capacity(items.len());
    let mut authored = AuthoredPuts::default();
    for (item, shown) in items.iter().zip(&shown) {
        per_op.push(edits_for_op(&state, item.op, shown));
    }
    let mut pack: Vec<PathEdit> = Vec::new();
    let mut pack_bytes = 0usize;
    let flush = |pack: &mut Vec<PathEdit>| -> Result<AuthoredPuts, SyncSqliteError> {
        author_and_install(
            tx,
            group_id,
            author,
            &state,
            std::mem::take(pack),
            None,
            native_store::load_heads_at_paths,
        )
    };
    for edits in per_op {
        let bytes: usize = edits.iter().map(estimated_edit_bytes).sum();
        if !pack.is_empty()
            && (pack.len() + edits.len() > BULK_DELTA_MAX_OPS
                || pack_bytes + bytes > BULK_DELTA_MAX_BYTES)
        {
            authored.extend(flush(&mut pack)?);
            pack_bytes = 0;
        }
        pack_bytes += bytes;
        pack.extend(edits);
    }
    if !pack.is_empty() {
        authored.extend(flush(&mut pack)?);
    }
    Ok(authored)
}

/// How authoring reads the live heads at the paths an operation names: a
/// `NativeState` holding at least those paths' heads. Admission reads nothing
/// of the state but the heads at the paths it edits, so production loads
/// exactly those ([`native_store::load_heads_at_paths`]) and the cost of a
/// mutation does not grow with the group.
type ReadHeads =
    fn(&Connection, &FolderGroupId, &[&SyncPath]) -> Result<NativeState, SyncSqliteError>;

/// The paths an op reads or edits.
fn op_paths(op: &Op) -> Vec<&SyncPath> {
    match op {
        Op::Put { path, .. } | Op::Delete { path } => vec![path],
        Op::Move { from, to, .. } => vec![from, to],
    }
}

/// The distinct paths of `ops`.
fn paths_of_ops<'a>(ops: impl IntoIterator<Item = &'a Op>) -> Vec<&'a SyncPath> {
    let mut paths: Vec<&SyncPath> = ops.into_iter().flat_map(op_paths).collect();
    paths.sort();
    paths.dedup();
    paths
}

/// [`author_op`] with what the writer was shown given rather than read.
fn author_op_shown(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    op: &Op,
    shown: &Shown,
) -> Result<AuthoredPuts, SyncSqliteError> {
    author_op_shown_reading(tx, group_id, author, op, shown, native_store::load_heads_at_paths)
}

fn author_op_shown_reading(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    op: &Op,
    shown: &Shown,
    read_heads: ReadHeads,
) -> Result<AuthoredPuts, SyncSqliteError> {
    let state = read_heads(tx, group_id, &op_paths(op))?;
    let edits = edits_for_op(&state, op, shown);
    author_and_install(tx, group_id, author, &state, edits, None, read_heads)
}

/// [`author_recursive_part`] with each op's capture-time witness, in
/// the same order as `ops`.
pub fn author_recursive_part_witnessed(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    ops: &[Op],
    witnesses: &[Option<&NativeCaptureWitness>],
) -> Result<AuthoredPuts, SyncSqliteError> {
    author_recursive_part_tagged(tx, group_id, author, ops, witnesses, None)
}

/// [`author_recursive_part_witnessed`] naming the operation the part
/// belongs to in the deltas it signs. `recursive_part.part_index` is the index
/// of the part's first delta; each further delta of the part's chain takes the
/// next index (see [`recursive_part_delta_count`]).
pub fn author_recursive_part_tagged(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    ops: &[Op],
    witnesses: &[Option<&NativeCaptureWitness>],
    recursive_part: Option<yadorilink_replica_domain::signed_delta::RecursivePart>,
) -> Result<AuthoredPuts, SyncSqliteError> {
    let shown = shown_versions(tx, group_id, &author.author, ops, witnesses)?;
    author_part_shown(tx, group_id, author, ops, &shown, recursive_part)
}

fn author_part_shown(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    ops: &[Op],
    shown: &[Shown],
    recursive_part: Option<yadorilink_replica_domain::signed_delta::RecursivePart>,
) -> Result<AuthoredPuts, SyncSqliteError> {
    author_part_shown_reading(
        tx,
        group_id,
        author,
        ops,
        shown,
        recursive_part,
        native_store::load_heads_at_paths,
    )
}

fn author_part_shown_reading(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    ops: &[Op],
    shown: &[Shown],
    recursive_part: Option<yadorilink_replica_domain::signed_delta::RecursivePart>,
    read_heads: ReadHeads,
) -> Result<AuthoredPuts, SyncSqliteError> {
    if ops.is_empty() {
        return Ok(AuthoredPuts::default());
    }
    let state = read_heads(tx, group_id, &paths_of_ops(ops))?;
    let edits = part_edits(&state, ops, shown);
    author_and_install(tx, group_id, author, &state, edits, recursive_part, read_heads)
}

/// The edits of one recursive part, one per op in order.
fn part_edits(state: &NativeState, ops: &[Op], shown: &[Shown]) -> Vec<PathEdit> {
    ops.iter().zip(shown).flat_map(|(op, shown)| edits_for_op(state, op, shown)).collect()
}

/// How many deltas authoring this recursive part would sign: none when every
/// op has nothing left to remove or put, otherwise its chain of removals. The operation's part count is the sum over its parts, so
/// an operation whose deltas all authored is complete.
pub fn recursive_part_delta_count(
    tx: &Connection,
    group_id: &FolderGroupId,
    own: &yadorilink_replica_domain::author::AuthorId,
    ops: &[Op],
    witnesses: &[Option<&NativeCaptureWitness>],
) -> Result<u32, SyncSqliteError> {
    recursive_part_delta_count_reading(
        tx,
        group_id,
        own,
        ops,
        witnesses,
        native_store::load_heads_at_paths,
    )
}

fn recursive_part_delta_count_reading(
    tx: &Connection,
    group_id: &FolderGroupId,
    own: &yadorilink_replica_domain::author::AuthorId,
    ops: &[Op],
    witnesses: &[Option<&NativeCaptureWitness>],
    read_heads: ReadHeads,
) -> Result<u32, SyncSqliteError> {
    let shown = shown_versions(tx, group_id, own, ops, witnesses)?;
    let state = read_heads(tx, group_id, &paths_of_ops(ops))?;
    let edits = part_edits(&state, ops, &shown);
    if edits.is_empty() {
        return Ok(0);
    }
    Ok(chain_rounds(&merge_edits(edits)?) as u32)
}

/// The `PathEdit`s one op contributes, against a fixed pre-state `state`.
fn edits_for_op(state: &NativeState, op: &Op, shown: &Shown) -> Vec<PathEdit> {
    match op {
        Op::Put { path, version } => vec![put_edit(state, path, *version, shown)],
        // A delete of a version native no longer shows has nothing to remove:
        // that entry authors nothing, and the rest of its part still does.
        Op::Delete { path } => delete_edit(state, path, shown).into_iter().collect(),
        Op::Move { from, to, version } => delete_edit(state, from, shown)
            .into_iter()
            .chain(std::iter::once(put_edit(state, to, *version, shown)))
            .collect(),
    }
}

/// What the writer was looking at when it made ONE op: for each path the op
/// touches, the version the index row displayed, and -- when a capture-time
/// witness is known -- the exact heads of the version at the op's source path
/// that the writer's state held. One per op: two ops of a recursive part can
/// act on the same source path with different rows (a winner and a folded
/// copy) and must not share what they were shown.
#[derive(Default, Debug)]
struct Shown {
    versions: std::collections::BTreeMap<SyncPath, Option<VersionHash>>,
    /// Restricts the heads of the shown version at this path that an edit
    /// supersedes to these. Unrestricted (every live head of the version) when
    /// absent, which is right when nothing was captured earlier than the
    /// authoring itself.
    class: Option<(SyncPath, std::collections::BTreeSet<Dot>)>,
}

impl Shown {
    /// The captured class for `path`, when this op has one for that path.
    fn class_at(&self, path: &SyncPath) -> Option<&std::collections::BTreeSet<Dot>> {
        self.class.as_ref().filter(|(source, _)| source == path).map(|(_, class)| class)
    }
}

fn shown_versions(
    tx: &Connection,
    group_id: &FolderGroupId,
    own: &yadorilink_replica_domain::author::AuthorId,
    ops: &[Op],
    witnesses: &[Option<&NativeCaptureWitness>],
) -> Result<Vec<Shown>, SyncSqliteError> {
    let distinct: Vec<&str> = paths_of_ops(ops).into_iter().map(|path| path.as_str()).collect();
    let rows = crate::store::read_canonical_current_rows(tx, group_id.as_str(), &distinct)?;
    let mut all = Vec::with_capacity(ops.len());
    for (index, op) in ops.iter().enumerate() {
        let mut out = Shown::default();
        for path in op_paths(op) {
            out.versions.insert(
                path.clone(),
                rows.get(path.as_str())
                    .filter(|row| !row.snapshot.deleted)
                    .map(|row| row.version_hash()),
            );
        }
        // The witness names the path the op acts on. What it recorded is what the
        // writer saw: the row is not read again, since it may have changed
        // since the capture.
        if let Some(Some(witness)) = witnesses.get(index) {
            if witness.shown_version.is_some() {
                out.versions.insert(witness.path.clone(), witness.shown_version);
                if !witness.shown_class.is_empty() {
                    out.class =
                        Some((witness.path.clone(), witness.shown_class.iter().cloned().collect()));
                }
            } else if let Some(Some(row_version)) = out.versions.get(&witness.path).copied() {
                // Nothing vouches for the disk (a locally captured row whose
                // proof the capture left out). The row's version may be only
                // ahead of the disk through a remote write, and a remote write
                // never puts an own head: the row stands in for the disk only
                // when every live head of its version here is this author's.
                let heads = native_store::native_heads_at(tx, group_id, &witness.path)?;
                let all_own = heads
                    .iter()
                    .filter(|head| head.payload.version == row_version)
                    .all(|head| head.dot.author == *own);
                if !all_own {
                    out.versions.insert(witness.path.clone(), None);
                }
            }
        }
        all.push(out);
    }
    Ok(all)
}

/// Every live head at `path` of the version its index row displayed -- the
/// content the writer saw, which is one piece of content however many heads
/// hold it (identical-content collapse) -- limited to the writer's captured
/// class when one is known, so a head that arrived after the capture is not
/// superseded by an edit that never saw it. Superseding is per exact head
/// (each removal names its `(path, dot, provenance)`). Nothing when the
/// row's version is not live in native (a new file, or content a peer
/// already superseded): the edit is then concurrent with what is live.
fn observed_target(state: &NativeState, path: &SyncPath, shown: &Shown) -> Vec<Dot> {
    let Some(Some(version)) = shown.versions.get(path) else { return Vec::new() };
    heads_of_shown_class(state, path, version, shown.class_at(path))
}

fn heads_of_shown_class(
    state: &NativeState,
    path: &SyncPath,
    version: &VersionHash,
    class: Option<&std::collections::BTreeSet<Dot>>,
) -> Vec<Dot> {
    let mut dots: Vec<Dot> = state
        .heads_at(path)
        .filter(|head| head.payload.version == *version)
        .filter(|head| class.is_none_or(|class| class.contains(&head.dot)))
        .map(|head| head.dot)
        .collect();
    dots.sort();
    // Every head of the class: a head left behind would resolve present again.
    // One op carries at most `MAX_REMOVES_PER_OP` removals on the wire, so a
    // larger class is signed as a chain of deltas by [`author_and_install`].
    dots
}

/// `None` when there is nothing to delete: the version the writer deleted is
/// not live in native, so no head is removed and no delta is owed.
fn delete_edit(state: &NativeState, path: &SyncPath, shown: &Shown) -> Option<PathEdit> {
    let observed = observed_target(state, path, shown);
    (!observed.is_empty()).then(|| PathEdit { path: path.clone(), observed, put: None })
}

fn put_edit(state: &NativeState, path: &SyncPath, version: VersionHash, shown: &Shown) -> PathEdit {
    let observed = observed_target(state, path, shown);
    PathEdit {
        path: path.clone(),
        observed,
        put: Some(HeadPayload { version, provenance: DeltaHash::default() }),
    }
}

/// Combines multiple `PathEdit`s at the same path into one, unioning their
/// observed dots -- needed because `NativeState::author` refuses more than one
/// edit per path in a single mutation, but a recursive-operation part can
/// legitimately produce two edits at the same source path (e.g. a directory
/// move's winner and a concurrent unresolved loser both removing their own dot
/// at the same pre-move path). A delta carries one put per path, so two edits
/// that both put are refused rather than one put being dropped; a caller that
/// has a second put chains it as a follow-up delta.
fn merge_edits(edits: Vec<PathEdit>) -> Result<Vec<PathEdit>, SyncSqliteError> {
    let mut merged: std::collections::BTreeMap<SyncPath, PathEdit> =
        std::collections::BTreeMap::new();
    for edit in edits {
        match merged.entry(edit.path.clone()) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(edit);
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                let existing = slot.get_mut();
                if existing.put.is_some() && edit.put.is_some() {
                    return Err(SyncSqliteError::InvalidInput(format!(
                        "two puts at {:?} cannot share one delta",
                        edit.path.as_str()
                    )));
                }
                for dot in &edit.observed {
                    if !existing.observed.contains(dot) {
                        existing.observed.push(dot.clone());
                    }
                }
                if existing.put.is_none() {
                    existing.put = edit.put;
                }
            }
        }
    }
    Ok(merged.into_values().collect())
}

/// Refuses to sign as `author` unless it is this replica's current author
/// incarnation, and refuses when a peer has reported that incarnation ahead
/// in `group_id`. With no incarnation record at all nothing has ever been
/// rotated away, so no author can be a retired one and only the report check
/// applies (it finds nothing without a record). A rotation retires the
/// previous incarnation for good, including for handles built before it.
fn refuse_unless_current_author(
    conn: &Connection,
    group_id: &str,
    author: &yadorilink_replica_domain::author::AuthorId,
) -> Result<(), SyncSqliteError> {
    use yadorilink_replica_domain::author::AuthoringRefusal;
    let Some(current) = crate::author_incarnation::incarnation_record(conn)? else {
        return Ok(());
    };
    if current.author != *author {
        return Err(SyncSqliteError::AuthoringRefused {
            refusal: AuthoringRefusal::StaleAuthor {
                author: author.clone(),
                current: current.author,
            },
        });
    }
    if let Some(report) = crate::author_incarnation::own_author_ahead(conn, group_id)? {
        return Err(SyncSqliteError::AuthoringRefused {
            refusal: AuthoringRefusal::OwnAuthorAhead {
                author: report.author,
                local: report.local,
                reported: report.reported,
            },
        });
    }
    Ok(())
}

fn author_and_install(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    state: &NativeState,
    edits: Vec<PathEdit>,
    recursive_part: Option<yadorilink_replica_domain::signed_delta::RecursivePart>,
    _read_heads: ReadHeads,
) -> Result<AuthoredPuts, SyncSqliteError> {
    refuse_unless_current_author(tx, group_id.as_str(), &author.author)?;
    if edits.is_empty() {
        // Every op deleted a version native no longer shows: nothing to author.
        return Ok(AuthoredPuts::default());
    }
    let edits = merge_edits(edits)?;
    // A put that would leave more than `MAX_SELF_HEADS` of this author's own
    // heads at a path is refused as such, so the caller can preserve the edit
    // as a conflict copy; left to fail at install, it surfaces as an opaque
    // invalid-input error and the same write is retried forever.
    if let Err(yadorilink_replica_domain::native_state::AuthorError::SelfHeadBound { path }) =
        state.check_edits(&author.author, &edits)
    {
        return Err(SyncSqliteError::AuthoringRefused {
            refusal: yadorilink_replica_domain::author::AuthoringRefusal::OwnBucketOverCap {
                path,
                count: yadorilink_replica_domain::author::MAX_SELF_HEADS + 1,
            },
        });
    }
    let current = native_store::frontier_entry_get(tx, group_id, &author.author)?;
    let mut seq = match &current {
        None => AuthorSeq::FIRST,
        Some(entry) => entry.seq.checked_next().ok_or_else(|| {
            SyncSqliteError::InvalidInput("author has reached the highest storable sequence".into())
        })?,
    };
    let mut prev = current.map(|entry| entry.tip);

    // One op carries at most `MAX_REMOVES_PER_OP` removals, and one delta may
    // not name a path twice, so a class larger than that is removed by a chain
    // of this author's consecutive deltas, all signed and installed in this
    // transaction. Only the last delta carries the puts, so a peer that has
    // admitted a prefix of the chain still shows the content as present, never
    // as lost, and the path is absent (or holds the put) only once every head
    // of the class is gone. When the mutation is part of a recursive operation
    // every delta of the chain is tagged with consecutive part indexes.
    let max_removes = yadorilink_replica_domain::signed_delta::MAX_REMOVES_PER_OP;
    let rounds = chain_rounds(&edits);
    let mut puts = std::collections::BTreeMap::new();
    let mut installed = std::collections::BTreeMap::new();
    let mut obligations = std::collections::BTreeMap::new();
    for round in 0..rounds {
        let last_round = round + 1 == rounds;
        let mut ops = Vec::new();
        for edit in &edits {
            let removes: Vec<HeadRef> = edit
                .observed
                .chunks(max_removes)
                .nth(round)
                .unwrap_or_default()
                .iter()
                .map(|dot| HeadRef {
                    dot: dot.clone(),
                    provenance: provenance_of(state, &edit.path, dot),
                })
                .collect();
            let put = edit
                .put
                .as_ref()
                .filter(|_| last_round)
                .map(|payload| DeltaPut { version: payload.version });
            if removes.is_empty() && put.is_none() {
                continue;
            }
            ops.push(DeltaOp { path: edit.path.clone(), removes, put });
        }
        let mut delta = NativeDelta {
            recursive_part: recursive_part.map(|part| {
                yadorilink_replica_domain::signed_delta::RecursivePart {
                    part_index: part.part_index + round as u32,
                    ..part
                }
            }),
            group_id: group_id.clone(),
            author: author.author.clone(),
            seq,
            prev,
            ops,
            signature: [0u8; 64],
        };
        delta.sign(author.signing_key);
        let (_, installed_heads) = native_store::install_authored_delta(
            tx,
            group_id,
            &delta,
            &author.signing_key.verifying_key(),
            native_store::Admission::of(author.capture),
        )?;
        let armed = crate::native_desired_state::arm_projection_for_delta(
            tx,
            group_id.as_str(),
            &delta,
            true,
        )?;
        installed.extend(installed_heads);
        obligations.extend(armed);
        let (dot, provenance) = (delta.dot(), delta.delta_hash());
        puts.extend(delta.ops.iter().filter(|op| op.put.is_some()).map(|op| {
            (
                op.path.clone(),
                yadorilink_replica_domain::native_plan::NativeRowIdentity {
                    source_path: op.path.clone(),
                    dot: dot.clone(),
                    provenance,
                },
            )
        }));
        if !last_round {
            seq = seq.checked_next().ok_or_else(|| {
                SyncSqliteError::InvalidInput(
                    "author has reached the highest storable sequence".into(),
                )
            })?;
            prev = Some(provenance);
        }
    }
    Ok(AuthoredPuts { puts, installed, armed: obligations })
}

/// What [`author_forks`] signed and what it left for later.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ForkAuthored {
    /// Deltas signed and installed.
    pub deltas: usize,
    /// Paths that wait for a version record to arrive.
    pub waiting_for_records: usize,
    /// Paths whose fork cannot be made; they stay contested.
    pub refused: usize,
}

/// Signs, as `author`, the deltas by which the losing heads of `owner` move to
/// their copy paths ([`yadorilink_replica_domain::native_fork::plan_forks`]),
/// each installed after the previous in this transaction. With `owner` the
/// author itself this is its own fork; for another owner the caller has
/// checked `fallback_may_fork`.
fn author_forks(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    owner: &yadorilink_replica_domain::author::AuthorId,
    limits: yadorilink_replica_domain::native_fork::ForkLimits,
    state: &NativeState,
) -> Result<ForkAuthored, SyncSqliteError> {
    refuse_unless_current_author(tx, group_id.as_str(), &author.author)?;
    let mut kinds = std::collections::HashMap::new();
    for heads in state.heads.values() {
        for payload in heads.values() {
            if let std::collections::hash_map::Entry::Vacant(slot) = kinds.entry(payload.version) {
                let info =
                    crate::dag_store::get_file_version(tx, group_id.as_str(), &payload.version)?
                        .map(|version| VersionInfo {
                            kind: version.meta.record_kind,
                            content: Some(version.content_identity()),
                            mode_bridge: version.mode_bridge(),
                        });
                slot.insert(info);
            }
        }
    }
    let plan = yadorilink_replica_domain::native_fork::plan_forks(
        state,
        owner,
        &author.author,
        |version| kinds.get(version).copied().flatten(),
        limits,
    )
    .map_err(|error| SyncSqliteError::InvalidInput(error.to_string()))?;
    let mut out = ForkAuthored {
        deltas: 0,
        waiting_for_records: plan.waiting_for_records.len(),
        refused: plan.refused.len(),
    };
    if plan.deltas.is_empty() {
        return Ok(out);
    }
    let current = native_store::frontier_entry_get(tx, group_id, &author.author)?;
    let mut seq = match &current {
        None => AuthorSeq::FIRST,
        Some(entry) => entry.seq.checked_next().ok_or_else(|| {
            SyncSqliteError::InvalidInput("author has reached the highest storable sequence".into())
        })?,
    };
    let mut prev = current.map(|entry| entry.tip);
    for planned in plan.deltas {
        let ops = planned
            .ops
            .into_iter()
            .map(|op| DeltaOp { path: op.path, removes: op.removes, put: op.put })
            .collect();
        let mut delta = NativeDelta {
            recursive_part: None,
            group_id: group_id.clone(),
            author: author.author.clone(),
            seq,
            prev,
            ops,
            signature: [0u8; 64],
        };
        delta.sign(author.signing_key);
        native_store::install_authored_delta(
            tx,
            group_id,
            &delta,
            &author.signing_key.verifying_key(),
            native_store::Admission::of(author.capture),
        )?;
        crate::native_desired_state::arm_projection_for_delta(tx, group_id.as_str(), &delta, true)?;
        out.deltas += 1;
        prev = Some(delta.delta_hash());
        seq = seq.checked_next().ok_or_else(|| {
            SyncSqliteError::InvalidInput("author has reached the highest storable sequence".into())
        })?;
    }
    Ok(out)
}

/// [`author_forks`] for every author with a head in the group that `eligible`
/// admits (told whether the author is closed): the author itself always, any
/// other only under the fallback rule the caller applies. One write, owners in
/// author order.
pub fn author_all_forks(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    eligible: &dyn Fn(&yadorilink_replica_domain::author::AuthorId, bool) -> bool,
) -> Result<ForkAuthored, SyncSqliteError> {
    // Nothing new is contested since the last pass looked: nothing to read.
    if !crate::native_contest_candidates::has_unattempted(tx, group_id.as_str())? {
        return Ok(ForkAuthored::default());
    }
    let limits = yadorilink_replica_domain::native_fork::ForkLimits {
        max_ops_per_delta: BULK_DELTA_MAX_OPS,
        max_bytes_per_delta: BULK_DELTA_MAX_BYTES,
    };
    let mut total = ForkAuthored::default();
    // A fork can put a head where a larger version already stands, which is a
    // contest of its own at the copy path: plan again from the new state until
    // a round authors nothing, so what it created is not marked looked-at.
    for _round in 0..16 {
        let mut state = native_store::load_state(tx, group_id)?;
        let owners: std::collections::BTreeSet<_> = state
            .heads
            .values()
            .flat_map(|heads| heads.keys().map(|dot| dot.author.clone()))
            .collect();
        let mut round = ForkAuthored::default();
        for owner in owners {
            let own = owner == author.author;
            if !own && !eligible(&owner, native_store::is_closed(tx, group_id, &owner)?) {
                continue;
            }
            let done = author_forks(tx, group_id, author, &owner, limits, &state)?;
            if done.deltas > 0 {
                state = native_store::load_state(tx, group_id)?;
            }
            round.deltas += done.deltas;
            round.waiting_for_records += done.waiting_for_records;
            round.refused += done.refused;
        }
        total.deltas += round.deltas;
        total.waiting_for_records = round.waiting_for_records;
        total.refused = round.refused;
        if round.deltas == 0 {
            break;
        }
    }
    crate::native_contest_candidates::finish_attempt(tx, group_id.as_str())?;
    Ok(total)
}

/// The number of consecutive deltas the removals of `edits` need: one per
/// `MAX_REMOVES_PER_OP` of the largest class, and at least one.
fn chain_rounds(edits: &[PathEdit]) -> usize {
    let max_removes = yadorilink_replica_domain::signed_delta::MAX_REMOVES_PER_OP;
    edits.iter().map(|edit| edit.observed.len().div_ceil(max_removes)).max().unwrap_or(0).max(1)
}

fn provenance_of(state: &NativeState, path: &SyncPath, dot: &Dot) -> DeltaHash {
    state.heads_at(path).find(|h| h.dot == *dot).map(|h| h.payload.provenance).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
    use yadorilink_replica_domain::ids::DeviceId;

    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        crate::replica_tables::init(&c).unwrap();
        c
    }

    fn group() -> FolderGroupId {
        FolderGroupId("g1".into())
    }

    fn author() -> (LocalAuthorOwned, ed25519_dalek::SigningKey) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let author = yadorilink_replica_domain::author::AuthorId {
            device: DeviceId("device-a".into()),
            incarnation: IncarnationId([1u8; 16]),
        };
        (LocalAuthorOwned { author }, signing_key)
    }

    /// `LocalAuthor` borrows its signing key; this test-only owned twin
    /// lets each test build one `SigningKey` and hand out `LocalAuthor`
    /// borrows from it without fighting the borrow checker across
    /// multiple `author_op` calls.
    struct LocalAuthorOwned {
        author: AuthorId,
    }

    impl LocalAuthorOwned {
        fn as_local<'a>(&self, key: &'a ed25519_dalek::SigningKey) -> LocalAuthor<'a> {
            LocalAuthor { author: self.author.clone(), signing_key: key, capture: None }
        }
    }

    /// The versions the writer was looking at: the native winner of every
    /// path the op touches, as an index row showing the current winner would
    /// say.
    fn seeing_winner(c: &Connection, ops: &[Op]) -> Vec<Shown> {
        use yadorilink_replica_domain::native_state::{resolve_winner, LiveHead};
        let state = native_store::load_state(c, &group()).unwrap();
        ops.iter()
            .map(|op| {
                let mut shown = Shown::default();
                let paths: Vec<&SyncPath> = match op {
                    Op::Put { path, .. } | Op::Delete { path } => vec![path],
                    Op::Move { from, to, .. } => vec![from, to],
                };
                for path in paths {
                    let heads: Vec<LiveHead> = state.heads_at(path).collect();
                    shown.versions.insert(
                        path.clone(),
                        resolve_winner(heads.iter()).map(|h| h.payload.version),
                    );
                }
                shown
            })
            .collect()
    }

    fn author_local_op(
        c: &Connection,
        local: &LocalAuthor<'_>,
        op: &Op,
        _row_path: &SyncPath,
    ) -> Result<(), SyncSqliteError> {
        author_op_shown(c, &group(), local, op, &seeing_winner(c, std::slice::from_ref(op))[0])
            .map(|_| ())
    }

    fn author_local_part(
        c: &Connection,
        local: &LocalAuthor<'_>,
        part: &[(Op, SyncPath)],
    ) -> Result<(), SyncSqliteError> {
        let ops: Vec<Op> = part.iter().map(|(op, _)| op.clone()).collect();
        author_part_shown(c, &group(), local, &ops, &seeing_winner(c, &ops), None).map(|_| ())
    }

    fn shown_of(path: &SyncPath, version: VersionHash) -> Shown {
        Shown { versions: [(path.clone(), Some(version))].into(), class: None }
    }

    fn direct_put(path: &str, version_byte: u8) -> Op {
        Op::Put { path: SyncPath(path.into()), version: VersionHash([version_byte; 32]) }
    }

    #[test]
    fn create_edit_delete_reflected_in_native_state_and_frontier_advances() {
        let c = conn();
        let (owned, key) = author();
        let local = owned.as_local(&key);

        author_local_op(&c, &local, &direct_put("x", 1), &SyncPath("x".into())).unwrap();
        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(state.heads_at(&SyncPath("x".into())).count(), 1);
        let frontier = native_store::load_frontier(&c, &group()).unwrap();
        assert_eq!(frontier[&owned.author].seq, AuthorSeq(1));

        author_local_op(&c, &local, &direct_put("x", 2), &SyncPath("x".into())).unwrap();
        let state = native_store::load_state(&c, &group()).unwrap();
        let heads: Vec<_> = state.heads_at(&SyncPath("x".into())).collect();
        assert_eq!(
            heads.len(),
            1,
            "an ordinary edit supersedes the prior head, not adds beside it"
        );
        assert_eq!(heads[0].payload.version, VersionHash([2u8; 32]));
        let frontier = native_store::load_frontier(&c, &group()).unwrap();
        assert_eq!(frontier[&owned.author].seq, AuthorSeq(2));

        author_local_op(
            &c,
            &local,
            &Op::Delete { path: SyncPath("x".into()) },
            &SyncPath("x".into()),
        )
        .unwrap();
        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(state.heads_at(&SyncPath("x".into())).count(), 0);
        let frontier = native_store::load_frontier(&c, &group()).unwrap();
        assert_eq!(frontier[&owned.author].seq, AuthorSeq(3));
    }

    /// An author whose own two heads at a path are versions the writer was
    /// not shown cannot put a third: the refusal is the typed one the capture
    /// layer turns into a conflict copy, and nothing is written.
    #[test]
    fn a_third_own_head_at_a_path_is_refused_as_over_cap() {
        let c = conn();
        let (owned, key) = author();
        let local = owned.as_local(&key);
        let x = SyncPath("x".into());
        let blind = Shown { versions: [(x.clone(), None)].into(), class: None };

        for version in [1u8, 2] {
            author_op_shown(&c, &group(), &local, &direct_put("x", version), &blind).unwrap();
        }
        let before = native_store::load_frontier(&c, &group()).unwrap();
        let refused =
            author_op_shown(&c, &group(), &local, &direct_put("x", 3), &blind).unwrap_err();

        assert!(
            matches!(
                refused,
                SyncSqliteError::AuthoringRefused {
                    refusal:
                        yadorilink_replica_domain::author::AuthoringRefusal::OwnBucketOverCap { .. }
                }
            ),
            "{refused:?}"
        );
        assert_eq!(native_store::load_frontier(&c, &group()).unwrap(), before, "nothing written");
    }

    #[test]
    fn rename_removes_at_source_and_puts_at_destination() {
        let c = conn();
        let (owned, key) = author();
        let local = owned.as_local(&key);

        author_local_op(&c, &local, &direct_put("old", 1), &SyncPath("old".into())).unwrap();
        author_local_op(
            &c,
            &local,
            &Op::Move {
                from: SyncPath("old".into()),
                to: SyncPath("new".into()),
                version: VersionHash([1u8; 32]),
            },
            &SyncPath("new".into()),
        )
        .unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(
            state.heads_at(&SyncPath("old".into())).count(),
            0,
            "source must be empty after the rename"
        );
        let new_heads: Vec<_> = state.heads_at(&SyncPath("new".into())).collect();
        assert_eq!(new_heads.len(), 1);
        assert_eq!(new_heads[0].payload.version, VersionHash([1u8; 32]));
    }

    #[test]
    fn chain_advances_correctly_across_many_authored_ops() {
        let c = conn();
        let (owned, key) = author();
        let local = owned.as_local(&key);

        for i in 1..=5u8 {
            author_local_op(&c, &local, &direct_put("x", i), &SyncPath("x".into())).unwrap();
        }
        let frontier = native_store::load_frontier(&c, &group()).unwrap();
        assert_eq!(frontier[&owned.author].seq, AuthorSeq(5));
        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(state.context_of(&owned.author), Some(AuthorSeq(5)));
    }

    fn author_b() -> (LocalAuthorOwned, ed25519_dalek::SigningKey) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]);
        let author =
            AuthorId { device: DeviceId("device-b".into()), incarnation: IncarnationId([1u8; 16]) };
        (LocalAuthorOwned { author }, signing_key)
    }

    /// Directly installs a create at `path` with an *empty* observed set,
    /// bypassing `author_op`'s ordinary-edit assumption
    /// (`observed = everything currently shown`) -- needed to simulate a
    /// genuinely concurrent write on a single shared `NativeState` (as two
    /// independent replicas would each capture their own write before
    /// either has seen the other's), the same way P1V's differential tests
    /// built a real two-head conflict.
    fn concurrent_create(
        c: &Connection,
        local: &LocalAuthor<'_>,
        path: &SyncPath,
        version_byte: u8,
    ) {
        concurrent_create_version(c, local, path, VersionHash([version_byte; 32]));
    }

    fn concurrent_create_version(
        c: &Connection,
        local: &LocalAuthor<'_>,
        path: &SyncPath,
        version: VersionHash,
    ) {
        let mut delta = NativeDelta {
            recursive_part: None,
            group_id: group(),
            author: local.author.clone(),
            seq: AuthorSeq::FIRST,
            prev: None,
            ops: vec![DeltaOp {
                path: path.clone(),
                removes: vec![],
                put: Some(DeltaPut { version }),
            }],
            signature: [0u8; 64],
        };
        delta.sign(local.signing_key);
        native_store::install_verified_delta(
            c,
            &group(),
            &delta,
            &local.signing_key.verifying_key(),
        )
        .unwrap();
    }

    /// The longest device id the replication layer accepts.
    const MAX_DEVICE_ID_BYTES: usize = 256;

    fn author_named(index: usize, device_bytes: usize) -> AuthorId {
        AuthorId {
            device: DeviceId(format!("{index:0>device_bytes$}")),
            incarnation: IncarnationId([1u8; 16]),
        }
    }

    /// The bytes one op takes in the canonical delta encoding: a delta of that op
    /// less a delta of none.
    fn encoded_op_bytes(op: DeltaOp) -> usize {
        let delta = |ops: Vec<DeltaOp>| NativeDelta {
            recursive_part: None,
            group_id: group(),
            author: author_named(0, 1),
            seq: AuthorSeq::FIRST,
            prev: None,
            ops,
            signature: [0u8; 64],
        };
        delta(vec![op]).to_wire_bytes().len() - delta(Vec::new()).to_wire_bytes().len()
    }

    /// The estimate that cuts a bulk run is never under the canonical encoding of
    /// the op it stands for, whatever the lengths of the device ids the removals
    /// name and however many there are: the estimate is checked against the
    /// largest op that can be signed from the heads at the path.
    #[test]
    fn the_estimate_of_an_edit_is_never_under_its_encoded_op() {
        use crate::native_store_reference::support::Rng;
        use yadorilink_replica_domain::signed_delta::MAX_REMOVES_PER_OP;
        let mut rng = Rng(21);
        for round in 0..200 {
            let heads = rng.below(2 * MAX_REMOVES_PER_OP + 1);
            let path = SyncPath("p".repeat(1 + rng.below(4000)));
            let mut state = NativeState::default();
            let mut dots = Vec::new();
            for i in 0..heads {
                // Mostly the longest ids, so a cut that took the first heads met would fall short.
                let len = if rng.chance(70) { MAX_DEVICE_ID_BYTES } else { 1 + rng.below(255) };
                let payload = HeadPayload {
                    version: VersionHash([1u8; 32]),
                    provenance: DeltaHash([i as u8; 32]),
                };
                dots.push(
                    state.put(&author_named(i, len), path.clone(), &[], payload).expect("put"),
                );
            }
            let observed: Vec<Dot> = dots
                .iter()
                .filter(|_| rng.chance(40))
                .take(2 * MAX_REMOVES_PER_OP)
                .cloned()
                .collect();
            let put = rng.chance(50).then(|| HeadPayload {
                version: VersionHash([2u8; 32]),
                provenance: DeltaHash::default(),
            });
            let edit =
                PathEdit { path: path.clone(), observed: observed.clone(), put: put.clone() };

            let mut sorted: Vec<&Dot> = observed.iter().collect();
            sorted.sort_by_key(|dot| std::cmp::Reverse(dot.author.device.0.len()));
            let removes: Vec<HeadRef> = sorted
                .into_iter()
                .take(MAX_REMOVES_PER_OP)
                .map(|dot| HeadRef {
                    dot: dot.clone(),
                    provenance: provenance_of(&state, &path, dot),
                })
                .collect();
            let op = DeltaOp {
                path: path.clone(),
                removes,
                put: put.map(|payload| DeltaPut { version: payload.version }),
            };
            let encoded = encoded_op_bytes(op);
            let estimated = estimated_edit_bytes(&edit);
            assert!(
                estimated >= encoded,
                "round {round}: estimated {estimated} < encoded {encoded}"
            );
        }
    }

    /// A bulk run at long paths, each op superseding a full class of heads, with
    /// the longest device ids, is signed as deltas that each sum to no more than
    /// their estimate and fit one replication item: nothing authored can fail
    /// to be delivered.
    #[test]
    fn a_worst_case_bulk_run_is_signed_within_the_estimate_and_the_item_budget() {
        use yadorilink_replica_domain::signed_delta::MAX_REMOVES_PER_OP;
        let c = conn();
        let (owned, key) = author();
        let local = owned.as_local(&key);
        // Enough ops of full classes to need several deltas; the bound on ops per
        // delta is covered by the property above and the bulk tests.
        let paths: Vec<SyncPath> =
            (0..128).map(|i| SyncPath(format!("{}/{i:04}", "d".repeat(3000)))).collect();
        let old = VersionHash([1u8; 32]);
        let mut state = native_store::load_state(&c, &group()).unwrap();
        let mut classes = Vec::new();
        for path in &paths {
            let mut class = Vec::new();
            for i in 0..MAX_REMOVES_PER_OP {
                let payload = HeadPayload { version: old, provenance: DeltaHash([i as u8; 32]) };
                class.push(
                    state
                        .put(&author_named(i + 1, MAX_DEVICE_ID_BYTES), path.clone(), &[], payload)
                        .unwrap(),
                );
            }
            class.sort();
            classes.push(class);
        }
        native_store::install_state(&c, &group(), &state).unwrap();
        let ops: Vec<Op> = paths
            .iter()
            .map(|path| Op::Put { path: path.clone(), version: VersionHash([3u8; 32]) })
            .collect();
        let witnesses: Vec<NativeCaptureWitness> = paths
            .iter()
            .zip(&classes)
            .map(|(path, class)| NativeCaptureWitness {
                path: path.clone(),
                shown_class: class.clone(),
                shown_version: Some(old),
                row_version: Some(old),
            })
            .collect();
        let items: Vec<BulkOp<'_>> = ops
            .iter()
            .zip(&witnesses)
            .map(|(op, witness)| BulkOp { op, witness: Some(witness) })
            .collect();
        author_bulk_group(&c, &group(), &local, &items).unwrap();

        let signed = native_store::load_frontier(&c, &group()).unwrap()[&owned.author].seq.get();
        assert!(signed >= 2, "a run this size is cut into several deltas: {signed}");
        for seq in 1..=signed {
            let body = native_store::fetch_delta_body(&c, &group(), &owned.author, AuthorSeq(seq))
                .unwrap()
                .unwrap();
            assert!(body.len() <= yadorilink_replica_domain::protocol5::MAX_BATCH_ITEM_BYTES);
            let delta = NativeDelta::from_wire_bytes(&body).unwrap();
            let estimated: usize = delta
                .ops
                .iter()
                .map(|op| {
                    let observed = op.removes.iter().map(|r| r.dot.clone()).collect();
                    let edit = PathEdit { path: op.path.clone(), observed, put: None };
                    estimated_edit_bytes(&edit)
                })
                .sum();
            let header = NativeDelta { ops: Vec::new(), ..delta.clone() }.to_wire_bytes().len();
            let encoded_ops = body.len() - header;
            assert!(estimated >= encoded_ops, "delta {seq}: estimated {estimated} < {encoded_ops}");
        }
    }

    fn delete_op(path: &str) -> Op {
        Op::Delete { path: SyncPath(path.into()) }
    }

    /// `rm -rf dir` captured as one part with a
    /// Delete per entry lands as one atomic native delta removing every
    /// entry under the prefix.
    #[test]
    fn recursive_delete_part_removes_every_entry_atomically() {
        let c = conn();
        let (owned, key) = author();
        let local = owned.as_local(&key);

        author_local_op(&c, &local, &direct_put("dir", 1), &SyncPath("dir".into())).unwrap();
        author_local_op(&c, &local, &direct_put("dir/a", 2), &SyncPath("dir/a".into())).unwrap();
        author_local_op(&c, &local, &direct_put("dir/b", 3), &SyncPath("dir/b".into())).unwrap();

        let part = vec![
            (delete_op("dir"), SyncPath("dir".into())),
            (delete_op("dir/a"), SyncPath("dir/a".into())),
            (delete_op("dir/b"), SyncPath("dir/b".into())),
        ];
        author_local_part(&c, &local, &part).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(state.heads_at(&SyncPath("dir".into())).count(), 0);
        assert_eq!(state.heads_at(&SyncPath("dir/a".into())).count(), 0);
        assert_eq!(state.heads_at(&SyncPath("dir/b".into())).count(), 0);
        // One atomic delta for the whole part, not three.
        let frontier = native_store::load_frontier(&c, &group()).unwrap();
        assert_eq!(
            frontier[&owned.author].seq,
            AuthorSeq(4),
            "3 creates + 1 atomic recursive delete = seq 4"
        );
    }

    /// A single-file rename only ever touches the
    /// renamed entry -- the per-entry op expansion means this needs no
    /// special casing here, it falls out of `edits_for_op` applied once.
    #[test]
    fn single_file_rename_part_touches_only_the_renamed_entry() {
        let c = conn();
        let (owned, key) = author();
        let local = owned.as_local(&key);
        author_local_op(&c, &local, &direct_put("dir/a", 1), &SyncPath("dir/a".into())).unwrap();

        let part = vec![(
            Op::Move {
                from: SyncPath("dir/a".into()),
                to: SyncPath("dir2/a".into()),
                version: VersionHash([1u8; 32]),
            },
            SyncPath("dir2/a".into()),
        )];
        author_local_part(&c, &local, &part).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(state.heads_at(&SyncPath("dir/a".into())).count(), 0);
        assert_eq!(state.heads_at(&SyncPath("dir2/a".into())).count(), 1);
    }

    /// A directory move is a per-entry Delete/Put expansion for
    /// several entries at once, atomically -- proving the multi-entry case
    /// (not just a single file) needs no logic beyond what `edits_for_op`
    /// already provides per entry.
    #[test]
    fn directory_move_part_moves_every_entry_atomically() {
        let c = conn();
        let (owned, key) = author();
        let local = owned.as_local(&key);
        author_local_op(&c, &local, &direct_put("dir/a", 1), &SyncPath("dir/a".into())).unwrap();
        author_local_op(&c, &local, &direct_put("dir/b", 2), &SyncPath("dir/b".into())).unwrap();

        let part = vec![
            (
                Op::Move {
                    from: SyncPath("dir/a".into()),
                    to: SyncPath("dir2/a".into()),
                    version: VersionHash([1u8; 32]),
                },
                SyncPath("dir2/a".into()),
            ),
            (
                Op::Move {
                    from: SyncPath("dir/b".into()),
                    to: SyncPath("dir2/b".into()),
                    version: VersionHash([2u8; 32]),
                },
                SyncPath("dir2/b".into()),
            ),
        ];
        author_local_part(&c, &local, &part).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(state.heads_at(&SyncPath("dir/a".into())).count(), 0);
        assert_eq!(state.heads_at(&SyncPath("dir/b".into())).count(), 0);
        assert_eq!(state.heads_at(&SyncPath("dir2/a".into())).count(), 1);
        assert_eq!(state.heads_at(&SyncPath("dir2/b".into())).count(), 1);
    }

    /// A genuine unresolved conflict (2+ live heads, no materialized copy
    /// row) at a path: an *ordinary* edit/delete there must supersede only
    /// the winner, never the concurrent loser it never observed (a write never
    /// supersedes a version its author did not observe).
    #[test]
    fn ordinary_edit_at_a_conflicted_path_touches_only_the_winner() {
        let c = conn();
        let (owned_a, key_a) = author();
        let (owned_b, key_b) = author_b();
        let a = owned_a.as_local(&key_a);
        let b = owned_b.as_local(&key_b);

        concurrent_create(&c, &a, &SyncPath("x".into()), 2); // winner (higher version)
        concurrent_create(&c, &b, &SyncPath("x".into()), 1); // loser

        // a edits the file it sees (the winner) at its real name.
        author_local_op(&c, &a, &direct_put("x", 3), &SyncPath("x".into())).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        let heads: Vec<_> = state.heads_at(&SyncPath("x".into())).collect();
        assert_eq!(
            heads.len(),
            2,
            "the concurrent loser must survive an edit that never observed it"
        );
        let versions: std::collections::BTreeSet<VersionHash> =
            heads.iter().map(|h| h.payload.version).collect();
        assert!(versions.contains(&VersionHash([3u8; 32])), "the edit itself must be live");
        assert!(
            versions.contains(&VersionHash([1u8; 32])),
            "the untouched loser must still be live"
        );
    }

    /// A peer's head that arrived and has not been projected here is not
    /// something the writer saw: an edit of the content the row still shows
    /// leaves it live beside the edit, whatever its version.
    #[test]
    fn an_edit_never_supersedes_a_head_the_row_did_not_show() {
        let c = conn();
        let (owned_a, key_a) = author();
        let (owned_b, key_b) = author_b();
        let a = owned_a.as_local(&key_a);
        let b = owned_b.as_local(&key_b);
        let x = SyncPath("x".into());

        // The peer's newer head is live; the row this device edits still
        // shows version 1, which the peer already superseded (no longer live).
        author_local_op(&c, &b, &direct_put("x", 9), &x).unwrap();

        let shown = shown_of(&x, VersionHash([1u8; 32]));
        author_op_shown(&c, &group(), &a, &direct_put("x", 3), &shown).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        let versions: std::collections::BTreeSet<VersionHash> =
            state.heads_at(&x).map(|h| h.payload.version).collect();
        assert_eq!(
            versions,
            [VersionHash([9u8; 32]), VersionHash([3u8; 32])].into_iter().collect()
        );
    }

    /// The head an edit supersedes is the one whose version the row shows,
    /// even when another head would win the name.
    #[test]
    fn an_edit_supersedes_the_head_of_the_shown_version_not_the_winner() {
        let c = conn();
        let (owned_a, key_a) = author();
        let (owned_b, key_b) = author_b();
        let a = owned_a.as_local(&key_a);
        let b = owned_b.as_local(&key_b);
        let x = SyncPath("x".into());
        concurrent_create(&c, &a, &x, 1); // shown, the lower version
        concurrent_create(&c, &b, &x, 2); // unseen, the winner

        let shown = shown_of(&x, VersionHash([1u8; 32]));
        author_op_shown(&c, &group(), &a, &direct_put("x", 3), &shown).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        let versions: std::collections::BTreeSet<VersionHash> =
            state.heads_at(&x).map(|h| h.payload.version).collect();
        assert_eq!(
            versions,
            [VersionHash([2u8; 32]), VersionHash([3u8; 32])].into_iter().collect()
        );
    }

    /// Deleting content native no longer shows removes nothing and authors
    /// nothing.
    #[test]
    fn deleting_a_version_native_no_longer_shows_authors_no_delta() {
        let c = conn();
        let (owned_a, key_a) = author();
        let (owned_b, key_b) = author_b();
        let a = owned_a.as_local(&key_a);
        let b = owned_b.as_local(&key_b);
        let x = SyncPath("x".into());
        author_local_op(&c, &b, &direct_put("x", 9), &x).unwrap();
        let before = native_store::load_frontier(&c, &group()).unwrap();

        let shown = shown_of(&x, VersionHash([1u8; 32]));
        author_op_shown(&c, &group(), &a, &Op::Delete { path: x.clone() }, &shown).unwrap();

        assert_eq!(native_store::load_frontier(&c, &group()).unwrap(), before);
        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(state.heads_at(&x).count(), 1, "the peer's head is untouched");
    }

    fn author_c() -> (LocalAuthorOwned, ed25519_dalek::SigningKey) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let author =
            AuthorId { device: DeviceId("device-c".into()), incarnation: IncarnationId([1u8; 16]) };
        (LocalAuthorOwned { author }, signing_key)
    }

    fn dot_of_device(c: &Connection, path: &str, device: &str) -> Dot {
        native_store::load_state(c, &group())
            .unwrap()
            .heads_at(&SyncPath(path.into()))
            .find(|h| h.dot.author.device.0 == device)
            .expect("that device has a head there")
            .dot
    }

    fn versions_at(c: &Connection, path: &str) -> std::collections::BTreeSet<VersionHash> {
        native_store::load_state(c, &group())
            .unwrap()
            .heads_at(&SyncPath(path.into()))
            .map(|h| h.payload.version)
            .collect()
    }

    /// A head of the same content that arrived after the capture was never
    /// seen by the writer: it survives the delete.
    #[test]
    fn a_head_of_the_same_content_that_arrived_after_the_capture_survives() {
        let c = conn();
        let (oa, ka) = author();
        let (ob, kb) = author_b();
        let (oc, kc) = author_c();
        let x = SyncPath("x".into());
        concurrent_create(&c, &ob.as_local(&kb), &x, 2);
        concurrent_create(&c, &oc.as_local(&kc), &x, 2);
        let captured_only_b = [dot_of_device(&c, "x", "device-b")];
        let witness = NativeCaptureWitness {
            path: x.clone(),
            shown_class: captured_only_b.to_vec(),
            shown_version: Some(VersionHash([2u8; 32])),
            row_version: Some(VersionHash([2u8; 32])),
        };

        author_op_witnessed(
            &c,
            &group(),
            &oa.as_local(&ka),
            &Op::Delete { path: SyncPath("x".into()) },
            Some(&witness),
        )
        .unwrap();

        let devices: Vec<String> = native_store::load_state(&c, &group())
            .unwrap()
            .heads_at(&SyncPath("x".into()))
            .map(|h| h.dot.author.device.0.clone())
            .collect();
        assert!(
            devices.iter().any(|d| d == "device-c"),
            "c's head arrived after the capture and must live: {devices:?}"
        );
        assert!(
            !devices.iter().any(|d| d == "device-b"),
            "b's head was captured and must be gone: {devices:?}"
        );
        assert!(versions_at(&c, "x").contains(&VersionHash([2u8; 32])));
    }

    /// An ordinary edit of content two heads hold leaves no copy of the old
    /// content behind.
    #[test]
    fn editing_content_held_by_two_heads_leaves_no_copy_of_the_old_content() {
        let c = conn();
        let (oa, ka) = author();
        let (ob, kb) = author_b();
        let x = SyncPath("x".into());
        concurrent_create(&c, &oa.as_local(&ka), &x, 1);
        concurrent_create(&c, &ob.as_local(&kb), &x, 1);
        let shown = shown_of(&x, VersionHash([1u8; 32]));

        author_op_shown(&c, &group(), &oa.as_local(&ka), &direct_put("x", 3), &shown).unwrap();

        assert_eq!(versions_at(&c, "x"), [VersionHash([3u8; 32])].into_iter().collect());
    }

    /// The index row is not read again at commit: what the capture recorded is
    /// what the writer saw, so a row that changed in between cannot redirect
    /// which content the edit supersedes.
    #[test]
    fn the_witness_not_the_row_at_commit_decides_which_content_was_shown() {
        let c = conn();
        let (oa, ka) = author();
        let (ob, kb) = author_b();
        let x = SyncPath("x".into());
        concurrent_create(&c, &oa.as_local(&ka), &x, 1);
        concurrent_create(&c, &ob.as_local(&kb), &x, 2);
        let seen_v1 = NativeCaptureWitness {
            path: x.clone(),
            shown_class: vec![dot_of_device(&c, "x", "device-a")],
            shown_version: Some(VersionHash([1u8; 32])),
            row_version: Some(VersionHash([1u8; 32])),
        };
        // The index row at x has meanwhile been replaced by content 2's.
        let shown = shown_versions(
            &c,
            &group(),
            &author().0.author,
            &[Op::Delete { path: x.clone() }],
            &[Some(&seen_v1)],
        )
        .unwrap();
        assert_eq!(shown[0].versions.get(&x), Some(&Some(VersionHash([1u8; 32]))));
    }

    /// 65 devices created identical content at `x`; one replica holds every head and its
    /// user deletes the single visible file. Every head goes, however many ops that takes, and
    /// a peer admitting the produced deltas one by one ends with `x` absent too.
    #[test]
    fn deleting_a_class_larger_than_an_op_can_carry_removes_every_head_on_both_replicas() {
        use yadorilink_replica_domain::signed_delta::MAX_REMOVES_PER_OP;
        let c = conn();
        let (oa, ka) = author();
        let x = SyncPath("x".into());
        let mut state = NativeState::new();
        for i in 0..(MAX_REMOVES_PER_OP + 1) {
            let who = AuthorId {
                device: DeviceId(format!("dev-{i:03}")),
                incarnation: IncarnationId([1u8; 16]),
            };
            state
                .put(
                    &who,
                    x.clone(),
                    &[],
                    HeadPayload {
                        version: VersionHash([1u8; 32]),
                        provenance: DeltaHash([i as u8 + 1; 32]),
                    },
                )
                .unwrap();
        }
        native_store::install_state(&c, &group(), &state).unwrap();
        let peer = conn();
        native_store::install_state(&peer, &group(), &state).unwrap();
        let shown = shown_of(&x, VersionHash([1u8; 32]));

        author_op_shown(&c, &group(), &oa.as_local(&ka), &Op::Delete { path: x.clone() }, &shown)
            .unwrap();

        assert_eq!(native_store::load_state(&c, &group()).unwrap().heads_at(&x).count(), 0);

        // Every delta a peer can decode, admitted one by one in sequence order.
        let author_id = oa.author.clone();
        let last = native_store::load_frontier(&c, &group()).unwrap()[&author_id].seq.get();
        assert!(last >= 2, "the class needs more than one delta");
        for n in 1..=last {
            let body = native_store::fetch_delta_body(&c, &group(), &author_id, AuthorSeq(n))
                .unwrap()
                .expect("the delta body is stored");
            let delta =
                NativeDelta::from_wire_bytes(&body).expect("a peer can decode what was authored");
            assert!(delta.ops.iter().all(|op| op.removes.len() <= MAX_REMOVES_PER_OP));
            native_store::install_verified_delta(&peer, &group(), &delta, &ka.verifying_key())
                .unwrap();
            let remaining = native_store::load_state(&peer, &group()).unwrap();
            let expected = if n == last {
                0
            } else {
                MAX_REMOVES_PER_OP + 1 - n as usize * MAX_REMOVES_PER_OP
            };
            assert_eq!(remaining.heads_at(&x).count(), expected);
        }
    }

    /// Every delta of a chained delete is a part of the recursive operation it
    /// belongs to: the removal of each head, whichever chunk it was in, is
    /// attributed to the operation (a folder restore finds the operation by the
    /// head the trashed row showed), and a replica that has admitted only a
    /// prefix of the chain does not report the operation complete.
    #[test]
    fn every_delta_of_a_chained_recursive_delete_carries_the_operation() {
        use yadorilink_replica_domain::recursive_operation::{
            RecursiveOperationId, RecursiveOperationRef,
        };
        use yadorilink_replica_domain::signed_delta::{RecursivePart, MAX_REMOVES_PER_OP};
        let c = conn();
        let (oa, ka) = author();
        let x = SyncPath("x".into());
        let mut state = NativeState::new();
        for i in 0..(MAX_REMOVES_PER_OP + 1) {
            let who = AuthorId {
                device: DeviceId(format!("dev-{i:03}")),
                incarnation: IncarnationId([1u8; 16]),
            };
            let payload = HeadPayload {
                version: VersionHash([1u8; 32]),
                provenance: DeltaHash([i as u8 + 1; 32]),
            };
            state.put(&who, x.clone(), &[], payload).unwrap();
        }
        native_store::install_state(&c, &group(), &state).unwrap();
        let peer = conn();
        native_store::install_state(&peer, &group(), &state).unwrap();

        let operation_id = RecursiveOperationId([5u8; 16]);
        author_part_shown(
            &c,
            &group(),
            &oa.as_local(&ka),
            &[Op::Delete { path: x.clone() }],
            &[shown_of(&x, VersionHash([1u8; 32]))],
            Some(RecursivePart { operation_id, part_index: 0, part_count: 2 }),
        )
        .unwrap();

        let operation = RecursiveOperationRef { author: oa.author.device.clone(), operation_id };
        let last = native_store::load_frontier(&c, &group()).unwrap()[&oa.author].seq.get();
        assert_eq!(last, 2, "the class takes two deltas");
        for n in 1..=last {
            let body = native_store::fetch_delta_body(&c, &group(), &oa.author, AuthorSeq(n))
                .unwrap()
                .unwrap();
            let delta = NativeDelta::from_wire_bytes(&body).unwrap();
            let part = delta.recursive_part.expect("every delta of the chain is tagged");
            assert_eq!(
                (part.operation_id, part.part_index, part.part_count),
                (operation_id, n as u32 - 1, 2)
            );
            for removal in delta.ops.iter().flat_map(|op| &op.removes) {
                assert_eq!(
                    crate::native_recursive_operation::operation_removing(
                        &c,
                        "g1",
                        "x",
                        &removal.provenance.0
                    )
                    .unwrap(),
                    Some(operation.clone()),
                    "the removal of {:?} is attributed",
                    removal.provenance
                );
            }
            native_store::install_verified_delta(&peer, &group(), &delta, &ka.verifying_key())
                .unwrap();
            let complete =
                crate::native_recursive_operation::completeness(&peer, "g1", &operation).unwrap();
            assert_eq!(
                complete
                    == crate::native_recursive_operation::NativeOperationCompleteness::Complete,
                n == last,
                "complete only after every delta of the chain"
            );
        }
    }

    /// A replica admitting the same deltas reaches the author's own frontier entry.
    #[test]
    fn a_remote_admission_reaches_the_same_frontier_entry_as_the_author() {
        let c = conn();
        let peer = conn();
        let (oa, ka) = author();
        let local = oa.as_local(&ka);
        let x = SyncPath("x".into());
        author_local_op(&c, &local, &direct_put("x", 1), &x).unwrap();
        author_local_op(&c, &local, &direct_put("x", 2), &x).unwrap();
        for n in [1, 2] {
            let body = native_store::fetch_delta_body(&c, &group(), &oa.author, AuthorSeq(n))
                .unwrap()
                .unwrap();
            let delta = NativeDelta::from_wire_bytes(&body).unwrap();
            native_store::install_verified_delta(&peer, &group(), &delta, &ka.verifying_key())
                .unwrap();
        }
        let theirs =
            native_store::frontier_entry_get(&peer, &group(), &oa.author).unwrap().unwrap();
        let ours = native_store::frontier_entry_get(&c, &group(), &oa.author).unwrap().unwrap();
        assert_eq!(theirs, ours);
    }

    /// A delta carries one put per path: merging two edits that both put is
    /// refused, never resolved by dropping one of the puts.
    #[test]
    fn merging_two_puts_at_one_path_is_refused_not_dropped() {
        let put = |byte: u8| PathEdit {
            path: SyncPath("x".into()),
            observed: Vec::new(),
            put: Some(HeadPayload {
                version: VersionHash([byte; 32]),
                provenance: DeltaHash::default(),
            }),
        };
        assert!(merge_edits(vec![put(1), put(2)]).is_err());
        let removal = PathEdit { put: None, ..put(3) };
        let merged = merge_edits(vec![removal, put(1)]).unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].put.as_ref().map(|p| p.version), Some(VersionHash([1u8; 32])));
    }

    /// The whole-group read authoring used before it read only the paths it
    /// edits: the reference the differential tests below hold it to.
    fn read_whole_group(
        c: &Connection,
        group_id: &FolderGroupId,
        _paths: &[&SyncPath],
    ) -> Result<NativeState, SyncSqliteError> {
        native_store::load_state(c, group_id)
    }

    fn remote_key(index: usize) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[20 + index as u8; 32])
    }

    fn remote_author(index: usize) -> AuthorId {
        AuthorId {
            device: DeviceId(format!("remote-{index}")),
            incarnation: IncarnationId([index as u8 + 1; 16]),
        }
    }

    /// Installs one delta of remote author `index` on every connection of
    /// `conns`: a put of `version` at `path` superseding `removes` (each with
    /// its live provenance).
    fn remote_delta(
        conns: &[&Connection],
        index: usize,
        path: &SyncPath,
        version: Option<VersionHash>,
        removes: &[Dot],
    ) -> Vec<String> {
        let author = remote_author(index);
        let key = remote_key(index);
        let state = native_store::load_state(conns[0], &group()).unwrap();
        let frontier = native_store::load_frontier(conns[0], &group()).unwrap();
        let entry = frontier.get(&author);
        let live: Vec<_> = state.heads_at(path).collect();
        let removals: Vec<HeadRef> = removes
            .iter()
            .filter_map(|dot| live.iter().find(|head| head.dot == *dot))
            .map(|head| HeadRef { dot: head.dot.clone(), provenance: head.payload.provenance })
            .collect();
        let mut delta = NativeDelta {
            recursive_part: None,
            group_id: group(),
            author,
            seq: entry.map_or(AuthorSeq::FIRST, |e| e.seq.checked_next().unwrap()),
            prev: entry.map(|e| e.tip),
            ops: vec![DeltaOp {
                path: path.clone(),
                removes: removals,
                put: version.map(|version| DeltaPut { version }),
            }],
            signature: [0u8; 64],
        };
        delta.sign(&key);
        conns
            .iter()
            .map(|c| {
                format!(
                    "{:?}",
                    native_store::install_verified_delta(c, &group(), &delta, &key.verifying_key())
                        .map_err(|e| e.to_string())
                )
            })
            .collect()
    }

    /// What a writer looking at the current winner of each path of `ops` was
    /// shown, perturbed at random: another live version, nothing, or a
    /// restricted class of heads.
    fn random_shown(rng: &mut RngRef, c: &Connection, ops: &[Op]) -> Vec<Shown> {
        let state = native_store::load_state(c, &group()).unwrap();
        ops.iter()
            .map(|op| {
                let mut shown = Shown::default();
                for path in op_paths(op) {
                    let heads: Vec<_> = state.heads_at(path).collect();
                    let version = match rng.below(10) {
                        0 | 1 => None,
                        2 => Some(VersionHash([1 + rng.below(4) as u8; 32])),
                        _ if heads.is_empty() => None,
                        _ => Some(heads[rng.below(heads.len())].payload.version),
                    };
                    shown.versions.insert(path.clone(), version);
                }
                let source = op_paths(op)[0];
                if let Some(Some(version)) = shown.versions.get(source).cloned() {
                    if rng.below(10) < 3 {
                        let class: std::collections::BTreeSet<Dot> = state
                            .heads_at(source)
                            .filter(|head| head.payload.version == version)
                            .map(|head| head.dot)
                            .filter(|_| rng.below(10) < 7)
                            .collect();
                        shown.class = Some((source.clone(), class));
                    }
                }
                shown
            })
            .collect()
    }

    fn result_text(result: Result<AuthoredPuts, SyncSqliteError>) -> String {
        match result {
            Ok(puts) => format!("ok {puts:?}"),
            Err(error) => format!("err {error}"),
        }
    }

    type RngRef = crate::native_store_reference::support::Rng;

    const DIFF_PATHS: [&str; 7] = ["a", "a/b", "a/b/c", "a/d", "e", "e/f", "g"];

    fn random_op(rng: &mut RngRef) -> Op {
        let path = |rng: &mut RngRef| SyncPath(DIFF_PATHS[rng.below(DIFF_PATHS.len())].into());
        let version = VersionHash([1 + rng.below(4) as u8; 32]);
        match rng.below(10) {
            0..=4 => Op::Put { path: path(rng), version },
            5..=6 => Op::Delete { path: path(rng) },
            _ => Op::Move { from: path(rng), to: path(rng), version },
        }
    }

    /// What one differential step authored.
    #[derive(Default)]
    struct StepTally {
        authored: usize,
        chained: usize,
    }

    fn live_dots(c: &Connection, path: &SyncPath) -> Vec<Dot> {
        let state = native_store::load_state(c, &group()).unwrap();
        state.heads_at(path).map(|head| head.dot).collect()
    }

    fn remote_step(rng: &mut RngRef, a: &Connection, b: &Connection, label: &str) {
        let path = SyncPath(DIFF_PATHS[rng.below(DIFF_PATHS.len())].into());
        let live: Vec<Dot> =
            live_dots(a, &path).into_iter().filter(|_| rng.below(10) < 6).collect();
        let version = (rng.below(10) < 8).then(|| VersionHash([1 + rng.below(4) as u8; 32]));
        let who = rng.below(2);
        let verdicts = remote_delta(&[a, b], who, &path, version, &live);
        assert_eq!(verdicts[0], verdicts[1], "{label}: remote");
    }

    fn single_op_step(
        rng: &mut RngRef,
        a: &Connection,
        b: &Connection,
        local: &LocalAuthor<'_>,
        label: &str,
    ) -> usize {
        let op = random_op(rng);
        let shown = random_shown(rng, a, std::slice::from_ref(&op));
        let incremental = author_op_shown(a, &group(), local, &op, &shown[0]);
        let reference =
            author_op_shown_reading(b, &group(), local, &op, &shown[0], read_whole_group);
        let (got, want) = (result_text(incremental), result_text(reference));
        assert_eq!(got, want, "{label}: {op:?}");
        usize::from(got.starts_with("ok"))
    }

    /// Returns `(authored, chained)`.
    fn part_step(
        rng: &mut RngRef,
        a: &Connection,
        b: &Connection,
        local: &LocalAuthor<'_>,
        label: &str,
    ) -> (usize, usize) {
        let ops: Vec<Op> = (0..1 + rng.below(4)).map(|_| random_op(rng)).collect();
        let part = ops.clone();
        let shown = random_shown(rng, a, &ops);
        let before = native_store::load_frontier(a, &group()).unwrap();
        let count_new = recursive_part_delta_count_reading(
            a,
            &group(),
            &local.author,
            &part,
            &[],
            native_store::load_heads_at_paths,
        );
        let count_old = recursive_part_delta_count_reading(
            b,
            &group(),
            &local.author,
            &part,
            &[],
            read_whole_group,
        );
        assert_eq!(
            count_new.as_ref().map_err(|e| e.to_string()),
            count_old.as_ref().map_err(|e| e.to_string()),
            "{label}: delta count of {part:?}"
        );
        let incremental = author_part_shown(a, &group(), local, &part, &shown, None);
        let reference =
            author_part_shown_reading(b, &group(), local, &part, &shown, None, read_whole_group);
        let (got, want) = (result_text(incremental), result_text(reference));
        assert_eq!(got, want, "{label}: part {part:?}");
        let after = native_store::load_frontier(a, &group()).unwrap();
        let seq_of = |f: &yadorilink_replica_domain::native_frontier::NativeAuthorFrontier| {
            f.get(&local.author).map_or(0, |e| e.seq.get())
        };
        (usize::from(got.starts_with("ok")), usize::from(seq_of(&after) - seq_of(&before) > 1))
    }

    /// Authoring from the heads at the paths an operation touches signs, byte
    /// for byte, the deltas authoring from the whole group's state signs, and
    /// leaves every persisted row the same: over random sequences of local
    /// puts, deletes, moves, write-throughs of copies and multi-op parts,
    /// interleaved with concurrent remote authors' deltas that make conflicts.
    #[test]
    fn authoring_from_the_touched_heads_matches_authoring_from_the_whole_state() {
        use crate::native_store_reference::support::{dump_native, Rng};
        let (owned, key) = author();
        let local = owned.as_local(&key);
        let mut tally = StepTally::default();
        for seed in 0..300u64 {
            let mut rng = Rng(seed);
            let (a, b) = (conn(), conn());
            for step in 0..28 {
                let label = format!("seed {seed} step {step}");
                match rng.below(100) {
                    0..=39 => remote_step(&mut rng, &a, &b, &label),
                    40..=79 => tally.authored += single_op_step(&mut rng, &a, &b, &local, &label),
                    _ => {
                        let (authored, chained) = part_step(&mut rng, &a, &b, &local, &label);
                        tally.authored += authored;
                        tally.chained += chained;
                    }
                }
                assert_eq!(dump_native(&a), dump_native(&b), "{label}: rows differ");
            }
        }
        assert!(tally.authored > 1500, "only {} authored steps", tally.authored);
    }

    /// A class of more than one op's removal cap of same-version heads is
    /// removed by a chain of deltas; the chain is the same from the touched
    /// heads as from the whole state.
    #[test]
    fn a_class_beyond_the_removal_cap_signs_the_same_chain_from_the_touched_heads() {
        use crate::native_store_reference::support::dump_native;
        let (owned, key) = author();
        let local = owned.as_local(&key);
        let x = SyncPath("x".into());
        let version = VersionHash([7u8; 32]);
        let cap = yadorilink_replica_domain::signed_delta::MAX_REMOVES_PER_OP;
        // Edits of the class, as a lone op and as part of a move.
        for op in [
            Op::Put { path: x.clone(), version: VersionHash([8u8; 32]) },
            Op::Delete { path: x.clone() },
            Op::Move { from: x.clone(), to: SyncPath("y".into()), version },
        ] {
            let (a, b) = (conn(), conn());
            for index in 0..cap + 6 {
                let author = remote_author(index);
                let key = remote_key(index);
                let mut delta = NativeDelta {
                    recursive_part: None,
                    group_id: group(),
                    author,
                    seq: AuthorSeq::FIRST,
                    prev: None,
                    ops: vec![DeltaOp {
                        path: x.clone(),
                        removes: vec![],
                        put: Some(DeltaPut { version }),
                    }],
                    signature: [0u8; 64],
                };
                delta.sign(&key);
                for c in [&a, &b] {
                    native_store::install_verified_delta(c, &group(), &delta, &key.verifying_key())
                        .unwrap();
                }
            }
            let shown = Shown { versions: [(x.clone(), Some(version))].into(), class: None };
            let got = result_text(author_op_shown(&a, &group(), &local, &op, &shown));
            let want = result_text(author_op_shown_reading(
                &b,
                &group(),
                &local,
                &op,
                &shown,
                read_whole_group,
            ));
            assert!(got.starts_with("ok"), "{got}");
            assert_eq!(got, want, "{op:?}");
            assert_eq!(dump_native(&a), dump_native(&b), "{op:?}");
            assert!(
                native_store::load_frontier(&a, &group()).unwrap()[&owned.author].seq
                    > AuthorSeq(1),
                "the removal of {} heads was chained",
                cap + 6
            );
        }
    }

    /// 2000 contested paths are forked by one author in a chain; no prefix of
    /// the chain, admitted by a peer, ever leaves a version without a home: a
    /// removal and the put that keeps its version are always one delta.
    #[test]
    fn fork_of_2000_paths_never_leaves_a_removal_without_its_put() {
        use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
        let (owned, key) = author();
        let local = owned.as_local(&key);
        let (ob, _kb) = author_b();
        let paths: Vec<String> = (0..2000).map(|i| format!("d/f{i:04}")).collect();
        let versions: Vec<FileVersion> = (1..=2)
            .map(|seed| {
                FileVersion::new(
                    vec![yadorilink_replica_domain::file::VersionBlock {
                        hash: yadorilink_replica_domain::ids::BlockHash(vec![seed as u8; 32]),
                        size: 1,
                    }],
                    1,
                    FileMeta {
                        mtime_unix_nanos: seed,
                        unix_mode: Some(0o644),
                        symlink_target: None,
                        record_kind: RecordKind::File,
                        xattrs: Vec::new(),
                    },
                )
            })
            .collect();
        let (a, b) = (conn(), conn());
        let mut state = NativeState::new();
        for (i, path) in paths.iter().enumerate() {
            for (who, version) in [(&owned.author, &versions[0]), (&ob.author, &versions[1])] {
                state
                    .put(
                        who,
                        SyncPath(path.clone()),
                        &[],
                        HeadPayload {
                            version: version.version_hash,
                            provenance: DeltaHash(
                                [version.meta.mtime_unix_nanos as u8 ^ i as u8; 32],
                            ),
                        },
                    )
                    .unwrap();
            }
        }
        for c in [&a, &b] {
            native_store::install_state(c, &group(), &state).unwrap();
            for version in &versions {
                crate::dag_store::put_file_version(c, "g1", version).unwrap();
            }
        }
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        crate::native_contest_candidates::note(&a, "g1", &refs).unwrap();
        assert_eq!(crate::native_contest_candidates::count(&a, "g1").unwrap(), 2000);

        let done = author_all_forks(&a, &group(), &local, &|_, _| false).unwrap();

        assert!(done.deltas >= 1, "{done:?}");
        let forked =
            crate::native_store::load_frontier(&a, &group()).unwrap()[&owned.author].seq.get();
        let before = native_store::load_state(&b, &group()).unwrap();
        let versions_of =
            |state: &NativeState| -> std::collections::BTreeSet<(String, VersionHash)> {
                state
                    .heads
                    .iter()
                    .flat_map(|(path, heads)| {
                        heads.values().map(move |p| (path.as_str().to_owned(), p.version))
                    })
                    .collect()
            };
        let originally: std::collections::BTreeSet<VersionHash> =
            versions.iter().map(|v| v.version_hash).collect();
        let _ = &before;
        let mut seen_at: std::collections::BTreeMap<
            String,
            std::collections::BTreeSet<VersionHash>,
        > = std::collections::BTreeMap::new();
        for (path, version) in versions_of(&before) {
            seen_at.entry(path).or_default().insert(version);
        }
        for seq in 1..=forked {
            let body = native_store::fetch_delta_body(&a, &group(), &owned.author, AuthorSeq(seq))
                .unwrap()
                .unwrap();
            let delta = NativeDelta::from_wire_bytes(&body).unwrap();
            native_store::install_verified_delta(&b, &group(), &delta, &key.verifying_key())
                .unwrap();
            // Every version that was live anywhere is still live somewhere.
            let live: std::collections::BTreeSet<VersionHash> =
                versions_of(&native_store::load_state(&b, &group()).unwrap())
                    .into_iter()
                    .map(|(_, version)| version)
                    .collect();
            assert!(originally.is_subset(&live), "delta {seq} dropped a version");
            // And per path: a version removed at a path is put at its copy in
            // the same delta, so the pair (path, version) either stays or has
            // moved whole.
            for op in &delta.ops {
                if !op.removes.is_empty() {
                    assert!(
                        delta.ops.iter().any(|other| other.put.is_some() && other.path != op.path),
                        "a removal at {:?} without the put of its copy in delta {seq}",
                        op.path
                    );
                }
            }
        }
        // After the whole chain both replicas agree and nothing is contested.
        assert_eq!(
            native_store::load_state(&a, &group()).unwrap(),
            native_store::load_state(&b, &group()).unwrap()
        );
        crate::native_contest_candidates::finish_attempt(&a, "g1").unwrap();
        assert_eq!(crate::native_contest_candidates::count(&a, "g1").unwrap(), 0);
    }

    // --- identical content written independently ---------------------------

    fn file_version(
        c: &Connection,
        content: u8,
        mtime: i64,
        mode: Option<u32>,
    ) -> yadorilink_replica_domain::file::FileVersion {
        use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
        let version = FileVersion::new(
            vec![VersionBlock {
                hash: yadorilink_replica_domain::ids::BlockHash(vec![content; 32]),
                size: 1,
            }],
            1,
            FileMeta {
                mtime_unix_nanos: mtime,
                unix_mode: mode,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        crate::dag_store::put_file_version(c, "g1", &version).unwrap();
        version
    }

    /// Every device runs its fork pass over the converged state, in `order`,
    /// until nothing is left to author.
    fn settle_forks(c: &Connection, order: &[&LocalAuthor<'_>]) {
        for _ in 0..8 {
            let mut moved = 0;
            for local in order {
                crate::native_contest_candidates::reset_attempts(c, "g1").unwrap();
                moved += author_all_forks(c, &group(), local, &|_, _| false).unwrap().deltas;
            }
            if moved == 0 {
                return;
            }
        }
        panic!("forks did not settle");
    }

    fn live_paths(
        c: &Connection,
    ) -> std::collections::BTreeMap<String, Vec<(String, VersionHash)>> {
        let state = native_store::load_state(c, &group()).unwrap();
        let mut out = std::collections::BTreeMap::new();
        for (path, heads) in &state.heads {
            let mut got: Vec<_> = heads
                .iter()
                .map(|(dot, payload)| (dot.author.device.0.clone(), payload.version))
                .collect();
            got.sort();
            out.insert(path.as_str().to_owned(), got);
        }
        out
    }

    fn note_x(c: &Connection) {
        crate::native_contest_candidates::note(c, "g1", &["x"]).unwrap();
    }

    #[test]
    fn identical_content_written_at_different_times_converges_without_a_copy_in_any_order() {
        for a_first in [true, false] {
            let c = conn();
            let (owned_a, key_a) = author();
            let (owned_b, key_b) = author_b();
            let (a, b) = (owned_a.as_local(&key_a), owned_b.as_local(&key_b));
            let early = file_version(&c, 7, 1_000, Some(0o644));
            let late = file_version(&c, 7, 2_000, Some(0o644));
            assert_ne!(early.version_hash, late.version_hash);
            concurrent_create_version(&c, &a, &SyncPath("x".into()), early.version_hash);
            concurrent_create_version(&c, &b, &SyncPath("x".into()), late.version_hash);
            note_x(&c);
            assert_eq!(crate::native_contest_candidates::count(&c, "g1").unwrap(), 1);

            if a_first {
                settle_forks(&c, &[&a, &b]);
            } else {
                settle_forks(&c, &[&b, &a]);
            }

            let larger = early.version_hash.max(late.version_hash);
            let live = live_paths(&c);
            assert_eq!(live.len(), 1, "no conflicted copy: {live:?}");
            assert_eq!(
                live["x"],
                [("device-a".to_owned(), larger), ("device-b".to_owned(), larger)],
                "both authors' heads kept, one version"
            );
            assert_eq!(crate::native_contest_candidates::count(&c, "g1").unwrap(), 0);
        }
    }

    #[test]
    fn a_difference_in_bytes_or_mode_is_still_a_conflict_with_a_copy() {
        for (label, other) in [
            ("bytes", (8u8, Some(0o644u32))),
            ("mode", (7, Some(0o755))),
            ("another plain mode", (7, Some(0o600))),
        ] {
            let c = conn();
            let (owned_a, key_a) = author();
            let (owned_b, key_b) = author_b();
            let (a, b) = (owned_a.as_local(&key_a), owned_b.as_local(&key_b));
            let first = file_version(&c, 7, 1_000, Some(0o644));
            let second = file_version(&c, other.0, 2_000, other.1);
            concurrent_create_version(&c, &a, &SyncPath("x".into()), first.version_hash);
            concurrent_create_version(&c, &b, &SyncPath("x".into()), second.version_hash);
            note_x(&c);

            settle_forks(&c, &[&a, &b]);

            let live = live_paths(&c);
            assert_eq!(live.len(), 2, "{label}: the loser stands at a copy path: {live:?}");
            let versions: std::collections::BTreeSet<VersionHash> =
                live.values().flatten().map(|(_, v)| *v).collect();
            assert_eq!(
                versions,
                [first.version_hash, second.version_hash].into(),
                "{label}: both versions survive"
            );
        }
    }

    /// A device without unix modes (device-b records none) and a Unix device
    /// (device-a, 0644) writing the same bytes converge on the Unix version
    /// in either hash order and either planning order, with no copy.
    #[test]
    fn a_device_without_a_mode_adopts_the_equal_unix_version_in_any_order() {
        for (unix_time, win_time) in [(1_000, 2_000), (2_000, 1_000)] {
            for unix_first in [true, false] {
                let c = conn();
                let (owned_a, key_a) = author();
                let (owned_b, key_b) = author_b();
                let (unix, win) = (owned_a.as_local(&key_a), owned_b.as_local(&key_b));
                let on_unix = file_version(&c, 7, unix_time, Some(0o644));
                let on_win = file_version(&c, 7, win_time, None);
                concurrent_create_version(&c, &unix, &SyncPath("x".into()), on_unix.version_hash);
                concurrent_create_version(&c, &win, &SyncPath("x".into()), on_win.version_hash);
                note_x(&c);

                if unix_first {
                    settle_forks(&c, &[&unix, &win]);
                } else {
                    settle_forks(&c, &[&win, &unix]);
                }

                let live = live_paths(&c);
                if on_unix.version_hash > on_win.version_hash {
                    assert_eq!(live.len(), 1, "no conflicted copy: {live:?}");
                    assert_eq!(
                        live["x"],
                        [
                            ("device-a".to_owned(), on_unix.version_hash),
                            ("device-b".to_owned(), on_unix.version_hash)
                        ],
                        "the Unix mode stands on both"
                    );
                } else {
                    // The largest raw version keeps the path; the mode-less
                    // head never adopts, so the Unix head is a plain loser
                    // and its mode survives at the conflicted copy.
                    assert_eq!(live.len(), 2, "{live:?}");
                    assert_eq!(live["x"], [("device-b".to_owned(), on_win.version_hash)]);
                    assert!(live.iter().any(|(path, heads)| path != "x"
                        && heads == &[("device-a".to_owned(), on_unix.version_hash)]));
                }
                assert_eq!(crate::native_contest_candidates::count(&c, "g1").unwrap(), 0);
            }
        }
    }

    /// A Unix head, a head with other bytes and a mode-less head of the Unix
    /// bytes, planned in every order: whichever hash order the three have, a
    /// head stays at the original path and no version is lost.
    #[test]
    fn a_mode_less_head_beside_a_unix_head_and_other_bytes_always_leaves_a_head_at_the_path() {
        let orders: [[usize; 3]; 6] =
            [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
        for salt in 0..6i64 {
            for order in orders {
                let c = conn();
                let (owned_a, key_a) = author();
                let (owned_b, key_b) = author_b();
                let signing_key_c = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
                let owned_c = LocalAuthorOwned {
                    author: AuthorId {
                        device: DeviceId("device-c".into()),
                        incarnation: IncarnationId([1u8; 16]),
                    },
                };
                let authors = [
                    owned_a.as_local(&key_a),
                    owned_b.as_local(&key_b),
                    owned_c.as_local(&signing_key_c),
                ];
                let unix = file_version(&c, 7, 1_000 + salt, Some(0o644));
                let win = file_version(&c, 7, 2_000 + salt * 3, None);
                let other = file_version(&c, 9, 3_000 + salt * 7, Some(0o644));
                concurrent_create_version(
                    &c,
                    &authors[0],
                    &SyncPath("x".into()),
                    unix.version_hash,
                );
                concurrent_create_version(&c, &authors[1], &SyncPath("x".into()), win.version_hash);
                concurrent_create_version(
                    &c,
                    &authors[2],
                    &SyncPath("x".into()),
                    other.version_hash,
                );
                note_x(&c);
                settle_forks(&c, &[&authors[order[0]], &authors[order[1]], &authors[order[2]]]);

                let live = live_paths(&c);
                assert!(live.contains_key("x"), "a head stays at x ({salt}, {order:?}): {live:?}");
                let versions: std::collections::BTreeSet<VersionHash> =
                    live.values().flatten().map(|(_, v)| *v).collect();
                assert!(versions.contains(&unix.version_hash), "unix head lost: {live:?}");
                assert!(versions.contains(&other.version_hash), "other bytes lost: {live:?}");
                assert_eq!(crate::native_contest_candidates::count(&c, "g1").unwrap(), 0);
            }
        }
    }

    #[test]
    fn a_set_exec_bit_against_no_mode_is_still_a_conflict_with_a_copy() {
        let c = conn();
        let (owned_a, key_a) = author();
        let (owned_b, key_b) = author_b();
        let (unix, win) = (owned_a.as_local(&key_a), owned_b.as_local(&key_b));
        let exec = file_version(&c, 7, 1_000, Some(0o755));
        let none = file_version(&c, 7, 2_000, None);
        concurrent_create_version(&c, &unix, &SyncPath("x".into()), exec.version_hash);
        concurrent_create_version(&c, &win, &SyncPath("x".into()), none.version_hash);
        note_x(&c);
        settle_forks(&c, &[&unix, &win]);
        let live = live_paths(&c);
        assert_eq!(live.len(), 2, "{live:?}");
        let versions: std::collections::BTreeSet<VersionHash> =
            live.values().flatten().map(|(_, v)| *v).collect();
        assert_eq!(versions, [exec.version_hash, none.version_hash].into());
    }

    /// A and B hold one content (at two times), C another that wins. When the
    /// author of the smaller version acts first, it unifies before anything is
    /// copied and the two end with one copy; when the other acts first, each
    /// moves its own version and the identical content stands at two copies.
    /// Either way nothing is contested and no version is lost.
    #[test]
    fn two_devices_with_one_content_and_a_third_with_another_never_lose_a_version() {
        for smaller_first in [true, false] {
            let c = conn();
            let (owned_a, key_a) = author();
            let (owned_b, key_b) = author_b();
            let signing_key_c = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
            let owned_c = LocalAuthorOwned {
                author: AuthorId {
                    device: DeviceId("device-c".into()),
                    incarnation: IncarnationId([1u8; 16]),
                },
            };
            let (a, b, d) = (
                owned_a.as_local(&key_a),
                owned_b.as_local(&key_b),
                owned_c.as_local(&signing_key_c),
            );
            let x1 = file_version(&c, 7, 1_000, Some(0o644));
            let x2 = file_version(&c, 7, 2_000, Some(0o644));
            let y = file_version(&c, 9, 3_000, Some(0o644));
            concurrent_create_version(&c, &a, &SyncPath("x".into()), x1.version_hash);
            concurrent_create_version(&c, &b, &SyncPath("x".into()), x2.version_hash);
            concurrent_create_version(&c, &d, &SyncPath("x".into()), y.version_hash);
            note_x(&c);
            let a_is_smaller = x1.version_hash < x2.version_hash;

            // The contest is decided by the larger version of each content.
            let (smaller, larger) = if a_is_smaller { (&a, &b) } else { (&b, &a) };
            if smaller_first {
                settle_forks(&c, &[smaller, larger, &d]);
            } else {
                settle_forks(&c, &[larger, smaller, &d]);
            }

            let live = live_paths(&c);
            let versions: std::collections::BTreeSet<VersionHash> =
                live.values().flatten().map(|(_, v)| *v).collect();
            assert!(versions.contains(&y.version_hash), "{smaller_first}: {live:?}");
            assert!(
                versions.contains(&x1.version_hash.max(x2.version_hash)),
                "{smaller_first}: the content of x survives as its larger version: {live:?}"
            );
            let copies: Vec<_> = live.iter().filter(|(path, _)| path.as_str() != "x").collect();
            assert!(!copies.is_empty(), "{smaller_first}: the losing content is kept: {live:?}");
            if smaller_first {
                assert_eq!(copies.len(), 1, "unified before copied: {live:?}");
                assert_eq!(copies[0].1.len(), 2, "both authors' heads kept at the copy");
            } else {
                assert!(copies.len() <= 2, "{live:?}");
            }
            assert_eq!(live["x"].len(), 1, "{smaller_first}: {live:?}");
            assert_eq!(crate::native_contest_candidates::count(&c, "g1").unwrap(), 0);
        }
    }
}
