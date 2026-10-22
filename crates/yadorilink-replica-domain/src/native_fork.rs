//! Resolving a contested path: the author of a losing head renames it.
//!
//! A conflict is resolved by an ordinary delta. The author of a head that
//! loses its path removes that head and puts the same version at a copy path
//! derived from the path and the version alone ([`copy_path`]). Nothing about
//! the delta is special: it is exactly what the author would have signed had
//! the user renamed the file, and admission applies no extra rule to it.
//!
//! This module computes those deltas as pure data from the replicated
//! [`NativeState`]. It never signs, reads a disk or looks at occupancy.
//!
//! # Rules
//!
//! * Only the author of a head moves it ([`plan_own_forks`]); a Writer moves
//!   another author's head only when that author can never act
//!   ([`fallback_may_fork`]), and then removes only that author's heads.
//! * A head loses when [`crate::native_project::loses`] says so: it is
//!   file-like and the path has to be a directory, or a version of larger
//!   [`crate::native_state::win_key`] holds the path. Directory heads are
//!   never copied.
//! * Versions that differ only in mtime hold the same content (equal
//!   [`ContentIdentity`]; see [`adoption_version`]). Two devices that write the
//!   same bytes independently produce such versions, and there is nothing to
//!   choose between them. The author of a head whose version is smaller than
//!   the largest version of its content at the path replaces that head with a
//!   head of the largest one (an ordinary delta at the same path), so every
//!   replica converges on one version without a conflicted copy. This happens
//!   before any copy is made, so authors of one losing content later move the
//!   same version to the same copy path. Any other difference (bytes, mode,
//!   symlink target, xattrs, kind) is a real contest, with one exception: for
//!   a regular file, no mode (a device without unix permissions) equals a
//!   plain non-executable read/write mode ([`ModeBridge`]). Only the
//!   mode-less head moves, and it adopts the existing Unix version, so a Unix
//!   mode is never changed or dropped and a Unix head is never replaced by a
//!   mode-less one. A set exec bit, other mode bits and several differing
//!   Unix modes stay a contest. The bridge only decides where a mode-less
//!   head goes, never who wins: the version that keeps a path is the largest
//!   raw [`crate::native_state::win_key`] of the heads present, a pure
//!   function of the multiset of raw version hashes. It never changes when a
//!   loser is removed, replaced or adopts, and no head that holds the path
//!   adopts, so concurrent plans that saw different subsets of the heads can
//!   never all abandon the path. The price: when the mode-less version has
//!   the largest hash, the Unix head of the same bytes is an ordinary loser
//!   and is moved to a conflicted copy.
//! * Every delta is self-contained: it puts every version it removes, so no
//!   admitted prefix of a plan can leave a head removed without its copy.
//! * An author holds at most [`MAX_SELF_HEADS`] heads at a path. A put into a
//!   full bucket supersedes only a head of the same version; a bucket full of
//!   other versions is resolved first (its heads are forks of their own) or
//!   the plan is refused. A distinct version is never dropped.
//! * A copy path that is occupied is an ordinary contest at that path and is
//!   handled by the next round of planning, not by choosing another name.

use std::collections::BTreeSet;

use crate::author::{AuthorId, MAX_SELF_HEADS};
use crate::conflict::{truncate_stem_to_fit, MAX_COMPONENT_BYTES};
use crate::file::RecordKind;
use crate::ids::{ContentIdentity, DeltaHash, SyncPath, VersionHash};
use crate::limits::MAX_PATH_BYTES;
use crate::native_project::loses;
use crate::native_state::{win_key, HeadPayload, LiveHead, NativeState, RemoteOp};
use crate::signed_delta::{DeltaPut, HeadRef};

/// What fork planning needs to know about one version: its kind, and the
/// identity of its content when that is known.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct VersionInfo {
    pub kind: RecordKind,
    /// `None` makes the version its own content: it is the same content as
    /// itself and as nothing else.
    pub content: Option<ContentIdentity>,
    /// How the version relates to the other platform's idea of a mode, for a
    /// regular file with no exec bit (see [`ModeBridge`]); `None` otherwise.
    pub mode_bridge: Option<ModeBridge>,
}

/// The cross-platform view of a regular file's mode. A device without unix
/// permissions records no mode, while a Unix device records the permission
/// word, so the same bytes written on both are never equal by
/// [`ContentIdentity`]. A version with no mode (`modeless`) is the same
/// content as a version whose mode has no exec bit and no bit beyond
/// read/write (`!modeless`) when everything else is equal (`base` is the
/// identity with the mode removed). A set exec bit, any other mode bit, a
/// symlink or a directory is never bridged.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ModeBridge {
    pub base: ContentIdentity,
    pub modeless: bool,
}

impl From<RecordKind> for VersionInfo {
    fn from(kind: RecordKind) -> Self {
        VersionInfo { kind, content: None, mode_bridge: None }
    }
}

/// The version a mode-less `own` (a version with no mode) stands for among the
/// heads at the path: the largest version of the one content that holds the
/// same bytes with a non-executable mode. `Some(None)` when there is no such
/// version, or when there are several that differ in mode (which of them the
/// mode-less head should become is then not decided, and it stays a real
/// contest); `None` while a version record is missing.
///
/// Only the mode-less head ever moves, and it moves to a version that already
/// exists, which keeps the Unix author's mode untouched; a head with a mode is
/// never replaced by a mode-less one.
fn mode_bridge_target<K: Into<VersionInfo>>(
    own: &VersionInfo,
    heads_at_path: &crate::native_state::PathHeads,
    info_of: &impl Fn(&VersionHash) -> Option<K>,
) -> Option<Option<VersionHash>> {
    let Some(bridge) = own.mode_bridge.filter(|b| b.modeless) else { return Some(None) };
    let mut identities: BTreeSet<ContentIdentity> = BTreeSet::new();
    let mut best: Option<VersionHash> = None;
    for payload in heads_at_path.values() {
        let other: VersionInfo = info_of(&payload.version)?.into();
        let Some(other_bridge) = other.mode_bridge.filter(|b| !b.modeless) else { continue };
        if other_bridge.base != bridge.base {
            continue;
        }
        let Some(identity) = other.content else { continue };
        identities.insert(identity);
        best = best.max(Some(payload.version));
    }
    Some(if identities.len() == 1 { best } else { None })
}

/// The version `version` should be replaced by, if any: the largest version
/// among the heads at the path that hold the same content (equal identity,
/// which includes the same kind). `Some(None)` when `version` is already the
/// largest of its content; `None` while some version record is missing.
///
/// A function of the heads and the version records alone, so every author
/// that sees the same heads replaces toward the same version.
pub fn adoption_version<K: Into<VersionInfo>>(
    version: &VersionHash,
    heads_at_path: &crate::native_state::PathHeads,
    info_of: impl Fn(&VersionHash) -> Option<K>,
) -> Option<Option<VersionHash>> {
    let own: VersionInfo = info_of(version)?.into();
    if let Some(target) = mode_bridge_target(&own, heads_at_path, &info_of)? {
        // The version that keeps the path never moves, and never adopts: the
        // winner is the largest raw [`win_key`] at the path whichever heads
        // are present, so removing or replacing a loser cannot change it.
        let own_key = win_key(own.kind == RecordKind::Directory, *version);
        for payload in heads_at_path.values() {
            let other: VersionInfo = info_of(&payload.version)?.into();
            if win_key(other.kind == RecordKind::Directory, payload.version) > own_key {
                return Some(Some(target));
            }
        }
        return Some(None);
    }
    let Some(identity) = own.content else { return Some(None) };
    if own.kind == RecordKind::Directory {
        return Some(None);
    }
    let mut best = *version;
    for payload in heads_at_path.values() {
        let other: VersionInfo = info_of(&payload.version)?.into();
        if other.content == Some(identity) {
            best = best.max(payload.version);
        }
    }
    Some((best != *version).then_some(best))
}

/// How many leading bytes of the copy id a copy name shows: 128 bits, 32 hex
/// characters.
pub const COPY_ID_BYTES: usize = 16;

/// Domain separator of the copy id preimage.
const COPY_ID_DOMAIN: &[u8] = b"ylnk-copy-2";

/// The name of the copy of `version` that lost the path `path`:
/// `name (conflicted copy, <id>).ext`, where
/// `id = hex(SHA-256("ylnk-copy-2" || u32be(len(path)) || path || version)[..16])`.
///
/// A pure function of the full source path (including any copy marker it
/// already carries: a copy of a copy is a different path and so a different
/// id) and the full version hash. No occupancy, salt, clock, device or
/// arrival order is an input, so every replica derives the same name. Only the
/// stem is shortened, on a character boundary, to keep the component within
/// [`MAX_COMPONENT_BYTES`]; the id covers the untruncated path.
pub fn copy_path(path: &str, version: &VersionHash) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(COPY_ID_DOMAIN);
    hasher.update((path.len() as u32).to_be_bytes());
    hasher.update(path.as_bytes());
    hasher.update(version.0);
    let digest = hasher.finalize();
    let id = hex::encode(&digest[..COPY_ID_BYTES]);

    let (dir, filename) = match path.rsplit_once('/') {
        Some((dir, name)) => (format!("{dir}/"), name),
        None => (String::new(), path),
    };
    let suffix = format!(" (conflicted copy, {id})");
    let (stem, ext) = match filename.rsplit_once('.') {
        // An extension too long to leave room for the suffix is not kept as
        // one: the whole file name is the stem, so the component stays
        // within the limit whatever the source looked like.
        Some((stem, ext))
            if !stem.is_empty() && suffix.len() + 1 + ext.len() < MAX_COMPONENT_BYTES / 2 =>
        {
            (stem, Some(ext))
        }
        _ => (filename, None),
    };
    let ext_bytes = ext.map_or(0, |ext| 1 + ext.len());
    let stem = truncate_stem_to_fit(stem, suffix.len() + ext_bytes);
    match ext {
        Some(ext) => format!("{dir}{stem}{suffix}.{ext}"),
        None => format!("{dir}{stem}{suffix}"),
    }
}

/// One path of a fork delta, in the shape of an ordinary delta op.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ForkOp {
    pub path: SyncPath,
    pub removes: Vec<HeadRef>,
    pub put: Option<DeltaPut>,
}

/// The ops of one delta the author signs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ForkDelta {
    pub ops: Vec<ForkOp>,
}

/// An ordered chain of deltas of one author, each applied after the previous.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ForkPlan {
    pub deltas: Vec<ForkDelta>,
    /// Paths with an own head that cannot be judged yet because the record of
    /// some head's version is missing. They are forked once it arrives.
    pub waiting_for_records: Vec<SyncPath>,
    /// Paths whose fork cannot be made (the copy path is too long, or the
    /// signer's bucket at it is full of other versions). They stay contested;
    /// they do not stop the forks of other paths.
    pub refused: Vec<(SyncPath, ForkError)>,
}

/// The shape bound of one planned delta.
#[derive(Clone, Copy, Debug)]
pub struct ForkLimits {
    /// The most ops one delta of the chain may carry. At least
    /// [`MIN_OPS_PER_DELTA`].
    pub max_ops_per_delta: usize,
    /// The most bytes (estimated, never under the encoded size) the ops of one
    /// delta may take, so that a delta always fits one replication item. A
    /// group of one remove plus put is never split, so one group over the
    /// budget travels alone.
    pub max_bytes_per_delta: usize,
}

/// The bytes an op takes on the wire, estimated from above: the path
/// (length-prefixed), the counts, each removal naming a head (device id,
/// incarnation, sequence, provenance) and the put.
fn fork_op_bytes(op: &ForkOp) -> usize {
    op.path.as_str().len()
        + 64
        + op.removes.iter().map(|removal| 60 + removal.dot.author.device.0.len()).sum::<usize>()
}

/// One path's fork needs an op for the path itself and one per distinct
/// losing version of the author, at most [`MAX_SELF_HEADS`].
pub const MIN_OPS_PER_DELTA: usize = 1 + MAX_SELF_HEADS;

/// Why a plan could not be made.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ForkError {
    #[error("a fork delta needs room for at least {MIN_OPS_PER_DELTA} ops")]
    OpBudgetTooSmall,
    #[error("two losing heads would be copied to {path:?}")]
    DestinationCollision { path: SyncPath },
    #[error("the author's heads at {path:?} cannot take another version without dropping one")]
    BucketFull { path: SyncPath },
    #[error("copy destinations form a cycle at {path:?}")]
    Cycle { path: SyncPath },
    #[error("the copy path of {path:?} would exceed the path length limit")]
    DestinationTooLong { path: SyncPath },
    #[error("the author's sequence is exhausted")]
    SeqExhausted,
}

struct Group {
    source: SyncPath,
    removes: Vec<HeadRef>,
    puts: Vec<(SyncPath, VersionHash)>,
    /// The version put at `source` in place of the removed heads, when they
    /// are replaced rather than moved to copy paths.
    adopt: Option<VersionHash>,
}

/// The deltas by which `author` moves each of its own losing heads to the
/// copy path of its version.
///
/// A function of `state`, `author` and the record kinds only. Applying the
/// plan and planning again yields the contests that remain (an occupied copy
/// path, for one), never the same heads twice.
pub fn plan_own_forks<K: Into<VersionInfo>>(
    state: &NativeState,
    author: &AuthorId,
    kind_of: impl Fn(&VersionHash) -> Option<K>,
    limits: ForkLimits,
) -> Result<ForkPlan, ForkError> {
    plan_forks(state, author, author, kind_of, limits)
}

/// Whether a Writer other than the owner of a losing head may move it.
///
/// Only when the owner can never act: its author state is `Closed`, or its
/// device is not a writer at the policy point the caller verified. The
/// answer is a function of those two facts alone: no clock, heartbeat,
/// reachability or disk input exists.
///
/// Replicas may hold different verified policy points, so they may disagree
/// (a replica that has not seen a revocation says no; after a revocation
/// followed by a re-grant a lagging replica can say yes where an advanced one
/// says no). That is harmless by construction rather than by agreement: what
/// a fallback signs is an ordinary delta that every replica admits as a
/// writer's delta, and concurrent forks of one head converge to one visible
/// copy without losing a version.
pub fn fallback_may_fork(owner_closed: bool, owner_is_writer_at_policy_point: bool) -> bool {
    owner_closed || !owner_is_writer_at_policy_point
}

/// The deltas by which `signer` moves the losing heads of `owner`: the
/// removals name only `owner`'s heads and the puts land in `signer`'s own
/// bucket at the copy paths. With `owner == signer` this is the author
/// forking its own heads ([`plan_own_forks`]); with another signer it is the
/// fallback of [`fallback_may_fork`], and the caller must have checked that.
pub fn plan_forks<K: Into<VersionInfo>>(
    state: &NativeState,
    owner: &AuthorId,
    signer: &AuthorId,
    info_of: impl Fn(&VersionHash) -> Option<K>,
    limits: ForkLimits,
) -> Result<ForkPlan, ForkError> {
    if limits.max_ops_per_delta < MIN_OPS_PER_DELTA {
        return Err(ForkError::OpBudgetTooSmall);
    }
    let kind_of = |version: &VersionHash| info_of(version).map(|info| info.into().kind);
    let mut plan = ForkPlan::default();
    let mut groups: Vec<Group> = Vec::new();

    for (path, heads) in &state.heads {
        if !heads.keys().any(|dot| dot.author == *owner) {
            continue;
        }
        let has_descendant = state
            .heads
            .range(SyncPath(format!("{}/", path.as_str()))..)
            .next()
            .is_some_and(|(key, _)| key.as_str().starts_with(&format!("{}/", path.as_str())));
        // Heads of a version smaller than the largest of their content are
        // replaced first (see the module rules); one content per pass.
        let mut adopting: Vec<(VersionHash, HeadRef)> = Vec::new();
        let mut adoption_judged = true;
        for (dot, payload) in heads {
            if dot.author != *owner {
                continue;
            }
            match adoption_version(&payload.version, heads, &info_of) {
                None => {
                    adoption_judged = false;
                    break;
                }
                Some(Some(target)) => adopting
                    .push((target, HeadRef { dot: dot.clone(), provenance: payload.provenance })),
                Some(None) => {}
            }
        }
        if !adoption_judged {
            plan.waiting_for_records.push(path.clone());
            continue;
        }
        if let Some(target) = adopting.iter().map(|(target, _)| *target).min() {
            let removes =
                adopting.into_iter().filter(|(t, _)| *t == target).map(|(_, r)| r).collect();
            let group =
                Group { source: path.clone(), removes, puts: Vec::new(), adopt: Some(target) };
            // A signer whose bucket at the path has no room for the put (the
            // fallback for a closed author) cannot replace in place: the
            // losing heads are then copied as they are, as for any contest.
            if adoption_put(state, signer, &group).is_ok() {
                groups.push(group);
                continue;
            }
        }
        let mut removes = Vec::new();
        let mut versions: BTreeSet<VersionHash> = BTreeSet::new();
        let mut judged = true;
        for (dot, payload) in heads {
            if dot.author != *owner {
                continue;
            }
            let head = LiveHead { dot: dot.clone(), payload: payload.clone() };
            match loses(&head, kind_of, heads, has_descendant) {
                None => {
                    judged = false;
                    break;
                }
                Some(true) => {
                    removes.push(HeadRef { dot: dot.clone(), provenance: payload.provenance });
                    versions.insert(payload.version);
                }
                Some(false) => {}
            }
        }
        if !judged {
            plan.waiting_for_records.push(path.clone());
            continue;
        }
        if removes.is_empty() {
            continue;
        }
        let puts: Vec<(SyncPath, VersionHash)> = versions
            .into_iter()
            .map(|version| (SyncPath(copy_path(path.as_str(), &version)), version))
            .collect::<Vec<_>>();
        if let Some((destination, _)) = puts.iter().find(|(d, _)| d.as_str().len() > MAX_PATH_BYTES)
        {
            plan.refused
                .push((path.clone(), ForkError::DestinationTooLong { path: destination.clone() }));
            continue;
        }
        groups.push(Group { source: path.clone(), removes, puts, adopt: None });
    }

    // A copy is not put where this plan also replaces heads in place: the
    // fork would have to refer to a head the plan itself creates, which has no
    // identity until it is signed. The fork is planned again once the
    // replacement is installed.
    let replaced_in_place: BTreeSet<SyncPath> =
        groups.iter().filter(|g| g.adopt.is_some()).map(|g| g.source.clone()).collect();
    groups.retain(|g| {
        g.adopt.is_some()
            || g.puts.iter().all(|(destination, _)| !replaced_in_place.contains(destination))
    });

    let mut destinations: BTreeSet<&SyncPath> = BTreeSet::new();
    for group in &groups {
        for (destination, _) in &group.puts {
            if !destinations.insert(destination) {
                return Err(ForkError::DestinationCollision { path: destination.clone() });
            }
        }
    }

    let ordered = order_groups(groups)?;

    // Emit the chain against a simulation of the author's own state.
    let mut sim = state.clone();
    let mut current: Vec<ForkOp> = Vec::new();
    let mut touched: BTreeSet<SyncPath> = BTreeSet::new();
    let mut current_bytes = 0usize;
    for group in &ordered {
        loop {
            let ops = match group_ops(&sim, signer, group) {
                Ok(ops) => ops,
                // The bucket may be full only until the delta being built is
                // applied (it moves heads out of that path).
                Err(ForkError::BucketFull { .. }) if !current.is_empty() => {
                    flush(&mut sim, signer, &mut current, &mut touched, &mut plan)?;
                    current_bytes = 0;
                    continue;
                }
                Err(error @ ForkError::BucketFull { .. }) => {
                    plan.refused.push((group.source.clone(), error));
                    break;
                }
                Err(error) => return Err(error),
            };
            let overlaps = ops.iter().any(|op| touched.contains(&op.path));
            let bytes: usize = ops.iter().map(fork_op_bytes).sum();
            let too_big = current.len() + ops.len() > limits.max_ops_per_delta
                || current_bytes + bytes > limits.max_bytes_per_delta;
            if (overlaps || too_big) && !current.is_empty() {
                flush(&mut sim, signer, &mut current, &mut touched, &mut plan)?;
                current_bytes = 0;
                continue;
            }
            current_bytes += bytes;
            for op in ops {
                touched.insert(op.path.clone());
                current.push(op);
            }
            break;
        }
    }
    if !current.is_empty() {
        flush(&mut sim, signer, &mut current, &mut touched, &mut plan)?;
    }
    Ok(plan)
}

/// Orders groups so that a group whose source is another group's destination
/// goes before that group.
fn order_groups(groups: Vec<Group>) -> Result<Vec<Group>, ForkError> {
    // `before[g]` are the groups that have to go before `g`: those whose
    // source is one of its destinations.
    let by_source: std::collections::BTreeMap<&SyncPath, usize> =
        groups.iter().enumerate().map(|(i, g)| (&g.source, i)).collect();
    let before: Vec<Vec<usize>> = groups
        .iter()
        .map(|g| g.puts.iter().filter_map(|(d, _)| by_source.get(d).copied()).collect())
        .collect();
    // 0 unvisited, 1 on the stack, 2 done.
    let mut mark = vec![0u8; groups.len()];
    let mut order = Vec::with_capacity(groups.len());
    for start in 0..groups.len() {
        let mut stack = vec![(start, 0usize)];
        while let Some((node, next)) = stack.pop() {
            if next == 0 {
                match mark[node] {
                    2 => continue,
                    1 => return Err(ForkError::Cycle { path: groups[node].source.clone() }),
                    _ => mark[node] = 1,
                }
            }
            if let Some(&dep) = before[node].get(next) {
                stack.push((node, next + 1));
                if mark[dep] == 1 {
                    return Err(ForkError::Cycle { path: groups[dep].source.clone() });
                }
                if mark[dep] == 0 {
                    stack.push((dep, 0));
                }
            } else {
                mark[node] = 2;
                order.push(node);
            }
        }
    }
    let mut slots: Vec<Option<Group>> = groups.into_iter().map(Some).collect();
    Ok(order.into_iter().map(|i| slots[i].take().expect("each group once")).collect())
}

/// The put that replaces a group's removed heads at its source path, with the
/// signer's own heads it has to supersede to make room for it.
///
/// The put is always a fresh head, even when the signer already holds a head
/// of the adopted version: a replica that has seen only that existing head may
/// concurrently delete it, and a removal that left nothing behind would turn
/// that delete into the end of a write it never observed. When the signer's
/// bucket at the path is full, only its heads of the adopted version are
/// superseded; if there are not enough of them the group is refused.
fn adoption_put(
    sim: &NativeState,
    signer: &AuthorId,
    group: &Group,
) -> Result<Option<(DeltaPut, Vec<HeadRef>)>, ForkError> {
    let Some(version) = group.adopt else { return Ok(None) };
    let own: Vec<(&crate::native_state::Dot, &HeadPayload)> = sim
        .heads
        .get(&group.source)
        .into_iter()
        .flatten()
        .filter(|(dot, _)| dot.author == *signer && !group.removes.iter().any(|r| r.dot == **dot))
        .collect();
    let mut superseded = Vec::new();
    if own.len() + 1 > MAX_SELF_HEADS {
        let need = own.len() + 1 - MAX_SELF_HEADS;
        let same: Vec<_> = own.iter().filter(|(_, payload)| payload.version == version).collect();
        if same.len() < need {
            return Err(ForkError::BucketFull { path: group.source.clone() });
        }
        for (dot, payload) in same.into_iter().take(need) {
            superseded.push(HeadRef { dot: (*dot).clone(), provenance: payload.provenance });
        }
    }
    Ok(Some((DeltaPut { version }, superseded)))
}

fn group_ops(
    sim: &NativeState,
    author: &AuthorId,
    group: &Group,
) -> Result<Vec<ForkOp>, ForkError> {
    let (adopted, superseded) = match adoption_put(sim, author, group)? {
        Some((put, superseded)) => (Some(put), superseded),
        None => (None, Vec::new()),
    };
    let mut ops = vec![ForkOp {
        path: group.source.clone(),
        removes: group.removes.iter().cloned().chain(superseded).collect(),
        put: adopted,
    }];
    for (destination, version) in &group.puts {
        let own: Vec<(&crate::native_state::Dot, &HeadPayload)> = sim
            .heads
            .get(destination)
            .into_iter()
            .flat_map(|heads| heads.iter())
            .filter(|(dot, _)| dot.author == *author)
            .collect();
        let mut removes = Vec::new();
        if own.len() + 1 > MAX_SELF_HEADS {
            // Supersede only heads of the very version being put: the copy
            // stays represented, nothing distinct is dropped.
            let need = own.len() + 1 - MAX_SELF_HEADS;
            let same: Vec<_> =
                own.iter().filter(|(_, payload)| payload.version == *version).collect();
            if same.len() < need {
                return Err(ForkError::BucketFull { path: destination.clone() });
            }
            for (dot, payload) in same.into_iter().take(need) {
                removes.push(HeadRef { dot: (*dot).clone(), provenance: payload.provenance });
            }
        }
        ops.push(ForkOp {
            path: destination.clone(),
            removes,
            put: Some(DeltaPut { version: *version }),
        });
    }
    Ok(ops)
}

fn flush(
    sim: &mut NativeState,
    author: &AuthorId,
    current: &mut Vec<ForkOp>,
    touched: &mut BTreeSet<SyncPath>,
    plan: &mut ForkPlan,
) -> Result<(), ForkError> {
    let ops = std::mem::take(current);
    touched.clear();
    let seq = sim.next_dot(author).map_err(|_| ForkError::SeqExhausted)?.seq;
    let mut provenance = [0u8; 32];
    provenance[..8].copy_from_slice(&seq.0.to_be_bytes());
    let remote: Vec<RemoteOp> = ops
        .iter()
        .map(|op| RemoteOp {
            path: op.path.clone(),
            removes: op.removes.clone(),
            put: op
                .put
                .as_ref()
                .map(|put| HeadPayload { version: put.version, provenance: DeltaHash(provenance) }),
        })
        .collect();
    sim.receive_verified(author, seq, &remote).map_err(|_| ForkError::SeqExhausted)?;
    if let Err(violation) = sim.check_invariants() {
        use crate::native_state::InvariantViolation;
        return Err(match violation {
            InvariantViolation::SelfHeadBound { path, .. } => ForkError::BucketFull { path },
            _ => ForkError::SeqExhausted,
        });
    }
    plan.deltas.push(ForkDelta { ops });
    Ok(())
}

/// Every distinct version live anywhere in `state`.
pub fn live_versions(state: &NativeState) -> BTreeSet<VersionHash> {
    state.heads.values().flat_map(|heads| heads.values().map(|p| p.version)).collect()
}

#[cfg(test)]
mod tests;
