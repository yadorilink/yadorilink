//! Native causal state: per-path live heads as the primary source of
//! truth, with no change log, no ancestry graph, no basis admission and no base.
//!
//! A replica keeps, and only keeps:
//!
//! * `context`: per author, the highest sequence number it has observed
//!   (gap-free by construction under the honest-author model);
//! * `heads`: per path, the live heads, each identified by its dot
//!   `(author, seq)` and carrying its payload (content version, provenance).
//!
//! A local mutation issues exactly one dot and edits any number of paths
//! through the single [`NativeState::author`] primitive; [`join`] keeps a
//! head of one side when the other side holds it too or has not observed
//! its dot yet. Deleted heads are forgotten; the memory of a deletion is
//! the context alone.
//!
//! The winner order implemented here is documented on [`win_key`] and
//! [`resolve_winner`].
//!
//! Scope: honest authors. An author computes each mutation against its own
//! current state, never issues two payloads for one dot and never claims
//! context it has not observed. Transport may delay, duplicate, reorder and
//! partition. Nothing here authenticates a remote state; that is
//! [`crate::local_op`]'s and a future `SignedDelta`'s job.

// A fork carries both payloads (with their provenance) as evidence; errors
// are rare, so their size does not matter here.
#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};

use crate::author::{AuthorId, MAX_SELF_HEADS};
use crate::ids::{AuthorSeq, SyncPath, VersionHash};
use crate::signed_delta::HeadRef;

// The header hash of the signed delta that created a head is its
// authenticated provenance, part of the head's identity (the same dot with a
// different provenance is a fork).
pub use crate::ids::DeltaHash;

/// One path's edit within an already-admitted remote delta, as
/// [`NativeState::receive_verified`] takes it: each removal names the
/// provenance it expects to still find live there (`(dot, header)`,
/// mirroring `signed_delta::HeadRef`), since a removal only applies when
/// that exact provenance is still the live one (see that method's doc).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RemoteOp {
    pub path: SyncPath,
    pub removes: Vec<HeadRef>,
    pub put: Option<HeadPayload>,
}

/// The identity of one mutation: its author and the author's sequence
/// number.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Dot {
    pub author: AuthorId,
    pub seq: AuthorSeq,
}

/// The identity of one head in every module: the path it lives at, the dot
/// that created it and the provenance (header hash) of the delta that did so.
/// A removal or kept-copy reference inside an op is the path-scoped form,
/// [`HeadRef`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct HeadId {
    pub path: SyncPath,
    pub dot: Dot,
    pub provenance: DeltaHash,
}

/// What a live head carries besides its dot.
///
/// `provenance` picks which of several heads of one version represents that
/// version; no join/author/context rule below inspects it beyond identity.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct HeadPayload {
    pub version: VersionHash,
    pub provenance: DeltaHash,
}

/// A live head at one path. A mutation landing content at several paths
/// yields one head per path, all with the same dot; the head identity is
/// `(dot, path)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LiveHead {
    pub dot: Dot,
    pub payload: HeadPayload,
}

/// The live heads of one path, keyed by dot.
pub type PathHeads = BTreeMap<Dot, HeadPayload>;

/// Capture witness: what a local writer was shown, at prepare time, for the
/// path it is about to act on.
///
/// `shown_version` is the content the index row displayed when the writer
/// looked, and `shown_class` is every live head at the path whose version is
/// that content, sorted. Heads of one version at one path are one visible
/// piece of content, so an edit or delete of the row supersedes all of them,
/// and only those: a head that arrives after the capture was never seen and
/// survives, and so does every head of another version. Both are empty when
/// the row showed nothing.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NativeCaptureWitness {
    pub path: SyncPath,
    pub shown_class: Vec<Dot>,
    /// The version the disk is guaranteed to hold (the usable materialization
    /// proof's), whatever the index row says: what `shown_class` is the class
    /// of. Authoring takes it from here, never by re-reading anything at
    /// commit. `None` when nothing vouches for the disk.
    pub shown_version: Option<VersionHash>,
    /// The version the index row displayed at capture. A row that has since
    /// changed to another version makes the capture stale; it decides nothing
    /// about what an edit supersedes.
    pub row_version: Option<VersionHash>,
}

/// A replica state. An absent author has context 0 (no prior sequence); an
/// absent path has no heads. Canonical: a path is present only with at
/// least one head, so two equal states compare equal.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct NativeState {
    pub context: BTreeMap<AuthorId, AuthorSeq>,
    pub heads: BTreeMap<SyncPath, PathHeads>,
}

/// One path of a local mutation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PathEdit {
    pub path: SyncPath,
    /// The heads at `path` the author observed and supersedes. Must be
    /// current heads of the author's own state.
    pub observed: Vec<Dot>,
    /// Content landed at `path`; `None` for a delete.
    pub put: Option<HeadPayload>,
}

/// Why a local mutation was refused (the author-side discipline).
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum AuthorError {
    #[error("mutation carries no path edits")]
    Empty,
    #[error("duplicate path {path:?} in one mutation")]
    DuplicatePath { path: SyncPath },
    #[error("duplicate observed dot {dot:?} at {path:?}")]
    DuplicateObserved { path: SyncPath, dot: Dot },
    #[error("observed dot {dot:?} is not a current head at {path:?}")]
    ObservedNotCurrentHead { path: SyncPath, dot: Dot },
    /// The mutation would leave more than [`MAX_SELF_HEADS`] heads of its
    /// author at `path`.
    #[error("mutation would leave more than {MAX_SELF_HEADS} heads of one author at {path:?}")]
    SelfHeadBound { path: SyncPath },
}

/// The same dot carries two different payloads at one path: an author fork
/// (equivocation). Fail closed; the join never picks one
/// (no winner order is consulted for this case; it is a distinct
/// causal-state error).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fork {
    pub path: SyncPath,
    pub dot: Dot,
    pub left: HeadPayload,
    pub right: HeadPayload,
}

#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum InvariantViolation {
    #[error("dot {dot:?} at {path:?} carries a zero sequence")]
    ZeroSeq { path: SyncPath, dot: Dot },
    #[error("dot {dot:?} at {path:?} is beyond its author's context ({context:?})")]
    HeadBeyondContext { path: SyncPath, dot: Dot, context: Option<AuthorSeq> },
    #[error("path {path:?} is stored with no heads")]
    EmptyPath { path: SyncPath },
    #[error("author {author:?} has more than {MAX_SELF_HEADS} heads at {path:?}")]
    SelfHeadBound { path: SyncPath, author: AuthorId },
}

/// Whether `path` is `prefix` itself or lies below the directory `prefix`.
pub fn is_under(path: &str, prefix: &str) -> bool {
    path == prefix
        || (path.len() > prefix.len()
            && path.starts_with(prefix)
            && path.as_bytes()[prefix.len()] == b'/')
}

fn context_of(context: &BTreeMap<AuthorId, AuthorSeq>, author: &AuthorId) -> Option<AuthorSeq> {
    context.get(author).copied()
}

fn observed_by(context: &BTreeMap<AuthorId, AuthorSeq>, dot: &Dot) -> bool {
    context_of(context, &dot.author).is_some_and(|seq| dot.seq <= seq)
}

impl NativeState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn context_of(&self, author: &AuthorId) -> Option<AuthorSeq> {
        context_of(&self.context, author)
    }

    pub fn heads_at(&self, path: &SyncPath) -> impl Iterator<Item = LiveHead> + '_ {
        self.heads.get(path).into_iter().flat_map(|heads| {
            heads
                .iter()
                .map(|(dot, payload)| LiveHead { dot: dot.clone(), payload: payload.clone() })
        })
    }

    pub fn dots_at(&self, path: &SyncPath) -> Vec<Dot> {
        self.heads.get(path).map(|h| h.keys().cloned().collect()).unwrap_or_default()
    }

    /// The dot the next mutation of `author` issues.
    pub fn next_dot(&self, author: &AuthorId) -> Result<Dot, AuthorError> {
        let seq = match self.context_of(author) {
            None => AuthorSeq::FIRST,
            Some(prev) => prev
                .checked_next()
                .ok_or_else(|| AuthorError::SelfHeadBound { path: SyncPath(String::new()) })?,
        };
        Ok(Dot { author: author.clone(), seq })
    }

    /// Applies a local mutation of `author`: one new dot; per edited path,
    /// the observed heads are removed and the landed content (if any)
    /// added. All-or-nothing: a refused mutation leaves the state
    /// unchanged.
    pub fn author(&mut self, author: &AuthorId, edits: Vec<PathEdit>) -> Result<Dot, AuthorError> {
        self.check_edits(author, &edits)?;
        let dot = self.next_dot(author)?;
        self.context.insert(author.clone(), dot.seq);
        for edit in edits {
            let mut heads = self.heads.remove(&edit.path).unwrap_or_default();
            for observed in &edit.observed {
                heads.remove(observed);
            }
            if let Some(payload) = edit.put {
                heads.insert(dot.clone(), payload);
            }
            if !heads.is_empty() {
                self.heads.insert(edit.path, heads);
            }
        }
        Ok(dot)
    }

    /// The author-side discipline [`Self::author`] enforces: distinct
    /// paths, observed heads distinct and current, and at most
    /// [`MAX_SELF_HEADS`] heads of `author` left at each edited path.
    pub fn check_edits(&self, author: &AuthorId, edits: &[PathEdit]) -> Result<(), AuthorError> {
        if edits.is_empty() {
            return Err(AuthorError::Empty);
        }
        let mut paths = BTreeSet::new();
        for edit in edits {
            if !paths.insert(&edit.path) {
                return Err(AuthorError::DuplicatePath { path: edit.path.clone() });
            }
            let current = self.heads.get(&edit.path);
            let mut seen = BTreeSet::new();
            for dot in &edit.observed {
                if !seen.insert(dot) {
                    return Err(AuthorError::DuplicateObserved {
                        path: edit.path.clone(),
                        dot: dot.clone(),
                    });
                }
                if !current.is_some_and(|heads| heads.contains_key(dot)) {
                    return Err(AuthorError::ObservedNotCurrentHead {
                        path: edit.path.clone(),
                        dot: dot.clone(),
                    });
                }
            }
            let kept_own = current
                .into_iter()
                .flat_map(|heads| heads.keys())
                .filter(|d| d.author == *author && !seen.contains(d))
                .count();
            if kept_own + usize::from(edit.put.is_some()) > MAX_SELF_HEADS {
                return Err(AuthorError::SelfHeadBound { path: edit.path.clone() });
            }
        }
        Ok(())
    }

    /// Lands `payload` at `path`, superseding exactly `observed`.
    pub fn put(
        &mut self,
        author: &AuthorId,
        path: SyncPath,
        observed: &[Dot],
        payload: HeadPayload,
    ) -> Result<Dot, AuthorError> {
        self.author(
            author,
            vec![PathEdit { path, observed: observed.to_vec(), put: Some(payload) }],
        )
    }

    /// Removes exactly `observed` at `path`; unobserved heads survive.
    pub fn delete(
        &mut self,
        author: &AuthorId,
        path: SyncPath,
        observed: &[Dot],
    ) -> Result<Dot, AuthorError> {
        self.author(author, vec![PathEdit { path, observed: observed.to_vec(), put: None }])
    }

    /// The edits of `rm -rf prefix` against this state: every current head
    /// at `prefix` and below, and nothing else.
    pub fn clear_prefix_edits(&self, prefix: &str) -> Vec<PathEdit> {
        self.heads
            .iter()
            .filter(|(path, _)| is_under(path.as_str(), prefix))
            .map(|(path, heads)| PathEdit {
                path: path.clone(),
                observed: heads.keys().cloned().collect(),
                put: None,
            })
            .collect()
    }

    /// `rm -rf prefix` as one mutation.
    pub fn clear_prefix(&mut self, author: &AuthorId, prefix: &str) -> Result<Dot, AuthorError> {
        let edits = self.clear_prefix_edits(prefix);
        self.author(author, edits)
    }

    /// Applies one already-chain-verified, already-context-gated remote
    /// delta's ops (remote admission). `author`/`seq` are the delta's
    /// own dot, already confirmed by the caller to be exactly this
    /// author's next sequence (see `native_frontier::check_chain_advance`);
    /// this method does not re-derive it.
    ///
    /// Unlike [`Self::author`] (an honest author's own view of its
    /// current state, scoped by this module's doc), a received delta's
    /// removals were computed against the *sender's* view at signing time,
    /// which may already have moved on by the time it is admitted here
    /// (a concurrent local or third-party edit landed first). A removal
    /// naming a dot this replica has never observed at all is an admission
    /// precondition the caller must gate before calling this method (hold
    /// the delta instead); but a removal naming a dot this replica *has*
    /// observed, and which is no longer a live head there (already removed,
    /// or superseded with a different provenance than the removal's own
    /// `header`), is not an error here — it is simply not applied. A live
    /// head only comes out when it is still live
    /// with the exact provenance the removal names; any other case
    /// (absent, or live with a different provenance) is silently skipped,
    /// never rejects the whole delta. Two authors' concurrent edits at one
    /// path are expected to disagree about which heads are still live —
    /// that is ordinary convergence, not a fault.
    ///
    /// Still rejects what is structurally malformed regardless of sender
    /// honesty: a duplicate path, or a duplicate observed dot at one path,
    /// in the same delta (checked before any state is touched).
    pub fn receive_verified(
        &mut self,
        author: &AuthorId,
        seq: AuthorSeq,
        ops: &[RemoteOp],
    ) -> Result<Dot, AuthorError> {
        let mut paths = BTreeSet::new();
        for op in ops {
            if !paths.insert(&op.path) {
                return Err(AuthorError::DuplicatePath { path: op.path.clone() });
            }
            let mut seen = BTreeSet::new();
            for removal in &op.removes {
                if !seen.insert(&removal.dot) {
                    return Err(AuthorError::DuplicateObserved {
                        path: op.path.clone(),
                        dot: removal.dot.clone(),
                    });
                }
            }
        }

        let dot = Dot { author: author.clone(), seq };
        self.context.insert(author.clone(), seq);
        for op in ops {
            let mut heads = self.heads.remove(&op.path).unwrap_or_default();
            for removal in &op.removes {
                if heads.get(&removal.dot).is_some_and(|live| live.provenance == removal.provenance)
                {
                    heads.remove(&removal.dot);
                }
            }
            if let Some(payload) = &op.put {
                heads.insert(dot.clone(), payload.clone());
            }
            if !heads.is_empty() {
                self.heads.insert(op.path.clone(), heads);
            }
        }
        Ok(dot)
    }

    /// Every head's dot is observed by the context and no path is stored
    /// without heads.
    pub fn check_invariants(&self) -> Result<(), InvariantViolation> {
        for (path, heads) in &self.heads {
            if heads.is_empty() {
                return Err(InvariantViolation::EmptyPath { path: path.clone() });
            }
            let mut per_author: BTreeMap<&AuthorId, usize> = BTreeMap::new();
            for dot in heads.keys() {
                *per_author.entry(&dot.author).or_default() += 1;
            }
            if let Some((&author, _)) = per_author.iter().find(|(_, &n)| n > MAX_SELF_HEADS) {
                return Err(InvariantViolation::SelfHeadBound {
                    path: path.clone(),
                    author: author.clone(),
                });
            }
            for dot in heads.keys() {
                if dot.seq.get() == 0 {
                    return Err(InvariantViolation::ZeroSeq {
                        path: path.clone(),
                        dot: dot.clone(),
                    });
                }
                let context = self.context_of(&dot.author);
                if context.is_none_or(|c| dot.seq > c) {
                    return Err(InvariantViolation::HeadBeyondContext {
                        path: path.clone(),
                        dot: dot.clone(),
                        context,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Joins the heads of one path: a left head survives when the right side
/// holds it too or has not observed its dot, and symmetrically.
pub(crate) fn join_path(
    path: &SyncPath,
    left: Option<&PathHeads>,
    right: Option<&PathHeads>,
    left_context: &BTreeMap<AuthorId, AuthorSeq>,
    right_context: &BTreeMap<AuthorId, AuthorSeq>,
) -> Result<PathHeads, Fork> {
    let empty = PathHeads::new();
    let left = left.unwrap_or(&empty);
    let right = right.unwrap_or(&empty);
    let mut joined = PathHeads::new();
    for (dot, payload) in left {
        match right.get(dot) {
            Some(other) if other != payload => {
                return Err(Fork {
                    path: path.clone(),
                    dot: dot.clone(),
                    left: payload.clone(),
                    right: other.clone(),
                });
            }
            Some(_) => {
                joined.insert(dot.clone(), payload.clone());
            }
            None if !observed_by(right_context, dot) => {
                joined.insert(dot.clone(), payload.clone());
            }
            None => {}
        }
    }
    for (dot, payload) in right {
        if !left.contains_key(dot) && !observed_by(left_context, dot) {
            joined.insert(dot.clone(), payload.clone());
        }
    }
    Ok(joined)
}

/// Joins two states: context is the componentwise max; per path, see
/// [`join_path`]. Commutative, associative and idempotent on fork-free
/// inputs; a live same-dot fork with differing payloads is an error
/// (never tie-broken, always fail closed).
pub fn join(left: &NativeState, right: &NativeState) -> Result<NativeState, Fork> {
    let mut context = left.context.clone();
    for (author, seq) in &right.context {
        let entry = context.entry(author.clone()).or_insert(*seq);
        if *seq > *entry {
            *entry = *seq;
        }
    }
    let paths: BTreeSet<&SyncPath> = left.heads.keys().chain(right.heads.keys()).collect();
    let mut heads = BTreeMap::new();
    for path in paths {
        let joined = join_path(
            path,
            left.heads.get(path),
            right.heads.get(path),
            &left.context,
            &right.context,
        )?;
        if !joined.is_empty() {
            heads.insert(path.clone(), joined);
        }
    }
    Ok(NativeState { context, heads })
}

/// The canonical order that decides which of several concurrent heads keeps
/// the original name: `(is_directory, version_hash)`, the maximum wins. It is
/// a function of the head's kind and content version alone, so every replica
/// that holds the same live heads picks the same winner whatever order they
/// arrived in, and heads with equal keys are the same version.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct WinKey {
    pub is_directory: bool,
    pub version: VersionHash,
}

/// The [`WinKey`] of a head of the given kind and version.
pub fn win_key(is_directory: bool, version: VersionHash) -> WinKey {
    WinKey { is_directory, version }
}

/// The winner among candidate heads of one kind at one path: the highest
/// content version (the [`WinKey`] order within a kind). Heads of the same
/// version are the same content; the one with the larger `provenance` stands
/// for them, so the representative is a function of the heads alone and `Dot`
/// takes no part. Returns `None` for an empty candidate set.
///
/// Callers must have already fail-closed on same-dot/different-provenance
/// equivocation before calling this — that case is a [`Fork`], not an input.
pub fn resolve_winner<'a>(
    candidates: impl IntoIterator<Item = &'a LiveHead>,
) -> Option<&'a LiveHead> {
    candidates
        .into_iter()
        .max_by_key(|head| (win_key(false, head.payload.version), head.payload.provenance))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn author(name: &str) -> AuthorId {
        author_incarnation(name, 1)
    }

    fn author_incarnation(name: &str, incarnation: u8) -> AuthorId {
        AuthorId {
            device: crate::ids::DeviceId(name.to_owned()),
            incarnation: crate::author::IncarnationId([incarnation; 16]),
        }
    }

    fn path(p: &str) -> SyncPath {
        SyncPath(p.to_owned())
    }

    fn version(byte: u8) -> VersionHash {
        VersionHash([byte; 32])
    }

    fn hash(byte: u8) -> DeltaHash {
        DeltaHash([byte; 32])
    }

    fn payload(v: u8, prov: u8) -> HeadPayload {
        HeadPayload { version: version(v), provenance: hash(prov) }
    }

    // A head is identified by its path, its dot and its provenance together: a
    // difference in any one of them is a different head.
    #[test]
    fn head_id_is_path_dot_and_provenance() {
        let base = HeadId {
            path: path("x"),
            dot: Dot { author: author("a"), seq: AuthorSeq(1) },
            provenance: hash(1),
        };
        let other_path = HeadId { path: path("y"), ..base.clone() };
        let other_dot =
            HeadId { dot: Dot { author: author("a"), seq: AuthorSeq(2) }, ..base.clone() };
        let other_provenance = HeadId { provenance: hash(2), ..base.clone() };
        for different in [&other_path, &other_dot, &other_provenance] {
            assert_ne!(&base, different);
        }
        assert_eq!(base, base.clone());
        // Ordered by path first, then dot, then provenance.
        assert!(base < other_path && base < other_dot && base < other_provenance);
        assert!(other_provenance < other_dot && other_dot < other_path);
    }

    #[test]
    fn check_invariants_catches_a_hand_constructed_zero_seq_head() {
        let a = author("a");
        let mut s = NativeState::new();
        s.context.insert(a.clone(), AuthorSeq(1));
        let zero_dot = Dot { author: a.clone(), seq: AuthorSeq(0) };
        s.heads.insert(path("x"), BTreeMap::from([(zero_dot.clone(), payload(1, 1))]));
        let err = s.check_invariants().unwrap_err();
        assert_eq!(err, InvariantViolation::ZeroSeq { path: path("x"), dot: zero_dot });
    }

    // Create, update and delete of one path.
    #[test]
    fn create_update_delete() {
        let a = author("a");
        let mut s = NativeState::new();
        let d1 = s.put(&a, path("x"), &[], payload(1, 1)).unwrap();
        let d2 = s.put(&a, path("x"), &[d1], payload(2, 2)).unwrap();
        assert_eq!(s.dots_at(&path("x")), vec![d2.clone()]);
        s.delete(&a, path("x"), &[d2]).unwrap();
        assert!(s.dots_at(&path("x")).is_empty());
        s.check_invariants().unwrap();
    }

    // Concurrent creates keep both heads.
    #[test]
    fn concurrent_create_keeps_both_heads() {
        let a = author("a");
        let b = author("b");
        let mut left = NativeState::new();
        left.put(&a, path("x"), &[], payload(1, 1)).unwrap();
        let mut right = NativeState::new();
        right.put(&b, path("x"), &[], payload(2, 2)).unwrap();
        let joined = join(&left, &right).unwrap();
        assert_eq!(joined.dots_at(&path("x")).len(), 2);
        joined.check_invariants().unwrap();
    }

    // Conflict-copy edit and delete act on the copy only,
    // as one atomic mutation touching both the real name and the copy path.
    #[test]
    fn conflict_copy_edit_and_delete_act_on_the_copy_only() {
        let a = author("a");
        let b = author("b");
        let mut left = NativeState::new();
        let winner = left.put(&a, path("x"), &[], payload(1, 1)).unwrap();
        let mut right = NativeState::new();
        let loser = right.put(&b, path("x"), &[], payload(2, 2)).unwrap();
        let mut joined = join(&left, &right).unwrap();
        assert_eq!(joined.dots_at(&path("x")).len(), 2);

        // Edit the conflict copy of the loser: remove the loser at the real
        // name, put new content at the copy path — one atomic `author()`
        // call.
        let copy = path("x (conflict)");
        joined
            .author(
                &b,
                vec![
                    PathEdit { path: path("x"), observed: vec![loser.clone()], put: None },
                    PathEdit { path: copy.clone(), observed: vec![], put: Some(payload(5, 5)) },
                ],
            )
            .unwrap();
        assert_eq!(joined.dots_at(&path("x")), vec![winner.clone()]);
        assert_eq!(joined.dots_at(&copy).len(), 1);
        let copy_dot = joined.dots_at(&copy)[0].clone();

        // Delete the conflict copy: removes only the copy's own head
        // (this head lives at the copy path already, unlike the
        // loser case above which lived at the real name).
        joined.delete(&b, copy.clone(), &[copy_dot]).unwrap();
        assert!(joined.dots_at(&copy).is_empty());
        assert_eq!(joined.dots_at(&path("x")), vec![winner]);
        joined.check_invariants().unwrap();
    }

    // `rm -rf` removes the known descendants and the root entry.
    #[test]
    fn rm_rf_removes_known_descendants_and_root_entry() {
        let a = author("a");
        let mut s = NativeState::new();
        s.put(&a, path("dir"), &[], payload(1, 1)).unwrap();
        s.put(&a, path("dir/foo"), &[], payload(2, 2)).unwrap();
        s.clear_prefix(&a, "dir").unwrap();
        assert!(s.dots_at(&path("dir")).is_empty());
        assert!(s.dots_at(&path("dir/foo")).is_empty());
        s.check_invariants().unwrap();
    }

    // `rm -rf` does not remove a concurrent descendant create:
    // a descendant created concurrently, and never observed by the rm -rf's
    // dot, survives the join.
    #[test]
    fn rm_rf_does_not_remove_concurrent_descendant_create() {
        let a = author("a");
        let b = author("b");
        let mut left = NativeState::new();
        left.put(&a, path("dir/foo"), &[], payload(1, 1)).unwrap();
        let rmrf_dot = left.clear_prefix(&a, "dir").unwrap();
        assert!(left.dots_at(&path("dir/foo")).is_empty());

        let mut right = NativeState::new();
        right.put(&b, path("dir/bar"), &[], payload(2, 2)).unwrap();

        let joined = join(&left, &right).unwrap();
        assert!(joined.dots_at(&path("dir/foo")).is_empty());
        assert_eq!(joined.dots_at(&path("dir/bar")).len(), 1);
        assert!(joined.context_of(&a).is_some_and(|seq| seq == rmrf_dot.seq));
        joined.check_invariants().unwrap();
    }

    // Same dot, different payload: an author fork. `join` must fail closed,
    // never pick a winner.
    #[test]
    fn same_dot_fork_fails_closed() {
        let dot = Dot { author: author("a"), seq: AuthorSeq::FIRST };
        let mut left = NativeState::new();
        left.context.insert(author("a"), AuthorSeq::FIRST);
        left.heads.insert(path("x"), BTreeMap::from([(dot.clone(), payload(1, 1))]));
        let mut right = NativeState::new();
        right.context.insert(author("a"), AuthorSeq::FIRST);
        right.heads.insert(path("x"), BTreeMap::from([(dot.clone(), payload(2, 2))]));

        let err = join(&left, &right).unwrap_err();
        assert_eq!(err.dot, dot);
    }

    // The version decides the winner, not provenance or arrival order.
    #[test]
    fn the_higher_version_wins_whatever_the_provenance() {
        let a = LiveHead {
            dot: Dot { author: author("a"), seq: AuthorSeq::FIRST },
            payload: payload(2, 9),
        };
        let b = LiveHead {
            dot: Dot { author: author("b"), seq: AuthorSeq::FIRST },
            payload: payload(1, 200),
        };
        assert_eq!(resolve_winner([&a, &b]).unwrap().payload.version, version(2));
        assert_eq!(resolve_winner([&b, &a]).unwrap().payload.version, version(2));
    }

    // Heads of one version are represented by the larger provenance even
    // when the smaller `Dot` carries it: `Dot` never participates.
    #[test]
    fn equal_version_heads_are_represented_by_the_larger_provenance() {
        let smaller_dot_bigger_hash = LiveHead {
            dot: Dot { author: author("a"), seq: AuthorSeq::FIRST },
            payload: payload(1, 250),
        };
        let bigger_dot_smaller_hash = LiveHead {
            dot: Dot { author: author("z"), seq: AuthorSeq::FIRST },
            payload: payload(1, 10),
        };
        let winner = resolve_winner([&smaller_dot_bigger_hash, &bigger_dot_smaller_hash]).unwrap();
        assert_eq!(winner.payload.provenance, hash(250));
    }

    /// A restored/cloned replica of the same device, under a different
    /// incarnation, is a distinct author: it does not inherit or collide
    /// with the original incarnation's sequence numbers. Same `DeviceId`,
    /// different `IncarnationId` heads coexist as two independent authors.
    #[test]
    fn same_device_different_incarnation_is_a_distinct_author_with_no_seq_collision() {
        let original = author_incarnation("device-a", 1);
        let restored = author_incarnation("device-a", 2);
        assert_eq!(original.device, restored.device);
        assert_ne!(original, restored);

        let mut s = NativeState::new();
        s.put(&original, path("x"), &[], payload(1, 1)).unwrap();
        s.put(&original, path("x"), &[s.dots_at(&path("x"))[0].clone()], payload(2, 2)).unwrap();
        assert_eq!(s.context_of(&original), Some(AuthorSeq(2)));
        assert_eq!(
            s.context_of(&restored),
            None,
            "the restored incarnation has never authored here"
        );

        // The restored incarnation starts its own chain at seq 1 --
        // independent of, and not colliding with, the original's seq 2.
        let restored_dot = s.put(&restored, path("y"), &[], payload(3, 3)).unwrap();
        assert_eq!(restored_dot.seq, AuthorSeq::FIRST);
        assert_eq!(
            s.context_of(&original),
            Some(AuthorSeq(2)),
            "the original's position is untouched"
        );
        s.check_invariants().unwrap();
    }

    // --- `receive_verified` (remote admission's best-effort apply) --

    #[test]
    fn receive_verified_lands_a_first_delta_like_author_does() {
        let mut s = NativeState::new();
        let a = author("a");
        let dot = s
            .receive_verified(
                &a,
                AuthorSeq::FIRST,
                &[RemoteOp { path: path("x"), removes: vec![], put: Some(payload(1, 1)) }],
            )
            .unwrap();
        assert_eq!(dot, Dot { author: a.clone(), seq: AuthorSeq::FIRST });
        assert_eq!(s.heads[&path("x")][&dot], payload(1, 1));
        assert_eq!(s.context_of(&a), Some(AuthorSeq::FIRST));
    }

    /// The defining case: a removal
    /// naming a dot this replica *has* observed, but which a concurrent
    /// edit already superseded with a different provenance, is not an
    /// error -- it is simply skipped, and the delta's own `put` still
    /// lands.
    #[test]
    fn receive_verified_silently_skips_a_removal_whose_live_head_has_a_different_provenance() {
        let mut s = NativeState::new();
        let a = author("a");
        let b = author("b");
        let concurrent_dot = s.put(&b, path("x"), &[], payload(9, 100)).unwrap();
        // `a`'s delta was signed against an earlier view of `x` and claims
        // to remove `concurrent_dot` under a provenance that is no longer
        // (or never was) the one actually live there.
        let stale_removal = HeadRef { dot: concurrent_dot.clone(), provenance: hash(1) };
        let dot = s
            .receive_verified(
                &a,
                AuthorSeq::FIRST,
                &[RemoteOp {
                    path: path("x"),
                    removes: vec![stale_removal],
                    put: Some(payload(2, 1)),
                }],
            )
            .unwrap();
        assert_eq!(
            s.heads[&path("x")].get(&concurrent_dot),
            Some(&payload(9, 100)),
            "mismatched-provenance removal must not apply"
        );
        assert_eq!(
            s.heads[&path("x")].get(&dot),
            Some(&payload(2, 1)),
            "the delta's own put must still land"
        );
    }

    /// A removal naming a dot never observed at this path at all (already
    /// removed by someone else, or simply never present) is likewise a
    /// no-op, not an error.
    #[test]
    fn receive_verified_silently_skips_a_removal_of_an_absent_dot() {
        let mut s = NativeState::new();
        let a = author("a");
        let phantom = Dot { author: author("ghost"), seq: AuthorSeq::FIRST };
        let dot = s
            .receive_verified(
                &a,
                AuthorSeq::FIRST,
                &[RemoteOp {
                    path: path("x"),
                    removes: vec![HeadRef { dot: phantom, provenance: hash(1) }],
                    put: Some(payload(1, 1)),
                }],
            )
            .unwrap();
        assert_eq!(s.heads[&path("x")].len(), 1);
        assert!(s.heads[&path("x")].contains_key(&dot));
    }

    /// A removal whose live head matches its claimed provenance exactly
    /// still applies (ordinary convergence case), exactly like `author`.
    #[test]
    fn receive_verified_applies_a_removal_whose_provenance_matches() {
        let mut s = NativeState::new();
        let a = author("a");
        let existing = Dot { author: author("b"), seq: AuthorSeq::FIRST };
        s.heads.insert(path("x"), BTreeMap::from([(existing.clone(), payload(9, 5))]));
        s.context.insert(author("b"), AuthorSeq::FIRST);
        s.receive_verified(
            &a,
            AuthorSeq::FIRST,
            &[RemoteOp {
                path: path("x"),
                removes: vec![HeadRef { dot: existing.clone(), provenance: hash(5) }],
                put: None,
            }],
        )
        .unwrap();
        assert!(!s.heads.contains_key(&path("x")), "the path is empty and must not be stored");
    }

    #[test]
    fn receive_verified_rejects_a_duplicate_path_as_malformed() {
        let mut s = NativeState::new();
        let a = author("a");
        let err = s
            .receive_verified(
                &a,
                AuthorSeq::FIRST,
                &[
                    RemoteOp { path: path("x"), removes: vec![], put: Some(payload(1, 1)) },
                    RemoteOp { path: path("x"), removes: vec![], put: Some(payload(2, 1)) },
                ],
            )
            .unwrap_err();
        assert!(matches!(err, AuthorError::DuplicatePath { .. }));
        assert!(s.heads.is_empty(), "a refused delta must not touch state");
    }

    #[test]
    fn receive_verified_rejects_a_duplicate_observed_dot_at_one_path_as_malformed() {
        let mut s = NativeState::new();
        let a = author("a");
        let existing = Dot { author: author("b"), seq: AuthorSeq::FIRST };
        let err = s
            .receive_verified(
                &a,
                AuthorSeq::FIRST,
                &[RemoteOp {
                    path: path("x"),
                    removes: vec![
                        HeadRef { dot: existing.clone(), provenance: hash(1) },
                        HeadRef { dot: existing, provenance: hash(1) },
                    ],
                    put: None,
                }],
            )
            .unwrap_err();
        assert!(matches!(err, AuthorError::DuplicateObserved { .. }));
    }
}
