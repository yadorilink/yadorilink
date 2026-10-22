//! Trie operations over decoded views of stored nodes.
//!
//! A [`View`] is a subtree positioned at some key: either a digest still in
//! the store (read only when an operation needs to look inside it) or one
//! decoded node whose children are stored digests. Operations descend one
//! position at a time, as the uncompressed trie of the reference model
//! does, and rebuild with [`mk`], which restores canonical form at every
//! level: folding entry-less single-child positions into a `skip` and
//! merging subtrees whose entries share one bucket trie into one uniform
//! node.
//!
//! A position's heads are named by the digest of its bucket trie (the
//! empty digest when the position holds no entry), so comparing heads is
//! comparing digests; bucket tries are read only where two sides differ.

use std::collections::{BTreeSet, HashMap};

use yadorilink_replica_domain::author::AuthorBuckets;
use yadorilink_replica_domain::ids::{DeltaHash, SyncPath};

use crate::bucket;
use crate::v2::{NodeStoreV2, PathDiffV2};
use crate::{
    empty_digest, HeadAggregates, NamespaceError, NodeDigest, NodeV2, PathBits, ShapeNodeV2,
};

type Bits = Vec<bool>;

/// A content-shape node's fields below its `skip`.
#[derive(Clone, Debug)]
pub(crate) struct ShapeBody {
    entry: bool,
    entry_count: u64,
    zero: NodeDigest,
    one: NodeDigest,
}

/// A subtree positioned at some key; `skip`s are relative to that key.
#[derive(Clone, Debug)]
pub(crate) enum View {
    Empty,
    /// A non-empty stored subtree, not read yet.
    Stored(NodeDigest),
    Branch {
        skip: Bits,
        buckets: NodeDigest,
        aggregates: HeadAggregates,
        conflict: bool,
        zero: NodeDigest,
        one: NodeDigest,
    },
    /// Every entry of `shape` (rooted at the end of `skip`) holds the
    /// bucket trie `buckets`, whose counts are `per_entry`.
    Uniform {
        skip: Bits,
        buckets: NodeDigest,
        per_entry: HeadAggregates,
        shape: ShapeBody,
    },
}

impl View {
    pub(crate) fn stored(digest: NodeDigest) -> Self {
        if digest == empty_digest() {
            View::Empty
        } else {
            View::Stored(digest)
        }
    }

    fn is_empty(&self) -> bool {
        matches!(self, View::Empty)
    }

    /// The `skip` of a decoded view; empty for [`View::Empty`].
    fn skip(&self) -> &[bool] {
        match self {
            View::Branch { skip, .. } | View::Uniform { skip, .. } => skip,
            View::Empty | View::Stored(_) => &[],
        }
    }

    /// The same decoded subtree with another `skip`.
    fn with_skip(self, new_skip: Bits) -> Self {
        match self {
            View::Branch { buckets, aggregates, conflict, zero, one, .. } => {
                View::Branch { skip: new_skip, buckets, aggregates, conflict, zero, one }
            }
            View::Uniform { buckets, per_entry, shape, .. } => {
                View::Uniform { skip: new_skip, buckets, per_entry, shape }
            }
            other => other,
        }
    }

    /// Whether some entry below has more than one head.
    fn conflict(&self) -> bool {
        match self {
            View::Branch { conflict, .. } => *conflict,
            View::Uniform { per_entry, .. } => per_entry.head_count > 1,
            View::Empty | View::Stored(_) => false,
        }
    }

    /// The counts of a decoded view.
    fn aggregates(&self) -> HeadAggregates {
        match self {
            View::Branch { aggregates, .. } => *aggregates,
            View::Uniform { per_entry, shape, .. } => per_entry.times(shape.entry_count),
            View::Empty | View::Stored(_) => HeadAggregates::default(),
        }
    }

    fn uniform(&self) -> Option<(NodeDigest, HeadAggregates)> {
        match self {
            View::Uniform { buckets, per_entry, .. } => Some((*buckets, *per_entry)),
            _ => None,
        }
    }
}

fn shape_root(shape: &ShapeBody) -> ShapeNodeV2 {
    ShapeNodeV2 {
        skip: PathBits::default(),
        entry: shape.entry,
        entry_count: shape.entry_count,
        zero: shape.zero,
        one: shape.one,
    }
}

/// The node a decoded view is stored as.
fn to_node(view: &View) -> Option<NodeV2> {
    match view {
        View::Branch { skip, buckets, aggregates, conflict, zero, one } => Some(NodeV2::Branch {
            skip: PathBits::from_bits(skip),
            buckets: *buckets,
            aggregates: *aggregates,
            conflict: *conflict,
            zero: *zero,
            one: *one,
        }),
        View::Uniform { skip, buckets, shape, .. } => Some(NodeV2::Uniform {
            skip: PathBits::from_bits(skip),
            shape: shape_root(shape).digest(),
            buckets: *buckets,
            aggregates: view.aggregates(),
        }),
        View::Empty | View::Stored(_) => None,
    }
}

/// The committed digest of a view, without reading or writing the store.
pub(crate) fn digest_of(view: &View) -> NodeDigest {
    match view {
        View::Empty => empty_digest(),
        View::Stored(digest) => *digest,
        decoded => to_node(decoded).map_or_else(empty_digest, |node| node.digest()),
    }
}

/// Writes a view's own nodes (its children are already stored) and returns
/// its digest.
pub(crate) fn store_view(
    store: &mut dyn NodeStoreV2,
    view: &View,
) -> Result<NodeDigest, NamespaceError> {
    if let View::Uniform { shape, .. } = view {
        store.put_shape(&shape_root(shape))?;
    }
    match to_node(view) {
        Some(node) => store.put(&node),
        None => Ok(digest_of(view)),
    }
}

pub(crate) fn load_node(
    store: &dyn NodeStoreV2,
    digest: &NodeDigest,
) -> Result<NodeV2, NamespaceError> {
    let node = store.get(digest)?.ok_or(NamespaceError::MissingNode(*digest))?;
    if node.digest() != *digest {
        return Err(NamespaceError::DigestMismatch(*digest));
    }
    Ok(node)
}

fn load_shape(store: &dyn NodeStoreV2, digest: &NodeDigest) -> Result<ShapeNodeV2, NamespaceError> {
    let node = store.get_shape(digest)?.ok_or(NamespaceError::MissingNode(*digest))?;
    if node.digest() != *digest {
        return Err(NamespaceError::DigestMismatch(*digest));
    }
    Ok(node)
}

/// The fields of a shape node below its skip, checking the rules a single
/// node can show: a position without an entry has two non-empty children,
/// and a subtree has at least one entry.
fn shape_body(node: &ShapeNodeV2, owner: &NodeDigest) -> Result<ShapeBody, NamespaceError> {
    let empty = empty_digest();
    if node.entry_count == 0 || (!node.entry && (node.zero == empty || node.one == empty)) {
        return Err(NamespaceError::NotCanonical(*owner));
    }
    Ok(ShapeBody {
        entry: node.entry,
        entry_count: node.entry_count,
        zero: node.zero,
        one: node.one,
    })
}

/// Decodes a stored view; any other view is returned as is. Checks the
/// canonical rules a single node shows (an entry-less branch has two
/// children; a uniform node has heads and a shape rooted at its own
/// position, and counts divisible by that shape's entry count), so that a
/// node received from elsewhere is checked as it is reached.
fn resolve(store: &dyn NodeStoreV2, view: View) -> Result<View, NamespaceError> {
    let View::Stored(digest) = view else {
        return Ok(view);
    };
    let not_canonical = || NamespaceError::NotCanonical(digest);
    let empty = empty_digest();
    Ok(match load_node(store, &digest)? {
        NodeV2::Branch { skip, buckets, aggregates, conflict, zero, one } => {
            if buckets == empty && (zero == empty || one == empty) {
                return Err(not_canonical());
            }
            View::Branch { skip: skip.to_bits(), buckets, aggregates, conflict, zero, one }
        }
        NodeV2::Uniform { skip, shape, buckets, aggregates } => {
            if buckets == empty {
                return Err(not_canonical());
            }
            let root = load_shape(store, &shape)?;
            if root.skip.len != 0 {
                return Err(not_canonical());
            }
            let shape = shape_body(&root, &digest)?;
            let n = shape.entry_count;
            if aggregates.head_count % n != 0 || aggregates.duplicate_author_count % n != 0 {
                return Err(not_canonical());
            }
            let per_entry = HeadAggregates {
                head_count: aggregates.head_count / n,
                duplicate_author_count: aggregates.duplicate_author_count / n,
            };
            View::Uniform { skip: skip.to_bits(), buckets, per_entry, shape }
        }
    })
}

/// The uniform subtree over shape child `digest`.
fn uniform_child(
    store: &dyn NodeStoreV2,
    buckets: NodeDigest,
    per_entry: HeadAggregates,
    digest: &NodeDigest,
) -> Result<View, NamespaceError> {
    if *digest == empty_digest() {
        return Ok(View::Empty);
    }
    let node = load_shape(store, digest)?;
    Ok(View::Uniform {
        skip: node.skip.to_bits(),
        buckets,
        per_entry,
        shape: shape_body(&node, digest)?,
    })
}

/// One position of the uncompressed trie: the bucket trie at the view's
/// own key (the empty digest for no entry) and the subtrees one bit below
/// it (zero child, one child).
///
pub(crate) fn split(
    store: &dyn NodeStoreV2,
    view: View,
) -> Result<(NodeDigest, View, View), NamespaceError> {
    let view = resolve(store, view)?;
    if let Some((&first, rest)) = view.skip().split_first() {
        let rest = rest.to_vec();
        let child = view.with_skip(rest);
        return Ok(if first {
            (empty_digest(), View::Empty, child)
        } else {
            (empty_digest(), child, View::Empty)
        });
    }
    match view {
        View::Branch { buckets, zero, one, .. } => {
            Ok((buckets, View::stored(zero), View::stored(one)))
        }
        View::Uniform { buckets, per_entry, shape, .. } => {
            let own = if shape.entry { buckets } else { empty_digest() };
            let zero = uniform_child(store, buckets, per_entry, &shape.zero)?;
            let one = uniform_child(store, buckets, per_entry, &shape.one)?;
            Ok((own, zero, one))
        }
        View::Empty | View::Stored(_) => Ok((empty_digest(), View::Empty, View::Empty)),
    }
}

/// `view` moved down by `prefix`: placed at `prefix` below its position.
fn prefixed(store: &dyn NodeStoreV2, view: View, prefix: &[bool]) -> Result<View, NamespaceError> {
    if prefix.is_empty() || view.is_empty() {
        return Ok(view);
    }
    let view = resolve(store, view)?;
    let mut skip = prefix.to_vec();
    skip.extend_from_slice(view.skip());
    Ok(view.with_skip(skip))
}

/// The content-shape digest and entry count of a uniform child (stored),
/// or the empty digest and zero.
fn shape_of(store: &mut dyn NodeStoreV2, view: &View) -> Result<(NodeDigest, u64), NamespaceError> {
    match view {
        View::Uniform { skip, shape, .. } => {
            let digest = store.put_shape(&ShapeNodeV2 {
                skip: PathBits::from_bits(skip),
                entry: shape.entry,
                entry_count: shape.entry_count,
                zero: shape.zero,
                one: shape.one,
            })?;
            Ok((digest, shape.entry_count))
        }
        _ => Ok((empty_digest(), 0)),
    }
}

/// Smart constructor: the canonical subtree with bucket trie `own` at this
/// position (the empty digest for no entry) and children `zero`, `one`
/// (each canonical, positioned one bit below).
///
pub(crate) fn mk(
    store: &mut dyn NodeStoreV2,
    own: NodeDigest,
    zero: View,
    one: View,
) -> Result<View, NamespaceError> {
    let zero_view = resolve(&*store, zero.clone())?;
    let one_view = resolve(&*store, one.clone())?;
    let has_own = own != empty_digest();
    if !has_own {
        match (zero_view.is_empty(), one_view.is_empty()) {
            (true, true) => return Ok(View::Empty),
            (false, true) => return prefixed(&*store, zero_view, &[false]),
            (true, false) => return prefixed(&*store, one_view, &[true]),
            (false, false) => {}
        }
    }
    let child_uniform = zero_view.uniform().or(one_view.uniform());
    let candidate = if has_own { Some(own) } else { child_uniform.map(|(buckets, _)| buckets) };
    if let Some(uniform) = candidate {
        let fits = |view: &View| view.is_empty() || view.uniform().map(|(b, _)| b) == Some(uniform);
        if fits(&zero_view) && fits(&one_view) {
            let per_entry = match child_uniform {
                Some((_, per_entry)) => per_entry,
                None => bucket::aggregates(&*store, &uniform)?,
            };
            let (zero_shape, zero_count) = shape_of(store, &zero_view)?;
            let (one_shape, one_count) = shape_of(store, &one_view)?;
            let shape = ShapeBody {
                entry: has_own,
                entry_count: u64::from(has_own)
                    .saturating_add(zero_count)
                    .saturating_add(one_count),
                zero: zero_shape,
                one: one_shape,
            };
            return Ok(View::Uniform { skip: Vec::new(), buckets: uniform, per_entry, shape });
        }
    }
    let own_aggregates = bucket::aggregates(&*store, &own)?;
    let conflict = own_aggregates.head_count > 1 || zero_view.conflict() || one_view.conflict();
    let aggregates = own_aggregates.plus(zero_view.aggregates()).plus(one_view.aggregates());
    Ok(View::Branch {
        skip: Vec::new(),
        buckets: own,
        aggregates,
        conflict,
        zero: store_view(store, &zero)?,
        one: store_view(store, &one)?,
    })
}

fn common_prefix(a: &[bool], b: &[bool]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

/// The subtree at `key` below the view's position.
///
pub(crate) fn sub(
    store: &dyn NodeStoreV2,
    view: View,
    key: &[bool],
) -> Result<View, NamespaceError> {
    let mut view = view;
    let mut key = key;
    loop {
        if key.is_empty() {
            return Ok(view);
        }
        view = resolve(store, view)?;
        if view.is_empty() {
            return Ok(View::Empty);
        }
        let skip = view.skip();
        if !skip.is_empty() {
            let shared = common_prefix(skip, key);
            if shared == key.len() {
                let rest = skip[shared..].to_vec();
                return Ok(view.with_skip(rest));
            }
            if shared < skip.len() {
                return Ok(View::Empty);
            }
            view = view.with_skip(Vec::new());
            key = &key[shared..];
            continue;
        }
        let (_, zero, one) = split(store, view)?;
        view = if key[0] { one } else { zero };
        key = &key[1..];
    }
}

/// Replaces the subtree at `key` with `f` of it, rebuilding only the
/// positions on the way to `key`.
///
pub(crate) fn at_prefix<F>(
    store: &mut dyn NodeStoreV2,
    view: View,
    key: &[bool],
    f: F,
) -> Result<View, NamespaceError>
where
    F: FnOnce(&mut dyn NodeStoreV2, View) -> Result<View, NamespaceError>,
{
    if key.is_empty() {
        return f(store, view);
    }
    let view = resolve(&*store, view)?;
    if view.is_empty() {
        let placed = f(store, View::Empty)?;
        return prefixed(&*store, placed, key);
    }
    let skip = view.skip().to_vec();
    if skip.is_empty() {
        let (own, zero, one) = split(&*store, view)?;
        return if key[0] {
            let one = at_prefix(store, one, &key[1..], f)?;
            mk(store, own, zero, one)
        } else {
            let zero = at_prefix(store, zero, &key[1..], f)?;
            mk(store, own, zero, one)
        };
    }
    let shared = common_prefix(&skip, key);
    if shared == skip.len() {
        // `key` runs through this node's position.
        let inner = at_prefix(store, view.with_skip(Vec::new()), &key[shared..], f)?;
        return prefixed(&*store, inner, &skip);
    }
    if shared == key.len() {
        // `key` ends inside this node's skip.
        let replaced = f(store, view.with_skip(skip[shared..].to_vec()))?;
        return prefixed(&*store, replaced, key);
    }
    // `key` leaves this node's skip: the subtree there is empty.
    let placed = f(store, View::Empty)?;
    if placed.is_empty() {
        return Ok(view);
    }
    let existing = view.with_skip(skip[shared + 1..].to_vec());
    let placed = prefixed(&*store, placed, &key[shared + 1..])?;
    let (zero, one) = if skip[shared] { (placed, existing) } else { (existing, placed) };
    let fork = mk(store, empty_digest(), zero, one)?;
    prefixed(&*store, fork, &skip[..shared])
}

/// One position of the uncompressed trie, as [`split`] returns it.
type Position = (NodeDigest, View, View);

/// How two views at the same position are walked together.
#[derive(Clone)]
enum Aligned {
    /// Both continue with the same bits: descend both by them at once.
    Shared(Box<(Bits, View, View)>),
    /// Split both one position.
    Split(Box<(Position, Position)>),
}

fn align(store: &dyn NodeStoreV2, a: View, b: View) -> Result<Aligned, NamespaceError> {
    let a = resolve(store, a)?;
    let b = resolve(store, b)?;
    // An empty side continues with any bits, so both descend by the other
    // side's whole skip at once.
    let (shared, bits_of) = match (a.is_empty(), b.is_empty()) {
        (true, _) => (b.skip().len(), &b),
        (false, true) => (a.skip().len(), &a),
        (false, false) => (common_prefix(a.skip(), b.skip()), &a),
    };
    if shared > 0 {
        let bits = bits_of.skip()[..shared].to_vec();
        let a_rest = a.skip().get(shared..).unwrap_or_default().to_vec();
        let b_rest = b.skip().get(shared..).unwrap_or_default().to_vec();
        return Ok(Aligned::Shared(Box::new((bits, a.with_skip(a_rest), b.with_skip(b_rest)))));
    }
    Ok(Aligned::Split(Box::new((split(store, a)?, split(store, b)?))))
}

/// The whole map of the bucket trie `digest`.
pub(crate) fn read_buckets(
    store: &dyn NodeStoreV2,
    digest: &NodeDigest,
) -> Result<AuthorBuckets, NamespaceError> {
    let mut budget = usize::MAX;
    bucket::read(store, digest, &mut budget)
}

/// The path of a whole-byte key.
fn path_of(bits: &[bool]) -> Result<SyncPath, NamespaceError> {
    if !bits.len().is_multiple_of(8) {
        return Err(NamespaceError::Malformed(
            "entry at a key that is not a whole number of bytes".to_string(),
        ));
    }
    let bytes = PathBits::from_bits(bits).bytes;
    String::from_utf8(bytes)
        .map(SyncPath)
        .map_err(|_| NamespaceError::Malformed("entry key is not UTF-8".to_string()))
}

/// Appends every path under `position` whose heads differ, in key order.
pub(crate) fn diff(
    store: &dyn NodeStoreV2,
    left: View,
    right: View,
    position: &mut Bits,
    out: &mut Vec<PathDiffV2>,
) -> Result<(), NamespaceError> {
    if digest_of(&left) == digest_of(&right) {
        return Ok(());
    }
    match align(store, left, right)? {
        Aligned::Shared(shared) => {
            let (bits, left, right) = *shared;
            let depth = position.len();
            position.extend_from_slice(&bits);
            let result = diff(store, left, right, position, out);
            position.truncate(depth);
            result?;
        }
        Aligned::Split(pair) => {
            let ((left_own, left_zero, left_one), (right_own, right_zero, right_one)) = *pair;
            if left_own != right_own {
                out.push(PathDiffV2 {
                    path: path_of(position)?,
                    left: read_buckets(store, &left_own)?,
                    right: read_buckets(store, &right_own)?,
                });
            }
            position.push(false);
            let result = diff(store, left_zero, right_zero, position, out);
            position.pop();
            result?;
            position.push(true);
            let result = diff(store, left_one, right_one, position, out);
            position.pop();
            result?;
        }
    }
    Ok(())
}

/// The bucket trie `digest` without the heads `seen` answers for.
fn filter_buckets(
    store: &mut dyn NodeStoreV2,
    digest: NodeDigest,
    seen: &dyn Fn(&DeltaHash) -> bool,
) -> Result<(NodeDigest, HeadAggregates), NamespaceError> {
    let mut heads = read_buckets(&*store, &digest)?;
    for bucket in heads.by_author.values_mut() {
        bucket.retain(|head| !seen(head));
    }
    bucket::store_heads(store, &heads)
}

/// Keeps the heads the other side has not seen.
///
fn filter_unseen(
    store: &mut dyn NodeStoreV2,
    view: View,
    seen: &dyn Fn(&DeltaHash) -> bool,
) -> Result<View, NamespaceError> {
    let view = resolve(&*store, view)?;
    match view {
        View::Empty | View::Stored(_) => Ok(View::Empty),
        View::Uniform { skip, buckets, shape, .. } => {
            let (buckets, per_entry) = filter_buckets(store, buckets, seen)?;
            Ok(if buckets == empty_digest() {
                View::Empty
            } else {
                View::Uniform { skip, buckets, per_entry, shape }
            })
        }
        branch @ View::Branch { .. } if !branch.skip().is_empty() => {
            let skip = branch.skip().to_vec();
            let inner = filter_unseen(store, branch.with_skip(Vec::new()), seen)?;
            prefixed(&*store, inner, &skip)
        }
        branch => {
            let (own, zero, one) = split(&*store, branch)?;
            let (own, _) = filter_buckets(store, own, seen)?;
            let zero = filter_unseen(store, zero, seen)?;
            let one = filter_unseen(store, one, seen)?;
            mk(store, own, zero, one)
        }
    }
}

/// The per-path join of two bucket tries, author by author.
///
fn join_buckets(
    store: &mut dyn NodeStoreV2,
    left: NodeDigest,
    right: NodeDigest,
    seen_by_left: &dyn Fn(&DeltaHash) -> bool,
    seen_by_right: &dyn Fn(&DeltaHash) -> bool,
) -> Result<NodeDigest, NamespaceError> {
    let left = read_buckets(&*store, &left)?;
    let right = read_buckets(&*store, &right)?;
    let right_heads = bucket::flatten(&right);
    let mut joined = AuthorBuckets::default();
    let authors: BTreeSet<_> = left.by_author.keys().chain(right.by_author.keys()).collect();
    for author in authors {
        let from_left = left.by_author.get(author).into_iter().flatten();
        let from_right = right.by_author.get(author).into_iter().flatten();
        let bucket: Vec<DeltaHash> = from_left
            .filter(|head| right_heads.contains(head) || !seen_by_right(head))
            .chain(from_right.filter(|head| !seen_by_left(head)))
            .copied()
            .collect();
        joined.by_author.insert(author.clone(), bucket);
    }
    Ok(bucket::store_heads(store, &joined)?.0)
}

/// Joins two full states by digest.
///
pub(crate) fn full_zip(
    store: &mut dyn NodeStoreV2,
    left: View,
    right: View,
    seen_by_left: &dyn Fn(&DeltaHash) -> bool,
    seen_by_right: &dyn Fn(&DeltaHash) -> bool,
) -> Result<View, NamespaceError> {
    if left.is_empty() {
        return filter_unseen(store, right, seen_by_left);
    }
    if right.is_empty() {
        return filter_unseen(store, left, seen_by_right);
    }
    if digest_of(&left) == digest_of(&right) {
        return Ok(left);
    }
    match align(&*store, left, right)? {
        Aligned::Shared(shared) => {
            let (bits, left, right) = *shared;
            let inner = full_zip(store, left, right, seen_by_left, seen_by_right)?;
            prefixed(&*store, inner, &bits)
        }
        Aligned::Split(pair) => {
            let ((left_own, left_zero, left_one), (right_own, right_zero, right_one)) = *pair;
            let own = if left_own == right_own {
                left_own
            } else {
                join_buckets(store, left_own, right_own, seen_by_left, seen_by_right)?
            };
            let zero = full_zip(store, left_zero, right_zero, seen_by_left, seen_by_right)?;
            let one = full_zip(store, left_one, right_one, seen_by_left, seen_by_right)?;
            mk(store, own, zero, one)
        }
    }
}

// --- Canonical-form check ---------------------------------------------------

/// What a checked subtree looks like to its parent.
enum Checked {
    Empty,
    Uniform { buckets: NodeDigest, per_entry: HeadAggregates, aggregates: HeadAggregates },
    Branch { conflict: bool, aggregates: HeadAggregates },
}

impl Checked {
    fn is_empty(&self) -> bool {
        matches!(self, Checked::Empty)
    }

    fn uniform(&self) -> Option<NodeDigest> {
        match self {
            Checked::Uniform { buckets, .. } => Some(*buckets),
            _ => None,
        }
    }

    fn conflict(&self) -> bool {
        match self {
            Checked::Empty => false,
            Checked::Uniform { per_entry, .. } => per_entry.head_count > 1,
            Checked::Branch { conflict, .. } => *conflict,
        }
    }

    fn aggregates(&self) -> HeadAggregates {
        match self {
            Checked::Empty => HeadAggregates::default(),
            Checked::Uniform { aggregates, .. } | Checked::Branch { aggregates, .. } => *aggregates,
        }
    }
}

struct Checker<'a> {
    store: &'a dyn NodeStoreV2,
    remaining: usize,
    /// Bucket tries already checked, with their counts.
    buckets: HashMap<NodeDigest, HeadAggregates>,
}

impl Checker<'_> {
    fn spend(&mut self) -> Result<(), NamespaceError> {
        if self.remaining == 0 {
            return Err(NamespaceError::Malformed("namespace exceeds its node budget".to_string()));
        }
        self.remaining -= 1;
        Ok(())
    }

    /// Checks the bucket trie `digest` and returns its counts.
    fn buckets(&mut self, digest: &NodeDigest) -> Result<HeadAggregates, NamespaceError> {
        if let Some(aggregates) = self.buckets.get(digest) {
            return Ok(*aggregates);
        }
        let heads = bucket::read(self.store, digest, &mut self.remaining)?;
        let aggregates = heads
            .by_author
            .values()
            .fold(HeadAggregates::default(), |sum, b| sum.plus(HeadAggregates::of_bucket(b.len())));
        self.buckets.insert(*digest, aggregates);
        Ok(aggregates)
    }

    /// Checks the heads subtree `digest` whose parent position ends
    /// `depth` bits into the key.
    fn node(&mut self, digest: &NodeDigest, depth: usize) -> Result<Checked, NamespaceError> {
        if *digest == empty_digest() {
            return Ok(Checked::Empty);
        }
        self.spend()?;
        let not_canonical = || NamespaceError::NotCanonical(*digest);
        match load_node(self.store, digest)? {
            NodeV2::Branch { skip, buckets, aggregates, conflict, zero, one } => {
                let at = depth + skip.len as usize;
                let has_own = buckets != empty_digest();
                if has_own && !at.is_multiple_of(8) {
                    return Err(not_canonical());
                }
                let own = self.buckets(&buckets)?;
                let zero = self.node(&zero, at + 1)?;
                let one = self.node(&one, at + 1)?;
                if !has_own && (zero.is_empty() || one.is_empty()) {
                    return Err(not_canonical());
                }
                let candidate =
                    if has_own { Some(buckets) } else { zero.uniform().or(one.uniform()) };
                if let Some(uniform) = candidate {
                    let fits = |c: &Checked| c.is_empty() || c.uniform() == Some(uniform);
                    if fits(&zero) && fits(&one) {
                        return Err(not_canonical());
                    }
                }
                let derived = own.head_count > 1 || zero.conflict() || one.conflict();
                if conflict != derived {
                    return Err(not_canonical());
                }
                let sum = own
                    .checked_plus(zero.aggregates())
                    .and_then(|sum| sum.checked_plus(one.aggregates()));
                if sum != Some(aggregates) {
                    return Err(not_canonical());
                }
                Ok(Checked::Branch { conflict, aggregates })
            }
            NodeV2::Uniform { skip, shape, buckets, aggregates } => {
                if buckets == empty_digest() {
                    return Err(not_canonical());
                }
                let at = depth + skip.len as usize;
                self.spend()?;
                let root = load_shape(self.store, &shape)?;
                if root.skip.len != 0 {
                    return Err(not_canonical());
                }
                let entries = self.shape_body(&root, at, digest)?;
                let per_entry = self.buckets(&buckets)?;
                if per_entry.checked_times(entries) != Some(aggregates) {
                    return Err(not_canonical());
                }
                Ok(Checked::Uniform { buckets, per_entry, aggregates })
            }
        }
    }

    /// Checks a shape node's fields at position `at` (after its skip) and
    /// returns its entry count.
    fn shape_body(
        &mut self,
        node: &ShapeNodeV2,
        at: usize,
        owner: &NodeDigest,
    ) -> Result<u64, NamespaceError> {
        let not_canonical = || NamespaceError::NotCanonical(*owner);
        if node.entry && !at.is_multiple_of(8) {
            return Err(not_canonical());
        }
        let zero = self.shape(&node.zero, at + 1)?;
        let one = self.shape(&node.one, at + 1)?;
        if !node.entry && (zero == 0 || one == 0) {
            return Err(not_canonical());
        }
        let derived = u64::from(node.entry).checked_add(zero).and_then(|n| n.checked_add(one));
        if derived != Some(node.entry_count) {
            return Err(not_canonical());
        }
        Ok(node.entry_count)
    }

    /// Checks the shape subtree `digest` and returns its entry count (zero
    /// for the empty shape).
    fn shape(&mut self, digest: &NodeDigest, depth: usize) -> Result<u64, NamespaceError> {
        if *digest == empty_digest() {
            return Ok(0);
        }
        self.spend()?;
        let node = load_shape(self.store, digest)?;
        self.shape_body(&node, depth + node.skip.len as usize, digest)
    }
}

pub(crate) fn check_canonical(
    store: &dyn NodeStoreV2,
    root: &NodeDigest,
    max_nodes: usize,
) -> Result<(), NamespaceError> {
    let mut checker = Checker { store, remaining: max_nodes, buckets: HashMap::new() };
    checker.node(root, 0).map(|_| ())
}
