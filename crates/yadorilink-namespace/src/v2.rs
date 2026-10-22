//! The namespace operations over [`AuthorBuckets`] (one bucket per author), on
//! the node format fixed in the crate doc ("Author buckets", "Node
//! encodings and digests").

use yadorilink_replica_domain::author::{AuthorBuckets, AuthorId, NodeDigest};
use yadorilink_replica_domain::ids::{DeltaHash, SyncPath};

use crate::engine::{self, View};
use crate::{
    bucket, empty_digest, AuthorNode, HeadAggregates, NamespaceError, NodeV2, PathBits, ShapeNodeV2,
};

/// Where nodes are read from and written to. Implemented by the caller's
/// storage; every read is verified against the requested digest, and a node
/// the store does not hold fails with [`NamespaceError::MissingNode`].
///
/// Each `put` stores a node under its digest and returns it; storing a node
/// that is already present is not an error.
pub trait NodeStoreV2 {
    fn get(&self, digest: &NodeDigest) -> Result<Option<NodeV2>, NamespaceError>;
    fn put(&mut self, node: &NodeV2) -> Result<NodeDigest, NamespaceError>;
    fn get_author(&self, digest: &NodeDigest) -> Result<Option<AuthorNode>, NamespaceError>;
    fn put_author(&mut self, node: &AuthorNode) -> Result<NodeDigest, NamespaceError>;
    fn get_shape(&self, digest: &NodeDigest) -> Result<Option<ShapeNodeV2>, NamespaceError>;
    fn put_shape(&mut self, node: &ShapeNodeV2) -> Result<NodeDigest, NamespaceError>;
}

/// One path's new heads in a [`patch`]; empty heads (no bucket) remove the
/// entry. Each bucket is taken as a set (its order and repetitions do not
/// matter); an empty bucket is no bucket, and one with more than
/// `MAX_SELF_HEADS` heads fails the patch as malformed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PathEditV2 {
    pub path: SyncPath,
    pub heads: AuthorBuckets,
}

/// One path whose heads differ between two namespaces.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PathDiffV2 {
    pub path: SyncPath,
    pub left: AuthorBuckets,
    pub right: AuthorBuckets,
}

/// The heads at `path` in the namespace rooted at `root`.
pub fn lookup(
    store: &dyn NodeStoreV2,
    root: &NodeDigest,
    path: &SyncPath,
) -> Result<AuthorBuckets, NamespaceError> {
    let key = PathBits::of_path(path).to_bits();
    let at = engine::sub(store, View::stored(*root), &key)?;
    let (own, _, _) = engine::split(store, at)?;
    engine::read_buckets(store, &own)
}

/// One author's bucket at `path`: `O(depth + log A)` node reads.
pub fn lookup_bucket(
    store: &dyn NodeStoreV2,
    root: &NodeDigest,
    path: &SyncPath,
    author: &AuthorId,
) -> Result<Vec<DeltaHash>, NamespaceError> {
    let key = PathBits::of_path(path).to_bits();
    let at = engine::sub(store, View::stored(*root), &key)?;
    let (own, _, _) = engine::split(store, at)?;
    bucket::lookup(store, &own, author)
}

/// Applies `edits` in order and returns the new canonical root.
///
pub fn patch(
    store: &mut dyn NodeStoreV2,
    root: &NodeDigest,
    edits: &[PathEditV2],
) -> Result<NodeDigest, NamespaceError> {
    let mut view = View::stored(*root);
    for edit in edits {
        let (own, _) = bucket::store_heads(store, &edit.heads)?;
        let key = PathBits::of_path(&edit.path).to_bits();
        view = engine::at_prefix(store, view, &key, move |store, at| {
            let (_, zero, one) = engine::split(&*store, at)?;
            engine::mk(store, own, zero, one)
        })?;
    }
    engine::store_view(store, &view)
}

/// Every path whose heads differ between `left` and `right`, ascending,
/// descending only where digests differ.
pub fn diff(
    store: &dyn NodeStoreV2,
    left: &NodeDigest,
    right: &NodeDigest,
) -> Result<Vec<PathDiffV2>, NamespaceError> {
    let mut out = Vec::new();
    let mut position = Vec::new();
    engine::diff(store, View::stored(*left), View::stored(*right), &mut position, &mut out)?;
    Ok(out)
}

/// The authenticated aggregate counts of the namespace rooted at `root`,
/// read from the root node alone (the empty namespace has zero counts). The seal reads
/// `duplicate_author_count == 0`.
pub fn root_aggregates(
    store: &dyn NodeStoreV2,
    root: &NodeDigest,
) -> Result<HeadAggregates, NamespaceError> {
    if *root == empty_digest() {
        return Ok(HeadAggregates::default());
    }
    Ok(match engine::load_node(store, root)? {
        NodeV2::Branch { aggregates, .. } | NodeV2::Uniform { aggregates, .. } => aggregates,
    })
}

/// Joins two full namespaces by digest: identical subtrees are shared, a
/// subtree present on one side only keeps the heads the other side has not
/// seen, and differing paths are joined author by author. `seen_by_left`
/// and `seen_by_right` answer whether a head's sequence number is within
/// that side's watermark for its author. A joined bucket over
/// `MAX_SELF_HEADS` fails as malformed.
///
pub fn full_zip(
    store: &mut dyn NodeStoreV2,
    left: &NodeDigest,
    right: &NodeDigest,
    seen_by_left: &dyn Fn(&DeltaHash) -> bool,
    seen_by_right: &dyn Fn(&DeltaHash) -> bool,
) -> Result<NodeDigest, NamespaceError> {
    let view = engine::full_zip(
        store,
        View::stored(*left),
        View::stored(*right),
        seen_by_left,
        seen_by_right,
    )?;
    engine::store_view(store, &view)
}

/// Verifies that `root` names a canonical namespace every node of which is
/// available and every count and flag of which is derived from its
/// content, reading at most `max_nodes` nodes of every kind together.
///
pub fn open(
    store: &dyn NodeStoreV2,
    root: &NodeDigest,
    max_nodes: usize,
) -> Result<(), NamespaceError> {
    engine::check_canonical(store, root, max_nodes)
}
