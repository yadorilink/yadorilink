//! An in-memory [`NodeStoreV2`].

use std::collections::HashMap;

use crate::v2::NodeStoreV2;
use crate::{AuthorNode, NamespaceError, NodeDigest, NodeV2, ShapeNodeV2};

/// A [`NodeStoreV2`] holding every node in memory, keyed by digest. Nodes
/// are never removed.
#[derive(Clone, Debug, Default)]
pub struct MemoryNodeStore {
    nodes: HashMap<NodeDigest, NodeV2>,
    authors: HashMap<NodeDigest, AuthorNode>,
    shapes: HashMap<NodeDigest, ShapeNodeV2>,
}

impl MemoryNodeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored nodes of every kind.
    pub fn len(&self) -> usize {
        self.nodes.len() + self.authors.len() + self.shapes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl NodeStoreV2 for MemoryNodeStore {
    fn get(&self, digest: &NodeDigest) -> Result<Option<NodeV2>, NamespaceError> {
        Ok(self.nodes.get(digest).cloned())
    }

    fn put(&mut self, node: &NodeV2) -> Result<NodeDigest, NamespaceError> {
        let digest = node.digest();
        self.nodes.entry(digest).or_insert_with(|| node.clone());
        Ok(digest)
    }

    fn get_author(&self, digest: &NodeDigest) -> Result<Option<AuthorNode>, NamespaceError> {
        Ok(self.authors.get(digest).cloned())
    }

    fn put_author(&mut self, node: &AuthorNode) -> Result<NodeDigest, NamespaceError> {
        let digest = node.digest();
        self.authors.entry(digest).or_insert_with(|| node.clone());
        Ok(digest)
    }

    fn get_shape(&self, digest: &NodeDigest) -> Result<Option<ShapeNodeV2>, NamespaceError> {
        Ok(self.shapes.get(digest).cloned())
    }

    fn put_shape(&mut self, node: &ShapeNodeV2) -> Result<NodeDigest, NamespaceError> {
        let digest = node.digest();
        self.shapes.entry(digest).or_insert_with(|| node.clone());
        Ok(digest)
    }
}
