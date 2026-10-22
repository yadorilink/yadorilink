//! The authenticated namespace: a binary Patricia trie over path bits whose
//! nodes carry the present heads of their path, kept per author, and a
//! committed digest.
//!
//! The root digest is a function of the logical state (path -> author ->
//! heads) alone, because every stored trie is canonical. That makes three
//! things cheap:
//!
//! * diffing two namespaces descends only where the two tries' digests
//!   differ;
//! * two full states on different bases join by sharing identical subtrees;
//! * whether some author holds two heads at one path is read from the
//!   root's aggregate counts, without enumerating heads.
//!
//! Tries are persistent and content addressed: an operation writes only the
//! nodes on the paths it changes, and every untouched subtree of the result
//! is the input's subtree, referenced by the same digest. The operations
//! are in [`v2`].
//!
//! # Path keys
//!
//! A path's key is the bit string of its UTF-8 bytes, each byte most
//! significant bit first, with no terminator. A path's node therefore sits
//! on the way to every longer path it is a byte prefix of. The subtree of a
//! directory `d` is keyed by `key(d) ++ key("/")`, so `a/` covers `a/b` but
//! not `ab`, and not the entry `a` itself; the root directory's subtree is
//! the empty key.
//!
//! # Author buckets
//!
//! The heads at a path are kept per author: a path holds an authenticated
//! map from author to that author's heads there (its *bucket*, one or two
//! change hashes, strictly ascending; `MAX_SELF_HEADS` in the replica
//! domain), and every node carries authenticated aggregate counts
//! ([`HeadAggregates`]). One author's bucket is read in `O(log A)`
//! bucket-trie nodes for `A` authors ([`v2::lookup_bucket`]), and a base is
//! sealable (no path with two heads from one author) exactly when the
//! root's `duplicate_author_count` is zero.
//!
//! Writes are not yet per author: [`v2::patch`] takes a path's whole
//! author map, and the join and filter rebuild the whole
//! bucket trie of every path they change, so each touched path costs
//! `O(A)` bucket-trie node writes; digests do not depend on this. An edit that rewrites only the affected authors' leaves
//! and reuses every untouched child digest would bring a step to
//! `O((|basis| + 1) log A)` nodes per touched path.
//!
//! An author's key is the bit string of its canonical `AuthorId` encoding:
//! the device id's UTF-8 byte length as a big-endian `u32`, the device id,
//! then the 16 incarnation bytes, most significant bit first. The length
//! prefix makes the keys prefix-free, so in a bucket trie an entry sits
//! only at a leaf.
//!
//! # Node encodings and digests
//!
//! Every digest is SHA-256 over an eight-byte domain tag followed by the
//! node's encoding. Integers are big-endian; a bit string is its bit length
//! as `u32` followed by `ceil(len / 8)` bytes, most significant bit first,
//! unused trailing bits zero.
//!
//! * Empty trie (heads, bucket or shape): `SHA-256(`[`EMPTY_TAG`]`)`, no
//!   encoding, zero counts.
//! * Author branch ([`AUTHOR_BRANCH_TAG`]): `skip`, `u64` head count, `u64`
//!   duplicate-author count, the zero child's digest, the one child's
//!   digest. Both children are non-empty (canonical form), and the counts
//!   are the sums of the children's.
//! * Author bucket ([`AUTHOR_BUCKET_TAG`]): `skip` (the rest of the author's
//!   key), `u32` head count (1 or 2), the heads' change hashes strictly
//!   ascending (32 bytes each). Its head count is its number of heads; its
//!   duplicate-author count is `1` when it holds two heads, else `0`. A
//!   bucket with no heads is not stored (an author with no head has no
//!   entry); one with more than two is malformed.
//! * Branch ([`BRANCH_V2_TAG`]): `skip` (the key bits between the parent's
//!   branching bit and this node), the digest of the path's bucket trie
//!   (the empty digest when the path holds no entry), `u64` head count,
//!   `u64` duplicate-author count, one conflict-flag byte (`1` when some
//!   path at or below has more than one head, from any authors, else `0`),
//!   the zero child's digest, the one child's digest (32 bytes each; an
//!   absent child is the empty digest). The counts are the path's own
//!   bucket trie's plus both children's: the number of heads, and the
//!   number of (path, author) pairs with two heads, at or below the node.
//! * Uniform ([`UNIFORM_V2_TAG`]): `skip`, the content shape's digest, the
//!   shared bucket trie's digest, `u64` head count, `u64` duplicate-author
//!   count: every path of the shape carries that bucket trie, so the counts
//!   are the bucket trie's times the shape's entry count.
//! * Shape ([`SHAPE_V2_TAG`]): `skip`, one entry byte (`1` when the node's
//!   path holds an entry), `u64` entry count (entries at or below the
//!   node), the zero and one children's shape digests (an absent child is
//!   the empty digest).
//!
//! A node's children sit one bit below its position: the zero child covers
//! the keys continuing with bit `0`, the one child those continuing with
//! bit `1`, and each child's `skip` starts after that bit. The root node's
//! `skip` is measured from the start of the key (bit 0).
//!
//! Canonical form: no branch with no entry and two empty children; no
//! branch with no entry and exactly one non-empty child (it is folded into
//! the child's `skip`); a subtree whose every entry has the same bucket-trie
//! digest is a uniform node, never a branch. Equivalently, every node sits
//! at the longest common prefix of the keys of the entries below it, which
//! is an entry of its own or a point where both children are non-empty. A
//! uniform node's `skip` leads to that position and the root of its content
//! shape sits there too, so a uniform node's shape root always has an empty
//! `skip`; the shape's own children follow the same rule. Entries sit only
//! at whole-byte positions. A bucket trie follows the same rule over author
//! keys. Every count and every conflict flag is derived, and a node whose
//! counts or flag disagree with its content is not canonical.
//!
//! Every operation reads nodes through a [`v2::NodeStoreV2`] and checks each
//! one against the digest it was requested by. Operations other than
//! [`v2::open`] assume a canonical input; [`v2::open`] checks that for a root
//! received from elsewhere.
//!

mod bucket;
mod encoding;
mod engine;
mod memory;
pub mod v2;

#[cfg(test)]
mod tests;

pub use memory::MemoryNodeStore;
pub use yadorilink_replica_domain::author::NodeDigest;
use yadorilink_replica_domain::ids::DeltaHash;

/// Domain tag of the empty trie's digest.
pub const EMPTY_TAG: &[u8; 8] = b"YLNKnsE\x01";
/// Domain tag of a branch node (crate doc, "Node encodings and digests").
pub const BRANCH_V2_TAG: &[u8; 8] = b"YLNKnsN\x02";
/// Domain tag of a uniform-heads node.
pub const UNIFORM_V2_TAG: &[u8; 8] = b"YLNKnsU\x02";
/// Domain tag of a content-shape node, which carries its entry count.
pub const SHAPE_V2_TAG: &[u8; 8] = b"YLNKnsS\x02";
/// Domain tag of an inner node of a path's bucket trie.
pub const AUTHOR_BRANCH_TAG: &[u8; 8] = b"YLNKnsA\x01";
/// Domain tag of one author's bucket in a path's bucket trie.
pub const AUTHOR_BUCKET_TAG: &[u8; 8] = b"YLNKnsB\x01";

/// A bit string, most significant bit of each byte first.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct PathBits {
    /// Packed bits; unused trailing bits are zero.
    pub bytes: Vec<u8>,
    /// Number of bits.
    pub len: u32,
}

/// The authenticated aggregate counts of a node: the heads at or below it,
/// and the (path, author) pairs at or below it whose bucket holds two
/// heads. A sealable namespace has a root `duplicate_author_count` of zero.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct HeadAggregates {
    pub head_count: u64,
    pub duplicate_author_count: u64,
}

impl HeadAggregates {
    /// The counts of one bucket holding `heads` heads.
    pub fn of_bucket(heads: usize) -> Self {
        Self { head_count: heads as u64, duplicate_author_count: u64::from(heads > 1) }
    }

    /// The sum of two counts, or `None` on overflow.
    pub fn checked_plus(self, other: Self) -> Option<Self> {
        Some(Self {
            head_count: self.head_count.checked_add(other.head_count)?,
            duplicate_author_count: self
                .duplicate_author_count
                .checked_add(other.duplicate_author_count)?,
        })
    }

    /// The counts of `n` entries holding these counts each, or `None` on
    /// overflow.
    pub fn checked_times(self, n: u64) -> Option<Self> {
        Some(Self {
            head_count: self.head_count.checked_mul(n)?,
            duplicate_author_count: self.duplicate_author_count.checked_mul(n)?,
        })
    }

    /// [`Self::checked_plus`], saturating: only a namespace received from
    /// elsewhere and not checked by [`v2::open`] can overflow.
    pub(crate) fn plus(self, other: Self) -> Self {
        self.checked_plus(other)
            .unwrap_or(Self { head_count: u64::MAX, duplicate_author_count: u64::MAX })
    }

    /// [`Self::checked_times`], saturating.
    pub(crate) fn times(self, n: u64) -> Self {
        self.checked_times(n)
            .unwrap_or(Self { head_count: u64::MAX, duplicate_author_count: u64::MAX })
    }
}

/// One node of a path's bucket trie, keyed by author.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AuthorNode {
    Branch {
        skip: PathBits,
        aggregates: HeadAggregates,
        zero: NodeDigest,
        one: NodeDigest,
    },
    /// `skip` is the rest of the author's key; one or two heads.
    Bucket {
        skip: PathBits,
        heads: Vec<DeltaHash>,
    },
}

/// One node of the heads trie: a path's heads are the bucket trie named by
/// `buckets`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NodeV2 {
    Branch {
        skip: PathBits,
        buckets: NodeDigest,
        aggregates: HeadAggregates,
        conflict: bool,
        zero: NodeDigest,
        one: NodeDigest,
    },
    Uniform {
        skip: PathBits,
        shape: NodeDigest,
        buckets: NodeDigest,
        aggregates: HeadAggregates,
    },
}

/// One node of the content-shape trie.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ShapeNodeV2 {
    pub skip: PathBits,
    pub entry: bool,
    pub entry_count: u64,
    pub zero: NodeDigest,
    pub one: NodeDigest,
}

/// Why a namespace operation failed.
#[derive(Debug, thiserror::Error)]
pub enum NamespaceError {
    #[error("namespace node {0:?} is not available")]
    MissingNode(NodeDigest),
    #[error("namespace node {0:?} does not hash to its digest")]
    DigestMismatch(NodeDigest),
    #[error("namespace node is malformed: {0}")]
    Malformed(String),
    #[error("namespace trie is not canonical at {0:?}")]
    NotCanonical(NodeDigest),
    #[error("namespace store failed: {0}")]
    Store(String),
}

/// The digest of the empty trie (heads, bucket or shape).
pub fn empty_digest() -> NodeDigest {
    encoding::tagged_digest(EMPTY_TAG, &[])
}
