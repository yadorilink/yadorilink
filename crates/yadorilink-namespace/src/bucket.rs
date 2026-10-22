//! A path's bucket trie: the authenticated map from author to that
//! author's heads at the path (crate doc, "Author buckets").
//!
//! The trie is a compressed binary trie over author keys. Author keys are
//! prefix-free, so every bucket sits at a leaf and every inner node has two
//! non-empty children; the trie, and so its digest, is a function of the
//! map alone.

use std::collections::{BTreeMap, BTreeSet};

use yadorilink_replica_domain::author::{AuthorBuckets, AuthorId, MAX_SELF_HEADS};
use yadorilink_replica_domain::ids::DeltaHash;

use crate::encoding::{author_key_bytes, author_of_key_bytes};
use crate::v2::NodeStoreV2;
use crate::{empty_digest, AuthorNode, HeadAggregates, NamespaceError, NodeDigest, PathBits};

type Bits = Vec<bool>;

fn malformed(what: &str) -> NamespaceError {
    NamespaceError::Malformed(what.to_string())
}

/// The key bits of `author`.
fn author_key(author: &AuthorId) -> Bits {
    PathBits::of_bytes(&author_key_bytes(author)).to_bits()
}

/// The author whose key is exactly `bits`.
fn author_of_key(bits: &[bool]) -> Result<AuthorId, NamespaceError> {
    if !bits.len().is_multiple_of(8) {
        return Err(malformed("author key is not a whole number of bytes"));
    }
    author_of_key_bytes(&PathBits::from_bits(bits).bytes)
}

/// Every head of `heads`, whatever its author.
pub(crate) fn flatten(heads: &AuthorBuckets) -> BTreeSet<DeltaHash> {
    heads.by_author.values().flatten().copied().collect()
}

/// The aggregate counts of a map of buckets, each already normalized.
fn aggregates_of(heads: &AuthorBuckets) -> HeadAggregates {
    heads.by_author.values().fold(HeadAggregates::default(), |sum, bucket| {
        sum.plus(HeadAggregates::of_bucket(bucket.len()))
    })
}

/// `heads` with every bucket sorted and deduplicated and empty buckets
/// dropped; a bucket over [`MAX_SELF_HEADS`] is malformed.
pub(crate) fn normalize(heads: &AuthorBuckets) -> Result<AuthorBuckets, NamespaceError> {
    let mut by_author = BTreeMap::new();
    for (author, bucket) in &heads.by_author {
        let mut bucket = bucket.clone();
        bucket.sort();
        bucket.dedup();
        if bucket.len() > MAX_SELF_HEADS {
            return Err(malformed("an author's bucket holds more than the per-author bound"));
        }
        if !bucket.is_empty() {
            by_author.insert(author.clone(), bucket);
        }
    }
    Ok(AuthorBuckets { by_author })
}

fn load(store: &dyn NodeStoreV2, digest: &NodeDigest) -> Result<AuthorNode, NamespaceError> {
    let node = store.get_author(digest)?.ok_or(NamespaceError::MissingNode(*digest))?;
    if node.digest() != *digest {
        return Err(NamespaceError::DigestMismatch(*digest));
    }
    Ok(node)
}

/// Stores the bucket trie of `heads` and returns its digest and counts.
pub(crate) fn store_heads(
    store: &mut dyn NodeStoreV2,
    heads: &AuthorBuckets,
) -> Result<(NodeDigest, HeadAggregates), NamespaceError> {
    let heads = normalize(heads)?;
    let mut entries: Vec<(Bits, &Vec<DeltaHash>)> =
        heads.by_author.iter().map(|(author, bucket)| (author_key(author), bucket)).collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let digest = build(store, &entries, 0)?;
    Ok((digest, aggregates_of(&heads)))
}

/// The canonical trie of `entries` (distinct keys, ascending, prefix-free)
/// whose keys agree on their first `depth` bits.
fn build(
    store: &mut dyn NodeStoreV2,
    entries: &[(Bits, &Vec<DeltaHash>)],
    depth: usize,
) -> Result<NodeDigest, NamespaceError> {
    match entries {
        [] => Ok(empty_digest()),
        [(key, heads)] => store.put_author(&AuthorNode::Bucket {
            skip: PathBits::from_bits(&key[depth..]),
            heads: (*heads).clone(),
        }),
        [(first, _), .., (last, _)] => {
            let shared =
                first[depth..].iter().zip(&last[depth..]).take_while(|(a, b)| a == b).count();
            let at = depth + shared;
            if at >= first.len() || at >= last.len() {
                return Err(malformed("author keys are not prefix-free"));
            }
            let split = entries.partition_point(|(key, _)| !key[at]);
            let zero_entries = &entries[..split];
            let one_entries = &entries[split..];
            let zero = build(store, zero_entries, at + 1)?;
            let one = build(store, one_entries, at + 1)?;
            let aggregates = zero_entries
                .iter()
                .chain(one_entries)
                .fold(HeadAggregates::default(), |sum, (_, heads)| {
                    sum.plus(HeadAggregates::of_bucket(heads.len()))
                });
            store.put_author(&AuthorNode::Branch {
                skip: PathBits::from_bits(&first[depth..at]),
                aggregates,
                zero,
                one,
            })
        }
    }
}

/// The counts of the bucket trie `digest`, read from its root alone.
pub(crate) fn aggregates(
    store: &dyn NodeStoreV2,
    digest: &NodeDigest,
) -> Result<HeadAggregates, NamespaceError> {
    if *digest == empty_digest() {
        return Ok(HeadAggregates::default());
    }
    Ok(load(store, digest)?.aggregates())
}

/// The whole map of the bucket trie `digest`, checking canonical form and
/// every derived count on the way and reading at most `budget` nodes.
pub(crate) fn read(
    store: &dyn NodeStoreV2,
    digest: &NodeDigest,
    budget: &mut usize,
) -> Result<AuthorBuckets, NamespaceError> {
    let mut heads = AuthorBuckets::default();
    if *digest != empty_digest() {
        let mut key = Vec::new();
        read_into(store, digest, &mut key, budget, &mut heads)?;
    }
    Ok(heads)
}

fn read_into(
    store: &dyn NodeStoreV2,
    digest: &NodeDigest,
    key: &mut Bits,
    budget: &mut usize,
    out: &mut AuthorBuckets,
) -> Result<HeadAggregates, NamespaceError> {
    if *digest == empty_digest() {
        return Err(NamespaceError::NotCanonical(*digest));
    }
    if *budget == 0 {
        return Err(malformed("namespace exceeds its node budget"));
    }
    *budget -= 1;
    let depth = key.len();
    let result = match load(store, digest)? {
        AuthorNode::Bucket { skip, heads } => {
            key.extend(skip.to_bits());
            let author = author_of_key(key)?;
            let aggregates = HeadAggregates::of_bucket(heads.len());
            out.by_author.insert(author, heads);
            aggregates
        }
        AuthorNode::Branch { skip, aggregates, zero, one } => {
            let not_canonical = || NamespaceError::NotCanonical(*digest);
            if zero == empty_digest() || one == empty_digest() {
                return Err(not_canonical());
            }
            key.extend(skip.to_bits());
            let at = key.len();
            key.push(false);
            let zero = read_into(store, &zero, key, budget, out)?;
            key.truncate(at);
            key.push(true);
            let one = read_into(store, &one, key, budget, out)?;
            if zero.checked_plus(one) != Some(aggregates) {
                return Err(not_canonical());
            }
            aggregates
        }
    };
    key.truncate(depth);
    Ok(result)
}

/// `author`'s bucket in the bucket trie `digest`: one node per branching
/// position on the way to the author's key.
pub(crate) fn lookup(
    store: &dyn NodeStoreV2,
    digest: &NodeDigest,
    author: &AuthorId,
) -> Result<Vec<DeltaHash>, NamespaceError> {
    let key = author_key(author);
    let mut at = 0;
    let mut digest = *digest;
    loop {
        if digest == empty_digest() {
            return Ok(Vec::new());
        }
        let node = load(store, &digest)?;
        let (AuthorNode::Branch { skip, .. } | AuthorNode::Bucket { skip, .. }) = &node;
        let skip = skip.to_bits();
        if !key[at.min(key.len())..].starts_with(&skip) {
            return Ok(Vec::new());
        }
        at += skip.len();
        match node {
            AuthorNode::Bucket { heads, .. } => {
                return Ok(if at == key.len() { heads } else { Vec::new() });
            }
            AuthorNode::Branch { zero, one, .. } => {
                let Some(&bit) = key.get(at) else { return Ok(Vec::new()) };
                digest = if bit { one } else { zero };
                at += 1;
            }
        }
    }
}
