use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashSet};

use yadorilink_replica_domain::author::{AuthorBuckets, AuthorId, IncarnationId, MAX_SELF_HEADS};
use yadorilink_replica_domain::ids::{DeltaHash, DeviceId, SyncPath};

use super::*;
use crate::v2::{NodeStoreV2, PathEditV2};

type Model = BTreeMap<String, Vec<DeltaHash>>;

// --- Flat-heads adapter ------------------------------------------------------
//
// Most properties below are about paths and heads, not about who wrote a
// head, so the tests keep a flat model and give each head a fixed author
// (the parity of its number). Every head set the tests build then holds at
// most two heads per author.

fn author(i: u64) -> AuthorId {
    AuthorId { device: DeviceId(format!("device-{i}")), incarnation: IncarnationId([i as u8; 16]) }
}

fn author_of(head: &DeltaHash) -> AuthorId {
    let mut number = [0u8; 8];
    number.copy_from_slice(&head.0[..8]);
    author(u64::from_be_bytes(number) % 2)
}

fn per_author(heads: &[DeltaHash]) -> AuthorBuckets {
    let mut out = AuthorBuckets::default();
    for head in heads {
        out.by_author.entry(author_of(head)).or_default().push(*head);
    }
    out
}

fn flat(heads: &AuthorBuckets) -> Vec<DeltaHash> {
    let mut out: Vec<DeltaHash> = heads.by_author.values().flatten().copied().collect();
    out.sort();
    out
}

#[derive(Clone)]
struct PathEdit {
    path: SyncPath,
    heads: Vec<DeltaHash>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct PathDiff {
    path: SyncPath,
    left: Vec<DeltaHash>,
    right: Vec<DeltaHash>,
}

fn patch(
    store: &mut dyn NodeStoreV2,
    root: &NodeDigest,
    edits: &[PathEdit],
) -> Result<NodeDigest, NamespaceError> {
    let edits: Vec<PathEditV2> = edits
        .iter()
        .map(|e| PathEditV2 { path: e.path.clone(), heads: per_author(&e.heads) })
        .collect();
    v2::patch(store, root, &edits)
}

fn lookup(
    store: &dyn NodeStoreV2,
    root: &NodeDigest,
    path: &SyncPath,
) -> Result<Vec<DeltaHash>, NamespaceError> {
    v2::lookup(store, root, path).map(|heads| flat(&heads))
}

fn diff(
    store: &dyn NodeStoreV2,
    left: &NodeDigest,
    right: &NodeDigest,
) -> Result<Vec<PathDiff>, NamespaceError> {
    Ok(v2::diff(store, left, right)?
        .into_iter()
        .map(|d| PathDiff { path: d.path, left: flat(&d.left), right: flat(&d.right) })
        .collect())
}

use v2::{full_zip, open};

/// Deterministic xorshift generator; tests must not depend on the host.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn hash(i: u64) -> DeltaHash {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&i.to_be_bytes());
    bytes[31] = 0x5a;
    DeltaHash(bytes)
}

fn path(s: &str) -> SyncPath {
    SyncPath(s.to_string())
}

const PARTS: &[&str] = &["a", "b", "ab", "b.c", "c", "a b"];

fn random_path(rng: &mut Rng) -> String {
    let depth = 1 + rng.below(3);
    (0..depth).map(|_| PARTS[rng.below(PARTS.len())]).collect::<Vec<_>>().join("/")
}

/// Heads from a small pool, so that uniform subtrees occur often.
fn random_heads(rng: &mut Rng) -> Vec<DeltaHash> {
    let mut heads: Vec<DeltaHash> =
        (0..1 + rng.below(2)).map(|_| hash(rng.below(4) as u64)).collect();
    heads.sort();
    heads.dedup();
    heads
}

fn random_model(rng: &mut Rng, ops: usize) -> Model {
    let mut model = Model::new();
    for _ in 0..ops {
        let p = random_path(rng);
        if rng.below(5) == 0 {
            model.remove(&p);
        } else {
            model.insert(p, random_heads(rng));
        }
    }
    model
}

fn build(store: &mut MemoryNodeStore, entries: &[(String, Vec<DeltaHash>)]) -> NodeDigest {
    let edits: Vec<PathEdit> =
        entries.iter().map(|(p, heads)| PathEdit { path: path(p), heads: heads.clone() }).collect();
    patch(store, &empty_digest(), &edits).unwrap()
}

fn shuffled(model: &Model, rng: &mut Rng) -> Vec<(String, Vec<DeltaHash>)> {
    let mut entries: Vec<_> = model.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    for i in (1..entries.len()).rev() {
        entries.swap(i, rng.below(i + 1));
    }
    entries
}

/// Every entry of `root`, read back through `diff` against the empty trie.
fn contents(store: &MemoryNodeStore, root: &NodeDigest) -> Model {
    diff(store, &empty_digest(), root)
        .unwrap()
        .into_iter()
        .map(|d| {
            assert!(d.left.is_empty());
            (d.path.0, d.right)
        })
        .collect()
}

fn assert_represents(store: &MemoryNodeStore, root: &NodeDigest, model: &Model) {
    open(store, root, 1 << 20).unwrap();
    assert_eq!(&contents(store, root), model);
    for (p, heads) in model {
        assert_eq!(&lookup(store, root, &path(p)).unwrap(), heads, "at {p}");
    }
    for absent in ["", "a/", "zz", "a/b/c/d", "b.", "ab/"] {
        if !model.contains_key(absent) {
            assert!(lookup(store, root, &path(absent)).unwrap().is_empty());
        }
    }
}

/// Mirrors Lean `canonical_ext` / `canonical_compressed_ext`: the root is a
/// function of the path map alone, whatever the order and history of the
/// edits that produced it.
#[test]
fn canonical_root_is_independent_of_edit_order_and_history() {
    for seed in 1..60u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let mut store = MemoryNodeStore::new();
        let mut model = Model::new();
        let mut root = empty_digest();
        for _ in 0..40 {
            let p = random_path(&mut rng);
            let heads = if rng.below(4) == 0 { Vec::new() } else { random_heads(&mut rng) };
            root = patch(&mut store, &root, &[PathEdit { path: path(&p), heads: heads.clone() }])
                .unwrap();
            if heads.is_empty() {
                model.remove(&p);
            } else {
                model.insert(p, heads);
            }
        }
        assert_represents(&store, &root, &model);
        for _ in 0..3 {
            let mut fresh = MemoryNodeStore::new();
            let rebuilt = build(&mut fresh, &shuffled(&model, &mut rng));
            assert_eq!(rebuilt, root, "seed {seed}");
        }
        // Deleting everything returns to the empty root.
        let clear: Vec<PathEdit> =
            model.keys().map(|p| PathEdit { path: path(p), heads: Vec::new() }).collect();
        assert_eq!(patch(&mut store, &root, &clear).unwrap(), empty_digest());
    }
}

#[test]
fn uniform_subtrees_compress_and_expand() {
    let mut store = MemoryNodeStore::new();
    let same: Vec<(String, Vec<DeltaHash>)> =
        (0..50).map(|i| (format!("dir/f{i}"), vec![hash(7)])).collect();
    let root = build(&mut store, &same);
    // One uniform node over one content shape.
    match store.get(&root).unwrap().unwrap() {
        NodeV2::Uniform { buckets, aggregates, .. } => {
            assert_eq!(flat(&engine::read_buckets(&store, &buckets).unwrap()), vec![hash(7)]);
            assert_eq!(aggregates, HeadAggregates { head_count: 50, duplicate_author_count: 0 });
        }
        other => panic!("expected a uniform root, got {other:?}"),
    }
    // Changing one entry's heads splits the uniform node; restoring them
    // merges it back into the same root.
    let edited = patch(
        &mut store,
        &root,
        &[PathEdit { path: path("dir/f13"), heads: vec![hash(7), hash(8)] }],
    )
    .unwrap();
    assert!(matches!(store.get(&edited).unwrap().unwrap(), NodeV2::Branch { conflict: true, .. }));
    open(&store, &edited, 1 << 20).unwrap();
    let restored =
        patch(&mut store, &edited, &[PathEdit { path: path("dir/f13"), heads: vec![hash(7)] }])
            .unwrap();
    assert_eq!(restored, root);
}

/// A store that records every node read.
struct CountingStore {
    inner: MemoryNodeStore,
    reads: RefCell<Vec<NodeDigest>>,
}

impl CountingStore {
    fn new(inner: MemoryNodeStore) -> Self {
        Self { inner, reads: RefCell::new(Vec::new()) }
    }

    /// Every node read since the last call.
    fn take_reads(&self) -> Vec<NodeDigest> {
        std::mem::take(&mut self.reads.borrow_mut())
    }
}

impl NodeStoreV2 for CountingStore {
    fn get(&self, digest: &NodeDigest) -> Result<Option<NodeV2>, NamespaceError> {
        self.reads.borrow_mut().push(*digest);
        self.inner.get(digest)
    }
    fn put(&mut self, node: &NodeV2) -> Result<NodeDigest, NamespaceError> {
        self.inner.put(node)
    }
    fn get_author(&self, digest: &NodeDigest) -> Result<Option<AuthorNode>, NamespaceError> {
        self.reads.borrow_mut().push(*digest);
        self.inner.get_author(digest)
    }
    fn put_author(&mut self, node: &AuthorNode) -> Result<NodeDigest, NamespaceError> {
        self.inner.put_author(node)
    }
    fn get_shape(&self, digest: &NodeDigest) -> Result<Option<ShapeNodeV2>, NamespaceError> {
        self.reads.borrow_mut().push(*digest);
        self.inner.get_shape(digest)
    }
    fn put_shape(&mut self, node: &ShapeNodeV2) -> Result<NodeDigest, NamespaceError> {
        self.inner.put_shape(node)
    }
}

/// Every heads, bucket and shape node digest reachable from `root`.
fn reachable(store: &MemoryNodeStore, root: &NodeDigest) -> HashSet<NodeDigest> {
    let mut out = HashSet::new();
    let mut heads_nodes = vec![*root];
    let mut buckets = Vec::new();
    let mut shapes = Vec::new();
    while let Some(d) = heads_nodes.pop() {
        if d == empty_digest() || !out.insert(d) {
            continue;
        }
        match store.get(&d).unwrap().unwrap() {
            NodeV2::Branch { buckets: own, zero, one, .. } => {
                buckets.push(own);
                heads_nodes.extend([zero, one]);
            }
            NodeV2::Uniform { shape, buckets: own, .. } => {
                buckets.push(own);
                shapes.push(shape);
            }
        }
    }
    while let Some(d) = buckets.pop() {
        if d == empty_digest() || !out.insert(d) {
            continue;
        }
        if let AuthorNode::Branch { zero, one, .. } = store.get_author(&d).unwrap().unwrap() {
            buckets.extend([zero, one]);
        }
    }
    while let Some(d) = shapes.pop() {
        if d == empty_digest() || !out.insert(d) {
            continue;
        }
        let node = store.get_shape(&d).unwrap().unwrap();
        shapes.extend([node.zero, node.one]);
    }
    out
}

#[test]
fn diff_lists_exactly_the_differing_paths() {
    for seed in 1..40u64 {
        let mut rng = Rng(seed.wrapping_mul(0x51_7cc1_b727_220a));
        let mut store = MemoryNodeStore::new();
        let a = random_model(&mut rng, 25);
        let b = random_model(&mut rng, 25);
        let ra = build(&mut store, &shuffled(&a, &mut rng));
        let rb = build(&mut store, &shuffled(&b, &mut rng));
        let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
        let expected: Vec<PathDiff> = keys
            .into_iter()
            .filter(|k| a.get(*k) != b.get(*k))
            .map(|k| PathDiff {
                path: path(k),
                left: a.get(k).cloned().unwrap_or_default(),
                right: b.get(k).cloned().unwrap_or_default(),
            })
            .collect();
        assert_eq!(diff(&store, &ra, &rb).unwrap(), expected, "seed {seed}");
    }
}

/// Mirrors Lean `fullZip_core`: the digest zipper computes the pointwise
/// join (equal heads join to themselves).
#[test]
fn full_zip_is_the_pointwise_join() {
    let seen_by_left = |h: &DeltaHash| h.0[7].is_multiple_of(2);
    let seen_by_right = |h: &DeltaHash| h.0[7] < 2;
    for seed in 1..40u64 {
        let mut rng = Rng(seed.wrapping_mul(0x1405_7b7e_f767_814f));
        let mut store = MemoryNodeStore::new();
        let a = random_model(&mut rng, 25);
        let mut b = a.clone();
        for (p, heads) in random_model(&mut rng, 10) {
            b.insert(p, heads);
        }
        let ra = build(&mut store, &shuffled(&a, &mut rng));
        let rb = build(&mut store, &shuffled(&b, &mut rng));
        let joined = full_zip(&mut store, &ra, &rb, &seen_by_left, &seen_by_right).unwrap();

        let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
        let mut expected = Model::new();
        for k in keys {
            let l = a.get(k).cloned().unwrap_or_default();
            let r = b.get(k).cloned().unwrap_or_default();
            let heads = if l == r {
                l
            } else {
                let mut out: Vec<DeltaHash> = l
                    .iter()
                    .filter(|h| r.contains(h) || !seen_by_right(h))
                    .chain(r.iter().filter(|h| !seen_by_left(h)))
                    .copied()
                    .collect();
                out.sort();
                out.dedup();
                out
            };
            if !heads.is_empty() {
                expected.insert(k.clone(), heads);
            }
        }
        assert_represents(&store, &joined, &expected);
    }
}

#[test]
fn encodings_round_trip_and_reject_malformed_bytes() {
    let aggregates = HeadAggregates { head_count: 3, duplicate_author_count: 1 };
    let branch = NodeV2::Branch {
        skip: PathBits::from_bits(&[true, false, true]),
        buckets: hash_digest(7),
        aggregates,
        conflict: true,
        zero: empty_digest(),
        one: hash_digest(3),
    };
    let uniform = NodeV2::Uniform {
        skip: PathBits::default(),
        shape: hash_digest(4),
        buckets: hash_digest(5),
        aggregates,
    };
    for node in [branch.clone(), uniform] {
        assert_eq!(NodeV2::decode(node.tag(), &node.encode()).unwrap(), node);
    }
    let author_branch = AuthorNode::Branch {
        skip: PathBits::from_bits(&[false; 11]),
        aggregates,
        zero: hash_digest(8),
        one: hash_digest(9),
    };
    let bucket =
        AuthorNode::Bucket { skip: PathBits::from_bits(&[true; 5]), heads: vec![hash(1), hash(2)] };
    for node in [author_branch, bucket.clone()] {
        assert_eq!(AuthorNode::decode(node.tag(), &node.encode()).unwrap(), node);
    }
    let shape = ShapeNodeV2 {
        skip: PathBits::from_bits(&[false; 9]),
        entry: true,
        entry_count: 12,
        zero: hash_digest(6),
        one: empty_digest(),
    };
    assert_eq!(ShapeNodeV2::decode(&shape.encode()).unwrap(), shape);

    let mut bytes = branch.encode();
    bytes.push(0);
    assert!(NodeV2::decode(BRANCH_V2_TAG, &bytes).is_err());
    assert!(NodeV2::decode(SHAPE_V2_TAG, &branch.encode()).is_err());
    assert!(AuthorNode::decode(BRANCH_V2_TAG, &bucket.encode()).is_err());
    // Unsorted, empty and over-full buckets.
    for heads in [vec![hash(2), hash(1)], vec![], vec![hash(1), hash(2), hash(3)]] {
        let node = AuthorNode::Bucket { skip: PathBits::default(), heads };
        assert!(AuthorNode::decode(AUTHOR_BUCKET_TAG, &node.encode()).is_err());
    }
    // Non-zero padding bits in a skip.
    let mut padded = branch.encode();
    padded[4] |= 0x01;
    assert!(NodeV2::decode(BRANCH_V2_TAG, &padded).is_err());

    let tags = [
        EMPTY_TAG,
        BRANCH_V2_TAG,
        UNIFORM_V2_TAG,
        SHAPE_V2_TAG,
        AUTHOR_BRANCH_TAG,
        AUTHOR_BUCKET_TAG,
    ];
    let distinct: HashSet<_> = tags.iter().collect();
    assert_eq!(distinct.len(), tags.len());
}

fn hash_digest(i: u8) -> NodeDigest {
    NodeDigest([i; 32])
}

#[test]
fn path_keys_keep_directories_contiguous() {
    let key = PathBits::of_path(&path("a"));
    assert_eq!((key.bytes.as_slice(), key.len), (&b"a"[..], 8));
    let dir = PathBits::subtree_of(Some(&path("a"))).to_bits();
    assert!(PathBits::of_path(&path("a/b")).to_bits().starts_with(&dir));
    assert!(!PathBits::of_path(&path("ab")).to_bits().starts_with(&dir));
    assert!(!PathBits::of_path(&path("a")).to_bits().starts_with(&dir));
    assert_eq!(PathBits::subtree_of(None), PathBits::default());
}

#[test]
fn open_rejects_non_canonical_and_tampered_tries() {
    let mut store = MemoryNodeStore::new();
    let leaf = build(&mut store, &[("a".to_string(), vec![hash(1)])]);
    let one_head = HeadAggregates { head_count: 1, duplicate_author_count: 0 };
    // An entry-less branch with a single child must be folded into a skip.
    let folded = store
        .put(&NodeV2::Branch {
            skip: PathBits::default(),
            buckets: empty_digest(),
            aggregates: one_head,
            conflict: false,
            zero: leaf,
            one: empty_digest(),
        })
        .unwrap();
    assert!(matches!(open(&store, &folded, 100), Err(NamespaceError::NotCanonical(_))));
    // Two identical single-entry children must be one uniform node.
    let pair = build(
        &mut store,
        &[("x/0".to_string(), vec![hash(1)]), ("x/1".to_string(), vec![hash(2)])],
    );
    open(&store, &pair, 100).unwrap();
    let NodeV2::Branch { skip, buckets, aggregates, zero, one, .. } =
        store.get(&pair).unwrap().unwrap()
    else {
        panic!("expected a branch");
    };
    let same = store
        .put(&NodeV2::Branch {
            skip: skip.clone(),
            buckets,
            aggregates,
            conflict: false,
            zero,
            one: zero,
        })
        .unwrap();
    assert!(matches!(open(&store, &same, 100), Err(NamespaceError::NotCanonical(_))));
    // A wrong conflict flag.
    let flagged = store
        .put(&NodeV2::Branch { skip: skip.clone(), buckets, aggregates, conflict: true, zero, one })
        .unwrap();
    assert!(open(&store, &flagged, 100).is_err());
    // Wrong counts.
    for wrong in [
        HeadAggregates { head_count: 3, duplicate_author_count: 0 },
        HeadAggregates { head_count: 2, duplicate_author_count: 1 },
    ] {
        let counted = store
            .put(&NodeV2::Branch {
                skip: skip.clone(),
                buckets,
                aggregates: wrong,
                conflict: false,
                zero,
                one,
            })
            .unwrap();
        assert!(matches!(open(&store, &counted, 100), Err(NamespaceError::NotCanonical(_))));
    }
    // The node budget.
    assert!(open(&store, &pair, 1).is_err());
    // Missing nodes.
    assert!(matches!(open(&store, &hash_digest(0xee), 100), Err(NamespaceError::MissingNode(_))));

    // A store answering with a node that does not hash to the digest.
    struct Lying(MemoryNodeStore, NodeDigest);
    impl NodeStoreV2 for Lying {
        fn get(&self, _: &NodeDigest) -> Result<Option<NodeV2>, NamespaceError> {
            self.0.get(&self.1)
        }
        fn put(&mut self, node: &NodeV2) -> Result<NodeDigest, NamespaceError> {
            self.0.put(node)
        }
        fn get_author(&self, digest: &NodeDigest) -> Result<Option<AuthorNode>, NamespaceError> {
            self.0.get_author(digest)
        }
        fn put_author(&mut self, node: &AuthorNode) -> Result<NodeDigest, NamespaceError> {
            self.0.put_author(node)
        }
        fn get_shape(&self, digest: &NodeDigest) -> Result<Option<ShapeNodeV2>, NamespaceError> {
            self.0.get_shape(digest)
        }
        fn put_shape(&mut self, node: &ShapeNodeV2) -> Result<NodeDigest, NamespaceError> {
            self.0.put_shape(node)
        }
    }
    let lying = Lying(store, leaf);
    assert!(matches!(lookup(&lying, &pair, &path("x/0")), Err(NamespaceError::DigestMismatch(_))));
}

/// Pins the byte format: these digests change only with a deliberate
/// encoding change. The single-entry root was recomputed independently
/// from the crate doc's byte format.
#[test]
fn digests_are_stable() {
    let hex = |d: NodeDigest| d.0.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut store = MemoryNodeStore::new();
    let one = build(&mut store, &[("a".to_string(), vec![hash(1)])]);
    let two =
        build(&mut store, &[("a".to_string(), vec![hash(1)]), ("b".to_string(), vec![hash(2)])]);
    assert_eq!(
        [hex(empty_digest()), hex(one), hex(two)],
        [
            "34950ebcc61f46879f852c432907cc19f11b30d9b3293617f96816a83fee7817",
            "6625a0341cca47a9058233a52887c1321b24ce0f5201fe27017d659353ee0b04",
            "8a4a8387362ebb5bcdcc86cde8367b92510551f3cb3b81700e8c922615d6141d",
        ]
    );
}

#[test]
fn empty_namespace_is_the_empty_digest() {
    let mut store = MemoryNodeStore::new();
    let empty = empty_digest();
    assert_eq!(v2::patch(&mut store, &empty, &[]).unwrap(), empty);
    let root = build(&mut store, &[("a/b".to_string(), vec![hash(1)])]);
    let cleared =
        patch(&mut store, &root, &[PathEdit { path: path("a/b"), heads: Vec::new() }]).unwrap();
    assert_eq!(cleared, empty);
    // An edit whose buckets are all empty is no entry.
    let mut empty_buckets = AuthorBuckets::default();
    empty_buckets.by_author.insert(author(0), Vec::new());
    let edit = PathEditV2 { path: path("x"), heads: empty_buckets };
    assert_eq!(v2::patch(&mut store, &empty, &[edit]).unwrap(), empty);
    assert_eq!(v2::root_aggregates(&store, &empty).unwrap(), HeadAggregates::default());
    assert!(v2::lookup(&store, &empty, &path("a/b")).unwrap().by_author.is_empty());
    assert!(v2::diff(&store, &empty, &empty).unwrap().is_empty());
    open(&store, &empty, 1).unwrap();
    // The edit with only empty buckets wrote no node.
    assert_eq!(store.len(), reachable(&store, &root).len());
}

#[test]
fn aggregates_count_heads_and_two_head_buckets() {
    let mut store = MemoryNodeStore::new();
    let mut heads = AuthorBuckets::default();
    heads.by_author.insert(author(1), vec![hash(3), hash(1)]);
    heads.by_author.insert(author(2), vec![hash(9)]);
    let edits: Vec<PathEditV2> = (0..30)
        .map(|i| PathEditV2 { path: path(&format!("dir/f{i}")), heads: heads.clone() })
        .chain([PathEditV2 { path: path("single"), heads: per_author(&[hash(4)]) }])
        .collect();
    let root = v2::patch(&mut store, &empty_digest(), &edits).unwrap();
    open(&store, &root, 1 << 20).unwrap();
    assert_eq!(
        v2::root_aggregates(&store, &root).unwrap(),
        HeadAggregates { head_count: 30 * 3 + 1, duplicate_author_count: 30 }
    );
    // Superseding one of the two heads everywhere makes the namespace
    // sealable.
    let mut one_each = heads.clone();
    one_each.by_author.insert(author(1), vec![hash(5)]);
    let edits: Vec<PathEditV2> = (0..30)
        .map(|i| PathEditV2 { path: path(&format!("dir/f{i}")), heads: one_each.clone() })
        .collect();
    let sealable = v2::patch(&mut store, &root, &edits).unwrap();
    open(&store, &sealable, 1 << 20).unwrap();
    assert_eq!(
        v2::root_aggregates(&store, &sealable).unwrap(),
        HeadAggregates { head_count: 61, duplicate_author_count: 0 }
    );
    assert_eq!(v2::lookup(&store, &sealable, &path("dir/f7")).unwrap(), one_each);
}

#[test]
fn a_bucket_over_the_bound_is_refused() {
    let mut store = MemoryNodeStore::new();
    let mut heads = AuthorBuckets::default();
    let over: Vec<DeltaHash> = (0..=MAX_SELF_HEADS as u64).map(|i| hash(2 * i + 1)).collect();
    heads.by_author.insert(author(1), over);
    let edit = PathEditV2 { path: path("a"), heads };
    assert!(matches!(
        v2::patch(&mut store, &empty_digest(), &[edit]),
        Err(NamespaceError::Malformed(_))
    ));
}

/// One author's bucket is read along one key of the path's bucket trie,
/// whatever the number of authors at the path.
#[test]
fn lookup_bucket_reads_one_author_path() {
    let mut store = MemoryNodeStore::new();
    let mut heads = AuthorBuckets::default();
    for i in 0..64u64 {
        heads.by_author.insert(author(i), vec![hash(100 + i)]);
    }
    heads.by_author.insert(author(64), vec![hash(7), hash(8)]);
    let root = v2::patch(
        &mut store,
        &empty_digest(),
        &[
            PathEditV2 { path: path("shared"), heads: heads.clone() },
            PathEditV2 { path: path("other"), heads: per_author(&[hash(1)]) },
        ],
    )
    .unwrap();
    open(&store, &root, 1 << 20).unwrap();
    assert_eq!(v2::lookup(&store, &root, &path("shared")).unwrap(), heads);
    let counting = CountingStore::new(store);
    for i in [0u64, 17, 63] {
        let bucket = v2::lookup_bucket(&counting, &root, &path("shared"), &author(i)).unwrap();
        assert_eq!(bucket, vec![hash(100 + i)]);
        let reads = counting.take_reads().len();
        assert!(reads <= 12, "{reads} reads for one bucket among 65 authors");
    }
    let two = v2::lookup_bucket(&counting, &root, &path("shared"), &author(64)).unwrap();
    assert_eq!(two, vec![hash(7), hash(8)]);
    assert!(v2::lookup_bucket(&counting, &root, &path("shared"), &author(99)).unwrap().is_empty());
    assert!(v2::lookup_bucket(&counting, &root, &path("none"), &author(0)).unwrap().is_empty());
}
