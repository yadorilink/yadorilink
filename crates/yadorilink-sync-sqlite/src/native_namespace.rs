//! The group's namespace trie, kept in SQLite and patched from the heads that changed.
//!
//! The namespace root a `Summary` carries is the root of the authenticated trie over every live head
//! (`yadorilink-namespace::v2`). It used to be rebuilt from every head row whenever the group changed,
//! which made a 100k-path group cost its whole trie in memory and CPU on every summary exchange during
//! an import or a receive. The trie is now stored node by node and patched by the paths that changed.
//!
//! # Storage
//!
//! `native_namespace_node` holds every node of every kind by digest, with the number of references to
//! it: one for each stored parent that names it and one for the root pointer. A patch writes the nodes
//! along the changed paths; the nodes it replaced lose their reference and are deleted the moment the
//! count reaches zero, so the table holds exactly the nodes the current root reaches. There is no
//! sweep. `native_namespace_root` holds the root pointer.
//!
//! # Lazy maintenance
//!
//! Patching on every head write would rewrite the upper levels of the trie once per write, and the
//! nodes' random digests make every one of those rows a random page. So a head write only notes its
//! path: a trigger on `native_heads`, which no writer can skip or forget, adds the path to
//! `native_namespace_pending` in the same statement's transaction. The trie is patched from the
//! pending paths, one `v2::patch` for everything pending, when the root is wanted: a summary
//! exchange or a seal. The root and the pending set together always define the state: the root is
//! that of the heads as of the last patch, and the pending paths are exactly those that may differ.
//! A reader that finds paths pending has not been given a current root and gets an error rather than
//! a stale one; the callers that need the root flush first.

use rusqlite::{Connection, OptionalExtension};

use yadorilink_namespace::v2::{self, NodeStoreV2, PathEditV2};
use yadorilink_namespace::{
    empty_digest, AuthorNode, NamespaceError, NodeDigest, NodeV2, ShapeNodeV2, AUTHOR_BRANCH_TAG,
    AUTHOR_BUCKET_TAG, BRANCH_V2_TAG, UNIFORM_V2_TAG,
};
use yadorilink_replica_domain::author::AuthorBuckets;
use yadorilink_replica_domain::ids::{FolderGroupId, SyncPath};

use crate::error::SyncSqliteError;

/// How many paths one patch takes inside a transaction that flushes everything.
const FLUSH_CHUNK: usize = 5000;
/// How many paths one write transaction of [`flush_all`] takes.
const FLUSH_TX_PATHS: usize = 2000;

const KIND_HEADS: i64 = 0;
const KIND_AUTHOR: i64 = 1;
const KIND_SHAPE: i64 = 2;

/// Creates the tables and the triggers that note every write of a head row.
pub(crate) fn init_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS native_namespace_node (
            group_id  TEXT NOT NULL,
            kind      INTEGER NOT NULL,
            digest    BLOB NOT NULL,
            body      BLOB NOT NULL,
            refs      INTEGER NOT NULL,
            PRIMARY KEY (group_id, kind, digest)
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS native_namespace_root (
            group_id  TEXT PRIMARY KEY,
            root      BLOB NOT NULL
        ) WITHOUT ROWID;
        CREATE TABLE IF NOT EXISTS native_namespace_pending (
            group_id  TEXT NOT NULL,
            path      TEXT NOT NULL,
            PRIMARY KEY (group_id, path)
        ) WITHOUT ROWID;
        CREATE TRIGGER IF NOT EXISTS native_heads_namespace_insert AFTER INSERT ON native_heads
        BEGIN
            INSERT OR IGNORE INTO native_namespace_pending (group_id, path)
            VALUES (NEW.group_id, NEW.path);
        END;
        CREATE TRIGGER IF NOT EXISTS native_heads_namespace_update AFTER UPDATE ON native_heads
        BEGIN
            INSERT OR IGNORE INTO native_namespace_pending (group_id, path)
            VALUES (NEW.group_id, NEW.path);
            INSERT OR IGNORE INTO native_namespace_pending (group_id, path)
            VALUES (OLD.group_id, OLD.path);
        END;
        CREATE TRIGGER IF NOT EXISTS native_heads_namespace_delete AFTER DELETE ON native_heads
        BEGIN
            INSERT OR IGNORE INTO native_namespace_pending (group_id, path)
            VALUES (OLD.group_id, OLD.path);
        END;",
    )?;
    Ok(())
}

fn store_error(err: rusqlite::Error) -> NamespaceError {
    NamespaceError::Store(err.to_string())
}

/// A decoded node of any kind.
enum Node {
    Heads(NodeV2),
    Author(AuthorNode),
    Shape(ShapeNodeV2),
}

impl Node {
    fn decode(kind: i64, body: &[u8]) -> Result<Self, NamespaceError> {
        Ok(match kind {
            KIND_HEADS => Node::Heads(decode_heads(body)?),
            KIND_AUTHOR => Node::Author(decode_author(body)?),
            _ => Node::Shape(ShapeNodeV2::decode(body)?),
        })
    }

    fn duplicate(&self) -> Self {
        match self {
            Node::Heads(n) => Node::Heads(n.clone()),
            Node::Author(n) => Node::Author(n.clone()),
            Node::Shape(n) => Node::Shape(n.clone()),
        }
    }

    fn encode(&self) -> Vec<u8> {
        match self {
            Node::Heads(node) => encode_heads(node),
            Node::Author(node) => encode_author(node),
            Node::Shape(node) => node.encode(),
        }
    }

    /// The nodes this one names, with the kind of each; the empty trie is not a node.
    fn children(&self) -> Vec<(i64, NodeDigest)> {
        let mut out: Vec<(i64, NodeDigest)> = Vec::new();
        let mut push = |kind: i64, digest: NodeDigest| {
            if digest != empty_digest() {
                out.push((kind, digest));
            }
        };
        match self {
            Node::Heads(NodeV2::Branch { buckets, zero, one, .. }) => {
                push(KIND_AUTHOR, *buckets);
                push(KIND_HEADS, *zero);
                push(KIND_HEADS, *one);
            }
            Node::Heads(NodeV2::Uniform { shape, buckets, .. }) => {
                push(KIND_SHAPE, *shape);
                push(KIND_AUTHOR, *buckets);
            }
            Node::Author(AuthorNode::Branch { zero, one, .. }) => {
                push(KIND_AUTHOR, *zero);
                push(KIND_AUTHOR, *one);
            }
            Node::Author(AuthorNode::Bucket { .. }) => {}
            Node::Shape(shape) => {
                push(KIND_SHAPE, shape.zero);
                push(KIND_SHAPE, shape.one);
            }
        }
        out
    }
}

/// The digests a stored node names, with the kind of each.
fn children(kind: i64, body: &[u8]) -> Result<Vec<(i64, NodeDigest)>, NamespaceError> {
    Ok(Node::decode(kind, body)?.children())
}

// A head node is stored with its tag so one decoder serves both variants.
fn encode_heads(node: &NodeV2) -> Vec<u8> {
    let mut out = node.tag().to_vec();
    out.extend_from_slice(&node.encode());
    out
}

fn decode_heads(body: &[u8]) -> Result<NodeV2, NamespaceError> {
    let (tag, rest) = split_tag(body)?;
    if tag == *BRANCH_V2_TAG || tag == *UNIFORM_V2_TAG {
        NodeV2::decode(&tag, rest)
    } else {
        Err(NamespaceError::Malformed("stored heads node has an unknown tag".into()))
    }
}

fn encode_author(node: &AuthorNode) -> Vec<u8> {
    let mut out = node.tag().to_vec();
    out.extend_from_slice(&node.encode());
    out
}

fn decode_author(body: &[u8]) -> Result<AuthorNode, NamespaceError> {
    let (tag, rest) = split_tag(body)?;
    if tag == *AUTHOR_BRANCH_TAG || tag == *AUTHOR_BUCKET_TAG {
        AuthorNode::decode(&tag, rest)
    } else {
        Err(NamespaceError::Malformed("stored author node has an unknown tag".into()))
    }
}

fn split_tag(body: &[u8]) -> Result<([u8; 8], &[u8]), NamespaceError> {
    if body.len() < 8 {
        return Err(NamespaceError::Malformed("stored node shorter than its tag".into()));
    }
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&body[..8]);
    Ok((tag, &body[8..]))
}

type Key = (i64, [u8; 32]);

/// How many dead nodes one delete statement names.
const DELETE_GROUP: usize = 40;

/// A [`NodeStoreV2`] over the group's node table that keeps what a patch writes in memory.
///
/// Reads see the patch's own nodes first, then the table, and remember every stored node they read
/// with its reference count. Nothing is written until the patch is done and the new root is known,
/// so only nodes the result reaches are ever stored, and the reference counts of everything the
/// patch touched are settled once, in memory, before a statement is spent on them.
struct PatchStore<'a> {
    conn: &'a Connection,
    group: &'a str,
    fresh: std::collections::HashMap<Key, Node>,
    stored: std::cell::RefCell<std::collections::HashMap<Key, (Node, i64)>>,
}

impl<'a> PatchStore<'a> {
    fn new(conn: &'a Connection, group: &'a str) -> Self {
        Self {
            conn,
            group,
            fresh: std::collections::HashMap::new(),
            stored: std::cell::RefCell::new(std::collections::HashMap::new()),
        }
    }

    fn row(&self, kind: i64, digest: &[u8; 32]) -> Result<Option<(Vec<u8>, i64)>, rusqlite::Error> {
        self.conn
            .prepare_cached(
                "SELECT body, refs FROM native_namespace_node \
                 WHERE group_id = ?1 AND kind = ?2 AND digest = ?3",
            )
            .and_then(|mut stmt| {
                stmt.query_row(rusqlite::params![self.group, kind, digest.as_slice()], |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
                })
                .optional()
            })
    }

    fn read(&self, kind: i64, digest: &NodeDigest) -> Result<Option<Node>, NamespaceError> {
        let key = (kind, digest.0);
        if let Some(node) = self.fresh.get(&key) {
            return Ok(Some(node.duplicate()));
        }
        if let Some((node, _)) = self.stored.borrow().get(&key) {
            return Ok(Some(node.duplicate()));
        }
        let Some((body, refs)) = self.row(kind, &digest.0).map_err(store_error)? else {
            return Ok(None);
        };
        let node = Node::decode(kind, &body)?;
        self.stored.borrow_mut().insert(key, (node.duplicate(), refs));
        Ok(Some(node))
    }

    /// The children and count of a stored node, from what the patch read or from the table.
    fn stored_node(&self, key: Key) -> Result<(Vec<(i64, NodeDigest)>, i64), SyncSqliteError> {
        if let Some((node, refs)) = self.stored.borrow().get(&key) {
            return Ok((node.children(), *refs));
        }
        let (body, refs) = self.row(key.0, &key.1)?.ok_or_else(|| {
            SyncSqliteError::CorruptState(
                "namespace trie: a node the root reached is missing".into(),
            )
        })?;
        Ok((children(key.0, &body).map_err(namespace_error)?, refs))
    }

    /// Stores the new root's nodes the table lacks and settles every reference count: one from each
    /// new parent and the root pointer, minus the old root's, with whatever that frees deleted.
    fn flush(self, old_root: &NodeDigest, new_root: &NodeDigest) -> Result<(), SyncSqliteError> {
        use std::collections::{HashMap, HashSet};
        // Reachable fresh nodes, children before parents.
        let mut order: Vec<Key> = Vec::new();
        let mut seen: HashSet<Key> = HashSet::new();
        if *new_root != empty_digest() {
            let mut stack = vec![((KIND_HEADS, new_root.0), false)];
            while let Some((key, expanded)) = stack.pop() {
                if expanded {
                    order.push(key);
                    continue;
                }
                if !seen.insert(key) {
                    continue;
                }
                let Some(node) = self.fresh.get(&key) else { continue };
                stack.push((key, true));
                for (kind, child) in node.children() {
                    stack.push(((kind, child.0), false));
                }
            }
        }
        // Parent edges inside the fresh nodes, and the root pointer's.
        let mut incoming: HashMap<Key, i64> = HashMap::new();
        if *new_root != empty_digest() {
            *incoming.entry((KIND_HEADS, new_root.0)).or_default() += 1;
        }
        for key in &order {
            for (kind, child) in self.fresh[key].children() {
                *incoming.entry((kind, child.0)).or_default() += 1;
            }
        }
        // A node is new when the insert took. A new node's parents are all new (a stored parent
        // would have stored it), so its count is the edges counted above.
        let mut insert = self.conn.prepare_cached(
            "INSERT OR IGNORE INTO native_namespace_node (group_id, kind, digest, body, refs) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )?;
        let mut added: HashSet<Key> = HashSet::new();
        for key in &order {
            let refs = incoming.get(key).copied().unwrap_or(0);
            let changed = insert.execute(rusqlite::params![
                self.group,
                key.0,
                key.1.as_slice(),
                self.fresh[key].encode(),
                refs
            ])?;
            if changed == 1 {
                added.insert(*key);
            }
        }
        drop(insert);

        // What changes the count of a node that was already stored.
        let mut delta: HashMap<Key, i64> = HashMap::new();
        for key in &added {
            for (kind, child) in self.fresh[key].children() {
                if !added.contains(&(kind, child.0)) {
                    *delta.entry((kind, child.0)).or_default() += 1;
                }
            }
        }
        if *new_root != empty_digest() && !added.contains(&(KIND_HEADS, new_root.0)) {
            *delta.entry((KIND_HEADS, new_root.0)).or_default() += 1;
        }
        if *old_root != empty_digest() {
            *delta.entry((KIND_HEADS, old_root.0)).or_default() -= 1;
        }
        // A reference a new node takes on a subtree and the one its old parent held cancel, so only
        // nodes whose count really changes are looked at. When the old path dies its children lose a
        // reference, and those that fall to zero die with it.
        delta.retain(|_, d| *d != 0);
        let mut dead: HashSet<Key> = HashSet::new();
        let mut queue: Vec<Key> = delta.iter().filter(|(_, d)| **d < 0).map(|(k, _)| *k).collect();
        while let Some(key) = queue.pop() {
            if dead.contains(&key) {
                continue;
            }
            let change = delta.get(&key).copied().unwrap_or(0);
            if change >= 0 {
                continue;
            }
            let (kids, refs) = self.stored_node(key)?;
            let remaining = refs + change;
            if remaining < 0 {
                return Err(SyncSqliteError::CorruptState(
                    "namespace trie: a node lost more references than it held".into(),
                ));
            }
            if remaining == 0 {
                dead.insert(key);
                for (kind, child) in kids {
                    let child_key = (kind, child.0);
                    *delta.entry(child_key).or_default() -= 1;
                    queue.push(child_key);
                }
            }
        }
        let mut bump = self.conn.prepare_cached(
            "UPDATE native_namespace_node SET refs = refs + ?4 \
             WHERE group_id = ?1 AND kind = ?2 AND digest = ?3",
        )?;
        for (key, change) in &delta {
            if *change == 0 || dead.contains(key) {
                continue;
            }
            let updated =
                bump.execute(rusqlite::params![self.group, key.0, key.1.as_slice(), change])?;
            if updated != 1 {
                return Err(SyncSqliteError::CorruptState(
                    "namespace trie: a node a new node names is not stored".into(),
                ));
            }
        }
        drop(bump);
        // Dead nodes go by kind, an `IN` list of digests per statement (the primary key is
        // `(group_id, kind, digest)`, so each name is an index lookup).
        for kind in [KIND_HEADS, KIND_AUTHOR, KIND_SHAPE] {
            let digests: Vec<[u8; 32]> =
                dead.iter().filter(|(k, _)| *k == kind).map(|(_, d)| *d).collect();
            for group in digests.chunks(DELETE_GROUP) {
                let marks = vec!["?"; group.len()].join(",");
                let mut stmt = self.conn.prepare_cached(&format!(
                    "DELETE FROM native_namespace_node \
                     WHERE group_id = ? AND kind = ? AND digest IN ({marks})"
                ))?;
                let mut params: Vec<rusqlite::types::Value> =
                    vec![self.group.to_owned().into(), kind.into()];
                params.extend(group.iter().map(|d| rusqlite::types::Value::from(d.to_vec())));
                stmt.execute(rusqlite::params_from_iter(params))?;
            }
        }
        Ok(())
    }
}

impl NodeStoreV2 for PatchStore<'_> {
    fn get(&self, digest: &NodeDigest) -> Result<Option<NodeV2>, NamespaceError> {
        Ok(match self.read(KIND_HEADS, digest)? {
            Some(Node::Heads(node)) => Some(node),
            _ => None,
        })
    }

    fn put(&mut self, node: &NodeV2) -> Result<NodeDigest, NamespaceError> {
        let digest = node.digest();
        self.fresh.entry((KIND_HEADS, digest.0)).or_insert_with(|| Node::Heads(node.clone()));
        Ok(digest)
    }

    fn get_author(&self, digest: &NodeDigest) -> Result<Option<AuthorNode>, NamespaceError> {
        Ok(match self.read(KIND_AUTHOR, digest)? {
            Some(Node::Author(node)) => Some(node),
            _ => None,
        })
    }

    fn put_author(&mut self, node: &AuthorNode) -> Result<NodeDigest, NamespaceError> {
        let digest = node.digest();
        self.fresh.entry((KIND_AUTHOR, digest.0)).or_insert_with(|| Node::Author(node.clone()));
        Ok(digest)
    }

    fn get_shape(&self, digest: &NodeDigest) -> Result<Option<ShapeNodeV2>, NamespaceError> {
        Ok(match self.read(KIND_SHAPE, digest)? {
            Some(Node::Shape(node)) => Some(node),
            _ => None,
        })
    }

    fn put_shape(&mut self, node: &ShapeNodeV2) -> Result<NodeDigest, NamespaceError> {
        let digest = node.digest();
        self.fresh.entry((KIND_SHAPE, digest.0)).or_insert_with(|| Node::Shape(node.clone()));
        Ok(digest)
    }
}

fn namespace_error(err: NamespaceError) -> SyncSqliteError {
    SyncSqliteError::CorruptState(format!("namespace trie: {err}"))
}

fn root_row(conn: &Connection, group: &str) -> Result<Option<NodeDigest>, SyncSqliteError> {
    let row: Option<Vec<u8>> = conn
        .prepare_cached("SELECT root FROM native_namespace_root WHERE group_id = ?1")?
        .query_row([group], |row| row.get(0))
        .optional()?;
    row.map(|root| {
        if root.is_empty() {
            Ok(empty_digest())
        } else {
            Ok(NodeDigest(crate::native_store::as_array32(&root)?))
        }
    })
    .transpose()
}

/// Patches `edits` into the stored trie.
fn patch(
    conn: &Connection,
    group_id: &FolderGroupId,
    edits: &[PathEditV2],
) -> Result<(), SyncSqliteError> {
    let group = group_id.as_str();
    let old_root = root_row(conn, group)?.unwrap_or_else(empty_digest);
    let mut store = PatchStore::new(conn, group);
    let new_root = v2::patch(&mut store, &old_root, edits).map_err(namespace_error)?;
    store.flush(&old_root, &new_root)?;
    conn.prepare_cached(
        "INSERT INTO native_namespace_root (group_id, root) VALUES (?1, ?2) \
         ON CONFLICT (group_id) DO UPDATE SET root = excluded.root",
    )?
    .execute(rusqlite::params![group, root_blob(&new_root)])?;
    Ok(())
}

fn root_blob(root: &NodeDigest) -> Vec<u8> {
    if *root == empty_digest() {
        Vec::new()
    } else {
        root.0.to_vec()
    }
}

/// Patches up to `limit` of the group's pending paths into the trie: reads each one's current heads
/// from `native_heads` (none: the path is removed), patches them in one `v2::patch` and forgets
/// them. Returns how many paths it took; zero means nothing was pending. Runs in the caller's
/// transaction, so the patch and the forgetting commit together.
fn flush_some(
    conn: &Connection,
    group_id: &FolderGroupId,
    limit: usize,
) -> Result<usize, SyncSqliteError> {
    let group = group_id.as_str();
    let mut stmt = conn.prepare_cached(
        "SELECT p.path, h.author, h.incarnation, h.seq, h.version, h.provenance \
         FROM (SELECT path FROM native_namespace_pending WHERE group_id = ?1 \
               ORDER BY path LIMIT ?2) p \
         LEFT JOIN native_heads h ON h.group_id = ?1 AND h.path = p.path \
         ORDER BY p.path",
    )?;
    let mut rows = stmt.query(rusqlite::params![group, limit as i64])?;
    let mut edits: Vec<PathEditV2> = Vec::new();
    let mut current: Option<(SyncPath, std::collections::BTreeMap<_, _>)> = None;
    while let Some(row) = rows.next()? {
        let path: String = row.get(0)?;
        if !matches!(&current, Some((p, _)) if p.as_str() == path) {
            if let Some((path, heads)) = current.take() {
                edits.push(PathEditV2 {
                    path,
                    heads: crate::native_store::author_buckets_of(&heads),
                });
            }
            current = Some((SyncPath(path), std::collections::BTreeMap::new()));
        }
        // A path with no head row comes back once, with NULL head columns: a removal.
        if row.get::<_, Option<String>>(1)?.is_some() {
            let head = crate::native_store::live_head_at(row, 1)?;
            if let Some((_, heads)) = &mut current {
                heads.insert(head.dot, head.payload);
            }
        }
    }
    if let Some((path, heads)) = current.take() {
        edits.push(PathEditV2 { path, heads: crate::native_store::author_buckets_of(&heads) });
    }
    drop(rows);
    drop(stmt);
    if edits.is_empty() {
        return Ok(0);
    }
    patch(conn, group_id, &edits)?;
    let mut forget = conn
        .prepare_cached("DELETE FROM native_namespace_pending WHERE group_id = ?1 AND path = ?2")?;
    for edit in &edits {
        forget.execute(rusqlite::params![group, edit.path.as_str()])?;
    }
    Ok(edits.len())
}

/// Brings the group's stored trie up to its heads, in the caller's transaction: every pending path,
/// `FLUSH_CHUNK` at a time, so memory is one chunk however many paths are pending.
pub fn flush_pending(conn: &Connection, group_id: &FolderGroupId) -> Result<(), SyncSqliteError> {
    // A savepoint, so a caller on a bare connection gets the same all-or-nothing the patch needs (it
    // changes node rows, the root and the pending rows) and one inside a transaction adds nothing.
    conn.execute_batch("SAVEPOINT native_namespace_flush")?;
    let flushed = (|| {
        while flush_some(conn, group_id, FLUSH_CHUNK)? > 0 {}
        Ok(())
    })();
    match flushed {
        Ok(()) => {
            conn.execute_batch("RELEASE native_namespace_flush")?;
            Ok(())
        }
        Err(error) => {
            conn.execute_batch(
                "ROLLBACK TO native_namespace_flush; RELEASE native_namespace_flush",
            )?;
            Err(error)
        }
    }
}

/// Brings every group's stored trie up to its heads, for a caller that is about to read roots
/// and holds no transaction: each chunk of `FLUSH_TX_PATHS` paths is its own write transaction, so
/// the writer gate is held for one chunk at a time and a crash between chunks leaves the trie
/// and the pending set consistent with each other. Cheap when nothing is pending.
pub fn flush_all(db: &yadorilink_sqlite_runtime::SyncDatabase) -> Result<(), SyncSqliteError> {
    // What was pending when this call began: sustained writes add paths faster than a caller should
    // wait for, and a path they add after this point is the next call's (a reader that finds one
    // asks again, a bounded number of times).
    let mut budget: i64 = db.read(|conn| {
        Ok::<_, SyncSqliteError>(conn.query_row(
            "SELECT COUNT(*) FROM native_namespace_pending",
            [],
            |row| row.get(0),
        )?)
    })?;
    while budget > 0 {
        let took = db.write_immediate::<_, SyncSqliteError>(|tx| {
            let groups: Vec<String> = tx
                .prepare_cached("SELECT DISTINCT group_id FROM native_namespace_pending LIMIT 1")?
                .query_map([], |row| row.get(0))?
                .collect::<Result<_, _>>()?;
            let Some(group) = groups.into_iter().next() else { return Ok(0) };
            flush_some(tx, &FolderGroupId(group), FLUSH_TX_PATHS)
        })?;
        if took == 0 {
            break;
        }
        budget -= took as i64;
    }
    Ok(())
}

/// The group's namespace root. An error while paths are pending: the root would not be the heads'.
pub(crate) fn namespace_root(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<NodeDigest, SyncSqliteError> {
    let pending: bool = conn
        .prepare_cached(
            "SELECT EXISTS (SELECT 1 FROM native_namespace_pending WHERE group_id = ?1)",
        )?
        .query_row([group_id.as_str()], |row| row.get(0))?;
    if pending {
        return Err(SyncSqliteError::NamespaceBehind);
    }
    Ok(root_row(conn, group_id.as_str())?.unwrap_or_else(empty_digest))
}

/// The empty bucket map of a removal, for callers that build edits.
#[allow(dead_code)]
pub(crate) fn removal(path: SyncPath) -> PathEditV2 {
    PathEditV2 { path, heads: AuthorBuckets::default() }
}

/// Checks the stored nodes against the root: they are exactly the nodes it reaches, and every count is
/// the number of parents plus the root pointer.
#[cfg(any(test, feature = "test-support"))]
pub fn check_integrity(conn: &Connection, group_id: &FolderGroupId) -> Result<(), String> {
    use std::collections::{BTreeMap, BTreeSet};
    let group = group_id.as_str();
    flush_pending(conn, group_id).map_err(|e| e.to_string())?;
    let root = namespace_root(conn, group_id).map_err(|e| e.to_string())?;
    let mut stored: BTreeMap<(i64, [u8; 32]), (Vec<u8>, i64)> = BTreeMap::new();
    let mut stmt = conn
        .prepare("SELECT kind, digest, body, refs FROM native_namespace_node WHERE group_id = ?1")
        .map_err(|e| e.to_string())?;
    let mut rows = stmt.query([group]).map_err(|e| e.to_string())?;
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        let digest: Vec<u8> = row.get(1).map_err(|e| e.to_string())?;
        let digest: [u8; 32] = digest.as_slice().try_into().map_err(|_| "digest length")?;
        stored.insert(
            (row.get(0).map_err(|e| e.to_string())?, digest),
            (row.get(2).map_err(|e| e.to_string())?, row.get(3).map_err(|e| e.to_string())?),
        );
    }
    let mut expected: BTreeMap<(i64, [u8; 32]), i64> = BTreeMap::new();
    let mut reached: BTreeSet<(i64, [u8; 32])> = BTreeSet::new();
    let mut stack = Vec::new();
    if root != empty_digest() {
        *expected.entry((KIND_HEADS, root.0)).or_default() += 1;
        stack.push((KIND_HEADS, root.0));
    }
    while let Some(key) = stack.pop() {
        if !reached.insert(key) {
            continue;
        }
        let (body, _) =
            stored.get(&key).ok_or_else(|| format!("reachable node {key:?} is not stored"))?;
        for (kind, child) in children(key.0, body).map_err(|e| e.to_string())? {
            *expected.entry((kind, child.0)).or_default() += 1;
            stack.push((kind, child.0));
        }
    }
    let stored_keys: BTreeSet<_> = stored.keys().copied().collect();
    if stored_keys != reached {
        return Err(format!(
            "stored nodes differ from reachable ones: {} stored, {} reachable",
            stored_keys.len(),
            reached.len()
        ));
    }
    for (key, (_, refs)) in &stored {
        let want = expected.get(key).copied().unwrap_or(0);
        if *refs != want {
            return Err(format!("node {key:?} counts {refs} references, has {want}"));
        }
    }
    Ok(())
}
