//! The signed data of a change, and the universe of all signed changes.
//!
//! A change touches paths through operations. Each operation either lands
//! content (`Effect::Put`) or removes it (`Effect::Delete`), and carries its
//! signed basis: the changes it supersedes at that path. A history is a set
//! of change identifiers drawn from a [`Universe`].
//!

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Identifies one signed change (a change hash in production).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ChangeId(pub u64);

impl fmt::Display for ChangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "c{}", self.0)
    }
}

/// Identifies an author: the key of a watermark.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct AuthorId(pub u32);

/// An author and a sequence number.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Dot {
    pub author: AuthorId,
    pub seq: u64,
}

/// Identifies a content version. Preservation re-lands an existing version.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Version(pub u64);

/// A path. Directories are `/`-separated prefixes and may be entries too.
pub type Path = String;

/// The per-path heads of a history: only present entries, never an empty
/// set.
pub type Heads = BTreeMap<Path, BTreeSet<ChangeId>>;

/// A history: a set of changes of one universe.
pub type History = BTreeSet<ChangeId>;

/// What an operation does at its path.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Effect {
    /// Lands content with this version.
    Put(Version),
    /// Lands nothing.
    Delete,
}

/// One touched path of a change.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Op {
    pub path: Path,
    pub effect: Effect,
    /// The changes this operation supersedes at `path`.
    pub basis: Vec<ChangeId>,
}

/// A signed conflict preservation: `source`, consumed at `source_path`, is
/// re-landed with the same version at `target_path` by the same change.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Preservation {
    pub source_path: Path,
    pub source: ChangeId,
    pub target_path: Path,
    pub version: Version,
}

/// A signed change.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Change {
    pub id: ChangeId,
    pub author: AuthorId,
    /// Strictly positive.
    pub seq: u64,
    pub ops: Vec<Op>,
    pub preservations: Vec<Preservation>,
}

impl Change {
    pub fn dot(&self) -> Dot {
        Dot { author: self.author, seq: self.seq }
    }

    /// Whether any operation of the change is at `path`.
    ///
    pub fn touched(&self, path: &str) -> bool {
        self.ops.iter().any(|op| op.path == path)
    }

    /// Whether any operation at `path` lands content.
    ///
    pub fn lands(&self, path: &str) -> bool {
        self.ops.iter().any(|op| op.path == path && matches!(op.effect, Effect::Put(_)))
    }

    /// Whether `member` is in the basis of any operation at `path`.
    ///
    pub fn in_basis(&self, path: &str, member: ChangeId) -> bool {
        self.ops.iter().any(|op| op.path == path && op.basis.contains(&member))
    }

    /// Every basis member of every operation at `path`.
    pub fn basis_at<'a>(&'a self, path: &'a str) -> impl Iterator<Item = ChangeId> + 'a {
        self.ops.iter().filter(move |op| op.path == path).flat_map(|op| op.basis.iter().copied())
    }

    /// The version the change lands at `path`, if it lands content there.
    ///
    pub fn version_at(&self, path: &str) -> Option<Version> {
        self.ops.iter().find_map(|op| match op.effect {
            Effect::Put(v) if op.path == path => Some(v),
            _ => None,
        })
    }
}

/// The deterministic conflict path at which `source`'s version at `path`
/// is preserved.
///
pub fn conflict_path(path: &str, source: ChangeId) -> Path {
    format!("{path}~{}", source.0)
}

/// Whether `path` is `prefix` itself or lies below the directory `prefix`.
pub fn is_under(path: &str, prefix: &str) -> bool {
    path == prefix
        || (path.len() > prefix.len()
            && path.starts_with(prefix)
            && path.as_bytes()[prefix.len()] == b'/')
}

/// Every signed change known to a test, forks included.
#[derive(Clone, Default, Debug)]
pub struct Universe {
    changes: BTreeMap<ChangeId, Change>,
}

impl Universe {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `change`, replacing any change with the same identifier.
    pub fn insert(&mut self, change: Change) {
        self.changes.insert(change.id, change);
    }

    pub fn get(&self, id: ChangeId) -> Option<&Change> {
        self.changes.get(&id)
    }

    /// The change `id`.
    ///
    /// # Panics
    ///
    /// When `id` is not in the universe.
    pub fn change(&self, id: ChangeId) -> &Change {
        self.changes.get(&id).unwrap_or_else(|| panic!("{id} is not in the universe"))
    }

    pub fn changes(&self) -> impl Iterator<Item = &Change> {
        self.changes.values()
    }

    pub fn len(&self) -> usize {
        self.changes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}
