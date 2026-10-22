//! Content-addressed identities and opaque string newtypes shared across
//! the replica domain model.

/// SHA-256 of a signed delta's header — its content-addressed identity, and
/// the provenance of every head it lands. Two byte-identical headers hash
/// equal on every device. Zero where nothing is signed yet.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct DeltaHash(pub [u8; 32]);

/// SHA-256 of a `FileVersion`'s canonical encoding.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VersionHash(pub [u8; 32]);

/// SHA-256 of a `FileVersion`'s canonical encoding with the modification time
/// zeroed: the identity of what a version holds (kind, size, block list, mode,
/// symlink target, xattrs) apart from when it was written. Two versions that
/// differ only in `mtime` have distinct [`VersionHash`]es and one
/// `ContentIdentity`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentIdentity(pub [u8; 32]);

impl std::fmt::Debug for ContentIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ContentIdentity({})", hex::encode(self.0))
    }
}

/// Content hash of a single stored block. Length-prefixed in the canonical
/// encoding rather than fixed at 32 bytes, so the hash width is not baked
/// into the wire format.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct BlockHash(pub Vec<u8>);

/// A device's stable identity string (the same value used as the
/// `device_id` key throughout the index and wire protocol).
///
/// This is also the *author* identity of a change: the coordination plane
/// issues a fresh device id per registration, and a signing key is bound to
/// that device once and never rebound, so a key change or a recovery is a
/// re-registration under a new device id. Together with the group and an
/// [`AuthorSeq`] it forms a change's causal dot, `(group_id, device_id,
/// author_seq)`. A purely local, self-minted author identity was
/// deliberately rejected for that role: nothing outside the device would
/// attest it, so any holder of the signing key could claim a fresh one at
/// will, and a whole-directory copy would duplicate it along with the key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DeviceId(pub String);

/// One author's position in its own change chain, scoped to a single group:
/// the third component of a change's causal dot, `(group_id, device_id,
/// author_seq)`.
///
/// It starts at 1 for an author's first change in a group, increases by
/// exactly one per change that author admits there, and never resets — not
/// when history is compacted onto a new base, and not when the author goes
/// offline and returns. It is emphatically **not** the Lamport clock:
/// `lamport` summarizes what the author had seen from everyone, while this
/// counts only what the author itself wrote. Zero is not a valid sequence;
/// it is reserved so an unset field cannot pass for a real position.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct AuthorSeq(pub u64);

impl AuthorSeq {
    /// The sequence an author's very first change in a group carries.
    pub const FIRST: Self = Self(1);

    /// The highest sequence a change may carry.
    ///
    /// The field is a `u64` on the wire, but every store that records it
    /// keeps it in a SQLite `INTEGER` column, which is signed 64-bit — so a
    /// value above this would be written back as a negative number and then
    /// read back as a position no author chain has. The field is signed by
    /// whoever wrote the change, so the value is a peer's to choose; this
    /// ceiling is checked where a change is built and where one is decoded,
    /// so no change carrying a sequence the store cannot hold ever reaches
    /// the store. It is far beyond any reachable count of changes: an author
    /// writing a thousand changes a second would need longer than the age of
    /// the universe to approach it.
    pub const MAX: Self = Self(i64::MAX as u64);

    pub fn get(self) -> u64 {
        self.0
    }

    /// The position immediately after this one — the only sequence a
    /// following change by the same author in the same group may carry —
    /// or `None` when this author has reached [`MAX`](Self::MAX) and has no
    /// next position at all.
    ///
    /// Checked rather than saturating, and that distinction is a
    /// correctness one rather than a tidiness one. A saturating successor
    /// reports `MAX` as the position after `MAX`, so the sequence an
    /// exhausted author's next change would carry is the one its last
    /// change already carries: two distinct changes at one dot, which is
    /// exactly the state the dot exists to make impossible. Every caller
    /// must fail closed on `None` — refuse to emit, refuse to admit —
    /// rather than reuse a position.
    ///
    /// Unreachable in practice: an author writing a thousand changes a
    /// second would need longer than the age of the universe to get here.
    /// It is checked anyway because the cost of checking is a branch and
    /// the cost of not checking is a silent collision in the one structure
    /// every convergence argument rests on.
    pub fn checked_next(self) -> Option<Self> {
        let next = self.0.checked_add(1)?;
        (next <= Self::MAX.0).then_some(Self(next))
    }
}

impl std::fmt::Display for AuthorSeq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A synced folder group's identity string.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct FolderGroupId(pub String);

/// A file path relative to a folder group's root, as an opaque UTF-8 string.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct SyncPath(pub String);

macro_rules! string_newtype {
    ($t:ty) => {
        impl $t {
            pub fn as_str(&self) -> &str {
                &self.0
            }
            pub fn into_string(self) -> String {
                self.0
            }
        }
        impl From<String> for $t {
            fn from(s: String) -> Self {
                Self(s)
            }
        }
        impl From<&str> for $t {
            fn from(s: &str) -> Self {
                Self(s.to_string())
            }
        }
        impl std::fmt::Display for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}
string_newtype!(DeviceId);
string_newtype!(FolderGroupId);
string_newtype!(SyncPath);

impl std::fmt::Debug for DeltaHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DeltaHash({})", hex::encode(self.0))
    }
}
impl std::fmt::Debug for VersionHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VersionHash({})", hex::encode(self.0))
    }
}
impl DeltaHash {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl VersionHash {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
