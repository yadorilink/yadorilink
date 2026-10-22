//! What materialization has to make true, in NativeState's own terms:
//! the exact live head each node stands for, where it goes on
//! disk, and nothing borrowed from DCF -- no change hash, no `PathHead`, no
//! synthetic tombstone. Absence is the absence of a node; it carries no
//! authorship, so nothing can be deleted "because of" a stand-in identity.
//!
//! A plan is a value: the same state yields an equal plan, and a plan
//! prepared before a fetch is compared with the plan recomputed under the
//! path lock to decide whether the prepared work is still what native wants.

use crate::file::RecordKind;
use crate::ids::{SyncPath, VersionHash};
use crate::native_state::{Dot, LiveHead};

use std::collections::BTreeMap;

/// A live head together with the logical path it lives at. One delta puts
/// the same dot at several paths, so a dot alone never identifies what a
/// physical entry stands for; `(source_path, dot)` does, and `provenance`
/// (in the payload) pins the exact signed delta that wrote it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NativeLocatedHead {
    pub source_path: SyncPath,
    pub head: LiveHead,
}

impl NativeLocatedHead {
    pub fn dot(&self) -> &Dot {
        &self.head.dot
    }

    pub fn version(&self) -> VersionHash {
        self.head.payload.version
    }
}

/// A path's own-account requirement: what the winner (or the tree
/// constraint) makes of exactly this path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NativeDesiredNode {
    /// Native holds nothing for this path.
    Absent,
    /// A directory only because something live sits below it.
    StructuralDirectory,
    ExplicitDirectory {
        head: NativeLocatedHead,
    },
    Entry {
        head: NativeLocatedHead,
        kind: RecordKind,
    },
}

/// One physical node of a level.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum NativePlannedNode {
    StructuralDirectory,
    ExplicitDirectory {
        head: NativeLocatedHead,
    },
    /// A File or Symlink at its own path (the map key), standing for `head`.
    Entry {
        head: NativeLocatedHead,
        kind: RecordKind,
    },
}

/// Every node of one directory level, keyed by path. A path with no key is
/// absent, unless it is contested.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct NativeLevelPlan {
    pub nodes: BTreeMap<SyncPath, NativePlannedNode>,
    /// Paths of the level that project `Pending`: two versions hold them, or
    /// a file holds a path that has to be a directory, or a version record
    /// has not arrived. Nothing is planned for them and nothing below them is
    /// created or removed.
    pub contested: std::collections::BTreeSet<SyncPath>,
}

/// What a `files` row displays, in NativeState's terms: the exact head it
/// was materialized from. Stored as ONE canonical blob so that a row either
/// carries a whole identity or none, and so that "the row still shows this
/// head" is a single equality. The provenance leads (32 bytes) so the schema
/// can verify it against the installed delta log without decoding the rest.
///
/// A row with no identity is "unknown": it is never guessed from a version
/// or a path.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NativeRowIdentity {
    pub source_path: SyncPath,
    pub dot: Dot,
    pub provenance: crate::native_state::DeltaHash,
}

/// Why a stored identity blob was refused.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[error("malformed native row identity: {0}")]
pub struct NativeRowIdentityError(&'static str);

impl NativeRowIdentity {
    /// The identity of the row a head materializes into.
    pub fn of(head: &NativeLocatedHead) -> Self {
        Self {
            source_path: head.source_path.clone(),
            dot: head.head.dot.clone(),
            provenance: head.head.payload.provenance,
        }
    }

    /// `provenance (32) || seq (u64 BE) || incarnation (16) || device_len (u16 BE)
    /// || device || source_path`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let device = self.dot.author.device.0.as_bytes();
        let mut out =
            Vec::with_capacity(32 + 8 + 16 + 2 + device.len() + self.source_path.as_str().len());
        out.extend_from_slice(&self.provenance.0);
        out.extend_from_slice(&self.dot.seq.get().to_be_bytes());
        out.extend_from_slice(&self.dot.author.incarnation.0);
        out.extend_from_slice(&(device.len() as u16).to_be_bytes());
        out.extend_from_slice(device);
        out.extend_from_slice(self.source_path.as_str().as_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NativeRowIdentityError> {
        const FIXED: usize = 32 + 8 + 16 + 2;
        if bytes.len() < FIXED {
            return Err(NativeRowIdentityError("shorter than the fixed header"));
        }
        let provenance: [u8; 32] = bytes[..32].try_into().expect("32 bytes");
        let seq = u64::from_be_bytes(bytes[32..40].try_into().expect("8 bytes"));
        let incarnation: [u8; 16] = bytes[40..56].try_into().expect("16 bytes");
        let device_len = u16::from_be_bytes(bytes[56..58].try_into().expect("2 bytes")) as usize;
        let rest = &bytes[FIXED..];
        if rest.len() < device_len {
            return Err(NativeRowIdentityError("device name truncated"));
        }
        let device = std::str::from_utf8(&rest[..device_len])
            .map_err(|_| NativeRowIdentityError("device name is not UTF-8"))?;
        let source = std::str::from_utf8(&rest[device_len..])
            .map_err(|_| NativeRowIdentityError("source path is not UTF-8"))?;
        let seq = crate::ids::AuthorSeq(seq);
        if seq.get() == 0 {
            return Err(NativeRowIdentityError("sequence 0"));
        }
        Ok(Self {
            source_path: SyncPath(source.to_owned()),
            dot: Dot {
                author: crate::author::AuthorId {
                    device: crate::ids::DeviceId(device.to_owned()),
                    incarnation: crate::author::IncarnationId(incarnation),
                },
                seq,
            },
            provenance: crate::native_state::DeltaHash(provenance),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::author::{AuthorId, IncarnationId};
    use crate::ids::{AuthorSeq, DeviceId};
    use crate::native_state::DeltaHash;

    fn identity() -> NativeRowIdentity {
        NativeRowIdentity {
            source_path: SyncPath("dir/a b.txt".into()),
            dot: Dot {
                author: AuthorId {
                    device: DeviceId("device-7".into()),
                    incarnation: IncarnationId([3; 16]),
                },
                seq: AuthorSeq(42),
            },
            provenance: DeltaHash([9; 32]),
        }
    }

    #[test]
    fn an_identity_round_trips_and_leads_with_its_provenance() {
        let id = identity();
        let bytes = id.to_bytes();
        assert_eq!(&bytes[..32], &[9u8; 32]);
        assert_eq!(NativeRowIdentity::from_bytes(&bytes).unwrap(), id);
    }

    #[test]
    fn every_field_changes_the_encoding() {
        let base = identity().to_bytes();
        let mut other = identity();
        other.source_path = SyncPath("dir/other".into());
        assert_ne!(other.to_bytes(), base);
        let mut other = identity();
        other.dot.seq = AuthorSeq(43);
        assert_ne!(other.to_bytes(), base);
        let mut other = identity();
        other.provenance = DeltaHash([8; 32]);
        assert_ne!(other.to_bytes(), base);
        let mut other = identity();
        other.dot.author.device = DeviceId("device-8".into());
        assert_ne!(other.to_bytes(), base);
    }

    #[test]
    fn a_malformed_blob_is_refused_not_repaired() {
        let bytes = identity().to_bytes();
        assert!(NativeRowIdentity::from_bytes(&bytes[..10]).is_err());
        assert!(NativeRowIdentity::from_bytes(&bytes[..60]).is_err(), "device name truncated");
        let mut zero_seq = bytes.clone();
        zero_seq[32..40].copy_from_slice(&0u64.to_be_bytes());
        assert!(NativeRowIdentity::from_bytes(&zero_seq).is_err());
    }
}
