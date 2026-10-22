//! Path keys and the byte encodings of nodes.

use sha2::{Digest, Sha256};
use yadorilink_replica_domain::author::{AuthorId, IncarnationId, MAX_SELF_HEADS};
use yadorilink_replica_domain::ids::{DeltaHash, DeviceId, SyncPath};

use crate::{
    AuthorNode, HeadAggregates, NamespaceError, NodeDigest, NodeV2, PathBits, ShapeNodeV2,
    AUTHOR_BRANCH_TAG, AUTHOR_BUCKET_TAG, BRANCH_V2_TAG, SHAPE_V2_TAG, UNIFORM_V2_TAG,
};

/// SHA-256 over `tag` followed by `body`.
pub(crate) fn tagged_digest(tag: &[u8; 8], body: &[u8]) -> NodeDigest {
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(body);
    NodeDigest(hasher.finalize().into())
}

impl PathBits {
    /// The key of `path`.
    pub fn of_path(path: &SyncPath) -> Self {
        Self::of_bytes(path.as_str().as_bytes())
    }

    /// The key prefix of the subtree under directory `dir` (`None` for the
    /// root directory).
    pub fn subtree_of(dir: Option<&SyncPath>) -> Self {
        match dir {
            None => Self::default(),
            Some(dir) => {
                let mut bytes = dir.as_str().as_bytes().to_vec();
                bytes.push(b'/');
                Self::of_bytes(&bytes)
            }
        }
    }

    /// The bit string of `bytes`, whole bytes only.
    pub(crate) fn of_bytes(bytes: &[u8]) -> Self {
        let len = u32::try_from(bytes.len() * 8).expect("path key exceeds u32::MAX bits");
        Self { bytes: bytes.to_vec(), len }
    }

    /// Bit `i`, most significant bit of each byte first.
    fn bit(&self, i: usize) -> bool {
        self.bytes.get(i / 8).is_some_and(|byte| byte & (0x80 >> (i % 8)) != 0)
    }

    /// The bits as one `bool` each.
    pub(crate) fn to_bits(&self) -> Vec<bool> {
        (0..self.len as usize).map(|i| self.bit(i)).collect()
    }

    /// Packs `bits`, unused trailing bits zero.
    pub(crate) fn from_bits(bits: &[bool]) -> Self {
        let mut bytes = vec![0u8; bits.len().div_ceil(8)];
        for (i, _) in bits.iter().enumerate().filter(|(_, bit)| **bit) {
            bytes[i / 8] |= 0x80 >> (i % 8);
        }
        let len = u32::try_from(bits.len()).expect("bit string exceeds u32::MAX bits");
        Self { bytes, len }
    }

    /// Appends the encoding: `u32` length, then exactly `ceil(len / 8)`
    /// packed bytes with unused trailing bits zero, whatever `bytes` holds
    /// beyond them.
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.len.to_be_bytes());
        out.extend_from_slice(&Self::from_bits(&self.to_bits()).bytes);
    }
}

/// The canonical key encoding of an author: the device id's UTF-8 byte
/// length as a big-endian `u32`, the device id, then the 16 incarnation
/// bytes. The length prefix makes the keys of distinct authors prefix-free.
pub(crate) fn author_key_bytes(author: &AuthorId) -> Vec<u8> {
    let device = author.device.0.as_bytes();
    let len = u32::try_from(device.len()).expect("device id exceeds u32::MAX bytes");
    let mut out = Vec::with_capacity(4 + device.len() + author.incarnation.0.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(device);
    out.extend_from_slice(&author.incarnation.0);
    out
}

/// The author whose key encoding is exactly `bytes`.
pub(crate) fn author_of_key_bytes(bytes: &[u8]) -> Result<AuthorId, NamespaceError> {
    let mut reader = Reader { bytes, at: 0 };
    let len = reader.u32()? as usize;
    let device = String::from_utf8(reader.take(len)?.to_vec())
        .map_err(|_| malformed("author device id is not UTF-8"))?;
    let mut incarnation = [0u8; 16];
    incarnation.copy_from_slice(reader.take(16)?);
    reader.finish()?;
    Ok(AuthorId { device: DeviceId(device), incarnation: IncarnationId(incarnation) })
}

fn encode_aggregates(aggregates: &HeadAggregates, out: &mut Vec<u8>) {
    out.extend_from_slice(&aggregates.head_count.to_be_bytes());
    out.extend_from_slice(&aggregates.duplicate_author_count.to_be_bytes());
}

impl NodeV2 {
    /// The node's domain tag.
    pub fn tag(&self) -> &'static [u8; 8] {
        match self {
            NodeV2::Branch { .. } => BRANCH_V2_TAG,
            NodeV2::Uniform { .. } => UNIFORM_V2_TAG,
        }
    }

    /// The node's encoding, without its tag.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            NodeV2::Branch { skip, buckets, aggregates, conflict, zero, one } => {
                skip.encode_into(&mut out);
                out.extend_from_slice(&buckets.0);
                encode_aggregates(aggregates, &mut out);
                out.push(u8::from(*conflict));
                out.extend_from_slice(&zero.0);
                out.extend_from_slice(&one.0);
            }
            NodeV2::Uniform { skip, shape, buckets, aggregates } => {
                skip.encode_into(&mut out);
                out.extend_from_slice(&shape.0);
                out.extend_from_slice(&buckets.0);
                encode_aggregates(aggregates, &mut out);
            }
        }
        out
    }

    /// Decodes an encoding produced by [`Self::encode`] for `tag`.
    ///
    /// Only the byte format is checked here (flag bytes, zero padding, no
    /// trailing bytes); canonical form and derived counts are properties
    /// of a whole trie, checked by [`crate::v2::open`].
    pub fn decode(tag: &[u8; 8], bytes: &[u8]) -> Result<Self, NamespaceError> {
        let mut reader = Reader { bytes, at: 0 };
        let node = if tag == BRANCH_V2_TAG {
            let skip = reader.bits()?;
            let buckets = reader.digest()?;
            let aggregates = reader.aggregates()?;
            let conflict = reader.flag()?;
            let zero = reader.digest()?;
            let one = reader.digest()?;
            NodeV2::Branch { skip, buckets, aggregates, conflict, zero, one }
        } else if tag == UNIFORM_V2_TAG {
            let skip = reader.bits()?;
            let shape = reader.digest()?;
            let buckets = reader.digest()?;
            let aggregates = reader.aggregates()?;
            NodeV2::Uniform { skip, shape, buckets, aggregates }
        } else {
            return Err(malformed("unknown heads-node tag"));
        };
        reader.finish()?;
        Ok(node)
    }

    /// SHA-256 over the node's tag and encoding.
    pub fn digest(&self) -> NodeDigest {
        tagged_digest(self.tag(), &self.encode())
    }
}

impl AuthorNode {
    /// The node's domain tag.
    pub fn tag(&self) -> &'static [u8; 8] {
        match self {
            AuthorNode::Branch { .. } => AUTHOR_BRANCH_TAG,
            AuthorNode::Bucket { .. } => AUTHOR_BUCKET_TAG,
        }
    }

    /// The node's encoding, without its tag.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            AuthorNode::Branch { skip, aggregates, zero, one } => {
                skip.encode_into(&mut out);
                encode_aggregates(aggregates, &mut out);
                out.extend_from_slice(&zero.0);
                out.extend_from_slice(&one.0);
            }
            AuthorNode::Bucket { skip, heads } => {
                skip.encode_into(&mut out);
                encode_heads(heads, &mut out);
            }
        }
        out
    }

    /// Decodes an encoding produced by [`Self::encode`] for `tag`. A bucket
    /// must hold one or [`MAX_SELF_HEADS`] heads, strictly ascending.
    pub fn decode(tag: &[u8; 8], bytes: &[u8]) -> Result<Self, NamespaceError> {
        let mut reader = Reader { bytes, at: 0 };
        let node = if tag == AUTHOR_BRANCH_TAG {
            let skip = reader.bits()?;
            let aggregates = reader.aggregates()?;
            let zero = reader.digest()?;
            let one = reader.digest()?;
            AuthorNode::Branch { skip, aggregates, zero, one }
        } else if tag == AUTHOR_BUCKET_TAG {
            let skip = reader.bits()?;
            let heads = reader.heads()?;
            if heads.is_empty() || heads.len() > MAX_SELF_HEADS {
                return Err(malformed("author bucket holds no heads or too many"));
            }
            AuthorNode::Bucket { skip, heads }
        } else {
            return Err(malformed("unknown bucket-node tag"));
        };
        reader.finish()?;
        Ok(node)
    }

    /// SHA-256 over the node's tag and encoding.
    pub fn digest(&self) -> NodeDigest {
        tagged_digest(self.tag(), &self.encode())
    }

    /// The node's aggregate counts: stored on a branch, derived for a
    /// bucket.
    pub fn aggregates(&self) -> HeadAggregates {
        match self {
            AuthorNode::Branch { aggregates, .. } => *aggregates,
            AuthorNode::Bucket { heads, .. } => HeadAggregates::of_bucket(heads.len()),
        }
    }
}

impl ShapeNodeV2 {
    /// The node's domain tag, [`SHAPE_V2_TAG`].
    pub fn tag(&self) -> &'static [u8; 8] {
        SHAPE_V2_TAG
    }

    /// The node's encoding, without its tag.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.skip.encode_into(&mut out);
        out.push(u8::from(self.entry));
        out.extend_from_slice(&self.entry_count.to_be_bytes());
        out.extend_from_slice(&self.zero.0);
        out.extend_from_slice(&self.one.0);
        out
    }

    /// Decodes an encoding produced by [`Self::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, NamespaceError> {
        let mut reader = Reader { bytes, at: 0 };
        let node = ShapeNodeV2 {
            skip: reader.bits()?,
            entry: reader.flag()?,
            entry_count: reader.u64()?,
            zero: reader.digest()?,
            one: reader.digest()?,
        };
        reader.finish()?;
        Ok(node)
    }

    /// SHA-256 over [`SHAPE_V2_TAG`] and the node's encoding.
    pub fn digest(&self) -> NodeDigest {
        tagged_digest(SHAPE_V2_TAG, &self.encode())
    }
}

fn encode_heads(heads: &[DeltaHash], out: &mut Vec<u8>) {
    let count = u32::try_from(heads.len()).expect("head count exceeds u32::MAX");
    out.extend_from_slice(&count.to_be_bytes());
    for head in heads {
        out.extend_from_slice(&head.0);
    }
}

fn malformed(what: &str) -> NamespaceError {
    NamespaceError::Malformed(what.to_string())
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], NamespaceError> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| malformed("truncated node encoding"))?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn u32(&mut self) -> Result<u32, NamespaceError> {
        let raw = self.take(4)?;
        Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    fn u64(&mut self) -> Result<u64, NamespaceError> {
        let mut raw = [0u8; 8];
        raw.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(raw))
    }

    fn aggregates(&mut self) -> Result<HeadAggregates, NamespaceError> {
        Ok(HeadAggregates { head_count: self.u64()?, duplicate_author_count: self.u64()? })
    }

    fn array32(&mut self) -> Result<[u8; 32], NamespaceError> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.take(32)?);
        Ok(out)
    }

    fn digest(&mut self) -> Result<NodeDigest, NamespaceError> {
        Ok(NodeDigest(self.array32()?))
    }

    fn flag(&mut self) -> Result<bool, NamespaceError> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(malformed("flag byte is neither 0 nor 1")),
        }
    }

    fn bits(&mut self) -> Result<PathBits, NamespaceError> {
        let len = self.u32()?;
        let bytes = self.take((len as usize).div_ceil(8))?.to_vec();
        let used = len as usize % 8;
        if used != 0 && bytes.last().is_some_and(|last| last & (0xff >> used) != 0) {
            return Err(malformed("bit string has non-zero padding"));
        }
        Ok(PathBits { bytes, len })
    }

    fn heads(&mut self) -> Result<Vec<DeltaHash>, NamespaceError> {
        let count = self.u32()? as usize;
        if count > (self.bytes.len() - self.at) / 32 {
            return Err(malformed("truncated head list"));
        }
        let mut heads = Vec::with_capacity(count);
        for _ in 0..count {
            heads.push(DeltaHash(self.array32()?));
        }
        if heads.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(malformed("heads are not strictly ascending"));
        }
        Ok(heads)
    }

    fn finish(&self) -> Result<(), NamespaceError> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(malformed("trailing bytes after node encoding"))
        }
    }
}
