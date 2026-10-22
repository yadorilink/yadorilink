//! Protobuf-free domain equivalents of the wire messages
//! `crates/yadorilink-ipc-proto/proto/sync.proto` defines. Mirrors the
//! `DurableVersionQuery` pattern `peer_replica_engine.rs` uses: a frame holds only the fields its
//! consumer
//! actually reads, not a 1:1 mirror of every proto field.

/// One Change together with the `checkpoint_hash` naming the authorization
/// checkpoint that covers it, and the Merkle proof against that checkpoint's
/// root. `proof: None` here means the wire
/// message omitted it (malformed or genuinely absent) -- the receive path
/// treats that as an immediate rejection of THIS entry, never the whole
/// batch, matching the wire's own graceful-degradation convention for a
/// single bad field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedChangeFrame {
    /// `Change::to_wire_bytes()` -- canonical bytes + 64-byte signature.
    pub change: Vec<u8>,
    pub checkpoint_hash: Vec<u8>,
    pub proof: Option<AuthorizationMerkleProofFrame>,
}

/// Mirrors `yadorilink_replica_domain::authorization_checkpoint::MerkleProof`
/// field-for-field, protobuf-free.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationMerkleProofFrame {
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub siblings: Vec<Vec<u8>>,
}

/// A self-contained `AuthorizationCheckpoint` plus its authority signature
/// and the author's raw Ed25519 public key -- see `proto::
/// AuthorizationCheckpointEnvelope`'s own doc comment in `sync.proto` for
/// why the raw key travels with the checkpoint rather than being assumed
/// already pinned locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCheckpointEnvelopeFrame {
    pub checkpoint_hash: Vec<u8>,
    /// `authorization_checkpoint::canonical_signing_bytes`'s exact output.
    pub checkpoint: Vec<u8>,
    pub signature: Vec<u8>,
    pub author_signing_public_key: Vec<u8>,
}

/// A peer's request for one block's content: the first message on a block
/// stream.
///
/// Plain field mirror of the wire message, and all three fields are read:
/// `folder_group_id`/`file_path` for the authorization/reference/
/// declared-size lookups, `block_hash` for the store read. There is no
/// correlation id, because the stream is the correlation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRequestHeaderFrame {
    pub folder_group_id: String,
    pub file_path: String,
    pub block_hash: Vec<u8>,
}

/// Domain form of `proto::block_response_header::Outcome`'s oneof.
///
/// Both directions use this one type, unlike the inline reply it replaces,
/// which needed a separate sending-side enum because the receiver ignored
/// fields the sender always set. Every field here is read on both sides:
/// the requester acts on `queue_depth` when choosing a source, and `Found`
/// carries exactly what the receiver needs to read the body that follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockResponseOutcomeFrame {
    /// `size` is the number of raw body bytes that follow on the stream --
    /// post-compression, so it is what to read, not what will be left after
    /// decompressing. `hash` is echoed from the request so the requester can
    /// refuse a response bound to a different block than the one it asked
    /// for.
    Found {
        size: u64,
        hash: Vec<u8>,
        compression: i32,
    },
    DontHave,
    Busy {
        retry_after_ms: u32,
        queue_depth: u32,
    },
    Rejected {
        reason: String,
    },
}

/// A peer's answer to a block request: the second message on a block
/// stream. Under exact-generation ALPN a same-generation peer's
/// `BlockResponseHeader` always sets exactly one `outcome`; an absent oneof
/// is malformed for this generation and is rejected at decode time (see
/// `ProtobufPeerWireCodec::decode_block_response_header`), never treated as
/// `DontHave`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockResponseHeaderFrame {
    pub outcome: BlockResponseOutcomeFrame,
}
