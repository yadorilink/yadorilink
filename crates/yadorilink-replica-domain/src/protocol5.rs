//! Protocol 5 — native causal-state's wire message layer.
//!
//! **Transport-neutral by construction, not just by convention.** This
//! crate's own `workspace_dependencies = []` rule (`.config/architecture.toml`)
//! makes a dependency from here onto `yadorilink-sync-substrate` (the
//! `domain`-layer crate this crate sits below can never see an upper-layer
//! crate) a compile-time impossibility, not a promise this module could
//! quietly break. Nothing here knows about `Lane`, QUIC, iroh, connections,
//! streams, retries, or wall-clock time.
//!
//! [`MessageClass`] labels each message kind by traffic shape (small
//! discovery/comparison, verifiable history bulk, ...) in same-crate terms,
//! with no reference to any transport type. How a transport carries the
//! classes is that transport's decision; if it changes, this module does not.
//!
//! Message payloads reuse each domain type's own canonical wire encoding
//! wherever one already exists ([`crate::signed_delta::NativeDelta`],
//! [`crate::authorization_checkpoint::MerkleProof`]) rather than
//! re-encoding anything that already has a canonical form. This module's
//! own job is the envelope/framing/batching/hardening around those
//! payloads, not a second encoding of them.
//!
//! ## Timeout shape
//!
//! Every request message pairs with exactly one response message, or an
//! explicit [`Refusal`] — see `SummaryRequest`/`SummaryResponse`,
//! `FrontierDiffRequest`/`FrontierDiffResponse`. A transport can wrap "send
//! one request, await exactly one of {response, refusal, decode-error}" in
//! its own timeout; this module has no timer and no notion of elapsed
//! time. A batch message ([`Message::DeltaBatch`]) is a single,
//! complete, self-delimited push with no reply of its own — also a bounded
//! one-shot operation, never a long-lived stream a transport would need to
//! time out mid-flight.
//!
//! ## Hardening summary
//!
//! * **Bounded frame/message size**: [`MAX_MESSAGE_BYTES`]. A transport
//!   must call [`accept_declared_length`] on a length prefix *before*
//!   allocating a receive buffer of that size (see its doc); this module's
//!   own [`encode_message`] refuses to return bytes over that bound.
//! * **Bounded collection counts**: every batch/list field is read with
//!   [`Reader::bounded_count`] against a `MAX_*_ITEMS`/`MAX_*_ENTRIES`
//!   constant below, so a hostile count can never size an allocation
//!   before it is checked.
//! * **Fallible decode, no panics**: every decoder returns
//!   `Result<_, ProtocolError>`; see the adversarial tests at the bottom of
//!   this file.
//! * **Unknown type/version fail-closed**: [`decode_message`] rejects an
//!   unrecognized [`MessageKind`] byte and any protocol-version byte other
//!   than [`PROTOCOL5_VERSION`] — never best-effort parsed, never silently
//!   skipped.
//! * **Malformed/truncated rejection**: every decoder is truncation-safe
//!   (see the byte-mutation tests).
//! * **Replay/duplicate identity**: [`delta_batch_entry_identity`] gives a
//!   delta batch entry its canonical hash as identity for free;
//!   [`RequestId`] gives every request message an identity a transport can
//!   dedupe retries against. No enforcement store is built here — identity
//!   only, per this slice's scope.

use crate::author::{AuthorId, IncarnationId};
use crate::authorization_checkpoint::{decode_merkle_proof, encode_merkle_proof, MerkleProof};
use crate::codec::{put_str, put_u32, put_u64, ChangeError, Reader};
use crate::ids::{AuthorSeq, DeviceId, FolderGroupId};
use crate::native_protocol::{native_domain_tag, NATIVE_TAG_PREFIX_LEN};
use crate::native_state::DeltaHash;
use crate::signed_delta::NativeDelta;

/// This module's own protocol identifier. Distinct from, and never
/// renumbering, any protocol/schema version constant elsewhere in the
/// workspace (in particular `yadorilink-sqlite-runtime::SCHEMA_VERSION`);
/// this is just this codec's own version tag.
pub const PROTOCOL5_VERSION: u8 = 5;

/// Domain tag for one envelope. Trailing byte is the generation; there is
/// no migration ladder (mirrors every other domain tag in this crate).
pub const PROTOCOL5_ENVELOPE_TAG: &[u8; 8] = &native_domain_tag(b"YLNKp5e");

/// The largest total encoded length of one message (envelope included).
/// A transport must reject a declared length over this bound *before*
/// allocating a buffer for it — see [`accept_declared_length`].
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// The most bytes one `RecoveryChunk` carries.
pub const MAX_RECOVERY_CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// The most chunks one recovery bundle may be cut into: with
/// [`MAX_RECOVERY_CHUNK_BYTES`] this bounds a bundle at 512 MiB.
pub const MAX_RECOVERY_CHUNKS: u32 = 128;

/// The most entries a single `DeltaBatch` message may carry.
pub const MAX_BATCH_ITEMS: usize = 4096;

/// The most content versions one `DeltaBatch` entry may carry (a delta's ops
/// each put at most one).
pub const MAX_VERSIONS_PER_ENTRY: usize = 4096;

/// The most `(author, seq)` entries a single `FrontierDiffRequest`'s
/// "since" list, or a single `FrontierDiffResponse`'s entry list, may
/// carry.
pub const MAX_FRONTIER_ENTRIES: usize = 1 << 16;

/// The largest single item (a delta, a checkpoint, a proof or a carried
/// content version) a `DeltaBatch` entry may carry, independent of the
/// overall message bound above (a tighter per-item budget so one oversized
/// item can't consume the whole message budget by itself).
pub const MAX_BATCH_ITEM_BYTES: usize = 4 * 1024 * 1024;

// A content version must always fit the item budget it is carried under.
const _: () = assert!(crate::limits::MAX_ENCODED_VERSION_BYTES <= MAX_BATCH_ITEM_BYTES);

/// Rejection reasons for the codec layer. Never an authorization or
/// semantic verdict (those stay with the domain types this module wraps,
/// e.g. `ChangeError`, `CheckpointDecodeError`) — only "these bytes are not
/// a well-formed, in-bounds protocol 5 message."
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolError {
    #[error("declared message length {declared} exceeds the {max}-byte bound")]
    MessageTooLarge { declared: usize, max: usize },
    #[error("not a protocol 5 envelope")]
    BadEnvelopeTag,
    #[error("this build speaks protocol 5, message claims protocol {theirs}")]
    UnsupportedProtocolVersion { theirs: u8 },
    #[error("unrecognized message kind byte {0}")]
    UnknownMessageKind(u8),
    #[error("count {count} exceeds bound {max}")]
    CountExceedsBound { count: usize, max: usize },
    #[error("item of {declared} bytes exceeds the {max}-byte per-item bound")]
    ItemTooLarge { declared: usize, max: usize },
    #[error("malformed protocol 5 message: {0}")]
    Malformed(String),
}

impl From<ChangeError> for ProtocolError {
    fn from(e: ChangeError) -> Self {
        ProtocolError::Malformed(e.to_string())
    }
}

/// Checks a length prefix a transport has just read off the wire, *before*
/// it allocates a receive buffer of that size. Returns the checked length
/// as a `usize` ready to size that allocation.
pub fn accept_declared_length(declared: u32) -> Result<usize, ProtocolError> {
    let declared = declared as usize;
    if declared > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge { declared, max: MAX_MESSAGE_BYTES });
    }
    Ok(declared)
}

/// The label taxonomy this codec assigns its own message kinds, expressed
/// with no reference to any transport type. See the module doc's boundary
/// note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageClass {
    /// Small, latency-sensitive discovery/comparison traffic.
    Reconciliation,
    /// Verifiable history bulk.
    History,
    /// Raw content. Not produced by this module at all — protocol 5 carries
    /// no content-block message of its own; content bytes travel on the
    /// block transport as-is.
    Block,
    /// Small one-shot request/response, if ever needed beyond the two
    /// defined here (which are themselves classed `Reconciliation`).
    Service,
}

/// One protocol 5 message kind, tagged by a single byte on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageKind {
    SummaryRequest = 1,
    SummaryResponse = 2,
    FrontierDiffRequest = 3,
    FrontierDiffResponse = 4,
    DeltaBatch = 5,
    Refused = 6,
    RecoveryRequest = 7,
    RecoveryChunk = 8,
}

impl MessageKind {
    fn from_byte(b: u8) -> Result<Self, ProtocolError> {
        Ok(match b {
            1 => Self::SummaryRequest,
            2 => Self::SummaryResponse,
            3 => Self::FrontierDiffRequest,
            4 => Self::FrontierDiffResponse,
            5 => Self::DeltaBatch,
            6 => Self::Refused,
            7 => Self::RecoveryRequest,
            8 => Self::RecoveryChunk,
            other => return Err(ProtocolError::UnknownMessageKind(other)),
        })
    }

    /// This kind's [`MessageClass`] — the mapping table the mapping test
    /// below checks verbatim:
    /// `Summary/Frontier -> Reconciliation`, `Delta batch -> History`, `Content -> Block` (protocol 5 defines no
    /// content message, so `Block` has no `MessageKind` producing it —
    /// documented on [`MessageClass::Block`] itself).
    pub fn class(&self) -> MessageClass {
        match self {
            Self::SummaryRequest | Self::SummaryResponse => MessageClass::Reconciliation,
            Self::FrontierDiffRequest | Self::FrontierDiffResponse => MessageClass::Reconciliation,
            Self::DeltaBatch | Self::RecoveryChunk => MessageClass::History,
            Self::RecoveryRequest => MessageClass::Reconciliation,
            Self::Refused => MessageClass::Service,
        }
    }
}

/// A transport-supplied identity for a request message, so it can dedupe a
/// retried send against an earlier one. Opaque: this module neither
/// generates nor persists these, only carries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(pub [u8; 16]);

/// Why a peer refused a request — carried in a [`Message::Refused`],
/// itself the "no" half of a request/response pair (see the module doc's
/// timeout shape).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    Unauthorized,
    NotFound,
    Overloaded,
    Malformed,
    /// The request starts below the history the peer retains: the peer no longer
    /// holds the deltas the requester lacks, and says which trusted checkpoint
    /// its retained history begins at. Unlike [`Self::NotFound`], which is a
    /// single body that is not held, this is the peer's declared floor.
    HistoryTruncated {
        /// The trusted checkpoint the peer's retained history begins at.
        checkpoint_id: [u8; 32],
        /// The frontier root that checkpoint's rows build.
        frontier_root: [u8; 32],
    },
}

impl RefusalReason {
    fn encode_into(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Unauthorized => buf.push(1),
            Self::NotFound => buf.push(2),
            Self::Overloaded => buf.push(3),
            Self::Malformed => buf.push(4),
            Self::HistoryTruncated { checkpoint_id, frontier_root } => {
                buf.push(5);
                buf.extend_from_slice(checkpoint_id);
                buf.extend_from_slice(frontier_root);
            }
        }
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        Ok(match r.u8()? {
            1 => Self::Unauthorized,
            2 => Self::NotFound,
            3 => Self::Overloaded,
            4 => Self::Malformed,
            5 => {
                Self::HistoryTruncated { checkpoint_id: r.array32()?, frontier_root: r.array32()? }
            }
            other => {
                return Err(ProtocolError::Malformed(format!("unknown refusal reason {other}")))
            }
        })
    }
}

/// One `(author, seq)` pair, as carried by [`Message::FrontierDiffRequest`]
/// (the requester's own known frontier — "since") and
/// [`Message::FrontierDiffResponse`] (the peer's newer entries).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontierEntry {
    pub author: AuthorId,
    pub seq: AuthorSeq,
    /// Only present on a response entry: the tip's identity, so the
    /// requester can fetch exactly that delta from a following
    /// `DeltaBatch` request. Absent on a request entry (the requester is
    /// only naming what it already has, not asking anything about it).
    pub tip: Option<DeltaHash>,
}

fn encode_author_id(buf: &mut Vec<u8>, author: &AuthorId) {
    author.encode_into(buf);
}

fn decode_author_id(r: &mut Reader<'_>) -> Result<AuthorId, ChangeError> {
    let device = DeviceId(r.string()?);
    let incarnation = IncarnationId(r.take(16)?.try_into().expect("take(16) yields 16 bytes"));
    Ok(AuthorId { device, incarnation })
}

fn encode_frontier_entry(buf: &mut Vec<u8>, e: &FrontierEntry, with_tip: bool) {
    encode_author_id(buf, &e.author);
    put_u64(buf, e.seq.get());
    if with_tip {
        match e.tip {
            None => buf.push(0),
            Some(tip) => {
                buf.push(1);
                buf.extend_from_slice(&tip.0);
            }
        }
    }
}

fn decode_frontier_entry(
    r: &mut Reader<'_>,
    with_tip: bool,
) -> Result<FrontierEntry, ProtocolError> {
    let author = decode_author_id(r)?;
    let seq = AuthorSeq(r.u64()?);
    let tip = if with_tip {
        match r.u8()? {
            0 => None,
            1 => Some(DeltaHash(r.array32()?)),
            other => {
                return Err(ProtocolError::Malformed(format!("bad tip presence byte {other}")))
            }
        }
    } else {
        None
    };
    Ok(FrontierEntry { author, seq, tip })
}

/// One `NativeDelta`, bundled with everything a receiver needs to verify
/// its publish-time authorization offline — the wire shape of
/// `crate::proof_carrying_delta::ProofCarryingDelta`, owned rather than
/// borrowed so it can round-trip through this codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaBatchEntry {
    pub encoded_delta: Vec<u8>,
    pub checkpoint_hash: [u8; 32],
    pub checkpoint_encoded: Vec<u8>,
    pub checkpoint_signature: [u8; 64],
    pub author_signing_public_key: [u8; 32],
    pub proof_encoded: Vec<u8>,
    /// The canonical encodings of the content versions the delta's puts name,
    /// as the sender holds them. Untrusted but self-verifying: a version is
    /// stored only when its own hash is one the delta puts.
    pub versions: Vec<Vec<u8>>,
}

/// One protocol 5 message body. See [`MessageKind`] for the wire tag each
/// variant carries and [`MessageClass`] for its traffic shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Request: "what do you have for this group?" Reconciliation class.
    SummaryRequest { request_id: RequestId, group_id: FolderGroupId },
    /// Response: roots as **hints only** — per the plan, state only ever
    /// advances via a verified signed delta or a verified checkpoint,
    /// never by joining a peer's claimed root directly.
    SummaryResponse {
        request_id: RequestId,
        group_id: FolderGroupId,
        namespace_root: [u8; 32],
        author_state_root: [u8; 32],
    },
    /// Request: "here is everything I already have; tell me what's newer."
    FrontierDiffRequest {
        request_id: RequestId,
        group_id: FolderGroupId,
        since: Vec<FrontierEntry>,
    },
    /// Response: the peer's entries strictly newer than what `since` named.
    FrontierDiffResponse { request_id: RequestId, entries: Vec<FrontierEntry> },
    /// Push: a batch of proof-carrying deltas. No reply.
    DeltaBatch { group_id: FolderGroupId, entries: Vec<DeltaBatchEntry> },
    /// The refusal half of any request/response pair above.
    Refused { request_id: RequestId, reason: RefusalReason },
    /// Request: "my replica's log can no longer be brought up to date by
    /// deltas; seal your state for me." Answered with `RecoveryChunk`s (or a
    /// refusal). Reconciliation class.
    RecoveryRequest { request_id: RequestId, group_id: FolderGroupId },
    /// Push: chunk `index` of `count` of one recovery bundle, the canonical
    /// bytes of a sealed state (see `native_bootstrap_codec`). The receiver
    /// assembles all `count` chunks and verifies the whole bundle; no chunk
    /// is acted on alone.
    RecoveryChunk {
        request_id: RequestId,
        group_id: FolderGroupId,
        index: u32,
        count: u32,
        bytes: Vec<u8>,
    },
}

impl Message {
    pub fn kind(&self) -> MessageKind {
        match self {
            Self::SummaryRequest { .. } => MessageKind::SummaryRequest,
            Self::SummaryResponse { .. } => MessageKind::SummaryResponse,
            Self::FrontierDiffRequest { .. } => MessageKind::FrontierDiffRequest,
            Self::FrontierDiffResponse { .. } => MessageKind::FrontierDiffResponse,
            Self::DeltaBatch { .. } => MessageKind::DeltaBatch,
            Self::Refused { .. } => MessageKind::Refused,
            Self::RecoveryRequest { .. } => MessageKind::RecoveryRequest,
            Self::RecoveryChunk { .. } => MessageKind::RecoveryChunk,
        }
    }

    fn encode_body(&self, buf: &mut Vec<u8>) {
        match self {
            Self::SummaryRequest { request_id, group_id } => {
                buf.extend_from_slice(&request_id.0);
                put_str(buf, group_id.as_str());
            }
            Self::SummaryResponse { request_id, group_id, namespace_root, author_state_root } => {
                buf.extend_from_slice(&request_id.0);
                put_str(buf, group_id.as_str());
                buf.extend_from_slice(namespace_root);
                buf.extend_from_slice(author_state_root);
            }
            Self::FrontierDiffRequest { request_id, group_id, since } => {
                buf.extend_from_slice(&request_id.0);
                put_str(buf, group_id.as_str());
                put_u32(buf, since.len() as u32);
                for e in since {
                    encode_frontier_entry(buf, e, false);
                }
            }
            Self::FrontierDiffResponse { request_id, entries } => {
                buf.extend_from_slice(&request_id.0);
                put_u32(buf, entries.len() as u32);
                for e in entries {
                    encode_frontier_entry(buf, e, true);
                }
            }
            Self::DeltaBatch { group_id, entries } => {
                put_str(buf, group_id.as_str());
                put_u32(buf, entries.len() as u32);
                for e in entries {
                    put_u32(buf, e.encoded_delta.len() as u32);
                    buf.extend_from_slice(&e.encoded_delta);
                    buf.extend_from_slice(&e.checkpoint_hash);
                    put_u32(buf, e.checkpoint_encoded.len() as u32);
                    buf.extend_from_slice(&e.checkpoint_encoded);
                    buf.extend_from_slice(&e.checkpoint_signature);
                    buf.extend_from_slice(&e.author_signing_public_key);
                    put_u32(buf, e.proof_encoded.len() as u32);
                    buf.extend_from_slice(&e.proof_encoded);
                    put_u32(buf, e.versions.len() as u32);
                    for version in &e.versions {
                        put_u32(buf, version.len() as u32);
                        buf.extend_from_slice(version);
                    }
                }
            }
            Self::Refused { request_id, reason } => {
                buf.extend_from_slice(&request_id.0);
                reason.encode_into(buf);
            }
            Self::RecoveryRequest { request_id, group_id } => {
                buf.extend_from_slice(&request_id.0);
                put_str(buf, group_id.as_str());
            }
            Self::RecoveryChunk { request_id, group_id, index, count, bytes } => {
                buf.extend_from_slice(&request_id.0);
                put_str(buf, group_id.as_str());
                put_u32(buf, *index);
                put_u32(buf, *count);
                put_u32(buf, bytes.len() as u32);
                buf.extend_from_slice(bytes);
            }
        }
    }

    fn decode_body(kind: MessageKind, r: &mut Reader<'_>) -> Result<Self, ProtocolError> {
        Ok(match kind {
            MessageKind::SummaryRequest => {
                let request_id = RequestId(r.take(16)?.try_into().expect("16 bytes"));
                let group_id = FolderGroupId(r.string()?);
                Self::SummaryRequest { request_id, group_id }
            }
            MessageKind::SummaryResponse => {
                let request_id = RequestId(r.take(16)?.try_into().expect("16 bytes"));
                let group_id = FolderGroupId(r.string()?);
                let namespace_root = r.array32()?;
                let author_state_root = r.array32()?;
                Self::SummaryResponse { request_id, group_id, namespace_root, author_state_root }
            }
            MessageKind::FrontierDiffRequest => {
                let request_id = RequestId(r.take(16)?.try_into().expect("16 bytes"));
                let group_id = FolderGroupId(r.string()?);
                let count = r.bounded_count(24, MAX_FRONTIER_ENTRIES)?;
                let mut since = Vec::with_capacity(count);
                for _ in 0..count {
                    since.push(decode_frontier_entry(r, false)?);
                }
                Self::FrontierDiffRequest { request_id, group_id, since }
            }
            MessageKind::FrontierDiffResponse => {
                let request_id = RequestId(r.take(16)?.try_into().expect("16 bytes"));
                let count = r.bounded_count(25, MAX_FRONTIER_ENTRIES)?;
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    entries.push(decode_frontier_entry(r, true)?);
                }
                Self::FrontierDiffResponse { request_id, entries }
            }
            MessageKind::DeltaBatch => {
                let group_id = FolderGroupId(r.string()?);
                let count = r.bounded_count(4 + 32 + 4 + 64 + 32 + 4 + 4, MAX_BATCH_ITEMS)?;
                if count > MAX_BATCH_ITEMS {
                    return Err(ProtocolError::CountExceedsBound { count, max: MAX_BATCH_ITEMS });
                }
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    let encoded_delta = bounded_len_bytes(r, MAX_BATCH_ITEM_BYTES)?;
                    let checkpoint_hash = r.array32()?;
                    let checkpoint_encoded = bounded_len_bytes(r, MAX_BATCH_ITEM_BYTES)?;
                    let checkpoint_signature: [u8; 64] = r.take(64)?.try_into().expect("64 bytes");
                    let author_signing_public_key = r.array32()?;
                    let proof_encoded = bounded_len_bytes(r, MAX_BATCH_ITEM_BYTES)?;
                    let version_count = r.bounded_count(4, MAX_VERSIONS_PER_ENTRY)?;
                    let mut versions = Vec::with_capacity(version_count);
                    for _ in 0..version_count {
                        versions.push(bounded_len_bytes(r, MAX_BATCH_ITEM_BYTES)?);
                    }
                    entries.push(DeltaBatchEntry {
                        encoded_delta,
                        checkpoint_hash,
                        checkpoint_encoded,
                        checkpoint_signature,
                        author_signing_public_key,
                        proof_encoded,
                        versions,
                    });
                }
                Self::DeltaBatch { group_id, entries }
            }
            MessageKind::Refused => {
                let request_id = RequestId(r.take(16)?.try_into().expect("16 bytes"));
                let reason = RefusalReason::decode(r)?;
                Self::Refused { request_id, reason }
            }
            MessageKind::RecoveryRequest => {
                let request_id = RequestId(r.take(16)?.try_into().expect("16 bytes"));
                let group_id = FolderGroupId(r.string()?);
                Self::RecoveryRequest { request_id, group_id }
            }
            MessageKind::RecoveryChunk => {
                let request_id = RequestId(r.take(16)?.try_into().expect("16 bytes"));
                let group_id = FolderGroupId(r.string()?);
                let index = r.u32()?;
                let count = r.u32()?;
                if count == 0 || count > MAX_RECOVERY_CHUNKS || index >= count {
                    return Err(ProtocolError::Malformed(format!(
                        "recovery chunk {index} of {count} is out of range"
                    )));
                }
                let bytes = bounded_len_bytes(r, MAX_RECOVERY_CHUNK_BYTES)?;
                Self::RecoveryChunk { request_id, group_id, index, count, bytes }
            }
        })
    }
}

/// Reads a `u32` length prefix, rejects it against `max` *before*
/// allocating, then reads exactly that many bytes.
fn bounded_len_bytes(r: &mut Reader<'_>, max: usize) -> Result<Vec<u8>, ProtocolError> {
    let declared = r.u32()? as usize;
    if declared > max {
        return Err(ProtocolError::ItemTooLarge { declared, max });
    }
    Ok(r.take(declared)?.to_vec())
}

/// Encodes `message` as a full envelope: domain tag, protocol version,
/// message kind, then the body. Returns
/// [`ProtocolError::MessageTooLarge`] rather than ever handing the caller
/// oversized bytes to put on the wire.
pub fn encode_message(message: &Message) -> Result<Vec<u8>, ProtocolError> {
    let mut buf = Vec::new();
    buf.extend_from_slice(PROTOCOL5_ENVELOPE_TAG);
    buf.push(PROTOCOL5_VERSION);
    buf.push(message.kind() as u8);
    message.encode_body(&mut buf);
    if buf.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge { declared: buf.len(), max: MAX_MESSAGE_BYTES });
    }
    Ok(buf)
}

/// Decodes one full envelope. Rejects a bad domain tag, an unsupported
/// protocol version, an unknown message kind, any truncated/malformed
/// body, and any trailing bytes after the body — all as a clean `Err`,
/// never a panic (see the adversarial tests below).
pub fn decode_message(bytes: &[u8]) -> Result<Message, ProtocolError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(ProtocolError::MessageTooLarge {
            declared: bytes.len(),
            max: MAX_MESSAGE_BYTES,
        });
    }
    let mut r = Reader::new(bytes);
    let tag = r.take(NATIVE_TAG_PREFIX_LEN + 1).map_err(|_| ProtocolError::BadEnvelopeTag)?;
    if tag[..NATIVE_TAG_PREFIX_LEN] != PROTOCOL5_ENVELOPE_TAG[..NATIVE_TAG_PREFIX_LEN] {
        return Err(ProtocolError::BadEnvelopeTag);
    }
    if tag[NATIVE_TAG_PREFIX_LEN] != PROTOCOL5_ENVELOPE_TAG[NATIVE_TAG_PREFIX_LEN] {
        return Err(ProtocolError::BadEnvelopeTag);
    }
    let version = r.u8().map_err(|_| ProtocolError::BadEnvelopeTag)?;
    if version != PROTOCOL5_VERSION {
        return Err(ProtocolError::UnsupportedProtocolVersion { theirs: version });
    }
    let kind = MessageKind::from_byte(r.u8().map_err(|_| ProtocolError::BadEnvelopeTag)?)?;
    let message = Message::decode_body(kind, &mut r)?;
    r.expect_end().map_err(|e| ProtocolError::Malformed(e.to_string()))?;
    Ok(message)
}

/// [`DeltaBatchEntry::encoded_delta`]'s real domain identity — decodes it
/// and returns the [`NativeDelta`]'s own [`DeltaHash`], exactly the
/// identity `native_delta_log` already keys admission/duplicate-detection
/// on at the storage layer. Structural-decode failures here are reported
/// as-is; this function does not verify the delta's signature or
/// authorization (that is the storage layer's job).
pub fn delta_batch_entry_identity(entry: &DeltaBatchEntry) -> Result<DeltaHash, ProtocolError> {
    let delta = NativeDelta::from_wire_bytes(&entry.encoded_delta)?;
    Ok(delta.delta_hash())
}

/// Re-encodes a [`MerkleProof`] for embedding in a [`DeltaBatchEntry`].
pub fn encode_proof(proof: &MerkleProof) -> Vec<u8> {
    encode_merkle_proof(proof)
}

/// The inverse of [`encode_proof`].
pub fn decode_proof(bytes: &[u8]) -> Result<MerkleProof, ProtocolError> {
    decode_merkle_proof(bytes).map_err(|e| ProtocolError::Malformed(format!("{e:?}")))
}

#[cfg(test)]
mod tests;
