//! The one place in `peer_wire/` (and, once every message family has
//! migrated, in this whole crate) allowed to depend on
//! `yadorilink_ipc_proto`/`prost`. Every other module under `peer_wire/`
//! only knows the domain `*Frame` types.

use prost::Message as _;
use yadorilink_ipc_proto::sync as proto;

use super::error::WireError;
use super::frame::{BlockRequestHeaderFrame, BlockResponseHeaderFrame, BlockResponseOutcomeFrame};

impl TryFrom<proto::BlockRequestHeader> for BlockRequestHeaderFrame {
    type Error = WireError;

    fn try_from(value: proto::BlockRequestHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            folder_group_id: value.folder_group_id,
            file_path: value.file_path,
            block_hash: value.block_hash,
        })
    }
}

impl TryFrom<proto::BlockResponseHeader> for BlockResponseHeaderFrame {
    type Error = WireError;

    fn try_from(value: proto::BlockResponseHeader) -> Result<Self, Self::Error> {
        use proto::block_response_header::Outcome;
        let Some(outcome) = value.outcome else {
            return Err(WireError::Decode(
                "BlockResponseHeader with no outcome is malformed for this generation".to_string(),
            ));
        };
        let outcome = match outcome {
            Outcome::Found(found) => BlockResponseOutcomeFrame::Found {
                size: found.size,
                hash: found.hash,
                compression: found.compression,
            },
            Outcome::DontHave(_) => BlockResponseOutcomeFrame::DontHave,
            Outcome::Busy(busy) => BlockResponseOutcomeFrame::Busy {
                retry_after_ms: busy.retry_after_ms,
                queue_depth: busy.queue_depth,
            },
            Outcome::Rejected(rejected) => {
                BlockResponseOutcomeFrame::Rejected { reason: rejected.reason }
            }
        };
        Ok(Self { outcome })
    }
}

impl From<BlockResponseHeaderFrame> for proto::BlockResponseHeader {
    fn from(value: BlockResponseHeaderFrame) -> Self {
        use proto::block_response_header::Outcome;
        let outcome = match value.outcome {
            BlockResponseOutcomeFrame::Found { size, hash, compression } => {
                Outcome::Found(proto::BlockFound { size, hash, compression })
            }
            BlockResponseOutcomeFrame::DontHave => Outcome::DontHave(true),
            BlockResponseOutcomeFrame::Busy { retry_after_ms, queue_depth } => {
                Outcome::Busy(proto::BlockBusy { retry_after_ms, queue_depth })
            }
            BlockResponseOutcomeFrame::Rejected { reason } => {
                Outcome::Rejected(proto::BlockRejected { reason })
            }
        };
        Self { outcome: Some(outcome) }
    }
}

/// Converts between raw block-stream header bytes and domain frames, backed
/// by this crate's protobuf schema.
pub struct ProtobufPeerWireCodec;

impl ProtobufPeerWireCodec {
    /// Block-stream headers are the only messages this codec knows: each is
    /// one length-prefixed message on a block stream, with no envelope
    /// around it.
    pub fn encode_block_request_header(
        &self,
        frame: BlockRequestHeaderFrame,
    ) -> Result<Vec<u8>, WireError> {
        Ok(proto::BlockRequestHeader {
            folder_group_id: frame.folder_group_id,
            file_path: frame.file_path,
            block_hash: frame.block_hash,
        }
        .encode_to_vec())
    }

    pub fn decode_block_request_header(
        &self,
        bytes: &[u8],
    ) -> Result<BlockRequestHeaderFrame, WireError> {
        proto::BlockRequestHeader::decode(bytes)
            .map_err(|e| WireError::Decode(e.to_string()))?
            .try_into()
    }

    pub fn encode_block_response_header(
        &self,
        frame: BlockResponseHeaderFrame,
    ) -> Result<Vec<u8>, WireError> {
        Ok(proto::BlockResponseHeader::from(frame).encode_to_vec())
    }

    pub fn decode_block_response_header(
        &self,
        bytes: &[u8],
    ) -> Result<BlockResponseHeaderFrame, WireError> {
        proto::BlockResponseHeader::decode(bytes)
            .map_err(|e| WireError::Decode(e.to_string()))?
            .try_into()
    }
}

/// Round trips of every block-stream header shape.
#[cfg(test)]
mod outbound_parity_tests;

#[cfg(test)]
mod tests;
