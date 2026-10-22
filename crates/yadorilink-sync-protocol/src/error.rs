//! Framing failures.

use thiserror::Error;

/// A hello the peer sent that cannot be decoded.
///
/// Every variant describes a claim the peer made that the bytes do not
/// support; the stream is abandoned.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("frame claims {needed} more bytes but only {available} are present")]
    Truncated { needed: usize, available: usize },

    #[error("{0} unread bytes after the frame")]
    TrailingBytes(usize),

    #[error("group identifier declares {declared} bytes, limit is {limit}")]
    GroupTooLong { declared: usize, limit: usize },

    #[error("peer speaks protocol version {theirs}, this node speaks {ours}")]
    UnsupportedVersion { theirs: u32, ours: u32 },

    #[error("group identifier is not valid UTF-8")]
    MalformedGroupId,
}

/// Anything that ends a lane's opening.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("transport failed: {0}")]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Wire(#[from] WireError),

    /// A frame declared more bytes than are ever accepted for its kind.
    #[error("frame declares {declared} bytes, limit is {limit}")]
    FrameTooLarge { declared: usize, limit: usize },

    /// The peer opened a lane and closed it without saying what it was for.
    #[error("peer opened a lane without a hello")]
    NoHello,
}
