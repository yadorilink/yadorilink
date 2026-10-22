//! This crate's single error type.

#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("connection pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("database error: {0}")]
    Database(#[from] yadorilink_sqlite_runtime::DatabaseError),

    #[error("local storage error: {0}")]
    Storage(#[from] yadorilink_local_storage::StorageError),

    #[error("transport error: {0}")]
    Transport(#[from] yadorilink_transport::TransportError),

    #[error("network error: {0}")]
    Network(#[from] yadorilink_sync_substrate::SubstrateError),

    #[error("could not reach device {0} in time")]
    DialTimedOut(String),

    #[error("wire decode error: {0}")]
    Decode(#[from] prost::DecodeError),

    #[error("unknown transfer id: {0}")]
    UnknownTransfer(String),

    #[error("transfer {0} was offered to a different device than the one this connection authenticated as")]
    WrongPeer(String),

    #[error("no known address for device {0}")]
    NoKnownAddress(String),

    #[error("no known signing key for device {0}")]
    NoKnownDeviceKey(String),

    #[error("transfer {0} was canceled; retry it to resume")]
    TransferCanceled(String),

    #[error("transfer {0} is already being received")]
    AlreadyReceiving(String),

    #[error("transfer {transfer_id} cannot be retried while it is {status}")]
    NotRetryable { transfer_id: String, status: &'static str },

    #[error("destination {0} cannot be used: {1}")]
    BadDestination(String, String),

    #[error("peer rejected the offer: {0}")]
    OfferRejected(String),

    #[error("peer rejected the pull: {0}")]
    PullRejected(String),

    #[error("manifest is empty: {0} contains no readable files")]
    EmptyManifest(String),

    #[error("chunk {chunk_index} of file {file_index} failed integrity verification")]
    ChunkHashMismatch { file_index: u32, chunk_index: u32 },

    #[error("the other device stopped reading what was being sent to it")]
    ReceiverStalled,

    #[error("peer sent malformed data: {0}")]
    Protocol(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("transfer {0} was sent by this device, not received")]
    NotReceived(String),

    #[error("transfer {0} was received by this device, not sent")]
    NotSent(String),

    #[error(
        "the file or folder offered in transfer {0} changed or is gone since it was offered; \
         send it again to offer what is there now"
    )]
    SourceChanged(String),

    #[error(
        "device {0} is not the one transfer {1} was offered to any more; send it again to the \
         device now known"
    )]
    TargetChanged(String, String),

    #[error(
        "this device cannot send to {0} now without a new authorization; send it again once the \
         device is available"
    )]
    NeedsNewAuthorization(String),
}

/// Closed reasons a transfer stopped, as stored and listed. Shells word them.
pub mod failure {
    /// The other device could not be reached.
    pub const UNREACHABLE: &str = "unreachable";
    /// The receiving device declined the offer.
    pub const DECLINED: &str = "declined";
    /// The sending device canceled the transfer.
    pub const SENDER_CANCELED: &str = "sender_canceled";
    /// The sending device does not hold the offer as accepted.
    pub const NOT_ACCEPTED: &str = "not_accepted";
    /// The other device refused for another reason.
    pub const REJECTED: &str = "rejected";
    /// What arrived did not match what was offered.
    pub const VERIFICATION_FAILED: &str = "verification_failed";
    /// This device could not store what arrived.
    pub const LOCAL_STORAGE: &str = "local_storage";
    /// The other device stopped reading what this device was sending it, so serving it ended.
    pub const STALLED: &str = "stalled";
    /// The transfer stopped without a clearer reason.
    pub const INTERRUPTED: &str = "interrupted";
}

/// What a sender tells a receiver that tries to pull a transfer the sender canceled.
pub(crate) const PULL_REASON_CANCELED: &str = "the sender canceled this transfer";
/// What a sender tells a receiver that pulls an offer the sender does not hold as accepted.
pub(crate) const PULL_REASON_NOT_ACCEPTED: &str = "offer was not accepted; nothing to pull";

impl SendError {
    /// The closed reason code for a transfer that stopped with this error.
    pub(crate) fn failure_code(&self) -> &'static str {
        match self {
            SendError::DialTimedOut(_)
            | SendError::NoKnownAddress(_)
            | SendError::NoKnownDeviceKey(_)
            | SendError::Network(_)
            | SendError::Transport(_) => failure::UNREACHABLE,
            SendError::ReceiverStalled => failure::STALLED,
            SendError::OfferRejected(_) => failure::DECLINED,
            SendError::PullRejected(reason) if reason == PULL_REASON_CANCELED => {
                failure::SENDER_CANCELED
            }
            SendError::PullRejected(reason) if reason == PULL_REASON_NOT_ACCEPTED => {
                failure::NOT_ACCEPTED
            }
            SendError::PullRejected(_) => failure::REJECTED,
            SendError::ChunkHashMismatch { .. } | SendError::Protocol(_) | SendError::Decode(_) => {
                failure::VERIFICATION_FAILED
            }
            SendError::Io(_) | SendError::Storage(_) | SendError::BadDestination(..) => {
                failure::LOCAL_STORAGE
            }
            _ => failure::INTERRUPTED,
        }
    }
}

impl yadorilink_sqlite_runtime::SqlOperationError for SendError {
    fn is_locked(&self) -> bool {
        matches!(
            self,
            SendError::Sqlite(rusqlite::Error::SqliteFailure(e, _))
                if matches!(
                    e.code,
                    rusqlite::ErrorCode::DatabaseLocked | rusqlite::ErrorCode::DatabaseBusy
                )
        )
    }
}

pub type Result<T> = std::result::Result<T, SendError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Each kind of stop has its own closed reason; a broken connection is never blamed on the
    /// disk, and a disk fault is never blamed on the connection.
    #[test]
    fn failures_are_classified_by_where_they_came_from() {
        let io = || std::io::Error::from(std::io::ErrorKind::UnexpectedEof);
        assert_eq!(
            SendError::Transport(yadorilink_transport::TransportError::Io(io())).failure_code(),
            failure::UNREACHABLE
        );
        assert_eq!(SendError::DialTimedOut("d".into()).failure_code(), failure::UNREACHABLE);
        assert_eq!(SendError::Io(io()).failure_code(), failure::LOCAL_STORAGE);
        assert_eq!(
            SendError::PullRejected(PULL_REASON_CANCELED.into()).failure_code(),
            failure::SENDER_CANCELED
        );
        assert_eq!(
            SendError::PullRejected(PULL_REASON_NOT_ACCEPTED.into()).failure_code(),
            failure::NOT_ACCEPTED
        );
        assert_eq!(SendError::PullRejected("x".into()).failure_code(), failure::REJECTED);
        assert_eq!(SendError::OfferRejected("x".into()).failure_code(), failure::DECLINED);
        assert_eq!(
            SendError::ChunkHashMismatch { file_index: 0, chunk_index: 0 }.failure_code(),
            failure::VERIFICATION_FAILED
        );
        assert_eq!(SendError::UnknownTransfer("t".into()).failure_code(), failure::INTERRUPTED);
        assert_eq!(SendError::ReceiverStalled.failure_code(), failure::STALLED);
    }
}
