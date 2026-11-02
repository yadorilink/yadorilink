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

    /// Every dial attempt within the deadline failed; `detail` says how, in a sentence a person
    /// can act on (which addresses were tried, and whether this device's own network refused).
    #[error("could not reach device {device_id}: {detail}")]
    DialFailed { device_id: String, reason: DialReason, detail: String },

    /// The other device stopped sending, and could not be reached again within the time a receive
    /// keeps trying. The offer is of no further use from this side: ask for it to be sent again.
    #[error("device {0} stopped sending and could not be reached again; ask for a new link or send it again")]
    SenderGone(String),

    #[error("device {0} did not answer the offer in time")]
    OfferUnanswered(String),

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
         device is available. If it was sent through a send link (a device on another account), \
         create a new link: a link's authorization is used once and cannot be retried"
    )]
    NeedsNewAuthorization(String),
}

/// Why a dial gave up, as far as this device can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialReason {
    /// This device's operating system refused to send to the local network (macOS Local Network
    /// privacy, a firewall): only a path that does not need the local network can work.
    LocalNetworkBlocked,
    /// There was nothing to dial: no address is known for the device.
    NoAddress,
    /// The device answered and turned the connection down.
    Refused,
    /// Nothing answered: the handshake never completed on any path.
    NoResponse,
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
    /// This device had no room to store what arrived.
    pub const NO_SPACE: &str = "no_space";
    /// This device's operating system refused to send to the local network, so a device on the
    /// same network could not be reached (see [`super::DialReason::LocalNetworkBlocked`]).
    pub const LOCAL_NETWORK_BLOCKED: &str = "local_network_blocked";
    /// The sending device stopped sending and could not be reached again; only a new offer helps.
    pub const SENDER_GONE: &str = "sender_gone";
    /// The receiving device canceled the transfer.
    pub const RECEIVER_CANCELED: &str = "receiver_canceled";
    /// The receiving device reported that its receive failed, or has fetched nothing for a long
    /// time. The transfer is still offered: the receiver can fetch it again.
    pub const RECEIVER_STOPPED: &str = "receiver_stopped";
    /// The transfer stopped without a clearer reason.
    pub const INTERRUPTED: &str = "interrupted";
}

/// What a sender tells a receiver that tries to pull a transfer the sender canceled.
pub(crate) const PULL_REASON_CANCELED: &str = "the sender canceled this transfer";
/// What a sender tells a receiver that pulls an offer the sender does not hold as accepted.
pub(crate) const PULL_REASON_NOT_ACCEPTED: &str = "offer was not accepted; nothing to pull";

/// Whether an I/O error is the disk (or quota) being full.
fn io_is_no_space(error: &std::io::Error) -> bool {
    // ENOSPC, ERROR_DISK_FULL, ERROR_HANDLE_DISK_FULL
    error.kind() == std::io::ErrorKind::StorageFull
        || matches!(error.raw_os_error(), Some(28 | 112 | 39))
}

impl SendError {
    /// Whether this device ran out of room to store what it was receiving.
    #[must_use]
    pub fn is_no_space(&self) -> bool {
        use yadorilink_local_storage::StorageError;
        match self {
            SendError::Io(error) | SendError::Storage(StorageError::Io(error)) => {
                io_is_no_space(error)
            }
            SendError::Storage(StorageError::DiskPressure { .. }) => true,
            _ => false,
        }
    }

    /// Whether the other device could not be reached.
    #[must_use]
    pub fn is_unreachable(&self) -> bool {
        matches!(self.failure_code(), failure::UNREACHABLE | failure::LOCAL_NETWORK_BLOCKED)
    }

    /// Whether this device's own operating system refused to reach the local network.
    #[must_use]
    pub fn is_local_network_blocked(&self) -> bool {
        self.failure_code() == failure::LOCAL_NETWORK_BLOCKED
    }

    /// The closed reason code for a transfer that stopped with this error.
    pub fn failure_code(&self) -> &'static str {
        match self {
            SendError::DialFailed { reason: DialReason::LocalNetworkBlocked, .. } => {
                failure::LOCAL_NETWORK_BLOCKED
            }
            SendError::SenderGone(_) => failure::SENDER_GONE,
            SendError::DialFailed { .. }
            | SendError::OfferUnanswered(_)
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
            _ if self.is_no_space() => failure::NO_SPACE,
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

    fn dial_failed(reason: DialReason) -> SendError {
        SendError::DialFailed { device_id: "d".into(), reason, detail: "x".into() }
    }

    /// Each kind of stop has its own closed reason; a broken connection is never blamed on the
    /// disk, and a disk fault is never blamed on the connection.
    #[test]
    fn failures_are_classified_by_where_they_came_from() {
        let io = || std::io::Error::from(std::io::ErrorKind::UnexpectedEof);
        assert_eq!(
            SendError::Transport(yadorilink_transport::TransportError::Io(io())).failure_code(),
            failure::UNREACHABLE
        );
        assert_eq!(dial_failed(DialReason::NoResponse).failure_code(), failure::UNREACHABLE);
        assert_eq!(
            dial_failed(DialReason::LocalNetworkBlocked).failure_code(),
            failure::LOCAL_NETWORK_BLOCKED
        );
        assert!(dial_failed(DialReason::LocalNetworkBlocked).is_unreachable());
        assert_eq!(SendError::SenderGone("d".into()).failure_code(), failure::SENDER_GONE);
        assert_eq!(SendError::Io(io()).failure_code(), failure::LOCAL_STORAGE);
        let full = || std::io::Error::from(std::io::ErrorKind::StorageFull);
        assert_eq!(SendError::Io(full()).failure_code(), failure::NO_SPACE);
        assert!(SendError::Io(full()).is_no_space());
        assert!(SendError::Io(std::io::Error::from_raw_os_error(28)).is_no_space());
        assert_eq!(
            SendError::Storage(yadorilink_local_storage::StorageError::Io(full())).failure_code(),
            failure::NO_SPACE
        );
        assert!(dial_failed(DialReason::Refused).is_unreachable());
        assert!(!SendError::Io(io()).is_unreachable());
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
