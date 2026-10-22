//! Errors surfaced by the replica-engine's own ports.

/// The port error of `DurabilityEvidencePort`.
#[derive(Debug, thiserror::Error)]
pub enum ReplicaEngineError {
    #[error("replica storage operation failed: {0}")]
    Storage(String),
    #[error("corrupt replica state: {0}")]
    CorruptState(String),
    #[error("invalid replica input: {0}")]
    InvalidInput(String),
}

impl From<yadorilink_replica_domain::codec::ChangeError> for ReplicaEngineError {
    fn from(error: yadorilink_replica_domain::codec::ChangeError) -> Self {
        ReplicaEngineError::CorruptState(error.to_string())
    }
}
