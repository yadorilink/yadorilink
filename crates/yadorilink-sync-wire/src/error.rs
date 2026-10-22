/// Errors from encoding/decoding a peer wire frame. Deliberately not
/// `crate::error::SyncError` -- this is a narrower, wire-specific error
/// type so `yadorilink-sync-wire` doesn't need to depend on this crate's much broader error enum.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("wire message could not be decoded: {0}")]
    Decode(String),

    #[error("wire message could not be encoded: {0}")]
    Encode(String),

    #[error("invalid wire field {field}: {detail}")]
    InvalidField { field: &'static str, detail: String },

    #[error("unsupported wire message")]
    Unsupported,
}
