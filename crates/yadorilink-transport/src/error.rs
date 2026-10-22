#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("message too large: {0} bytes (max {1} fragments per message)")]
    MessageTooLarge(usize, usize),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("peer channel closed")]
    ChannelClosed,

    #[error("no route to peer: {0}")]
    NoRoute(String),
}

impl TransportError {
    /// A short, stable category label for connection-attempt diagnostics —
    /// mirrors
    /// `CliError::report_category`'s "coarse, stable category, never the
    /// raw error text" convention, so a bounded connection-trace history
    /// can record *why* an attempt failed without ever holding onto (or
    /// having to redact) the raw `Display` text, which can embed a peer's
    /// address or protocol detail.
    pub fn category(&self) -> &'static str {
        match self {
            TransportError::InvalidKey(_) => "invalid_key",
            TransportError::MessageTooLarge(..) => "message_too_large",
            TransportError::Io(_) => "io",
            TransportError::ChannelClosed => "channel_closed",
            TransportError::NoRoute(_) => "no_route",
        }
    }
}
