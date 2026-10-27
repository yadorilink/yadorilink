/// What a person can do next about a refusal, as an action rather than a command line. The
/// daemon's refusal texts never name a command or a flag; the front end words the step for its
/// own surface (the wire form is `NextStep`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextStep {
    /// Look at the folder's sync status.
    CheckLinkStatus,
    /// Look at the list of linked folders to verify what is linked.
    CheckLinkList,
    /// Keep a provider-folder item on this device to download it now.
    KeepItemOnDevice,
    /// See a provider-folder item's local state and the folder's download progress.
    ShowProviderLocalState,
    /// Create a provider folder, the only kind of folder that can be on-demand.
    CreateProviderFolder,
    /// Turn on submission for the report's type in the reporting consent settings.
    EnableReportSubmission,
    /// Try the storage-mode change again.
    RetryStorageModeChange,
}

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("sync error: {0}")]
    Sync(#[from] crate::sync_error::SyncError),

    #[error("root authority error: {0}")]
    RootAuthority(#[from] yadorilink_root_authority::RootAuthorityError),

    /// `peer_orchestrator`'s transport-level failures (e.g. a `PeerChannel`
    /// that could not be constructed for a peer).
    #[error("transport error: {0}")]
    Transport(#[from] yadorilink_transport::TransportError),

    #[error("device identity load error: {0}")]
    KeyLoad(#[from] yadorilink_transport::KeyLoadError),

    /// Peer signing-key-pin persistence (`signing_keys.json`) failed to
    /// parse/serialize.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Catch-all for local validation failures that aren't naturally an
    /// `Err` from another crate (invalid coordination address scheme,
    /// malformed access token header,...).
    #[error("{0}")]
    Config(String),

    /// A refusal whose own text is host-neutral, plus what the person can do next as a typed
    /// step the front end words for itself.
    #[error("{message}")]
    Advised { message: String, step: NextStep },

    /// A link was refused because of the folder's place on this device
    /// (nested in or around another link, or overlapping the recovery
    /// area); no confirmation overrides it.
    #[error("{0}")]
    PathNotAllowed(String),

    /// A link start was refused because a safe stop is under way. Nothing was changed; the
    /// same request succeeds once the stop has failed or been abandoned.
    #[error("a safe stop is in progress; try again in a few seconds")]
    SafeStopInProgress,

    /// The netmap subscription's WebSocket connection/protocol errors.
    /// Boxed because `tungstenite::Error` is large, so an unboxed variant
    /// would make every `Result<_, DaemonError>` return type oversized
    /// (`clippy::result_large_err`). The manual `From` impl below keeps `?`
    /// working directly on a `Result<_, tungstenite::Error>`.
    #[error("websocket error: {0}")]
    WebSocket(Box<tokio_tungstenite::tungstenite::Error>),
}

impl DaemonError {
    /// The refusal a client can branch on, when this failure is one.
    pub(crate) fn link_refusal(&self) -> Option<crate::application::model::LinkRefusal> {
        use crate::application::model::LinkRefusal;
        match self {
            DaemonError::PathNotAllowed(_) => Some(LinkRefusal::PathNotAllowed),
            DaemonError::Io(e) if e.kind() == std::io::ErrorKind::StorageFull => {
                Some(LinkRefusal::DiskFull)
            }
            DaemonError::RootAuthority(yadorilink_root_authority::RootAuthorityError::Io(e))
                if e.kind() == std::io::ErrorKind::PermissionDenied =>
            {
                Some(LinkRefusal::AccessDenied)
            }
            DaemonError::Sync(e) => e.link_refusal(),
            _ => None,
        }
    }
}

impl From<tokio_tungstenite::tungstenite::Error> for DaemonError {
    fn from(err: tokio_tungstenite::tungstenite::Error) -> Self {
        DaemonError::WebSocket(Box::new(err))
    }
}
