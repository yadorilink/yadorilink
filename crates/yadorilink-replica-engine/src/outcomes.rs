//! Semantic outcome types for `PeerReplicaEngine`'s own methods.

/// `PeerReplicaEngine::holds_version_durably`'s result. Every non-`present`
/// case except an unreadable current-version record is a silent `false` (by
/// design, matching every other condition this check fails closed on); only
/// that one case previously logged, so it is the only one carrying a
/// warning here.
pub struct CustodyEvaluation {
    pub present: bool,
    pub warning: Option<CustodyWarning>,
}

pub struct CustodyWarning {
    pub message: String,
}
