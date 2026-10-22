//! A writer this group's signed policy authorizes, with the signing key its
//! Grant bound, as the policy and peer-authority code name it.

/// One device this group's signed policy currently (or, for
/// `GroupPolicyState::writers_at`-style historical queries, as of a given
/// sequence) grants write access to, together with the signing-key
/// fingerprint its Grant bound.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthorizedWriter {
    pub device_id: String,
    pub signing_key_fingerprint: [u8; 32],
}
