//! The identities a lane hello and its handlers exchange.

use std::fmt;

/// The folder group being reconciled.
///
/// A thin newtype rather than the domain's own group id: this crate is
/// deliberately unaware of the domain's types, and the adapter converts.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct GroupId(pub String);

impl GroupId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The transport identity of the peer on the other end.
///
/// Carrier identity only. It selects which set is disclosable and nothing
/// else; it never contributes to whether a Change may be admitted.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerKey(pub [u8; 32]);

impl PeerKey {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerKey(")?;
        for byte in &self.0[..6] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("..)")
    }
}
