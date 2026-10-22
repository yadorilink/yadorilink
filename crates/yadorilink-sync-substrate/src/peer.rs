//! Transport-level peer identity.
//!
//! This is deliberately its own type and not a re-export of a p2panda or iroh
//! key type. It identifies a *carrier*: who a byte stream came from. It says
//! nothing about who is authorized to write, and it must never be consulted
//! when deciding whether to admit a Change — that decision belongs entirely to
//! the proof carried by the Change itself.

use std::fmt;

/// The transport identity of a remote node.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId([u8; 32]);

impl PeerId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({self})")
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..8] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("..")
    }
}

impl PeerId {
    /// Parse the 64-character hex form used by the coordination plane.
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != 64 {
            return None;
        }
        let mut bytes = [0u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
        }
        Some(Self(bytes))
    }

    /// The 64-character hex form.
    pub fn to_hex(self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

#[cfg(test)]
mod tests;
