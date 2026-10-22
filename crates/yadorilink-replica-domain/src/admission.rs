//! Pure value types a device's admission and authoring share: why a delta was
//! refused for a path it names, and the signing identity a device authors its
//! own deltas with.

/// Why a delta was refused for a path it names.
///
/// Decided from the delta's own signed bytes alone, before anything about
/// its chain or its author is consulted, and final for the same reason:
/// re-delivering the identical delta can never produce another verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathRefusal {
    /// The path collides with the reserved artefact namespace this project
    /// writes its own staging and lock files under.
    ReservedNamespaceCollision { path: String },
    /// The path cannot be stored faithfully and unambiguously on every
    /// platform this group may sync to.
    NonPortablePath { path: String },
}

impl std::fmt::Display for PathRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReservedNamespaceCollision { path } => {
                write!(f, "reserved namespace collision: {path:?}")
            }
            Self::NonPortablePath { path } => write!(f, "non-portable path: {path:?}"),
        }
    }
}

/// The material a device needs to sign the changes it originates: its
/// device id, its current author incarnation, and its Ed25519 signing key.
/// Held separately from the store so the store never touches secret key
/// material.
///
/// The incarnation is part of the author a change is signed as
/// ([`author`](Self::author)), so a handle always carries one. No
/// signing-key fingerprint is exposed here: the device ↔ signing-key
/// binding belongs to the policy layer.
pub struct LocalAuthorKey {
    device_id: crate::ids::DeviceId,
    incarnation: crate::author::IncarnationId,
    signing_key: ed25519_dalek::SigningKey,
}

impl LocalAuthorKey {
    /// A handle authoring as `author`.
    pub fn new(author: crate::author::AuthorId, signing_key: ed25519_dalek::SigningKey) -> Self {
        Self { device_id: author.device, incarnation: author.incarnation, signing_key }
    }

    /// A handle for a test that authors as `device_id` without an opened
    /// author identity: a fixed, non-reserved incarnation.
    #[cfg(any(test, feature = "test-support"))]
    pub fn for_tests(device_id: impl Into<String>, signing_key: ed25519_dalek::SigningKey) -> Self {
        Self {
            device_id: crate::ids::DeviceId(device_id.into()),
            incarnation: crate::author::IncarnationId([0x7e; 16]),
            signing_key,
        }
    }

    pub fn device_id(&self) -> &str {
        self.device_id.as_str()
    }

    pub fn device(&self) -> &crate::ids::DeviceId {
        &self.device_id
    }

    pub fn incarnation(&self) -> crate::author::IncarnationId {
        self.incarnation
    }

    /// The author this handle signs as.
    pub fn author(&self) -> crate::author::AuthorId {
        crate::author::AuthorId { device: self.device_id.clone(), incarnation: self.incarnation }
    }

    pub fn signing_key(&self) -> &ed25519_dalek::SigningKey {
        &self.signing_key
    }
}
