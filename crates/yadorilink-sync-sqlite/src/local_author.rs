//! The identity a replica signs its local writes with.

use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::author::AuthorId;

use crate::dag_store::LocalAuthorKey;
use crate::native_rebootstrap::CaptureAuthority;

/// The identity a replica signs its local changes with.
pub struct LocalAuthor<'a> {
    pub author: AuthorId,
    pub signing_key: &'a SigningKey,
    /// The one capability that lets this author's deltas through a rebootstrap's freeze while the
    /// rebootstrap captures the disk (see [`CaptureAuthority`]). `None` for every other writer.
    pub capture: Option<&'a CaptureAuthority>,
}

impl<'a> LocalAuthor<'a> {
    /// The author and key of the local author handle `key`.
    pub fn of_key(key: &'a LocalAuthorKey) -> Self {
        Self { author: key.author(), signing_key: key.signing_key(), capture: None }
    }
}
