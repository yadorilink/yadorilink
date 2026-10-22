//! The OS-native backend.
//!
//! On macOS this is the Data Protection Keychain, in the one keychain access
//! group that the host app, the daemon helper and the CLI share
//! (`yadorilink-os-keychain`): access is decided by the `keychain-access-groups`
//! entitlement the process is signed with, not by a per-signer ACL, so none of
//! them prompts and the extensions cannot read it. There is no read of a
//! login-keychain item written by an earlier build and no fallback to another
//! store: an unsigned build fails with `errSecMissingEntitlement` naming
//! `YADORILINK_CREDENTIAL_STORE=file`. On Windows and Linux it is `keyring`
//! (Credential Manager / Secret Service), unchanged.
//!
//!
//! One entry holds the whole document. The two `token_store.rs` modules this
//! replaces used three entries under `(yadorilink, access_token)` and
//! `(yadorilink, refresh_token)`; one entry is used here because the record's
//! fields are only meaningful together, and because a keyring offers no
//! transaction -- three writes can be interrupted after two, and the result is
//! a store that looks enrolled and cannot authenticate.
//!
//! This module used to carry the names of those two legacy entries as a
//! `RETIRED_KEYS` constant, and `clear` swept them on every logout. Both are
//! gone. The entries they named belonged to the `sessions` credential plane,
//! whose server-side tables `migrations/0021_drop_legacy_session_plane.sql`
//! drops: what a pre-cutover build left in an OS keyring now authenticates
//! against nothing, because there is no longer anything on the other end to
//! authenticate against.
//!
//! Keeping the sweep would have meant the running product permanently knowing
//! the key names of a plane it does not implement -- a list that reads as
//! documentation of where credentials used to live, and the natural place for
//! someone to put a third name. A cleanup that can only ever delete a dead
//! value is not a security measure; it is a legacy shape kept alive by a
//! comment explaining why it is still here.

use super::{StoreError, StoreResult};

/// The single entry this build reads and writes, and the only entry name this
/// crate knows.
#[cfg(any(windows, target_os = "linux", target_os = "macos"))]
const CREDENTIALS_KEY: &str = "credentials";

#[cfg(target_os = "macos")]
mod os {
    use super::{StoreError, StoreResult, CREDENTIALS_KEY};
    use yadorilink_os_keychain::Keychain;

    fn err(e: yadorilink_os_keychain::KeychainError) -> StoreError {
        StoreError::Keyring(e.to_string())
    }

    pub(super) fn read() -> StoreResult<Option<String>> {
        let Some(bytes) = Keychain::system().read(CREDENTIALS_KEY).map_err(err)? else {
            return Ok(None);
        };
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| StoreError::Keyring("the stored credential is not valid UTF-8".to_owned()))
    }

    pub(super) fn write(document: &str) -> StoreResult<()> {
        Keychain::system().write(CREDENTIALS_KEY, document.as_bytes()).map_err(err)
    }

    pub(super) fn clear() -> StoreResult<()> {
        Keychain::system().delete(CREDENTIALS_KEY).map_err(err)
    }

    /// Every item this product has in the credential access group (the
    /// credential and the device-key mirrors): the local purge behind
    /// `uninstall.sh --purge-data`.
    pub(super) fn purge_all() -> StoreResult<()> {
        Keychain::system().delete_all().map_err(err)
    }
}

#[cfg(any(windows, target_os = "linux"))]
mod os {
    use super::{StoreError, StoreResult, CREDENTIALS_KEY};

    /// Unchanged from the modules this replaces, so an OS keyring that already
    /// holds YadoriLink entries keeps them under one service.
    const SERVICE: &str = "yadorilink";

    /// The one entry this crate touches. Takes no argument on purpose: with no
    /// key parameter, "this crate knows one keyring entry" is a fact about the
    /// code rather than a claim in a comment.
    fn entry() -> StoreResult<keyring::Entry> {
        keyring::Entry::new(SERVICE, CREDENTIALS_KEY)
            .map_err(|e| StoreError::Keyring(e.to_string()))
    }

    pub(super) fn read() -> StoreResult<Option<String>> {
        match entry()?.get_password() {
            Ok(document) => Ok(Some(document)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(StoreError::Keyring(e.to_string())),
        }
    }

    pub(super) fn write(document: &str) -> StoreResult<()> {
        entry()?.set_password(document).map_err(|e| StoreError::Keyring(e.to_string()))
    }

    pub(super) fn clear() -> StoreResult<()> {
        match entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(StoreError::Keyring(e.to_string())),
        }
    }

    /// Windows and Linux hold only the one credential entry.
    pub(super) fn purge_all() -> StoreResult<()> {
        clear()
    }
}

/// Every other target (iOS, the BSDs, ...): the `keyring` crate is not even a dependency here,
/// because without a native feature it would fall back to its in-memory mock, where
/// `set_password` succeeds and the secret is gone at the next process start. A credential store
/// that cannot persist must refuse, never pretend. iOS needs a Data Protection Keychain backend
/// (`yadorilink-os-keychain`); until then it selects `YADORILINK_CREDENTIAL_STORE=file` or fails.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
mod os {
    use super::{StoreError, StoreResult};

    fn unsupported() -> StoreError {
        StoreError::Keyring("this target has no OS credential store backend".to_owned())
    }

    pub(super) fn read() -> StoreResult<Option<String>> {
        Err(unsupported())
    }

    pub(super) fn write(_document: &str) -> StoreResult<()> {
        Err(unsupported())
    }

    pub(super) fn clear() -> StoreResult<()> {
        Err(unsupported())
    }

    pub(super) fn purge_all() -> StoreResult<()> {
        Err(unsupported())
    }
}

pub(super) fn read() -> StoreResult<Option<String>> {
    os::read()
}

pub(super) fn write(document: &str) -> StoreResult<()> {
    os::write(document)
}

pub(super) fn clear() -> StoreResult<()> {
    os::clear()
}

pub(super) fn purge_all() -> StoreResult<()> {
    os::purge_all()
}

/// Runs on the iOS simulator (`cargo test --target aarch64-apple-ios-sim`); on a target the
/// `keyring` crate supports natively there is nothing to refuse.
#[cfg(all(test, not(any(windows, target_os = "linux", target_os = "macos"))))]
mod unsupported_target_tests {
    use super::*;

    #[test]
    fn a_target_without_a_native_store_refuses_instead_of_using_a_mock() {
        assert!(write("{}").is_err(), "a write must not appear to succeed");
        assert!(read().is_err(), "a read must not report an empty, enrollable store");
        assert!(clear().is_err());
        assert!(purge_all().is_err());
    }
}
