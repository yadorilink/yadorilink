// apple-cfg-file: ios-explicit the access group differs on iOS (shared with the File Provider extension); every other Apple platform is the macOS group
//! The Apple credential keychain (macOS and iOS): generic-password items in the **Data
//! Protection Keychain**, in one dedicated keychain access group.
//!
//! # Why this and not the login keychain
//!
//! A login-keychain item is guarded by an ACL bound to the code identity that
//! created it, so every distinct signer or path (an ad-hoc CLI, the host app,
//! the daemon helper) is asked about separately. A Data Protection Keychain
//! item has no ACL: which processes may read it is decided entirely by the
//! `keychain-access-groups` entitlement they are signed with. The host app, the
//! daemon helper and the CLI executable inside the host app carry
//! [`ACCESS_GROUP`]; on macOS the FinderSync and File Provider extensions carry no
//! keychain group and therefore cannot read these items. On iOS the app and its
//! File Provider extension carry the same group ([`IOS_ACCESS_GROUP`]).
//!
//! No `SecAccessCreate`, no ACL, no legacy-keychain call anywhere in this crate,
//! and no read of a login-keychain item from an earlier build: an installation
//! that has nothing in the group is simply not enrolled (one re-login after
//! the upgrade).
//!
//! # Attributes
//!
//! Every item and every query carries the same identity: class generic
//! password, [`SERVICE`], the account, [`ACCESS_GROUP`],
//! `kSecUseDataProtectionKeychain = true` and `kSecAttrSynchronizable = false`
//! (never iCloud). Stored items are
//! `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: the daemon runs as a
//! login-session agent and must keep refreshing while the screen is locked
//! (the Data Protection default, `WhenUnlocked`, would break that), and a
//! credential must not move to another device through a backup restore.
//!
//! The attribute sets are built as plain data ([`Attr`]) and handed to a
//! [`Backend`]; the real backend converts them to a CFDictionary for
//! `SecItem*`. That seam is what the unit tests check, off-device, without a
//! keychain.
//!
//! A build that is not signed with the group fails with
//! `errSecMissingEntitlement` (-34018). That is reported as an error naming
//! `YADORILINK_CREDENTIAL_STORE=file`, never papered over by another store.

use std::fmt;

#[cfg(target_vendor = "apple")]
mod sec;

#[cfg(target_vendor = "apple")]
pub use sec::SecItems;

/// The macOS group, shared ONLY by the host app, the daemon helper and the CLI.
/// The team prefix is the Developer ID team. Permanent once shipped: renaming
/// it orphans every stored credential. Must equal the string in
/// `App.entitlements` and `Daemon.entitlements` (the macOS installer's
/// `validate-macos-profiles.py` checks the signed bundles).
pub const MACOS_ACCESS_GROUP: &str = "594UQF7QX3.com.juntaki.yadorilink.credentials";

/// The iOS group, shared by the app and its File Provider extension (the engine
/// writer), which read and write the same items. Both entitlement files declare
/// `$(AppIdentifierPrefix)com.juntaki.yadorilink.ios.shared`; this runtime value
/// assumes that Team ID prefix `594UQF7QX3` applies to the iOS app signature (not
/// yet verified against a signed iOS build). The Apple repository's
/// `check-ios-identifiers.py` keeps the two entitlement files identical and
/// documents this value; a change here must change both.
pub const IOS_ACCESS_GROUP: &str = "594UQF7QX3.com.juntaki.yadorilink.ios.shared";

/// The access group of the platform this build targets.
#[cfg(target_os = "ios")]
pub const ACCESS_GROUP: &str = IOS_ACCESS_GROUP;

/// The access group of the platform this build targets.
#[cfg(not(target_os = "ios"))]
pub const ACCESS_GROUP: &str = MACOS_ACCESS_GROUP;

/// The generic-password service of every item this crate writes.
pub const SERVICE: &str = "yadorilink";

const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

/// One key/value pair of a keychain query or item, with the value fixed by the
/// key (so no combination can be spelled that this crate does not mean).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attr {
    /// `kSecClass = kSecClassGenericPassword`.
    ClassGenericPassword,
    /// `kSecAttrService`.
    Service(String),
    /// `kSecAttrAccount`.
    Account(String),
    /// `kSecAttrAccessGroup`.
    AccessGroup(String),
    /// `kSecUseDataProtectionKeychain`.
    UseDataProtectionKeychain(bool),
    /// `kSecAttrSynchronizable`.
    Synchronizable(bool),
    /// `kSecAttrAccessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
    AccessibleAfterFirstUnlockThisDeviceOnly,
    /// `kSecValueData`.
    ValueData(Vec<u8>),
    /// `kSecReturnData`.
    ReturnData(bool),
    /// `kSecMatchLimit = kSecMatchLimitOne`.
    MatchLimitOne,
}

/// The outcome of a failed `SecItem*` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    NotFound,
    Duplicate,
    Other(i32),
}

impl Status {
    #[must_use]
    pub fn from_os_status(code: i32) -> Self {
        match code {
            ERR_SEC_ITEM_NOT_FOUND => Self::NotFound,
            ERR_SEC_DUPLICATE_ITEM => Self::Duplicate,
            other => Self::Other(other),
        }
    }

    fn code(self) -> i32 {
        match self {
            Self::NotFound => ERR_SEC_ITEM_NOT_FOUND,
            Self::Duplicate => ERR_SEC_DUPLICATE_ITEM,
            Self::Other(code) => code,
        }
    }
}

/// The four `SecItem*` operations this crate uses, over plain attribute data.
pub trait Backend {
    fn add(&self, attributes: &[Attr]) -> Result<(), Status>;
    fn update(&self, query: &[Attr], changes: &[Attr]) -> Result<(), Status>;
    /// The `kSecValueData` of the one item the query matches.
    fn copy_data(&self, query: &[Attr]) -> Result<Vec<u8>, Status>;
    /// Deletes every item the query matches.
    fn delete(&self, query: &[Attr]) -> Result<(), Status>;
}

/// A keychain operation that failed (never "not found": that is absence).
#[derive(Debug, thiserror::Error)]
#[error("keychain {op} failed (OSStatus {code}){}", hint(*.code))]
pub struct KeychainError {
    op: &'static str,
    code: i32,
}

impl KeychainError {
    /// The OSStatus code.
    #[must_use]
    pub fn code(&self) -> i32 {
        self.code
    }
}

fn hint(code: i32) -> &'static str {
    if code == ERR_SEC_MISSING_ENTITLEMENT {
        ": this build is not signed with the credential keychain access group (an unsigned, \
         ad-hoc or development build); set YADORILINK_CREDENTIAL_STORE=file to use the file store"
    } else {
        ""
    }
}

fn failed(op: &'static str, status: Status) -> KeychainError {
    KeychainError { op, code: status.code() }
}

/// The identity every item and query shares.
fn identity(account: Option<&str>) -> Vec<Attr> {
    let mut attrs = vec![Attr::ClassGenericPassword, Attr::Service(SERVICE.to_owned())];
    if let Some(account) = account {
        attrs.push(Attr::Account(account.to_owned()));
    }
    attrs.extend([
        Attr::AccessGroup(ACCESS_GROUP.to_owned()),
        Attr::UseDataProtectionKeychain(true),
        Attr::Synchronizable(false),
    ]);
    attrs
}

/// The credential keychain: items in [`ACCESS_GROUP`], by account name.
#[derive(Debug, Clone, Copy, Default)]
pub struct Keychain<B> {
    backend: B,
}

#[cfg(target_vendor = "apple")]
impl Keychain<SecItems> {
    /// The system keychain.
    #[must_use]
    pub fn system() -> Self {
        Self::new(SecItems)
    }
}

impl<B: Backend> Keychain<B> {
    #[must_use]
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// The secret stored under `account`, or `None` when there is none.
    pub fn read(&self, account: &str) -> Result<Option<Vec<u8>>, KeychainError> {
        let mut query = identity(Some(account));
        query.extend([Attr::ReturnData(true), Attr::MatchLimitOne]);
        match self.backend.copy_data(&query) {
            Ok(data) => Ok(Some(data)),
            Err(Status::NotFound) => Ok(None),
            Err(status) => Err(failed("read", status)),
        }
    }

    /// Stores `secret` under `account`, replacing what was there.
    pub fn write(&self, account: &str, secret: &[u8]) -> Result<(), KeychainError> {
        let changes =
            [Attr::ValueData(secret.to_vec()), Attr::AccessibleAfterFirstUnlockThisDeviceOnly];
        match self.backend.update(&identity(Some(account)), &changes) {
            Ok(()) => return Ok(()),
            Err(Status::NotFound) => {}
            Err(status) => return Err(failed("update", status)),
        }
        let mut item = identity(Some(account));
        item.extend(changes.iter().cloned());
        match self.backend.add(&item) {
            Ok(()) => Ok(()),
            // Another process added it between our update and our add: it
            // exists now, so replace it.
            Err(Status::Duplicate) => self
                .backend
                .update(&identity(Some(account)), &changes)
                .map_err(|status| failed("update", status)),
            Err(status) => Err(failed("add", status)),
        }
    }

    /// Removes `account`'s item; removing what is not there is not an error.
    pub fn delete(&self, account: &str) -> Result<(), KeychainError> {
        self.delete_matching("delete", &identity(Some(account)))
    }

    /// Removes every item this crate has in the group (the credential and the
    /// device-key mirrors): the local purge behind `--purge-data`.
    pub fn delete_all(&self) -> Result<(), KeychainError> {
        self.delete_matching("purge", &identity(None))
    }

    fn delete_matching(&self, op: &'static str, query: &[Attr]) -> Result<(), KeychainError> {
        match self.backend.delete(query) {
            Ok(()) | Err(Status::NotFound) => Ok(()),
            Err(status) => Err(failed(op, status)),
        }
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OSStatus {}", self.code())
    }
}

#[cfg(test)]
mod tests;
