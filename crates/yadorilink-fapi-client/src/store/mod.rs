//! The credential store: one implementation, two first-class backends.
//!
//! # What is stored, and what deliberately is not
//!
//! Three things, and they are one record because they are useless apart: the
//! `client_id`, the **client private key**, and the **refresh token**. The
//! client key authenticates the installation; the refresh token is the
//! authority to continue a session; and a refresh token carries no DPoP
//! binding (measured against the deployed server), so *the client key plus the refresh token is the
//! session*. Splitting them across separate entries would mean a half-written
//! save leaves a store that looks configured and is not.
//!
//! The **access token is never persisted**. It lives for five minutes
//! (the coordination service), it is a process-local
//! cache in [`crate::CredentialManager`], and writing it to disk would put a
//! bearer-shaped credential at rest to save one HTTP round trip per process
//! start.
//!
//! The **DPoP key is never persisted** either. It is per-process proof
//! material; a fresh one is generated at startup and the refresh exchange
//! re-establishes the sender constraint onto it.
//!
//! # Two backends, neither a fallback
//!
//! [`Backend::Keyring`] is the OS-native store. [`Backend::File`] is an
//! owner-only file. The file backend is **not** a degraded mode: a headless
//! Linux host has no Secret Service, and requiring one there is what made this
//! undeployable. So it is the default on Linux, and the keyring is the default
//! on macOS and Windows, and either can be selected explicitly.
//!
//! What this module will not do is *fall back*. A keyring that cannot be
//! reached is an error naming `YADORILINK_CREDENTIAL_STORE=file`, never a
//! silent switch to a different store -- silently changing where a credential
//! lives is how an installation ends up anonymous while reporting success.
//!
//! # Refusing a half-configured store
//!
//! Modelled on the daemon's path witness sink: the
//! combinations that cannot mean anything are named and refused at startup,
//! rather than defaulted into something that starts cleanly and is wrong.
//! `YADORILINK_CREDENTIAL_FILE` with `YADORILINK_CREDENTIAL_STORE=keyring` is
//! refused because one of the two was going to be ignored; an unknown store
//! name is refused rather than treated as the default; and a record missing
//! any of its three fields is refused as `HalfConfigured` rather than read as
//! "not enrolled", because the two want opposite responses -- one is
//! `yadorilink login`, the other is a corrupted store that a login would
//! silently paper over.
//!
//! # There is exactly one way to be "not enrolled"
//!
//! **The backend holding no value.** That is the whole list. [`Document`] has
//! no optional member, so a document that exists names a complete
//! [`Credentials`], and every other byte sequence is a refusal:
//!
//! | stored bytes | outcome |
//! |---|---|
//! | *(no value in the backend)* | `Ok(None)` -- not enrolled |
//! | `{"format":2,"client":{..four fields..}}` | `Ok(Some(..))` |
//! | `{"format":2}` | refused: missing `client` |
//! | a member this build does not define | refused: unknown field |
//! | `{"format":1,..}` | refused: `UnsupportedFormat` |
//! | anything else | refused: [`StoreError::Unreadable`] |
//!
//! This is not defensive parsing for its own sake. A document that parsed
//! leniently made two states reachable that the product must never enter. A
//! `client`-less document read as `Ok(None)` reported corruption as absence,
//! and the caller's response to absence is `yadorilink login`, which would
//! have papered over the damage with a second registration. And a document
//! carrying members this build does not define read as valid, so the deleted
//! `legacy_session` plane -- and an `access_token`, the one credential this
//! store exists to never write down -- could sit in the file while the store
//! reported a clean read. Refusing the *shape* is what makes those
//! unrepresentable; refusing them one by one would only be a list that the
//! next member is missing from.
//!
//! No migration is offered for any of it. An unreadable pre-release credential
//! means re-enrol, so [`CredentialStore::save`] replaces the document without
//! reading it -- refusing to read a damaged store is only a policy if the
//! remedy it names can actually be carried out.

mod entry_claim;
mod file;
mod keyring_backend;
mod lock;

use std::path::{Path, PathBuf};

pub use entry_claim::{EntryClaim, FileEntryLock};
pub use lock::CredentialLock;

/// Selects the backend. Unset means the platform default.
pub const STORE_VAR: &str = "YADORILINK_CREDENTIAL_STORE";
/// Overrides where the file backend keeps its document.
pub const FILE_VAR: &str = "YADORILINK_CREDENTIAL_FILE";

/// The file backend's default name inside the config directory.
pub const CREDENTIALS_FILE: &str = "credentials.json";
/// The rotation lock's name inside the config directory.
pub const LOCK_FILE: &str = "credentials.lock";

/// The stored document's shape. Bumped only for a change that an older build
/// cannot read; a mismatch is refused rather than migrated, matching
/// `device.json`'s rule for this pre-release tree.
///
/// Bumped to 2 when the `legacy_session` member was deleted. That is the whole
/// migration story: a document written by a build that still had the legacy
/// coordination plane is refused with `UnsupportedFormat`, and the user
/// re-enrols. There is deliberately no reader for the old shape -- a
/// compatibility parser that imported a pre-release credential into the new
/// design would be the legacy plane surviving as data.
pub const FORMAT_VERSION: u32 = 2;

/// One installation's OAuth credentials.
///
/// `client_key_jwk` is the private JWK document verbatim, which is the form
/// [`crate::Es256Key::from_jwk_json`] reads and the form the Authorization
/// Server's own tooling emits. Keeping it as text rather than as a parsed key
/// means exactly one parser exists for it.
///
/// All four members are mandatory and no other member is accepted. The strict
/// shape is load-bearing one level down as well as at the document level: the
/// obvious thing for a future build to smuggle in here is an `access_token`,
/// and this module's first paragraph is a promise that one is never written to
/// disk. A lenient parser would have let one be stored and then silently
/// dropped on read, which is the promise being broken without any signal.
/// # The members are private
///
/// They were all `pub`, which made a `Credentials` a struct literal any caller
/// could spell -- and two callers did, the CLI's login and its wire-contract
/// harness, writing the same four lines with the same four expressions. That is
/// not a credential-forging hole (the `refresh_token` in a hand-built record
/// still has to be one the Authorization Server issued and has not revoked, so
/// a fabricated one buys a `400 invalid_grant`), but it is the shape that
/// invites one: four independent expressions with nothing relating them, where
/// the `client_id` and the `client_key_jwk` are only each other's counterpart
/// because the author remembered.
///
/// [`Credentials::new`] stays public because building the record is not the
/// privileged act -- the store is where a login is *durable*, and a test with a
/// temp directory has every right to write one. What is no longer possible is
/// reaching in and changing one member of a record that already exists.
/// [`crate::CredentialManager::establish`] is the product's only writer, and it
/// derives all four members from the client that obtained the tokens rather
/// than accepting them.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credentials {
    /// The Authorization Server these credentials belong to. Stored so a
    /// store pointed at a different issuer is a refusal rather than a
    /// confusing `invalid_client`.
    issuer: String,
    client_id: String,
    client_key_jwk: String,
    refresh_token: String,
}

impl std::fmt::Debug for Credentials {
    /// Renders the issuer and the `client_id`, the two members that identify
    /// the record. Never the client key and never the refresh token: together
    /// they are the whole authority to continue this installation's session
    /// and a derived `Debug` would put
    /// both into the first log line or `anyhow` chain that formatted one.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl Credentials {
    /// One installation's credential record.
    ///
    /// Not itself an authenticated credential: nothing here is checked against
    /// a server, and a record whose `refresh_token` the Authorization Server
    /// never issued simply fails at the first refresh. What this type is, is
    /// the complete set of things that have to be persisted together, which is
    /// why the constructor takes all four and there is no way to build a
    /// partial one.
    #[must_use]
    pub fn new(
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        client_key_jwk: impl Into<String>,
        refresh_token: impl Into<String>,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            client_id: client_id.into(),
            client_key_jwk: client_key_jwk.into(),
            refresh_token: refresh_token.into(),
        }
    }

    /// The Authorization Server this credential belongs to.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// This installation's registered `client_id`.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The client's private JWK document, verbatim.
    #[must_use]
    pub fn client_key_jwk(&self) -> &str {
        &self.client_key_jwk
    }

    /// The refresh token, which is this installation's durable half of the
    /// session.
    #[must_use]
    pub fn refresh_token(&self) -> &str {
        &self.refresh_token
    }

    fn check(&self) -> Result<(), StoreError> {
        let missing = [
            ("issuer", self.issuer.is_empty()),
            ("client_id", self.client_id.is_empty()),
            ("client_key_jwk", self.client_key_jwk.is_empty()),
            ("refresh_token", self.refresh_token.is_empty()),
        ]
        .into_iter()
        .filter_map(|(name, empty)| empty.then_some(name))
        .collect::<Vec<_>>();
        if missing.is_empty() {
            return Ok(());
        }
        Err(StoreError::HalfConfigured(missing.join(", ")))
    }
}

/// The whole stored document. One value, so a save is one atomic write and a
/// partially-updated store cannot exist.
///
/// One member, deliberately, and **not** an optional one. `client` used to be
/// `Option<Credentials>`, which made a stored `{"format":2}` deserialise to
/// `None` and read as *not enrolled* -- so a damaged store and an installation
/// that has never logged in were the same value, even though they want
/// opposite responses. Absence of a backend value is now the only way to spell
/// "not enrolled", and every document that exists carries exactly one complete
/// credential.
///
/// It also used to carry a second member, `legacy_session`, for the
/// pre-cutover `/auth/google/*` plane -- a stored access token with no
/// client-side way to re-mint it. That plane is gone, and the field is not
/// parked here as an optional one for a store written by an older build: a
/// document carrying it is a pre-release store, and re-enrolling is the
/// supported answer rather than importing it. `deny_unknown_fields` makes that
/// a refusal rather than a silent drop, and makes the same true of whatever a
/// later build invents -- the rule is the shape, not a list of rejected names.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    format: u32,
    client: Credentials,
}

/// Reads `format` and nothing else.
///
/// A two-stage parse, because the two refusals answer different questions and
/// the more specific one has to win. `{"format":1,"legacy_session":{..}}` is
/// structurally invalid *and* from a retired generation; parsed in one stage it
/// would come back as "unknown field `legacy_session`", when what the user
/// needs to be told is that this is a pre-release store and the answer is to
/// re-enrol. So the generation is established first, and only a document
/// claiming to be this generation is then held to this generation's shape.
///
/// Deliberately lenient about everything except `format`: its whole job is to
/// answer "which build wrote this?", and being strict here would make it fail
/// on exactly the foreign documents it exists to classify. `format` itself is
/// mandatory -- an unversioned document is not a credential this build wrote.
#[derive(serde::Deserialize)]
struct Generation {
    format: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("{STORE_VAR} is {0:?}, which is not a credential store this build implements; use \"keyring\" or \"file\"")]
    UnknownBackend(String),

    #[error(
        "refusing to start: {FILE_VAR} names a credential file but {STORE_VAR} selects the OS \
         keyring, so one of the two was going to be ignored; set {STORE_VAR}=file or unset {FILE_VAR}"
    )]
    ConflictingConfiguration,

    #[error(
        "the stored credential is missing {0}; this is a damaged store rather than an absent \
         login, so it is refused instead of being treated as \"not enrolled\""
    )]
    HalfConfigured(String),

    #[error(
        "the stored credential document is format {found}, and this build reads format \
         {FORMAT_VERSION}; re-enrol rather than migrating a pre-release store"
    )]
    UnsupportedFormat { found: u32 },

    #[error(
        "there is no stored credential to rotate a refresh token into; this installation has not \
         enrolled, and writing one now would leave a record with no client key, which is the \
         half-configured store this module refuses to create"
    )]
    NotEnrolled,

    #[error(
        "{path} is readable by more than its owner (mode {mode:#o}); a credential file is \
         refused rather than repaired, because the secret has already been exposed to whoever \
         could read it"
    )]
    Permissions { path: PathBuf, mode: u32 },

    #[error("the OS keyring is unavailable ({0}); on a host with no Secret Service, set {STORE_VAR}=file, which is a supported backend and not a fallback")]
    Keyring(String),

    #[error("credential store I/O at {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },

    #[error(
        "the stored credential document is not a format {FORMAT_VERSION} credential ({0}); a \
         document that exists and does not have exactly this shape is a damaged store rather \
         than an absent login, so it is refused instead of being read as \"not enrolled\" -- run \
         `yadorilink logout` to discard it and enrol again"
    )]
    Unreadable(serde_json::Error),

    #[error(
        "another process has held the credential rotation lock at {path} for longer than \
         {waited:?}; refusing to refresh rather than racing it, because two processes spending \
         the same refresh token takes the whole grant down"
    )]
    LockTimeout { path: PathBuf, waited: std::time::Duration },

    #[error(
        "the stored credential now names client_id {found:?}, not {expected:?} that this \
         rotation was computed for; another process replaced this installation's credential (a \
         logout and a fresh enrolment, most likely) since this one was read, so the rotation is \
         refused rather than applied to the wrong installation"
    )]
    ClientIdChanged { expected: String, found: String },

    #[error(
        "the credential file {0} cannot be claimed (its lock file cannot be created beside it), \
         so whether another engine uses the same entry cannot be told"
    )]
    UnresolvableCredentialPath(PathBuf),

    #[error(
        "the credential file {0} is named like the rotation lock file (`credentials.lock`), \
         which the store takes for every refresh; use another file name"
    )]
    CredentialFileIsRotationLock(PathBuf),

    #[error(
        "the credential file {0} is a symbolic link; name the file itself, because saving \
         replaces the link with a regular file"
    )]
    CredentialFileIsSymlink(PathBuf),

    #[error("the credential entry {0} is already in use by another engine")]
    EntryInUse(PathBuf),

    #[error("{0:?} is not a keyring scope: use 1 to 64 of lowercase letters a-z, digits, '.', '_' and '-'")]
    InvalidKeyringScope(String),

    #[error(
        "this `CredentialLock` was acquired for {held}, not this store's own lock file {expected}; \
         a lock over a different config directory proves nothing about mutual exclusion on THIS \
         store's document, so the mutation is refused rather than run unlocked in every sense \
         that matters"
    )]
    WrongLock { held: PathBuf, expected: PathBuf },
}

pub type StoreResult<T> = Result<T, StoreError>;

/// Which backing store holds the document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backend {
    /// The OS-native credential store. `scope` names this engine's own entry inside it
    /// (the account is `credentials.<scope>`); `None` is the one entry the desktop
    /// installation, daemon and CLI share.
    Keyring { scope: Option<String> },
    /// An owner-only file at this path.
    File(PathBuf),
}

impl Backend {
    /// The default for this platform.
    ///
    /// Linux gets the file backend because a headless Linux host -- the
    /// deployment this whole workstream exists to make possible -- has no
    /// Secret Service, and a default that cannot start there is a default that
    /// does not work. macOS and Windows have an OS store that is always
    /// present, so they use it.
    #[must_use]
    pub fn platform_default(config_dir: &Path) -> Self {
        if cfg!(target_os = "linux") {
            Backend::File(config_dir.join(CREDENTIALS_FILE))
        } else {
            Backend::Keyring { scope: None }
        }
    }

    /// The OS keyring entry private to `scope`: two engines of one process with different
    /// scopes keep different entries, so neither can read or rotate the other's credential.
    ///
    /// A scope is lowercase ASCII only (`a-z`, `0-9`, `.`, `_`, `-`, 1 to 64 long) and anything
    /// else is refused, never normalized: Windows Credential Manager target names are
    /// case-insensitive, so `engine-a` and `ENGINE-A` would be one credential under two
    /// spellings, and two engines could pass admission over it. With one canonical spelling,
    /// comparing scopes literally compares the entries.
    pub fn scoped_keyring(scope: &str) -> StoreResult<Self> {
        let valid = !scope.is_empty()
            && scope.len() <= 64
            && scope.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
            });
        if !valid {
            return Err(StoreError::InvalidKeyringScope(scope.to_owned()));
        }
        Ok(Backend::Keyring { scope: Some(scope.to_owned()) })
    }

    /// Resolves the backend a process's environment selects: `YADORILINK_CREDENTIAL_STORE`
    /// and `YADORILINK_CREDENTIAL_FILE`. The one place those variables are read; a host that
    /// has its own configuration builds a [`Backend`] directly.
    pub fn from_env(config_dir: &Path) -> StoreResult<Self> {
        let selected = std::env::var(STORE_VAR).ok();
        let file_override = std::env::var_os(FILE_VAR).map(PathBuf::from);
        Self::select(selected.as_deref(), file_override, config_dir)
    }

    /// The selection rules, over already-read values.
    pub fn select(
        selected: Option<&str>,
        file_override: Option<PathBuf>,
        config_dir: &Path,
    ) -> StoreResult<Self> {
        match (selected, file_override) {
            (None, None) => Ok(Backend::platform_default(config_dir)),
            (None, Some(path)) | (Some("file"), Some(path)) => Ok(Backend::File(path)),
            (Some("file"), None) => Ok(Backend::File(config_dir.join(CREDENTIALS_FILE))),
            (Some("keyring"), None) => Ok(Backend::Keyring { scope: None }),
            (Some("keyring"), Some(_)) => Err(StoreError::ConflictingConfiguration),
            (Some(other), _) => Err(StoreError::UnknownBackend(other.to_owned())),
        }
    }
}

/// The one credential store.
#[derive(Debug, Clone)]
pub struct CredentialStore {
    backend: Backend,
    lock_path: PathBuf,
}

impl CredentialStore {
    /// A store on `backend`. `config_dir` holds the rotation lock whichever backend holds the
    /// secret: the CLI and the daemon share a config directory, and the OS keyring offers no
    /// lock primitive of its own.
    #[must_use]
    pub fn with_backend(backend: Backend, config_dir: &Path) -> Self {
        Self { backend, lock_path: config_dir.join(LOCK_FILE) }
    }

    #[must_use]
    pub fn backend(&self) -> &Backend {
        &self.backend
    }

    #[must_use]
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    /// This installation's OAuth credentials, or `None` if it has never
    /// enrolled.
    ///
    /// A record that exists but is incomplete is an error, not a `None`. The
    /// two cases call for opposite responses and conflating them is how a
    /// damaged store gets papered over by a fresh login that then has two
    /// registrations to its name.
    pub fn load(&self) -> StoreResult<Option<Credentials>> {
        let Some(document) = self.read()? else { return Ok(None) };
        document.client.check()?;
        Ok(Some(document.client))
    }

    /// Replaces this installation's OAuth credentials.
    ///
    /// Writes without reading first, on purpose. Enrolment is the *answer* to
    /// every refusal [`CredentialStore::load`] can raise -- a pre-release
    /// format, a smuggled member, a document with no `client` -- and a save
    /// that had to parse the document it is about to overwrite would refuse
    /// exactly when it is needed, leaving `yadorilink login` unable to repair
    /// the store its own error message tells the user to repair. There is
    /// nothing in the old document worth preserving: this is the only writer
    /// of a whole record, and the record is complete.
    ///
    /// `lock` is proof this caller holds [`CredentialLock`] -- checked, not
    /// merely required by the signature, against exactly this store's own
    /// lock path. Every mutation this store can perform -- [`Self::save`],
    /// [`Self::clear`], [`Self::rotate_refresh_token`] -- takes the same
    /// proof, so a fresh enrolment's write can never land in the middle of
    /// another process's read-refresh-persist rotation. Before this, each
    /// method took its own lock or none at all, and a `save` for a NEW
    /// enrolment could interleave with a DIFFERENT process's in-flight
    /// rotation of the credential it was about to replace: the rotation reads
    /// whatever document happens to be on disk when it runs, so the race
    /// produced a record carrying one installation's `client_id` and key with
    /// another installation's freshly rotated refresh token.
    pub fn save(&self, lock: &CredentialLock, credentials: &Credentials) -> StoreResult<()> {
        self.require_our_lock(lock)?;
        credentials.check()?;
        self.write(credentials)
    }

    /// Replaces only the refresh token, leaving `client_id` and the client key
    /// alone.
    ///
    /// This is the rotation path and it is separate on purpose: a refresh
    /// response rotates the refresh token and nothing else, and a caller that
    /// had to re-supply the client key in order to record a rotation could
    /// write a stale key over a newer one.
    ///
    /// Unlike [`CredentialStore::save`] this does read first, and must: a
    /// rotation is an edit to a record it does not carry, so there has to be
    /// one to edit. Nothing stored is [`StoreError::NotEnrolled`] rather than a
    /// fabricated record -- a rotation cannot invent a client key, and writing
    /// a refresh token without one produces exactly the half-configured store
    /// that every read path here refuses.
    ///
    /// `expected_client_id` is checked against what is actually on disk before
    /// anything is written, on top of `lock` rather than instead of it: the
    /// lock is what stops a concurrent replacement from happening at all, and
    /// this is the second, independent check that the record this rotation was
    /// computed for is still the one being edited -- belt and braces for a
    /// write that a wrong guess turns into a corrupted credential rather than
    /// a loud failure.
    pub fn rotate_refresh_token(
        &self,
        lock: &CredentialLock,
        expected_client_id: &str,
        refresh_token: &str,
    ) -> StoreResult<()> {
        self.require_our_lock(lock)?;
        let mut credentials = self.read()?.ok_or(StoreError::NotEnrolled)?.client;
        if credentials.client_id != expected_client_id {
            return Err(StoreError::ClientIdChanged {
                expected: expected_client_id.to_owned(),
                found: credentials.client_id,
            });
        }
        credentials.refresh_token = refresh_token.to_owned();
        credentials.check()?;
        self.write(&credentials)
    }

    /// Removes everything this store holds.
    ///
    /// The configured backend and nothing else. This used to also sweep two OS
    /// keyring entries named by a `RETIRED_KEYS` constant, whatever backend was
    /// selected, so that a logout destroyed what a pre-cutover build had left
    /// behind. Those entries held `sessions`-plane tokens, and that plane's
    /// server-side tables are dropped
    /// (`migrations/0021_drop_legacy_session_plane.sql`) -- so there is nothing
    /// left for them to authenticate to, and the sweep was the running product
    /// carrying a list of the key names of a credential design it no longer
    /// implements.
    pub fn clear(&self, lock: &CredentialLock) -> StoreResult<()> {
        self.require_our_lock(lock)?;
        match &self.backend {
            Backend::Keyring { scope } => keyring_backend::clear(scope.as_deref()),
            Backend::File(path) => file::clear(path),
        }
    }

    /// Removes everything this installation keeps in the configured backend,
    /// including what [`Self::clear`] leaves: on macOS, every item of this
    /// product in the credential keychain access group (the device-key
    /// mirrors as well as the credential). This is the local purge behind
    /// `uninstall.sh --purge-data` (`yadorilink credentials purge`); nothing is
    /// revoked on the server. Idempotent: nothing stored is success.
    pub fn purge_local(&self, lock: &CredentialLock) -> StoreResult<()> {
        self.require_our_lock(lock)?;
        match &self.backend {
            Backend::Keyring { scope } => keyring_backend::purge_all(scope.as_deref()),
            Backend::File(path) => file::clear(path),
        }
    }

    /// Refuses a [`CredentialLock`] that was not acquired from THIS store's
    /// own lock path.
    ///
    /// Without this, `&CredentialLock` in a mutation's signature is proof
    /// that *some* store's lock is held, not proof that *this* store's is --
    /// a lock acquired from one `CredentialStore` (one config directory)
    /// passed into another's `save`/`clear`/`rotate_refresh_token` compiled
    /// and ran, taking neither store's rotation lock during the mutation it
    /// performed. Two `CredentialStore` values over the SAME config
    /// directory -- the ordinary case, since the CLI and the daemon each
    /// build their own -- share a `lock_path` and pass this check against
    /// each other's lock, which is correct: they are contending for the same
    /// file underneath, and the actual mutual exclusion was always `flock` on
    /// that path, never Rust ownership of the token. What this refuses is a
    /// lock from a genuinely DIFFERENT path -- a different config directory,
    /// a test fixture's temp directory reused by mistake -- which proves
    /// nothing about this store's own file.
    fn require_our_lock(&self, lock: &CredentialLock) -> StoreResult<()> {
        if lock.path() != self.lock_path {
            return Err(StoreError::WrongLock {
                held: lock.path().to_path_buf(),
                expected: self.lock_path.clone(),
            });
        }
        Ok(())
    }

    /// Takes the cross-process rotation lock, waiting up to `timeout`.
    ///
    /// Held across the whole read-refresh-persist sequence. Without it the CLI
    /// and the daemon spend the same refresh token concurrently, the server's
    /// reuse defence fires, and it revokes the entire family -- correct
    /// behaviour on its part, and a user who is silently logged out on both.
    ///
    /// A bounded `try_lock` retry loop rather than a blocking acquire, so this
    /// never parks a reactor thread and never needs a blocking pool to exist.
    pub async fn lock(&self, timeout: std::time::Duration) -> StoreResult<CredentialLock> {
        lock::acquire(&self.lock_path, timeout).await
    }

    /// The stored document, or `None` when the backend holds no value.
    ///
    /// `None` here is the single source of "not enrolled" in this module. Every
    /// other outcome is either a document of exactly this generation's shape or
    /// an error; there is no third reading in which bytes are present and mean
    /// nothing.
    fn read(&self) -> StoreResult<Option<Document>> {
        let raw = match &self.backend {
            Backend::Keyring { scope } => keyring_backend::read(scope.as_deref())?,
            Backend::File(path) => file::read(path)?,
        };
        let Some(raw) = raw else { return Ok(None) };

        // Which generation wrote this, before holding it to this generation's
        // shape -- so a pre-release store is named as one rather than reported
        // as whichever of its members this build happens not to know.
        let generation: Generation = serde_json::from_str(&raw).map_err(StoreError::Unreadable)?;
        if generation.format != FORMAT_VERSION {
            return Err(StoreError::UnsupportedFormat { found: generation.format });
        }

        serde_json::from_str(&raw).map(Some).map_err(StoreError::Unreadable)
    }

    /// The only writer, and it takes a [`Credentials`] rather than a
    /// [`Document`] so that `format` has exactly one value in the tree: there
    /// is no call site that could stamp a document with anything but this
    /// build's version, and therefore no version-stamping mistake to defend
    /// against with a re-stamp that can never change anything.
    fn write(&self, credentials: &Credentials) -> StoreResult<()> {
        let document = Document { format: FORMAT_VERSION, client: credentials.clone() };
        // A `format: u32` plus a struct of `String`s cannot fail to serialize;
        // an empty document written in place of a real error would be the
        // half-configured store this module exists to refuse, produced by the
        // one writer that is supposed to prevent it.
        let raw = serde_json::to_string(&document)
            .expect("Document holds only a u32 and Strings, which always serialize");
        match &self.backend {
            Backend::Keyring { scope } => keyring_backend::write(scope.as_deref(), &raw),
            Backend::File(path) => file::write(path, &raw),
        }
    }
}

#[cfg(test)]
mod tests;
