//! The credential manager: a live access token, for as long as the process
//! runs.
//!
//! # The problem it exists to solve
//!
//! The access token's lifetime is **five minutes**
//! (the coordination service). A daemon that reads a
//! token at startup and passes it around as a value is authenticated for five
//! minutes and broken for the rest of the day. So the token is not a value
//! that callers hold; it is something they ask for, and the asking is what
//! refreshes it.
//!
//! # What is cached, and what is persisted
//!
//! The access token is cached **in this process only** and is never written
//! anywhere. What is persisted is the client key and the refresh token, and
//! rotation of the latter is the only thing this type writes.
//!
//! # The DPoP key is fresh every process, deliberately
//!
//! A refresh token carries no DPoP binding (measured): the server
//! copies `jkt` onto a refresh token only for a client authenticating with
//! `none`, and this client authenticates with `private_key_jwt`. So refreshing
//! under a DPoP key that never saw the original grant is *correct*, and it is
//! what lets the DPoP key be per-process rather than persisted.
//!
//! That is a property of the server, not a law, so it is asserted rather than
//! relied on silently:
//! `tests/credential_manager.rs::refreshing_happens_under_a_dpop_key_the_grant_has_never_seen`
//! forces the case, and the live counterpart in `tests/vertical_flow.rs`
//! proves it against a real server. If a later server change starts binding
//! refresh tokens, those tests fail rather than the daemon quietly losing its
//! session at every restart.
//!
//! # Rotation is the dangerous part
//!
//! A refresh response rotates the refresh token and kills the one presented.
//! Replaying a spent one does not fail harmlessly -- it fires the reuse
//! defence and tears down the whole grant family. Two processes sharing one
//! stored credential is the ordinary case here, not a corner: the user runs a
//! CLI command while the daemon is running. So every refresh happens under the
//! cross-process lock in [`crate::store`], and the refresh token is re-read
//! from the store *inside* the lock rather than trusted from memory -- because
//! the other process may have rotated it since this one last looked.
//!
//! # The crash window, and why the client has no recovery code
//!
//! Between the server rotating the token and this process's durable write
//! there is a window no client ordering can close: a power loss or `SIGKILL`
//! there leaves the disk holding the token the server just retired. The server
//! closes it instead. For a short window after a rotation it accepts the
//! retired token again from the same client, provided its successor was never
//! used, and answers with a fresh successor in place of the unconfirmed one --
//! so a restarted process simply refreshes with what the disk holds, and the
//! response is persisted like any other rotation. A failed refresh is a single
//! request that leaves the stored token untouched; there is no retry loop here,
//! and the caller's next attempt re-presents the same token. The DPoP key is
//! not part of that contract, because it is fresh in every process.
//!
//! A refresh that does *not* rotate is a failure, not a warning. This module
//! used to log one, leave the spent token in the store, and hand the caller an
//! access token: a session that was already over, reported as success, good for
//! one more five-minute window before failing somewhere that could not explain
//! why. The requirement now lives in [`crate::TokenResponse`], so by the time
//! `refresh_now` has a value the rotation has happened, and the store write
//! below has no branch.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::client::{FapiClient, TokenResponse};
use crate::error::{Error, Result};
use crate::key::Es256Key;
use crate::store::{CredentialStore, Credentials};

/// Refresh this far before the token actually expires.
///
/// A token that is about to expire is as good as expired: the request it is
/// attached to has to travel, be processed and be answered. Sixty seconds out
/// of a three-hundred-second lifetime is a fifth of the window spent on
/// safety, which is the right trade when the alternative is a 401 the caller
/// has to understand and retry.
pub const DEFAULT_REFRESH_SKEW: Duration = Duration::from_secs(60);

/// How long to wait for the cross-process rotation lock before refusing.
///
/// Long enough for another process's refresh round trip (and a retry of it),
/// short enough that a stuck holder surfaces as an error rather than a hang.
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_secs(30);

struct Cached {
    access_token: String,
    expires_at: Instant,
}

/// How [`CredentialManager`] runs the write that follows a successful
/// refresh, once the server has already rotated the token.
///
/// The default -- [`CredentialManager::with_client`]'s starting value, via
/// [`run_inline`] -- simply calls the closure in place, on the same future
/// that is refreshing. That is correct for a short-lived CLI process and for
/// every test in this crate, and it is why this type exists as an injectable
/// seam rather than as a hardcoded `tokio::spawn`: this crate is linked into
/// `yadorilink-daemon`'s deterministic-simulation build, whose tokio has no
/// runtime to spawn onto (see this crate's `Cargo.toml`), so nothing in
/// ordinary use may assume one exists.
///
/// The daemon overrides it (`yadorilink-daemon::credential_store`), and the
/// reason is its own essential-task supervisor
/// (`supervise::EssentialTasks::shutdown`): the instant any ONE essential task
/// fails, every other one is aborted immediately, and refreshing a credential
/// is ordinary work an essential task does inline. If that abort lands
/// between the server rotating the refresh token and this process's write of
/// the rotation, the store is left holding a token the server has already
/// killed -- permanently, since rotation is one-shot and nothing later
/// re-derives a value that was never persisted. A real crash (`SIGKILL`,
/// power loss) cannot be defended against this way; nothing the process being
/// killed does can survive that. But an abort this same process issues
/// against itself is not a crash, so the daemon runs the write detached from
/// whatever task asked for the refresh -- a plain `tokio::spawn`, holding no
/// `AbortHandle` that `EssentialTasks::shutdown` could ever reach -- so
/// aborting the caller can no longer cancel a write the network round trip
/// has already made necessary.
pub type Detach = Arc<dyn Fn(Box<dyn FnOnce() + Send>) + Send + Sync>;

/// The default [`Detach`]: run the closure in place.
fn run_inline(work: Box<dyn FnOnce() + Send>) {
    work();
}

/// Keeps one installation authenticated.
pub struct CredentialManager {
    client: FapiClient,
    store: Arc<CredentialStore>,
    /// Serializes refreshes *within* this process. Held across the whole
    /// refresh, so two tasks noticing the same expiry produce one round trip
    /// rather than two -- and, more importantly, not two rotations.
    refreshing: tokio::sync::Mutex<()>,
    /// Never held across an `await`.
    cached: std::sync::Mutex<Option<Cached>>,
    refresh_skew: Duration,
    lock_timeout: Duration,
    detach: Detach,
}

impl std::fmt::Debug for CredentialManager {
    /// Renders no credential: not the access token, not the refresh token, not
    /// the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialManager")
            .field("client_id", &self.client.client_id())
            .field("issuer", &self.client.metadata().issuer)
            .field("dpop_jkt", &self.client.dpop_jkt())
            .finish_non_exhaustive()
    }
}

impl CredentialManager {
    /// Build a manager from what the credential store holds.
    ///
    /// `base_url` is the socket to dial, which is not necessarily the issuer.
    /// The DPoP key is generated here, per process.
    ///
    /// Refuses rather than returning an unauthenticated manager: an
    /// installation that has not enrolled needs to enrol, and a manager that
    /// exists but can never produce a token is a failure deferred to whichever
    /// request happens to come first.
    pub async fn restore(
        http: reqwest::Client,
        base_url: &str,
        store: Arc<CredentialStore>,
    ) -> Result<Self> {
        let credentials = store.load()?.ok_or(Error::NotEnrolled)?;
        Self::from_credentials(http, base_url, store, &credentials).await
    }

    /// Build a manager from credentials that have just been obtained and
    /// stored.
    pub async fn from_credentials(
        http: reqwest::Client,
        base_url: &str,
        store: Arc<CredentialStore>,
        credentials: &Credentials,
    ) -> Result<Self> {
        let client_key = Es256Key::from_jwk_json(credentials.client_key_jwk())?;
        let client = FapiClient::discover(
            http,
            base_url,
            credentials.client_id().to_owned(),
            client_key,
            Es256Key::generate(),
        )
        .await?;
        Self::over_client_for(client, store, credentials)
    }

    /// Build a manager from a metadata document that was fetched on some
    /// earlier run, for an installation whose Authorization Server is
    /// unreachable right now.
    ///
    /// The same client [`from_credentials`](Self::from_credentials) builds,
    /// minus the fetch. Every check that constructor depends on still runs
    /// here -- [`FapiClient::from_metadata`] re-checks the profile and the
    /// socket, and the issuer comparison below is the same one -- because a
    /// document handed in rather than fetched is exactly the case those
    /// checks were made unconditional for.
    ///
    /// This does not make the server optional. Nothing it returns can mint a
    /// token without reaching the token endpoint; what it buys is a process
    /// that starts, does whatever it can do without the server, and
    /// authenticates the moment the server answers again -- instead of one
    /// that refuses to start because a network was down at the wrong moment.
    pub fn from_credentials_and_metadata(
        http: reqwest::Client,
        base_url: &str,
        store: Arc<CredentialStore>,
        credentials: &Credentials,
        metadata: crate::discovery::Metadata,
    ) -> Result<Self> {
        let client_key = Es256Key::from_jwk_json(credentials.client_key_jwk())?;
        let client = FapiClient::from_metadata(
            http,
            url::Url::parse(base_url)?,
            metadata,
            credentials.client_id().to_owned(),
            client_key,
            Es256Key::generate(),
        )?;
        Self::over_client_for(client, store, credentials)
    }

    /// The one gate both credential-shaped constructors pass through: the
    /// client must belong to the deployment the stored credential names.
    fn over_client_for(
        client: FapiClient,
        store: Arc<CredentialStore>,
        credentials: &Credentials,
    ) -> Result<Self> {
        // A store carried over from a different deployment authenticates
        // against nothing and says `invalid_client` while doing it. Say which
        // two issuers disagree instead.
        if client.metadata().issuer != credentials.issuer() {
            return Err(Error::IssuerMismatch {
                stored: credentials.issuer().to_owned(),
                discovered: client.metadata().issuer.clone(),
            });
        }

        Ok(Self::with_client(client, store))
    }

    /// Record a completed login: persist the credential, and hand back a
    /// manager already holding the access token that login produced.
    ///
    /// This is the **only** door from a finished authorization-code exchange to
    /// a usable credential, and it exists because there used to be no door at
    /// all -- just four public seams a call site was expected to operate in the
    /// right order (`Credentials { .. }`, `store.save`, `with_client`, `seed`).
    /// Two call sites operated them, identically, by copying each other.
    ///
    /// Three things are true here that were previously true only by convention:
    ///
    /// * the stored `issuer` and `client_id` come from `client`, so the record
    ///   cannot name a registration other than the one that holds the tokens;
    /// * the store is written **before** the manager exists, so there is no
    ///   value a caller can hold that authenticates a process whose disk says
    ///   it never logged in;
    /// * the access token just issued is in the cache, so the first request
    ///   after a login does not spend the refresh token to re-obtain a token it
    ///   was already handed.
    ///
    /// `client_key_jwk` is passed rather than read back off `client`:
    /// [`Es256Key`] deliberately does not expose its private half, and the
    /// serialized JWK is produced at enrolment, before the key is moved into
    /// the client by value.
    pub async fn establish(
        client: FapiClient,
        client_key_jwk: impl Into<String>,
        tokens: &TokenResponse,
        store: Arc<CredentialStore>,
    ) -> Result<Self> {
        // Under the same rotation lock every other mutation of this store
        // takes, so a fresh enrolment's write can never land in the middle of
        // a DIFFERENT process's read-refresh-persist sequence for whatever
        // credential this save is about to replace.
        let lock = store.lock(DEFAULT_LOCK_TIMEOUT).await?;
        store.save(
            &lock,
            &Credentials::new(
                client.metadata().issuer.clone(),
                client.client_id(),
                client_key_jwk,
                tokens.refresh_token(),
            ),
        )?;
        drop(lock);
        let manager = Self::with_client(client, store);
        manager.seed(tokens);
        Ok(manager)
    }

    /// A manager over an already-built client, holding no token yet.
    ///
    /// `pub(crate)`, with [`crate::test_support`] re-exporting it for tests
    /// that need a manager without a server. It was public so that the CLI's
    /// login could hand its client over without re-discovering, and so that
    /// four integration tests could build one -- but paired with [`Self::seed`]
    /// it is the assembly line for a `CredentialManager` holding a token no
    /// server issued, and from there a [`crate::CoordinationAuth`] that signs
    /// real DPoP proofs over it. The product reaches a manager through
    /// [`Self::establish`], [`Self::restore`] or [`Self::from_credentials`],
    /// all three of which either carry a checked [`TokenResponse`] or carry no
    /// token at all.
    #[must_use]
    pub(crate) fn with_client(client: FapiClient, store: Arc<CredentialStore>) -> Self {
        Self {
            client,
            store,
            refreshing: tokio::sync::Mutex::new(()),
            cached: std::sync::Mutex::new(None),
            refresh_skew: DEFAULT_REFRESH_SKEW,
            lock_timeout: DEFAULT_LOCK_TIMEOUT,
            detach: Arc::new(run_inline),
        }
    }

    #[must_use]
    pub fn with_refresh_skew(mut self, skew: Duration) -> Self {
        self.refresh_skew = skew;
        self
    }

    #[must_use]
    pub fn with_lock_timeout(mut self, timeout: Duration) -> Self {
        self.lock_timeout = timeout;
        self
    }

    /// Overrides how the write that follows a successful refresh is run. See
    /// [`Detach`].
    #[must_use]
    pub fn with_detach(mut self, detach: Detach) -> Self {
        self.detach = detach;
        self
    }

    /// The client this manager authenticates as. This crate's own
    /// out-of-process tests read it directly (a five-minute boundary and a
    /// cross-process rotation cannot be proven without one), so this stays
    /// public rather than `pub(crate)`; what is narrowed instead is
    /// [`crate::CoordinationAuth`], which no longer hands one back to a
    /// caller that only ever held the wrapper.
    #[must_use]
    pub fn client(&self) -> &FapiClient {
        &self.client
    }

    /// This installation's registered `client_id`.
    #[must_use]
    pub fn client_id(&self) -> &str {
        self.client.client_id()
    }

    /// Seed the cache from a token response that has just been received, so
    /// the first request after a login does not immediately refresh a token
    /// that is seconds old.
    ///
    /// Only the access token is adopted. The refresh token is the store's, and
    /// a caller that has one to record uses [`CredentialManager::adopt`].
    ///
    /// `pub(crate)` for the same reason as [`Self::with_client`]: this is the
    /// one method that puts a token into the cache without a round trip, and a
    /// cached token is what makes a manager -- and therefore a
    /// [`crate::CoordinationAuth`] -- authenticated. [`Self::establish`] is the
    /// product's caller. [`crate::test_support`] re-exports it for tests.
    pub(crate) fn seed(&self, tokens: &TokenResponse) {
        self.cache(tokens);
    }

    /// Record a freshly issued token pair: the access token into this
    /// process's cache, the refresh token into the store.
    ///
    /// Unconditional, because [`TokenResponse`] cannot exist without a refresh
    /// token. The `if let` that used to stand here silently produced an
    /// installation whose store held nothing to refresh with.
    pub async fn adopt(&self, tokens: &TokenResponse) -> Result<()> {
        let lock = self.store.lock(self.lock_timeout).await?;
        self.store.rotate_refresh_token(&lock, self.client.client_id(), tokens.refresh_token())?;
        self.cache(tokens);
        Ok(())
    }

    /// A live access token, refreshing if the cached one is spent or close to
    /// it.
    ///
    /// This is the method every authenticated call goes through. It is cheap
    /// on the common path -- one mutex and a clock read -- so there is no
    /// reason for a caller to hold onto the result.
    pub async fn access_token(&self) -> Result<String> {
        Ok(self.access_token_and_origin().await?.0)
    }

    /// [`Self::access_token`], also saying whether the token came from a refresh this call made
    /// (`true`) or from the cache (`false`). Only the former is evidence about what the server
    /// accepts now.
    pub async fn access_token_and_origin(&self) -> Result<(String, bool)> {
        if let Some(token) = self.fresh_enough() {
            return Ok((token, false));
        }

        // One refresh per process, whatever the arrival rate. Everything below
        // runs exactly once for a burst of callers.
        let _serialized = self.refreshing.lock().await;
        if let Some(token) = self.fresh_enough() {
            return Ok((token, false));
        }
        Ok((self.refresh_now().await?, true))
    }

    /// Refresh unconditionally.
    ///
    /// The recovery path for a 401 that the cache could not have predicted --
    /// a revocation, a clock skew, a server restart. Callers should try this
    /// once and then surface the failure rather than looping: a refused
    /// refresh against a revoked registration will be refused again.
    pub async fn force_refresh(&self) -> Result<String> {
        let _serialized = self.refreshing.lock().await;
        self.refresh_now().await
    }

    async fn refresh_now(&self) -> Result<String> {
        // The whole read-refresh-persist sequence is inside the lock. Any
        // shorter critical section admits the interleaving the lock exists to
        // stop: this process reads a token, the other process rotates it, and
        // this process then presents the dead one. The lock is released by
        // `lock`'s `Drop`, which now runs inside `self.detach`'s closure
        // rather than at the end of this function -- see below.
        let lock = self.store.lock(self.lock_timeout).await?;

        let stored = self.store.load()?.ok_or(Error::NotEnrolled)?;
        // The store is shared with the CLI, whose `login` replaces the whole
        // installation. This process's client is fixed at construction, so a
        // changed store cannot be refreshed with it: refuse before sending.
        if stored.client_id() != self.client.client_id() {
            return Err(Error::InstallationChanged {
                running: self.client.client_id().to_owned(),
                stored: stored.client_id().to_owned(),
            });
        }
        let tokens = self.client.refresh(stored.refresh_token()).await?;

        // Persist before returning the access token. A crash between the
        // server rotating and this write leaves the stored token dead, and
        // that window cannot be closed without the server accepting either
        // token -- but that window is only unavoidable for a real crash. Run
        // through `self.detach` rather than called inline, this write cannot
        // be cut short by *this process's own* cancellation of whatever task
        // is currently awaiting it: see [`Detach`].
        //
        // Unconditional: a response that carried no rotated refresh token never
        // becomes a `TokenResponse` at all, so the `?` above has already
        // returned and the store still holds what it held. That is the point --
        // the old branch here logged a warning, kept the spent token, and
        // handed the caller an access token, so a session that was already over
        // reported success and bought five more minutes.
        let store = Arc::clone(&self.store);
        let client_id = self.client.client_id().to_owned();
        let new_refresh_token = tokens.refresh_token().to_owned();
        let (persisted_tx, persisted_rx) = tokio::sync::oneshot::channel();
        (self.detach)(Box::new(move || {
            let result = store.rotate_refresh_token(&lock, &client_id, &new_refresh_token);
            // Ignored: a receiver that is gone means the caller that wanted
            // this refresh was itself cancelled after the write was already
            // underway, which is exactly the case this exists to make safe --
            // the write still happened, there is simply nobody left waiting
            // to hear about it.
            let _ = persisted_tx.send(result);
        }));
        // The channel closing without a value means `self.detach` dropped the
        // closure instead of running it, which is a bug in whatever supplied
        // it, not a normal outcome for `refresh_now`'s caller to route through
        // `Result`.
        persisted_rx.await.expect("a Detach must always run the closure it is given")?;

        let access_token = tokens.access_token().to_owned();
        self.cache(&tokens);
        Ok(access_token)
    }

    fn fresh_enough(&self) -> Option<String> {
        let cached = self.cached.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let cached = cached.as_ref()?;
        (cached.expires_at > Instant::now() + self.refresh_skew)
            .then(|| cached.access_token.clone())
    }

    fn cache(&self, tokens: &TokenResponse) {
        // The server's own lifetime, never a guess: a `TokenResponse` cannot
        // exist without a non-zero `expires_in`.
        let mut cached = self.cached.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *cached = Some(Cached {
            access_token: tokens.access_token().to_owned(),
            expires_at: Instant::now() + tokens.expires_in(),
        });
    }
}

#[cfg(test)]
mod tests;
