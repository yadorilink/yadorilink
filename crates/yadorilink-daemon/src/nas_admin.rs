//! Managing this device from another device on the same account.
//!
//! The substrate answers the management ALPN (`yadorilink-sync-substrate`'s
//! `nas_admin`); this module supplies its two answers:
//!
//! - who may manage this device: [`AccountDevices`], the devices the
//!   coordination plane lists on this device's own account and does not
//!   mark signed out, checked against the key each one proved in its
//!   handshake. A folder-sharing peer is in the netmap, not in that list,
//!   unless it is on the same account. While the plane cannot be reached
//!   the last listing it gave keeps answering, for at most
//!   [`LAST_LISTING_SERVES_FOR`].
//!
//! Offered only where the engine tuning's `offer_nas_admin` (the desktop daemon maps
//! `YADORILINK_NAS_ADMIN` into it) turns it on: the headless (system
//! service) profile. Elsewhere the ALPN is not registered at all, so a
//! dialler is refused at the handshake exactly as by an older build.
//! - where an authorized stream goes: this device's own dashboard, handed
//!   the stream in-process ([`yadorilink_http_api::PeerStreams`]). No
//!   address is resolved and no socket is opened, so nothing here can be
//!   pointed anywhere else; when the dashboard is not serving, the stream is
//!   answered "unavailable" and nothing else is offered.
//!
//! Only the device list crosses the coordination plane. Management bytes
//! travel on the device connection alone.

use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime};

use yadorilink_http_api::PeerStreams;
use yadorilink_sync_substrate::{
    NasAdminAuthorizer, NasAdminEndpoint, NasAdminLimits, NasAdminService, NasAdminStream, PeerId,
};

use crate::coordination_client::DeviceListingError;
use crate::daemon_state::DaemonState;

/// How long one device listing answers for. Bounds both how long a removed
/// device can keep opening streams and how often anyone (an authenticated
/// stranger included) can make this device ask the coordination plane.
const LISTING_FRESH_FOR: Duration = Duration::from_secs(30);

/// How long the last listing the coordination plane gave keeps answering
/// while the plane cannot be reached (no answer, a timeout or a 5xx). A
/// product decision: a NAS cut off from the internet stays manageable from
/// the LAN for a day, and after that management refuses everyone until the
/// plane answers again (ssh is the fallback). Measured in real time, a
/// suspended machine's sleep included (see [`Fetched::age`]). It never covers
/// a refusal: a
/// 401/403, an unusable listing, or a listing that leaves a device out ends
/// that device's (or everyone's) admission at once.
pub(crate) const LAST_LISTING_SERVES_FOR: Duration = Duration::from_secs(24 * 60 * 60);

/// How long after a failed listing the next attempt waits. Until then the
/// failure stands: the last listing (unreachable) or nobody (refused).
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(5);

/// How long one device listing may take before it counts as unreachable.
const LISTING_TIMEOUT: Duration = Duration::from_secs(10);

/// How often [`run`] checks whether the device endpoint exists yet.
const ENDPOINT_POLL_INTERVAL: Duration = Duration::from_millis(500);

type Keys = Arc<HashSet<[u8; 32]>>;
type WallClock = Box<dyn Fn() -> SystemTime + Send + Sync>;
type MonoClock = Box<dyn Fn() -> Option<Duration> + Send + Sync>;

/// When a listing was fetched, on two clocks.
#[derive(Clone, Copy)]
struct Fetched {
    /// [`suspend_aware_now`] at the fetch; `None` when it could not be read.
    mono: Option<Duration>,
    wall: SystemTime,
}

/// Time since an arbitrary point that keeps counting while the machine is
/// suspended: `CLOCK_BOOTTIME` on Linux. `None` when the clock cannot be
/// read (the caller then treats the age as unbounded: fail closed).
/// Elsewhere it is the process's `Instant` clock, which on those platforms
/// is the best this module has (the wall clock still covers the sleep).
#[cfg(target_os = "linux")]
fn suspend_aware_now() -> Option<Duration> {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid, writable timespec for the call's duration.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    if rc != 0 || ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
        return None;
    }
    Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

#[cfg(not(target_os = "linux"))]
fn suspend_aware_now() -> Option<Duration> {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    Some(START.get_or_init(Instant::now).elapsed())
}

impl Fetched {
    /// How old the listing is: the larger of the wall-clock time since it
    /// was fetched and the suspend-aware monotonic time since then (see
    /// [`suspend_aware_now`]). The monotonic time is the floor, so setting
    /// the wall clock back can never make a listing younger than the real
    /// time that has passed, sleep included. Setting the wall clock forward
    /// only ages the listing sooner (fail closed), and so does a monotonic
    /// clock that cannot be read: the age is then unbounded.
    fn age(&self, mono: Option<Duration>, wall: SystemTime) -> Duration {
        let Some((then, now)) = self.mono.zip(mono) else {
            return Duration::MAX;
        };
        wall.duration_since(self.wall).unwrap_or_default().max(now.saturating_sub(then))
    }
}
type ListingFuture =
    Pin<Box<dyn Future<Output = Result<HashSet<[u8; 32]>, DeviceListingError>> + Send>>;
type FetchListing = Box<dyn Fn() -> ListingFuture + Send + Sync>;

/// What the listing has said so far.
struct Known {
    /// The last listing the plane gave, and when. Replaced by every newer
    /// one, so a device a newer listing leaves out (signed out, removed) is
    /// never admitted again from an older one. Cleared by a refusal.
    listed: Option<(Fetched, Keys)>,
    /// No new listing is asked for before this.
    next_attempt: Instant,
}

/// The account's devices, by signing key, as last listed.
pub(crate) struct AccountDevices {
    fetch: FetchListing,
    /// `SystemTime::now`, replaced by a test that simulates a suspend.
    wall_clock: WallClock,
    /// [`suspend_aware_now`], replaced by a test that simulates a suspend.
    mono_clock: MonoClock,
    known: Mutex<Known>,
    /// One listing at a time; callers that waited reuse its answer.
    refreshing: tokio::sync::Mutex<()>,
    /// [`LISTING_FRESH_FOR`], [`RETRY_AFTER_FAILURE`] and
    /// [`LAST_LISTING_SERVES_FOR`], shortened by tests.
    fresh_for: Duration,
    retry_after: Duration,
    serves_for: Duration,
}

impl std::fmt::Debug for AccountDevices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccountDevices(..)")
    }
}

impl AccountDevices {
    pub(crate) fn new(fetch: FetchListing) -> Self {
        Self {
            fetch,
            wall_clock: Box::new(SystemTime::now),
            mono_clock: Box::new(suspend_aware_now),
            known: Mutex::new(Known { listed: None, next_attempt: Instant::now() }),
            refreshing: tokio::sync::Mutex::new(()),
            fresh_for: LISTING_FRESH_FOR,
            retry_after: RETRY_AFTER_FAILURE,
            serves_for: LAST_LISTING_SERVES_FOR,
        }
    }

    /// The same listing with shorter periods, so a test can watch a
    /// withdrawal take effect without waiting out the real ones.
    #[cfg(test)]
    pub(crate) fn with_periods(mut self, fresh_for: Duration, retry_after: Duration) -> Self {
        self.fresh_for = fresh_for;
        self.retry_after = retry_after;
        self
    }

    /// A shorter [`LAST_LISTING_SERVES_FOR`], for a test.
    #[cfg(test)]
    pub(crate) fn serving_last_listing_for(mut self, serves_for: Duration) -> Self {
        self.serves_for = serves_for;
        self
    }

    /// A wall clock of the test's choosing, to simulate a suspend (the wall
    /// clock moves on while `Instant` does not).
    #[cfg(test)]
    pub(crate) fn with_wall_clock(mut self, wall_clock: WallClock) -> Self {
        self.wall_clock = wall_clock;
        self
    }

    /// A monotonic clock of the test's choosing, which can advance across a
    /// simulated suspend or fail.
    #[cfg(test)]
    pub(crate) fn with_mono_clock(mut self, mono_clock: MonoClock) -> Self {
        self.mono_clock = mono_clock;
        self
    }

    /// The production listing: `GET /devices` with this device's own
    /// credential. A device that is not signed in lists nobody.
    pub(crate) fn of(state: &Arc<DaemonState>) -> Self {
        let state: Weak<DaemonState> = Arc::downgrade(state);
        Self::new(Box::new(move || {
            let state = state.clone();
            Box::pin(async move {
                let refused = |why: &str| DeviceListingError::Refused(why.to_string());
                let state = state.upgrade().ok_or_else(|| refused("the daemon is stopping"))?;
                let config = state
                    .coordination_client_config()
                    .ok_or_else(|| refused("this device is not signed in"))?;
                let keys = crate::coordination_client::list_account_device_keys(
                    &config.addr,
                    &config.auth,
                )
                .await?;
                Ok(keys.into_iter().collect())
            })
        }))
    }

    /// The answer without asking the plane, or `None` when it is time to ask.
    fn settled(&self, now: Instant) -> Option<Option<Keys>> {
        let known = self.known.lock().unwrap_or_else(|p| p.into_inner());
        (now < known.next_attempt).then(|| self.usable(&known))
    }

    /// The last listing, while it may still answer.
    fn usable(&self, known: &Known) -> Option<Keys> {
        let wall = (self.wall_clock)();
        let mono = (self.mono_clock)();
        known
            .listed
            .as_ref()
            .filter(|(fetched, _)| fetched.age(mono, wall) < self.serves_for)
            .map(|(_, keys)| keys.clone())
    }

    async fn admits(&self, peer: PeerId) -> bool {
        let admits = |keys: Option<Keys>| keys.is_some_and(|keys| keys.contains(peer.as_bytes()));
        if let Some(keys) = self.settled(Instant::now()) {
            return admits(keys);
        }
        let _one_at_a_time = self.refreshing.lock().await;
        if let Some(keys) = self.settled(Instant::now()) {
            return admits(keys);
        }
        // Bounded: the lock above makes every other caller wait on this one,
        // so a listing that never answers must not hold management shut.
        let listed =
            tokio::time::timeout(LISTING_TIMEOUT, (self.fetch)()).await.unwrap_or_else(|_| {
                Err(DeviceListingError::Unreachable("the device listing timed out".to_string()))
            });
        let now = Instant::now();
        let mut known = self.known.lock().unwrap_or_else(|p| p.into_inner());
        match listed {
            Ok(keys) => {
                let fetched = Fetched { mono: (self.mono_clock)(), wall: (self.wall_clock)() };
                known.listed = Some((fetched, Arc::new(keys)));
                known.next_attempt = now + self.fresh_for;
            }
            Err(DeviceListingError::Unreachable(error)) => {
                tracing::debug!(%error, "could not reach the device listing; using the last one");
                known.next_attempt = now + self.retry_after;
            }
            Err(DeviceListingError::Refused(error)) => {
                tracing::debug!(%error, "the device listing was refused; refusing management");
                known.listed = None;
                known.next_attempt = now + self.retry_after;
            }
        }
        admits(self.usable(&known))
    }
}

impl NasAdminAuthorizer for AccountDevices {
    fn authorize(&self, peer: PeerId) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        Box::pin(self.admits(peer))
    }
}

/// This device's dashboard, as the one place a management stream can go.
pub(crate) struct Dashboard {
    pub(crate) streams: Option<PeerStreams>,
}

impl NasAdminEndpoint for Dashboard {
    fn available(&self) -> bool {
        self.streams.as_ref().is_some_and(PeerStreams::is_serving)
    }

    fn deliver(&self, stream: NasAdminStream) {
        if let Some(streams) = &self.streams {
            streams.offer(Box::new(stream));
        }
    }
}

/// The bounds `run` serves with: every open connection is re-authorized as
/// often as the listing is refreshed.
pub(crate) fn production_limits() -> NasAdminLimits {
    NasAdminLimits { recheck: LISTING_FRESH_FOR, ..NasAdminLimits::default() }
}

/// Serves management connections for the life of the daemon.
///
/// Waits for the device endpoint, takes its management queue and serves each
/// connection. `dashboard` is `None` when the dashboard is disabled or did not
/// start; every stream is then answered "unavailable".
pub async fn run(
    state: Arc<DaemonState>,
    dashboard: Option<PeerStreams>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut inbound, authorizer) = loop {
        if let Some(driver) = state.peer_session_driver() {
            let endpoint = driver.stack().endpoint();
            let Some(taken) = endpoint.take_nas_admin_inbound() else {
                return Err("the management queue was already taken".into());
            };
            break taken;
        }
        tokio::time::sleep(ENDPOINT_POLL_INTERVAL).await;
    };
    // Re-authorized as often as the listing is refreshed, so a removed
    // device loses even the streams it holds within one listing period.
    let service = NasAdminService::new(
        authorizer,
        Arc::new(Dashboard { streams: dashboard }),
        production_limits(),
    );
    while let Some(connection) = inbound.recv().await {
        tokio::spawn(service.clone().serve(connection));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
