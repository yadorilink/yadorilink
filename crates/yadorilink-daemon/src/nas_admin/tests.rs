use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::coordination_client::DeviceListingError;

fn peer(seed: u8) -> PeerId {
    PeerId::from_bytes([seed; 32])
}

/// An account listing `keys`, or failing when `keys` is `None`, counting how
/// often it was asked.
fn account(keys: Option<Vec<u8>>) -> (AccountDevices, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let devices = AccountDevices::new(Box::new(move || {
        counted.fetch_add(1, Ordering::SeqCst);
        let keys = keys.clone();
        Box::pin(async move {
            keys.map(|seeds| seeds.into_iter().map(|seed| [seed; 32]).collect::<HashSet<_>>())
                .ok_or_else(|| DeviceListingError::Refused("refused".to_string()))
        })
    }));
    (devices, calls)
}

#[tokio::test]
async fn a_device_on_the_account_is_admitted_and_any_other_is_refused() {
    let (devices, _) = account(Some(vec![1, 2]));
    assert!(devices.admits(peer(1)).await);
    assert!(devices.admits(peer(2)).await);
    // A folder-sharing peer on another account is not in the listing.
    assert!(!devices.admits(peer(3)).await);
}

#[tokio::test]
async fn a_listing_that_cannot_be_had_refuses_everyone() {
    let (devices, _) = account(None);
    assert!(!devices.admits(peer(1)).await, "no listing, no management");
}

/// An authenticated stranger can make this device ask, but not more often
/// than the listing's lifetime: a fresh listing answers unknown keys itself.
#[tokio::test]
async fn unknown_devices_do_not_make_the_device_ask_again() {
    let (devices, calls) = account(Some(vec![1]));
    for seed in 10..40 {
        assert!(!devices.admits(peer(seed)).await);
    }
    assert!(devices.admits(peer(1)).await);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let (failing, calls) = account(None);
    for seed in 10..40 {
        assert!(!failing.admits(peer(seed)).await);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1, "a failed listing is held, not retried per call");
}

/// One scripted answer per listing; the last one repeats.
type Answer = Result<Vec<u8>, DeviceListingError>;

fn unreachable() -> Answer {
    Err(DeviceListingError::Unreachable("no answer".to_string()))
}

fn refused() -> Answer {
    Err(DeviceListingError::Refused("HTTP 401".to_string()))
}

/// An account whose listings answer `answers` in turn, with short periods:
/// a listing is fresh for 50 ms and a failure is retried after 10 ms.
fn scripted(answers: Vec<Answer>) -> AccountDevices {
    let answers = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::from(answers)));
    AccountDevices::new(Box::new(move || {
        let mut answers = answers.lock().unwrap();
        let answer = if answers.len() > 1 { answers.pop_front() } else { answers.front().cloned() };
        Box::pin(async move {
            answer
                .expect("an answer")
                .map(|seeds| seeds.into_iter().map(|seed| [seed; 32]).collect::<HashSet<_>>())
        })
    }))
    .with_periods(Duration::from_millis(50), Duration::from_millis(10))
}

/// Long enough for a fresh listing (and any failure hold) to have lapsed.
async fn next_listing() {
    tokio::time::sleep(Duration::from_millis(80)).await;
}

#[tokio::test]
async fn an_unreachable_plane_keeps_the_last_listing_answering() {
    let devices = scripted(vec![Ok(vec![1]), unreachable()]);
    assert!(devices.admits(peer(1)).await);
    for _ in 0..3 {
        next_listing().await;
        assert!(devices.admits(peer(1)).await, "the last listing still answers");
        assert!(!devices.admits(peer(2)).await, "and still refuses who it did not list");
    }
}

#[tokio::test]
async fn the_last_listing_stops_answering_once_it_is_too_old() {
    let devices = scripted(vec![Ok(vec![1]), unreachable()])
        .serving_last_listing_for(Duration::from_millis(200));
    assert!(devices.admits(peer(1)).await);
    next_listing().await;
    assert!(devices.admits(peer(1)).await, "younger than the limit");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!devices.admits(peer(1)).await, "older than the limit: nobody is admitted");
}

/// A NAS that suspends while the plane is down: its monotonic clock stops,
/// the wall clock does not, and the listing's age is real time. A wall clock
/// set back never makes the listing younger than the time spent awake.
#[tokio::test]
async fn the_last_listing_ages_in_real_time_across_a_suspend() {
    let offset = Arc::new(std::sync::Mutex::new(Duration::ZERO));
    let back = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let start = std::time::SystemTime::now();
    let wall = {
        let offset = offset.clone();
        Box::new(move || std::time::SystemTime::now() + *offset.lock().unwrap())
    };
    let devices = scripted(vec![Ok(vec![1]), unreachable()]).with_wall_clock(wall);
    assert!(devices.admits(peer(1)).await);
    next_listing().await;
    assert!(devices.admits(peer(1)).await, "an outage, not yet a day");

    // Slept for 25 h: no time passed for `Instant`.
    *offset.lock().unwrap() = Duration::from_secs(25 * 60 * 60);
    next_listing().await;
    assert!(!devices.admits(peer(1)).await, "more than a day of real time has passed");

    // The wall clock set back an hour before the fetch: the time spent
    // awake still counts, so a short limit still runs out.
    let devices = scripted(vec![Ok(vec![1]), unreachable()])
        .serving_last_listing_for(Duration::from_millis(200))
        .with_wall_clock({
            let back = back.clone();
            Box::new(move || {
                if back.load(Ordering::SeqCst) {
                    start - Duration::from_secs(3600)
                } else {
                    std::time::SystemTime::now()
                }
            })
        });
    assert!(devices.admits(peer(1)).await);
    back.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(!devices.admits(peer(1)).await, "awake time is the floor");
}

/// Suspend with the wall clock set back: the suspend-aware clock
/// advances 25 h, the wall clock does not, and the listing is still too old.
#[tokio::test]
async fn a_suspend_with_the_wall_clock_set_back_still_ages_the_listing() {
    let mono = Arc::new(std::sync::Mutex::new(Duration::from_secs(1000)));
    let fixed_wall = std::time::SystemTime::now();
    let devices = scripted(vec![Ok(vec![1]), unreachable()])
        .with_wall_clock(Box::new(move || fixed_wall))
        .with_mono_clock({
            let mono = mono.clone();
            Box::new(move || Some(*mono.lock().unwrap()))
        });
    assert!(devices.admits(peer(1)).await);
    next_listing().await;
    assert!(devices.admits(peer(1)).await, "an outage, not yet a day");
    *mono.lock().unwrap() += Duration::from_secs(25 * 60 * 60);
    next_listing().await;
    assert!(
        !devices.admits(peer(1)).await,
        "the suspend counts although the wall clock did not move"
    );
}

/// A monotonic clock that cannot be read never shortens the age.
#[tokio::test]
async fn an_unreadable_monotonic_clock_fails_closed() {
    let readable = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let devices = scripted(vec![Ok(vec![1]), unreachable()]).with_mono_clock({
        let readable = readable.clone();
        Box::new(move || readable.load(Ordering::SeqCst).then_some(Duration::from_secs(5)))
    });
    assert!(devices.admits(peer(1)).await);
    next_listing().await;
    assert!(devices.admits(peer(1)).await);
    readable.store(false, Ordering::SeqCst);
    next_listing().await;
    assert!(!devices.admits(peer(1)).await, "unknown age is treated as too old");
}

#[cfg(target_os = "linux")]
#[test]
fn the_linux_boot_clock_is_readable_and_does_not_go_backwards() {
    let a = suspend_aware_now().expect("CLOCK_BOOTTIME is readable");
    let b = suspend_aware_now().expect("CLOCK_BOOTTIME is readable");
    assert!(b >= a);
}

#[test]
fn the_last_listing_answers_for_a_day() {
    assert_eq!(LAST_LISTING_SERVES_FOR, Duration::from_secs(24 * 60 * 60));
}

/// A device a newer listing leaves out (signed out, or removed) is refused
/// at once, and an outage after that never brings an older listing back.
#[tokio::test]
async fn a_device_a_fresh_listing_leaves_out_is_never_readmitted_from_an_older_one() {
    let devices = scripted(vec![Ok(vec![1, 2]), Ok(vec![2]), unreachable()]);
    assert!(devices.admits(peer(1)).await);
    next_listing().await;
    assert!(!devices.admits(peer(1)).await, "left out by the fresh listing");
    for _ in 0..3 {
        next_listing().await;
        assert!(!devices.admits(peer(1)).await, "the plane is down; still refused");
        assert!(devices.admits(peer(2)).await, "the device still listed is still admitted");
    }
}

/// A refused listing (this device's own credential rejected) is not an
/// outage: it refuses everyone at once and drops the last listing.
#[tokio::test]
async fn a_refused_listing_refuses_everyone_and_the_last_listing_is_dropped() {
    let devices = scripted(vec![Ok(vec![1]), refused(), unreachable()]);
    assert!(devices.admits(peer(1)).await);
    next_listing().await;
    assert!(!devices.admits(peer(1)).await, "refused, not unreachable");
    next_listing().await;
    assert!(!devices.admits(peer(1)).await, "an outage after it does not restore the old listing");
}

#[test]
fn only_an_explicit_setting_offers_management() {
    let set = |v: &str| Ok(v.to_string());
    assert!(offered_by(set("1")));
    assert!(offered_by(set("true")));
    assert!(offered_by(set(" TRUE ")));
    for off in ["", "0", "false", "yes", "on", "2"] {
        assert!(!offered_by(set(off)), "{off:?}");
    }
    assert!(!offered_by(Err(std::env::VarError::NotPresent)));
}

/// The headless unit is what sets the offer: it is in the unit (replaced on
/// every upgrade), not in the admin-edited settings file, so an upgraded NAS
/// offers management without anyone editing anything.
#[test]
fn the_headless_unit_offers_management_and_the_desktop_unit_does_not() {
    let headless = include_str!("../../../../packaging/linux/systemd/yadorilink-headless.service");
    assert!(headless.lines().any(|line| line.trim() == format!("Environment={OFFER_ENV}=1")));
    let desktop = include_str!("../../../../packaging/linux/systemd/yadorilink-daemon.service");
    assert!(!desktop.contains(OFFER_ENV));
}

#[test]
fn without_a_running_dashboard_the_service_is_unavailable() {
    assert!(!Dashboard { streams: None }.available());
}

/// The handler has nowhere to send a stream but the dashboard it was given:
/// no address, no socket, and the only coordination call is the device
/// listing, which carries no management bytes.
#[test]
fn the_handler_resolves_no_address_and_sends_nothing_but_the_listing_request() {
    let source = include_str!("../nas_admin.rs");
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in
        ["SocketAddr", "TcpStream", "TcpListener", "UnixStream", "ToSocketAddrs", "PORT_FILE_NAME"]
    {
        assert!(!code.contains(forbidden), "nas_admin.rs must not use {forbidden}");
    }
    // Functions (lower-case names) only: the listing's error type is named too.
    let coordination_calls: Vec<&str> = code
        .split("coordination_client::")
        .skip(1)
        .filter_map(|rest| rest.split(|c: char| !(c.is_alphanumeric() || c == '_')).next())
        .filter(|name| name.starts_with(|c: char| c.is_ascii_lowercase()))
        .collect();
    assert_eq!(coordination_calls, vec!["list_account_device_keys"]);
}

/// End to end on the NAS side: a real device connection, a real management
/// stream, handed in-process to a real dashboard. A page and an API request
/// come back with no token and with the managing browser's own port in
/// `Host`; a state change without `Origin` is still refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_management_stream_reaches_the_running_dashboard_without_a_token() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use yadorilink_sync_substrate::{AdmitNone, NetworkConfig, SubstrateNode};

    let dir = tempfile::tempdir().unwrap();
    let config = yadorilink_http_api::HttpApiConfig {
        #[cfg(unix)]
        control_socket_path: dir.path().join("absent.sock"),
        #[cfg(windows)]
        control_pipe_name: r"\\.\pipe\yadorilink-absent-for-test".to_string(),
        token_path: dir.path().join("http-api-token"),
        port_path: dir.path().join("http-api-port"),
        port: 0,
        extra_allowed_origins: Vec::new(),
    };
    let handle = yadorilink_http_api::bind(&config).await.unwrap();
    let dashboard = Dashboard { streams: Some(handle.peer_streams()) };
    let serving = tokio::spawn(yadorilink_http_api::run(handle));

    let (mac_seed, nas_seed) = ([41u8; 32], [42u8; 32]);
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let (mac, _) =
        SubstrateNode::spawn_as_device(mac_seed, NetworkConfig::direct_only(), Arc::new(AdmitNone))
            .await
            .unwrap();
    let mac_id = mac.peer_id();
    let authorizer: Arc<dyn NasAdminAuthorizer> = Arc::new(AccountDevices::new(Box::new({
        let mac_key = *mac_id.as_bytes();
        move || Box::pin(async move { Ok(HashSet::from([mac_key])) })
    })));
    let (nas, _) = SubstrateNode::spawn_as_device(
        nas_seed,
        NetworkConfig::direct_only().with_nas_admin(authorizer.clone(), tx),
        Arc::new(AdmitNone),
    )
    .await
    .unwrap();
    let service = NasAdminService::new(authorizer, Arc::new(dashboard), NasAdminLimits::default());
    tokio::spawn(async move {
        while let Some(connection) = rx.recv().await {
            tokio::spawn(service.clone().serve(connection));
        }
    });

    let connection = mac.connect_nas_admin(&nas.local_address()).await.expect("connects");
    let exchange = |request: String| {
        let connection = connection.clone();
        async move {
            let mut stream = connection.open_stream().await.expect("the dashboard is ready");
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(15), stream.read_to_end(&mut response))
                .await
                .expect("response in time")
                .unwrap();
            String::from_utf8_lossy(&response).into_owned()
        }
    };
    let host = "127.0.0.1:53111";
    let page =
        exchange(format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")).await;
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    let api =
        exchange(format!("GET /api/status HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"))
            .await;
    assert!(
        !api.starts_with("HTTP/1.1 401") && !api.starts_with("HTTP/1.1 403"),
        "no token is asked of a device-authorized request: {api}"
    );
    let change = exchange(format!(
        "POST /api/pause HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
    ))
    .await;
    assert!(change.starts_with("HTTP/1.1 403"), "{change}");

    // The dashboard stops: the next stream is told so, and nothing else answers.
    serving.abort();
    let _ = serving.await;
    assert_eq!(
        connection.open_stream().await.err(),
        Some(yadorilink_sync_substrate::NasAdminError::Unavailable)
    );
}

/// Keeps every stream it is handed open, as a dashboard serving a
/// long-lived connection (a WebSocket, a keep-alive page) does.
#[derive(Default)]
struct Holding(std::sync::Mutex<Vec<NasAdminStream>>);

impl NasAdminEndpoint for Holding {
    fn available(&self) -> bool {
        true
    }

    fn deliver(&self, stream: NasAdminStream) {
        self.0.lock().unwrap().push(stream);
    }
}

/// `mac`'s next management connection to `nas` is refused.
async fn refused_from(
    mac: &yadorilink_sync_substrate::SubstrateNode,
    nas: &yadorilink_sync_substrate::SubstrateNode,
) {
    use yadorilink_sync_substrate::NasAdminError;
    let refusal = match mac.connect_nas_admin(&nas.local_address()).await {
        Ok(connection) => connection.open_stream().await.err(),
        Err(error) => Some(error),
    };
    assert_eq!(refusal, Some(NasAdminError::Unauthorized));
}

/// A NAS whose management authorizer lists devices through the real
/// `GET /devices` client against a stand-in coordination plane, and a Mac
/// the plane lists. Short periods (300 ms listing, retry and recheck) stand
/// in for the real ones.
struct ManagedNas {
    mac: yadorilink_sync_substrate::SubstrateNode,
    nas: yadorilink_sync_substrate::SubstrateNode,
    plane: wiremock::MockServer,
    mac_key: String,
}

const PERIOD: Duration = Duration::from_millis(300);

impl ManagedNas {
    async fn start(seed: u8) -> Self {
        use base64::Engine as _;
        use yadorilink_sync_substrate::{AdmitNone, NetworkConfig, SubstrateNode};

        let (mac, _) = SubstrateNode::spawn_as_device(
            [seed; 32],
            NetworkConfig::direct_only(),
            Arc::new(AdmitNone),
        )
        .await
        .unwrap();
        let mac_key = base64::engine::general_purpose::STANDARD.encode(mac.peer_id().as_bytes());
        let plane = wiremock::MockServer::start().await;
        let addr = plane.uri();
        let authorizer: Arc<dyn NasAdminAuthorizer> = Arc::new(
            AccountDevices::new(Box::new(move || {
                let addr = addr.clone();
                Box::pin(async move {
                    let auth = yadorilink_fapi_client::test_support::offline_auth();
                    Ok(crate::coordination_client::list_account_device_keys(&addr, &auth)
                        .await?
                        .into_iter()
                        .collect())
                })
            }))
            .with_periods(PERIOD, PERIOD),
        );
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let (nas, _) = SubstrateNode::spawn_as_device(
            [seed + 1; 32],
            NetworkConfig::direct_only().with_nas_admin(authorizer.clone(), tx),
            Arc::new(AdmitNone),
        )
        .await
        .unwrap();
        let limits = NasAdminLimits { recheck: PERIOD, ..NasAdminLimits::default() };
        let service = NasAdminService::new(authorizer, Arc::new(Holding::default()), limits);
        tokio::spawn(async move {
            while let Some(connection) = rx.recv().await {
                tokio::spawn(service.clone().serve(connection));
            }
        });
        Self { mac, nas, plane, mac_key }
    }

    /// From now on the plane answers `GET /devices` with `response`.
    async fn answers(&self, response: wiremock::ResponseTemplate) {
        use wiremock::matchers::{method, path};
        self.plane.reset().await;
        wiremock::Mock::given(method("GET"))
            .and(path("/devices"))
            .respond_with(response)
            .mount(&self.plane)
            .await;
    }

    /// The plane lists the Mac, signed out or not.
    async fn lists_mac(&self, signed_out: bool) {
        self.answers(wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "devices": [{
                "deviceId": "mac", "deviceName": "Mac",
                "signingPublicKeyBase64": self.mac_key, "signedOut": signed_out,
            }]
        })))
        .await;
    }

    /// A management stream from the Mac, held open.
    async fn held_stream(&self) -> NasAdminStream {
        let connection =
            self.mac.connect_nas_admin(&self.nas.local_address()).await.expect("connects");
        connection.open_stream().await.expect("admitted")
    }

    /// The Mac's next management connection is refused.
    async fn mac_is_refused(&self) {
        refused_from(&self.mac, &self.nas).await;
    }
}

/// Signing out reaches a stream the device already holds: the real listing
/// parser reads `signedOut: true` from the plane, the per-connection recheck
/// closes the connection, and neither a new connection nor the plane going
/// down afterwards lets the device back in.
#[tokio::test(flavor = "multi_thread")]
async fn a_signed_out_device_loses_the_stream_it_holds_and_stays_refused() {
    use tokio::io::AsyncReadExt as _;

    let managed = ManagedNas::start(61).await;
    managed.lists_mac(false).await;
    let mut held = managed.held_stream().await;

    managed.lists_mac(true).await;
    let mut byte = [0u8; 1];
    let ended = tokio::time::timeout(Duration::from_secs(5), held.read(&mut byte))
        .await
        .expect("the held stream ends within the recheck, with nothing new opened");
    assert!(matches!(ended, Ok(0) | Err(_)), "{ended:?}");
    managed.mac_is_refused().await;

    // The plane goes down (5xx, which is "unreachable", not a refusal): the
    // listing that admitted the device is gone for good, so the outage does
    // not bring it back.
    managed.answers(wiremock::ResponseTemplate::new(503)).await;
    tokio::time::sleep(PERIOD * 2).await;
    managed.mac_is_refused().await;
}

/// The plane going down is not a reason to cut a device off: the held
/// stream survives several rechecks and a new connection is admitted, on
/// the last listing. A 401 for this NAS's own credential is a refusal, not
/// an outage: it ends the stream at the next recheck.
#[tokio::test(flavor = "multi_thread")]
async fn an_outage_keeps_the_session_and_a_refused_credential_ends_it() {
    use tokio::io::AsyncReadExt as _;

    let managed = ManagedNas::start(81).await;
    managed.lists_mac(false).await;
    let mut held = managed.held_stream().await;

    managed.answers(wiremock::ResponseTemplate::new(503)).await;
    let mut byte = [0u8; 1];
    assert!(
        tokio::time::timeout(PERIOD * 5, held.read(&mut byte)).await.is_err(),
        "the held stream outlives several rechecks while the plane is down"
    );
    let _another = managed.held_stream().await;

    managed.answers(wiremock::ResponseTemplate::new(401)).await;
    let ended = tokio::time::timeout(Duration::from_secs(5), held.read(&mut byte))
        .await
        .expect("a refused credential ends the held stream");
    assert!(matches!(ended, Ok(0) | Err(_)), "{ended:?}");
    managed.mac_is_refused().await;
}

/// Management is offered only by a daemon whose profile turns it on: the
/// desktop one refuses the handshake as an older build does, and the
/// headless one accepts it (and then refuses this device, which nothing
/// lists, since it is not signed in).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_a_daemon_that_offers_management_accepts_its_protocol() {
    use crate::sync_adapter::sync_stack::SyncStack;
    use crate::test_support::sync_stack_fixture::device;
    use yadorilink_sync_substrate::{AdmitNone, NasAdminError, NetworkConfig, SubstrateNode};

    let (mac, _) = SubstrateNode::spawn_as_device(
        [71u8; 32],
        NetworkConfig::direct_only(),
        Arc::new(AdmitNone),
    )
    .await
    .unwrap();

    let (desktop, _desktop_dir) = device("device-desktop", 72);
    let desktop = SyncStack::spawn_offering(desktop, NetworkConfig::direct_only(), false)
        .await
        .expect("the desktop stack starts");
    assert_eq!(
        mac.connect_nas_admin(&desktop.local_address()).await.err(),
        Some(NasAdminError::Unsupported),
        "a desktop does not answer the management protocol"
    );

    let (headless, _headless_dir) = device("device-headless", 73);
    let headless = SyncStack::spawn_offering(headless, NetworkConfig::direct_only(), true)
        .await
        .expect("the headless stack starts");
    let answered = match mac.connect_nas_admin(&headless.local_address()).await {
        Ok(connection) => connection.open_stream().await.err(),
        Err(error) => Some(error),
    };
    assert_eq!(answered, Some(NasAdminError::Unauthorized), "accepted, then authorized");

    desktop.shutdown().await;
    headless.shutdown().await;
}
