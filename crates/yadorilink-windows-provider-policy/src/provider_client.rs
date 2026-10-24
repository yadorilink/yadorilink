//! Typed requests of the provider-root protocol, each over one short-lived connection: the
//! extension handshake for the root first, then the request, then the matching response (other
//! messages the daemon may push on the connection, such as status updates, are skipped).
//!
//! A transport failure (unreachable daemon, timeout, a closed connection) is `None`, never an
//! empty success: a caller that reconciles the local namespace against an answer must not read
//! "could not ask" as "nothing there".

use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::runtime::Runtime;
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    ActivityKind, EnumerateChildrenRequest, ExtensionHandshake, MaterializeProgress,
    MaterializeToTempRequest, MaterializeToTempResponse, ProviderActivity,
    ProviderApplyChangeRequest, ProviderApplyChangeResponse, ProviderItem, ShellIpcMessage,
};

/// How the host reaches the daemon: one new connection per call. The Windows crate implements
/// it over the daemon's named pipe; a connection that cannot be made is an error, which every
/// request here turns into `None`.
#[allow(async_fn_in_trait)]
pub trait Connect {
    type Stream: AsyncRead + AsyncWrite + Unpin;
    async fn connect(&self) -> std::io::Result<Self::Stream>;
}

const ENUMERATE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long one materialization request may go without a progress message from the daemon (see
/// `call_unless`): a stall, not a total, so a window or a file that keeps arriving over a slow
/// route is never cut off by its size.
pub const MATERIALIZE_TIMEOUT: Duration = Duration::from_secs(40);
/// The request that records a whole version after its windows were delivered. The daemon
/// assembles the whole file from blocks it already has, which takes as long as the file is big;
/// nothing waits for it.
pub const RECORD_TIMEOUT: Duration = Duration::from_secs(600);
const APPLY_TIMEOUT: Duration = Duration::from_secs(60);
const EXTENSION_BUILD: &str = "1";
/// Children per enumeration page.
const PAGE_LIMIT: u32 = 500;
/// A folder never has more pages than this; a daemon that keeps returning page tokens is broken.
const MAX_PAGES: usize = 100_000;

/// The runtime blocking callers (the host's loop and the Cloud Files callbacks, which run on
/// operating-system threads at the same time) drive their requests on.
pub fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("failed to start the provider client runtime")
    })
}

/// Sends the handshake for `root` and `request`, then reads until `pick` accepts a message.
pub async fn exchange<S, T>(
    stream: &mut S,
    root: &[u8],
    request: Payload,
    pick: impl Fn(Payload) -> Option<T>,
) -> Option<T>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let handshake = Payload::ExtensionHandshake(ExtensionHandshake {
        root_id: root.to_vec(),
        extension_build: EXTENSION_BUILD.into(),
    });
    write_message(stream, &ShellIpcMessage { payload: Some(handshake) }).await.ok()?;
    write_message(stream, &ShellIpcMessage { payload: Some(request) }).await.ok()?;
    loop {
        match read_message::<ShellIpcMessage>(stream).await {
            Ok(Some(ShellIpcMessage { payload: Some(payload) })) => {
                if let Some(answer) = pick(payload) {
                    return Some(answer);
                }
            }
            Ok(Some(_)) => {}
            _ => return None,
        }
    }
}

fn call<T>(
    connector: &impl Connect,
    timeout: Duration,
    root: &[u8],
    request: Payload,
    pick: impl Fn(Payload) -> Option<T>,
) -> Option<T> {
    call_unless(connector, timeout, &AtomicBool::new(false), root, request, pick)
}

/// [`call`] that gives up as soon as `cancel` is set: the connection is dropped, which makes the
/// daemon abort the request.
///
/// `timeout` is how long the request may go without a sign of life, not its total duration: every
/// progress message of the daemon starts it over, so a long transfer that keeps moving is never cut
/// off, and one that stalls for `timeout` is. A request the daemon does not report progress for
/// is bounded in total, as before.
fn call_unless<T>(
    connector: &impl Connect,
    timeout: Duration,
    cancel: &AtomicBool,
    root: &[u8],
    request: Payload,
    pick: impl Fn(Payload) -> Option<T>,
) -> Option<T> {
    runtime().block_on(async {
        let last_sign = Cell::new(Instant::now());
        let work = async {
            let mut stream = connector.connect().await.ok()?;
            exchange(&mut stream, root, request, |payload| {
                if matches!(payload, Payload::MaterializeProgress(_)) {
                    last_sign.set(Instant::now());
                }
                pick(payload)
            })
            .await
        };
        tokio::pin!(work);
        let cancelled = async {
            while !cancel.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        tokio::pin!(cancelled);
        loop {
            let stalled_at = tokio::time::Instant::from_std(last_sign.get() + timeout);
            tokio::select! {
                answer = &mut work => return answer,
                () = &mut cancelled => return None,
                () = tokio::time::sleep_until(stalled_at) => {
                    // A sign of life since this wait began moved the deadline: wait again.
                    if last_sign.get().elapsed() >= timeout {
                        return None;
                    }
                }
            }
        }
    })
}

/// Every child of folder `parent` (empty: the root container), all pages. `None` when any page
/// could not be confirmed.
pub fn enumerate_children(
    connector: &impl Connect,
    root: &[u8],
    parent: &[u8],
) -> Option<Vec<ProviderItem>> {
    let mut items = Vec::new();
    let mut page_token = Vec::new();
    for _ in 0..MAX_PAGES {
        let response = call(
            connector,
            ENUMERATE_TIMEOUT,
            root,
            Payload::EnumerateChildrenRequest(EnumerateChildrenRequest {
                root_id: root.to_vec(),
                parent_item_id: parent.to_vec(),
                page_token: page_token.clone(),
                limit: PAGE_LIMIT,
            }),
            |payload| match payload {
                Payload::EnumerateChildrenResponse(r) => Some(r),
                _ => None,
            },
        )?;
        if !response.ok {
            eprintln!(
                "yadorilink-cfapi-host: enumeration refused (failure {}): {}",
                response.failure, response.error
            );
            return None;
        }
        items.extend(response.items);
        if response.next_page_token.is_empty() {
            return Some(items);
        }
        page_token = response.next_page_token;
    }
    None
}

/// What a fetch asks the daemon for: the exact `version`, whole (`range` `None`) or only the
/// bytes `[offset, offset + length)` of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FetchTarget {
    pub version: [u8; 32],
    pub range: Option<(u64, u64)>,
}

/// The versions of the items the host has shown, by `(root, item)`: the version a placeholder
/// stands for, which is what a fetch of it asks the daemon for. Replaced as a whole per root
/// whenever the host records or loads what it shows.
type ShownVersions = std::sync::Mutex<std::collections::HashMap<(Vec<u8>, Vec<u8>), [u8; 32]>>;

fn shown_versions() -> &'static ShownVersions {
    static SHOWN: OnceLock<ShownVersions> = OnceLock::new();
    SHOWN.get_or_init(Default::default)
}

/// The version hash inside a 40-byte content version identifier (hash, then generation); `None`
/// for anything else.
pub fn version_hash_of(content_version: &[u8]) -> Option<[u8; 32]> {
    if content_version.len() != 40 {
        return None;
    }
    content_version[..32].try_into().ok()
}

/// Records the versions of the items now shown in `root`, replacing what was recorded for it.
pub fn set_shown_versions<'a>(root: &[u8], items: impl IntoIterator<Item = (&'a [u8], &'a [u8])>) {
    let mut shown = shown_versions().lock().unwrap();
    shown.retain(|(r, _), _| r != root);
    for (item, content_version) in items {
        if let Some(hash) = version_hash_of(content_version) {
            shown.insert((root.to_vec(), item.to_vec()), hash);
        }
    }
}

/// The version of `item` as shown in `root`; `None` when none was recorded.
pub fn shown_version(root: &[u8], item: &[u8]) -> Option<[u8; 32]> {
    shown_versions().lock().unwrap().get(&(root.to_vec(), item.to_vec())).copied()
}

/// The request for `item`: the current whole file (`target` `None`), or the exact version named
/// by `target`, whole or one window of it.
pub fn materialize_request(
    root: &[u8],
    item: &[u8],
    request_id: &[u8],
    target: Option<FetchTarget>,
) -> MaterializeToTempRequest {
    let range = target.and_then(|t| t.range);
    MaterializeToTempRequest {
        request_id: request_id.to_vec(),
        root_id: root.to_vec(),
        item_id: item.to_vec(),
        requested_version_hash: target.map_or_else(Vec::new, |t| t.version.to_vec()),
        ranged: range.is_some(),
        range_offset: range.map_or(0, |r| r.0),
        range_length: range.map_or(0, |r| r.1),
        // Set by the caller that wants progress; the default waits for the one response.
        report_progress: false,
    }
}

/// Asks the daemon for bytes of `item`, as a verified file in its handoff directory. A ranged
/// `target` is answered with only that window of that exact version (a daemon that predates
/// ranged requests answers with the whole file and `ranged` unset, see
/// [`MaterializeToTempResponse`]); a whole one with the whole file of that version, which the
/// daemon records as handed over; `None` with the whole current file.
pub fn materialize(
    connector: &impl Connect,
    root: &[u8],
    item: &[u8],
    request_id: &[u8],
    target: Option<FetchTarget>,
) -> Option<MaterializeToTempResponse> {
    materialize_within(
        connector,
        MATERIALIZE_TIMEOUT,
        &AtomicBool::new(false),
        root,
        item,
        request_id,
        target,
    )
}

/// [`materialize`] with its own `timeout`, abandoned (the connection dropped) once `cancel` is
/// set.
pub fn materialize_within(
    connector: &impl Connect,
    timeout: Duration,
    cancel: &AtomicBool,
    root: &[u8],
    item: &[u8],
    request_id: &[u8],
    target: Option<FetchTarget>,
) -> Option<MaterializeToTempResponse> {
    materialize_reporting(connector, timeout, cancel, root, item, request_id, target, None)
}

/// [`materialize_within`] that also asks the daemon for progress and passes each message for this
/// request to `on_progress` as `(completed, total)` bytes before the answer arrives. A daemon
/// that predates progress sends none, which is "no information", never "no progress".
#[allow(clippy::too_many_arguments)]
pub fn materialize_reporting(
    connector: &impl Connect,
    timeout: Duration,
    cancel: &AtomicBool,
    root: &[u8],
    item: &[u8],
    request_id: &[u8],
    target: Option<FetchTarget>,
    on_progress: Option<&dyn Fn(u64, u64)>,
) -> Option<MaterializeToTempResponse> {
    let mut request = materialize_request(root, item, request_id, target);
    request.report_progress = on_progress.is_some();
    call_unless(
        connector,
        timeout,
        cancel,
        root,
        Payload::MaterializeToTempRequest(request),
        move |payload| match payload {
            Payload::MaterializeToTempResponse(r) if r.request_id == request_id => Some(r),
            // A message for another request id is stale.
            Payload::MaterializeProgress(MaterializeProgress {
                request_id: id,
                completed,
                total,
                ..
            }) if id == request_id => {
                if let Some(report) = on_progress {
                    report(completed, total);
                }
                None
            }
            _ => None,
        },
    )
}

/// Sends one change the user made to the daemon and returns its answer; `None` when the daemon
/// could not be asked or did not answer (the change may or may not have been applied: send the
/// same request again).
pub fn apply(
    connector: &impl Connect,
    root: &[u8],
    request: ProviderApplyChangeRequest,
) -> Option<ProviderApplyChangeResponse> {
    let request_id = request.request_id.clone();
    call(
        connector,
        APPLY_TIMEOUT,
        root,
        Payload::ProviderApplyChangeRequest(request),
        move |payload| match payload {
            Payload::ProviderApplyChangeResponse(r) if r.request_id == request_id => Some(r),
            _ => None,
        },
    )
}

/// Tells the daemon that the user is reading `item` (it pauses background prefetch). The daemon
/// answers nothing; failures are ignored.
pub fn note_fetch_activity(connector: &impl Connect, root: &[u8], item: &[u8]) {
    runtime().block_on(async {
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            let mut stream = connector.connect().await.ok()?;
            let message = |payload| ShellIpcMessage { payload: Some(payload) };
            write_message(
                &mut stream,
                &message(Payload::ExtensionHandshake(ExtensionHandshake {
                    root_id: root.to_vec(),
                    extension_build: EXTENSION_BUILD.into(),
                })),
            )
            .await
            .ok()?;
            write_message(
                &mut stream,
                &message(Payload::ProviderActivity(ProviderActivity {
                    root_id: root.to_vec(),
                    item_id: item.to_vec(),
                    activity_kind: ActivityKind::Fetch as i32,
                })),
            )
            .await
            .ok()
        })
        .await;
    });
}

#[cfg(test)]
mod tests {
    /// A daemon that cannot be reached.
    struct Unreachable;

    impl Connect for Unreachable {
        type Stream = tokio::io::DuplexStream;
        async fn connect(&self) -> std::io::Result<Self::Stream> {
            Err(std::io::ErrorKind::NotFound.into())
        }
    }

    /// "Could not ask" is `None`, never an empty folder or an empty success.
    #[test]
    fn an_unreachable_daemon_is_no_answer_not_an_empty_success() {
        assert!(enumerate_children(&Unreachable, b"root", b"").is_none());
        assert!(materialize(&Unreachable, b"root", b"item", b"id", None).is_none());
        assert!(apply(&Unreachable, b"root", ProviderApplyChangeRequest::default()).is_none());
    }

    /// A 4 KiB open of a 1 GiB file is a ranged request of that window, naming the version; a
    /// whole-version request names the version only; a request without a target is the current
    /// whole file.
    #[test]
    fn the_request_names_the_window_and_the_version() {
        let target = FetchTarget { version: [3; 32], range: Some((1 << 29, 4096)) };
        let request = materialize_request(&[1; 16], &[2; 16], b"id", Some(target));
        assert!(request.ranged);
        assert_eq!((request.range_offset, request.range_length), (1 << 29, 4096));
        assert_eq!(request.requested_version_hash, vec![3; 32]);
        let whole_version = FetchTarget { version: [3; 32], range: None };
        let request = materialize_request(&[1; 16], &[2; 16], b"id", Some(whole_version));
        assert!(!request.ranged && request.requested_version_hash == vec![3; 32]);
        let whole = materialize_request(&[1; 16], &[2; 16], b"id", None);
        assert!(!whole.ranged && whole.requested_version_hash.is_empty());
        assert_eq!((whole.range_offset, whole.range_length), (0, 0));
    }

    /// The version a placeholder stands for is the hash of its 40-byte content version, and a
    /// root's record is replaced as a whole.
    #[test]
    fn shown_versions_are_the_hash_of_the_content_version() {
        assert_eq!(version_hash_of(&[9; 39]), None);
        let mut content = vec![4u8; 32];
        content.extend_from_slice(&7u64.to_le_bytes());
        assert_eq!(version_hash_of(&content), Some([4; 32]));
        let root = b"shown-versions-root";
        set_shown_versions(root, [(&b"item-a"[..], &content[..]), (&b"item-b"[..], &[1u8][..])]);
        assert_eq!(shown_version(root, b"item-a"), Some([4; 32]));
        assert_eq!(shown_version(root, b"item-b"), None);
        set_shown_versions(root, std::iter::empty());
        assert_eq!(shown_version(root, b"item-a"), None);
    }

    use super::*;
    use yadorilink_ipc_proto::shellipc::{EnumerateChildrenResponse, StatusPush};

    /// A daemon end of an in-memory connection, handed out once.
    struct Scripted(std::sync::Mutex<Option<tokio::io::DuplexStream>>);

    impl Connect for Scripted {
        type Stream = tokio::io::DuplexStream;
        async fn connect(&self) -> std::io::Result<Self::Stream> {
            self.0.lock().unwrap().take().ok_or_else(|| std::io::ErrorKind::NotFound.into())
        }
    }

    fn scripted_daemon(
        script: impl FnOnce(MaterializeToTempRequest) -> Vec<Payload> + Send + 'static,
    ) -> Scripted {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        runtime().spawn(async move {
            let _handshake: ShellIpcMessage = read_message(&mut server).await.unwrap().unwrap();
            let request: ShellIpcMessage = read_message(&mut server).await.unwrap().unwrap();
            let Some(Payload::MaterializeToTempRequest(request)) = request.payload else {
                panic!("not a materialization request");
            };
            for payload in script(request) {
                write_message(&mut server, &ShellIpcMessage { payload: Some(payload) })
                    .await
                    .unwrap();
            }
            // Keep the connection open until the client has read everything and left.
            let _ = read_message::<ShellIpcMessage>(&mut server).await;
        });
        Scripted(std::sync::Mutex::new(Some(client)))
    }

    /// Progress is asked for, delivered in order for this request only, and the answer still
    /// comes last; messages for another request are ignored.
    #[test]
    fn progress_of_this_request_is_passed_on_before_the_answer() {
        let daemon = scripted_daemon(|request| {
            assert!(request.report_progress, "the request asks for progress");
            let progress = |id: &[u8], completed, done| {
                Payload::MaterializeProgress(MaterializeProgress {
                    request_id: id.to_vec(),
                    completed,
                    total: 100,
                    done,
                })
            };
            vec![
                progress(b"id", 10, false),
                progress(b"other", 99, false),
                progress(b"id", 60, false),
                progress(b"id", 100, true),
                Payload::MaterializeToTempResponse(MaterializeToTempResponse {
                    request_id: b"id".to_vec(),
                    ok: true,
                    ..Default::default()
                }),
            ]
        });
        let seen = std::cell::RefCell::new(Vec::new());
        let answer = materialize_reporting(
            &daemon,
            Duration::from_secs(10),
            &AtomicBool::new(false),
            b"root",
            b"item",
            b"id",
            None,
            Some(&|completed, total| seen.borrow_mut().push((completed, total))),
        )
        .expect("answered");
        assert!(answer.ok);
        assert_eq!(*seen.borrow(), [(10, 100), (60, 100), (100, 100)]);
    }

    /// A daemon end that sends `progress_messages` progress messages `gap` apart and then, when
    /// `answer` is set, the response.
    fn slow_daemon(progress_messages: u64, gap: Duration, answer: bool) -> Scripted {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        runtime().spawn(async move {
            let _handshake: ShellIpcMessage = read_message(&mut server).await.unwrap().unwrap();
            let request: ShellIpcMessage = read_message(&mut server).await.unwrap().unwrap();
            let Some(Payload::MaterializeToTempRequest(request)) = request.payload else {
                panic!("not a materialization request");
            };
            for completed in 1..=progress_messages {
                tokio::time::sleep(gap).await;
                let progress = Payload::MaterializeProgress(MaterializeProgress {
                    request_id: request.request_id.clone(),
                    completed,
                    total: progress_messages,
                    done: false,
                });
                write_message(&mut server, &ShellIpcMessage { payload: Some(progress) })
                    .await
                    .unwrap();
            }
            if answer {
                let response = Payload::MaterializeToTempResponse(MaterializeToTempResponse {
                    request_id: request.request_id,
                    ok: true,
                    ..Default::default()
                });
                write_message(&mut server, &ShellIpcMessage { payload: Some(response) })
                    .await
                    .unwrap();
            }
            let _ = read_message::<ShellIpcMessage>(&mut server).await;
        });
        Scripted(std::sync::Mutex::new(Some(client)))
    }

    /// A transfer that keeps reporting progress outlives the request timeout: the timeout is a
    /// stall bound, not a cap on how long a large file may take.
    #[test]
    fn a_transfer_that_keeps_moving_outlives_the_timeout() {
        let timeout = Duration::from_millis(400);
        let started = Instant::now();
        // Ten messages 120 ms apart: 1.2 s in total, three times the timeout.
        let daemon = slow_daemon(10, Duration::from_millis(120), true);
        let answer = materialize_reporting(
            &daemon,
            timeout,
            &AtomicBool::new(false),
            b"root",
            b"item",
            b"id",
            None,
            Some(&|_, _| {}),
        );
        assert!(answer.is_some_and(|a| a.ok), "a moving transfer is not cut off");
        assert!(started.elapsed() > timeout * 2);
    }

    /// A transfer that stops reporting for the timeout is abandoned, however much it had done.
    #[test]
    fn a_stalled_transfer_is_abandoned_after_the_timeout() {
        let timeout = Duration::from_millis(400);
        let started = Instant::now();
        let daemon = slow_daemon(3, Duration::from_millis(100), false);
        let answer = materialize_reporting(
            &daemon,
            timeout,
            &AtomicBool::new(false),
            b"root",
            b"item",
            b"id",
            None,
            Some(&|_, _| {}),
        );
        assert!(answer.is_none());
        assert!(started.elapsed() >= timeout + Duration::from_millis(300));
    }

    /// Without a progress sink the daemon is not asked to send any.
    #[test]
    fn no_progress_is_asked_for_without_a_sink() {
        let daemon = scripted_daemon(|request| {
            assert!(!request.report_progress);
            vec![Payload::MaterializeToTempResponse(MaterializeToTempResponse {
                request_id: request.request_id,
                ok: true,
                ..Default::default()
            })]
        });
        let answer = materialize_within(
            &daemon,
            Duration::from_secs(10),
            &AtomicBool::new(false),
            b"r",
            b"i",
            b"id",
            None,
        );
        assert!(answer.is_some_and(|a| a.ok));
    }

    /// A cancel while the daemon is still working drops the call without an answer.
    #[test]
    fn a_cancel_abandons_a_request_still_in_progress() {
        let daemon = scripted_daemon(|request| {
            vec![Payload::MaterializeProgress(MaterializeProgress {
                request_id: request.request_id,
                completed: 1,
                total: 2,
                done: false,
            })]
        });
        let cancel = AtomicBool::new(false);
        let answer = materialize_reporting(
            &daemon,
            Duration::from_secs(30),
            &cancel,
            b"root",
            b"item",
            b"id",
            None,
            Some(&|_, _| cancel.store(true, Ordering::Relaxed)),
        );
        assert!(answer.is_none());
    }

    /// The handshake precedes the request, pushes in between are skipped, and the matching
    /// response is returned.
    #[tokio::test]
    async fn the_handshake_comes_first_and_unrelated_pushes_are_skipped() {
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let daemon = tokio::spawn(async move {
            let first: ShellIpcMessage = read_message(&mut server).await.unwrap().unwrap();
            assert!(matches!(first.payload, Some(Payload::ExtensionHandshake(_))));
            let second: ShellIpcMessage = read_message(&mut server).await.unwrap().unwrap();
            assert!(matches!(second.payload, Some(Payload::EnumerateChildrenRequest(_))));
            write_message(
                &mut server,
                &ShellIpcMessage { payload: Some(Payload::StatusPush(StatusPush::default())) },
            )
            .await
            .unwrap();
            write_message(
                &mut server,
                &ShellIpcMessage {
                    payload: Some(Payload::EnumerateChildrenResponse(EnumerateChildrenResponse {
                        ok: true,
                        items: vec![ProviderItem { name: "a".into(), ..Default::default() }],
                        ..Default::default()
                    })),
                },
            )
            .await
            .unwrap();
        });
        let answer = exchange(
            &mut client,
            &[7; 16],
            Payload::EnumerateChildrenRequest(EnumerateChildrenRequest::default()),
            |payload| match payload {
                Payload::EnumerateChildrenResponse(r) => Some(r),
                _ => None,
            },
        )
        .await
        .expect("an answer");
        assert_eq!(answer.items[0].name, "a");
        daemon.await.unwrap();
    }

    /// A connection that closes before the answer is a failure, not an empty success.
    #[tokio::test]
    async fn a_closed_connection_is_no_answer() {
        let (mut client, server) = tokio::io::duplex(1024);
        drop(server);
        let answer = exchange(
            &mut client,
            &[7; 16],
            Payload::EnumerateChildrenRequest(EnumerateChildrenRequest::default()),
            |payload| match payload {
                Payload::EnumerateChildrenResponse(r) => Some(r),
                _ => None,
            },
        )
        .await;
        assert!(answer.is_none());
    }
}
