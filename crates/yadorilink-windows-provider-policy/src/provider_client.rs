//! Typed requests of the provider-root protocol, each over one short-lived connection: the
//! extension handshake for the root first, then the request, then the matching response (other
//! messages the daemon may push on the connection, such as status updates, are skipped).
//!
//! A transport failure (unreachable daemon, timeout, a closed connection) is `None`, never an
//! empty success: a caller that reconciles the local namespace against an answer must not read
//! "could not ask" as "nothing there".

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::runtime::Runtime;
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    ActivityKind, EnumerateChildrenRequest, ExtensionHandshake, MaterializeToTempRequest,
    MaterializeToTempResponse, ProviderActivity, ProviderApplyChangeRequest,
    ProviderApplyChangeResponse, ProviderItem, ShellIpcMessage,
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
/// One materialization request. A fetch is served in bounded windows (see `windowed_fetch`), so
/// this bounds one window and does not grow with the size of the file.
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
fn call_unless<T>(
    connector: &impl Connect,
    timeout: Duration,
    cancel: &AtomicBool,
    root: &[u8],
    request: Payload,
    pick: impl Fn(Payload) -> Option<T>,
) -> Option<T> {
    runtime().block_on(async {
        let work = tokio::time::timeout(timeout, async {
            let mut stream = connector.connect().await.ok()?;
            exchange(&mut stream, root, request, pick).await
        });
        let cancelled = async {
            while !cancel.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        tokio::select! {
            answer = work => answer.ok()?,
            () = cancelled => None,
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
        // This client waits for the one response.
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
    call_unless(
        connector,
        timeout,
        cancel,
        root,
        Payload::MaterializeToTempRequest(materialize_request(root, item, request_id, target)),
        move |payload| match payload {
            Payload::MaterializeToTempResponse(r) if r.request_id == request_id => Some(r),
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
