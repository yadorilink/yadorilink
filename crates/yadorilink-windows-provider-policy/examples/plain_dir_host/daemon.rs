//! The stand-in's connection to the daemon: the shell socket, the list of provider folders and the
//! acknowledgements the host's loop sends.

use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::time::Duration;

use tokio::net::UnixStream;
use tokio::sync::mpsc::UnboundedSender;
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    DomainEvidence, EvictResult, ListProviderFoldersRequest, NextProviderDownloadsRequest,
    NextProviderDownloadsResponse, ProviderDomainState, ProviderEvictDone, ProviderFolder,
    ProviderMaterializedReport, ProviderRemoval, ProviderSignalDone, ShellIpcMessage,
};
use yadorilink_windows_provider_policy::host::{HostEvent, Reports};
use yadorilink_windows_provider_policy::provider_client::{runtime, Connect};
use yadorilink_windows_provider_policy::provider_session::{event_of, SessionEvent};

/// One new connection to the daemon's shell socket per call.
#[derive(Clone)]
pub struct Socket(pub PathBuf);

impl Connect for Socket {
    type Stream = UnixStream;

    async fn connect(&self) -> std::io::Result<UnixStream> {
        UnixStream::connect(&self.0).await
    }
}

/// The host's ONE persistent connection to the daemon, the attached host. The first domain-state
/// message that names a root attaches it; from then on the daemon pushes changes and eviction
/// requests down it, and answers the Eager driver's queries on it. It reconnects by itself.
///
/// This is `provider_session::spawn` plus the Eager driver's answer, which that session does not
/// carry (the Windows host has no Eager driver).
#[derive(Clone)]
pub struct Link {
    commands: UnboundedSender<ShellIpcMessage>,
    next_request: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Link {
    fn send(&self, payload: Payload) {
        let _ = self.commands.send(ShellIpcMessage { payload: Some(payload) });
    }

    /// Asks the daemon which items to download next (the Eager driver's query) and returns the
    /// request id the answer will carry: one id per query, so an answer that arrives after its
    /// query was given up on is recognised as stale and dropped.
    pub fn next_downloads(&self, root: &[u8], exclude: Vec<Vec<u8>>, max: u32) -> Vec<u8> {
        let id = self.next_request.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        let request_id = id.to_be_bytes().to_vec();
        self.send(Payload::NextProviderDownloadsRequest(NextProviderDownloadsRequest {
            root_id: root.to_vec(),
            exclude_item_ids: exclude,
            max,
            request_id: request_id.clone(),
        }));
        request_id
    }
}

impl Reports for Link {
    fn domain_state(&self, root: &[u8], evidence: DomainEvidence, preserved_location: &str) {
        self.send(Payload::ProviderDomainState(ProviderDomainState {
            root_id: root.to_vec(),
            evidence: evidence as i32,
            preserved_location: preserved_location.to_string(),
            last_acked_namespace_revision: 0,
        }));
    }

    fn signal_done(&self, root: &[u8], revision: u64, request_id: &[u8], error: Option<&str>) {
        self.send(Payload::ProviderSignalDone(ProviderSignalDone {
            root_id: root.to_vec(),
            namespace_revision: revision,
            ok: error.is_none(),
            error: error.unwrap_or_default().to_string(),
            request_id: request_id.to_vec(),
        }));
    }

    fn evict_done(&self, root: &[u8], request_id: &[u8], result: EvictResult, error: &str) {
        self.send(Payload::ProviderEvictDone(ProviderEvictDone {
            root_id: root.to_vec(),
            request_id: request_id.to_vec(),
            result: result as i32,
            error: error.to_string(),
        }));
    }

    fn materialized(&self, report: ProviderMaterializedReport) {
        self.send(Payload::ProviderMaterializedReport(report));
    }
}

/// Starts the connection thread. Daemon pushes arrive on `events`, answers to the Eager driver's
/// query on `downloads`.
pub fn spawn(
    socket: Socket,
    events: Sender<HostEvent>,
    downloads: Sender<NextProviderDownloadsResponse>,
) -> Link {
    let (commands, receiver) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to start the session runtime");
        runtime.block_on(keep_connected(socket, receiver, events, downloads));
    });
    Link { commands, next_request: Default::default() }
}

/// Hands one daemon message to whoever waits for it; false when nobody does any more.
fn deliver(
    payload: Payload,
    events: &Sender<HostEvent>,
    downloads: &Sender<NextProviderDownloadsResponse>,
) -> bool {
    match payload {
        Payload::NextProviderDownloadsResponse(answer) => downloads.send(answer).is_ok(),
        other => event_of(other).is_none_or(|event| events.send(HostEvent::Session(event)).is_ok()),
    }
}

async fn write_loop(
    mut writer: impl tokio::io::AsyncWrite + Unpin,
    commands: &mut tokio::sync::mpsc::UnboundedReceiver<ShellIpcMessage>,
) {
    while let Some(message) = commands.recv().await {
        if write_message(&mut writer, &message).await.is_err() {
            break;
        }
    }
}

async fn read_loop(
    mut reader: impl tokio::io::AsyncRead + Unpin,
    events: &Sender<HostEvent>,
    downloads: &Sender<NextProviderDownloadsResponse>,
) {
    loop {
        match read_message::<ShellIpcMessage>(&mut reader).await {
            Ok(Some(ShellIpcMessage { payload: Some(payload) })) => {
                if !deliver(payload, events, downloads) {
                    break;
                }
            }
            Ok(Some(_)) => {}
            _ => break,
        }
    }
}

async fn keep_connected(
    socket: Socket,
    mut commands: tokio::sync::mpsc::UnboundedReceiver<ShellIpcMessage>,
    events: Sender<HostEvent>,
    downloads: Sender<NextProviderDownloadsResponse>,
) {
    loop {
        if let Ok(stream) = socket.connect().await {
            // What was queued for the previous connection is stale: the loop attaches every
            // root it serves again when it sees `Connected`.
            while commands.try_recv().is_ok() {}
            if events.send(HostEvent::Session(SessionEvent::Connected)).is_err() {
                return;
            }
            let (reader, writer) = tokio::io::split(stream);
            tokio::select! {
                () = write_loop(writer, &mut commands) => {}
                () = read_loop(reader, &events, &downloads) => {}
            }
            if events.send(HostEvent::Session(SessionEvent::Closed)).is_err() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub type Snapshot = (Vec<ProviderFolder>, Vec<ProviderRemoval>);

/// The provider folders the daemon declares, `None` when it could not confirm them (the host then
/// changes nothing). `container` is the host's own data directory the daemon adopts as its
/// provider temp root (`<container>/provider`).
pub fn list_provider_folders(socket: &Socket, container: &str) -> Option<Snapshot> {
    runtime().block_on(async {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = socket.connect().await.ok()?;
            let request = ShellIpcMessage {
                payload: Some(Payload::ListProviderFoldersRequest(ListProviderFoldersRequest {
                    app_group_container: container.to_string(),
                })),
            };
            write_message(&mut stream, &request).await.ok()?;
            loop {
                match read_message::<ShellIpcMessage>(&mut stream).await {
                    Ok(Some(ShellIpcMessage {
                        payload: Some(Payload::ListProviderFoldersResponse(r)),
                    })) => {
                        return r.snapshot_available.then_some((r.folders, r.removals));
                    }
                    Ok(Some(_)) => {}
                    _ => return None,
                }
            }
        })
        .await
        .ok()?
    })
}
