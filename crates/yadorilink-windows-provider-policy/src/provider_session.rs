//! The host's ONE persistent connection to the daemon.
//!
//! The first domain-state message that names a root makes this connection the daemon's attached
//! host: from then on the daemon pushes `ProviderChanged` (the namespace moved; show it, then
//! acknowledge) and `ProviderEvictRequest` (drop the operating system's old copy of an item before
//! the new version is published, then acknowledge) down it, and waits for the acknowledgement.
//! Commands go out in order; pushes come back as [`SessionEvent`]s on a channel the host's loop
//! reads. The connection is kept alive for the life of the process: when it ends the session says
//! so, waits a moment and connects again, and the loop re-attaches every root it serves.

use std::sync::mpsc::Sender;
use std::time::Duration;

use tokio::sync::mpsc;

pub use crate::provider_client::Connect;
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    DomainEvidence, EvictResult, ProviderDomainState, ProviderEvictDone,
    ProviderMaterializedReport, ProviderSignalDone, ShellIpcMessage,
};

const RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// What the daemon told the host over the persistent connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    /// A fresh connection is up: every served root must be (re-)attached.
    Connected,
    /// The connection ended; the session reconnects by itself.
    Closed,
    /// Committed changes exist for `root` (empty `root`: the set of provider folders changed).
    Changed { root: Vec<u8>, revision: u64, request_id: Vec<u8> },
    /// Drop the operating system's copy of `item`.
    Evict { root: Vec<u8>, item: Vec<u8>, request_id: Vec<u8>, require_shown_version: Vec<u8> },
    /// The latest handoff sequence of `root` changed.
    EvidenceTick { root: Vec<u8>, seq: u64 },
    /// The daemon's answer to a materialized-set report.
    ReportAck { root: Vec<u8>, epoch: u64, needs_full: bool },
}

/// The sending half: what the host's loop tells the daemon.
#[derive(Clone)]
pub struct Session {
    commands: mpsc::UnboundedSender<ShellIpcMessage>,
}

impl Session {
    /// Reports what the host knows about the sync root of `root`. The first report on a
    /// connection attaches it as the host.
    pub fn domain_state(&self, root: &[u8], evidence: DomainEvidence, preserved_location: &str) {
        self.send(Payload::ProviderDomainState(ProviderDomainState {
            root_id: root.to_vec(),
            evidence: evidence as i32,
            preserved_location: preserved_location.to_string(),
            last_acked_namespace_revision: 0,
        }));
    }

    pub fn signal_done(&self, root: &[u8], revision: u64, request_id: &[u8], error: Option<&str>) {
        self.send(Payload::ProviderSignalDone(ProviderSignalDone {
            root_id: root.to_vec(),
            namespace_revision: revision,
            ok: error.is_none(),
            error: error.unwrap_or_default().to_string(),
            request_id: request_id.to_vec(),
        }));
    }

    pub fn evict_done(&self, root: &[u8], request_id: &[u8], result: EvictResult, error: &str) {
        self.send(Payload::ProviderEvictDone(ProviderEvictDone {
            root_id: root.to_vec(),
            request_id: request_id.to_vec(),
            result: result as i32,
            error: error.to_string(),
        }));
    }

    /// Reports the materialized set (see `provider_report`).
    pub fn materialized(&self, report: ProviderMaterializedReport) {
        self.send(Payload::ProviderMaterializedReport(report));
    }

    fn send(&self, payload: Payload) {
        let _ = self.commands.send(ShellIpcMessage { payload: Some(payload) });
    }
}

/// The event a daemon message becomes, or `None` for a message the host does not act on.
pub fn event_of(payload: Payload) -> Option<SessionEvent> {
    match payload {
        Payload::ProviderChanged(changed) => Some(SessionEvent::Changed {
            root: changed.root_id,
            revision: changed.namespace_revision,
            request_id: changed.request_id,
        }),
        Payload::ProviderEvictRequest(evict) => Some(SessionEvent::Evict {
            root: evict.root_id,
            item: evict.item_id,
            request_id: evict.request_id,
            require_shown_version: evict.require_shown_version,
        }),
        Payload::ProviderEvidenceTick(tick) => {
            Some(SessionEvent::EvidenceTick { root: tick.root_id, seq: tick.evidence_seq })
        }
        Payload::ProviderReportAck(ack) => Some(SessionEvent::ReportAck {
            root: ack.root_id,
            epoch: ack.reporter_epoch,
            needs_full: ack.needs_full,
        }),
        _ => None,
    }
}

/// Starts the session thread. Events arrive on `events`; the returned handle sends commands.
pub fn spawn<C, E>(connector: C, events: Sender<E>) -> Session
where
    C: Connect + Send + 'static,
    E: From<SessionEvent> + Send + 'static,
{
    let (commands, receiver) = mpsc::unbounded_channel();
    std::thread::Builder::new()
        .name("yadorilink-provider-session".into())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to start the provider session runtime");
            runtime.block_on(keep_connected(&connector, receiver, events));
        })
        .expect("failed to start the provider session thread");
    Session { commands }
}

async fn keep_connected<E: From<SessionEvent>>(
    connector: &impl Connect,
    mut commands: mpsc::UnboundedReceiver<ShellIpcMessage>,
    events: Sender<E>,
) {
    loop {
        if let Ok(stream) = connector.connect().await {
            // What was queued for the previous connection is stale: the loop re-attaches
            // everything it serves when it sees `Connected`.
            while commands.try_recv().is_ok() {}
            if events.send(SessionEvent::Connected.into()).is_err() {
                return;
            }
            run_over(stream, &mut commands, &events).await;
            if events.send(SessionEvent::Closed.into()).is_err() {
                return;
            }
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// Runs the connection until it ends: commands go out in order, pushes become events.
pub async fn run_over<S, E: From<SessionEvent>>(
    stream: S,
    commands: &mut mpsc::UnboundedReceiver<ShellIpcMessage>,
    events: &Sender<E>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    // Two independent loops (a read is never cancelled half-way): the connection ends when
    // either ends.
    let writing = async {
        while let Some(message) = commands.recv().await {
            if write_message(&mut writer, &message).await.is_err() {
                break;
            }
        }
    };
    let reading = async {
        loop {
            match read_message::<ShellIpcMessage>(&mut reader).await {
                Ok(Some(ShellIpcMessage { payload: Some(payload) })) => {
                    if let Some(event) = event_of(payload) {
                        if events.send(event.into()).is_err() {
                            break;
                        }
                    }
                }
                Ok(Some(_)) => {}
                _ => break,
            }
        }
    };
    tokio::select! {
        () = writing => {}
        () = reading => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_ipc_proto::shellipc::{ProviderChanged, ProviderEvictRequest};

    #[test]
    fn pushes_the_host_acts_on_become_events() {
        let changed = event_of(Payload::ProviderChanged(ProviderChanged {
            root_id: vec![1],
            namespace_revision: 8,
            request_id: vec![9],
            ..Default::default()
        }));
        assert_eq!(
            changed,
            Some(SessionEvent::Changed { root: vec![1], revision: 8, request_id: vec![9] })
        );
        let evict = event_of(Payload::ProviderEvictRequest(ProviderEvictRequest {
            root_id: vec![1],
            item_id: vec![2],
            request_id: vec![3],
            ..Default::default()
        }));
        assert_eq!(
            evict,
            Some(SessionEvent::Evict {
                root: vec![1],
                item: vec![2],
                request_id: vec![3],
                require_shown_version: vec![]
            })
        );
        assert_eq!(
            event_of(Payload::ProviderEvidenceTick(
                yadorilink_ipc_proto::shellipc::ProviderEvidenceTick {
                    root_id: vec![1],
                    evidence_seq: 9
                }
            )),
            Some(SessionEvent::EvidenceTick { root: vec![1], seq: 9 })
        );
        assert_eq!(
            event_of(Payload::ProviderReportAck(
                yadorilink_ipc_proto::shellipc::ProviderReportAck {
                    root_id: vec![1],
                    reporter_epoch: 4,
                    accepted_seq: 2,
                    needs_full: true
                }
            )),
            Some(SessionEvent::ReportAck { root: vec![1], epoch: 4, needs_full: true })
        );
        assert_eq!(event_of(Payload::StatusPush(Default::default())), None);
    }

    /// Commands reach the daemon in order and the daemon's pushes come back as events; a closed
    /// stream ends the run.
    #[tokio::test]
    async fn commands_go_out_and_pushes_come_back() {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (events_tx, events_rx) = std::sync::mpsc::channel();
        let session = Session { commands: tx };
        session.domain_state(&[5; 16], DomainEvidence::Registered, "");
        session.signal_done(&[5; 16], 3, &[1], None);

        let daemon = tokio::spawn(async move {
            let first: ShellIpcMessage = read_message(&mut server).await.unwrap().unwrap();
            let second: ShellIpcMessage = read_message(&mut server).await.unwrap().unwrap();
            write_message(
                &mut server,
                &ShellIpcMessage {
                    payload: Some(Payload::ProviderChanged(ProviderChanged {
                        root_id: vec![5; 16],
                        namespace_revision: 4,
                        request_id: vec![2],
                        ..Default::default()
                    })),
                },
            )
            .await
            .unwrap();
            (first, second)
        });
        run_over(client, &mut rx, &events_tx).await;
        let (first, second) = daemon.await.unwrap();
        let Some(Payload::ProviderDomainState(state)) = first.payload else { panic!() };
        assert_eq!(state.evidence, DomainEvidence::Registered as i32);
        let Some(Payload::ProviderSignalDone(done)) = second.payload else { panic!() };
        assert!(done.ok && done.namespace_revision == 3);
        assert!(matches!(events_rx.try_recv(), Ok(SessionEvent::Changed { revision: 4, .. })));
    }
}
