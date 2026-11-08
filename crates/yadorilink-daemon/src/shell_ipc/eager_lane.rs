//! The host connection's Eager queries, answered in the order they arrive.
//!
//! The host matches an answer to its query by position on the connection, so answers must leave
//! in query order. An answer that has nothing to say yet (no download to offer, nothing settled)
//! is held for a bounded time and given as soon as there is something, which saves the host a
//! poll tick between a slot freeing and the next download starting. The hold stands in one task
//! per connection, so it delays only the Eager answers behind it, never the connection's other
//! messages, and it ends with the connection.

use std::sync::Arc;

use tokio::sync::mpsc;
use yadorilink_ipc_proto::shellipc::{
    shell_ipc_message::Payload, NextProviderDownloadsRequest, ShellIpcMessage,
};

use crate::shell_context::ShellContext;

pub(super) struct EagerLane {
    queries: mpsc::UnboundedSender<NextProviderDownloadsRequest>,
}

impl EagerLane {
    /// A lane answering on `host_tx`. The task ends when the lane is dropped or the connection's
    /// receiving side is gone.
    pub(super) fn spawn(
        context: Arc<ShellContext>,
        host_tx: mpsc::UnboundedSender<ShellIpcMessage>,
    ) -> Self {
        let (queries, rx) = mpsc::unbounded_channel();
        tokio::spawn(serve(context, host_tx, rx));
        Self { queries }
    }

    pub(super) fn submit(&self, request: NextProviderDownloadsRequest) {
        let _ = self.queries.send(request);
    }
}

async fn serve(
    context: Arc<ShellContext>,
    host_tx: mpsc::UnboundedSender<ShellIpcMessage>,
    mut queries: mpsc::UnboundedReceiver<NextProviderDownloadsRequest>,
) {
    while let Some(request) = queries.recv().await {
        // Only the attached host is answered; any other connection on the user-owned socket gets
        // nothing.
        if !context.provider_host.is_attached(&host_tx) {
            continue;
        }
        let hold = context.eager.hold();
        let deadline = tokio::time::Instant::now() + hold.total;
        let response = loop {
            let response = {
                let handoff_root = context.handoff.get();
                let inputs = crate::provider_eager::EagerInputs {
                    coordinator: &context.replica_coordinator,
                    membership: &context.membership,
                    staging_dir: handoff_root.as_ref().map(|h| h.staging_dir()),
                    host_attached: true,
                };
                context.eager.next_downloads(&inputs, &request)
            };
            let waiting = crate::provider_eager::EagerDriver::has_nothing_to_say(&response)
                && tokio::time::Instant::now() < deadline
                && !host_tx.is_closed()
                && context.provider_host.is_attached(&host_tx);
            if !waiting {
                break response;
            }
            tokio::time::sleep(hold.step).await;
        };
        if host_tx
            .send(ShellIpcMessage {
                payload: Some(Payload::NextProviderDownloadsResponse(response)),
            })
            .is_err()
        {
            return;
        }
    }
}
