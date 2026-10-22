//! `GET /api/events` -- a Server-Sent-Events stream.
//!
//! `control_socket.rs` is pure request/response (confirmed against its full
//! dispatch table): there is no daemon-side "subscribe to status changes"
//! IPC call this adapter could forward. A real push-based event bus does
//! exist in-process (`RuntimeTelemetry`'s `broadcast::Sender<StatusPush>`),
//! but it is private to `yadorilink-daemon`, wired only to the separate
//! shell-integration IPC surface, and covers only per-file materialization
//! state -- not the links/peers/conflicts/overall-state data this
//! dashboard's `/api/status` already exposes. Reaching into it would mean
//! either widening `yadorilink-daemon`'s internal visibility or duplicating
//! its wiring in a second crate, both bigger changes than this adapter's
//! "thin translation, no new daemon capability" scope allows for a first
//! pass.
//!
//! So this stream is built the same way any client polling `GET /api/status`
//! in a loop would build one -- it uses no daemon capability beyond what
//! `/api/status` itself already forwards: a fixed-interval `Status` request,
//! re-sent on this same `ControlClient`. It emits a new `event: status` only
//! when the serialized snapshot actually changed since the last poll, so an
//! idle daemon does not spam the stream. A transient control-socket failure
//! (daemon briefly unreachable) emits `event: error` and keeps polling,
//! rather than closing the stream -- from a dashboard's point of view, a
//! blip in reachability is exactly the kind of thing it should show, not
//! disconnect for.
//!
//! Two things bound this loop's lifetime and count, both load-bearing:
//!
//! - Disconnect detection cannot rely solely on a failed `tx.send` --  on an
//!   idle daemon (the common headless/NAS case) the serialized snapshot is
//!   byte-stable, so the loop can go arbitrarily long without ever calling
//!   `tx.send` at all, and therefore never notices a dropped receiver. Every
//!   loop iteration instead races the next poll tick against
//!   `tx.closed()`, which resolves as soon as axum drops the response body
//!   (client disconnect, tab close, or the bundled Web UI's own
//!   reconnect-every-few-seconds loop moving on) -- see the comment above
//!   the `tokio::select!` near the bottom of this file for how a leaked
//!   poller was actually measured before this fix.
//! - `AppState::sse_slots` bounds how many of these polling tasks can be
//!   alive at once, independent of the disconnect fix above: even with
//!   prompt cleanup, a burst of concurrent connections (or a client that
//!   doesn't cleanly close) should have a hard ceiling on the resulting
//!   control-socket polling load rather than an unbounded one.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::Stream;
use tokio::sync::mpsc;
use yadorilink_ipc_proto::daemonctl::daemon_control_request::Payload as ReqPayload;
use yadorilink_ipc_proto::daemonctl::daemon_control_response::Payload as RespPayload;
use yadorilink_ipc_proto::daemonctl::StatusRequest;

use super::reads::status_response_json;
use crate::error::ApiError;
use crate::AppState;

/// How often the daemon is re-polled for a status snapshot. A dashboard
/// stat, not a sync-latency-sensitive path -- a couple of seconds of
/// staleness is an acceptable trade for not hammering the control socket.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

#[allow(
    clippy::excessive_nesting,
    reason = "the SSE poll loop lives inside the spawned task that owns the stream permit, and \
              the status arm's nesting (loop -> match -> if let RespPayload::Status -> \
              changed-snapshot check -> send-failure check) is what makes every disconnect path \
              `return` out of that task and drop the permit; extracting it would move the \
              permit's lifetime away from the loop that must release it"
)]
pub async fn events(
    State(state): State<AppState>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    // Rejected outright (no queueing) once `AppState::sse_slots` is
    // exhausted -- a dashboard client is expected to hold at most one
    // stream, so hitting this cap means something is already wrong
    // (a client stuck in a fast reconnect loop, or many browser tabs) and
    // queuing would just hide that rather than bound it.
    let permit =
        state.sse_slots.clone().try_acquire_owned().map_err(|_| ApiError::TooManyStreams)?;

    let (tx, rx) = mpsc::channel::<Event>(16);

    tokio::spawn(async move {
        // Held for the task's whole lifetime; dropping it (on every `return`
        // below, including the disconnect path) releases the slot back to
        // `AppState::sse_slots`.
        let _permit = permit;

        let mut last_snapshot: Option<String> = None;
        loop {
            match state.control.send(ReqPayload::Status(StatusRequest {})).await {
                Ok(resp) => {
                    if let Some(RespPayload::Status(status)) = resp.payload {
                        let text = status_response_json(&status).to_string();
                        if last_snapshot.as_deref() != Some(text.as_str()) {
                            let event = Event::default().event("status").data(text.clone());
                            last_snapshot = Some(text);
                            if tx.send(event).await.is_err() {
                                // Receiver dropped: the client disconnected
                                // and axum tore down the response body.
                                // Nothing left to do but stop polling.
                                return;
                            }
                        }
                    }
                }
                Err(e) => {
                    let body = serde_json::json!({ "error": e.to_string() }).to_string();
                    let event = Event::default().event("error").data(body);
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }
            // Wait for whichever comes first: the next poll tick, or the
            // client disconnecting. Sleeping unconditionally here (the
            // original shape of this loop) is exactly the bug: on an idle
            // daemon `tx.send` above is never reached at all, so a plain
            // `sleep` alone never gives this loop a chance to notice the
            // receiver is gone -- confirmed empirically (1000
            // opened-then-closed connections against an idle daemon left
            // every one of their pollers running, still polling the control
            // socket every 2s, 65s after every client had disconnected).
            tokio::select! {
                _ = tx.closed() => return,
                _ = tokio::time::sleep(POLL_INTERVAL) => {}
            }
        }
    });

    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|item| (Ok(item), rx))
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}
