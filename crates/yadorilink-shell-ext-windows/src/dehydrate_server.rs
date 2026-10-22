//! A second named-pipe server, hosted by `yadorilink-cfapi-host.exe`
//! itself (unlike every other shell-IPC message pair, which flows shell
//! extension/cfapi-host -> daemon over the daemon's OWN pipe -- see
//! `crates/yadorilink-daemon/src/shell_ipc.rs`), so the daemon can dial IN
//! and get a synchronous, confirmed answer to "did native dehydration of
//! this placeholder actually happen" before it commits the row to
//! `Placeholder` and reclaims blocks.
//!
//! Why this needs its own pipe rather than reusing the daemon's existing
//! shell-IPC connection (`ListOnDemandFoldersRequest`/`ListFolderFilesRequest`
//! etc): that connection is opened BY cfapi-host, as a CLIENT, per call
//! (see `ipc_client.rs`) -- there is no mechanism for the daemon to push an
//! unprompted request down it and correlate a later response, since the
//! daemon's own `shell_ipc::handle_connection` loop only ever responds to
//! messages the connected client sent, or pushes fire-and-forget
//! `StatusPush` updates. And why this needs a real cross-process call at
//! all, rather than the daemon calling `CfDehydratePlaceholder` directly
//! the way `placeholder_inspect_windows.rs` calls `CfGetPlaceholderInfo`
//! directly (that module's own "any connected provider suffices" bet):
//! that bet is for a READ-ONLY query, whose failure mode when wrong is
//! merely "always fall back to safe", but `CfDehydratePlaceholder` is a
//! data-DESTRUCTIVE mutation -- the confirmation gate around block
//! reclamation needs the higher-confidence answer this dedicated RPC gives,
//! not an unverified guess about whether a second process can mutate a
//! placeholder connection it doesn't own.
//!
//! One request/response pair per connection, matching `HydrateRequest`'s
//! own per-call connection style on the daemon's pipe -- not a persistent
//! duplex connection like `shell_ipc::handle_connection`, since this pipe
//! never needs to push anything unprompted.

use std::path::Path;
use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::Semaphore;
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{DehydrateResponse, ShellIpcMessage};

use crate::windows_pipe_security::PipeSecurityAttributes;

/// Cap on concurrent in-flight dehydrate connections -- generous relative
/// to expected load (eviction is not a hot path the way `StatusQuery` is),
/// matching the daemon's own `MAX_SHELL_IPC_CONNECTIONS` reasoning: a
/// bound exists so a runaway or malicious local client can't exhaust pipe
/// instances, not because this many concurrent evictions are expected in
/// practice.
const MAX_DEHYDRATE_CONNECTIONS: usize = 16;

/// Dehydrate pipe of this host's state directory, derived by the same helper the daemon
/// client uses, so the two sides agree and two state directories never share the pipe.
pub fn pipe_name() -> String {
    yadorilink_fs_platform::state_dir::dehydrate_pipe_name()
}

fn create_first_pipe_server(pipe_name: &str) -> std::io::Result<NamedPipeServer> {
    let mut attrs = PipeSecurityAttributes::new_current_user_and_system_only()?;
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .create_with_security_attributes_raw(pipe_name, attrs.as_mut_ptr())
    }
}

fn create_next_pipe_server(pipe_name: &str) -> std::io::Result<NamedPipeServer> {
    let mut attrs = PipeSecurityAttributes::new_current_user_and_system_only()?;
    unsafe {
        ServerOptions::new().create_with_security_attributes_raw(pipe_name, attrs.as_mut_ptr())
    }
}

/// Runs forever, accepting one connection at a time and spawning a handler
/// for each -- mirrors `yadorilink_daemon::shell_ipc::windows_transport::
/// serve`'s exact accept-loop structure (see that function's own doc
/// comment for the concurrent-connection pipe-instance race this avoids:
/// the next server instance is created and ready to accept BEFORE the
/// current one is handed off to its connection handler).
pub async fn serve(pipe_name: &str) -> std::io::Result<()> {
    eprintln!("yadorilink-cfapi-host: dehydrate pipe listening on {pipe_name}");
    let mut server = create_first_pipe_server(pipe_name)?;
    let connection_slots = Arc::new(Semaphore::new(MAX_DEHYDRATE_CONNECTIONS));

    loop {
        let connection_slot = connection_slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| std::io::Error::other("dehydrate pipe semaphore closed"))?;
        let next_server = create_next_pipe_server(pipe_name)?;
        server.connect().await?;
        let connected = server;
        server = next_server;

        tokio::spawn(async move {
            let _connection_slot = connection_slot;
            let (mut read_half, mut write_half) = tokio::io::split(connected);
            if let Err(e) = handle_one_request(&mut read_half, &mut write_half).await {
                eprintln!("yadorilink-cfapi-host: dehydrate pipe connection ended: {e}");
            }
            let _ = write_half.shutdown().await;
        });
    }
}

async fn handle_one_request<R, W>(read_half: &mut R, write_half: &mut W) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let Some(incoming) = read_message::<ShellIpcMessage>(read_half).await? else {
        return Ok(()); // client disconnected without sending anything
    };
    let response = match incoming.payload {
        Some(Payload::DehydrateRequest(req)) => {
            let path = Path::new(&req.path);
            match crate::cfapi::dehydrate_placeholder(path, req.expected_generation) {
                Ok(()) => DehydrateResponse { ok: true, error: String::new() },
                Err(error) => DehydrateResponse { ok: false, error },
            }
        }
        _ => DehydrateResponse {
            ok: false,
            error: "expected a DehydrateRequest on this connection".to_string(),
        },
    };
    write_message(
        write_half,
        &ShellIpcMessage { payload: Some(Payload::DehydrateResponse(response)) },
    )
    .await
}
