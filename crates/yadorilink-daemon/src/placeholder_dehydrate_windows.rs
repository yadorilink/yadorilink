#![cfg(windows)]

//! The daemon-process side of `dehydrate_server`'s pipe --
//! `materialization_eviction.rs`'s ONLY way to get a confirmed answer
//! that a Windows placeholder's local content was actually dehydrated
//! before it commits the row to `Remote` and reclaims blocks. See
//! `crates/yadorilink-shell-ext-windows/src/dehydrate_server.rs`'s own module doc for why
//! this is a real cross-process RPC (daemon dials cfapi-host), unlike
//! `placeholder_inspect_windows.rs`'s direct-call bet for the read-only
//! dirty-detection query.
//!
//! Mirrors `shell_ipc::client::query_status`'s Windows client (bounded retry
//! on `ERROR_PIPE_BUSY`), and additionally verifies that the pipe is served by
//! a process running as the current user before sending anything, as
//! `crates/yadorilink-shell-ext-windows/src/ipc_client.rs` does.

use std::sync::OnceLock;
use std::time::Duration;

use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::runtime::Runtime;
use yadorilink_ipc_proto::framing::{read_message, write_message};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{DehydrateRequest, DehydrateResponse, ShellIpcMessage};

const ERROR_PIPE_BUSY: i32 = 231;
const MAX_ATTEMPTS: u32 = 5;
const RETRY_DELAY: Duration = Duration::from_millis(50);

/// `MaterializationExecutionPort::dehydrate_windows_placeholder` (the port
/// method `materialization_eviction::evict_to_placeholder` calls) is a
/// plain synchronous trait method -- matching every other method on that
/// port, and callable from `evict_file`'s own synchronous call sites
/// (the eviction sweep, the CLI's manual evict command) without requiring
/// them to become async -- but this module's own client call is
/// inherently async (named-pipe I/O). Bridges the two with a dedicated,
/// lazily-started, single-threaded runtime blocked on per call, the exact
/// same pattern `crates/yadorilink-shell-ext-windows/src/ipc_client.rs`'s own doc comment
/// documents for the identical problem on the shell-extension side
/// ("COM shell-extension callbacks are inherently synchronous, so this
/// module owns one... runtime and blocks on it per call"). A dedicated
/// runtime rather than `tokio::runtime::Handle::current().block_on(...)`:
/// the latter panics if `evict_file` is ever called from within an
/// existing async task on a current-thread runtime (nesting a runtime
/// inside itself) -- an independent runtime has no such restriction, at
/// the cost of blocking whatever OS thread calls in for up to
/// `DEHYDRATE_TIMEOUT`.
fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to start the dehydrate pipe client's background Tokio runtime")
    })
}

/// Synchronous wrapper around [`dehydrate_via_cfapi_host`] -- see
/// [`runtime`]'s doc comment for why a blocking wrapper is needed here.
/// This is what `ReplicaCoordinator`'s `MaterializationExecutionPort`
/// implementation actually calls.
pub fn dehydrate_via_cfapi_host_blocking(
    absolute_path: &str,
    expected_generation: u64,
) -> Result<(), DehydrateError> {
    runtime().block_on(dehydrate_via_cfapi_host(absolute_path, expected_generation))
}

/// Bounded well above any expected `CfDehydratePlaceholder` call (a local,
/// synchronous driver operation with no network I/O, unlike hydration's
/// `HYDRATE_TIMEOUT`) but still finite: if `cfapi-host.exe` is wedged or
/// its dehydrate pipe is saturated, `evict_file`'s caller must eventually
/// get an error back rather than hang the eviction sweep indefinitely --
/// see [`DehydrateError`]'s own doc comment for what the caller does with
/// that error (NOT an unconditional rollback to `Present`).
const DEHYDRATE_TIMEOUT: Duration = Duration::from_secs(15);

/// Not every variant here means "dehydration did NOT happen":
/// `dehydrate_server` performs the real
/// `CfDehydratePlaceholder` call BEFORE writing its response, so `Io`/
/// `Timeout` can both occur AFTER that call already succeeded server-side
/// (a dropped connection, a lost response, a slow driver call racing the
/// client's own timeout). Only [`Self::Rejected`] means a coherent
/// response was actually received, so cfapi-host's own logic ran to
/// completion and its answer can be trusted.
///
/// `dehydrate_windows_placeholder`'s `ReplicaCoordinator` implementation
/// maps this split onto two DIFFERENT `MaterializationExecutionError`
/// variants for exactly this reason: `Io`/`Timeout` become
/// `EvictionOutcomeAmbiguous` (the caller must NOT assume the file is
/// still materialized), `Rejected` becomes `EvictionRejected` (the caller
/// safely rolls the row back to `Present`). A `CfDehydratePlaceholder`
/// call that itself partially completes before erroring at the Win32
/// layer is a separate, deeper residual risk this module cannot close
/// (see `dehydrate_placeholder`'s own doc comment in `cfapi.rs`) --
/// orthogonal to the transport-level ambiguity this enum's split exists
/// to handle.
#[derive(Debug)]
pub enum DehydrateError {
    Io(std::io::Error),
    Timeout,
    /// cfapi-host itself reported failure (`DehydrateResponse{ ok: false,
    /// error }`), or returned a well-formed message of an unexpected
    /// payload type -- the `String` is a human-readable reason for
    /// logging, not something a caller should pattern-match on.
    Rejected(String),
}

impl std::fmt::Display for DehydrateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DehydrateError::Io(e) => write!(f, "dehydrate pipe I/O error: {e}"),
            DehydrateError::Timeout => {
                write!(f, "dehydrate pipe call timed out after {DEHYDRATE_TIMEOUT:?}")
            }
            DehydrateError::Rejected(reason) => write!(f, "dehydrate rejected: {reason}"),
        }
    }
}

impl std::error::Error for DehydrateError {}

/// Must agree with the host's `dehydrate_server::pipe_name`: both use the one state-dir derivation.
fn pipe_name() -> String {
    yadorilink_fs_platform::state_dir::dehydrate_pipe_name()
}

/// Asks `cfapi-host.exe` to natively dehydrate the placeholder at
/// `absolute_path`, blocking until it confirms success or failure (or
/// this call times out). `expected_generation`: the generation this
/// process's index has recorded for the file (see
/// `MaterializationExecutionPort::get_recorded_placeholder_identity`),
/// passed through unchanged as `DehydrateRequest`'s own defense-in-depth
/// identity guard. cfapi-host always verifies it; there is no
/// unconditional-dehydrate path.
pub async fn dehydrate_via_cfapi_host(
    absolute_path: &str,
    expected_generation: u64,
) -> Result<(), DehydrateError> {
    tokio::time::timeout(DEHYDRATE_TIMEOUT, dehydrate_inner(absolute_path, expected_generation))
        .await
        .map_err(|_| DehydrateError::Timeout)?
}

async fn dehydrate_inner(
    absolute_path: &str,
    expected_generation: u64,
) -> Result<(), DehydrateError> {
    let mut stream = connect().await.map_err(DehydrateError::Io)?;
    write_message(
        &mut stream,
        &ShellIpcMessage {
            payload: Some(Payload::DehydrateRequest(DehydrateRequest {
                path: absolute_path.to_string(),
                expected_generation,
            })),
        },
    )
    .await
    .map_err(DehydrateError::Io)?;
    let response =
        read_message::<ShellIpcMessage>(&mut stream).await.map_err(DehydrateError::Io)?;
    // `None` here means the connection closed with no message at all --
    // e.g. cfapi-host crashed or dropped the pipe after actually running
    // the dehydrate but before it could write the response back. That is
    // exactly as ambiguous as a bare `Io`/`Timeout` failure (the operation
    // may have already succeeded), NOT a coherent "it was rejected"
    // answer -- routed through the `Io` arm below so it reaches the
    // caller as `EvictionOutcomeAmbiguous`, not `EvictionRejected`.
    let Some(payload) = response.and_then(|m| m.payload) else {
        return Err(DehydrateError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "dehydrate pipe closed before sending a response",
        )));
    };
    match payload {
        Payload::DehydrateResponse(DehydrateResponse { ok: true, .. }) => Ok(()),
        Payload::DehydrateResponse(DehydrateResponse { ok: false, error }) => {
            Err(DehydrateError::Rejected(error))
        }
        // A well-formed message of the WRONG payload type -- structurally
        // unreachable given `dehydrate_server` only ever sends
        // `DehydrateResponse` on this connection, but a real (if
        // malformed) message was received, so treated as a coherent
        // (if nonsensical) answer rather than routed through the
        // ambiguous `Io` path.
        _ => Err(DehydrateError::Rejected(
            "cfapi-host's dehydrate pipe returned an unexpected payload type".to_string(),
        )),
    }
}

async fn connect() -> std::io::Result<NamedPipeClient> {
    let name = pipe_name();
    let mut attempt = 0;
    loop {
        match ClientOptions::new().open(&name) {
            Ok(client) => {
                // A pipe another user created first could answer "dehydrated"
                // and make the caller reclaim blocks still needed locally.
                yadorilink_ipc_proto::pipe_peer::verify_pipe_server_is_current_user(&client)?;
                return Ok(client);
            }
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempt < MAX_ATTEMPTS => {
                attempt += 1;
                tokio::time::sleep(RETRY_DELAY).await;
            }
            Err(e) => return Err(e),
        }
    }
}
