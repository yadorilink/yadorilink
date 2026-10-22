//! Bearer-token generation/storage for this adapter's own auth.
//!
//! Mirrors two existing local-secret patterns already established in this
//! codebase rather than inventing a third:
//! - generation: `yadorilink-root-authority::root_identity::mint_root_token`'s
//!   "32 random bytes via `rand::fill`, hex-encoded" shape (`rand = "0.10.2"`
//!   is the version this whole workspace already pins for exactly this kind
//!   of use);
//! - storage: `yadorilink-daemon::resource_lock::open_sidecar_file` /
//!   `shell_ipc::unix_transport::serve`'s "our own sidecar file, `0o600` on
//!   Unix, parent directory `0o700`" convention -- the same reasoning
//!   `control_socket::unix_transport::serve`'s own doc comment gives for its
//!   socket file ("restrict to the owning user so another local account
//!   can't ... (defense in depth)") applies equally here.
//!
//! A fresh token is generated on every daemon startup and never persisted
//! across restarts -- deliberate, not a limitation: it bounds a leaked
//! token's usable lifetime to one daemon run, and it means there is no
//! "first run vs. subsequent run" special case to get wrong.
//!
//! Matching this codebase's existing precedent exactly: the `0o600`/`0o700`
//! narrowing below is Unix-only. `resource_lock.rs`'s sidecar file and
//! `shell_ipc.rs`'s socket file apply no equivalent ACL restriction on
//! Windows either (Windows local-IPC secrecy in this codebase is handled
//! separately, via named-pipe ACLs in `windows_pipe_security.rs`, which
//! doesn't apply to a plain file); this crate does not introduce a new
//! Windows-specific mechanism.

use std::path::Path;

/// Generates a fresh 256-bit token, hex-encoded (64 characters).
pub fn generate() -> String {
    random_hex(32)
}

/// Generates `n_bytes` of randomness, hex-encoded. Shared by the bearer
/// token above and `webui::index`'s per-request CSP script nonce (16 bytes
/// there -- 128 bits, the minimum the CSP spec recommends for a nonce, well
/// under this token's own 256 bits since a nonce only needs to be
/// unguessable for one page load, not to double as a standing secret).
pub fn random_hex(n_bytes: usize) -> String {
    let mut bytes = vec![0u8; n_bytes];
    rand::fill(bytes.as_mut_slice());
    hex::encode(bytes)
}

/// Writes `token` to `path`. The file is created with `0o600` from the
/// instant it exists (the exact mode is passed to `open(2)`'s `O_CREAT`, not
/// applied after the fact), so there is no window where a concurrently
/// running process on this machine could observe it more permissively than
/// its final mode; `set_permissions` afterward additionally covers the case
/// where `path` already existed (a file's mode is not affected by `O_CREAT`
/// when the file isn't newly created).
#[cfg(unix)]
pub fn write_token_file(path: &Path, token: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(token.as_bytes())?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
pub fn write_token_file(path: &Path, token: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, token)
}

#[cfg(test)]
mod tests;
