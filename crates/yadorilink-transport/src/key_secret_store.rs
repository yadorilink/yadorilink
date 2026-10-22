//! Storage-at-rest for a device's 32-byte private key secret: the Ed25519
//! seed that is this device's whole identity, signing its change history and
//! authenticating its transport.
//!
//! Two layers are used, in defense-in-depth order:
//!
//!  1. The OS keyring (macOS Keychain / Windows Credential Manager / Linux
//!     Secret Service) via the `keyring` crate — the same OS-native credential
//!     store the coordination-token loader uses. Encrypted / access-controlled
//!     by the OS.
//!  2. A hardened on-disk file holding one hex-encoded 32-byte secret, created
//!     owner-only: unix `0o600`, and on Windows a DACL restricted to the
//!     current user with inheritance disabled (see `harden_key_file`) — the
//!     practical equivalent of `0o600`, because a freshly created file would
//!     otherwise inherit the parent directory's weaker ACL.
//!
//! The on-disk file is the SOURCE OF TRUTH for the device identity and is
//! never deleted: losing it de-identifies the device permanently. The keyring
//! copy is populated best-effort and serves two purposes — recovering the file
//! if it is lost or damaged, and adding at-rest protection where the OS keyring
//! is available.
//!
//! Durability rules, all enforced by the single [`write_secret_file`]
//! primitive. Every secret file this module creates goes through it, so a
//! future writer cannot reintroduce a half-written or world-readable key file:
//!
//!  * The secret is written to a temporary file, `sync_all`'d, and only then
//!    published under its final name. The final name therefore never exists in
//!    a partially written state, so a power cut can lose the write but can
//!    never corrupt an identity that was already there.
//!  * Publication refuses to replace by default. A plain `rename` replaces the
//!    destination unconditionally, which would silently break the create-race
//!    recovery both callers in `keys.rs` depend on: two daemons starting
//!    concurrently would each publish their own freshly generated identity and
//!    the loser would keep using a secret that is no longer on disk. A
//!    no-replace publish (`durable_dir::publish_durably` with `Replace::No`: a
//!    no-replace durable move, or a hard link where the volume offers none)
//!    fails with `AlreadyExists` instead, so the loser reliably re-reads the
//!    winner's file. [`Publish::Replace`] opts into clobbering, and is used
//!    only to repair a file whose bytes are already known to be garbage. The
//!    new name is on disk when the publish returns.
//!  * The file is made owner-only *before* any secret byte reaches it, and a
//!    hardening failure aborts the write rather than warning. A key file at the
//!    OS default ACL is not an acceptable outcome.
//!
//! Because a corrupt key file is recoverable from the keyring and an absent one
//! is regenerated, the identity survives every crash point in this module; the
//! one unrecoverable state — a file that decodes to the wrong secret — is the
//! state the atomic publication above makes unreachable.
//!
//! Note on guarantees: the file fallback stores the secret as plaintext-at-rest
//! protected only by filesystem permissions. The keyring is defense-in-depth,
//! not a guarantee on every platform — a headless Linux host with no Secret
//! Service simply keeps using the hardened file. Which path is in use is logged
//! at load/persist time.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::error::TransportError;

/// OS keyring service name. Shared with the coordination-token loader; device
/// key entries use path-derived usernames (see `keyring_username`) so they can
/// never collide with the token loader's fixed usernames.
#[cfg(all(not(test), not(turmoil), any(windows, target_os = "linux")))]
const KEYRING_SERVICE: &str = "yadorilink";

/// Decodes the hex-encoded 32-byte secret held in `contents`.
fn decode_secret(contents: &str) -> Result<Zeroizing<[u8; 32]>, TransportError> {
    let bytes = Zeroizing::new(
        hex::decode(contents.trim()).map_err(|e| TransportError::InvalidKey(e.to_string()))?,
    );
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| TransportError::InvalidKey("private key must be 32 bytes".into()))?;
    Ok(Zeroizing::new(array))
}

/// What a key file at a given path turned out to hold.
enum KeyFile {
    Secret(Zeroizing<[u8; 32]>),
    Missing,
    /// The file exists but holds no usable secret: empty, truncated, or
    /// non-UTF-8 garbage. This is distinct from an I/O failure because it is
    /// recoverable — the keyring may still hold the identity — whereas an
    /// unreadable file (EACCES, EIO) signals a sick system that we must not
    /// paper over by rewriting the key file from a second-hand copy.
    Corrupt(TransportError),
}

/// Reads and decodes the key file at `path`.
///
/// Reads bytes rather than a `String` so that non-UTF-8 content is classified
/// as [`KeyFile::Corrupt`] (recoverable) instead of surfacing as an I/O error;
/// a torn write can leave arbitrary bytes behind.
fn read_secret_file(path: &Path) -> Result<KeyFile, TransportError> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            let Ok(text) = std::str::from_utf8(&bytes) else {
                return Ok(KeyFile::Corrupt(TransportError::InvalidKey(
                    "device key file is not valid UTF-8".into(),
                )));
            };
            Ok(match decode_secret(text) {
                Ok(secret) => KeyFile::Secret(secret),
                Err(err) => KeyFile::Corrupt(err),
            })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(KeyFile::Missing),
        Err(err) => Err(err.into()),
    }
}

/// How [`write_secret_file`] publishes the finished file under its final name.
enum Publish {
    /// Fail with `AlreadyExists` if the name is already taken. Used whenever a
    /// new identity is recorded: a concurrent creator must lose the race and
    /// adopt the winner's identity rather than overwrite it.
    CreateNew,
    /// Replace whatever is at the name. Only for repairing a file already
    /// established to be corrupt, where the existing bytes carry no identity
    /// and there is nothing to lose.
    Replace,
}

/// Writes `secret` to `path` durably and owner-only.
///
/// The one primitive every secret file in this module is created through; see
/// the module docs for the durability and exclusivity rules it enforces.
fn write_secret_file(
    path: &Path,
    secret: &[u8; 32],
    publish: Publish,
) -> Result<(), TransportError> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        // A bare file name is relative to the current directory, which is also
        // where the temporary file has to land so the publishing link stays
        // within one filesystem.
        _ => PathBuf::from("."),
    };
    yadorilink_fs_platform::durable_dir::create_dir_all_durably(&parent)?;

    let (temp_path, file) = create_temp_secret_file(&parent, path)?;
    let published = write_and_publish(file, &temp_path, path, secret, publish);

    // Always drop the temporary name: on success it is a redundant second link
    // to the published file (or already consumed by a `Replace`), and on
    // failure it holds a secret that nobody will ever read.
    let _ = std::fs::remove_file(&temp_path);

    published
}

/// Creates a uniquely named, owner-only, empty temporary file next to `path`.
///
/// The random suffix keeps two concurrent writers from colliding; a collision
/// that does happen is retried rather than surfaced, because callers read
/// `AlreadyExists` as "another process published the identity first" and a
/// temp-name clash must never be mistaken for that.
fn create_temp_secret_file(
    parent: &Path,
    path: &Path,
) -> Result<(PathBuf, std::fs::File), TransportError> {
    let file_name = path
        .file_name()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "device key path has no file name",
            )
        })?
        .to_string_lossy()
        .into_owned();

    for _ in 0..16 {
        let mut nonce = [0u8; 8];
        rand::fill(&mut nonce[..]);
        let temp_path = parent.join(format!("{file_name}.tmp.{:016x}", u64::from_le_bytes(nonce)));
        match create_owner_only_file(&temp_path) {
            Ok(file) => return Ok((temp_path, file)),
            Err(TransportError::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                continue
            }
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::other("could not create a unique temporary device key file").into())
}

/// Creates `path` exclusively and restricts it to the current user, returning
/// the open handle.
///
/// Hardening happens here, on the still-empty file, so no secret byte is ever
/// written to a file at the OS default permissions — and a hardening failure is
/// fatal, because at this point there is nothing to lose by aborting.
fn create_owner_only_file(path: &Path) -> Result<std::fs::File, TransportError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Narrow the window: the file is owner-only from the instant it exists,
        // rather than briefly at the mode `harden_key_file` will re-assert.
        options.mode(0o600);
    }
    let file = options.open(path)?;

    if let Err(err) = harden_key_file(path) {
        let _ = std::fs::remove_file(path);
        return Err(err);
    }
    Ok(file)
}

/// Fills, flushes and publishes the temporary file created for `path`.
fn write_and_publish(
    mut file: std::fs::File,
    temp_path: &Path,
    path: &Path,
    secret: &[u8; 32],
    publish: Publish,
) -> Result<(), TransportError> {
    use std::io::Write;

    let encoded = Zeroizing::new(hex::encode(secret));
    file.write_all(encoded.as_bytes())?;
    // `sync_all`, not `flush`: flush only pushes the bytes out of the process,
    // which a power cut discards. The fsync must complete before the final name
    // exists, or the name could be published pointing at unwritten blocks.
    file.sync_all()?;
    drop(file);

    use yadorilink_fs_platform::durable_dir::{publish_durably, Replace};
    match publish {
        // Atomic *and* exclusive. See the module docs for why this is not a
        // plain `rename`.
        Publish::CreateNew => publish_durably(temp_path, path, Replace::No)?,
        Publish::Replace => publish_durably(temp_path, path, Replace::Yes)?,
    }
    Ok(())
}

/// Restricts a private-key file to the current user only.
///
/// On unix this re-asserts `0o600` even though the file is created with that
/// mode: `open`'s mode argument is masked by the process umask, and the load
/// path uses this to tighten a key file that was created before hardening
/// existed or had its mode loosened since. On Windows a newly created file
/// inherits the parent directory's DACL, so we replace it with a protected,
/// current-user-only DACL — the practical equivalent of `0o600`.
#[cfg(unix)]
fn harden_key_file(path: &Path) -> Result<(), TransportError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn harden_key_file(_path: &Path) -> Result<(), TransportError> {
    Ok(())
}

#[cfg(windows)]
fn harden_key_file(path: &Path) -> Result<(), TransportError> {
    windows_acl::restrict_to_current_user(path).map_err(TransportError::Io)
}

// --- Keyring layer -------------------------------------------------------
//
// Three build variants, mutually exclusive and exhaustive:
//   * cfg(test)                      -> in-memory store, never touches the real
//                                       OS keychain (avoids prompts / pollution
//                                       and keeps tests deterministic).
//   * not(test), not(turmoil)        -> the real OS keyring.
//   * not(test), turmoil             -> no-op (simulation stays deterministic
//                                       and never reaches for a real keychain).
// On top of these, `YADORILINK_DISABLE_OS_KEYRING=1` short-circuits both entry
// points before any backend is reached (see `DISABLE_OS_KEYRING_VAR`).

/// Outcome of mirroring the on-disk secret into the OS keyring.
///
/// Simulation builds never reach a real keychain, so only `Unavailable` is
/// constructed there; the variants still have to exist for the shared load path
/// to match on.
#[cfg_attr(all(not(test), turmoil), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyringMirror {
    /// The keyring holds this exact secret — it already did, or we wrote it and
    /// read it back.
    Present,
    /// The keyring is unavailable, locked, or failed. File-only at rest.
    Unavailable,
    /// The keyring holds a *different* secret for this path. Never resolved by
    /// overwriting: a mirror that the file silently overwrites is not an
    /// independent copy of anything, and whichever side is stale, destroying it
    /// is the one irreversible move available here.
    Conflict,
}

/// What a keyring lookup found, telling a missing entry from a keyring that could not be asked.
#[cfg_attr(all(not(test), turmoil), allow(dead_code))]
enum KeyringProbe {
    /// The keyring answered and holds no usable entry for the path.
    Absent,
    /// The entry's secret.
    Held(Zeroizing<[u8; 32]>),
    /// The keyring is locked, unavailable or failed: nothing is known about the entry.
    Unavailable,
}

/// The raw answer of the OS store for one username.
#[cfg(all(not(test), not(turmoil)))]
enum StoreRead {
    Absent,
    Value(String),
    Failed,
}

/// The keyring lookup key for a given on-disk key file: the file's absolute
/// path. Each device-key file therefore maps 1:1 to its own keyring entry and
/// cannot collide with another key file or with the coordination-token entries
/// (which use fixed, non-path usernames).
#[cfg(any(test, not(turmoil)))]
fn keyring_username(path: &Path) -> String {
    let abs = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
    format!("device-key:{}", abs.to_string_lossy())
}

/// The real OS store, by username: Windows Credential Manager / Linux Secret
/// Service through `keyring`.
#[cfg(all(not(test), not(turmoil), any(windows, target_os = "linux")))]
fn os_store_read(username: &str) -> StoreRead {
    let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, username) else {
        return StoreRead::Failed;
    };
    match entry.get_password() {
        Ok(value) => StoreRead::Value(value),
        Err(keyring::Error::NoEntry) => StoreRead::Absent,
        Err(_) => StoreRead::Failed,
    }
}

#[cfg(all(not(test), not(turmoil), any(windows, target_os = "linux")))]
fn os_store_set(username: &str, value: &str) -> bool {
    keyring::Entry::new(KEYRING_SERVICE, username).is_ok_and(|e| e.set_password(value).is_ok())
}

/// A target with no OS store backend (iOS until it has a Data Protection Keychain backend, the
/// BSDs): the mirror is honestly `Unavailable` and the hardened key file stays the only copy. There
/// is no store that could hold a retired key, so a lookup finds the entry absent.
/// `keyring` is not a dependency here, so nothing can fall back to its in-memory mock, which
/// would report a mirrored secret that vanishes at the next process start.
#[cfg(all(not(test), not(turmoil), not(any(windows, target_os = "linux", target_os = "macos"))))]
fn os_store_read(_username: &str) -> StoreRead {
    StoreRead::Absent
}

#[cfg(all(not(test), not(turmoil), not(any(windows, target_os = "linux", target_os = "macos"))))]
fn os_store_set(_username: &str, _value: &str) -> bool {
    false
}

/// The real OS store on macOS: the Data Protection Keychain, in the credential
/// access group (`yadorilink-os-keychain`). A process not signed with the group
/// (an extension, an unsigned dev build) gets an error here, which is the
/// `Unavailable` outcome: the key file stays the source of truth.
#[cfg(all(not(test), not(turmoil), target_os = "macos"))]
fn os_store_read(username: &str) -> StoreRead {
    match yadorilink_os_keychain::Keychain::system().read(username) {
        Ok(Some(bytes)) => String::from_utf8(bytes).map_or(StoreRead::Absent, StoreRead::Value),
        Ok(None) => StoreRead::Absent,
        Err(_) => StoreRead::Failed,
    }
}

#[cfg(all(not(test), not(turmoil)))]
fn os_store_get(username: &str) -> Option<String> {
    match os_store_read(username) {
        StoreRead::Value(value) => Some(value),
        StoreRead::Absent | StoreRead::Failed => None,
    }
}

#[cfg(all(not(test), not(turmoil), target_os = "macos"))]
fn os_store_set(username: &str, value: &str) -> bool {
    yadorilink_os_keychain::Keychain::system().write(username, value.as_bytes()).is_ok()
}

#[cfg(all(not(test), not(turmoil)))]
fn keyring_load_backend(path: &Path) -> Option<Zeroizing<[u8; 32]>> {
    let hex = Zeroizing::new(os_store_get(&keyring_username(path))?);
    decode_secret(&hex).ok()
}

#[cfg(all(not(test), not(turmoil)))]
fn keyring_probe_backend(path: &Path) -> KeyringProbe {
    match os_store_read(&keyring_username(path)) {
        StoreRead::Absent => KeyringProbe::Absent,
        StoreRead::Failed => KeyringProbe::Unavailable,
        // An entry we cannot decode holds no identity.
        StoreRead::Value(hex) => {
            decode_secret(&Zeroizing::new(hex)).map_or(KeyringProbe::Absent, KeyringProbe::Held)
        }
    }
}

/// Mirrors `secret` into the keyring. Best-effort: any keyring failure
/// (unavailable / locked / headless) reports `Unavailable` — the hardened file
/// remains the source of truth. Nothing is ever deleted based on the result.
#[cfg(all(not(test), not(turmoil)))]
fn keyring_mirror_backend(path: &Path, secret: &[u8; 32]) -> KeyringMirror {
    if let Some(existing) = os_store_get(&keyring_username(path)) {
        let existing = Zeroizing::new(existing);
        match decode_secret(&existing) {
            Ok(existing) if existing.as_slice() == secret.as_slice() => {
                return KeyringMirror::Present
            }
            Ok(_) => return KeyringMirror::Conflict,
            // An entry we cannot decode holds no identity, so replacing it
            // destroys nothing and lets a damaged keyring entry self-heal.
            Err(_) => {}
        }
    }

    let encoded = Zeroizing::new(hex::encode(secret));
    if !os_store_set(&keyring_username(path), &encoded) {
        return KeyringMirror::Unavailable;
    }
    // Independent round-trip read-back: only claim success when the keyring
    // actually returns the secret we just wrote.
    match keyring_load_backend(path) {
        Some(v) if v.as_slice() == secret.as_slice() => KeyringMirror::Present,
        _ => KeyringMirror::Unavailable,
    }
}

/// Overwrites the keyring entry of `path` with `secret`. Only [`replace_retiring`] calls it, after
/// the secret being displaced is safe under another name.
#[cfg(all(not(test), not(turmoil)))]
fn keyring_overwrite_backend(path: &Path, secret: &[u8; 32]) -> bool {
    let encoded = Zeroizing::new(hex::encode(secret));
    os_store_set(&keyring_username(path), &encoded)
}

#[cfg(all(not(test), turmoil))]
fn keyring_overwrite_backend(_path: &Path, _secret: &[u8; 32]) -> bool {
    false
}

#[cfg(test)]
fn keyring_overwrite_backend(path: &Path, secret: &[u8; 32]) -> bool {
    test_keyring::set(&keyring_username(path), secret)
}

/// Simulation never reaches a keychain, so there is never an entry to find.
#[cfg(all(not(test), turmoil))]
fn keyring_probe_backend(_path: &Path) -> KeyringProbe {
    KeyringProbe::Absent
}

#[cfg(all(not(test), turmoil))]
fn keyring_load_backend(_path: &Path) -> Option<Zeroizing<[u8; 32]>> {
    None
}

#[cfg(all(not(test), turmoil))]
fn keyring_mirror_backend(_path: &Path, _secret: &[u8; 32]) -> KeyringMirror {
    KeyringMirror::Unavailable
}

#[cfg(test)]
fn keyring_probe_backend(path: &Path) -> KeyringProbe {
    match test_keyring::probe(&keyring_username(path)) {
        None => KeyringProbe::Unavailable,
        Some(None) => KeyringProbe::Absent,
        Some(Some(secret)) => KeyringProbe::Held(Zeroizing::new(secret)),
    }
}

#[cfg(test)]
fn keyring_load_backend(path: &Path) -> Option<Zeroizing<[u8; 32]>> {
    test_keyring::get(&keyring_username(path)).map(Zeroizing::new)
}

#[cfg(test)]
fn keyring_mirror_backend(path: &Path, secret: &[u8; 32]) -> KeyringMirror {
    if let Some(existing) = test_keyring::get(&keyring_username(path)) {
        return if existing == *secret { KeyringMirror::Present } else { KeyringMirror::Conflict };
    }
    if !test_keyring::set(&keyring_username(path), secret) {
        return KeyringMirror::Unavailable;
    }
    match keyring_load_backend(path) {
        Some(v) if v.as_slice() == secret.as_slice() => KeyringMirror::Present,
        _ => KeyringMirror::Unavailable,
    }
}

/// Environment switch that turns the OS keyring mirror off entirely: with
/// `YADORILINK_DISABLE_OS_KEYRING=1` no keyring read, write or probe is ever
/// issued and the hardened key file is the only copy (the same "OS keyring
/// unavailable, using file at rest" path as a headless host). Production
/// default is unchanged: unset means the keyring is used. Test and sweep
/// harnesses set it (`.config/nextest.toml`)
/// so a run never touches the developer's real keychain; the credential store
/// has its own, existing `YADORILINK_CREDENTIAL_STORE=file`, which the same
/// harnesses set alongside.
#[cfg(not(test))]
const DISABLE_OS_KEYRING_VAR: &str = "YADORILINK_DISABLE_OS_KEYRING";

/// Whether `value` of [`DISABLE_OS_KEYRING_VAR`] switches the keyring off.
fn disables_keyring(value: Option<&str>) -> bool {
    matches!(value, Some("1"))
}

/// Unit tests ignore the environment (the harness sets it for the whole run,
/// and the in-memory keyring tests must still exercise the mirror); they drive
/// the switch through `test_keyring::set_disabled` instead.
fn os_keyring_disabled() -> bool {
    #[cfg(test)]
    return test_keyring::disabled();
    #[cfg(not(test))]
    return disables_keyring(std::env::var(DISABLE_OS_KEYRING_VAR).ok().as_deref());
}

fn keyring_load(path: &Path) -> Option<Zeroizing<[u8; 32]>> {
    if os_keyring_disabled() {
        return None;
    }
    keyring_load_backend(path)
}

fn keyring_mirror(path: &Path, secret: &[u8; 32]) -> KeyringMirror {
    if os_keyring_disabled() {
        return KeyringMirror::Unavailable;
    }
    keyring_mirror_backend(path, secret)
}

// --- Orchestration -------------------------------------------------------

/// Loads the persisted 32-byte secret for `path`, or `None` if neither the
/// hardened file nor the keyring holds one.
///
/// The on-disk file is the source of truth. If it decodes it is used, and the
/// keyring is brought up to date to mirror it (the migration path for
/// identities created before keyring storage existed). If the file is missing
/// or corrupt but the keyring still holds the identity, the secret is recovered
/// from the keyring and the hardened file is restored. The file is never
/// deleted, so the device identity cannot be lost.
pub(crate) fn load_persisted_secret(
    path: &Path,
) -> Result<Option<Zeroizing<[u8; 32]>>, TransportError> {
    match read_secret_file(path)? {
        KeyFile::Secret(secret) => {
            // Re-assert restrictive permissions on load, so a key file that a
            // previous write could not harden is tightened on the next daemon
            // start. Best-effort *here* — unlike the create path, the identity
            // already exists and refusing to load it over a permissions call we
            // cannot complete would lock the user out of their own device.
            if let Err(err) = harden_key_file(path) {
                tracing::warn!("could not re-restrict permissions on device key file: {err}");
            }
            match keyring_mirror(path, &secret) {
                KeyringMirror::Present => {
                    tracing::debug!(
                        "device key loaded from hardened file; OS keyring copy present"
                    );
                }
                KeyringMirror::Unavailable => {
                    tracing::debug!(
                        "device key loaded from hardened file; OS keyring unavailable, using file at rest"
                    );
                }
                KeyringMirror::Conflict => {
                    tracing::warn!(
                        "the OS keyring holds a different device key than the key file; \
                         keeping the key file as the source of truth and leaving the keyring \
                         entry untouched for inspection"
                    );
                }
            }
            Ok(Some(secret))
        }

        // The config directory was wiped while the OS credential store survived.
        KeyFile::Missing => recover_from_keyring(path),

        // A file that exists but does not decode is what a power cut during a
        // pre-atomic write leaves behind. The keyring may still hold the
        // identity, so this must not be reported before asking it — returning
        // the decode error here would strand a device whose key the OS keyring
        // could have handed back.
        KeyFile::Corrupt(err) => {
            let Some(secret) = keyring_load(path) else {
                return Err(err);
            };
            // Deliberately not a regenerate: the file is unreadable, not
            // absent, so `Replace` restores the identity the keyring vouches
            // for instead of minting a new one.
            write_secret_file(path, &secret, Publish::Replace)?;
            tracing::warn!(
                "device key file was unreadable ({err}); restored it from the OS keyring copy"
            );
            Ok(Some(secret))
        }
    }
}

/// Restores the on-disk source of truth from the keyring copy, if there is one.
fn recover_from_keyring(path: &Path) -> Result<Option<Zeroizing<[u8; 32]>>, TransportError> {
    let Some(secret) = keyring_load(path) else {
        return Ok(None);
    };
    match write_secret_file(path, &secret, Publish::CreateNew) {
        Ok(()) => {
            tracing::info!("device key recovered from OS keyring; rewrote hardened file on disk");
            Ok(Some(secret))
        }
        Err(TransportError::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another process created the file first; prefer whatever is on
            // disk now, falling back to the keyring copy we already hold if the
            // winner's bytes are not readable.
            match read_secret_file(path)? {
                KeyFile::Secret(on_disk) => Ok(Some(on_disk)),
                _ => Ok(Some(secret)),
            }
        }
        Err(err) => Err(err),
    }
}

/// Persists a freshly generated secret. Writes the hardened file first, so the
/// device identity is durably recorded on disk before anything else, then
/// mirrors it into the keyring best-effort. Surfaces `AlreadyExists` so the
/// caller can run its create-race recovery.
pub(crate) fn persist_new_secret(path: &Path, secret: &[u8; 32]) -> Result<(), TransportError> {
    write_secret_file(path, secret, Publish::CreateNew)?;
    match keyring_mirror(path, secret) {
        KeyringMirror::Present => {
            tracing::debug!("device key persisted to hardened file and OS keyring");
        }
        KeyringMirror::Unavailable => {
            tracing::info!(
                "device key persisted to hardened file; OS keyring unavailable, using file at rest"
            );
        }
        KeyringMirror::Conflict => {
            tracing::warn!(
                "the OS keyring already holds a different device key for this path; \
                 keeping the new key file as the source of truth and leaving the keyring \
                 entry untouched for inspection"
            );
        }
    }
    Ok(())
}

/// Replaces the identity at `path` with `new`, keeping the displaced one at `retired`.
///
/// The displaced secret is written to `retired` (file and keyring copy) first; only then is `path`
/// replaced and its keyring entry overwritten, so the overwrite destroys nothing, and a lost key
/// file at `path` recovers `new` rather than the retired identity. A `retired` name that already
/// holds a different secret is an error and nothing is replaced. Running it again after an
/// interruption finishes the replacement.
pub(crate) fn replace_retiring(
    path: &Path,
    retired: &Path,
    new: &[u8; 32],
) -> Result<(), TransportError> {
    let current = load_persisted_secret(path)?.ok_or_else(|| {
        TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no device key to retire",
        ))
    })?;
    if current.as_slice() == new.as_slice() {
        // Replaced before an interruption; only the keyring entry may still be behind.
        return overwrite_keyring_entry(path, new);
    }
    match persist_new_secret(retired, &current) {
        Ok(()) => {}
        Err(TransportError::Io(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            match load_persisted_secret(retired)? {
                Some(kept) if kept.as_slice() == current.as_slice() => {}
                Some(_) => {
                    return Err(TransportError::InvalidKey(
                        "the retired key name already holds a different device key".into(),
                    ));
                }
                None => {
                    return Err(TransportError::InvalidKey(
                        "the retired key name could not be read".into(),
                    ))
                }
            }
        }
        Err(err) => return Err(err),
    }
    write_secret_file(path, new, Publish::Replace)?;
    overwrite_keyring_entry(path, new)
}

/// Makes the keyring entry of `path` hold `new`, when the keyring holds an entry for `path` at all.
/// A keyring that cannot be read is an error, never an absent entry. An entry that cannot be replaced is an error: a lost key file would otherwise recover the
/// retired identity from it. Running the replacement again repairs the entry.
fn overwrite_keyring_entry(path: &Path, new: &[u8; 32]) -> Result<(), TransportError> {
    if os_keyring_disabled() {
        return Ok(());
    }
    match keyring_probe_backend(path) {
        KeyringProbe::Absent => return Ok(()),
        KeyringProbe::Held(entry) if entry.as_slice() == new.as_slice() => return Ok(()),
        KeyringProbe::Held(_) => {}
        // A keyring that cannot be asked may still hold the retired key; "absent" is not assumed.
        KeyringProbe::Unavailable => {
            return Err(TransportError::InvalidKey(
                "the OS keyring could not be read, so whether it still holds the retired device \
                 key is unknown; unlock or enable the keyring and run the same step again"
                    .into(),
            ))
        }
    }
    keyring_overwrite_backend(path, new);
    match keyring_load(path) {
        Some(entry) if entry.as_slice() == new.as_slice() => Ok(()),
        _ => Err(TransportError::InvalidKey(
            "the OS keyring entry for the device key could not be replaced; run the same step \
             again once the keyring is available"
                .into(),
        )),
    }
}

/// Owner-only DACL hardening for private-key files on Windows.
#[cfg(windows)]
mod windows_acl {
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{null_mut, NonNull};

    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACL, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// Replaces `path`'s DACL with a protected (no inherited ACEs),
    /// current-user-only entry granting full file access — the Windows
    /// equivalent of unix `0o600`.
    pub(super) fn restrict_to_current_user(path: &Path) -> std::io::Result<()> {
        let sid = current_user_sid_string()?;
        // `D:` DACL, `P` protected (blocks inherited ACEs), one allow ACE
        // granting full access (`FA`) to the current user only.
        let sddl = widestr(&format!("D:P(A;;FA;;;{sid})"));

        let mut security_descriptor: *mut c_void = null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut security_descriptor,
                null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let result = apply_dacl(path, security_descriptor);
        unsafe {
            LocalFree(security_descriptor);
        }
        result
    }

    fn apply_dacl(path: &Path, security_descriptor: *mut c_void) -> std::io::Result<()> {
        let mut dacl_present: i32 = 0;
        let mut dacl: *mut ACL = null_mut();
        let mut dacl_defaulted: i32 = 0;
        let ok = unsafe {
            GetSecurityDescriptorDacl(
                security_descriptor,
                &mut dacl_present,
                &mut dacl,
                &mut dacl_defaulted,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut wide_path: Vec<u16> =
            path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        // PROTECTED_DACL_SECURITY_INFORMATION strips inherited ACEs so the file
        // no longer inherits the parent directory's (weaker) permissions.
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide_path.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }

    fn widestr(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn current_user_sid_string() -> std::io::Result<String> {
        let mut token: HANDLE = null_mut();
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let sid = unsafe { current_user_sid_string_from_token(token) };
        unsafe {
            CloseHandle(token);
        }
        sid
    }

    /// Reads the token's *user* SID.
    ///
    /// `TokenUser`, not `TokenOwner`: the owner SID is merely the default owner
    /// stamped on objects this process creates, and for an elevated process
    /// that is the Administrators *group*. Building the DACL from it would
    /// grant the key file to every local administrator instead of to the one
    /// account the key belongs to.
    unsafe fn current_user_sid_string_from_token(token: HANDLE) -> std::io::Result<String> {
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, null_mut(), 0, &mut len);
        if len == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut buffer = vec![0u8; len as usize];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            len,
            &mut len,
        );
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let user = buffer.as_ptr().cast::<TOKEN_USER>().read_unaligned();
        let mut sid_string = null_mut();
        let ok = ConvertSidToStringSidW(user.User.Sid, &mut sid_string);
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let sid_string = NonNull::new(sid_string)
            .ok_or_else(|| std::io::Error::other("ConvertSidToStringSidW returned null"))?;
        let mut chars = 0usize;
        while *sid_string.as_ptr().add(chars) != 0 {
            chars += 1;
        }
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(sid_string.as_ptr(), chars));
        LocalFree(sid_string.as_ptr().cast::<c_void>());
        Ok(sid)
    }
}

/// In-memory keyring stand-in for tests: never touches the real OS keychain, so
/// unit tests neither prompt for keychain access nor pollute it, and stay
/// deterministic. Defaults to "unavailable" so the file-only fallback is the
/// path exercised unless a test explicitly opts in with `set_available(true)`.
#[cfg(test)]
mod test_keyring;

#[cfg(test)]
mod tests;
