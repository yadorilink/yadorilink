// apple-cfg-file: macos-only ioreg exists only on macOS; other Apple platforms have no machine id, so migration detection is off there
//! A fingerprint of the machine the replica database is opened on.
//!
//! It is **not** part of the author identity. Its only use is to notice a
//! database copied together with its `<db>.instance` sidecar to another
//! machine, and its only effect is a `Migration` rotation of the author
//! incarnation (`yadorilink_sync_sqlite::author_incarnation`).
//!
//! The fingerprint is SHA-256 over the domain string
//! `yadorilink machine fingerprint v1` followed by the platform machine id:
//! IOPlatformUUID on macOS, `/etc/machine-id` (falling back to
//! `/var/lib/dbus/machine-id`) on Linux, and the `MachineGuid` registry value
//! on Windows. An embedding host that supplies its own id ([`install_host_id`]) replaces the
//! platform id on every platform, and iOS has no other source: it reads no hardware
//! identifier, the host passes an install-scoped id (for example one it generated and stored in
//! its app group, or `identifierForVendor`). Such an id resets when the app is reinstalled; the
//! engine's state then goes with it (the app group is deleted with the last app of the vendor),
//! so the fresh install mints a new author incarnation, which is the correct outcome. If the
//! id changes while the database survives (a restore onto another device), the changed
//! fingerprint is a `Migration` rotation. A host that supplies none on iOS is refused at
//! engine start rather than run with migration detection off. When no id is readable the fingerprint is the hash of the
//! domain string and the constant `unavailable` ([`is_unavailable`]) and a
//! warning is logged. The author identity open then compares the record's
//! own fingerprint instead, so migration detection is off for that open
//! (a transient read failure causes no rotation); the device and sidecar
//! checks still apply.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"yadorilink machine fingerprint v1";
const UNAVAILABLE: &[u8] = b"unavailable";

/// The id test engines in this crate's test binary are started with.
#[cfg(test)]
pub(crate) const TEST_HOST_ID: &str = "engine-test-host-id";

/// Why a host machine id was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HostIdError {
    #[error("the host machine id is empty")]
    Empty,
    #[error("the host machine id is the reserved value that marks an unreadable machine id")]
    Reserved,
    #[error("a different host machine id is already in use by this process")]
    Conflict,
    #[error(
        "this process already fingerprinted its machine from the platform id; a host id would \
         change the fingerprint under databases opened with it"
    )]
    PlatformAlreadyUsed,
}

/// Where this process's fingerprint comes from. It is chosen by the first use and then fixed:
/// a source that changed later would make every database opened under the earlier one look
/// like a migration.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    /// Not used yet: either source may still be chosen.
    Unset,
    /// The platform id was used.
    Platform,
    /// The host's id.
    Host(String),
}

/// The process's choice of source (one instance is the process-wide one; tests use their own).
struct Choice(std::sync::Mutex<Source>);

impl Choice {
    const fn new(initial: Source) -> Self {
        Self(std::sync::Mutex::new(initial))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Source> {
        self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether `id` could be installed now. Changes nothing.
    fn check_host(&self, id: &str) -> Result<(), HostIdError> {
        let id = valid_host_id(id)?;
        match &*self.lock() {
            Source::Unset => Ok(()),
            Source::Platform => Err(HostIdError::PlatformAlreadyUsed),
            Source::Host(have) if *have == id => Ok(()),
            Source::Host(_) => Err(HostIdError::Conflict),
        }
    }

    /// Chooses the host's id, or confirms it is already the choice. Nothing changes on refusal.
    fn install_host(&self, id: &str) -> Result<(), HostIdError> {
        let id = valid_host_id(id)?;
        let mut source = self.lock();
        match &*source {
            Source::Unset => {
                *source = Source::Host(id);
                Ok(())
            }
            Source::Platform => Err(HostIdError::PlatformAlreadyUsed),
            Source::Host(have) if *have == id => Ok(()),
            Source::Host(_) => Err(HostIdError::Conflict),
        }
    }

    /// The host id when that is the source; choosing the platform's otherwise.
    fn host_id_or_choose_platform(&self) -> Option<String> {
        let mut source = self.lock();
        match &*source {
            Source::Host(id) => Some(id.clone()),
            Source::Platform => None,
            Source::Unset => {
                *source = Source::Platform;
                None
            }
        }
    }
}

// A test binary starts every engine with `TEST_HOST_ID`, so its source is that id from the
// start; nothing in it reads the real platform id.
#[cfg(test)]
static CHOICE: std::sync::LazyLock<Choice> =
    std::sync::LazyLock::new(|| Choice::new(Source::Host(TEST_HOST_ID.to_owned())));
#[cfg(not(test))]
static CHOICE: Choice = Choice::new(Source::Unset);

/// Whether [`install_host_id`] would accept `id` now. Changes nothing, so a start can refuse
/// before it does anything else.
///
/// # Errors
/// The [`HostIdError`] that installing it would return.
pub fn check_host_id(id: &str) -> Result<(), HostIdError> {
    CHOICE.check_host(id)
}

/// Makes `id` this process's machine id, replacing the platform one. The same id again is
/// accepted. A different one is refused, and so is any id once the platform's was used: the
/// source is fixed by its first use. Nothing changes on refusal.
///
/// # Errors
/// [`HostIdError`].
pub fn install_host_id(id: &str) -> Result<(), HostIdError> {
    CHOICE.install_host(id)
}

/// This machine's fingerprint: the host's id when that is the source, else the platform's,
/// read once per process. The first call fixes the source.
pub fn machine_fingerprint() -> Vec<u8> {
    if let Some(id) = CHOICE.host_id_or_choose_platform() {
        return fingerprint_of(Some(&id));
    }
    static CACHED: OnceLock<Vec<u8>> = OnceLock::new();
    CACHED
        .get_or_init(|| {
            let id = platform_machine_id();
            if id.is_none() {
                tracing::warn!(
                    "no platform machine id is readable; database migration detection is off \
                     until the next start (the device and sidecar checks still apply)"
                );
            }
            fingerprint_of(id.as_deref())
        })
        .clone()
}

/// The fingerprint of a machine with platform id `id` (`None`: unreadable).
pub fn fingerprint_of(id: Option<&str>) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(id.map_or(UNAVAILABLE, str::as_bytes));
    hasher.finalize().to_vec()
}

/// Whether `fingerprint` is the one of a machine whose id was unreadable.
pub fn is_unavailable(fingerprint: &[u8]) -> bool {
    fingerprint == fingerprint_of(None).as_slice()
}

/// A host id must be non-empty and must not be the reserved text whose fingerprint marks an
/// unreadable machine id: `fingerprint_of(Some("unavailable"))` would equal the unavailable
/// fingerprint and silently disable migration detection for a copied database.
fn valid_host_id(value: &str) -> Result<String, HostIdError> {
    let id = non_empty(value).ok_or(HostIdError::Empty)?;
    if id.as_bytes() == UNAVAILABLE {
        return Err(HostIdError::Reserved);
    }
    Ok(id)
}

fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

#[cfg(target_os = "macos")]
fn platform_machine_id() -> Option<String> {
    let output = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_ioreg_uuid(&String::from_utf8_lossy(&output.stdout))
}

/// The value of `"IOPlatformUUID" = "…"` in `ioreg` output.
#[cfg(any(target_os = "macos", test))]
fn parse_ioreg_uuid(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        if key.trim().trim_matches('"') != "IOPlatformUUID" {
            return None;
        }
        non_empty(value.trim().trim_matches('"'))
    })
}

#[cfg(target_os = "linux")]
fn platform_machine_id() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok().and_then(|id| non_empty(&id)))
}

#[cfg(windows)]
fn platform_machine_id() -> Option<String> {
    let output = std::process::Command::new("reg")
        .args(["query", r"HKLM\SOFTWARE\Microsoft\Cryptography", "/v", "MachineGuid"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_reg_machine_guid(&String::from_utf8_lossy(&output.stdout))
}

/// The value of the `MachineGuid    REG_SZ    …` line in `reg query` output.
#[cfg(any(windows, test))]
fn parse_reg_machine_guid(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        (fields.next()? == "MachineGuid" && fields.next()? == "REG_SZ")
            .then(|| fields.next().and_then(non_empty))
            .flatten()
    })
}

// apple-cfg: ios-explicit iOS reads no hardware identifier: the host supplies the id
// ([`install_host_id`]) and engine start refuses an iOS host that gave none.
#[cfg(target_os = "ios")]
fn platform_machine_id() -> Option<String> {
    None
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "ios", windows)))]
fn platform_machine_id() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reserved_unavailable_text_is_not_a_valid_host_id() {
        assert_eq!(valid_host_id("unavailable"), Err(HostIdError::Reserved));
        assert_eq!(valid_host_id("  "), Err(HostIdError::Empty));
        assert_eq!(valid_host_id(" abc "), Ok("abc".to_string()));
        // The collision this guards against: the same hash as an unreadable machine id.
        assert_eq!(fingerprint_of(Some("unavailable")), fingerprint_of(None));
    }

    #[test]
    fn the_fingerprint_is_a_domain_separated_hash_of_the_machine_id() {
        let mut expected = Sha256::new();
        expected.update(b"yadorilink machine fingerprint v1");
        expected.update(b"abc");
        assert_eq!(fingerprint_of(Some("abc")), expected.finalize().to_vec());
        assert_eq!(fingerprint_of(Some("abc")), fingerprint_of(Some("abc")));
        assert_ne!(fingerprint_of(Some("abc")), fingerprint_of(Some("abd")));
        assert_ne!(fingerprint_of(Some("abc")), Sha256::digest(b"abc").to_vec());
    }

    #[test]
    fn an_unreadable_machine_id_hashes_the_unavailable_constant() {
        let mut expected = Sha256::new();
        expected.update(b"yadorilink machine fingerprint v1");
        expected.update(b"unavailable");
        assert_eq!(fingerprint_of(None), expected.finalize().to_vec());
        assert_ne!(fingerprint_of(None), fingerprint_of(Some("abc")));
    }

    #[test]
    fn the_source_is_fixed_by_its_first_use() {
        // The platform's id used first: a host id is refused and nothing changes.
        let platform = Choice::new(Source::Unset);
        assert_eq!(platform.host_id_or_choose_platform(), None);
        assert_eq!(platform.install_host("a"), Err(HostIdError::PlatformAlreadyUsed));
        assert_eq!(platform.check_host("a"), Err(HostIdError::PlatformAlreadyUsed));
        assert_eq!(platform.host_id_or_choose_platform(), None);

        // Host ids: the same one again is fine, another is refused, an empty one never.
        let host = Choice::new(Source::Unset);
        assert_eq!(host.install_host("  "), Err(HostIdError::Empty));
        assert_eq!(host.check_host("a"), Ok(()));
        assert_eq!(host.host_id_or_choose_platform(), None, "a check chose nothing");
        let host = Choice::new(Source::Unset);
        host.install_host("a").unwrap();
        host.install_host("a").unwrap();
        assert_eq!(host.install_host("b"), Err(HostIdError::Conflict));
        assert_eq!(host.check_host("b"), Err(HostIdError::Conflict));
        assert_eq!(host.host_id_or_choose_platform().as_deref(), Some("a"));
    }

    #[test]
    fn the_process_source_in_tests_is_the_test_host_id() {
        install_host_id(TEST_HOST_ID).unwrap();
        assert_eq!(install_host_id("another-host-id"), Err(HostIdError::Conflict));
        assert_eq!(machine_fingerprint(), fingerprint_of(Some(TEST_HOST_ID)));
    }

    #[test]
    fn this_machine_has_a_stable_fingerprint() {
        let first = machine_fingerprint();
        assert_eq!(first.len(), 32);
        assert_eq!(machine_fingerprint(), first);
    }

    #[test]
    fn the_platform_id_parsers_read_the_expected_field() {
        let ioreg = "+-o J413AP  <class IOPlatformExpertDevice>\n    \
                     \"IOPlatformSerialNumber\" = \"XYZ\"\n    \
                     \"IOPlatformUUID\" = \"1234-ABCD\"\n";
        assert_eq!(parse_ioreg_uuid(ioreg).as_deref(), Some("1234-ABCD"));
        assert_eq!(parse_ioreg_uuid("\"IOPlatformUUID\" = \"\"\n"), None);
        assert_eq!(parse_ioreg_uuid("nothing here"), None);

        let reg = "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\r\n    \
                   MachineGuid    REG_SZ    5a1b-77\r\n\r\n";
        assert_eq!(parse_reg_machine_guid(reg).as_deref(), Some("5a1b-77"));
        assert_eq!(parse_reg_machine_guid("MachineGuid REG_DWORD 0x1"), None);
    }
}
