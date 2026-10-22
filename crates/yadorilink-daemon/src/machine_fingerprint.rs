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
//! on Windows. When no id is readable the fingerprint is the hash of the
//! domain string and the constant `unavailable` ([`is_unavailable`]) and a
//! warning is logged. The author identity open then compares the record's
//! own fingerprint instead, so migration detection is off for that open
//! (a transient read failure causes no rotation); the device and sidecar
//! checks still apply.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"yadorilink machine fingerprint v1";
const UNAVAILABLE: &[u8] = b"unavailable";

/// This machine's fingerprint, read once per process.
pub fn machine_fingerprint() -> Vec<u8> {
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

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn platform_machine_id() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

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
