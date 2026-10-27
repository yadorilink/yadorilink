//! The keychain instance nonce: a copied or restored data area on a host whose keychain does not
//! travel with it (iOS).
//!
//! A random nonce is kept in two places: the host's keychain ([`InstanceNonceKeychain`], a port the
//! host supplies; on iOS the shared keychain access group, `ThisDeviceOnly`) and a small file beside
//! the database (`<db>.keychain-nonce`). A backup or copy of the data area brings the file along
//! but not the keychain item (and a keychain wipe leaves the file), so on every open the two are
//! compared ([`judge`]):
//!
//! * neither exists: a new install (or the first open of a build that introduced the nonce); both
//!   are created;
//! * the database holds no identity of this device: new, or the device was registered again. The
//!   nonce starts over whatever either side says;
//! * the file and the keychain item agree: continue;
//! * they differ, or the keychain item is missing beside the file: the data area is a copy or
//!   restore ([`Restored::KeychainNonceMismatch`] or [`Restored::KeychainNonceMissing`]). The open
//!   is refused exactly as the installation witness refuses one (status `database_restored`);
//!   nothing is deleted and the way out is the same start over as a new device;
//! * the file is missing beside a keychain item while the database holds this device's identity:
//!   the keychain is device-bound and a copy never carries it, so this is this device's own
//!   interrupted mint (the keychain is written first) or a deleted file. The file is rewritten from
//!   the keychain value ([`Verdict::Repair`]), which makes the mint crash-safe and idempotent;
//! * a file that cannot be read: refused as unverifiable.
//!
//! A host that supplies no keychain (desktop, tests) is unaffected.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::install_witness::Restored;

/// The nonce's size in bytes.
pub const NONCE_LEN: usize = 16;

/// One instance nonce.
pub type Nonce = [u8; NONCE_LEN];

/// The host's keychain holding this installation's nonce. An error is an unusable keychain, never
/// absence (`Ok(None)`).
pub trait InstanceNonceKeychain: std::fmt::Debug + Send + Sync {
    fn read(&self) -> io::Result<Option<Nonce>>;
    fn write(&self, nonce: &Nonce) -> io::Result<()>;
}

/// What the file beside the database holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DataNonce {
    Absent,
    Present(Nonce),
    Unreadable,
}

/// What to do with the open.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// Store this nonce in the keychain and beside the data (a fresh or restarted nonce).
    Mint,
    /// The keychain holds the nonce and the file is missing: write the file from it.
    Repair(Nonce),
    /// The two agree.
    Continue,
    Refuse(Restored),
}

/// Compares the file beside the database with the keychain item. `no_identity_here` is true when
/// the database holds no author of the device being opened.
#[must_use]
pub fn judge(data: DataNonce, keychain: Option<Nonce>, no_identity_here: bool) -> Verdict {
    match (data, keychain) {
        _ if no_identity_here => Verdict::Mint,
        (DataNonce::Unreadable, _) => Verdict::Refuse(Restored::Unverifiable),
        (DataNonce::Absent, None) => Verdict::Mint,
        (DataNonce::Absent, Some(keychain)) => Verdict::Repair(keychain),
        (DataNonce::Present(_), None) => Verdict::Refuse(Restored::KeychainNonceMissing),
        (DataNonce::Present(data), Some(keychain)) if data == keychain => Verdict::Continue,
        (DataNonce::Present(_), Some(_)) => Verdict::Refuse(Restored::KeychainNonceMismatch),
    }
}

const MAGIC: [u8; 4] = *b"YLIN";
const FORMAT_VERSION: u8 = 1;
const LEN: usize = MAGIC.len() + 1 + NONCE_LEN;

/// `<db_path>.keychain-nonce`.
#[must_use]
pub fn nonce_path(db_path: &Path) -> PathBuf {
    let mut name = OsString::from(db_path.as_os_str());
    name.push(".keychain-nonce");
    PathBuf::from(name)
}

fn read_data(db_path: &Path) -> io::Result<DataNonce> {
    let bytes = match fs::read(nonce_path(db_path)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(DataNonce::Absent),
        Err(error) => return Err(error),
    };
    if bytes.len() != LEN || bytes[..4] != MAGIC || bytes[4] != FORMAT_VERSION {
        return Ok(DataNonce::Unreadable);
    }
    Ok(bytes[5..].try_into().map_or(DataNonce::Unreadable, DataNonce::Present))
}

fn write_data(db_path: &Path, nonce: &Nonce) -> io::Result<()> {
    let path = nonce_path(db_path);
    let mut bytes = Vec::with_capacity(LEN);
    bytes.extend_from_slice(&MAGIC);
    bytes.push(FORMAT_VERSION);
    bytes.extend_from_slice(nonce);
    let mut temp_name = OsString::from(path.as_os_str());
    temp_name.push(format!(".{}.tmp", uuid::Uuid::new_v4().simple()));
    let temp = PathBuf::from(temp_name);
    let mut file = fs::File::create(&temp)?;
    file.write_all(&bytes)?;
    yadorilink_fs_platform::flush::sync_file(&file)?;
    drop(file);
    let published = yadorilink_fs_platform::durable_dir::publish_durably(
        &temp,
        &path,
        yadorilink_fs_platform::durable_dir::Replace::Yes,
    );
    if published.is_err() {
        let _ = fs::remove_file(&temp);
    }
    published
}

/// Why the nonce could not be checked.
#[derive(Debug, thiserror::Error)]
pub enum NonceError {
    /// The data area is a copy or restore.
    #[error("{0}")]
    Restored(Restored),
    /// The keychain or the file could not be read or written, so nothing can be compared.
    #[error("instance nonce: {0}")]
    Io(#[from] io::Error),
}

/// Compares and, for a new install, creates the nonce for the database at `db_path`. The keychain
/// item is written first, so a crash between the two writes leaves the keychain ahead of the file,
/// which the next open repairs ([`Verdict::Repair`]); a file without a keychain item is a copy and
/// is refused.
///
/// # Errors
/// [`NonceError::Restored`] for a copy or restore; [`NonceError::Io`] when a side is unusable.
pub fn check(
    db_path: &Path,
    keychain: &dyn InstanceNonceKeychain,
    no_identity_here: bool,
) -> Result<(), NonceError> {
    check_with(db_path, keychain, no_identity_here, write_data)
}

fn check_with(
    db_path: &Path,
    keychain: &dyn InstanceNonceKeychain,
    no_identity_here: bool,
    write_file: impl Fn(&Path, &Nonce) -> io::Result<()>,
) -> Result<(), NonceError> {
    match judge(read_data(db_path)?, keychain.read()?, no_identity_here) {
        Verdict::Refuse(reason) => Err(NonceError::Restored(reason)),
        Verdict::Continue => Ok(()),
        Verdict::Repair(nonce) => Ok(write_file(db_path, &nonce)?),
        Verdict::Mint => {
            let nonce: Nonce = rand::random();
            keychain.write(&nonce)?;
            write_file(db_path, &nonce)?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// An in-memory keychain.
    #[derive(Debug, Default)]
    struct MemoryKeychain(Mutex<Option<Nonce>>);

    impl InstanceNonceKeychain for MemoryKeychain {
        fn read(&self) -> io::Result<Option<Nonce>> {
            Ok(*self.0.lock().unwrap())
        }
        fn write(&self, nonce: &Nonce) -> io::Result<()> {
            *self.0.lock().unwrap() = Some(*nonce);
            Ok(())
        }
    }

    fn area(dir: &Path, name: &str) -> PathBuf {
        let area = dir.join(name);
        fs::create_dir_all(&area).unwrap();
        area.join("sync.db")
    }

    fn refused(result: Result<(), NonceError>) -> Restored {
        match result {
            Err(NonceError::Restored(reason)) => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_fresh_install_creates_the_nonce_and_the_same_area_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let db = area(dir.path(), "a");
        let keychain = MemoryKeychain::default();
        check(&db, &keychain, true).unwrap();
        assert!(keychain.read().unwrap().is_some());
        assert!(matches!(read_data(&db).unwrap(), DataNonce::Present(_)));
        // Restarts, now with an identity.
        check(&db, &keychain, false).unwrap();
        check(&db, &keychain, false).unwrap();
    }

    #[test]
    fn a_data_area_copied_to_another_keychain_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let original = area(dir.path(), "a");
        let keychain = MemoryKeychain::default();
        check(&original, &keychain, true).unwrap();
        let copy = area(dir.path(), "b");
        fs::copy(nonce_path(&original), nonce_path(&copy)).unwrap();

        // A device whose keychain never saw the nonce.
        let other = MemoryKeychain::default();
        assert_eq!(refused(check(&copy, &other, false)), Restored::KeychainNonceMissing);
        // A device that has its own, different nonce.
        let own = area(dir.path(), "c");
        let other_keychain = MemoryKeychain::default();
        check(&own, &other_keychain, true).unwrap();
        fs::copy(nonce_path(&original), nonce_path(&own)).unwrap();
        assert_eq!(refused(check(&own, &other_keychain, false)), Restored::KeychainNonceMismatch);
        // Nothing was deleted.
        assert!(nonce_path(&copy).exists());
    }

    #[test]
    fn a_wiped_keychain_beside_existing_data_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let db = area(dir.path(), "a");
        check(&db, &MemoryKeychain::default(), true).unwrap();
        let wiped = MemoryKeychain::default();
        assert_eq!(refused(check(&db, &wiped, false)), Restored::KeychainNonceMissing);
    }

    #[test]
    fn a_missing_file_beside_the_keychain_is_repaired_from_it() {
        let dir = tempfile::tempdir().unwrap();
        let db = area(dir.path(), "a");
        let keychain = MemoryKeychain::default();
        check(&db, &keychain, true).unwrap();
        let nonce = keychain.read().unwrap().unwrap();
        fs::remove_file(nonce_path(&db)).unwrap();
        check(&db, &keychain, false).unwrap();
        assert_eq!(read_data(&db).unwrap(), DataNonce::Present(nonce));
        check(&db, &keychain, false).unwrap();
        // A new or re-registered identity starts the nonce over.
        fs::remove_file(nonce_path(&db)).unwrap();
        check(&db, &keychain, true).unwrap();
        assert_ne!(keychain.read().unwrap().unwrap(), nonce);
    }

    /// A keychain whose writes fail on demand.
    #[derive(Debug, Default)]
    struct FlakyKeychain {
        inner: MemoryKeychain,
        fail_write: std::sync::atomic::AtomicBool,
        unavailable: std::sync::atomic::AtomicBool,
    }

    impl InstanceNonceKeychain for FlakyKeychain {
        fn read(&self) -> io::Result<Option<Nonce>> {
            if self.unavailable.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(io::Error::other("keychain locked"));
            }
            self.inner.read()
        }
        fn write(&self, nonce: &Nonce) -> io::Result<()> {
            if self.fail_write.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(io::Error::other("keychain write failed"));
            }
            self.inner.write(nonce)
        }
    }

    fn failing_file(_: &Path, _: &Nonce) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(28))
    }

    #[test]
    fn an_interrupted_upgrade_mint_recovers_at_every_step_and_keeps_the_identity() {
        use std::sync::atomic::Ordering::SeqCst;
        let dir = tempfile::tempdir().unwrap();

        // Step 1 fails: the keychain write. Nothing was written; the next open mints.
        let db = area(dir.path(), "step1");
        let keychain = FlakyKeychain::default();
        keychain.fail_write.store(true, SeqCst);
        assert!(matches!(check(&db, &keychain, false), Err(NonceError::Io(_))));
        assert_eq!(read_data(&db).unwrap(), DataNonce::Absent);
        assert_eq!(keychain.read().unwrap(), None);
        keychain.fail_write.store(false, SeqCst);
        check(&db, &keychain, false).unwrap();
        check(&db, &keychain, false).unwrap();

        // Step 2 fails: the file write after the keychain write (ENOSPC, or a kill).
        let db = area(dir.path(), "step2");
        let keychain = FlakyKeychain::default();
        assert!(matches!(check_with(&db, &keychain, false, failing_file), Err(NonceError::Io(_))));
        let nonce = keychain.read().unwrap().unwrap();
        assert_eq!(read_data(&db).unwrap(), DataNonce::Absent);
        // The repair itself fails once, then succeeds; the nonce never changes.
        assert!(matches!(check_with(&db, &keychain, false, failing_file), Err(NonceError::Io(_))));
        check(&db, &keychain, false).unwrap();
        assert_eq!(read_data(&db).unwrap(), DataNonce::Present(nonce));
        assert_eq!(keychain.read().unwrap(), Some(nonce));
        check(&db, &keychain, false).unwrap();
    }

    #[test]
    fn a_file_without_a_keychain_item_stays_a_refused_copy() {
        let dir = tempfile::tempdir().unwrap();
        let db = area(dir.path(), "a");
        check(&db, &MemoryKeychain::default(), true).unwrap();
        let before = fs::read(nonce_path(&db)).unwrap();
        let other = MemoryKeychain::default();
        assert_eq!(refused(check(&db, &other, false)), Restored::KeychainNonceMissing);
        assert_eq!(refused(check(&db, &other, false)), Restored::KeychainNonceMissing);
        assert_eq!(other.read().unwrap(), None);
        assert_eq!(fs::read(nonce_path(&db)).unwrap(), before);
    }

    #[test]
    fn an_unavailable_keychain_is_an_io_error_not_a_verdict() {
        use std::sync::atomic::Ordering::SeqCst;
        let dir = tempfile::tempdir().unwrap();
        let db = area(dir.path(), "a");
        let keychain = FlakyKeychain::default();
        check(&db, &keychain, true).unwrap();
        keychain.unavailable.store(true, SeqCst);
        assert!(matches!(check(&db, &keychain, false), Err(NonceError::Io(_))));
        assert!(matches!(check(&db, &keychain, true), Err(NonceError::Io(_))));
    }

    #[test]
    fn an_unreadable_file_is_refused_and_a_pre_nonce_install_is_minted() {
        let dir = tempfile::tempdir().unwrap();
        let db = area(dir.path(), "a");
        // An existing install from before the nonce: neither side has one.
        let keychain = MemoryKeychain::default();
        check(&db, &keychain, false).unwrap();
        fs::write(nonce_path(&db), b"garbage").unwrap();
        assert_eq!(refused(check(&db, &keychain, false)), Restored::Unverifiable);
    }
}
