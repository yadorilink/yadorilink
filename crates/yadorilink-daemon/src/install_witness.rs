//! The installation witness: a restore or copy of the replica database onto
//! the machine it came from.
//!
//! The machine fingerprint and the `<db>.instance` sidecar cannot see a
//! database restored together with its own sidecar on the same machine (a
//! Time Machine or disk-image restore): both are inside what a backup holds.
//! The witness is a second copy of a random per-installation token and a
//! monotonic write generation, kept where a backup of the data does not
//! reach ([`FileWitnessStore`]: the platform cache directory; on Windows a sibling of the
//! state directory, which a whole-profile or disk-image restore also replaces), and recorded
//! inside the database too. On every open the two are compared ([`judge`]):
//!
//! * no witness anywhere: a new install, or the first run after an upgrade
//!   that introduced the witness. It is recorded and nothing is refused;
//! * the database holds a witness the side store has not seen (the side
//!   store is gone, or the daemon died between the two writes): the database
//!   is not behind anything, so it is recorded again;
//! * same token, database generation not behind: continue, generation + 1;
//! * a different token, or a database generation behind the side copy: the
//!   database is a copy of another installation or an older state of this
//!   one. The open is refused ([`Restored`]); nothing is minted, rotated or
//!   signed, and the status reports `database_restored`;
//! * a side copy that cannot be read as a witness: the comparison cannot be
//!   made, so the open is refused the same way.
//!
//! The generation advances once per open (and so per rotation), so a restore
//! is seen when the database it brings back was last opened before the
//! newest open of this install. A backup taken and restored within one run
//! of the daemon is not detected; the network check (`own_author_ahead`)
//! remains for that. A database copied to a different path has no side copy
//! there and reads as a new install.
//!
//! The recovery is the user's: the engine never reuses the old author state,
//! so the device starts over as a new device (client core
//! `start_over_as_new_device`: the old identity is retired, the files and the
//! database stay, and the machine registers again). A
//! database holding no author of the device being opened starts a new
//! witness, so the refusal ends with the new registration.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use yadorilink_sync_sqlite::author_incarnation::InstallWitness;

/// Why a database was refused; the argument of the `database_restored`
/// attention item.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Restored {
    /// The database is older than this installation's newest recorded state.
    OlderGeneration,
    /// The database belongs to another installation.
    DifferentInstall,
    /// The side copy exists but cannot be read, so nothing can be compared.
    Unverifiable,
}

impl Restored {
    pub fn category(self) -> &'static str {
        match self {
            Self::OlderGeneration => "older_generation",
            Self::DifferentInstall => "different_install",
            Self::Unverifiable => "unverifiable",
        }
    }
}

impl std::fmt::Display for Restored {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the replica database was restored or copied ({}); this device must start over as a \
             new device",
            self.category()
        )
    }
}

/// What the side store holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SideCopy {
    Absent,
    Present(InstallWitness),
    Unreadable,
}

/// The copy of the witness kept outside the database's backup set.
pub trait WitnessStore {
    fn read(&self) -> io::Result<SideCopy>;
    fn write(&self, witness: &InstallWitness) -> io::Result<()>;
}

/// What to do with the open.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// Record this witness in the database, then in the side store.
    Record(InstallWitness),
    Refuse(Restored),
}

/// Compares the database's witness with the side copy. `no_identity_here` is
/// true when the database holds no author of the device being opened: it is
/// new or wiped, or the device was registered again. A stale side copy beside
/// it is leftover from a reset, not evidence of a restore, and the witness
/// starts over.
pub fn judge(
    database: Option<InstallWitness>,
    side: SideCopy,
    no_identity_here: bool,
    fresh_token: [u8; 16],
) -> Verdict {
    let next = |token, generation: u64| {
        Verdict::Record(InstallWitness { token, generation: generation.saturating_add(1) })
    };
    match (database, side) {
        (_, SideCopy::Present(_) | SideCopy::Unreadable) if no_identity_here => {
            next(fresh_token, 0)
        }
        (_, SideCopy::Unreadable) => Verdict::Refuse(Restored::Unverifiable),
        (None, SideCopy::Absent) => next(fresh_token, 0),
        // A database that predates the witness, beside an installation that
        // has one: an older database was put back.
        (None, SideCopy::Present(_)) => Verdict::Refuse(Restored::DifferentInstall),
        (Some(database), SideCopy::Absent) => next(database.token, database.generation),
        (Some(database), SideCopy::Present(side)) if database.token != side.token => {
            Verdict::Refuse(Restored::DifferentInstall)
        }
        (Some(database), SideCopy::Present(side)) if database.generation < side.generation => {
            Verdict::Refuse(Restored::OlderGeneration)
        }
        (Some(database), SideCopy::Present(_)) => next(database.token, database.generation),
    }
}

const MAGIC: [u8; 4] = *b"YLIW";
const FORMAT_VERSION: u8 = 1;
const LEN: usize = MAGIC.len() + 1 + 16 + 8;

/// A witness file per database path, under a directory a backup of the data
/// does not include.
pub struct FileWitnessStore {
    path: PathBuf,
}

impl FileWitnessStore {
    /// The store for the database at `db_path` under `dir`.
    pub fn new(dir: &Path, db_path: &Path) -> Self {
        let key = fs::canonicalize(db_path).unwrap_or_else(|_| db_path.to_path_buf());
        let digest = Sha256::digest(key.to_string_lossy().as_bytes());
        Self { path: dir.join(format!("install-witness-{}.bin", hex::encode(&digest[..12]))) }
    }

    /// The platform's store for the database at `db_path`:
    /// `YADORILINK_WITNESS_DIR`, else the user's cache directory (excluded from
    /// Time Machine on macOS; not part of a profile or home backup on Linux). On Windows it is
    /// `%USERPROFILE%\.yadorilink-witness`, a sibling of the state directory: a backup or restore
    /// of `.yadorilink` alone does not replace it, but a whole-profile backup or restore does,
    /// and then the witness and the database are restored together and the restore is not seen
    /// (the network check `own_author_ahead` remains). The witness of an earlier build in
    /// `%LOCALAPPDATA%\YadoriLink\Cache` is not read: the first open records a new one.
    pub fn platform(db_path: &Path) -> io::Result<Self> {
        Ok(Self::new(&witness_dir()?, db_path))
    }
}

fn witness_dir() -> io::Result<PathBuf> {
    let missing =
        |what: &str| io::Error::new(io::ErrorKind::NotFound, format!("{what} is not set"));
    use yadorilink_fs_platform::state_dir::{process_override, PathOverride};
    if let Some(dir) = process_override(PathOverride::WitnessDir)
        .map_err(|refusal| io::Error::new(io::ErrorKind::PermissionDenied, refusal))?
    {
        return Ok(dir);
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME").ok_or_else(|| missing("HOME"))?;
        Ok(PathBuf::from(home).join("Library/Caches/YadoriLink"))
    }
    #[cfg(windows)]
    {
        // Outside AppData (a packaged process's AppData is virtualized and deleted on uninstall,
        // which would defeat a witness meant to outlive the state directory) and beside, not
        // inside, the state directory the witness checks.
        let base = std::env::var_os("USERPROFILE").ok_or_else(|| missing("USERPROFILE"))?;
        Ok(PathBuf::from(base).join(".yadorilink-witness"))
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        if let Some(cache) = std::env::var_os("XDG_CACHE_HOME") {
            return Ok(PathBuf::from(cache).join("yadorilink"));
        }
        let home = std::env::var_os("HOME").ok_or_else(|| missing("HOME"))?;
        Ok(PathBuf::from(home).join(".cache/yadorilink"))
    }
}

impl WitnessStore for FileWitnessStore {
    fn read(&self) -> io::Result<SideCopy> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(SideCopy::Absent),
            Err(error) => return Err(error),
        };
        if bytes.len() != LEN || bytes[..4] != MAGIC || bytes[4] != FORMAT_VERSION {
            return Ok(SideCopy::Unreadable);
        }
        let (Ok(token), Ok(generation)) =
            (bytes[5..21].try_into(), <[u8; 8]>::try_from(&bytes[21..]))
        else {
            return Ok(SideCopy::Unreadable);
        };
        Ok(SideCopy::Present(InstallWitness { token, generation: u64::from_le_bytes(generation) }))
    }

    fn write(&self, witness: &InstallWitness) -> io::Result<()> {
        let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        yadorilink_fs_platform::durable_dir::create_dir_all_durably(dir)?;
        let mut bytes = Vec::with_capacity(LEN);
        bytes.extend_from_slice(&MAGIC);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(&witness.token);
        bytes.extend_from_slice(&witness.generation.to_le_bytes());
        let temp = self.path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4().simple()));
        let mut file = fs::File::create(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        let published = yadorilink_fs_platform::durable_dir::publish_durably(
            &temp,
            &self.path,
            yadorilink_fs_platform::durable_dir::Replace::Yes,
        );
        if published.is_err() {
            let _ = fs::remove_file(&temp);
        }
        published
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use std::cell::Cell;

    use super::*;

    /// An in-memory side store for tests.
    pub(crate) struct MemoryWitness(pub(crate) Cell<SideCopy>);

    impl MemoryWitness {
        pub(crate) fn new() -> Self {
            Self(Cell::new(SideCopy::Absent))
        }
    }

    impl WitnessStore for MemoryWitness {
        fn read(&self) -> io::Result<SideCopy> {
            Ok(self.0.get())
        }
        fn write(&self, witness: &InstallWitness) -> io::Result<()> {
            self.0.set(SideCopy::Present(*witness));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRESH: [u8; 16] = [9; 16];

    fn w(token: u8, generation: u64) -> InstallWitness {
        InstallWitness { token: [token; 16], generation }
    }

    fn record(token: [u8; 16], generation: u64) -> Verdict {
        Verdict::Record(InstallWitness { token, generation })
    }

    #[test]
    fn a_fresh_install_records_a_new_token() {
        assert_eq!(judge(None, SideCopy::Absent, true, FRESH), record(FRESH, 1));
    }

    #[test]
    fn a_pre_upgrade_install_is_recorded_not_refused() {
        // A database from before the witness, with no side copy yet.
        assert_eq!(judge(None, SideCopy::Absent, false, FRESH), record(FRESH, 1));
        // A database holding a witness whose side copy is gone keeps its token.
        assert_eq!(judge(Some(w(1, 4)), SideCopy::Absent, false, FRESH), record([1; 16], 5));
    }

    #[test]
    fn a_normal_restart_advances_the_generation() {
        assert_eq!(
            judge(Some(w(1, 4)), SideCopy::Present(w(1, 4)), false, FRESH),
            record([1; 16], 5)
        );
        // The side write of the previous open was lost: the database is ahead.
        assert_eq!(
            judge(Some(w(1, 5)), SideCopy::Present(w(1, 4)), false, FRESH),
            record([1; 16], 6)
        );
    }

    #[test]
    fn an_older_database_of_this_install_is_refused() {
        assert_eq!(
            judge(Some(w(1, 2)), SideCopy::Present(w(1, 7)), false, FRESH),
            Verdict::Refuse(Restored::OlderGeneration)
        );
    }

    #[test]
    fn a_database_of_another_install_is_refused() {
        assert_eq!(
            judge(Some(w(2, 9)), SideCopy::Present(w(1, 3)), false, FRESH),
            Verdict::Refuse(Restored::DifferentInstall)
        );
        // An older database without a witness beside an install that has one.
        assert_eq!(
            judge(None, SideCopy::Present(w(1, 3)), false, FRESH),
            Verdict::Refuse(Restored::DifferentInstall)
        );
    }

    #[test]
    fn a_wiped_database_beside_a_stale_side_copy_is_a_new_install() {
        assert_eq!(judge(None, SideCopy::Present(w(1, 3)), true, FRESH), record(FRESH, 1));
    }

    #[test]
    fn registering_the_device_again_starts_a_new_witness() {
        assert_eq!(
            judge(Some(w(2, 9)), SideCopy::Present(w(1, 30)), true, FRESH),
            record(FRESH, 1)
        );
    }

    #[test]
    fn a_corrupted_side_copy_is_refused() {
        assert_eq!(
            judge(Some(w(1, 3)), SideCopy::Unreadable, false, FRESH),
            Verdict::Refuse(Restored::Unverifiable)
        );
        // Not for a database with no author of this device: registering again
        // replaces the unreadable copy.
        assert_eq!(judge(None, SideCopy::Unreadable, true, FRESH), record(FRESH, 1));
    }

    #[test]
    fn the_file_store_round_trips_and_reads_garbage_as_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileWitnessStore::new(&dir.path().join("cache"), Path::new("/x/replica.db"));
        assert_eq!(store.read().unwrap(), SideCopy::Absent);
        store.write(&w(3, 12)).unwrap();
        assert_eq!(store.read().unwrap(), SideCopy::Present(w(3, 12)));
        std::fs::write(&store.path, b"garbage").unwrap();
        assert_eq!(store.read().unwrap(), SideCopy::Unreadable);
        // Another database path has a witness of its own.
        let other = FileWitnessStore::new(&dir.path().join("cache"), Path::new("/y/replica.db"));
        assert_eq!(other.read().unwrap(), SideCopy::Absent);
    }
}
