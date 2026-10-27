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
//! * a side copy that is absent beside a database that records a witness: recorded again (a
//!   clearable cache directory), unless the host guaranteed the store persists
//!   ([`WitnessPlacement::Persistent`]), where it cannot be told from a restore and is refused
//!   as unverifiable;
//! * a side copy that cannot be read as a witness: the comparison cannot be
//!   made, so the open is refused the same way.
//!
//! The generation advances once per open (and so per rotation), so a restore
//! is seen when the database it brings back was last opened before the
//! newest open of this install. A backup taken and restored within one run
//! of the daemon is not detected; the network check (`own_author_ahead`)
//! remains for that. The side copy is named by the database's canonical path. Where the side
//! store may be cleared (the desktop's cache directory), a database copied to a different path
//! has no side copy there and reads as a new install. Where the host guarantees the store
//! persists ([`WitnessPlacement::Persistent`]) that same case is refused as unverifiable: the
//! database must stay at one stable absolute path, and so must the witness directory. There is
//! no migration of an earlier witness location (a host that changes the directory, or moves from
//! `BesideDatabase` to `Persistent`, is refused the same way; no build with an embedded engine
//! that kept it elsewhere has shipped).
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
    /// The keychain instance nonce differs from the one beside the data
    /// ([`crate::instance_nonce`]).
    KeychainNonceMismatch,
    /// The keychain instance nonce is missing beside the data, or the data's beside the keychain's.
    KeychainNonceMissing,
}

impl Restored {
    pub fn category(self) -> &'static str {
        match self {
            Self::OlderGeneration => "older_generation",
            Self::DifferentInstall => "different_install",
            Self::Unverifiable => "unverifiable",
            Self::KeychainNonceMismatch => "keychain_nonce_mismatch",
            Self::KeychainNonceMissing => "keychain_nonce_missing",
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
    /// Whether the store's location is guaranteed to persist (a directory the host keeps outside
    /// the backup unit and that the system does not purge). Where it is, a database that records
    /// a witness beside a side copy that is gone cannot be told from a restore, so the open is
    /// refused ([`judge_with`]); where it is not (a cache directory a user or the system may
    /// clear), a missing copy is recorded again.
    fn persists(&self) -> bool {
        false
    }
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
    judge_with(database, side, no_identity_here, fresh_token, false)
}

/// [`judge`], where `side_persists` says the side store's location is guaranteed to persist
/// ([`WitnessStore::persists`]): a database that records a witness while the side copy is
/// absent is then refused as unverifiable, not recorded again. A genuinely fresh install (the
/// database records no witness) is unaffected.
pub fn judge_with(
    database: Option<InstallWitness>,
    side: SideCopy,
    no_identity_here: bool,
    fresh_token: [u8; 16],
    side_persists: bool,
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
        (Some(_), SideCopy::Absent) if side_persists && !no_identity_here => {
            Verdict::Refuse(Restored::Unverifiable)
        }
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
    persists: bool,
}

impl FileWitnessStore {
    /// The store for the database at `db_path` under `dir`.
    pub fn new(dir: &Path, db_path: &Path) -> Self {
        let key = fs::canonicalize(db_path).unwrap_or_else(|_| db_path.to_path_buf());
        let digest = Sha256::digest(key.to_string_lossy().as_bytes());
        Self {
            path: dir.join(format!("install-witness-{}.bin", hex::encode(&digest[..12]))),
            persists: false,
        }
    }
}

/// Where an engine keeps its installation witness. Chosen by the engine's composition root.
///
/// The witness only does its job outside the data area and outside what a backup of it restores:
/// restoring a backup puts the database back, and a witness restored with it agrees with the
/// stale database (a backup that restores both is not detected). So an engine given no placement
/// does not guess one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum WitnessPlacement {
    /// No placement was given. Opening the author identity is refused, and an embedded engine
    /// refuses to start: the host must name a directory (or opt into [`Self::BesideDatabase`]).
    #[default]
    Unset,
    /// Beside the database file. An explicit opt-in for tests and tools: restoring the data area
    /// restores the witness with it, so a restored database is not seen.
    BesideDatabase,
    /// In this directory, which a backup or restore of the data area does not include but which
    /// may be cleared (the desktop's cache directory): a missing copy is recorded again.
    At(PathBuf),
    /// In this directory, which the host guarantees persists and keeps outside the backup unit of
    /// the data area (on iOS a separate directory in the app group's Application Support,
    /// excluded from backup; never Caches, which the system may purge). A missing witness beside
    /// a database that records one is refused as unverifiable rather than recorded again, since
    /// a purge would otherwise let a restored old database through. An embedded host passes this.
    Persistent(PathBuf),
    /// No directory could be chosen (the desktop daemon's platform default could not be
    /// resolved); opening the author identity is refused with this reason rather than falling
    /// back to a weaker placement.
    Unavailable(String),
}

impl WitnessPlacement {
    /// The witness store for the database at `db_path`.
    pub fn store(&self, db_path: &Path) -> io::Result<FileWitnessStore> {
        match self {
            Self::Unset => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no installation witness location was given (EngineTuning::witness)",
            )),
            Self::BesideDatabase => {
                Ok(FileWitnessStore::new(db_path.parent().unwrap_or(Path::new(".")), db_path))
            }
            Self::At(dir) => Ok(FileWitnessStore::new(dir, db_path)),
            Self::Persistent(dir) => {
                Ok(FileWitnessStore { persists: true, ..FileWitnessStore::new(dir, db_path) })
            }
            Self::Unavailable(reason) => {
                Err(io::Error::new(io::ErrorKind::NotFound, reason.clone()))
            }
        }
    }

    /// The placement the platform default selects, from the environment `var` reads.
    #[must_use]
    pub fn platform(var: impl Fn(&str) -> Option<std::ffi::OsString>) -> Self {
        match platform_witness_dir(var) {
            Ok(dir) => Self::At(dir),
            Err(error) => Self::Unavailable(error.to_string()),
        }
    }
}

/// `path` as the filesystem resolves it (symlinks followed) when it exists; otherwise its
/// nearest existing ancestor resolved, with the not-yet-existing remainder appended. A remainder
/// that cannot be named without looking at the filesystem (a `..` below the first missing
/// component) and any error other than "not found" are refused: never guessed.
fn resolve_through_existing_ancestor(path: &Path) -> Result<PathBuf, String> {
    let mut missing = Vec::new();
    let mut probe =
        if path.as_os_str().is_empty() { PathBuf::from(".") } else { path.to_path_buf() };
    loop {
        match std::fs::canonicalize(&probe) {
            Ok(mut resolved) => {
                resolved.extend(missing.iter().rev());
                return Ok(resolved);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let Some(name) = probe.file_name().map(std::ffi::OsStr::to_owned) else {
                    return Err(format!("{} cannot be resolved", path.display()));
                };
                missing.push(name);
                probe.pop();
                if probe.as_os_str().is_empty() {
                    probe = PathBuf::from(".");
                }
            }
            Err(error) => return Err(format!("{} cannot be resolved: {error}", path.display())),
        }
    }
}

/// Refuses a [`WitnessPlacement::Persistent`] directory that would not keep the witness outside
/// the data area: a path that is not absolute (it would land in the process's working directory),
/// or one that, with symlinks resolved, is or lies inside any of `data_areas` (the state
/// directory, the database's directory, the block store, the provider temp root). Nothing is created. A not-yet-existing
/// directory is judged by its nearest existing ancestor. Where a host places the directory in a
/// backup unit of its own choosing cannot be seen from here.
///
/// # Errors
/// The reason the directory is unusable.
pub fn check_persistent_dir(dir: &Path, data_areas: &[&Path]) -> Result<(), String> {
    if !dir.is_absolute() {
        return Err(format!("{} is not an absolute path", dir.display()));
    }
    let witness = resolve_through_existing_ancestor(dir)?;
    for area in data_areas {
        let area_resolved = resolve_through_existing_ancestor(area)?;
        if witness.starts_with(&area_resolved) {
            return Err(format!(
                "{} is, or is inside, the data area {}",
                dir.display(),
                area.display()
            ));
        }
    }
    Ok(())
}

/// The platform's default witness directory, from the environment `var` reads (the desktop
/// composition root passes the process environment; an embedded host names its directory itself):
/// the user's cache directory (excluded from Time Machine on macOS; not part of a profile or
/// home backup on Linux). On Windows it is `%USERPROFILE%\.yadorilink-witness`, a sibling of the
/// state directory: a backup or restore of `.yadorilink` alone does not replace it, but a
/// whole-profile backup or restore does, and then the witness and the database are restored
/// together and the restore is not seen (the network check `own_author_ahead` remains). The
/// witness of an earlier build in `%LOCALAPPDATA%\YadoriLink\Cache` is not read: the first open
/// records a new one.
pub fn platform_witness_dir(
    var: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> io::Result<PathBuf> {
    let missing =
        |what: &str| io::Error::new(io::ErrorKind::NotFound, format!("{what} is not set"));
    #[cfg(target_vendor = "apple")]
    {
        let home = var("HOME").ok_or_else(|| missing("HOME"))?;
        Ok(PathBuf::from(home).join("Library/Caches/YadoriLink"))
    }
    #[cfg(windows)]
    {
        // Outside AppData (a packaged process's AppData is virtualized and deleted on uninstall,
        // which would defeat a witness meant to outlive the state directory) and beside, not
        // inside, the state directory the witness checks.
        let base = var("USERPROFILE").ok_or_else(|| missing("USERPROFILE"))?;
        Ok(PathBuf::from(base).join(".yadorilink-witness"))
    }
    #[cfg(not(any(target_vendor = "apple", windows)))]
    {
        if let Some(cache) = var("XDG_CACHE_HOME") {
            return Ok(PathBuf::from(cache).join("yadorilink"));
        }
        let home = var("HOME").ok_or_else(|| missing("HOME"))?;
        Ok(PathBuf::from(home).join(".cache/yadorilink"))
    }
}

impl WitnessStore for FileWitnessStore {
    fn persists(&self) -> bool {
        self.persists
    }

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
        yadorilink_fs_platform::flush::sync_file(&file)?;
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

#[cfg(test)]
mod placement_tests {
    use super::*;

    /// The placements put the witness where they say, and the default places nothing.
    #[test]
    fn the_placements_choose_where_the_witness_lives() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("data/replica.db");
        let outside = dir.path().join("caches");

        assert!(WitnessPlacement::default().store(&db).is_err(), "no placement is guessed");
        assert!(WitnessPlacement::Unavailable("no home".into()).store(&db).is_err());
        let beside = WitnessPlacement::BesideDatabase.store(&db).unwrap();
        let named = WitnessPlacement::At(outside.clone()).store(&db).unwrap();
        let persistent = WitnessPlacement::Persistent(outside.clone()).store(&db).unwrap();
        assert_eq!(beside.path.parent(), db.parent());
        assert_eq!(named.path.parent(), Some(outside.as_path()));
        assert_eq!(persistent.path, named.path);
        assert!(persistent.persists() && !named.persists() && !beside.persists());
    }

    /// Why beside the database is the weak choice: a backup restores both files together, so the
    /// restored database agrees with its own witness; a witness kept elsewhere is ahead of it.
    #[test]
    fn a_witness_outside_the_data_sees_a_restored_database_and_one_beside_it_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let db = data.join("replica.db");
        std::fs::write(&db, b"db").unwrap();
        let older = InstallWitness { token: [1; 16], generation: 3 };
        let newer = InstallWitness { token: [1; 16], generation: 9 };

        let outside = WitnessPlacement::At(dir.path().join("caches")).store(&db).unwrap();
        let beside = WitnessPlacement::BesideDatabase.store(&db).unwrap();
        // The database was backed up at generation 3 and has since advanced to 9.
        for store in [&outside, &beside] {
            store.write(&newer).unwrap();
        }
        // Restoring the backup puts back the database's own record and, for the witness beside
        // it, the file as it was backed up.
        beside.write(&older).unwrap();

        assert_eq!(outside.read().unwrap(), SideCopy::Present(newer));
        assert_eq!(beside.read().unwrap(), SideCopy::Present(older));
        // The database is the restored one, at generation 3.
        let seen_outside = judge(Some(older), outside.read().unwrap(), false, [0; 16]);
        let seen_beside = judge(Some(older), beside.read().unwrap(), false, [0; 16]);
        assert!(matches!(seen_outside, Verdict::Refuse(_)), "{seen_outside:?}");
        assert!(
            matches!(seen_beside, Verdict::Record(_)),
            "a witness restored with the database agrees with it: {seen_beside:?}"
        );
    }

    /// A host that guarantees its witness persists gets no silent re-record: a database that
    /// records a witness beside a missing side copy (a purge, or a restore of the database onto
    /// a device whose witness is gone) is refused as unverifiable. A fresh install, and a store
    /// that may be cleared, are unaffected.
    #[test]
    fn a_missing_side_copy_beside_a_recorded_witness_is_refused_only_where_it_persists() {
        let fresh = [9; 16];
        let recorded = Some(InstallWitness { token: [1; 16], generation: 4 });
        assert_eq!(
            judge_with(recorded, SideCopy::Absent, false, fresh, true),
            Verdict::Refuse(Restored::Unverifiable)
        );
        assert!(matches!(
            judge_with(recorded, SideCopy::Absent, false, fresh, false),
            Verdict::Record(_)
        ));
        // Genuinely fresh: the database records no witness yet.
        assert!(matches!(
            judge_with(None, SideCopy::Absent, false, fresh, true),
            Verdict::Record(_)
        ));
        // A new or re-registered identity starts over whatever the side copy says.
        assert!(matches!(
            judge_with(recorded, SideCopy::Absent, true, fresh, true),
            Verdict::Record(_)
        ));
    }
}

#[cfg(test)]
mod persistent_dir_tests {
    use super::*;

    fn refused(dir: &Path, areas: &[&Path]) -> String {
        check_persistent_dir(dir, areas).expect_err("must be refused")
    }

    #[test]
    fn a_persistent_directory_must_be_absolute_and_outside_every_data_area() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let db_dir = root.path().join("db");
        let blocks = root.path().join("blocks");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(&db_dir).unwrap();
        let areas: [&Path; 3] = [&state, &db_dir, &blocks];

        assert!(refused(Path::new(""), &areas).contains("absolute"));
        assert!(refused(Path::new("witness"), &areas).contains("absolute"));
        assert!(refused(Path::new("./witness"), &areas).contains("absolute"));
        assert!(refused(&state, &areas).contains("data area"));
        assert!(refused(&state.join("witness"), &areas).contains("data area"));
        assert!(refused(&state.join("a/b/not/yet"), &areas).contains("data area"));
        assert!(refused(&db_dir.join("witness"), &areas).contains("data area"));
        // The provider temp root (swept by the OS) counts too: see the engine-start test.
        // The block store need not exist yet.
        assert!(refused(&blocks.join("witness"), &areas).contains("data area"));
        // A `..` that climbs back into the state directory is resolved, not trusted.
        std::fs::create_dir_all(root.path().join("elsewhere")).unwrap();
        assert!(refused(&root.path().join("elsewhere/../state/w"), &areas).contains("data area"));
        // A `..` below a missing component cannot be named without asking the filesystem: on
        // Unix it is refused, not guessed. Windows collapses `..` lexically before the lookup
        // (the path has no other meaning there), so it names `root\x` and is judged as such.
        #[cfg(unix)]
        assert!(refused(&root.path().join("missing/../x"), &areas).contains("resolved"));
        #[cfg(windows)]
        {
            assert!(refused(&root.path().join("missing/../state/w"), &areas).contains("data area"));
            check_persistent_dir(&root.path().join("missing/../x"), &areas).unwrap();
        }

        // Outside every area, existing or not, it is accepted; a sibling that shares a name
        // prefix with a data area is not inside it.
        std::fs::create_dir_all(root.path().join("witness")).unwrap();
        check_persistent_dir(&root.path().join("witness"), &areas).unwrap();
        check_persistent_dir(&root.path().join("not/yet/witness"), &areas).unwrap();
        check_persistent_dir(&root.path().join("state-witness"), &areas).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_into_a_data_area_does_not_escape_the_check() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&state, &link).unwrap();
        // A witness directory behind the link, existing or not.
        assert!(refused(&link, &[&state]).contains("data area"));
        assert!(refused(&link.join("witness"), &[&state]).contains("data area"));
        // The data area itself reached through a link is still the same directory.
        let areas_link = root.path().join("areas");
        std::os::unix::fs::symlink(&state, &areas_link).unwrap();
        assert!(refused(&state.join("w"), &[&areas_link]).contains("data area"));
    }
}
