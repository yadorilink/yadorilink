//! The hand-off journal: the only recovery input of an interrupted hand-off.
//!
//! One small file in the config directory, replaced atomically and durably at every step, so a
//! crash or power loss leaves the previous version or the next one and never a partial one. A
//! file that is nevertheless unreadable (damaged by something else) is reported as such and every
//! hand-off action refuses; nothing is inferred from leftover files.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ownership::OwnershipRecord;
use crate::service_registrations::Kind;

/// The journal's file name inside the config directory.
pub const FILE_NAME: &str = "handoff-journal.json";
/// The directory beside it that holds the definitions moved aside, so a roll-back restores them.
pub const BACKUP_DIR_NAME: &str = "handoff-backup";
/// The lock that keeps two hand-offs of one data area from running at once.
pub const LOCK_FILE_NAME: &str = ".handoff.lock";

const FORMAT: u32 = 1;

/// How far the hand-off got. The order is the order of the steps; later values are appended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Planned and journaled. Nothing has been changed; the old daemon may still run.
    Planned,
    /// The old daemon is stopped and this operation holds the data-area lock. Nothing has been
    /// changed besides that.
    Stopped,
    /// The owner switch is in progress: some of the mutations may be applied. A resting state
    /// only after a crash, and a state in which no daemon may start.
    Switching,
    /// The registrations are disabled and the record names the app: the data area is released to
    /// the app. It stays here until the app commits or rolls back.
    Switched,
    /// A roll-back is undoing the mutations. No daemon may start until it ends.
    RollingBack,
}

/// How far one mutation got.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationState {
    /// Not started; nothing to undo.
    Pending,
    /// Journaled and possibly applied (the process may have died in the middle).
    Intended,
    /// Applied and journaled as such.
    Done,
}

/// One OS registration that is moved aside, with everything its inverse needs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationPlan {
    pub kind: Kind,
    pub name: String,
    /// Where the OS keeps the definition now.
    pub definition: PathBuf,
    /// Where the definition is kept while the hand-off is open.
    pub backup: PathBuf,
    /// Whether the manager had it active (loaded/enabled) before the hand-off.
    pub was_active: bool,
}

/// One step of the owner switch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "what", rename_all = "snake_case")]
pub enum MutationKind {
    DisableRegistration {
        plan: RegistrationPlan,
    },
    /// Replace the ownership record `previous` with `target`.
    RewriteRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mutation {
    pub kind: MutationKind,
    pub state: MutationState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    pub format: u32,
    /// The record before the hand-off; a roll-back restores exactly this.
    pub previous: OwnershipRecord,
    /// The record that names the app as owner once the hand-off is switched.
    pub target: OwnershipRecord,
    /// Whether a daemon of the previous owner was running when the hand-off began (a roll-back
    /// starts it again only then).
    pub daemon_was_running: bool,
    pub phase: Phase,
    /// In the order they are applied; undone in reverse.
    pub mutations: Vec<Mutation>,
    pub started_at: u64,
}

impl Journal {
    #[must_use]
    pub fn new(
        previous: OwnershipRecord,
        target: OwnershipRecord,
        daemon_was_running: bool,
        mutations: Vec<MutationKind>,
        started_at: u64,
    ) -> Self {
        Self {
            format: FORMAT,
            previous,
            target,
            daemon_was_running,
            phase: Phase::Planned,
            mutations: mutations
                .into_iter()
                .map(|kind| Mutation { kind, state: MutationState::Pending })
                .collect(),
            started_at,
        }
    }

    /// Whether the data area may be half-switched: no daemon of either owner may start.
    #[must_use]
    pub fn blocks_daemon_start(&self) -> bool {
        matches!(self.phase, Phase::Switching | Phase::RollingBack)
    }
}

/// What the config directory holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalState {
    Missing,
    Present(Box<Journal>),
    /// A journal exists and cannot be read or understood.
    Unreadable(String),
}

fn path(config_dir: &Path) -> PathBuf {
    config_dir.join(FILE_NAME)
}

/// Reads the journal. Read-only.
#[must_use]
pub fn read(config_dir: &Path) -> JournalState {
    let bytes = match std::fs::read(path(config_dir)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return JournalState::Missing,
        Err(e) => return JournalState::Unreadable(format!("cannot read {FILE_NAME}: {e}")),
    };
    match serde_json::from_slice::<Journal>(&bytes) {
        Ok(j) if j.format == FORMAT => JournalState::Present(Box::new(j)),
        Ok(j) => JournalState::Unreadable(format!(
            "{FILE_NAME} has format {} but this program understands {FORMAT}",
            j.format
        )),
        Err(e) => JournalState::Unreadable(format!("{FILE_NAME} is not a valid journal: {e}")),
    }
}

/// Writes the journal: a temporary file, flushed, then published over the old one durably.
///
/// # Errors
/// The file cannot be written or published; the previous journal is untouched.
pub fn write(config_dir: &Path, journal: &Journal) -> std::io::Result<()> {
    use std::io::Write;

    let target = path(config_dir);
    let temporary = config_dir.join(format!(".{FILE_NAME}.tmp-{}", std::process::id()));
    let _ = yadorilink_fs_platform::durable_dir::remove_file_durably(&temporary);
    let body = serde_json::to_vec_pretty(journal).map_err(std::io::Error::other)?;
    let result = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new().create_new(true).write(true).open(&temporary)?;
        file.write_all(&body)?;
        file.sync_all()?;
        drop(file);
        yadorilink_fs_platform::durable_dir::publish_durably(
            &temporary,
            &target,
            yadorilink_fs_platform::durable_dir::Replace::Yes,
        )
    })();
    if result.is_err() {
        let _ = yadorilink_fs_platform::durable_dir::remove_file_durably(&temporary);
    }
    result
}

/// Removes the journal durably. Already gone is fine.
///
/// # Errors
/// The file cannot be removed.
pub fn remove(config_dir: &Path) -> std::io::Result<()> {
    yadorilink_fs_platform::durable_dir::remove_file_durably(&path(config_dir))
}

/// Where the definition of `name` is kept while a hand-off is open.
#[must_use]
pub fn backup_path(config_dir: &Path, name: &str) -> PathBuf {
    config_dir.join(BACKUP_DIR_NAME).join(name)
}
