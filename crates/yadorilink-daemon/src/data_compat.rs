//! `yadorilink-daemon --check-data-compat`: can this build use the data already on this device?
//!
//! An installer runs the bundle's own daemon with this flag after it has verified the bundle and
//! before it replaces anything. The only source of truth is the sync-state database: it is opened
//! read-only (see [`yadorilink_sqlite_runtime::read_state_stamp`]) and its stamp is compared with
//! the state versions this build, as its `engine-identity.json` declares them, can read. No daemon
//! is started, nothing is created, locked, stamped or migrated.
//!
//! Exit status: [`EXIT_COMPATIBLE`], [`EXIT_NEWER`] (the data was written by a newer build:
//! installing this one would be a downgrade, refused), [`EXIT_UNDETERMINED`] (the stamp could not
//! be established; the caller stops, because replacing programs over data it could not read is
//! the unsafe direction).

use std::path::Path;

use yadorilink_local_storage::release_descriptor::{
    identity_dir, read_identity, IdentityFile, StateRefusal, StateSchema,
};
use yadorilink_sqlite_runtime::{read_state_stamp, StateStamp, SCHEMA_VERSION};

/// The data can be used, or there is none.
pub const EXIT_COMPATIBLE: i32 = 0;
/// The data was written by a newer build than this one reads.
pub const EXIT_NEWER: i32 = 20;
/// Whether the data is usable could not be established.
pub const EXIT_UNDETERMINED: i32 = 21;

/// The verdict and the one line to show for it (empty for a plain "compatible").
#[derive(Debug, PartialEq, Eq)]
pub struct Verdict {
    pub code: i32,
    pub message: String,
}

/// What this build reads: its identity file's declaration, else the version it writes.
fn target(exe: &Path) -> StateSchema {
    let declared = match read_identity(identity_dir(exe).as_deref()) {
        IdentityFile::Present(identity) => identity.state_schema,
        IdentityFile::Absent | IdentityFile::Unreadable(_) => None,
    };
    declared.unwrap_or_else(|| {
        // The constant is a positive literal; a build where it is not declares nothing readable.
        let writes = u32::try_from(SCHEMA_VERSION).unwrap_or(u32::MAX);
        StateSchema { writes, reads_from: writes }
    })
}

/// Judges the database at `db_path` against what `target` reads.
#[must_use]
pub fn judge(db_path: &Path, target: StateSchema) -> Verdict {
    let stamp = match read_state_stamp(db_path) {
        Ok(stamp) => stamp,
        Err(why) => {
            return Verdict {
                code: EXIT_UNDETERMINED,
                message: format!(
                    "cannot tell which version of YadoriLink last used the data on this device: \
                     {why}. Nothing was changed. If a YadoriLink daemon is running, stop it; \
                     otherwise start the daemon once and stop it cleanly (so its database is \
                     brought up to date), then run the installer again. If the file belongs to \
                     another program, move it away only if you know it is not YadoriLink data."
                ),
            };
        }
    };
    let on_disk = match stamp {
        StateStamp::Fresh => {
            return Verdict { code: EXIT_COMPATIBLE, message: String::new() };
        }
        StateStamp::Version(v) => v,
    };
    match StateSchema::check_readable(on_disk, Some(target)) {
        Ok(()) => Verdict { code: EXIT_COMPATIBLE, message: String::new() },
        Err(refusal @ StateRefusal::NewerThanReadable { .. }) => {
            Verdict { code: EXIT_NEWER, message: refusal.message() }
        }
        // Older data: this is the only way forward from it. The daemon refuses it when it starts
        // and says how to start over; refusing here would leave an upgrade impossible.
        Err(refusal @ StateRefusal::OlderThanReadable { .. }) => Verdict {
            code: EXIT_COMPATIBLE,
            message: format!(
                "warning: {}; the daemon will explain how to start over",
                refusal.message()
            ),
        },
        Err(refusal @ StateRefusal::Undeclarable) => {
            Verdict { code: EXIT_UNDETERMINED, message: refusal.message() }
        }
    }
}

/// Process entry: prints the message (when there is one) to stderr and returns the exit status.
pub fn run_from_env() -> i32 {
    let db_path = match crate::app::DaemonConfig::from_env() {
        Ok(config) => config.sync_db_path,
        Err(e) => {
            eprintln!(
                "cannot tell where the data on this device is kept ({e}). Nothing was changed."
            );
            return EXIT_UNDETERMINED;
        }
    };
    let exe = crate::update::install_source::running_exe();
    let verdict = judge(&db_path, target(&exe));
    if !verdict.message.is_empty() {
        eprintln!("{}", verdict.message);
    }
    verdict.code
}

#[cfg(test)]
mod tests;
