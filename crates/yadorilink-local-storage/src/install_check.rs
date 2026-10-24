//! `yadorilink doctor`'s installation cross-check: does what the ownership record says agree with
//! the structural facts that can be read off this machine?
//!
//! Facts compared: the recorded `install_source` against the layout of the recorded install root
//! (an application bundle, a Windows Store package location), against the `install_source` the
//! running daemon reports (the value its update check uses to pick manifest entries), and against
//! the OS service registrations present (see [`crate::service_registrations`]). Every finding
//! carries the precise fix. The check only reads: it never repairs, rewrites the record or
//! removes a registration, and a disagreement is an owner-unknown state that mutating actions
//! refuse on, as the design requires.

use std::path::Path;

use crate::daemon_lock::LockProbe;
use crate::ownership::{self, Owner, RecordState};
use crate::release_descriptor::{self, DescriptorProblem, ReleaseDescriptor};
use crate::service_registrations::{self, Roots};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Severity {
    Ok,
    Warn,
    Error,
}

/// One row of the report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub check: &'static str,
    pub detail: String,
}

/// What the running daemon reported through `identify`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunningInstall {
    pub install_source: String,
    pub install_root: String,
    pub version: String,
    pub release_id: String,
    pub engine_api_version: u32,
}

impl RunningInstall {
    fn descriptor(&self) -> ReleaseDescriptor {
        ReleaseDescriptor {
            version: self.version.clone(),
            channel: String::new(),
            install_source: self.install_source.clone(),
            release_id: self.release_id.clone(),
            engine_api_version: self.engine_api_version,
            state_schema: None,
        }
    }
}

/// The facts the check compares; the caller reads them, this module judges them.
pub struct Facts<'a> {
    pub config_dir: &'a Path,
    pub record: &'a RecordState,
    pub lock: &'a LockProbe,
    /// `None` when no daemon answered the control socket.
    pub running: Option<&'a RunningInstall>,
    /// The descriptor of the program running this check, or why it cannot be trusted.
    pub local: &'a Result<ReleaseDescriptor, DescriptorProblem>,
    pub roots: &'a Roots,
}

/// The `check` name of the rows about OS service registrations.
pub const CHECK_REGISTRATIONS: &str = "service registrations";

fn finding(severity: Severity, check: &'static str, detail: impl Into<String>) -> Finding {
    Finding { severity, check, detail: detail.into() }
}

/// The `install_source` an install root's layout allows, `None` when the layout says nothing.
fn layout_source(install_root: &str) -> Option<&'static str> {
    let root = Path::new(install_root);
    if ownership::is_windows_store_path(root) {
        Some("microsoft_store")
    } else if ownership::is_app_bundle_path(&root.join("Contents")) {
        Some("app_bundle")
    } else {
        None
    }
}

fn shown(release_id: &str) -> &str {
    if release_id.is_empty() {
        "(no engine identity)"
    } else {
        release_id
    }
}

/// The daemon records its own release at every start (see the daemon's `gate_start`), so a
/// record naming another release than the running daemon was not written by it.
fn stale_release_row(
    record: &ownership::OwnershipRecord,
    running: &RunningInstall,
) -> Option<Finding> {
    (record.release_id != running.release_id).then(|| {
        finding(
            Severity::Error,
            "ownership record",
            format!(
                "the record names release {} but the running daemon is release {}; the daemon \
                 writes its own release into the record when it starts. Fix: restart the daemon \
                 (stop it, then start it again with the tool that started it)",
                shown(&record.release_id),
                shown(&running.release_id)
            ),
        )
    })
}

/// Runs every check. Read-only.
#[must_use]
pub fn check(facts: &Facts<'_>) -> Vec<Finding> {
    let mut rows = Vec::new();
    let record_path = facts.config_dir.join(ownership::FILE_NAME);

    rows.push(match facts.lock {
        LockProbe::Free => finding(Severity::Ok, "daemon lock", "no daemon owns the data area"),
        LockProbe::Held if facts.running.is_some() => {
            finding(Severity::Ok, "daemon lock", "a daemon owns the data area and answers")
        }
        LockProbe::Held => finding(
            Severity::Warn,
            "daemon lock",
            "a daemon holds the data area but does not answer: it is starting or wedged. Wait a \
             moment and run doctor again; do not start another (it would be refused). If it \
             stays like this, stop the process that holds it with the tool that started it",
        ),
        LockProbe::Unknown(reason) => finding(
            Severity::Warn,
            "daemon lock",
            format!(
                "the data area's lock could not be examined ({reason}); treat a daemon as running"
            ),
        ),
    });

    let record = match facts.record {
        RecordState::Missing => {
            rows.push(finding(
                Severity::Warn,
                "ownership record",
                format!(
                    "no owner is recorded yet. The first daemon to start records itself; until \
                     then self-update and migration refuse. Fix: start the daemon you want to \
                     keep ({} is written on its first start)",
                    record_path.display()
                ),
            ));
            None
        }
        RecordState::Unreadable(reason) => {
            rows.push(finding(
                Severity::Error,
                "ownership record",
                format!(
                    "{reason}. The owner is unknown, so every start, update and migration \
                     refuses. Fix: stop the daemon, delete {}, then start the installation you \
                     want to keep",
                    record_path.display()
                ),
            ));
            None
        }
        RecordState::Present(record) => Some(record),
    };

    // Without a record the running daemon's own report is the best statement of who we are
    // checking registrations for; it is reported as such, never written back.
    let source = record
        .map(|r| r.install_source.as_str())
        .or_else(|| facts.running.map(|r| r.install_source.as_str()));

    if let Some(record) = record {
        rows.push(finding(
            Severity::Ok,
            "ownership record",
            format!(
                "owned by {} ({}) at {}",
                record.owner.as_str(),
                record.install_source,
                record.install_root
            ),
        ));
        let implied = Owner::for_install_source(&record.install_source);
        if implied != record.owner {
            rows.push(finding(
                Severity::Error,
                "ownership record",
                format!(
                    "the record names owner {} but install_source {} belongs to {}; the daemon \
                     of that installation is refused at start. Fix: stop the daemon, delete {}, \
                     then start the installation you want to keep so that it records itself",
                    record.owner.as_str(),
                    record.install_source,
                    implied.as_str(),
                    record_path.display()
                ),
            ));
        }
        let expected = layout_source(&record.install_root);
        let layout_row = match (expected, record.install_source.as_str()) {
            (Some(layout), recorded) if layout != recorded => Some(format!(
                "the record says {recorded}, but {} is laid out as {layout}. Fix: stop the \
                 daemon, delete {}, then start the installation you want to keep so that it \
                 records itself",
                record.install_root,
                record_path.display()
            )),
            (None, recorded @ ("app_bundle" | "microsoft_store")) => Some(format!(
                "the record says {recorded}, but {} is not {} location. Fix: stop the daemon, \
                 delete {}, then start the installation you want to keep so that it records \
                 itself",
                record.install_root,
                if recorded == "app_bundle" {
                    "an application bundle"
                } else {
                    "a Windows Store package"
                },
                record_path.display()
            )),
            _ => None,
        };
        rows.push(match layout_row {
            Some(detail) => finding(Severity::Error, "install source", detail),
            None => finding(
                Severity::Ok,
                "install source",
                format!("{} matches the install root's layout", record.install_source),
            ),
        });
    }

    if let (Some(record), Some(running)) = (record, facts.running) {
        rows.push(if running.install_source == record.install_source {
            finding(
                Severity::Ok,
                "update channel",
                format!(
                    "the running daemon is the recorded installation; updates are selected for \
                     install_source {}",
                    running.install_source
                ),
            )
        } else {
            finding(
                Severity::Error,
                "update channel",
                format!(
                    "the running daemon is installed as {} ({}), the record says {} ({}). Its \
                     update check would pick manifest entries of the wrong kind. Fix: stop that \
                     daemon and start the recorded installation, or hand the data over by \
                     deleting {} after stopping it",
                    running.install_source,
                    running.install_root,
                    record.install_source,
                    record.install_root,
                    record_path.display()
                ),
            )
        });
    }

    if let (Some(record), Some(running)) = (record, facts.running) {
        rows.extend(stale_release_row(record, running));
    }

    match (facts.local, facts.running) {
        (Err(problem), _) => {
            rows.push(finding(Severity::Error, "release descriptor", problem.message()))
        }
        (Ok(local), Some(running)) => {
            let daemon = running.descriptor();
            rows.push(match release_descriptor::check_pair(local, &daemon) {
                Ok(()) => finding(
                    Severity::Ok,
                    "release descriptor",
                    format!(
                        "this program and the running daemon are the same release (version {}, \
                         engine API {})",
                        daemon.version, daemon.engine_api_version
                    ),
                ),
                Err(mismatch) => {
                    finding(Severity::Error, "release descriptor", mismatch.message(local, &daemon))
                }
            });
        }
        (Ok(_), None) => {}
    }

    if let Some(source) = source {
        let conflicts = service_registrations::conflicting(source, facts.roots);
        if conflicts.is_empty() {
            rows.push(finding(
                Severity::Ok,
                CHECK_REGISTRATIONS,
                format!("no registration of another installation is present beside {source}"),
            ));
        }
        for registration in conflicts {
            rows.push(finding(
                Severity::Error,
                CHECK_REGISTRATIONS,
                format!(
                    "{} (belongs to {}) is registered but this data area is owned by {source}; \
                     two auto-starters would fight over one data area. Fix: {}",
                    registration.name,
                    registration.install_sources.join("/"),
                    service_registrations::removal_hint(registration)
                ),
            ));
        }
    }

    rows
}

#[cfg(test)]
mod tests;
