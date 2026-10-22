//! Who this daemon is and who owns its data area: the `identify` report and the start gate.
//!
//! Everything environmental (the executable's path, the install source, the clock, the process
//! id) is an input of [`IdentityInputs`], so tests choose a layout instead of depending on where
//! the test binary happens to live. The data area's recorded owner is read from disk each time
//! it is reported; reporting never writes.

use std::path::{Path, PathBuf};

use yadorilink_ipc_proto::daemonctl::{
    IdentifyResponse, OwnershipRecordInfo, OwnershipRecordStatus,
};
use yadorilink_local_storage::ownership::{
    self, Owner, OwnershipRecord, RecordState, Refusal, StartVerdict,
};
use yadorilink_local_storage::release_descriptor::{DescriptorProblem, ReleaseDescriptor};

/// The start was refused because another owner is recorded for the data area, or the record is
/// unreadable. Nothing was started or modified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipRefused(pub Refusal, pub PathBuf);

impl std::fmt::Display for OwnershipRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "refusing to start: {}", self.0.message(&self.1))
    }
}

impl std::error::Error for OwnershipRefused {}

/// The status a daemon exits with when another owner manages its data area (`EX_CONFIG`).
pub const REFUSAL_EXIT_CODE: i32 = 78;

/// How long a refused daemon waits before exiting, so a service manager that restarts it does
/// so about once a minute instead of in a tight loop.
pub const REFUSAL_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);

/// The environment facts an identity is derived from.
#[derive(Debug, Clone)]
pub struct IdentityInputs {
    pub exe: PathBuf,
    /// Already refined (see `update::install_source::refine`).
    pub install_source: String,
    pub pid: u32,
    pub started_at_unix: u64,
    pub config_dir: Option<PathBuf>,
}

#[derive(Debug)]
pub struct RuntimeIdentity {
    exe: PathBuf,
    install_source: String,
    install_root: PathBuf,
    owner: Owner,
    /// This build's release descriptor, or why it cannot be trusted (the start is then refused).
    descriptor: Result<ReleaseDescriptor, DescriptorProblem>,
    pid: u32,
    started_at_unix: u64,
    config_dir: Option<PathBuf>,
}

impl RuntimeIdentity {
    #[must_use]
    pub fn from_inputs(inputs: IdentityInputs) -> Self {
        let install_root = ownership::app_bundle_root(&inputs.exe)
            .or_else(|| inputs.exe.parent().map(Path::to_path_buf))
            .unwrap_or_default();
        let descriptor = ReleaseDescriptor::of_program(
            env!("CARGO_PKG_VERSION"),
            &inputs.install_source,
            yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION,
            yadorilink_local_storage::release_descriptor::identity_dir(&inputs.exe).as_deref(),
        );
        Self {
            exe: inputs.exe,
            owner: Owner::for_install_source(&inputs.install_source),
            descriptor,
            install_source: inputs.install_source,
            install_root,
            pid: inputs.pid,
            started_at_unix: inputs.started_at_unix,
            config_dir: inputs.config_dir,
        }
    }

    /// This process, as installed.
    #[must_use]
    pub fn detect(config_dir: Option<PathBuf>) -> Self {
        Self::from_inputs(IdentityInputs {
            exe: crate::update::install_source::running_exe(),
            install_source: crate::update::manager::PlatformInfo::detect().install_source,
            pid: std::process::id(),
            started_at_unix: now_unix(),
            config_dir,
        })
    }

    /// What disappearing means this installation is gone: the application bundle when the
    /// daemon runs from one (the bundle is replaced or deleted as a whole), else the executable.
    /// `None` when the executable's path is unknown.
    #[must_use]
    pub fn watched_path(&self) -> Option<PathBuf> {
        if self.exe.as_os_str().is_empty() {
            return None;
        }
        Some(ownership::app_bundle_root(&self.exe).unwrap_or_else(|| self.exe.clone()))
    }

    #[must_use]
    pub fn owner(&self) -> Owner {
        self.owner
    }

    #[must_use]
    pub fn install_source(&self) -> &str {
        &self.install_source
    }

    /// The engine build, empty when the installation carries no engine identity or its
    /// descriptor is unusable.
    fn release_id(&self) -> String {
        self.descriptor.as_ref().map(|d| d.release_id.clone()).unwrap_or_default()
    }

    /// The record this daemon would write for itself.
    #[must_use]
    pub fn own_record(&self, written_at: u64) -> OwnershipRecord {
        OwnershipRecord {
            owner: self.owner,
            install_source: self.install_source.clone(),
            install_root: self.install_root.display().to_string(),
            release_id: self.release_id(),
            written_at,
        }
    }

    /// Decides whether this daemon may run over `config_dir`, which the caller has already
    /// locked. The recorded installation (same owner and `install_source`) proceeds;
    /// an installation whose release descriptor is unusable is refused first; another owner, another installation of the same kind or an unreadable record refuses; with
    /// no record this daemon records itself as the owner (the lock proves nothing else is
    /// running, and the record is what keeps a later start by another owner out); if that write
    /// fails the start is refused.
    ///
    /// # Errors
    /// [`OwnershipRefused`], with nothing written.
    pub fn gate_start(&self, config_dir: &Path) -> Result<(), OwnershipRefused> {
        // Mismatch stop: an installation whose own descriptor is unusable runs nothing and
        // writes nothing, whatever the record says.
        if let Err(problem) = &self.descriptor {
            return Err(OwnershipRefused(
                Refusal::DescriptorUnusable { problem: problem.clone() },
                config_dir.to_path_buf(),
            ));
        }
        // A hand-off to the app that stopped half-way settles who owns the data area: no daemon
        // of either owner starts until it is finished or rolled back.
        if let Some(refusal) = yadorilink_local_storage::handoff::start_refusal(config_dir) {
            return Err(OwnershipRefused(refusal, config_dir.to_path_buf()));
        }
        match ownership::start_verdict_for_installation(
            &ownership::read(config_dir),
            self.owner,
            &self.install_source,
        ) {
            StartVerdict::Proceed => self.refresh_release(config_dir),
            StartVerdict::Refuse(refusal) => {
                Err(OwnershipRefused(refusal, config_dir.to_path_buf()))
            }
            StartVerdict::NoRecord => {
                // Without a record another install source could claim the data area later, so
                // a start that cannot record its owner does not happen.
                ownership::write(config_dir, &self.own_record(now_unix())).map_err(|e| {
                    OwnershipRefused(
                        Refusal::OwnerRecordUnwritable { reason: e.to_string() },
                        config_dir.to_path_buf(),
                    )
                })
            }
        }
    }

    /// The recorded installation is this one and may start; its record says which release it was
    /// when it was recorded. A self-updating install moves past that release, so the daemon that
    /// now holds the lock (the descriptor was checked above, the record names its installation)
    /// states its own release in the record, atomically and keeping everything else, so that
    /// `doctor` can compare the record with the running daemon. A hand-off journal in the config
    /// directory means the record belongs to that hand-off: it is left alone. If the record cannot
    /// be rewritten the start is refused, as for a first record.
    fn refresh_release(&self, config_dir: &Path) -> Result<(), OwnershipRefused> {
        if yadorilink_local_storage::handoff::is_open(config_dir) {
            return Ok(());
        }
        let RecordState::Present(mut record) = ownership::read(config_dir) else {
            return Ok(());
        };
        let release_id = self.release_id();
        if record.release_id == release_id {
            return Ok(());
        }
        record.release_id = release_id;
        record.written_at = now_unix();
        ownership::write(config_dir, &record).map_err(|e| {
            OwnershipRefused(
                Refusal::OwnerRecordUnwritable { reason: e.to_string() },
                config_dir.to_path_buf(),
            )
        })
    }

    /// The `identify` answer. Reads the recorded owner; writes nothing.
    #[must_use]
    pub fn report(&self) -> IdentifyResponse {
        let (status, record, detail) = match self.config_dir.as_deref().map(ownership::read) {
            None | Some(RecordState::Missing) => {
                (OwnershipRecordStatus::Missing, None, String::new())
            }
            Some(RecordState::Present(r)) => (
                OwnershipRecordStatus::Recorded,
                Some(OwnershipRecordInfo {
                    owner: r.owner.as_str().to_string(),
                    install_source: r.install_source,
                    install_root: r.install_root,
                    release_id: r.release_id,
                    written_at_unix: r.written_at,
                }),
                String::new(),
            ),
            Some(RecordState::Unreadable(reason)) => {
                (OwnershipRecordStatus::Unreadable, None, reason)
            }
        };
        IdentifyResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            engine_api_version: yadorilink_ipc_proto::PROVIDER_HOST_API_VERSION,
            release_id: self.release_id(),
            install_source: self.install_source.clone(),
            install_root: self.install_root.display().to_string(),
            owner: self.owner.as_str().to_string(),
            ownership_status: status as i32,
            ownership_record: record,
            ownership_detail: detail,
            pid: self.pid,
            started_at_unix: self.started_at_unix,
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests;
