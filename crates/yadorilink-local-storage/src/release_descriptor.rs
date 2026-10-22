//! The release descriptor an installed distribution carries, and the mismatch stop.
//!
//! One engine build is described by `engine-identity.json` beside its binaries. The descriptor
//! adds what the running engine knows about itself (its product version, its `install_source`,
//! the local control surface version it was compiled for) so that every component can compare
//! itself with the others it pairs with. Components of different builds never run together
//! (compat model B, "Local components"): a disagreement stops the caller before any
//! state-changing request, and nothing is written, started, stopped or deleted because of it.
//!
//! Everything here only reads.

use std::path::{Path, PathBuf};

use crate::ownership::Owner;

/// The engine identity file shipped beside the engine binaries.
pub const ENGINE_IDENTITY_FILE: &str = "engine-identity.json";

/// The build identity compiled into the program: `<public_commit_sha>:<build_config_digest>`
/// and the release channel, set by the release build through `YADORILINK_RELEASE_ID` and
/// `YADORILINK_CHANNEL`. A program that carries them names its own build without looking at where
/// it is installed, so the desktop host loading the static facade and a program run outside the
/// published layout are judged exactly like the daemon beside its `engine-identity.json`. Plain
/// development builds embed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmbeddedBuild {
    pub release_id: &'static str,
    pub channel: &'static str,
}

/// What this program was built as, `None` for a build that embeds no identity.
#[must_use]
pub fn embedded_build() -> Option<EmbeddedBuild> {
    let release_id = option_env!("YADORILINK_RELEASE_ID").unwrap_or_default();
    let channel = option_env!("YADORILINK_CHANNEL").unwrap_or_default();
    (!release_id.is_empty()).then_some(EmbeddedBuild { release_id, channel })
}

/// The directory holding the engine identity of the program at `exe`: beside it, or, for the
/// published macOS layout (`bin/<program>`, identity at the bundle root), one level up. When the
/// file is in neither place this is the directory beside the program.
#[must_use]
pub fn identity_dir(exe: &Path) -> Option<PathBuf> {
    let beside = exe.parent()?;
    if beside.join(ENGINE_IDENTITY_FILE).exists() {
        return Some(beside.to_path_buf());
    }
    if beside.file_name().is_some_and(|name| name == "bin") {
        if let Some(root) = beside.parent().filter(|r| r.join(ENGINE_IDENTITY_FILE).exists()) {
            return Some(root.to_path_buf());
        }
    }
    Some(beside.to_path_buf())
}

/// What `engine-identity.json` says about the build.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineIdentity {
    /// `<public_commit_sha>:<build_config_digest>`: the exact build.
    pub release_id: String,
    /// The release channel the artifact was built for; empty when the file names none.
    pub channel: String,
    /// The local control surface version the bundle was built for.
    pub engine_api_version: u32,
}

/// What a directory holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityFile {
    /// No identity file: a build tree or a package that ships none.
    Absent,
    Present(EngineIdentity),
    /// The file exists and cannot be read or understood. The build is unknown.
    Unreadable(String),
}

/// Reads the engine identity in `dir`. Read-only.
#[must_use]
pub fn read_identity(dir: Option<&Path>) -> IdentityFile {
    let Some(dir) = dir else { return IdentityFile::Absent };
    let bytes = match std::fs::read(dir.join(ENGINE_IDENTITY_FILE)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return IdentityFile::Absent,
        Err(e) => {
            return IdentityFile::Unreadable(format!("cannot read {ENGINE_IDENTITY_FILE}: {e}"))
        }
    };
    parse_identity(&bytes).map_or_else(IdentityFile::Unreadable, IdentityFile::Present)
}

fn parse_identity(bytes: &[u8]) -> Result<EngineIdentity, String> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes)
        .map_err(|e| format!("{ENGINE_IDENTITY_FILE} is not valid JSON: {e}"))?;
    let text = |key: &str| value.get(key).and_then(|v| v.as_str());
    let (Some(commit), Some(digest)) = (text("public_commit_sha"), text("build_config_digest"))
    else {
        return Err(format!(
            "{ENGINE_IDENTITY_FILE} lacks public_commit_sha or build_config_digest"
        ));
    };
    let api = value
        .get("engine_api_version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .ok_or_else(|| format!("{ENGINE_IDENTITY_FILE} lacks engine_api_version"))?;
    Ok(EngineIdentity {
        release_id: format!("{commit}:{digest}"),
        channel: text("channel").unwrap_or_default().to_string(),
        engine_api_version: api,
    })
}

/// The descriptor of one running component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseDescriptor {
    /// The product version.
    pub version: String,
    /// The channel the build was made for; empty when unknown.
    pub channel: String,
    pub install_source: String,
    /// The exact build; empty when the installation carries no engine identity.
    pub release_id: String,
    /// The local control surface version this component speaks.
    pub engine_api_version: u32,
}

/// Why a component's own descriptor cannot be trusted. Fail closed: such a component does not run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DescriptorProblem {
    /// The identity file beside the binaries exists but cannot be read or understood.
    Unreadable { reason: String },
    /// The identity beside the binaries was made for another control surface version than the
    /// binary speaks: parts of two builds are mixed in one install.
    MixedBundle { identity_api: u32, binary_api: u32, identity_path: PathBuf },
    /// The identity beside the binaries names another build than the one compiled into the
    /// program: parts of two builds are mixed in one install.
    BuildMismatch { embedded: String, identity: String, identity_path: PathBuf },
}

impl DescriptorProblem {
    /// The explanation shown to the user, with the one action that fixes it.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            DescriptorProblem::Unreadable { reason } => format!(
                "the release descriptor of this installation cannot be read ({reason}); nothing \
                 was started. Reinstall or finish updating YadoriLink with the updater that \
                 installed it."
            ),
            DescriptorProblem::MixedBundle { identity_api, binary_api, identity_path } => format!(
                "this installation mixes two builds: {} was made for engine API {identity_api} \
                 but this program speaks engine API {binary_api}; nothing was started. Finish \
                 updating (or reinstall) YadoriLink with the updater that installed it.",
                identity_path.display()
            ),
            DescriptorProblem::BuildMismatch { embedded, identity, identity_path } => format!(
                "this installation mixes two builds: this program was built as {embedded} but \
                 {} names {identity}; nothing was started. Finish updating (or reinstall) \
                 YadoriLink with the updater that installed it.",
                identity_path.display()
            ),
        }
    }
}

impl ReleaseDescriptor {
    /// The descriptor of a program that speaks `binary_api`, installed beside `identity_dir`,
    /// with the build identity compiled into this program ([`embedded_build`]).
    ///
    /// # Errors
    /// [`DescriptorProblem`] when the identity file is unreadable or disagrees with the program.
    pub fn of_program(
        version: &str,
        install_source: &str,
        binary_api: u32,
        identity_dir: Option<&Path>,
    ) -> Result<Self, DescriptorProblem> {
        Self::of_build(version, install_source, binary_api, identity_dir, embedded_build())
    }

    /// [`Self::of_program`] for a program built as `embedded`. The embedded identity is the
    /// program's own statement of its build; an `engine-identity.json` beside it may only
    /// confirm it, and one that names another build is a mixed install. Without an embedded
    /// identity the file beside the binaries is the only statement.
    ///
    /// # Errors
    /// [`DescriptorProblem`] when the identity file is unreadable or disagrees with the program.
    pub fn of_build(
        version: &str,
        install_source: &str,
        binary_api: u32,
        identity_dir: Option<&Path>,
        embedded: Option<EmbeddedBuild>,
    ) -> Result<Self, DescriptorProblem> {
        let from_file = match read_identity(identity_dir) {
            IdentityFile::Absent => None,
            IdentityFile::Unreadable(reason) => {
                return Err(DescriptorProblem::Unreadable { reason });
            }
            IdentityFile::Present(identity) => {
                let identity_path =
                    identity_dir.map(|d| d.join(ENGINE_IDENTITY_FILE)).unwrap_or_default();
                if identity.engine_api_version != binary_api {
                    return Err(DescriptorProblem::MixedBundle {
                        identity_api: identity.engine_api_version,
                        binary_api,
                        identity_path,
                    });
                }
                if let Some(built) = embedded.filter(|b| b.release_id != identity.release_id) {
                    return Err(DescriptorProblem::BuildMismatch {
                        embedded: built.release_id.to_string(),
                        identity: identity.release_id,
                        identity_path,
                    });
                }
                Some(identity)
            }
        };
        let (release_id, channel) = match (embedded, from_file) {
            (Some(built), _) => (built.release_id.to_string(), built.channel.to_string()),
            (None, Some(identity)) => (identity.release_id, identity.channel),
            (None, None) => (String::new(), String::new()),
        };
        Ok(Self {
            version: version.to_string(),
            channel,
            install_source: install_source.to_string(),
            release_id,
            engine_api_version: binary_api,
        })
    }
}

/// How a caller and the daemon it pairs with disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairMismatch {
    /// Different local control surface versions.
    EngineApi { caller: u32, daemon: u32 },
    /// Different builds of the engine (or the daemon carries no identity while the caller does).
    Build { caller: String, daemon: String },
}

/// Compares the caller's descriptor with the daemon's, as `identify` reports it.
///
/// A caller that carries no engine identity cannot name its build and is compared by control
/// surface version only; a caller that carries one needs the daemon to carry the same.
///
/// # Errors
/// [`PairMismatch`]; the control surface version is judged first.
pub fn check_pair(
    caller: &ReleaseDescriptor,
    daemon: &ReleaseDescriptor,
) -> Result<(), PairMismatch> {
    if caller.engine_api_version != daemon.engine_api_version {
        return Err(PairMismatch::EngineApi {
            caller: caller.engine_api_version,
            daemon: daemon.engine_api_version,
        });
    }
    if !caller.release_id.is_empty() && caller.release_id != daemon.release_id {
        return Err(PairMismatch::Build {
            caller: caller.release_id.clone(),
            daemon: daemon.release_id.clone(),
        });
    }
    Ok(())
}

impl PairMismatch {
    /// The explanation: which component is out of date and which updater fixes it. Nothing was
    /// changed, and nothing will be until the installation is finished updating.
    #[must_use]
    pub fn message(&self, caller: &ReleaseDescriptor, daemon: &ReleaseDescriptor) -> String {
        let what = match self {
            PairMismatch::EngineApi { caller, daemon } => {
                format!(
                    "they speak different engine APIs (this program {caller}, the daemon {daemon})"
                )
            }
            PairMismatch::Build { caller, daemon } => format!(
                "they are different builds (this program {}, the daemon {})",
                shown(caller),
                shown(daemon)
            ),
        };
        let fix = match Owner::for_install_source(&daemon.install_source) {
            Owner::Gui => "Open the YadoriLink app so that it finishes updating".to_string(),
            Owner::Cli => format!(
                "Finish updating the {} installation with its own updater and restart its daemon",
                daemon.install_source
            ),
        };
        format!(
            "this YadoriLink program ({}) and the running daemon ({}) do not come from the same \
             release: {what}. Nothing was changed. {fix}; only read-only commands such as \
             `yadorilink doctor` work until then.",
            caller.version, daemon.version
        )
    }
}

fn shown(release_id: &str) -> &str {
    if release_id.is_empty() {
        "no engine identity"
    } else {
        release_id
    }
}

#[cfg(test)]
mod tests;
