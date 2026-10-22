//! Signed update discovery for desktop builds (v1 ships manual updates:
//! the daemon checks and reports a new version, the user downloads and
//! installs it). See each submodule's doc comment:
//!  - `manifest`: the signed update manifest.
//!  - `trust`: the key-rotation/revocation chain extending the pinned keys.
//!  - `replay`: rollback protection (newest accepted `generated_at` per channel).
//!  - `policy`: persisted daemon update policy/state.
//!  - `manager`: check orchestration and background scheduling.
//!  - `install_source`: how this copy was installed (apt, Homebrew,
//!    Microsoft Store, WinGet, standalone).

pub mod install_source;
pub mod manager;
pub mod manifest;
pub mod policy;
pub mod replay;
pub mod trust;
