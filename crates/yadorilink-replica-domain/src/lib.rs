//! Pure replica domain model -- identities, file/version records, the
//! signed canonical `Change`, and deterministic conflict policy. No
//! filesystem, network, database, or async runtime dependency: everything
//! here is a synchronous, deterministic function of its inputs. The
//! boundary is declared in `.config/architecture.toml` (this crate is the base of
//! the `domain` layer) and enforced by `.github/checks/check-architecture.py`.

pub mod admission;
pub mod author;
pub mod author_closure;
pub mod authorization_checkpoint;
pub mod codec;
pub mod conflict;
pub mod file;
pub mod history_truncation;
pub mod ids;
pub mod limits;
pub mod local_op;
pub mod native_checkpoint;
pub mod native_checkpoint_seal;
pub mod native_fork;
pub mod native_frontier;
pub mod native_plan;
pub mod native_project;
pub mod native_protocol;
pub mod native_state;
pub mod proof_carrying_delta;
pub mod protocol5;
pub mod recovery;
pub mod recursive_operation;
pub mod reserved_paths;
pub mod rewind;
pub mod session_state;
pub mod signed_delta;
