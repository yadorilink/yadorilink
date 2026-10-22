//! A reference oracle for signed per-path bases.
//!
//! Every change signs, per touched path, the changes it supersedes there
//! (its basis). Path supersession is the transitive closure of those signed
//! edges, and the heads of a history at a path are the changes that land
//! content there and that nothing in the history supersedes.
//!
//! This crate computes heads straight from that definition over an explicit
//! set of changes. It keeps no watermarks, applies no transition rule and
//! shares no code with any implementation, so it can check incremental
//! step/join implementations differentially:
//!
//! * [`model`]: changes, operations, preservations, the universe of signed
//!   changes.
//! * [`semantics`]: supersession, heads, joins as unions, representability,
//!   future equivalence.
//! * [`strict`]: the author-side rule against an author's own pre-state.
//! * [`generate`]: random histories that satisfy the author-side rule.
//! * [`harness`]: [`check`] and [`check_join`] run an implementation on
//!   generated histories and report the first disagreement.
//!

pub mod generate;
pub mod harness;
pub mod model;
pub mod semantics;
pub mod strict;

pub use generate::{generate, GenConfig, Scenario};
pub use harness::{check, check_join, CheckConfig, CheckReport, Mismatch};
pub use model::{
    conflict_path, AuthorId, Change, ChangeId, Dot, Effect, Heads, History, Op, Path, Preservation,
    Universe, Version,
};
pub use semantics::{heads_of_history, is_future_equivalent, supersedes};
pub use strict::{verify_strict, verify_strict_safe, StrictViolation};
