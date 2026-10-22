//! `SyncState`-backed implementations of `application::ports::*Repository`
//! traits -- the only place in this crate that hands a raw `SyncState`
//! method call to `application` code, wrapped one method at a time behind
//! the narrow contract each repository port declares.

pub(crate) mod enrollment;
pub(crate) mod membership;
pub(crate) mod replica_role;
