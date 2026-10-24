//! The platform-independent policy of the Windows provider host.
//!
//! Nothing here calls the operating system's Win32 or Cloud Files interfaces, so everything,
//! including its tests, runs on any platform. The Windows host crate owns the glue (the named
//! pipe transport, the Cloud Files calls, the NTFS change journal) and implements the traits
//! declared here.

pub mod fetch_report;
pub mod host;
pub mod host_paths;
pub mod namespace_policy;
pub mod provider_authoring;
pub mod provider_client;
pub mod provider_report;
pub mod provider_session;
pub mod stage_ledger;
pub mod windowed_fetch;
