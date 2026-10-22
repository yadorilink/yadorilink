//! Protection: if this device were lost now, is the data still somewhere else.
//!
//! One of two independent product dimensions (the other is [`crate::availability`]). It is
//! derived only from durability and replication truth the daemon already computes, never from
//! whether a device is online right now: a confirmed copy on an offline device is still a copy.
//! "Unavailable" is never a protection state.
//!
//! * `Protected`: a copy on another device is confirmed
//! * `AtRisk`: confirmed that only this device holds the current content
//! * `Pending`: a copy is being made or a confirmation is still awaited
//! * `Unknown`: not enough evidence; never read as `Protected`
//!
//! Aggregation (a folder set is as protected as its least protected part, the first match wins):
//!
//! 1. `AtRisk`: one confirmed single copy is a loss waiting to happen whatever the rest say
//! 2. `Pending`: protection is on its way but not there yet
//! 3. `Unknown`: no evidence
//! 4. `Protected`
//!
//! A set is `Protected` only when every part is provably `Protected`. An empty set has nothing
//! to prove, so it is `Unknown`, not `Protected`; shells show no protection line with no folders.
//!
//! Serialization contract: [`Protection::as_str`] names are stable snake_case and are what
//! `status --json` prints; the wire enum is `DataProtection`, where an unset value is `Unknown`.

use std::collections::BTreeSet;

use yadorilink_ipc_proto::daemonctl::{DataProtection, LinkStatus};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    Protected,
    AtRisk,
    Pending,
    Unknown,
}

impl Protection {
    pub fn as_str(self) -> &'static str {
        match self {
            Protection::Protected => "protected",
            Protection::AtRisk => "at_risk",
            Protection::Pending => "pending",
            Protection::Unknown => "unknown",
        }
    }

    pub fn from_wire(wire: DataProtection) -> Self {
        match wire {
            DataProtection::Protected => Protection::Protected,
            DataProtection::AtRisk => Protection::AtRisk,
            DataProtection::Pending => Protection::Pending,
            DataProtection::Unknown | DataProtection::Unspecified => Protection::Unknown,
        }
    }

    pub fn to_wire(self) -> DataProtection {
        match self {
            Protection::Protected => DataProtection::Protected,
            Protection::AtRisk => DataProtection::AtRisk,
            Protection::Pending => DataProtection::Pending,
            Protection::Unknown => DataProtection::Unknown,
        }
    }

    /// Higher rank wins an aggregation (see the module doc).
    fn rank(self) -> u8 {
        match self {
            Protection::AtRisk => 3,
            Protection::Pending => 2,
            Protection::Unknown => 1,
            Protection::Protected => 0,
        }
    }
}

/// The protection state with the devices it concerns: the other devices that confirmed holding
/// the data when `Protected`, the devices a confirmation is awaited from when `Pending` (empty
/// when this device itself is still catching up), empty otherwise. Sorted without duplicates; a
/// shell resolves them to display names and never shows the ids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectionSummary {
    pub protection: Protection,
    pub device_ids: Vec<String>,
}

impl ProtectionSummary {
    /// Read from the daemon's per-link fields; an older daemon's unset fields read `Unknown`.
    pub fn from_link(link: &LinkStatus) -> Self {
        ProtectionSummary {
            protection: Protection::from_wire(link.protection()),
            device_ids: link.protection_device_ids.clone(),
        }
    }

    /// The least protected of `parts` (see the module doc). The devices are those of the parts
    /// that decided the result: copies for `Protected`, awaited devices for `Pending`, none for
    /// `AtRisk` and `Unknown`.
    pub fn aggregate(parts: &[ProtectionSummary]) -> Self {
        let protection = if parts.is_empty() {
            Protection::Unknown
        } else {
            parts.iter().map(|p| p.protection).fold(Protection::Protected, |a, b| {
                if b.rank() > a.rank() {
                    b
                } else {
                    a
                }
            })
        };
        let device_ids: BTreeSet<&String> = match protection {
            Protection::Protected | Protection::Pending => parts
                .iter()
                .filter(|p| p.protection == protection)
                .flat_map(|p| &p.device_ids)
                .collect(),
            Protection::AtRisk | Protection::Unknown => BTreeSet::new(),
        };
        ProtectionSummary { protection, device_ids: device_ids.into_iter().cloned().collect() }
    }
}

#[cfg(test)]
mod tests;
