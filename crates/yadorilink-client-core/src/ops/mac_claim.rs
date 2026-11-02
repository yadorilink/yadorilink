//! One build per Mac (direct vs Mac App Store): the app's view of the engine's claim. A thin layer over
//! `yadorilink_local_storage::mac_claim`, which the daemon takes at start; this module only reads why a start was
//! refused and performs the two explicit moves (take over, release) while no daemon of the build runs.

use std::path::Path;

use yadorilink_local_storage::mac_claim::{self, Channel, Refusal};
use yadorilink_local_storage::startup_refusal::{self, RefusalCode};

use crate::dto::{MacBuild, MacClaimRefusal};

fn build_of(channel: &str) -> Option<MacBuild> {
    match channel {
        "direct" => Some(MacBuild::Direct),
        "store" => Some(MacBuild::Store),
        _ => None,
    }
}

fn channel_of(build: MacBuild) -> Channel {
    match build {
        MacBuild::Direct => Channel::Direct,
        MacBuild::Store => Channel::Store,
    }
}

fn build_from(channel: Channel) -> MacBuild {
    match channel {
        Channel::Direct => MacBuild::Direct,
        Channel::Store => MacBuild::Store,
    }
}

fn refusal_from(refusal: Refusal) -> MacClaimRefusal {
    match refusal {
        Refusal::OtherChannelRunning(c) => {
            MacClaimRefusal::OtherBuildRunning { build: build_from(c) }
        }
        Refusal::OtherChannelConfigured(c) => {
            MacClaimRefusal::OtherBuildConfigured { build: build_from(c) }
        }
        Refusal::StillRunning(c) => MacClaimRefusal::StillRunning { build: build_from(c) },
        Refusal::Unavailable(message) => MacClaimRefusal::Unavailable { message },
    }
}

/// Why the daemon last refused to start because of the other build, if that is the recorded reason. A refusal for
/// another reason, or none, is `None`.
#[must_use]
pub fn startup_refusal_claim() -> Option<MacClaimRefusal> {
    let dir = crate::coordination::device_config::config_dir().ok()?;
    refusal_in(&dir)
}

fn refusal_in(config_dir: &Path) -> Option<MacClaimRefusal> {
    match startup_refusal::read(config_dir)?.code? {
        RefusalCode::OtherChannelRunning(c) => {
            Some(MacClaimRefusal::OtherBuildRunning { build: build_of(&c)? })
        }
        RefusalCode::OtherChannelConfigured(c) => {
            Some(MacClaimRefusal::OtherBuildConfigured { build: build_of(&c)? })
        }
    }
}

/// The person confirmed switching this Mac to `this` build: records it as the configured build. Refused (`Some`) while a
/// daemon of the other build runs, or when the claim cannot be read; the shared lock proves nothing is using the Mac.
/// The caller then starts its daemon, which takes the claim itself.
#[must_use]
pub fn take_over(container: &Path, this: MacBuild) -> Option<MacClaimRefusal> {
    // The returned claim (a shared lock) is dropped at once: only the record is the decision, and the daemon that starts
    // next takes its own lock.
    mac_claim::take_over(container, channel_of(this)).err().map(refusal_from)
}

/// `this` build gives the Mac up (sign-out or removal, after pending edits were refused or kept). Refused (`Some`) while a
/// daemon of this build runs or when `this` is not the configured build.
#[must_use]
pub fn release(container: &Path, this: MacBuild) -> Option<MacClaimRefusal> {
    mac_claim::release(container, channel_of(this)).err().map(refusal_from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recorded_claim_refusal_reads_back_as_the_other_build() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(refusal_in(dir.path()), None);
        startup_refusal::record(
            dir.path(),
            &startup_refusal::StartupRefusal::coded(
                "x",
                RefusalCode::OtherChannelConfigured("direct".into()),
            ),
        )
        .unwrap();
        assert_eq!(
            refusal_in(dir.path()),
            Some(MacClaimRefusal::OtherBuildConfigured { build: MacBuild::Direct })
        );
        startup_refusal::record(
            dir.path(),
            &startup_refusal::StartupRefusal::coded(
                "x",
                RefusalCode::OtherChannelRunning("store".into()),
            ),
        )
        .unwrap();
        assert_eq!(
            refusal_in(dir.path()),
            Some(MacClaimRefusal::OtherBuildRunning { build: MacBuild::Store })
        );
    }

    #[test]
    fn a_refusal_for_another_reason_is_not_a_claim_refusal() {
        let dir = tempfile::tempdir().unwrap();
        startup_refusal::record(dir.path(), &startup_refusal::StartupRefusal::plain("cannot open"))
            .unwrap();
        assert_eq!(refusal_in(dir.path()), None);
    }

    #[test]
    fn take_over_is_refused_while_the_other_build_runs_and_release_while_this_one_runs() {
        let dir = tempfile::tempdir().unwrap();
        let running = mac_claim::acquire(dir.path(), Channel::Direct).unwrap();
        assert_eq!(
            take_over(dir.path(), MacBuild::Store),
            Some(MacClaimRefusal::OtherBuildRunning { build: MacBuild::Direct })
        );
        assert_eq!(
            release(dir.path(), MacBuild::Direct),
            Some(MacClaimRefusal::StillRunning { build: MacBuild::Direct })
        );
        drop(running);
        assert_eq!(take_over(dir.path(), MacBuild::Store), None);
        // after the switch the old build can start again only through its own take over
        assert!(matches!(
            mac_claim::acquire(dir.path(), Channel::Direct),
            Err(Refusal::OtherChannelConfigured(Channel::Store))
        ));
        assert_eq!(release(dir.path(), MacBuild::Store), None);
        assert!(mac_claim::acquire(dir.path(), Channel::Direct).is_ok());
    }
}
