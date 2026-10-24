//! The process's machine id source is fixed by its first use. This binary holds one test: the
//! source is process-wide.

use yadorilink_daemon::machine_fingerprint::{fingerprint_of, machine_fingerprint};
use yadorilink_embedded_host::{EmbeddedHost, HostError, HostState, StartError};

mod support;
use support::{area, serialized};

// apple-cfg: ios-explicit iOS has no platform id: its host must supply one, so there is no
// platform-first start to test there.
#[cfg(not(target_os = "ios"))]
#[test]
fn a_host_id_after_the_platform_id_was_used_is_refused_and_changes_nothing() {
    let _serial = serialized();
    let area = area();

    // First engine: no host id, so the platform's fingerprint is used.
    let mut first = area.config.clone();
    first.machine_id = None;
    let host = EmbeddedHost::new(first.clone());
    host.start().unwrap();
    let platform = machine_fingerprint();
    host.stop().unwrap();

    // A later start with a host id is refused before anything changes.
    let mut with_id = first.clone();
    with_id.machine_id = Some("late-host-id".to_owned());
    let late = EmbeddedHost::new(with_id);
    let refused = late.start().unwrap_err();
    assert!(matches!(refused, HostError::Start(StartError::Other(_))), "{refused}");
    assert!(refused.to_string().contains("platform"), "{refused}");
    assert_eq!(late.state(), HostState::Stopped);
    assert_ne!(machine_fingerprint(), fingerprint_of(Some("late-host-id")));
    assert_eq!(machine_fingerprint(), platform);

    // The first engine's database reopens under the same fingerprint.
    host.start().unwrap();
    assert_eq!(machine_fingerprint(), platform);
    host.stop().unwrap();
}
