//! A start that fails validation installs no machine id, and the host id is then fixed by the
//! first start that gets as far as using it. This binary holds one test: the source is
//! process-wide.

use yadorilink_daemon::machine_fingerprint::{fingerprint_of, machine_fingerprint};
use yadorilink_embedded_host::EmbeddedHost;

mod support;
use support::{area, serialized};

#[test]
fn a_failed_start_installs_nothing_and_ids_are_fixed_by_the_first_good_start() {
    let _serial = serialized();

    // A start refused for its id, and one that fails on its state, install nothing.
    let bad = area();
    let mut empty = bad.config.clone();
    empty.machine_id = Some(" ".to_owned());
    assert!(EmbeddedHost::new(empty).start().is_err());
    std::fs::create_dir_all(&bad.config.config_dir).unwrap();
    std::fs::write(bad.config.config_dir.join("device.json"), "not json").unwrap();
    let mut broken = bad.config.clone();
    broken.machine_id = Some("never-installed".to_owned());
    assert!(EmbeddedHost::new(broken).start().is_err());

    // So another id still starts, and then it is the one: the same id again is accepted and a
    // different one is refused.
    let good = area();
    let mut a = good.config.clone();
    a.machine_id = Some("id-a".to_owned());
    let host = EmbeddedHost::new(a.clone());
    host.start().unwrap();
    assert_eq!(machine_fingerprint(), fingerprint_of(Some("id-a")));
    host.stop().unwrap();
    host.start().unwrap();
    host.stop().unwrap();

    let mut b = good.config.clone();
    b.machine_id = Some("id-b".to_owned());
    assert!(EmbeddedHost::new(b).start().is_err());
    assert_eq!(machine_fingerprint(), fingerprint_of(Some("id-a")));
}
