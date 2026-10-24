//! The embedded engine's default budgets, pinned where the daemon is built without its desktop
//! process model (this crate's dependency). The daemon's own tests cannot pin them: its
//! self dev-dependency turns the process model on in every one of its test binaries.

use yadorilink_embedded_host::EngineTuning;

#[test]
fn the_embedded_default_budgets_are_the_small_ones() {
    let defaults = EngineTuning::default();
    assert_eq!(defaults.receive_write_permits, 8, "per-engine receive write permits");
    assert_eq!(defaults.group_commit.max_cached_readers, 16, "cached segment readers");
}
