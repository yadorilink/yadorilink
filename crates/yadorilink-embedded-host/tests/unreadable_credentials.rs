//! A credential store that cannot be read refuses the start before the engine touches its
//! data: the block store and the database are neither created nor migrated.

use yadorilink_embedded_host::EmbeddedHost;

mod support;
use support::{area, serialized};

#[test]
fn an_unreadable_credential_store_refuses_the_start_before_any_data_is_created() {
    let _serial = serialized();
    let a = area();
    let state = &a.config.config_dir;
    std::fs::create_dir_all(state).unwrap();
    std::fs::write(state.join("credentials.json"), b"not a credential document").unwrap();

    let host = EmbeddedHost::new(a.config.clone());
    assert!(host.start().is_err(), "an unreadable credential store must refuse the start");
    assert!(!a.config.block_store_root.exists(), "the block store was created");
    assert!(!a.config.sync_db_path.exists(), "the database was created");
}
