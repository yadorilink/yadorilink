//! Manual verification helper: seeds an
//! OnDemand-policy folder link + one Placeholder-state file record
//! directly into the daemon's SQLite state, bypassing the CLI's
//! coordination-plane-dependent `link` command (which needs a
//! logged-in, registered device) — mirrors
//! `seed_overlay_test_data.rs`'s pattern, extended with
//! `set_materialization_policy`/`set_materialization_state` so the
//! macOS File Provider extension has an OnDemand folder group to
//! discover and register as an `NSFileProviderDomain`.
//!
//! Usage: `cargo run --example seed_ondemand_test_data -- <folder> <group_id> <relative_file>`

use std::sync::Arc;

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let folder = args.get(1).expect("usage: <folder> <group_id> <relative_file>");
    let group_id = args.get(2).expect("usage: <folder> <group_id> <relative_file>");
    let relative_file = args.get(3).expect("usage: <folder> <group_id> <relative_file>");

    let config_dir =
        std::env::var("YADORILINK_CONFIG_DIR").expect("YADORILINK_CONFIG_DIR must be set");
    let config_dir = std::path::PathBuf::from(config_dir);
    std::fs::create_dir_all(&config_dir).unwrap();

    let store = Arc::new(SegmentBlockStore::new(config_dir.join("blocks")).unwrap());
    let sync_state =
        Arc::new(ReplicaCoordinator::open(config_dir.join("sync-state.sqlite3")).unwrap());

    sync_state.link_repository().add_link(folder, group_id).unwrap();
    sync_state
        .link_repository()
        .set_materialization_policy(folder, MaterializationPolicy::OnDemand)
        .unwrap();

    let path = std::path::Path::new(folder).join(relative_file);
    let content = std::fs::read(&path).unwrap();
    let blocks = yadorilink_local_storage::chunk_file(store.as_ref(), &path).unwrap();

    sync_state
        .file_index_repository()
        .upsert_file(
            group_id,
            &FileRecord {
                path: relative_file.clone(),
                size: content.len() as u64,
                mtime_unix_nanos: 0,
                blocks,
                deleted: false,
            },
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();
    sync_state
        .materialization_state_repository()
        .set_materialization_state(
            group_id,
            relative_file,
            MaterializationState::Remote,
            &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
        )
        .unwrap();

    println!(
        "seeded OnDemand: folder={folder} group={group_id} file={relative_file} (Placeholder)"
    );
}
