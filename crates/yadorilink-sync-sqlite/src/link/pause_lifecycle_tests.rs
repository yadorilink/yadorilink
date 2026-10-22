#![cfg(test)]

//! A pause belongs to the folder link it was made on: it must not survive
//! the link, nor carry into a provider root of the same group.

use super::*;
use crate::paused_items::PausedItemRepository;
use crate::provider::ProviderRepository;
use yadorilink_replica_domain::session_state::ProviderKind;

fn open_full_test_db() -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            crate::replica_tables::init_for_tests(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            yadorilink_sqlite_runtime::init_schema(conn)
        })
        .expect("open in-memory db"),
    )
}

struct Fixture {
    db: Arc<SyncDatabase>,
    links: LinkRepository,
    pauses: PausedItemRepository,
}

fn fixture() -> Fixture {
    let db = open_full_test_db();
    Fixture {
        links: LinkRepository::new(db.clone()),
        pauses: PausedItemRepository::new(db.clone()),
        db,
    }
}

fn pending_obligation_backoff(db: &Arc<SyncDatabase>, group: &str) -> i64 {
    db.read::<_, SyncSqliteError>(|conn| {
        Ok(conn.query_row(
            "SELECT next_attempt_at FROM projection_obligations WHERE group_id = ?1",
            [group],
            |r| r.get(0),
        )?)
    })
    .unwrap()
}

/// The reported scenario at its lowest level: link as a folder, pause,
/// unlink, link the same group as a provider root. No pause may remain.
#[test]
fn a_pause_does_not_survive_unlink_and_relink_as_a_provider_root() {
    let f = fixture();
    f.links.add_link("/folders/g", "g").unwrap();
    f.pauses.pause("g", "dir").unwrap();

    assert!(f.links.remove_link("/folders/g").unwrap());
    f.links.add_link("/provider/g", "g").unwrap();
    ProviderRepository::new(f.db.clone())
        .declare_root("g", ProviderKind::MacFileProvider, "G")
        .unwrap();

    assert!(f.pauses.list("g").unwrap().is_empty(), "a provider root must start unpaused");
}

#[test]
fn unlinking_the_last_link_clears_the_groups_pauses_and_releases_its_obligations() {
    let f = fixture();
    f.links.add_link("/folders/g", "g").unwrap();
    f.pauses.pause("g", "dir").unwrap();
    f.pauses.pause("g", "other/file.txt").unwrap();
    f.db.write::<_, SyncSqliteError>(|conn| {
        crate::projection_obligations::bump_projection_obligations_for_touched_paths(
            conn,
            "g",
            &["dir/a.txt"],
            1,
        )?;
        conn.execute("UPDATE projection_obligations SET next_attempt_at = 1000000", [])?;
        Ok(())
    })
    .unwrap();

    f.links.remove_link("/folders/g").unwrap();

    assert!(f.pauses.list("g").unwrap().is_empty());
    assert_eq!(pending_obligation_backoff(&f.db, "g"), 0);
}

#[test]
fn the_pauses_of_other_groups_are_untouched_by_an_unlink() {
    let f = fixture();
    f.links.add_link("/folders/g", "g").unwrap();
    f.links.add_link("/folders/h", "h").unwrap();
    f.pauses.pause("g", "dir").unwrap();
    f.pauses.pause("h", "keep").unwrap();

    f.links.remove_link("/folders/g").unwrap();

    assert_eq!(f.pauses.list("h").unwrap(), vec!["keep".to_string()]);
}

#[test]
fn pause_and_resume_still_work_on_a_relinked_folder() {
    let f = fixture();
    f.links.add_link("/folders/g", "g").unwrap();
    f.pauses.pause("g", "dir").unwrap();
    f.links.remove_link("/folders/g").unwrap();
    f.links.add_link("/folders/g", "g").unwrap();
    assert!(f.pauses.list("g").unwrap().is_empty());

    f.pauses.pause("g", "dir").unwrap();
    assert_eq!(f.pauses.list("g").unwrap(), vec!["dir".to_string()]);
    assert!(f.pauses.resume("g", "dir").unwrap());
    assert!(f.pauses.list("g").unwrap().is_empty());
}

/// Declaring an existing folder link a provider root also ends its pauses.
#[test]
fn declaring_a_provider_root_on_a_paused_group_clears_the_pauses() {
    let f = fixture();
    f.links.add_link("/folders/g", "g").unwrap();
    f.pauses.pause("g", "dir").unwrap();
    f.pauses.pause("h", "keep").unwrap();

    ProviderRepository::new(f.db.clone())
        .declare_root("g", ProviderKind::MacFileProvider, "G")
        .unwrap();

    assert!(f.pauses.list("g").unwrap().is_empty());
    assert_eq!(f.pauses.list("h").unwrap(), vec!["keep".to_string()]);
}

/// The unlink and the pause clear are one transaction: when the removal
/// cannot complete, the link row and the pauses are all still there.
#[test]
fn a_failed_unlink_leaves_the_pauses_in_place() {
    let f = fixture();
    f.links.add_link("/provider/g", "g").unwrap();
    ProviderRepository::new(f.db.clone())
        .declare_root("g", ProviderKind::MacFileProvider, "G")
        .unwrap();
    // Pause rows cannot be made through the repository for a provider group
    // by design of the clear; write one directly to model prior state.
    f.db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO paused_items (group_id, path, paused_at_unix_nanos) VALUES ('g','dir',1)",
            [],
        )?;
        conn.execute_batch(
            "CREATE TRIGGER fail_removal BEFORE INSERT ON provider_removals \
             BEGIN SELECT RAISE(ABORT, 'injected'); END;",
        )?;
        Ok(())
    })
    .unwrap();

    assert!(f.links.remove_link("/provider/g").is_err());

    assert_eq!(f.pauses.list("g").unwrap(), vec!["dir".to_string()]);
    assert_eq!(f.links.list_links().unwrap().len(), 1);
}
