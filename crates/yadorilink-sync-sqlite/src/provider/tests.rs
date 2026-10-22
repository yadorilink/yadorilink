#![cfg(test)]

use super::*;

const GROUP: &str = "g";

fn open_db() -> Arc<SyncDatabase> {
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

fn put(db: &SyncDatabase, path: &str) {
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted) \
             VALUES (?1, ?2, 0, 0, '[]', 0)",
            rusqlite::params![GROUP, path],
        )?;
        Ok(())
    })
    .unwrap();
}

fn tombstone(db: &SyncDatabase, path: &str) {
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "UPDATE files SET deleted = 1 WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![GROUP, path],
        )?;
        Ok(())
    })
    .unwrap();
}

fn remove_row(db: &SyncDatabase, path: &str) {
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "DELETE FROM files WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![GROUP, path],
        )?;
        Ok(())
    })
    .unwrap();
}

fn add_link(db: &SyncDatabase) {
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute("INSERT INTO links (local_path, group_id) VALUES ('/p', ?1)", [GROUP])?;
        Ok(())
    })
    .unwrap();
}

fn declared() -> (Arc<SyncDatabase>, ProviderRepository, String) {
    let db = open_db();
    add_link(&db);
    let repo = ProviderRepository::new(db.clone());
    let root = repo.declare_root(GROUP, ProviderKind::MacFileProvider, "Photos").unwrap();
    (db, repo, root)
}

fn root(repo: &ProviderRepository) -> ProviderRoot {
    match repo.declaration_for_group(GROUP).unwrap() {
        ProviderDeclaration::Provider(root) => root,
        other => panic!("not a provider root: {other:?}"),
    }
}

/// A link that declares no provider is plain, and a root is declared ON a link.
#[test]
fn a_link_that_declares_nothing_is_plain() {
    let db = open_db();
    add_link(&db);
    let repo = ProviderRepository::new(db);
    assert_eq!(repo.declaration_for_group(GROUP).unwrap(), ProviderDeclaration::Plain);
    assert!(repo.require_plain(GROUP).is_ok());
    assert!(repo.declare_root(GROUP, ProviderKind::None, "x").is_err());
    assert!(repo.declare_root(GROUP, ProviderKind::MacFileProvider, "  ").is_err());
    assert!(repo.declare_root("unlinked", ProviderKind::MacFileProvider, "x").is_err());
}

/// The declaration (kind and root id) lives on the link: it is the single source of truth.
/// Provider state lost while the link is kept is corrupt, never a plain directory.
#[test]
fn provider_state_lost_under_a_declaring_link_is_corrupt_not_plain() {
    let (db, repo, root_id) = declared();
    assert!(matches!(repo.declaration_for_group(GROUP).unwrap(), ProviderDeclaration::Provider(_)));
    assert!(repo.require_plain(GROUP).is_err());

    // A restore loses the provider rows but keeps the link.
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute("DELETE FROM provider_roots WHERE root_id = ?1", [&root_id])?;
        Ok(())
    })
    .unwrap();
    assert!(
        matches!(repo.declaration_for_group(GROUP).unwrap(), ProviderDeclaration::Corrupt(_)),
        "a link declaring a provider with no provider state was read as plain"
    );
    let error = repo.require_plain(GROUP).unwrap_err().to_string();
    assert!(error.contains("rebootstrap required"), "{error}");

    // A link naming a root that is not there is the same.
    let (db, repo, _root) = declared();
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute("UPDATE links SET provider_root_id = 'other'", [])?;
        Ok(())
    })
    .unwrap();
    assert!(matches!(repo.declaration_for_group(GROUP).unwrap(), ProviderDeclaration::Corrupt(_)));
}

/// Readiness is evidence, in order: domain registered, an extension handshake since, and no
/// explicit error.
#[test]
fn readiness_follows_registration_handshake_and_error() {
    let (_db, repo, root_id) = declared();
    let readiness = || root(&repo).readiness();
    assert_eq!(readiness(), Readiness::NotReady(NotReady::DomainNotRegistered));
    repo.set_domain_registered(&root_id, true).unwrap();
    assert_eq!(readiness(), Readiness::NotReady(NotReady::ExtensionNotEnabled));
    repo.record_extension_handshake(&root_id, 10).unwrap();
    assert_eq!(readiness(), Readiness::Ready);
    repo.record_provider_error(&root_id, "domain invalid").unwrap();
    assert_eq!(readiness(), Readiness::NotReady(NotReady::ProviderError("domain invalid".into())));
    // A relaunched extension is fresh evidence.
    repo.record_extension_handshake(&root_id, 20).unwrap();
    assert_eq!(readiness(), Readiness::Ready);
    assert_eq!(root(&repo).first_handshake_at, Some(10));
}

/// Once ready, nothing the extension does NOT do changes readiness: there is no timer, no
/// heartbeat and no per-launch expiry, only removal or an explicit error. A restart keeps it.
#[test]
fn silence_never_reverts_a_ready_root_and_readiness_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("index.sqlite3");
    let open = || {
        Arc::new(
            SyncDatabase::open(&path, |conn| {
                crate::replica_tables::init_for_tests(conn).map_err(|e| {
                    yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
                })?;
                yadorilink_sqlite_runtime::init_schema(conn)
            })
            .unwrap(),
        )
    };
    let root_id = {
        let db = open();
        add_link(&db);
        let repo = ProviderRepository::new(db);
        let root_id = repo.declare_root(GROUP, ProviderKind::MacFileProvider, "Photos").unwrap();
        repo.set_domain_registered(&root_id, true).unwrap();
        repo.record_extension_handshake(&root_id, 1).unwrap();
        root_id
    };
    // A restart, with no handshake since.
    let repo = ProviderRepository::new(open());
    let row = root(&repo);
    assert_eq!(row.root_id, root_id);
    assert_eq!(row.readiness(), Readiness::Ready, "a restart unlearned the handshake");
}

/// A removal rebootstraps the root, so a stale extension's late report for the old root_id
/// finds no root; the re-registered domain is a NEW root and needs its own handshake.
#[test]
fn a_domain_removal_replaces_the_root_and_stale_reports_are_ignored() {
    let (db, repo, old) = declared();
    put(&db, "a.txt");
    let item = repo.mint_item(&old, "a.txt").unwrap();
    repo.set_domain_registered(&old, true).unwrap();
    repo.record_extension_handshake(&old, 1).unwrap();

    assert!(repo.set_domain_registered(&old, false).unwrap());
    let new = root(&repo).root_id;
    assert_ne!(new, old);
    assert!(repo.path_for_item(&old, &item).unwrap().is_none(), "the old items survived");
    assert_eq!(root(&repo).readiness(), Readiness::NotReady(NotReady::DomainNotRegistered));
    // The link follows the new root.
    assert!(
        matches!(repo.declaration_for_group(GROUP).unwrap(), ProviderDeclaration::Provider(r) if r.root_id == new)
    );

    repo.set_domain_registered(&new, true).unwrap();
    // The old extension's delayed reports name the old root: ignored.
    assert!(!repo.record_extension_handshake(&old, 2).unwrap());
    assert!(!repo.record_provider_error(&old, "late").unwrap());
    assert!(!repo.set_domain_registered(&old, false).unwrap());
    assert_eq!(
        root(&repo).readiness(),
        Readiness::NotReady(NotReady::ExtensionNotEnabled),
        "a stale handshake marked the new domain ready"
    );
    repo.record_extension_handshake(&new, 3).unwrap();
    assert_eq!(root(&repo).readiness(), Readiness::Ready);
}

#[test]
fn a_rebootstrap_changes_root_id_and_forgets_every_item() {
    let (db, repo, root_id) = declared();
    put(&db, "a.txt");
    let item = repo.mint_item(&root_id, "a.txt").unwrap();
    let new_root = repo.rebootstrap_root(GROUP).unwrap();
    assert_ne!(new_root, root_id);
    assert!(repo.path_for_item(&root_id, &item).unwrap().is_none());
    assert_eq!(repo.item_for_path(&new_root, "a.txt").unwrap(), None);
    let minted = repo.mint_item(&new_root, "a.txt").unwrap();
    assert_ne!(minted, item, "a rebootstrap reused an item id");
    let row = root(&repo);
    assert_eq!(row.root_id, new_root);
    assert_eq!(row.readiness(), Readiness::NotReady(NotReady::DomainNotRegistered));
}

#[test]
fn registration_waits_for_the_namespace() {
    let (_db, repo, root_id) = declared();
    let ready = || root(&repo).namespace_ready;
    assert!(!ready());
    repo.set_namespace_ready(&root_id, true).unwrap();
    assert!(ready());
}

/// An item id is minted once per live path and names the same item afterwards.
#[test]
fn an_item_keeps_its_id_and_a_reused_path_gets_a_new_one() {
    let (db, repo, root) = declared();
    put(&db, "a.txt");
    let first = repo.mint_item(&root, "a.txt").unwrap();
    assert_eq!(repo.mint_item(&root, "a.txt").unwrap(), first);
    tombstone(&db, "a.txt");
    assert_eq!(repo.path_for_item(&root, &first).unwrap(), Some(("a.txt".into(), false)));
    assert_eq!(repo.item_for_path(&root, "a.txt").unwrap(), None);
    // The path is created again: a new item.
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "UPDATE files SET deleted = 0 WHERE group_id = ?1 AND path = 'a.txt'",
            [GROUP],
        )?;
        Ok(())
    })
    .unwrap();
    let second = repo.mint_item(&root, "a.txt").unwrap();
    assert_ne!(second, first);
}

/// The parent index follows delete and update in the same transaction as the
/// semantic row, by trigger.
#[test]
fn the_parent_index_follows_deletes_in_the_same_transaction() {
    let (db, repo, root) = declared();
    put(&db, "dir/a.txt");
    put(&db, "dir/b.txt");
    put(&db, "dir2/c.txt");
    for path in ["dir/a.txt", "dir/b.txt", "dir2/c.txt"] {
        repo.mint_item(&root, path).unwrap();
    }
    let names = |parent: &str| -> Vec<String> {
        repo.list_children(&root, parent).unwrap().into_iter().map(|(n, _)| n).collect()
    };
    assert_eq!(names("dir"), ["a.txt", "b.txt"]);
    assert_eq!(names("dir2"), ["c.txt"], "a prefix sibling must not be under dir");
    tombstone(&db, "dir/a.txt");
    assert_eq!(names("dir"), ["b.txt"]);
    remove_row(&db, "dir/b.txt");
    assert_eq!(names("dir"), Vec::<String>::new());
    assert_eq!(names("dir2"), ["c.txt"]);
}

/// A directory that loses its own row but keeps live descendants stays an item.
#[test]
fn a_directory_with_live_descendants_stays_live_when_its_own_row_goes() {
    let (db, repo, root) = declared();
    put(&db, "dir");
    put(&db, "dir/a.txt");
    let dir = repo.mint_item(&root, "dir").unwrap();
    tombstone(&db, "dir");
    assert_eq!(repo.item_for_path(&root, "dir").unwrap(), Some(dir));
    tombstone(&db, "dir/a.txt");
    assert_eq!(repo.item_for_path(&root, "dir").unwrap(), None);
}

/// A rename keeps every item id (the directory's and its descendants') and
/// rewrites the parent index in the caller's transaction.
#[test]
fn a_tree_rename_keeps_item_ids_and_moves_the_parent_index() {
    let (db, repo, root) = declared();
    put(&db, "old");
    put(&db, "old/a.txt");
    put(&db, "old/sub/b.txt");
    put(&db, "older/c.txt");
    let ids: Vec<ItemId> = ["old", "old/a.txt", "old/sub/b.txt", "older/c.txt"]
        .iter()
        .map(|p| repo.mint_item(&root, p).unwrap())
        .collect();

    db.write_immediate::<_, SyncSqliteError>(|tx| rename_tree_in_tx(tx, GROUP, "old", "new"))
        .unwrap();

    assert_eq!(repo.item_for_path(&root, "new").unwrap(), Some(ids[0]));
    assert_eq!(repo.item_for_path(&root, "new/a.txt").unwrap(), Some(ids[1]));
    assert_eq!(repo.item_for_path(&root, "new/sub/b.txt").unwrap(), Some(ids[2]));
    assert_eq!(repo.item_for_path(&root, "old").unwrap(), None);
    assert_eq!(repo.item_for_path(&root, "older/c.txt").unwrap(), Some(ids[3]), "sibling prefix");
    let children = repo.list_children(&root, "new").unwrap();
    assert!(children.iter().any(|(n, id)| n == "a.txt" && *id == ids[1]));
    assert!(repo.list_children(&root, "old").unwrap().is_empty());
}

/// A remote rename that names no source is a delete of the old path and a create
/// at the new one: the new path mints a NEW item id.
#[test]
fn a_rename_without_proof_retires_the_old_item_and_mints_a_new_one() {
    let (db, repo, root) = declared();
    put(&db, "a.txt");
    let old = repo.mint_item(&root, "a.txt").unwrap();
    tombstone(&db, "a.txt");
    put(&db, "b.txt");
    let new = repo.mint_item(&root, "b.txt").unwrap();
    assert_ne!(new, old);
    assert_eq!(repo.path_for_item(&root, &old).unwrap(), Some(("a.txt".into(), false)));
}

fn replace_version(db: &SyncDatabase, path: &str, next_seq: i64) {
    // The shape of every ordinary version replacement: the current row is first set
    // superseded, and only then is the new current row inserted, in ONE transaction.
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        tx.execute(
            "UPDATE files SET state = 'superseded' WHERE group_id = ?1 AND path = ?2 \
             AND state = 'current'",
            rusqlite::params![GROUP, path],
        )?;
        tx.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
             version_seq, state) VALUES (?1, ?2, 1, 1, '[]', 0, ?3, 'current')",
            rusqlite::params![GROUP, path, next_seq],
        )?;
        Ok(())
    })
    .unwrap();
}

/// Editing a file replaces its version; the item keeps its id. (The per-row trigger of the
/// first cut retired the item between the supersede and the insert.)
#[test]
fn a_version_replacement_keeps_the_item_id() {
    let (db, repo, root) = declared();
    put(&db, "a.txt");
    let id = repo.mint_item(&root, "a.txt").unwrap();
    replace_version(&db, "a.txt", 2);
    replace_version(&db, "a.txt", 3);
    assert_eq!(repo.item_for_path(&root, "a.txt").unwrap(), Some(id), "an edit retired the item");
    assert_eq!(repo.list_children(&root, "").unwrap(), [("a.txt".to_string(), id)]);
}

/// A delete retires the item even though the same statements also supersede the old row,
/// and a recreated path is a NEW item; deleting and recreating in ONE transaction is a
/// replacement and keeps the id.
#[test]
fn delete_and_revival_follow_the_final_state() {
    let (db, repo, root) = declared();
    put(&db, "a.txt");
    let first = repo.mint_item(&root, "a.txt").unwrap();

    // Delete: supersede the live row, insert a tombstone.
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        tx.execute(
            "UPDATE files SET state = 'superseded' WHERE group_id = ?1 AND path = 'a.txt'",
            [GROUP],
        )?;
        tx.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
             version_seq, state) VALUES (?1, 'a.txt', 0, 2, '[]', 1, 2, 'current')",
            [GROUP],
        )?;
        Ok(())
    })
    .unwrap();
    assert_eq!(repo.item_for_path(&root, "a.txt").unwrap(), None);
    assert_eq!(repo.path_for_item(&root, &first).unwrap(), Some(("a.txt".into(), false)));

    // Created again later: a new item.
    replace_version(&db, "a.txt", 3);
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "UPDATE files SET deleted = 0 WHERE group_id = ?1 AND path = 'a.txt' \
             AND state = 'current'",
            [GROUP],
        )?;
        Ok(())
    })
    .unwrap();
    let second = repo.mint_item(&root, "a.txt").unwrap();
    assert_ne!(second, first);
    // Delete and recreate inside ONE transaction keeps the item id (the path is the identity the
    // user named); the projector advances the item's generation on such a replacement, so every
    // token taken before it is stale (`a_replaced_file_rejects_the_predecessors_token`).
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        tx.execute(
            "UPDATE files SET deleted = 1 WHERE group_id = ?1 AND path = 'a.txt' \
             AND state = 'current'",
            [GROUP],
        )?;
        tx.execute(
            "UPDATE files SET deleted = 0 WHERE group_id = ?1 AND path = 'a.txt' \
             AND state = 'current'",
            [GROUP],
        )?;
        Ok(())
    })
    .unwrap();
    assert_eq!(repo.item_for_path(&root, "a.txt").unwrap(), Some(second));
}

/// A row whose path changes (a held row moved to a copy name) re-evaluates BOTH paths.
#[test]
fn moving_a_row_re_evaluates_the_old_and_the_new_path() {
    let (db, repo, root) = declared();
    put(&db, "held.txt");
    let id = repo.mint_item(&root, "held.txt").unwrap();
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        tx.execute(
            "UPDATE files SET path = 'held (copy).txt' WHERE group_id = ?1 AND path = 'held.txt'",
            [GROUP],
        )?;
        Ok(())
    })
    .unwrap();
    assert_eq!(repo.item_for_path(&root, "held.txt").unwrap(), None, "the old path stayed live");
    assert_eq!(repo.path_for_item(&root, &id).unwrap(), Some(("held.txt".into(), false)));
}

// ---- publication (the fence is derived: published version != current version) ----

fn set_row(db: &SyncDatabase, path: &str, seq: i64, size: i64, mtime: i64) {
    // One block per non-empty file, its hash derived from the size, so equal sizes are
    // equal content and different sizes are different content.
    let blocks = if size == 0 {
        "[]".to_string()
    } else {
        format!(r#"[{{"hash":{:?},"offset":0,"size":{size}}}]"#, vec![size as u8; 32])
    };
    // A version replacement: supersede the current row, insert the new one, one transaction.
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        tx.execute(
            "UPDATE files SET state = 'superseded' WHERE group_id = ?1 AND path = ?2 \
             AND state = 'current'",
            rusqlite::params![GROUP, path],
        )?;
        tx.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
             version_seq, state) VALUES (?1, ?2, ?3, ?4, ?6, 0, ?5, 'current')",
            rusqlite::params![GROUP, path, size, mtime, seq, blocks],
        )?;
        // Every committed version is kept in the immutable version store.
        let version = current_version(tx, GROUP, path)?.expect("a live row");
        crate::dag_store::put_file_version(tx, GROUP, &version)?;
        Ok(())
    })
    .unwrap();
}

/// Tells the OS the item's current version (as a first enumeration or a signal ack does) and
/// keeps that version in the immutable version store, as every committed version is.
fn publish_current(
    db: &SyncDatabase,
    repo: &ProviderRepository,
    root: &str,
    id: &ItemId,
    path: &str,
) {
    db.write::<_, SyncSqliteError>(|conn| {
        let version = current_version(conn, GROUP, path)?.expect("a live row");
        crate::dag_store::put_file_version(conn, GROUP, &version)?;
        Ok(())
    })
    .unwrap();
    let current = repo.current_version_hash(root, id).unwrap().unwrap();
    assert!(repo.publish_for_tests(root, id, current).unwrap());
}

fn pending(repo: &ProviderRepository, root: &str) -> Vec<(String, Publication)> {
    repo.pending_items(root).unwrap().into_iter().map(|i| (i.path, i.publication)).collect()
}

#[test]
fn a_content_change_is_pending_and_a_metadata_only_change_is_not() {
    let (db, repo, root) = declared();
    set_row(&db, "a.txt", 1, 10, 100);
    set_row(&db, "b.txt", 1, 20, 100);
    let a = repo.mint_item(&root, "a.txt").unwrap();
    let b = repo.mint_item(&root, "b.txt").unwrap();
    assert_eq!(repo.publication(&root, &a).unwrap(), Some(Publication::Unpublished));
    publish_current(&db, &repo, &root, &a, "a.txt");
    publish_current(&db, &repo, &root, &b, "b.txt");
    assert!(pending(&repo, &root).is_empty());

    set_row(&db, "a.txt", 2, 99, 100); // content (size) changed
    set_row(&db, "b.txt", 2, 20, 555); // mtime only

    assert_eq!(repo.publication(&root, &a).unwrap(), Some(Publication::ContentPending));
    assert_eq!(repo.publication(&root, &b).unwrap(), Some(Publication::MetadataOnly));
    assert_eq!(
        pending(&repo, &root),
        [
            ("a.txt".to_string(), Publication::ContentPending),
            ("b.txt".to_string(), Publication::MetadataOnly)
        ]
    );
}

/// While the fence is on the OS is shown the PUBLISHED version, content and metadata exactly
/// as it last saw them; V2's size and mtime are never observable.
#[test]
fn the_served_view_is_the_published_version_until_it_is_published() {
    let (db, repo, root) = declared();
    set_row(&db, "a.txt", 1, 10, 100);
    let id = repo.mint_item(&root, "a.txt").unwrap();
    // Never published: served at its current version.
    let first = repo.served_view(&root, &id).unwrap().unwrap();
    assert!(!first.published);
    publish_current(&db, &repo, &root, &id, "a.txt");

    set_row(&db, "a.txt", 2, 99, 777);
    let view = repo.served_view(&root, &id).unwrap().unwrap();
    assert!(view.published);
    assert_eq!((view.version.size, view.version.meta.mtime_unix_nanos), (10, 100));

    // Publication (the signal's ack for exactly that version) moves the view to it.
    let current = repo.current_version_hash(&root, &id).unwrap().unwrap();
    assert!(repo.publish_for_tests(&root, &id, current).unwrap());
    let view = repo.served_view(&root, &id).unwrap().unwrap();
    assert_eq!((view.version.size, view.version.meta.mtime_unix_nanos), (99, 777));
    assert_eq!(repo.publication(&root, &id).unwrap(), Some(Publication::Published));
}

/// V2 then V3 before the ack: the ack publishes the CURRENT version (V3); V2 is never
/// published, and a content change that reverts to the published content is not pending.
#[test]
fn versions_collapse_to_the_latest_and_a_revert_is_not_pending() {
    let (db, repo, root) = declared();
    set_row(&db, "a.txt", 1, 10, 100);
    let id = repo.mint_item(&root, "a.txt").unwrap();
    publish_current(&db, &repo, &root, &id, "a.txt");
    let v1 = repo.served_view(&root, &id).unwrap().unwrap().version.version_hash;

    set_row(&db, "a.txt", 2, 20, 100); // V2
    let v2 = repo.current_version_hash(&root, &id).unwrap().unwrap();
    set_row(&db, "a.txt", 3, 30, 100); // V3, before anything was published
                                       // An acknowledgement for V2 does not publish the newer V3.
    assert!(!repo.publish_for_tests(&root, &id, v2).unwrap(), "an ack for V2 published V3's fence");
    assert_eq!(repo.publication(&root, &id).unwrap(), Some(Publication::ContentPending));
    let v3 = repo.current_version_hash(&root, &id).unwrap().unwrap();
    assert!(repo.publish_for_tests(&root, &id, v3).unwrap());
    let published = repo.served_view(&root, &id).unwrap().unwrap().version;
    assert_eq!(published.size, 30, "V2 was published");
    assert_ne!(published.version_hash, v1);
    assert_eq!(repo.publication(&root, &id).unwrap(), Some(Publication::Published));

    // Back to V1's exact content and metadata: the same version, nothing to do.
    set_row(&db, "a.txt", 4, 10, 100);
    set_row(&db, "a.txt", 5, 30, 100);
    set_row(&db, "a.txt", 6, 30, 100);
    assert_eq!(repo.publication(&root, &id).unwrap(), Some(Publication::Published));
    // Same content, different mtime: metadata only.
    set_row(&db, "a.txt", 7, 30, 4242);
    assert_eq!(repo.publication(&root, &id).unwrap(), Some(Publication::MetadataOnly));
}

/// An item that goes back to its published version (same hash, e.g. a restore that brings the
/// original content and mtime back) while another version is announced is not "published": the OS
/// was told the other one. The announcement is withdrawn and the item announced again, so the OS
/// converges on the current version whatever the mtimes say.
#[test]
fn returning_to_the_published_version_withdraws_the_stale_announcement() {
    let (db, repo, root) = declared();
    set_row(&db, "a.txt", 1, 10, 500);
    let id = repo.mint_item(&root, "a.txt").unwrap();
    publish_current(&db, &repo, &root, &id, "a.txt");
    let v1 = repo.current_version_hash(&root, &id).unwrap().unwrap();

    set_row(&db, "a.txt", 2, 20, 900);
    let v2 = repo.current_version_hash(&root, &id).unwrap().unwrap();
    assert!(repo.announce_version(&root, &id, v2, 1_000).unwrap().is_some());

    // Back to V1 exactly (older content and older mtime), before V2 was published.
    set_row(&db, "a.txt", 3, 10, 500);
    assert_eq!(repo.current_version_hash(&root, &id).unwrap().unwrap(), v1);
    assert_eq!(repo.publication(&root, &id).unwrap(), Some(Publication::ContentPending));
    assert_eq!(pending(&repo, &root), [("a.txt".to_string(), Publication::ContentPending)]);

    assert!(repo.announce_version(&root, &id, v1, 2_000).unwrap().is_some());
    assert_eq!(repo.publication(&root, &id).unwrap(), Some(Publication::Published));
    assert!(pending(&repo, &root).is_empty());
    assert_eq!(repo.pending_publications(&root, 3_000, 5).unwrap().0.count, 0);
    let view = repo.served_view(&root, &id).unwrap().unwrap();
    assert_eq!((view.version.version_hash, view.version.size), (v1, 10));
    // Nothing left to announce.
    assert!(repo.announce_version(&root, &id, v1, 3_000).unwrap().is_none());
}

/// Whether a version is newer or older is never judged by its mtime: a different version with an
/// older mtime than the published one is a pending content change like any other.
#[test]
fn a_version_with_an_older_mtime_is_published_like_any_other() {
    let (db, repo, root) = declared();
    set_row(&db, "a.txt", 1, 10, 5_000);
    let id = repo.mint_item(&root, "a.txt").unwrap();
    publish_current(&db, &repo, &root, &id, "a.txt");

    set_row(&db, "a.txt", 2, 20, 1_000); // different content, older mtime
    assert_eq!(repo.publication(&root, &id).unwrap(), Some(Publication::ContentPending));
    let v2 = repo.current_version_hash(&root, &id).unwrap().unwrap();
    assert!(repo.announce_version(&root, &id, v2, 1_000).unwrap().is_some());
    assert!(repo.publish_for_tests(&root, &id, v2).unwrap());
    let view = repo.served_view(&root, &id).unwrap().unwrap();
    assert_eq!((view.version.size, view.version.meta.mtime_unix_nanos), (20, 1_000));
    assert_eq!(repo.publication(&root, &id).unwrap(), Some(Publication::Published));
}

/// Published state that cannot be resolved is lost evidence: an error, never "current".
#[test]
fn an_unresolvable_published_version_is_an_error_not_a_guess() {
    let (db, repo, root) = declared();
    set_row(&db, "a.txt", 1, 10, 100);
    let id = repo.mint_item(&root, "a.txt").unwrap();
    publish_current(&db, &repo, &root, &id, "a.txt");
    set_row(&db, "a.txt", 2, 20, 100);
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute("DELETE FROM file_versions", [])?;
        Ok(())
    })
    .unwrap();
    assert!(repo.publication(&root, &id).is_err());
    assert!(repo.served_view(&root, &id).is_err());
    assert!(repo.pending_items(&root).is_err());
}

/// A rename keeps the item's published version: a pending V2 stays pending under the new name.
#[test]
fn a_rename_keeps_the_item_pending() {
    let (db, repo, root) = declared();
    set_row(&db, "old.txt", 1, 10, 100);
    let id = repo.mint_item(&root, "old.txt").unwrap();
    publish_current(&db, &repo, &root, &id, "old.txt");
    set_row(&db, "old.txt", 2, 99, 100);
    assert_eq!(repo.publication(&root, &id).unwrap(), Some(Publication::ContentPending));

    db.write_immediate::<_, SyncSqliteError>(|tx| {
        rename_tree_in_tx(tx, GROUP, "old.txt", "new.txt")?;
        // The semantic rename: the rows follow the path.
        tx.execute(
            "UPDATE files SET path = 'new.txt' WHERE group_id = ?1 AND path = 'old.txt'",
            [GROUP],
        )?;
        Ok(())
    })
    .unwrap();
    assert_eq!(repo.item_for_path(&root, "new.txt").unwrap(), Some(id));
    assert_eq!(repo.publication(&root, &id).unwrap(), Some(Publication::ContentPending));
}

/// The OS deleted what it showed (V1); a newer version survives and is a NEW item.
#[test]
fn a_retired_item_is_replaced_by_a_new_id_for_the_surviving_version() {
    let (db, repo, root) = declared();
    set_row(&db, "a.txt", 1, 10, 100);
    let old = repo.mint_item(&root, "a.txt").unwrap();
    publish_current(&db, &repo, &root, &old, "a.txt");
    set_row(&db, "a.txt", 2, 99, 100);

    assert!(repo.retire_item(&root, &old).unwrap());
    assert_eq!(repo.path_for_item(&root, &old).unwrap(), Some(("a.txt".into(), false)));
    let new = repo.mint_item(&root, "a.txt").unwrap();
    assert_ne!(new, old);
    assert_eq!(repo.publication(&root, &new).unwrap(), Some(Publication::Unpublished));
}

#[test]
fn the_published_bound_is_what_the_os_saw() {
    let (db, repo, root) = declared();
    set_row(&db, "d/a.txt", 1, 10, 100);
    set_row(&db, "d/b.txt", 1, 20, 100);
    set_row(&db, "dd/c.txt", 1, 30, 100);
    let a = repo.mint_item(&root, "d/a.txt").unwrap();
    repo.mint_item(&root, "d/b.txt").unwrap(); // never published
    let c = repo.mint_item(&root, "dd/c.txt").unwrap();
    publish_current(&db, &repo, &root, &a, "d/a.txt");
    publish_current(&db, &repo, &root, &c, "dd/c.txt");
    set_row(&db, "d/a.txt", 2, 99, 100);

    let bound = repo.published_bound(&root, "d").unwrap();
    assert_eq!(bound.len(), 1, "an unpublished item or a prefix sibling was bound");
    let v1 = repo.served_view(&root, &a).unwrap().unwrap().version.version_hash;
    assert_eq!(bound.get("d/a.txt"), Some(&v1));
}

#[test]
fn the_namespace_revision_advances_only_with_logged_events() {
    let (db, repo, root) = declared();
    assert_eq!(repo.namespace_revision(&root).unwrap(), Some(0));
    let advance = |to: i64| {
        db.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "UPDATE provider_roots SET namespace_revision = ?2 WHERE root_id = ?1",
                rusqlite::params![root, to],
            )?;
            Ok(())
        })
    };
    // No event: refused, and nothing moved.
    assert!(advance(1).is_err());
    assert_eq!(repo.namespace_revision(&root).unwrap(), Some(0));
    // An event through the one append path advances it by exactly one, durably.
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        assert_eq!(append_event(tx, &root, "upsert", &[1; 16], &[], None)?, 1);
        assert_eq!(append_event(tx, &root, "delete", &[1; 16], &[], None)?, 2);
        Ok(())
    })
    .unwrap();
    assert_eq!(repo.namespace_revision(&root).unwrap(), Some(2));
    // Skipping a number, or advancing past the last event, is refused.
    assert!(advance(4).is_err());
    assert!(advance(3).is_err());
    assert_eq!(repo.namespace_revision(&root).unwrap(), Some(2));
}

/// The one function that used to take a revision without an event is gone, and nothing outside
/// the reconcile and the event append writes the revision column.
#[test]
fn no_source_file_writes_the_revision_except_the_event_paths() {
    fn scan(dir: &std::path::Path, hits: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan(&path, hits);
            } else if path.extension().is_some_and(|e| e == "rs")
                && !path.to_string_lossy().ends_with("tests.rs")
            {
                let text = std::fs::read_to_string(&path).unwrap();
                let forbidden = concat!("bump_", "namespace_revision");
                if text.contains(forbidden) {
                    hits.push(format!("{} names {forbidden}", path.display()));
                }
                for (n, line) in text.lines().enumerate() {
                    if line.contains("SET namespace_revision") {
                        hits.push(format!("{}:{}", path.display(), n + 1));
                    }
                }
            }
        }
    }
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut hits = Vec::new();
    scan(&manifest.join("src"), &mut hits);
    scan(&manifest.join("../yadorilink-sqlite-runtime/src"), &mut hits);
    scan(&manifest.join("../yadorilink-daemon/src"), &mut hits);
    hits.sort();
    // The reconcile's one statement (after its events), the folder child-set path's and the
    // append path's.
    assert_eq!(hits.len(), 3, "{hits:#?}");
    assert!(hits.iter().any(|h| h.contains("schema.rs")));
    assert!(hits.iter().any(|h| h.contains("provider.rs")));
}

/// The published version is read from the immutable version store, which history retention
/// (it deletes superseded `files` rows past the count and age bounds) never touches: after a
/// retention sweep over many replaced versions the OS can still be shown exactly what it
/// last saw. (No code path deletes `file_versions` rows; this keeps it that way.)
#[test]
fn retention_does_not_take_the_published_version_away() {
    let (db, repo, root) = declared();
    set_row(&db, "a.txt", 1, 10, 100);
    let id = repo.mint_item(&root, "a.txt").unwrap();
    publish_current(&db, &repo, &root, &id, "a.txt");
    let v1 = repo.served_view(&root, &id).unwrap().unwrap().version;
    for seq in 2..40 {
        set_row(&db, "a.txt", seq, 10 + seq, 100);
    }
    // Retention ages by admission: make the history old enough to expire.
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        tx.execute("UPDATE files SET admitted_at_unix_nanos = 0", [])?;
        Ok(())
    })
    .unwrap();

    let expired = crate::file_index::FileIndexRepository::new(db.clone())
        .expire_superseded_and_trashed_versions(GROUP, i64::MAX / 2, &Default::default())
        .unwrap();
    assert!(expired > 0, "the sweep removed nothing: the test did not exercise retention");

    let still = repo.served_view(&root, &id).unwrap().unwrap();
    assert_eq!(still.version, v1, "retention changed what the OS is shown");
    assert_eq!(repo.publication(&root, &id).unwrap(), Some(Publication::ContentPending));
}

// ---- declaration validation and listing ----

/// A state row borrowed from another group, or of another kind than the link declares, is
/// corrupt: the link names the root, and the row must agree with it.
#[test]
fn a_state_row_that_does_not_match_its_link_is_corrupt() {
    let (db, repo, root_id) = declared();
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "UPDATE provider_roots SET group_id = 'another-group' WHERE root_id = ?1",
            [&root_id],
        )?;
        Ok(())
    })
    .unwrap();
    assert!(matches!(repo.declaration_for_group(GROUP).unwrap(), ProviderDeclaration::Corrupt(_)));

    let (db, repo, root_id) = declared();
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute("UPDATE links SET provider_kind = 'mac_file_provider'", [])?;
        conn.execute("UPDATE provider_roots SET kind = 'none' WHERE root_id = ?1", [&root_id])?;
        Ok(())
    })
    .unwrap();
    assert!(matches!(repo.declaration_for_group(GROUP).unwrap(), ProviderDeclaration::Corrupt(_)));
}

/// The listing validates EVERY live provider declaration: one that lost its state makes the
/// whole listing an error (an unavailable snapshot), it does not quietly drop out of it.
#[test]
fn a_corrupt_declaration_makes_the_listing_unavailable() {
    let (db, repo, root_id) = declared();
    assert_eq!(repo.list_declared_roots().unwrap().len(), 1);
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute("DELETE FROM provider_roots WHERE root_id = ?1", [&root_id])?;
        Ok(())
    })
    .unwrap();
    assert!(
        repo.list_declared_roots().is_err(),
        "a root that lost its state vanished from the listing"
    );

    // A state row of another group is the same.
    let (db, repo, root_id) = declared();
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute("UPDATE provider_roots SET group_id = 'x' WHERE root_id = ?1", [&root_id])?;
        Ok(())
    })
    .unwrap();
    assert!(repo.list_declared_roots().is_err());
}

/// A connection-level (autocommit) write only RECORDS the changed paths, in the same statement
/// that changes the rows; it is never followed by work that can fail after it committed. Every
/// read of the item index settles first, so it never answers from a liveness that lags the rows:
/// the item is gone the moment the delete is visible.
#[test]
fn a_connection_level_delete_is_never_seen_with_a_still_live_item() {
    let (db, repo, root_id) = declared();
    put(&db, "a.txt");
    repo.mint_item(&root_id, "a.txt").unwrap();

    remove_row(&db, "a.txt"); // an autocommit write, no transaction of its own
                              // The very next read, with no other write in between.
    assert_eq!(repo.item_for_path(&root_id, "a.txt").unwrap(), None);
    assert!(repo.list_children(&root_id, "").unwrap().is_empty());
}

/// A reconcile that cannot run neither turns a committed write into an error nor leaves the
/// liveness half done: the write succeeds, the changed paths stay recorded, and the next read
/// settles them once it can.
#[test]
fn a_failing_reconcile_does_not_fail_or_half_apply_a_committed_write() {
    let (db, repo, root_id) = declared();
    put(&db, "a.txt");
    let item = repo.mint_item(&root_id, "a.txt").unwrap();
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute_batch(
            "CREATE TRIGGER sabotage BEFORE UPDATE ON provider_items \
             BEGIN SELECT RAISE(ABORT, 'reconcile sabotaged'); END;",
        )?;
        Ok(())
    })
    .unwrap();

    remove_row(&db, "a.txt"); // the write itself succeeds
    assert!(repo.item_for_path(&root_id, "a.txt").is_err(), "the sabotaged settle must fail");
    let dirty: i64 = db
        .read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row("SELECT COUNT(*) FROM provider_dirty_paths", [], |r| r.get(0))?)
        })
        .unwrap();
    assert!(dirty > 0, "the changed paths were forgotten");

    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute_batch("DROP TRIGGER sabotage;")?;
        Ok(())
    })
    .unwrap();
    assert_eq!(repo.item_for_path(&root_id, "a.txt").unwrap(), None);
    assert_eq!(repo.path_for_item(&root_id, &item).unwrap(), Some(("a.txt".into(), false)));
}

/// A deletion that commits BETWEEN a provider read's settle and its snapshot never yields a live
/// item for a deleted file: the read notices the new dirty path and settles again.
#[test]
fn a_deletion_between_the_settle_and_the_read_is_never_a_live_item() {
    let (db, repo, root) = declared();
    put(&db, "a.txt");
    let id = repo.mint_item(&root, "a.txt").unwrap();
    assert_eq!(repo.path_for_item(&root, &id).unwrap().unwrap().0, "a.txt");

    let db_for_hook = db.clone();
    AFTER_SETTLE.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || tombstone(&db_for_hook, "a.txt")));
    });
    let (_, live) = repo.path_for_item(&root, &id).unwrap().unwrap();
    assert!(!live, "a deleted file was served as a live item");
    assert_eq!(repo.item_for_path(&root, "a.txt").unwrap(), None);
}

/// The first publication records the version the OS was SERVED, and only if it is still current:
/// a version committed between serving and recording is never marked published.
#[test]
fn a_first_publication_binds_the_served_version() {
    let (db, repo, root) = declared();
    set_row(&db, "a.txt", 1, 10, 100);
    let id = repo.mint_item(&root, "a.txt").unwrap();
    let served = repo.current_version_hash(&root, &id).unwrap().unwrap();

    // V2 lands after the OS was served V1 and before the publication was recorded.
    set_row(&db, "a.txt", 2, 20, 100);
    assert!(
        !repo.publish_first(&root, &id, served).unwrap(),
        "a stale served version was recorded"
    );
    assert_eq!(repo.publication(&root, &id).unwrap(), Some(Publication::Unpublished));

    // Served again at the current version, it is recorded; a second record changes nothing.
    let current = repo.current_version_hash(&root, &id).unwrap().unwrap();
    assert!(repo.publish_first(&root, &id, current).unwrap());
    assert!(!repo.publish_first(&root, &id, current).unwrap());
}

/// A retired item keeps no published version: nothing can ever need to resolve it again, so a
/// missing version of a retired item cannot go unnoticed by recovery.
#[test]
fn retiring_an_item_drops_its_published_version() {
    let (db, repo, root) = declared();
    set_row(&db, "gone.txt", 1, 10, 100);
    let id = repo.mint_item(&root, "gone.txt").unwrap();
    publish_current(&db, &repo, &root, &id, "gone.txt");
    let published = |conn: &rusqlite::Connection| -> Option<Vec<u8>> {
        conn.query_row(
            "SELECT published_version_hash FROM provider_items WHERE root_id = ?1",
            [&root],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert!(db.read::<_, SyncSqliteError>(|conn| Ok(published(conn))).unwrap().is_some());

    tombstone(&db, "gone.txt");
    assert!(repo.path_for_item(&root, &id).unwrap().is_some_and(|(_, live)| !live));
    assert_eq!(
        db.read::<_, SyncSqliteError>(|conn| Ok(published(conn))).unwrap(),
        None,
        "a retired item still names a published version"
    );
}

/// A fetch failure is charged to the version that was attempted, and only while that version is
/// still current: a version replaced meanwhile never inherits the failure.
#[test]
fn a_failure_of_a_replaced_version_is_not_charged_to_the_current_one() {
    let (db, repo, root) = declared();
    set_row(&db, "a.txt", 1, 10, 100);
    let id = repo.mint_item(&root, "a.txt").unwrap();
    let v1 = repo.current_version_hash(&root, &id).unwrap().unwrap();
    set_row(&db, "a.txt", 2, 20, 100);
    let v2 = repo.current_version_hash(&root, &id).unwrap().unwrap();
    assert_ne!(v1, v2);

    assert!(repo.record_download_failure(&root, &id, v1, 0, |_| 1000).unwrap().is_none());
    assert!(repo.download_failure(&root, &id).unwrap().is_none(), "v2 was charged for v1");
    let recorded = repo.record_download_failure(&root, &id, v2, 0, |_| 1000).unwrap().unwrap();
    assert_eq!((recorded.version_hash, recorded.failures), (v2, 1));
}

/// A retired item keeps no failure row, whether the OS deleted it or its file went away.
#[test]
fn retiring_an_item_deletes_its_download_failures() {
    let (db, repo, root) = declared();
    set_row(&db, "gone.txt", 1, 10, 100);
    set_row(&db, "deleted.txt", 1, 10, 100);
    let (gone, deleted) =
        (repo.mint_item(&root, "gone.txt").unwrap(), repo.mint_item(&root, "deleted.txt").unwrap());
    for item in [&gone, &deleted] {
        let version = repo.current_version_hash(&root, item).unwrap().unwrap();
        repo.record_download_failure(&root, item, version, 0, |_| 1000).unwrap().unwrap();
    }

    assert!(repo.retire_item(&root, &gone).unwrap());
    assert!(repo.download_failure(&root, &gone).unwrap().is_none());
    // A write transaction reconciles liveness before it commits, so the row goes with the item
    // in that same transaction.
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        tx.execute(
            "UPDATE files SET deleted = 1 WHERE group_id = ?1 AND path = 'deleted.txt'",
            [GROUP],
        )?;
        Ok(())
    })
    .unwrap();
    assert!(
        repo.download_failure(&root, &deleted).unwrap().is_none(),
        "a failure row outlived its item"
    );
}

// ---- the namespace layer: structural directories, the change log ----

type EventRow = (i64, String, Vec<u8>, Vec<u8>, Option<Vec<u8>>);

fn events(db: &SyncDatabase, root: &str) -> Vec<EventRow> {
    db.read::<_, SyncSqliteError>(|conn| {
        let mut stmt = conn.prepare(
            "SELECT seq, kind, item_id, parent_item_id, old_parent_item_id \
             FROM provider_change_events WHERE root_id = ?1 ORDER BY seq",
        )?;
        let rows = stmt
            .query_map([root], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?
            .collect::<Result<_, _>>()?;
        Ok(rows)
    })
    .unwrap()
}

fn dirs(db: &SyncDatabase) -> Vec<String> {
    db.read::<_, SyncSqliteError>(|conn| {
        let mut stmt = conn.prepare("SELECT path FROM provider_dirs ORDER BY path")?;
        let rows = stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
        Ok(rows)
    })
    .unwrap()
}

/// A transactional tombstone: the commit-time reconcile runs, as for every real write.
fn tombstone_tx(db: &SyncDatabase, path: &str) {
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        tx.execute(
            "UPDATE files SET deleted = 1 WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![GROUP, path],
        )?;
        Ok(())
    })
    .unwrap();
}

fn enumerate(db: &SyncDatabase, root: &str, parent: &[u8]) {
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT OR IGNORE INTO provider_enumerated_parents (root_id, parent_item_id) \
             VALUES (?1, ?2)",
            rusqlite::params![root, parent],
        )?;
        Ok(())
    })
    .unwrap();
}

fn revision(repo: &ProviderRepository, root: &str) -> u64 {
    repo.namespace_revision(root).unwrap().unwrap()
}

/// Structural directories exist at every depth and follow the last live descendant, in the same
/// transaction as the row change; scaffold rows (`version_seq = 0`) are not a namespace.
#[test]
fn structural_directories_of_any_depth_follow_their_descendants() {
    let (db, _repo, _root) = declared();
    set_row(&db, "a/b/c/f", 1, 10, 100);
    assert_eq!(dirs(&db), ["a", "a/b", "a/b/c"]);
    set_row(&db, "a/b/c/g", 1, 10, 100);
    tombstone_tx(&db, "a/b/c/f");
    assert_eq!(dirs(&db), ["a", "a/b", "a/b/c"], "a directory with a live descendant went");
    tombstone_tx(&db, "a/b/c/g");
    assert_eq!(dirs(&db), Vec::<String>::new());

    db.write_immediate::<_, SyncSqliteError>(|tx| {
        // A scaffold row: no version_seq.
        tx.execute(
            "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
             version_seq, state) VALUES (?1, 's/t/u', 0, 0, '[]', 0, 0, 'current')",
            [GROUP],
        )?;
        Ok(())
    })
    .unwrap();
    assert_eq!(dirs(&db), Vec::<String>::new(), "a scaffold row made a directory");
}

/// A namespace nobody has opened writes no change event and does not move the revision: the
/// 100k build pays no log cost.
#[test]
fn importing_a_namespace_writes_no_events() {
    let (db, repo, root) = declared();
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        for n in 0..500 {
            tx.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
                 version_seq, state) VALUES (?1, ?2, 1, 1, '[]', 0, 1, 'current')",
                rusqlite::params![GROUP, format!("d{}/f{n}", n % 10)],
            )?;
        }
        Ok(())
    })
    .unwrap();
    assert!(events(&db, &root).is_empty());
    assert_eq!(revision(&repo, &root), 0);
}

/// What the OS can know is logged, in the transaction of the change, with one unique sequence
/// per event: a create under an enumerated parent mints the item and appends an upsert; a
/// delete of a published item and of an item under an enumerated parent appends a delete; a
/// create under a never-opened folder and the delete of an unexposed item append nothing.
#[test]
fn events_are_written_only_for_what_the_os_can_know() {
    let (db, repo, root) = declared();
    enumerate(&db, &root, b"");

    // Three creates in ONE transaction: three events, three distinct sequences.
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        for name in ["a", "b", "c"] {
            tx.execute(
                "INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
                 version_seq, state) VALUES (?1, ?2, 1, 1, '[]', 0, 1, 'current')",
                rusqlite::params![GROUP, name],
            )?;
        }
        Ok(())
    })
    .unwrap();
    let log = events(&db, &root);
    assert_eq!(log.iter().map(|e| e.0).collect::<Vec<_>>(), [1, 2, 3]);
    assert!(log.iter().all(|e| e.1 == "upsert" && e.3.is_empty()), "{log:?}");
    assert_eq!(revision(&repo, &root), 3);
    let a = repo.item_for_path(&root, "a").unwrap().expect("minted by the event");

    // A create below a folder nobody opened: nothing (not even an item).
    set_row(&db, "deep/er/x", 1, 10, 100);
    assert_eq!(events(&db, &root).len(), 4, "the new structural folder `deep` is under the root");
    assert!(repo.item_for_path(&root, "deep/er/x").unwrap().is_none());

    // A delete of an item under an enumerated parent is told; the parent id is the root's.
    tombstone(&db, "a");
    repo.path_for_item(&root, &a).unwrap(); // settle
    let log = events(&db, &root);
    let last = log.last().unwrap();
    assert_eq!((last.1.as_str(), last.2.as_slice()), ("delete", &a[..]));

    // A delete of an item that was never exposed and sits under an unopened folder: nothing.
    let before = events(&db, &root).len();
    set_row(&db, "deep/y", 1, 10, 100);
    let y = repo.mint_item(&root, "deep/y").unwrap();
    let _ = y;
    tombstone(&db, "deep/y");
    repo.path_for_item(&root, &y).unwrap();
    assert_eq!(events(&db, &root).len(), before, "an unexposed item's delete was logged");
}

/// A published item's delete is told even when its parent was never enumerated.
#[test]
fn the_delete_of_a_published_item_is_told_under_an_unopened_folder() {
    let (db, repo, root) = declared();
    set_row(&db, "f/g", 1, 10, 100);
    let id = repo.mint_item(&root, "f/g").unwrap();
    publish_current(&db, &repo, &root, &id, "f/g");
    tombstone(&db, "f/g");
    repo.path_for_item(&root, &id).unwrap();
    let log = events(&db, &root);
    assert_eq!(log.len(), 1, "{log:?}");
    assert_eq!(log[0].1, "delete");
}

/// A rename of an exposed item is one event with the same id: a move when the parent changed
/// (old and new parent recorded), an upsert when only the name did.
#[test]
fn a_rename_is_one_event_with_the_same_item_id() {
    let (db, repo, root) = declared();
    enumerate(&db, &root, b"");
    set_row(&db, "d/x", 1, 10, 100);
    let d = repo.mint_item(&root, "d").unwrap();
    enumerate(&db, &root, &d);
    let x = repo.mint_item(&root, "d/x").unwrap();
    publish_current(&db, &repo, &root, &x, "d/x");
    let before = events(&db, &root).len();

    // Move d/x to the root as `x2`.
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        rename_tree_in_tx(tx, GROUP, "d/x", "x2")?;
        tx.execute("UPDATE files SET path = 'x2' WHERE group_id = ?1 AND path = 'd/x'", [GROUP])?;
        Ok(())
    })
    .unwrap();
    let log = events(&db, &root);
    let moves: Vec<_> = log[before..].iter().filter(|e| e.2 == x.to_vec()).collect();
    assert_eq!(moves.len(), 1, "{log:?}");
    assert_eq!(moves[0].1, "move");
    assert_eq!(moves[0].3, Vec::<u8>::new(), "new parent is the root container");
    assert_eq!(moves[0].4.as_deref(), Some(&d[..]), "old parent is d");
}

/// The children of a folder are one keyset on the parent index (not a scan of the group).
#[test]
fn the_children_query_uses_the_parent_index() {
    let (db, _repo, _root) = declared();
    let plan: String = db
        .read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "EXPLAIN QUERY PLAN SELECT path FROM files \
                 WHERE group_id = ?1 AND state = 'current' AND deleted = 0 AND version_seq > 0 \
                 AND rtrim(rtrim(path, replace(path, '/', '')), '/') = ?2 AND path > ?3 \
                 ORDER BY path LIMIT 10",
            )?;
            let rows: Vec<String> = stmt
                .query_map(rusqlite::params![GROUP, "a", ""], |r| r.get(3))?
                .collect::<Result<_, _>>()?;
            Ok(rows.join(" | "))
        })
        .unwrap();
    assert!(plan.contains("files_parent_path"), "{plan}");
    assert!(!plan.contains("SCAN"), "{plan}");
}

/// The owner-created empty folder becomes a provider root with its install recorded; a group that
/// holds any file, one that is already a provider root, and one with no link are refused.
#[test]
fn only_an_empty_plain_group_becomes_a_provider_root() {
    let db = open_db();
    add_link(&db);
    let repo = ProviderRepository::new(db.clone());
    put(&db, "a.txt");
    assert!(repo.declare_empty_root(GROUP, ProviderKind::MacFileProvider, "P").is_err());
    assert!(matches!(repo.declaration_for_group(GROUP).unwrap(), ProviderDeclaration::Plain));
    tombstone(&db, "a.txt");
    let root = repo.declare_empty_root(GROUP, ProviderKind::MacFileProvider, "P").unwrap();
    let declared = repo.list_declared_roots().unwrap();
    assert_eq!(declared.len(), 1);
    assert_eq!(declared[0].root_id, root);
    let installed: bool = db
        .read::<_, SyncSqliteError>(|c| {
            Ok(c.query_row(
                "SELECT install_done FROM provider_roots WHERE root_id = ?1",
                [&root],
                |r| r.get(0),
            )?)
        })
        .unwrap();
    assert!(installed, "an empty namespace waited for an install");
    assert!(
        repo.declare_empty_root(GROUP, ProviderKind::MacFileProvider, "P").is_err(),
        "declared twice"
    );
    assert!(repo.declare_empty_root("nolink", ProviderKind::MacFileProvider, "P").is_err());
    assert!(repo.declare_empty_root(GROUP, ProviderKind::None, "P").is_err());
}

/// Items waiting to be published are counted with the age of the oldest and listed oldest first.
#[test]
fn waiting_publications_are_counted_and_listed_oldest_first() {
    let (db, repo, root) = declared();
    put(&db, "a.txt");
    put(&db, "b.txt");
    put(&db, "c.txt");
    let a = repo.mint_item(&root, "a.txt").unwrap();
    let b = repo.mint_item(&root, "b.txt").unwrap();
    let _c = repo.mint_item(&root, "c.txt").unwrap();
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "UPDATE provider_items SET pending_since = 1000 WHERE item_id = ?1",
            [&a[..]],
        )?;
        conn.execute(
            "UPDATE provider_items SET pending_since = 4000 WHERE item_id = ?1",
            [&b[..]],
        )?;
        Ok(())
    })
    .unwrap();
    let (summary, items) = repo.pending_publications(&root, 10_000, 5).unwrap();
    assert_eq!((summary.count, summary.oldest_age_ms), (2, 9_000));
    assert_eq!(items, [("a.txt".to_owned(), 9_000), ("b.txt".to_owned(), 6_000)]);
    assert_eq!(repo.pending_publications(&root, 10_000, 1).unwrap().1.len(), 1);
    assert!(repo.pending_publications(&root, 10_000, 0).unwrap().1.is_empty());
}

/// Prefetch candidates are the not-yet-enumerated folders, shallow first, bounded by depth, resumable
/// by cursor.
#[test]
fn prefetch_candidates_are_breadth_first_unenumerated_and_bounded() {
    let (db, repo, root) = declared();
    for path in ["a/x/f", "a/y/f", "b/f", "c/d/e/f"] {
        put(&db, path);
    }
    let all = repo.prefetch_candidates(&root, 3, 100, None, 50).unwrap();
    let names: Vec<_> = all.iter().map(|(d, p, _)| (*d, p.as_str())).collect();
    assert_eq!(
        names,
        [(1, "a"), (1, "b"), (1, "c"), (2, "a/x"), (2, "a/y"), (2, "c/d"), (3, "c/d/e")]
    );
    let shallow = repo.prefetch_candidates(&root, 1, 100, None, 50).unwrap();
    assert_eq!(shallow.len(), 3, "the depth bound was ignored");
    let page = repo.prefetch_candidates(&root, 3, 100, Some((1, "b")), 2).unwrap();
    assert_eq!(page, [(1, "c".to_owned(), 1), (2, "a/x".to_owned(), 1)]);
    // A folder with more children than the bound is skipped; an enumerated one is not offered.
    assert!(!repo
        .prefetch_candidates(&root, 3, 1, None, 50)
        .unwrap()
        .iter()
        .any(|(_, p, _)| p == "a"));
    let a = repo.mint_item(&root, "a").unwrap();
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO provider_enumerated_parents (root_id, parent_item_id) VALUES (?1, ?2)",
            rusqlite::params![root, &a[..]],
        )?;
        Ok(())
    })
    .unwrap();
    assert!(!repo
        .prefetch_candidates(&root, 3, 100, None, 50)
        .unwrap()
        .iter()
        .any(|(_, p, _)| p == "a"));
}

/// A provider link never yields a filesystem path: the listing says so in its type, and every
/// by-group path lookup refuses instead of handing out the synthetic locator.
#[test]
fn a_provider_link_never_yields_a_path() {
    use yadorilink_replica_domain::session_state::LinkLocation;
    let (db, _repo, root) = declared();
    let links = crate::link::LinkRepository::new(db.clone());
    let listed = links.list_links().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].folder_path(), None, "a provider link produced a folder path");
    assert!(
        matches!(&listed[0].location, LinkLocation::Provider { root_id, .. } if *root_id == root)
    );
    for result in [
        links.live_link_local_path_for_group(GROUP).map(|_| ()),
        links.live_link_paths_for_group(GROUP).map(|_| ()),
        links.link_gate_for_group(GROUP).map(|_| ()),
    ] {
        assert!(matches!(result, Err(SyncSqliteError::NotFilesystemRoot(_))), "{result:?}");
    }
    // The key is still available for keyed writes (storage mode), and is not an openable path.
    assert!(links.live_link_key_for_group(GROUP).unwrap().is_some());
}

fn spec(name: &str, empty_owner: bool) -> crate::provider::ProviderLinkSpec {
    crate::provider::ProviderLinkSpec {
        kind: ProviderKind::MacFileProvider,
        display_name: name.to_string(),
        empty_owner,
        on_demand: false,
        creation_digest: "digest-1".to_string(),
    }
}

/// Creates a provider link the way the enrollment commit does: the link row, the root and the install
/// marker in ONE transaction.
fn create_provider_link(
    db: &SyncDatabase,
    locator: &str,
    group: &str,
    spec: &crate::provider::ProviderLinkSpec,
) -> Result<String, SyncSqliteError> {
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        crate::link::LinkRepository::insert_link_row(tx, locator, group)?;
        crate::provider::declare_link_root_in_tx(tx, group, spec)
    })
}

/// A provider link has no folder to scan, so it never owes a startup scan; a folder link does.
#[test]
fn only_a_folder_link_owes_a_startup_scan() {
    let db = open_db();
    let links = crate::link::LinkRepository::new(db.clone());
    create_provider_link(&db, "provider://t2", "g-provider", &spec("P", false)).unwrap();
    db.write_immediate::<_, SyncSqliteError>(|tx| {
        crate::link::LinkRepository::insert_link_row(tx, "/some/folder", "g-folder")
    })
    .unwrap();
    assert!(!links.has_live_link_for_group("g-provider").unwrap());
    assert!(links.has_live_link_for_group("g-folder").unwrap());
}

/// The link, its root, its token digest and its install marker commit together; an owner-created
/// empty group is installed at once, a joined group is installed only if its native base already is
/// (the install finished before the link existed); a failure leaves nothing behind.
#[test]
fn a_provider_link_commits_its_root_and_derives_the_install_marker() {
    let db = open_db();
    let repo = ProviderRepository::new(db.clone());
    let links = crate::link::LinkRepository::new(db.clone());

    let owner =
        create_provider_link(&db, "provider://t1", "g-owner", &spec("Owned", true)).unwrap();
    assert_eq!(links.creation_digest("provider://t1").unwrap().as_deref(), Some("digest-1"));
    assert_eq!(repo.root_display_name(&owner).unwrap().as_deref(), Some("Owned"));
    assert!(repo.install_done_for_tests(&owner), "an empty owner group waited for an install");

    let joined =
        create_provider_link(&db, "provider://t2", "g-join", &spec("Joined", false)).unwrap();
    assert!(!repo.install_done_for_tests(&joined), "a join with no base claimed an install");

    // The install finished before the link row existed: the commit derives the marker.
    db.write::<_, SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT INTO native_author_context (group_id, author, incarnation, seq) \
             VALUES ('g-late', 'a', x'00', 1)",
            [],
        )?;
        Ok(())
    })
    .unwrap();
    let late = create_provider_link(&db, "provider://t3", "g-late", &spec("Late", false)).unwrap();
    assert!(repo.install_done_for_tests(&late), "an already-installed base was not derived");

    // A duplicate display name is refused and nothing of the failed attempt remains.
    let refused = create_provider_link(&db, "provider://t4", "g-dup", &spec("Owned", true));
    assert!(matches!(refused, Err(SyncSqliteError::InvalidInput(_))), "{refused:?}");
    assert!(links.list_links().unwrap().iter().all(|l| l.group_id != "g-dup"));
}

/// Unlinking writes a durable removal intent and KEEPS the provider state and the upload
/// journal until the host reports the removal; the report deletes the state, keeps the journal as
/// orphans and records where the OS kept the user's data; a repeated report is a no-op; the group
/// cannot get a new root until the removal is finished.
#[test]
fn unlink_keeps_state_until_the_host_acknowledges_the_removal() {
    let (db, repo, root) = declared();
    put(&db, "a.txt");
    let item = repo.mint_item(&root, "a.txt").unwrap();
    repo.journal_pending_ingest(&root, b"s", 1, "ingest-1", 1).unwrap();
    let links = crate::link::LinkRepository::new(db.clone());

    assert!(links.remove_link("/p").unwrap());
    let removals = repo.removals().unwrap();
    assert_eq!(removals.len(), 1);
    assert!(removals[0].requested);
    assert_eq!(removals[0].root_id, root);
    assert!(repo.path_for_item(&root, &item).unwrap().is_some(), "state deleted before the ack");
    assert!(repo.pending_ingest_name(&root, b"s", 1).unwrap().is_some());

    // A new link of the group is refused while the old root is still being removed.
    let relink = create_provider_link(&db, "provider://again", GROUP, &spec("Photos", true));
    assert!(matches!(relink, Err(SyncSqliteError::InvalidInput(_))), "{relink:?}");

    assert!(repo.domain_removed(&root, "/Users/u/Library/CloudStorage/kept").unwrap());
    let done = &repo.removals().unwrap()[0];
    assert!(!done.requested);
    assert_eq!(done.preserved_location.as_deref(), Some("/Users/u/Library/CloudStorage/kept"));
    assert!(repo.path_for_item(&root, &item).unwrap().is_none(), "state survived the ack");
    assert!(
        repo.pending_ingest_name(&root, b"s", 1).unwrap().is_some(),
        "the upload journal was deleted with the root"
    );
    assert!(!repo.domain_removed(&root, "").unwrap(), "a repeated report was not a no-op");
}

/// A domain the USER removed rebootstraps a live root and records the old id as done (the host
/// already saw it gone); a rebootstrap the daemon starts asks the host to remove the old domain.
#[test]
fn a_rebootstrap_records_who_removed_the_old_domain() {
    let (_db, repo, root) = declared();
    assert!(repo.domain_removed(&root, "").unwrap());
    let first = repo.removals().unwrap();
    assert_eq!(
        (first.len(), first[0].requested),
        (1, false),
        "an observed removal asked for another"
    );

    let current = match repo.declaration_for_group(GROUP).unwrap() {
        ProviderDeclaration::Provider(r) => r.root_id,
        other => panic!("{other:?}"),
    };
    assert_ne!(current, root);
    let newer = repo.rebootstrap_root(GROUP).unwrap();
    let removals = repo.removals().unwrap();
    let requested: Vec<_> =
        removals.iter().filter(|r| r.requested).map(|r| r.root_id.clone()).collect();
    assert_eq!(requested, [current], "the old root of a daemon rebootstrap was not requested");
    assert_ne!(newer, requested[0]);
}

/// Undoing a link write that created a provider root removes the root with the row.
#[test]
fn undoing_a_provider_link_removes_its_root() {
    let db = open_db();
    let repo = ProviderRepository::new(db.clone());
    let links = crate::link::LinkRepository::new(db.clone());
    let root = create_provider_link(&db, "provider://u1", "g-undo", &spec("Undone", true)).unwrap();
    links
        .undo_link_row(
            "provider://u1",
            "g-undo",
            &yadorilink_replica_domain::session_state::LinkRowWrite::Inserted,
        )
        .unwrap();
    assert!(repo.root_display_name(&root).unwrap().is_none(), "the root outlived its link row");
    assert!(links.list_links().unwrap().is_empty());
}

/// The guarded unlink (digest recheck) writes the same removal intent: no path deletes a
/// provider link without it.
#[test]
fn the_guarded_unlink_also_writes_the_removal_intent() {
    let (db, repo, root) = declared();
    let links = crate::link::LinkRepository::new(db.clone());
    let digest = db
        .read::<_, SyncSqliteError>(|conn| {
            Ok(crate::file_index::enumerate_group_durability_roots_on_conn(conn, GROUP)?.digest)
        })
        .unwrap();
    assert!(links.recheck_digest_then_remove_link(GROUP, "/p", digest).unwrap());
    let removals = repo.removals().unwrap();
    assert_eq!((removals.len(), removals[0].requested, &removals[0].root_id), (1, true, &root));
}

/// (review) Acknowledging the removal of an OLD root, after the daemon rebootstrapped the group, must not
/// touch the replacement root or its link.
#[test]
fn acknowledging_an_old_roots_removal_leaves_the_replacement_root_intact() {
    let (db, repo, old) = declared();
    put(&db, "a.txt");
    let new = repo.rebootstrap_root(GROUP).unwrap();
    let item = repo.mint_item(&new, "a.txt").unwrap();
    assert!(repo.removals().unwrap().iter().any(|r| r.root_id == old && r.requested));

    assert!(repo.domain_removed(&old, "/kept").unwrap());

    assert_eq!(
        repo.root_display_name(&new).unwrap().as_deref(),
        Some("Photos"),
        "the new root was deleted"
    );
    assert!(
        repo.path_for_item(&new, &item).unwrap().is_some(),
        "the new root's items were deleted"
    );
    let links = crate::link::LinkRepository::new(db.clone());
    assert_eq!(links.list_links().unwrap().len(), 1);
    assert!(
        matches!(repo.declaration_for_group(GROUP).unwrap(), ProviderDeclaration::Provider(r) if r.root_id == new)
    );
    assert!(!repo.removals().unwrap().iter().any(|r| r.requested));
}

/// (review) The child bound counts ALL direct children, files included: a folder of exactly the bound is
/// a candidate with its real count, one more is skipped, and a huge folder with no sub-folder at all is
/// skipped without the scan growing with its size.
#[test]
fn the_prefetch_child_bound_counts_files_and_folders() {
    let (db, repo, root) = declared();
    let bulk = |dir: &str, files: u32| {
        db.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?3) \
                 INSERT INTO files (group_id, path, size, mtime_unix_nanos, blocks_json, deleted) \
                 SELECT ?1, ?2 || '/f' || i, 0, 0, '[]', 0 FROM n",
                rusqlite::params![GROUP, dir, files],
            )?;
            Ok(())
        })
        .unwrap();
    };
    bulk("n999", 999);
    bulk("n1000", 1000);
    bulk("n1001", 1001);
    bulk("big", 50_000);
    let found: Vec<_> = repo
        .prefetch_candidates(&root, 3, 1000, None, 10)
        .unwrap()
        .into_iter()
        .map(|(_, p, children)| (p, children))
        .collect();
    assert_eq!(
        found,
        [("n1000".to_owned(), 1000), ("n999".to_owned(), 999)],
        "the bound is on real children (files count), 1001 and 50 000 files are skipped"
    );
}

/// A provider folder created in on-demand mode is stored as on-demand; the default is eager.
#[test]
fn a_provider_link_keeps_the_requested_materialization_policy() {
    let db = open_db();
    let links = crate::link::LinkRepository::new(db.clone());
    let mut on_demand = spec("Lazy", true);
    on_demand.on_demand = true;
    create_provider_link(&db, "provider://lazy", "g-lazy", &on_demand).unwrap();
    create_provider_link(&db, "provider://full", "g-full", &spec("Full", true)).unwrap();
    let policy = |group: &str| links.materialization_policy_for_group(group).unwrap();
    assert_eq!(
        policy("g-lazy"),
        Some(yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand)
    );
    assert_eq!(
        policy("g-full"),
        Some(yadorilink_replica_domain::session_state::MaterializationPolicy::Eager)
    );
}

/// A joiner that caught up by ordinary replay is installed only when a round proved it in sync; a
/// plain group, an unknown group and an already installed root are untouched, and repeating is harmless.
#[test]
fn a_root_is_installed_by_the_in_sync_mark_only_and_idempotently() {
    let db = open_db();
    let repo = ProviderRepository::new(db.clone());
    let joined =
        create_provider_link(&db, "provider://j", "g-join", &spec("Joined", false)).unwrap();
    assert!(!repo.install_done_for_tests(&joined), "a joiner waits for its install");

    assert!(!repo.mark_installed_when_in_sync("unknown-group").unwrap());
    assert!(!repo.install_done_for_tests(&joined));

    assert!(repo.mark_installed_when_in_sync("g-join").unwrap());
    assert!(repo.install_done_for_tests(&joined));
    assert!(!repo.mark_installed_when_in_sync("g-join").unwrap(), "idempotent");
    assert!(repo.install_done_for_tests(&joined));
}

/// A version whose admission time is unknown is still bounded by the
/// version-count cap, so such rows cannot accumulate.
#[test]
fn versions_without_an_admission_time_are_bounded_by_the_count_cap() {
    let (db, _repo, _root) = declared();
    for seq in 1..=14 {
        set_row(&db, "n.txt", seq, 10 + seq, 100);
    }
    let expired = crate::file_index::FileIndexRepository::new(db.clone())
        .expire_superseded_and_trashed_versions(GROUP, 0, &Default::default())
        .unwrap();
    // 13 superseded rows, ten kept by count.
    assert_eq!(expired, 3);
}
