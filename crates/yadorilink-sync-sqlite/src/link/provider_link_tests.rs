#![cfg(test)]

//! A provider folder linked without an enrollment journal (an accepted invite): the link row, the
//! declared root and the first-link history floor commit together, and a refused declaration
//! leaves nothing behind.

use super::*;
use crate::provider::{ProviderLinkSpec, ProviderRepository};
use yadorilink_replica_domain::session_state::{MaterializationPolicy, ProviderKind};

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

fn spec(name: &str) -> ProviderLinkSpec {
    ProviderLinkSpec {
        kind: ProviderKind::WindowsCfapi,
        display_name: name.into(),
        empty_owner: false,
        on_demand: true,
        creation_digest: "digest".into(),
    }
}

#[test]
fn a_provider_link_declares_its_root_in_the_same_commit() {
    let db = open_full_test_db();
    let links = LinkRepository::new(db.clone());
    let providers = ProviderRepository::new(db.clone());
    let write = links.add_provider_link("provider://token", "group-1", &spec("Shared")).unwrap();
    assert!(matches!(write, LinkRowWrite::Inserted));
    let roots = providers.list_declared_roots().unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!((roots[0].display_name.as_str(), roots[0].group_id.as_str()), ("Shared", "group-1"));
    let linked = links.list_links().unwrap();
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].key(), "provider://token");
    assert_eq!(linked[0].materialization_policy, MaterializationPolicy::OnDemand);
    assert_eq!(links.creation_digest("provider://token").unwrap().as_deref(), Some("digest"));
}

#[test]
fn a_name_already_taken_commits_neither_the_link_nor_a_root() {
    let db = open_full_test_db();
    let links = LinkRepository::new(db.clone());
    let providers = ProviderRepository::new(db);
    links.add_provider_link("provider://one", "group-1", &spec("Shared")).unwrap();
    let refused = links.add_provider_link("provider://two", "group-2", &spec("Shared"));
    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(providers.list_declared_roots().unwrap().len(), 1);
    assert_eq!(links.list_links().unwrap().len(), 1, "the refused link row was rolled back");
}
