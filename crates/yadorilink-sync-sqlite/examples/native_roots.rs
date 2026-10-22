//! Prints each folder group's native summary roots and table row counts of a replica database as
//! one JSON line, for the maintainers' large-tree acceptance script. Run it on a database no daemon has open.
//!
//! `cargo run --release -p yadorilink-sync-sqlite --example native_roots -- <sync-state.sqlite3>`

use rusqlite::Connection;
use yadorilink_replica_domain::ids::FolderGroupId;

fn main() {
    let path = std::env::args().nth(1).expect("usage: native_roots <sync-state.sqlite3>");
    let conn = Connection::open(path).expect("open the database");
    let mut groups: Vec<String> = conn
        .prepare("SELECT DISTINCT group_id FROM native_heads")
        .and_then(|mut s| s.query_map([], |r| r.get(0))?.collect())
        .expect("list groups");
    groups.sort();
    let roots: Vec<_> = groups
        .iter()
        .map(|group| {
            let r = yadorilink_sync_sqlite::native_replication::summary_roots(
                &conn,
                &FolderGroupId(group.clone()),
            )
            .expect("summary roots");
            serde_json::json!({
                "group": group,
                "namespace_root": hex::encode(r.namespace_root),
                "author_state_root": hex::encode(r.author_state_root),
            })
        })
        .collect();
    let tables: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .and_then(|mut s| s.query_map([], |r| r.get(0))?.collect())
        .expect("list tables");
    let mut rows = serde_json::Map::new();
    for table in tables {
        let n: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |r| r.get(0))
            .unwrap_or(-1);
        if n != 0 {
            rows.insert(table, n.into());
        }
    }
    println!("{}", serde_json::json!({ "roots": roots, "table_rows": rows }));
}
