//! A generation token per group, and the memo of the summary roots it keys.
//!
//! The two roots a `Summary` carries are functions of four tables
//! (`native_heads`, `native_author_context`, `native_author_frontier`,
//! `native_closed_authors`). Computing them rebuilds the whole namespace trie,
//! so answering a peer every few seconds must not do it for a group that did
//! not change. Every write to those tables, by whoever makes it, replaces the
//! group's token inside the same statement's transaction (a trigger, so a
//! writer cannot forget it and a raw statement cannot skip it). A reader takes
//! the token and the state from one snapshot, so the token names exactly the
//! state the roots are computed from.
//!
//! The token is a fresh random value rather than a counter: two copies of a
//! database that diverge from a common ancestor cannot arrive at the same token
//! with different state, and the memo may therefore be shared by every database
//! in the process without being keyed by which one it is.

use std::collections::HashMap;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension};

use yadorilink_replica_domain::ids::FolderGroupId;

use crate::error::SyncSqliteError;
use crate::native_replication::SummaryRoots;
use crate::native_store;

/// The tables whose rows the summary roots are computed from.
const ROOT_TABLES: [&str; 4] =
    ["native_heads", "native_author_context", "native_author_frontier", "native_closed_authors"];

/// How many groups' roots the memo keeps before it starts over. Each entry is
/// 64 bytes; a replica serves a handful of groups.
const MEMO_CAPACITY: usize = 256;

type Token = [u8; 16];

static MEMO: Mutex<Option<HashMap<Token, SummaryRoots>>> = Mutex::new(None);

/// Counts how many times the roots were computed from rows, for tests that pin
/// that an unchanged group is answered from the memo. Compiled out of
/// production builds.
#[cfg(any(test, feature = "test-support"))]
pub mod recompute_counter {
    use std::cell::Cell;

    thread_local! {
        static COMPUTED: Cell<u64> = const { Cell::new(0) };
    }

    /// Roots computed from rows on this thread so far.
    pub fn computed() -> u64 {
        COMPUTED.with(Cell::get)
    }

    pub(crate) fn add() {
        COMPUTED.with(|c| c.set(c.get() + 1));
    }
}

/// Creates the token table and the triggers that replace a group's token on
/// every insert, update and delete of a row of any root table.
pub(crate) fn init_tables(conn: &Connection) -> Result<(), SyncSqliteError> {
    let mut sql = String::from(
        "CREATE TABLE IF NOT EXISTS native_state_generation (
            group_id  TEXT PRIMARY KEY,
            token     BLOB NOT NULL
        ) WITHOUT ROWID;\n",
    );
    let bump = |row: &str| {
        format!(
            "INSERT INTO native_state_generation (group_id, token) \
             VALUES ({row}.group_id, randomblob(16)) \
             ON CONFLICT (group_id) DO UPDATE SET token = randomblob(16);"
        )
    };
    for table in ROOT_TABLES {
        sql.push_str(&format!(
            "CREATE TRIGGER IF NOT EXISTS {table}_generation_insert AFTER INSERT ON {table} \
             BEGIN {} END;\n",
            bump("NEW")
        ));
        sql.push_str(&format!(
            "CREATE TRIGGER IF NOT EXISTS {table}_generation_update AFTER UPDATE ON {table} \
             BEGIN {} END;\n",
            bump("NEW")
        ));
        // A row moved to another group changes the group it left as well.
        sql.push_str(&format!(
            "CREATE TRIGGER IF NOT EXISTS {table}_generation_update_old AFTER UPDATE ON {table} \
             WHEN OLD.group_id IS NOT NEW.group_id BEGIN {} END;\n",
            bump("OLD")
        ));
        sql.push_str(&format!(
            "CREATE TRIGGER IF NOT EXISTS {table}_generation_delete AFTER DELETE ON {table} \
             BEGIN {} END;\n",
            bump("OLD")
        ));
    }
    conn.execute_batch(&sql)?;
    Ok(())
}

/// The group's current token; `None` for a group no root table has ever held a
/// row of.
pub(crate) fn state_token(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<Option<Token>, SyncSqliteError> {
    let token: Option<Vec<u8>> = conn
        .prepare_cached("SELECT token FROM native_state_generation WHERE group_id = ?1")?
        .query_row([group_id.as_str()], |row| row.get(0))
        .optional()?;
    token
        .map(|bytes| {
            bytes.as_slice().try_into().map_err(|_| {
                SyncSqliteError::CorruptState("a native state token is not 16 bytes".into())
            })
        })
        .transpose()
}

fn memo_get(token: &Token) -> Option<SummaryRoots> {
    let guard = MEMO.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.as_ref().and_then(|memo| memo.get(token).copied())
}

fn memo_put(token: Token, roots: SummaryRoots) {
    let mut guard = MEMO.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let memo = guard.get_or_insert_with(HashMap::new);
    if memo.len() >= MEMO_CAPACITY {
        memo.clear();
    }
    memo.insert(token, roots);
}

/// The roots computed from the rows, bypassing the memo.
pub fn compute_summary_roots(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<SummaryRoots, SyncSqliteError> {
    #[cfg(any(test, feature = "test-support"))]
    recompute_counter::add();
    let state = native_store::load_state(conn, group_id)?;
    Ok(SummaryRoots {
        namespace_root: native_store::namespace_root(&state)?.0,
        author_state_root: native_store::author_state_root(conn, group_id)?.0,
    })
}

/// The group's roots: from the memo when its state is the one the memo
/// computed them for, from the rows otherwise.
pub(crate) fn summary_roots(
    conn: &Connection,
    group_id: &FolderGroupId,
) -> Result<SummaryRoots, SyncSqliteError> {
    // One snapshot for the token and every row the roots are computed from. A
    // savepoint, because a caller may already hold a transaction.
    conn.execute_batch("SAVEPOINT native_summary_roots")?;
    let result = (|| {
        let token = state_token(conn, group_id)?;
        if let Some(roots) = token.as_ref().and_then(memo_get) {
            return Ok(roots);
        }
        let roots = compute_summary_roots(conn, group_id)?;
        if let Some(token) = token {
            memo_put(token, roots);
        }
        Ok(roots)
    })();
    conn.execute_batch("RELEASE native_summary_roots")?;
    result
}
