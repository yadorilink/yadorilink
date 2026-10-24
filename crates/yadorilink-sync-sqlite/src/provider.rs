//! The provider layer's per-root state and item index (the OS owns the local
//! copy of a provider root; the daemon keeps what the OS was told).
//!
//! The provider DECLARATION lives on the link row (`links.provider_kind` and
//! `links.provider_root_id`): that is the one source of truth for whether a root is plain
//! or provider-backed. `provider_roots` holds the per-root state that declaration names. A
//! link that declares a provider whose state row is missing is corrupt: fail closed and
//! rebootstrap, never a plain directory.
//!
//! Two identifiers exist only here. `root_id` is the stable id of a provider root (the OS
//! domain identity), minted per root and NEW on every rebootstrap, which is also what every
//! domain removal does: a stale extension's late report names the old `root_id` and is
//! simply ignored. `item_id` is an opaque stable id of one item, never a path: a rename
//! keeps it and only changes the path, and a path reused after a delete gets a new one.
//!
//! This is DOMAIN-BOUND state, not semantic authority and not rebuildable inside the same
//! domain: if it is lost the root is rebootstrapped (new `root_id`, new `item_id`s), never
//! repaired by guessing what the OS holds.
//!
//! Readiness is evidence, with no timers: the host reports the domain registered or
//! removed, the extension reports a handshake per launch (persisted, so a daemon restart
//! does not unlearn it), and an explicit provider error makes the root not ready. The
//! extension's later silence never reverts a ready root.

use std::sync::Arc;

use rusqlite::OptionalExtension;
use yadorilink_replica_domain::session_state::{NotReady, ProviderKind, Readiness};
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::error::SyncSqliteError;

/// A 16-byte opaque item id.
pub type ItemId = [u8; 16];

/// One durable domain-removal intent (see the `provider_removals` table).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderRemoval {
    pub root_id: String,
    pub group_id: String,
    pub display_name: String,
    /// `true` until the host reported the removal.
    pub requested: bool,
    pub requested_at: i64,
    /// Where the OS kept the user's downloaded data, once removed.
    pub preserved_location: Option<String>,
}

/// What a link declares when it is created as a provider root.
#[derive(Clone, Debug)]
pub struct ProviderLinkSpec {
    pub kind: ProviderKind,
    pub display_name: String,
    /// The owner-created EMPTY group: there is no install to wait for.
    pub empty_owner: bool,
    /// Create the link in on-demand mode (the default is eager).
    pub on_demand: bool,
    /// Digest of the creation request, stored with the link (see `links.creation_digest`).
    pub creation_digest: String,
}

/// One `provider_roots` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderRoot {
    pub root_id: String,
    pub group_id: String,
    pub kind: ProviderKind,
    pub display_name: String,
    pub domain_registered: bool,
    pub first_handshake_at: Option<i64>,
    pub error_description: Option<String>,
    pub namespace_ready: bool,
    pub latest_evidence_seq: u64,
}

impl ProviderRoot {
    /// Readiness from the persisted evidence alone.
    pub fn readiness(&self) -> Readiness {
        if let Some(error) = &self.error_description {
            return Readiness::NotReady(NotReady::ProviderError(error.clone()));
        }
        if !self.domain_registered {
            return Readiness::NotReady(NotReady::DomainNotRegistered);
        }
        if self.first_handshake_at.is_none() {
            return Readiness::NotReady(NotReady::ExtensionNotEnabled);
        }
        Readiness::Ready
    }
}

/// What a group's link declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderDeclaration {
    /// The link declares no provider: the direct-filesystem path.
    Plain,
    /// The link declares a provider and its state exists.
    Provider(ProviderRoot),
    /// The link declares a provider whose state row is missing (lost or rolled back):
    /// rebootstrap required, never `Plain`.
    Corrupt(String),
}

/// The state row a link declares, validated against the link: it must exist and carry the same
/// root id, group and kind. `Ok(Err(reason))` is a corrupt declaration.
fn declared_root(
    conn: &rusqlite::Connection,
    group_id: &str,
    kind: &str,
    root_id: Option<&str>,
) -> Result<Result<ProviderRoot, String>, SyncSqliteError> {
    let Some(root_id) = root_id else {
        return Ok(Err("the link declares a provider but names no root".into()));
    };
    let root = conn
        .query_row(
            &format!("SELECT {ROOT_COLUMNS} FROM provider_roots WHERE root_id = ?1"),
            [root_id],
            row_to_root,
        )
        .optional()?;
    Ok(match root {
        None => Err("the link declares a provider root but its provider state is missing".into()),
        Some(root) if root.group_id != group_id => {
            Err("the declared provider root belongs to another group".into())
        }
        Some(root) if root.kind != ProviderKind::from_db_str(kind) => {
            Err("the declared provider root is of another kind than the link declares".into())
        }
        Some(root) => Ok(root),
    })
}

fn mint_root_id() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

fn row_to_root(r: &rusqlite::Row<'_>) -> rusqlite::Result<ProviderRoot> {
    Ok(ProviderRoot {
        root_id: r.get(0)?,
        group_id: r.get(1)?,
        kind: ProviderKind::from_db_str(&r.get::<_, String>(2)?),
        display_name: r.get(3)?,
        domain_registered: r.get::<_, i64>(4)? != 0,
        first_handshake_at: r.get(5)?,
        error_description: r.get(6)?,
        namespace_ready: r.get::<_, i64>(7)? != 0,
        latest_evidence_seq: r.get::<_, i64>(8)? as u64,
    })
}

const ROOT_COLUMNS: &str = "root_id, group_id, kind, display_name, domain_registered, \
     first_handshake_at, error_description, namespace_ready, latest_evidence_seq";

/// `(parent_path, name)` of a `/`-separated relative path: the parent index keys.
pub(crate) fn split_parent(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(at) => (&path[..at], &path[at + 1..]),
        None => ("", path),
    }
}

pub struct ProviderRepository {
    database: Arc<SyncDatabase>,
}

impl ProviderRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// The database, for the write path's own transaction (`provider_write`).
    pub(crate) fn database_for_write(&self) -> &SyncDatabase {
        &self.database
    }

    /// Runs a read of the item index against a snapshot in which no changed path is waiting to be
    /// reconciled: settle, then read in ONE snapshot that re-checks the dirty paths first, and
    /// start over if a write slipped in between. A read therefore never answers from a liveness
    /// that lags the rows it sits on, whatever interleaving the writers produce.
    pub(crate) fn read_settled<T>(
        &self,
        mut read: impl FnMut(&rusqlite::Connection) -> Result<T, SyncSqliteError>,
    ) -> Result<T, SyncSqliteError> {
        for _ in 0..64 {
            self.settle()?;
            #[cfg(test)]
            run_after_settle_hook();
            let answer = self.database.read_snapshot::<_, SyncSqliteError>(|conn| {
                let dirty: bool =
                    conn.query_row("SELECT EXISTS(SELECT 1 FROM provider_dirty_paths)", [], |r| {
                        r.get(0)
                    })?;
                if dirty {
                    return Ok(None);
                }
                Ok(Some(read(conn)?))
            })?;
            if let Some(answer) = answer {
                return Ok(answer);
            }
        }
        Err(SyncSqliteError::CorruptState("the provider item index could not settle".into()))
    }

    /// Brings provider item liveness up to date with the committed `files` rows. A write
    /// transaction reconciles before it commits; a connection-level autocommit write only records
    /// which paths changed (atomically with the change). Every read of the item index settles
    /// first, so it never answers from a liveness that lags the rows, however they were written.
    fn settle(&self) -> Result<(), SyncSqliteError> {
        let dirty = self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM provider_dirty_paths)", [], |r| {
                r.get::<_, bool>(0)
            })?)
        })?;
        if dirty {
            // The write transaction's own reconcile runs before it commits.
            self.database.write_immediate::<_, SyncSqliteError>(|_| Ok(()))?;
        }
        Ok(())
    }

    /// Declares the group's link a provider root of `kind`: mints its `root_id`, records
    /// the declaration on the link and creates the state row, in one transaction.
    /// `ProviderKind::None` is not a declaration (a link declares `none` by default).
    pub fn declare_root(
        &self,
        group_id: &str,
        kind: ProviderKind,
        display_name: &str,
    ) -> Result<String, SyncSqliteError> {
        if kind == ProviderKind::None {
            return Err(SyncSqliteError::InvalidInput(
                "a provider root needs a provider kind".into(),
            ));
        }
        if display_name.trim().is_empty() {
            return Err(SyncSqliteError::InvalidInput(
                "a provider root needs a non-empty display name".into(),
            ));
        }
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let root_id = mint_root_id();
            insert_root(tx, &root_id, group_id, kind.as_db_str(), display_name)?;
            Ok(root_id)
        })
    }

    /// The owner-created EMPTY folder flow: declares the group's link a provider root and records its
    /// install as done (an empty namespace has no install to wait for), in one transaction. Refused
    /// unless the group is a plain root with no live file at all: a plain folder that holds files
    /// must never be re-declared (a provider root is never scanned, so its files would be read as
    /// absent). The platform capability is the CALLER's check (macOS only).
    pub fn declare_empty_root(
        &self,
        group_id: &str,
        kind: ProviderKind,
        display_name: &str,
    ) -> Result<String, SyncSqliteError> {
        if kind == ProviderKind::None || display_name.trim().is_empty() {
            return Err(SyncSqliteError::InvalidInput(
                "a provider root needs a kind and a non-empty display name".into(),
            ));
        }
        self.require_plain(group_id)?;
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let has_files: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM files WHERE group_id = ?1 AND state = 'current' \
                 AND deleted = 0)",
                [group_id],
                |r| r.get(0),
            )?;
            if has_files {
                return Err(SyncSqliteError::InvalidInput(format!(
                    "group {group_id} already holds files and cannot become a provider root"
                )));
            }
            let root_id = mint_root_id();
            insert_root(tx, &root_id, group_id, kind.as_db_str(), display_name)?;
            tx.execute(
                "UPDATE provider_roots SET install_done = 1 WHERE root_id = ?1",
                [&root_id],
            )?;
            Ok(root_id)
        })
    }

    /// Creates the provider state row (and its item index) for `group_id` WITHOUT declaring it on
    /// the link: the group stays a plain root, so a test can exercise the index through the real
    /// filesystem capture path, which a declared provider root is (correctly) closed to.
    #[cfg(any(test, feature = "test-support"))]
    pub fn declare_state_only_for_tests(
        &self,
        group_id: &str,
        display_name: &str,
    ) -> Result<String, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let root_id = mint_root_id();
            tx.execute(
                "INSERT INTO provider_roots (root_id, group_id, kind, display_name) \
                 VALUES (?1, ?2, 'mac_file_provider', ?3)",
                rusqlite::params![root_id, group_id, display_name],
            )?;
            Ok(root_id)
        })
    }

    /// What the group's live link declares. No link, or a link declaring `none`, is plain
    /// (nothing provider-backed exists to protect); a declared provider whose state is missing
    /// or does not match the link (another group's row, another kind, another root id) is
    /// `Corrupt`.
    pub fn declaration_for_group(
        &self,
        group_id: &str,
    ) -> Result<ProviderDeclaration, SyncSqliteError> {
        self.database.read_snapshot::<_, SyncSqliteError>(|conn| {
            let declared: Option<(String, Option<String>)> = conn
                .query_row(
                    "SELECT provider_kind, provider_root_id FROM links \
                     WHERE group_id = ?1 AND orphaned = 0 ORDER BY local_path LIMIT 1",
                    [group_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((kind, root_id)) = declared else { return Ok(ProviderDeclaration::Plain) };
            if kind == "none" {
                return Ok(ProviderDeclaration::Plain);
            }
            Ok(match declared_root(conn, group_id, &kind, root_id.as_deref())? {
                Ok(root) => ProviderDeclaration::Provider(root),
                Err(reason) => ProviderDeclaration::Corrupt(reason),
            })
        })
    }

    /// Ok only for a plain root. A provider root (ready or not) and inconsistent provider
    /// state are refused: the direct-filesystem pipeline must never read a provider root's
    /// directory.
    pub fn require_plain(&self, group_id: &str) -> Result<(), SyncSqliteError> {
        match self.declaration_for_group(group_id)? {
            ProviderDeclaration::Plain => Ok(()),
            ProviderDeclaration::Provider(_) => Err(SyncSqliteError::InvalidInput(format!(
                "group {group_id} is a provider-backed root: it has no filesystem pipeline"
            ))),
            ProviderDeclaration::Corrupt(reason) => Err(SyncSqliteError::InvalidInput(format!(
                "group {group_id}: rebootstrap required ({reason})"
            ))),
        }
    }

    /// Every provider root a live link declares. EVERY live provider declaration is validated:
    /// one whose state is missing or does not match its link makes the whole listing an error
    /// (an unavailable snapshot, so the host leaves its domains alone), never a quiet omission.
    pub fn list_declared_roots(&self) -> Result<Vec<ProviderRoot>, SyncSqliteError> {
        self.database.read_snapshot::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT group_id, provider_kind, provider_root_id FROM links \
                 WHERE orphaned = 0 AND provider_kind <> 'none' ORDER BY provider_root_id",
            )?;
            let declared: Vec<(String, String, Option<String>)> = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                .collect::<Result<_, _>>()?;
            let mut roots = Vec::new();
            for (group_id, kind, root_id) in declared {
                match declared_root(conn, &group_id, &kind, root_id.as_deref())? {
                    Ok(root) => roots.push(root),
                    Err(reason) => {
                        return Err(SyncSqliteError::CorruptState(format!(
                            "group {group_id}: {reason}"
                        )))
                    }
                }
            }
            Ok(roots)
        })
    }

    /// The host reports the domain registered or removed. A fresh registration clears the
    /// handshake (the extension must handshake again for the NEW domain). A REMOVAL
    /// rebootstraps the root: a new `root_id`, so a stale extension's delayed report for the
    /// old one finds no root and is ignored, and a re-registration is a new domain. `false`
    /// when the root is unknown.
    pub fn set_domain_registered(
        &self,
        root_id: &str,
        registered: bool,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let row: Option<(String, i64)> = tx
                .query_row(
                    "SELECT group_id, domain_registered FROM provider_roots WHERE root_id = ?1",
                    [root_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((group_id, was)) = row else { return Ok(false) };
            if registered {
                if was == 0 {
                    tx.execute(
                        "UPDATE provider_roots SET domain_registered = 1, \
                            first_handshake_at = NULL WHERE root_id = ?1",
                        [root_id],
                    )?;
                }
            } else {
                rebootstrap_in_tx(tx, &group_id, "done", None)?;
            }
            Ok(true)
        })
    }

    /// The host reports the domain REMOVED (observed, and only for a root the daemon named or a
    /// domain the user removed). A root with a requested removal intent is torn down now: its
    /// provider state is deleted (the upload journal stays as orphans) and the intent is marked
    /// done with the location the OS kept the user's downloaded data at. A live root whose domain
    /// the user removed is rebootstrapped (a new `root_id`) and the old id recorded as done.
    /// `false` when the root is unknown (nothing to do: a repeated report).
    pub fn domain_removed(
        &self,
        root_id: &str,
        preserved_location: &str,
    ) -> Result<bool, SyncSqliteError> {
        let location = (!preserved_location.is_empty()).then_some(preserved_location);
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let requested: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM provider_removals \
                 WHERE root_id = ?1 AND state = 'requested')",
                [root_id],
                |r| r.get(0),
            )?;
            if requested {
                let group: String = tx.query_row(
                    "SELECT group_id FROM provider_removals WHERE root_id = ?1",
                    [root_id],
                    |r| r.get(0),
                )?;
                delete_provider_state(tx, root_id, &group)?;
                tx.execute(
                    "UPDATE provider_removals SET state = 'done', preserved_location = ?2 \
                     WHERE root_id = ?1",
                    rusqlite::params![root_id, location],
                )?;
                return Ok(true);
            }
            let group: Option<String> = tx
                .query_row(
                    "SELECT group_id FROM provider_roots WHERE root_id = ?1",
                    [root_id],
                    |r| r.get(0),
                )
                .optional()?;
            let Some(group) = group else { return Ok(false) };
            rebootstrap_in_tx(tx, &group, "done", location)?;
            Ok(true)
        })
    }

    /// Whether the root's install marker is set (tests).
    #[cfg(any(test, feature = "test-support"))]
    pub fn install_done_for_tests(&self, root_id: &str) -> bool {
        self.database
            .read::<_, SyncSqliteError>(|conn| {
                Ok(conn.query_row(
                    "SELECT install_done FROM provider_roots WHERE root_id = ?1",
                    [root_id],
                    |r| r.get::<_, i64>(0),
                )? != 0)
            })
            .unwrap_or(false)
    }

    /// The display name of a root, `None` when the root does not exist.
    pub fn root_display_name(&self, root_id: &str) -> Result<Option<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn
                .query_row(
                    "SELECT display_name FROM provider_roots WHERE root_id = ?1",
                    [root_id],
                    |r| r.get(0),
                )
                .optional()?)
        })
    }

    /// Every removal the daemon knows of, requested or done, oldest first.
    pub fn removals(&self) -> Result<Vec<ProviderRemoval>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let mut stmt = conn.prepare(
                "SELECT root_id, group_id, display_name, state, requested_at, preserved_location \
                 FROM provider_removals ORDER BY requested_at, root_id",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(ProviderRemoval {
                    root_id: r.get(0)?,
                    group_id: r.get(1)?,
                    display_name: r.get(2)?,
                    requested: r.get::<_, String>(3)? == "requested",
                    requested_at: r.get(4)?,
                    preserved_location: r.get(5)?,
                })
            })?;
            Ok(rows.collect::<Result<_, _>>()?)
        })
    }

    /// The extension completed a handshake (once per process launch). Keeps the first
    /// handshake time since the domain was registered, and clears an earlier explicit
    /// error: a relaunched extension is fresh evidence.
    pub fn record_extension_handshake(
        &self,
        root_id: &str,
        now_unix_nanos: i64,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let changed = tx.execute(
                "UPDATE provider_roots SET \
                    first_handshake_at = COALESCE(first_handshake_at, ?2), \
                    error_description = NULL \
                 WHERE root_id = ?1",
                rusqlite::params![root_id, now_unix_nanos],
            )?;
            Ok(changed > 0)
        })
    }

    /// The extension reported an explicit, fatal provider condition.
    pub fn record_provider_error(
        &self,
        root_id: &str,
        description: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let description = if description.is_empty() { "provider error" } else { description };
            let changed = tx.execute(
                "UPDATE provider_roots SET error_description = ?2 WHERE root_id = ?1",
                rusqlite::params![root_id, description],
            )?;
            Ok(changed > 0)
        })
    }

    /// A replica that is exactly in sync with a connected peer (its native summary equals the peer's)
    /// has the whole native state: a provider root that caught up by ordinary replay, with no
    /// checkpoint install, is installed then. Idempotent, and a read-only check first so the
    /// periodic round does not take the writer gate for a plain group or an installed root.
    /// Returns whether it changed anything.
    pub fn mark_installed_when_in_sync(&self, group_id: &str) -> Result<bool, SyncSqliteError> {
        let pending: bool = self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM provider_roots WHERE group_id = ?1 AND install_done = 0)",
                [group_id],
                |r| r.get(0),
            )?)
        })?;
        if !pending {
            return Ok(false);
        }
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            Ok(tx.execute(
                "UPDATE provider_roots SET install_done = 1 WHERE group_id = ?1 AND install_done = 0",
                [group_id],
            )? > 0)
        })
    }

    /// Records that the root's namespace was installed (an owner-created empty folder has no
    /// install to wait for; a checkpoint install records it itself).
    #[cfg(any(test, feature = "test-support"))]
    pub fn mark_install_done(&self, root_id: &str) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            Ok(tx.execute(
                "UPDATE provider_roots SET install_done = 1 WHERE root_id = ?1",
                [root_id],
            )? > 0)
        })
    }

    /// Marks the root's children queryable (or not): the daemon's gate for domain
    /// registration, because the OS caches an empty root listing.
    pub fn set_namespace_ready(&self, root_id: &str, ready: bool) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let changed = tx.execute(
                "UPDATE provider_roots SET namespace_ready = ?2 WHERE root_id = ?1",
                rusqlite::params![root_id, i64::from(ready)],
            )?;
            Ok(changed > 0)
        })
    }

    /// Rebootstrap of a root: a NEW `root_id` (a new domain) and no items, so every item is
    /// minted again. The old root's evidence is gone with it.
    pub fn rebootstrap_root(&self, group_id: &str) -> Result<String, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            rebootstrap_in_tx(tx, group_id, "requested", None)
        })
    }

    /// The `item_id` of the live item at `path`, minted if there is none yet. Called
    /// when a live path is first projected to the root.
    pub fn mint_item(&self, root_id: &str, path: &str) -> Result<ItemId, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            // Inside the writer transaction, so no write can slip in between the settle and the read.
            yadorilink_sqlite_runtime::reconcile_provider_liveness(tx)?;
            mint_item_in_tx(tx, root_id, path)
        })
    }

    /// The live item at `path`.
    pub fn item_for_path(
        &self,
        root_id: &str,
        path: &str,
    ) -> Result<Option<ItemId>, SyncSqliteError> {
        self.read_settled(|conn| {
            let row: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT item_id FROM provider_items \
                     WHERE root_id = ?1 AND path = ?2 AND live = 1",
                    rusqlite::params![root_id, path],
                    |r| r.get(0),
                )
                .optional()?;
            row.as_deref().map(item_id_from).transpose()
        })
    }

    /// The path an item currently names and whether it is live. A retired item
    /// still resolves (a late `deleteItem` for it must).
    pub fn path_for_item(
        &self,
        root_id: &str,
        item_id: &ItemId,
    ) -> Result<Option<(String, bool)>, SyncSqliteError> {
        self.read_settled(|conn| {
            Ok(conn
                .query_row(
                    "SELECT path, live FROM provider_items WHERE root_id = ?1 AND item_id = ?2",
                    rusqlite::params![root_id, &item_id[..]],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? != 0)),
                )
                .optional()?)
        })
    }

    /// The next folders worth warming, breadth first: directories of the root's group that the OS has
    /// not enumerated yet, at most `max_depth` levels deep (the root's children are depth 1) and with
    /// at most `max_children` DIRECT children (files and folders, a folder with its own entry counted
    /// once), ordered by `(depth, path)` and strictly after `after`. Returns `(depth, path, children)`
    /// with the real child count (bounded by the `max_children + 1` scan, so a huge folder costs no
    /// more than a small one).
    pub fn prefetch_candidates(
        &self,
        root_id: &str,
        max_depth: u32,
        max_children: u32,
        after: Option<(u32, &str)>,
        limit: u32,
    ) -> Result<Vec<(u32, String, u32)>, SyncSqliteError> {
        const DEPTH: &str = "(length(d.path) - length(replace(d.path, '/', '')) + 1)";
        self.read_settled(|conn| {
            let sql = format!(
                "SELECT depth, path, children FROM ( \
                   SELECT {DEPTH} AS depth, d.path AS path, \
                     (SELECT COUNT(*) FROM ( \
                        SELECT f.path FROM files f \
                         WHERE f.group_id = d.group_id AND f.state = 'current' AND f.deleted = 0 \
                           AND f.version_seq > 0 \
                           AND rtrim(rtrim(f.path, replace(f.path, '/', '')), '/') = d.path \
                        UNION \
                        SELECT c.path FROM provider_dirs c \
                         WHERE c.group_id = d.group_id AND c.parent_path = d.path \
                        LIMIT ?5 + 1)) AS children \
                   FROM provider_dirs d \
                   JOIN provider_roots r ON r.group_id = d.group_id \
                   WHERE r.root_id = ?1 AND {DEPTH} <= ?2 \
                     AND ({DEPTH} > ?3 OR ({DEPTH} = ?3 AND d.path > ?4)) \
                     AND NOT EXISTS (SELECT 1 FROM provider_items pi \
                          JOIN provider_enumerated_parents e \
                            ON e.root_id = pi.root_id AND e.parent_item_id = pi.item_id \
                          WHERE pi.root_id = r.root_id AND pi.path = d.path AND pi.live = 1)) \
                 WHERE children <= ?5 ORDER BY depth, path LIMIT ?6"
            );
            let (after_depth, after_path) = after.unwrap_or((0, ""));
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(
                rusqlite::params![
                    root_id,
                    i64::from(max_depth),
                    i64::from(after_depth),
                    after_path,
                    i64::from(max_children),
                    i64::from(limit)
                ],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)? as u32,
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(2)? as u32,
                    ))
                },
            )?;
            rows.collect::<Result<_, _>>().map_err(Into::into)
        })
    }

    /// The live items directly below `parent_path` ("" is the root), by name: the
    /// parent index, so a folder opens in proportion to its own children.
    pub fn list_children(
        &self,
        root_id: &str,
        parent_path: &str,
    ) -> Result<Vec<(String, ItemId)>, SyncSqliteError> {
        self.read_settled(|conn| {
            let mut stmt = conn.prepare(
                "SELECT name, item_id FROM provider_items \
                 WHERE root_id = ?1 AND parent_path = ?2 AND live = 1 ORDER BY name",
            )?;
            let rows = stmt.query_map(rusqlite::params![root_id, parent_path], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?;
            let mut out = Vec::new();
            for row in rows {
                let (name, id) = row?;
                out.push((name, item_id_from(&id)?));
            }
            Ok(out)
        })
    }
}

/// Where an item stands between the daemon's current version and what the OS was told.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Publication {
    /// The OS was never told this item (it is served at its current version when first
    /// enumerated). Never fenced.
    Unpublished,
    /// The OS was told exactly the current version.
    Published,
    /// Only metadata (mtime, mode, xattrs) differs from what the OS was told: its bytes are
    /// still right, so the change is published by a signal ALONE (no eviction, no fence).
    MetadataOnly,
    /// The CONTENT differs: the fence is ON until the old copy is evicted and the new
    /// version is signalled.
    ContentPending,
}

/// One live regular file as the Eager driver sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileCandidate {
    pub path: String,
    pub size: u64,
    /// `None` until the file has been projected as an item.
    pub item_id: Option<ItemId>,
}

/// How often fetching one version of an item failed, and when it may be offered again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DownloadFailure {
    pub version_hash: yadorilink_replica_domain::ids::VersionHash,
    pub failures: u32,
    pub next_attempt_ms: i64,
}

/// A ledger entry: a verified handoff of a version to the OS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handoff {
    pub version_hash: yadorilink_replica_domain::ids::VersionHash,
    pub evidence_seq: u64,
}

type PendingRow = (Vec<u8>, String, String, Option<Vec<u8>>, Option<Vec<u8>>);

/// One item that needs a publication step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingItem {
    pub item_id: ItemId,
    pub path: String,
    pub publication: Publication,
}

/// What the OS is shown for an item: the published version, never a newer one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServedView {
    pub path: String,
    pub version: yadorilink_replica_domain::file::FileVersion,
    /// Whether this is the published version (false: the item was never published and is
    /// served at its current version).
    pub published: bool,
}

/// The identity of a version's CONTENT: what the OS's bytes depend on. Metadata (mtime,
/// mode, xattrs) is not part of it.
fn same_content(
    a: &yadorilink_replica_domain::file::FileVersion,
    b: &yadorilink_replica_domain::file::FileVersion,
) -> bool {
    a.size == b.size
        && a.blocks == b.blocks
        && a.meta.record_kind == b.meta.record_kind
        && a.meta.symlink_target == b.meta.symlink_target
}

pub(crate) fn hash_from(
    bytes: &[u8],
) -> Result<yadorilink_replica_domain::ids::VersionHash, SyncSqliteError> {
    <[u8; 32]>::try_from(bytes).map(yadorilink_replica_domain::ids::VersionHash).map_err(|_| {
        SyncSqliteError::CorruptState("a published version hash is not 32 bytes".into())
    })
}

/// The version the daemon holds for the live path now.
pub(crate) fn current_version(
    conn: &rusqlite::Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<yadorilink_replica_domain::file::FileVersion>, SyncSqliteError> {
    Ok(crate::read_canonical_current_row(conn, group_id, path)?
        .filter(|row| !row.snapshot.deleted)
        .map(|row| {
            yadorilink_replica_domain::session_state::CurrentVersionRecord::from(row.snapshot)
                .to_file_version()
        }))
}

/// Publication state of one item, from the committed rows only (nothing is stored for the
/// fence). A published version that cannot be resolved is lost evidence (invariant I2): an
/// error the caller turns into a rebootstrap, never a guess.
///
/// What the OS was last told is the announced version when one is pending and is not the current
/// version (the OS may already hold its bytes), else the published one. The comparison is by
/// version identity only: a current version that returned to the published one (same hash) is
/// still not what the OS was told while another version is announced.
pub(crate) fn publication_in(
    conn: &rusqlite::Connection,
    group_id: &str,
    path: &str,
    published: Option<Vec<u8>>,
    announced: Option<Vec<u8>>,
) -> Result<Publication, SyncSqliteError> {
    let Some(published) = published else { return Ok(Publication::Unpublished) };
    let published = hash_from(&published)?;
    // EVERY published reference is resolved, including one equal to the current version: a
    // published version that is gone is lost evidence however the current row looks.
    let resolve = |hash| {
        crate::dag_store::get_file_version(conn, group_id, hash)?.ok_or_else(|| {
            SyncSqliteError::CorruptState("the published version of an item is gone".into())
        })
    };
    let published_version = resolve(&published)?;
    let Some(current) = current_version(conn, group_id, path)? else {
        // The path has no live current row (retired or structural): nothing to fence.
        return Ok(Publication::Published);
    };
    let announced = announced.map(|a| hash_from(&a)).transpose()?;
    let told = match announced {
        Some(announced) if announced != current.version_hash => announced,
        _ => published,
    };
    if current.version_hash == told {
        return Ok(Publication::Published);
    }
    let old = if told == published { published_version } else { resolve(&told)? };
    Ok(if same_content(&old, &current) {
        Publication::MetadataOnly
    } else {
        Publication::ContentPending
    })
}

impl ProviderRepository {
    /// The hash of the version the daemon holds for the live item now.
    pub fn current_version_hash(
        &self,
        root_id: &str,
        item_id: &ItemId,
    ) -> Result<Option<yadorilink_replica_domain::ids::VersionHash>, SyncSqliteError> {
        self.read_settled(|conn| {
            let row: Option<(String, String)> = conn
                .query_row(
                    "SELECT group_id, path FROM provider_items \
                     WHERE root_id = ?1 AND item_id = ?2 AND live = 1",
                    rusqlite::params![root_id, &item_id[..]],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((group_id, path)) = row else { return Ok(None) };
            Ok(current_version(conn, &group_id, &path)?.map(|version| version.version_hash))
        })
    }

    /// Records that the daemon handed the OS the bytes of version `version` of the item (verified
    /// against the block store by the caller). Only the CURRENT version can be handed over: a
    /// handoff of a version that is no longer current is a stale claim and records nothing
    /// (`None`). Takes the next evidence sequence of the root and returns it. One row per item,
    /// latest wins. A handoff alone proves nothing about what the OS holds (see the evidence rule
    /// in the daemon).
    pub fn record_handoff(
        &self,
        root_id: &str,
        item_id: &ItemId,
        version: yadorilink_replica_domain::ids::VersionHash,
    ) -> Result<Option<u64>, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            record_ledger_in_tx(tx, HANDOFFS, root_id, item_id, version)
        })
    }

    /// Records that the daemon handed the OS a verified WINDOW of the current version `version`
    /// (never the whole file). Same rules and evidence sequence as [`Self::record_handoff`], in
    /// its own ledger: a window serve is never presence of the content.
    pub fn record_window_serve(
        &self,
        root_id: &str,
        item_id: &ItemId,
        version: yadorilink_replica_domain::ids::VersionHash,
    ) -> Result<Option<u64>, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            record_ledger_in_tx(tx, WINDOW_SERVES, root_id, item_id, version)
        })
    }

    /// The window-serve entry of an item: the version a window was last handed over for and the
    /// evidence sequence it took.
    pub fn window_serve(
        &self,
        root_id: &str,
        item_id: &ItemId,
    ) -> Result<Option<Handoff>, SyncSqliteError> {
        self.read_ledger(WINDOW_SERVES, root_id, item_id)
    }

    /// Whether the version a window was last served for has exactly the content of the item's
    /// current version. False when no window was served or either version is unreadable.
    pub fn window_serve_has_current_content(
        &self,
        root_id: &str,
        item_id: &ItemId,
    ) -> Result<bool, SyncSqliteError> {
        self.ledger_has_current_content(WINDOW_SERVES, root_id, item_id)
    }

    /// The ledger entry of an item: the version handed over and the evidence sequence it took.
    pub fn handoff(
        &self,
        root_id: &str,
        item_id: &ItemId,
    ) -> Result<Option<Handoff>, SyncSqliteError> {
        self.read_ledger(HANDOFFS, root_id, item_id)
    }

    /// Whether the version last handed over for the item has exactly the content of its current
    /// version (the metadata may differ). False when nothing was handed over or either version is
    /// unreadable.
    pub fn handoff_has_current_content(
        &self,
        root_id: &str,
        item_id: &ItemId,
    ) -> Result<bool, SyncSqliteError> {
        self.ledger_has_current_content(HANDOFFS, root_id, item_id)
    }

    fn read_ledger(
        &self,
        table: &'static str,
        root_id: &str,
        item_id: &ItemId,
    ) -> Result<Option<Handoff>, SyncSqliteError> {
        self.read_settled(|conn| {
            let row: Option<(Vec<u8>, i64)> = conn
                .query_row(
                    &format!(
                        "SELECT version_hash, evidence_seq FROM {table} \
                         WHERE root_id = ?1 AND item_id = ?2"
                    ),
                    rusqlite::params![root_id, &item_id[..]],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            row.map(|(hash, seq)| {
                Ok(Handoff { version_hash: hash_from(&hash)?, evidence_seq: seq as u64 })
            })
            .transpose()
        })
    }

    fn ledger_has_current_content(
        &self,
        table: &'static str,
        root_id: &str,
        item_id: &ItemId,
    ) -> Result<bool, SyncSqliteError> {
        self.read_settled(|conn| {
            let row: Option<(Vec<u8>, String, String)> = conn
                .query_row(
                    &format!(
                        "SELECT h.version_hash, i.group_id, i.path FROM {table} h \
                         JOIN provider_items i ON i.root_id = h.root_id AND i.item_id = h.item_id \
                         WHERE h.root_id = ?1 AND h.item_id = ?2 AND i.live = 1"
                    ),
                    rusqlite::params![root_id, &item_id[..]],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((handed, group_id, path)) = row else { return Ok(false) };
            let handed = crate::dag_store::get_file_version(conn, &group_id, &hash_from(&handed)?)?;
            let current = current_version(conn, &group_id, &path)?;
            Ok(matches!((handed, current), (Some(handed), Some(current)) if same_content(&handed, &current)))
        })
    }

    /// The latest evidence sequence of the root (replayable state: the host reads it on connect).
    pub fn latest_evidence_seq(&self, root_id: &str) -> Result<Option<u64>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn
                .query_row(
                    "SELECT latest_evidence_seq FROM provider_roots WHERE root_id = ?1",
                    [root_id],
                    |r| r.get::<_, i64>(0),
                )
                .optional()?
                .map(|v| v as u64))
        })
    }

    /// The group a root belongs to.
    pub fn group_of_root(&self, root_id: &str) -> Result<Option<String>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn
                .query_row(
                    "SELECT group_id FROM provider_roots WHERE root_id = ?1",
                    [root_id],
                    |r| r.get(0),
                )
                .optional()?)
        })
    }

    /// The durable namespace revision of the root.
    pub fn namespace_revision(&self, root_id: &str) -> Result<Option<u64>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            Ok(conn
                .query_row(
                    "SELECT namespace_revision FROM provider_roots WHERE root_id = ?1",
                    [root_id],
                    |r| r.get::<_, i64>(0),
                )
                .optional()?
                .map(|r| r as u64))
        })
    }

    /// The publication state of one live item.
    pub fn publication(
        &self,
        root_id: &str,
        item_id: &ItemId,
    ) -> Result<Option<Publication>, SyncSqliteError> {
        self.read_settled(|conn| {
            type Row = (String, String, Option<Vec<u8>>, Option<Vec<u8>>);
            let row: Option<Row> = conn
                .query_row(
                    "SELECT group_id, path, published_version_hash, announce_version_hash \
                     FROM provider_items WHERE root_id = ?1 AND item_id = ?2 AND live = 1",
                    rusqlite::params![root_id, &item_id[..]],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            row.map(|(group_id, path, published, announced)| {
                publication_in(conn, &group_id, &path, published, announced)
            })
            .transpose()
        })
    }

    /// Every live item that needs a publication step (a content or a metadata-only change
    /// since the OS was told). One snapshot, so the answer describes one instant.
    pub fn pending_items(&self, root_id: &str) -> Result<Vec<PendingItem>, SyncSqliteError> {
        self.read_settled(|conn| {
            let mut stmt = conn.prepare(
                "SELECT item_id, group_id, path, published_version_hash, announce_version_hash \
                 FROM provider_items WHERE root_id = ?1 AND live = 1 AND published_version_hash IS NOT NULL \
                 ORDER BY path",
            )?;
            let rows: Vec<PendingRow> = stmt
                .query_map([root_id], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
                })?
                .collect::<Result<_, _>>()?;
            let mut out = Vec::new();
            for (item, group_id, path, published, announced) in rows {
                let publication = publication_in(conn, &group_id, &path, published, announced)?;
                if matches!(publication, Publication::MetadataOnly | Publication::ContentPending) {
                    out.push(PendingItem { item_id: item_id_from(&item)?, path, publication });
                }
            }
            Ok(out)
        })
    }

    /// TEST SEAM: publishes `version` of the item as if its publication had completed. Nothing in
    /// production calls this: a version is published only by a handoff of it (provenance), by our
    /// own timer ([`Self::release_expired`]) or at an item's first listing. The host's signal,
    /// wait or acknowledgement never publish anything.
    #[cfg(any(test, feature = "test-support"))]
    pub fn publish_for_tests(
        &self,
        root_id: &str,
        item_id: &ItemId,
        version: yadorilink_replica_domain::ids::VersionHash,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            yadorilink_sqlite_runtime::reconcile_provider_liveness(tx)?;
            let row: Option<(String, String)> = tx
                .query_row(
                    "SELECT group_id, path FROM provider_items \
                     WHERE root_id = ?1 AND item_id = ?2 AND live = 1",
                    rusqlite::params![root_id, &item_id[..]],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((group_id, path)) = row else { return Ok(false) };
            match current_version(tx, &group_id, &path)? {
                Some(current) if current.version_hash == version => {}
                _ => return Ok(false),
            }
            tx.execute(
                "UPDATE provider_items SET published_version_hash = ?3, \
                 announce_version_hash = NULL, announce_seq = NULL, pending_since = NULL \
                 WHERE root_id = ?1 AND item_id = ?2",
                rusqlite::params![root_id, &item_id[..], &version.0[..]],
            )?;
            Ok(true)
        })
    }

    /// Announces `version` of the item: in ONE transaction the version is recorded as the one
    /// being announced and an upsert event is appended, and the event's sequence and the item's
    /// parent are returned (the sequence is also the revision the signal carries). From this
    /// moment the shown view is `version` (enumerations, lookups and change reports), while the
    /// content fence is untouched: the announced version is fetchable, nothing newer is, and it
    /// is published by a handoff of it or by our own timer; nothing the host or the OS reports
    /// releases it. Idempotent: announcing the same version again returns the same sequence.
    /// `None` when the item is gone, `version` is no longer current, or it is already
    /// published with nothing else announced (when another version is announced, that
    /// announcement is withdrawn and the item is announced again as it is published).
    pub fn announce_version(
        &self,
        root_id: &str,
        item_id: &ItemId,
        version: yadorilink_replica_domain::ids::VersionHash,
        now_ms: i64,
    ) -> Result<Option<Announced>, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            yadorilink_sqlite_runtime::reconcile_provider_liveness(tx)?;
            let row: Option<AnnounceRow> = tx
                .query_row(
                    "SELECT group_id, path, published_version_hash, announce_version_hash, \
                     announce_seq FROM provider_items \
                     WHERE root_id = ?1 AND item_id = ?2 AND live = 1",
                    rusqlite::params![root_id, &item_id[..]],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?;
            let Some((group_id, path, published, announced, announced_seq)) = row else {
                return Ok(None);
            };
            match current_version(tx, &group_id, &path)? {
                Some(current) if current.version_hash == version => {}
                _ => return Ok(None),
            }
            let parent = parent_item_id(tx, root_id, split_parent(&path).0)?;
            if published.as_deref() == Some(&version.0[..]) {
                // The current version is the published one. Nothing is left to announce, unless
                // another version is still announced (the item came back to the published
                // version before that one was published): that announcement is withdrawn, and
                // the OS is told the item again so it shows the version it is now.
                if announced.is_none() {
                    return Ok(None);
                }
                let seq = append_event(tx, root_id, "upsert", &item_id[..], &parent, None)?;
                tx.execute(
                    "UPDATE provider_items SET announce_version_hash = NULL, \
                     announce_seq = NULL, pending_since = NULL, generation = generation + 1 \
                     WHERE root_id = ?1 AND item_id = ?2",
                    rusqlite::params![root_id, &item_id[..]],
                )?;
                return Ok(Some(Announced { seq, parent_item_id: parent }));
            }
            if let (Some(announced), Some(seq)) = (announced, announced_seq) {
                if announced == version.0 {
                    return Ok(Some(Announced { seq: seq as u64, parent_item_id: parent }));
                }
            }
            let seq = append_event(tx, root_id, "upsert", &item_id[..], &parent, None)?;
            // A new announcement changes what the item shows: its generation advances, the
            // pending episode starts (or continues: `pending_since` is kept).
            tx.execute(
                "UPDATE provider_items SET announce_version_hash = ?3, announce_seq = ?4, \
                 generation = generation + 1, \
                 pending_since = COALESCE(pending_since, ?5) \
                 WHERE root_id = ?1 AND item_id = ?2",
                rusqlite::params![root_id, &item_id[..], &version.0[..], seq as i64, now_ms],
            )?;

            Ok(Some(Announced { seq, parent_item_id: parent }))
        })
    }

    /// Releases the announced version of the item by OUR OWN timer: `release_after_ms` after the
    /// item first became pending (`pending_since`, which survives successive announcements, so a
    /// stream of newer commits cannot postpone it forever) the latest announced version becomes
    /// the published one, whatever has been committed since (a newer version simply starts a new
    /// episode). Nothing the OS does releases it. The release is NOT delivery: the item is
    /// reported as "published, not yet confirmed" until a confirmed handoff shows the OS
    /// fetching it. `true` when something was released.
    pub fn release_expired(
        &self,
        root_id: &str,
        item_id: &ItemId,
        now_ms: i64,
        release_after_ms: i64,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let changed = tx.execute(
                "UPDATE provider_items SET published_version_hash = announce_version_hash, \
                 announce_version_hash = NULL, announce_seq = NULL, pending_since = NULL, \
                 unconfirmed_since = ?3 \
                 WHERE root_id = ?1 AND item_id = ?2 AND live = 1 \
                   AND announce_version_hash IS NOT NULL AND pending_since IS NOT NULL \
                   AND pending_since + ?4 <= ?3",
                rusqlite::params![root_id, &item_id[..], now_ms, release_after_ms],
            )?;
            Ok(changed > 0)
        })
    }

    /// Milliseconds until the timer releases the item's announcement (`Some(0)` when due), or
    /// `None` when nothing is announced.
    pub fn release_due_in(
        &self,
        root_id: &str,
        item_id: &ItemId,
        now_ms: i64,
        release_after_ms: i64,
    ) -> Result<Option<i64>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let since: Option<Option<i64>> = conn
                .query_row(
                    "SELECT pending_since FROM provider_items \
                     WHERE root_id = ?1 AND item_id = ?2 AND live = 1 \
                       AND announce_version_hash IS NOT NULL",
                    rusqlite::params![root_id, &item_id[..]],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(since.flatten().map(|since| (since + release_after_ms - now_ms).max(0)))
        })
    }

    /// Whether the item's announced version is its current one: fetches of the ANNOUNCED version
    /// are allowed from the announcement on, of nothing newer.
    pub fn announced_is_current(
        &self,
        root_id: &str,
        item_id: &ItemId,
    ) -> Result<bool, SyncSqliteError> {
        self.read_settled(|conn| {
            let row: Option<(String, String, Option<Vec<u8>>)> = conn
                .query_row(
                    "SELECT group_id, path, announce_version_hash FROM provider_items \
                     WHERE root_id = ?1 AND item_id = ?2 AND live = 1",
                    rusqlite::params![root_id, &item_id[..]],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((group_id, path, Some(announced))) = row else { return Ok(false) };
            Ok(current_version(conn, &group_id, &path)?
                .is_some_and(|current| current.version_hash.0[..] == announced[..]))
        })
    }

    /// Items whose new version is waiting to be published (the eviction of the old copy is busy or
    /// the release is waiting): how many, the age of the oldest, and up to `limit` of them
    /// (oldest first) as `(path, age_ms)`.
    pub fn pending_publications(
        &self,
        root_id: &str,
        now_ms: i64,
        limit: u32,
    ) -> Result<(Unresolved, Vec<(String, u64)>), SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let (count, oldest): (i64, Option<i64>) = conn.query_row(
                "SELECT COUNT(*), MIN(pending_since) FROM provider_items \
                 WHERE root_id = ?1 AND live = 1 AND pending_since IS NOT NULL",
                [root_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let mut stmt = conn.prepare(
                "SELECT path, pending_since FROM provider_items \
                 WHERE root_id = ?1 AND live = 1 AND pending_since IS NOT NULL \
                 ORDER BY pending_since, path LIMIT ?2",
            )?;
            let items = stmt
                .query_map(rusqlite::params![root_id, i64::from(limit)], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                })?
                .map(|row| row.map(|(path, since)| (path, (now_ms - since).max(0) as u64)))
                .collect::<Result<_, _>>()?;
            Ok((
                Unresolved {
                    count: count as u64,
                    oldest_age_ms: oldest.map_or(0, |since| (now_ms - since).max(0) as u64),
                },
                items,
            ))
        })
    }

    /// The versions released by the timer and not yet confirmed by a handoff: how many items and
    /// how long the oldest has waited (the "published, not yet confirmed by the OS" report).
    pub fn unresolved_publications(
        &self,
        root_id: &str,
        now_ms: i64,
    ) -> Result<Unresolved, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let (count, oldest): (i64, Option<i64>) = conn.query_row(
                "SELECT COUNT(*), MIN(unconfirmed_since) FROM provider_items \
                 WHERE root_id = ?1 AND live = 1 AND unconfirmed_since IS NOT NULL",
                [root_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            Ok(Unresolved {
                count: count as u64,
                oldest_age_ms: oldest.map_or(0, |since| (now_ms - since).max(0) as u64),
            })
        })
    }

    /// Records the FIRST publication of an item: the OS was just served it at version `served`
    /// (an enumeration). Only an item never published is touched, and only if `served` is STILL
    /// its current version, compared inside the same transaction: a version committed between
    /// serving and recording is never marked published (the item stays unpublished, so the host
    /// serves it again). `false` when nothing was recorded.
    pub fn publish_first(
        &self,
        root_id: &str,
        item_id: &ItemId,
        served: yadorilink_replica_domain::ids::VersionHash,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            yadorilink_sqlite_runtime::reconcile_provider_liveness(tx)?;
            let row: Option<(String, String, Option<Vec<u8>>)> = tx
                .query_row(
                    "SELECT group_id, path, published_version_hash FROM provider_items \
                     WHERE root_id = ?1 AND item_id = ?2 AND live = 1",
                    rusqlite::params![root_id, &item_id[..]],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((group_id, path, None)) = row else { return Ok(false) };
            match current_version(tx, &group_id, &path)? {
                Some(current) if current.version_hash == served => {}
                _ => return Ok(false),
            }
            tx.execute(
                "UPDATE provider_items SET published_version_hash = ?3, exposed = 1 \
                 WHERE root_id = ?1 AND item_id = ?2",
                rusqlite::params![root_id, &item_id[..], &served.0[..]],
            )?;
            Ok(true)
        })
    }

    /// One page of the root's live regular files in download order: (size, path), after the
    /// given key, each with its item (`None` while the file has no item yet). Only real current
    /// rows (not the `version_seq = 0` scaffold). The Eager driver walks pages until it has
    /// enough candidates, so a query costs in proportion to what it skips, not to the root.
    pub fn eager_page(
        &self,
        root_id: &str,
        kept_only: bool,
        after: Option<(u64, &str)>,
        limit: usize,
    ) -> Result<Vec<FileCandidate>, SyncSqliteError> {
        // `kept_only`: only the files at or beneath a path the user keeps on this device (a pin;
        // the empty path is the whole root).
        let filter = if kept_only {
            " AND EXISTS (SELECT 1 FROM pinned_items p WHERE p.group_id = r.group_id AND \
             (p.path = '' OR p.path = f.path OR substr(f.path, 1, length(p.path) + 1) = p.path || '/'))"
        } else {
            ""
        };
        self.read_settled(|conn| {
            let (after_size, after_path) = match after {
                Some((size, path)) => (size as i64, path.to_string()),
                None => (-1, String::new()),
            };
            let mut stmt = conn.prepare(&format!(
                "SELECT f.path, f.size, i.item_id \
                 FROM provider_roots r \
                 JOIN files f ON f.group_id = r.group_id AND f.state = 'current' \
                      AND f.deleted = 0 AND f.record_kind = 'file' AND f.version_seq > 0 \
                 LEFT JOIN provider_items i ON i.root_id = r.root_id AND i.path = f.path \
                      AND i.live = 1 \
                 WHERE r.root_id = ?1 AND (f.size > ?2 OR (f.size = ?2 AND f.path > ?3)){filter} \
                 ORDER BY f.size, f.path LIMIT ?4"
            ))?;
            let rows = stmt.query_map(
                rusqlite::params![root_id, after_size, after_path, limit as i64],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                },
            )?;
            let mut out = Vec::new();
            for row in rows {
                let (path, size, item) = row?;
                out.push(FileCandidate {
                    path,
                    size: size as u64,
                    item_id: item.as_deref().map(item_id_from).transpose()?,
                });
            }
            Ok(out)
        })
    }

    /// The failure record of an item, if any (version-bound by the caller).
    pub fn download_failure(
        &self,
        root_id: &str,
        item_id: &ItemId,
    ) -> Result<Option<DownloadFailure>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            let row: Option<(Vec<u8>, i64, i64)> = conn
                .query_row(
                    "SELECT version_hash, failures, next_attempt_ms FROM \
                     provider_download_failures WHERE root_id = ?1 AND item_id = ?2",
                    rusqlite::params![root_id, &item_id[..]],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            row.map(|(version, failures, next)| {
                Ok(DownloadFailure {
                    version_hash: hash_from(&version)?,
                    failures: failures as u32,
                    next_attempt_ms: next,
                })
            })
            .transpose()
        })
    }

    /// Fetching `version` of the item failed (no reachable peer had its content): one more
    /// failure of THAT version (a different version starts again at one) and the next time it
    /// may be offered, `delay_ms(failures)` after `now_ms`. Recorded only while `version` is
    /// still the item's current one, checked in the same transaction: a failure of a version
    /// that was replaced meanwhile says nothing about the current one (`None`).
    pub fn record_download_failure(
        &self,
        root_id: &str,
        item_id: &ItemId,
        version: yadorilink_replica_domain::ids::VersionHash,
        now_ms: i64,
        delay_ms: impl Fn(u32) -> i64,
    ) -> Result<Option<DownloadFailure>, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let live: Option<(String, String)> = tx
                .query_row(
                    "SELECT group_id, path FROM provider_items \
                     WHERE root_id = ?1 AND item_id = ?2 AND live = 1",
                    rusqlite::params![root_id, &item_id[..]],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((group_id, path)) = live else { return Ok(None) };
            let current = current_version(tx, &group_id, &path)?.map(|v| v.version_hash);
            if current != Some(version) {
                return Ok(None);
            }
            let previous: Option<(Vec<u8>, i64)> = tx
                .query_row(
                    "SELECT version_hash, failures FROM provider_download_failures \
                     WHERE root_id = ?1 AND item_id = ?2",
                    rusqlite::params![root_id, &item_id[..]],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let failures = match previous {
                Some((prior, count)) if prior == version.0 => count as u32 + 1,
                _ => 1,
            };
            let next = now_ms.saturating_add(delay_ms(failures));
            tx.execute(
                "INSERT OR REPLACE INTO provider_download_failures \
                 (root_id, item_id, version_hash, failures, next_attempt_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![root_id, &item_id[..], &version.0[..], failures as i64, next],
            )?;
            Ok(Some(DownloadFailure { version_hash: version, failures, next_attempt_ms: next }))
        })
    }

    /// The OS refused a download request before any fetch: not a fetch failure, so no failure is
    /// counted, but the item is not offered again before `next_attempt_ms`.
    pub fn record_download_rejection(
        &self,
        root_id: &str,
        item_id: &ItemId,
        version: yadorilink_replica_domain::ids::VersionHash,
        next_attempt_ms: i64,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let failures: i64 = tx
                .query_row(
                    "SELECT failures FROM provider_download_failures \
                     WHERE root_id = ?1 AND item_id = ?2 AND version_hash = ?3",
                    rusqlite::params![root_id, &item_id[..], &version.0[..]],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or(0);
            tx.execute(
                "INSERT OR REPLACE INTO provider_download_failures \
                 (root_id, item_id, version_hash, failures, next_attempt_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![root_id, &item_id[..], &version.0[..], failures, next_attempt_ms],
            )?;
            Ok(())
        })
    }

    /// The item's content arrived: forget its failures.
    pub fn clear_download_failure(
        &self,
        root_id: &str,
        item_id: &ItemId,
    ) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "DELETE FROM provider_download_failures WHERE root_id = ?1 AND item_id = ?2",
                rusqlite::params![root_id, &item_id[..]],
            )?;
            Ok(())
        })
    }

    /// A handoff of `version` was delivered but `version` is no longer the item's current one: the
    /// OS may hold those bytes, so the item is published at `version` again (the derived pending
    /// state then evicts and signals the current version). Only a version that can still be
    /// resolved is recorded. `false` when nothing was changed (the item is gone, `version` is
    /// current after all, or the version cannot be resolved).
    pub fn reopen_stale_handoff(
        &self,
        root_id: &str,
        item_id: &ItemId,
        version: yadorilink_replica_domain::ids::VersionHash,
    ) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            yadorilink_sqlite_runtime::reconcile_provider_liveness(tx)?;
            let row: Option<(String, String)> = tx
                .query_row(
                    "SELECT group_id, path FROM provider_items \
                     WHERE root_id = ?1 AND item_id = ?2 AND live = 1",
                    rusqlite::params![root_id, &item_id[..]],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((group_id, path)) = row else { return Ok(false) };
            match current_version(tx, &group_id, &path)? {
                Some(current) if current.version_hash != version => {}
                _ => return Ok(false),
            }
            if crate::dag_store::get_file_version(tx, &group_id, &version)?.is_none() {
                return Ok(false);
            }
            tx.execute(
                "UPDATE provider_items SET published_version_hash = ?3 \
                 WHERE root_id = ?1 AND item_id = ?2",
                rusqlite::params![root_id, &item_id[..], &version.0[..]],
            )?;
            Ok(true)
        })
    }

    /// The change count a ROOT-level signal still has to announce: provider-visible changes
    /// (a rename, a create, a delete, a parent change) the OS was never told about. `None` when
    /// everything is announced.
    pub fn unannounced_changes(&self, root_id: &str) -> Result<Option<u64>, SyncSqliteError> {
        self.read_settled(|conn| {
            let row: Option<(i64, i64)> = conn
                .query_row(
                    "SELECT change_seq, announced_change_seq FROM provider_roots \
                     WHERE root_id = ?1",
                    [root_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            Ok(row.filter(|(rev, sig)| rev > sig).map(|(rev, _)| rev as u64))
        })
    }

    /// The OS acknowledged a root-level signal sent after `changes` changes had been counted.
    pub fn mark_announced(&self, root_id: &str, changes: u64) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            tx.execute(
                "UPDATE provider_roots SET announced_change_seq = MAX(announced_change_seq, ?2) \
                 WHERE root_id = ?1",
                rusqlite::params![root_id, changes as i64],
            )?;
            Ok(())
        })
    }

    /// What the OS is shown for the item: its PUBLISHED version (content and metadata exactly
    /// as the OS last saw it, rebuilt from the immutable version store), never a newer one
    /// while the fence is on; an unpublished item is served at its current version.
    pub fn served_view(
        &self,
        root_id: &str,
        item_id: &ItemId,
    ) -> Result<Option<ServedView>, SyncSqliteError> {
        self.read_settled(|conn| {
            let row: Option<(String, String, Option<Vec<u8>>)> = conn
                .query_row(
                    "SELECT group_id, path, published_version_hash FROM provider_items \
                     WHERE root_id = ?1 AND item_id = ?2 AND live = 1",
                    rusqlite::params![root_id, &item_id[..]],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((group_id, path, published)) = row else { return Ok(None) };
            match published {
                Some(published) => {
                    let hash = hash_from(&published)?;
                    let version = crate::dag_store::get_file_version(conn, &group_id, &hash)?
                        .ok_or_else(|| {
                            SyncSqliteError::CorruptState(
                                "the published version of an item is gone".into(),
                            )
                        })?;
                    Ok(Some(ServedView { path, version, published: true }))
                }
                None => Ok(current_version(conn, &group_id, &path)?.map(|version| ServedView {
                    path,
                    version,
                    published: false,
                })),
            }
        })
    }

    /// The user's keep-on-device state changed at `path`: the item, everything beneath it and the
    /// folders above it are served differently now (their eviction permission), so the OS is told
    /// to read them again.
    pub fn retention_changed(&self, group_id: &str, path: &str) -> Result<(), SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            Ok(yadorilink_sqlite_runtime::note_retention_changed(tx, group_id, path)?)
        })
    }

    /// Retires an item the OS deleted (its `deleteItem`): the id is dead, so a version that
    /// survived the delete (a newer one the user never saw) is projected as a NEW item.
    pub fn retire_item(&self, root_id: &str, item_id: &ItemId) -> Result<bool, SyncSqliteError> {
        self.database.write_immediate::<_, SyncSqliteError>(|tx| {
            let changed = tx.execute(
                "UPDATE provider_items SET live = 0, published_version_hash = NULL \
                 WHERE root_id = ?1 AND item_id = ?2 \
                 AND live = 1",
                rusqlite::params![root_id, &item_id[..]],
            )?;

            // A retired item's download failures die with it.
            tx.execute(
                "DELETE FROM provider_download_failures WHERE root_id = ?1 AND item_id = ?2",
                rusqlite::params![root_id, &item_id[..]],
            )?;
            Ok(changed > 0)
        })
    }

    /// The version each live item under `path` (inclusive) was PUBLISHED at, keyed by path:
    /// the bound of a user's delete (they deleted what they saw). Items never published are
    /// absent (the caller falls back to the current version).
    pub fn published_bound(
        &self,
        root_id: &str,
        path: &str,
    ) -> Result<
        std::collections::HashMap<String, yadorilink_replica_domain::ids::VersionHash>,
        SyncSqliteError,
    > {
        self.read_settled(|conn| {
            let mut stmt = conn.prepare(
                "SELECT path, published_version_hash FROM provider_items \
                 WHERE root_id = ?1 AND live = 1 AND published_version_hash IS NOT NULL \
                 AND (path = ?2 OR (path > ?2 || '/' AND path < ?2 || '0'))",
            )?;
            let rows: Vec<(String, Vec<u8>)> = stmt
                .query_map(rusqlite::params![root_id, path], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
            rows.into_iter().map(|(p, h)| Ok((p, hash_from(&h)?))).collect()
        })
    }
}

/// The live item at `path`, minted if there is none yet, in the caller's transaction.
pub(crate) fn mint_item_in_tx(
    tx: &rusqlite::Transaction<'_>,
    root_id: &str,
    path: &str,
) -> Result<ItemId, SyncSqliteError> {
    let existing: Option<Vec<u8>> = tx
        .query_row(
            "SELECT item_id FROM provider_items WHERE root_id = ?1 AND path = ?2 AND live = 1",
            rusqlite::params![root_id, path],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(existing) = existing {
        return item_id_from(&existing);
    }
    let group_id: String = tx
        .query_row("SELECT group_id FROM provider_roots WHERE root_id = ?1", [root_id], |r| {
            r.get(0)
        })
        .optional()?
        .ok_or_else(|| SyncSqliteError::NotFound(format!("provider root {root_id}")))?;
    let item_id: ItemId = rand::random();
    let (parent_path, name) = split_parent(path);
    tx.execute(
        "INSERT INTO provider_items (root_id, item_id, group_id, path, parent_path, name) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![root_id, &item_id[..], group_id, path, parent_path, name],
    )?;
    Ok(item_id)
}

pub(crate) fn item_id_from(bytes: &[u8]) -> Result<ItemId, SyncSqliteError> {
    <ItemId>::try_from(bytes)
        .map_err(|_| SyncSqliteError::CorruptState("a provider item id is not 16 bytes".into()))
}

fn insert_root(
    tx: &rusqlite::Transaction<'_>,
    root_id: &str,
    group_id: &str,
    kind: &str,
    display_name: &str,
) -> Result<(), SyncSqliteError> {
    // The declaration lives on the link, in the same transaction as the state row.
    let linked = tx.execute(
        "UPDATE links SET provider_kind = ?2, provider_root_id = ?3 WHERE group_id = ?1",
        rusqlite::params![group_id, kind, root_id],
    )?;
    if linked == 0 {
        return Err(SyncSqliteError::NotFound(format!(
            "group {group_id} has no link to declare a provider root on"
        )));
    }
    tx.execute(
        "INSERT INTO provider_roots (root_id, group_id, kind, display_name) \
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![root_id, group_id, kind, display_name],
    )?;
    // Pauses belong to folder links; none may carry into a provider root.
    crate::paused_items::clear_group_in_tx(tx, group_id)?;
    Ok(())
}

pub(crate) fn request_removal_in_tx(
    tx: &rusqlite::Transaction<'_>,
    root_id: &str,
    group_id: &str,
    display_name: &str,
) -> Result<(), SyncSqliteError> {
    record_removal(tx, root_id, group_id, display_name, "requested", None)
}

fn record_removal(
    tx: &rusqlite::Transaction<'_>,
    root_id: &str,
    group_id: &str,
    display_name: &str,
    state: &str,
    preserved_location: Option<&str>,
) -> Result<(), SyncSqliteError> {
    tx.execute(
        "INSERT INTO provider_removals (root_id, group_id, display_name, state, requested_at, \
         preserved_location) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
         ON CONFLICT(root_id) DO UPDATE SET state = excluded.state, \
         preserved_location = excluded.preserved_location",
        rusqlite::params![root_id, group_id, display_name, state, unix_now(), preserved_location],
    )?;
    Ok(())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Deletes a group's provider state (items, events, placements, apply log, sessions) but NEVER
/// the upload journal, which outlives its root as orphan records.
pub(crate) fn delete_provider_state(
    tx: &rusqlite::Transaction<'_>,
    root_id: &str,
    group: &str,
) -> Result<(), SyncSqliteError> {
    // Keyed on the ROOT being removed: after a rebootstrap the group already has a replacement root
    // whose state must survive the acknowledgement of the old root's removal.
    for table in [
        "provider_handoffs",
        "provider_window_serves",
        "provider_download_failures",
        "provider_apply_log",
        "provider_apply_sessions",
        "provider_change_events",
        "provider_enumerated_parents",
        "provider_items",
    ] {
        tx.execute(&format!("DELETE FROM {table} WHERE root_id = ?1"), [root_id])?;
    }
    tx.execute("DELETE FROM provider_roots WHERE root_id = ?1", [root_id])?;
    // The group-level derived index goes only when no root of the group is left to use it.
    let remaining: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_roots WHERE group_id = ?1)",
        [group],
        |r| r.get(0),
    )?;
    if !remaining {
        tx.execute("DELETE FROM provider_dirs WHERE group_id = ?1", [group])?;
    }
    Ok(())
}

/// Declares the link just inserted for `group_id` a provider root, in the SAME transaction as the
/// link row: mints the root, writes the state row, and derives `install_done` (an empty owner
/// group has nothing to install; a joined group whose native base is already installed is done).
pub fn declare_link_root_in_tx(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    spec: &ProviderLinkSpec,
) -> Result<String, SyncSqliteError> {
    if spec.kind == ProviderKind::None || spec.display_name.trim().is_empty() {
        return Err(SyncSqliteError::InvalidInput(
            "a provider root needs a kind and a non-empty display name".into(),
        ));
    }
    let name_taken: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_roots WHERE display_name = ?1 AND group_id <> ?2)",
        rusqlite::params![spec.display_name, group_id],
        |r| r.get(0),
    )?;
    if name_taken {
        return Err(SyncSqliteError::InvalidInput(format!(
            "a provider folder named '{}' already exists on this device",
            spec.display_name
        )));
    }
    let removing: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_roots WHERE group_id = ?1)",
        [group_id],
        |r| r.get(0),
    )?;
    if removing {
        return Err(SyncSqliteError::InvalidInput(format!(
            "group {group_id} still has a provider folder whose removal is not finished"
        )));
    }
    let root_id = mint_root_id();
    insert_root(tx, &root_id, group_id, spec.kind.as_db_str(), &spec.display_name)?;
    tx.execute(
        "UPDATE links SET creation_digest = ?2 WHERE group_id = ?1",
        rusqlite::params![group_id, spec.creation_digest],
    )?;
    if spec.on_demand {
        tx.execute(
            "UPDATE links SET materialization_policy = ?2 WHERE group_id = ?1",
            rusqlite::params![
                group_id,
                yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand
                    .as_db_str()
            ],
        )?;
    }
    let installed: bool = spec.empty_owner
        || tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM native_author_context WHERE group_id = ?1)",
            [group_id],
            |r| r.get(0),
        )?;
    if installed {
        tx.execute("UPDATE provider_roots SET install_done = 1 WHERE root_id = ?1", [&root_id])?;
    }
    Ok(root_id)
}

/// Replaces the group's provider root by a new one: new `root_id`, same kind and display
/// name, no items and no evidence.
fn rebootstrap_in_tx(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    old_intent: &str,
    preserved_location: Option<&str>,
) -> Result<String, SyncSqliteError> {
    let old: Option<(String, String, String)> = tx
        .query_row(
            "SELECT root_id, kind, display_name FROM provider_roots WHERE group_id = ?1",
            [group_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((old_root, kind, display_name)) = old else {
        return Err(SyncSqliteError::NotFound(format!(
            "group {group_id} has no provider root to rebootstrap"
        )));
    };
    let was_installed: bool = tx.query_row(
        "SELECT install_done FROM provider_roots WHERE root_id = ?1",
        [&old_root],
        |r| r.get(0),
    )?;
    tx.execute("DELETE FROM provider_handoffs WHERE root_id = ?1", [&old_root])?;
    tx.execute("DELETE FROM provider_window_serves WHERE root_id = ?1", [&old_root])?;
    tx.execute("DELETE FROM provider_download_failures WHERE root_id = ?1", [&old_root])?;
    tx.execute("DELETE FROM provider_apply_log WHERE root_id = ?1", [&old_root])?;
    // `provider_pending_ingest` is NOT touched: the journal of an undecided upload outlives its root
    // (an orphan record, never aged out) so teardown can never turn retained bytes into byte loss.
    tx.execute("DELETE FROM provider_apply_sessions WHERE root_id = ?1", [&old_root])?;
    tx.execute("DELETE FROM provider_change_events WHERE root_id = ?1", [&old_root])?;
    tx.execute("DELETE FROM provider_enumerated_parents WHERE root_id = ?1", [&old_root])?;
    tx.execute("DELETE FROM provider_items WHERE root_id = ?1", [&old_root])?;
    tx.execute("DELETE FROM provider_roots WHERE root_id = ?1", [&old_root])?;
    // The old domain's removal is a durable fact: `done` when the host already saw it gone,
    // `requested` when the daemon wants the host to remove it.
    record_removal(tx, &old_root, group_id, &display_name, old_intent, preserved_location)?;
    let root_id = mint_root_id();
    insert_root(tx, &root_id, group_id, &kind, &display_name)?;
    // The completed-install marker is carried to the new root ONLY when the same semantic
    // namespace is completely built (the install was recorded and no projection obligation is
    // open), so only the provider root is being recreated; otherwise the new root waits for its
    // own install like any other.
    let open: i64 = tx.query_row(
        "SELECT COUNT(*) FROM projection_obligations WHERE group_id = ?1",
        [group_id],
        |r| r.get(0),
    )?;
    if was_installed && open == 0 {
        tx.execute("UPDATE provider_roots SET install_done = 1 WHERE root_id = ?1", [&root_id])?;
    }
    Ok(root_id)
}

/// `rename_tree_in_tx` for tests outside this crate, which have no other way to make the
/// semantic rename's provider half happen without a signed emission.
#[cfg(any(test, feature = "test-support"))]
pub fn rename_tree_for_tests(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    from: &str,
    to: &str,
) -> Result<(), SyncSqliteError> {
    rename_tree_in_tx(tx, group_id, from, to)
}

#[cfg(test)]
thread_local! {
    /// Test seam: runs between a read's settle and its snapshot, to inject a concurrent write.
    static AFTER_SETTLE: std::cell::RefCell<Option<Box<dyn Fn()>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn run_after_settle_hook() {
    AFTER_SETTLE.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
}

/// A directory rename keeps every item's id: the items at `from` and below move to
/// the same place under `to`, with the parent index rewritten, in the caller's
/// transaction (so the index never disagrees with the semantic rename). Items
/// already live at `to` or below are retired first (the rename replaces them).
pub(crate) fn rename_tree_in_tx(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    from: &str,
    to: &str,
) -> Result<(), SyncSqliteError> {
    let any: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_items WHERE group_id = ?1 AND live = 1 \
         AND (path = ?2 OR (path > ?2 || '/' AND path < ?2 || '0')))",
        rusqlite::params![group_id, from],
        |r| r.get(0),
    )?;
    if !any {
        return Ok(());
    }
    // A rename never replaces: an item already live at or under the destination is a collision
    // the caller had to rule out (the write path does, in its own transaction). Retiring it here
    // would silently discard an item the user may not have seen.
    let occupied: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_items WHERE group_id = ?1 AND live = 1 \
         AND (path = ?2 OR (path > ?2 || '/' AND path < ?2 || '0')))",
        rusqlite::params![group_id, to],
        |r| r.get(0),
    )?;
    if occupied {
        return Err(SyncSqliteError::InvalidInput(format!(
            "the destination {to:?} holds live provider items; a rename never replaces them"
        )));
    }
    let mut stmt = tx.prepare(
        "SELECT root_id, item_id, path FROM provider_items WHERE group_id = ?1 AND live = 1 \
         AND (path = ?2 OR (path > ?2 || '/' AND path < ?2 || '0')) ORDER BY path",
    )?;
    let moving: Vec<(String, Vec<u8>, String)> = stmt
        .query_map(rusqlite::params![group_id, from], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect::<Result<_, _>>()?;
    drop(stmt);
    for (root_id, item_id, path) in moving {
        let moved_top = path == from;
        let old_parent = split_parent(&path).0.to_owned();
        let new_path = format!("{to}{}", &path[from.len()..]);
        let (parent_path, name) = split_parent(&new_path);
        tx.execute(
            "UPDATE provider_items SET path = ?3, parent_path = ?4, name = ?5 \
             WHERE root_id = ?1 AND item_id = ?2",
            rusqlite::params![root_id, item_id, new_path, parent_path, name],
        )?;
        tx.execute(
            "UPDATE provider_roots SET change_seq = change_seq + 1 WHERE root_id = ?1",
            [&root_id],
        )?;
        // Only the renamed item itself changes parent or name; its descendants keep theirs.
        if moved_top {
            tx.execute(
                "UPDATE provider_items SET generation = generation + 1 \
                 WHERE root_id = ?1 AND item_id = ?2",
                rusqlite::params![root_id, item_id],
            )?;
            // Both folders' child sets changed.
            yadorilink_sqlite_runtime::note_child_set_change(tx, &root_id, parent_path)?;
            yadorilink_sqlite_runtime::note_child_set_change(tx, &root_id, &old_parent)?;
            let new_parent = parent_item_id(tx, &root_id, parent_path)?;
            let old_parent = parent_item_id(tx, &root_id, &old_parent)?;
            let published: bool = tx.query_row(
                "SELECT published_version_hash IS NOT NULL FROM provider_items \
                 WHERE root_id = ?1 AND item_id = ?2",
                rusqlite::params![root_id, item_id],
                |r| r.get(0),
            )?;
            if published
                || parent_is_enumerated(tx, &root_id, &new_parent)?
                || parent_is_enumerated(tx, &root_id, &old_parent)?
            {
                let moved = new_parent != old_parent;
                append_event(
                    tx,
                    &root_id,
                    if moved { "move" } else { "upsert" },
                    &item_id,
                    &new_parent,
                    moved.then_some(old_parent.as_slice()),
                )?;
            }
        }
    }
    Ok(())
}

/// Versions released by the timer that no confirmed handoff has shown the OS fetching yet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Unresolved {
    pub count: u64,
    pub oldest_age_ms: u64,
}

/// What an announcement is: its event's sequence (the revision the signal carries) and the
/// folder the host waits below (empty = the root container).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announced {
    pub seq: u64,
    pub parent_item_id: Vec<u8>,
}

/// `(group, path, published, announced, announce_seq)` of a live item.
type AnnounceRow = (String, String, Option<Vec<u8>>, Option<Vec<u8>>, Option<i64>);

/// The item id of the live item at `parent_path` of the root; the empty id is the root
/// container (`""`), and a parent that has no live item has none either.
fn parent_item_id(
    tx: &rusqlite::Transaction<'_>,
    root_id: &str,
    parent_path: &str,
) -> Result<Vec<u8>, SyncSqliteError> {
    if parent_path.is_empty() {
        return Ok(Vec::new());
    }
    Ok(tx
        .query_row(
            "SELECT item_id FROM provider_items WHERE root_id = ?1 AND path = ?2 AND live = 1",
            rusqlite::params![root_id, parent_path],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or_default())
}

/// Whether the OS has requested the contents of the folder `parent_item_id`.
pub(crate) fn parent_is_enumerated(
    tx: &rusqlite::Transaction<'_>,
    root_id: &str,
    parent_item_id: &[u8],
) -> Result<bool, SyncSqliteError> {
    Ok(tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_enumerated_parents \
         WHERE root_id = ?1 AND parent_item_id = ?2)",
        rusqlite::params![root_id, parent_item_id],
        |r| r.get(0),
    )?)
}

/// Appends one change event with the next sequence of the root (the revision advances once per
/// event) in the caller's transaction, and returns the sequence.
pub(crate) fn append_event(
    tx: &rusqlite::Transaction<'_>,
    root_id: &str,
    kind: &str,
    item_id: &[u8],
    parent_item_id: &[u8],
    old_parent_item_id: Option<&[u8]>,
) -> Result<u64, SyncSqliteError> {
    // The event first, then the revision: the revision only ever advances to a sequence that has
    // its event (the schema refuses any other advance).
    let seq: i64 = tx.query_row(
        "SELECT namespace_revision + 1 FROM provider_roots WHERE root_id = ?1",
        [root_id],
        |r| r.get(0),
    )?;
    tx.execute(
        "INSERT INTO provider_change_events \
         (root_id, seq, kind, item_id, parent_item_id, old_parent_item_id, at_s) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, CAST(strftime('%s', 'now') AS INTEGER))",
        rusqlite::params![root_id, seq, kind, item_id, parent_item_id, old_parent_item_id],
    )?;
    tx.execute(
        "UPDATE provider_roots SET namespace_revision = ?2 WHERE root_id = ?1",
        rusqlite::params![root_id, seq],
    )?;
    Ok(seq as u64)
}

/// [`ProviderRepository::record_handoff`] inside the caller's transaction: the authoring path
/// records the version it commits (the OS supplied those bytes) in the transaction of the change.
pub(crate) fn record_handoff_in_tx(
    tx: &rusqlite::Transaction<'_>,
    root_id: &str,
    item_id: &ItemId,
    version: yadorilink_replica_domain::ids::VersionHash,
) -> Result<Option<u64>, SyncSqliteError> {
    record_ledger_in_tx(tx, HANDOFFS, root_id, item_id, version)
}

/// The ledger of whole-version handoffs.
const HANDOFFS: &str = "provider_handoffs";
/// The ledger of versions served to the OS in windows only.
const WINDOW_SERVES: &str = "provider_window_serves";

fn record_ledger_in_tx(
    tx: &rusqlite::Transaction<'_>,
    table: &'static str,
    root_id: &str,
    item_id: &ItemId,
    version: yadorilink_replica_domain::ids::VersionHash,
) -> Result<Option<u64>, SyncSqliteError> {
    yadorilink_sqlite_runtime::reconcile_provider_liveness(tx)?;
    let row: Option<(String, String)> = tx
        .query_row(
            "SELECT group_id, path FROM provider_items \
                 WHERE root_id = ?1 AND item_id = ?2 AND live = 1",
            rusqlite::params![root_id, &item_id[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((group_id, path)) = row else { return Ok(None) };
    match current_version(tx, &group_id, &path)? {
        Some(current) if current.version_hash == version => {}
        _ => return Ok(None),
    }
    let content_sig: String = tx.query_row(
        "SELECT size || '|' || blocks_json || '|' || record_kind || '|' \
                    || COALESCE(CAST(symlink_target AS TEXT), '') \
             FROM files WHERE group_id = ?1 AND path = ?2 AND state = 'current'",
        rusqlite::params![group_id, path],
        |r| r.get(0),
    )?;
    tx.execute(
        "UPDATE provider_roots SET latest_evidence_seq = latest_evidence_seq + 1 \
             WHERE root_id = ?1",
        [root_id],
    )?;
    let seq: i64 = tx.query_row(
        "SELECT latest_evidence_seq FROM provider_roots WHERE root_id = ?1",
        [root_id],
        |r| r.get(0),
    )?;
    tx.execute(
        &format!(
            "INSERT OR REPLACE INTO {table} \
                (root_id, item_id, version_hash, content_sig, evidence_seq) \
             VALUES (?1, ?2, ?3, ?4, ?5)"
        ),
        rusqlite::params![root_id, &item_id[..], &version.0[..], content_sig, seq],
    )?;
    Ok(Some(seq as u64))
}

#[cfg(test)]
mod tests;
