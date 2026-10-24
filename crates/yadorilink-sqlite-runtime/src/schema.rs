//! Schema creation and version checking for the sync index database. Pure,
//! stateless functions -- no `SyncState` fields live here;
//! `SyncState::open`/`open_in_memory` call [`init_schema`] once per freshly
//! opened connection.

use rusqlite::{Connection, OptionalExtension};

use crate::error::DatabaseError;

/// The on-disk schema's version, stored in SQLite's `PRAGMA user_version`.
///
/// There is one schema, not a ladder: [`init_schema`] creates the current
/// shape outright, and [`check_schema_version_supported`] refuses any
/// database stamped with a different version rather than upgrading it. A
/// pre-release build does not carry data migrations -- the user deletes the
/// index database and re-imports the folder.
///
/// Bump this whenever the created shape changes at all, since the previous
/// shape becomes unopenable by this binary and unopenable is the intended
/// outcome.
pub const SCHEMA_VERSION: i32 = 133;

/// Reads `PRAGMA user_version` and refuses anything that is not exactly
/// this binary's [`SCHEMA_VERSION`], in either direction: a newer stamp is
/// an older binary opening state it does not understand, and an older
/// stamp is a database this pre-release codebase has no migration for.
///
/// `0` is accepted here because it is also what a brand-new file reports,
/// and this function alone cannot tell that from a database an
/// un-stamping build left behind. [`check_replica_schema_generation`] is
/// the entry point that can, and is what the replica index opens through.
pub fn check_schema_version_supported(conn: &Connection) -> Result<(), DatabaseError> {
    let on_disk_version: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if on_disk_version > SCHEMA_VERSION {
        return Err(DatabaseError::UnsupportedSchemaDowngrade {
            on_disk_version,
            supported_version: SCHEMA_VERSION,
        });
    }
    if on_disk_version != 0 && on_disk_version < SCHEMA_VERSION {
        return Err(DatabaseError::CorruptSchema(format!(
            "index database schema v{on_disk_version} predates this build's v{SCHEMA_VERSION}, \
             and pre-release builds do not migrate old databases -- delete the index database \
             and re-import the folder"
        )));
    }
    Ok(())
}

/// The replica index database's own generation policy, for its owner to
/// call as the FIRST thing in its `schema_init` -- before any table is
/// created, which is what makes the distinction below possible.
///
/// On top of [`check_schema_version_supported`], this refuses the one case
/// that function cannot see: `user_version == 0` on a database that
/// already holds tables. A brand-new file reports `0` and has none, so the
/// two are distinguishable exactly here and nowhere later. Accepting `0`
/// unconditionally is how a database written before this build stamped
/// versions at all would have been adopted in place, silently, with no
/// migration and no check on its actual shape.
pub fn check_replica_schema_generation(conn: &Connection) -> Result<(), DatabaseError> {
    check_schema_version_supported(conn)?;
    let on_disk_version: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if on_disk_version != 0 {
        return Ok(());
    }
    let tables: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' \
         AND name NOT LIKE 'sqlite_%' AND name <> 'writer_generation'",
        [],
        |r| r.get(0),
    )?;
    if tables > 0 {
        return Err(DatabaseError::CorruptSchema(
            "index database carries tables but no schema version stamp, so this build cannot \
             establish what shape it is in -- delete the index database and re-import the folder"
                .to_string(),
        ));
    }
    Ok(())
}

/// This crate's own core schema: its tables, indexes and triggers, in one
/// ordered DDL sequence. Takes only a raw SQLite [`Connection`] and knows
/// nothing about any caller's domain concepts; the `files` authoring
/// triggers reference `native_authoring_witness`, which the caller
/// (`yadorilink-sync-sqlite`'s replica schema) creates. It does not
/// check or stamp `user_version`: the replica open does that, in the same
/// transaction.
pub fn init_schema(conn: &Connection) -> Result<(), DatabaseError> {
    create_tables_and_links_triggers(conn)?;
    files_authoring_triggers(conn)?;
    create_root_set_generation(conn)?;
    refuse_unverified_authoring_rows(conn, unverified_authoring_identity)
}

#[allow(
    clippy::too_many_lines,
    reason = "one ordered DDL sequence: the `files` primary-key rebuild, the idempotent \
              CREATE TABLE/ALTER TABLE DDL and the `links` triggers must run in exactly this \
              order against the same connection, and each step's comment explains the \
              dependency on the step before it; it stays private so that only `init_schema` \
              sequences it"
)]
fn create_tables_and_links_triggers(conn: &Connection) -> Result<(), DatabaseError> {
    // Widening `files`' primary key
    // from `(group_id, path)` to `(group_id, path, version_seq)` is not
    // expressible as an `ALTER TABLE... ADD COLUMN` — SQLite has no
    // syntax to change a declared primary key in place. Must run
    // *before* the `CREATE TABLE IF NOT EXISTS`/`ALTER TABLE` migration
    // below, which only ever adds columns to whatever `files` table
    // already exists; see the function's own doc comment for the
    // rebuild it performs (a no-op on a brand-new database, and
    // idempotent on one already migrated).
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS files (
            group_id          TEXT NOT NULL,
            path              TEXT NOT NULL,
            size              INTEGER NOT NULL,
            mtime_unix_nanos  INTEGER NOT NULL,
            blocks_json       TEXT NOT NULL,
            deleted           INTEGER NOT NULL DEFAULT 0,
            -- `version_seq` is a per-`(group_id, path)` monotonically
            -- increasing counter; exactly one row per `(group_id, path)`
            -- has `state = 'current'` at a time.
            version_seq       INTEGER NOT NULL DEFAULT 1,
            state             TEXT NOT NULL DEFAULT 'current',
            origin_device_id  TEXT,
            -- The NativeState head this row was materialized from
            -- (`NativeRowIdentity`, one canonical blob, provenance first).
            -- NULL when the row was not produced under native authority:
            -- never inferred from a version or a path.
            native_authoring_identity BLOB,
            materialization_state TEXT NOT NULL DEFAULT 'remote',
            record_kind       TEXT NOT NULL DEFAULT 'file',
            symlink_target    BLOB,
            -- -1 means "no Unix permission info".
            unix_mode         INTEGER NOT NULL DEFAULT -1,
            held_reason       TEXT,
            held_since_unix_nanos INTEGER,
            -- What a hold that waits on the file itself was decided
            -- against (its observed identity, the path's mutation fence and
            -- the desired version), so an unchanged path is not re-examined.
            -- NULL for every other hold; cleared with `held_reason`.
            held_key          TEXT,
            symlink_out_of_root INTEGER NOT NULL DEFAULT 0,
            placeholder_dev   INTEGER,
            placeholder_ino   INTEGER,
            placeholder_provider_kind TEXT,
            xattrs_json       TEXT NOT NULL DEFAULT '[]',
            admitted_at_unix_nanos INTEGER,
            -- On a `trashed` row whose deletion was one part of a recursive
            -- delete or directory rename: that operation's author and id.
            -- Kept on the row itself so restoring the whole operation does
            -- not depend on the deleting change still being retained.
            -- NULL for every other row.
            trashed_by_operation_author TEXT,
            trashed_by_operation_id     BLOB,
            -- The path's name-collision keys, written with the row by every
            -- writer that sets `path` (the shared folds, so the hazard check
            -- is an index lookup rather than a scan of the group). Empty only
            -- on a row inserted by hand outside those writers.
            case_fold_key      TEXT NOT NULL DEFAULT '',
            canonical_fold_key TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (group_id, path, version_seq)
        );
        CREATE INDEX IF NOT EXISTS files_case_fold_key
            ON files (group_id, case_fold_key) WHERE state = 'current' AND deleted = 0;
        CREATE INDEX IF NOT EXISTS files_canonical_fold_key
            ON files (group_id, canonical_fold_key) WHERE state = 'current' AND deleted = 0;
        -- The live rows whose path carries the conflict-copy marker anywhere,
        -- so the retirement pass reads only these instead of decoding the
        -- whole group. A superset of the filename-only rule: the reader
        -- applies that rule itself. The query must repeat this predicate
        -- verbatim for the planner to use the index.
        CREATE INDEX IF NOT EXISTS files_conflict_copy_candidates
            ON files (group_id, path)
            WHERE state = 'current' AND deleted = 0
              AND instr(path, ' (conflicted copy, ') > 0;

        CREATE TABLE IF NOT EXISTS links (
            local_path TEXT PRIMARY KEY,
            group_id   TEXT NOT NULL,
            paused     INTEGER NOT NULL DEFAULT 0,
            materialization_policy TEXT NOT NULL DEFAULT 'eager',
            windows_symlink_opt_in INTEGER NOT NULL DEFAULT 0,
            orphaned   INTEGER NOT NULL DEFAULT 0,
            root_token TEXT,
            -- The provider declaration of this link: `none` (the direct-filesystem path),
            -- or a provider kind plus the `provider_roots.root_id` it names. A link that
            -- declares a provider whose `provider_roots` row is missing or names another
            -- root is CORRUPT state (never read as a plain directory).
            provider_kind TEXT NOT NULL DEFAULT 'none',
            provider_root_id TEXT,
            -- A provider link's creation request, bound to its token (the locator): a digest of the
            -- display name, group and policy, so a retry of the SAME token with a different request
            -- is refused instead of answered with the old link.
            creation_digest TEXT,
            -- Set by departed-root recovery: while 1, a full scan is
            -- additive (indexes what it finds, emits no deletions) so the
            -- departed root's paths survive and can hydrate from a peer.
            -- Cleared after one clean full scan.
            suppress_tombstones_until_scan INTEGER NOT NULL DEFAULT 0,
            -- The volume the link root was on when its index was last proven
            -- consistent with it (`device_boundary::root_volume_identity`: the
            -- filesystem's own UUID or fsid, a share's source, the Windows volume
            -- serial, or `unknown:<mount>` for a filesystem without one: only
            -- that one mount, confirmed by the user, matches). The folder is
            -- written, and a tombstone authored, only while the root is still on
            -- this volume: an unmounted volume or a swapped root volume leaves an
            -- empty directory that must not receive files or read as a mass
            -- deletion. NULL on provider links and until the link's first safe
            -- full scan adopts it (that scan emits no deletes).
            capture_volume_identity TEXT
        );

        CREATE TABLE IF NOT EXISTS duplicate_recovery_paths (
            group_id TEXT NOT NULL,
            path     TEXT NOT NULL,
            PRIMARY KEY (group_id, path)
        );

        -- One outstanding local link with an unconfirmed coordination-plane
        -- activation -- the crash-safety net for a create/join whose local
        -- link is already committed but whose matching server-side
        -- activation was never confirmed (the caller was killed in that
        -- exact window). Keyed by `operation_id` (idempotent: re-recording after a retry
        -- that reaches the same point again is a plain overwrite, not a
        -- duplicate entry). Lives in the same database as `links` so
        -- `add_link_with_pending_enrollment` can write both in one
        -- transaction -- a local link is never committed without a durable
        -- trace of the coordination-side enrollment it depends on.
        CREATE TABLE IF NOT EXISTS pending_enrollments (
            operation_id TEXT PRIMARY KEY,
            kind         TEXT NOT NULL,
            group_id     TEXT NOT NULL,
            device_id    TEXT NOT NULL,
            local_path   TEXT NOT NULL
        );

        -- Anti-rollback watermark for each group's signed policy log (see
        -- `PolicyWatermark`). One row per group; the daemon advances it
        -- only forward and rejects any snapshot that would move it back,
        -- so a replayed older-but-valid chain cannot survive a restart. A
        -- new additive table, so a bare `CREATE TABLE IF NOT EXISTS` is the
        -- whole migration, like `files`/`links` themselves.
        CREATE TABLE IF NOT EXISTS group_policy_watermark (
            group_id                  TEXT PRIMARY KEY,
            highest_verified_seq      INTEGER NOT NULL,
            highest_verified_head     BLOB NOT NULL,
            authority_key_generation  INTEGER NOT NULL,
            -- SHA-256 of the authority public key at that head. Required:
            -- the only writer is a completed verification, which always has
            -- it, so there is no "unknown fingerprint" state for the
            -- verifier to treat leniently.
            authority_key_fingerprint BLOB NOT NULL
        );
        -- Durable journal of local paths detected as changed but not yet
        -- fully processed into the index + native state. A path is recorded
        -- here *before* the read/blockify/put/index+delta step runs and only
        -- deleted once that step commits, so a crash, restart, or a
        -- multi-second block-store fault (disk-full / EIO) mid-processing
        -- can never silently drop an already-detected local edit: the row
        -- survives and the daemon re-drives it (startup rescan + retry).
        -- One row per `(group_id, path)`; a fresher watcher event for the
        -- same path supersedes `change_kind`/`observed_at_unix_nanos` (via
        -- `INSERT ... ON CONFLICT`) rather than accumulating history, while
        -- `first_seen_unix_nanos` records when the divergence was first
        -- noticed and `attempts`/`last_error` accrue across retries for
        -- diagnosis. A new additive table, so a bare `CREATE TABLE IF NOT
        -- EXISTS` is the whole migration, like `files`/`links` themselves.
        CREATE TABLE IF NOT EXISTS local_dirty_paths (
            group_id               TEXT NOT NULL,
            path                   TEXT NOT NULL,
            change_kind            TEXT NOT NULL,
            first_seen_unix_nanos  INTEGER NOT NULL,
            observed_at_unix_nanos INTEGER NOT NULL,
            attempts               INTEGER NOT NULL DEFAULT 0,
            last_error             TEXT,
            PRIMARY KEY (group_id, path)
        );

        -- Restore spans an atomic filesystem rename and a SQLite index
        -- transaction. Persist the intended new current row before the
        -- rename; completing the index upsert deletes this row in the
        -- same transaction, making startup reconciliation idempotent.
        CREATE TABLE IF NOT EXISTS restore_operations (
            operation_id      TEXT PRIMARY KEY,
            group_id          TEXT NOT NULL,
            path              TEXT NOT NULL,
            target_version_seq INTEGER NOT NULL,
            expected_current_version_seq INTEGER,
            state             TEXT NOT NULL,
            size              INTEGER NOT NULL,
            mtime_unix_nanos  INTEGER NOT NULL,
            blocks_json       TEXT NOT NULL,
            origin_device_id  TEXT NOT NULL,
            -- The native head the restore authored (`NativeRowIdentity`
            -- bytes), so the committed row shows it.
            authoring_native_identity BLOB,
            created_at_unix_nanos INTEGER NOT NULL,
            record_kind       TEXT NOT NULL DEFAULT 'file',
            symlink_target    BLOB,
            symlink_out_of_root INTEGER NOT NULL DEFAULT 0,
            -- `-1` = no Unix permission info (see `SCHEMA_VERSION` v23's
            -- own doc comment); `0..=0o777` = actual replicated mode bits.
            unix_mode          INTEGER NOT NULL DEFAULT -1,
            -- See `files.xattrs_json`'s own comment (`SCHEMA_VERSION` v24).
            xattrs_json        TEXT NOT NULL DEFAULT '[]'
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_restore_operations_path
            ON restore_operations(group_id, path);

        -- One row per folder-rewind execution: its progress, never the
        -- namespace's truth (what a rewind changed is the ordinary signed
        -- changes it authored). No per-path state: an interrupted run is
        -- never resumed, so startup decides from this row alone (a run that
        -- committed a chunk becomes `needs_replan`, any other unfinished run
        -- `failed` / `interrupted`). `state` and `failure_kind` hold the
        -- `RewindRunState` / `RewindFailureKind` strings; `failure_kind` is
        -- set exactly when `state` is `failed`, and `unavailable_files` is
        -- the N of a `content_unavailable` failure.
        CREATE TABLE IF NOT EXISTS rewind_runs (
            run_id                TEXT PRIMARY KEY,
            group_id              TEXT NOT NULL,
            target_unix_nanos     INTEGER NOT NULL,
            plan_id               BLOB NOT NULL,
            state                 TEXT NOT NULL,
            chunks_done           INTEGER NOT NULL DEFAULT 0,
            unavailable_files     INTEGER NOT NULL DEFAULT 0,
            failure_kind          TEXT,
            -- JSON array of device ids: the members not connected when a
            -- `transient` run could not gather its content. A fact of that
            -- attempt, read long after it ended, so it cannot be derived.
            offline_devices_json  TEXT NOT NULL DEFAULT '[]',
            -- Progress and summary: how many chunks the run commits in all
            -- (set at `prefetched`), and the paths committed chunks
            -- restored and removed. Advanced in the same transaction as
            -- each chunk's signed change.
            chunks_total          INTEGER NOT NULL DEFAULT 0,
            restored              INTEGER NOT NULL DEFAULT 0,
            deleted               INTEGER NOT NULL DEFAULT 0,
            created_at_unix_nanos INTEGER NOT NULL,
            CHECK ((state = 'failed') = (failure_kind IS NOT NULL))
        );
        -- At most one unfinished run per group, durably: a second execution
        -- of the same group is refused even across a restart that has not
        -- yet settled the first.
        CREATE UNIQUE INDEX IF NOT EXISTS idx_rewind_runs_one_active
            ON rewind_runs(group_id)
            WHERE state IN ('planned', 'prefetched', 'committing');

        -- A coordination-service-issued complete-copy-handoff lease this
        -- device (as the handoff TARGET) is currently holding, pinning the
        -- exact `(path, version_seq)` rows its own local readiness check
        -- verified at request time against this device's retention sweep
        -- (`expire_superseded_and_trashed_versions`) until the source's
        -- role-loss commit confirms the lease or it is released/expires.
        -- See `HandoffLease`'s doc comment for the full lifecycle. One row
        -- per outstanding lease; a device normally holds at most one
        -- lease per `group_id` at a time, but this is not enforced here
        -- (a stale, not-yet-swept row for an old lease is simply ignored
        -- once its `state`/`expires_at_unix` no longer qualify it as
        -- pinning). A new additive table, so a bare `CREATE TABLE IF NOT
        -- EXISTS` is the whole migration, like `local_dirty_paths` above.
        CREATE TABLE IF NOT EXISTS handoff_leases (
            lease_id             TEXT PRIMARY KEY,
            group_id             TEXT NOT NULL,
            root_digest          BLOB NOT NULL,
            state                TEXT NOT NULL DEFAULT 'provisional',
            pinned_versions_json TEXT NOT NULL,
            created_at_unix      INTEGER NOT NULL,
            expires_at_unix      INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_handoff_leases_group_id ON handoff_leases(group_id);

        -- A durable journal of an in-flight complete-copy role-loss
        -- operation (demote/unlink) this device is driving as the
        -- SOURCE device: the coordination service role-loss commit
        -- (`commit_handoff_role_loss`) and this device's own matching
        -- local policy/link change are two separate commits, and a
        -- crash -- or a local failure landing AFTER the Worker commit
        -- already succeeded -- must not be left as a silent split
        -- state (Worker thinks this device demoted; local storage
        -- still thinks it's eager). This row is written BEFORE the
        -- Worker commit and only removed once the operation's outcome
        -- is fully settled, one way or the other -- see
        -- `RoleLossOperation`'s doc comment for the full state
        -- machine. A new additive table, so a bare `CREATE TABLE IF
        -- NOT EXISTS` is the whole migration, like `handoff_leases`
        -- above.
        CREATE TABLE IF NOT EXISTS role_loss_operations (
            operation_id     TEXT PRIMARY KEY,
            group_id         TEXT NOT NULL,
            source_device_id TEXT NOT NULL,
            target_device_id TEXT NOT NULL,
            -- Required: `open_role_loss_operation` is the only writer and
            -- always supplies it. A row without one cannot be compensated.
            lease_id         TEXT NOT NULL,
            worker_membership_generation INTEGER,
            action           TEXT NOT NULL,
            state            TEXT NOT NULL,
            local_path       TEXT,
            attempts         INTEGER NOT NULL DEFAULT 0,
            created_at_unix  INTEGER NOT NULL,
            updated_at_unix  INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_role_loss_operations_state
            ON role_loss_operations(state);
        -- A durable journal for an account-membership operation this
        -- device drives against another device (revoke from one group,
        -- or remove from the whole account): unlike
        -- `role_loss_operations` above (this device's OWN demotion,
        -- always one group/lease), a single removal here can span
        -- several groups at once (account-wide `handoff-remove`), so
        -- `group_ids`/`target_device_ids`/`lease_ids` are JSON arrays,
        -- index-parallel to each other. A row is written whenever the
        -- coordination-plane commit's outcome is ambiguous (so the
        -- caller must not release tickets or fall through to a plain
        -- revoke/remove — the Worker may already have committed) or
        -- when `--force` proceeds without a verified list of groups at
        -- risk (`state = 'unknown-scope'`, `group_ids = []`) so
        -- `status` can keep reporting degraded until the scope is
        -- known. A new additive table, so a bare `CREATE TABLE IF NOT
        -- EXISTS` is the whole migration, like `role_loss_operations`
        -- above.
        CREATE TABLE IF NOT EXISTS membership_operations (
            operation_id      TEXT PRIMARY KEY,
            action            TEXT NOT NULL,
            commit_mode       TEXT NOT NULL DEFAULT 'plain-revoke',
            removed_device_id TEXT NOT NULL,
            group_ids         TEXT NOT NULL,
            target_device_ids TEXT NOT NULL,
            lease_ids         TEXT NOT NULL,
            state             TEXT NOT NULL,
            durability_scope  TEXT NOT NULL DEFAULT 'known',
            latch_group_ids   TEXT NOT NULL DEFAULT '[]',
            last_error        TEXT,
            created_at_unix   INTEGER NOT NULL,
            updated_at_unix   INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_membership_operations_state
            ON membership_operations(state);
        -- Force overrides must remain visible after daemon restart until
        -- a later positive whole-group durability check clears them.
        CREATE TABLE IF NOT EXISTS durability_unknown_latches (
            group_id TEXT PRIMARY KEY
        );
        -- Durable journal of an in-flight materialization write: one row
        -- per `(group_id, path)` whose on-disk content a
        -- temp-write-then-rename is CURRENTLY producing but has not yet
        -- finished and fsynced into place. The row is written BEFORE that
        -- write begins and deleted only AFTER it completes, so startup
        -- repair can tell a genuine crash-mid-materialization (intent
        -- still present => the indexed blocks must be re-assembled onto
        -- disk) apart from a file the user deleted or renamed while the
        -- daemon was stopped (no intent => a real offline deletion that
        -- must propagate as a tombstone, never be silently reconstructed
        -- from the index). `PRAGMA synchronous = FULL` (set at open) makes
        -- the intent durable before the disk write starts, which is what
        -- makes the disambiguation crash-safe. One row per
        -- `(group_id, path)`; a fresh write for the same path overwrites
        -- the previous intent via `INSERT ... ON CONFLICT`. A new additive
        -- table, so a bare `CREATE TABLE IF NOT EXISTS` is the whole
        -- migration, like `local_dirty_paths`/`restore_operations` above.
        --
        -- `kind` says which obligation the row is. `write` (the default) is the
        -- materialization above. `structural_mkdir` is the first phase of a
        -- `mkdir` the materializer makes only to hold descendants: it carries the
        -- path's mutation fence as the intent bumped it in `mutation_generation`
        -- (completion is refused once anything else has moved the fence), an
        -- empty `target_version_hash`, and is resolved by the writer on every
        -- exit, or at startup and link start when the process died. A path can
        -- carry one row of each kind at once.
        CREATE TABLE IF NOT EXISTS materialization_intents (
            group_id              TEXT NOT NULL,
            path                  TEXT NOT NULL,
            kind                  TEXT NOT NULL DEFAULT 'write',
            target_version_hash   BLOB NOT NULL,
            created_at_unix_nanos INTEGER NOT NULL,
            mutation_generation   INTEGER,
            PRIMARY KEY (group_id, path, kind)
        );
        -- The temp files writers are creating or have not yet renamed away or
        -- removed. A row is written BEFORE its file is created and deleted
        -- AFTER the file is gone, so the rows are exactly the temp files a
        -- crash can have left behind; recovery removes the file each row
        -- names and the row, and never looks at a file name to decide
        -- anything. One row per temp file (not per path): a newer write of
        -- the same path replaces the path's intent, but not the earlier
        -- write's temp file. `tmp_path` is the absolute path as the link
        -- table's root spelled it.
        CREATE TABLE IF NOT EXISTS materialization_tmp_files (
            group_id TEXT NOT NULL,
            tmp_path TEXT NOT NULL,
            PRIMARY KEY (group_id, tmp_path)
        );
        -- The directories a durable removal moved aside and could not put back
        -- (a child appeared meanwhile and something else took the name): the
        -- directory and its child stand under the reserved name at
        -- `dir_path` (absolute, as the link root spelled it) and nothing was
        -- deleted. Written when that happens, so the user can be told; status
        -- counts the rows whose path still stands. A row is kept when its path
        -- is gone (an unmounted volume looks the same).
        CREATE TABLE IF NOT EXISTS stranded_directories (
            group_id TEXT NOT NULL,
            dir_path TEXT NOT NULL,
            PRIMARY KEY (group_id, dir_path)
        );
        -- The content targets of earlier writes of a path that a newer
        -- write's intent replaced before they were proven. Such a write may
        -- have renamed its bytes onto disk and then lost its proof commit
        -- (the path moved on meanwhile), so while the newer intent is open
        -- these are content this daemon itself may have put there, never a
        -- local edit. Cleared with the path's intent.
        CREATE TABLE IF NOT EXISTS materialization_replaced_targets (
            group_id            TEXT NOT NULL,
            path                TEXT NOT NULL,
            target_version_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, path, target_version_hash)
        );
        -- A durable backstop for the one enrollment-rollback path that
        -- had none: if `link()` fails during create/join AND the
        -- immediate cancel-with-retries also fails, NOTHING is written
        -- anywhere else -- the journal is opened BEFORE remote prepare is
        -- ever called, not just as a late backstop for a `link()`
        -- failure: `PreparePending` covers the window before the
        -- coordination plane has even heard of this operation,
        -- `Prepared` the window after prepare confirms a `group_id` but
        -- before the local link/pending_enrollment handoff commits,
        -- `Transferred` the brief window between that handoff commit and
        -- this row's own cleanup delete, and `CancelPending` a `link()`
        -- failure needing remote cancellation -- durable and retried
        -- until CONFIRMED, never a late best-effort insert. `group_id`
        -- is nullable (a `Create` row has none until prepare confirms
        -- one); `group_name` is only meaningful for a `Create` row still
        -- in `PreparePending` (needed to resend the exact same prepare
        -- request). `RecoveryBlocked` (see `membership_operations`'
        -- sibling state of the same name) marks a row automatic recovery
        -- must never touch again: an operation_id conflict, a malformed
        -- row, or an identity mismatch. Same shape (and same
        -- no-migration, refuse-at-open policy) as `membership_operations`.
        CREATE TABLE IF NOT EXISTS enrollment_operations (
            operation_id    TEXT PRIMARY KEY,
            kind            TEXT NOT NULL,
            group_id        TEXT,
            group_name      TEXT,
            device_id       TEXT NOT NULL,
            local_path      TEXT NOT NULL,
            storage_mode    TEXT NOT NULL,
            state           TEXT NOT NULL,
            last_error      TEXT,
            attempts        INTEGER NOT NULL DEFAULT 0,
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL,
            -- What this operation's link commit did to the `links` row,
            -- written in that commit's transaction so crash recovery can
            -- undo exactly that and nothing more: NULL before the commit,
            -- 'inserted' for a new row, 'updated' for a row that already
            -- existed at the path for the same group (a re-join), with the
            -- prior values of the columns a re-link and its setup change.
            -- The row's `root_token` is never among them: a re-link never
            -- touches it, so an undo leaves it where it was.
            link_row_write                 TEXT,
            prior_link_paused              INTEGER,
            prior_link_orphaned            INTEGER,
            prior_link_policy              TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_enrollment_operations_state
            ON enrollment_operations(state);
        -- Durable record of a
        -- peer EXPLICITLY, definitively refusing a fetch for lack of
        -- verified provenance on the EXACT current version
        -- (`FetchOutcome::Rejected { reason: NoVerifiedProvenance }`) --
        -- deliberately distinct both from a transient miss
        -- (`NotFound`/`TimedOut`/`Busy`) and from any OTHER rejection
        -- reason (unauthorized, malformed request, etc.), neither of
        -- which writes a row here: only a rejection that specifically
        -- proves "this peer does not hold this exact version's bytes" is
        -- evidence of unobtainability. This is keyed by `version_hash`,
        -- not just `path`: a refusal recorded against an OLDER version
        -- must never be read as evidence about a NEWER version that
        -- superseded it (a stale-refusal false positive: `path` alone
        -- conflates every version a file has ever had). This is the evidence
        -- `known_unobtainable_required_
        -- content` (`DurabilityFacts`) needs to positively confirm no
        -- CURRENTLY authorized peer can serve the CURRENT version's
        -- content, rather than merely inferring it from
        -- connectivity/timing. One row per `(group_id, path, version_
        -- hash, peer_device_id)`; a fresh rejection overwrites the
        -- previous one via `INSERT ... ON CONFLICT`, and a later
        -- successful fetch of the SAME version from the SAME peer
        -- deletes any prior refusal row for it (see `ensure_blocks_
        -- present`'s success arm) -- old evidence never outlives being
        -- proven wrong. A new additive table, so a bare `CREATE TABLE IF
        -- NOT EXISTS` is the whole migration, like `materialization_
        -- intents`/`enrollment_operations` above.
        CREATE TABLE IF NOT EXISTS block_fetch_refusals (
            group_id              TEXT NOT NULL,
            path                  TEXT NOT NULL,
            version_hash          TEXT NOT NULL,
            peer_device_id        TEXT NOT NULL,
            reason                TEXT NOT NULL,
            refused_at_unix_nanos INTEGER NOT NULL,
            PRIMARY KEY (group_id, path, version_hash, peer_device_id)
        );

        -- The instant this device's own *continuous* local file history for
        -- a group begins, when that history started somewhere other than at
        -- this device's own first sight of each path. One event writes it, at
        -- the moment it happens:
        --
        --   * LINKING a group this device did not originate and holds no
        --     files for yet -- both link commits that can name such a group
        --     (`add_link_with_pending_enrollment_and_begin_setup` with a
        --     `Join` marker, and the marker-less `add_link` behind
        --     `share accept`/`yadorilink link`). Every path the group
        --     already holds arrives afterwards, and `upsert_file_in_tx`
        --     numbers a path it is seeing for the first time from
        --     `version_seq = 1` however much history that path already has
        --     elsewhere.
        --
        -- After it, a row's `version_seq` says nothing about when THIS
        -- device first saw the path.
        --
        -- Read only by the rewind planning layer, which needs it to decide
        -- whether the evidence is usable: below this instant its own `version_seq` evidence
        -- describes someone else's history and cannot be reasoned from, so
        -- the honest answer for a target that early is "no answer here"
        -- rather than an inference. At or above it, the group's local
        -- history is this device's own unbroken record and the inference is
        -- sound. No row means this device originated the group locally, so
        -- its history really does run back to each path's own first version.
        --
        -- One row per group, overwritten (never accumulated) by each such
        -- event, because only the most recent one bounds the history that
        -- actually survives. Deliberately stores the instant alone, with no
        -- cause attached. A new additive table, so a bare `CREATE TABLE IF NOT
        -- EXISTS` is the whole migration, like `group_policy_watermark`
        -- above.
        CREATE TABLE IF NOT EXISTS group_local_history_floor (
            group_id         TEXT PRIMARY KEY,
            floor_unix_nanos INTEGER NOT NULL
        );

        -- The per-path counterpart of `group_local_history_floor`: one row
        -- per path whose every `files` row this device has erased (the
        -- ignore sweep's `FileIndexRepository::remove_file`). The erasure
        -- takes the path's admission timestamps with it, and a later
        -- re-index numbers the path from `version_seq = 1` again, so its
        -- surviving rows no longer reach back to its own first version.
        --
        -- Read only by the rewind planning layer: for a path listed here,
        -- "no row at or before the target and `version_seq` starts at 1" is
        -- not evidence that the path did not exist yet, so the answer is
        -- "no answer here" rather than `Delete`. A listed path with no
        -- `files` row at all (erased and never indexed again) is part of
        -- the plan too: before `erased_at_unix_nanos` this device held it
        -- and cannot say what it held, so a target that early is
        -- unanswerable unless the path is still excluded from sync. At or
        -- after it the path had no entry here then and has none now.
        -- `erased_at_unix_nanos` is the latest erasure (a later one
        -- replaces it), or `i64::MAX` when the clock could not be read, so
        -- every target reads as before it. Never removed: the rows it
        -- stands in for never come back.
        CREATE TABLE IF NOT EXISTS path_local_history_erased (
            group_id             TEXT NOT NULL,
            path                 TEXT NOT NULL,
            erased_at_unix_nanos INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );

        -- The last authorization a live netmap gave this device about its
        -- peers, kept so a restart taken while the coordination plane is
        -- unreachable can go on talking to peers that plane already
        -- authorized. A last-known-good snapshot, NOT an authority: every
        -- row here was written by a live netmap application and is replaced
        -- or deleted by the next one, so this can only ever repeat a
        -- decision the plane made, never make one.
        --
        -- One row per peer device. `signing_key` is that device's pinned
        -- Ed25519 key, which is also its endpoint id: it is the identity a
        -- local-network announcement must prove, and a different key
        -- announcing the same device id matches nothing here.
        -- `membership_generation` and `captured_at_unix` record which
        -- authorization version this row mirrors and when, so a reader can
        -- say how old the offline authorization it is running on is.
        CREATE TABLE IF NOT EXISTS offline_peer_authorization (
            device_id             TEXT PRIMARY KEY,
            signing_key           BLOB NOT NULL,
            membership_generation INTEGER NOT NULL,
            captured_at_unix      INTEGER NOT NULL
        );

        -- The two version counters the peer rows above cannot carry between
        -- them, in one single-row table (`id` is pinned to 1).
        --
        -- `membership_generation` is this device's own authorization
        -- version, and it must never go BACKWARDS across a restart: a
        -- version-present confirmation compares one captured before a peer
        -- round-trip against one captured after it, so a generation the
        -- previous run had already passed must not be handed out again.
        -- Taking the maximum over the surviving peer rows is not enough,
        -- because the row carrying the highest generation is exactly the
        -- one a withdrawal DELETES, and unchanged rows are not rewritten
        -- just to restate a number. This row advances (never retreats) in
        -- the same transaction as every row write and every withdrawal, so
        -- it costs no extra transaction and cannot be lost with the row
        -- that moved it.
        --
        -- `snapshot_generation` is the coordination plane's own snapshot
        -- version that the peer rows were last written from -- the
        -- provenance of the cache, not an authority. A run that starts on
        -- this cache uses it to refuse the destructive half of a FIRST
        -- netmap frame older than the cache itself: an authenticated but
        -- replayed frame may still be applied additively, but it may not
        -- prune peers the plane never withdrew. 0 means "no netmap has
        -- ever written these rows", which gates nothing.
        CREATE TABLE IF NOT EXISTS offline_authorization_snapshot (
            id                    INTEGER PRIMARY KEY CHECK (id = 1),
            membership_generation INTEGER NOT NULL,
            snapshot_generation   INTEGER NOT NULL
        );

        -- What each peer in `offline_peer_authorization` was authorized for:
        -- one row per (device, group) writer edge, with the netmap's
        -- complete-copy attribute for that edge. A peer with no row here is
        -- pinned but authorized for nothing, which is not enough to act on
        -- a local-network announcement for it.
        --
        -- Rewritten wholesale with its parent row, never patched, for the
        -- same reason `replace_peer_netmap_metadata` replaces rather than
        -- patches: a demotion must not be able to leave a stale writer edge
        -- behind.
        CREATE TABLE IF NOT EXISTS offline_peer_authorization_group (
            device_id       TEXT NOT NULL,
            group_id        TEXT NOT NULL,
            is_full_replica INTEGER NOT NULL,
            PRIMARY KEY (device_id, group_id)
        );

        -- The raw signed policy log the coordination plane last sent for
        -- each group, kept so a restart taken while that plane is
        -- unreachable can re-verify it and go on admitting changes instead
        -- of withholding every group until a netmap arrives.
        --
        -- Signed bytes, not a decision: every record in `log` carries the
        -- group authority's signature over its own canonical preimage, and
        -- the reader verifies the whole chain against this device's pinned
        -- coordination service key and against `group_policy_watermark`
        -- before believing any of it. A tampered row fails verification and
        -- an older chain fails the watermark, so this table cannot widen
        -- what the plane granted.
        CREATE TABLE IF NOT EXISTS offline_group_policy_log (
            group_id         TEXT PRIMARY KEY,
            log              TEXT NOT NULL,
            captured_at_unix INTEGER NOT NULL
        );
        "#,
    )?;

    // A group has at most ONE live link. Enforced in the schema itself, not
    // only in Rust: the index is group-scoped and path-relative while every
    // scan is root-scoped and authoritative, so two live roots on one group
    // make each root's scan read the other's files as deleted and tombstone
    // them — signed deltas that replicate to every device. This
    // layer survives a writer that never reads the Rust chokepoint, a raw
    // `sqlite3` session, and a second process.
    //
    // A partial UNIQUE index on `group_id` would be the obvious spelling and
    // is WRONG twice over: `INSERT OR REPLACE` against a UNIQUE index does
    // not error, it DELETES the conflicting row (silent link loss), and the
    // index cannot even be CREATEd on a database that already holds a
    // duplicate — i.e. it fails exactly on the installs that need it. A
    // BEFORE trigger raising ABORT installs cleanly on such a database,
    // leaves both rows intact and visible for recovery, and overrides
    // `INSERT OR REPLACE` rather than being subverted by it.
    //
    // Placed after the `orphaned` ALTER above, and kept there. SQLite
    // resolves a trigger's column references when the trigger FIRES, not
    // when it is created (measured), so this would in fact tolerate being
    // created before that ALTER — every statement in `init_schema` runs before any
    // caller can insert. That tolerance is a coincidence of ordering rather
    // than a guarantee, and it fails loudly and totally if the column is
    // never added at all ("no such column: NEW.orphaned", on every insert),
    // so this stays downstream of the column it depends on, where the
    // dependency is visible.
    //
    // The UPDATE trigger's `WHEN` is scoped to the 0 ← 1 un-orphan
    // transition rather than to `NEW.orphaned = 0` alone. Unscoped, it
    // aborts ordinary pause/policy/token writes on an
    // already-duplicated database — turning a rare data-loss bug into a
    // common "cannot use the app" bug. Transition-scoped, every legitimate
    // update passes and the un-orphan hole still closes. That hole is real
    // and not theoretical: `INSERT OR REPLACE` silently flipped `orphaned`
    // 1 → 0, which is why this trigger exists alongside the INSERT one.
    conn.execute_batch(
        "CREATE TRIGGER IF NOT EXISTS links_one_live_root_per_group_insert \
         BEFORE INSERT ON links \
         WHEN NEW.orphaned = 0 AND EXISTS ( \
             SELECT 1 FROM links \
             WHERE group_id = NEW.group_id AND orphaned = 0 \
               AND local_path <> NEW.local_path) \
         BEGIN \
             SELECT RAISE(ABORT, \
                 'links: group already has a live link at a different local_path'); \
         END; \
         CREATE TRIGGER IF NOT EXISTS links_one_live_root_per_group_unorphan \
         BEFORE UPDATE ON links \
         WHEN NEW.orphaned = 0 AND OLD.orphaned = 1 AND EXISTS ( \
             SELECT 1 FROM links \
             WHERE group_id = NEW.group_id AND orphaned = 0 \
               AND local_path <> NEW.local_path) \
         BEGIN \
             SELECT RAISE(ABORT, \
                 'links: un-orphaning would give this group a second live link'); \
         END;",
    )?;
    Ok(())
}

/// The `files` authoring-identity triggers. They read
/// `native_authoring_witness`, created by the caller (`yadorilink-sync-sqlite`);
/// SQLite resolves a trigger body's names when the trigger fires, not when it
/// is created.
pub fn files_authoring_triggers(conn: &Connection) -> Result<(), DatabaseError> {
    let violation = unverified_authoring_identity("NEW");
    conn.execute_batch(&format!(
        r#"
        -- Recreated on every open, so a database created before the predicate
        -- last changed enforces the current one.
        DROP TRIGGER IF EXISTS files_require_authoring_identity_on_insert;
        DROP TRIGGER IF EXISTS files_require_authoring_identity_on_update;
        CREATE TRIGGER files_require_authoring_identity_on_insert
        AFTER INSERT ON files
        WHEN {violation}
        BEGIN
            SELECT RAISE(ABORT, 'current DAG-backed file row requires verified authoring identity');
        END;

        CREATE TRIGGER files_require_authoring_identity_on_update
        AFTER UPDATE OF state, version_seq, native_authoring_identity ON files
        WHEN {violation}
        BEGIN
            SELECT RAISE(ABORT, 'current DAG-backed file row requires verified authoring identity');
        END;
        "#
    ))?;
    Ok(())
}

fn create_root_set_generation(conn: &Connection) -> Result<(), DatabaseError> {
    // A change-detector for each group's durability-root set, so a caller
    // can tell "this group's root set has not moved since I last read it"
    // in one indexed row read instead of re-enumerating and re-hashing
    // every root.
    //
    // It is a trigger rather than a counter bumped from Rust deliberately.
    // The consumer is a memoised digest, and a memo that misses an
    // invalidation hands back a digest the table no longer supports --
    // which, for the durability comparison this backs, is a false positive
    // in the one direction that must never happen. A Rust-side bump would
    // be correct against today's write paths and silently wrong the first
    // time a new one is added; a trigger cannot be bypassed by any SQL
    // path, including one written later, and it commits in the same
    // transaction as the write it observes, so a rolled-back write takes
    // its own bump back with it.
    //
    // Deliberately never deleted, not even when a group is unlinked. The
    // row is one integer, and restarting a group's generation at 1 after a
    // relink is exactly how a memo keyed on it could match an entry
    // belonging to the previous life of the same group id.
    //
    // Must come after the primary-key rebuild above, which drops and
    // recreates `files` and would take any trigger attached to it along.
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS file_root_set_generation (
            group_id   TEXT PRIMARY KEY,
            generation INTEGER NOT NULL
        );

        CREATE TRIGGER IF NOT EXISTS files_root_set_generation_on_insert
        AFTER INSERT ON files
        BEGIN
            INSERT INTO file_root_set_generation (group_id, generation)
            VALUES (NEW.group_id, 1)
            ON CONFLICT(group_id) DO UPDATE SET generation = generation + 1;
        END;

        -- Bumps BOTH sides, because an UPDATE can move a row between
        -- groups. Bumping only `NEW.group_id` would leave the group the row
        -- LEFT with an unchanged generation and one fewer root -- a memo
        -- keyed on that generation would go on serving a digest that
        -- includes the departed row, for as long as nothing else writes to
        -- that group. No production statement moves a row across groups
        -- today; the trigger does not depend on that staying true, which is
        -- the only reason to prefer a trigger here at all.
        CREATE TRIGGER IF NOT EXISTS files_root_set_generation_on_update
        AFTER UPDATE ON files
        BEGIN
            INSERT INTO file_root_set_generation (group_id, generation)
            VALUES (NEW.group_id, 1)
            ON CONFLICT(group_id) DO UPDATE SET generation = generation + 1;
            INSERT INTO file_root_set_generation (group_id, generation)
            SELECT OLD.group_id, 1 WHERE OLD.group_id <> NEW.group_id
            ON CONFLICT(group_id) DO UPDATE SET generation = generation + 1;
        END;

        CREATE TRIGGER IF NOT EXISTS files_root_set_generation_on_delete
        AFTER DELETE ON files
        BEGIN
            INSERT INTO file_root_set_generation (group_id, generation)
            VALUES (OLD.group_id, 1)
            ON CONFLICT(group_id) DO UPDATE SET generation = generation + 1;
        END;
        "#,
    )?;
    create_provider_tables(conn)?;
    create_provider_window_ledger(conn)?;
    create_provider_removals(conn)?;
    Ok(())
}

/// The durable removal intents of provider roots (written by an unlink, read by the host app).
fn create_provider_removals(conn: &Connection) -> Result<(), DatabaseError> {
    conn.execute_batch(
        r#"
        -- The DURABLE intent to remove a provider root's OS domain: written in the transaction of the
        -- unlink (or of a rebootstrap the daemon starts), read by the host as the only authority to
        -- remove a domain. `requested` until the host reports the removal; then `done`, with the
        -- location the OS preserved the user's downloaded data at. The provider state of an unlinked
        -- root is kept until the removal is acknowledged.
        CREATE TABLE IF NOT EXISTS provider_removals (
            root_id            TEXT PRIMARY KEY,
            group_id           TEXT NOT NULL,
            display_name       TEXT NOT NULL,
            state              TEXT NOT NULL CHECK (state IN ('requested', 'done')),
            requested_at       INTEGER NOT NULL,
            preserved_location TEXT
        );
        "#,
    )?;
    Ok(())
}

/// The ledger of versions served to the OS in windows only (see `provider_handoffs`).
fn create_provider_window_ledger(conn: &Connection) -> Result<(), DatabaseError> {
    conn.execute_batch(
        r#"
        -- The ledger of verified WINDOWS: for each item, the version whose bytes the daemon handed
        -- to the OS only in ranged windows (a large file is read that way), with the same content
        -- signature and evidence sequence as a handoff. A window serve says the OS may hold SOME
        -- bytes of that version, never all of them: it is never presence of the content (the
        -- `provider_handoffs` rule), and only lets the user's explicit eviction ask the host to
        -- drop what it holds of exactly that version. Demoted with the handoff row.
        CREATE TABLE IF NOT EXISTS provider_window_serves (
            root_id      TEXT NOT NULL,
            item_id      BLOB NOT NULL,
            version_hash BLOB NOT NULL,
            content_sig  TEXT NOT NULL,
            evidence_seq INTEGER NOT NULL,
            PRIMARY KEY (root_id, item_id)
        ) WITHOUT ROWID;
        "#,
    )?;
    Ok(())
}

/// The provider layer's per-root state and item index. DOMAIN-BOUND state: it
/// records what the OS was told and is NOT rebuildable inside the same domain
/// (if it is lost or rolled back the root is rebootstrapped with a new `root_id`).
/// Must come after `files`, which its liveness triggers attach to.
fn create_provider_tables(conn: &Connection) -> Result<(), DatabaseError> {
    conn.execute_batch(
        r#"
        -- One row per provider-backed root (a group with no row is kind `none`).
        CREATE TABLE IF NOT EXISTS provider_roots (
            root_id            TEXT PRIMARY KEY,
            group_id           TEXT NOT NULL UNIQUE,
            kind               TEXT NOT NULL,
            display_name       TEXT NOT NULL,
            domain_registered  INTEGER NOT NULL DEFAULT 0,
            -- Unix nanos of the first extension handshake since the domain was
            -- registered; persisted so a daemon restart does not unlearn it.
            first_handshake_at INTEGER,
            error_description  TEXT,
            -- Set when the root's children are queryable: gates registration.
            namespace_ready    INTEGER NOT NULL DEFAULT 0,
            -- The daemon's durable, monotonic revision of the namespace it has told the OS
            -- (bumped before each publication; the host persists the highest it acknowledged,
            -- so a restored or rolled-back database is detected by a lower revision).
            namespace_revision INTEGER NOT NULL DEFAULT 0,
            -- Latest handoff sequence: replayable state the host reads on connect (`evidence_seq`).
            latest_evidence_seq INTEGER NOT NULL DEFAULT 0,
            -- Counts provider-visible namespace changes (a rename, a create, a delete, a parent
            -- change), bumped in the transaction of the change itself; `announced_change_seq` is
            -- how many of them a root-level signal has been acknowledged for.
            change_seq INTEGER NOT NULL DEFAULT 0,
            announced_change_seq INTEGER NOT NULL DEFAULT 0,
            -- The lowest event sequence still retained in `provider_change_events`: an anchor
            -- below it can no longer be answered incrementally.
            change_floor INTEGER NOT NULL DEFAULT 0,
            -- The group's namespace was installed (a checkpoint install, or the creation of an
            -- empty owner folder): before it, an empty verification is not "queryable".
            install_done INTEGER NOT NULL DEFAULT 0,
            -- User edits kept as a file beside the item instead of changing the canonical
            -- version (the provenance of their bytes could not be proven): how many, and when
            -- the first was kept (unix ms). Surfaced in the status.
            kept_edits INTEGER NOT NULL DEFAULT 0,
            kept_edit_first_ms INTEGER
        );

        -- The derived item index of a provider root: opaque stable `item_id`s,
        -- the path they currently name, and the parent index (`parent_path`,
        -- `name`). `published_version_hash` is the version the OS was last told.
        CREATE TABLE IF NOT EXISTS provider_items (
            root_id                TEXT NOT NULL,
            item_id                BLOB NOT NULL,
            group_id               TEXT NOT NULL,
            path                   TEXT NOT NULL,
            parent_path            TEXT NOT NULL,
            name                   TEXT NOT NULL,
            live                   INTEGER NOT NULL DEFAULT 1,
            published_version_hash BLOB,
            -- The version being announced (its change event is durable, the signal may not
            -- have been acknowledged yet) and that event's sequence. NULL when nothing is in
            -- flight. The shown view is this version when set, else the published one.
            announce_version_hash  BLOB,
            announce_seq           INTEGER,
            -- Strictly increasing and never reused: advanced in the transaction of every change
            -- of what the item SHOWS (an announcement, a rename or move, a direct edit). The
            -- OS-visible version identifiers carry it.
            generation             INTEGER NOT NULL DEFAULT 1,
            -- How many of the generation's advances were a change of this folder's CHILD SET or of
            -- anything below it (a child added, removed or moved in or out, or a descendant
            -- changed at any depth). `generation - child_bumps` is the
            -- folder's PLACE generation (renames, moves, announcements): the source-folder
            -- check of a rename uses it, so a sibling being added does not stale a rename.
            child_bumps            INTEGER NOT NULL DEFAULT 0,
            -- When the item first became pending in the current episode (unix ms); stays through
            -- successive announcements and is cleared when the announced version is released.
            pending_since          INTEGER,
            -- Set when a version was released by the timer (not by a confirmed handoff of it)
            -- and no confirmed handoff has shown the OS fetching it yet (unix ms): reported as
            -- "published, not yet confirmed by the OS".
            unconfirmed_since      INTEGER,
            -- Working-set membership: the OS was shown the item and no removal was reported.
            -- SEPARATE from the history of what was published and handed (`published_version_hash`,
            -- the handoff ledger), which a removal never erases.
            exposed                INTEGER NOT NULL DEFAULT 0,
            -- What YadoriLink MAY HAVE handed the OS for this item: a monotone summary within an
            -- epoch (never served -> one content -> mixed, absorbing), never a history. Only a
            -- trusted local edit starts the next epoch (Single of its content, with the
            -- generation advanced in the same transaction). Written BEFORE any bytes are sent.
            -- See `provider_provenance`.
            served_content_sig     TEXT,
            served_mixed           INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (root_id, item_id)
        ) WITHOUT ROWID;

        CREATE UNIQUE INDEX IF NOT EXISTS provider_items_live_path
            ON provider_items (root_id, path) WHERE live = 1;
        CREATE INDEX IF NOT EXISTS provider_items_parent
            ON provider_items (root_id, parent_path, name) WHERE live = 1;
        CREATE INDEX IF NOT EXISTS provider_items_group_path
            ON provider_items (group_id, path) WHERE live = 1;

        -- Liveness is reconciled AFTER the complete semantic mutation, in the same
        -- transaction, never from per-row triggers that would see intermediate states
        -- (a version replacement first sets the current row superseded and only then
        -- inserts the new one). The triggers below only RECORD which paths changed
        -- (`provider_dirty_paths`); `reconcile_provider_liveness` runs before the commit
        -- of every write and evaluates the FINAL set: an item is live iff its path has a
        -- live current row or a live current row below it, and a change at a path
        -- re-evaluates that path and each of its ancestors. A directory rename keeps its
        -- `item_id`s through `provider::rename_tree`, which runs first.
        -- Cost: groups without a provider root pay one UNIQUE-index existence check per
        -- `files` write (the WHEN clause) and one empty-table check per transaction.
        -- The ledger of verified handoffs: for each item, the version the daemon handed to the OS
        -- (bytes verified against the block store), the signature of that version's CONTENT, and
        -- the evidence sequence it took. It is what the daemon itself did and cannot be recomputed
        -- from anything else, so it is stored; it is DOMAIN-BOUND like the item index. A version
        -- change that alters the content deletes the row in the same transaction (see
        -- `reconcile_provider_liveness`): the OS drops its blocks on an update.
        CREATE TABLE IF NOT EXISTS provider_handoffs (
            root_id      TEXT NOT NULL,
            item_id      BLOB NOT NULL,
            version_hash BLOB NOT NULL,
            content_sig  TEXT NOT NULL,
            evidence_seq INTEGER NOT NULL,
            PRIMARY KEY (root_id, item_id)
        ) WITHOUT ROWID;

        -- The Eager download driver's only persistent state: per item, how many times fetching
        -- the version `version_hash` failed (no peer had the content) and when it may be
        -- offered again. Bound to the version: a different current version ignores the row.
        -- Domain-bound like the item index (cleared with the root).
        CREATE TABLE IF NOT EXISTS provider_download_failures (
            root_id         TEXT NOT NULL,
            item_id         BLOB NOT NULL,
            version_hash    BLOB NOT NULL,
            failures        INTEGER NOT NULL,
            next_attempt_ms INTEGER NOT NULL,
            PRIMARY KEY (root_id, item_id)
        ) WITHOUT ROWID;

        -- The provider write path's idempotency: the stored result of every applied operation
        -- (one per logical OS action, `(session_id, operation_seq)`), written in the SAME
        -- transaction as the change, so a replay returns the result and never re-authors. The
        -- fingerprint hashes the operation's stable wire fields. Bounded (24 h / 4096 per root).
        CREATE TABLE IF NOT EXISTS provider_apply_log (
            root_id       TEXT NOT NULL,
            session_id    BLOB NOT NULL,
            operation_seq INTEGER NOT NULL,
            fingerprint   BLOB NOT NULL,
            result        BLOB NOT NULL,
            created_ms    INTEGER NOT NULL,
            PRIMARY KEY (root_id, session_id, operation_seq)
        ) WITHOUT ROWID;
        -- The uploads (ingest copies) of operations that carry bytes and are not decided yet,
        -- journaled by operation identity BEFORE the first transaction and removed in the same
        -- transaction as the operation's log entry. A copy named here is never aged out as an
        -- abandoned upload, and a retry of the same operation finds and reuses it.
        CREATE TABLE IF NOT EXISTS provider_pending_ingest (
            root_id       TEXT NOT NULL,
            session_id    BLOB NOT NULL,
            operation_seq INTEGER NOT NULL,
            ingest_name   TEXT NOT NULL,
            created_ms    INTEGER NOT NULL,
            PRIMARY KEY (root_id, session_id, operation_seq)
        ) WITHOUT ROWID;
        -- The compact "processed" identity that outlives the stored result: every operation_seq
        -- up to `floor` was processed (or abandoned), `above` lists the processed ones above it
        -- as big-endian u64s. A late replay whose result expired is STALE, never a new change.
        CREATE TABLE IF NOT EXISTS provider_apply_sessions (
            root_id    TEXT NOT NULL,
            session_id BLOB NOT NULL,
            floor_seq  INTEGER NOT NULL,
            above      BLOB NOT NULL,
            seen_ms    INTEGER NOT NULL,
            PRIMARY KEY (root_id, session_id)
        ) WITHOUT ROWID;

        CREATE TABLE IF NOT EXISTS provider_dirty_paths (
            group_id TEXT NOT NULL,
            path     TEXT NOT NULL,
            PRIMARY KEY (group_id, path)
        ) WITHOUT ROWID;
        CREATE TRIGGER IF NOT EXISTS provider_items_dirty_insert
        AFTER INSERT ON files
        WHEN EXISTS (SELECT 1 FROM provider_roots WHERE group_id = NEW.group_id)
        BEGIN
            INSERT OR IGNORE INTO provider_dirty_paths (group_id, path)
            VALUES (NEW.group_id, NEW.path);
        END;
        CREATE TRIGGER IF NOT EXISTS provider_items_dirty_update
        AFTER UPDATE OF path, state, deleted ON files
        WHEN EXISTS (SELECT 1 FROM provider_roots WHERE group_id = NEW.group_id)
        BEGIN
            INSERT OR IGNORE INTO provider_dirty_paths (group_id, path)
            VALUES (NEW.group_id, NEW.path);
            INSERT OR IGNORE INTO provider_dirty_paths (group_id, path)
            SELECT OLD.group_id, OLD.path WHERE OLD.path <> NEW.path;
        END;
        CREATE TRIGGER IF NOT EXISTS provider_items_dirty_delete
        AFTER DELETE ON files
        WHEN EXISTS (SELECT 1 FROM provider_roots WHERE group_id = OLD.group_id)
        BEGIN
            INSERT OR IGNORE INTO provider_dirty_paths (group_id, path)
            VALUES (OLD.group_id, OLD.path);
        END;
        "#,
    )?;
    create_provider_namespace_tables(conn)?;
    Ok(())
}

/// The namespace layer of a provider root: the change log, the folders the OS opened, the
/// structural directories and the parent index. Must come after `provider_roots` and `files`.
fn create_provider_namespace_tables(conn: &Connection) -> Result<(), DatabaseError> {
    conn.execute_batch(
        r#"
        -- The append-only change log of a root: ONE row per event with a unique, strictly
        -- increasing `seq` (taken from `provider_roots.namespace_revision`, which advances once
        -- per event). Written in the transaction that causes the event, and only for what the OS
        -- can know (a published item, or an item under an enumerated parent). `kind` is
        -- 'upsert', 'move' or 'delete'; `old_parent_item_id` is set for a move. The empty blob
        -- is the root container. Pruned only from the front, raising `change_floor`.
        CREATE TABLE IF NOT EXISTS provider_change_events (
            root_id            TEXT NOT NULL,
            seq                INTEGER NOT NULL,
            kind               TEXT NOT NULL,
            item_id            BLOB NOT NULL,
            parent_item_id     BLOB NOT NULL,
            old_parent_item_id BLOB,
            at_s               INTEGER NOT NULL,
            PRIMARY KEY (root_id, seq)
        ) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS provider_change_events_parent
            ON provider_change_events (root_id, parent_item_id, seq);
        CREATE INDEX IF NOT EXISTS provider_change_events_old_parent
            ON provider_change_events (root_id, old_parent_item_id, seq)
            WHERE old_parent_item_id IS NOT NULL;

        -- The revision of a root advances if and only if change events exist for every number it
        -- advances over: no code path can move the anchor without a durable event.
        CREATE TRIGGER IF NOT EXISTS provider_revision_needs_events
        BEFORE UPDATE OF namespace_revision ON provider_roots
        WHEN NEW.namespace_revision > OLD.namespace_revision
         AND (SELECT COUNT(*) FROM provider_change_events e
              WHERE e.root_id = NEW.root_id
                AND e.seq > OLD.namespace_revision AND e.seq <= NEW.namespace_revision)
             <> NEW.namespace_revision - OLD.namespace_revision
        BEGIN
            SELECT RAISE(ABORT, 'the namespace revision advances only with logged change events');
        END;

        -- The folders whose contents the OS has requested (the empty blob is the root
        -- container). A hint: losing it only costs extra signals.
        CREATE TABLE IF NOT EXISTS provider_enumerated_parents (
            root_id        TEXT NOT NULL,
            parent_item_id BLOB NOT NULL,
            PRIMARY KEY (root_id, parent_item_id)
        ) WITHOUT ROWID;

        -- Every directory path that is an ancestor of a live row of a provider group,
        -- structural ones (no row of their own) included, at any depth. Maintained by
        -- `reconcile_provider_liveness` in the transaction of every semantic mutation.
        CREATE TABLE IF NOT EXISTS provider_dirs (
            group_id    TEXT NOT NULL,
            path        TEXT NOT NULL,
            parent_path TEXT NOT NULL,
            PRIMARY KEY (group_id, path)
        ) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS provider_dirs_parent
            ON provider_dirs (group_id, parent_path, path);

        -- The children of a folder in one index: the keyset of an enumeration page. The
        -- scaffold rows (`version_seq = 0`) are never part of a namespace.
        CREATE INDEX IF NOT EXISTS files_parent_path
            ON files (group_id, (rtrim(rtrim(path, replace(path, '/', '')), '/')), path)
            WHERE state = 'current' AND deleted = 0 AND version_seq > 0;
        "#,
    )?;
    Ok(())
}

/// Reconciles `provider_items.live` against the FINAL state of the paths recorded in
/// `provider_dirty_paths`, then clears them. Call it before a write transaction
/// commits (`SyncDatabase` does), so liveness never reflects an intermediate state of
/// one semantic mutation. A no-op when nothing was recorded.
pub fn reconcile_provider_liveness(conn: &Connection) -> rusqlite::Result<()> {
    let dirty: bool =
        conn.query_row("SELECT EXISTS(SELECT 1 FROM provider_dirty_paths)", [], |r| r.get(0))?;
    if !dirty {
        return Ok(());
    }
    // The ancestors of every changed path (and the paths themselves), for the steps below.
    conn.execute_batch(
        r#"
        CREATE TEMP TABLE IF NOT EXISTS provider_anc (g TEXT NOT NULL, p TEXT NOT NULL, PRIMARY KEY (g, p)) WITHOUT ROWID;
        CREATE TEMP TABLE IF NOT EXISTS provider_retiring (root_id TEXT NOT NULL, item_id BLOB NOT NULL, parent_path TEXT NOT NULL, published BLOB);
        CREATE TEMP TABLE IF NOT EXISTS provider_new_paths (root_id TEXT NOT NULL, group_id TEXT NOT NULL, path TEXT NOT NULL);
        DELETE FROM provider_anc;
        DELETE FROM provider_retiring;
        DELETE FROM provider_new_paths;
        INSERT OR IGNORE INTO provider_anc (g, p)
        WITH RECURSIVE ancestors(g, p) AS (
            SELECT group_id, path FROM provider_dirty_paths
            UNION
            SELECT g, rtrim(rtrim(p, replace(p, '/', '')), '/')
            FROM ancestors WHERE instr(p, '/') > 0
        )
        SELECT g, p FROM ancestors;
        -- The items about to retire, with what decides whether the OS must be told.
        INSERT INTO provider_retiring (root_id, item_id, parent_path, published)
        SELECT pi.root_id, pi.item_id, pi.parent_path, pi.published_version_hash
        FROM provider_anc a CROSS JOIN provider_items pi
             ON pi.group_id = a.g AND pi.path = a.p AND pi.live = 1
        WHERE NOT EXISTS (SELECT 1 FROM files f
                          WHERE f.group_id = pi.group_id AND f.state = 'current'
                            AND f.deleted = 0 AND f.path = pi.path)
          AND NOT EXISTS (SELECT 1 FROM files f
                          WHERE f.group_id = pi.group_id AND f.state = 'current'
                            AND f.deleted = 0
                            AND f.path > pi.path || '/' AND f.path < pi.path || '0');
        "#,
    )?;
    let retired = conn.execute(
        r#"
        -- Driven from the changed paths (a handful), never from every live item: each candidate is
        -- two primary-key probes of `files` (the path itself, then the range below it).
        UPDATE provider_items SET live = 0, published_version_hash = NULL
        WHERE live = 1
          AND (root_id, item_id) IN (
              SELECT pi.root_id, pi.item_id
              FROM provider_anc a CROSS JOIN provider_items pi
                   ON pi.group_id = a.g AND pi.path = a.p AND pi.live = 1
              WHERE NOT EXISTS (SELECT 1 FROM files f
                                WHERE f.group_id = pi.group_id AND f.state = 'current'
                                  AND f.deleted = 0 AND f.path = pi.path)
                AND NOT EXISTS (SELECT 1 FROM files f
                                WHERE f.group_id = pi.group_id AND f.state = 'current'
                                  AND f.deleted = 0
                                  AND f.path > pi.path || '/' AND f.path < pi.path || '0'))
        "#,
        [],
    )?;
    if retired > 0 {
        // The download failures of an item that is no longer live have nothing left to hold back.
        conn.execute(
            "DELETE FROM provider_download_failures WHERE EXISTS ( \
                 SELECT 1 FROM provider_items i \
                 WHERE i.root_id = provider_download_failures.root_id \
                   AND i.item_id = provider_download_failures.item_id AND i.live = 0)",
            [],
        )?;
    }
    // A provider-visible namespace change (a delete, or a create/rename target the OS has no item
    // for yet) is counted in this same transaction, so a change that makes no item pending is
    // still announced by a root-level signal. A content change of a known item is not one: its
    // own signal announces it.
    let created: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_dirty_paths d \
         JOIN files f ON f.group_id = d.group_id AND f.path = d.path \
         AND f.state = 'current' AND f.deleted = 0 \
         JOIN provider_roots r ON r.group_id = d.group_id \
         WHERE NOT EXISTS (SELECT 1 FROM provider_items i WHERE i.root_id = r.root_id \
                           AND i.path = d.path AND i.live = 1))",
        [],
        |r| r.get(0),
    )?;
    if retired > 0 || created {
        conn.execute(
            "UPDATE provider_roots SET change_seq = change_seq + 1 \
             WHERE group_id IN (SELECT group_id FROM provider_dirty_paths)",
            [],
        )?;
    }
    reconcile_provider_namespace(conn)?;
    conn.execute_batch(
        r#"
        -- Demotion: a changed path whose live current row no longer has the content that was
        -- handed over (or has none) loses its handoff, in this same transaction, so the daemon
        -- never claims the OS holds bytes that an update has since replaced.
        DELETE FROM provider_handoffs
        WHERE EXISTS (SELECT 1 FROM provider_items i
                      JOIN provider_dirty_paths d ON d.group_id = i.group_id AND d.path = i.path
                      WHERE i.root_id = provider_handoffs.root_id
                        AND i.item_id = provider_handoffs.item_id)
          AND NOT EXISTS (SELECT 1 FROM provider_items i
                          JOIN files f ON f.group_id = i.group_id AND f.path = i.path
                          WHERE i.root_id = provider_handoffs.root_id
                            AND i.item_id = provider_handoffs.item_id
                            AND f.state = 'current' AND f.deleted = 0
                            AND (f.size || '|' || f.blocks_json || '|' || f.record_kind || '|'
                                 || COALESCE(CAST(f.symlink_target AS TEXT), ''))
                                = provider_handoffs.content_sig);
        DELETE FROM provider_window_serves
        WHERE EXISTS (SELECT 1 FROM provider_items i
                      JOIN provider_dirty_paths d ON d.group_id = i.group_id AND d.path = i.path
                      WHERE i.root_id = provider_window_serves.root_id
                        AND i.item_id = provider_window_serves.item_id)
          AND NOT EXISTS (SELECT 1 FROM provider_items i
                          JOIN files f ON f.group_id = i.group_id AND f.path = i.path
                          WHERE i.root_id = provider_window_serves.root_id
                            AND i.item_id = provider_window_serves.item_id
                            AND f.state = 'current' AND f.deleted = 0
                            AND (f.size || '|' || f.blocks_json || '|' || f.record_kind || '|'
                                 || COALESCE(CAST(f.symlink_target AS TEXT), ''))
                                = provider_window_serves.content_sig);
        DELETE FROM provider_dirty_paths;
        "#,
    )
}

/// Whether this database carries the provider tables (the replica index does; the
/// other databases opened through this crate do not).
pub fn has_provider_liveness(conn: &Connection) -> rusqlite::Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' \
         AND name = 'provider_dirty_paths')",
        [],
        |r| r.get(0),
    )
}

fn refuse_unverified_authoring_rows(
    conn: &Connection,
    unverified: fn(&str) -> String,
) -> Result<(), DatabaseError> {
    let invalid_authoring_rows: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM files f WHERE {}", unverified("f")),
        [],
        |row| row.get(0),
    )?;
    if invalid_authoring_rows != 0 {
        return Err(DatabaseError::CorruptSchema(format!(
            "{invalid_authoring_rows} current DAG-backed file row(s) lack verified authoring identity"
        )));
    }
    Ok(())
}

/// The condition under which the `files` row `row` names no verified
/// authoring identity.
///
/// A native head that was held when the row was written
/// (`native_authoring_witness`) vouches for it. A tombstone names no content,
/// so it needs none.
///
/// This is the definition of "has retained evidence" -- the `files` triggers
/// and the open-time check both read it, so they cannot disagree about which
/// rows are authored.
///
/// Evidence only: that a native identity's head was held. That the row *shows
/// the version* its native head carried is not expressible here (a version
/// hash is derived from several columns); the writers check it in the
/// transaction that completes the row (`require_row_shows_native_head`).
pub fn authoring_evidence_missing(row: &str) -> String {
    format!(
        "({row}.deleted = 0
          AND ({row}.native_authoring_identity IS NULL
               OR length({row}.native_authoring_identity) < 58
               OR NOT EXISTS(
                   SELECT 1 FROM native_authoring_witness
                    WHERE group_id = {row}.group_id
                      AND identity = {row}.native_authoring_identity
               )))"
    )
}

/// The trigger condition: a current row, in a group that has native history,
/// without a verified authoring identity. Before that a row may be unauthored
/// (the initial scan writes rows before it authors them).
fn unverified_authoring_identity(row: &str) -> String {
    format!(
        "{row}.state = 'current' AND {row}.version_seq > 0
          AND EXISTS(SELECT 1 FROM native_authoring_witness WHERE group_id = {row}.group_id)
          AND {}",
        authoring_evidence_missing(row)
    )
}

pub fn table_exists(conn: &Connection, table: &str) -> Result<bool, DatabaseError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |r| r.get(0),
    )?;
    Ok(count > 0)
}

#[cfg(test)]
mod tests;

/// A folder's child set changed: its generation (and `child_bumps`) advance and, when the OS can
/// know the folder (it is published, or its own parent is enumerated), an upsert event tells it the
/// folder's new token. `next` is the last event sequence used; the caller stores the revision.
fn bump_item(
    conn: &Connection,
    root_id: &str,
    folder_path: &str,
    next: &mut i64,
    child_set: bool,
) -> rusqlite::Result<()> {
    if folder_path.is_empty() {
        return Ok(());
    }
    let row: Option<(Vec<u8>, bool, String)> = conn
        .query_row(
            "UPDATE provider_items SET generation = generation + 1, child_bumps = child_bumps + ?3 \
             WHERE root_id = ?1 AND path = ?2 AND live = 1 \
             RETURNING item_id, published_version_hash IS NOT NULL, parent_path",
            rusqlite::params![root_id, folder_path, i64::from(child_set)],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((item_id, published, parent_path)) = row else { return Ok(()) };
    if published {
        *next += 1;
        conn.execute(
            "INSERT INTO provider_change_events \
             (root_id, seq, kind, item_id, parent_item_id, old_parent_item_id, at_s) \
             VALUES (?1, ?2, 'upsert', ?3, \
                     COALESCE((SELECT p.item_id FROM provider_items p WHERE p.root_id = ?1 \
                               AND p.path = ?4 AND p.live = 1 AND ?4 <> ''), x''), \
                     NULL, CAST(strftime('%s', 'now') AS INTEGER))",
            rusqlite::params![root_id, *next, item_id, parent_path],
        )?;
    }
    Ok(())
}

fn bump_folder(
    conn: &Connection,
    root_id: &str,
    folder_path: &str,
    next: &mut i64,
) -> rusqlite::Result<()> {
    bump_item(conn, root_id, folder_path, next, true)
}

/// The item at `path` of the provider group was REPLACED (the same path now shows another head, or
/// was deleted and recreated in one transaction): its generation advances and the OS is told, so
/// every token taken before the replacement is stale even when the new version hashes the same.
/// The item id is kept (the path is the identity the user named); the token is what changes.
pub fn note_item_replaced(conn: &Connection, group_id: &str, path: &str) -> rusqlite::Result<()> {
    let known: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_items WHERE group_id = ?1 AND path = ?2 AND live = 1)",
        rusqlite::params![group_id, path],
        |r| r.get(0),
    )?;
    if !known {
        return Ok(());
    }
    let roots: Vec<String> = {
        let mut stmt = conn.prepare("SELECT root_id FROM provider_roots WHERE group_id = ?1")?;
        let rows = stmt.query_map([group_id], |r| r.get(0))?.collect::<Result<_, _>>()?;
        rows
    };
    for root in roots {
        bump_and_store(conn, &root, path, false)?;
    }
    Ok(())
}

/// What the OS may do with an item depends on whether the user keeps it on this device, so a pin or
/// an unpin at `path` changes how the item at `path`, everything beneath it, and every folder above
/// it are served. Each of them advances (the item and its descendants by a new generation, an
/// ancestor by a child-set bump that leaves its children's tokens alone) and the change counter
/// that raises a root-level signal moves once, so the OS re-reads them. A group with no provider
/// root is untouched.
pub fn note_retention_changed(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> rusqlite::Result<()> {
    let roots: Vec<String> = {
        let mut stmt = conn.prepare("SELECT root_id FROM provider_roots WHERE group_id = ?1")?;
        let rows = stmt.query_map([group_id], |r| r.get(0))?.collect::<Result<_, _>>()?;
        rows
    };
    for root in roots {
        let base: i64 = conn.query_row(
            "SELECT namespace_revision FROM provider_roots WHERE root_id = ?1",
            [&root],
            |r| r.get(0),
        )?;
        let mut ancestors = Vec::new();
        let mut prefix = path;
        while let Some((parent, _)) = prefix.rsplit_once('/') {
            ancestors.push(parent.to_owned());
            prefix = parent;
        }
        let covered: Vec<String> = {
            let mut stmt = conn.prepare(
                "SELECT path FROM provider_items WHERE root_id = ?1 AND live = 1 AND ( \
                   ?2 = '' OR path = ?2 OR (path > ?2 || '/' AND path < ?2 || '0')) \
                 ORDER BY path",
            )?;
            let rows = stmt
                .query_map(rusqlite::params![root, path], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            rows
        };
        for folder in &ancestors {
            bump_and_store(conn, &root, folder, true)?;
        }
        for item in &covered {
            bump_and_store(conn, &root, item, false)?;
        }
        let after: i64 = conn.query_row(
            "SELECT namespace_revision FROM provider_roots WHERE root_id = ?1",
            [&root],
            |r| r.get(0),
        )?;
        if after != base {
            conn.execute(
                "UPDATE provider_roots SET change_seq = change_seq + 1 WHERE root_id = ?1",
                [&root],
            )?;
        }
    }
    Ok(())
}

/// [`bump_folder`] outside the reconcile (a local create or move changed the folder's child set):
/// advances the root's revision with the event it logged.
pub fn note_child_set_change(
    conn: &Connection,
    root_id: &str,
    folder_path: &str,
) -> rusqlite::Result<()> {
    bump_and_store(conn, root_id, folder_path, true)
}

/// Advances the item at `path` (see [`bump_item`]) and stores the revision its event moved to: the
/// one statement of this module that writes the revision outside the reconcile.
fn bump_and_store(
    conn: &Connection,
    root_id: &str,
    path: &str,
    child_set: bool,
) -> rusqlite::Result<()> {
    let base: i64 = conn.query_row(
        "SELECT namespace_revision FROM provider_roots WHERE root_id = ?1",
        [root_id],
        |r| r.get(0),
    )?;
    let mut next = base;
    bump_item(conn, root_id, path, &mut next, child_set)?;
    if next != base {
        conn.execute(
            "UPDATE provider_roots SET namespace_revision = ?2 WHERE root_id = ?1",
            rusqlite::params![root_id, next],
        )?;
    }
    Ok(())
}

/// The namespace half of the reconcile, in the same transaction: keeps `provider_dirs` equal to
/// the set of ancestors of live rows (structural directories included), and appends the change
/// events of what the OS can know. Runs after the liveness update, over the `provider_anc`,
/// `provider_retiring` and `provider_new_paths` scratch tables filled by the caller.
///
/// An event is written only for an item that is published or whose parent is an enumerated
/// parent, so importing a namespace nobody has opened writes none.
fn reconcile_provider_namespace(conn: &Connection) -> rusqlite::Result<()> {
    const DESCENDANT: &str = "EXISTS (SELECT 1 FROM files f WHERE f.group_id = a.g \
         AND f.state = 'current' AND f.deleted = 0 AND f.version_seq > 0 \
         AND f.path > a.p || '/' AND f.path < a.p || '0')";
    // Directories that gained their first live descendant: new entries (and, below, new items
    // when their parent is enumerated).
    conn.execute_batch(&format!(
        r#"
        CREATE TEMP TABLE IF NOT EXISTS provider_new_dirs (g TEXT NOT NULL, p TEXT NOT NULL);
        DELETE FROM provider_new_dirs;
        INSERT INTO provider_new_dirs (g, p)
        SELECT a.g, a.p FROM provider_anc a
        WHERE a.p <> ''
          AND EXISTS (SELECT 1 FROM provider_roots r WHERE r.group_id = a.g)
          AND NOT EXISTS (SELECT 1 FROM provider_dirs d WHERE d.group_id = a.g AND d.path = a.p)
          AND {DESCENDANT};
        INSERT INTO provider_dirs (group_id, path, parent_path)
        SELECT g, p, rtrim(rtrim(p, replace(p, '/', '')), '/') FROM provider_new_dirs;
        -- The direct-child set transitions of this transaction, whatever the child is to the OS:
        -- a path that is live now but has no item (new, or never minted under an unopened
        -- folder), a path that is no longer live, and the structural directories that appeared
        -- or vanished. The folder each belongs to has its child set changed.
        CREATE TEMP TABLE IF NOT EXISTS provider_child_changes (g TEXT NOT NULL, parent TEXT NOT NULL);
        DELETE FROM provider_child_changes;
        INSERT INTO provider_child_changes (g, parent)
        SELECT d.group_id, rtrim(rtrim(d.path, replace(d.path, '/', '')), '/')
        FROM provider_dirty_paths d
        WHERE EXISTS (SELECT 1 FROM provider_roots r WHERE r.group_id = d.group_id)
          AND ((EXISTS (SELECT 1 FROM files f WHERE f.group_id = d.group_id AND f.path = d.path
                        AND f.state = 'current' AND f.deleted = 0 AND f.version_seq > 0)
                AND NOT EXISTS (SELECT 1 FROM provider_items i WHERE i.group_id = d.group_id
                                AND i.path = d.path AND i.live = 1))
               OR NOT EXISTS (SELECT 1 FROM files f WHERE f.group_id = d.group_id
                              AND f.state = 'current' AND f.deleted = 0 AND f.version_seq > 0
                              AND (f.path = d.path
                                   OR (f.path > d.path || '/' AND f.path < d.path || '0'))));
        INSERT INTO provider_child_changes (g, parent)
        SELECT g, rtrim(rtrim(p, replace(p, '/', '')), '/') FROM provider_new_dirs;
        INSERT INTO provider_child_changes (g, parent)
        SELECT d.group_id, d.parent_path FROM provider_dirs d
        WHERE EXISTS (SELECT 1 FROM provider_anc a WHERE a.g = d.group_id AND a.p = d.path
                      AND NOT {DESCENDANT});
        DELETE FROM provider_dirs
        WHERE EXISTS (SELECT 1 FROM provider_anc a WHERE a.g = provider_dirs.group_id
                      AND a.p = provider_dirs.path
                      AND NOT {DESCENDANT});
        "#
    ))?;

    let roots: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT DISTINCT r.root_id FROM provider_roots r \
             WHERE r.group_id IN (SELECT group_id FROM provider_dirty_paths)",
        )?;
        let rows = stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
        rows
    };
    // Is the parent (by item id expression) an enumerated parent of the root?
    for root in roots {
        let base: i64 = conn.query_row(
            "SELECT namespace_revision FROM provider_roots WHERE root_id = ?1",
            [&root],
            |r| r.get(0),
        )?;
        let mut next = base;
        // Created items: a live row (or a new structural directory) under an enumerated parent
        // that has no item yet is minted now, and told as an upsert.
        conn.execute(
            r#"
            INSERT INTO provider_new_paths (root_id, group_id, path)
            SELECT r.root_id, r.group_id, d.path FROM provider_dirty_paths d
            JOIN provider_roots r ON r.group_id = d.group_id AND r.root_id = ?1
            WHERE EXISTS (SELECT 1 FROM files f WHERE f.group_id = d.group_id AND f.path = d.path
                          AND f.state = 'current' AND f.deleted = 0 AND f.version_seq > 0)
            UNION
            SELECT r.root_id, r.group_id, n.p FROM provider_new_dirs n
            JOIN provider_roots r ON r.group_id = n.g AND r.root_id = ?1
            "#,
            [&root],
        )?;
        const PARENT_ENUMERATED: &str = "(CASE WHEN {pp} = '' THEN EXISTS (SELECT 1 FROM provider_enumerated_parents e WHERE e.root_id = {root} AND e.parent_item_id = x'') ELSE EXISTS (SELECT 1 FROM provider_items pi JOIN provider_enumerated_parents e ON e.root_id = pi.root_id AND e.parent_item_id = pi.item_id WHERE pi.root_id = {root} AND pi.path = {pp} AND pi.live = 1) END)";
        let enumerated = |pp: &str, root_col: &str| {
            PARENT_ENUMERATED.replace("{pp}", pp).replace("{root}", root_col)
        };
        let pp_new = "rtrim(rtrim(n.path, replace(n.path, '/', '')), '/')";
        let minted: Vec<(Vec<u8>, String)> = {
            let mut stmt = conn.prepare(&format!(
                r#"
                INSERT INTO provider_items (root_id, item_id, group_id, path, parent_path, name, live)
                SELECT n.root_id, randomblob(16), n.group_id, n.path, {pp_new},
                       substr(n.path, length({pp_new}) + CASE WHEN {pp_new} = '' THEN 1 ELSE 2 END), 1
                FROM provider_new_paths n
                WHERE n.root_id = ?1
                  AND NOT EXISTS (SELECT 1 FROM provider_items i WHERE i.root_id = n.root_id
                                  AND i.path = n.path AND i.live = 1)
                  AND {enumerated}
                RETURNING item_id, parent_path
                "#,
                enumerated = enumerated(pp_new, "n.root_id")
            ))?;
            let rows = stmt
                .query_map([&root], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
            rows
        };
        for (item_id, parent_path) in minted {
            next += 1;
            conn.execute(
                r#"
                INSERT INTO provider_change_events (root_id, seq, kind, item_id, parent_item_id, old_parent_item_id, at_s)
                VALUES (?1, ?2, 'upsert', ?3,
                        COALESCE((SELECT p.item_id FROM provider_items p WHERE p.root_id = ?1
                                  AND p.path = ?4 AND p.live = 1 AND ?4 <> ''), x''),
                        NULL, CAST(strftime('%s', 'now') AS INTEGER))
                "#,
                rusqlite::params![root, next, item_id, parent_path],
            )?;
        }
        // Retired items the OS knew: published, or under an enumerated parent.
        let pp_ret = "t.parent_path";
        let events = conn.execute(
            &format!(
                r#"
                INSERT INTO provider_change_events (root_id, seq, kind, item_id, parent_item_id, old_parent_item_id, at_s)
                SELECT t.root_id, ?2 + row_number() OVER (ORDER BY t.item_id), 'delete', t.item_id,
                       COALESCE((SELECT p.item_id FROM provider_items p WHERE p.root_id = t.root_id
                                 AND p.path = t.parent_path AND p.live = 1 AND t.parent_path <> ''), x''),
                       NULL, CAST(strftime('%s', 'now') AS INTEGER)
                FROM provider_retiring t
                WHERE t.root_id = ?1 AND (t.published IS NOT NULL OR {enumerated})
                "#,
                enumerated = enumerated(pp_ret, "t.root_id")
            ),
            rusqlite::params![root, next],
        )?;
        next += events as i64;
        // A folder whose child set changed advances its generation (and tells the OS): a delete
        // based on an older view of the folder is a stale view.
        let parents: Vec<String> = {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT c.parent FROM provider_child_changes c \
                 JOIN provider_roots r ON r.group_id = c.g WHERE r.root_id = ?1",
            )?;
            let rows =
                stmt.query_map([&root], |r| r.get::<_, String>(0))?.collect::<Result<_, _>>()?;
            rows
        };
        // The same advance, once per folder, for every folder ABOVE a changed path: a folder's
        // token covers its whole subtree (a recursive delete is fenced by it), so a change at any
        // depth, content edits included, moves every ancestor's token. The cost is the number of
        // distinct ancestors of the changed paths, never the size of any subtree.
        let ancestors: Vec<String> = {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT a.p FROM provider_anc a \
                 JOIN provider_roots r ON r.group_id = a.g \
                 WHERE r.root_id = ?1 AND a.p <> '' \
                   AND EXISTS (SELECT 1 FROM provider_dirty_paths d WHERE d.group_id = a.g \
                               AND d.path > a.p || '/' AND d.path < a.p || '0')",
            )?;
            let rows =
                stmt.query_map([&root], |r| r.get::<_, String>(0))?.collect::<Result<_, _>>()?;
            rows
        };
        let folders: std::collections::BTreeSet<&String> =
            parents.iter().chain(ancestors.iter()).collect();
        let before_bumps = next;
        for folder in folders {
            bump_folder(conn, &root, folder, &mut next)?;
        }
        if next != before_bumps {
            // The upserts above are only delivered by a host signal. A change that makes no item
            // pending (an edit of a known file below a folder) raises none of its own, so a folder
            // whose token moved must raise one, or a delete on its old token would stay stale
            // with nothing to refresh the OS.
            conn.execute(
                "UPDATE provider_roots SET change_seq = change_seq + 1 WHERE root_id = ?1",
                [&root],
            )?;
        }
        if next != base {
            conn.execute(
                "UPDATE provider_roots SET namespace_revision = ?2 WHERE root_id = ?1",
                rusqlite::params![root, next],
            )?;
        }
    }
    Ok(())
}
