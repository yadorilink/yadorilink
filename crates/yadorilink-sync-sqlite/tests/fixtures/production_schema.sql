-- index authorization_checkpoints_by_device ON authorization_checkpoints
CREATE INDEX authorization_checkpoints_by_device
            ON authorization_checkpoints(group_id, device_id);

-- index change_authorization_by_checkpoint ON change_authorization
CREATE INDEX change_authorization_by_checkpoint
            ON change_authorization(checkpoint_hash);

-- index change_file_versions_by_version ON change_file_versions
CREATE INDEX change_file_versions_by_version
            ON change_file_versions(group_id, version_hash);

-- index change_parents_by_parent ON change_parents
CREATE INDEX change_parents_by_parent
            ON change_parents(parent_hash);

-- index change_store_by_author ON change_store
CREATE UNIQUE INDEX change_store_by_author
            ON change_store(group_id, device_id, author_incarnation, author_seq);

-- index change_store_by_group ON change_store
CREATE INDEX change_store_by_group ON change_store(group_id);

-- index dag_retention_roots_by_change ON dag_retention_roots
CREATE INDEX dag_retention_roots_by_change
            ON dag_retention_roots(group_id, change_hash, retention_class);

-- index dag_retention_roots_by_owner ON dag_retention_roots
CREATE INDEX dag_retention_roots_by_owner
            ON dag_retention_roots(owner_kind, group_id);

-- index dcf_admission_holds_by_wait ON dcf_admission_holds
CREATE INDEX dcf_admission_holds_by_wait
            ON dcf_admission_holds(group_id, wait_kind, wait_key, change_hash);

-- index dcf_admission_node_waits_by_node ON dcf_admission_node_waits
CREATE INDEX dcf_admission_node_waits_by_node
            ON dcf_admission_node_waits(group_id, digest, change_hash);

-- index dcf_change_dots_by_dot ON dcf_change_dots
CREATE UNIQUE INDEX dcf_change_dots_by_dot
            ON dcf_change_dots(group_id, author_device, author_incarnation, author_seq);

-- index dcf_path_basis_by_member ON dcf_path_basis
CREATE INDEX dcf_path_basis_by_member
            ON dcf_path_basis(group_id, path, member);

-- index dcf_path_heads_by_bucket ON dcf_path_heads
CREATE INDEX dcf_path_heads_by_bucket
            ON dcf_path_heads(group_id, path, author_device, author_incarnation);

-- index dcf_retry_dependencies_by_change ON dcf_retry_dependencies
CREATE INDEX dcf_retry_dependencies_by_change
            ON dcf_retry_dependencies(group_id, change_hash);

-- index dcf_stable_projection_binding_by_stable_path ON dcf_stable_projection_binding
CREATE INDEX dcf_stable_projection_binding_by_stable_path
            ON dcf_stable_projection_binding (group_id, stable_path);

-- index dcf_unsettled_changes_by_group ON dcf_unsettled_changes
CREATE INDEX dcf_unsettled_changes_by_group
            ON dcf_unsettled_changes(group_id, kind, change_hash);

-- index file_versions_by_group ON file_versions
CREATE INDEX file_versions_by_group ON file_versions(group_id);

-- index idx_change_checkpoint_snapshots_group ON change_checkpoint_snapshots
CREATE INDEX idx_change_checkpoint_snapshots_group
    ON change_checkpoint_snapshots(group_id);

-- index idx_change_checkpoints_group ON change_checkpoints
CREATE INDEX idx_change_checkpoints_group
    ON change_checkpoints(group_id, seq);

-- index idx_enrollment_operations_state ON enrollment_operations
CREATE INDEX idx_enrollment_operations_state
            ON enrollment_operations(state);

-- index idx_handoff_leases_group_id ON handoff_leases
CREATE INDEX idx_handoff_leases_group_id ON handoff_leases(group_id);

-- index idx_history_base_path_heads_change_base ON history_base_path_heads
CREATE INDEX idx_history_base_path_heads_change_base
    ON history_base_path_heads(group_id, change_hash, base_hash);

-- index idx_history_base_path_heads_path ON history_base_path_heads
CREATE INDEX idx_history_base_path_heads_path
    ON history_base_path_heads(group_id, path);

-- index idx_membership_operations_state ON membership_operations
CREATE INDEX idx_membership_operations_state
            ON membership_operations(state);

-- index idx_native_heads_version ON native_heads
CREATE INDEX idx_native_heads_version ON native_heads (group_id, version);

-- index idx_projection_obligations_runnable ON projection_obligations
CREATE INDEX idx_projection_obligations_runnable
             ON projection_obligations (state, next_attempt_at);

-- index idx_restore_operations_path ON restore_operations
CREATE UNIQUE INDEX idx_restore_operations_path
            ON restore_operations(group_id, path);

-- index idx_role_loss_operations_state ON role_loss_operations
CREATE INDEX idx_role_loss_operations_state
            ON role_loss_operations(state);

-- index native_authorization_checkpoints_by_device ON native_authorization_checkpoints
CREATE INDEX native_authorization_checkpoints_by_device
            ON native_authorization_checkpoints(group_id, device_id);

-- index native_checkpoint_frontier_snapshot_by_checkpoint ON native_checkpoint_frontier_snapshot
CREATE INDEX native_checkpoint_frontier_snapshot_by_checkpoint
            ON native_checkpoint_frontier_snapshot(group_id, checkpoint_hash);

-- index native_delta_authorization_by_checkpoint ON native_delta_authorization
CREATE INDEX native_delta_authorization_by_checkpoint
            ON native_delta_authorization(checkpoint_hash);

-- index native_delta_bodies_by_hash ON native_delta_bodies
CREATE INDEX native_delta_bodies_by_hash
            ON native_delta_bodies (group_id, delta_hash);

-- index native_delta_holds_waiting_on ON native_delta_holds
CREATE INDEX native_delta_holds_waiting_on
            ON native_delta_holds (group_id, waiting_on_author, waiting_on_incarnation, waiting_on_seq);

-- index native_stable_projection_binding_by_stable_path ON native_stable_projection_binding
CREATE INDEX native_stable_projection_binding_by_stable_path
            ON native_stable_projection_binding (group_id, stable_path);

-- index recursive_operation_parts_by_change ON recursive_operation_parts
CREATE INDEX recursive_operation_parts_by_change
            ON recursive_operation_parts(change_hash);

-- index structural_directory_origins_by_object ON structural_directory_origins
CREATE INDEX structural_directory_origins_by_object
            ON structural_directory_origins(group_id, object_address);

-- table author_chain_state ON author_chain_state
CREATE TABLE author_chain_state (
            group_id        TEXT NOT NULL,
            device_id       TEXT NOT NULL,
            incarnation     BLOB NOT NULL CHECK (length(incarnation) = 16),
            watermark       INTEGER NOT NULL,
            tip_change_hash BLOB NOT NULL,
            anchor_base     BLOB,
            PRIMARY KEY (group_id, device_id, incarnation)
        ) WITHOUT ROWID;

-- table author_incarnation ON author_incarnation
CREATE TABLE author_incarnation (
            singleton           INTEGER PRIMARY KEY CHECK (singleton = 1),
            device_id           TEXT NOT NULL,
            incarnation         BLOB NOT NULL CHECK (length(incarnation) = 16),
            db_instance_nonce   BLOB NOT NULL CHECK (length(db_instance_nonce) = 16),
            machine_fingerprint BLOB NOT NULL,
            minted_reason       TEXT NOT NULL,
            previous            BLOB CHECK (previous IS NULL OR length(previous) = 16)
        );

-- table author_own_ahead ON author_own_ahead
CREATE TABLE author_own_ahead (
            group_id     TEXT NOT NULL,
            device_id    TEXT NOT NULL,
            incarnation  BLOB NOT NULL,
            local_seq    INTEGER NOT NULL,
            reported_seq INTEGER NOT NULL,
            PRIMARY KEY (group_id, device_id, incarnation)
        ) WITHOUT ROWID;

-- table authorization_checkpoints ON authorization_checkpoints
CREATE TABLE authorization_checkpoints (
            checkpoint_hash BLOB PRIMARY KEY,
            group_id        TEXT NOT NULL,
            device_id       TEXT NOT NULL,
            checkpoint_seq  INTEGER NOT NULL,
            encoded         BLOB NOT NULL,
            signature       BLOB NOT NULL,
            -- The device's raw 32-byte Ed25519 verifying key, carried
            -- alongside the checkpoint so a fresh device (or one that
            -- never pinned this author's key locally) can verify history
            -- from a since-revoked/forgotten author. The daemon
            -- verifies `SHA256(author_signing_public_key) ==
            -- signing_key_fingerprint` (implied by `encoded`'s own signed
            -- content) before ever storing this, so a stored row's key is
            -- always the one the authority actually vouched for.
            author_signing_public_key BLOB NOT NULL
        );

-- table block_fetch_refusals ON block_fetch_refusals
CREATE TABLE block_fetch_refusals (
            group_id              TEXT NOT NULL,
            path                  TEXT NOT NULL,
            version_hash          TEXT NOT NULL,
            peer_device_id        TEXT NOT NULL,
            reason                TEXT NOT NULL,
            refused_at_unix_nanos INTEGER NOT NULL,
            PRIMARY KEY (group_id, path, version_hash, peer_device_id)
        );

-- table change_authorization ON change_authorization
CREATE TABLE change_authorization (
            change_hash     BLOB PRIMARY KEY,
            checkpoint_hash BLOB NOT NULL,
            merkle_proof    BLOB NOT NULL
        );

-- table change_checkpoint_snapshots ON change_checkpoint_snapshots
CREATE TABLE change_checkpoint_snapshots (
    checkpoint_hash BLOB PRIMARY KEY,
    group_id        TEXT NOT NULL,
    snapshot        BLOB NOT NULL
);

-- table change_checkpoints ON change_checkpoints
CREATE TABLE change_checkpoints (
    checkpoint_hash BLOB PRIMARY KEY,
    group_id        TEXT NOT NULL,
    snapshot_hash   BLOB NOT NULL,
    encoded         BLOB NOT NULL,
    seq             INTEGER NOT NULL
);

-- table change_file_versions ON change_file_versions
CREATE TABLE change_file_versions (
            group_id     TEXT NOT NULL,
            change_hash  BLOB NOT NULL,
            version_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, change_hash, version_hash)
        );

-- table change_parents ON change_parents
CREATE TABLE change_parents (
            child_hash  BLOB NOT NULL,
            parent_hash BLOB NOT NULL,
            PRIMARY KEY (child_hash, parent_hash)
        );

-- table change_store ON change_store
CREATE TABLE change_store (
            change_hash          BLOB PRIMARY KEY,
            group_id             TEXT NOT NULL,
            device_id            TEXT NOT NULL,
            -- The incarnation half of the change's author: the author is
            -- `(device_id, author_incarnation)`, and `author_seq` counts that
            -- author's changes.
            author_incarnation   BLOB NOT NULL
                DEFAULT X'00000000000000000000000000000000'
                CHECK (length(author_incarnation) = 16),
            -- This change's position in its own author's chain within
            -- `group_id`: the third component of its causal dot,
            -- `(group_id, device_id, author_seq)`. A plain column copy of
            -- the signed field, exactly like `device_id`, so an author's
            -- next position can be read without decoding
            -- `encoded`. It counts only this author's own writes, is
            -- consecutive from 1, and never restarts.
            author_seq           INTEGER NOT NULL,
            display_rank              INTEGER NOT NULL,
            encoded              BLOB NOT NULL,
            -- The change's authenticated header, computed once at append
            -- time so it can be read without decoding `encoded`.
            authenticated_header BLOB NOT NULL DEFAULT X''
        );

-- table dag_retention_roots ON dag_retention_roots
CREATE TABLE dag_retention_roots (
            owner_kind       TEXT NOT NULL,
            owner_id         TEXT NOT NULL,
            group_id         TEXT NOT NULL,
            change_hash      BLOB NOT NULL,
            retention_class  TEXT NOT NULL,
            -- When this row was first inserted (real wall clock, stamped by
            -- `register_retention_root` itself -- see that function's doc).
            -- `INSERT OR IGNORE` never updates it on a re-registration, so it
            -- is the true first-registration instant for the row's whole
            -- life. An owner's orphan sweep uses it to bound the window
            -- between a root being registered and its owning record being
            -- created, when the two happen as separate steps: age, not mere
            -- presence, is what distinguishes an in-flight pair from a
            -- stranded root.
            registered_at_unix_nanos INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (owner_kind, owner_id, group_id, change_hash, retention_class)
        );

-- table dcf_admission_holds ON dcf_admission_holds
CREATE TABLE dcf_admission_holds (
            group_id           TEXT NOT NULL,
            change_hash        BLOB NOT NULL,
            wait_kind          INTEGER NOT NULL,
            wait_key           BLOB,
            path               TEXT,
            author_device      TEXT,
            author_incarnation BLOB,
            PRIMARY KEY (group_id, change_hash)
        );

-- table dcf_admission_node_waits ON dcf_admission_node_waits
CREATE TABLE dcf_admission_node_waits (
            group_id    TEXT NOT NULL,
            change_hash BLOB NOT NULL,
            digest      BLOB NOT NULL,
            PRIMARY KEY (group_id, change_hash, digest)
        );

-- table dcf_change_dots ON dcf_change_dots
CREATE TABLE dcf_change_dots (
            group_id           TEXT NOT NULL,
            change_hash        BLOB NOT NULL,
            author_device      TEXT NOT NULL,
            author_incarnation BLOB NOT NULL,
            author_seq         INTEGER NOT NULL,
            display_rank       INTEGER NOT NULL,
            PRIMARY KEY (group_id, change_hash)
        );

-- table dcf_namespace_roots ON dcf_namespace_roots
CREATE TABLE dcf_namespace_roots (
            group_id TEXT NOT NULL PRIMARY KEY,
            root     BLOB NOT NULL
        );

-- table dcf_path_basis ON dcf_path_basis
CREATE TABLE dcf_path_basis (
            group_id    TEXT NOT NULL,
            path        TEXT NOT NULL,
            change_hash BLOB NOT NULL,
            member      BLOB NOT NULL,
            PRIMARY KEY (group_id, path, change_hash, member)
        );

-- table dcf_path_effects ON dcf_path_effects
CREATE TABLE dcf_path_effects (
            group_id     TEXT NOT NULL,
            path         TEXT NOT NULL,
            change_hash  BLOB NOT NULL,
            lands        INTEGER NOT NULL,
            version_hash BLOB,
            naming_device_id TEXT NOT NULL,
            PRIMARY KEY (group_id, path, change_hash)
        );

-- table dcf_path_heads ON dcf_path_heads
CREATE TABLE dcf_path_heads (
            group_id           TEXT NOT NULL,
            path               TEXT NOT NULL,
            change_hash        BLOB NOT NULL,
            author_device      TEXT NOT NULL,
            author_incarnation BLOB NOT NULL,
            PRIMARY KEY (group_id, path, change_hash)
        );

-- table dcf_pending_retries ON dcf_pending_retries
CREATE TABLE dcf_pending_retries (
            group_id    TEXT NOT NULL,
            change_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, change_hash)
        ) WITHOUT ROWID;

-- table dcf_retired_subtrees ON dcf_retired_subtrees
CREATE TABLE dcf_retired_subtrees (
            group_id     TEXT NOT NULL,
            epoch        BLOB NOT NULL,
            prefix       TEXT NOT NULL,
            retired_root BLOB NOT NULL,
            retired_by   BLOB NOT NULL,
            PRIMARY KEY (group_id, epoch, prefix, retired_root)
        ) WITHOUT ROWID;

-- table dcf_retry_dependencies ON dcf_retry_dependencies
CREATE TABLE dcf_retry_dependencies (
            group_id           TEXT NOT NULL,
            path               TEXT NOT NULL,
            author_device      TEXT NOT NULL,
            author_incarnation BLOB NOT NULL,
            change_hash        BLOB NOT NULL,
            PRIMARY KEY (group_id, path, author_device, author_incarnation, change_hash)
        ) WITHOUT ROWID;

-- table dcf_stable_projection_binding ON dcf_stable_projection_binding
CREATE TABLE dcf_stable_projection_binding (
            group_id     TEXT NOT NULL,
            source_path  TEXT NOT NULL,
            change_hash  BLOB NOT NULL,
            stable_path  TEXT NOT NULL,
            PRIMARY KEY (group_id, source_path, change_hash)
        );

-- table dcf_unsettled_changes ON dcf_unsettled_changes
CREATE TABLE dcf_unsettled_changes (
            group_id    TEXT NOT NULL,
            kind        INTEGER NOT NULL,
            change_hash BLOB NOT NULL,
            PRIMARY KEY (kind, change_hash)
        );

-- table device_frontier ON device_frontier
CREATE TABLE device_frontier (
            group_id    TEXT NOT NULL,
            device_id   TEXT NOT NULL,
            change_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, device_id, change_hash)
        );

-- table duplicate_recovery_paths ON duplicate_recovery_paths
CREATE TABLE duplicate_recovery_paths (
            group_id TEXT NOT NULL,
            path     TEXT NOT NULL,
            PRIMARY KEY (group_id, path)
        );

-- table durability_unknown_latches ON durability_unknown_latches
CREATE TABLE durability_unknown_latches (
            group_id TEXT PRIMARY KEY
        );

-- table enrollment_operations ON enrollment_operations
CREATE TABLE enrollment_operations (
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
            prior_link_policy              TEXT,
            prior_link_max_local_size_bytes INTEGER
        );

-- table file_root_set_generation ON file_root_set_generation
CREATE TABLE file_root_set_generation (
            group_id   TEXT PRIMARY KEY,
            generation INTEGER NOT NULL
        );

-- table file_versions ON file_versions
CREATE TABLE file_versions (
            version_hash BLOB NOT NULL,
            group_id     TEXT NOT NULL,
            encoded      BLOB NOT NULL,
            PRIMARY KEY (group_id, version_hash)
        );

-- table files ON files
CREATE TABLE files (
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
            -- Causal identity of the DAG change that authored this
            -- projection. Only the pre-import scan may leave it NULL; once
            -- a group has history the triggers below require one.
            authoring_change_hash BLOB,
            -- The NativeState head this row was materialized from
            -- (`NativeRowIdentity`, one canonical blob, provenance first).
            -- NULL when the row was not produced under native authority:
            -- never inferred from a version, a path or a DCF change hash.
            native_authoring_identity BLOB,
            materialization_state TEXT NOT NULL DEFAULT 'remote',
            pinned            INTEGER NOT NULL DEFAULT 0,
            last_accessed_unix INTEGER,
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
            PRIMARY KEY (group_id, path, version_seq)
        );

-- table group_authority ON group_authority
CREATE TABLE group_authority (
            group_id  TEXT PRIMARY KEY,
            authority TEXT NOT NULL CHECK (authority IN ('dcf', 'native'))
        );

-- table group_block_provenance ON group_block_provenance
CREATE TABLE group_block_provenance (
            group_id   TEXT NOT NULL,
            block_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, block_hash)
        );

-- table group_heads ON group_heads
CREATE TABLE group_heads (
            group_id    TEXT NOT NULL,
            change_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, change_hash)
        );

-- table group_history_bases ON group_history_bases
CREATE TABLE group_history_bases (
    group_id                 TEXT PRIMARY KEY,
    history_base             BLOB NOT NULL,
    checkpoint_hash          BLOB NOT NULL,
    previous_checkpoint_hash BLOB
);

-- table group_local_history_floor ON group_local_history_floor
CREATE TABLE group_local_history_floor (
            group_id         TEXT PRIMARY KEY,
            floor_unix_nanos INTEGER NOT NULL
        );

-- table group_policy_watermark ON group_policy_watermark
CREATE TABLE group_policy_watermark (
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

-- table handoff_leases ON handoff_leases
CREATE TABLE handoff_leases (
            lease_id             TEXT PRIMARY KEY,
            group_id             TEXT NOT NULL,
            root_digest          BLOB NOT NULL,
            state                TEXT NOT NULL DEFAULT 'provisional',
            pinned_versions_json TEXT NOT NULL,
            created_at_unix      INTEGER NOT NULL,
            expires_at_unix      INTEGER NOT NULL
        );

-- table history_base_author_state ON history_base_author_state
CREATE TABLE history_base_author_state (
    group_id        TEXT NOT NULL,
    base_hash       BLOB NOT NULL,
    device_id       TEXT NOT NULL,
    incarnation     BLOB NOT NULL,
    seq             INTEGER NOT NULL,
    tip_header      BLOB NOT NULL,
    tip_change_hash BLOB NOT NULL,
    PRIMARY KEY (group_id, base_hash, device_id, incarnation)
);

-- table history_base_carried_authors ON history_base_carried_authors
CREATE TABLE history_base_carried_authors (
    group_id    TEXT NOT NULL,
    base_hash   BLOB NOT NULL,
    change_hash BLOB NOT NULL,
    PRIMARY KEY (group_id, base_hash, change_hash)
);

-- table history_base_meta ON history_base_meta
CREATE TABLE history_base_meta (
    group_id       TEXT NOT NULL,
    base_hash      BLOB NOT NULL,
    namespace_root BLOB NOT NULL,
    PRIMARY KEY (group_id, base_hash)
);

-- table history_base_path_heads ON history_base_path_heads
CREATE TABLE history_base_path_heads (
    group_id         TEXT NOT NULL,
    base_hash        BLOB NOT NULL,
    path             TEXT NOT NULL,
    change_hash      BLOB NOT NULL,
    device_id        TEXT NOT NULL,
    incarnation      BLOB NOT NULL,
    author_seq       INTEGER NOT NULL,
    header           BLOB NOT NULL,
    version_hash     BLOB NOT NULL,
    naming_device_id TEXT NOT NULL,
    PRIMARY KEY (group_id, base_hash, path, change_hash)
);

-- table links ON links
CREATE TABLE links (
            local_path TEXT PRIMARY KEY,
            group_id   TEXT NOT NULL,
            paused     INTEGER NOT NULL DEFAULT 0,
            materialization_policy TEXT NOT NULL DEFAULT 'eager',
            max_local_size_bytes INTEGER,
            windows_symlink_opt_in INTEGER NOT NULL DEFAULT 0,
            orphaned   INTEGER NOT NULL DEFAULT 0,
            root_token TEXT,
            -- Set by departed-root recovery: while 1, a full scan is
            -- additive (indexes what it finds, emits no deletions) so the
            -- departed root's paths survive and can hydrate from a peer.
            -- Cleared after one clean full scan.
            suppress_tombstones_until_scan INTEGER NOT NULL DEFAULT 0
        );

-- table local_capture_changes ON local_capture_changes
CREATE TABLE local_capture_changes (
            group_id    TEXT NOT NULL,
            path        TEXT NOT NULL,
            change_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, path)
        );

-- table local_dirty_paths ON local_dirty_paths
CREATE TABLE local_dirty_paths (
            group_id               TEXT NOT NULL,
            path                   TEXT NOT NULL,
            change_kind            TEXT NOT NULL,
            first_seen_unix_nanos  INTEGER NOT NULL,
            observed_at_unix_nanos INTEGER NOT NULL,
            attempts               INTEGER NOT NULL DEFAULT 0,
            last_error             TEXT,
            PRIMARY KEY (group_id, path)
        );

-- table materialization_intents ON materialization_intents
CREATE TABLE materialization_intents (
            group_id              TEXT NOT NULL,
            path                  TEXT NOT NULL,
            target_version_hash   BLOB NOT NULL,
            created_at_unix_nanos INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );

-- table membership_operations ON membership_operations
CREATE TABLE membership_operations (
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

-- table namespace_nodes ON namespace_nodes
CREATE TABLE namespace_nodes (
    group_id TEXT NOT NULL,
    digest   BLOB NOT NULL,
    tag      BLOB NOT NULL,
    encoding BLOB NOT NULL,
    PRIMARY KEY (group_id, digest)
) WITHOUT ROWID;

-- table native_author_context ON native_author_context
CREATE TABLE native_author_context (
            group_id     TEXT NOT NULL,
            author       TEXT NOT NULL,
            incarnation  BLOB NOT NULL,
            seq          INTEGER NOT NULL,
            PRIMARY KEY (group_id, author, incarnation)
        );

-- table native_author_frontier ON native_author_frontier
CREATE TABLE native_author_frontier (
            group_id          TEXT NOT NULL,
            author            TEXT NOT NULL,
            incarnation       BLOB NOT NULL,
            seq               INTEGER NOT NULL,
            tip               BLOB NOT NULL,
            -- The display rank of the last delta this author signed that
            -- carried a Put (`NativeAuthorFrontierEntry::tip_display_rank`'s
            -- doc) -- survives a later delta that removes that Put's head.
            tip_display_rank  INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (group_id, author, incarnation)
        );

-- table native_authoring_witness ON native_authoring_witness
CREATE TABLE native_authoring_witness (
            group_id  TEXT NOT NULL,
            identity  BLOB NOT NULL,
            -- The version the head carried: a row may cite this identity only
            -- while it shows this version.
            version   BLOB NOT NULL,
            PRIMARY KEY (group_id, identity)
        );

-- table native_authorization_checkpoints ON native_authorization_checkpoints
CREATE TABLE native_authorization_checkpoints (
            checkpoint_hash            BLOB PRIMARY KEY,
            group_id                   TEXT NOT NULL,
            device_id                  TEXT NOT NULL,
            checkpoint_seq             INTEGER NOT NULL,
            encoded                    BLOB NOT NULL,
            signature                  BLOB NOT NULL,
            author_signing_public_key  BLOB NOT NULL
        );

-- table native_checkpoint_frontier_snapshot ON native_checkpoint_frontier_snapshot
CREATE TABLE native_checkpoint_frontier_snapshot (
            group_id       TEXT NOT NULL,
            checkpoint_hash BLOB NOT NULL,
            author          TEXT NOT NULL,
            incarnation     BLOB NOT NULL,
            seq             INTEGER NOT NULL,
            tip             BLOB NOT NULL,
            tip_display_rank INTEGER NOT NULL,
            is_retired      INTEGER NOT NULL,
            PRIMARY KEY (group_id, checkpoint_hash, author, incarnation)
        );

-- table native_checkpoint_seal_evidence ON native_checkpoint_seal_evidence
CREATE TABLE native_checkpoint_seal_evidence (
            group_id       TEXT NOT NULL,
            checkpoint_hash BLOB NOT NULL,
            evidence_sealer TEXT NOT NULL,
            evidence_bytes  BLOB NOT NULL,
            PRIMARY KEY (group_id, checkpoint_hash)
        );

-- table native_checkpoints ON native_checkpoints
CREATE TABLE native_checkpoints (
            group_id              TEXT NOT NULL,
            checkpoint_hash        BLOB NOT NULL,
            namespace_root         BLOB NOT NULL,
            active_frontier_root   BLOB NOT NULL,
            retired_frontier_root  BLOB NOT NULL,
            signature              BLOB NOT NULL,
            installed_at_unixtime  INTEGER NOT NULL,
            PRIMARY KEY (group_id, checkpoint_hash)
        );

-- table native_delta_authorization ON native_delta_authorization
CREATE TABLE native_delta_authorization (
            delta_hash      BLOB PRIMARY KEY,
            checkpoint_hash BLOB NOT NULL,
            merkle_proof    BLOB NOT NULL
        );

-- table native_delta_bodies ON native_delta_bodies
CREATE TABLE native_delta_bodies (
            group_id       TEXT NOT NULL,
            author         TEXT NOT NULL,
            incarnation    BLOB NOT NULL,
            seq            INTEGER NOT NULL,
            delta_hash     BLOB NOT NULL,
            encoded_delta  BLOB NOT NULL,
            PRIMARY KEY (group_id, author, incarnation, seq)
        );

-- table native_delta_holds ON native_delta_holds
CREATE TABLE native_delta_holds (
            group_id                TEXT NOT NULL,
            author                   TEXT NOT NULL,
            incarnation              BLOB NOT NULL,
            seq                      INTEGER NOT NULL,
            wire_bytes               BLOB NOT NULL,
            waiting_on_author        TEXT NOT NULL,
            waiting_on_incarnation   BLOB NOT NULL,
            waiting_on_seq           INTEGER NOT NULL,
            received_at_unixtime     INTEGER NOT NULL,
            PRIMARY KEY (group_id, author, incarnation, seq)
        );

-- table native_delta_log ON native_delta_log
CREATE TABLE native_delta_log (
            group_id     TEXT NOT NULL,
            author       TEXT NOT NULL,
            incarnation  BLOB NOT NULL,
            seq          INTEGER NOT NULL,
            delta_hash   BLOB NOT NULL,
            PRIMARY KEY (group_id, author, incarnation, seq)
        );

-- table native_delta_pending_evidence ON native_delta_pending_evidence
CREATE TABLE native_delta_pending_evidence (
            delta_hash      BLOB PRIMARY KEY,
            checkpoint_hash BLOB NOT NULL,
            merkle_proof    BLOB NOT NULL
        );

-- table native_frontier_nodes ON native_frontier_nodes
CREATE TABLE native_frontier_nodes (
            group_id  TEXT NOT NULL,
            digest    BLOB NOT NULL,
            tag       BLOB NOT NULL,
            encoding  BLOB NOT NULL,
            PRIMARY KEY (group_id, digest)
        );

-- table native_heads ON native_heads
CREATE TABLE native_heads (
            group_id      TEXT NOT NULL,
            path          TEXT NOT NULL,
            author        TEXT NOT NULL,
            incarnation   BLOB NOT NULL,
            seq           INTEGER NOT NULL,
            version       BLOB NOT NULL,
            display_rank  INTEGER NOT NULL,
            provenance    BLOB NOT NULL,
            PRIMARY KEY (group_id, path, author, incarnation, seq)
        );

-- table native_kept_copy ON native_kept_copy
CREATE TABLE native_kept_copy (
            group_id    TEXT NOT NULL,
            source_path TEXT NOT NULL,
            version     BLOB NOT NULL,
            PRIMARY KEY (group_id, source_path, version)
        );

-- table native_local_capture ON native_local_capture
CREATE TABLE native_local_capture (
            group_id TEXT NOT NULL,
            path     TEXT NOT NULL,
            identity BLOB NOT NULL,
            PRIMARY KEY (group_id, path)
        );

-- table native_namespace_nodes ON native_namespace_nodes
CREATE TABLE native_namespace_nodes (
            group_id  TEXT NOT NULL,
            digest    BLOB NOT NULL,
            tag       BLOB NOT NULL,
            encoding  BLOB NOT NULL,
            PRIMARY KEY (group_id, digest)
        );

-- table native_physical_placement ON native_physical_placement
CREATE TABLE native_physical_placement (
            group_id      TEXT NOT NULL,
            physical_path TEXT NOT NULL,
            source_path   TEXT NOT NULL,
            author        TEXT NOT NULL,
            incarnation   BLOB NOT NULL,
            seq           INTEGER NOT NULL,
            provenance    BLOB NOT NULL,
            version       BLOB NOT NULL,
            display_rank  INTEGER NOT NULL,
            origin        TEXT NOT NULL,
            PRIMARY KEY (group_id, physical_path)
        );

-- table native_recursive_operation_parts ON native_recursive_operation_parts
CREATE TABLE native_recursive_operation_parts (
            group_id     TEXT NOT NULL,
            author       TEXT NOT NULL,
            operation_id BLOB NOT NULL,
            part_index   INTEGER NOT NULL,
            part_count   INTEGER NOT NULL,
            PRIMARY KEY (group_id, author, operation_id, part_index)
        );

-- table native_removal_operation ON native_removal_operation
CREATE TABLE native_removal_operation (
            group_id     TEXT NOT NULL,
            path         TEXT NOT NULL,
            provenance   BLOB NOT NULL,
            author       TEXT NOT NULL,
            operation_id BLOB NOT NULL,
            PRIMARY KEY (group_id, path, provenance)
        );

-- table native_retired_authors ON native_retired_authors
CREATE TABLE native_retired_authors (
            group_id             TEXT NOT NULL,
            author               TEXT NOT NULL,
            incarnation          BLOB NOT NULL,
            reason               TEXT NOT NULL,
            retired_at_unixtime  INTEGER NOT NULL,
            PRIMARY KEY (group_id, author, incarnation)
        );

-- table native_stable_projection_binding ON native_stable_projection_binding
CREATE TABLE native_stable_projection_binding (
            group_id     TEXT NOT NULL,
            source_path  TEXT NOT NULL,
            author       TEXT NOT NULL,
            incarnation  BLOB NOT NULL,
            seq          INTEGER NOT NULL,
            stable_path  TEXT NOT NULL,
            PRIMARY KEY (group_id, source_path, author, incarnation, seq)
        );

-- table offline_authorization_snapshot ON offline_authorization_snapshot
CREATE TABLE offline_authorization_snapshot (
            id                    INTEGER PRIMARY KEY CHECK (id = 1),
            membership_generation INTEGER NOT NULL,
            snapshot_generation   INTEGER NOT NULL
        );

-- table offline_group_policy_log ON offline_group_policy_log
CREATE TABLE offline_group_policy_log (
            group_id         TEXT PRIMARY KEY,
            log              TEXT NOT NULL,
            captured_at_unix INTEGER NOT NULL
        );

-- table offline_peer_authorization ON offline_peer_authorization
CREATE TABLE offline_peer_authorization (
            device_id             TEXT PRIMARY KEY,
            signing_key           BLOB NOT NULL,
            membership_generation INTEGER NOT NULL,
            captured_at_unix      INTEGER NOT NULL
        );

-- table offline_peer_authorization_group ON offline_peer_authorization_group
CREATE TABLE offline_peer_authorization_group (
            device_id       TEXT NOT NULL,
            group_id        TEXT NOT NULL,
            is_full_replica INTEGER NOT NULL,
            PRIMARY KEY (device_id, group_id)
        );

-- table path_actual_mutation_fences ON path_actual_mutation_fences
CREATE TABLE path_actual_mutation_fences (
            group_id            TEXT NOT NULL,
            path                TEXT NOT NULL,
            mutation_generation INTEGER NOT NULL,
            last_mutation_kind  TEXT NOT NULL,
            last_mutation_at    INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );

-- table path_materialized_generations ON path_materialized_generations
CREATE TABLE path_materialized_generations (
            group_id                   TEXT NOT NULL,
            path                       TEXT NOT NULL,
            generation_id              TEXT NOT NULL,
            -- The sorted, concatenated hashes of the path's present heads
            -- when the proof was published.
            reflected_heads BLOB NOT NULL,
            resolved_path_state_hash   BLOB NOT NULL,
            object_kind                TEXT NOT NULL,
            version_hash               BLOB,
            filesystem_identity        BLOB,
            metadata_fingerprint       BLOB,
            hardlink_group_id          TEXT,
            encoding_version           INTEGER NOT NULL,
            updated_at_unix_nanos      INTEGER NOT NULL,
            published_under_mutation_generation INTEGER,
            PRIMARY KEY (group_id, path)
        );

-- table paused_items ON paused_items
CREATE TABLE paused_items (
            group_id             TEXT NOT NULL,
            path                 TEXT NOT NULL,
            paused_at_unix_nanos INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );

-- table pending_enrollments ON pending_enrollments
CREATE TABLE pending_enrollments (
            operation_id TEXT PRIMARY KEY,
            kind         TEXT NOT NULL,
            group_id     TEXT NOT NULL,
            device_id    TEXT NOT NULL,
            local_path   TEXT NOT NULL
        );

-- table pinned_directories ON pinned_directories
CREATE TABLE pinned_directories (
            group_id TEXT NOT NULL,
            prefix   TEXT NOT NULL,
            PRIMARY KEY (group_id, prefix)
        );

-- table projection_obligation_incarnations ON projection_obligation_incarnations
CREATE TABLE projection_obligation_incarnations (
            id INTEGER PRIMARY KEY AUTOINCREMENT
        );

-- table projection_obligations ON projection_obligations
CREATE TABLE projection_obligations (
            group_id                TEXT NOT NULL,
            path                    TEXT NOT NULL,
            invalidation_generation INTEGER NOT NULL,
            state                   TEXT NOT NULL,
            created_at              INTEGER NOT NULL,
            updated_at              INTEGER NOT NULL,
            attempt_count           INTEGER NOT NULL DEFAULT 0,
            next_attempt_at         INTEGER NOT NULL DEFAULT 0,
            obligation_incarnation  INTEGER NOT NULL DEFAULT 0,
            -- Which bump seam last touched this row; `'remote'` is the
            -- veto-preserving value (see `ObligationOrigin`).
            origin                  TEXT NOT NULL DEFAULT 'remote',
            PRIMARY KEY (group_id, path)
        );

-- table pruned_published_change_versions ON pruned_published_change_versions
CREATE TABLE pruned_published_change_versions (
            group_id              TEXT NOT NULL,
            version_hash          BLOB NOT NULL,
            authoring_change_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, version_hash)
        );

-- table recursive_operation_parts ON recursive_operation_parts
CREATE TABLE recursive_operation_parts (
            group_id          TEXT NOT NULL,
            author_device_id  TEXT NOT NULL,
            operation_id      BLOB NOT NULL,
            history_epoch     BLOB NOT NULL,
            part_index        INTEGER NOT NULL,
            change_hash       BLOB NOT NULL,
            -- `encode_op_list` of the part's effect ops, so the effect set
            -- can be rebuilt after the change itself is gone.
            effect_ops        BLOB NOT NULL,
            PRIMARY KEY (group_id, author_device_id, operation_id, history_epoch, part_index)
        );

-- table recursive_operations ON recursive_operations
CREATE TABLE recursive_operations (
            group_id          TEXT NOT NULL,
            author_device_id  TEXT NOT NULL,
            operation_id      BLOB NOT NULL,
            -- The history the recorded parts were written on: empty for
            -- genesis, the base's bytes above one.
            history_epoch     BLOB NOT NULL,
            -- `RecursiveOperationDescriptor::to_bytes`: the fields every
            -- part of the operation carries identically.
            descriptor        BLOB NOT NULL,
            part_count        INTEGER NOT NULL,
            PRIMARY KEY (group_id, author_device_id, operation_id, history_epoch)
        );

-- table restore_operations ON restore_operations
CREATE TABLE restore_operations (
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
            authoring_change_hash BLOB,
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

-- table retained_directories ON retained_directories
CREATE TABLE retained_directories (
            group_id               TEXT NOT NULL,
            path                   TEXT NOT NULL,
            reason                 TEXT NOT NULL,
            filesystem_identity    BLOB,
            retained_at_unix_nanos INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );

-- table role_loss_operations ON role_loss_operations
CREATE TABLE role_loss_operations (
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

-- table held_paths ON held_paths
CREATE TABLE held_paths (
            group_id                    TEXT NOT NULL,
            path                        TEXT NOT NULL,
            -- NULL: the replaced index had no live row here, so nothing
            -- this device placed can be on disk under this name.
            prior_record_kind           TEXT,
            prior_materialization_state TEXT,
            prior_size                  INTEGER,
            prior_blocks_json           TEXT,
            prior_unix_mode             INTEGER,
            prior_xattrs_json           TEXT,
            prior_symlink_target        BLOB,
            held_at_unix_nanos          INTEGER NOT NULL,
            -- Moves every time an install holds the path again, so a
            -- reconciliation that read an earlier install's row cannot
            -- release the hold a later one renewed.
            generation                  INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (group_id, path)
        );

-- table structural_directory_intents ON structural_directory_intents
CREATE TABLE structural_directory_intents (
            group_id             TEXT NOT NULL,
            path                 TEXT NOT NULL,
            mutation_generation  INTEGER NOT NULL,
            intent_at_unix_nanos INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );

-- table structural_directory_origins ON structural_directory_origins
CREATE TABLE structural_directory_origins (
            group_id               TEXT NOT NULL,
            path                   TEXT NOT NULL,
            object_address         BLOB NOT NULL,
            filesystem_identity    BLOB NOT NULL,
            recorded_at_unix_nanos INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );

-- table structural_provenance_lost ON structural_provenance_lost
CREATE TABLE structural_provenance_lost (
            group_id               TEXT NOT NULL,
            path                   TEXT NOT NULL,
            filesystem_identity    BLOB NOT NULL,
            recorded_at_unix_nanos INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );

-- trigger authorization_checkpoints_protect_referenced ON authorization_checkpoints
CREATE TRIGGER authorization_checkpoints_protect_referenced
        BEFORE DELETE ON authorization_checkpoints
        WHEN EXISTS (
            SELECT 1 FROM change_authorization
            WHERE checkpoint_hash = OLD.checkpoint_hash
        )
        BEGIN
            SELECT RAISE(ABORT, 'authorization_checkpoints row is still referenced by change_authorization');
        END;

-- trigger change_authorization_requires_checkpoint ON change_authorization
CREATE TRIGGER change_authorization_requires_checkpoint
        BEFORE INSERT ON change_authorization
        WHEN NOT EXISTS (
            SELECT 1 FROM authorization_checkpoints
            WHERE checkpoint_hash = NEW.checkpoint_hash
        )
        BEGIN
            SELECT RAISE(ABORT, 'change_authorization.checkpoint_hash references a checkpoint that does not exist');
        END;

-- trigger dcf_unsettled_on_admit ON dcf_change_dots
CREATE TRIGGER dcf_unsettled_on_admit AFTER INSERT ON dcf_change_dots BEGIN
            DELETE FROM dcf_unsettled_changes WHERE kind = 0 AND change_hash = NEW.change_hash;
            INSERT OR IGNORE INTO dcf_unsettled_changes (group_id, kind, change_hash)
                SELECT NEW.group_id, 2, NEW.change_hash WHERE NOT EXISTS
                    (SELECT 1 FROM change_store c
                      WHERE c.change_hash = NEW.change_hash AND c.group_id = NEW.group_id);
        END;

-- trigger dcf_unsettled_on_publish ON change_authorization
CREATE TRIGGER dcf_unsettled_on_publish
            AFTER INSERT ON change_authorization BEGIN
            DELETE FROM dcf_unsettled_changes WHERE kind = 1 AND change_hash = NEW.change_hash;
        END;

-- trigger dcf_unsettled_on_retain ON change_store
CREATE TRIGGER dcf_unsettled_on_retain AFTER INSERT ON change_store BEGIN
            INSERT OR IGNORE INTO dcf_unsettled_changes (group_id, kind, change_hash)
                SELECT NEW.group_id, 0, NEW.change_hash WHERE NOT EXISTS
                    (SELECT 1 FROM dcf_change_dots d
                      WHERE d.group_id = NEW.group_id AND d.change_hash = NEW.change_hash);
            INSERT OR IGNORE INTO dcf_unsettled_changes (group_id, kind, change_hash)
                SELECT NEW.group_id, 1, NEW.change_hash WHERE NOT EXISTS
                    (SELECT 1 FROM change_authorization a WHERE a.change_hash = NEW.change_hash);
            DELETE FROM dcf_unsettled_changes WHERE kind = 2 AND change_hash = NEW.change_hash;
        END;

-- trigger dcf_unsettled_on_retire ON change_store
CREATE TRIGGER dcf_unsettled_on_retire AFTER DELETE ON change_store BEGIN
            DELETE FROM dcf_unsettled_changes
                WHERE kind IN (0, 1) AND change_hash = OLD.change_hash;
            INSERT OR IGNORE INTO dcf_unsettled_changes (group_id, kind, change_hash)
                SELECT OLD.group_id, 2, OLD.change_hash WHERE EXISTS
                    (SELECT 1 FROM dcf_change_dots d
                      WHERE d.group_id = OLD.group_id AND d.change_hash = OLD.change_hash);
        END;

-- trigger dcf_unsettled_on_unadmit ON dcf_change_dots
CREATE TRIGGER dcf_unsettled_on_unadmit AFTER DELETE ON dcf_change_dots BEGIN
            DELETE FROM dcf_unsettled_changes WHERE kind = 2 AND change_hash = OLD.change_hash;
            INSERT OR IGNORE INTO dcf_unsettled_changes (group_id, kind, change_hash)
                SELECT OLD.group_id, 0, OLD.change_hash WHERE EXISTS
                    (SELECT 1 FROM change_store c
                      WHERE c.change_hash = OLD.change_hash AND c.group_id = OLD.group_id);
        END;

-- trigger dcf_unsettled_on_unpublish ON change_authorization
CREATE TRIGGER dcf_unsettled_on_unpublish
            AFTER DELETE ON change_authorization BEGIN
            INSERT OR IGNORE INTO dcf_unsettled_changes (group_id, kind, change_hash)
                SELECT c.group_id, 1, c.change_hash FROM change_store c
                 WHERE c.change_hash = OLD.change_hash;
        END;

-- trigger files_require_authoring_identity_on_insert ON files
CREATE TRIGGER files_require_authoring_identity_on_insert
        AFTER INSERT ON files
        WHEN NEW.state = 'current' AND NEW.version_seq > 0
          AND EXISTS(SELECT 1 FROM group_authority ga WHERE ga.group_id = NEW.group_id AND ga.authority = 'native')
          AND EXISTS(SELECT 1 FROM native_authoring_witness WHERE group_id = NEW.group_id)
          AND (NEW.deleted = 0
          AND (NEW.native_authoring_identity IS NULL
               OR length(NEW.native_authoring_identity) < 58
               OR NOT EXISTS(
                   SELECT 1 FROM native_authoring_witness
                    WHERE group_id = NEW.group_id
                      AND identity = NEW.native_authoring_identity
               )))
        BEGIN
            SELECT RAISE(ABORT, 'current DAG-backed file row requires verified authoring identity');
        END;

-- trigger files_require_authoring_identity_on_update ON files
CREATE TRIGGER files_require_authoring_identity_on_update
        AFTER UPDATE OF state, version_seq, authoring_change_hash, native_authoring_identity ON files
        WHEN NEW.state = 'current' AND NEW.version_seq > 0
          AND EXISTS(SELECT 1 FROM group_authority ga WHERE ga.group_id = NEW.group_id AND ga.authority = 'native')
          AND EXISTS(SELECT 1 FROM native_authoring_witness WHERE group_id = NEW.group_id)
          AND (NEW.deleted = 0
          AND (NEW.native_authoring_identity IS NULL
               OR length(NEW.native_authoring_identity) < 58
               OR NOT EXISTS(
                   SELECT 1 FROM native_authoring_witness
                    WHERE group_id = NEW.group_id
                      AND identity = NEW.native_authoring_identity
               )))
        BEGIN
            SELECT RAISE(ABORT, 'current DAG-backed file row requires verified authoring identity');
        END;

-- trigger files_root_set_generation_on_delete ON files
CREATE TRIGGER files_root_set_generation_on_delete
        AFTER DELETE ON files
        BEGIN
            INSERT INTO file_root_set_generation (group_id, generation)
            VALUES (OLD.group_id, 1)
            ON CONFLICT(group_id) DO UPDATE SET generation = generation + 1;
        END;

-- trigger files_root_set_generation_on_insert ON files
CREATE TRIGGER files_root_set_generation_on_insert
        AFTER INSERT ON files
        BEGIN
            INSERT INTO file_root_set_generation (group_id, generation)
            VALUES (NEW.group_id, 1)
            ON CONFLICT(group_id) DO UPDATE SET generation = generation + 1;
        END;

-- trigger files_root_set_generation_on_update ON files
CREATE TRIGGER files_root_set_generation_on_update
        AFTER UPDATE ON files
        BEGIN
            INSERT INTO file_root_set_generation (group_id, generation)
            VALUES (NEW.group_id, 1)
            ON CONFLICT(group_id) DO UPDATE SET generation = generation + 1;
            INSERT INTO file_root_set_generation (group_id, generation)
            SELECT OLD.group_id, 1 WHERE OLD.group_id <> NEW.group_id
            ON CONFLICT(group_id) DO UPDATE SET generation = generation + 1;
        END;

-- trigger links_one_live_root_per_group_insert ON links
CREATE TRIGGER links_one_live_root_per_group_insert BEFORE INSERT ON links WHEN NEW.orphaned = 0 AND EXISTS ( SELECT 1 FROM links WHERE group_id = NEW.group_id AND orphaned = 0 AND local_path <> NEW.local_path) BEGIN SELECT RAISE(ABORT, 'links: group already has a live link at a different local_path'); END;

-- trigger links_one_live_root_per_group_unorphan ON links
CREATE TRIGGER links_one_live_root_per_group_unorphan BEFORE UPDATE ON links WHEN NEW.orphaned = 0 AND OLD.orphaned = 1 AND EXISTS ( SELECT 1 FROM links WHERE group_id = NEW.group_id AND orphaned = 0 AND local_path <> NEW.local_path) BEGIN SELECT RAISE(ABORT, 'links: un-orphaning would give this group a second live link'); END;

-- trigger native_authorization_checkpoints_protect_referenced ON native_authorization_checkpoints
CREATE TRIGGER native_authorization_checkpoints_protect_referenced
        BEFORE DELETE ON native_authorization_checkpoints
        WHEN EXISTS (
            SELECT 1 FROM native_delta_authorization
            WHERE checkpoint_hash = OLD.checkpoint_hash
        )
        BEGIN
            SELECT RAISE(ABORT, 'native_authorization_checkpoints row is still referenced by native_delta_authorization');
        END;

-- trigger native_delta_authorization_requires_checkpoint ON native_delta_authorization
CREATE TRIGGER native_delta_authorization_requires_checkpoint
        BEFORE INSERT ON native_delta_authorization
        WHEN NOT EXISTS (
            SELECT 1 FROM native_authorization_checkpoints
            WHERE checkpoint_hash = NEW.checkpoint_hash
        )
        BEGIN
            SELECT RAISE(ABORT, 'native_delta_authorization.checkpoint_hash references a checkpoint that does not exist');
        END;

-- view admitted_changes ON admitted_changes
CREATE VIEW admitted_changes AS
  SELECT s.* FROM change_store s
  JOIN dcf_change_dots d ON d.group_id = s.group_id AND d.change_hash = s.change_hash;

-- view published_evidence ON published_evidence
CREATE VIEW published_evidence AS
  SELECT ca.* FROM change_authorization ca;

