//! What YadoriLink MAY HAVE handed the OS, per item, and the one predicate that decides whether
//! an edit's base can be trusted.
//!
//! PRINCIPLE: we do not trust OS state. Before any bytes may reach the OS we durably and
//! monotonically record the content we may have handed over. Only when that record ALONE proves
//! an edit's base is the edit canonical; otherwise the canonical version is never overwritten
//! and the edit is saved as a conflict.
//!
//! The record is a SUMMARY on the item row, never a history: `served_content_sig` (the content
//! identity of the only content served in the current epoch) and `served_mixed` (a second,
//! different content was served). The transitions are strictly monotone WITHIN an epoch:
//!
//! ```text
//!   never served  + A  =>  Single(A)
//!   Single(A)     + A  =>  Single(A)
//!   Single(A)     + B  =>  Mixed
//!   Mixed         + any =>  Mixed
//! ```
//!
//! INVARIANT: may-have-served provenance is monotone WITHIN an epoch. An ordinary remote update,
//! an announcement, a working-set removal and re-add, a restart, a signal, an eviction and a timer
//! release never forget a possibility. Only a trusted local edit that durable state alone proves
//! to be made from the epoch's only possible base (`Single(base)`) may start the NEXT epoch, in
//! the same transaction as the canonical version and the generation update: the summary becomes
//! `Single(new content)` and the generation advances, so every callback still naming the old
//! generation is stale and never trusted. `Mixed` is ABSORBING: `Mixed` + anything is `Mixed`,
//! and `Mixed` never becomes `Single` again, not even through a trusted edit (an edit on a mixed
//! item is untrusted by the predicate, so no epoch can start). A new `root_id` or `item_id` is a
//! new identity with a new row. There is no bounded history, so no old content is garbage
//! collected into trust.
//!
//! DURABILITY ORDER (mandatory): [`ProviderRepository::record_may_serve`] commits BEFORE the
//! bytes are sent; if it fails nothing is served. The update is one `UPDATE` with `CASE`
//! expressions, so concurrent handoffs of different content cannot lose an update: the result
//! is always `Mixed`.
//!
//! Nothing the host or the OS reports is an input: the handoff presence evidence
//! (`provider_handoffs`) is a different thing for a different purpose (is the content present on
//! the OS) and is never read by [`edit_base_trusted`].

use rusqlite::OptionalExtension;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::VersionHash;

use crate::error::SyncSqliteError;
use crate::provider::{current_version, ItemId, ProviderRepository};

/// The identity of a version's CONTENT: its size, blocks, kind and symlink target, never its
/// metadata. Provenance compares contents by this one function.
pub fn content_sig(version: &FileVersion) -> String {
    let mut sig = format!("{}|{:?}|", version.size, version.meta.record_kind);
    for block in &version.blocks {
        sig.push_str(&hex_of(&block.hash.0));
        sig.push(':');
        sig.push_str(&block.size.to_string());
        sig.push(',');
    }
    sig.push('|');
    if let Some(target) = &version.meta.symlink_target {
        sig.push_str(&hex_of(target));
    }
    sig
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What an item's sticky summary says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Served {
    /// No content was ever served: the absence of a record is NEVER positive evidence.
    Never,
    /// Exactly one content was ever served.
    Single(String),
    /// Two different contents were served: forever.
    Mixed,
}

/// What the trust decision is made from (all of it committed state).
#[derive(Clone, Debug)]
pub struct ProvenanceInput {
    /// The version the OS names as the one the edit is based on, and the item's current version.
    pub base: Option<VersionHash>,
    pub current: VersionHash,
    /// The content identity of the base version (`None` when the base is not a known version).
    pub base_content_sig: Option<String>,
    /// The item's current generation, and the generation the OS named (absent = unknown).
    pub item_generation: u64,
    pub base_generation: Option<u64>,
    /// Whether an announcement of a newer version is in flight.
    pub announce_in_flight: bool,
    pub served: Served,
}

/// THE trust predicate: may an edit based on `base` be authored in place as an edit of it?
///
/// Exactly: the view is current (`base_generation == item_generation`, `base == current`, no
/// announcement in flight) AND the sticky summary is `Single` with the base's content. `Never` is
/// not trusted (nothing positive is known), `Mixed` is not trusted (older different bytes may
/// still be served from the OS's cache). No OS observation is an input, and the only value the OS
/// supplies (`base_generation`) can only make the answer false. A write that should be trusted
/// (a create, a trusted edit) sets the summary on ITS OWN write path; the predicate has no special
/// cases.
pub fn edit_base_trusted(input: &ProvenanceInput) -> bool {
    if input.base_generation != Some(input.item_generation)
        || input.base != Some(input.current)
        || input.announce_in_flight
    {
        return false;
    }
    match (&input.served, &input.base_content_sig) {
        (Served::Single(served), Some(base)) => served == base,
        _ => false,
    }
}

/// The monotone transition of the summary for `sig`, in the caller's transaction, as ONE
/// statement (a concurrent handoff of other content can never be lost).
fn serve_in_tx(
    tx: &rusqlite::Transaction<'_>,
    root_id: &str,
    item_id: &ItemId,
    sig: &str,
) -> Result<(), SyncSqliteError> {
    tx.execute(
        "UPDATE provider_items SET \
            served_mixed = CASE \
                WHEN served_mixed = 1 THEN 1 \
                WHEN served_content_sig IS NULL THEN 0 \
                WHEN served_content_sig = ?3 THEN 0 \
                ELSE 1 END, \
            served_content_sig = CASE \
                WHEN served_mixed = 1 THEN served_content_sig \
                WHEN served_content_sig IS NULL THEN ?3 \
                ELSE served_content_sig END \
         WHERE root_id = ?1 AND item_id = ?2",
        rusqlite::params![root_id, &item_id[..], sig],
    )?;
    Ok(())
}

/// Starts a provenance epoch for a write this device AUTHORED from the OS's own bytes (a create,
/// or a trusted edit made from the epoch's only possible base): the OS holds exactly this content
/// for the item, so the summary is `Single(sig)`. The caller advances the generation in the same
/// transaction. Never applied to a `Mixed` item: `Mixed` is absorbing.
pub(crate) fn authored_in_tx(
    tx: &rusqlite::Transaction<'_>,
    root_id: &str,
    item_id: &ItemId,
    sig: &str,
) -> Result<(), SyncSqliteError> {
    tx.execute(
        "UPDATE provider_items SET served_content_sig = ?3 \
         WHERE root_id = ?1 AND item_id = ?2 AND served_mixed = 0",
        rusqlite::params![root_id, &item_id[..], sig],
    )?;
    Ok(())
}

pub(crate) fn served_in(
    conn: &rusqlite::Connection,
    root_id: &str,
    item_id: &ItemId,
) -> Result<Served, SyncSqliteError> {
    let row: Option<(Option<String>, bool)> = conn
        .query_row(
            "SELECT served_content_sig, served_mixed FROM provider_items \
             WHERE root_id = ?1 AND item_id = ?2",
            rusqlite::params![root_id, &item_id[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(match row {
        Some((_, true)) => Served::Mixed,
        Some((Some(sig), false)) => Served::Single(sig),
        _ => Served::Never,
    })
}

impl ProviderRepository {
    /// BEFORE any bytes of `version` may reach the OS: records that this content MAY HAVE been
    /// served. The transaction commits before the caller sends anything; an error means NOTHING
    /// is served. `None` when the item is gone or `version` is no longer its current version
    /// (nothing is recorded and nothing may be sent); otherwise the item's generation in the same
    /// transaction, which with `version` forms the 40-byte token these bytes are paired with.
    ///
    /// As a LIVENESS convenience only, a handoff of the announced version also publishes it (the
    /// OS asked for it): this never affects the summary or any trust decision.
    pub fn record_may_serve(
        &self,
        root_id: &str,
        item_id: &ItemId,
        version: VersionHash,
    ) -> Result<Option<u64>, SyncSqliteError> {
        self.database_for_write().write_immediate::<_, SyncSqliteError>(|tx| {
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
            let sig = match current_version(tx, &group_id, &path)? {
                Some(current) if current.version_hash == version => content_sig(&current),
                _ => return Ok(None),
            };
            serve_in_tx(tx, root_id, item_id, &sig)?;
            tx.execute(
                "UPDATE provider_items SET published_version_hash = announce_version_hash, \
                 announce_version_hash = NULL, announce_seq = NULL, pending_since = NULL, \
                 unconfirmed_since = NULL \
                 WHERE root_id = ?1 AND item_id = ?2 AND announce_version_hash = ?3",
                rusqlite::params![root_id, &item_id[..], &version.0[..]],
            )?;
            tx.execute(
                "UPDATE provider_items SET unconfirmed_since = NULL \
                 WHERE root_id = ?1 AND item_id = ?2 AND published_version_hash = ?3",
                rusqlite::params![root_id, &item_id[..], &version.0[..]],
            )?;
            let generation: i64 = tx.query_row(
                "SELECT generation FROM provider_items WHERE root_id = ?1 AND item_id = ?2",
                rusqlite::params![root_id, &item_id[..]],
                |r| r.get(0),
            )?;
            Ok(Some(generation as u64))
        })
    }

    /// The sticky summary of an item.
    pub fn served(&self, root_id: &str, item_id: &ItemId) -> Result<Served, SyncSqliteError> {
        self.database_for_write()
            .read::<_, SyncSqliteError>(|conn| served_in(conn, root_id, item_id))
    }

    /// TEST SEAM: records that content with identity `sig` may have been served, with no version
    /// check (the concurrency test serves several contents at once).
    #[cfg(test)]
    pub(crate) fn record_served_sig_for_tests(
        &self,
        root_id: &str,
        item_id: &ItemId,
        sig: &str,
    ) -> Result<(), SyncSqliteError> {
        self.database_for_write()
            .write_immediate::<_, SyncSqliteError>(|tx| serve_in_tx(tx, root_id, item_id, sig))
    }
}
