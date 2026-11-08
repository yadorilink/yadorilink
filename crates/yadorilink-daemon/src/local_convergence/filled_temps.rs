//! Temp files of large received files that are completely written and verified, waiting for their
//! settle (single-pass receive, large files).
//!
//! An entry is `Ready`: every block written at its offset, the data flushed and the written bytes
//! read back and checked against the record. Nothing partly filled is ever in this registry, so the
//! settle's availability check may treat a match as "the content is here" without asking anything
//! else. The key is the exact (group, path, version): an entry built for one version can never be
//! taken for another.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use yadorilink_local_storage::TempFileLedger;

/// (group, path, version hash as hex)
pub(crate) type FilledKey = (String, String, String);

/// A completely written, flushed and verified temp, beside its target and recorded in the temp
/// ledger. It carries what must live until the file is in place: the disk headroom reserved for it
/// and its entry in the status model's active transfers.
pub(crate) struct ReadyTemp {
    /// Which registration this is: a pass discards only what it registered itself.
    pub(crate) id: u64,
    pub(crate) tmp_path: PathBuf,
    pub(crate) ledger: Arc<dyn TempFileLedger>,
    pub(crate) reservation: Arc<super::reconcile::HeadroomReservation>,
    pub(crate) progress: Option<crate::transfer_progress::TransferProgressGuard>,
    /// What the temp looked like when its data had been flushed and read back: a flush that is
    /// owed later is skipped only for a temp still exactly so.
    pub(crate) flushed: Option<yadorilink_local_storage::FlushedStamp>,
    /// The object the temp's handle wrote and verified; the rename and the flush barrier accept
    /// the name only while it still leads to this object.
    pub(crate) object: Option<yadorilink_local_storage::ObjectKey>,
}

impl ReadyTemp {
    /// Removes the temp and releases its ledger record. Blocking.
    pub(crate) fn discard(&self) {
        yadorilink_local_storage::discard_temp_file(&self.tmp_path, self.ledger.as_ref());
    }
}

/// How long a partly filled temp is kept for a later attempt of its version.
pub(crate) const PARKED_TEMP_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(600);

/// A partly filled large-file temp kept after an attempt ended (a dropped link, a peer that
/// answered nothing, a timeout) so that the next attempt of the same version in this process does
/// not fetch again what is already in it. Nothing in it is trusted: the claims are blocks the
/// attempt wrote, and the next attempt reads each back and hashes it before counting it. It holds
/// the file's disk reservation while it exists, and is dropped (the temp removed through its
/// ledger) when its version is superseded, when it is too old, or when the process ends.
pub(crate) struct ParkedTemp {
    pub(crate) staged: Arc<yadorilink_local_storage::StagedFile>,
    pub(crate) reservation: Arc<super::reconcile::HeadroomReservation>,
    /// Hashes the attempt wrote at all their offsets.
    pub(crate) written: std::collections::HashSet<Vec<u8>>,
    pub(crate) parked_at: std::time::Instant,
}

/// The partly filled temps, by (group, path, version). At most one per (group, path).
#[derive(Default)]
pub(crate) struct PartialTemps {
    parked: Mutex<HashMap<FilledKey, ParkedTemp>>,
}

impl PartialTemps {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<FilledKey, ParkedTemp>> {
        self.parked.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Keeps `temp` for the next attempt of exactly this version; whatever was kept for the path
    /// (this version or another) is dropped, and so is anything too old.
    pub(crate) fn park(&self, key: FilledKey, temp: ParkedTemp) {
        let mut parked = self.lock();
        parked.retain(|other, kept| {
            !(other.0 == key.0 && other.1 == key.1)
                && kept.parked_at.elapsed() <= PARKED_TEMP_MAX_AGE
        });
        parked.insert(key, temp);
    }

    /// The temp kept for exactly this (group, path, version), if it is not too old. Any other
    /// version kept for the path is superseded and dropped.
    pub(crate) fn take(&self, key: &FilledKey) -> Option<ParkedTemp> {
        let mut parked = self.lock();
        parked.retain(|other, kept| {
            (other == key || !(other.0 == key.0 && other.1 == key.1))
                && kept.parked_at.elapsed() <= PARKED_TEMP_MAX_AGE
        });
        parked.remove(key)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drops what is too old. A parked temp holds its file's disk reservation, so this runs at the
    /// start of every receive pass, not only when another temp is parked or taken.
    pub(crate) fn purge_expired(&self) {
        self.lock().retain(|_, kept| kept.parked_at.elapsed() <= PARKED_TEMP_MAX_AGE);
    }
}

#[derive(Default)]
pub(crate) struct FilledTemps {
    ready: Mutex<HashMap<FilledKey, ReadyTemp>>,
    next_id: std::sync::atomic::AtomicU64,
}

impl FilledTemps {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<FilledKey, ReadyTemp>> {
        self.ready.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Registers a ready temp. An entry already there for the same key is returned: the caller
    /// owns its discard.
    pub(crate) fn insert_ready(&self, key: FilledKey, temp: ReadyTemp) -> Option<ReadyTemp> {
        self.lock().insert(key, temp)
    }

    /// A fresh registration id.
    pub(crate) fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1
    }

    /// Removes the entry for `key` only if it is the registration `id`: another pass's entry that
    /// replaced it is not this pass's to discard.
    fn take_registered(&self, key: &FilledKey, id: u64) -> Option<ReadyTemp> {
        let mut ready = self.lock();
        if ready.get(key).is_some_and(|temp| temp.id == id) {
            ready.remove(key)
        } else {
            None
        }
    }

    /// Whether a ready temp exists for exactly this (group, path, version).
    pub(crate) fn holds(&self, group_id: &str, path: &str, version_hex: &str) -> bool {
        self.lock().contains_key(&(group_id.to_owned(), path.to_owned(), version_hex.to_owned()))
    }

    /// Hands the ready temp for exactly this key to the settle, which then owns it.
    pub(crate) fn take(&self, group_id: &str, path: &str, version_hex: &str) -> Option<ReadyTemp> {
        self.lock().remove(&(group_id.to_owned(), path.to_owned(), version_hex.to_owned()))
    }
}

/// Removes the temps on a blocking thread: the discard unlinks a file and flushes a directory, so it
/// must not run on a runtime worker.
fn discard_in_background(temps: Vec<ReadyTemp>) {
    if temps.is_empty() {
        return;
    }
    let discard = move || temps.iter().for_each(ReadyTemp::discard);
    match tokio::runtime::Handle::try_current() {
        Ok(runtime) => {
            runtime.spawn_blocking(discard);
        }
        Err(_) => discard(),
    }
}

/// A ready temp the settle has taken. Unless it is handed on to the rename (`into_inner`), dropping
/// it, on any way out of the settle, removes the temp.
pub(crate) struct TakenReady(Option<ReadyTemp>, bool);

impl TakenReady {
    pub(crate) fn new(temp: ReadyTemp) -> Self {
        Self(Some(temp), true)
    }

    pub(crate) fn reservation(&self) -> &Arc<super::reconcile::HeadroomReservation> {
        &self.0.as_ref().expect("a taken temp is present until handed on").reservation
    }

    pub(crate) fn tmp_path(&self) -> PathBuf {
        self.0.as_ref().expect("a taken temp is present until handed on").tmp_path.clone()
    }

    /// The entry in the status model's transfers, to keep until the file is in place.
    pub(crate) fn take_progress(
        &mut self,
    ) -> Option<crate::transfer_progress::TransferProgressGuard> {
        self.0.as_mut().and_then(|temp| temp.progress.take())
    }

    /// The stamp of the temp as it was when its data was flushed.
    pub(crate) fn data_flushed(&self) -> Option<yadorilink_local_storage::FlushedStamp> {
        self.0.as_ref().and_then(|temp| temp.flushed)
    }

    /// The object the temp's handle wrote and verified.
    pub(crate) fn object(&self) -> Option<yadorilink_local_storage::ObjectKey> {
        self.0.as_ref().and_then(|temp| temp.object)
    }

    /// Whether dropping this removes the temp. A caller that takes the removal over for a while
    /// (it needs to keep the ledger record when the sync root is lost) turns it off and back on.
    pub(crate) fn set_cleanup_on_drop(&mut self, on: bool) {
        self.1 = on;
    }

    /// Hands the temp on to whoever now owns its removal (the rename removes it on failure).
    pub(crate) fn defuse(mut self) {
        self.0.take();
    }
}

impl Drop for TakenReady {
    fn drop(&mut self) {
        if let Some(temp) = self.0.take() {
            if self.1 {
                discard_in_background(vec![temp]);
            }
        }
    }
}

/// The ready temps one pass registered; what the settle did not take is discarded when the pass ends
/// or is dropped, on a blocking thread (the discard removes a file and flushes a directory).
pub(crate) struct FilledTempsHold {
    registry: Arc<FilledTemps>,
    keys: Vec<(FilledKey, u64)>,
}

impl FilledTempsHold {
    pub(crate) fn new(registry: Arc<FilledTemps>) -> Self {
        Self { registry, keys: Vec::new() }
    }

    pub(crate) fn push(&mut self, key: FilledKey, id: u64) {
        self.keys.push((key, id));
    }
}

impl Drop for FilledTempsHold {
    fn drop(&mut self) {
        let left: Vec<ReadyTemp> = std::mem::take(&mut self.keys)
            .into_iter()
            .filter_map(|(key, id)| self.registry.take_registered(&key, id))
            .collect();
        discard_in_background(left);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(version: &str) -> FilledKey {
        ("g".into(), "big.bin".into(), version.into())
    }

    fn temp(name: &str) -> ReadyTemp {
        ReadyTemp {
            id: 0,
            tmp_path: PathBuf::from(name),
            ledger: Arc::new(yadorilink_local_storage::NoTempLedger),
            reservation: Arc::new(
                crate::local_convergence::reconcile::HeadroomReservation::for_tests(
                    "filled-temps-test",
                    0,
                ),
            ),
            progress: None,
            flushed: None,
            object: None,
        }
    }

    fn path_of(temp: Option<ReadyTemp>) -> Option<PathBuf> {
        temp.map(|temp| temp.tmp_path)
    }

    #[test]
    fn only_the_exact_group_path_and_version_is_held_and_taking_hands_it_over_once() {
        let registry = FilledTemps::default();
        assert!(registry.insert_ready(key("v1"), temp("t1")).is_none());
        assert!(registry.holds("g", "big.bin", "v1"));
        assert!(!registry.holds("g", "big.bin", "v2"), "another version is not this one");
        assert!(!registry.holds("g", "other.bin", "v1"), "another path");
        assert!(!registry.holds("h", "big.bin", "v1"), "another group");
        assert_eq!(path_of(registry.take("g", "big.bin", "v1")), Some(PathBuf::from("t1")));
        assert!(registry.take("g", "big.bin", "v1").is_none(), "the settle owns it now");
        assert!(!registry.holds("g", "big.bin", "v1"));
    }

    #[test]
    fn a_second_entry_for_the_same_key_hands_the_first_back_for_its_discard() {
        let registry = FilledTemps::default();
        registry.insert_ready(key("v1"), temp("old"));
        assert_eq!(
            path_of(registry.insert_ready(key("v1"), temp("new"))),
            Some(PathBuf::from("old"))
        );
        assert!(registry.take("g", "big.bin", "v1").is_some());
        assert!(registry.take("g", "big.bin", "v1").is_none());
    }

    fn temp_in(dir: &std::path::Path, name: &str, id: u64) -> ReadyTemp {
        let tmp_path = dir.join(name);
        std::fs::write(&tmp_path, b"x").unwrap();
        ReadyTemp { id, tmp_path, ..temp(name) }
    }

    #[test]
    fn a_pass_discards_only_the_temp_it_registered_itself() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(FilledTemps::default());
        let mut older = FilledTempsHold::new(registry.clone());
        let first = registry.next_id();
        assert!(registry.insert_ready(key("v1"), temp_in(dir.path(), "first", first)).is_none());
        older.push(key("v1"), first);
        // Another pass registers the same key and takes the entry over (the first is its to discard).
        let second = registry.next_id();
        let replaced =
            registry.insert_ready(key("v1"), temp_in(dir.path(), "second", second)).unwrap();
        replaced.discard();

        drop(older);

        assert!(registry.holds("g", "big.bin", "v1"), "the newer pass's entry is still registered");
        assert!(dir.path().join("second").exists(), "and its temp is still there");
    }

    #[test]
    fn a_taken_temp_is_removed_on_any_way_out_until_it_is_handed_on() {
        let dir = tempfile::tempdir().unwrap();
        let dropped = TakenReady::new(temp_in(dir.path(), "dropped", 1));
        drop(dropped);
        assert!(!dir.path().join("dropped").exists(), "a settle that failed leaves no temp");

        let handed_on = TakenReady::new(temp_in(dir.path(), "handed-on", 2));
        handed_on.defuse();
        assert!(dir.path().join("handed-on").exists(), "once the rename owns it, the guard is off");
    }

    #[cfg(unix)]
    fn parked_in(dir: &std::path::Path, name: &str, age: std::time::Duration) -> ParkedTemp {
        let staged = yadorilink_local_storage::StagedFile::create(
            &dir.join(name),
            4,
            Arc::new(yadorilink_local_storage::NoTempLedger),
        )
        .unwrap();
        ParkedTemp {
            staged: Arc::new(staged),
            reservation: temp("x").reservation,
            written: std::collections::HashSet::from([vec![1u8]]),
            parked_at: std::time::Instant::now().checked_sub(age).unwrap(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_kept_temp_is_given_up_after_its_age_and_for_a_newer_version() {
        let dir = tempfile::tempdir().unwrap();
        let kept = PartialTemps::default();
        // Too old: not handed out, and its temp is removed.
        kept.park(key("v1"), parked_in(dir.path(), "a", PARKED_TEMP_MAX_AGE * 2));
        assert!(kept.take(&key("v1")).is_none());
        assert_eq!(kept.len(), 0);
        // Fresh: handed out once.
        kept.park(key("v1"), parked_in(dir.path(), "b", std::time::Duration::ZERO));
        assert!(kept.take(&key("v1")).is_some());
        assert!(kept.take(&key("v1")).is_none());
        // A newer version of the path drops the older one's.
        kept.park(key("v1"), parked_in(dir.path(), "c", std::time::Duration::ZERO));
        assert!(kept.take(&key("v2")).is_none());
        assert_eq!(kept.len(), 0, "the superseded version's temp was dropped");
        let leftovers = std::fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(leftovers, 0, "every dropped temp was removed from disk");
        // A pass start drops what is too old although nothing else is parked or taken.
        kept.park(key("v1"), parked_in(dir.path(), "d", PARKED_TEMP_MAX_AGE * 2));
        kept.purge_expired();
        assert_eq!(kept.len(), 0);
    }
}
