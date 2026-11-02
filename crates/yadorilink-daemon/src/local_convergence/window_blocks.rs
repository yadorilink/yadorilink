//! Blocks a receive pass holds in memory instead of in the block store.
//!
//! With single-pass receive (the default), the blocks of a small file that a pass fetched are not
//! committed to the block store (an fsync wave, a store-index transaction and a provenance
//! transaction per batch); they stay here until the pass has written the file, and are read from
//! here by the assembly and the checks that follow it. Nothing in this module is durable: a block
//! that is gone when it is asked for again is fetched again.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use yadorilink_local_storage::{BlockContentStore, ContentHash, LocallyHashedBlock, StorageError};

/// The most memory the blocks held for passes may use at once.
pub(crate) const WINDOW_BLOCKS_CAPACITY_BYTES: u64 = 64 * 1024 * 1024;

/// Files above this size are not held in memory: their blocks go to the store as before, so a large
/// file never occupies the budget that a window of small ones needs.
pub(crate) const WINDOW_BLOCKS_FILE_MAX_BYTES: u64 = 4 * 1024 * 1024;

struct Entry {
    bytes: Arc<Vec<u8>>,
    /// group -> number of passes of that group holding the block. A block is a group's to use only
    /// while a pass of that group holds it: bytes another group fetched are not this group's.
    holders: HashMap<String, u32>,
}

#[derive(Default)]
struct State {
    blocks: HashMap<String, Entry>,
    bytes: u64,
}

pub(crate) struct WindowBlocks {
    state: Mutex<State>,
    capacity_bytes: u64,
}

impl WindowBlocks {
    pub(crate) fn new(capacity_bytes: u64) -> Self {
        Self { state: Mutex::new(State::default()), capacity_bytes }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Holds `data` under `hash_hex` for one more pass of `group_id`. `false` when the budget has
    /// no room for a new block; a block already held is always taken (it costs nothing).
    pub(crate) fn try_hold(&self, group_id: &str, hash_hex: &str, data: &[u8]) -> bool {
        let mut state = self.lock();
        if let Some(entry) = state.blocks.get_mut(hash_hex) {
            *entry.holders.entry(group_id.to_owned()).or_insert(0) += 1;
            return true;
        }
        let len = data.len() as u64;
        if state.bytes + len > self.capacity_bytes {
            return false;
        }
        state.bytes += len;
        state.blocks.insert(
            hash_hex.to_owned(),
            Entry {
                bytes: Arc::new(data.to_vec()),
                holders: HashMap::from([(group_id.to_owned(), 1)]),
            },
        );
        true
    }

    /// One pass of `group_id` lets go of `hash_hex`; the block is dropped when no pass holds it.
    pub(crate) fn release(&self, group_id: &str, hash_hex: &str) {
        let mut state = self.lock();
        let Some(entry) = state.blocks.get_mut(hash_hex) else { return };
        if let Some(count) = entry.holders.get_mut(group_id) {
            *count -= 1;
            if *count == 0 {
                entry.holders.remove(group_id);
            }
        }
        if !entry.holders.is_empty() {
            return;
        }
        let len = entry.bytes.len() as u64;
        state.blocks.remove(hash_hex);
        state.bytes -= len;
    }

    /// Whether a pass of `group_id` holds `hash_hex`: the question that decides whether a file of
    /// that group may be written from it.
    pub(crate) fn held_for(&self, group_id: &str, hash_hex: &str) -> bool {
        self.lock().blocks.get(hash_hex).is_some_and(|entry| entry.holders.contains_key(group_id))
    }

    /// Whether any pass holds `hash_hex`. Only for reading bytes a group-aware check has already
    /// admitted.
    pub(crate) fn contains(&self, hash_hex: &str) -> bool {
        self.lock().blocks.contains_key(hash_hex)
    }

    fn get(&self, hash_hex: &str) -> Option<Arc<Vec<u8>>> {
        self.lock().blocks.get(hash_hex).map(|entry| Arc::clone(&entry.bytes))
    }

    #[cfg(test)]
    pub(crate) fn held_bytes(&self) -> u64 {
        self.lock().bytes
    }
}

/// What one pass of one group holds; dropping it lets go of every block, however the pass ends. The
/// hold is created where the blocks are taken, so it is released also when whoever was to receive it
/// is gone.
pub(crate) struct WindowBlocksHold {
    cache: Arc<WindowBlocks>,
    group_id: String,
    hashes: Vec<String>,
}

impl WindowBlocksHold {
    pub(crate) fn new(cache: Arc<WindowBlocks>, group_id: &str) -> Self {
        Self { cache, group_id: group_id.to_owned(), hashes: Vec::new() }
    }

    /// Holds one more block for this pass; `false` when the budget has no room.
    pub(crate) fn try_hold(&mut self, hash_hex: &str, data: &[u8]) -> bool {
        let held = self.cache.try_hold(&self.group_id, hash_hex, data);
        if held {
            self.hashes.push(hash_hex.to_owned());
        }
        held
    }

    /// Takes over what `other` holds; `other` then holds nothing.
    pub(crate) fn absorb(&mut self, other: &mut WindowBlocksHold) {
        self.hashes.append(&mut other.hashes);
    }
}

impl Drop for WindowBlocksHold {
    fn drop(&mut self) {
        for hash in &self.hashes {
            self.cache.release(&self.group_id, hash);
        }
    }
}

/// The executor's view of block content: the block store, with the blocks the passes in flight hold
/// in memory read first. Writes go to the store untouched.
pub(crate) struct WindowOverlayStore {
    inner: Arc<dyn BlockContentStore>,
    cache: Arc<WindowBlocks>,
}

impl WindowOverlayStore {
    pub(crate) fn new(inner: Arc<dyn BlockContentStore>, cache: Arc<WindowBlocks>) -> Self {
        Self { inner, cache }
    }
}

impl BlockContentStore for WindowOverlayStore {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        self.inner.put(data)
    }

    fn put_prepared(&self, prepared: &LocallyHashedBlock) -> Result<(), StorageError> {
        self.inner.put_prepared(prepared)
    }

    fn put_prepared_batch(&self, prepared: &[LocallyHashedBlock]) -> Result<(), StorageError> {
        self.inner.put_prepared_batch(prepared)
    }

    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        match self.cache.get(hash) {
            Some(bytes) => Ok(bytes.as_ref().clone()),
            None => self.inner.get(hash),
        }
    }

    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        let mut present = self.inner.present_blocks(hashes)?;
        for (hash, present) in hashes.iter().zip(present.iter_mut()) {
            if !*present {
                *present = self.cache.contains(hash);
            }
        }
        Ok(present)
    }

    fn data_dir(&self) -> Option<&std::path::Path> {
        self.inner.data_dir()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_block_is_held_until_its_last_pass_lets_go_and_the_budget_is_kept() {
        let cache = Arc::new(WindowBlocks::new(10));
        assert!(cache.try_hold("g", "a", &[1; 6]));
        assert!(cache.try_hold("g", "a", &[1; 6]), "a block already held costs nothing");
        assert_eq!(cache.held_bytes(), 6);
        assert!(!cache.try_hold("g", "b", &[2; 6]), "no room for a second block");
        cache.release("g", "a");
        assert!(cache.contains("a"), "one pass still holds it");
        cache.release("g", "a");
        assert!(!cache.contains("a"));
        assert_eq!(cache.held_bytes(), 0);
        assert!(cache.try_hold("g", "b", &[2; 6]));
    }

    #[test]
    fn a_block_one_group_holds_is_not_held_for_another_group() {
        let cache = Arc::new(WindowBlocks::new(100));
        assert!(cache.try_hold("a", "h", &[1; 4]));
        assert!(cache.held_for("a", "h"));
        assert!(!cache.held_for("b", "h"), "another group's pass is not this group's proof");
        assert!(cache.try_hold("b", "h", &[1; 4]));
        assert!(cache.held_for("b", "h"));
        cache.release("a", "h");
        assert!(!cache.held_for("a", "h") && cache.held_for("b", "h"));
        cache.release("b", "h");
        assert!(!cache.contains("h"));
    }

    #[test]
    fn dropping_a_hold_releases_every_block_it_took_and_a_merged_hold_takes_them_over() {
        let cache = Arc::new(WindowBlocks::new(100));
        let mut batch = WindowBlocksHold::new(cache.clone(), "g");
        assert!(batch.try_hold("a", &[1; 4]));
        assert!(batch.try_hold("b", &[2; 4]));
        let mut pass = WindowBlocksHold::new(cache.clone(), "g");
        pass.absorb(&mut batch);
        drop(batch);
        assert_eq!(
            cache.held_bytes(),
            8,
            "the batch's drop must not release what the pass took over"
        );
        drop(pass);
        assert_eq!(cache.held_bytes(), 0);
    }

    #[test]
    fn a_batch_hold_nobody_received_releases_on_drop() {
        let cache = Arc::new(WindowBlocks::new(100));
        let mut batch = WindowBlocksHold::new(cache.clone(), "g");
        assert!(batch.try_hold("a", &[1; 4]));
        drop(batch);
        assert_eq!(cache.held_bytes(), 0);
    }
}
