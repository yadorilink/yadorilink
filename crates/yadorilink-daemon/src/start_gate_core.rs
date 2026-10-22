//! The slot table and start gate behind `LinkRegistry`, kept free of daemon types so the
//! Shuttle explorer (`xtask/tests/shuttle_races.rs`) can compile this exact file with
//! `#[path]` against a scheduler-aware `sync_facade` and explore the real code.
//!
//! Invariant: the gate is read under the same lock as the reservation, so once `close_gate`
//! has returned no `reserve` can add a slot, and a safe stop's snapshot of the table cannot
//! grow under it.
//!
//! This file may only depend on `crate::sync_facade` and `std` collections.

use std::collections::HashMap;

use crate::sync_facade::{AtomicUsize, Mutex, MutexGuard, Ordering};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReserveError {
    GateClosed,
    Occupied,
}

pub(crate) struct SlotTable<S> {
    slots: Mutex<HashMap<String, S>>,
    /// How many safe-stop requests hold the gate; above zero no slot may be reserved.
    gate: AtomicUsize,
}

impl<S> SlotTable<S> {
    pub(crate) fn new() -> Self {
        Self { slots: Mutex::new(HashMap::new()), gate: AtomicUsize::new(0) }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, HashMap<String, S>> {
        self.slots.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn close_gate(&self) {
        let _guard = self.lock();
        self.gate.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn open_gate(&self) {
        let _guard = self.lock();
        self.gate.fetch_sub(1, Ordering::SeqCst);
    }

    pub(crate) fn reserve(&self, path: String, slot: S) -> Result<(), ReserveError> {
        let mut slots = self.lock();
        if self.gate.load(Ordering::SeqCst) > 0 {
            return Err(ReserveError::GateClosed);
        }
        if slots.contains_key(&path) {
            return Err(ReserveError::Occupied);
        }
        slots.insert(path, slot);
        Ok(())
    }
}
