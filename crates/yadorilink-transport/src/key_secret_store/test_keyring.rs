#![cfg(test)]

use std::cell::{Cell, RefCell};
use std::collections::HashMap;

thread_local! {
    static STORE: RefCell<HashMap<String, [u8; 32]>> = RefCell::new(HashMap::new());
    static CALLS: Cell<usize> = const { Cell::new(0) };
    static AVAILABLE: Cell<bool> = const { Cell::new(false) };
    static FAIL_WRITES: Cell<bool> = const { Cell::new(false) };
    static FAIL_DELETES: Cell<bool> = const { Cell::new(false) };
}

/// Reads and writes keep working, deletes are refused.
pub(super) fn set_fail_deletes(value: bool) {
    FAIL_DELETES.with(|f| f.set(value));
}

/// Removes `key`; an unavailable keyring or a refused delete is a failure, a missing entry is not.
pub(super) fn delete(key: &str) -> super::StoreDelete {
    count_call();
    if !is_available() {
        return super::StoreDelete::Failed("keyring unavailable".into());
    }
    if FAIL_DELETES.with(Cell::get) {
        return super::StoreDelete::Failed("delete refused".into());
    }
    match STORE.with(|s| s.borrow_mut().remove(key)) {
        Some(_) => super::StoreDelete::Deleted,
        None => super::StoreDelete::Absent,
    }
}

/// Reads keep working, writes are refused (a locked keyring).
pub(super) fn set_fail_writes(value: bool) {
    FAIL_WRITES.with(|f| f.set(value));
}

pub(super) fn set_available(value: bool) {
    AVAILABLE.with(|a| a.set(value));
}

fn is_available() -> bool {
    AVAILABLE.with(Cell::get)
}

/// Backend operations (get/set) issued so far on this thread.
pub(super) fn calls() -> usize {
    CALLS.with(Cell::get)
}

fn count_call() {
    CALLS.with(|c| c.set(c.get() + 1));
}

pub(super) fn reset() {
    CALLS.with(|c| c.set(0));
    STORE.with(|s| s.borrow_mut().clear());
    set_available(false);
    set_fail_writes(false);
    set_fail_deletes(false);
}

pub(super) fn get(key: &str) -> Option<[u8; 32]> {
    count_call();
    if !is_available() {
        return None;
    }
    STORE.with(|s| s.borrow().get(key).copied())
}

pub(super) fn set(key: &str, value: &[u8; 32]) -> bool {
    count_call();
    if !is_available() || FAIL_WRITES.with(Cell::get) {
        return false;
    }
    STORE.with(|s| s.borrow_mut().insert(key.to_string(), *value));
    true
}

/// `None`: the keyring cannot be asked (locked or unavailable); `Some(None)`: asked, no entry.
pub(super) fn probe(key: &str) -> Option<Option<[u8; 32]>> {
    count_call();
    if !is_available() {
        return None;
    }
    Some(STORE.with(|s| s.borrow().get(key).copied()))
}
