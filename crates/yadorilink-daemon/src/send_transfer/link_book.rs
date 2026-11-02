//! The Send links this device created, kept in a small file beside Track Send's own store.
//!
//! The coordination service keeps a link's state but does not list a sender's links, and
//! which transfer a link started is known only to the process that started it. This book holds
//! both across restarts: the list a front end shows ("my links"), and the link -> transfer
//! map that lets a granted link read as done or interrupted after the engine restarted instead
//! of as still transferring. The code is never written down: the service keeps only its hash
//! and the sender is shown it once.
//!
//! Bounded: entries expire out of the book a while after the link's own expiry, and at most
//! [`MAX_ENTRIES`] newest ones are kept.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// How long an entry stays listed after its link expired.
const KEEP_AFTER_EXPIRY_SECS: i64 = 30 * 24 * 60 * 60;

/// The most links kept.
const MAX_ENTRIES: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LinkRecord {
    pub(crate) link_id: String,
    pub(crate) created_at_unix: i64,
    pub(crate) expires_at_unix: i64,
    /// How many files the link was created to carry.
    #[serde(default)]
    pub(crate) file_count: u32,
    /// The transfer a send under this link started, once one did.
    #[serde(default)]
    pub(crate) transfer_id: Option<String>,
    /// Why the last send under this link stopped before an offer was accepted, when it did. The
    /// service has by then usually spent the link's one grant, so without this the link would
    /// read as still going.
    #[serde(default)]
    pub(crate) send_failure: Option<String>,
}

#[derive(Default, Serialize, Deserialize)]
struct Contents {
    #[serde(default)]
    links: Vec<LinkRecord>,
}

pub(crate) struct LinkBook {
    path: PathBuf,
    contents: Mutex<Contents>,
}

impl LinkBook {
    /// Opens the book in `dir`. A missing or unreadable file is an empty book: it holds
    /// conveniences, and the service still has every link.
    pub(crate) fn open(dir: &Path) -> Self {
        let path = dir.join("send_links.json");
        let contents = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|error| {
                tracing::warn!(%error, path = %path.display(), "the send link list is unreadable; starting empty");
                Contents::default()
            }),
            Err(_) => Contents::default(),
        };
        Self { path, contents: Mutex::new(contents) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Contents> {
        self.contents.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Newest first.
    pub(crate) fn list(&self) -> Vec<LinkRecord> {
        let mut links = self.lock().links.clone();
        links.sort_by_key(|l| std::cmp::Reverse(l.created_at_unix));
        links
    }

    pub(crate) fn transfer_of(&self, link_id: &str) -> Option<String> {
        self.lock().links.iter().find(|l| l.link_id == link_id)?.transfer_id.clone()
    }

    /// Notes a link just created.
    pub(crate) fn record(&self, record: LinkRecord, now_unix: i64) {
        let mut contents = self.lock();
        contents.links.retain(|l| l.link_id != record.link_id);
        contents.links.push(record);
        Self::prune(&mut contents, now_unix);
        self.save(&contents);
    }

    /// Notes that a send under `link_id` stopped with `reason` (or, with `None`, that the new
    /// attempt is under way).
    pub(crate) fn set_send_failure(&self, link_id: &str, reason: Option<&str>) {
        let mut contents = self.lock();
        if let Some(link) = contents.links.iter_mut().find(|l| l.link_id == link_id) {
            link.send_failure = reason.map(str::to_owned);
            self.save(&contents);
        }
    }

    pub(crate) fn send_failure_of(&self, link_id: &str) -> Option<String> {
        self.lock().links.iter().find(|l| l.link_id == link_id)?.send_failure.clone()
    }

    /// Notes the transfer a send under `link_id` started. A link the book does not hold (made
    /// before the book existed, or by another process) is not added: only the sender's own
    /// creation lists a link.
    pub(crate) fn set_transfer(&self, link_id: &str, transfer_id: &str) {
        let mut contents = self.lock();
        if let Some(link) = contents.links.iter_mut().find(|l| l.link_id == link_id) {
            link.transfer_id = Some(transfer_id.to_owned());
            link.send_failure = None;
            self.save(&contents);
        }
    }

    /// Drops a link the service no longer knows.
    pub(crate) fn forget(&self, link_id: &str) {
        let mut contents = self.lock();
        let before = contents.links.len();
        contents.links.retain(|l| l.link_id != link_id);
        if contents.links.len() != before {
            self.save(&contents);
        }
    }

    fn prune(contents: &mut Contents, now_unix: i64) {
        contents
            .links
            .retain(|l| l.expires_at_unix.saturating_add(KEEP_AFTER_EXPIRY_SECS) > now_unix);
        if contents.links.len() > MAX_ENTRIES {
            contents.links.sort_by_key(|l| std::cmp::Reverse(l.created_at_unix));
            contents.links.truncate(MAX_ENTRIES);
        }
    }

    /// Best effort (temp file, then rename): a failed write only means the list is shorter
    /// after a restart.
    fn save(&self, contents: &Contents) {
        let write = || -> std::io::Result<()> {
            if let Some(parent) = self.path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let tmp = self.path.with_extension("json.tmp");
            std::fs::write(&tmp, serde_json::to_vec(contents)?)?;
            std::fs::rename(&tmp, &self.path)
        };
        if let Err(error) = write() {
            tracing::warn!(%error, path = %self.path.display(), "could not save the send link list");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str, created: i64, expires: i64) -> LinkRecord {
        LinkRecord {
            link_id: id.into(),
            created_at_unix: created,
            expires_at_unix: expires,
            file_count: 1,
            transfer_id: None,
            send_failure: None,
        }
    }

    #[test]
    fn links_and_their_transfers_survive_a_reopen_newest_first() {
        let dir = tempfile::tempdir().unwrap();
        let book = LinkBook::open(dir.path());
        book.record(record("a", 10, 1_000), 20);
        book.record(record("b", 30, 1_000), 40);
        book.set_transfer("a", "t-1");
        let reopened = LinkBook::open(dir.path());
        let ids: Vec<_> = reopened.list().into_iter().map(|l| l.link_id).collect();
        assert_eq!(ids, ["b", "a"]);
        assert_eq!(reopened.transfer_of("a").as_deref(), Some("t-1"));
        assert_eq!(reopened.transfer_of("b"), None);
    }

    #[test]
    fn a_transfer_for_a_link_the_book_does_not_hold_is_not_listed() {
        let dir = tempfile::tempdir().unwrap();
        let book = LinkBook::open(dir.path());
        book.set_transfer("stranger", "t-1");
        assert!(book.list().is_empty());
    }

    #[test]
    fn long_expired_links_leave_the_book_and_it_stays_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let book = LinkBook::open(dir.path());
        book.record(record("old", 0, 100), 0);
        book.record(record("new", 1, 2_000_000_000), KEEP_AFTER_EXPIRY_SECS + 1_000);
        let ids: Vec<_> = book.list().into_iter().map(|l| l.link_id).collect();
        assert_eq!(ids, ["new"]);
        for i in 0..(MAX_ENTRIES + 20) {
            book.record(record(&format!("l{i}"), 10 + i as i64, 2_000_000_000), 0);
        }
        assert_eq!(book.list().len(), MAX_ENTRIES);
    }

    #[test]
    fn an_unreadable_file_is_an_empty_book_and_forget_removes_a_link() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("send_links.json"), "{ nope").unwrap();
        let book = LinkBook::open(dir.path());
        assert!(book.list().is_empty());
        book.record(record("a", 1, 2_000_000_000), 0);
        book.forget("a");
        assert!(LinkBook::open(dir.path()).list().is_empty());
    }
}
