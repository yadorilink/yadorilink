//! The Send links this device redeemed and has not yet received, kept in a small file beside Track
//! Send's own store.
//!
//! Redeeming is the person's one consent to receive what the link carries. The offer that
//! arrives later under that link is received by the engine without another step; this book is
//! how it knows the link is one the person redeemed, and where they want the files. An entry is
//! used up by the first offer that matches it: a link's grant is single-use, so one redeem
//! receives one offer. An offer under a link that is not here, like any offer without a link,
//! waits in the inbox for an explicit receive.
//!
//! Bounded: an entry goes once a link could no longer have an offer (links live at most a week),
//! and at most [`MAX_ENTRIES`] newest ones are kept.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Longer than a link can live (seven days), so an entry never outlasts its link by much.
const KEEP_SECS: i64 = 8 * 24 * 60 * 60;

const MAX_ENTRIES: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RedeemRecord {
    pub(crate) link_id: String,
    /// Where the person wants the link's files; absolute.
    pub(crate) destination_dir: String,
    pub(crate) redeemed_at_unix: i64,
}

#[derive(Default, Serialize, Deserialize)]
struct Contents {
    #[serde(default)]
    redeemed: Vec<RedeemRecord>,
}

pub(crate) struct RedeemBook {
    path: PathBuf,
    contents: Mutex<Contents>,
}

impl RedeemBook {
    /// Opens the book in `dir`. A missing or unreadable file is an empty book: an offer under a
    /// link that is not here is not lost, it waits for an explicit receive.
    pub(crate) fn open(dir: &Path) -> Self {
        let path = dir.join("redeemed_send_links.json");
        let contents = match std::fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|error| {
                tracing::warn!(%error, path = %path.display(), "the redeemed send link list is unreadable; starting empty");
                Contents::default()
            }),
            Err(_) => Contents::default(),
        };
        Self { path, contents: Mutex::new(contents) }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Contents> {
        self.contents.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Notes a link just redeemed by this device.
    pub(crate) fn record(&self, record: RedeemRecord, now_unix: i64) {
        let mut contents = self.lock();
        contents.redeemed.retain(|r| r.link_id != record.link_id);
        contents.redeemed.push(record);
        contents.redeemed.retain(|r| r.redeemed_at_unix.saturating_add(KEEP_SECS) > now_unix);
        if contents.redeemed.len() > MAX_ENTRIES {
            contents.redeemed.sort_by_key(|r| std::cmp::Reverse(r.redeemed_at_unix));
            contents.redeemed.truncate(MAX_ENTRIES);
        }
        self.save(&contents);
    }

    /// Uses up the entry for `link_id`, when this device redeemed it.
    pub(crate) fn take(&self, link_id: &str) -> Option<RedeemRecord> {
        let mut contents = self.lock();
        let at = contents.redeemed.iter().position(|r| r.link_id == link_id)?;
        let record = contents.redeemed.remove(at);
        self.save(&contents);
        Some(record)
    }

    /// Best effort (temp file, then rename): a failed write only means an offer waits for an
    /// explicit receive after a restart.
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
            tracing::warn!(%error, path = %self.path.display(), "could not save the redeemed send link list");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(link_id: &str, at: i64) -> RedeemRecord {
        RedeemRecord {
            link_id: link_id.to_string(),
            destination_dir: format!("/tmp/{link_id}"),
            redeemed_at_unix: at,
        }
    }

    #[test]
    fn an_entry_is_used_up_by_the_first_match_and_survives_a_reopen_until_then() {
        let dir = tempfile::tempdir().unwrap();
        let book = RedeemBook::open(dir.path());
        book.record(record("a", 1_000), 1_000);
        book.record(record("b", 1_000), 1_000);
        assert!(RedeemBook::open(dir.path()).take("a").is_some(), "persisted across a restart");
        assert!(book.take("a").is_some());
        assert!(book.take("a").is_none(), "single use");
        assert!(book.take("unknown").is_none());
        assert!(RedeemBook::open(dir.path()).take("a").is_none(), "the use is persisted too");
        assert_eq!(book.take("b").unwrap().destination_dir, "/tmp/b");
    }

    #[test]
    fn entries_older_than_a_link_can_live_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let book = RedeemBook::open(dir.path());
        book.record(record("old", 0), 0);
        book.record(record("new", KEEP_SECS + 10), KEEP_SECS + 10);
        assert!(book.take("old").is_none());
        assert!(book.take("new").is_some());
    }
}
