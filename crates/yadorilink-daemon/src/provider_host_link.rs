//! The daemon's end of the provider channel to the host app (the menu-bar app), over the shell
//! socket: pushes `ProviderEvictRequest` / `ProviderChanged` to
//! the connection the app attached, and completes the waiting publication step when the app's
//! `ProviderEvictDone` / `ProviderSignalDone` arrives. One host connection at a time; a new
//! one replaces the old. With no host attached every request answers `NotConnected`, which the
//! publication machine retries; the host's attach runs a pass.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use yadorilink_ipc_proto::shellipc::shell_ipc_message::Payload;
use yadorilink_ipc_proto::shellipc::{
    EvictResult, ProviderChanged, ProviderEvictDone, ProviderEvictRequest, ProviderEvidenceTick,
    ProviderSignalDone, ShellIpcMessage,
};
use yadorilink_sync_sqlite::provider::ItemId;

use crate::application::ports::BoxFuture;
use crate::provider_publication::{EvictOutcome, ProviderHost};

/// How long the daemon waits for the host's acknowledgement of one request.
const ACK_TIMEOUT: Duration = Duration::from_secs(30);

enum Reply {
    Evict(EvictOutcome),
    Signal(bool),
}

#[derive(Default)]
pub(crate) struct ProviderHostLink {
    sender: Mutex<Option<mpsc::UnboundedSender<ShellIpcMessage>>>,
    waiters: Mutex<HashMap<Vec<u8>, oneshot::Sender<Reply>>>,
    /// The handoff root whose unconsumed files a newer version revokes.
    handoff: Mutex<Option<std::sync::Arc<crate::provider_handoff::HandoffSlot>>>,
    /// Domains the host reported for roots this database does not know, with when they were last
    /// reported: kept for recovery, shown in `status`, never removed.
    orphans: Mutex<HashMap<String, std::time::Instant>>,
    /// Consecutive readings, from the attached host, that found a registered root's domain missing
    /// from a readable domain list. The engine's own evidence for a removal: the host reports raw
    /// readings and never decides. In memory on purpose: a restart starts counting again.
    absent: Mutex<HashMap<String, u32>>,
}

/// How many consecutive absent readings the engine needs before it treats a domain as removed by
/// the user. One reading can be a stale or racing list.
pub(crate) const ABSENT_READINGS_FOR_REMOVAL: u32 = 2;

/// Removes a request's waiter on drop, so a cancelled request never leaves an entry behind.
struct WaiterGuard<'a> {
    link: &'a ProviderHostLink,
    key: Vec<u8>,
}

impl Drop for WaiterGuard<'_> {
    fn drop(&mut self) {
        self.link.waiters.lock().unwrap_or_else(|p| p.into_inner()).remove(&self.key);
    }
}

/// How long an orphan report stays current: the host repeats it on every reconcile.
const ORPHAN_REPORT_TTL: std::time::Duration = std::time::Duration::from_secs(30);

impl ProviderHostLink {
    /// Makes `sender` the host connection. One host at a time: a second connection cannot take
    /// the host over while the first is alive (the shell socket is user-owned, so this is not
    /// authentication, only a guard against a stray or stale connection stealing the channel);
    /// once the first is gone the next one attaches. True when `sender` is the attached host.
    pub(crate) fn try_attach(&self, sender: mpsc::UnboundedSender<ShellIpcMessage>) -> bool {
        let mut current = self.sender.lock().unwrap_or_else(|p| p.into_inner());
        match current.as_ref() {
            Some(attached) if !attached.is_closed() && !attached.same_channel(&sender) => false,
            Some(attached) if attached.same_channel(&sender) => true,
            _ => {
                // A different host takes over: whatever was waiting on the previous one is
                // never answered, so it fails now and its items re-run.
                self.waiters.lock().unwrap_or_else(|p| p.into_inner()).clear();
                // Readings of the previous host say nothing about this one.
                self.absent.lock().unwrap_or_else(|p| p.into_inner()).clear();
                *current = Some(sender);
                true
            }
        }
    }

    /// Gives the link the handoff root it revokes from.
    pub(crate) fn set_handoff_slot(
        &self,
        slot: std::sync::Arc<crate::provider_handoff::HandoffSlot>,
    ) {
        *self.handoff.lock().unwrap_or_else(|p| p.into_inner()) = Some(slot);
    }

    /// The handoff root, opened now when it can be.
    pub(crate) fn handoff_root(
        &self,
    ) -> Option<std::sync::Arc<crate::provider_handoff::HandoffRoot>> {
        let slot = self.handoff.lock().unwrap_or_else(|p| p.into_inner()).clone();
        slot.and_then(|slot| slot.get())
    }

    /// Counts one more consecutive absent reading for `root_id` and returns the engine's verdict:
    /// true once the absence has been read [`ABSENT_READINGS_FOR_REMOVAL`] times in a row (the
    /// counter then starts over).
    pub(crate) fn note_absent(&self, root_id: &str) -> bool {
        let mut absent = self.absent.lock().unwrap_or_else(|p| p.into_inner());
        let count = absent.entry(root_id.to_string()).or_insert(0);
        *count += 1;
        if *count >= ABSENT_READINGS_FOR_REMOVAL {
            absent.remove(root_id);
            return true;
        }
        false
    }

    /// Any reading other than "absent" breaks the run.
    pub(crate) fn clear_absent(&self, root_id: &str) {
        self.absent.lock().unwrap_or_else(|p| p.into_inner()).remove(root_id);
    }

    /// Records an orphan domain report.
    pub(crate) fn note_orphan(&self, root_id: &str) {
        self.orphans
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(root_id.to_string(), std::time::Instant::now());
    }

    /// The orphan domains reported recently, by root id.
    pub(crate) fn orphans(&self) -> Vec<String> {
        let mut orphans = self.orphans.lock().unwrap_or_else(|p| p.into_inner());
        orphans.retain(|_, seen| seen.elapsed() < ORPHAN_REPORT_TTL);
        let mut roots: Vec<String> = orphans.keys().cloned().collect();
        roots.sort();
        roots
    }

    /// Whether a host connection is attached and alive.
    pub(crate) fn host_connected(&self) -> bool {
        self.sender
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .is_some_and(|attached| !attached.is_closed())
    }

    /// Whether `sender` is the attached host connection.
    pub(crate) fn is_attached(&self, sender: &mpsc::UnboundedSender<ShellIpcMessage>) -> bool {
        self.sender
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .is_some_and(|attached| attached.same_channel(sender))
    }

    /// Detaches `sender` if it is the attached host (its connection ended). True when it was.
    pub(crate) fn detach(&self, sender: &mpsc::UnboundedSender<ShellIpcMessage>) -> bool {
        let mut current = self.sender.lock().unwrap_or_else(|p| p.into_inner());
        if current.as_ref().is_some_and(|attached| attached.same_channel(sender)) {
            *current = None;
            // Waiters were bound to this attachment: they fail, the items stay pending and
            // run again when a host attaches.
            self.waiters.lock().unwrap_or_else(|p| p.into_inner()).clear();
            return true;
        }
        false
    }

    fn send(&self, payload: Payload) -> bool {
        self.sender
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .is_some_and(|sender| sender.send(ShellIpcMessage { payload: Some(payload) }).is_ok())
    }

    /// Registers a waiter for `key`. The returned guard removes the entry when dropped, whether
    /// the request finished, timed out, or its future was cancelled by the caller.
    fn wait_for(&self, key: Vec<u8>) -> (WaiterGuard<'_>, oneshot::Receiver<Reply>) {
        let (tx, rx) = oneshot::channel();
        self.waiters.lock().unwrap_or_else(|p| p.into_inner()).insert(key.clone(), tx);
        (WaiterGuard { link: self, key }, rx)
    }

    /// Prompts the host to list the provider folders again (a root was replaced): a
    /// `ProviderChanged` naming the new root, which the host does not know yet.
    pub(crate) fn push_folders_changed(&self, new_root_id: &str) {
        self.send(Payload::ProviderChanged(ProviderChanged {
            root_id: hex::decode(new_root_id).unwrap_or_default(),
            namespace_revision: 0,
            changed_item_ids: Vec::new(),
            changed_parent_ids: Vec::new(),
            signal_working_set: false,
            request_id: Vec::new(),
        }));
    }

    /// Pushes the root's latest evidence sequence (best effort: the host also reads it on connect).
    pub(crate) fn evidence_tick(&self, root_id: &str, evidence_seq: u64) {
        self.send(Payload::ProviderEvidenceTick(ProviderEvidenceTick {
            root_id: hex::decode(root_id).unwrap_or_default(),
            evidence_seq,
        }));
    }

    /// Sends one message to the attached host connection (an acknowledgement of its report).
    pub(crate) fn send_to_host(&self, payload: Payload) -> bool {
        self.send(payload)
    }

    pub(crate) fn complete_evict(&self, done: &ProviderEvictDone) {
        let outcome = match EvictResult::try_from(done.result).unwrap_or(EvictResult::Unspecified) {
            EvictResult::Evicted => EvictOutcome::Evicted,
            EvictResult::NotMaterialized => EvictOutcome::NotMaterialized,
            EvictResult::Busy => EvictOutcome::Busy,
            EvictResult::Error | EvictResult::Unspecified => {
                EvictOutcome::Error(done.error.clone())
            }
        };
        if let Some(waiter) =
            self.waiters.lock().unwrap_or_else(|p| p.into_inner()).remove(&done.request_id)
        {
            let _ = waiter.send(Reply::Evict(outcome));
        }
    }

    pub(crate) fn complete_signal(&self, done: &ProviderSignalDone) {
        if let Some(waiter) =
            self.waiters.lock().unwrap_or_else(|p| p.into_inner()).remove(&done.request_id)
        {
            let _ = waiter.send(Reply::Signal(done.ok));
        }
    }
}

impl ProviderHostLink {
    /// Asks the host to drop its copy of `item` only while it shows exactly the version `target`: a request that is
    /// answered late then cannot drop content that arrived after the version was confirmed.
    pub(crate) fn evict_shown_version<'a>(
        &'a self,
        root_id: &'a str,
        item: ItemId,
        target: [u8; 32],
    ) -> BoxFuture<'a, EvictOutcome> {
        self.send_evict(root_id, item, target, true)
    }

    fn send_evict<'a>(
        &'a self,
        root_id: &'a str,
        item: ItemId,
        target: [u8; 32],
        require_shown: bool,
    ) -> BoxFuture<'a, EvictOutcome> {
        Box::pin(async move {
            let request_id: [u8; 16] = rand::random();
            let (_waiter, rx) = self.wait_for(request_id.to_vec());
            let sent = self.send(Payload::ProviderEvictRequest(ProviderEvictRequest {
                root_id: hex::decode(root_id).unwrap_or_default(),
                item_id: item.to_vec(),
                request_id: request_id.to_vec(),
                target_version_hash: target.to_vec(),
                require_shown_version: if require_shown { target.to_vec() } else { Vec::new() },
            }));
            if !sent {
                return EvictOutcome::NotConnected;
            }
            match tokio::time::timeout(ACK_TIMEOUT, rx).await {
                Ok(Ok(Reply::Evict(outcome))) => outcome,
                _ => EvictOutcome::Error("the host did not answer the eviction request".into()),
            }
        })
    }
}

impl ProviderHost for ProviderHostLink {
    fn revoke_unconsumed_handoffs(&self, root_id: &str, item: &ItemId) -> bool {
        let slot = self.handoff.lock().unwrap_or_else(|p| p.into_inner()).clone();
        let Some(root) = slot.and_then(|slot| slot.get()) else { return true };
        match root.revoke_unconsumed(root_id, item) {
            Ok(revoked) => {
                if revoked > 0 {
                    tracing::debug!(revoked, "revoked unconsumed handoff files of an updated item");
                }
                true
            }
            Err(error) => {
                tracing::warn!(%error, "could not revoke a handoff file; publication is retried");
                false
            }
        }
    }

    fn folders_changed(&self, new_root_id: &str) {
        self.push_folders_changed(new_root_id);
    }

    fn evict<'a>(
        &'a self,
        root_id: &'a str,
        item: ItemId,
        target: [u8; 32],
    ) -> BoxFuture<'a, EvictOutcome> {
        self.send_evict(root_id, item, target, false)
    }

    fn signal<'a>(
        &'a self,
        root_id: &'a str,
        namespace_revision: u64,
        items: Vec<ItemId>,
        parent_ids: Vec<Vec<u8>>,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let root = hex::decode(root_id).unwrap_or_default();
            // Correlated by a fresh id, NOT by (root, revision): an item signal and the root signal of one
            // publication share a revision and run at the same time.
            let key: Vec<u8> = rand::random::<[u8; 16]>().to_vec();
            let (_waiter, rx) = self.wait_for(key.clone());
            let sent = self.send(Payload::ProviderChanged(ProviderChanged {
                root_id: root,
                namespace_revision,
                changed_item_ids: items.iter().map(|i| i.to_vec()).collect(),
                changed_parent_ids: parent_ids,
                signal_working_set: true,
                request_id: key.clone(),
            }));
            if !sent {
                return false;
            }
            match tokio::time::timeout(ACK_TIMEOUT, rx).await {
                Ok(Ok(Reply::Signal(ok))) => ok,
                _ => false,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// (review) An item signal and the root signal of one publication share a namespace revision and run
    /// at the same time: each acknowledgement reaches ITS OWN waiter (correlated by request id), whatever
    /// the order they come back in and whatever each says.
    #[tokio::test]
    async fn concurrent_signals_of_one_revision_are_answered_separately() {
        let link = Arc::new(ProviderHostLink::default());
        let (tx, mut rx) = mpsc::unbounded_channel();
        assert!(link.try_attach(tx));
        let root = hex::encode([7u8; 16]);
        let revision = 5;
        let item_signal = {
            let (link, root) = (link.clone(), root.clone());
            tokio::spawn(async move { link.signal(&root, revision, vec![[1u8; 16]], vec![]).await })
        };
        let root_signal = {
            let (link, root) = (link.clone(), root.clone());
            tokio::spawn(async move { link.signal(&root, revision, vec![], vec![]).await })
        };
        let mut pushed = Vec::new();
        while pushed.len() < 2 {
            let Some(ShellIpcMessage { payload: Some(Payload::ProviderChanged(changed)) }) =
                rx.recv().await
            else {
                panic!("expected a ProviderChanged");
            };
            pushed.push(changed);
        }
        assert_ne!(
            pushed[0].request_id, pushed[1].request_id,
            "two signals shared a correlation id"
        );
        // The signal that named items fails, the root-level one succeeds; answered in the opposite order.
        let (with_items, without) = if pushed[0].changed_item_ids.is_empty() {
            (pushed[1].clone(), pushed[0].clone())
        } else {
            (pushed[0].clone(), pushed[1].clone())
        };
        for (changed, ok) in [(&without, true), (&with_items, false)] {
            link.complete_signal(&ProviderSignalDone {
                root_id: changed.root_id.clone(),
                namespace_revision: changed.namespace_revision,
                ok,
                error: String::new(),
                request_id: changed.request_id.clone(),
            });
        }
        assert!(!item_signal.await.unwrap(), "the item signal took the other signal's answer");
        assert!(root_signal.await.unwrap(), "the root signal took the other signal's answer");
    }

    /// A request future cancelled by its caller (the publication timeout is shorter than the ack
    /// timeout) must not leave its waiter behind.
    #[tokio::test]
    async fn a_cancelled_request_leaves_no_waiter() {
        let link = ProviderHostLink::default();
        let (tx, _rx) = mpsc::unbounded_channel();
        assert!(link.try_attach(tx));
        let root = hex::encode([7u8; 16]);
        for _ in 0..5 {
            let evict = tokio::time::timeout(
                Duration::from_millis(20),
                link.evict(&root, [1u8; 16], [2u8; 32]),
            );
            assert!(evict.await.is_err(), "the host never answers");
            assert!(link.waiters.lock().unwrap().is_empty(), "evict left a waiter");
            let signal = tokio::time::timeout(
                Duration::from_millis(20),
                link.signal(&root, 1, vec![], vec![]),
            );
            assert!(signal.await.is_err());
            assert!(link.waiters.lock().unwrap().is_empty(), "signal left a waiter");
        }
    }

    /// A late acknowledgement of a cancelled request neither satisfies nor disturbs a new one.
    #[tokio::test]
    async fn a_late_ack_for_a_cancelled_request_does_not_answer_a_new_one() {
        let link = Arc::new(ProviderHostLink::default());
        let (tx, mut rx) = mpsc::unbounded_channel();
        assert!(link.try_attach(tx));
        let root = hex::encode([7u8; 16]);
        let cancelled =
            tokio::time::timeout(Duration::from_millis(20), link.signal(&root, 1, vec![], vec![]))
                .await;
        assert!(cancelled.is_err());
        let Some(ShellIpcMessage { payload: Some(Payload::ProviderChanged(old)) }) =
            rx.recv().await
        else {
            panic!("expected a ProviderChanged");
        };
        let fresh = {
            let (link, root) = (link.clone(), root.clone());
            tokio::spawn(async move { link.signal(&root, 2, vec![], vec![]).await })
        };
        let Some(ShellIpcMessage { payload: Some(Payload::ProviderChanged(new)) }) =
            rx.recv().await
        else {
            panic!("expected a ProviderChanged");
        };
        assert_ne!(old.request_id, new.request_id, "request ids were reused");
        link.complete_signal(&ProviderSignalDone {
            root_id: old.root_id.clone(),
            namespace_revision: 1,
            ok: true,
            error: String::new(),
            request_id: old.request_id.clone(),
        });
        assert!(!fresh.is_finished(), "the late ack answered the new request");
        link.complete_signal(&ProviderSignalDone {
            root_id: new.root_id.clone(),
            namespace_revision: 2,
            ok: true,
            error: String::new(),
            request_id: new.request_id.clone(),
        });
        assert!(fresh.await.unwrap());
        assert!(link.waiters.lock().unwrap().is_empty());
    }
}
