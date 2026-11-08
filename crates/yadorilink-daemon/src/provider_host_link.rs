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
    EvictResult, PinChoice, PinResult, ProviderChanged, ProviderEvictDone, ProviderEvictRequest,
    ProviderEvidenceTick, ProviderPinDone, ProviderPinPlan, ProviderPinPlanEntry,
    ProviderPinRequest, ProviderSignalDone, ShellIpcMessage,
};
use yadorilink_sync_sqlite::provider::ItemId;

use crate::application::ports::BoxFuture;
use crate::provider_publication::{EvictOutcome, ProviderHost};

/// How long the daemon waits for the host's acknowledgement of one request.
const ACK_TIMEOUT: Duration = Duration::from_secs(30);

enum Reply {
    Evict(EvictOutcome),
    Signal(bool),
    Pin(PinAnswer),
}

/// What the host answered to a request to apply the person's keep-on-this-device choice, or why it
/// could not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PinAnswer {
    /// The pin is set and the content is on this device (or there was nothing to fetch).
    Done,
    /// The pin is set and the operating system is fetching the content.
    Downloading,
    /// The item is not shown in the folder: nothing was changed.
    NotFound,
    /// This host cannot pin: nothing was changed.
    Unsupported,
    Error(String),
    /// No host is attached.
    NotConnected,
}

#[derive(Default)]
pub(crate) struct ProviderHostLink {
    sender: Mutex<Option<mpsc::UnboundedSender<ShellIpcMessage>>>,
    waiters: Mutex<HashMap<Vec<u8>, oneshot::Sender<Reply>>>,
    /// The handoff root whose unconsumed files a newer version revokes.
    handoff: Mutex<Option<std::sync::Arc<crate::provider_handoff::HandoffSlot>>>,
    /// Roots the attached host reported as no longer registered with the operating system (its
    /// domain removed, or missing from a readable list), until it reports them registered again or
    /// the host changes. While a root is here, what the operating system shows in it says nothing
    /// about what the person did: changes from it are not applied.
    lost: Mutex<std::collections::HashSet<String>>,
    /// Roots with a publication being held back because the handoff root cannot open, with when
    /// the first one was refused. In memory: the retry sets it again after a restart.
    held: Mutex<HashMap<String, std::time::Instant>>,
    /// Domains the host reported for roots this database does not know, with when they were last
    /// reported: kept for recovery, shown in `status`, never removed.
    orphans: Mutex<HashMap<String, std::time::Instant>>,
    /// Consecutive readings, from the attached host, that found a registered root's domain missing
    /// from a readable domain list. The engine's own evidence for a removal: the host reports raw
    /// readings and never decides. In memory on purpose: a restart starts counting again.
    absent: Mutex<HashMap<String, u32>>,
    /// The roots the attached host last reported as registered (its sync root connected). Emptied when
    /// the host detaches: a root is served only while the host that says so is attached.
    served: Mutex<std::collections::HashSet<String>>,
    /// Woken (all waiters) each time a host attaches, for [`Self::wait_connected`].
    attached: tokio::sync::Notify,
}

/// The most entries one pin plan message carries (an entry is about 20 bytes; a wire frame is 1 MiB).
pub(crate) const PIN_PLAN_CHUNK: usize = 1000;

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
                // What the previous host reported lost says nothing about this one.
                self.lost.lock().unwrap_or_else(|p| p.into_inner()).clear();
                *current = Some(sender);
                self.attached.notify_waiters();
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

    /// How long a publication of `root_id` has been held back for want of a handoff root, if one is.
    /// Once the root opens every hold ends, whether or not a publication ran again to say so (the
    /// item may have been deleted or superseded meanwhile).
    pub(crate) fn handoff_hold_ms(&self, root_id: &str) -> Option<u64> {
        let mut held = self.held.lock().unwrap_or_else(|p| p.into_inner());
        if held.is_empty() {
            return None;
        }
        let slot = self.handoff.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if slot.is_none_or(|slot| slot.get().is_some()) {
            held.clear();
            return None;
        }
        held.get(root_id).map(|since| since.elapsed().as_millis() as u64)
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

    /// Resolves once a host connection is attached and alive (at once if one is).
    pub(crate) async fn wait_connected(&self) {
        loop {
            let attached = self.attached.notified();
            tokio::pin!(attached);
            // Registered before the check: an attach between the two is not missed.
            attached.as_mut().enable();
            if self.host_connected() {
                return;
            }
            attached.await;
        }
    }

    /// Whether a host connection is attached and alive.
    pub(crate) fn host_connected(&self) -> bool {
        self.sender
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .is_some_and(|attached| !attached.is_closed())
    }

    /// Records what the attached host last said about the domain of `root_id`: registered (it serves
    /// the root) or anything else (it does not).
    pub(crate) fn note_domain_registered(&self, root_id: &str, registered: bool) {
        let mut served = self.served.lock().unwrap_or_else(|p| p.into_inner());
        if registered {
            served.insert(root_id.to_owned());
        } else {
            served.remove(root_id);
        }
    }

    /// Records whether the attached host reported `root_id` as lost (see the field).
    pub(crate) fn note_domain_lost(&self, root_id: &str, lost: bool) {
        let mut roots = self.lost.lock().unwrap_or_else(|p| p.into_inner());
        if lost {
            roots.insert(root_id.to_owned());
        } else {
            roots.remove(root_id);
        }
    }

    /// Runs `apply` unless the root is reported lost, and holds the report back while it runs: a loss
    /// reported meanwhile is recorded only after `apply` has finished, so a change that passed the
    /// check cannot commit after the report. `None`: the root is lost and `apply` did not run.
    pub(crate) fn while_not_lost<R>(&self, root_id: &str, apply: impl FnOnce() -> R) -> Option<R> {
        let lost = self.lost.lock().unwrap_or_else(|p| p.into_inner());
        if lost.contains(root_id) {
            return None;
        }
        let result = apply();
        drop(lost);
        Some(result)
    }

    /// Whether the attached host has reported the root as no longer registered.
    pub(crate) fn root_reported_lost(&self, root_id: &str) -> bool {
        self.lost.lock().unwrap_or_else(|p| p.into_inner()).contains(root_id)
    }

    /// Whether the attached host serves the root `root_id` right now: it reported the root
    /// registered and its connection is up. A host that is attached but does not serve a root (its
    /// sync root is not connected) says nothing reliable about that root's items.
    pub(crate) fn serves_root(&self, root_id: &str) -> bool {
        self.host_connected()
            && self.served.lock().unwrap_or_else(|p| p.into_inner()).contains(root_id)
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
            self.lost.lock().unwrap_or_else(|p| p.into_inner()).clear();
            self.served.lock().unwrap_or_else(|p| p.into_inner()).clear();
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

    pub(crate) fn complete_pin(&self, done: &ProviderPinDone) {
        let answer = match PinResult::try_from(done.result).unwrap_or(PinResult::Unspecified) {
            PinResult::Done => PinAnswer::Done,
            PinResult::Downloading => PinAnswer::Downloading,
            PinResult::NotFound => PinAnswer::NotFound,
            PinResult::Unsupported => PinAnswer::Unsupported,
            PinResult::Error | PinResult::Unspecified => PinAnswer::Error(done.error.clone()),
        };
        if let Some(waiter) =
            self.waiters.lock().unwrap_or_else(|p| p.into_inner()).remove(&done.request_id)
        {
            let _ = waiter.send(Reply::Pin(answer));
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

    /// Asks the host to apply the person's choice for `item` (`None`: the folder's root) in the
    /// operating system. The choice is already recorded by the daemon; the host only makes the OS
    /// agree and reports what it found.
    pub(crate) fn pin_item<'a>(
        &'a self,
        root_id: &'a str,
        item: Option<ItemId>,
        choice: PinChoice,
    ) -> BoxFuture<'a, PinAnswer> {
        Box::pin(async move {
            let request_id: [u8; 16] = rand::random();
            let (_waiter, rx) = self.wait_for(request_id.to_vec());
            let sent = self.send(Payload::ProviderPinRequest(ProviderPinRequest {
                root_id: hex::decode(root_id).unwrap_or_default(),
                item_id: item.map(|item| item.to_vec()).unwrap_or_default(),
                request_id: request_id.to_vec(),
                choice: choice as i32,
            }));
            if !sent {
                return PinAnswer::NotConnected;
            }
            match tokio::time::timeout(ACK_TIMEOUT, rx).await {
                Ok(Ok(Reply::Pin(answer))) => answer,
                _ => PinAnswer::Error("the host did not answer the pin request".into()),
            }
        })
    }

    /// Tells the attached host which pins the rules ask for (`None`: the folder itself). Not
    /// acknowledged; false when no host is attached. Sent in messages of at most
    /// [`PIN_PLAN_CHUNK`] entries, in order (one channel, so they arrive in order): a plan that
    /// outgrew a wire frame would otherwise close the connection every time it was sent.
    pub(crate) fn send_pin_plan(
        &self,
        root_id: &str,
        entries: Vec<(Option<ItemId>, PinChoice)>,
    ) -> bool {
        let root = hex::decode(root_id).unwrap_or_default();
        let messages: Vec<Payload> = entries
            .chunks(PIN_PLAN_CHUNK)
            .map(|chunk| {
                Payload::ProviderPinPlan(ProviderPinPlan {
                    root_id: root.clone(),
                    entries: chunk
                        .iter()
                        .map(|(item, choice)| ProviderPinPlanEntry {
                            item_id: item.map(|item| item.to_vec()).unwrap_or_default(),
                            choice: *choice as i32,
                        })
                        .collect(),
                })
            })
            .collect();
        self.send_together(messages)
    }

    /// Sends the messages one after another with the connection held, so nothing else is put between
    /// them: a pin request for an item that a later message of the same plan names would otherwise be
    /// followed by the plan's older choice for it. False when no host is attached.
    fn send_together(&self, payloads: Vec<Payload>) -> bool {
        let attached = self.sender.lock().unwrap_or_else(|p| p.into_inner());
        let Some(sender) = attached.as_ref() else { return false };
        payloads
            .into_iter()
            .all(|payload| sender.send(ShellIpcMessage { payload: Some(payload) }).is_ok())
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
        // No slot: this engine has no handoff area at all, so nothing was ever delivered.
        let Some(slot) = slot else { return true };
        // A slot whose root cannot open yet (on macOS the root is adopted from the container the
        // host app reports) cannot say that nothing is left: a previous run may have left handoff
        // files the extension still holds a response for, and only opening the root sweeps them.
        // Publishing a newer version now could let the OS take the old bytes after it, so the
        // publication waits and is retried.
        let Some(root) = slot.get() else {
            tracing::debug!("the handoff root is not open yet; publication is retried");
            self.held
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .entry(root_id.to_string())
                .or_insert_with(std::time::Instant::now);
            return false;
        };
        self.held.lock().unwrap_or_else(|p| p.into_inner()).remove(root_id);
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

    /// A pin request reaches the attached host with its item and choice, each answer completes ITS OWN
    /// request (correlated by request id, whatever order they come back in), and with no host attached the
    /// answer is `NotConnected` without waiting.
    #[tokio::test]
    async fn pin_requests_are_answered_each_by_its_own_reply_and_never_without_a_host() {
        let link = Arc::new(ProviderHostLink::default());
        let root = hex::encode([7u8; 16]);
        assert_eq!(
            link.pin_item(&root, Some([1u8; 16]), PinChoice::Keep).await,
            PinAnswer::NotConnected
        );

        let (tx, mut rx) = mpsc::unbounded_channel();
        assert!(link.try_attach(tx));
        let first = {
            let (link, root) = (link.clone(), root.clone());
            tokio::spawn(
                async move { link.pin_item(&root, Some([1u8; 16]), PinChoice::Keep).await },
            )
        };
        let second = {
            let (link, root) = (link.clone(), root.clone());
            tokio::spawn(async move { link.pin_item(&root, None, PinChoice::Clear).await })
        };
        let mut pushed = Vec::new();
        while pushed.len() < 2 {
            let Some(ShellIpcMessage { payload: Some(Payload::ProviderPinRequest(request)) }) =
                rx.recv().await
            else {
                panic!("expected a ProviderPinRequest");
            };
            pushed.push(request);
        }
        assert_ne!(pushed[0].request_id, pushed[1].request_id);
        let (for_item, for_root) = if pushed[0].item_id.is_empty() {
            (pushed[1].clone(), pushed[0].clone())
        } else {
            (pushed[0].clone(), pushed[1].clone())
        };
        assert_eq!(for_item.item_id, vec![1u8; 16]);
        assert_eq!(for_item.choice, PinChoice::Keep as i32);
        assert_eq!(for_root.choice, PinChoice::Clear as i32);
        assert_eq!(for_root.root_id, vec![7u8; 16]);
        // Answered in the opposite order, each with a different result.
        for (request, result) in
            [(&for_root, PinResult::Downloading), (&for_item, PinResult::NotFound)]
        {
            link.complete_pin(&ProviderPinDone {
                root_id: request.root_id.clone(),
                request_id: request.request_id.clone(),
                result: result as i32,
                error: String::new(),
            });
        }
        assert_eq!(first.await.unwrap(), PinAnswer::NotFound, "took the other request's answer");
        assert_eq!(
            second.await.unwrap(),
            PinAnswer::Downloading,
            "took the other request's answer"
        );
    }

    /// A loss reported while a change is being applied waits for it: the change was already allowed,
    /// and nothing allowed after the report can run.
    #[test]
    fn a_loss_reported_during_an_apply_is_recorded_after_it_not_before_it_ends() {
        let link = std::sync::Arc::new(ProviderHostLink::default());
        let root = hex::encode([5u8; 16]);
        let (tx, _rx) = mpsc::unbounded_channel();
        assert!(link.try_attach(tx));
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let applied = link.while_not_lost(&root, || {
            let (link, root) = (link.clone(), root.clone());
            std::thread::spawn(move || {
                link.note_domain_lost(&root, true);
                let _ = done_tx.send(());
            });
            // The report cannot be recorded while the change is still being applied.
            assert!(
                done_rx.recv_timeout(Duration::from_millis(200)).is_err(),
                "the loss was recorded in the middle of the apply"
            );
            7
        });
        assert_eq!(applied, Some(7));
        done_rx.recv_timeout(Duration::from_secs(10)).expect("the report was never recorded");
        assert!(link.root_reported_lost(&root));
        assert_eq!(link.while_not_lost(&root, || 8), None, "an apply ran for a lost root");
    }

    /// A root the attached host reported lost stays lost until it reports it registered again; a
    /// different host, or none, says nothing about it.
    #[test]
    fn a_root_reported_lost_stays_lost_until_the_host_says_otherwise() {
        let link = ProviderHostLink::default();
        let root = hex::encode([5u8; 16]);
        assert!(!link.root_reported_lost(&root));
        let (tx, _rx) = mpsc::unbounded_channel();
        assert!(link.try_attach(tx.clone()));
        link.note_domain_lost(&root, true);
        assert!(link.root_reported_lost(&root));
        assert!(!link.root_reported_lost(&hex::encode([6u8; 16])), "another root");
        link.note_domain_lost(&root, false);
        assert!(!link.root_reported_lost(&root));

        link.note_domain_lost(&root, true);
        assert!(link.detach(&tx));
        assert!(!link.root_reported_lost(&root), "the host that reported it is gone");
        let (first, keep_first) = mpsc::unbounded_channel();
        assert!(link.try_attach(first));
        link.note_domain_lost(&root, true);
        drop(keep_first);
        let (second, _keep_second) = mpsc::unbounded_channel();
        assert!(link.try_attach(second));
        assert!(!link.root_reported_lost(&root), "a host that took over inherited the report");
    }

    /// A root is served only while the host that reported it registered is attached, and a host that
    /// is attached but reports a root as anything else does not serve it.
    #[test]
    fn a_root_is_served_only_while_the_attached_host_reports_it_registered() {
        let link = ProviderHostLink::default();
        let (one, two) = (hex::encode([1u8; 16]), hex::encode([2u8; 16]));
        link.note_domain_registered(&one, true);
        assert!(!link.serves_root(&one), "no host is attached");

        let (tx, _rx) = mpsc::unbounded_channel();
        assert!(link.try_attach(tx.clone()));
        link.note_domain_registered(&one, true);
        assert!(link.serves_root(&one));
        assert!(!link.serves_root(&two), "a root the host never reported");
        link.note_domain_registered(&two, true);
        link.note_domain_registered(&two, false);
        assert!(!link.serves_root(&two), "reported as not registered afterwards");
        assert!(link.serves_root(&one), "another root is unaffected");

        assert!(link.detach(&tx));
        assert!(!link.serves_root(&one), "the host is gone");
        let (tx, _rx) = mpsc::unbounded_channel();
        assert!(link.try_attach(tx));
        assert!(!link.serves_root(&one), "a new host has not reported it");
    }

    /// The plan reaches the attached host with its entries in order, and no host means nothing sent.
    #[tokio::test]
    async fn a_pin_plan_goes_to_the_attached_host_in_order_and_to_nobody_otherwise() {
        let link = ProviderHostLink::default();
        let root = hex::encode([7u8; 16]);
        let entries = vec![(None, PinChoice::Keep), (Some([3u8; 16]), PinChoice::OnlineOnly)];
        assert!(!link.send_pin_plan(&root, entries.clone()), "no host: nothing is sent");

        let (tx, mut rx) = mpsc::unbounded_channel();
        assert!(link.try_attach(tx));
        assert!(link.send_pin_plan(&root, entries));
        let Some(ShellIpcMessage { payload: Some(Payload::ProviderPinPlan(plan)) }) =
            rx.recv().await
        else {
            panic!("expected a ProviderPinPlan");
        };
        assert_eq!(plan.root_id, vec![7u8; 16]);
        assert_eq!(plan.entries.len(), 2);
        assert!(plan.entries[0].item_id.is_empty());
        assert_eq!(plan.entries[0].choice, PinChoice::Keep as i32);
        assert_eq!(plan.entries[1].item_id, vec![3u8; 16]);
        assert_eq!(plan.entries[1].choice, PinChoice::OnlineOnly as i32);
    }

    /// A handoff slot whose root has not opened (the host app has not reported its container) does not
    /// let a publication go ahead: files of a previous run may still be there. Once the container is
    /// adopted the root opens, sweeps them, and the publication goes through.
    #[test]
    fn a_publication_waits_while_the_handoff_root_cannot_open_yet() {
        let link = ProviderHostLink::default();
        let item = [3u8; 16];
        assert!(link.revoke_unconsumed_handoffs("root", &item), "no handoff area: nothing to take");
        assert!(link.handoff_hold_ms("root").is_none(), "no handoff area: nothing is held");

        let slot = crate::provider_handoff::HandoffSlot::lazy(Arc::new(|| None), Arc::new(|_| {}));
        link.set_handoff_slot(slot.clone());
        assert!(
            !link.revoke_unconsumed_handoffs("root", &item),
            "the root is not open: a leftover file cannot be ruled out"
        );

        // A handoff file a previous run delivered, still fresh: opening the root removes it, so
        // nothing the extension holds a response for survives into the publication.
        assert!(link.handoff_hold_ms("root").is_some(), "the refused publication is on record");
        assert!(link.handoff_hold_ms("other").is_none());
        let dir = tempfile::tempdir().unwrap();
        let leftover = dir.path().join("provider/handoff/previous-run");
        std::fs::create_dir_all(leftover.parent().unwrap()).unwrap();
        std::fs::write(&leftover, b"old version").unwrap();
        assert!(slot.adopt(dir.path().to_str().unwrap()));
        assert!(link.revoke_unconsumed_handoffs("root", &item), "the root opened and swept");
        assert!(!leftover.exists(), "a previous run's handoff file survived the open");
        assert!(link.handoff_hold_ms("root").is_none(), "the hold ended with the open");
        // The hold also ends when the root opens without a publication running again.
        let slot = crate::provider_handoff::HandoffSlot::lazy(Arc::new(|| None), Arc::new(|_| {}));
        let other = ProviderHostLink::default();
        other.set_handoff_slot(slot.clone());
        assert!(!other.revoke_unconsumed_handoffs("root", &item));
        assert!(other.handoff_hold_ms("root").is_some());
        assert!(slot.adopt(dir.path().to_str().unwrap()));
        assert!(other.handoff_hold_ms("root").is_none(), "the root opened: nothing is held");
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
