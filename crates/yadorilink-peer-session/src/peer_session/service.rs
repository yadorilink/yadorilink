//! The service RPC lane: answering a peer's service requests (version
//! presence, durability summary, handoff lease/ticket) and
//! issuing this device's own requests to the peer.

use std::sync::Arc;

use yadorilink_replica_domain::file::VersionBlock;
use yadorilink_replica_domain::ids::VersionHash;

use crate::error::PeerSessionError;

use super::{
    PeerHandoffLeaseGrant, PeerHandoffTicketGrant, PeerSyncSession, SERVICE_RPC_MAX_BYTES,
};

/// The answer an unauthorized request gets: shaped like a real one and
/// indistinguishable from a genuine negative. A refusal that looked different
/// would tell an unauthorized peer that the group exists.
fn refusal_for(
    request: &crate::service_rpc::ServiceRequest,
) -> crate::service_rpc::ServiceResponse {
    match request {
        crate::service_rpc::ServiceRequest::VersionPresent { .. } => {
            crate::service_rpc::ServiceResponse::VersionPresent { present: false }
        }
        crate::service_rpc::ServiceRequest::HandoffLease { .. } => {
            crate::service_rpc::ServiceResponse::HandoffLease { grant: None }
        }
        crate::service_rpc::ServiceRequest::HandoffTicket { .. } => {
            crate::service_rpc::ServiceResponse::HandoffTicket { grant: None }
        }
        // A lease release on an unauthorized group ends nothing, and says so.
        crate::service_rpc::ServiceRequest::HandoffLeaseRelease { .. } => {
            crate::service_rpc::ServiceResponse::ReleaseNotConfirmed
        }
        // A ticket release changes nothing here on an unauthorized group.
        crate::service_rpc::ServiceRequest::HandoffTicketRelease { .. } => {
            crate::service_rpc::ServiceResponse::Released
        }
        crate::service_rpc::ServiceRequest::GroupDurabilitySummary { .. } => {
            crate::service_rpc::ServiceResponse::GroupDurabilitySummary { summary: None }
        }
        crate::service_rpc::ServiceRequest::CustodyAcquire { .. } => {
            crate::service_rpc::ServiceResponse::CustodyAcquire { granted: false }
        }
        // Not reached for a custody release: it is answered for any
        // authenticated peer, so a lease outlives the group authorization.
        crate::service_rpc::ServiceRequest::CustodyRelease { .. } => {
            crate::service_rpc::ServiceResponse::CustodyRelease { released: false }
        }
        crate::service_rpc::ServiceRequest::CustodyRehome { .. } => {
            crate::service_rpc::ServiceResponse::CustodyRehome { moved: false }
        }
    }
}

impl PeerSyncSession {
    /// Test-only: this session's own service RPC deadline.
    pub fn set_service_rpc_deadline_for_tests(&self, deadline: std::time::Duration) {
        self.service_rpc_deadline_ms
            .store(deadline.as_millis() as u64, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether this peer has sent a service RPC of another version. Such a peer is reachable, but
    /// nothing it says (or fails to say) may be read as a custody answer.
    pub fn rpc_version_mismatch(&self) -> bool {
        self.rpc_version_mismatch.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn note_rpc_version_mismatch(&self, error: &crate::service_rpc::ServiceRpcError) {
        if matches!(error, crate::service_rpc::ServiceRpcError::UnsupportedVersion(_)) {
            self.rpc_version_mismatch.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Make one service RPC and read its single answer.
    ///
    /// No request id, no pending map, and no cancellation guard to stop that
    /// map leaking: the stream is the correlation, and dropping this future
    /// closes it. The whole exchange is bounded by the session's service RPC
    /// deadline, so a peer that takes the stream and never answers gives the
    /// caller `None` -- the same as any other failure -- rather than a hang.
    async fn service_rpc(
        &self,
        transport: &Arc<dyn crate::ports::ServiceStreamTransport>,
        request: &crate::service_rpc::ServiceRequest,
    ) -> Option<crate::service_rpc::ServiceResponse> {
        let deadline = std::time::Duration::from_millis(
            self.service_rpc_deadline_ms.load(std::sync::atomic::Ordering::Relaxed),
        );
        match tokio::time::timeout(deadline, self.service_rpc_unbounded(transport, request)).await {
            Ok(response) => response,
            Err(_) => {
                tracing::debug!(peer = %self.peer_device_id, "service RPC timed out");
                None
            }
        }
    }

    async fn service_rpc_unbounded(
        &self,
        transport: &Arc<dyn crate::ports::ServiceStreamTransport>,
        request: &crate::service_rpc::ServiceRequest,
    ) -> Option<crate::service_rpc::ServiceResponse> {
        let mut stream = match transport.open(request.group_id()).await {
            Ok(stream) => stream,
            Err(error) => {
                tracing::debug!(%error, peer = %self.peer_device_id, "could not open a service stream");
                return None;
            }
        };
        if let Err(error) = stream.send_request(&crate::service_rpc::encode_request(request)).await
        {
            tracing::debug!(%error, peer = %self.peer_device_id, "service request could not be sent");
            return None;
        }
        let encoded = match stream.recv_message(SERVICE_RPC_MAX_BYTES).await {
            Ok(encoded) => encoded,
            Err(error) => {
                tracing::debug!(%error, peer = %self.peer_device_id, "service response never arrived");
                return None;
            }
        };
        match crate::service_rpc::decode_response(&encoded) {
            Ok(response) => Some(response),
            Err(error) => {
                self.note_rpc_version_mismatch(&error);
                tracing::warn!(%error, peer = %self.peer_device_id, "service response did not decode");
                None
            }
        }
    }

    /// Answer one inbound service RPC on the stream it arrived on.
    ///
    /// Authorization is resolved here, per request, from live session
    /// membership — never from anything remembered when the stream opened.
    /// A stream can outlive a revocation, and transport identity is not
    /// service authorization.
    pub async fn serve_service_stream(
        self: Arc<Self>,
        hello_group: &str,
        mut stream: Box<dyn crate::ports::PeerServiceStream>,
    ) {
        let encoded = match stream.recv_message(SERVICE_RPC_MAX_BYTES).await {
            Ok(encoded) => encoded,
            Err(error) => {
                tracing::debug!(%error, peer = %self.peer_device_id, "service request never arrived");
                return;
            }
        };
        let request = match crate::service_rpc::decode_request(&encoded) {
            Ok(request) => request,
            Err(error) => {
                self.note_rpc_version_mismatch(&error);
                tracing::warn!(%error, peer = %self.peer_device_id, "service request did not decode");
                return;
            }
        };

        // The hello named a group and the request names a group. If they can
        // differ, the thing authorized is not the thing acted on -- so they
        // may not differ.
        if request.group_id() != hello_group {
            tracing::warn!(
                hello_group,
                request_group = %request.group_id(),
                peer = %self.peer_device_id,
                "refusing a service request whose group disagrees with its stream's hello"
            );
            let _ = stream
                .send_response(&crate::service_rpc::encode_response(&refusal_for(&request)))
                .await;
            return;
        }

        // A release names only the lease this authenticated peer holds, so it
        // needs no group authorization: a requester removed from the group
        // must still be able to end the lease that pins our blocks.
        let is_release =
            matches!(request, crate::service_rpc::ServiceRequest::CustodyRelease { .. });
        let response = if is_release || self.shares_group(request.group_id()) {
            self.answer_service_request(&request).await
        } else {
            // Answered rather than dropped, and answered immediately. A
            // silent drop would make an unauthorized peer wait out its own
            // timeout for a negative answer, and the delay difference between
            // "unauthorized" and "genuinely absent" is itself a timing
            // side-channel.
            tracing::warn!(
                group_id = %request.group_id(),
                peer = %self.peer_device_id,
                "refusing a service request for an unauthorized/unshared folder group"
            );
            refusal_for(&request)
        };

        if let Err(error) =
            stream.send_response(&crate::service_rpc::encode_response(&response)).await
        {
            tracing::debug!(%error, peer = %self.peer_device_id, "service response could not be sent");
        }
    }

    async fn answer_service_request(
        &self,
        request: &crate::service_rpc::ServiceRequest,
    ) -> crate::service_rpc::ServiceResponse {
        match request {
            crate::service_rpc::ServiceRequest::VersionPresent {
                group_id,
                file_path,
                version_hash,
                blocks,
                for_handoff,
            } => {
                crate::custody_diag::record_query(
                    group_id,
                    file_path,
                    version_hash.as_bytes(),
                    *for_handoff,
                    blocks.len(),
                );
                // The proof reads and hashes every block: synchronous disk work
                // that must not hold an async worker.
                let engine = self.replica_engine.clone();
                let query = yadorilink_replica_engine::DurableVersionQuery {
                    folder_group_id: group_id.clone(),
                    file_path: file_path.clone(),
                    block_hashes: blocks.iter().map(|b| b.hash.0.clone()).collect(),
                    for_handoff: *for_handoff,
                    version_hash: version_hash.as_bytes().to_vec(),
                    block_sizes: blocks.iter().map(|b| b.size).collect(),
                };
                let evaluation =
                    match super::spawn_blocking(move || engine.holds_version_durably(&query)).await
                    {
                        Ok(evaluation) => evaluation,
                        Err(error) => {
                            tracing::warn!(%error, "version proof task failed; answering absent");
                            yadorilink_replica_engine::outcomes::CustodyEvaluation {
                                present: false,
                                warning: None,
                            }
                        }
                    };
                if let Some(warning) = &evaluation.warning {
                    tracing::warn!(
                        group_id = %group_id,
                        path = %file_path,
                        error = %warning.message,
                        "refusing to serve block: current version record is unreadable"
                    );
                }
                crate::service_rpc::ServiceResponse::VersionPresent { present: evaluation.present }
            }
            crate::service_rpc::ServiceRequest::HandoffLease { group_id } => {
                let grant = self.handoff_lease_responder.request_handoff_lease(group_id).await;
                crate::service_rpc::ServiceResponse::HandoffLease {
                    grant: grant.map(|g| crate::service_rpc::LeaseGrant {
                        lease_id: g.lease_id,
                        root_digest: g.root_digest,
                        expires_at_unix: g.expires_at_unix,
                        ttl_seconds: g.ttl_seconds,
                    }),
                }
            }
            crate::service_rpc::ServiceRequest::HandoffTicket { group_id } => {
                let grant = self.handoff_ticket_responder.request_handoff_ticket(group_id).await;
                // A ticket with no lease id or no target device is not a
                // ticket. Fail closed here rather than send half of one and
                // leave the far end to decide what that means.
                crate::service_rpc::ServiceResponse::HandoffTicket {
                    grant: grant.and_then(|g| {
                        Some(crate::service_rpc::TicketGrant {
                            lease_id: g.lease_id?,
                            expires_at_unix: g.expires_at_unix,
                            target_device_id: g.target_device_id?,
                        })
                    }),
                }
            }
            crate::service_rpc::ServiceRequest::HandoffLeaseRelease { group_id, lease_id } => {
                if self.handoff_lease_responder.release_handoff_lease(group_id, lease_id).await {
                    crate::service_rpc::ServiceResponse::Released
                } else {
                    crate::service_rpc::ServiceResponse::ReleaseNotConfirmed
                }
            }
            crate::service_rpc::ServiceRequest::HandoffTicketRelease {
                group_id,
                target_device_id,
                lease_id,
            } => {
                self.handoff_ticket_responder
                    .release_handoff_ticket(group_id, target_device_id, lease_id)
                    .await;
                crate::service_rpc::ServiceResponse::Released
            }
            crate::service_rpc::ServiceRequest::GroupDurabilitySummary { group_id } => {
                // The answer observes this device's folder root on disk, and a
                // hung network mount blocks that call: it must not hold an
                // async worker.
                let engine = self.replica_engine.clone();
                let group_id = group_id.clone();
                let summary = match super::spawn_blocking(move || {
                    Self::group_durability_summary_for(&engine, &group_id)
                })
                .await
                {
                    Ok(summary) => summary,
                    Err(error) => {
                        tracing::warn!(%error, "durability summary task failed; refusing");
                        None
                    }
                };
                crate::service_rpc::ServiceResponse::GroupDurabilitySummary { summary }
            }
            crate::service_rpc::ServiceRequest::CustodyAcquire {
                group_id,
                file_path,
                version_hash,
                blocks,
                membership_generation,
                attempt_token,
            } => {
                // The lease is held for the authenticated peer of this session,
                // never for a device the request names.
                // The proof reads and hashes every block and commits the lease:
                // synchronous disk work (and a wait for a running block
                // deletion) that must not hold an async worker. Its guards live
                // and end inside the blocking task.
                let engine = self.replica_engine.clone();
                let requester = self.peer_device_id.clone();
                let query = yadorilink_replica_engine::DurableVersionQuery {
                    folder_group_id: group_id.clone(),
                    file_path: file_path.clone(),
                    block_hashes: blocks.iter().map(|b| b.hash.0.clone()).collect(),
                    for_handoff: false,
                    version_hash: version_hash.as_bytes().to_vec(),
                    block_sizes: blocks.iter().map(|b| b.size).collect(),
                };
                let (generation, token) = (*membership_generation, *attempt_token);
                let evaluation = match super::spawn_blocking(move || {
                    engine.acquire_custody_lease(&requester, &query, generation, token)
                })
                .await
                {
                    Ok(evaluation) => evaluation,
                    Err(error) => {
                        tracing::warn!(%error, "custody acquire task failed; refusing");
                        yadorilink_replica_engine::outcomes::CustodyEvaluation {
                            present: false,
                            warning: None,
                        }
                    }
                };
                if let Some(warning) = &evaluation.warning {
                    tracing::warn!(
                        group_id = %group_id,
                        path = %file_path,
                        error = %warning.message,
                        "refusing a custody lease"
                    );
                }
                crate::service_rpc::ServiceResponse::CustodyAcquire { granted: evaluation.present }
            }
            crate::service_rpc::ServiceRequest::CustodyRelease {
                group_id,
                file_path,
                version_hash,
                attempt_token,
            } => {
                let released = match self.replica_engine.release_custody_lease(
                    &self.peer_device_id,
                    group_id,
                    file_path,
                    version_hash.as_bytes(),
                    attempt_token,
                ) {
                    Ok(()) => true,
                    Err(error) => {
                        tracing::warn!(%error, group_id = %group_id, path = %file_path, "custody lease release failed");
                        false
                    }
                };
                crate::service_rpc::ServiceResponse::CustodyRelease { released }
            }
            crate::service_rpc::ServiceRequest::CustodyRehome {
                group_id,
                file_path,
                version_hash,
                attempt_token,
            } => crate::service_rpc::ServiceResponse::CustodyRehome {
                moved: self
                    .custody_rehome_responder
                    .rehome(
                        &self.peer_device_id,
                        group_id,
                        file_path,
                        *version_hash,
                        *attempt_token,
                    )
                    .await,
            },
        }
    }

    /// Answers the background health question about this device's own state.
    ///
    /// Reads the index, reads no block, and hashes no payload. That is the
    /// contract, and it is the whole reason this RPC exists: the asker used
    /// to learn the same thing by making this device read every block of
    /// every durability root back off disk, once every ninety seconds.
    ///
    /// `None` for every refusal, indistinguishably: not `Eager` for the
    /// group, or an unreadable index. Both are the engine's own decision
    /// (see `PeerReplicaEngine::root_set_summary`). Whether this peer may
    /// answer for `group_id` at all was already settled upstream, by the
    /// same stream-scoped authorization check every other service RPC goes
    /// through.
    fn group_durability_summary_for(
        engine: &yadorilink_replica_engine::PeerReplicaEngine,
        group_id: &str,
    ) -> Option<crate::service_rpc::GroupDurabilitySummary> {
        let summary = engine.root_set_summary(&yadorilink_replica_domain::ids::FolderGroupId(
            group_id.to_string(),
        ))?;
        Some(crate::service_rpc::GroupDurabilitySummary {
            // `root_set_summary` already refused a non-`Eager` device, so
            // reaching here means it is one. Carried explicitly anyway: the
            // asker's own check must not depend on inferring a precondition
            // from the presence of a message.
            eager: true,
            fully_materialized: summary.fully_materialized(),
            current_digest: summary.current_digest,
            current_count: summary.current_count,
            roots_digest: summary.roots_digest,
            roots_count: summary.roots_count,
            root_set_generation: summary.generation,
        })
    }

    /// Asks this peer whether it durably holds the exact file version
    /// identified by `version_hash` — the `VersionHash`,
    /// SHA-256 of the version's canonical `FileVersion`
    /// encoding (ordered block list with per-block size, total size, and
    /// metadata) — and returns its answer. `blocks` restates the same
    /// version's ordered block list (hash + size) so the responder can run
    /// its explicit block/size check and `get()` verification loop without a
    /// second round trip; the caller passes both explicitly rather than
    /// letting this function re-derive them, since the caller is the one
    /// pinning the exact version being confirmed (see `DaemonState::
    /// confirm_version_present_via_peer` / `peer_holds_entire_group`'s doc
    /// comments for why re-deriving here would risk attributing an in-flight
    /// confirmation to a version a concurrent local edit already replaced).
    /// The reply is trusted because it arrives over this authenticated peer
    /// channel from a device the netmap has confirmed a full-replica member
    /// of the group; a peer that does not answer within a bounded time does
    /// not confirm custody (returns `false`, fail closed). Never involves the
    /// coordination plane.
    ///
    /// `for_handoff` selects which of the responder's versions may satisfy the
    /// query (see `VersionPresentQuery.for_handoff`'s wire doc):
    /// - `false` for the on-demand per-file eviction custody gate: a device
    ///   reclaims its last cached copy of a file's CURRENT version only when a
    ///   full replica confirms that same content is *its own current* version,
    ///   never merely a retained (superseded/trashed) one that retention could
    ///   later reclaim.
    /// - `true` for the whole-group durability handoff: the peer may confirm
    ///   the queried version against any version it still retains, so retained
    ///   durability roots (not just current heads) are covered by the handoff.
    pub async fn request_version_present(
        &self,
        group_id: &str,
        file_path: &str,
        version_hash: VersionHash,
        blocks: &[VersionBlock],
        for_handoff: bool,
    ) -> bool {
        let request = crate::service_rpc::ServiceRequest::VersionPresent {
            group_id: group_id.to_string(),
            file_path: file_path.to_string(),
            version_hash,
            blocks: blocks.to_vec(),
            for_handoff,
        };
        matches!(
            self.service_rpc(&self.transports.service, &request).await,
            Some(crate::service_rpc::ServiceResponse::VersionPresent { present: true })
        )
    }

    /// Asks this peer to take durable custody of exactly this version: it
    /// commits a lease that keeps the version's blocks live before it answers.
    /// `true` only for that acknowledgement; every refusal, failure and
    /// timeout is `false` (fail closed).
    pub async fn request_custody_acquire(
        &self,
        group_id: &str,
        file_path: &str,
        version_hash: VersionHash,
        blocks: &[VersionBlock],
        membership_generation: u64,
        attempt_token: [u8; 16],
    ) -> bool {
        let request = crate::service_rpc::ServiceRequest::CustodyAcquire {
            group_id: group_id.to_string(),
            file_path: file_path.to_string(),
            version_hash,
            blocks: blocks.to_vec(),
            membership_generation,
            attempt_token,
        };
        matches!(
            self.service_rpc(&self.transports.service, &request).await,
            Some(crate::service_rpc::ServiceResponse::CustodyAcquire { granted: true })
        )
    }

    /// Asks this peer to end the lease it holds for this device on exactly
    /// this version. `true` once the peer acknowledged.
    pub async fn request_custody_release(
        &self,
        group_id: &str,
        file_path: &str,
        version_hash: VersionHash,
        attempt_token: [u8; 16],
    ) -> bool {
        let request = crate::service_rpc::ServiceRequest::CustodyRelease {
            group_id: group_id.to_string(),
            file_path: file_path.to_string(),
            version_hash,
            attempt_token,
        };
        matches!(
            self.service_rpc(&self.transports.service, &request).await,
            Some(crate::service_rpc::ServiceResponse::CustodyRelease { released: true })
        )
    }

    /// Asks this peer, the requester of a lease this device holds, to move
    /// that custody to another full replica and release ours. `true` only
    /// when the peer answered that it no longer depends on our lease.
    pub async fn request_custody_rehome(
        &self,
        group_id: &str,
        file_path: &str,
        version_hash: VersionHash,
        attempt_token: [u8; 16],
    ) -> bool {
        let request = crate::service_rpc::ServiceRequest::CustodyRehome {
            group_id: group_id.to_string(),
            file_path: file_path.to_string(),
            version_hash,
            attempt_token,
        };
        matches!(
            self.service_rpc(&self.transports.service, &request).await,
            Some(crate::service_rpc::ServiceResponse::CustodyRehome { moved: true })
        )
    }

    /// Asks this peer, over the service RPC lane, to describe its own
    /// durable state for `group_id` — the background health question.
    ///
    /// One round-trip for a whole group, and the peer reads no block to
    /// answer it. That is the entire point, and also the limit of what the
    /// answer is worth: it reports what the peer's index says, so it can
    /// support a health indicator and can never support letting go of a
    /// copy of anything. The per-root
    /// [`Self::request_version_present`] with `for_handoff = true` remains
    /// the only question whose answer a destructive action may act on.
    ///
    /// `None` on a refusal, a malformed reply, or no reply at all — all
    /// fail-closed and all indistinguishable here, matching every other
    /// service RPC on this lane.
    pub async fn request_group_durability_summary(
        &self,
        group_id: &str,
    ) -> Option<crate::service_rpc::GroupDurabilitySummary> {
        crate::custody_diag::record_summary_request();
        let request = crate::service_rpc::ServiceRequest::GroupDurabilitySummary {
            group_id: group_id.to_string(),
        };
        match self.service_rpc(&self.transports.service, &request).await {
            Some(crate::service_rpc::ServiceResponse::GroupDurabilitySummary { summary }) => {
                summary
            }
            _ => None,
        }
    }

    /// Asks this peer, over the service RPC lane, for a handoff lease on
    /// `group_id`. The caller (the daemon's source-side role-loss
    /// orchestration) is expected to only ever call this against a peer it
    /// has already confirmed, via the whole-group durability-handoff
    /// `request_version_present`, holds every root it itself holds.
    ///
    /// Returns `None` on any failure to obtain a genuinely granted lease: the
    /// request failing or refusing, an explicit
    /// `granted = false` answer, an empty `lease_id`, or a `root_digest`
    /// that isn't exactly 32 bytes. This method only carries the round trip
    /// -- it does NOT compare the returned digest against anything; the
    /// caller does that itself, daemon-local, against its own already-known
    /// digest.
    pub async fn request_handoff_lease_from_peer(
        &self,
        group_id: &str,
    ) -> Option<PeerHandoffLeaseGrant> {
        let request =
            crate::service_rpc::ServiceRequest::HandoffLease { group_id: group_id.to_string() };
        match self.service_rpc(&self.transports.service, &request).await {
            Some(crate::service_rpc::ServiceResponse::HandoffLease { grant }) => {
                grant.map(|g| PeerHandoffLeaseGrant {
                    lease_id: g.lease_id,
                    root_digest: g.root_digest,
                    expires_at_unix: g.expires_at_unix,
                    ttl_seconds: g.ttl_seconds,
                })
            }
            _ => None,
        }
    }

    /// Releases a lease this peer granted earlier. `Ok` only when the target
    /// answered that it processed the release; no answer (offline, timed out,
    /// refused) is an error, so a caller that must know the lease is ended can
    /// tell. The target validates current group membership before touching
    /// either half of the id-only lease reservation.
    pub async fn release_handoff_lease_to_peer(
        &self,
        group_id: &str,
        lease_id: &str,
    ) -> Result<(), PeerSessionError> {
        let response = self
            .service_rpc(
                &self.transports.service,
                &crate::service_rpc::ServiceRequest::HandoffLeaseRelease {
                    group_id: group_id.to_string(),
                    lease_id: lease_id.to_string(),
                },
            )
            .await;
        match response {
            Some(crate::service_rpc::ServiceResponse::Released) => Ok(()),
            _ => Err(PeerSessionError::NotFound(
                "the handoff lease release was not acknowledged".to_string(),
            )),
        }
    }

    /// Asks this peer (the device being removed/revoked), over the service
    /// RPC lane, for a handoff ticket on `group_id`. The caller is the
    /// OPERATING device's daemon (X), asking a DIFFERENT device (B, this
    /// session's peer) to attest and hand off its own roots — see
    /// `HandoffTicketResponder`'s doc comment for the trust model.
    ///
    /// Returns `None` on any failure to obtain a genuinely granted ticket:
    /// the request failing or refusing, or an explicit
    /// `granted = false` answer. X never distinguishes these — every one of
    /// them means "cannot lift the cross-device fail-closed gate for this
    /// group this round."
    pub async fn request_handoff_ticket_from_peer(
        &self,
        group_id: &str,
    ) -> Option<PeerHandoffTicketGrant> {
        let request =
            crate::service_rpc::ServiceRequest::HandoffTicket { group_id: group_id.to_string() };
        match self.service_rpc(&self.transports.service, &request).await {
            Some(crate::service_rpc::ServiceResponse::HandoffTicket { grant }) => {
                grant.map(|g| PeerHandoffTicketGrant {
                    lease_id: Some(g.lease_id),
                    target_device_id: Some(g.target_device_id),
                    expires_at_unix: g.expires_at_unix,
                })
            }
            _ => None,
        }
    }

    /// Best-effort cancellation of a removed-device ticket. The peer that
    /// created the ticket remains responsible for routing the final lease
    /// release to the target that owns it.
    pub async fn release_handoff_ticket_to_peer(
        &self,
        group_id: &str,
        target_device_id: &str,
        lease_id: &str,
    ) -> Result<(), PeerSessionError> {
        // Acknowledged rather than fire-and-forget: the answer costs one
        // stream and turns "probably released" into "released".
        self.service_rpc(
            &self.transports.service,
            &crate::service_rpc::ServiceRequest::HandoffTicketRelease {
                group_id: group_id.to_string(),
                target_device_id: target_device_id.to_string(),
                lease_id: lease_id.to_string(),
            },
        )
        .await;
        Ok(())
    }
}
