//! The service-lane RPC encoding.
//!
//! One request, one response, one stream. There is no request id here and no
//! table to look one up in: the stream a response arrives on is which request
//! it answers. That removes, per RPC that moves onto this lane, an id
//! allocator, a pending map, a cancellation guard to stop that map leaking,
//! and a timeout whose only job was to bound a reply that might never be
//! correlated.
//!
//! Every declared length is checked before it is allocated for. These bytes
//! come from a peer.

use yadorilink_replica_domain::file::VersionBlock;
use yadorilink_replica_domain::ids::{BlockHash, VersionHash};

/// Bumped if the layout below changes.
const RPC_VERSION: u8 = 2;

const KIND_VERSION_PRESENT: u8 = 1;
const KIND_HANDOFF_LEASE: u8 = 2;
const KIND_HANDOFF_TICKET: u8 = 3;
const KIND_HANDOFF_LEASE_RELEASE: u8 = 4;
const KIND_HANDOFF_TICKET_RELEASE: u8 = 5;
// 6 was a retired request/response, removed. Not reused.
const KIND_GROUP_DURABILITY_SUMMARY: u8 = 7;
// 8 and 9 were the custody acquire and release without an attempt token,
// retired. Not reused.
const KIND_CUSTODY_ACQUIRE: u8 = 10;
const KIND_CUSTODY_RELEASE: u8 = 11;
const KIND_CUSTODY_REHOME: u8 = 12;
const KIND_HANDOFF_LEASE_RELEASE_NOT_CONFIRMED: u8 = 13;

/// Ceilings, applied before allocation.
const MAX_GROUP_BYTES: usize = 512;
const MAX_PATH_BYTES: usize = yadorilink_replica_domain::limits::MAX_PATH_BYTES;
const MAX_BLOCKS: usize = yadorilink_replica_domain::limits::MAX_BLOCKS;
const MAX_BLOCK_HASH_BYTES: usize = 64;
const MAX_LEASE_ID_BYTES: usize = 256;
const MAX_DEVICE_ID_BYTES: usize = 256;

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ServiceRpcError {
    #[error("service rpc claims {needed} more bytes but only {available} are present")]
    Truncated { needed: usize, available: usize },

    #[error("service rpc declares version {0}, this node encodes version {RPC_VERSION}")]
    UnsupportedVersion(u8),

    #[error("unknown service rpc kind {0}")]
    UnknownKind(u8),

    #[error("{field} declares {declared}, limit is {limit}")]
    FieldTooLarge { field: &'static str, declared: usize, limit: usize },

    #[error("{field} is not valid UTF-8")]
    NotUtf8 { field: &'static str },

    #[error("{0} unread bytes after the message")]
    TrailingBytes(usize),
}

/// A request one peer makes of another over the service lane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceRequest {
    /// Whether the answering device can be trusted, right now, as a durable
    /// full-replica holder of exactly this version.
    VersionPresent {
        group_id: String,
        file_path: String,
        version_hash: VersionHash,
        blocks: Vec<VersionBlock>,
        for_handoff: bool,
    },
    /// Ask this peer for a handoff lease on a group.
    HandoffLease { group_id: String },
    /// Ask this peer for a removed-device handoff ticket on a group.
    HandoffTicket { group_id: String },
    /// Best-effort release of a lease this device holds from the peer.
    ///
    /// A release was fire-and-forget on the legacy path: nothing correlated a
    /// reply, so the sender never learned whether it landed. Here it is a
    /// request like any other and the peer acknowledges it, which costs one
    /// stream and turns "probably released" into "released".
    HandoffLeaseRelease { group_id: String, lease_id: String },
    /// Best-effort cancellation of a ticket, acknowledged for the same reason.
    HandoffTicketRelease { group_id: String, target_device_id: String, lease_id: String },
    /// Ask this peer to describe its own durable state for a group in one
    /// message: two digests and two counts, derived from its index alone.
    ///
    /// This is the background health check, and it is a different question
    /// from [`Self::VersionPresent`] with `for_handoff = true`. That one asks
    /// the peer to read every block back and re-checksum it, and is what a
    /// destructive action requires. This one asks only what the peer's index
    /// says, costs one round-trip for a whole group rather than one per
    /// durability root, and can never authorize anything.
    GroupDurabilitySummary { group_id: String },
    /// Ask this full replica to take durable custody of exactly this version
    /// for the sender: the responder commits a lease row that keeps the
    /// version's blocks live, and answers `granted` only after that commit.
    /// Unlike [`Self::VersionPresent`] the answer is a promise that lasts until
    /// [`Self::CustodyRelease`], not a statement about this instant.
    /// `membership_generation` is the sender's authorization epoch.
    /// `attempt_token` names this attempt: the lease is held by it, and a
    /// release of the same token that reached the responder first makes this
    /// acquire commit nothing.
    CustodyAcquire {
        group_id: String,
        file_path: String,
        version_hash: VersionHash,
        blocks: Vec<VersionBlock>,
        membership_generation: u64,
        attempt_token: [u8; 16],
    },
    /// Ends the lease the sender holds on exactly this version through the
    /// attempt `attempt_token`, and makes a not-yet-arrived acquire of that
    /// attempt a no-op. Acknowledged whether or not such a lease existed, so
    /// a release can be retried.
    CustodyRelease {
        group_id: String,
        file_path: String,
        version_hash: VersionHash,
        attempt_token: [u8; 16],
    },
    /// Sent by a full replica that is about to stop being one, to the
    /// requester of a lease it holds: move your custody of this version to
    /// another full replica and release mine. Names the lease by the attempt
    /// that holds it.
    CustodyRehome {
        group_id: String,
        file_path: String,
        version_hash: VersionHash,
        attempt_token: [u8; 16],
    },
}

impl ServiceRequest {
    /// The group this request is scoped to.
    ///
    /// Every service RPC is group-scoped, and the answering side authorizes
    /// against *this* rather than against anything it remembered when the
    /// stream opened — see `PeerSyncSession::serve_service_stream`.
    pub fn group_id(&self) -> &str {
        match self {
            ServiceRequest::VersionPresent { group_id, .. }
            | ServiceRequest::HandoffLease { group_id }
            | ServiceRequest::HandoffTicket { group_id }
            | ServiceRequest::HandoffLeaseRelease { group_id, .. }
            | ServiceRequest::HandoffTicketRelease { group_id, .. }
            | ServiceRequest::GroupDurabilitySummary { group_id }
            | ServiceRequest::CustodyAcquire { group_id, .. }
            | ServiceRequest::CustodyRelease { group_id, .. }
            | ServiceRequest::CustodyRehome { group_id, .. } => group_id,
        }
    }
}

/// The single answer to a [`ServiceRequest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceResponse {
    VersionPresent {
        present: bool,
    },
    /// `None` is a refusal — not granted, or not authorized. The two are
    /// deliberately indistinguishable to the asker.
    HandoffLease {
        grant: Option<LeaseGrant>,
    },
    HandoffTicket {
        grant: Option<TicketGrant>,
    },
    /// The release was received. Carries nothing: there is nothing to say
    /// beyond that it arrived.
    Released,
    /// A handoff lease release that did not end the lease (refused, or the
    /// lease could not be ended). Only `Released` says the lease is gone.
    ReleaseNotConfirmed,
    /// `None` is a refusal — not a full replica of the group, an
    /// authorization this device will not vouch for, or an index it could
    /// not read. Deliberately indistinguishable to the asker, like
    /// `HandoffLease`, and fail-closed for all three.
    GroupDurabilitySummary {
        summary: Option<GroupDurabilitySummary>,
    },
    /// `granted` only when the lease row is committed. A refusal of any kind
    /// is `false`, indistinguishable to the asker.
    CustodyAcquire {
        granted: bool,
    },
    /// `released` only when the lease is gone, or never was. A responder that
    /// could not delete the row answers `false`, so the requester keeps
    /// retrying instead of believing a lease ended that still pins blocks.
    CustodyRelease {
        released: bool,
    },
    /// `moved` only when the requester no longer depends on the sender's
    /// lease: it holds custody at another full replica, or never needed it,
    /// and the sender's lease is released. `false` leaves the lease in place.
    CustodyRehome {
        moved: bool,
    },
}

/// One peer's answer about its own durable state for a group.
///
/// Every field is read from that peer's own index. **No block is read and
/// no payload is hashed to produce one**, which is the entire difference
/// between this and the handoff proof, and the reason a value of this type
/// must never reach a destructive-action gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupDurabilitySummary {
    /// The responder's own retention policy for the group is `Eager`.
    ///
    /// The same precondition `holds_version_durably` checks first: an
    /// on-demand device may hold blocks transiently and evict them at any
    /// moment, so its agreement is not a durability claim at all.
    pub eager: bool,
    /// Every one of the responder's current rows for the group is
    /// materialized locally.
    ///
    /// Load-bearing, not informational. An index row exists from the moment
    /// its change is projected, which is long before the content behind it
    /// has been fetched — so a peer that has caught up on native state and
    /// downloaded nothing at all produces exactly the same
    /// [`Self::current_digest`] as one holding every byte. Without this, a
    /// device that joined a folder a minute ago and is still transferring
    /// would corroborate immediately, and the group would report itself
    /// protected while precisely one device had the data.
    pub fully_materialized: bool,
    /// Over `state = 'current'` alone, using the same digest function and
    /// the same row category the handoff proof enumerates. The convergent
    /// subset, and the only digest a positive rests on.
    pub current_digest: [u8; 32],
    pub current_count: u64,
    /// Over the responder's full durability-root set — current, retained
    /// superseded and trash-restorable alike.
    ///
    /// An observation, never a requirement. Two honest eager replicas
    /// routinely disagree here forever: a device that joins a folder starts
    /// from a local history floor and never reconstructs what came before
    /// it, and retention keeps a version that is within the count bound no
    /// matter how old it gets. Requiring equality would have left the most
    /// ordinary two-device topology permanently uncorroborated. When it
    /// does match, more is true, and that is worth reporting.
    pub roots_digest: [u8; 32],
    pub roots_count: u64,
    /// The responder's own root-set generation counter. Recorded, never
    /// compared: a number a peer reports about its own state proves nothing
    /// about freshness. Freshness is the asker's own clock and its own
    /// membership generation.
    ///
    /// Nothing else about the responder's own view of the world is carried
    /// here, deliberately. A peer's account of its own authorization would
    /// be another self-report, and the questions it could answer are
    /// already answered without it: whether this peer may speak for the
    /// group at all is decided by the service stream's own authorization
    /// check before the responder is reached, and whether the ASKER can
    /// currently trust its own policy view for the group is the asker's own
    /// `group_policy_stale` fact, folded into its classification either
    /// way.
    pub root_set_generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseGrant {
    pub lease_id: String,
    pub root_digest: [u8; 32],
    pub expires_at_unix: i64,
    /// How long the lease lives, as a duration: the one lifetime two devices
    /// can compare without trusting each other's clocks.
    pub ttl_seconds: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TicketGrant {
    pub lease_id: String,
    pub expires_at_unix: i64,
    pub target_device_id: String,
}

pub fn encode_request(request: &ServiceRequest) -> Vec<u8> {
    let mut out = vec![RPC_VERSION];
    match request {
        ServiceRequest::VersionPresent {
            group_id,
            file_path,
            version_hash,
            blocks,
            for_handoff,
        } => {
            out.push(KIND_VERSION_PRESENT);
            put_str(&mut out, group_id);
            put_str(&mut out, file_path);
            out.extend_from_slice(version_hash.as_bytes());
            out.push(u8::from(*for_handoff));
            put_blocks(&mut out, blocks);
        }
        ServiceRequest::HandoffLease { group_id } => {
            out.push(KIND_HANDOFF_LEASE);
            put_str(&mut out, group_id);
        }
        ServiceRequest::HandoffTicket { group_id } => {
            out.push(KIND_HANDOFF_TICKET);
            put_str(&mut out, group_id);
        }
        ServiceRequest::HandoffLeaseRelease { group_id, lease_id } => {
            out.push(KIND_HANDOFF_LEASE_RELEASE);
            put_str(&mut out, group_id);
            put_str(&mut out, lease_id);
        }
        ServiceRequest::HandoffTicketRelease { group_id, target_device_id, lease_id } => {
            out.push(KIND_HANDOFF_TICKET_RELEASE);
            put_str(&mut out, group_id);
            put_str(&mut out, target_device_id);
            put_str(&mut out, lease_id);
        }
        ServiceRequest::GroupDurabilitySummary { group_id } => {
            out.push(KIND_GROUP_DURABILITY_SUMMARY);
            put_str(&mut out, group_id);
        }
        ServiceRequest::CustodyAcquire {
            group_id,
            file_path,
            version_hash,
            blocks,
            membership_generation,
            attempt_token,
        } => {
            out.push(KIND_CUSTODY_ACQUIRE);
            put_str(&mut out, group_id);
            put_str(&mut out, file_path);
            out.extend_from_slice(version_hash.as_bytes());
            out.extend_from_slice(&membership_generation.to_be_bytes());
            out.extend_from_slice(attempt_token);
            put_blocks(&mut out, blocks);
        }
        ServiceRequest::CustodyRelease { group_id, file_path, version_hash, attempt_token } => {
            out.push(KIND_CUSTODY_RELEASE);
            put_str(&mut out, group_id);
            put_str(&mut out, file_path);
            out.extend_from_slice(version_hash.as_bytes());
            out.extend_from_slice(attempt_token);
        }
        ServiceRequest::CustodyRehome { group_id, file_path, version_hash, attempt_token } => {
            out.push(KIND_CUSTODY_REHOME);
            put_str(&mut out, group_id);
            put_str(&mut out, file_path);
            out.extend_from_slice(version_hash.as_bytes());
            out.extend_from_slice(attempt_token);
        }
    }
    out
}

pub fn decode_request(bytes: &[u8]) -> Result<ServiceRequest, ServiceRpcError> {
    let mut cursor = Cursor { bytes, at: 0 };
    let version = cursor.u8()?;
    if version != RPC_VERSION {
        return Err(ServiceRpcError::UnsupportedVersion(version));
    }
    let request = match cursor.u8()? {
        KIND_VERSION_PRESENT => {
            let group_id = cursor.str_field("group id", MAX_GROUP_BYTES)?;
            let file_path = cursor.str_field("file path", MAX_PATH_BYTES)?;
            let version_hash = VersionHash(cursor.array32()?);
            let for_handoff = cursor.u8()? != 0;
            let blocks = cursor.blocks()?;
            ServiceRequest::VersionPresent {
                group_id,
                file_path,
                version_hash,
                blocks,
                for_handoff,
            }
        }
        KIND_HANDOFF_LEASE => ServiceRequest::HandoffLease {
            group_id: cursor.str_field("group id", MAX_GROUP_BYTES)?,
        },
        KIND_HANDOFF_TICKET => ServiceRequest::HandoffTicket {
            group_id: cursor.str_field("group id", MAX_GROUP_BYTES)?,
        },
        KIND_HANDOFF_LEASE_RELEASE => ServiceRequest::HandoffLeaseRelease {
            group_id: cursor.str_field("group id", MAX_GROUP_BYTES)?,
            lease_id: cursor.str_field("lease id", MAX_LEASE_ID_BYTES)?,
        },
        KIND_HANDOFF_TICKET_RELEASE => ServiceRequest::HandoffTicketRelease {
            group_id: cursor.str_field("group id", MAX_GROUP_BYTES)?,
            target_device_id: cursor.str_field("device id", MAX_DEVICE_ID_BYTES)?,
            lease_id: cursor.str_field("lease id", MAX_LEASE_ID_BYTES)?,
        },
        KIND_GROUP_DURABILITY_SUMMARY => ServiceRequest::GroupDurabilitySummary {
            group_id: cursor.str_field("group id", MAX_GROUP_BYTES)?,
        },
        KIND_CUSTODY_ACQUIRE => ServiceRequest::CustodyAcquire {
            group_id: cursor.str_field("group id", MAX_GROUP_BYTES)?,
            file_path: cursor.str_field("file path", MAX_PATH_BYTES)?,
            version_hash: VersionHash(cursor.array32()?),
            membership_generation: cursor.u64()?,
            attempt_token: cursor.array16()?,
            blocks: cursor.blocks()?,
        },
        KIND_CUSTODY_RELEASE => ServiceRequest::CustodyRelease {
            group_id: cursor.str_field("group id", MAX_GROUP_BYTES)?,
            file_path: cursor.str_field("file path", MAX_PATH_BYTES)?,
            version_hash: VersionHash(cursor.array32()?),
            attempt_token: cursor.array16()?,
        },
        KIND_CUSTODY_REHOME => ServiceRequest::CustodyRehome {
            group_id: cursor.str_field("group id", MAX_GROUP_BYTES)?,
            file_path: cursor.str_field("file path", MAX_PATH_BYTES)?,
            version_hash: VersionHash(cursor.array32()?),
            attempt_token: cursor.array16()?,
        },
        other => return Err(ServiceRpcError::UnknownKind(other)),
    };
    if cursor.at != bytes.len() {
        return Err(ServiceRpcError::TrailingBytes(bytes.len() - cursor.at));
    }
    Ok(request)
}

pub fn encode_response(response: &ServiceResponse) -> Vec<u8> {
    let mut out = vec![RPC_VERSION];
    match response {
        ServiceResponse::VersionPresent { present } => {
            out.push(KIND_VERSION_PRESENT);
            out.push(u8::from(*present));
        }
        ServiceResponse::HandoffLease { grant } => {
            out.push(KIND_HANDOFF_LEASE);
            match grant {
                None => out.push(0),
                Some(grant) => {
                    out.push(1);
                    put_str(&mut out, &grant.lease_id);
                    out.extend_from_slice(&grant.root_digest);
                    out.extend_from_slice(&grant.expires_at_unix.to_be_bytes());
                    out.extend_from_slice(&grant.ttl_seconds.to_be_bytes());
                }
            }
        }
        ServiceResponse::HandoffTicket { grant } => {
            out.push(KIND_HANDOFF_TICKET);
            match grant {
                None => out.push(0),
                Some(grant) => {
                    out.push(1);
                    put_str(&mut out, &grant.lease_id);
                    out.extend_from_slice(&grant.expires_at_unix.to_be_bytes());
                    put_str(&mut out, &grant.target_device_id);
                }
            }
        }
        ServiceResponse::Released => out.push(KIND_HANDOFF_LEASE_RELEASE),
        ServiceResponse::ReleaseNotConfirmed => out.push(KIND_HANDOFF_LEASE_RELEASE_NOT_CONFIRMED),
        ServiceResponse::CustodyAcquire { granted } => {
            out.push(KIND_CUSTODY_ACQUIRE);
            out.push(u8::from(*granted));
        }
        ServiceResponse::CustodyRelease { released } => {
            out.push(KIND_CUSTODY_RELEASE);
            out.push(u8::from(*released));
        }
        ServiceResponse::CustodyRehome { moved } => {
            out.push(KIND_CUSTODY_REHOME);
            out.push(u8::from(*moved));
        }
        ServiceResponse::GroupDurabilitySummary { summary } => {
            out.push(KIND_GROUP_DURABILITY_SUMMARY);
            match summary {
                None => out.push(0),
                Some(summary) => {
                    out.push(1);
                    out.push(u8::from(summary.eager));
                    out.push(u8::from(summary.fully_materialized));
                    out.extend_from_slice(&summary.current_digest);
                    out.extend_from_slice(&summary.current_count.to_be_bytes());
                    out.extend_from_slice(&summary.roots_digest);
                    out.extend_from_slice(&summary.roots_count.to_be_bytes());
                    out.extend_from_slice(&summary.root_set_generation.to_be_bytes());
                }
            }
        }
    }
    out
}

pub fn decode_response(bytes: &[u8]) -> Result<ServiceResponse, ServiceRpcError> {
    let mut cursor = Cursor { bytes, at: 0 };
    let version = cursor.u8()?;
    if version != RPC_VERSION {
        return Err(ServiceRpcError::UnsupportedVersion(version));
    }
    let response = match cursor.u8()? {
        KIND_VERSION_PRESENT => ServiceResponse::VersionPresent { present: cursor.u8()? != 0 },
        KIND_HANDOFF_LEASE => ServiceResponse::HandoffLease {
            grant: match cursor.u8()? {
                0 => None,
                _ => Some(LeaseGrant {
                    lease_id: cursor.str_field("lease id", MAX_LEASE_ID_BYTES)?,
                    root_digest: cursor.array32()?,
                    expires_at_unix: cursor.i64()?,
                    ttl_seconds: cursor.i64()?,
                }),
            },
        },
        KIND_HANDOFF_TICKET => ServiceResponse::HandoffTicket {
            grant: match cursor.u8()? {
                0 => None,
                _ => Some(TicketGrant {
                    lease_id: cursor.str_field("lease id", MAX_LEASE_ID_BYTES)?,
                    expires_at_unix: cursor.i64()?,
                    target_device_id: cursor.str_field("device id", MAX_DEVICE_ID_BYTES)?,
                }),
            },
        },
        KIND_HANDOFF_LEASE_RELEASE => ServiceResponse::Released,
        KIND_HANDOFF_LEASE_RELEASE_NOT_CONFIRMED => ServiceResponse::ReleaseNotConfirmed,
        KIND_CUSTODY_ACQUIRE => ServiceResponse::CustodyAcquire { granted: cursor.u8()? != 0 },
        KIND_CUSTODY_RELEASE => ServiceResponse::CustodyRelease { released: cursor.u8()? != 0 },
        KIND_CUSTODY_REHOME => ServiceResponse::CustodyRehome { moved: cursor.u8()? != 0 },
        KIND_GROUP_DURABILITY_SUMMARY => ServiceResponse::GroupDurabilitySummary {
            summary: match cursor.u8()? {
                0 => None,
                _ => Some(GroupDurabilitySummary {
                    eager: cursor.u8()? != 0,
                    fully_materialized: cursor.u8()? != 0,
                    current_digest: cursor.array32()?,
                    current_count: cursor.u64()?,
                    roots_digest: cursor.array32()?,
                    roots_count: cursor.u64()?,
                    root_set_generation: cursor.u64()?,
                }),
            },
        },
        other => return Err(ServiceRpcError::UnknownKind(other)),
    };
    if cursor.at != bytes.len() {
        return Err(ServiceRpcError::TrailingBytes(bytes.len() - cursor.at));
    }
    Ok(response)
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn put_blocks(out: &mut Vec<u8>, blocks: &[VersionBlock]) {
    out.extend_from_slice(&(blocks.len() as u32).to_be_bytes());
    for block in blocks {
        put_bytes(out, &block.hash.0);
        out.extend_from_slice(&block.size.to_be_bytes());
    }
}

fn put_str(out: &mut Vec<u8>, text: &str) {
    put_bytes(out, text.as_bytes());
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], ServiceRpcError> {
        let available = self.bytes.len() - self.at;
        if available < count {
            return Err(ServiceRpcError::Truncated { needed: count, available });
        }
        let slice = &self.bytes[self.at..self.at + count];
        self.at += count;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, ServiceRpcError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, ServiceRpcError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }

    fn i64(&mut self) -> Result<i64, ServiceRpcError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")))
    }

    fn u64(&mut self) -> Result<u64, ServiceRpcError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")))
    }

    /// A block list: a count, then each block's hash and size. A count larger
    /// than the bytes present is refused before a single element is reserved.
    fn blocks(&mut self) -> Result<Vec<VersionBlock>, ServiceRpcError> {
        // A block entry is at minimum a 4-byte length prefix and a 4-byte size.
        let declared = self.u32()? as usize;
        if declared > MAX_BLOCKS {
            return Err(ServiceRpcError::FieldTooLarge {
                field: "block count",
                declared,
                limit: MAX_BLOCKS,
            });
        }
        let remaining = self.bytes.len() - self.at;
        if declared.saturating_mul(8) > remaining {
            return Err(ServiceRpcError::Truncated {
                needed: declared.saturating_mul(8),
                available: remaining,
            });
        }
        let mut blocks = Vec::with_capacity(declared);
        for _ in 0..declared {
            let hash = self.bytes_field("block hash", MAX_BLOCK_HASH_BYTES)?.to_vec();
            let size = self.u32()?;
            blocks.push(VersionBlock { hash: BlockHash(hash), size });
        }
        Ok(blocks)
    }

    fn array16(&mut self) -> Result<[u8; 16], ServiceRpcError> {
        Ok(self.take(16)?.try_into().expect("16 bytes"))
    }

    fn array32(&mut self) -> Result<[u8; 32], ServiceRpcError> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }

    fn bytes_field(
        &mut self,
        field: &'static str,
        limit: usize,
    ) -> Result<&'a [u8], ServiceRpcError> {
        let declared = self.u32()? as usize;
        if declared > limit {
            return Err(ServiceRpcError::FieldTooLarge { field, declared, limit });
        }
        self.take(declared)
    }

    fn str_field(&mut self, field: &'static str, limit: usize) -> Result<String, ServiceRpcError> {
        let bytes = self.bytes_field(field, limit)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| ServiceRpcError::NotUtf8 { field })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod handoff_tests;
