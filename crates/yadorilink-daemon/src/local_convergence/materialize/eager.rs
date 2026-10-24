use std::path::PathBuf;
use std::sync::Arc;

use yadorilink_peer_session::ports::OpenMaterializationIntent;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::{FileVersion, RecordKind};
use yadorilink_replica_domain::session_state::MaterializationState;

use super::super::types::*;
use super::MaterializationPlan;
use yadorilink_fs_platform::fs_identity::{disk_race_fingerprint, DiskRaceFingerprint};

// The eager lane is a pipeline. Each stage consumes the value the
// previous one produced, so a stage can only run once everything before it
// has: a write needs a revalidated target, a verification needs a written
// object whose payload metadata is applied, and the commit needs the
// verified evidence.

/// This path as it stood on disk before this pass asked for any blocks.
struct ObservedTarget {
    race_check_path: PathBuf,
    pre_fetch_disk_state: Option<(u64, Option<std::time::SystemTime>, i64, i64)>,
}

/// The answer to "is this record's content on this device?".
enum ContentLocation {
    /// Not all of it, and the session has not yet had its attempt at the
    /// block lane: hand the requirement to the session.
    NeedBlocks(BlockRequirement),
    /// Either all present, or the session already had its bounded attempt.
    Located(LocatedContent),
}

/// This record's content, located locally as far as it could be.
struct LocatedContent {
    race_check_path: PathBuf,
    all_present: bool,
}

/// A target that passed both pre-write revalidations -- nothing wrote to it
/// while blocks were fetched, and its bytes still match what this device
/// has indexed. Every write below consumes one.
struct RevalidatedTarget {
    all_present: bool,
    /// The target as it stood when it passed those revalidations; the
    /// write is only published over exactly this.
    baseline: TargetBaseline,
}

/// What the target looked like at the moment it was last found free of
/// uncaptured local state.
#[derive(Clone)]
struct TargetBaseline {
    fingerprint: Option<DiskRaceFingerprint>,
    /// Whether the path was already journaled dirty then. A path that
    /// becomes dirty afterwards was written to by someone else.
    was_dirty: bool,
}

/// Whether an assembled temp file was published.
enum AssembleOutcome {
    /// Published; carries the temp name when the flush was left to the
    /// window's batch barrier.
    Written(Option<PathBuf>),
    /// The target changed while the temp file was assembled; nothing was
    /// published.
    LocalEdit,
}

/// The row is committed under an open materialization intent, the target is
/// verified and preflighted, and the mutation fence is bumped for the
/// content write. The bytes are not written yet.
struct PendingContentWrite<'a> {
    intent_guard: Box<dyn OpenMaterializationIntent + Send + 'a>,
    out_path: PathBuf,
    written_version: FileVersion,
    mutation_generation: i64,
    baseline: TargetBaseline,
    /// Free space this write claimed, held until its bytes are in place.
    headroom: Arc<super::super::reconcile::HeadroomReservation>,
}

/// The outcome of the content write: the payload's bytes are durably
/// renamed into place, or the attempt was demoted to a retriable
/// placeholder.
enum Reconstruction {
    Written(Box<WrittenObject>),
    DemotedToPlaceholder,
    /// A local write landed while the bytes were being assembled and was
    /// left in place.
    LocalEditDuringAssembly,
}

/// The payload's bytes on disk at `out_path`, written under
/// `mutation_generation`.
struct WrittenObject {
    /// Set when the file was renamed into place unflushed: the temp name it was
    /// staged under, whose flush the window's barrier owes.
    deferred_tmp: Option<PathBuf>,
    out_path: PathBuf,
    written_version: FileVersion,
    mutation_generation: i64,
}

/// A write whose bytes reached the disk but are not yet closed.
struct LandedWrite {
    out_path: PathBuf,
    version: yadorilink_replica_domain::ids::VersionHash,
    mutation_generation: i64,
}

/// The written object with this payload's mode and xattrs applied.
struct AppliedObject {
    written: WrittenObject,
    /// The strict xattr check this attempt made before applying the final
    /// mode; the exactness gate uses it instead of re-reading a file the
    /// mode may have made unreadable.
    xattrs: super::super::types::XattrEvidence,
}

/// The applied object verified as the exact desired object, with the
/// evidence that says so. Only this is committed.
struct VerifiedObject {
    written: WrittenObject,
    evidence: SettlementEvidence,
}

impl super::super::LocalConvergenceExecutor {
    /// The eager lane of [`Self::materialize_local`]: this record's
    /// content is wanted on disk now.
    pub(super) async fn materialize_eager_lane(
        &self,
        plan: &MaterializationPlan<'_>,
    ) -> Result<LocalMaterializeOutcome, PeerSessionError> {
        yadorilink_fs_platform::join_timeline::mark(
            &self.local_device_id,
            plan.group_id,
            yadorilink_fs_platform::join_timeline::Milestone::MaterializationStarted,
        );
        let observed = self.observe_target(plan)?;
        let located = match self.locate_content(plan, observed)? {
            ContentLocation::NeedBlocks(requirement) => {
                return Ok(LocalMaterializeOutcome::NeedBlocks(requirement));
            }
            ContentLocation::Located(located) => located,
        };
        // Blocks are requested before this check, hazardous or not, and
        // that ordering is deliberate: this device may be another peer's
        // only currently-reachable source for these blocks even though it
        // cannot write them to disk under this name itself ("blocks still
        // requested/served to peers"). Only the write step below is
        // skipped for a held record.
        if let Some(reason) = &plan.hazard_reason {
            return self.hold_for_hazard(plan, reason);
        }
        let Some(target) = self.revalidate_target(plan, located)? else {
            return Ok(MaterializeResult::RetryRequired.into());
        };
        // Do not record unfetched content as hydrated:
        // `ensure_blocks_present` returns `false` (not an error) when a
        // peer could not supply one or more of this record's blocks
        // (reported not-found/unusable, or returned bytes failing
        // integrity verification). Committing a `Present` row and
        // running `reconstruct_file` here would then fail at
        // `store.get(<missing block>)` mid-loop, orphaning its temp file
        // and leaving a live-but-fileless `Present` row — which
        // `repair_interrupted_materializations` (blocks still absent)
        // demotes to an empty placeholder, silently destroying a
        // still-pending write (for a losing conflict copy, its only
        // preservation). Instead record a retriable `Remote` — the
        // exact `all_present == false` handling `hydration::hydrate_inner`
        // already uses — so the fetch is retried on a later reconcile
        // (`live_record_needs_rehydrate`) and recovery never
        // clobbers it. Reuses the not-admitted branch's placeholder path.
        if !target.all_present {
            return self.write_incomplete_content_placeholder(plan, target);
        }
        let pending = self.begin_content_write(plan, target).await?;
        let written = match self.reconstruct_content(plan, pending).await? {
            Reconstruction::Written(written) => *written,
            Reconstruction::DemotedToPlaceholder | Reconstruction::LocalEditDuringAssembly => {
                return Ok(MaterializeResult::RetryRequired.into());
            }
        };
        // The proof, the `Present` stamp, the intent clear and -- when
        // the obligation engine handed this attempt a claim on the path --
        // the obligation's completion are committed HERE, in one
        // transaction, under exactly the epoch this write bumped. The
        // engine publishes nothing more for this path and does not
        // complete it again (see `ReplicaCoordinator::close_content_write`).
        //
        // Publishing here is not what was reverted before. That was
        // the EXTERNAL-capture lane (`adopt_local_capture_actual_state`),
        // which mints a fresh epoch on its way to recording what it
        // was told: it moved the fence from `N` to `N+1` and
        // published a versionless proof under `N+1`, so the engine's
        // own CAS on `N` lost every time on the healthy path. The
        // internal commit used here mints nothing -- it CASes on the
        // epoch it is given, and publishes the version it is given.
        //
        // A crash before this commit leaves no proof at all, which is
        // the correct outcome: the intent is still open and the
        // obligation untouched, so the work is re-driven.
        tracing::debug!("phase T_recv_hydrated_commit: Hydrated state-machine commit completed");
        let landed = LandedWrite {
            out_path: written.out_path.clone(),
            version: written.written_version.version_hash,
            mutation_generation: written.mutation_generation,
        };
        let applied = match self.apply_written_metadata(plan, written) {
            Ok(applied) => applied,
            Err(error) => {
                return match self.settle_write_removed_by_user(plan, &landed)? {
                    Some(settled) => Ok(settled),
                    None => Err(error),
                };
            }
        };
        let verified = match self.verify_written_object(plan, applied).await {
            Ok(Some(verified)) => verified,
            Ok(None) => {
                // The bytes landed, but the path has moved on to a version
                // they are not. There is no exact claim to make about
                // them, so re-drive rather than settle -- and leave the
                // intent open, since nothing has been proven.
                return match self.settle_write_removed_by_user(plan, &landed)? {
                    Some(settled) => Ok(settled),
                    None => Ok(MaterializeResult::RetryRequired.into()),
                };
            }
            Err(error) => {
                return match self.settle_write_removed_by_user(plan, &landed)? {
                    Some(settled) => Ok(settled),
                    None => Err(error),
                };
            }
        };
        // The seam between the disk and the commit. Everything above it
        // is on disk and durable -- the temp file synced, renamed into
        // place, its parent directory synced (`assemble_and_persist`),
        // then the payload's metadata applied and the object verified --
        // and nothing about it is committed: no proof, no `Present`, the
        // intent and the obligation open. A crash here is exactly that
        // state, which repair and the next claim finish without rewriting
        // the bytes; a mutator landing here moves the fence or the claim
        // and the commit below refuses accordingly. A test parks here.
        #[cfg(any(test, feature = "test-support"))]
        {
            let probe =
                self.overlap_probe.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
            if let Some(probe) = probe {
                probe
                    .pass(crate::local_convergence::ProbeSeam::BeforeCommit, &plan.record.path)
                    .await;
            }
        }
        if let Some(claim) = plan.claim {
            claim.before_completion().await;
        }
        #[cfg(any(test, feature = "test-support"))]
        {
            let straggles = self
                .completion_straggler
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_deref()
                == Some(plan.record.path.as_str());
            if straggles {
                tokio::time::sleep(std::time::Duration::from_secs(600)).await;
            }
        }
        crate::receive_diag::mark(crate::receive_diag::Stage::PreCommit);
        self.commit_verified_object(plan, verified).await
    }

    /// Stage 1: fingerprint the target before any block is requested.
    fn observe_target(
        &self,
        plan: &MaterializationPlan<'_>,
    ) -> Result<ObservedTarget, PeerSessionError> {
        let MaterializationPlan { group_id, record, origin_device_id, .. } = *plan;
        // Snapshot this path's on-disk state before asking for blocks, so
        // it can be re-checked on re-entry, right before this
        // materialization writes anything.
        //
        // This is the one observation that has to cross the request
        // boundary, and the reason is that re-reading cannot recover it.
        // `path_lock` is held for this whole call, but it only serializes
        // *this device's own* SyncState-mediated writes -- it is not, and
        // cannot be, an OS file lock, so a genuine local edit (a real
        // user's editor, or this scenario's `solo-write`) can still land
        // directly on disk while the session is fetching. Confirmed,
        // reproduced: a local write that races into exactly this window is
        // silently clobbered by this materialization's own later rename,
        // then permanently invisible to every later check --
        // `flush_pending_local_change_before_reconcile` (already run by
        // every caller before taking `path_lock`) only catches an edit
        // that was *already* pending at that moment; it cannot see one
        // that has not happened yet, and calling it again from inside this
        // locked call would deadlock (see its own doc comment). Read
        // fresh, the fingerprint would simply describe the racing write as
        // if it had always been there; only a comparison against what was
        // on disk before the request went out can tell the two apart.
        let out_path_for_race_check = self.local_file_path(group_id, &record.path)?;
        let pre_fetch_disk_state = disk_race_fingerprint(&out_path_for_race_check);
        // The second fork: by the time an incoming change is about to be
        // written, are this device's own local bytes still on disk? If a
        // local write is lost despite the flush guard running, the length
        // here says whether the guard looked too late (bytes already
        // replaced) or the guard looked in the wrong place (bytes still
        // present and about to be overwritten by this call).
        yadorilink_peer_session::dst_trace(&record.path, || {
            format!(
                "materialize about to write on {} (origin={}): on_disk_len={:?} incoming_len={}",
                self.local_device_id,
                origin_device_id,
                pre_fetch_disk_state.as_ref().map(|(len, ..)| *len),
                record.size
            )
        });
        Ok(ObservedTarget { race_check_path: out_path_for_race_check, pre_fetch_disk_state })
    }

    /// Stage 2: ask local storage whether this record's content is here, and
    /// hand the session a block requirement if it is not and the session has
    /// not yet had its attempt.
    fn locate_content(
        &self,
        plan: &MaterializationPlan<'_>,
        observed: ObservedTarget,
    ) -> Result<ContentLocation, PeerSessionError> {
        let MaterializationPlan { group_id, payload, record, satisfied, .. } = *plan;
        let ObservedTarget { race_check_path, pre_fetch_disk_state } = observed;
        // Is this record's content already on this device? Two local
        // questions, both of them the same ones `ensure_blocks_present`
        // itself asks before it fetches anything: are the bytes in the
        // block store, and has this group independently obtained them.
        // A physical hit belonging only to another group is not this
        // group's to use, so both must hold for every block.
        let missing_blocks = self.blocks_missing_locally(group_id, record)?;
        if missing_blocks && satisfied.is_none() {
            // Stop here. Which peer to ask, how many blocks at once, what
            // a `DontHave` means, how long to wait and what to do with a
            // transport error are all the session's business, and none of
            // them belong on this side of the boundary.
            return Ok(ContentLocation::NeedBlocks(BlockRequirement {
                path: record.path.clone(),
                version_hash: payload.version().version_hash,
                record: record.clone(),
                observed_disk: pre_fetch_disk_state,
            }));
        }
        // `satisfied` says the session had its bounded attempt at the
        // block lane. Whether that attempt worked is answered the same
        // way it is answered on a first pass: by asking local storage.
        // If content is still absent the obligation stays unsettled --
        // recorded as a retriable placeholder below, re-driven by an
        // explicit wake. Nothing here polls.
        let all_present = !missing_blocks;
        Ok(ContentLocation::Located(LocatedContent { race_check_path, all_present }))
    }

    /// Stage 3: revalidate the target right before anything is written.
    /// `None` declines this pass for retry.
    fn revalidate_target(
        &self,
        plan: &MaterializationPlan<'_>,
        located: LocatedContent,
    ) -> Result<Option<RevalidatedTarget>, PeerSessionError> {
        let MaterializationPlan { group_id, record, satisfied, .. } = *plan;
        let LocatedContent { race_check_path: out_path_for_race_check, all_present } = located;
        // Re-check the snapshot taken before the blocks were requested: if
        // this path's on-disk state changed while the session was
        // fetching, something wrote to it independently of this
        // materialization. Proceeding would silently overwrite that write
        // with no error, no conflict copy, and (once the watcher's own
        // flush eventually runs against the post-overwrite bytes, which
        // now match exactly what this materialization is about to commit)
        // no trace at all -- the confirmed mechanism behind a
        // materialize-vs-local-edit race this check exists to close.
        // Decline instead: `RetryRequired` sends this back through the
        // ordinary reconcile retry path, by which point `path_lock` has
        // been released, the racing write has committed its own change,
        // and the next resolution correctly sees both as concurrent.
        //
        // Only meaningful on a re-entry that a fetch stands behind. On a
        // first pass the fingerprint was taken moments ago by this same
        // call with the lock already held, so there is no window for it to
        // describe and nothing to compare it against.
        let post_fetch_disk_state = disk_race_fingerprint(&out_path_for_race_check);
        if satisfied.is_some_and(|r| post_fetch_disk_state != r.observed_disk) {
            tracing::info!(
                group_id,
                path = %record.path,
                "declining a materialize whose target changed on disk while this device \
                 fetched blocks from a peer; leaving it for retry so the racing local edit \
                 is not silently overwritten"
            );
            return Ok(None);
        }
        // LAST LINE OF DEFENCE BEFORE THE BYTES ARE GONE.
        //
        // Everything upstream of here tries to get a local edit
        // *authored* before an incoming change lands on the same path:
        // `flush_pending_local_change_before_reconcile` force-flushes the
        // debounce accumulator, `capture_undiscovered_local_change` falls
        // back to reading the path off disk, and the metadata CAS above
        // catches a write that slips in during the block fetch. Each is
        // scheduling-dependent, and measurably none of them closes the
        // case where the write lands on disk *before* this materialize
        // started and its watcher event has not been processed yet.
        //
        // This check is not scheduling-dependent: it asks the bytes
        // themselves. If the file on disk no longer matches the content
        // this device has indexed for it, someone wrote to it outside the
        // index -- an unauthored local edit -- and overwriting it destroys
        // it permanently. Permanently is not hyperbole: after the rename
        // the edit exists nowhere (not on disk, not in the block store),
        // and the watcher's own flush then chunks the *remote* bytes,
        // finds them equal to what was just indexed, and suppresses the
        // whole thing as a self-echo (`local_change.rs`'s block-equality
        // check). No error, no conflict copy, no trace. That is why no
        // fix on the flush side can work -- there is nothing left to
        // recover by then.
        //
        // Compare against `local_row` (what this device believes is on
        // disk right now), NOT `record` (the incoming content this call
        // is about to install).
        //
        // Reproduced and traced on the retired network-fault scenario seed
        // 3298840609: a solo write landed while the previous round's race
        // winner was still materialising over it, was overwritten before
        // it could author, and left the harness reading back the previous
        // round's authored version -- two ops sharing one version, which
        // `oracle::supersedes` refuses to treat as superseding, surfacing
        // as `[NoLoss]`.
        //
        // Cost: one content hash of the destination (two for an unproven
        // `Remote` row), and only for a path that already exists as a
        // regular file. Skipped for an untouched placeholder and for
        // `Hydrating`/`Evicting` rows, whose whole point is to disagree
        // with their file, and for tombstones. Deliberately paid: the
        // alternative is silently destroying user data.
        //
        // A narrow TOCTOU window remains between this hash and the rename
        // below -- there is no portable "rename only if the destination
        // still hashes to X". The metadata CAS above is kept precisely as
        // a second, cheaper net across that window. Closing it fully
        // would mean preserving the displaced bytes before replacing them
        // (quarantine-on-divergence), which changes conflict semantics
        // and needs its own crash-recovery design; noted, not attempted.
        //
        // A path that no longer exists at all is NOT the same finding as
        // one whose bytes diverge, and must not be declined the same
        // way. A missing `out_path_for_race_check` is not proof anyone
        // wrote an unauthored edit -- it is equally consistent with this
        // path's *parent* having been renamed or removed by a local
        // operation whose watcher event has not reached this device's
        // local pipeline yet (confirmed, reproduced:
        // `dst_directory_move_edit_race.rs`'s `CbBeforeDirDispatch`
        // ordering hung forever on exactly this call site treating
        // `Absent` the same as `PresentButDifferent`, permanently
        // declining a legitimate fast-forward materialize with nothing
        // left to ever change the outcome). Declining forever on an
        // absent path is safe to avoid here specifically because
        // `flush_pending_local_change_before_reconcile` (called on
        // `record.path` above, before `path_lock` was even taken) has
        // already force-flushed any debounce entry keyed on this exact
        // path -- so a genuine, still-unflushed single-file local
        // deletion of THIS path cannot be what produced the absence; the
        // only thing an exact-path flush structurally cannot discover
        // and dispatch first is an ancestor-directory-level event, which
        // is exactly the case this guard must let through. Resurrecting
        // a file whose deletion truly wasn't caught by any of that is
        // still recoverable, unlike destroying divergent bytes: the
        // local pipeline's own Removed-event handling re-stats before
        // dispatch and will still author the deletion once it runs.
        //
        // Which rows this covers -- including a row with no blocks, and a
        // `Remote` row this device never wrote a placeholder for -- is
        // `disk_holds_uncaptured_local_bytes`'s own doc. Both were once
        // skipped, and both are how a file still being written (a `git
        // clone`'s pack) got this device's own older version of it written
        // back over it.
        if self.disk_holds_uncaptured_local_bytes(
            group_id,
            &record.path,
            &out_path_for_race_check,
            Some(&record.blocks),
        )? {
            tracing::info!(
                group_id,
                path = %record.path,
                "declining a materialize whose target no longer matches this \
                 device's indexed content; an unauthored local edit is on disk \
                 and overwriting it would destroy it silently"
            );
            yadorilink_peer_session::dst_trace(&record.path, || {
                format!(
                    "materialize DECLINED on {}: on-disk bytes diverge from \
                     indexed content -- unauthored local edit protected",
                    self.local_device_id
                )
            });
            return Ok(None);
        }
        let baseline = TargetBaseline {
            fingerprint: disk_race_fingerprint(&out_path_for_race_check),
            was_dirty: self.state.is_path_dirty(group_id, &record.path)?,
        };
        Ok(Some(RevalidatedTarget { all_present, baseline }))
    }

    /// Stage 3b, when not every block is present: record the version
    /// without its content and retry.
    fn write_incomplete_content_placeholder(
        &self,
        plan: &MaterializationPlan<'_>,
        _target: RevalidatedTarget,
    ) -> Result<LocalMaterializeOutcome, PeerSessionError> {
        let MaterializationPlan { group_id, record, permit: root_commit_permit, .. } = *plan;
        // Same journaled-write seam the sibling "demoted after a failed
        // reconstruct" arm below uses: the row is committed and the path
        // settled in separate steps, and a crash/restart in between must not
        // leave an indexed, not-deleted row with no protection at all.
        let out_path = self.local_file_path(group_id, &record.path)?;
        let object_present = std::fs::symlink_metadata(&out_path).is_ok();
        let intent_guard = self.state.open_remote_write(
            group_id,
            record,
            plan.origin_device_id,
            plan.authoring,
            &plan.columns,
            &|| self.root_lease_for(group_id),
            object_present,
            root_commit_permit,
        )?;
        // Bump before settling the path, same as any other mutator, so any
        // stale exact-object proof for this path is invalidated even though
        // this attempt itself never publishes one (it returns
        // `RetryRequired`, carrying no evidence).
        let provider_deferred =
            self.place_provider_object(plan, &out_path, object_present, "eager_remote_record")?;
        // Clear the intent unless Windows deferred the object to
        // `cfapi-host.exe`: nothing is on disk yet in that case, so the
        // intent must stay open -- this call returns `RetryRequired` below
        // regardless, so a later retry naturally re-examines this path.
        //
        // An older object standing under the newer row is not touched here
        // (no fence bump, no write), so a proof it had stays valid and the
        // untouched-proven exclusion keeps it out of repair's reach; the
        // intent only guards the transient row commit above. An object with
        // no standing proof keeps the intent, so repair recovers it rather
        // than authoring it over the newer row.
        if !provider_deferred
            && (!object_present
                || self.state.disk_is_untouched_proven_write_at(
                    group_id,
                    &record.path,
                    &out_path,
                )?)
        {
            intent_guard.clear()?;
        }
        // Eager wanted real content but not every block was available --
        // this is a retriable `Remote` row, not a settled outcome (the
        // confirmed bug this type exists to close: see `MaterializeResult`'s
        // own doc comment).
        Ok(MaterializeResult::RetryRequired.into())
    }

    /// Stage 4: commit the row under an open intent, with the fence bump for
    /// the content write that follows, in one transaction.
    async fn begin_content_write<'p>(
        &'p self,
        plan: &'p MaterializationPlan<'p>,
        target: RevalidatedTarget,
    ) -> Result<PendingContentWrite<'p>, PeerSessionError> {
        let MaterializationPlan { group_id, payload, record, permit: root_commit_permit, .. } =
            *plan;
        // Receiver-side phase marker: every block this file's
        // record lists is now present (already-local, or freshly
        // fetched-and-committed by `ensure_blocks_present` above) in
        // this device's own block store -- the eager-materialize
        // path's own completeness check, the counterpart of
        // `hydration.rs`'s identically-tagged `T_recv_all_blocks_
        // available` on the on-demand-sync path.
        tracing::debug!(
            "phase T_recv_all_blocks_available: every block this file needs is now local"
        );
        // Open the single sanctioned materialization-intent seam BEFORE
        // committing the brand-new row below. This branch deliberately
        // stamps the row `Present` optimistically, before the temp-
        // write-then-rename even begins (see the explicit stamp right
        // after `persist_row_under_fresh_operation` below -- `upsert_file_
        // with_origin` itself no longer defaults a fresh row to
        // `Present`; the schema's own default is `Remote` as of
        // v25, see `SCHEMA_VERSION`'s doc comment), and that commit is
        // durable (`PRAGMA synchronous = FULL`) — so a crash *after* it
        // but before the temp-write-then-rename lands would otherwise leave
        // a `Present` row with no file on disk, its blocks present, and no
        // intent. Startup/periodic repair reads exactly that state as an
        // offline deletion and tombstones the path, destroying a
        // just-received file group-wide. `MaterializationIntentGuard::open`
        // writes a durable intent first — the same seam
        // `reconstruct_file_journaled` uses for repair's own writes — so
        // repair instead sees the intent and reconstructs from the
        // locally-present blocks. The guard is cleared the instant the
        // rename is durable (below) or when this write is demoted to a
        // `Remote`; an early `?` return on a failed write drops it
        // without clearing, leaving the intent for repair.
        //
        // The owner operation below opens that intent, commits the row
        // under it, stamps the row with the in-flight state -- explicitly
        // NOT `Present`: the intent is what makes the row-before-file
        // ordering safe across a crash, not what makes the exact claim
        // true, and the bytes are still nowhere at this point (the batched
        // receive this branch was modelled on moved to the in-flight state
        // for the same reason, and left this one behind) -- clears any
        // hazard hold, and bumps the fence for the content write below
        // (the retry loop that follows is all one logical write attempt, so
        // one bump covers it -- a bump is safe-but-pessimistic, never a
        // lock: see the tombstone-delete branch for the identical
        // reasoning), all in ONE transaction that commits before anything
        // below touches the disk. The bumped value is kept so the eventual
        // `Settled` evidence CASes on the value this specific write
        // invalidated the path's prior proof under, not a value re-read
        // later that some other mutator could have already advanced past.
        //
        // In a window run the transaction is queued with the run's other files
        // and committed with them (`Participant::submit_open`): this future
        // keeps its path lock, the lane's operation and the row's own
        // operation until the outcome has come back, and writes no byte
        // before it has.
        let participant = super::super::completion_window::current_for_open();
        crate::receive_diag::mark(crate::receive_diag::Stage::ReadyToOpen);
        let (content_write_mutation_generation, intent_guard) = self
            .state
            .open_content_write_via(
                group_id,
                record,
                plan.origin_device_id,
                plan.authoring,
                &plan.columns,
                &|| self.root_lease_for(group_id),
                root_commit_permit,
                |open| async {
                    match &participant {
                        Some(participant) => participant.submit_open(&self.state, open).await,
                        None => self.state.commit_open_single(open).await,
                    }
                },
            )
            .await?;
        crate::receive_diag::mark(crate::receive_diag::Stage::Opened);
        let out_path = self.local_file_path(group_id, &record.path)?;
        // defense-in-depth: `is_safe_relative_path` (in
        // `reconcile_files`) already blocks `..`/absolute components,
        // but a *symlink* at an intermediate path component is
        // followed by the plain `create`/`rename` calls inside
        // `reconstruct_file`, which could otherwise land the write
        // outside `group_id`'s sync root. See `verify_write_target_
        // within_root`'s doc comment for what this does and does not
        // close.
        self.verify_write_target(group_id, &out_path)?;
        // Preflight before the
        // temp-then-rename write below begins — see
        // `preflight_disk_headroom`'s doc comment.
        let headroom = Arc::new(self.preflight_disk_headroom(group_id, &out_path, record.size)?);
        // Off the async runtime -- see `reconstruct_file_off_
        // runtime`'s own doc comment for the failure mode this closes
        // (large-file reconstruction blocking this process's tokio
        // worker pool long enough to starve this same peer's own
        // channel actor). This retry loop is the eager-fetch path's
        // OWN reconstruct call (the same shared assembly the interactive
        // hydration uses), so it gets the identical treatment here too.
        //
        // Receiver-side phase marker: about to begin
        // reconstructing the real file from CAS blocks -- the
        // eager-materialize path's counterpart of `hydration.rs`'s
        // identically-tagged `T_recv_materialize_start` on the
        // on-demand-sync path. Fired once even though a transient
        // read failure below can retry the reconstruct attempt itself
        // -- that retry re-reads already-local, already-verified
        // blocks, not a second "begins receiving" event.
        tracing::debug!(
            "phase T_recv_materialize_start: begins reconstructing the real file from CAS blocks"
        );
        // The payload's own version -- what these bytes ARE. Reading
        // it from the row, even before the write, asked about the row
        // instead: a supersession moves the row's version while the
        // payload does not move at all, and every check downstream then agreed with itself
        // while the bytes disagreed.
        let written_version = payload.version().clone();
        Ok(PendingContentWrite {
            intent_guard,
            out_path,
            written_version,
            mutation_generation: content_write_mutation_generation,
            baseline: target.baseline,
            headroom,
        })
    }

    /// Stage 5: reconstruct the payload's bytes into place,
    /// retrying a transient failure, and demote to a retriable placeholder
    /// if it never succeeds.
    async fn reconstruct_content(
        &self,
        plan: &MaterializationPlan<'_>,
        pending: PendingContentWrite<'_>,
    ) -> Result<Reconstruction, PeerSessionError> {
        let MaterializationPlan { group_id, record, permit: root_commit_permit, .. } = *plan;
        let PendingContentWrite {
            intent_guard,
            out_path,
            written_version,
            mutation_generation: content_write_mutation_generation,
            baseline,
            headroom,
        } = pending;
        // Guard the one-shot reconstruct. `reconstruct_file` reads every
        // block back through `store.get` mid-loop, so a *transient* block-
        // store read error (an EIO) fails the whole assembly *after* the
        // live row was already committed at the top of this branch — which,
        // left unhandled, orphans the temp file and leaves a live+Hydrated
        // row with no file on disk (a losing conflict copy would then be
        // permanently lost, since `repair_interrupted_materializations` /
        // the reconcile re-drive do not reliably revisit a same-device
        // conflict copy the peer never echoes back). The bytes are always
        // durably present in *this* device's own block store by now (the
        // eager fetch above stored them, or — for a losing conflict copy —
        // they are this device's own prior edit, per this function's
        // "content is always already present" invariant), so the correct
        // response to a transient read error is to retry the assembly in
        // place: a retry re-reads those same content-addressed blocks on a
        // later, non-faulting read. Retry a bounded number of times, then
        // fall back to the same retriable `Remote` the `all_present ==
        // false` branch uses (so a genuinely-stuck read still never leaves a
        // fileless Hydrated row).
        const MAX_RECONSTRUCT_RETRIES: u32 = 20;
        const RECONSTRUCT_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);
        let mut recon = self.assemble_and_persist(&out_path, plan, &baseline, &headroom).await;
        let mut attempts = 0u32;
        while recon.is_err() && attempts < MAX_RECONSTRUCT_RETRIES {
            attempts += 1;
            // Short backoff before re-reading the already-present blocks.
            // Under the deterministic simulator this advances virtual time
            // (letting any interfering condition clear) at no real cost.
            tokio::time::sleep(RECONSTRUCT_RETRY_BACKOFF).await;
            // Re-verify root identity before EVERY retry, not just the
            // single check before the first attempt above: up to
            // `MAX_RECONSTRUCT_RETRIES * RECONSTRUCT_RETRY_BACKOFF`
            // (~1s) elapses across this loop, during which the same
            // unmount-and-replace window `verify_write_target`'s own
            // re-check exists to close could still open between two
            // retries. A verify failure here surfaces as a real error
            // (not a demotion to `Remote`) since a replaced root
            // is not a transient, retriable condition.
            self.verify_write_target(group_id, &out_path)?;
            recon = self.assemble_and_persist(&out_path, plan, &baseline, &headroom).await;
        }
        let deferred_tmp = match &recon {
            Ok(AssembleOutcome::LocalEdit) => {
                // The intent stays open and nothing is proven, as when the
                // written object fails verification: the path is re-driven
                // once capture has taken the edit.
                drop(intent_guard);
                return Ok(Reconstruction::LocalEditDuringAssembly);
            }
            Ok(AssembleOutcome::Written(tmp)) => tmp.clone(),
            Err(_) => None,
        };
        if let Err(e) = recon {
            tracing::warn!(
                group_id,
                path = %record.path,
                error = %e,
                attempts,
                "reconstruct after eager fetch still failing; recording the version without \
                 its content for a retry"
            );
            // The failed write publishes by rename, so the path still holds
            // whatever it held before: an older version's bytes stay under
            // the newer row (`Present`), an empty path stays empty
            // (`Remote`).
            let object_present = std::fs::symlink_metadata(&out_path).is_ok();
            self.state.set_materialization_state(
                group_id,
                &record.path,
                if object_present {
                    MaterializationState::Present
                } else {
                    MaterializationState::Remote
                },
                root_commit_permit,
            )?;
            // A different mutation than the failed reconstruct above (the
            // row now names no content) -- its own bump, same reasoning as
            // the `!all_present` branch.
            let provider_deferred = self.place_provider_object(
                plan,
                &out_path,
                object_present,
                "eager_reconstruct_failed_record",
            )?;
            // Clear the intent unless Windows deferred the object to
            // `cfapi-host.exe` (nothing is on disk yet, so it must stay
            // open), or an older object still sits under the newer row. In
            // the latter case the fence bump at the start of this write
            // already invalidated that object's proof, so startup could not
            // tell "our untouched older version" from "an offline edit" and
            // would author it over the peer's newer version. The open intent
            // keeps it an interrupted write: repair quarantines the bytes
            // and rebuilds the row's version from the local blocks.
            if !provider_deferred && !object_present {
                intent_guard.clear()?;
            }
            // Reconstruct never actually succeeded despite the blocks being
            // fetched -- a retriable `Remote` row, not a settled outcome
            // (same reasoning as the `!all_present` branch above).
            return Ok(Reconstruction::DemotedToPlaceholder);
        }
        // Captured immediately
        // after this device's own successful reconstruct -- see
        // `MaterializationStateRepository::record_materialized_
        // fingerprint`'s own doc comment for what the daemon's
        // already-`Present` fast path (`hydration.rs::hydrate_inner`)
        // The temp-write-then-rename completed durably — clear the intent
        // NOW, before the post-write metadata touch below. Clearing only
        // after `apply_unix_mode` would leak the intent whenever reading or
        // applying the exec bit errored (a real `chmod` on POSIX) even though
        // the file is durably on disk and `Present`; a later genuine offline
        // delete of that path would then read `missing + intent present` and
        // wrongly resurrect it from the blocks. This is exactly
        // `reconstruct_file_journaled`'s "clear right after the rename"
        // ordering.
        // The intent is cleared by the commit below, not here:
        // clearing first leaves a window in which the bytes exist,
        // nothing records that a write was in flight, and no proof has
        // landed. Dropping the guard unclear is inert -- it has no
        // `Drop` behaviour of its own, and the commit owns the clear.
        drop(intent_guard);
        Ok(Reconstruction::Written(Box::new(WrittenObject {
            deferred_tmp,
            out_path,
            written_version,
            mutation_generation: content_write_mutation_generation,
        })))
    }

    /// Assembles the payload's bytes into a temp file beside `out_path` and
    /// publishes it by rename.
    ///
    /// The local-edit guard in `revalidate_target` ran before the assembly,
    /// which reads every block and fsyncs the result -- time proportional to
    /// the file. A user save landing in that time would be renamed over, and
    /// the watcher would then find disk equal to the index and drop the edit
    /// as an echo of this write. So the target is looked at again right
    /// before the rename, and the write is abandoned if it moved.
    async fn assemble_and_persist(
        &self,
        out_path: &std::path::Path,
        plan: &MaterializationPlan<'_>,
        baseline: &TargetBaseline,
        headroom: &Arc<super::super::reconcile::HeadroomReservation>,
    ) -> Result<AssembleOutcome, PeerSessionError> {
        let MaterializationPlan { group_id, record, permit: root_commit_permit, .. } = *plan;
        // A received file's content is already durable in the block store. When
        // the run's window flushes its files in one batch, neither the file nor
        // its directory is flushed here.
        let durability = if super::super::completion_window::current()
            .is_some_and(|window| window.deferred_flush_mode().is_some())
        {
            yadorilink_local_storage::Durability::DeferredToBatch
        } else {
            yadorilink_local_storage::Durability::Full
        };
        let tmp_path = reconstruct_file_to_temp_off_runtime_durable(
            self.store.clone(),
            out_path,
            &record.blocks,
            record.mtime_unix_nanos,
            Some(headroom.clone()),
            Arc::new(self.state.temp_ledger(group_id)),
            None,
            durability,
        )
        .await?;
        crate::receive_diag::mark(crate::receive_diag::Stage::TempWritten);
        #[cfg(any(test, feature = "test-support"))]
        {
            let hook = self
                .between_assemble_and_persist_hook
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            if let Some(hook) = hook {
                hook(out_path);
            }
            let probe =
                self.overlap_probe.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
            if let Some(probe) = probe {
                probe.pass(crate::local_convergence::ProbeSeam::BeforeRename, &record.path).await;
            }
        }
        let fingerprint = disk_race_fingerprint(out_path);
        let moved = fingerprint != baseline.fingerprint
            || (!baseline.was_dirty && self.state.is_path_dirty(group_id, &record.path)?);
        if moved {
            yadorilink_local_storage::discard_temp_file(
                &tmp_path,
                &self.state.temp_ledger(group_id),
            );
            self.state.journal_uncaptured_local_edit(
                group_id,
                &record.path,
                fingerprint.is_some(),
                root_commit_permit,
            )?;
            tracing::info!(
                group_id,
                path = %record.path,
                "the target changed on disk while its content was being assembled; leaving \
                 the local write in place and publishing nothing"
            );
            return Ok(AssembleOutcome::LocalEdit);
        }
        // The assembly above runs for time proportional to the file, long
        // enough for the volume under the root to go away and leave a bare
        // mountpoint. Prove the root's identity again immediately before the
        // rename, so the file is never published onto the parent filesystem
        // and no Present row follows; the open intent re-drives the write.
        if let Err(error) = self.verify_write_target(group_id, out_path) {
            yadorilink_local_storage::discard_temp_file(
                &tmp_path,
                &self.state.temp_ledger(group_id),
            );
            return Err(error);
        }
        let deferred_tmp = (durability == yadorilink_local_storage::Durability::DeferredToBatch)
            .then(|| tmp_path.clone());
        let persisted_tmp = tmp_path.clone();
        persist_reconstructed_file_off_runtime(
            tmp_path,
            out_path,
            Arc::new(self.state.temp_ledger(group_id)),
            durability,
        )
        .await?;
        crate::receive_diag::mark(crate::receive_diag::Stage::Renamed);
        // The file is in place unflushed: its flush is owed to the window's barrier
        // from here on, whatever the later steps do. Only a published close marks
        // the intent for the barrier to clear.
        if deferred_tmp.is_some() {
            if let Some(window) = super::super::completion_window::current() {
                window.note_flush_pending(super::super::completion_window::PendingFlush {
                    group_id: group_id.to_owned(),
                    path: record.path.clone(),
                    out_path: out_path.to_path_buf(),
                    object: yadorilink_local_storage::object_key(out_path),
                    root: self.sync_root(group_id)?,
                    tmp_path: persisted_tmp,
                    ledger: self.state.temp_ledger(group_id),
                    marked_under: None,
                });
            }
        }
        Ok(AssembleOutcome::Written(deferred_tmp))
    }

    /// Closes a write whose file the user removed after the bytes were placed
    /// and before the write was closed, whichever step noticed. `None` when the
    /// file is not gone, so the caller's own handling stands.
    ///
    /// This pass holds the path lock, so a file that is gone now was removed by
    /// the user. Leaving the row in flight would have a removal read as the
    /// daemon's own, drop the delete, and let the retry write the file back.
    /// The write itself did complete: it is closed without an identity (which
    /// vouches for nothing about the disk now), and the path is journaled
    /// first so the delete survives a crash. Local capture then authors the
    /// delete of a `Present` row that has a proof to parent it on.
    fn settle_write_removed_by_user(
        &self,
        plan: &MaterializationPlan<'_>,
        landed: &LandedWrite,
    ) -> Result<Option<LocalMaterializeOutcome>, PeerSessionError> {
        let absent = matches!(
            landed.out_path.symlink_metadata(),
            Err(ref error) if error.kind() == std::io::ErrorKind::NotFound
        );
        if !absent {
            return Ok(None);
        }
        let MaterializationPlan { group_id, record, permit, claim, .. } = *plan;
        self.state.journal_uncaptured_local_edit(group_id, &record.path, false, permit)?;
        let closed = self.state.close_content_write(
            group_id,
            &record.path,
            &yadorilink_sync_sqlite::exact_materialized_commit::ExactMaterializedState::Object {
                kind: RecordKind::File,
                version: landed.version,
                identity: Box::new(None),
            },
            landed.mutation_generation,
            yadorilink_sync_sqlite::exact_materialized_commit::ExpectedAuthoring {
                state: yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
                expected_version: Some(&landed.version),
            },
            claim.map(|claim| claim.token()),
            permit,
        )?;
        let crate::replica_coordinator::ContentWriteClose::Published { obligation } = closed else {
            return Ok(None);
        };
        if let (Some(claim), Some(_)) = (claim, obligation) {
            claim.record_decided(&record.path);
        }
        tracing::info!(
            group_id,
            path = %record.path,
            "the received file was deleted before its write was closed; closed the write and \
             journaled the delete for local capture"
        );
        Ok(Some(
            MaterializeResult::Settled(SettlementEvidence::ExactObject {
                kind: RecordKind::File,
                version: landed.version,
                identity: Box::new(None),
                mutation_generation: landed.mutation_generation,
            })
            .into(),
        ))
    }

    /// Stage 6: apply this payload's mode and xattrs to the written object.
    fn apply_written_metadata(
        &self,
        plan: &MaterializationPlan<'_>,
        written: WrittenObject,
    ) -> Result<AppliedObject, PeerSessionError> {
        // Apply the owner-executable bit and xattrs THIS PAYLOAD
        // specifies (POSIX: real chmod; no-op, no error, on Windows).
        //
        // From the payload, not the row -- the sharpest instance of
        // the split this commit closes. The content above was
        // reconstructed from the payload's blocks and the proof
        // below names the payload's version, but these two lines used
        // to read the row, so a supersession during the (arbitrarily
        // long) fetch and reconstruct produced exactly:
        //     content bytes    <- payload V1
        //     mode/xattrs      <- row V2
        //     proof version    <- payload V1
        // and V1's `version_hash` bakes in V1's mode and xattrs. The
        // `require_replicated_xattrs_exact` gate inside
        // `exact_object_evidence_after_write` compares disk against
        // the version, so this was a false `ExactObject` claim that
        // the exactness check itself could not catch -- it was
        // verifying against the same row that supplied the wrong
        // values.
        let xattrs = plan.apply_payload_metadata(&written.out_path)?;
        Ok(AppliedObject { written, xattrs })
    }

    /// Stage 7: verify disk holds the exact object the payload names.
    /// `None` when the path has moved on to a version these bytes are not.
    async fn verify_written_object(
        &self,
        plan: &MaterializationPlan<'_>,
        applied: AppliedObject,
    ) -> Result<Option<VerifiedObject>, PeerSessionError> {
        let AppliedObject { written, xattrs } = applied;
        #[cfg(any(test, feature = "test-support"))]
        {
            let hook = self
                .after_write_before_proof_hook
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            if let Some(hook) = hook {
                hook(&written.out_path);
            }
        }
        let Some(evidence) = self.exact_object_evidence_after_write(
            plan.group_id,
            &plan.record.path,
            RecordKind::File,
            &written.written_version,
            written.mutation_generation,
            &xattrs,
        )?
        else {
            return Ok(None);
        };
        // The evidence's identity is observed from whatever is on disk, so a
        // user save that landed between the rename and that observation
        // would be baked into it as if the daemon had written it, and the
        // commit-time identity check would then pass. Bind the proof to the
        // bytes written: they are compared AFTER the identity was taken, so
        // anything later changes the identity and anything earlier fails
        // here. A mismatch publishes nothing and journals the path, so
        // capture authors the edit.
        let (check_path, check_blocks) = (written.out_path.clone(), plan.record.blocks.clone());
        let bytes_match = tokio::task::spawn_blocking(move || {
            yadorilink_local_storage::disk_bytes_match_indexed_blocks(&check_path, &check_blocks)
                .unwrap_or(false)
        })
        .await
        .map_err(|e| PeerSessionError::CorruptState(format!("proof content check failed: {e}")))?;
        if !bytes_match {
            self.state.journal_uncaptured_local_edit(
                plan.group_id,
                &plan.record.path,
                true,
                plan.permit,
            )?;
            tracing::info!(
                group_id = plan.group_id,
                path = %plan.record.path,
                "the file changed on disk between the write and its proof; leaving the local \
                 write in place and publishing nothing"
            );
            return Ok(None);
        }
        Ok(Some(VerifiedObject { written, evidence }))
    }

    /// Stage 8: commit the proof, the `Present` stamp, the intent clear and
    /// the claimed obligation's completion under the fence this write
    /// bumped, and settle with the evidence.
    async fn commit_verified_object(
        &self,
        plan: &MaterializationPlan<'_>,
        verified: VerifiedObject,
    ) -> Result<LocalMaterializeOutcome, PeerSessionError> {
        let MaterializationPlan { group_id, record, permit: root_commit_permit, .. } = *plan;
        let VerifiedObject {
            written:
                WrittenObject {
                    deferred_tmp,
                    out_path,
                    written_version,
                    mutation_generation: content_write_mutation_generation,
                },
            evidence,
        } = verified;
        // The identity the exact verification vouched for, not a fresh
        // observation: an overwrite after that verification must not become
        // the baseline the commit-time check compares against.
        let verified_identity = match &evidence {
            SettlementEvidence::ExactObject { identity, .. } => **identity,
            _ => None,
        };
        let exact_state =
            yadorilink_sync_sqlite::exact_materialized_commit::ExactMaterializedState::Object {
                kind: RecordKind::File,
                version: written_version.version_hash,
                identity: Box::new(verified_identity),
            };
        let claim = plan.claim.map(|claim| claim.token());
        let closed = match super::super::completion_window::current() {
            // Queued with the run's other files and committed with them. This
            // future keeps its path lock, its root operation and its permit
            // until the outcome comes back: until then the row is `Hydrating`
            // over the new bytes, and only the lock keeps a capture from
            // authoring them (or a newer edit of them) as a local version.
            Some(window) => {
                window
                    .submit(
                        &self.state,
                        crate::replica_coordinator::ContentWriteCloseItem {
                            group_id: group_id.to_owned(),
                            path: record.path.clone(),
                            exact_state,
                            expected_mutation_generation: content_write_mutation_generation,
                            expected_version: written_version.version_hash,
                            claim,
                            root_check: root_commit_permit.owned_check(),
                            intent: match &deferred_tmp {
                                Some(_) => {
                                    yadorilink_sync_sqlite::IntentDisposition::FlushPending {
                                        mutation_generation: content_write_mutation_generation,
                                    }
                                }
                                None => yadorilink_sync_sqlite::IntentDisposition::Clear,
                            },
                            disk_check: Box::new({
                                let (path, out_path, blocks) =
                                    (record.path.clone(), out_path.clone(), record.blocks.clone());
                                move || {
                                    disk_still_the_verified_object(
                                        &path,
                                        &out_path,
                                        &blocks,
                                        verified_identity,
                                    )
                                }
                            }),
                        },
                    )
                    .await?
            }
            None => self.state.close_content_write(
                group_id,
                &record.path,
                &exact_state,
                content_write_mutation_generation,
                yadorilink_sync_sqlite::exact_materialized_commit::ExpectedAuthoring {
                    state: yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
                    expected_version: Some(&written_version.version_hash),
                },
                claim,
                root_commit_permit,
            )?,
        };
        if let (Some(_), Some(window)) = (&deferred_tmp, super::super::completion_window::current())
        {
            if matches!(closed, crate::replica_coordinator::ContentWriteClose::Published { .. }) {
                window.mark_flush_published(&out_path, content_write_mutation_generation);
            }
        }
        match closed {
            crate::replica_coordinator::ContentWriteClose::Refused => {
                let landed = LandedWrite {
                    out_path,
                    version: written_version.version_hash,
                    mutation_generation: content_write_mutation_generation,
                };
                match self.settle_write_removed_by_user(plan, &landed)? {
                    Some(settled) => Ok(settled),
                    None => Ok(MaterializeResult::RetryRequired.into()),
                }
            }
            crate::replica_coordinator::ContentWriteClose::Published { obligation } => {
                if let (Some(claim), Some(_)) = (plan.claim, obligation) {
                    claim.record_decided(&record.path);
                }
                yadorilink_fs_platform::join_timeline::mark(
                    &self.local_device_id,
                    group_id,
                    yadorilink_fs_platform::join_timeline::Milestone::FirstFileCommitted,
                );
                Ok(MaterializeResult::Settled(evidence).into())
            }
        }
    }
}

/// Whether `out_path` is still the object the exact verification vouched for
/// (`verified`, the identity recorded with that evidence): a regular file
/// whose identity, with the size and the modification and change times it
/// carries, is that one. A direct write by the user changes it without moving
/// any fence, and the proof the batch is about to publish would no longer be
/// true. A missing verified identity or an unavailable observation refuses.
/// Where the identity cannot show an in-place rewrite (Windows without a
/// change time) the bytes are compared with the blocks being proven.
fn disk_still_the_verified_object(
    path: &str,
    out_path: &std::path::Path,
    blocks: &[yadorilink_replica_domain::file::BlockInfo],
    verified: Option<yadorilink_fs_platform::fs_identity::FileIdentity>,
) -> bool {
    use yadorilink_fs_platform::fs_identity::FileIdentity;
    let identity_unchanged = verified.is_some()
        && super::super::types::require_physical_kind_matches(path, out_path, RecordKind::File)
            .is_ok()
        && FileIdentity::observe_path(out_path).ok() == verified;
    let unchanged = super::super::completion_window::verified_bytes_still_on_disk(
        identity_unchanged,
        FileIdentity::in_place_rewrite_visible(out_path),
        || {
            yadorilink_local_storage::disk_bytes_match_indexed_blocks(out_path, blocks)
                .unwrap_or(false)
        },
    );
    if !unchanged {
        tracing::warn!(
            path,
            "the file changed on disk after it was verified and before its batch committed; \
             nothing was recorded for the bytes written and the intent stays open"
        );
    }
    unchanged
}
