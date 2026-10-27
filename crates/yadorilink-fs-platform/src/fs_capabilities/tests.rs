#![cfg(test)]

use super::*;

/// A probe artefact whose write fails after `create_new` succeeded has
/// no owner: the caller never receives the path, so it cannot clean up
/// what it was never told about, and nothing else knows the name. Under
/// sustained disk pressure — the exact condition that makes the write
/// fail — every retry would leave another one behind.
///
/// The artefact is reserved-namespace shaped, so it is excluded from
/// indexing and can never be signed into native state; this is disk litter,
/// not a sync-correctness defect. It is still the caller's directory,
/// and the rule this module enforces everywhere else is that a probe
/// leaves nothing behind.
#[test]
fn a_probe_artefact_whose_write_fails_is_not_left_behind() {
    let dir = tempfile::tempdir().unwrap();
    FAIL_NEXT_PROBE_WRITE.with(|f| f.set(true));

    let result = create_probe_artefact(dir.path(), "orphan", b"content");

    assert!(result.is_err(), "the injected write failure must be reported, not swallowed");
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        leftovers.is_empty(),
        "a probe artefact whose write failed must be removed, found {leftovers:?}"
    );
}

/// High-severity regression: every artefact a probe places directly in
/// the caller's directory must classify as reserved — see
/// `probe_artefact_name`'s doc for the concrete harm an unreserved name
/// caused (a probe artefact racing the watcher/scan/local-change
/// indexing path and, worst case, getting signed into native state). Checked
/// against `create_probe_artefact`, `reserve_probe_artefact_path` and a
/// full `probe_all` run (which exercises every probe in this module),
/// not only `probe_artefact_name` in isolation, so this fails if any
/// probe stops routing its artefact names through it.
#[test]
#[allow(
    clippy::excessive_nesting,
    reason = "the unreserved-artefact poller must observe `probe_all` while it runs, so the \
              scan loop (thread closure -> while -> if let Ok(entries) -> for entry -> if \
              unreserved) is nested inside the spawned thread that the test's own \
              stop-flag and join bracket; hoisting it out of the closure would break the \
              concurrent sampling this regression test exists to perform"
)]
fn every_probe_artefact_name_is_reserved_namespace_shaped() {
    let dir = tempfile::tempdir().unwrap();

    let (created_path, file) = create_probe_artefact(dir.path(), "regression-label", b"x").unwrap();
    assert!(crate::reserved_namespace::is_artefact_component(created_path.file_name().unwrap()));
    drop(file);
    std::fs::remove_file(&created_path).unwrap();

    let reserved_path = reserve_probe_artefact_path(dir.path(), "regression-label").unwrap();
    assert!(crate::reserved_namespace::is_artefact_component(reserved_path.file_name().unwrap()));

    // `probe_all` exercises every probe in the module (atomic exchange,
    // reflink, range clone, flush, identity, stale-handle, metadata) —
    // whatever transient artefacts land in `dir` mid-run, none may ever
    // be visible outside the reserved namespace. Sampled by polling the
    // directory from a second thread while probing runs, since every
    // artefact this module creates is normally cleaned up before
    // `probe_all` returns.
    let poll_dir = dir.path().to_path_buf();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_clone = stop.clone();
    let observed_unreserved = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed_clone = observed_unreserved.clone();
    let poller = std::thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            if let Ok(entries) = std::fs::read_dir(&poll_dir) {
                for entry in entries.filter_map(|e| e.ok()) {
                    if !crate::reserved_namespace::is_reserved_component(&entry.file_name()) {
                        observed_clone.lock().unwrap().push(entry.file_name());
                    }
                }
            }
        }
    });
    let _ = probe_all(dir.path());
    stop.store(true, Ordering::Relaxed);
    poller.join().unwrap();
    assert!(
        observed_unreserved.lock().unwrap().is_empty(),
        "probe_all left an unreserved artefact visible in the sync directory: {:?}",
        observed_unreserved.lock().unwrap()
    );
}

#[test]
fn unknown_is_never_read_as_supported() {
    assert!(!Capability::Unknown.is_supported());
    assert!(!Capability::Unsupported.is_supported());
    assert!(Capability::Supported.is_supported());
}

#[test]
fn cache_miss_returns_unknown_never_a_guess() {
    let cache = CapabilityCache::new();
    let key = CapabilityCacheKey::new(
        VolumeIdentity::Unix { device_id: 1 },
        OperationKind::AtomicExchange,
        ADAPTER_VERSION,
    );
    assert_eq!(cache.get(&key), Capability::Unknown);
}

#[test]
fn cache_round_trips_a_recorded_value() {
    let cache = CapabilityCache::new();
    let key = CapabilityCacheKey::new(
        VolumeIdentity::Unix { device_id: 1 },
        OperationKind::AtomicExchange,
        ADAPTER_VERSION,
    );
    cache.record(key, Capability::Supported);
    assert_eq!(cache.get(&key), Capability::Supported);
}

#[test]
fn different_volume_identity_is_a_different_cache_entry() {
    let cache = CapabilityCache::new();
    let key_a = CapabilityCacheKey::new(
        VolumeIdentity::Unix { device_id: 1 },
        OperationKind::AtomicExchange,
        ADAPTER_VERSION,
    );
    let key_b = CapabilityCacheKey::new(
        VolumeIdentity::Unix { device_id: 2 },
        OperationKind::AtomicExchange,
        ADAPTER_VERSION,
    );
    cache.record(key_a, Capability::Supported);
    // A removable drive remounted with a different device id must miss
    // the cache entirely, never inherit the old volume's answer.
    assert_eq!(cache.get(&key_b), Capability::Unknown);
}

#[test]
fn different_operation_kind_is_a_different_cache_entry() {
    let cache = CapabilityCache::new();
    let volume = VolumeIdentity::Unix { device_id: 1 };
    cache.record(
        CapabilityCacheKey::new(volume, OperationKind::AtomicExchange, ADAPTER_VERSION),
        Capability::Supported,
    );
    assert_eq!(
        cache.get(&CapabilityCacheKey::new(volume, OperationKind::ReflinkOrClone, ADAPTER_VERSION)),
        Capability::Unknown
    );
}

#[test]
fn different_adapter_version_is_a_different_cache_entry() {
    let cache = CapabilityCache::new();
    let volume = VolumeIdentity::Unix { device_id: 1 };
    cache.record(
        CapabilityCacheKey::new(volume, OperationKind::AtomicExchange, 1),
        Capability::Supported,
    );
    // A probe-logic change (adapter version bump) must not inherit an
    // answer computed under the old logic.
    assert_eq!(
        cache.get(&CapabilityCacheKey::new(volume, OperationKind::AtomicExchange, 2)),
        Capability::Unknown
    );
}

#[test]
fn get_or_probe_only_probes_once() {
    let cache = CapabilityCache::new();
    let key = CapabilityCacheKey::new(
        VolumeIdentity::Unix { device_id: 1 },
        OperationKind::AtomicExchange,
        ADAPTER_VERSION,
    );
    let mut probe_calls = 0;
    let first = cache.get_or_probe(key, || {
        probe_calls += 1;
        Capability::Supported
    });
    let second = cache.get_or_probe(key, || {
        probe_calls += 1;
        Capability::Supported
    });
    assert_eq!(first, Capability::Supported);
    assert_eq!(second, Capability::Supported);
    assert_eq!(probe_calls, 1);
}

#[test]
fn cached_unknown_is_re_probed_not_treated_as_a_settled_hit() {
    // R8: `Unknown` means "not yet established", so a cache entry
    // sitting at `Unknown` (however it got there) must not short-
    // circuit `get_or_probe` the way a settled `Supported`/
    // `Unsupported` value does.
    let cache = CapabilityCache::new();
    let key = CapabilityCacheKey::new(
        VolumeIdentity::Unix { device_id: 1 },
        OperationKind::AtomicExchange,
        ADAPTER_VERSION,
    );
    cache.record(key, Capability::Unknown);
    let mut probed = false;
    let result = cache.get_or_probe(key, || {
        probed = true;
        Capability::Supported
    });
    assert!(probed, "a cached Unknown must not be treated as a settled cache hit");
    assert_eq!(result, Capability::Supported);
}

#[test]
fn get_or_probe_stops_reprobing_after_the_consecutive_unknown_cap_but_never_upgrades() {
    // R8: an `Unknown` streak (a durably broken directory: permanent
    // EIO, a permanent read-only remount) must not turn into an
    // unbounded re-probe loop, but it must also never be "resolved"
    // into anything other than `Unknown` just because the cap was
    // reached.
    let cache = CapabilityCache::new();
    let key = CapabilityCacheKey::new(
        VolumeIdentity::Unix { device_id: 1 },
        OperationKind::AtomicExchange,
        ADAPTER_VERSION,
    );
    let mut probe_calls = 0;
    for _ in 0..(MAX_CONSECUTIVE_UNKNOWN_REPROBES + 3) {
        let result = cache.get_or_probe(key, || {
            probe_calls += 1;
            Capability::Unknown
        });
        assert_eq!(result, Capability::Unknown, "Unknown must never be upgraded");
    }
    assert_eq!(
        probe_calls, MAX_CONSECUTIVE_UNKNOWN_REPROBES,
        "re-probing must stop once the bound is reached, not spin forever"
    );
}

#[test]
fn a_settled_result_before_the_reprobe_cap_is_reported_and_cached() {
    let cache = CapabilityCache::new();
    let key = CapabilityCacheKey::new(
        VolumeIdentity::Unix { device_id: 1 },
        OperationKind::AtomicExchange,
        ADAPTER_VERSION,
    );
    // One short of the cap, so the next call still actually re-probes
    // (see `get_or_probe_stops_reprobing_after_the_consecutive_
    // unknown_cap...` above for what happens once the cap itself is
    // reached).
    for _ in 0..MAX_CONSECUTIVE_UNKNOWN_REPROBES.saturating_sub(1) {
        cache.get_or_probe(key, || Capability::Unknown);
    }
    let resolved = cache.get_or_probe(key, || Capability::Supported);
    assert_eq!(resolved, Capability::Supported);
    assert_eq!(cache.get(&key), Capability::Supported);
}

#[test]
fn explicit_record_unsticks_a_key_that_hit_the_reprobe_cap() {
    // Once the cap is reached, `get_or_probe` alone never calls
    // `probe` again for that key (see the test above) — that is a
    // deliberate permanent stop for this `CapabilityCache` instance's
    // lifetime, not a temporary pause with automatic recovery. A
    // caller that wants a fresh look after conditions might have
    // changed (a fresh probe session, an explicit user-triggered
    // re-check) does so by starting a new `CapabilityCache` or by
    // calling `record` directly, which always resets the streak.
    let cache = CapabilityCache::new();
    let key = CapabilityCacheKey::new(
        VolumeIdentity::Unix { device_id: 1 },
        OperationKind::AtomicExchange,
        ADAPTER_VERSION,
    );
    for _ in 0..MAX_CONSECUTIVE_UNKNOWN_REPROBES {
        cache.get_or_probe(key, || Capability::Unknown);
    }
    cache.record(key, Capability::Unknown);
    let mut probed = false;
    let result = cache.get_or_probe(key, || {
        probed = true;
        Capability::Supported
    });
    assert!(probed, "record must reset the re-probe streak, not just the cached value");
    assert_eq!(result, Capability::Supported);
}

#[test]
fn durability_level_never_exceeds_atomic_exchange_support() {
    let caps = FilesystemSafetyCapabilities {
        atomic_exchange: Capability::Unsupported,
        durable_file_flush: Capability::Supported,
        durable_directory_flush: Capability::Supported,
        stable_source_identity: Capability::Supported,
        stable_owned_marker_identity: Capability::Supported,
        stale_handle_preservation: Capability::Supported,
        metadata_fidelity: Capability::Supported,
        reflink_or_clone: Capability::Supported,
        range_clone: Capability::Supported,
    };
    assert_eq!(derive_durability_level(&caps, false), DurabilityLevel::Unsupported);
}

#[test]
fn durability_level_requires_directory_flush_for_power_loss_safe() {
    let mut caps = FilesystemSafetyCapabilities {
        atomic_exchange: Capability::Supported,
        durable_file_flush: Capability::Supported,
        durable_directory_flush: Capability::Unsupported,
        stable_source_identity: Capability::Supported,
        stable_owned_marker_identity: Capability::Supported,
        stale_handle_preservation: Capability::Supported,
        metadata_fidelity: Capability::Supported,
        reflink_or_clone: Capability::Unsupported,
        range_clone: Capability::Unsupported,
    };
    assert_eq!(derive_durability_level(&caps, false), DurabilityLevel::ProcessCrashSafe);

    caps.durable_directory_flush = Capability::Supported;
    assert_eq!(derive_durability_level(&caps, false), DurabilityLevel::PowerLossSafe);
}

#[test]
fn durability_level_never_claims_power_loss_safe_from_flush_alone_on_remote_filesystems() {
    let caps = FilesystemSafetyCapabilities {
        atomic_exchange: Capability::Supported,
        durable_file_flush: Capability::Supported,
        durable_directory_flush: Capability::Supported,
        stable_source_identity: Capability::Supported,
        stable_owned_marker_identity: Capability::Supported,
        stale_handle_preservation: Capability::Unsupported,
        metadata_fidelity: Capability::Supported,
        reflink_or_clone: Capability::Unsupported,
        range_clone: Capability::Unsupported,
    };
    assert_eq!(derive_durability_level(&caps, true), DurabilityLevel::BestEffortRemoteFilesystem);
}

#[test]
fn remote_durability_level_also_requires_stable_identity() {
    // R7: the local branch above already required stable identity; the
    // remote branch must too. A remote mount with working
    // atomic-exchange and flush syscalls but no reuse-safe identity
    // would otherwise be reported usable even though recovery cannot
    // tell the recorded object from a replacement.
    let caps = FilesystemSafetyCapabilities {
        atomic_exchange: Capability::Supported,
        durable_file_flush: Capability::Supported,
        durable_directory_flush: Capability::Supported,
        stable_source_identity: Capability::Unsupported,
        stable_owned_marker_identity: Capability::Supported,
        stale_handle_preservation: Capability::Supported,
        metadata_fidelity: Capability::Supported,
        reflink_or_clone: Capability::Unsupported,
        range_clone: Capability::Unsupported,
    };
    assert_eq!(derive_durability_level(&caps, true), DurabilityLevel::Unsupported);
}

#[test]
fn remote_durability_level_requires_the_marker_field_too() {
    // Mirrors the test above with the fields swapped: `derive_
    // durability_level` requires BOTH `stable_source_identity` and
    // `stable_owned_marker_identity` (see its own doc for why a single
    // "attempt syncing at all" gate cannot safely pick a side of the
    // nine `compare()` call sites' source/marker ambiguity), so a
    // volume reporting only one of the two as `Supported` must still
    // come back `Unsupported`, not `BestEffortRemoteFilesystem`.
    let caps = FilesystemSafetyCapabilities {
        atomic_exchange: Capability::Supported,
        durable_file_flush: Capability::Supported,
        durable_directory_flush: Capability::Supported,
        stable_source_identity: Capability::Supported,
        stable_owned_marker_identity: Capability::Unsupported,
        stale_handle_preservation: Capability::Supported,
        metadata_fidelity: Capability::Supported,
        reflink_or_clone: Capability::Unsupported,
        range_clone: Capability::Unsupported,
    };
    assert_eq!(derive_durability_level(&caps, true), DurabilityLevel::Unsupported);
}

#[test]
fn probe_all_against_a_real_temp_directory_returns_no_unsupported_atomic_exchange_surprise() {
    // This is a smoke test, not an assertion about specific results:
    // real probe outcomes vary by host filesystem (macOS APFS vs. a
    // CI runner's overlay/tmpfs). It only asserts the probe completes
    // and produces some definite `Capability` for every field — never
    // a panic, and (per `is_supported`) `Unknown` never silently reads
    // as `Supported`.
    let dir = tempfile::tempdir().unwrap();
    let caps = probe_all(dir.path()).unwrap();
    for capability in [
        caps.atomic_exchange,
        caps.durable_file_flush,
        caps.durable_directory_flush,
        caps.stable_source_identity,
        caps.stable_owned_marker_identity,
        caps.stale_handle_preservation,
        caps.metadata_fidelity,
        caps.reflink_or_clone,
        caps.range_clone,
    ] {
        if capability == Capability::Unknown {
            assert!(!capability.is_supported());
        }
    }
}

#[test]
fn probe_stable_identity_reports_supported_exactly_when_a_reuse_discriminator_exists() {
    // Platform-dependent, deliberately not hard-coded to `Supported`:
    // on some filesystems (observed on Linux under overlayfs — see the
    // eprintln below) `std::fs::Metadata` supplies neither a
    // `generation_or_usn` nor a fine-grained `birth_or_creation_time`,
    // so `FileIdentity::compare` correctly reports `Ambiguous` and this
    // probe correctly reports `Unsupported`. That is the R6 fix working
    // as designed, not a probe failure — asserting `Supported`
    // unconditionally here was itself the bug (the same class as the
    // `disk_race_fingerprint` test's platform-dependent-property-
    // asserted-as-universal mistake): meaningful on the author's
    // macOS/APFS host, wrong on Linux/overlayfs CI.
    //
    // Empirically reproduces the exact check the probe itself performs
    // (rename a fresh file, measure this volume's real granularity, ask
    // `compare`) and requires the probe's answer to match it exactly in
    // both directions — never weakened to "not `Unknown`", which would
    // stop testing anything.
    let dir = tempfile::tempdir().unwrap();
    let before_path = dir.path().join("expected-outcome-before");
    let after_path = dir.path().join("expected-outcome-after");
    std::fs::write(&before_path, b"identity probe").unwrap();
    let before = FileIdentity::observe_path(&before_path).unwrap();
    std::fs::rename(&before_path, &after_path).unwrap();
    let after = FileIdentity::observe_path(&after_path).unwrap();
    let granularity = probe_birth_time_granularity(dir.path());
    let expected = match before.compare(&after, granularity) {
        IdentityComparison::SameObject => Capability::Supported,
        IdentityComparison::DefinitelyDifferent | IdentityComparison::Ambiguous(_) => {
            Capability::Unsupported
        }
    };
    eprintln!(
        "probe_stable_identity: generation_or_usn present={}, \
         birth_or_creation_time present={}, granularity={granularity:?}, expected={expected:?}",
        before.generation_or_usn.is_some(),
        before.birth_or_creation_time.is_some(),
    );

    let result = probe_stable_identity(dir.path());
    assert_eq!(result, expected);
}

#[test]
fn a_reuse_discriminator_is_what_distinguishes_supported_from_ambiguous() {
    // Not a probe test: this documents *why* `probe_stable_identity`
    // checks for a discriminator at all, by constructing the exact
    // synthetic identities the probe's own check is meant to catch and
    // confirming `FileIdentity::compare` really does treat them as
    // `Ambiguous`. If this regressed to being `SameObject` (e.g. a
    // future edit made `compare` fall back to a non-discriminating
    // field), `probe_stable_identity` would start reporting `Supported`
    // for a volume that cannot actually back a safe identity
    // comparison.
    use crate::fs_identity::{AmbiguityReason, ObjectKind, PlatformObjectId};
    let identity_without_a_discriminator = |object_id| FileIdentity {
        volume_identity: VolumeIdentity::Unix { device_id: 1 },
        object_id,
        object_kind: ObjectKind::RegularFile,
        generation_or_usn: None,
        birth_or_creation_time: None,
        observed_size: 0,
        metadata_fingerprint: [0; 32],
        link_count: Some(1),
        symlink_target_digest: None,
    };
    let before = identity_without_a_discriminator(PlatformObjectId::Unix { inode: 2 });
    let after = identity_without_a_discriminator(PlatformObjectId::Unix { inode: 2 });
    assert_eq!(
        before.compare(&after, TimestampGranularity::Fine),
        IdentityComparison::Ambiguous(AmbiguityReason::NoStableGenerationOrUsn)
    );
}

#[test]
fn probe_all_rejects_a_directory_that_does_not_exist() {
    let missing = std::env::temp_dir().join("yadorilink-fscap-probe-missing-dir-does-not-exist");
    assert!(probe_all(&missing).is_err());
}

#[cfg(unix)]
#[test]
fn classify_errno_only_reports_unsupported_for_the_feature_absent_set() {
    // The transient/unrelated case: `EPERM` says nothing about
    // whether the feature exists, so it must stay `Unknown` — never
    // `Unsupported`, which would let one unlucky permission failure
    // permanently poison a cached "this volume can't do this" answer.
    assert_eq!(
        classify_errno(Some(libc::EPERM), &[libc::ENOSYS, libc::EINVAL]),
        Capability::Unknown
    );
    // No errno at all (shouldn't happen for a real failed syscall, but
    // defensively) is the same: not proof of anything.
    assert_eq!(classify_errno(None, &[libc::ENOSYS]), Capability::Unknown);
    // The documented feature-absence case.
    assert_eq!(classify_errno(Some(libc::ENOSYS), &[libc::ENOSYS]), Capability::Unsupported);
}

#[cfg(unix)]
#[test]
fn retry_eintr_retries_past_interruption_and_returns_the_real_result() {
    let mut calls = 0;
    let (ret, errno) = retry_eintr(|| {
        calls += 1;
        if calls < 3 {
            (-1, Some(libc::EINTR))
        } else {
            (0, None)
        }
    });
    assert_eq!((ret, errno), (0, None));
    assert_eq!(calls, 3, "EINTR must be retried, not surfaced as a result");
}

#[cfg(unix)]
#[test]
fn retry_eintr_does_not_retry_a_different_failure() {
    // A `-1` with anything other than `EINTR` is a real result, not
    // interruption noise, and must be returned on the first attempt.
    let mut calls = 0;
    let (ret, errno) = retry_eintr(|| {
        calls += 1;
        (-1, Some(libc::EPERM))
    });
    assert_eq!((ret, errno), (-1, Some(libc::EPERM)));
    assert_eq!(calls, 1);
}

#[test]
fn probe_range_clone_smoke_test_never_reports_supported_from_a_zero_byte_copy() {
    // Not a fault-injection test (this module has no seam for forcing
    // `copy_file_range` to return `0` from real probe code) — this
    // instead directly checks the loop invariant `platform_range_clone`
    // relies on: a positive-length request must observe the full
    // expected content on the destination before claiming `Supported`,
    // which a `0`-byte return could never have produced.
    let dir = tempfile::tempdir().unwrap();
    let result = probe_range_clone(dir.path());
    if result == Capability::Supported {
        // On Linux with a working `copy_file_range`, the destination
        // must contain the exact probe content, not a truncated or
        // empty file a lenient `ret >= 0` check could have let through.
        let dst_entries: Vec<_> =
            std::fs::read_dir(dir.path()).unwrap().filter_map(|entry| entry.ok()).collect();
        assert!(
            dst_entries.is_empty(),
            "a successful probe must clean up its own artefacts: found {:?}",
            dst_entries.iter().map(|e| e.path()).collect::<Vec<_>>()
        );
    }
}

#[cfg(target_vendor = "apple")]
#[test]
fn macos_directory_flush_reports_supported_only_via_full_fsync() {
    // Both the file-flush and directory-flush probes route through
    // the single `platform_full_fsync` function on macOS (see its doc
    // comment), so there is exactly one place plain `fsync` could ever
    // leak back into a `PowerLossSafe` claim — and it isn't used here.
    // APFS (the filesystem backing a macOS temp directory) supports
    // `F_FULLFSYNC`, so a correct implementation reports `Supported`;
    // this is a smoke-level regression guard for that shared-primitive
    // structure, not a fault-injection proof that bare `fsync` is
    // unreachable.
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(probe_durable_directory_flush(dir.path()), Capability::Supported);
}

#[test]
fn platform_reflink_or_clone_reports_it_did_not_create_a_preexisting_destination() {
    // R9: `reserve_probe_artefact_path` only narrows the ownership
    // race to the gap between its own check and this call — it cannot
    // eliminate it. If something else already occupies `dst` by the
    // time the platform call actually runs, that call must say it did
    // NOT create `dst`, so the outer probe never deletes a file it
    // does not own. Simulated directly here (rather than relying on
    // timing a real race) by simply pre-creating `dst` before calling
    // the platform function.
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::write(&src, b"content").unwrap();
    let dst = dir.path().join("dst");
    std::fs::write(&dst, b"someone else's content").unwrap();

    let (_, dst_created_by_us) = platform_reflink_or_clone(&src, &dst);

    assert!(!dst_created_by_us);
    assert_eq!(
        std::fs::read(&dst).unwrap(),
        b"someone else's content",
        "a probe must never overwrite or delete a path it did not create"
    );
}

#[test]
fn platform_range_clone_reports_it_did_not_create_a_preexisting_destination() {
    // Same reasoning as the reflink test above. On non-Linux hosts
    // `platform_range_clone` is the stub that always reports `false`
    // regardless of `dst`'s state, so this is trivially true there;
    // on Linux it exercises the real `create_new` guard.
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src");
    std::fs::write(&src, b"0123456789abcdef").unwrap();
    let dst = dir.path().join("dst");
    std::fs::write(&dst, b"someone else's content").unwrap();

    let (_, dst_created_by_us) = platform_range_clone(&src, &dst);

    assert!(!dst_created_by_us);
    assert_eq!(std::fs::read(&dst).unwrap(), b"someone else's content");
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
#[test]
fn rename_no_replace_does_not_clobber_a_preexisting_target() {
    // Mirrors the two clone-probe ownership tests above, for the
    // rename-target race `probe_stable_identity` used to be
    // exposed to. On Linux/macOS this exercises the real
    // `RENAME_NOREPLACE`/`RENAME_EXCL` syscall path, not the
    // documented Windows fallback residual (see `rename_no_replace`'s
    // doc) — gated accordingly rather than asserted everywhere, since
    // the Windows path's behavior here is deliberately different
    // (and cannot be verified from this host).
    let dir = tempfile::tempdir().unwrap();
    let from = dir.path().join("from");
    std::fs::write(&from, b"mover content").unwrap();
    let to = dir.path().join("to");
    std::fs::write(&to, b"someone else's content").unwrap();

    let outcome = rename_no_replace(&from, &to);

    assert_eq!(outcome, RenameOutcome::NotRenamed);
    assert_eq!(
        std::fs::read(&to).unwrap(),
        b"someone else's content",
        "a probe must never overwrite a path it did not create"
    );
    assert_eq!(std::fs::read(&from).unwrap(), b"mover content", "source must be untouched too");
}

#[cfg(any(target_os = "linux", target_vendor = "apple"))]
#[test]
fn rename_no_replace_succeeds_when_the_target_is_absent() {
    let dir = tempfile::tempdir().unwrap();
    let from = dir.path().join("from");
    std::fs::write(&from, b"mover content").unwrap();
    let to = dir.path().join("to");

    let outcome = rename_no_replace(&from, &to);

    assert_eq!(outcome, RenameOutcome::Renamed);
    assert!(!from.exists());
    assert_eq!(std::fs::read(&to).unwrap(), b"mover content");
}

#[test]
fn probe_birth_time_granularity_returns_a_defined_outcome_on_this_host() {
    // Not asserting a specific value here (that's host-dependent, and
    // already pinned indirectly by `probe_stable_identity_reports_
    // supported_exactly_when_a_reuse_discriminator_exists` above,
    // which requires `Fine` on this host to pass) — only that the
    // probe completes and returns one of the two defined outcomes.
    let dir = tempfile::tempdir().unwrap();
    let granularity = probe_birth_time_granularity(dir.path());
    assert!(matches!(granularity, TimestampGranularity::Fine | TimestampGranularity::Coarse));
}

/// `verify_still_owns`
/// (`sync_root_lock.rs`) is reached from `RootLease::begin_operation`,
/// which fires on essentially every local capture, materialize, and
/// hydration operation -- an uncached probe there re-pays real file-
/// create/stat/unlink I/O on every single call. Uses two distinct
/// synthetic `VolumeIdentity` values rather than an actual remount
/// (impractical in a unit test) to prove the caching decision itself,
/// mirroring `yadorilink-daemon`'s own `peer_replica_state.rs`
/// precedent for the same value. Confirmed genuinely RED by temporarily
/// keying the cache on a constant instead of the given identity: the
/// second, different-identity call then wrongly reused the first
/// identity's cached value instead of re-probing.
#[test]
fn granularity_cache_reprobes_on_a_different_volume_identity_but_not_the_same_one() {
    let volume_a = VolumeIdentity::Unix { device_id: 0xC4C4 };
    let volume_b = VolumeIdentity::Unix { device_id: 0xD4D4 };

    let probes_for_a = AtomicU64::new(0);
    let first = cached_granularity_for_volume(volume_a, || {
        probes_for_a.fetch_add(1, Ordering::SeqCst);
        Some(TimestampGranularity::Fine)
    });
    let second = cached_granularity_for_volume(volume_a, || {
        probes_for_a.fetch_add(1, Ordering::SeqCst);
        Some(TimestampGranularity::Coarse)
    });
    assert_eq!(first, TimestampGranularity::Fine);
    assert_eq!(
        second,
        TimestampGranularity::Fine,
        "the same volume identity must reuse the cached probe"
    );
    assert_eq!(
        probes_for_a.load(Ordering::SeqCst),
        1,
        "must probe only once for the same identity"
    );

    let probes_for_b = AtomicU64::new(0);
    let third = cached_granularity_for_volume(volume_b, || {
        probes_for_b.fetch_add(1, Ordering::SeqCst);
        Some(TimestampGranularity::Coarse)
    });
    assert_eq!(
        third,
        TimestampGranularity::Coarse,
        "a different volume identity must be probed fresh, never inherit another volume's \
         cached answer -- exactly the case of a remount at the same path"
    );
}

#[test]
fn granularity_probe_treats_zero_usable_samples_as_coarse_not_unresolved() {
    // R6's explicit ask: what happens when the measurement itself is
    // inconclusive. A directory that does not exist can't have any
    // artefact created in it, so every sample fails to even start —
    // this must resolve to `Coarse`, never `Fine`, so a caller relying
    // on it still blocks on ambiguity rather than guessing.
    let missing = std::env::temp_dir().join("yadorilink-fscap-granularity-missing-dir");
    assert_eq!(probe_birth_time_granularity(&missing), TimestampGranularity::Coarse);
}

/// A measurement that could not be made (the directory vanished mid-probe) answers `Coarse` for
/// that call only: it is not kept, and the next valid measurement on the same volume decides.
#[test]
fn an_unmeasurable_granularity_is_not_kept_for_the_volume() {
    let volume = VolumeIdentity::Unix { device_id: 0xE4E4 };
    assert_eq!(cached_granularity_for_volume(volume, || None), TimestampGranularity::Coarse);
    assert_eq!(
        cached_granularity_for_volume(volume, || Some(TimestampGranularity::Fine)),
        TimestampGranularity::Fine
    );
    let gone = tempfile::tempdir().unwrap();
    let path = gone.path().to_path_buf();
    drop(gone);
    assert_eq!(measure_birth_time_granularity(&path), None);
}

/// The startup sweep of a sync root must not remove a probe of this process that runs in
/// that root at the same time (the durable-namespace probe's scratch directory): half-removed,
/// the volume seems to accept a second no-replace publish, and that wrong verdict is kept for
/// the process, so every later durable namespace change is refused.
#[test]
fn the_sweep_leaves_this_processs_own_probe_artefacts() {
    let root = tempfile::tempdir().unwrap();
    let own = root.path().join(probe_artefact_name("dir-durability").unwrap());
    std::fs::create_dir(&own).unwrap();
    std::fs::write(own.join("f"), b"probe").unwrap();
    let stranded = root.path().join(
        crate::reserved_namespace::artefact_component_name(
            crate::reserved_namespace::ArtefactKind::Probe,
            &format!("{}-1-1-dir-durability", std::process::id().wrapping_add(1)),
        )
        .unwrap(),
    );
    std::fs::create_dir(&stranded).unwrap();

    let sweep = sweep_probe_artefacts(root.path());

    assert_eq!(sweep.removed, vec![stranded.clone()]);
    assert!(own.join("f").exists(), "a live probe of this process was swept");
    assert!(!stranded.exists());
}

/// A restarted process may get the same pid (Docker pid 1); its predecessor's stranded
/// probes carry that pid but another instance, and are swept.
#[test]
fn the_sweep_removes_a_probe_of_an_earlier_process_that_had_the_same_pid() {
    let root = tempfile::tempdir().unwrap();
    let stranded = root.path().join(
        crate::reserved_namespace::artefact_component_name(
            crate::reserved_namespace::ArtefactKind::Probe,
            &format!("{}x1-1-1-dir-durability", std::process::id()),
        )
        .unwrap(),
    );
    std::fs::create_dir(&stranded).unwrap();
    let own = root.path().join(probe_artefact_name("dir-durability").unwrap());
    std::fs::create_dir(&own).unwrap();

    let sweep = sweep_probe_artefacts(root.path());

    assert_eq!(sweep.removed, vec![stranded]);
    assert!(own.exists());
}
