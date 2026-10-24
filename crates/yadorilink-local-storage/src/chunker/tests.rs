#![cfg(test)]

use super::*;
use crate::SegmentBlockStore;

/// `hash_file_blocks` exists to move the durability decision to the
/// caller, NOT to change what a file chunks into. A record built from
/// its output has to be the byte-for-byte record `chunk_file` produces
/// for the same file, or the two producers would author different
/// versions for identical content -- every cross-device comparison in
/// the system is on those hashes.
#[test]
fn hash_file_blocks_matches_chunk_file_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("multi-block.bin");
    // Several whole blocks plus a partial one, so boundary placement
    // and the short final read are both covered.
    let bytes: Vec<u8> = (0..DEFAULT_BLOCK_SIZE * 3 + 7919).map(|i| (i % 251) as u8).collect();
    fs::write(&path, &bytes).unwrap();

    let store = SegmentBlockStore::new(dir.path().join("store").as_path()).unwrap();
    let committed = chunk_file(&store, &path).unwrap();

    let mut staged = Vec::new();
    let hashed = hash_file_blocks::<StorageError>(&path, false, |block, prepared| {
        staged.push((block.hash.clone(), prepared.bytes().to_vec()));
        Ok(())
    })
    .unwrap();

    assert_eq!(hashed, committed, "fixed-size boundaries/offsets/hashes must be identical");
    assert!(hashed.len() > 3, "fixture must actually span multiple blocks");
    // The bytes handed to the sink are the file's, in order -- the
    // caller commits exactly these, so a mismatch here is content
    // corruption, not a layout difference.
    let reassembled: Vec<u8> = staged.iter().flat_map(|(_, b)| b.clone()).collect();
    assert_eq!(reassembled, bytes);
    assert_eq!(
        staged.iter().map(|(h, _)| h.clone()).collect::<Vec<_>>(),
        hashed.iter().map(|b| b.hash.clone()).collect::<Vec<_>>(),
        "the hash handed to the sink must be the one the returned BlockInfo carries"
    );
}

/// Same contract for the content-defined half.
#[test]
fn hash_file_blocks_matches_chunk_file_content_defined_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cdc.bin");
    // Above `CDC_MIN_SIZE` and varied enough to produce real internal
    // boundaries rather than one max-sized block.
    let bytes: Vec<u8> =
        (0..CDC_MIN_SIZE * 6).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    fs::write(&path, &bytes).unwrap();

    let store = SegmentBlockStore::new(dir.path().join("store").as_path()).unwrap();
    let committed = chunk_file_content_defined(&store, &path).unwrap();

    let hashed = hash_file_blocks::<StorageError>(&path, true, |_, _| Ok(())).unwrap();

    assert_eq!(hashed, committed, "CDC boundaries/offsets/hashes must be identical");
}

/// The sink owns the commit, so a commit failure has to reach the
/// caller as the caller's own error and stop the file -- not be
/// swallowed into a partially-hashed success, which would hand back
/// blocks nobody ever stored.
#[test]
fn hash_file_blocks_stops_at_the_first_sink_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fails.bin");
    fs::write(&path, vec![b'z'; DEFAULT_BLOCK_SIZE * 4]).unwrap();

    let mut seen = 0usize;
    let result = hash_file_blocks::<StorageError>(&path, false, |_, _| {
        seen += 1;
        if seen == 2 {
            return Err(StorageError::Chunking("sink refused".into()));
        }
        Ok(())
    });

    assert!(matches!(result, Err(StorageError::Chunking(_))));
    assert_eq!(seen, 2, "hashing must stop at the failing block, not run the file out");
}

#[cfg(target_os = "linux")]
#[test]
fn resolve_erange_reprobe_treats_a_positive_size_as_retry() {
    assert_eq!(resolve_erange_reprobe(42).unwrap(), Some(42));
}

#[cfg(target_os = "linux")]
#[test]
fn resolve_erange_reprobe_treats_a_zero_size_as_genuinely_empty() {
    assert_eq!(resolve_erange_reprobe(0).unwrap(), None);
}

/// `list_xattr_names_strict`/`get_xattr_value_strict` must not treat
/// ANY re-probe outcome `<= 0` (not just a genuine `0`) as "no
/// attributes": that would silently fold a real re-probe failure (`-1`,
/// e.g. an `EIO`/`EACCES` on the second call) into an empty result --
/// exactly the "could not check" read as "matches" this strict
/// reader's whole contract exists to rule out. Confirmed genuinely
/// RED against a version of this function using `if size <= 0 {
/// return Ok(None) }` in place of the separate `< 0`/`== 0` checks:
/// this exact case returned `Ok(None)` (treated as empty) instead of
/// `Err`.
#[cfg(target_os = "linux")]
#[test]
fn resolve_erange_reprobe_treats_a_negative_size_as_a_real_error() {
    assert!(resolve_erange_reprobe(-1).is_err());
}

#[test]
fn chunk_and_reconstruct_roundtrip() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();

    let src_dir = tempfile::tempdir().unwrap();
    let src_path = src_dir.path().join("file.bin");
    let content: Vec<u8> = (0..DEFAULT_BLOCK_SIZE * 3 + 777).map(|i| (i % 251) as u8).collect();
    fs::write(&src_path, &content).unwrap();

    let blocks = chunk_file(&store, &src_path).unwrap();
    assert_eq!(blocks.len(), 4); // 3 full blocks + 1 partial

    let out_path = src_dir.path().join("reconstructed.bin");
    crate::reconstruct_file(&store, &out_path, &blocks, -1).unwrap();

    let reconstructed = fs::read(&out_path).unwrap();
    assert_eq!(reconstructed, content);
}

/// `chunk_file_fixed_with_callback` differs from `chunk_file` only in
/// pipeline shape (hash-once, block callback, bulk commit) -- never in
/// what it produces. Its own doc comment rests on that: it exists to be
/// compared against the CDC path with every stage but boundary
/// selection held identical, which is only a valid comparison while its
/// boundaries and hashes still agree with the original fixed chunker's,
/// block for block. Pinned here because the buffer handling on its hot
/// loop is exactly the kind of thing that gets tuned.
#[test]
fn the_fixed_callback_chunker_agrees_block_for_block_with_chunk_file() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let src_dir = tempfile::tempdir().unwrap();
    let src_path = src_dir.path().join("file.bin");
    // Deliberately not a whole number of blocks: the short final read
    // is the case where a reused buffer is easiest to get wrong.
    let content: Vec<u8> = (0..DEFAULT_BLOCK_SIZE * 2 + 1234).map(|i| (i % 251) as u8).collect();
    fs::write(&src_path, &content).unwrap();

    let expected = chunk_file(&store, &src_path).unwrap();

    let mut seen: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let actual = chunk_file_fixed_with_callback(&store, &src_path, |block, data| {
        seen.push((block.hash.clone(), data.to_vec()));
    })
    .unwrap();

    assert_eq!(actual, expected, "boundaries and hashes must match `chunk_file` exactly");

    // The callback must see every block, with the bytes that actually
    // hash to the hash it is handed alongside them -- a consumer
    // sends these to a peer, which verifies by hash on arrival.
    assert_eq!(seen.len(), expected.len());
    for ((hash, data), block) in seen.iter().zip(&expected) {
        assert_eq!(hash, &block.hash);
        assert_eq!(data.len(), block.size as usize);
        assert_eq!(
            data.as_slice(),
            &content[block.offset as usize..block.offset as usize + block.size as usize]
        );
    }
}

#[test]
fn identical_blocks_across_files_are_deduped_in_storage() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let src_dir = tempfile::tempdir().unwrap();

    let content = vec![9u8; DEFAULT_BLOCK_SIZE];
    let path_a = src_dir.path().join("a.bin");
    let path_b = src_dir.path().join("b.bin");
    fs::write(&path_a, &content).unwrap();
    fs::write(&path_b, &content).unwrap();

    let blocks_a = chunk_file(&store, &path_a).unwrap();
    let blocks_b = chunk_file(&store, &path_b).unwrap();
    assert_eq!(blocks_a[0].hash, blocks_b[0].hash);
}

#[test]
fn block_size_scales_up_for_very_large_files() {
    assert_eq!(block_size_for(1024), DEFAULT_BLOCK_SIZE);
    let huge = (TARGET_MAX_BLOCKS + 1) * DEFAULT_BLOCK_SIZE as u64;
    assert!(block_size_for(huge) > DEFAULT_BLOCK_SIZE);
}

/// Deterministic pseudo-random content — real CDC boundary-finding
/// behavior depends on actual byte entropy, so a trivially repetitive
/// pattern (unlike the fixed-size tests above, which don't care)
/// isn't representative here.
fn pseudo_random_content(size: usize, seed: u64) -> Vec<u8> {
    use rand::{RngExt, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    (0..size).map(|_| rng.random()).collect()
}

/// A large file chunked with CDC round-trips correctly through
/// `reconstruct_file`.
#[test]
fn cdc_chunk_and_reconstruct_roundtrip() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let src_dir = tempfile::tempdir().unwrap();
    let src_path = src_dir.path().join("file.bin");

    let content = pseudo_random_content(10 * 1024 * 1024, 42);
    fs::write(&src_path, &content).unwrap();

    let blocks = chunk_file_content_defined(&store, &src_path).unwrap();
    assert!(blocks.len() > 1, "a 10MB file should produce multiple CDC chunks");

    let out_path = src_dir.path().join("reconstructed.bin");
    crate::reconstruct_file(&store, &out_path, &blocks, -1).unwrap();
    assert_eq!(fs::read(&out_path).unwrap(), content);
}

/// Inserting bytes partway through a large file and re-chunking with
/// CDC leaves most block hashes unchanged for the untouched regions,
/// while the same edit under fixed-size chunking changes every block
/// hash from the edit point onward.
#[test]
fn cdc_resists_boundary_shift_unlike_fixed_size_chunking() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let src_dir = tempfile::tempdir().unwrap();

    let original = pseudo_random_content(10 * 1024 * 1024, 7);
    let original_path = src_dir.path().join("original.bin");
    fs::write(&original_path, &original).unwrap();

    // Insert 37 bytes (not aligned to any block boundary) near the
    // start of the file — everything from there on shifts by 37 bytes
    // relative to fixed byte offsets.
    let insertion_point = 1024;
    let mut edited = original[..insertion_point].to_vec();
    edited.extend_from_slice(&pseudo_random_content(37, 999));
    edited.extend_from_slice(&original[insertion_point..]);
    let edited_path = src_dir.path().join("edited.bin");
    fs::write(&edited_path, &edited).unwrap();

    let fixed_before = chunk_file(&store, &original_path).unwrap();
    let fixed_after = chunk_file(&store, &edited_path).unwrap();
    let fixed_unchanged = count_shared_hashes(&fixed_before, &fixed_after);

    let cdc_before = chunk_file_content_defined(&store, &original_path).unwrap();
    let cdc_after = chunk_file_content_defined(&store, &edited_path).unwrap();
    let cdc_unchanged = count_shared_hashes(&cdc_before, &cdc_after);

    // Fixed-size: only the one block containing the insertion point
    // can coincidentally still match (it won't, since content shifted
    // within it) — expect (close to) nothing shared after the edit.
    assert!(
        fixed_unchanged <= 1,
        "fixed-size chunking should share almost no blocks after a mid-file insertion, shared {fixed_unchanged}"
    );
    // CDC: the vast majority of blocks after the (small, localized)
    // edit region should be found at the same content-relative
    // boundary and therefore hash identically to before the edit.
    assert!(
        cdc_unchanged as f64 / cdc_before.len() as f64 > 0.7,
        "CDC should preserve most block hashes after a small localized edit: {cdc_unchanged}/{} shared",
        cdc_before.len()
    );
    assert!(
        cdc_unchanged > fixed_unchanged,
        "CDC must share strictly more unchanged blocks than fixed-size chunking for the same edit"
    );
}

fn count_shared_hashes(before: &[BlockInfo], after: &[BlockInfo]) -> usize {
    let before_hashes: std::collections::HashSet<&Vec<u8>> =
        before.iter().map(|b| &b.hash).collect();
    after.iter().filter(|b| before_hashes.contains(&b.hash)).count()
}

/// Content below `CDC_SIZE_THRESHOLD` is a caller-side decision (this
/// function itself doesn't enforce the threshold) — confirm it still
/// functions correctly for a small file, since nothing here should
/// assume a minimum input size beyond `fastcdc`'s own `CDC_MIN_SIZE`.
#[test]
fn cdc_chunking_handles_small_input_correctly() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let src_dir = tempfile::tempdir().unwrap();
    let src_path = src_dir.path().join("small.bin");

    let content = pseudo_random_content(1000, 3);
    fs::write(&src_path, &content).unwrap();

    let blocks = chunk_file_content_defined(&store, &src_path).unwrap();
    let out_path = src_dir.path().join("out.bin");
    crate::reconstruct_file(&store, &out_path, &blocks, -1).unwrap();
    assert_eq!(fs::read(&out_path).unwrap(), content);
}

/// `chunk_file_content_defined_with_callback` must be
/// behavior-identical to the plain (no-op-callback) form for its
/// return value -- callers that don't need per-block notification
/// (i.e. every existing caller/test) must see zero change. Separately,
/// the callback itself must fire exactly once per block, IN ORDER,
/// with the exact same `(hash, offset, size)` the returned `Vec`
/// carries for that position, and with the exact same content bytes
/// that were just durably `store.put()` -- a caller acting on those
/// bytes depends on this matching precisely, not approximately.
#[test]
fn content_defined_callback_matches_plain_form_and_fires_once_per_block_in_order() {
    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    let src_dir = tempfile::tempdir().unwrap();
    let src_path = src_dir.path().join("large.bin");

    // Large enough to produce several real CDC blocks, not just one --
    // a single-block file wouldn't exercise "in order" or "exactly
    // once per block" at all.
    let content = pseudo_random_content(CDC_AVG_SIZE * 8, 42);
    fs::write(&src_path, &content).unwrap();

    let plain_blocks = chunk_file_content_defined(&store, &src_path).unwrap();
    assert!(plain_blocks.len() > 1, "test needs multiple blocks to be meaningful");

    let mut observed: Vec<(BlockInfo, Arc<[u8]>)> = Vec::new();
    let callback_blocks =
        chunk_file_content_defined_with_callback(&store, &src_path, |block, data| {
            observed.push((block.clone(), data));
        })
        .unwrap();

    assert_eq!(
        callback_blocks, plain_blocks,
        "the callback form's return value must be identical to the plain form's"
    );
    assert_eq!(
        observed.len(),
        plain_blocks.len(),
        "callback must fire exactly once per block, no more, no fewer"
    );
    for (i, (observed_block, observed_data)) in observed.iter().enumerate() {
        assert_eq!(
            observed_block, &plain_blocks[i],
            "callback's block info at position {i} must match the returned Vec's, in order"
        );
        assert_eq!(
            observed_data.len(),
            observed_block.size as usize,
            "callback's data length must match its own block's declared size"
        );
        let expected_content = &content
            [observed_block.offset as usize..observed_block.offset as usize + observed_data.len()];
        assert_eq!(
            observed_data.as_ref(),
            expected_content,
            "callback's data at position {i} must be the exact source bytes for that block's \
             offset/size, not some other block's"
        );
    }
}

/// Changing a file's permission bits actually changes what
/// `unix_mode_from_metadata` reads back.
#[cfg(unix)]
#[test]
fn reads_owner_unix_mode() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("maybe-script");
    fs::write(&path, b"echo hi").unwrap();

    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(unix_mode_from_metadata(&fs::metadata(&path).unwrap()), Some(0o644));

    fs::set_permissions(&path, fs::Permissions::from_mode(0o744)).unwrap();
    assert_eq!(unix_mode_from_metadata(&fs::metadata(&path).unwrap()), Some(0o744));
}

#[test]
fn owner_exec_reader_accepts_ordinary_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plain.txt");
    fs::write(&path, b"hello").unwrap();
    let _ = unix_mode_from_metadata(&fs::metadata(&path).unwrap());
}

/// Crash-safety property 4: a source's `FileRecord`/native state
/// publication can only ever reference blocks this function actually
/// returned as `Ok(Vec<BlockInfo>)` -- there is no other way for a
/// caller to get a block list to publish with. If a batch's durable
/// commit fails partway through capture, this function must propagate
/// that failure as `Err`, never hand back a partial or best-effort
/// block list a caller could mistake for something safe to publish.
/// Forces every durable commit to fail through the store's own
/// free-space headroom gate, rather than by exhausting real disk
/// space.
#[test]
fn a_failed_batch_flush_never_returns_a_partial_block_list() {
    use crate::BlockStore;

    let store_dir = tempfile::tempdir().unwrap();
    let store = SegmentBlockStore::new(store_dir.path()).unwrap();
    store.set_headroom_enforced(true);
    store.set_headroom_override_bytes(Some(u64::MAX));

    let src_dir = tempfile::tempdir().unwrap();
    let src_path = src_dir.path().join("file.bin");
    let content = pseudo_random_content(2 * 1024 * 1024, 99);
    fs::write(&src_path, &content).unwrap();

    let result = chunk_file_content_defined_with_callback(&store, &src_path, |_, _| {});
    assert!(
        result.is_err(),
        "a batch commit failure must surface as an error, never a partial block list a \
         caller could go on to publish a FileRecord from"
    );
}

/// Round trip: attributes set in reverse-alphabetical order on
/// disk must come back sorted ascending by name -- the canonical
/// encoding invariant `FileMeta::xattrs` requires of every capture
/// path, not just an accident of `listxattr`'s own (unspecified)
/// ordering.
#[cfg(target_os = "linux")]
#[test]
fn read_replicated_xattrs_captures_user_namespace_attributes_sorted_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();

    set_xattr_for_test(&path, "user.zzz", b"last");
    set_xattr_for_test(&path, "user.aaa", b"first");

    let file = fs::File::open(&path).unwrap();
    let xattrs = read_replicated_xattrs(&file);
    assert_eq!(
        xattrs,
        vec![
            ("user.aaa".to_string(), b"first".to_vec()),
            ("user.zzz".to_string(), b"last".to_vec()),
        ]
    );
}

/// The allow-list is the whole point of `read_replicated_xattrs`
/// (never every xattr a file happens to carry, see its own doc
/// comment) -- exercised directly against `read_xattrs_filtered`'s
/// predicate parameter rather than a real disallowed namespace, since
/// setting `security.*`/`trusted.*` requires privileges this test
/// process does not have; the predicate is the exact mechanism
/// `read_replicated_xattrs`'s own `LINUX_ALLOWED_PREFIX` check
/// delegates to, so this proves the same logic without needing root.
#[cfg(target_os = "linux")]
#[test]
fn read_xattrs_filtered_excludes_names_the_allow_predicate_rejects() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file.bin");
    fs::write(&path, b"content").unwrap();

    set_xattr_for_test(&path, "user.allowed", b"yes");
    set_xattr_for_test(&path, "user.rejected", b"no");

    let file = fs::File::open(&path).unwrap();
    let xattrs = read_xattrs_filtered(&file, |name| name == "user.allowed");
    assert_eq!(xattrs, vec![("user.allowed".to_string(), b"yes".to_vec())]);
}

#[cfg(target_os = "linux")]
fn set_xattr_for_test(path: &std::path::Path, name: &str, value: &[u8]) {
    let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    let c_name = std::ffi::CString::new(name).unwrap();
    let ret = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            0,
        )
    };
    assert_eq!(ret, 0, "setxattr({name}) failed: {}", std::io::Error::last_os_error());
}

/// A handle that opens but cannot be read: on Unix a directory opens read-only and every read
/// fails (EISDIR), the same shape as an EIO partway through a real file.
#[cfg(unix)]
fn unreadable_after_open() -> (tempfile::TempDir, fs::File) {
    let dir = tempfile::tempdir().unwrap();
    let file = fs::File::open(dir.path()).unwrap();
    (dir, file)
}

#[cfg(unix)]
fn assert_source_read(error: &StorageError) {
    assert!(
        matches!(error, StorageError::SourceRead(_)),
        "a failed read of the user's file must be marked as the source's, got {error:?}"
    );
}

/// The read of the user's own file is marked apart from a block-store fault in every producer, so
/// a caller can skip the file without guessing from the error's shape.
#[cfg(unix)]
#[test]
fn a_failed_read_of_the_source_is_marked_as_the_sources_in_every_producer() {
    let (dir, file) = unreadable_after_open();
    let store = SegmentBlockStore::new(dir.path().join("store-fixed").as_path()).unwrap();

    assert_source_read(&chunk_open_file(&store, &file).unwrap_err());
    assert_source_read(
        &chunk_open_file_fixed_with_callback(&store, &file, |_, _: Arc<[u8]>| {}).unwrap_err(),
    );
    assert_source_read(
        &chunk_open_file_content_defined_with_callback(&store, &file, |_, _: Arc<[u8]>| {})
            .unwrap_err(),
    );
    for content_defined in [false, true] {
        let error = hash_open_file_blocks::<StorageError>(&file, content_defined, |_, _| Ok(()))
            .unwrap_err();
        assert_source_read(&error);
    }
}

/// A block-store fault keeps its own shape: only the source's reads are marked.
#[test]
fn a_sink_failure_is_not_marked_as_a_source_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f.bin");
    fs::write(&path, vec![7u8; 1000]).unwrap();
    let error = hash_file_blocks::<StorageError>(&path, false, |_, _| {
        Err(StorageError::Io(std::io::Error::other("sink")))
    })
    .unwrap_err();
    assert!(matches!(error, StorageError::Io(_)), "got {error:?}");
}
