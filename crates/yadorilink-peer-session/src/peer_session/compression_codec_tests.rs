#![cfg(test)]

use super::{compress_block, decompress_block};

/// adaptive-skip heuristic: uniformly random bytes have no
/// exploitable redundancy, so a zstd level-3 pass shouldn't beat the
/// documented 95% threshold — the sender must fall back to raw rather
/// than pay for a compressed form that isn't meaningfully smaller.
#[test]
fn incompressible_random_bytes_are_sent_raw() {
    // A simple xorshift PRNG is enough here — no external `rand`
    // dependency needed just to get high-entropy bytes for this test.
    let mut state: u64 = 0x9E3779B97F4A7C15;
    let data: Vec<u8> = (0..64 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state & 0xFF) as u8
        })
        .collect();

    let (out, compression) = compress_block(&data);

    assert_eq!(compression, yadorilink_sync_wire::COMPRESSION_NONE);
    assert_eq!(out, data, "raw fallback must return the original bytes unchanged");
}

/// Already-zstd-compressed content is itself close to incompressible
/// (compressed bytes look like high-entropy noise to a second pass) —
/// matching the design's "already-compressed content is sent raw, spending
/// only the one cheap trial-compression pass."
#[test]
fn already_compressed_bytes_are_sent_raw() {
    let source = b"the quick brown fox jumps over the lazy dog ".repeat(500);
    let already_compressed = zstd::stream::encode_all(source.as_slice(), 19).unwrap();

    let (out, compression) = compress_block(&already_compressed);

    assert_eq!(compression, yadorilink_sync_wire::COMPRESSION_NONE);
    assert_eq!(out, already_compressed);
}

/// The positive case: highly repetitive synthetic text (the shape of
/// real source-tree/log/DB-dump content this feature targets) compresses
/// well past the 95% threshold and must be sent compressed.
#[test]
fn highly_repetitive_text_is_compressed() {
    let data = "the quick brown fox jumps over the lazy dog\n".repeat(10_000);

    let (out, compression) = compress_block(data.as_bytes());

    assert_eq!(compression, yadorilink_sync_wire::COMPRESSION_ZSTD);
    assert!(
        out.len() < data.len() / 10,
        "highly repetitive text should compress to well under 10% of its raw size, got \
         {} of {} bytes",
        out.len(),
        data.len()
    );
}

/// Empty input is never worth compressing (zstd's own frame overhead
/// alone would make a compressed form larger than nothing).
#[test]
fn empty_input_is_sent_raw() {
    let (out, compression) = compress_block(&[]);
    assert_eq!(compression, yadorilink_sync_wire::COMPRESSION_NONE);
    assert!(out.is_empty());
}

/// Round trip: whatever `compress_block` decides to do, `decompress_block`
/// must recover the exact original bytes.
#[test]
fn compress_then_decompress_round_trips_exactly() {
    let data = "abcdefgh".repeat(20_000);
    let (out, compression) = compress_block(data.as_bytes());
    assert_eq!(
        compression,
        yadorilink_sync_wire::COMPRESSION_ZSTD,
        "sanity: this input must compress"
    );

    let recovered = decompress_block(&out, compression, 10 * 1024 * 1024).unwrap();
    assert_eq!(recovered, data.as_bytes());
}

/// `Compression::None` is a pure passthrough — the byte-identity path
/// every pre-this-change / negotiation-declined block/index message
/// takes.
#[test]
fn none_compression_is_a_passthrough() {
    let data = b"uncompressed content".to_vec();
    let recovered = decompress_block(&data, yadorilink_sync_wire::COMPRESSION_NONE, 4).unwrap();
    assert_eq!(recovered, data, "None must pass bytes through even past `max_size`");
}

/// The decompression-bomb bound: a small
/// compressed payload that *claims* to expand far past `max_size` must
/// be rejected, not decompressed into memory. Compresses 64 MiB of
/// zeros (a classic zstd bomb shape — trivially compressible) down to
/// a few hundred bytes, then asks `decompress_block` to bound it to a
/// 1 KiB ceiling. If this function fully materialized the claimed
/// output before checking the size, this test would need ~64 MiB and
/// noticeable wall-clock time to complete; instead it must return an
/// error promptly, having never buffered more than `max_size + 1`
/// bytes (the `Read::take` bound baked into the implementation).
#[test]
fn decompression_bomb_is_rejected_without_materializing_the_full_output() {
    // Level 3 (not a high level) is enough: all-zero input compresses
    // to a tiny fraction of its size at any level, and keeping this
    // fast avoids adding CPU load to the suite under parallel test
    // execution.
    let huge_zeros = vec![0u8; 64 * 1024 * 1024];
    let bomb = zstd::stream::encode_all(huge_zeros.as_slice(), 3).unwrap();
    assert!(
        bomb.len() < 8192,
        "sanity: the bomb payload itself must be tiny relative to its claimed output"
    );
    drop(huge_zeros);

    let max_size = 1024;
    let start = std::time::Instant::now();
    let result = decompress_block(&bomb, yadorilink_sync_wire::COMPRESSION_ZSTD, max_size);
    let elapsed = start.elapsed();

    assert!(result.is_err(), "a payload exceeding max_size must be rejected, not accepted");
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "bounded decompression must not spend time producing megabytes of output it will \
         discard; took {elapsed:?}"
    );
}

/// A payload that is not valid zstd at all (never decompressed
/// successfully by any peer, honest or not) must also be rejected
/// cleanly rather than panicking.
#[test]
fn corrupt_non_zstd_payload_is_rejected() {
    let garbage = vec![0xFFu8; 128];
    let result = decompress_block(&garbage, yadorilink_sync_wire::COMPRESSION_ZSTD, 1024 * 1024);
    assert!(result.is_err());
}

/// A payload that decompresses to exactly `max_size` bytes (not one
/// byte over) must be accepted — the bound is inclusive, matching
/// `MAX_BLOCK_SIZE`'s own role as an upper bound on legitimate block
/// content.
#[test]
fn decompressed_size_exactly_at_the_bound_is_accepted() {
    let data = vec![0x7Au8; 1024];
    let compressed = zstd::stream::encode_all(data.as_slice(), 3).unwrap();
    let recovered =
        decompress_block(&compressed, yadorilink_sync_wire::COMPRESSION_ZSTD, 1024).unwrap();
    assert_eq!(recovered, data);
}
