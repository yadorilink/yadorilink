#![cfg(test)]

use super::*;

/// The input the reference vectors below were made from: `(i * 31 + 7) mod 251`.
fn reference_input(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
}

/// XXH3-64 (seed 0) as computed by the reference C implementation (xxHash 0.8.3, through its
/// Python binding), not by the crate under test: one vector for every length class XXH3 has its
/// own code path for (0, 1 to 3, 4 to 8, 9 to 16, 17 to 128, 129 to 240, over 240, over a stripe
/// block), on both sides of every boundary.
#[test]
fn checksum64_matches_the_reference_implementation() {
    const VECTORS: &[(usize, u64)] = &[
        (0, 0x2D06800538D394C2),
        (1, 0x4C5CCA45D0F4811F),
        (2, 0xA7E250C97710FF27),
        (3, 0x15F7093B173D005C),
        (4, 0xDCA012F95811B6B9),
        (5, 0xB290CAFC7B254345),
        (8, 0xDEC6A9A43575982E),
        (9, 0x15E553B97E27735D),
        (15, 0x66026768A0FE1A85),
        (16, 0xA7683B861E585AA6),
        (17, 0x637C1AA907698945),
        (31, 0x9A20D1569E8FF426),
        (32, 0xFB0A38FB3AF32306),
        (64, 0xA1688EF0A48A39D4),
        (127, 0x207564F9CA6034F8),
        (128, 0x6D0F64C82DDAAD27),
        (129, 0xEAF3FC97C05F44F3),
        (200, 0xF4B54CDC82F20685),
        (239, 0x1E645342FEBB13C1),
        (240, 0x22F28CBBFAF0447F),
        (241, 0x07525DBC14902C7F),
        (255, 0x3E64256196C9377B),
        (256, 0xA49B06AA88AB05E1),
        (257, 0x745AB87B9AE166E5),
        (1023, 0xFE4F1EAEDB87B59B),
        (1024, 0xE2898655DB7BC9EE),
        (1025, 0x134C652BA3D6FB9E),
        (4096, 0x04A1779C9E7DDCD7),
        (65536, 0x804C62B879E03431),
        (1_048_576, 0x95085E99FB411CBE),
    ];
    for (len, expected) in VECTORS {
        assert_eq!(checksum64(&reference_input(*len)), *expected, "length {len}");
    }
    assert_eq!(checksum64(b""), 0x2D06800538D394C2);
    assert_eq!(checksum64(b"abc"), 0x78AF5F94892F3950);
    assert_eq!(checksum64(b"123456789"), 0x72DCB18B67A17DFF);
    assert_eq!(checksum64(b"The quick brown fox jumps over the lazy dog"), 0xCE7D19A5418FB365);
}

/// The value depends on the bytes and not on where they sit in memory: the same contents at every
/// start alignment, and at lengths on both sides of every code path, give one value.
#[test]
fn checksum64_does_not_depend_on_alignment() {
    use rand::{RngExt, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x58_58_48_33);
    for case in 0..300 {
        let len = match case % 6 {
            0 => rng.random_range(0..17),
            1 => rng.random_range(17..129),
            2 => rng.random_range(129..241),
            3 => rng.random_range(241..2_048),
            4 => rng.random_range(2_048..70_000),
            _ => rng.random_range(0..300_000),
        };
        let mut content = vec![0u8; len];
        rng.fill(&mut content[..]);
        let expected = checksum64(&content);
        for offset in [1usize, 3, 7, 8, 15, 31, 63] {
            let mut shifted = vec![0u8; offset + len];
            shifted[offset..].copy_from_slice(&content);
            assert_eq!(checksum64(&shifted[offset..]), expected, "case {case}, offset {offset}");
        }
    }
}

/// Damage is seen: flipping any single bit of random contents of random lengths changes the value.
/// (A check that missed a flipped bit would let a record that rotted by one bit pass.)
#[test]
fn flipping_any_one_bit_changes_the_checksum() {
    use rand::{RngExt, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x00B1_7F11);
    for case in 0..400 {
        let len =
            if case % 20 == 0 { rng.random_range(1..70_000) } else { rng.random_range(1..600) };
        let mut data = vec![0u8; len];
        rng.fill(&mut data[..]);
        let before = checksum64(&data);
        let positions: Vec<usize> = if len * 8 <= 64 {
            (0..len * 8).collect()
        } else {
            (0..64).map(|_| rng.random_range(0..len * 8)).collect()
        };
        for bit in positions {
            data[bit / 8] ^= 1 << (bit % 8);
            assert_ne!(checksum64(&data), before, "case {case}, len {len}, bit {bit}");
            data[bit / 8] ^= 1 << (bit % 8);
        }
        assert_eq!(checksum64(&data), before, "restoring the bit restores the value");
    }
}

/// The record framing built on it sees a single flipped bit anywhere in a record: in the header
/// (rejected, never interpreted), in the payload, or in the trailer (the payload no longer matches).
#[test]
fn a_record_with_one_flipped_bit_is_noticed_wherever_the_bit_is() {
    use rand::{RngExt, SeedableRng};
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xFEED_0003);
    for case in 0..40 {
        let len = rng.random_range(1..3_000);
        let mut payload = vec![0u8; len];
        rng.fill(&mut payload[..]);
        let mut hash = [0u8; RAW_HASH_LEN];
        rng.fill(&mut hash[..]);
        let mut record = Vec::new();
        encode_record(&mut record, &hash, &payload);
        // Every bit of the header; one bit of every other byte, chosen at random.
        let bits: Vec<usize> = (0..record.len())
            .flat_map(|byte| {
                if byte < RECORD_HEADER_LEN {
                    (0..8).map(|bit| byte * 8 + bit).collect::<Vec<_>>()
                } else {
                    vec![byte * 8 + rng.random_range(0..8)]
                }
            })
            .collect();
        for bit in bits {
            let mut damaged = record.clone();
            damaged[bit / 8] ^= 1 << (bit % 8);
            if bit / 8 < RECORD_HEADER_LEN {
                assert!(
                    decode_record_header(&damaged, damaged.len() as u64).is_err(),
                    "case {case}: a flipped header bit {bit} was interpreted"
                );
            } else {
                let payload_end = RECORD_HEADER_LEN + len;
                assert!(
                    !payload_checksum_matches(
                        &damaged[RECORD_HEADER_LEN..payload_end],
                        &damaged[payload_end..]
                    ),
                    "case {case}: a flipped bit {bit} of the payload or trailer went unnoticed"
                );
            }
        }
    }
}

#[test]
fn a_round_tripped_record_reports_its_own_geometry() {
    let hash = [7u8; RAW_HASH_LEN];
    let mut buf = Vec::new();
    encode_record(&mut buf, &hash, b"payload bytes");
    assert_eq!(buf.len() as u64, record_len(13));

    let header = decode_record_header(&buf, buf.len() as u64).unwrap();
    assert_eq!(header.hash, hash);
    assert_eq!(header.payload_len, 13);
    assert_eq!(header.record_len(), buf.len() as u64);
    let payload = &buf[RECORD_HEADER_LEN..RECORD_HEADER_LEN + 13];
    assert!(payload_checksum_matches(payload, &buf[RECORD_HEADER_LEN + 13..]));
}

/// The property recovery depends on: a header whose bytes were only
/// partly written must be *rejected*, never interpreted. If a torn
/// header could still yield a `payload_len`, recovery would skip a
/// record-sized distance chosen by garbage.
#[test]
fn a_torn_header_is_rejected_rather_than_interpreted() {
    let mut buf = Vec::new();
    encode_record(&mut buf, &[3u8; RAW_HASH_LEN], b"x");
    for cut in 1..RECORD_HEADER_LEN {
        let partial = &buf[..cut];
        assert_eq!(
            decode_record_header(partial, partial.len() as u64),
            Err(HeaderReject::Truncated),
            "a {cut}-byte header prefix must not decode"
        );
    }
    // A header whose length field alone was corrupted after the fact.
    let mut damaged = buf.clone();
    damaged[40] ^= 0xFF;
    assert_eq!(
        decode_record_header(&damaged, damaged.len() as u64),
        Err(HeaderReject::BadChecksum)
    );
    // Unwritten tail bytes: all zero, so no magic.
    let zeros = vec![0u8; RECORD_HEADER_LEN];
    assert_eq!(decode_record_header(&zeros, zeros.len() as u64), Err(HeaderReject::BadMagic));
}

#[test]
fn a_header_claiming_more_than_the_file_holds_is_rejected() {
    let mut buf = Vec::new();
    encode_record(&mut buf, &[1u8; RAW_HASH_LEN], b"0123456789");
    assert_eq!(
        decode_record_header(&buf, buf.len() as u64 - 1),
        Err(HeaderReject::LengthOverrunsFile)
    );
}

#[test]
fn segment_headers_round_trip_and_reject_foreign_files() {
    let header = encode_segment_header(42);
    assert_eq!(decode_segment_header(&header).unwrap(), 42);

    let mut foreign = header;
    foreign[0] ^= 0xFF;
    assert!(matches!(decode_segment_header(&foreign), Err(StorageError::CorruptStore(_))));

    let mut future = header;
    future[4..6].copy_from_slice(&999u16.to_le_bytes());
    assert!(matches!(decode_segment_header(&future), Err(StorageError::CorruptStore(_))));

    // A segment of the previous layout (CRC-32 records) is refused, not read.
    let mut previous = header;
    previous[4..6].copy_from_slice(&1u16.to_le_bytes());
    let refused = decode_segment_header(&previous).unwrap_err().to_string();
    assert!(refused.contains("v1") && refused.contains("v2"), "{refused}");
}
