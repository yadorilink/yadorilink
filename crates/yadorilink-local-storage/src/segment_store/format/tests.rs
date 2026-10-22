#![cfg(test)]

use super::*;

#[test]
fn crc32_matches_known_vectors() {
    assert_eq!(crc32(b""), 0x0000_0000);
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414F_A339);
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
}
