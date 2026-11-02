#![cfg(test)]

use super::*;

/// Hand-builds a canonical `FileMeta` encoding directly (rather than going through `FileMeta`'s
/// own encoder, which cannot be asked to produce an invalid execute byte in the first place):
/// `record_kind` (`RecordKind::File` = 0), the execute byte, a fixed mtime, no symlink target.
fn encode_file_meta_bytes(exec_byte: u8) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0u8);
    buf.push(exec_byte);
    put_i64(&mut buf, 0);
    buf.push(0u8);
    buf
}

#[test]
fn decode_reads_the_execute_flag() {
    for (byte, exec) in [(0u8, false), (1u8, true)] {
        let bytes = encode_file_meta_bytes(byte);
        let meta = FileMeta::decode(&mut Reader::new(&bytes)).unwrap();
        assert_eq!(meta.exec, exec);
    }
}

/// The canonical encoding has one byte per flag value; anything else would give two encodings to
/// one meaning, so it is refused.
#[test]
fn decode_rejects_any_other_execute_byte() {
    for byte in [2u8, 0x7f, 0xff] {
        let bytes = encode_file_meta_bytes(byte);
        let err = FileMeta::decode(&mut Reader::new(&bytes)).unwrap_err();
        assert!(matches!(err, ChangeError::Encoding(_)), "{byte}: got {err:?}");
    }
}

#[test]
fn the_flag_round_trips_and_changes_the_hash() {
    let mut meta = FileMeta {
        mtime_unix_nanos: 1,
        exec: false,
        symlink_target: None,
        record_kind: RecordKind::File,
    };
    let plain = FileVersion::new(Vec::new(), 0, meta.clone());
    meta.exec = true;
    let executable = FileVersion::new(Vec::new(), 0, meta);
    assert_ne!(plain.version_hash, executable.version_hash);
    for version in [plain, executable] {
        let decoded = FileVersion::from_canonical_encoding(&version.canonical_encoding()).unwrap();
        assert_eq!(decoded, version);
    }
}
