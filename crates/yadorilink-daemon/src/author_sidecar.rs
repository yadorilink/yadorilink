//! The `<replica db>.instance` sidecar: the database instance nonce and the
//! author incarnation of the record it was written for
//! ([`InstanceSidecar`]).
//!
//! Format: a 4-byte magic, a 1-byte format version, then 32 bytes
//! (`db_instance_nonce` ‖ `incarnation`). A write goes to a temp file of its
//! own (unique per process and write), which is fsynced and renamed over the
//! sidecar, and then the directory is fsynced (on Unix), so a reader sees
//! either the old or the new sidecar, never a torn one, even if two writes
//! overlap.
//!
//! A sidecar that is absent or malformed reads as `None`: the incarnation
//! check then treats the database as restored and rotates, which is the
//! safe outcome. The sidecar is only ever compared with the database's
//! record, never read into it.

use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use yadorilink_replica_domain::author::IncarnationId;
use yadorilink_sync_sqlite::author_incarnation::InstanceSidecar;

const MAGIC: [u8; 4] = *b"YLIS";
const FORMAT_VERSION: u8 = 1;
const LEN: usize = MAGIC.len() + 1 + 16 + 16;

/// `<db_path>.instance`.
pub fn sidecar_path(db_path: &Path) -> PathBuf {
    let mut name = OsString::from(db_path.as_os_str());
    name.push(".instance");
    PathBuf::from(name)
}

/// `<db_path>.instance.<pid>.<random>.tmp`: no two writes share a temp
/// file, so one write's rename never publishes another's partial file.
fn temp_path(db_path: &Path) -> PathBuf {
    let mut name = OsString::from(sidecar_path(db_path).as_os_str());
    name.push(format!(".{}.{}.tmp", std::process::id(), uuid::Uuid::new_v4().simple()));
    PathBuf::from(name)
}

fn encode(sidecar: &InstanceSidecar) -> [u8; LEN] {
    let mut bytes = [0u8; LEN];
    bytes[..4].copy_from_slice(&MAGIC);
    bytes[4] = FORMAT_VERSION;
    bytes[5..21].copy_from_slice(&sidecar.db_instance_nonce);
    bytes[21..].copy_from_slice(&sidecar.incarnation.0);
    bytes
}

fn decode(bytes: &[u8]) -> Option<InstanceSidecar> {
    if bytes.len() != LEN || bytes[..4] != MAGIC || bytes[4] != FORMAT_VERSION {
        return None;
    }
    Some(InstanceSidecar {
        db_instance_nonce: bytes[5..21].try_into().ok()?,
        incarnation: IncarnationId(bytes[21..].try_into().ok()?),
    })
}

/// The sidecar beside `db_path`: `None` when it is absent or malformed. An
/// I/O error other than absence is returned, so the open fails closed.
pub fn read_sidecar(db_path: &Path) -> io::Result<Option<InstanceSidecar>> {
    let path = sidecar_path(db_path);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let sidecar = decode(&bytes);
    if sidecar.is_none() {
        tracing::warn!(path = %path.display(), "the replica instance sidecar is malformed");
    }
    Ok(sidecar)
}

/// Durably replaces the sidecar beside `db_path` with `sidecar`: temp file,
/// fsync, then a durable move over the old one. Returns only once the new
/// sidecar is durable.
pub fn write_sidecar(db_path: &Path, sidecar: &InstanceSidecar) -> io::Result<()> {
    let temp = temp_path(db_path);
    let written = (|| {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&temp)?;
        file.write_all(&encode(sidecar))?;
        yadorilink_fs_platform::flush::sync_file(&file)?;
        drop(file);
        yadorilink_fs_platform::durable_dir::publish_durably(
            &temp,
            &sidecar_path(db_path),
            yadorilink_fs_platform::durable_dir::Replace::Yes,
        )
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(byte: u8) -> InstanceSidecar {
        InstanceSidecar {
            db_instance_nonce: [byte; 16],
            incarnation: IncarnationId([byte.wrapping_add(1); 16]),
        }
    }

    #[test]
    fn the_sidecar_sits_beside_the_database() {
        assert_eq!(
            sidecar_path(Path::new("/a/b/replica.sqlite")),
            PathBuf::from("/a/b/replica.sqlite.instance")
        );
    }

    #[test]
    fn a_written_sidecar_reads_back_and_an_absent_one_is_none() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("replica.sqlite");
        assert_eq!(read_sidecar(&db).unwrap(), None);
        write_sidecar(&db, &sample(1)).unwrap();
        assert_eq!(read_sidecar(&db).unwrap(), Some(sample(1)));
        let bytes = fs::read(sidecar_path(&db)).unwrap();
        assert_eq!(bytes.len(), 37);
        assert_eq!(&bytes[..5], b"YLIS\x01");
    }

    /// A rewrite replaces the whole file and leaves no temp file behind; a
    /// temp file left by a crashed write is ignored by the reader and
    /// replaced by the next write.
    #[test]
    fn a_rewrite_is_atomic_and_a_crashed_temp_file_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("replica.sqlite");
        write_sidecar(&db, &sample(1)).unwrap();
        // A crash after writing the temp file, before the rename.
        let crashed = temp_path(&db);
        fs::write(&crashed, b"torn").unwrap();
        assert_eq!(read_sidecar(&db).unwrap(), Some(sample(1)));
        write_sidecar(&db, &sample(7)).unwrap();
        assert_eq!(read_sidecar(&db).unwrap(), Some(sample(7)));
        let mut left: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "tmp"))
            .collect();
        left.sort();
        assert_eq!(left, vec![crashed]);
    }

    #[test]
    fn every_write_uses_its_own_temp_file() {
        let db = Path::new("/a/replica.sqlite");
        let (one, two) = (temp_path(db), temp_path(db));
        assert_ne!(one, two);
        for temp in [one, two] {
            let name = temp.file_name().unwrap().to_string_lossy().into_owned();
            assert!(name.starts_with("replica.sqlite.instance."), "{name}");
            assert!(name.ends_with(".tmp"), "{name}");
        }
    }

    /// A failed write leaves no temp file behind.
    #[test]
    fn a_failed_write_removes_its_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("replica.sqlite");
        fs::create_dir(sidecar_path(&db)).unwrap();
        assert!(write_sidecar(&db, &sample(1)).is_err());
        let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn a_malformed_sidecar_reads_as_absent() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("replica.sqlite");
        let good = encode(&sample(3));
        let mut bad_magic = good;
        bad_magic[0] ^= 1;
        let mut bad_version = good;
        bad_version[4] = 2;
        for bytes in [&good[..36], &bad_magic[..], &bad_version[..], &[][..]] {
            fs::write(sidecar_path(&db), bytes).unwrap();
            assert_eq!(read_sidecar(&db).unwrap(), None);
        }
        let mut long = good.to_vec();
        long.push(0);
        fs::write(sidecar_path(&db), long).unwrap();
        assert_eq!(read_sidecar(&db).unwrap(), None);
    }
}
