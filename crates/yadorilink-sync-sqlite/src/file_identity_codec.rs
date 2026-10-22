use yadorilink_fs_platform::fs_identity::{
    FileIdentity, ObjectKind, PlatformObjectId, VolumeIdentity, WindowsObjectId,
};

use crate::error::SyncSqliteError;

/// Version stamp for this module's `FileIdentity` binary encoding -- stored
/// once per row (by `materialized_generation::record_materialized_generation`)
/// so a future layout change is detectable rather than silently misread. A
/// blob at an old version fails closed on decode (see
/// `decoding_an_unknown_encoding_version_fails_closed`) rather than being
/// reinterpreted -- delete and re-import rebuilds it.
pub const MATERIALIZED_GENERATION_ENCODING_VERSION: i32 = 3;

/// A materialized generation's own identity: minted fresh on every
/// `record_materialized_generation` call, never reused, never edited in
/// place. Opaque past that -- nothing compares two `GenerationId`s.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GenerationId(pub String);

fn object_kind_encoding_tag(k: ObjectKind) -> u8 {
    match k {
        ObjectKind::RegularFile => 0,
        ObjectKind::Directory => 1,
        ObjectKind::Symlink => 2,
        ObjectKind::Fifo => 3,
        ObjectKind::Socket => 4,
        ObjectKind::BlockDevice => 5,
        ObjectKind::CharDevice => 6,
        ObjectKind::ReparsePoint => 7,
        ObjectKind::Other => 8,
    }
}

fn object_kind_from_encoding_tag(tag: u8) -> Result<ObjectKind, SyncSqliteError> {
    match tag {
        0 => Ok(ObjectKind::RegularFile),
        1 => Ok(ObjectKind::Directory),
        2 => Ok(ObjectKind::Symlink),
        3 => Ok(ObjectKind::Fifo),
        4 => Ok(ObjectKind::Socket),
        5 => Ok(ObjectKind::BlockDevice),
        6 => Ok(ObjectKind::CharDevice),
        7 => Ok(ObjectKind::ReparsePoint),
        8 => Ok(ObjectKind::Other),
        other => Err(SyncSqliteError::CorruptState(format!(
            "unknown fs_identity::ObjectKind tag {other} in a stored filesystem_identity blob"
        ))),
    }
}

fn volume_identity_tag(v: VolumeIdentity) -> u8 {
    match v {
        VolumeIdentity::Unix { .. } => 0,
        VolumeIdentity::Windows { .. } => 1,
    }
}

fn platform_object_id_tag(o: PlatformObjectId) -> u8 {
    match o {
        PlatformObjectId::Unix { .. } => 0,
        PlatformObjectId::Windows(_) => 1,
    }
}

/// Sub-tag distinguishing `PlatformObjectId::Windows`'s two `WindowsObjectId`
/// cases -- only meaningful once `platform_object_id_tag` above is `1`.
fn windows_object_id_subtag(w: WindowsObjectId) -> u8 {
    match w {
        WindowsObjectId::Fallback { .. } => 0,
        WindowsObjectId::Proven { .. } => 1,
    }
}

/// The part of an identity that names *which* object it is -- volume and
/// object id -- without anything that describes its state or guards
/// against reuse. Two observations of one object always agree on it, so it
/// is what a lookup keyed by object (a directory that was renamed) seeks
/// on; whether a hit really is the same object is still
/// [`FileIdentity::compare`]'s question.
pub fn encode_object_address(identity: &FileIdentity) -> Vec<u8> {
    let mut buf = Vec::new();
    push_object_address(&mut buf, identity);
    buf
}

fn push_object_address(buf: &mut Vec<u8>, identity: &FileIdentity) {
    buf.push(volume_identity_tag(identity.volume_identity));
    match identity.volume_identity {
        VolumeIdentity::Unix { device_id } => buf.extend_from_slice(&device_id.to_be_bytes()),
        VolumeIdentity::Windows { volume_serial_number } => {
            buf.extend_from_slice(&volume_serial_number.to_be_bytes())
        }
    }
    buf.push(platform_object_id_tag(identity.object_id));
    match identity.object_id {
        PlatformObjectId::Unix { inode } => buf.extend_from_slice(&inode.to_be_bytes()),
        PlatformObjectId::Windows(w) => {
            buf.push(windows_object_id_subtag(w));
            match w {
                WindowsObjectId::Fallback { file_index } => {
                    buf.extend_from_slice(&file_index.to_be_bytes())
                }
                WindowsObjectId::Proven { file_id } => buf.extend_from_slice(&file_id),
            }
        }
    }
}

/// Encodes a [`FileIdentity`] as a versioned, self-describing byte blob.
/// Not content-addressed like `causal_basis`'s encoding: this is a direct
/// field encoding of one observation, not a hash naming a deduplicated set.
pub fn encode_file_identity(identity: &FileIdentity) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(MATERIALIZED_GENERATION_ENCODING_VERSION as u8);
    push_object_address(&mut buf, identity);
    buf.push(object_kind_encoding_tag(identity.object_kind));
    match identity.generation_or_usn {
        Some(g) => {
            buf.push(1);
            buf.extend_from_slice(&g.to_be_bytes());
        }
        None => buf.push(0),
    }
    match identity.birth_or_creation_time {
        Some(t) => {
            buf.push(1);
            buf.extend_from_slice(&t.seconds_since_unix_epoch.to_be_bytes());
            buf.extend_from_slice(&t.subsec_nanos.to_be_bytes());
        }
        None => buf.push(0),
    }
    buf.extend_from_slice(&identity.observed_size.to_be_bytes());
    buf.extend_from_slice(&identity.metadata_fingerprint);
    match identity.link_count {
        Some(l) => {
            buf.push(1);
            buf.extend_from_slice(&l.to_be_bytes());
        }
        None => buf.push(0),
    }
    match identity.symlink_target_digest {
        Some(d) => {
            buf.push(1);
            buf.extend_from_slice(&d);
        }
        None => buf.push(0),
    }
    buf
}

/// A minimal cursor over a byte slice for [`decode_file_identity`] --
/// errors on truncation rather than panicking, since this reads a stored
/// BLOB a future encoding-version mismatch or on-disk corruption could
/// have shortened.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], SyncSqliteError> {
        let end = self.pos.checked_add(n).ok_or_else(|| {
            SyncSqliteError::CorruptState("filesystem_identity blob length overflow".to_string())
        })?;
        let slice = self.buf.get(self.pos..end).ok_or_else(|| {
            SyncSqliteError::CorruptState("filesystem_identity blob truncated".to_string())
        })?;
        self.pos = end;
        Ok(slice)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, SyncSqliteError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, SyncSqliteError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, SyncSqliteError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub(crate) fn u128(&mut self) -> Result<u128, SyncSqliteError> {
        Ok(u128::from_be_bytes(self.take(16)?.try_into().unwrap()))
    }

    fn i64(&mut self) -> Result<i64, SyncSqliteError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub(crate) fn bool_flag(&mut self) -> Result<bool, SyncSqliteError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(SyncSqliteError::CorruptState(format!(
                "invalid boolean flag byte {other} in a stored filesystem_identity blob"
            ))),
        }
    }
}

pub fn decode_file_identity(blob: &[u8]) -> Result<FileIdentity, SyncSqliteError> {
    let mut r = Reader::new(blob);
    let encoding_version = r.u8()?;
    if encoding_version != MATERIALIZED_GENERATION_ENCODING_VERSION as u8 {
        return Err(SyncSqliteError::CorruptState(format!(
            "filesystem_identity blob encoding_version {encoding_version} is not this build's \
             {MATERIALIZED_GENERATION_ENCODING_VERSION}"
        )));
    }
    let volume_identity = match r.u8()? {
        0 => VolumeIdentity::Unix { device_id: r.u64()? },
        1 => VolumeIdentity::Windows { volume_serial_number: r.u64()? },
        other => {
            return Err(SyncSqliteError::CorruptState(format!(
                "unknown VolumeIdentity tag {other} in a stored filesystem_identity blob"
            )))
        }
    };
    let object_id = match r.u8()? {
        0 => PlatformObjectId::Unix { inode: r.u64()? },
        1 => match r.u8()? {
            0 => PlatformObjectId::Windows(WindowsObjectId::Fallback { file_index: r.u64()? }),
            1 => {
                let file_id: [u8; 16] =
                    r.take(16)?.try_into().expect("Reader::take(16) always returns 16 bytes");
                PlatformObjectId::Windows(WindowsObjectId::Proven { file_id })
            }
            other => {
                return Err(SyncSqliteError::CorruptState(format!(
                    "unknown WindowsObjectId subtag {other} in a stored filesystem_identity blob"
                )))
            }
        },
        other => {
            return Err(SyncSqliteError::CorruptState(format!(
                "unknown PlatformObjectId tag {other} in a stored filesystem_identity blob"
            )))
        }
    };
    let object_kind = object_kind_from_encoding_tag(r.u8()?)?;
    let generation_or_usn = if r.bool_flag()? { Some(r.u128()?) } else { None };
    let birth_or_creation_time = if r.bool_flag()? {
        let seconds_since_unix_epoch = r.i64()?;
        let subsec_nanos = r.u32()?;
        Some(yadorilink_fs_platform::fs_identity::Timestamp {
            seconds_since_unix_epoch,
            subsec_nanos,
        })
    } else {
        None
    };
    let observed_size = r.u64()?;
    let metadata_fingerprint: [u8; 32] =
        r.take(32)?.try_into().expect("Reader::take(32) always returns exactly 32 bytes");
    let link_count = if r.bool_flag()? { Some(r.u64()?) } else { None };
    let symlink_target_digest = if r.bool_flag()? {
        let bytes: [u8; 32] =
            r.take(32)?.try_into().expect("Reader::take(32) always returns exactly 32 bytes");
        Some(bytes)
    } else {
        None
    };
    Ok(FileIdentity {
        volume_identity,
        object_id,
        object_kind,
        generation_or_usn,
        birth_or_creation_time,
        observed_size,
        metadata_fingerprint,
        link_count,
        symlink_target_digest,
    })
}

#[cfg(test)]
mod tests;
