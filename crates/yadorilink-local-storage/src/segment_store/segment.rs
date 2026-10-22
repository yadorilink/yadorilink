//! Segment files: creation, sequential append, the one durability barrier
//! a group commit issues, and positional reads that take no store-wide
//! lock.
//!
//! A segment is immutable below its `durable_end` and append-only above
//! it, which is what lets a reader `pread` any index-covered range
//! concurrently with the writer extending the same file -- no lock, no
//! copy of the store's state, no coordination with the commit path at all.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::StorageError;
use crate::io_diag::{self, Op};
use crate::segment_store::format::{
    decode_record_header, decode_segment_header, encode_segment_header, payload_checksum_matches,
    HeaderReject, RecordHeader, RAW_HASH_LEN, RECORD_HEADER_LEN, RECORD_TRAILER_LEN,
    SEGMENT_HEADER_LEN,
};
use crate::segment_store::index::BlockLocation;

/// Subdirectory of the store root holding every segment file.
pub(crate) const SEGMENTS_DIR: &str = "segments";

/// `segments/0000000000000007.seg`. Zero-padded so a directory listing
/// sorts in id order, which is also append order.
pub(crate) fn segment_path(root: &Path, segment_id: u64) -> PathBuf {
    root.join(SEGMENTS_DIR).join(format!("{segment_id:016}.seg"))
}

/// The reserved Stage name a segment is created under before it is published:
/// `.yadorilink-v1-stage.seg-<id>` beside `<id>.seg`.
pub(crate) fn stage_path(root: &Path, segment_id: u64) -> Result<PathBuf, StorageError> {
    let name = yadorilink_fs_platform::reserved_namespace::artefact_component_name(
        yadorilink_fs_platform::reserved_namespace::ArtefactKind::Stage,
        &format!("seg-{segment_id:016}"),
    )
    .map_err(|error| StorageError::InvalidPath(error.to_string()))?;
    Ok(root.join(SEGMENTS_DIR).join(name))
}

/// The id of the segment a Stage name was made for, or `None` for any other
/// entry.
pub(crate) fn segment_id_from_stage_name(name: &str) -> Option<u64> {
    use yadorilink_fs_platform::reserved_namespace::{parse_artefact_component, ArtefactKind};
    let (ArtefactKind::Stage, id) = parse_artefact_component(name)? else { return None };
    let digits = id.strip_prefix("seg-")?;
    if digits.len() != 16 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The id encoded in a segment file's name, or `None` for any other entry.
pub(crate) fn segment_id_from_file_name(name: &str) -> Option<u64> {
    let digits = name.strip_suffix(".seg")?;
    if digits.len() != 16 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// A segment under its Stage name: complete header, flushed, not yet visible
/// under its own name.
pub(crate) struct StagedSegment {
    segment_id: u64,
    file: File,
    stage: PathBuf,
}

impl StagedSegment {
    /// Publishes the segment under its own name by a durable move that refuses
    /// an occupied name; the file stays open and keeps appending.
    pub(crate) fn publish(
        self,
        ns: &yadorilink_fs_platform::durable_dir::DurableNamespace,
    ) -> Result<SegmentWriter, StorageError> {
        let target = self.stage.with_file_name(format!("{:016}.seg", self.segment_id));
        ns.publish(
            &self.stage,
            &target,
            yadorilink_fs_platform::durable_dir::Replace::No,
            &yadorilink_fs_platform::durable_dir::NoLedger,
        )
        .map_err(|error| StorageError::Io(error.into()))?;
        Ok(SegmentWriter {
            segment_id: self.segment_id,
            file: self.file,
            write_end: SEGMENT_HEADER_LEN,
        })
    }
}

/// An open segment this store appends to.
pub(crate) struct SegmentWriter {
    pub(crate) segment_id: u64,
    file: File,
    /// Bytes handed to the kernel for this file. Ahead of the index's
    /// `durable_end` exactly between an append and the transaction that
    /// records it.
    write_end: u64,
}

impl SegmentWriter {
    /// Creates a brand-new segment file and writes its header. Issues no
    /// durability barrier of its own: the caller publishes the new
    /// directory entry (one `fsync` of `segments/`) and the file's
    /// contents (one `fsync` of the file) on its own schedule, which is
    /// what keeps both costs per-group rather than per-segment-per-block.
    pub(crate) fn create(root: &Path, segment_id: u64) -> Result<Self, StorageError> {
        let path = segment_path(root, segment_id);
        let mut file = io_diag::time(Op::SegmentCreate, 0, || {
            OpenOptions::new().write(true).read(true).create_new(true).open(&path)
        })?;
        let header = encode_segment_header(segment_id);
        file.write_all(&header)?;
        Ok(Self { segment_id, file, write_end: SEGMENT_HEADER_LEN })
    }

    /// Creates a brand-new segment under a reserved Stage name beside its final
    /// one, writes its header and flushes it. Nothing is visible under the
    /// segment's own name until [`StagedSegment::publish`].
    ///
    /// The Stage name is fixed by the segment id, so a crash that leaves it is
    /// told apart by the same rule as any other segment file no committed
    /// transaction mentions: nothing refers to it.
    pub(crate) fn stage(root: &Path, segment_id: u64) -> Result<StagedSegment, StorageError> {
        let path = stage_path(root, segment_id)?;
        let mut file = io_diag::time(Op::SegmentCreate, 0, || {
            OpenOptions::new().write(true).read(true).create_new(true).open(&path)
        })?;
        file.write_all(&encode_segment_header(segment_id))?;
        file.sync_all()?;
        Ok(StagedSegment { segment_id, file, stage: path })
    }

    /// Reopens an existing segment for further appends, positioned at
    /// `write_end` (which recovery has already proven is where the durable
    ///, index-covered content ends).
    pub(crate) fn reopen(
        root: &Path,
        segment_id: u64,
        write_end: u64,
    ) -> Result<Self, StorageError> {
        let path = segment_path(root, segment_id);
        let file = OpenOptions::new().write(true).read(true).open(path)?;
        Ok(Self { segment_id, file, write_end })
    }

    pub(crate) fn write_end(&self) -> u64 {
        self.write_end
    }

    /// Appends a whole group's records at the current end, writing each
    /// payload straight out of the caller's own buffer.
    ///
    /// Not one `write` per record and not one giant `write` for the group.
    /// Per record would put a syscall on every tiny block, which is the
    /// cost this store exists to remove. One giant write means first
    /// copying every payload into an intermediate buffer -- for a batch of
    /// 8 MiB blocks that is a few hundred megabytes of allocation, page
    /// faults and `memcpy` per group, and it measured as a real 1.6x
    /// penalty against the file-per-block shape on a 1 GiB corpus.
    ///
    /// Vectored writes give both: the kernel is handed pointers to the
    /// headers, the caller's payloads and the trailers, so no payload is
    /// copied, and the calls are batched to a bounded number of bytes and
    /// segments each, so neither a million tiny blocks nor a
    /// quarter-gigabyte batch turns into a pathological single call.
    pub(crate) fn append_frames(&mut self, frames: &[RecordFrame<'_>]) -> Result<(), StorageError> {
        if frames.is_empty() {
            return Ok(());
        }
        let total: u64 = frames.iter().map(|frame| frame.len()).sum();
        io_diag::time(Op::SegmentAppend, total, || -> std::io::Result<()> {
            let mut offset = self.write_end;
            let mut batch: Vec<&[u8]> = Vec::new();
            let mut batch_bytes = 0u64;
            for frame in frames {
                batch.push(&frame.header);
                batch.push(frame.payload);
                batch.push(&frame.trailer);
                batch_bytes += frame.len();
                if batch.len() + 3 > MAX_WRITE_SEGMENTS || batch_bytes >= WRITE_CHUNK_BYTES {
                    write_all_vectored_at(&self.file, &batch, offset)?;
                    offset += batch_bytes;
                    batch.clear();
                    batch_bytes = 0;
                }
            }
            write_all_vectored_at(&self.file, &batch, offset)?;
            Ok(())
        })?;
        self.write_end += total;
        Ok(())
    }

    /// Writes only the first `bytes` of `frames` and stops -- the shape a
    /// crash mid-append leaves on disk. Only the crash-injection seam
    /// calls this; see `segment_store::fault`.
    pub(crate) fn append_partial_frames_for_tests(
        &mut self,
        frames: &[RecordFrame<'_>],
        bytes: usize,
    ) -> Result<(), StorageError> {
        let mut left = bytes as u64;
        let mut offset = self.write_end;
        for frame in frames {
            for piece in [&frame.header[..], frame.payload, &frame.trailer[..]] {
                if left == 0 {
                    self.write_end = offset;
                    return Ok(());
                }
                let take = (left as usize).min(piece.len());
                write_all_vectored_at(&self.file, &[&piece[..take]], offset)?;
                offset += take as u64;
                left -= take as u64;
            }
        }
        self.write_end = offset;
        Ok(())
    }

    /// The group's single durability barrier. `sync_data` rather than
    /// `sync_all`: a segment's metadata that matters (its size) is
    /// data-integrity metadata, which `fdatasync` covers, and its
    /// directory entry is published separately, once per segment.
    pub(crate) fn sync(&self) -> Result<(), StorageError> {
        io_diag::time(Op::SegmentFsync, 0, || self.file.sync_data())?;
        Ok(())
    }

    /// Discards everything written past `len`, returning the writer to a
    /// state where its next append lands exactly at the index's
    /// `durable_end`. Used on the error path of a group commit and by
    /// startup recovery.
    /// Whether `judge` accepts the volume this open file is on (see
    /// [`yadorilink_fs_platform::durable_dir::judge_open_file`]).
    pub(crate) fn judge_volume(&self, path: &Path, judge: impl FnOnce(&Path) -> bool) -> bool {
        yadorilink_fs_platform::durable_dir::judge_open_file(&self.file, path, judge).is_ok()
    }

    pub(crate) fn truncate(&mut self, len: u64) -> Result<(), StorageError> {
        self.file.set_len(len)?;
        self.file.sync_data()?;
        self.write_end = len;
        Ok(())
    }
}

/// One record's bytes, as three pieces -- so the payload is never copied
/// on its way to the kernel. The header and trailer are tiny and owned;
/// the payload is borrowed from whoever is committing the block.
pub(crate) struct RecordFrame<'a> {
    pub(crate) header: [u8; RECORD_HEADER_LEN],
    pub(crate) payload: &'a [u8],
    pub(crate) trailer: [u8; RECORD_TRAILER_LEN],
}

impl<'a> RecordFrame<'a> {
    pub(crate) fn new(hash: &[u8; RAW_HASH_LEN], payload: &'a [u8]) -> Self {
        Self {
            header: crate::segment_store::format::frame_header(hash, payload.len() as u32),
            payload,
            trailer: crate::segment_store::format::frame_trailer(payload),
        }
    }

    pub(crate) fn len(&self) -> u64 {
        (RECORD_HEADER_LEN + self.payload.len() + RECORD_TRAILER_LEN) as u64
    }
}

/// Bytes one vectored write call carries at most. Bounded so a group of
/// large blocks does not become a single quarter-gigabyte call.
const WRITE_CHUNK_BYTES: u64 = 4 * 1024 * 1024;
/// Buffer segments one vectored write call carries at most. `IOV_MAX` is
/// 1024 on Linux and the same or larger elsewhere; staying under it means
/// the call never has to be split by the kernel.
const MAX_WRITE_SEGMENTS: usize = 1020;

/// Writes every buffer in `pieces`, in order, starting at `offset`,
/// without touching the file cursor. Handles a short write by resuming
/// from exactly where the kernel stopped.
fn write_all_vectored_at(file: &File, pieces: &[&[u8]], offset: u64) -> std::io::Result<()> {
    let mut slices: Vec<std::io::IoSlice<'_>> = pieces
        .iter()
        .filter(|piece| !piece.is_empty())
        .map(|piece| std::io::IoSlice::new(piece))
        .collect();
    let mut offset = offset;
    let mut cursor = 0usize;
    while cursor < slices.len() {
        let written = write_vectored_at(file, &slices[cursor..], offset)?;
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "the segment accepted no bytes",
            ));
        }
        offset += written as u64;
        let mut remaining = written;
        while cursor < slices.len() && remaining >= slices[cursor].len() {
            remaining -= slices[cursor].len();
            cursor += 1;
        }
        if remaining > 0 && cursor < slices.len() {
            // A partial buffer: re-point it past the bytes that landed.
            // Safe because the borrow is reconstructed from the same
            // original slice, just shorter.
            let piece = pieces.iter().filter(|p| !p.is_empty()).nth(cursor).expect("in range");
            slices[cursor] = std::io::IoSlice::new(&piece[remaining..]);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn write_vectored_at(
    file: &File,
    slices: &[std::io::IoSlice<'_>],
    offset: u64,
) -> std::io::Result<usize> {
    use std::os::fd::AsRawFd;
    let count = slices.len().min(MAX_WRITE_SEGMENTS) as libc::c_int;
    // SAFETY: `slices` is a valid, live slice of `IoSlice`, which is
    // documented to be ABI-compatible with `struct iovec`; `count` is
    // within its length; `file` owns a valid descriptor for the call.
    let written = unsafe {
        libc::pwritev(
            file.as_raw_fd(),
            slices.as_ptr().cast::<libc::iovec>(),
            count,
            offset as libc::off_t,
        )
    };
    if written < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(written as usize)
}

#[cfg(windows)]
fn write_vectored_at(
    file: &File,
    slices: &[std::io::IoSlice<'_>],
    offset: u64,
) -> std::io::Result<usize> {
    // Windows has no positional vectored write, so one buffer per call.
    // The batching above still bounds how much each call carries.
    use std::os::windows::fs::FileExt;
    match slices.first() {
        Some(first) => file.seek_write(first, offset),
        None => Ok(0),
    }
}

/// Reads exactly `buf.len()` bytes at `offset`, without disturbing any
/// file cursor -- safe to call concurrently on one handle from many
/// threads, which is why block reads need no lock.
pub(crate) fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_exact_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut filled = 0;
        while filled < buf.len() {
            match file.seek_read(&mut buf[filled..], offset + filled as u64) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "segment ended before the requested range",
                    ))
                }
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Why a record could not be read back from a segment. Every variant means
/// the same thing to the caller -- this mapping is gone and the block must
/// be re-fetched -- but they are reported apart because "the file is
/// missing" and "a payload bit flipped" are different incidents.
#[derive(Debug)]
pub(crate) enum RecordReadError {
    /// The segment file itself is absent or shorter than the index says.
    SegmentUnavailable(StorageError),
    /// The record's framing did not validate where the index said it was.
    FramingInvalid(String),
    /// The record's header named a different block than the index did.
    HashMismatch,
    /// The payload did not match its own checksum.
    PayloadCorrupt,
    /// Genuine I/O failure -- not evidence about the content either way.
    Io(StorageError),
}

impl RecordReadError {
    /// What to record about this failure. Carrying the underlying error's
    /// own words matters: "the file ended early" and "no record header at
    /// the indexed offset" point at different faults, and a caller reading
    /// the log is the only one who can tell them apart.
    pub(crate) fn reason(&self) -> String {
        match self {
            RecordReadError::SegmentUnavailable(error) => {
                format!("segment unreadable: {error}")
            }
            RecordReadError::FramingInvalid(detail) => detail.clone(),
            RecordReadError::HashMismatch => {
                "the record at the indexed offset names a different block".into()
            }
            RecordReadError::PayloadCorrupt => "payload failed its own checksum".into(),
            RecordReadError::Io(error) => format!("i/o error: {error}"),
        }
    }
}

/// Reads one record's payload, validating the framing around it against
/// what the index claimed. Does **not** verify the SHA-256 content hash:
/// that is the caller's decision (`get` does, `get_unchecked` does not),
/// and keeping it out of here is what makes the two a single code path
/// with one deliberate difference.
pub(crate) fn read_record_payload(
    file: &File,
    location: &BlockLocation,
    expected_hash: &[u8; RAW_HASH_LEN],
) -> Result<Vec<u8>, RecordReadError> {
    let mut header_bytes = [0u8; RECORD_HEADER_LEN];
    read_exact_at(file, &mut header_bytes, location.record_offset).map_err(map_read_error)?;
    let header: RecordHeader =
        decode_record_header(&header_bytes, u64::MAX).map_err(|reject| match reject {
            HeaderReject::Truncated | HeaderReject::LengthOverrunsFile => {
                RecordReadError::FramingInvalid("record header is truncated".into())
            }
            HeaderReject::BadMagic => {
                RecordReadError::FramingInvalid("no record header at the indexed offset".into())
            }
            HeaderReject::BadChecksum => {
                RecordReadError::FramingInvalid("record header checksum mismatch".into())
            }
        })?;
    if &header.hash != expected_hash {
        return Err(RecordReadError::HashMismatch);
    }
    if header.payload_len != location.length {
        return Err(RecordReadError::FramingInvalid(format!(
            "record declares {} payload bytes where the index recorded {}",
            header.payload_len, location.length
        )));
    }

    let mut payload = vec![0u8; header.payload_len as usize];
    read_exact_at(file, &mut payload, location.payload_offset()).map_err(map_read_error)?;
    let mut trailer = [0u8; RECORD_TRAILER_LEN];
    read_exact_at(file, &mut trailer, location.payload_offset() + u64::from(header.payload_len))
        .map_err(map_read_error)?;
    if !payload_checksum_matches(&payload, &trailer) {
        return Err(RecordReadError::PayloadCorrupt);
    }
    Ok(payload)
}

fn map_read_error(error: std::io::Error) -> RecordReadError {
    match error.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::UnexpectedEof => {
            RecordReadError::SegmentUnavailable(StorageError::Io(error))
        }
        _ => RecordReadError::Io(StorageError::Io(error)),
    }
}

/// Walks a segment's records from its header to the first byte that does
/// not begin a complete, self-consistent record, reporting where that is
/// and what each valid record claimed.
///
/// This is the offline path -- `fsck` and index rebuild -- and the tail
/// classifier recovery uses on the one segment that was open at the crash.
/// The normal startup path never calls it.
pub(crate) fn scan_segment_records(
    file: &File,
    file_len: u64,
) -> Result<ScannedSegment, StorageError> {
    let mut header_bytes = [0u8; SEGMENT_HEADER_LEN as usize];
    read_exact_at(file, &mut header_bytes, 0)
        .map_err(|e| StorageError::CorruptStore(format!("segment file header unreadable: {e}")))?;
    let segment_id = decode_segment_header(&header_bytes)?;

    let mut records = Vec::new();
    let mut offset = SEGMENT_HEADER_LEN;
    let mut stopped_because = None;
    while offset < file_len {
        let remaining = file_len - offset;
        let mut bytes = [0u8; RECORD_HEADER_LEN];
        let readable = remaining.min(RECORD_HEADER_LEN as u64) as usize;
        if read_exact_at(file, &mut bytes[..readable], offset).is_err() {
            stopped_because = Some(HeaderReject::Truncated);
            break;
        }
        let header = match decode_record_header(&bytes[..readable], remaining) {
            Ok(header) => header,
            Err(reject) => {
                stopped_because = Some(reject);
                break;
            }
        };
        records.push(ScannedRecord {
            hash: header.hash,
            record_offset: offset,
            payload_len: header.payload_len,
        });
        offset += header.record_len();
    }
    Ok(ScannedSegment { segment_id, complete_end: offset, records, stopped_because })
}

/// One record a scan found intact.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ScannedRecord {
    pub(crate) hash: [u8; RAW_HASH_LEN],
    pub(crate) record_offset: u64,
    pub(crate) payload_len: u32,
}

/// What a full walk of a segment file found.
#[derive(Debug)]
pub(crate) struct ScannedSegment {
    pub(crate) segment_id: u64,
    /// The offset just past the last complete record. Everything from here
    /// to the file's end is a partial write.
    pub(crate) complete_end: u64,
    pub(crate) records: Vec<ScannedRecord>,
    /// Why the walk stopped short of the file's end, if it did.
    pub(crate) stopped_because: Option<HeaderReject>,
}
