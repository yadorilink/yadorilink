//! Reading a file's USN (`FSCTL_READ_FILE_USN_DATA`): the update sequence number the volume's
//! change journal gives the file's last change. Only the file system moves it, so unlike a time
//! stamp it cannot be put back by a writer. The parser has no Win32 call in it and builds on
//! every platform; the caller supplies the ioctl.

/// The volume's file system has no change journal (FAT, exFAT, most shares answer so).
const ERROR_INVALID_FUNCTION: u32 = 1;

const ERROR_NOT_SUPPORTED: u32 = 50;

const ERROR_MORE_DATA: u32 = 234;

const ERROR_JOURNAL_DELETE_IN_PROGRESS: u32 = 1178;

const ERROR_JOURNAL_NOT_ACTIVE: u32 = 1179;

const ERROR_INVALID_DATA: u32 = 13;

/// Runs `ioctl` (fills the buffer, returns the bytes written or the Win32 error) with a buffer
/// that grows while the record (it carries the file name) does not fit, and reads the USN out.
pub fn read_usn(
    mut ioctl: impl FnMut(&mut [u8]) -> Result<usize, u32>,
) -> Result<Option<i64>, u32> {
    let mut size = 1024;
    loop {
        let mut out = vec![0u8; size];
        match ioctl(&mut out) {
            Ok(returned) => {
                // USN_RECORD_V2: the USN follows two 8-byte file references; V3 has 16-byte ones.
                let at = match u16::from_le_bytes([out[4], out[5]]) {
                    2 => 24,
                    3 => 40,
                    _ => return Err(ERROR_INVALID_DATA),
                };
                if returned < at + 8 {
                    return Err(ERROR_INVALID_DATA);
                }
                return Ok(Some(i64::from_le_bytes(out[at..at + 8].try_into().unwrap())));
            }
            Err(ERROR_MORE_DATA) if size < 1 << 16 => size *= 4,
            Err(
                ERROR_JOURNAL_NOT_ACTIVE
                | ERROR_JOURNAL_DELETE_IN_PROGRESS
                | ERROR_INVALID_FUNCTION
                | ERROR_NOT_SUPPORTED,
            ) => return Ok(None),
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(version: u16, usn: i64, name_len: usize) -> Vec<u8> {
        let at = if version == 2 { 24 } else { 40 };
        let mut r = vec![0u8; at + 8 + 12 + name_len];
        r[4..6].copy_from_slice(&version.to_le_bytes());
        r[at..at + 8].copy_from_slice(&usn.to_le_bytes());
        r
    }

    #[test]
    fn a_long_name_grows_the_buffer_and_only_a_missing_journal_reads_as_none() {
        let long = record(2, 77, 1500);
        let mut sizes = vec![];
        let got = read_usn(|out| {
            sizes.push(out.len());
            if out.len() < long.len() {
                return Err(ERROR_MORE_DATA);
            }
            out[..long.len()].copy_from_slice(&long);
            Ok(long.len())
        });
        assert_eq!(got, Ok(Some(77)));
        assert!(sizes.len() > 1);
        let v3 = record(3, 5, 10);
        let got = read_usn(|out| {
            out[..v3.len()].copy_from_slice(&v3);
            Ok(v3.len())
        });
        assert_eq!(got, Ok(Some(5)));
        assert_eq!(read_usn(|_| Err(ERROR_JOURNAL_NOT_ACTIVE)), Ok(None));
        assert_eq!(read_usn(|_| Err(ERROR_INVALID_FUNCTION)), Ok(None), "FAT has no journal");
        assert_eq!(read_usn(|_| Err(ERROR_NOT_SUPPORTED)), Ok(None));
        assert_eq!(read_usn(|_| Err(5)), Err(5), "access denied is not 'no journal'");
        assert_eq!(read_usn(|_| Err(ERROR_MORE_DATA)), Err(ERROR_MORE_DATA), "growth is bounded");
    }
}
