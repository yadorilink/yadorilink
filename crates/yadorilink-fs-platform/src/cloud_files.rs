//! What the file attributes of a Windows Cloud Files item mean, in one place.
//!
//! The daemon (what it tells an app about an item), the provider host (what it pins and reports)
//! and the checked publish (whether a target can be swapped) all read the same attribute word, so
//! they all read it through this module: the same bits never mean two things. The functions are
//! pure and compile everywhere; only [`attributes_of`] reads a file, and only on Windows.
//!
//! Measured limit: once a sync root's provider is gone the platform hides some of these bits
//! (`REPARSE_POINT`, `SPARSE_FILE` and `OFFLINE` of a dehydrated placeholder). A reading made then
//! cannot say that content is on this machine; callers that need a statement must know the
//! provider is connected first.

use std::path::Path;

/// `FILE_ATTRIBUTE_REPARSE_POINT`.
pub const REPARSE_POINT: u32 = 0x400;
/// `FILE_ATTRIBUTE_OFFLINE`: the data is not available locally.
pub const OFFLINE: u32 = 0x1000;
/// `FILE_ATTRIBUTE_RECALL_ON_OPEN`.
pub const RECALL_ON_OPEN: u32 = 0x4_0000;
/// `FILE_ATTRIBUTE_PINNED`: the person asked for this item to be kept on this device.
pub const PINNED: u32 = 0x8_0000;
/// `FILE_ATTRIBUTE_UNPINNED`: the person asked for this item to be online only.
pub const UNPINNED: u32 = 0x10_0000;
/// `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`.
pub const RECALL_ON_DATA_ACCESS: u32 = 0x40_0000;

/// Whether the item's content is not (all) on this machine.
#[must_use]
pub fn content_is_remote(attributes: u32) -> bool {
    attributes & (OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS) != 0
}

/// The pin the person set on an item, as the platform records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinMark {
    Pinned,
    Unpinned,
    /// Neither mark (the platform's default), or both (not a state the platform sets).
    Unset,
}

#[must_use]
pub fn pin_mark(attributes: u32) -> PinMark {
    match (attributes & PINNED != 0, attributes & UNPINNED != 0) {
        (true, false) => PinMark::Pinned,
        (false, true) => PinMark::Unpinned,
        _ => PinMark::Unset,
    }
}

/// The attributes of `path`, read without following a reparse point and without recalling
/// anything. `None` where the item cannot be read, and on platforms without this notion.
#[must_use]
pub fn attributes_of(path: &Path) -> Option<u32> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        std::fs::symlink_metadata(path).ok().map(|metadata| metadata.file_attributes())
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_recall_bit_alone_marks_the_content_remote_and_the_other_bits_do_not() {
        for bit in [OFFLINE, RECALL_ON_OPEN, RECALL_ON_DATA_ACCESS] {
            assert!(content_is_remote(bit), "{bit:#x}");
            assert!(content_is_remote(bit | 0x20 | PINNED), "{bit:#x}");
        }
        // An ordinary file, a placeholder that is hydrated, the pin marks and a reparse point
        // alone say nothing about where the content is.
        for attributes in [0x20, 0x20 | REPARSE_POINT, PINNED, UNPINNED, 0x20 | 0x200] {
            assert!(!content_is_remote(attributes), "{attributes:#x}");
        }
    }

    #[test]
    fn the_pin_marks_read_as_what_the_platform_means_by_them() {
        assert_eq!(pin_mark(0x20), PinMark::Unset);
        assert_eq!(pin_mark(0x20 | PINNED), PinMark::Pinned);
        assert_eq!(pin_mark(0x20 | UNPINNED), PinMark::Unpinned);
        assert_eq!(pin_mark(PINNED | UNPINNED), PinMark::Unset);
    }

    #[test]
    fn the_bit_values_are_the_windows_ones() {
        // winnt.h: OFFLINE 0x1000, RECALL_ON_OPEN 0x40000, PINNED 0x80000, UNPINNED 0x100000,
        // RECALL_ON_DATA_ACCESS 0x400000.
        assert_eq!(
            [OFFLINE, RECALL_ON_OPEN, PINNED, UNPINNED, RECALL_ON_DATA_ACCESS],
            [0x1000, 0x40000, 0x80000, 0x100000, 0x400000]
        );
    }
}
