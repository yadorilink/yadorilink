//! Maps a byte range of a file version to the blocks that cover it.
//!
//! The version's own block list is the only authority: the window is the contiguous run of
//! blocks overlapping the (clamped) range, so a ranged materialization fetches and verifies
//! exactly those blocks with the code the whole-file path uses.

use yadorilink_replica_domain::file::BlockInfo;

use crate::application::ports::ByteRange;
use crate::sync_error::SyncError;

/// The blocks covering one range, and where the range sits inside their concatenation.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct RangeWindow {
    /// The covering blocks, with offsets rebased to the start of the window (the layout of the
    /// assembled window file).
    pub blocks: Vec<BlockInfo>,
    /// The range actually served: the request clamped to the end of the file.
    pub served: ByteRange,
    /// Where `served` starts inside the assembled window.
    pub skip: u64,
}

impl RangeWindow {
    pub(super) fn window_len(&self) -> u64 {
        self.blocks.iter().map(|b| u64::from(b.size)).sum()
    }
}

/// `Ok(None)`: the offset is past the end of the file. An index whose blocks do not tile the
/// file exactly is corrupt state, never guessed around.
pub(super) fn plan(
    blocks: &[BlockInfo],
    size: u64,
    range: ByteRange,
) -> Result<Option<RangeWindow>, SyncError> {
    let mut end_of_blocks = 0u64;
    for block in blocks {
        if block.offset != end_of_blocks {
            return Err(SyncError::CorruptState("the version's blocks are not contiguous".into()));
        }
        end_of_blocks = end_of_blocks.saturating_add(u64::from(block.size));
    }
    if end_of_blocks != size {
        return Err(SyncError::CorruptState(
            "the version's blocks do not add up to its size".into(),
        ));
    }
    if range.offset > size {
        return Ok(None);
    }
    let start = range.offset;
    let end = start.saturating_add(range.len).min(size);
    let served = ByteRange { offset: start, len: end - start };
    if served.len == 0 {
        return Ok(Some(RangeWindow { blocks: Vec::new(), served, skip: 0 }));
    }
    let covering: Vec<&BlockInfo> =
        blocks.iter().filter(|b| b.offset < end && b.offset + u64::from(b.size) > start).collect();
    let first = covering.first().map_or(0, |b| b.offset);
    Ok(Some(RangeWindow {
        blocks: covering
            .iter()
            .map(|b| BlockInfo { offset: b.offset - first, ..(*b).clone() })
            .collect(),
        served,
        skip: start - first,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(sizes: &[u32]) -> (Vec<BlockInfo>, u64) {
        let mut offset = 0u64;
        let blocks = sizes
            .iter()
            .enumerate()
            .map(|(n, &size)| {
                let block = BlockInfo { hash: vec![n as u8; 32], offset, size };
                offset += u64::from(size);
                block
            })
            .collect();
        (blocks, offset)
    }

    fn hashes(window: &RangeWindow) -> Vec<u8> {
        window.blocks.iter().map(|b| b.hash[0]).collect()
    }

    #[test]
    fn a_middle_range_names_only_its_block() {
        let (blocks, size) = layout(&[10, 10, 10, 10]);
        let window = plan(&blocks, size, ByteRange { offset: 12, len: 3 }).unwrap().unwrap();
        assert_eq!(hashes(&window), [1]);
        assert_eq!((window.skip, window.served), (2, ByteRange { offset: 12, len: 3 }));
        assert_eq!(window.blocks[0].offset, 0);
    }

    #[test]
    fn a_range_across_a_boundary_names_both_blocks() {
        let (blocks, size) = layout(&[10, 10, 10, 10]);
        let window = plan(&blocks, size, ByteRange { offset: 18, len: 4 }).unwrap().unwrap();
        assert_eq!(hashes(&window), [1, 2]);
        assert_eq!(window.skip, 8);
        assert_eq!(window.blocks.iter().map(|b| b.offset).collect::<Vec<_>>(), [0, 10]);
        assert_eq!(window.window_len(), 20);
    }

    #[test]
    fn a_range_ending_exactly_on_a_boundary_does_not_take_the_next_block() {
        let (blocks, size) = layout(&[10, 10, 10]);
        let window = plan(&blocks, size, ByteRange { offset: 0, len: 10 }).unwrap().unwrap();
        assert_eq!(hashes(&window), [0]);
        let window = plan(&blocks, size, ByteRange { offset: 10, len: 10 }).unwrap().unwrap();
        assert_eq!(hashes(&window), [1]);
    }

    #[test]
    fn the_end_is_clamped_to_the_file_and_an_offset_past_it_is_refused() {
        let (blocks, size) = layout(&[10, 10, 5]);
        let window = plan(&blocks, size, ByteRange { offset: 22, len: u64::MAX }).unwrap().unwrap();
        assert_eq!((hashes(&window), window.served), (vec![2], ByteRange { offset: 22, len: 3 }));
        assert!(plan(&blocks, size, ByteRange { offset: 26, len: 1 }).unwrap().is_none());
        assert!(plan(&blocks, size, ByteRange { offset: u64::MAX, len: 0 }).unwrap().is_none());
    }

    #[test]
    fn an_empty_range_and_the_end_of_file_need_no_block() {
        let (blocks, size) = layout(&[10, 10]);
        for offset in [0, 7, 20] {
            let window = plan(&blocks, size, ByteRange { offset, len: 0 }).unwrap().unwrap();
            assert!(window.blocks.is_empty());
            assert_eq!(window.served, ByteRange { offset, len: 0 });
        }
        let window = plan(&blocks, size, ByteRange { offset: 20, len: 5 }).unwrap().unwrap();
        assert!(window.blocks.is_empty());
        assert_eq!(window.served.len, 0);
        let (none, zero) = layout(&[]);
        assert!(plan(&none, zero, ByteRange { offset: 0, len: 9 })
            .unwrap()
            .unwrap()
            .blocks
            .is_empty());
    }

    #[test]
    fn blocks_that_do_not_tile_the_file_are_corrupt_state() {
        let (mut blocks, size) = layout(&[10, 10]);
        assert!(plan(&blocks, size + 1, ByteRange { offset: 0, len: 1 }).is_err());
        blocks[1].offset = 11;
        assert!(plan(&blocks, size, ByteRange { offset: 0, len: 1 }).is_err());
    }
}
