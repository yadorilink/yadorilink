//! Observing a regular file in the rebootstrap quarantine hashes it through one fixed buffer:
//! no single allocation scales with the file. A counting global allocator records the
//! largest single allocation while a 256 MiB sparse file is observed.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Counting;
static LARGEST: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LARGEST.fetch_max(new_size, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

#[test]
#[ignore = "hashes 256 MiB; run explicitly"]
fn observing_a_256_mib_file_allocates_nothing_that_scales_with_it() {
    use yadorilink_sync_sqlite::native_rebootstrap_install::{observe_regular_file, Observed};
    const SIZE: u64 = 256 * 1024 * 1024;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big");
    std::fs::File::create(&path).unwrap().set_len(SIZE).unwrap();

    LARGEST.store(0, Ordering::Relaxed);
    let observed = observe_regular_file(std::fs::File::open(&path).unwrap()).unwrap();
    let largest = LARGEST.load(Ordering::Relaxed);

    let Observed::File { size, .. } = observed else { panic!("{observed:?}") };
    assert_eq!(size, SIZE);
    assert!(largest <= 4 * 1024 * 1024, "one allocation of {largest} bytes");
}
