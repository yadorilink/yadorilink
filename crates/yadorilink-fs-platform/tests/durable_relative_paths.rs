//! The durable helpers accept a bare file name, which lives in the current
//! directory. Its own test binary: the working directory is process-wide.

use std::fs;
use std::path::Path;

use yadorilink_fs_platform::durable_dir::{
    move_durably, publish_durably, remove_file_durably, Replace,
};

#[test]
fn bare_file_names_are_published_moved_and_removed_in_the_current_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    fs::write("staged", b"new").unwrap();
    publish_durably(Path::new("staged"), Path::new("target"), Replace::Yes).unwrap();
    assert_eq!(fs::read(dir.path().join("target")).unwrap(), b"new");

    move_durably(Path::new("target"), Path::new("moved"), Replace::No).unwrap();
    assert!(dir.path().join("moved").exists() && !dir.path().join("target").exists());

    remove_file_durably(Path::new("moved")).unwrap();
    remove_file_durably(Path::new("moved")).unwrap();
    let left: Vec<_> = fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert!(left.is_empty(), "{left:?}");
}
