//! What this machine's filesystems can actually say about object identity.
//!
//! Whether a device can conclude "the file I am looking at is still the
//! file I recorded" is not a property of the code -- it is a property of
//! the volume. `FileIdentity::compare` asks, in order, for a generation
//! counter, then a symlink's own target digest, then a birth time it is
//! allowed to trust; a volume that offers none of those cannot answer,
//! and the honest result is `Ambiguous`.
//!
//! Diagnostic, not an assertion: it reports what a given directory's
//! filesystem supports rather than requiring any particular answer, since
//! the answer legitimately differs between ext4, tmpfs, overlayfs and a
//! network mount. Run it against a specific directory with
//! `YADORILINK_IDENTITY_PROBE_DIR=/some/path cargo test -p
//! yadorilink-root-authority --test identity_probe -- --ignored
//! --nocapture`.

use yadorilink_fs_platform::fs_capabilities::probe_birth_time_granularity;
use yadorilink_fs_platform::fs_identity::FileIdentity;

#[ignore = "environment probe -- reports what this host's filesystem supports, asserts nothing"]
#[test]
fn report_what_this_filesystem_can_say_about_identity() {
    let dir = std::env::var("YADORILINK_IDENTITY_PROBE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("yadorilink-identity-probe.bin");
    std::fs::write(&path, b"probe").unwrap();

    let granularity = probe_birth_time_granularity(&dir);
    let first = FileIdentity::observe_path(&path).expect("observing a file just written");
    let second = FileIdentity::observe_path(&path).expect("observing the same file again");
    let comparison = first.compare(&second, granularity);

    println!("dir                     {}", dir.display());
    println!("birth_time_granularity  {granularity:?}");
    println!("object_kind             {:?}", first.object_kind);
    println!("volume_identity         {:?}", first.volume_identity);
    println!("object_id               {:?}", first.object_id);
    println!("generation_or_usn       {:?}", first.generation_or_usn);
    println!("birth_or_creation_time  {:?}", first.birth_or_creation_time);
    println!("compare(self, self)     {comparison:?}");
    println!(
        "verdict                 {}",
        match comparison {
            yadorilink_fs_platform::fs_identity::IdentityComparison::SameObject =>
                "this volume can confirm a regular file is unchanged, so zero-work closure \
                 works here for regular files",
            _ =>
                "this volume cannot confirm THIS regular file is unchanged. It says nothing \
                 about other kinds: a symlink carries its own target digest as a \
                 discriminator, and an absent path is settled by absence rather than by \
                 identity",
        }
    );

    let _ = std::fs::remove_file(&path);
}
