//! The pure rules of the host's view of a sync root, with no Win32 call behind them: what a
//! placeholder looks like to the walk ([`PlaceholderInfo`]), what the host has shown
//! ([`ShownItem`], [`ShownItems`]) and how much of it survives a walk that could not enter a
//! folder ([`keep_subtree`]), which names the host will create, whether a placeholder must be
//! brought up to date, how the change journal's answer is read and how it guards a bind, and how
//! a sync root folder is named. The functions that call the Cloud Files driver or the file
//! system stay in the Windows crate.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::provider_authoring::AdoptError;
use yadorilink_ipc_proto::shellipc::{EntryKind, ProviderItem};

/// What the Cloud Files driver and the file system say about one name in a sync root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlaceholderInfo {
    /// The item the placeholder was created for; `None` for a placeholder of another kind.
    pub item_id: Option<Vec<u8>>,
    /// The placeholder has not been modified by the user since it was last made current.
    pub in_sync: bool,
    pub is_dir: bool,
    pub size: u64,
    /// Last write time, in 100 ns ticks since 1601.
    pub mtime_ticks: u64,
    /// The content is not on the disk.
    pub dehydrated: bool,
}

/// A name the host will create in a sync root: one component, nothing the file system reads as
/// a path, a stream or a device.
pub fn valid_component(name: &str) -> bool {
    !is_reserved_device_name(name)
        && !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.ends_with(['.', ' '])
        && !name.contains(['\\', '/', ':', '*', '?', '"', '<', '>', '|', '\0'])
        && !name.chars().any(|c| (c as u32) < 0x20)
}

/// `CON`, `NUL`, `COM1`... (also with an extension): names the file system treats as devices.
pub fn is_reserved_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end().to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|digit| matches!(digit.as_bytes(), [b'0'..=b'9']))
        })
}

pub fn unix_nanos_to_ticks(unix_nanos: i64) -> u64 {
    const EPOCH_TICKS: i64 = 116_444_736_000_000_000;
    (unix_nanos / 100 + EPOCH_TICKS).max(0) as u64
}

/// An item as the sync root shows it: where it is, and what the daemon said about it when it was
/// shown. This is the host's knowledge of the provider state: a local change is judged against it
/// (the version the user saw is the base of an edit; the folder an item was in is the one a move
/// leaves).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShownItem {
    pub path: PathBuf,
    pub parent_item_id: Vec<u8>,
    pub name: String,
    pub directory: bool,
    pub size: u64,
    pub mtime_unix_nanos: i64,
    /// The 40-byte content version identifier, exactly as the daemon issued it.
    pub content_version: Vec<u8>,
    pub parent_generation: u64,
}

impl ShownItem {
    pub fn of(path: PathBuf, item: &ProviderItem) -> Self {
        Self {
            path,
            parent_item_id: item.parent_item_id.clone(),
            name: item.name.clone(),
            directory: item.entry_kind == EntryKind::Directory as i32,
            size: item.size,
            mtime_unix_nanos: item.mtime_unix_nanos,
            content_version: item.content_version.clone(),
            parent_generation: item.parent_generation,
        }
    }
}

/// How an eviction request ended.
#[derive(Debug, PartialEq, Eq)]
pub enum EvictOutcome {
    /// The local content was dropped; the placeholder stays.
    Evicted,
    /// There was no local content (already dehydrated, or the item is not shown).
    NotMaterialized,
    /// A process holds the file open; the daemon retries this item.
    Busy,
    Error(String),
}

/// The items shown, by item id.
pub type ShownItems = HashMap<Vec<u8>, ShownItem>;

/// Copies everything `previous` shows below `id` into `shown`, as it was observed.
pub fn keep_subtree(previous: &ShownItems, id: &[u8], shown: &mut ShownItems) {
    let mut parents = vec![id.to_vec()];
    while let Some(parent) = parents.pop() {
        for (child, item) in previous.iter().filter(|(_, i)| i.parent_item_id == parent) {
            if shown.insert(child.clone(), item.clone()).is_none() {
                parents.push(child.clone());
            }
        }
    }
}

/// Whether the placeholder must be brought to `item`: it holds another size, or it stands for
/// another version (or for none the host knows), or its time is not the item's (a repair after a
/// power loss that returned the metadata). A version is told from another by its hash: a time says
/// nothing about which is newer, so an item whose time is older than the placeholder's is replaced
/// like any other.
pub fn needs_update(
    info: &PlaceholderInfo,
    item: &ProviderItem,
    shown: Option<&ShownItem>,
) -> bool {
    use crate::provider_client::version_hash_of;
    info.in_sync
        && (info.size != item.size
            || info.mtime_ticks != unix_nanos_to_ticks(item.mtime_unix_nanos)
            || shown.and_then(|shown| version_hash_of(&shown.content_version))
                != version_hash_of(&item.content_version))
}

pub use yadorilink_fs_platform::usn::read_usn;

/// How the file compares with the USN it was copied at. `copied` is `None` only when nothing was
/// copied (a folder): there is nothing to guard. A copy always carries a USN (the ingest refuses
/// a volume without a change journal), so once there is one, a USN that cannot be read now is not
/// "unchanged": the bind fails closed and the file is never marked in sync. (Known limit: the
/// journal's own id is not compared, so deleting and recreating the volume's change journal
/// between the copy and the bind, which resets file USNs, is not detected.)
pub fn usn_guard(copied: Option<i64>, now: Result<Option<i64>, u32>) -> Result<(), AdoptError> {
    match (copied, now) {
        (None, _) => Ok(()),
        (Some(expected), Ok(Some(actual))) if actual == expected => Ok(()),
        (Some(_), Ok(Some(_))) => Err(AdoptError::Changed),
        (Some(_), Ok(None)) => Err(AdoptError::Failed("USN guard unavailable".into())),
        (Some(_), Err(code)) => {
            Err(AdoptError::Failed(format!("USN guard unavailable: error {code}")))
        }
    }
}

pub use yadorilink_fs_platform::windows_name::windows_name_key;

/// The sync root path the daemon's name suggests: the display name, made usable as one folder
/// name, below `parent`; a different folder name when that one is taken by something that is not
/// already this root's.
pub fn choose_root_path(
    parent: &Path,
    display_name: &str,
    root_id: &[u8],
    taken: &HashSet<PathBuf>,
) -> PathBuf {
    let mut name: String = display_name
        .chars()
        .map(|c| if "\\/:*?\"<>|".contains(c) || (c as u32) < 0x20 { '_' } else { c })
        .collect();
    name = name.trim_matches(['.', ' ']).to_string();
    if name.is_empty() {
        name = "YadoriLink".to_string();
    }
    if is_reserved_device_name(&name) {
        name = format!("{name} folder");
    }
    // Windows folder names do not differ by case.
    let taken: HashSet<String> =
        taken.iter().map(|path| windows_name_key(&path.to_string_lossy())).collect();
    let occupied = |path: &Path| {
        taken.contains(&windows_name_key(&path.to_string_lossy()))
            || std::fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_some())
            || path.symlink_metadata().is_ok_and(|m| !m.is_dir())
    };
    let plain = parent.join(&name);
    if !occupied(&plain) {
        return plain;
    }
    // Every candidate is checked the same way: a folder that is not empty, or that belongs to
    // another root, is never taken over.
    let suffix: String = root_id.iter().take(4).map(|b| format!("{b:02x}")).collect();
    let mut candidate = parent.join(format!("{name} ({suffix})"));
    let mut count = 2u32;
    while occupied(&candidate) {
        candidate = parent.join(format!("{name} ({suffix} {count})"));
        count += 1;
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_names_are_single_plain_names() {
        for good in ["a", "photo 1.jpg", "日本語.txt", ".hidden"] {
            assert!(valid_component(good), "{good}");
        }
        for bad in [
            "", ".", "..", "a/b", "a\\b", "c:", "a:b", "x.", "x ", "q?", "a\u{1}b", "a*b", "CON",
            "nul.txt", "Com1", "LPT9.log",
        ] {
            assert!(!valid_component(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_usn_guard_never_passes_a_copied_file_it_cannot_compare() {
        assert_eq!(usn_guard(None, Ok(None)), Ok(()), "nothing was copied: nothing to guard");
        assert_eq!(usn_guard(Some(0), Ok(Some(0))), Ok(()), "USN 0 is compared like any other");
        assert_eq!(usn_guard(Some(0), Ok(Some(9))), Err(AdoptError::Changed));
        for now in [Ok(None), Err(5)] {
            assert!(
                matches!(usn_guard(Some(4), now), Err(AdoptError::Failed(_))),
                "journal unavailable or unreadable must never mark in sync"
            );
        }
    }

    #[test]
    fn a_root_path_is_a_usable_folder_name_that_never_reuses_a_foreign_folder() {
        let parent = std::env::temp_dir().join(format!("yl-roots-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(&parent).unwrap();
        let taken = HashSet::new();
        assert_eq!(
            choose_root_path(&parent, "NUL", &[1, 2, 3, 4, 5], &taken),
            parent.join("NUL folder")
        );
        assert_eq!(
            choose_root_path(&parent, "My: Photos?", &[1, 2, 3, 4, 5], &taken),
            parent.join("My_ Photos_")
        );
        std::fs::create_dir_all(parent.join("Photos")).unwrap();
        std::fs::write(parent.join("Photos").join("mine.txt"), b"x").unwrap();
        assert_eq!(
            choose_root_path(&parent, "Photos", &[0xab, 0xcd, 0xef, 0x01, 9], &taken),
            parent.join("Photos (abcdef01)")
        );
        std::fs::create_dir_all(parent.join("Photos (abcdef01)")).unwrap();
        std::fs::write(parent.join("Photos (abcdef01)").join("x"), b"y").unwrap();
        assert_eq!(
            choose_root_path(&parent, "Photos", &[0xab, 0xcd, 0xef, 0x01, 9], &taken),
            parent.join("Photos (abcdef01 2)"),
            "a taken fallback folder was reused"
        );
        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn a_folder_the_walk_could_not_enter_keeps_everything_observed_below_it() {
        fn item(parent: &[u8], name: &str) -> ShownItem {
            ShownItem {
                path: PathBuf::from(name),
                parent_item_id: parent.to_vec(),
                name: name.to_string(),
                directory: true,
                size: 0,
                mtime_unix_nanos: 0,
                content_version: vec![],
                parent_generation: 0,
            }
        }
        let previous: ShownItems = HashMap::from([
            (b"d".to_vec(), item(b"", "d")),
            (b"c".to_vec(), item(b"d", "c")),
            (b"g".to_vec(), item(b"c", "g")),
            (b"other".to_vec(), item(b"", "other")),
        ]);
        let mut shown = ShownItems::new();
        keep_subtree(&previous, b"d", &mut shown);
        assert!(shown.contains_key(&b"c"[..]) && shown.contains_key(&b"g"[..]));
        assert!(!shown.contains_key(&b"other"[..]) && !shown.contains_key(&b"d"[..]));
    }
}
