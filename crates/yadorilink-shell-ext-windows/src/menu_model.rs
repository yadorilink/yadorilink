//! What the Explorer context menu offers for one path.
//!
//! The daemon decides which actions apply (`StatusResponse.actions_available`, `item_paused`,
//! `paused_by_ancestor`, `free_up_space_offered`); this module only turns that answer into menu
//! entries and builds the status deep link. There is no static action list: an untracked path and
//! an unreachable daemon yield no entry at all.

use yadorilink_ipc_proto::shellipc::{ContextAction, StatusResponse};

/// The facts of one status answer the menu needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MenuFacts {
    pub actions_available: bool,
    pub item_paused: bool,
    pub paused_by_ancestor: bool,
    pub free_up_space_offered: bool,
}

impl From<&StatusResponse> for MenuFacts {
    fn from(r: &StatusResponse) -> Self {
        Self {
            actions_available: r.actions_available,
            item_paused: r.item_paused,
            paused_by_ancestor: r.paused_by_ancestor,
            free_up_space_offered: r.free_up_space_offered,
        }
    }
}

/// One menu entry, in display order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuEntry {
    ViewStatus,
    Pause,
    Resume,
    FreeUpSpace,
}

impl MenuEntry {
    pub fn label(self) -> &'static str {
        match self {
            MenuEntry::ViewStatus => "View YadoriLink Status",
            MenuEntry::Pause => "Pause Syncing",
            MenuEntry::Resume => "Resume Syncing",
            MenuEntry::FreeUpSpace => "Free Up Space",
        }
    }

    /// The daemon action this entry sends; `ViewStatus` opens the app instead.
    pub fn daemon_action(self) -> Option<ContextAction> {
        match self {
            MenuEntry::ViewStatus => None,
            MenuEntry::Pause => Some(ContextAction::PauseItem),
            MenuEntry::Resume => Some(ContextAction::ResumeItem),
            MenuEntry::FreeUpSpace => Some(ContextAction::EvictItem),
        }
    }
}

/// The entries for a path. `None` (the daemon could not be asked) and an untracked path offer
/// nothing.
pub fn menu_entries(facts: Option<MenuFacts>) -> Vec<MenuEntry> {
    let Some(f) = facts.filter(|f| f.actions_available) else { return Vec::new() };
    let mut entries = vec![MenuEntry::ViewStatus];
    if f.item_paused {
        entries.push(MenuEntry::Resume);
    } else if !f.paused_by_ancestor {
        entries.push(MenuEntry::Pause);
    }
    if f.free_up_space_offered {
        entries.push(MenuEntry::FreeUpSpace);
    }
    entries
}

/// `yadorilink://folder?path=<percent-encoded absolute path>`. Everything but unreserved
/// characters is encoded, per UTF-8 byte, so a path can never add a query parameter or fragment.
pub fn status_deep_link(path: &str) -> String {
    let mut link = String::from("yadorilink://folder?path=");
    for b in path.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            link.push(b as char);
        } else {
            link.push_str(&format!("%{b:02X}"));
        }
    }
    link
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(paused: bool, ancestor: bool, free: bool) -> Option<MenuFacts> {
        Some(MenuFacts {
            actions_available: true,
            item_paused: paused,
            paused_by_ancestor: ancestor,
            free_up_space_offered: free,
        })
    }

    #[test]
    fn synced_item_offers_pause() {
        assert_eq!(
            menu_entries(facts(false, false, false)),
            [MenuEntry::ViewStatus, MenuEntry::Pause]
        );
    }

    #[test]
    fn paused_item_offers_resume_and_never_pause() {
        assert_eq!(
            menu_entries(facts(true, false, false)),
            [MenuEntry::ViewStatus, MenuEntry::Resume]
        );
    }

    #[test]
    fn item_paused_by_an_ancestor_offers_neither() {
        assert_eq!(menu_entries(facts(false, true, false)), [MenuEntry::ViewStatus]);
    }

    #[test]
    fn free_up_space_only_when_the_daemon_offers_it() {
        assert!(menu_entries(facts(false, false, true)).contains(&MenuEntry::FreeUpSpace));
        assert!(!menu_entries(facts(false, false, false)).contains(&MenuEntry::FreeUpSpace));
    }

    #[test]
    fn untracked_or_unreachable_offers_nothing() {
        let untracked = Some(MenuFacts {
            actions_available: false,
            item_paused: true,
            paused_by_ancestor: false,
            free_up_space_offered: true,
        });
        assert!(menu_entries(untracked).is_empty());
        assert!(menu_entries(None).is_empty());
    }

    #[test]
    fn labels_use_product_wording() {
        assert_eq!(MenuEntry::FreeUpSpace.label(), "Free Up Space");
        assert_eq!(MenuEntry::ViewStatus.label(), "View YadoriLink Status");
        assert_eq!(MenuEntry::ViewStatus.daemon_action(), None);
        assert_eq!(MenuEntry::FreeUpSpace.daemon_action(), Some(ContextAction::EvictItem));
    }

    #[test]
    fn deep_link_round_trips_reserved_characters() {
        let path = r"C:\Users\a b\x&y=1#z%2F?ü.txt";
        let link = status_deep_link(path);
        let encoded = link.strip_prefix("yadorilink://folder?path=").unwrap();
        assert!(!encoded.contains(['&', '#', ' ', '\\', '?', '=']));
        let mut bytes = Vec::new();
        let raw = encoded.as_bytes();
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == b'%' {
                bytes.push(u8::from_str_radix(&encoded[i + 1..i + 3], 16).unwrap());
                i += 3;
            } else {
                bytes.push(raw[i]);
                i += 1;
            }
        }
        assert_eq!(String::from_utf8(bytes).unwrap(), path);
    }
}
