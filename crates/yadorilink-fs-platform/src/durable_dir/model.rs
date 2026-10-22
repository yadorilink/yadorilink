//! A model of what survives a power loss, replayed over the steps the
//! namespace operations really took ([`super::trace`]).
//!
//! It keeps two views of a directory tree: the live one, and the one a crash
//! would leave. What enters the crash view depends on the profile:
//!
//! * [`Profile::WriteThroughMove`] (Windows, the minimal documented contract):
//!   only the entry a write-through move put under its new name, and the
//!   content of a file that was flushed. `mkdir`, `unlink`, `rmdir`, a plain
//!   rename and a directory flush add nothing.
//! * [`Profile::DirectorySync`] (Unix): a directory sync makes every entry of
//!   that directory, and every removal from it, durable.
//!
//! An entry reachable in the crash view needs every ancestor below `root` to be
//! in the crash view too; `root` itself is a directory that existed before.
//! Tests ask for the crash view after every step ([`Model::crash_views`]) and
//! check the invariants of the operation against each.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::trace::Event;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    WriteThroughMove,
    DirectorySync,
}

/// What a path names: a directory, or a file with a content state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node {
    pub id: u64,
    pub dir: bool,
    /// For a file: its content is flushed, so a crash keeps it whole.
    pub flushed: bool,
}

pub type View = BTreeMap<PathBuf, Node>;

#[derive(Debug)]
pub struct Model {
    root: PathBuf,
    profile: Profile,
    next_id: u64,
    live: View,
    crash: View,
}

impl Model {
    /// A model of `root` as it is on disk now: everything in it is durable.
    pub fn from_dir(root: &Path, profile: Profile) -> Self {
        let mut model = Self {
            root: root.to_path_buf(),
            profile,
            next_id: 1,
            live: View::new(),
            crash: View::new(),
        };
        model.scan(root);
        model.crash = model.live.clone();
        model
    }

    fn scan(&mut self, dir: &Path) {
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = entry.path();
            let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            let id = self.fresh_id();
            self.live.insert(path.clone(), Node { id, dir: is_dir, flushed: true });
            if is_dir {
                self.scan(&path);
            }
        }
    }

    fn fresh_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// Applies one step to both views.
    pub fn apply(&mut self, event: &Event) {
        match event {
            Event::Create { path, dir } => {
                let id = self.fresh_id();
                self.live.insert(path.clone(), Node { id, dir: *dir, flushed: *dir });
            }
            Event::FlushFile { path } => {
                if let Some(node) = self.live.get_mut(path) {
                    node.flushed = true;
                    let id = node.id;
                    for persisted in self.crash.values_mut().filter(|n| n.id == id) {
                        persisted.flushed = true;
                    }
                }
            }
            Event::Move { from, to, write_through } => self.apply_move(from, to, *write_through),
            Event::Remove { path } => {
                self.live.remove(path);
            }
            Event::FlushDir { dir } => {
                if self.profile == Profile::DirectorySync {
                    self.persist_directory(dir);
                }
            }
        }
    }

    fn apply_move(&mut self, from: &Path, to: &Path, write_through: bool) {
        rebase(&mut self.live, from, to);
        // Entries persisted inside a moved directory travel with it: they are
        // entries of the same directory object.
        let below: Vec<PathBuf> =
            self.crash.keys().filter(|p| *p != from && p.starts_with(from)).cloned().collect();
        for old in below {
            let node = self.crash.remove(&old).expect("listed above");
            let suffix = old.strip_prefix(from).expect("filtered above");
            self.crash.insert(to.join(suffix), node);
        }
        if write_through && self.profile == Profile::WriteThroughMove {
            // The moved entry under its new name, and the old name gone from
            // disk; its content is as durable as it was flushed.
            self.crash.remove(from);
            if let Some(node) = self.live.get(to).copied() {
                self.crash.insert(to.to_path_buf(), node);
            }
        }
    }

    fn persist_directory(&mut self, dir: &Path) {
        let in_dir = |p: &Path| p.parent() == Some(dir);
        self.crash.retain(|p, _| !in_dir(p) || self.live.contains_key(p));
        for (path, node) in self.live.iter().filter(|(p, _)| in_dir(p)) {
            let flushed = node.flushed;
            self.crash.insert(path.clone(), Node { flushed, ..*node });
        }
    }

    /// Treats `root` as the (empty, durable) root, for tests that feed
    /// hand-written steps.
    pub fn retarget(&mut self, root: &Path) {
        self.root = root.to_path_buf();
        self.live.clear();
        self.crash.clear();
    }

    /// The live tree.
    pub fn live(&self) -> &View {
        &self.live
    }

    /// What a crash right now would leave: the persisted entries whose
    /// ancestors below the root are persisted directories.
    pub fn crash_view(&self) -> View {
        self.crash
            .iter()
            .filter(|(path, _)| self.reachable(path))
            .map(|(p, n)| (p.clone(), *n))
            .collect()
    }

    fn reachable(&self, path: &Path) -> bool {
        let mut cur = path.parent();
        while let Some(parent) = cur {
            if parent == self.root {
                return true;
            }
            match self.crash.get(parent) {
                Some(node) if node.dir => cur = parent.parent(),
                _ => return false,
            }
        }
        false
    }

    /// The crash view before the first step and after each step of `trace`.
    pub fn crash_views(mut self, trace: &[Event]) -> Vec<View> {
        let mut views = vec![self.crash_view()];
        for event in trace {
            self.apply(event);
            views.push(self.crash_view());
        }
        views
    }
}

/// Renames `from` to `to` in `view`, together with everything below `from`.
fn rebase(view: &mut View, from: &Path, to: &Path) {
    let moved: Vec<PathBuf> = view.keys().filter(|p| p.starts_with(from)).cloned().collect();
    let mut entries = Vec::new();
    for old in moved {
        let node = view.remove(&old).expect("listed above");
        let suffix = old.strip_prefix(from).expect("filtered above");
        entries.push((to.join(suffix), node));
    }
    for (path, node) in entries {
        view.insert(path, node);
    }
}

/// A file in a crash view whose content did not survive whole.
pub fn torn_files(view: &View) -> Vec<&Path> {
    view.iter().filter(|(_, n)| !n.dir && !n.flushed).map(|(p, _)| p.as_path()).collect()
}
