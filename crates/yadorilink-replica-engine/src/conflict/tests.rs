use super::*;

fn head(change: u8, version: u8) -> PathHead {
    PathHead {
        change_hash: [change; 32],
        rank: 0,
        device_id: format!("device-{change}"),
        naming_device_id: format!("device-{change}"),
        content: Some(PathHeadContent { version_hash: [version; 32], mtime_unix_nanos: 0 }),
    }
}

fn removal(change: u8) -> PathHead {
    PathHead { content: None, ..head(change, 0) }
}

#[test]
fn no_content_head_means_absent() {
    assert_eq!(resolve_path_heads("a.txt", &[]), PathResolution::Absent);
    assert_eq!(resolve_path_heads("a.txt", &[removal(1), removal(2)]), PathResolution::Absent);
}

#[test]
fn the_highest_version_keeps_the_name_and_the_rest_stand_at_their_copy_paths() {
    let heads = [head(1, 5), head(2, 9), head(3, 7)];
    let PathResolution::Present { winner, conflict_copies } =
        resolve_path_heads("dir/a.txt", &heads)
    else {
        panic!("present")
    };
    assert_eq!(winner, 1);
    let copies: Vec<(usize, String)> =
        conflict_copies.into_iter().map(|c| (c.head, c.path)).collect();
    assert_eq!(copies.len(), 2);
    for (index, path) in copies {
        let version = heads[index].content.as_ref().unwrap().version_hash;
        assert_eq!(path, copy_path("dir/a.txt", &VersionHash(version)));
    }
}

#[test]
fn heads_of_one_version_are_one_piece_of_content() {
    let heads = [head(1, 5), head(2, 5), head(3, 9)];
    let PathResolution::Present { conflict_copies, .. } = resolve_path_heads("a", &heads) else {
        panic!("present")
    };
    assert_eq!(conflict_copies.len(), 1, "one copy for the one other version");
}

#[test]
fn a_tombstone_never_contests_content() {
    let heads = [removal(1), head(2, 3)];
    assert_eq!(
        resolve_path_heads("a", &heads),
        PathResolution::Present { winner: 1, conflict_copies: vec![] }
    );
}

#[test]
fn the_outcome_does_not_depend_on_the_order_of_the_heads() {
    let heads = [head(1, 5), head(2, 9), head(3, 7), head(4, 9)];
    let reference = resolve_path_heads("a", &heads);
    let summary = |r: &PathResolution, hs: &[PathHead]| match r {
        PathResolution::Absent => None,
        PathResolution::Present { winner, conflict_copies } => Some((
            hs[*winner].content.as_ref().unwrap().version_hash,
            conflict_copies
                .iter()
                .map(|c| c.path.clone())
                .collect::<std::collections::BTreeSet<_>>(),
        )),
    };
    let mut reversed = heads.clone();
    reversed.reverse();
    assert_eq!(
        summary(&reference, &heads),
        summary(&resolve_path_heads("a", &reversed), &reversed)
    );
}
