pub mod framing;
pub mod pipe_peer;

/// The engine API version a host app (macOS app, Windows shell) must match.
/// This is the single source of truth: the daemon reports it in `--version`
/// and in its status, and the engine identity file records it; the Apple host
/// reads it from that identity file, not from the FFI. Bump it by hand whenever the contract between the engine
/// and a host app changes incompatibly.
pub const PROVIDER_HOST_API_VERSION: u32 = 1;

pub mod sync {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.sync.v1.rs"));
}

pub mod shellipc {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.shellipc.v1.rs"));
}

pub mod local_discovery {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.local_discovery.v1.rs"));
}

// Track Send's own peer-to-peer wire protocol -- see `proto/send.proto`'s
// own doc comment for why this is a wholly separate message family from
// `sync` above, never exchanged over the sync protocol's ALPN/stream.
pub mod send {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.send.v1.rs"));
}

pub mod daemonctl {
    include!(concat!(env!("OUT_DIR"), "/yadorilink.daemonctl.v1.rs"));

    /// The one human-readable word for a path's local state, derived from its
    /// two independent facts: `remote` (nothing here), `local-stale` (an
    /// object stands but is not the current version), `local-current`,
    /// `hydrating`, `evicting`; `unknown` when the daemon reported nothing.
    #[must_use]
    pub fn local_state_word(state: Option<&LocalState>) -> &'static str {
        let Some(state) = state else { return "unknown" };
        match state.transition() {
            LocalTransition::Hydrating => "hydrating",
            LocalTransition::Evicting => "evicting",
            LocalTransition::None if state.current_content_present => "local-current",
            LocalTransition::None if state.local_object_present => "local-stale",
            LocalTransition::None => "remote",
        }
    }

    /// Exact daemon-control protocol generation for the current pre-release
    /// source tree. The CLI, desktop app, and daemon are shipped as one unit;
    /// development builds are not required to interoperate across protocol
    /// generations. A version mismatch should fail clearly rather than select a
    /// backward-compatibility path.
    ///
    /// `8`: adds Track Send's `send_file`/`list_inbox`/`receive_transfer`
    /// request and response variants.
    /// `9`: adds Folder Rewind's read-only `rewind_preview` request and
    /// response variants.
    /// `10`: added LAN discovery's read-only
    /// `list_lan_discovered_candidates` request and response variants.
    /// `11`: removes them again, together with the legacy LAN broadcast
    /// discovery that produced the candidate list -- peer connectivity is
    /// the reconciliation substrate's own endpoint, whose candidate set
    /// this daemon does not enumerate. A removal is as breaking as an
    /// addition: a stale CLI or desktop build would send a request
    /// variant this daemon no longer has a field for, and must be refused
    /// at the version check rather than have its request silently decode
    /// as "no payload set".
    ///
    /// `12`: adds the preserved-data requests (`list_preserved`, `restore_preserved`,
    /// `discard_preserved`) and the `preserved` summary of `StatusResponse`.
    ///
    /// `13`: adds `retry_preserved`.
    ///
    /// `14`: adds `LinkStatus.durability_check_pending`.
    ///
    /// `15`: removes the `pin`/`unpin` requests,
    /// `LinkRequest.max_local_size_bytes` and
    /// `MaterializationStatusResponse.pinned`.
    ///
    /// `16`: adds `list_retained_originals` / `release_retained_originals` and the retained
    /// counts of the `preserved` summary.
    /// `17`: adds `LinkStatus.requested_content_count`, the sole "content requested" signal;
    /// `hydrating_count` no longer counts evicting files.
    /// `18`: adds `RewindPreviewResponse.plan_id`.
    /// `19`: adds `link_preflight`; the daemon now refuses an unacknowledged risky link, create,
    /// join or invite acceptance itself.
    /// `20`: adds `open_nas_admin`, the one request whose connection stays open after its
    /// response (the session lives as long as the connection).
    /// `21`: adds `rewind_execute` and `rewind_status`.
    /// `22`: adds `RewindPreviewResponse.unavailable_message` and `RewindPlanStale.message`.
    /// `23`: adds `readopt_volume` and `LinkStatus.capture_volume_unconfirmed`.
    /// `24`: adds `ProviderRootStatus.counters_unreadable`.
    /// `25`: adds `resolve_conflict` and its refusal codes.
    /// `26`: adds `ConflictedFileInfo.origin_device_id`.
    /// `27`: adds `command_error` and the codes `DISK_FULL`, `PATH_NOT_ALLOWED`, `NOT_PROTECTED`,
    /// `INVITE_EXPIRED` and `INVITE_ALREADY_USED`; link and unlink refuse with them.
    /// `28`: adds `CreateAndLinkCommandRequest.create_local_path_if_missing`.
    /// `29`: adds `identify`, the read-only report of the daemon's version, engine build,
    /// install source and the data area's recorded owner.
    /// `30`: adds `request_safe_stop`, which brings the daemon to a safe point and exits cleanly
    /// or answers `busy` and keeps running.
    /// `31`: adds `mark_link_not_rejoined`, which start over uses to keep a folder it could not
    /// join again visible as needing the person.
    /// `32`: `LinkStatus` lists the files a scan could not read and that need the person
    /// (`unreadable_files`, `unreadable_file_count`).
    /// `33`: unlink, pause and resume take an optional `expected_group_id` and refuse with
    /// `GROUP_MISMATCH` when the link at the path belongs to another group.
    /// `34`: `LinkStatus` carries the requests waiting on the owner's approval
    /// (`pending_approvals`) and the bytes freeing up space would give back
    /// (`reclaimable_bytes`).
    /// `35`: adds `update_version_check` and `UpdateStatusResponse.manifest_generated_at`.
    /// `36`: transfers the device sent can be listed (`list_sent_transfers`), canceled and
    /// retried by id like received ones, and a failed received transfer lists why it stopped.
    /// `37`: adds the code `ACCESS_DENIED`; link refuses with it when the system denies the folder.
    /// `38`: adds `update_verified_entry`, which says whether an appcast item is covered by the
    /// verified channel manifest's `app_bundle` entry and returns that entry.
    pub const CONTROL_PROTOCOL_VERSION: u32 = 38;
}

#[cfg(test)]
mod tests;
