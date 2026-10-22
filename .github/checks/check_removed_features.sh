#!/usr/bin/env bash
#
# Residual-symbol guard for the simplified peer-to-peer product surface.
#
# Several advanced features were removed to keep the product to a small set of
# concepts (account, device, synced folder, and two storage modes) — folders
# sync across a single account's own devices only. This script fails if any of
# those removed features' active-use symbols reappear in shippable code,
# protocol definitions, or the CLI.
#
# Pre-release policy: migration history is not itself a compatibility boundary.
# Removed development-only tables/columns should be folded out of the canonical
# fresh schema, not kept alive by requiring historical migration files that add
# a column and later drop it again. Therefore this guard checks active product
# symbols only; it does not require old removal migrations to remain present.
#
# What counts as a violation is *active use* (a type, function, field, or column
# that only exists when the feature is present). Legitimate documentation of a
# removal is intentionally NOT a violation and is filtered out:
#   - protobuf `reserved` field-number/name declarations (they prevent reuse),
#   - SQL `DROP` statements in any still-relevant migration,
#   - the dedicated removal-guard test that lists forbidden symbols as data.
#
# Excluded from the scan: the VCS/build/dependency trees, lock files, and this
# script's own term list.
#
# Usage: check_removed_features.sh [--self-test]
#   --self-test  check the checker against throwaway fixture trees instead of
#                scanning the repository.

set -euo pipefail

# Shippable surfaces the guard scans for active-use residual symbols.
ROOTS=(
  crates
)

# Lines that document a removal rather than reintroduce a feature. Filtered out
# before a match is treated as a violation:
#   - protobuf `reserved` declarations and SQL `DROP` statements,
#   - comment-only lines (Rust `//` `///` `//!`, block-comment `*`
#     continuations, SQL `--`) — a symbol that appears only in a comment
#     documents the removal and is not active use.
ALLOWED_DOC_LINES='reserved |reserved"|DROP COLUMN|DROP TABLE|drop column|drop table'
COMMENT_ONLY_LINE='^[[:space:]]*(//|/\*|\*|--)'
# Files that are themselves removal enforcement (their term lists name the
# removed symbols as data, not as active use).
GUARD_FILES='check_removed_features\.sh|recovery_model\.rs'

# Each entry: "<feature label>|<space-separated active-use symbols>".
# Symbols are word-matched (grep -w), so bare prose does not match snake_case /
# CamelCase identifiers.
FEATURES=(
  "untrusted storage-only peer|StorageOnly storage_only require_storage_only"
  "directional sync modes|ReceiveOnly SendOnly receive_only send_only SyncDirection out_of_sync_count receive_only_changed_count"
  "device introduction / introducer|Introducer introduce_device introducer_device introducer_device_id IntroductionRequest is_introducer device_introductions"
  "legacy password / key-bundle auth|export_key_bundle import_key_bundle KeyBundle derive_bundle_key recovery_bundle"
  "cross-account folder sharing|createShareInvite acceptShareInvite revokeSharePartner addFolderSharePartner isFolderSharePartner listFolderSharePartners removeFolderSharePartnerCascade insertInvite findInviteByCodeHash tryConsumeInvite markInviteConsumed countInvitesCreatedSince listInvitesCreatedByUser enforceInviteRateQuota InviteRow FolderSharePartnerRow folder_share_partners"
)

# ---------------------------------------------------------------------------
# Transport consolidation (Phase A): the machinery QUIC replaced.
#
# Scanned over CODE ONLY, not docs. The list above is about product features,
# which design documents describe in prose; this list is about deleted
# implementation types, and the documents that record why they were deleted
# necessarily name them. Excluding Markdown is what lets those documents stay
# honest instead of being edited around a grep.
#
# `crates` includes the Windows shell extension crate: the removed
# implementations are Rust identifiers.
CODE_ROOTS=(
  crates
)

# Extra roots scanned together with CODE_ROOTS for the removed-implementation
# list only. Empty by default; a wrapper that sources this file may fill it.
EXTRA_IMPL_ROOTS=()
CODE_EXCLUDE='\.(md|txt):[0-9]+:'

# Each entry: "<label>|<symbols>". Removed implementations whose names are
# generic enough that a kept feature, or prose recording the removal, uses the
# same words. Only the removed implementation's own identifiers are listed, and
# only code is scanned, so the word alone is never a violation:
#   - The operator-run relay was removed: its server, hub, client, auth and
#     I/O modules, its wire messages and its `yadorilink-relay` binary. The
#     transport's own relay path (NAT-traversal fallback, e.g.
#     `PathKind::Relay`) is a kept feature and is deliberately not listed.
#   - The self-hosted gRPC coordination server and its `http-coordination`
#     Cargo feature were removed.
#   - The read/write share-role axis was removed: the policy role, the
#     per-group role map in the network map (camelCase on the wire), and the
#     sync core's gate that rejected writes from read-role peers. The
#     Owner/Editor/Viewer sharing roles (`ShareRole`) are a separate, kept
#     feature and are deliberately not listed.
#   - The legacy wire re-bootstrap protocol was removed: the service-lane
#     request/response that shipped a signed `RebootstrapRequired`, the
#     client request and responder, the handler port, and the SQLite install
#     that kept frontier bodies and installed the base's witnesses without
#     verifying them. A base now arrives only through the verified foreign
#     merge (`verify_foreign_base` -> `commit_foreign_merge`), installed by
#     the same atomic epoch reset a seal commits.
IMPL_REMOVED=(
  "operator relay server|relay_server relay_hub relay_client relay_auth relay_io RelayHub RelayConnection RelayClient RelayMessage yadorilink-relay TransportMode::Relay warn_once_about_ignored_relay_addr"
  "gRPC coordination server|GrpcCoordination coordination_server http-coordination"
  "legacy wire re-bootstrap protocol|request_rebootstrap_snapshot_from_peer prepare_rebootstrap_for KIND_REBOOTSTRAP RebootstrapRequired RebootstrapHandler PreparedRebootstrap DeniedRebootstrapHandler SyncStateRebootstrapInstaller AtomicRebootstrapInstaller verify_and_install_rebootstrap prepare_rebootstrap_required install_rebootstrap_snapshot"
  "read/write share-role axis|PolicyRole SHARE_ROLE_READ SHARE_ROLE_WRITE SHARE_ROLE_UNSPECIFIED shared_group_roles sharedGroupRoles PeerRole set_peer_role LiveGroupRoles live_group_roles grantAccessWithRole"
)

# Each entry: "<label>|<symbols>". These are the types deleted when the
# bespoke reliability, framing, tunnel and bulk-selector layers were
# replaced by QUIC. Reintroducing one means reintroducing a state machine
# QUIC already implements.
TRANSPORT_REMOVED=(
  "custom ARQ / retransmission|ReliableSend ReliableRecv RttEstimator RttState UnackedEntry RetransmitOutcome DecodedFrame"
  "custom fragmentation / framing|Reassembler PartialMessage fragment_message build_fragment wrap_ipv unwrap_ipv"
  "WireGuard transport|WgTunnel WireGuardEngine tunn_wrapper X25519"
  "bulk transport selector|BulkDataPlane BulkConnection BulkQuicError bulk_transport_config"
  # `chunk_offset`/`total_size` are deliberately NOT listed here: both
  # collide with unrelated live identifiers elsewhere (e.g.
  # multi_peer_hydration.rs's own `total_size` fixture field), and the
  # specific BlockReplyFound-shape regression they used to guard is already
  # pinned by stage2_block_serve_contract.rs, which checks the real message
  # shape rather than a bare grep. `reliable_enabled`/`enable_reliable_delivery`/
  # `supports_reliable_delivery` are also left out: the wire field is already
  # `reserved` in sync.proto, which this guard's own ALLOWED_DOC_LINES
  # filter would exempt, so the pattern buys nothing a bare `reserved` grep
  # doesn't already assert once, more precisely, in the schema.
  "inline block-reply chunking|PartialBlockReply MAX_BLOCK_REPLY_CHUNK_BYTES"
  # The former peer-device relay: a device forwarding another device's
  # opaque QUIC datagrams, authorized by a coordination-plane-issued
  # RelayGrant. Physically removed (R6 of the Iroh relay/service-plane
  # cutover) once the Iroh relay carried the reconciliation/block/service
  # substrate directly -- reintroducing any of these means reintroducing
  # the mechanism the cutover replaced, not the Iroh relay itself (which
  # needs none of them: no grant, no forwarding actor, no per-device
  # capability declaration).
  "peer-device relay|RelayGrant RelayGrantSource RelayForwarder RelaySessionHandler RelayReplySink RelayCapability RelayPathHandle RelayOpenFrame RelayOpenedFrame RelayDataFrame RelayCloseFrame"
)

# Each entry: "<label>|<symbols>". Rejected storage-backend prototypes --
# evaluated and explicitly turned down (see the pack-store characterization in git history),
# never shipped, no fallback/shim/feature-flag retained on removal (Phase
# D1R). Reintroducing one of these symbols without new evidence re-opens
# a question this project already closed.
STORAGE_REMOVED=(
  "rejected packed block-store prototype|PackStore enable_packed_bulk_ingest packed_store packed_bulk"
)

# Verification bypasses. These are not merely dead code: nothing above the
# transport encrypts file content, so a config that skips peer verification
# puts plaintext on the wire. `with_no_client_auth` additionally contradicts
# the mandatory-mutual-auth invariant -- a QUIC server that does not demand a
# client certificate cannot know which device it is serving.
#
# There is no exception: the one test that built an unauthenticated endpoint
# pair went away with the custom QUIC transport.
FORBIDDEN_TLS='SkipServerVerification with_no_client_auth dangerous_configuration'

# Set PRESENT to those of the given directories that exist. Not every checkout
# carries every scanned root, and grep exits 2 on a missing path, which under
# pipefail would discard the hits it did print for the roots that exist.
filter_present() {
  local dir
  PRESENT=()
  for dir in "$@"; do
    if [ -d "$dir" ]; then PRESENT+=("$dir"); fi
  done
  if [ "${#PRESENT[@]}" -eq 0 ]; then
    echo "check_removed_features: none of the scanned roots exist: $*" >&2
    return 1
  fi
}

# Scan the tree rooted at the current directory. Prints every violation and
# returns non-zero when there is at least one.
scan() {
  local fail=0 entry label symbols sym hits
  local roots code_roots impl_roots
  filter_present "${ROOTS[@]}" || return 1
  roots=("${PRESENT[@]}")
  filter_present "${CODE_ROOTS[@]}" || return 1
  code_roots=("${PRESENT[@]}")
  filter_present "${CODE_ROOTS[@]}" ${EXTRA_IMPL_ROOTS[@]+"${EXTRA_IMPL_ROOTS[@]}"} || return 1
  impl_roots=("${PRESENT[@]}")

  echo "Scanning shippable surfaces for removed-feature symbols..."
  for entry in "${FEATURES[@]}"; do
    label="${entry%%|*}"
    symbols="${entry#*|}"
    for sym in $symbols; do
      # -w so `storage_only` does not match e.g. `not_storage_only_ever`; the
      # `::` symbols contain no word chars at the boundary and match literally.
      if hits=$(grep -rInw "${roots[@]}" -e "$sym" 2>/dev/null \
          | grep -vE "$ALLOWED_DOC_LINES" \
          | grep -vE "$GUARD_FILES" \
          | grep -vE ":[0-9]+:${COMMENT_ONLY_LINE#^}"); then
        if [ -n "$hits" ]; then
          echo
          echo "VIOLATION [$label]: removed symbol \`$sym\` is still used:"
          echo "$hits" | sed 's/^/  /'
          fail=1
        fi
      fi
    done
  done

  echo "Scanning code surfaces for removed implementations..."
  for entry in "${IMPL_REMOVED[@]}"; do
    label="${entry%%|*}"
    symbols="${entry#*|}"
    for sym in $symbols; do
      if hits=$(grep -rInw "${impl_roots[@]}" -e "$sym" 2>/dev/null \
          | grep -vE "$CODE_EXCLUDE" \
          | grep -vE "$ALLOWED_DOC_LINES" \
          | grep -vE "$GUARD_FILES" \
          | grep -vE ":[0-9]+:${COMMENT_ONLY_LINE#^}"); then
        if [ -n "$hits" ]; then
          echo
          echo "VIOLATION [$label]: removed symbol \`$sym\` is back:"
          echo "$hits" | sed 's/^/  /'
          fail=1
        fi
      fi
    done
  done

  echo "Scanning code surfaces for consolidated-away transport machinery..."
  for entry in "${TRANSPORT_REMOVED[@]}"; do
    label="${entry%%|*}"
    symbols="${entry#*|}"
    for sym in $symbols; do
      if hits=$(grep -rInw "${code_roots[@]}" -e "$sym" 2>/dev/null \
          | grep -vE "$CODE_EXCLUDE" \
          | grep -vE "$GUARD_FILES" \
          | grep -vE ":[0-9]+:${COMMENT_ONLY_LINE#^}"); then
        if [ -n "$hits" ]; then
          echo
          echo "VIOLATION [$label]: consolidated-away symbol \`$sym\` is back:"
          echo "$hits" | sed 's/^/  /'
          fail=1
        fi
      fi
    done
  done

  echo "Scanning code surfaces for rejected storage-backend prototypes..."
  for entry in "${STORAGE_REMOVED[@]}"; do
    label="${entry%%|*}"
    symbols="${entry#*|}"
    for sym in $symbols; do
      if hits=$(grep -rInw "${code_roots[@]}" -e "$sym" 2>/dev/null \
          | grep -vE "$CODE_EXCLUDE" \
          | grep -vE "$GUARD_FILES" \
          | grep -vE ":[0-9]+:${COMMENT_ONLY_LINE#^}"); then
        if [ -n "$hits" ]; then
          echo
          echo "VIOLATION [$label]: rejected symbol \`$sym\` is back:"
          echo "$hits" | sed 's/^/  /'
          fail=1
        fi
      fi
    done
  done

  echo
  echo "Scanning code surfaces for TLS verification bypasses..."
  for sym in $FORBIDDEN_TLS; do
    if hits=$(grep -rInw "${code_roots[@]}" -e "$sym" 2>/dev/null \
        | grep -vE "$CODE_EXCLUDE" \
        | grep -vE "$GUARD_FILES" \
        | grep -vE ":[0-9]+:${COMMENT_ONLY_LINE#^}"); then
      if [ -n "$hits" ]; then
        echo
        echo "VIOLATION [TLS verification bypass]: \`$sym\` appears. Nothing above the transport encrypts file content,"
        echo "so this puts plaintext on the wire:"
        echo "$hits" | sed 's/^/  /'
        fail=1
      fi
    fi
  done

  return "$fail"
}

# Check the checker: a tree holding only kept features must pass, and each
# planted removed symbol must fail it. Runs against throwaway fixture trees,
# never the repository.
self_test() {
  local tmp status=0
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN

  make_kept_tree() {
    local root=$1 dir
    for dir in "${ROOTS[@]}" "${CODE_ROOTS[@]}" crates/sync/src crates/client/src; do
      mkdir -p "$root/$dir"
    done
    # The transport's relay path (NAT-traversal fallback) is a kept feature.
    cat >"$root/crates/sync/src/link.rs" <<'RS'
fn path_kind(addr: &iroh::TransportAddr) -> PathKind {
    match addr {
        iroh::TransportAddr::Relay(_) => crate::PathKind::Relay,
        _ => crate::PathKind::Direct,
    }
}
RS
    # Owner/Editor/Viewer sharing roles are a kept feature.
    cat >"$root/crates/client/src/dto.rs" <<'RS'
pub enum ShareRole { Owner, Editor, Viewer }
fn share_role(raw: &str) -> ShareRole { ShareRole::Viewer }
RS
    # Prose that names a removed implementation documents its removal.
    cat >"$root/crates/sync/NOTES.md" <<'MD'
The operator relay (`RelayHub`, `relay_server`) and the `http-coordination`
feature were removed.
MD
  }

  # "<case name>|<file>|<content>": each is planted into a fresh kept tree.
  local planted=(
    "operator relay type|crates/relay/src/hub.rs|pub struct RelayHub;"
    "operator relay client|crates/transport/src/lib.rs|mod relay_client;"
    "operator relay connection|crates/transport/src/relay.rs|pub struct RelayConnection;"
    "operator relay binary|crates/transport/Cargo.toml|name = \"yadorilink-relay\""
    "gRPC coordination feature|crates/daemon/Cargo.toml|http-coordination = []"
    "read/write role axis|crates/policy/src/role.rs|pub enum PolicyRole { Read, Write }"
    "read/write peer-role gate|crates/sync/src/peer.rs|pub enum PeerRole { Read, Write }"
    "read/write role map|crates/sync/src/netmap.ts|  sharedGroupRoles: Record<string, \"read\" | \"write\">;"
    "directional sync mode in prose|crates/sync/MODES.md|Set the folder to \`ReceiveOnly\` mode."
  )

  make_kept_tree "$tmp/kept"
  if (cd "$tmp/kept" && scan) >"$tmp/out" 2>&1; then
    echo "self-test ok: kept features pass"
  else
    echo "self-test FAILED: a tree with only kept features was rejected:"
    sed 's/^/  /' "$tmp/out"
    status=1
  fi

  local case name file content n=0
  for case in "${planted[@]}"; do
    name="${case%%|*}"
    file="${case#*|}"; file="${file%%|*}"
    content="${case#*|*|}"
    n=$((n + 1))
    make_kept_tree "$tmp/plant$n"
    mkdir -p "$(dirname "$tmp/plant$n/$file")"
    printf '%s\n' "$content" >"$tmp/plant$n/$file"
    # Detected means the scan fails AND names the planted file, so a failure
    # caused by something else in the fixture does not count.
    if ! (cd "$tmp/plant$n" && scan) >"$tmp/out" 2>&1 \
        && grep -qF "  $file:" "$tmp/out"; then
      echo "self-test ok: planted $name is detected"
    else
      echo "self-test FAILED: planted $name was not detected"
      status=1
    fi
  done

  # A checkout may carry only some of the scanned roots. A missing root must
  # not hide violations under the roots that are present.
  make_kept_tree "$tmp/partial"
  printf '%s\n' "pub struct RelayHub;" >"$tmp/partial/crates/sync/src/hub.rs"
  if ! (cd "$tmp/partial" && EXTRA_IMPL_ROOTS=(absent-root) && scan) >"$tmp/out" 2>&1 \
      && grep -qF "  crates/sync/src/hub.rs:" "$tmp/out"; then
    echo "self-test ok: planted symbol is detected with some roots missing"
  else
    echo "self-test FAILED: planted symbol was not detected with some roots missing"
    status=1
  fi
  return "$status"
}

# Run only when executed directly, so another script can source this file for
# its term lists and `scan`.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  if [ "${1:-}" = "--self-test" ]; then
    self_test
    exit $?
  fi

  cd "$(dirname "$0")/../.."

  if ! scan; then
    echo
    echo "check_removed_features: FAILED — a removed feature's symbols are present."
    exit 1
  fi
  echo
  echo "check_removed_features: OK — no residual removed-feature symbols."
fi
