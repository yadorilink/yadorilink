#!/usr/bin/env bash
# Build the standalone Ed25519 verifier reproducibly.
#
#   build-verifier.sh <target-name> <out-dir>
#
# <target-name> is the installer's platform name (linux-x86_64, macos-aarch64). Writes
# <out-dir>/yadorilink-verify-<target-name> and its .sha256 sidecar. The build path, the cargo
# and rustup homes are remapped out of the binary and the profile is fixed here, so the same
# source, lockfile and toolchain give the same bytes from any checkout location.
set -euo pipefail

target_name=${1:?target name}
out_dir=${2:?output directory}
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
crate="$root/crates/yadorilink-verify"

case "$target_name" in
    linux-x86_64) triple=x86_64-unknown-linux-gnu ;;
    macos-aarch64) triple=aarch64-apple-darwin ;;
    *) echo "unsupported target name: $target_name" >&2; exit 2 ;;
esac

mkdir -p "$out_dir"
build_dir="$(mktemp -d)"
trap 'rm -rf "$build_dir"' EXIT

export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_PANIC=abort
export CARGO_PROFILE_RELEASE_STRIP=symbols
export CARGO_PROFILE_RELEASE_DEBUG=false
export CARGO_INCREMENTAL=0
export MACOSX_DEPLOYMENT_TARGET=14.0
export SOURCE_DATE_EPOCH=0
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
export RUSTFLAGS="--remap-path-prefix=$crate=/verify --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$rustup_home=/rustup"

cargo build --release --locked --target "$triple" \
    --manifest-path "$crate/Cargo.toml" --target-dir "$build_dir/target"

bin="$build_dir/target/$triple/release/yadorilink-verify"
dest="$out_dir/yadorilink-verify-$target_name"
cp "$bin" "$dest"
chmod 755 "$dest"
if command -v sha256sum >/dev/null 2>&1; then
    sum="$(sha256sum "$dest" | cut -d' ' -f1)"
else
    sum="$(shasum -a 256 "$dest" | cut -d' ' -f1)"
fi
printf '%s  %s\n' "$sum" "yadorilink-verify-$target_name" > "$dest.sha256"
echo "$sum  yadorilink-verify-$target_name"
