#!/bin/bash
#
# Builds the C# binding of the client layer for the Windows engine bundle
# (.github/release/engine-bundle-layout.md).
#
#  1. The `yadorilink-client-ffi` dynamic library (or the one given with
#     --library).
#  2. The C# sources uniffi-bindgen-cs generates from that library, with the
#     generator built from the commit pinned in csharp-bindgen.pin.
#  3. A drift check of the generated API surface against the checked-in
#     snapshot (csharp-api-surface.txt), the generator's MPL-2.0 notice at the
#     top of each generated file, and BINDING-NOTES.md.
#
# Output (in --out DIR): Generated/*.cs and BINDING-NOTES.md. The app lives in
# its own repository and builds against the bundle; the sources are not checked
# in, only the API surface snapshot is.
#
# Usage:
#   .github/release/generate-csharp-binding.sh --out DIR [--library PATH]
#       [--debug] [--update-snapshot]
#
#   --library PATH     use this library (yadorilink_client_ffi.dll, lib*.so or
#                      lib*.dylib) instead of building one for this machine.
#                      The generated C# does not depend on the platform the
#                      library was built for.
#   --debug            build the library without optimization (the drift
#                      check in CI; the output is the same).
#   --update-snapshot  rewrite csharp-api-surface.txt instead of checking it.
#
# YADORILINK_CS_BINDGEN_ROOT chooses where the generator is installed
# (default: under cargo's target directory).
#
# The generated code refuses to load a library whose API checksums differ, so
# the bundle ships the library and the C# generated from it together.

set -euo pipefail

OUT_DIR=""
LIBRARY=""
PROFILE_ARGS=(--release)
PROFILE_DIR="release"
UPDATE=0
while [ $# -gt 0 ]; do
    case "$1" in
        --out) OUT_DIR="${2:?--out needs a directory}"; shift 2 ;;
        --library) LIBRARY="${2:?--library needs a path}"; shift 2 ;;
        --debug) PROFILE_ARGS=(); PROFILE_DIR="debug"; shift ;;
        --update-snapshot) UPDATE=1; shift ;;
        *) echo "usage: $0 --out DIR [--library PATH] [--debug] [--update-snapshot]" >&2; exit 2 ;;
    esac
done
[ -n "$OUT_DIR" ] || { echo "usage: $0 --out DIR [--library PATH] [--debug] [--update-snapshot]" >&2; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TOOL="$SCRIPT_DIR/csharp-binding.py"
PIN="$SCRIPT_DIR/csharp-bindgen.pin"

cd "$REPO_ROOT"

# The generator reads libraries from one UniFFI minor; it must be the one
# the workspace links.
python3 "$TOOL" pin-check

pin() { sed -n "s/^$1=//p" "$PIN"; }
GEN_REPO="$(pin repository)"
GEN_REV="$(pin rev)"
GEN_VERSION="$(pin version)"

TARGET_DIR="$(cargo metadata --format-version 1 --no-deps \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])')"

# ---- the generator ----------------------------------------------------------------

BINDGEN_ROOT="${YADORILINK_CS_BINDGEN_ROOT:-$TARGET_DIR/csharp-bindgen/$GEN_REV}"
BINDGEN="$BINDGEN_ROOT/bin/uniffi-bindgen-cs"
[ -f "$BINDGEN" ] || BINDGEN="$BINDGEN.exe"
if [ ! -f "$BINDGEN" ] || [ "$("$BINDGEN" --version 2>/dev/null || true)" != "uniffi-bindgen $GEN_VERSION" ]; then
    echo "== installing uniffi-bindgen-cs $GEN_VERSION ($GEN_REV) =="
    cargo install uniffi-bindgen-cs --git "$GEN_REPO" --rev "$GEN_REV" --locked --root "$BINDGEN_ROOT"
    BINDGEN="$BINDGEN_ROOT/bin/uniffi-bindgen-cs"
    [ -f "$BINDGEN" ] || BINDGEN="$BINDGEN.exe"
fi
[ "$("$BINDGEN" --version)" = "uniffi-bindgen $GEN_VERSION" ] \
    || { echo "uniffi-bindgen-cs at $BINDGEN is not $GEN_VERSION" >&2; exit 1; }

# ---- the library ------------------------------------------------------------------

if [ -z "$LIBRARY" ]; then
    echo "== building yadorilink-client-ffi ($PROFILE_DIR) =="
    cargo build -p yadorilink-client-ffi --locked ${PROFILE_ARGS[@]+"${PROFILE_ARGS[@]}"}
    case "$(uname -s)" in
        Darwin) LIBRARY="$TARGET_DIR/$PROFILE_DIR/libyadorilink_client_ffi.dylib" ;;
        MINGW* | MSYS* | CYGWIN*) LIBRARY="$TARGET_DIR/$PROFILE_DIR/yadorilink_client_ffi.dll" ;;
        *) LIBRARY="$TARGET_DIR/$PROFILE_DIR/libyadorilink_client_ffi.so" ;;
    esac
fi
test -f "$LIBRARY" || { echo "missing $LIBRARY"; exit 1; }

# ---- generate, check, write -------------------------------------------------------

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/Generated"
# --no-format: the formatter is an optional external tool, and the output has
# to be the same on every machine. Each crate's own uniffi.toml is found through
# cargo metadata, which is why this runs from the repository root.
"$BINDGEN" --no-format --library "$LIBRARY" --out-dir "$WORK/Generated"

if [ "$UPDATE" = "1" ]; then
    python3 "$TOOL" check "$WORK/Generated" --update
else
    python3 "$TOOL" check "$WORK/Generated"
fi
# The generator is MPL-2.0: put its notice at the top of each generated file.
python3 "$TOOL" notice "$WORK/Generated"
python3 "$TOOL" notes "$WORK/Generated" --out "$WORK/BINDING-NOTES.md"

rm -rf "$OUT_DIR/Generated"
mkdir -p "$OUT_DIR"
cp -R "$WORK/Generated" "$OUT_DIR/Generated"
cp "$WORK/BINDING-NOTES.md" "$OUT_DIR/BINDING-NOTES.md"

echo "== C# binding written: $OUT_DIR/Generated =="
