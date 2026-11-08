#!/usr/bin/env bash
# Fail if a Windows binary this checkout just built imports the Visual C++ runtime (it would not start on a
# clean Windows). Same check the release bundle build runs, applied to the build output so a lost
# static-CRT setting shows up before a tag.
# usage: check-built-pe-imports.sh shell <profile>   (the shell extension workspace: host exe + COM dll)
#        check-built-pe-imports.sh root <profile>    (the root workspace: every yadorilink*.exe)
set -euo pipefail
cd "$(dirname "$0")/../.."
mode=${1:?shell|root}; profile=${2:?debug|release}
manifest=Cargo.toml
[ "$mode" = shell ] && manifest=crates/yadorilink-shell-ext-windows/Cargo.toml
target=$(cargo metadata --no-deps --format-version 1 --manifest-path "$manifest" |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
files=()
if [ "$mode" = shell ]; then
  files=("$target/$profile/yadorilink-cfapi-host.exe" "$target/$profile/yadorilink_shell_ext.dll")
  for f in "${files[@]}"; do [ -f "$f" ] || { echo "error: $f was not built"; exit 1; }; done
else
  shopt -s nullglob
  files=("$target/$profile"/yadorilink*.exe)
  [ ${#files[@]} -gt 0 ] || { echo "error: no yadorilink*.exe under $target/$profile"; exit 1; }
fi
python3 .github/release/check-pe-imports.py "${files[@]}"
