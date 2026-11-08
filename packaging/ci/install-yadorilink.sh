#!/bin/sh
# Install a pinned YadoriLink engine on a macOS or Linux CI runner.
#
#   install-yadorilink.sh VERSION PREFIX [CHANNEL]
#
# The installer is taken from the release of exactly VERSION, its build-provenance attestation
# is verified with `gh attestation verify` (any failure fails the job), and only then is it run.
# The installer repeats the signed-manifest and hash checks for the engine bundle itself, so a
# CI install is verified the same way as an interactive one. Prints the bin directory on the
# last line of stdout.
set -eu

version=${1:?usage: install-yadorilink.sh VERSION PREFIX [CHANNEL]}
prefix=${2:?usage: install-yadorilink.sh VERSION PREFIX [CHANNEL]}
channel=${3:-beta}
repo=yadorilink/yadorilink

case "$version" in
    *[!0-9A-Za-z.+-]* | "" ) echo "error: not a version: $version" >&2; exit 2 ;;
esac
case "$prefix" in /*) ;; *) echo "error: the prefix must be an absolute path" >&2; exit 2 ;; esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

curl -fsSL --retry 3 -o "$work/install.sh" \
    "https://github.com/$repo/releases/download/v$version/install.sh"
gh attestation verify "$work/install.sh" --repo "$repo" >&2

sh "$work/install.sh" --yes --no-modify-path --channel "$channel" --version "$version" --prefix "$prefix" >&2
printf '%s\n' "$prefix/bin"
