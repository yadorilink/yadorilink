# APT repository tooling

**Status: not published yet.** There is no YadoriLink APT repository today and
no APT signing key exists. To install on Debian or Ubuntu, download the
`.deb` from GitHub Releases and install it with
`sudo apt install ./yadorilink-linux-amd64.deb` (see
[`../README.md`](../README.md)).

This directory holds the tooling for a signed APT repository (`Release` /
`InRelease` metadata, `Packages` indices and a `pool/` of `.deb` files) that
the release workflow can publish once a signing key is configured.

## What's here

- `install.sh`: registers the archive's public signing key and a `deb822`
  `.sources` entry (needs apt >= 2.4: Debian 12 / Ubuntu 22.04 or newer). It
  does not run `apt-get update` or `apt-get install` for you.
- `build-keyring-deb.sh`: builds `yadorilink-archive-keyring_<version>_all.deb`
  (the same key and `.sources` file, for a `dpkg -i` install instead of piping a
  script to a shell).
- `../build-apt-repo.sh`: assembles the repository tree (`dists/`, `pool/`)
  from already-built `.deb` files and signs it; its header comment describes
  the exact layout.

## Signing key (maintainers)

The publish step in `.github/workflows/release.yml` runs only when the
`APT_SIGNING_KEY` secret exists in the protected `release-signing`
Environment, and skips publishing without failing the release when it is
absent. Today it is absent, so this path has not run against a real key. The
mechanism is tested end to end (`gpg --verify` of `InRelease` and
`Release.gpg`, then `apt-get update && apt-get install yadorilink` in a clean
Ubuntu 24.04 container) with a throwaway development key that is never
committed.

To enable publishing:

1. Generate a dedicated GPG key for this archive only (Ed25519 is supported by
   every apt this project targets; RSA-4096 only if ancient apt versions
   must be supported) on a trusted machine, and record the participants, date,
   device and key fingerprint as release evidence.
2. Store the exported private key only as `APT_SIGNING_KEY` in the protected
   `release-signing` Environment, never as a repository-level secret. The
   workflow derives the key id from it and publishes the public half
   (`yadorilink-archive-keyring.asc`) itself.
3. To rotate, publish the new key's `.asc` and keyring `.deb` next to the old
   ones for a transition window long enough for existing installs to refresh
   the keyring package, then retire the old key.
