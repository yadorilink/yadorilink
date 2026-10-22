# Docker image

A minimal, multi-arch (`linux/amd64`, `linux/arm64`) image running only
`yadorilink-daemon` — no CLI, no desktop app, no file-manager
integration (none of those are meaningful inside a container). See
`Dockerfile`'s own header comment for build details.

## Run

```sh
docker run -d \
  --name yadorilink-daemon \
  -v yadorilink-data:/var/lib/yadorilink \
  ghcr.io/yadorilink/yadorilink-daemon:latest
```

State (device identity, the local SQLite index, sync policy) lives under
`/var/lib/yadorilink` (`YADORILINK_CONFIG_DIR`, set by the image) — mount
a named volume or bind mount there so it survives a container restart.
There is currently no way to drive the CLI (`yadorilink status`, `yadorilink
link ...`) against a containerized daemon from outside the container; use
`docker exec` with a CLI binary added to the image, or run the CLI on the
host against a bind-mounted control socket, until a dedicated
container-friendly control path exists.

## Build locally

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  -f packaging/docker/Dockerfile -t yadorilink-daemon:local .
```

Run from the **repository root** (the build stage needs the whole Cargo
workspace, not just this directory). A non-native `--platform` target
runs under QEMU emulation (see `Dockerfile`'s comment) — register it first
if `buildx` doesn't already have it:

```sh
docker run --privileged --rm tonistiigi/binfmt --install arm64
```

## Verification performed

`linux/amd64` was built **and run** (not just built) as part of this
verification pass; `linux/arm64` was not — see below.

- `linux/amd64`: native build, `docker run ... --version` printed
  `yadorilink-daemon 0.1.0`, confirmed non-root (`uid=999(yadorilink)`),
  final image size 173MB.
- `linux/arm64`: built and run under QEMU emulation (`docker run
  --platform linux/arm64 ...`). This caught a real bug — the Dockerfile
  originally pinned its builder stage to the *build* platform for speed,
  which silently produced a wrong-architecture (amd64) binary inside the
  arm64 runtime image; fixed by removing that pin (see the Dockerfile's
  own comment for the exact failure mode and why it wasn't `exec format
  error`). The fix was re-verified against real arm64 compilation
  mechanics (QEMU registered, workspace crates compiling for `aarch64`)
  but the final confirming end-to-end `docker run --platform linux/arm64
  ... --version` could not be completed to a clean pass — the build host
  ran low on disk space under concurrent load and repeatedly hit real
  disk exhaustion partway through a full-workspace emulated compile. The
  fix itself is well-understood and low-risk (removes an incorrect
  `--platform` pin, does not change what gets compiled); confirm it with
  a clean `docker buildx build --platform linux/arm64 ... --load` +
  `docker run --platform linux/arm64 ... --version` on a host with more
  headroom before relying on the published arm64 image.

## GHCR visibility

`.github/workflows/release.yml`'s `docker-artifacts` job pushes
to `ghcr.io/yadorilink/yadorilink-daemon` using the workflow's own
`GITHUB_TOKEN` (`packages: write`, scoped to that one job run — not a
managed secret). **A new GHCR package defaults to private** on its first
push; someone with admin access needs to set it to public once, in the
package's own Settings → Danger Zone (or link it to the `yadorilink`
repository, which also makes it inherit that repo's visibility) — not
something this workflow can do on its own via `GITHUB_TOKEN`.
