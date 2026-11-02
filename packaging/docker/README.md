# Docker image

`ghcr.io/yadorilink/yadorilink:<version>` is the image for a NAS or an
always-on server (`linux/amd64`, `linux/arm64`). It holds the sync daemon
(`yadorilink-daemon`) and the `yadorilink` command line of the same release,
and nothing else: no desktop app, no file-manager integration. Use the exact
release version as the tag (for example `0.1.0-beta.9`); pre-releases never
move `latest`.

## Run

Copy [`compose.yaml`](compose.yaml) next to a `.env` file:

```sh
IMAGE_TAG=0.1.0-beta.9      # the release you install
PUID=1000                   # owner of the synced folder (`id` on the NAS)
PGID=1000
```

```sh
docker compose up -d
docker compose exec yadorilink yadorilink login --device
docker compose exec yadorilink yadorilink device register --name my-nas
docker compose exec yadorilink yadorilink share create my-share --path /srv/yadorilink
```

`login --device` prints a link; open it in a browser on any computer and sign
in. Instead, you can create a code on your account's Devices page (Add device)
and run `docker compose exec yadorilink yadorilink login --code`, which asks
for it (valid 10 minutes, works once). Without Compose:

```sh
docker run -d --name yadorilink --restart unless-stopped \
  -e PUID=1000 -e PGID=1000 \
  -v yadorilink-data:/var/lib/yadorilink -v /srv/yadorilink:/srv/yadorilink \
  ghcr.io/yadorilink/yadorilink:0.1.0-beta.9
```

## Contract

| | |
|---|---|
| Command line | `yadorilink` is on `PATH`; use `docker exec NAME yadorilink ...`. It runs as the daemon's account, so credentials and the control socket agree. |
| Volumes | `/var/lib/yadorilink`: device identity, credentials, index and block store (`YADORILINK_CONFIG_DIR`). Never delete it (`down -v`) unless you want a new device identity. Synced folders are bind mounts you choose, for example `/srv/yadorilink`. |
| User | The daemon never runs as root. The entrypoint starts as root only to give the state volume to `PUID:PGID` (default `999:999`) and then drops to that account. `docker run --user UID:GID` skips the root step; then `/var/lib/yadorilink` must already be writable by that user. |
| Synced folders | Never chowned. Set `PUID`/`PGID` to the folder owner's ids (Synology and QNAP show them per user, or run `id`), so files the daemon writes stay yours and you can edit them. |
| Read-only root | Works: `read_only: true` with `tmpfs: /tmp`. Only the volumes are written. |
| Capabilities | `cap_drop: ALL` with `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID` and `SETGID` is enough (the entrypoint needs them only to hand the state volume over before it drops to `PUID:PGID`). |
| Ports | None published. Sync is outbound and peer to peer. The web dashboard listens on the container's loopback only; reach it with the app's Manage button, or put a TLS-terminating reverse proxy in front and set `YADORILINK_HTTP_API_PUBLIC_HOST` and `YADORILINK_HTTP_API_TRUST_REVERSE_PROXY=1`. An SSH tunnel to the host does not reach it. |
| Health | `HEALTHCHECK` runs `yadorilink-daemon --healthcheck`; `docker ps` shows `healthy`. |
| Stop | `SIGTERM` stops the daemon cleanly; Compose allows 60 s. |
| Restart inside the container | The entrypoint keeps the daemon running as PID 1's child: when the daemon exits on purpose with status 0 or 75 it starts it again, so `yadorilink device register` (the daemon reads its identity at startup) and `yadorilink daemon stop` restart the daemon and the `docker exec` finishes normally; they do not stop the container, with or without a restart policy. Any other exit status, and `docker stop` (SIGTERM), end the container. |
| Labels | Standard `org.opencontainers.image.*` (version, revision, source, licenses). |

Environment: `PUID`, `PGID`, `YADORILINK_COORDINATION_ADDR` (override the
service), `YADORILINK_NAS_ADMIN=1` (let the app's Manage button administer
this device). The image already sets `YADORILINK_CONFIG_DIR`,
`YADORILINK_CREDENTIAL_STORE=file` and `YADORILINK_DISABLE_OS_KEYRING=1`.

## Troubleshooting

`permission denied` while linking a folder means the daemon's account cannot
write it. Compare `docker compose exec yadorilink id` with `ls -ln` of the
folder and set `PUID`/`PGID` to the folder owner's ids.

## Build locally

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  -f packaging/docker/Dockerfile -t yadorilink:local .
```

Run from the repository root (the build stage needs the whole Cargo
workspace). Each architecture should be built on a machine of that
architecture (or `docker buildx` with a native builder node); an emulated
build of the whole workspace is very slow.

## Release

`.github/workflows/docker-image.yml` builds each architecture on its own
native runner for every `v*` tag, assembles one multi-architecture image,
signs a build-provenance attestation for the image digest, and verifies that
attestation before the job succeeds. Verify a pulled image yourself with
`gh attestation verify oci://ghcr.io/yadorilink/yadorilink:<version> --repo yadorilink/yadorilink`.
The GHCR package must be public once (package settings), after which nothing
needs credentials to pull.
