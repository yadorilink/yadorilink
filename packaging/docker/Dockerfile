# syntax=docker/dockerfile:1
#
# packaging/docker/Dockerfile
#
# The NAS / always-on-server image (linux/amd64, linux/arm64): the headless
# sync daemon plus the `yadorilink` command line, no desktop app and no
# file-manager integration (none of those are meaningful inside a container).
# Build with `docker buildx build -f packaging/docker/Dockerfile .` from the
# repository root (the build stage needs the whole workspace, so the build
# context must be the root, not this directory).
#
# Each architecture is built natively (on an arm64 builder for arm64) rather
# than cross-compiled: the builder stage is deliberately NOT pinned to
# `--platform=$BUILDPLATFORM`, because `cargo build --release` has no
# `--target` flag here and compiles for the architecture it runs on, which must
# be the architecture of the runtime stage below.
#
# The builder is Debian 12, so the binaries need glibc 2.36 or newer, the same
# floor as the runtime stage; rusqlite is built with the "bundled" feature and
# both HTTP clients use rustls, so the runtime needs no libsqlite3 or openssl.
#
# Runtime contract (see README.md next to this file):
#   * Volume /var/lib/yadorilink holds the device identity, sync state and
#     credentials (YADORILINK_CONFIG_DIR). Synced folders are bind mounts.
#   * The daemon never runs as root. The entrypoint starts as root only to
#     match the state directory to PUID/PGID (default 999:999) and then drops
#     to that account; `docker run --user UID:GID` skips the root step.
#   * The root filesystem can be read-only; only the volumes are written.
#   * `docker exec NAME yadorilink ...` runs the CLI as the daemon's account.
#   * HEALTHCHECK is `yadorilink-daemon --healthcheck`; SIGTERM stops the
#     daemon cleanly (docker stop's default).

ARG RUST_VERSION=1.98-bookworm

FROM rust:${RUST_VERSION} AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
# Full workspace copy: this is a Cargo workspace with a single Cargo.lock and
# path dependencies across crates, like every other build in this repository.
COPY . .
# Release images talk to the production coordination service by default;
# YADORILINK_COORDINATION_ADDR still overrides it at runtime. Plain local
# builds leave this empty and fall back to loopback.
ARG YADORILINK_DEFAULT_COORDINATION_ADDR=
# A release build also compiles in the release manifest trust root, exactly as
# the other release binaries do. Plain local builds leave both empty.
ARG YADORILINK_RELEASE_MANIFEST_KEY_ID=
ARG YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX=
RUN set -eu; \
    if [ -z "$YADORILINK_DEFAULT_COORDINATION_ADDR" ]; then unset YADORILINK_DEFAULT_COORDINATION_ADDR; fi; \
    features=""; \
    if [ -n "$YADORILINK_RELEASE_MANIFEST_KEY_ID" ]; then \
        export YADORILINK_RELEASE_MANIFEST_KEY_ID YADORILINK_RELEASE_MANIFEST_PUBLIC_KEY_HEX; \
        features="--features enforce-release-trust-root"; \
    fi; \
    cargo build --release --locked -p yadorilink-cli; \
    cargo build --release --locked -p yadorilink-daemon $features

FROM debian:bookworm-slim AS runtime
# Version and git ref (release tag, or commit for nightly builds) the image was
# built from; the ref names the corresponding source in
# /usr/share/doc/yadorilink/SOURCE.txt.
ARG YADORILINK_VERSION=0.0.0
ARG YADORILINK_SOURCE_REF=main
ARG YADORILINK_REVISION=
LABEL org.opencontainers.image.title="YadoriLink" \
      org.opencontainers.image.description="YadoriLink sync daemon and command line for a NAS or always-on server" \
      org.opencontainers.image.url="https://yadori.link" \
      org.opencontainers.image.documentation="https://github.com/yadorilink/yadorilink/tree/main/packaging/docker" \
      org.opencontainers.image.source="https://github.com/yadorilink/yadorilink" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${YADORILINK_VERSION}" \
      org.opencontainers.image.revision="${YADORILINK_REVISION}"
# util-linux (already in the base image) provides setpriv, used to drop root.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 999 yadorilink \
    && useradd --system --uid 999 --gid 999 --no-create-home --home-dir /var/lib/yadorilink --shell /usr/sbin/nologin yadorilink \
    && install -d -o 999 -g 999 -m 0700 /var/lib/yadorilink

COPY --from=builder /build/target/release/yadorilink-daemon /usr/local/bin/yadorilink-daemon
COPY --from=builder /build/target/release/yadorilink /usr/libexec/yadorilink/yadorilink
COPY packaging/docker/yadorilink-entrypoint.sh /usr/local/bin/yadorilink-entrypoint
COPY packaging/docker/yadorilink-cli.sh /usr/local/bin/yadorilink
# AGPL-3.0 licence text and the pointer to the corresponding source.
COPY --from=builder /build/LICENSE /usr/share/doc/yadorilink/LICENSE
RUN chmod 0755 /usr/local/bin/yadorilink-entrypoint /usr/local/bin/yadorilink \
    && printf 'Corresponding source: https://github.com/yadorilink/yadorilink/tree/%s\n' "$YADORILINK_SOURCE_REF" \
    > /usr/share/doc/yadorilink/SOURCE.txt

# Device identity, sync state, the local SQLite database and the sign-in
# credentials live in one directory that survives a container restart. The OS
# keyring does not exist in a container, so credentials go to a file in it.
ENV YADORILINK_CONFIG_DIR=/var/lib/yadorilink \
    YADORILINK_CREDENTIAL_STORE=file \
    YADORILINK_DISABLE_OS_KEYRING=1 \
    YADORILINK_IN_CONTAINER=1 \
    YADORILINK_DAEMON_SUPERVISED=1
VOLUME ["/var/lib/yadorilink"]
WORKDIR /var/lib/yadorilink

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD ["/usr/local/bin/yadorilink-daemon", "--healthcheck"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/yadorilink-entrypoint"]
