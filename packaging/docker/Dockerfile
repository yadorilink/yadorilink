# syntax=docker/dockerfile:1
#
# packaging/docker/Dockerfile
#
# Minimal multi-arch (linux/amd64, linux/arm64) image running only
# yadorilink-daemon -- the headless sync daemon, no CLI,
# no shell-extension integration (none of those are meaningful inside a
# container). Build and publish with `docker buildx build --platform
# linux/amd64,linux/arm64 -f packaging/docker/Dockerfile .` from the repo
# root (the build context must be the repo root, not this directory --
# the build stage needs the whole workspace).
#
# Cross-arch builds rely on buildx's QEMU emulation of the builder stage
# (no cross-compilation toolchain/target juggling): the builder stage is
# deliberately NOT pinned to `--platform=$BUILDPLATFORM` -- it must run
# under the *target* platform so `cargo build --release` (which targets
# whatever architecture it's actually running on, with no `--target` flag)
# produces a binary matching the runtime stage below, which is also the
# target platform. (An earlier version of this file pinned the builder to
# $BUILDPLATFORM for speed; that silently produced a wrong-architecture
# binary for any non-native --platform build -- "no such file or
# directory" at container start, not the "exec format error" a wrong-arch
# *static* binary gives, because the copied glibc dynamic linker path
# itself doesn't exist in the target-arch runtime image. Caught by
# actually running `docker run --platform linux/arm64 ... --version`, not
# just by a successful `docker buildx build`.) Slower than a real
# cross-compiler for a non-native target, but the whole point is this
# Dockerfile stays exactly as simple as a single-arch one.
#
# rusqlite is built with the "bundled" feature (see
# crates/yadorilink-daemon/Cargo.toml) and both HTTP clients use
# rustls, so the runtime stage needs no libsqlite3/openssl runtime
# package -- only ca-certificates, for the coordination-plane
# auth/update-manifest HTTPS calls that don't use the
# webpki-roots-bundled reqwest client.

ARG RUST_VERSION=1.98-bookworm

FROM rust:${RUST_VERSION} AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
# Full workspace copy (not just yadorilink-daemon): this is a Cargo
# workspace with a single Cargo.lock and path-dependencies across crates,
# same as every other build in this repo (`packaging/linux/build-deb.sh`,
# CI's `cargo build --workspace`).
COPY . .
# Release images talk to the production coordination service by default;
# YADORILINK_COORDINATION_ADDR still overrides it at runtime. Plain local
# builds leave this empty and fall back to loopback.
ARG YADORILINK_DEFAULT_COORDINATION_ADDR=
RUN if [ -z "$YADORILINK_DEFAULT_COORDINATION_ADDR" ]; then unset YADORILINK_DEFAULT_COORDINATION_ADDR; fi; \
    cargo build --release --locked \
    --workspace \
    --bin yadorilink-daemon

FROM debian:bookworm-slim AS runtime
# Git ref (release tag, or commit for nightly builds) the image was built from;
# it names the corresponding source in /usr/share/doc/yadorilink/SOURCE.txt.
ARG YADORILINK_SOURCE_REF=main
LABEL org.opencontainers.image.source="https://github.com/yadorilink/yadorilink" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /var/lib/yadorilink --shell /usr/sbin/nologin yadorilink

COPY --from=builder /build/target/release/yadorilink-daemon /usr/local/bin/yadorilink-daemon
# AGPL-3.0 licence text and the pointer to the corresponding source.
COPY --from=builder /build/LICENSE /usr/share/doc/yadorilink/LICENSE
RUN printf 'Corresponding source: https://github.com/yadorilink/yadorilink/tree/%s\n' "$YADORILINK_SOURCE_REF" \
    > /usr/share/doc/yadorilink/SOURCE.txt

# `device_config::config_dir()` (crates/yadorilink-daemon/src/device_config.rs)
# honors YADORILINK_CONFIG_DIR -- point it at a volume so device identity,
# sync state, and the local SQLite database survive a container restart.
ENV YADORILINK_CONFIG_DIR=/var/lib/yadorilink
VOLUME ["/var/lib/yadorilink"]

USER yadorilink
WORKDIR /var/lib/yadorilink
ENTRYPOINT ["/usr/local/bin/yadorilink-daemon"]
