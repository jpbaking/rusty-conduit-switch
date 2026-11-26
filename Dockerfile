# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder
WORKDIR /src

# Cache dependency compilation separately from source changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && printf 'pub fn _stub() {}\n' > src/lib.rs \
    && printf 'fn main() {}\n' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
RUN touch src/lib.rs src/main.rs \
    && cargo build --release --locked

FROM ubuntu:26.04 AS base
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get dist-upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 rusty-conduit-switch \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin rusty-conduit-switch \
    && install -d -o 10001 -g 10001 -m 0755 /var/log/rusty-conduit-switch

LABEL org.opencontainers.image.title="rusty-conduit-switch" \
      org.opencontainers.image.description="Lightweight HTTP/HTTPS and SOCKS4/4a/5 Auto Switch proxy server with optional HTTPS MITM inspection" \
      org.opencontainers.image.licenses="BSD-3-Clause"

# Listen on all interfaces inside the container; publish ports on loopback unless you
# intend to expose the proxy (v1 has no inbound authentication).
ENV RUSTY_CONDUIT_SWITCH_BIND=0.0.0.0

# glibc gives every worker thread its own malloc arena, which multiplies memory on hosts with
# many CPUs (about 8x per open connection); two arenas keep it low with no measurable
# throughput cost.
ENV MALLOC_ARENA_MAX=2

EXPOSE 3128 1080
# Numeric, so orchestrators can verify the image never runs as root (Kubernetes
# runAsNonRoot).
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/rusty-conduit-switch"]

# Fast multi-arch packaging target for CI (uses native binaries placed in dist/linux-<arch>/).
FROM base AS prebuilt
ARG TARGETARCH
COPY --chmod=0755 dist/linux-${TARGETARCH}/rusty-conduit-switch /usr/local/bin/rusty-conduit-switch

# Default target for local `docker build .` and CI Dockerfile validation.
FROM base AS runtime
COPY --from=builder --chmod=0755 /src/target/release/rusty-conduit-switch /usr/local/bin/rusty-conduit-switch
