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
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin rusty-conduit-switch

LABEL org.opencontainers.image.title="rusty-conduit-switch" \
      org.opencontainers.image.description="Lightweight HTTP/HTTPS and SOCKS4/4a/5 Auto Switch proxy server with optional HTTPS MITM inspection" \
      org.opencontainers.image.licenses="BSD-3-Clause"

# Listen on all interfaces inside the container; publish ports on loopback unless you
# intend to expose the proxy (v1 has no inbound authentication).
ENV RUSTY_CONDUIT_SWITCH_BIND=0.0.0.0

EXPOSE 3128 1080
USER rusty-conduit-switch
ENTRYPOINT ["/usr/local/bin/rusty-conduit-switch"]

# Fast multi-arch packaging target for CI (uses native binaries placed in dist/linux-<arch>/).
FROM base AS prebuilt
ARG TARGETARCH
COPY --chmod=0755 dist/linux-${TARGETARCH}/rusty-conduit-switch /usr/local/bin/rusty-conduit-switch

# Default target for local `docker build .` and CI Dockerfile validation.
FROM base AS runtime
COPY --from=builder --chmod=0755 /src/target/release/rusty-conduit-switch /usr/local/bin/rusty-conduit-switch
