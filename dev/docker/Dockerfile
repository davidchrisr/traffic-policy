# Runtime for the development stack: system packages, the pinned Bun, and the service accounts.
# The application is not in the image; the build service compiles the mounted source per stack.
# Reviewed 2026-11-07: the newest trixie-slim release older than 48 hours.
FROM debian:trixie-20261027-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4 AS base

# Bun from packaging/linux/runtime.json, verified as npm published it before extraction, and then
# as the binary the packaging pins. Only the binary reaches the runtime image. The pin is linux-x64,
# so other architectures stop here instead of failing later with an exec format error.
FROM base AS bun
ARG TARGETARCH
RUN if [ "$TARGETARCH" != amd64 ]; then \
      printf 'The development image is amd64 only (Bun linux-x64); this build targets %s\n' \
        "$TARGETARCH" >&2; \
      exit 1; \
    fi
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
ARG BUN_VERSION=1.4.2
ARG BUN_TARBALL_SHA512=f7f13f517393a52a3762c57983e161b5377fa93a625a82aec52d7672ab6e600d6cb2ef5f440a0f4278a91601b2724ded58eeb7894771062ca0abe9042c56b09e
ARG BUN_SHA256=a83d263767d839e4d2649ca8e35d07159c7afc99afdc96d731ced29e056dda0c
WORKDIR /tmp/bun
RUN curl -fsSL -w "%{stderr}curl: %{url}\n" -o bun.tgz \
      "https://registry.npmjs.org/@oven/bun-linux-x64/-/bun-linux-x64-${BUN_VERSION}.tgz" \
 && printf '%s  %s\n' "$BUN_TARBALL_SHA512" bun.tgz | sha512sum -c - \
 && tar -xzf bun.tgz package/bin/bun \
 && printf '%s  %s\n' "$BUN_SHA256" package/bin/bun | sha256sum -c -

FROM base
# curl and dnsutils generate the client's traffic; the rest are the gateway's dependencies from
# SETUP.md plus rsync for the build service.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    ca-certificates conntrack curl dnsutils iproute2 iputils-ping netcat-openbsd nftables \
    openssl procps rsync suricata util-linux \
 && rm -rf /var/lib/apt/lists/*

COPY --from=bun --chmod=0755 /tmp/bun/package/bin/bun /opt/traffic-policy/runtime/bin/bun

# The accounts SETUP.md creates. Suricata's account stays out of the traffic-policy group.
RUN groupadd --system traffic-policy \
 && useradd --system --gid traffic-policy --no-create-home --shell /usr/sbin/nologin traffic-policy \
 && groupadd --system traffic-policy-suricata \
 && useradd --system --gid traffic-policy-suricata --no-create-home \
    --shell /usr/sbin/nologin traffic-policy-suricata

# Stands in for systemd where the application calls systemctl.
COPY --chmod=0755 systemctl /usr/bin/systemctl
