# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Tiago Beltrao de Azevedo Tenorio Acioli / Postern Labs
#
# Consiglio console HTTP service — HOSTED deploy image (reference prototype).
#
# STATUS: DEFERRED / VM-host-service-gated. UNAUDITED. This wiring is WRITTEN and
# host-tested (the service + its self-check run GREEN on the build host), but the
# LIVE hosted deploy needs an operator to build + run this image on a VM/host
# service (Fly/Workers-container/a plain VM). It is NOT a Cloudflare Pages static
# asset and CANNOT be one: wallet-login verification spawns the NATIVE hybrid-PQ
# `consiglio-verify` binary (Falcon-1024 ‖ ML-DSA-65) — a browser/edge-Worker
# cannot run it, which is exactly why the shipping form is a server, not a page.
#
# WHY TWO STAGES
#   1. rust-builder — compiles the REAL verifier the JS bridge spawns. Without
#      this binary the service still boots but login FAILS CLOSED (never a stub).
#   2. runtime      — a Node image that carries ONLY the compiled binary + the
#      console source, and PINS CONSIGLIO_VERIFIER_BIN to the baked-in binary so
#      the bridge runs exactly that trusted path (fail-closed: no target/ scan).
#
# BUILD CONTEXT: the repository ROOT (needs crates/ + enterprise/).
#   docker build -f enterprise/cloud/services/console/http/deploy/Dockerfile -t consiglio-console .

# ---- stage 1: build the native hybrid-PQ verifier -------------------------
FROM rust:1.83-bookworm AS rust-builder
WORKDIR /src
# Copy the whole workspace so the git-sourced bloch-crypto dep resolves against
# the committed Cargo.lock (reproducible verifier provenance).
COPY . .
RUN cargo build --release --features verifier-bin --bins -p postern-consiglio-auth \
 && cp target/release/consiglio-verify /out-consiglio-verify

# ---- stage 2: the Node runtime service ------------------------------------
FROM node:22-bookworm-slim AS runtime
# The service is dependency-free Node (node: builtins only) — no npm install.
WORKDIR /app

# The console source (the JS mirror + the HTTP service).
COPY enterprise/cloud/services/console ./enterprise/cloud/services/console

# The trusted verifier binary, at a stable absolute path we PIN below.
COPY --from=rust-builder /out-consiglio-verify /opt/postern/bin/consiglio-verify
RUN chmod 0555 /opt/postern/bin/consiglio-verify

# Fail-closed provenance pin: the bridge runs EXACTLY this binary and refuses to
# fall back to a target/ scan. (See consiglio-verifier.mjs resolveVerifierPath.)
ENV CONSIGLIO_VERIFIER_BIN=/opt/postern/bin/consiglio-verify
# Durable store lives on a mounted volume so a restart keeps enrollments, live
# sessions, the sub registry, and the SHAKE-256 audit chain.
ENV CONSOLE_DATA_DIR=/data
ENV PORT=8803
ENV SESSION_TTL_SECS=3600

# Drop privileges — the service holds no secret key material, only public keys.
RUN useradd -r -u 10001 consiglio && mkdir -p /data && chown consiglio /data
USER consiglio
VOLUME ["/data"]
EXPOSE 8803

# Liveness: /healthz reports verifier availability + rails (no session needed).
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+ (process.env.PORT||8803) +'/healthz').then(r=>r.json()).then(j=>process.exit(j.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "enterprise/cloud/services/console/http/server.mjs"]
