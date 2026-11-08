# SPDX-License-Identifier: MIT OR Apache-2.0
# Dockerfile — deployable image for Bloch (enterprise/comms/app), Postern Labs'
# org-internal messenger. Build-only scaffold; sibling of the hosted "cloud"
# edition image at ../../../cloud/image/Containerfile, whose reproducibility /
# non-root / egress-controlled / telemetry-off conventions this MIRRORS.
#
# WHAT THIS IS. Bloch's app/ is a self-contained, framework-free static bundle
# (index.html + ES modules; connect-src 'none' in its own CSP). It has no
# server of its own — the app's README says "open index.html in a browser".
# This image adds the one thing a container needs that a browser doesn't: an
# HTTP listener. That listener is deploy/server.mjs — zero npm dependencies,
# `node:http` + `node:fs` only, in keeping with this repo's existing
# zero-dependency test/tooling convention (see enterprise/comms/app/self-check.mjs).
#
# REPRODUCIBLE-BY-DESIGN, NOT REPRODUCED (same disclosure as the cloud image):
# base pinned by DIGEST, SOURCE_DATE_EPOCH honored, no network during the final
# COPY/assembly stage. No independent bit-for-bit reproduction has been
# performed or attested here — verify it yourself (rebuild + sha256 compare).
#
# HOSTED = LESS PRIVATE (DISCLOSED). Same trade-off as the cloud image: running
# Bloch as a hosted/managed container lets the operator observe traffic,
# metadata and timing a self-hosted or on-device deployment would not expose.
# Bloch is already explicit that it is an employer-run tool, not "100%
# private" (src/transparency.mjs) — hosting it centrally does not change that,
# it is simply disclosed again here.
#
# NOT hardened beyond what is shown, NOT audited, NOT production-ready.
# Reference prototype, pre-production — matches the app's own README.
#
# Build (operator/dev-run; does NOT push or deploy):
#   docker build -f enterprise/comms/app/deploy/Dockerfile \
#     -t postern-comms-app:local .          # context MUST be the repo root —
#                                            # the image needs enterprise/features/
#                                            # and enterprise/comms/compliance/,
#                                            # which live outside comms/app/.
# or pin a vetted base + provenance the same way the cloud image does:
#   docker build \
#     --build-arg BASE_DIGEST=sha256:<vetted-node-slim-digest> \
#     --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct 2>/dev/null || echo 0)" \
#     -f enterprise/comms/app/deploy/Dockerfile -t postern-comms-app:local .

# ── Base, pinned by DIGEST (never a floating tag) ───────────────────────────
# Default below is the real node:22-bookworm-slim digest (vetted at authoring
# time) so the literal `docker build` command in this file's header/README
# resolves out of the box; override with --build-arg BASE_DIGEST=... to pin a
# freshly-vetted digest of your own, exactly like the cloud image's Containerfile.
# A tag can move; a digest cannot.
ARG BASE_DIGEST=sha256:53ada149d435c38b14476cb57e4a7da73c15595aba79bd6971b547ceb6d018bf
FROM node:22-bookworm-slim@${BASE_DIGEST} AS runtime

# ── Reproducibility knobs ───────────────────────────────────────────────────
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
ENV TZ=UTC LANG=C.UTF-8 LC_ALL=C.UTF-8

ARG POSTERN_EDITION=comms-app
ENV POSTERN_EDITION=${POSTERN_EDITION}

# ── OCI labels (provenance the operator fills in at build time) ─────────────
ARG VCS_REF=unknown
ARG BUILD_VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="Bloch (Postern comms-app)" \
      org.opencontainers.image.description="Bloch org-internal messenger — static app served over HTTP. Reference prototype, unaudited, enterprise-only (fail-closed without a valid license)." \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="${BUILD_VERSION}" \
      org.opencontainers.image.source="https://gitlab.com/postern" \
      com.postern.edition="comms-app" \
      com.postern.telemetry="off" \
      com.postern.privacy-note="hosted deployment is less private than self-hosting or on-device; disclosed in the app's own transparency panel."

# ── Non-root by construction ────────────────────────────────────────────────
RUN groupadd --system --gid 10001 postern \
 && useradd  --system --uid 10001 --gid postern --home /var/lib/postern \
             --shell /usr/sbin/nologin postern \
 && mkdir -p /var/lib/postern/enterprise \
 && chown -R postern:postern /var/lib/postern

WORKDIR /var/lib/postern

# ── Static bundle (this repo's own source — no external fetch, no build step) ─
# Only the subtree Bloch's ES-module graph actually reaches: features/ (license
# gate, sub-access, privacy text) and comms/ (the app itself + the compliance
# disclosure layer it imports from). See deploy/server.mjs's header comment for
# why the webroot has to be enterprise/, not just comms/app/.
COPY --chown=postern:postern enterprise/features/         enterprise/features/
COPY --chown=postern:postern enterprise/comms/app/         enterprise/comms/app/
COPY --chown=postern:postern enterprise/comms/compliance/  enterprise/comms/compliance/

USER postern

# ── Privacy / egress posture (same as the cloud image) ─────────────────────
ENV POSTERN_TELEMETRY=off \
    POSTERN_EGRESS=controlled \
    PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=2s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["node", "enterprise/comms/app/deploy/server.mjs"]
