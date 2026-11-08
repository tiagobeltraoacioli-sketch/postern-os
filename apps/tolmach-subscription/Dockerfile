# Tolmach Subscription proxy — hosted operator-proxy backend for the
# Subscription tier ONLY (the Sovereign tier is a static page and needs no
# server; do not containerize anything for it). Long-lived HTTP service that
# holds the operator's Anthropic key, meters usage, and forwards to
# api.anthropic.com. Matches the repo's node:20-slim service pattern
# (see community/postern-bot/Dockerfile).
#
# SPDX-License-Identifier: MIT
#
# Zero runtime dependencies (Node built-in fetch/http/crypto), so there is
# nothing to `npm install` — we copy only the files the proxy needs.
#
# SECRETS ARE NOT BAKED IN. ANTHROPIC_API_KEY, STRIPE_SECRET_KEY,
# STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_* must be injected at runtime
# (`fly secrets set …`, `docker run -e …`, or an orchestrator secret). Never
# add them to this image or to the repo. See .env.example for the full contract.
FROM node:20-slim
WORKDIR /app

# Persistent, writable store for the JSON account + token-count files
# (DATA_DIR). Mount a volume here in production so subscribers/usage survive a
# redeploy. Owned by the unprivileged `node` user because we drop privileges.
ENV DATA_DIR=/data
RUN mkdir -p /data && chown -R node:node /data
VOLUME ["/data"]

# Only the backend + its self-tests. The client (static HTML) and README ship
# via the site build, not in this image.
COPY server/ ./server/
COPY tools/ ./tools/
COPY package.json ./

# Default listen port (overridable with PORT). Documented, not privileged.
ENV PORT=8787
EXPOSE 8787

# Liveness: hit /healthz with Node itself (slim image has no curl). Non-2xx or
# a connection error fails the check. /healthz never touches the upstream key.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8787)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# Run unprivileged.
USER node
CMD ["node", "server/proxy.mjs"]
