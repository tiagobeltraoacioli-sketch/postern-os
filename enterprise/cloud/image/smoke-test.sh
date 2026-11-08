#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# smoke-test.sh — prove the Postern Cloud (hosted) image actually BUILDS and RUNS.
#
# It builds the image (build-image.sh, base pinned by digest), brings the stack
# up with `compose up`, waits for the container healthcheck to report healthy,
# then hits GET /v1/posture and GET /healthz to prove the container SERVES. It
# also asserts the fail-closed rail (SVC-1): the image REFUSES to start without a
# runtime-injected VENDOR_PUBLIC_KEY. Finally it tears the stack down.
#
# This is a REFERENCE smoke test, not a production readiness gate. Nothing is
# pushed or deployed. No secrets are baked — the vendor key is generated here and
# injected at runtime only.
#
# Usage: ./smoke-test.sh [-d sha256:<base-digest>] [-r <engine>] [-k]
#   -d  base image digest (default: the vetted digest pinned in the Containerfile)
#   -r  container engine (podman|docker; default: autodetect)
#   -k  keep the stack up after the test (skip teardown) for inspection
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prog="smoke-test"
die() { printf '%s: FAIL: %s\n' "$prog" "$*" >&2; exit 1; }
log() { printf '%s: %s\n' "$prog" "$*" >&2; }
ok()  { printf '%s: OK: %s\n' "$prog" "$*" >&2; }

BASE_DIGEST=""
ENGINE=""
KEEP=0
while getopts ':d:r:kh' opt; do
  case "$opt" in
    d) BASE_DIGEST="$OPTARG" ;;
    r) ENGINE="$OPTARG" ;;
    k) KEEP=1 ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    :) die "option -$OPTARG needs a value" ;;
    \?) die "unknown option -$OPTARG" ;;
  esac
done

# ── Pick an engine + its compose subcommand ─────────────────────────────────
if [ -z "$ENGINE" ]; then
  if command -v podman >/dev/null 2>&1; then ENGINE=podman
  elif command -v docker >/dev/null 2>&1; then ENGINE=docker
  else die "no container engine found (install podman or docker)"; fi
fi
command -v "$ENGINE" >/dev/null 2>&1 || die "engine not found: $ENGINE"
command -v node >/dev/null 2>&1 || die "node is required on the host to generate the test vendor key"

compose() {
  if [ "$ENGINE" = podman ]; then podman compose "$@"; else docker compose "$@"; fi
}

# ── Base digest: default to the one pinned in the Containerfile ─────────────
if [ -z "$BASE_DIGEST" ]; then
  BASE_DIGEST=$(sed -n 's/^ARG BASE_DIGEST=\(sha256:[0-9a-f]\{64\}\).*/\1/p' "$here/Containerfile" | head -n1)
  [ -n "$BASE_DIGEST" ] || die "could not read a pinned BASE_DIGEST from Containerfile; pass -d"
fi
log "engine=$ENGINE  base=$BASE_DIGEST"

TAG="postern-cloud:smoke"
PORT=8080
URL_BASE="http://127.0.0.1:${PORT}"

# ── Generate a REAL Ed25519 vendor public key (base64 raw 32 bytes) ─────────
# Runtime-injected only; never baked, never committed.
VENDOR_PUBLIC_KEY=$(node -e '
  const {generateKeyPairSync}=require("crypto");
  const {publicKey}=generateKeyPairSync("ed25519");
  const der=publicKey.export({format:"der",type:"spki"});
  process.stdout.write(der.subarray(der.length-32).toString("base64"));
')
[ -n "$VENDOR_PUBLIC_KEY" ] || die "failed to generate a test vendor key"
export VENDOR_PUBLIC_KEY
ok "generated ephemeral test VENDOR_PUBLIC_KEY (runtime-injected)"

cleanup() {
  if [ "$KEEP" -eq 1 ]; then log "leaving stack up (-k)"; return; fi
  log "tearing down ..."
  ( cd "$here" && compose down -v >/dev/null 2>&1 || true )
  "$ENGINE" rm -f postern-cloud-failclosed >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ── 1. Build the image (build only; never pushes/deploys) ───────────────────
log "[1/5] building image ..."
"$here/build-image.sh" -d "$BASE_DIGEST" -t "$TAG" -r "$ENGINE" >/dev/null || die "build failed"
IMG_ID=$("$ENGINE" inspect --format '{{.Id}}' "$TAG" 2>/dev/null || echo "?")
ok "built $TAG  id=$IMG_ID"

# ── 2. Fail-closed rail (SVC-1): no vendor key => refuse to start ───────────
log "[2/5] asserting fail-closed without VENDOR_PUBLIC_KEY ..."
if "$ENGINE" run --rm --name postern-cloud-failclosed -e VENDOR_PUBLIC_KEY= "$TAG" >/dev/null 2>&1; then
  die "container started WITHOUT a vendor key (fail-open) — SVC-1 violated"
fi
ok "container refused to start without a vendor key (fail-closed)"

# ── 3. compose up ───────────────────────────────────────────────────────────
log "[3/5] compose up ..."
mkdir -p "$here/config"
( cd "$here" && POSTERN_SERVICE=license compose up -d --build ) || die "compose up failed"

# ── 4. Wait for the container to report healthy, then serve ─────────────────
log "[4/5] waiting for health ..."
cid=$( cd "$here" && compose ps -q postern-cloud 2>/dev/null | head -n1 )
[ -n "$cid" ] || die "could not resolve container id"
healthy=0
for i in $(seq 1 60); do
  state=$("$ENGINE" inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$cid" 2>/dev/null || echo "?")
  running=$("$ENGINE" inspect --format '{{.State.Running}}' "$cid" 2>/dev/null || echo false)
  [ "$running" = "true" ] || die "container is not running (state=$state); logs:$(printf '\n'; "$ENGINE" logs "$cid" 2>&1 | tail -n 20)"
  if [ "$state" = "healthy" ]; then healthy=1; break; fi
  sleep 1
done
[ "$healthy" -eq 1 ] || die "container did not become healthy in time (last=$state); logs:$(printf '\n'; "$ENGINE" logs "$cid" 2>&1 | tail -n 20)"
ok "container reported healthy"

# ── 5. Prove it SERVES: GET /v1/posture and GET /healthz ───────────────────
log "[5/5] hitting the service over HTTP ..."
fetch() { # $1=path -> prints "STATUS<TAB>BODY"
  node -e '
    const p=process.argv[1];
    fetch("'"$URL_BASE"'"+p).then(async r=>{const t=await r.text();process.stdout.write(r.status+"\t"+t);})
      .catch(e=>{process.stdout.write("ERR\t"+e.message);});
  ' "$1"
}

posture=$(fetch /v1/posture)
pstatus=${posture%%$'\t'*}
pbody=${posture#*$'\t'}
[ "$pstatus" = "200" ] || die "/v1/posture returned status=$pstatus body=$pbody"
printf '%s' "$pbody" | grep -q 'postern-cloud-license' || die "/v1/posture body missing service id: $pbody"
printf '%s' "$pbody" | grep -q 'reference-prototype/unaudited' || die "/v1/posture missing unaudited status marker"
ok "/v1/posture -> 200 (posture=postern-cloud-license, status=unaudited)"

health=$(fetch /healthz)
hstatus=${health%%$'\t'*}
hbody=${health#*$'\t'}
[ "$hstatus" = "200" ] || die "/healthz returned status=$hstatus body=$hbody"
printf '%s' "$hbody" | grep -q '"ok":true' || die "/healthz body not ok: $hbody"
ok "/healthz -> 200 ($hbody)"

# ── Report the image digest/id for the record ──────────────────────────────
log "----------------------------------------------------------------"
ok  "SMOKE TEST PASSED — the Postern Cloud image builds and serves."
log "image tag:    $TAG"
log "image id:     $IMG_ID"
if rd=$("$ENGINE" inspect --format '{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}' "$TAG" 2>/dev/null); then
  [ -n "$rd" ] && log "repo digest:  $rd"
fi
log "base pinned:  $BASE_DIGEST"
log "reminder: reference/unaudited, hosted=less-private (disclosed), telemetry off, not production."
