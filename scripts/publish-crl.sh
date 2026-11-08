#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# publish-crl.sh — operator-facing driver for the PUBLISH step of the signed-CRL
# flow (docs/bucketC/SIGNED-CRL-FLOW.md, hop [3] and the "Operator activation
# sequence" steps 4-5). It wraps what an operator would otherwise hand-type
# every time a revocation is issued:
#
#   1. Pull the freshly-signed CRL from the Cloudflare Pages endpoint
#        GET https://<pages-host>/license/status  ->  .crl { payload, sig }
#   2. POST that signed CRL to the Fly hosted verifier
#        POST https://<fly-host>/v1/crl   (auth: Bearer $CRL_ADMIN_TOKEN)
#      The Fly service VERIFIES the signature against VENDOR_PUBLIC_KEY and
#      enforces monotonic version (anti-rollback); this script only transports.
#   3. Confirm by re-reading GET /v1/crl and echoing the served version.
#
# WHAT THIS IS / IS NOT:
#   * This is a TRANSPORT + CONFIRM step. It does NOT sign anything, does NOT
#     mint or hold any key, and does NOT decide what is revoked. The signing
#     happens on Pages (hop [2]); the verification + anti-rollback happens on
#     Fly (hop [3]). A successful run proves only that a CRL the vendor key
#     already signed was accepted and is now served.
#   * NO SECRET IS EMBEDDED HERE. The Fly admin bearer token is read from the
#     environment variable CRL_ADMIN_TOKEN, which the operator injects at
#     runtime. This script FAILS CLOSED if that variable is unset or empty —
#     it never falls back to a default, a prompt-less blank, or a file on disk.
#
# USAGE:
#   CRL_ADMIN_TOKEN=... ./scripts/publish-crl.sh [options]
#
# OPTIONS (all have honest defaults matching SIGNED-CRL-FLOW.md's example hosts):
#   --pages-host HOST   Cloudflare Pages host that signs the CRL.
#                       Default: posternlabs.com
#   --fly-host HOST     Fly host running the hosted verifier.
#                       Default: postern-cloud-demo.fly.dev
#   --dry-run           Fetch + show the signed CRL, but do NOT POST it.
#   -h, --help          Show this help and exit.
#
# ENVIRONMENT (required):
#   CRL_ADMIN_TOKEN     Fly service ADMIN_TOKEN (the same secret set via
#                       `fly secrets set ADMIN_TOKEN=... -a <app>`). REQUIRED
#                       unless --dry-run is given. Injected by the operator at
#                       runtime; never stored by this script.
#
# EXIT CODES:
#   0  published (or, with --dry-run, fetched) successfully
#   1  usage / precondition error (incl. missing CRL_ADMIN_TOKEN)
#   2  fetch of the signed CRL from Pages failed / malformed
#   3  publish to Fly rejected (e.g. 401 auth, 409 anti-rollback, 400 bad sig)

set -euo pipefail

PAGES_HOST="posternlabs.com"
FLY_HOST="postern-cloud-demo.fly.dev"
DRY_RUN=0

usage() {
  sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --pages-host) PAGES_HOST="${2:?--pages-host needs a value}"; shift 2 ;;
    --fly-host)   FLY_HOST="${2:?--fly-host needs a value}"; shift 2 ;;
    --dry-run)    DRY_RUN=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *) echo "publish-crl.sh: unknown argument: $1" >&2; echo "try --help" >&2; exit 1 ;;
  esac
done

for bin in curl python3; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "publish-crl.sh: required tool not found: $bin" >&2
    exit 1
  fi
done

# --- FAIL CLOSED on the operator secret -------------------------------------
# The admin bearer is NEVER embedded. Refuse to run a live publish without it.
if [ "$DRY_RUN" -eq 0 ]; then
  if [ -z "${CRL_ADMIN_TOKEN:-}" ]; then
    echo "publish-crl.sh: CRL_ADMIN_TOKEN is unset or empty." >&2
    echo "  This script embeds no secret; the operator must inject the Fly" >&2
    echo "  service ADMIN_TOKEN at runtime, e.g.:" >&2
    echo "    CRL_ADMIN_TOKEN=... $0" >&2
    echo "  Refusing to continue (fail-closed)." >&2
    exit 1
  fi
fi

STATUS_URL="https://${PAGES_HOST}/license/status"
PUBLISH_URL="https://${FLY_HOST}/v1/crl"
CONFIRM_URL="https://${FLY_HOST}/v1/crl"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/publish-crl.XXXXXX")"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

CRL_JSON="${WORKDIR}/crl.json"

# --- Step 1: pull the freshly-signed CRL from Pages -------------------------
echo ">> fetching signed CRL: GET ${STATUS_URL}" >&2
if ! curl -fsS "$STATUS_URL" > "${WORKDIR}/status.json"; then
  echo "publish-crl.sh: failed to GET ${STATUS_URL}" >&2
  exit 2
fi

# Extract just the { payload, sig } object — that's the body /v1/crl expects.
if ! python3 -c '
import json, sys
with open(sys.argv[1]) as f:
    doc = json.load(f)
crl = doc.get("crl")
if not isinstance(crl, dict) or "payload" not in crl or "sig" not in crl:
    sys.stderr.write("publish-crl.sh: status response has no signed .crl {payload,sig}\n")
    sys.exit(2)
with open(sys.argv[2], "w") as out:
    json.dump(crl, out, separators=(",", ":"))
ver = crl.get("payload", {}).get("version")
sys.stderr.write(">> signed CRL fetched: version=%s\n" % ver)
' "${WORKDIR}/status.json" "$CRL_JSON"; then
  exit 2
fi

if [ "$DRY_RUN" -eq 1 ]; then
  echo ">> --dry-run: NOT publishing. Signed CRL that WOULD be posted:" >&2
  cat "$CRL_JSON"
  echo
  exit 0
fi

# --- Step 2: publish it to the Fly hosted verifier --------------------------
# Fly VERIFIES the signature and enforces monotonic version itself; a stale or
# tampered CRL is rejected there (409 / 400), not here.
echo ">> publishing: POST ${PUBLISH_URL}" >&2
HTTP_CODE="$(curl -sS -o "${WORKDIR}/publish-resp.json" -w '%{http_code}' \
  -X POST "$PUBLISH_URL" \
  -H "authorization: Bearer ${CRL_ADMIN_TOKEN}" \
  -H "content-type: application/json" \
  --data-binary @"$CRL_JSON")" || {
    echo "publish-crl.sh: POST ${PUBLISH_URL} failed to connect" >&2
    exit 3
  }

if [ "$HTTP_CODE" != "200" ] && [ "$HTTP_CODE" != "201" ]; then
  echo "publish-crl.sh: publish rejected (HTTP ${HTTP_CODE})." >&2
  echo "  401=bad/missing admin token, 409=anti-rollback (stale version)," >&2
  echo "  400=signature did not verify against the vendor public key." >&2
  echo "  response body:" >&2
  cat "${WORKDIR}/publish-resp.json" >&2 || true
  echo >&2
  exit 3
fi
echo ">> publish accepted (HTTP ${HTTP_CODE})" >&2

# --- Step 3: confirm what is now served -------------------------------------
echo ">> confirming: GET ${CONFIRM_URL}" >&2
if ! curl -fsS "$CONFIRM_URL" > "${WORKDIR}/confirm.json"; then
  echo "publish-crl.sh: WARNING publish was accepted but confirm GET failed." >&2
  exit 0
fi
python3 -c '
import json, sys
with open(sys.argv[1]) as f:
    doc = json.load(f)
crl = doc.get("crl")
if not crl:
    sys.stderr.write(">> served CRL is still null (unexpected right after publish)\n")
    sys.exit(0)
ver = crl.get("payload", {}).get("version")
sys.stderr.write(">> confirmed: /v1/crl now serves signed CRL version=%s\n" % ver)
' "${WORKDIR}/confirm.json"

echo ">> done." >&2
