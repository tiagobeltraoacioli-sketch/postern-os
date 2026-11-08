#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# publish-crl.sh — pull the current vendor-signed CRL from the Pages site
# (functions/license/status.js) and publish it to the Fly hosted verifier
# (POST /v1/crl, enterprise/cloud/image/vendor/services/src/license-service.mjs).
#
# This wraps steps 3-5 of docs/bucketC/SIGNED-CRL-FLOW.md's "Operator
# activation sequence" into one script, so an operator doesn't have to
# hand-type the curl/python glue every time a revocation needs publishing.
#
# THIS SCRIPT NEVER SIGNS ANYTHING. It only fetches an already vendor-signed
# CRL and publishes it; the Fly service independently re-verifies the
# signature against VENDOR_PUBLIC_KEY before accepting it (see
# handlePublishCrl() in license-service.mjs) and enforces monotonic version
# (anti-rollback). This script adds no new authority.
#
# SECRETS: reads $ADMIN_TOKEN (the Fly ADMIN_TOKEN secret — NOT the same as
# Cloudflare Pages' LICENSE_ADMIN_TOKEN, see OPERATOR-SECRETS-RUNBOOK.md) from
# the environment. Never hardcode it, never echo it, never log it, never
# include it in an error message.
#
# Usage:
#   ADMIN_TOKEN=... ./publish-crl.sh [-n|--dry-run] [-h|--help]
#
#   -n, --dry-run   Fetch + validate the CRL and print it, but do NOT POST it
#                   to Fly. ADMIN_TOKEN is not required in dry-run mode.
#   -h, --help      Show this help.
#
# Env overrides (defaults match the live posternlabs.com / postern-cloud-demo
# deployment):
#   SITE_HOST   default https://posternlabs.com
#   FLY_HOST    default https://postern-cloud-demo.fly.dev
#
# Exit status: non-zero on ANY failure — a network error, a missing/malformed
# CRL, a non-2xx from either endpoint, or a publish response that does not
# report ok:true. Never treats a partial or ambiguous result as success.
set -euo pipefail

prog="publish-crl"
die() { printf '%s: FAIL: %s\n' "$prog" "$*" >&2; exit 1; }
log() { printf '%s: %s\n' "$prog" "$*" >&2; }
ok()  { printf '%s: OK: %s\n' "$prog" "$*" >&2; }

DRY_RUN=0
while [ $# -gt 0 ]; do
  case "$1" in
    -n|--dry-run) DRY_RUN=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (see -h)" ;;
  esac
done

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required (JSON handling; no jq dependency assumed)"

SITE="${SITE_HOST:-https://posternlabs.com}"
FLY="${FLY_HOST:-https://postern-cloud-demo.fly.dev}"

if [ "$DRY_RUN" -eq 0 ]; then
  : "${ADMIN_TOKEN:?set ADMIN_TOKEN (the Fly admin secret) in the environment first -- see docs/bucketC/OPERATOR-SECRETS-RUNBOOK.md section 2}"
fi

# fetch_json URL -> prints "HTTPSTATUS<TAB>BODY" on stdout; never uses -f so we
# always have a body to show on failure (a silent -f loses the error detail).
fetch_json() {
  curl -sS -w '\t%{http_code}' "$1"
}

# post_json URL BODY [AUTH_HEADER] -> prints "HTTPSTATUS<TAB>BODY" on stdout.
# AUTH_HEADER, if given, is passed verbatim to curl -H and is NEVER logged.
post_json() {
  local url="$1" body="$2" auth="${3:-}"
  if [ -n "$auth" ]; then
    curl -sS -w '\t%{http_code}' -X POST "$url" \
      -H "authorization: $auth" -H "content-type: application/json" \
      --data-binary "$body"
  else
    curl -sS -w '\t%{http_code}' -X POST "$url" \
      -H "content-type: application/json" --data-binary "$body"
  fi
}

split_status() { # $1 = "BODY<TAB>STATUS" combined curl -w output -> sets $reply_body / $reply_status
  reply_status="${1##*$'\t'}"
  reply_body="${1%$'\t'*}"
}

log "pulling signed CRL from $SITE/license/status ..."
raw=$(fetch_json "$SITE/license/status") || die "GET $SITE/license/status: curl itself failed (network error)"
split_status "$raw"
[ "$reply_status" = "200" ] || die "GET $SITE/license/status returned HTTP $reply_status: $reply_body"

crl_json=$(printf '%s' "$reply_body" | python3 -c '
import json, sys
d = json.load(sys.stdin)
crl = d.get("crl")
if not crl or not isinstance(crl, dict) or "payload" not in crl or "sig" not in crl:
    sys.exit("no signed CRL present in /license/status response (crl is null or malformed) -- has one ever been published on the Pages side? see OPERATOR-SECRETS-RUNBOOK.md section 1")
print(json.dumps(crl))
') || die "could not extract a signed CRL from the /license/status response"

version=$(printf '%s' "$crl_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["payload"]["version"])') \
  || die "CRL payload is missing a version field"
ok "fetched CRL version=$version"

if [ "$DRY_RUN" -eq 1 ]; then
  log "[dry-run] would POST this CRL to $FLY/v1/crl -- NOT sending (no ADMIN_TOKEN required for dry-run)"
  printf '%s\n' "$crl_json"
  ok "dry-run complete -- nothing was published"
  exit 0
fi

log "publishing to $FLY/v1/crl ..."
raw=$(post_json "$FLY/v1/crl" "$crl_json" "Bearer $ADMIN_TOKEN") || die "POST $FLY/v1/crl: curl itself failed (network error)"
split_status "$raw"
case "$reply_status" in
  200) : ;;
  401) die "Fly rejected the publish as unauthorized (HTTP 401) -- ADMIN_TOKEN is wrong or unset on the Fly side: $reply_body" ;;
  400) die "Fly rejected the CRL (HTTP 400, bad request/signature) -- the signed CRL did not verify against Fly's VENDOR_PUBLIC_KEY, or the keypair pair (Pages/Fly) is mismatched: $reply_body" ;;
  409) die "Fly rejected the CRL as stale (HTTP 409, anti-rollback) -- version=$version is not newer than what Fly already has published: $reply_body" ;;
  *)   die "POST $FLY/v1/crl returned HTTP $reply_status: $reply_body" ;;
esac

printf '%s' "$reply_body" | python3 -c '
import json, sys
d = json.load(sys.stdin)
if d.get("ok") is not True:
    sys.exit("publish response did not report ok:true: " + json.dumps(d))
print("published version=%s revoked_jti=%s revoked_master_pub=%s" % (
    d.get("version"), d.get("revoked_jti"), d.get("revoked_master_pub")))
' || die "publish response was HTTP 200 but did not confirm ok:true (see above)"

ok "CRL published successfully"
log "confirm with: curl -s $FLY/v1/crl"
