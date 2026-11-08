#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# gen-dev-signing-keys.sh — mint CLEARLY-MARKED PLACEHOLDER signing keys so an
# operator can exercise Postern Desktop's signing flow end-to-end WITHOUT ever
# touching a production key. It is the "signing scaffold" half of this package:
# package-signed.sh drives the build + the two reused pipelines; this script
# produces the dev key material those pipelines consume, all of it stamped
# dev-sample / DO-NOT-SHIP so nothing it emits can be mistaken for a real
# release signature.
#
# HONESTY HEADER — read before you run this:
#
#   * PLACEHOLDER / DEV-SAMPLE KEYS ONLY. Every key this script writes lands in
#     a directory literally named dev-keys-DO-NOT-SHIP/ and carries the token
#     "dev-sample" in its filename. That token is not cosmetic: it is the exact
#     string that trips the loud DEV/SAMPLE guard in ../../scripts/sign-release.sh
#     and makes package-signed.sh's output self-identify as non-production.
#     NEVER sign a release delivered to a user with anything this script makes.
#   * THIS SCRIPT GENERATES KEYS; IT NEVER SHIPS OR UPLOADS THEM. No commit,
#     no push, no network beyond what `minisign -G` / `postern-release keygen`
#     do locally on your own machine.
#   * NOT the production key story. Real signing needs operator-held keys, an
#     Apple Developer ID + notarization, a Windows Authenticode certificate,
#     and a real update/distribution channel — none of which live here. See
#     SIGNING.md for the full gate list. This script only unblocks LOCAL TESTING
#     of the mechanics.
#   * The minisign dev key is generated password-less (`-W`) on purpose: it is
#     a throwaway for CI/local flow tests, not a secret worth protecting.
#
# What it writes (under ./dev-keys-DO-NOT-SHIP/ by default):
#   dev-sample.minisign.key         minisign (Ed25519) SECRET key   — DO NOT SHIP
#   dev-sample.minisign.pub         minisign (Ed25519) public key
#   dev-sample.falcon.{pub,sec}     PQ Falcon-1024 keypair          — .sec DO NOT SHIP
#   dev-sample.mldsa.{pub,seed}     PQ ML-DSA-87 keypair            — .seed DO NOT SHIP
#   notarize.env.sample             macOS-notarization + Windows-Authenticode
#                                   env PLACEHOLDERS (all fake values)
#   README.txt                      how to feed these to package-signed.sh
#
# The PQ four-file prefix (dev-sample.{falcon,mldsa}.*) is exactly the shape
# scripts/sign-release.sh -k expects; the minisign secret key is what -s expects.
#
# Modes:
#   --check (default)  No key generation, no writes. Confirms the tools this
#                      scaffold needs are present (minisign, and cargo OR a
#                      prebuilt postern-release binary) and prints what a real
#                      run would create. Exits 0 on success.
#   --gen              Actually generate the dev-sample key set. Refuses to
#                      clobber an existing key dir unless --force is given.
#
# Usage:
#   ./gen-dev-signing-keys.sh [--check]
#   ./gen-dev-signing-keys.sh --gen [-o <out-dir>] [--force] [-b <postern-release-bin>]
#
#   -o       output dir for the dev key set (default: ./dev-keys-DO-NOT-SHIP)
#   --force  overwrite an existing output dir (only ever a dev key dir)
#   -b       path to a prebuilt postern-release binary (skips the cargo build)
#
# Does NOT modify packaging/ or scripts/ (those are the reused pipelines this
# scaffold only feeds).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PR_MANIFEST="${REPO_ROOT}/crates/postern-release/Cargo.toml"

log() { printf '[gen-dev-signing-keys] %s\n' "$*"; }
die() { printf '[gen-dev-signing-keys] ERROR: %s\n' "$*" >&2; exit 1; }

reminders() {
  log "REMINDER: every key here is dev-sample / DO-NOT-SHIP — NEVER sign a real release with it."
  log "REMINDER: real signing needs operator keys + Apple notarization + Windows Authenticode — see SIGNING.md."
}

# ── argument parsing ────────────────────────────────────────────────────────
MODE="check"
OUT_DIR="${SCRIPT_DIR}/dev-keys-DO-NOT-SHIP"
FORCE=0
PREBUILT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE="check"; shift ;;
    --gen)   MODE="gen"; shift ;;
    --force) FORCE=1; shift ;;
    -o) [ $# -ge 2 ] || die "-o needs a value"; OUT_DIR="$2"; shift 2 ;;
    -b) [ $# -ge 2 ] || die "-b needs a value"; PREBUILT="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

# ── tool discovery (shared by both modes) ───────────────────────────────────
have_minisign=0
command -v minisign >/dev/null 2>&1 && have_minisign=1

PR_MODE="none"   # "prebuilt" | "cargo" | "none"
if [ -n "${PREBUILT}" ]; then
  [ -x "${PREBUILT}" ] || die "prebuilt postern-release not found/executable: ${PREBUILT}"
  PR_MODE="prebuilt"
elif command -v cargo >/dev/null 2>&1 && [ -f "${PR_MANIFEST}" ]; then
  PR_MODE="cargo"
fi

run_pr() {
  case "${PR_MODE}" in
    prebuilt) "${PREBUILT}" "$@" ;;
    cargo)    cargo run --quiet --manifest-path "${PR_MANIFEST}" --bin postern-release -- "$@" ;;
    *)        die "postern-release unavailable (need cargo + ${PR_MANIFEST}, or -b <bin>)" ;;
  esac
}

# ── check mode ──────────────────────────────────────────────────────────────
if [ "${MODE}" = "check" ]; then
  [ "${have_minisign}" -eq 1 ] \
    && log "minisign: present ($(command -v minisign))" \
    || log "minisign: ABSENT — install (brew/apt/apk add minisign) before --gen"
  case "${PR_MODE}" in
    prebuilt) log "postern-release: prebuilt (${PREBUILT})" ;;
    cargo)    log "postern-release: buildable via cargo (${PR_MANIFEST})" ;;
    none)     log "postern-release: UNAVAILABLE — need cargo + the crate, or -b <bin> before --gen" ;;
  esac
  log "--gen would write dev-sample keys into: ${OUT_DIR}"
  log "  dev-sample.minisign.{key,pub}   (Ed25519, password-less dev key)"
  log "  dev-sample.{falcon,mldsa}.*     (PQ hybrid dev key prefix)"
  log "  notarize.env.sample, README.txt (placeholder env + usage)"
  reminders
  log "--check OK (no keys were generated)"
  exit 0
fi

# ── gen mode ────────────────────────────────────────────────────────────────
[ "${have_minisign}" -eq 1 ] || die "minisign not on PATH (brew/apt/apk add minisign)"
[ "${PR_MODE}" != "none" ] || die \
  "postern-release unavailable: need cargo + ${PR_MANIFEST}, or pass -b <prebuilt-bin>"

if [ -e "${OUT_DIR}" ]; then
  [ "${FORCE}" -eq 1 ] || die \
    "output dir already exists: ${OUT_DIR} (pass --force to overwrite a dev key dir)"
  log "overwriting existing dev key dir (--force): ${OUT_DIR}"
  rm -rf "${OUT_DIR}"
fi
mkdir -p "${OUT_DIR}"

MINISIGN_SEC="${OUT_DIR}/dev-sample.minisign.key"
MINISIGN_PUB="${OUT_DIR}/dev-sample.minisign.pub"
PQ_PREFIX="${OUT_DIR}/dev-sample"

# 1) minisign Ed25519 dev key — password-less (-W), throwaway by design.
log "generating dev-sample minisign (Ed25519) keypair ..."
minisign -G -W -p "${MINISIGN_PUB}" -s "${MINISIGN_SEC}" >/dev/null

# 2) PQ hybrid dev key prefix (Falcon-1024 + ML-DSA-87), DEV/SAMPLE-grade.
log "generating dev-sample PQ hybrid (Falcon-1024 + ML-DSA-87) key prefix ..."
run_pr keygen --out "${PQ_PREFIX}"
[ -f "${PQ_PREFIX}.falcon.sec" ] || die "postern-release keygen did not produce ${PQ_PREFIX}.falcon.sec"
[ -f "${PQ_PREFIX}.mldsa.seed" ] || die "postern-release keygen did not produce ${PQ_PREFIX}.mldsa.seed"

# 3) notarization / Authenticode env PLACEHOLDERS (all values fake).
cat > "${OUT_DIR}/notarize.env.sample" <<'ENVSAMPLE'
# notarize.env.sample — PLACEHOLDER signing/notarization environment.
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# EVERY VALUE BELOW IS FAKE. These are the env vars `cargo tauri build` reads to
# sign + notarize on macOS and to Authenticode-sign on Windows. Fill them with
# REAL operator credentials on the per-OS release runner — never commit real
# values, and note that tauri.conf.json keeps macOS.signingIdentity = null, so
# signing is opt-in via these vars (guarded by tests/bundle_config.rs).
#
# --- macOS code signing (Developer ID Application cert) ---
export APPLE_SIGNING_IDENTITY="Developer ID Application: PLACEHOLDER ORG (PLACEHOLDERTEAMID)"
# ...or supply the cert inline (base64 of a .p12) instead of an identity:
export APPLE_CERTIFICATE="PLACEHOLDER_BASE64_P12"
export APPLE_CERTIFICATE_PASSWORD="PLACEHOLDER_P12_PASSWORD"
export APPLE_TEAM_ID="PLACEHOLDERTEAMID"
#
# --- macOS notarization (pick ONE of the two auth methods) ---
# (a) Apple ID + app-specific password:
export APPLE_ID="placeholder@example.invalid"
export APPLE_PASSWORD="PLACEHOLDER-app-specific-password"
# (b) App Store Connect API key (preferred for CI):
export APPLE_API_ISSUER="00000000-0000-0000-0000-000000000000"
export APPLE_API_KEY="PLACEHOLDERKEYID"
export APPLE_API_KEY_PATH="/path/to/AuthKey_PLACEHOLDER.p8"
#
# --- Windows Authenticode ---
# Set bundle.windows.certificateThumbprint (+ digestAlgorithm/timestampUrl) in a
# release override of tauri.conf.json, or use a signCommand for a cloud HSM
# (Azure Trusted Signing / SignPath / DigiCert KeyLocker). Placeholder thumbprint:
export WINDOWS_CERTIFICATE_THUMBPRINT="0000000000000000000000000000000000000000"
ENVSAMPLE

# 4) usage README pointing back at package-signed.sh + sign-release.sh.
cat > "${OUT_DIR}/README.txt" <<READMESAMPLE
dev-keys-DO-NOT-SHIP — PLACEHOLDER signing keys (generated by gen-dev-signing-keys.sh)

DO NOT SHIP. Every key in this directory is dev-sample / throwaway. It exists
ONLY to exercise the signing flow locally. It is NOT a production signing key
and its signatures are NOT production signatures.

Exercise the full host-gated build + dev-key signing flow:

    POSTERN_PACKAGING_E2E=1 ./package-signed.sh --build \\
        -s "${MINISIGN_SEC}" \\
        -k "${PQ_PREFIX}"

package-signed.sh will build the current host's Tauri bundles, compute
SHA256SUMS, run the TUF dev-key leg (packaging/build-signed-bundle.sh), and then
the minisign + PQ hybrid leg (scripts/sign-release.sh) with the keys above. Both
scripts will LOUDLY warn that these are dev-sample keys — that warning is the
point.

For macOS notarization / Windows Authenticode placeholders, see
notarize.env.sample in this directory and ../SIGNING.md.
READMESAMPLE

log "wrote dev-sample key set into: ${OUT_DIR}"
log "  minisign secret: ${MINISIGN_SEC}"
log "  PQ key prefix:   ${PQ_PREFIX} (.falcon.{pub,sec}, .mldsa.{pub,seed})"
log "  placeholders:    ${OUT_DIR}/notarize.env.sample, ${OUT_DIR}/README.txt"
log "next: POSTERN_PACKAGING_E2E=1 ./package-signed.sh --build -s '${MINISIGN_SEC}' -k '${PQ_PREFIX}'"
reminders
