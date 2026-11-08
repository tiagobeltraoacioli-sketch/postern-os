#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# package-signed.sh — host-gated driver that feeds Postern Desktop's Tauri
# bundle output through the repo's EXISTING signing pipelines. It never
# reimplements them: it INVOKES ../../packaging/build-signed-bundle.sh (local
# dev-key TUF metadata + fail-closed verify) and, when an operator passes
# keys, ../../scripts/sign-release.sh (minisign + PQ hybrid leg over the same
# SHA256SUMS convention).
#
# HONESTY HEADER — what this script really is:
#
#   * UNAUDITED. Everything in this repo is an unaudited reference prototype;
#     nothing this script produces is a production release.
#   * Reproducible where the platform allows, and no further: deb/rpm/
#     AppImage payloads are only as deterministic as the toolchain and
#     SOURCE_DATE_EPOCH let them be; .dmg and NSIS installers embed
#     timestamps the platform tooling controls. This script does NOT claim
#     bit-for-bit reproducibility and must never be cited as proof of it.
#   * DEV/TEST KEYS ONLY. The TUF leg generates fresh throwaway keys into a
#     directory literally named dev-keys-DO-NOT-SHIP. The minisign/PQ leg
#     signs with operator-supplied keys when given (-s/-k); otherwise it mints
#     throwaway dev-sample keys (via gen-dev-signing-keys.sh, into a
#     dev-*-DO-NOT-SHIP dir, every key stamped "dev-sample") purely to run the
#     sign→verify path end-to-end. This script never bundles, generates, or
#     ships a production key, and nothing signed here may be delivered to a
#     user as a production signature.
#   * UNSIGNED / NOT NOTARIZED BINARY. tauri.conf.json keeps
#     macOS.signingIdentity=null, so the emitted .app/.dmg carry NO Apple
#     code signature and are NOT notarized. The dev-sample minisign/PQ
#     signatures are over the SHA256SUMS manifest only — they authenticate
#     the manifest bytes for a DEV flow test, not the binary to Gatekeeper.
#   * NO UPDATE SERVER. There is no live update channel or endpoint. The
#     desktop config keeps createUpdaterArtifacts=false (enforced by
#     tests/bundle_config.rs) and this script refuses to run if that flips.
#   * CROSS-PLATFORM BUNDLES ARE HOST-GATED. `cargo tauri build` can only
#     produce the CURRENT host's targets (deb/rpm/appimage on Linux,
#     app/dmg on macOS, msi/nsis on Windows). This script builds for the
#     host it runs on, nothing else — it does not cross-compile and does
#     not pretend to.
#
# Modes:
#   --check (default)   No network, no build, no keys. Validates
#                       tauri.conf.json parses, asserts
#                       createUpdaterArtifacts=false and a non-empty
#                       explicit targets array, and confirms both reused
#                       pipeline scripts exist. Exits 0 on success.
#   --build             Full host-gated run. Refuses unless
#                       POSTERN_PACKAGING_E2E=1 AND `cargo tauri` AND
#                       minisign are available. Runs `cargo tauri build`
#                       for the current host, asserts no updater artifacts
#                       were emitted, stages the host's bundle output
#                       (target/release/bundle/*), computes SHA256SUMS, runs
#                       the dev-key TUF pipeline (build-signed-bundle.sh),
#                       then the minisign+PQ pipeline (sign-release.sh — with
#                       operator keys if given, else freshly-minted dev-sample
#                       keys), then re-verifies both legs via verify-release.sh
#                       (dev-key path only). Fail-closed throughout.
#
# Usage:
#   ./package-signed.sh [--check]
#   POSTERN_PACKAGING_E2E=1 ./package-signed.sh --build \
#       [-s <minisign-seckey> -k <pq-key-prefix>] [-o <out-dir>]
#
#   -s  operator-held minisign secret key. Optional; when given, -k is also
#       required because ../../scripts/sign-release.sh mandates both legs.
#   -k  operator-held postern-release PQ key prefix (see sign-release.sh -h).
#   -o  output directory (default: a mktemp dir printed at the end).
#
# Does not commit, push, or upload anything. Does not modify packaging/ or
# scripts/.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CONF="${SCRIPT_DIR}/tauri.conf.json"
TUF_PIPELINE="${REPO_ROOT}/packaging/build-signed-bundle.sh"
SIGN_PIPELINE="${REPO_ROOT}/scripts/sign-release.sh"
VERIFY_PIPELINE="${REPO_ROOT}/scripts/verify-release.sh"
GEN_DEV_KEYS="${SCRIPT_DIR}/gen-dev-signing-keys.sh"

log() { printf '[package-signed] %s\n' "$*"; }
die() { printf '[package-signed] ERROR: %s\n' "$*" >&2; exit 1; }

reminders() {
  log "REMINDER: dev keys are DO-NOT-SHIP; nothing here is a production release."
  log "REMINDER: createUpdaterArtifacts stays false — there is no update server."
  log "REMINDER: unaudited; reproducible where the platform allows, no further."
}

# ── argument parsing ────────────────────────────────────────────────────────
MODE="check"
SECKEY=""
KEYPREFIX=""
OUT_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE="check"; shift ;;
    --build) MODE="build"; shift ;;
    -s) [ $# -ge 2 ] || die "-s needs a value"; SECKEY="$2"; shift 2 ;;
    -k) [ $# -ge 2 ] || die "-k needs a value"; KEYPREFIX="$2"; shift 2 ;;
    -o) [ $# -ge 2 ] || die "-o needs a value"; OUT_DIR="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

# ── shared config checks (no network, no build) ─────────────────────────────
run_config_checks() {
  [ -f "${CONF}" ] || die "tauri.conf.json not found at ${CONF}"

  # Parse check: python3 when available, plain grep-based sanity otherwise.
  if command -v python3 >/dev/null 2>&1; then
    python3 -m json.tool "${CONF}" >/dev/null \
      || die "tauri.conf.json is not valid JSON"
    log "tauri.conf.json parses (python3 -m json.tool)"
  else
    grep -q '"bundle"' "${CONF}" || die "tauri.conf.json missing bundle section"
    log "tauri.conf.json sanity-checked (grep; python3 unavailable)"
  fi

  grep -q '"createUpdaterArtifacts": false' "${CONF}" \
    || die "createUpdaterArtifacts must stay false (no update server exists)"
  log "createUpdaterArtifacts is false"

  # targets must be an explicit, non-empty array (reviewed list, not \"all\").
  grep -Eq '"targets": \[[^]]*"[^"]+"' "${CONF}" \
    || die "bundle.targets must be a non-empty explicit array"
  log "bundle.targets is an explicit non-empty array"

  [ -f "${TUF_PIPELINE}" ] \
    || die "reused pipeline missing: ${TUF_PIPELINE}"
  [ -f "${SIGN_PIPELINE}" ] \
    || die "reused pipeline missing: ${SIGN_PIPELINE}"
  [ -f "${VERIFY_PIPELINE}" ] \
    || die "reused pipeline missing: ${VERIFY_PIPELINE}"
  [ -f "${GEN_DEV_KEYS}" ] \
    || die "dev-key scaffold missing: ${GEN_DEV_KEYS}"
  log "reused pipelines present: packaging/build-signed-bundle.sh, scripts/{sign,verify}-release.sh"
}

if [ "${MODE}" = "check" ]; then
  run_config_checks
  reminders
  log "--check OK"
  exit 0
fi

# ── full mode: host-gated, env-gated ────────────────────────────────────────
[ "${POSTERN_PACKAGING_E2E:-0}" = "1" ] || die \
  "full mode is gated: set POSTERN_PACKAGING_E2E=1 to confirm you want a real
  host build (this runs cargo tauri build and the dev-key signing pipelines).
  Use --check for the safe, build-free validation."

command -v cargo >/dev/null 2>&1 || die "cargo not on PATH"
cargo tauri --help >/dev/null 2>&1 || die \
  "'cargo tauri' unavailable — install tauri-cli (cargo install tauri-cli)"
command -v minisign >/dev/null 2>&1 || die \
  "minisign not on PATH (brew/apt/apk add minisign)"

if [ -n "${SECKEY}" ]; then
  [ -f "${SECKEY}" ] || die "minisign secret key not found: ${SECKEY}"
  [ -n "${KEYPREFIX}" ] || die \
    "-s given without -k: scripts/sign-release.sh requires BOTH the minisign
  key (-s) and the PQ key prefix (-k); it will not run a minisign-only leg"
fi

run_config_checks

# Host-gated build: current host's targets only.
log "running 'cargo tauri build' for the CURRENT host only (no cross-compile)"
( cd "${SCRIPT_DIR}" && cargo tauri build )

# Locate the bundle output dir (workspace target dir, or CARGO_TARGET_DIR).
BUNDLE_ROOT=""
for cand in "${CARGO_TARGET_DIR:-}" "${REPO_ROOT}/target" "${SCRIPT_DIR}/target"; do
  [ -n "${cand}" ] || continue
  if [ -d "${cand}/release/bundle" ]; then
    BUNDLE_ROOT="${cand}/release/bundle"
    break
  fi
done
[ -n "${BUNDLE_ROOT}" ] || die "no target/release/bundle directory found after build"
log "host bundle output: ${BUNDLE_ROOT}"

# Fail-closed guard: createUpdaterArtifacts=false must mean NO updater artifacts
# were actually emitted. Tauri names them "<bundle>.tar.gz"/".zip" plus a
# detached "<bundle>.tar.gz.sig"/".zip.sig"; a stray one here would mean the
# config drifted at build time even if the JSON check passed. Refuse to proceed.
UPDATER_HITS="$(find "${BUNDLE_ROOT}" -type f \
  \( -name '*.app.tar.gz' -o -name '*.app.tar.gz.sig' \
     -o -name '*.tar.gz.sig' -o -name '*.zip.sig' -o -name '*.nsis.zip.sig' \
     -o -name '*.msi.zip.sig' \) 2>/dev/null | sort || true)"
if [ -n "${UPDATER_HITS}" ]; then
  printf '%s\n' "${UPDATER_HITS}" >&2
  die "updater artifacts were emitted despite createUpdaterArtifacts=false — config drifted at build time; refusing to continue (no update server exists)"
fi
log "no updater artifacts emitted (createUpdaterArtifacts=false honored at build time)"

if [ -z "${OUT_DIR}" ]; then
  OUT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/postern-package-signed.XXXXXX")"
fi
mkdir -p "${OUT_DIR}"
STAGE="${OUT_DIR}/artifacts"
mkdir -p "${STAGE}"

# Stage the host's bundle artifacts flat (build-signed-bundle.sh reads a flat
# dir). .app is a directory bundle — the .dmg is the distributable there.
#
# Filenames are normalised to be SPACE-FREE at stage time: macOS emits the .dmg
# as "<productName>_<ver>_<arch>.dmg" ("Postern Desktop_0.1.0_x64.dmg"), and both
# the signing pipeline and, more importantly, the tough-based TUF client that
# packaging/build-signed-bundle.sh drives address artifacts by name and cannot
# resolve a target name containing a space (its file:// fetch url-encodes it).
# Collapsing spaces to underscores keeps the whole reused pipeline on the exact
# space-free convention the Linux (deb/rpm/AppImage) and Windows (msi/nsis)
# bundlers already produce, so this is a no-op on every OS except macOS.
COUNT=0
while IFS= read -r f; do
  dest="$(basename "$f")"
  dest="${dest// /_}"
  cp "$f" "${STAGE}/${dest}"
  COUNT=$((COUNT + 1))
done < <(find "${BUNDLE_ROOT}" -type f \
  \( -name '*.deb' -o -name '*.rpm' -o -name '*.AppImage' \
     -o -name '*.dmg' -o -name '*.msi' -o -name '*.exe' \) | sort)
[ "${COUNT}" -gt 0 ] || die "no bundle artifacts found under ${BUNDLE_ROOT}"
log "staged ${COUNT} host artifact(s) into ${STAGE}"

# SHA256SUMS over the staged artifacts.
if command -v sha256sum >/dev/null 2>&1; then
  ( cd "${STAGE}" && sha256sum * ) > "${OUT_DIR}/SHA256SUMS"
else
  ( cd "${STAGE}" && shasum -a 256 * ) > "${OUT_DIR}/SHA256SUMS"
fi
log "wrote ${OUT_DIR}/SHA256SUMS"

# ── leg 1: reuse packaging/build-signed-bundle.sh (dev-key TUF + verify) ────
log "invoking ${TUF_PIPELINE} (dev-key TUF metadata + fail-closed verify)"
bash "${TUF_PIPELINE}" "${STAGE}" "${OUT_DIR}/tuf-out"

# ── leg 2: reuse scripts/sign-release.sh over the same manifest ─────────────
# The signature legs (minisign Ed25519 + PQ hybrid Falcon-1024/ML-DSA-87) always
# run. If an operator supplied their own keys (-s/-k) those are used verbatim;
# otherwise we mint CLEARLY-MARKED throwaway dev-sample keys via the existing
# gen-dev-signing-keys.sh so the whole sign→verify path still runs end-to-end.
# Those dev keys land in a directory literally named dev-*-DO-NOT-SHIP and carry
# the "dev-sample" token that trips sign-release.sh's loud non-production guard.
DEV_KEYS_DIR=""
MINISIGN_PUBFILE=""
if [ -z "${SECKEY}" ]; then
  DEV_KEYS_DIR="${OUT_DIR}/dev-signing-keys-DO-NOT-SHIP"
  log "no -s key given: minting throwaway dev-sample signing keys into ${DEV_KEYS_DIR}"
  log "  (dev-sample / DO-NOT-SHIP — NOT production keys; unsigned & un-notarized bundle)"
  bash "${GEN_DEV_KEYS}" --gen -o "${DEV_KEYS_DIR}" --force
  SECKEY="${DEV_KEYS_DIR}/dev-sample.minisign.key"
  KEYPREFIX="${DEV_KEYS_DIR}/dev-sample"
  MINISIGN_PUBFILE="${DEV_KEYS_DIR}/dev-sample.minisign.pub"
  [ -f "${SECKEY}" ] || die "dev-key mint did not produce ${SECKEY}"
fi

# Co-locate SHA256SUMS + .minisig + .pqsig in the STAGE dir so verify-release.sh
# (which reads all three from one -d dir) can re-verify the exact bytes.
log "invoking ${SIGN_PIPELINE} (minisign + PQ hybrid over SHA256SUMS)"
bash "${SIGN_PIPELINE}" -a "${STAGE}" -s "${SECKEY}" -k "${KEYPREFIX}" \
  -o "${STAGE}" -t "postern-desktop"
[ -f "${STAGE}/SHA256SUMS.minisig" ] || die "sign-release.sh did not produce SHA256SUMS.minisig"
[ -f "${STAGE}/SHA256SUMS.pqsig" ]   || die "sign-release.sh did not produce SHA256SUMS.pqsig"

# ── fail-closed verification: BOTH the dev-key TUF leg AND the minisign leg ──
# The dev-key TUF leg was already verified per-artifact INSIDE
# build-signed-bundle.sh above (postern-tuf verify, cross-checked against
# SHA256SUMS — it exits nonzero on any mismatch). Here we additionally drive the
# customer/operator-side verify-release.sh over the minisign + PQ signatures in
# the ONLY correct order (minisign → PQ hybrid → shasum -c). When the operator
# brought their OWN keys we can't derive their pubkey, so we only auto-verify the
# dev-key path; operators verify with their own pubkeys via verify-release.sh.
if [ -n "${MINISIGN_PUBFILE}" ]; then
  log "verifying signed bundle end-to-end via ${VERIFY_PIPELINE} (minisign → PQ → shasum)"
  bash "${VERIFY_PIPELINE}" -d "${STAGE}" \
    -p "${MINISIGN_PUBFILE}" --pq-pubkey "${KEYPREFIX}"
  log "VERIFY OK: dev-key TUF leg (build-signed-bundle.sh) AND minisign+PQ leg BOTH passed."
else
  log "operator keys supplied: skipping auto-verify (verify with verify-release.sh + YOUR pubkeys)."
fi

# Final invariant re-assert: the config the bundle was built from still forbids
# updater artifacts (defence in depth against an edit landing between checks).
grep -q '"createUpdaterArtifacts": false' "${CONF}" \
  || die "createUpdaterArtifacts flipped away from false — refusing to certify this run"
log "createUpdaterArtifacts=false still enforced."

reminders
log "SCOPE: UNAUDITED reference prototype; the .app/.dmg are UNSIGNED and NOT"
log "       notarized (macOS.signingIdentity=null); all signatures above are"
log "       dev-sample / DO-NOT-SHIP. designed != built != booted != shippable."
log "DONE (dev-only). Output: ${OUT_DIR}"
