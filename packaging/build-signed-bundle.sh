#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# build-signed-bundle.sh — DEV/TESTING-ONLY signed-bundle pipeline for the
# Postern TUF update-channel scaffold (packaging/tuf-channel, built on `tough`).
#
# HONESTY HEADER — what this script really does:
#
#   * DEV KEYS ONLY. Every run generates fresh ed25519 keys into a directory
#     literally named dev-keys-DO-NOT-SHIP. Nothing produced here may ever be
#     distributed to a user.
#   * UNAUDITED. The whole channel is a scaffold; no audit has happened.
#   * LOCAL METADATA ONLY. There is NO live update server or endpoint. This
#     script signs and verifies files on YOUR disk, nothing more.
#   * The desktop Tauri config keeps createUpdaterArtifacts=false (enforced by
#     desktop/tests/bundle_config.rs) until the channel is real — this script
#     does not change that and must never be cited as a reason to.
#
# What it does do, end to end, on one machine:
#   1. take a bundle directory (a future `tauri build` output dir), or
#      fabricate a dummy artifact under mktemp with --self-test;
#   2. compute SHA256SUMS over the bundle files;
#   3. build release-manifest.json (name/size/SHA-256 per artifact, honesty
#      note embedded), keygen fresh HYBRID Falcon-1024+ML-DSA-87 DEV keys
#      into dev-keys-DO-NOT-SHIP/, sign the manifest bytes (detached .pqsig,
#      AND-of-both — reusing crates/postern-release via
#      packaging/release-manifest), verify the signature AND re-hash/re-stat
#      the bundle dir against the manifest (fail closed), then cross-check
#      every manifest sha256 against the SHA256SUMS line for the same file;
#   4. run `cargo run --bin postern-tuf -- init/add-target/verify` so every
#      artifact goes through the full fail-closed TUF client path;
#   5. leave the local TUF repository (metadata/, targets/, dev keys), the
#      signed manifest, and the manifest dev keys in an output directory for
#      inspection.
#
# Usage:
#   ./build-signed-bundle.sh <bundle-dir> [out-dir]
#   ./build-signed-bundle.sh --self-test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="${SCRIPT_DIR}/tuf-channel"
MANIFEST_CRATE_DIR="${SCRIPT_DIR}/release-manifest"

log() { printf '[build-signed-bundle] %s\n' "$*"; }
die() { printf '[build-signed-bundle] ERROR: %s\n' "$*" >&2; exit 1; }

sha256_cmd() {
  # macOS ships `shasum`, most Linux distros ship `sha256sum`.
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

[ $# -ge 1 ] || die "usage: $0 <bundle-dir> [out-dir] | $0 --self-test"

SELF_TEST=0
CLEANUP_DIR=""
if [ "$1" = "--self-test" ]; then
  SELF_TEST=1
  CLEANUP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/postern-bundle-selftest.XXXXXX")"
  BUNDLE_DIR="${CLEANUP_DIR}/bundle"
  OUT_DIR="${CLEANUP_DIR}/out"
  mkdir -p "${BUNDLE_DIR}"
  # Fabricate a dummy artifact standing in for a future `tauri build` output.
  printf 'postern dummy bundle artifact (self-test, NOT a real build)\n%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${BUNDLE_DIR}/postern-app-0.0.0-dev.bin"
  log "--self-test: fabricated dummy artifact in ${BUNDLE_DIR}"
else
  BUNDLE_DIR="$1"
  OUT_DIR="${2:-${BUNDLE_DIR}.tuf-out}"
  [ -d "${BUNDLE_DIR}" ] || die "bundle directory not found: ${BUNDLE_DIR}"
fi

if [ ${SELF_TEST} -eq 1 ]; then
  trap '[ -n "${CLEANUP_DIR}" ] && rm -rf "${CLEANUP_DIR}"' EXIT
fi

mkdir -p "${OUT_DIR}"
REPO_DIR="${OUT_DIR}/tuf-repo"
[ ! -e "${REPO_DIR}" ] || die "refusing to reuse existing TUF repo dir: ${REPO_DIR}"

# Collect the bundle's regular files (one vertical slice: flat dir, no recursion).
ARTIFACTS=()
while IFS= read -r f; do
  ARTIFACTS+=("$f")
done < <(find "${BUNDLE_DIR}" -maxdepth 1 -type f ! -name 'SHA256SUMS' | sort)
[ "${#ARTIFACTS[@]}" -gt 0 ] || die "no files found in bundle dir: ${BUNDLE_DIR}"

# 1. SHA256SUMS over the bundle contents.
log "computing SHA256SUMS for ${#ARTIFACTS[@]} artifact(s)"
( cd "${BUNDLE_DIR}" && sha256_cmd $(for f in "${ARTIFACTS[@]}"; do basename "$f"; done) ) \
  > "${OUT_DIR}/SHA256SUMS"
log "wrote ${OUT_DIR}/SHA256SUMS"

# 2. release-manifest.json: build (name/size/sha256 + honesty note) -> fresh
#    HYBRID dev keygen -> detached Falcon-1024+ML-DSA-87 sign -> fail-closed
#    verify (AND-of-both signature + re-hash/re-stat of the bundle dir) ->
#    cross-check every manifest sha256 against SHA256SUMS. All crypto is
#    crates/postern-release, reused (not duplicated) via
#    packaging/release-manifest. DEV KEYS ONLY, UNAUDITED, LOCAL ONLY.
MANIFEST="${OUT_DIR}/release-manifest.json"
MANIFEST_KEYS_DIR="${OUT_DIR}/dev-keys-DO-NOT-SHIP"
MANIFEST_KEY_PREFIX="${MANIFEST_KEYS_DIR}/release-manifest-dev"
release_manifest() {
  cargo run --quiet --manifest-path "${MANIFEST_CRATE_DIR}/Cargo.toml" \
    --bin postern-release-manifest -- "$@"
}
log "postern-release-manifest build -> ${MANIFEST}"
release_manifest build "${BUNDLE_DIR}" "${MANIFEST}"
log "postern-release-manifest keygen (fresh HYBRID Falcon-1024+ML-DSA-87 DEV keys -> ${MANIFEST_KEYS_DIR})"
release_manifest keygen "${MANIFEST_KEY_PREFIX}"
log "postern-release-manifest sign (detached hybrid signature over the exact manifest bytes)"
release_manifest sign "${MANIFEST}" "${MANIFEST_KEY_PREFIX}"
log "postern-release-manifest verify (AND-of-both signature + fail-closed bundle re-check)"
manifest_lines="$(release_manifest verify "${BUNDLE_DIR}" "${MANIFEST}" "${MANIFEST_KEY_PREFIX}")"
# Cross-check EVERY manifest sha256 against the SHA256SUMS line for the same
# file (verify prints one `sha256sum`-format line per artifact on stdout).
# Any missing line or differing hash = die; a count mismatch = die.
manifest_count=0
while IFS= read -r line; do
  [ -n "${line}" ] || continue
  m_hash="${line%%  *}"
  m_name="${line#*  }"
  sums_hash="$(awk -v n="${m_name}" '$2==n || $2=="*"n {print $1}' "${OUT_DIR}/SHA256SUMS")"
  [ -n "${sums_hash}" ] || die "manifest artifact ${m_name} missing from SHA256SUMS"
  [ "${m_hash}" = "${sums_hash}" ] || \
    die "sha256 mismatch for ${m_name}: manifest=${m_hash} SHA256SUMS=${sums_hash}"
  manifest_count=$((manifest_count + 1))
done <<EOF
${manifest_lines}
EOF
sums_count="$(grep -c . "${OUT_DIR}/SHA256SUMS")"
[ "${manifest_count}" -eq "${sums_count}" ] || \
  die "artifact count mismatch: manifest=${manifest_count} SHA256SUMS=${sums_count}"
log "manifest<->SHA256SUMS cross-check OK (${manifest_count} artifact(s))"

if [ ${SELF_TEST} -eq 1 ]; then
  # Determinism proof (manifest/metadata layer ONLY): under SOURCE_DATE_EPOCH
  # (the reproducible-builds convention), two `build` runs over the identical
  # bundle dir must be byte-identical. HONESTY: this pins the MANIFEST bytes;
  # the bundle ARTIFACTS themselves are NOT claimed bit-reproducible.
  log "--self-test: SOURCE_DATE_EPOCH determinism check (two builds, byte-identical)"
  det_a="${CLEANUP_DIR}/det-a.release-manifest.json"
  det_b="${CLEANUP_DIR}/det-b.release-manifest.json"
  SOURCE_DATE_EPOCH=1700000000 release_manifest build "${BUNDLE_DIR}" "${det_a}"
  SOURCE_DATE_EPOCH=1700000000 release_manifest build "${BUNDLE_DIR}" "${det_b}"
  cmp -s "${det_a}" "${det_b}" || \
    die "self-test: two SOURCE_DATE_EPOCH builds differ — manifest determinism is broken"
  log "--self-test: determinism OK (manifest bytes identical; artifacts NOT claimed reproducible)"
fi

# 3. init a fresh local dev TUF repository (fresh dev keys every run).
log "postern-tuf init (fresh DEV keys -> dev-keys-DO-NOT-SHIP)"
cargo run --quiet --manifest-path "${CRATE_DIR}/Cargo.toml" --bin postern-tuf -- \
  init "${REPO_DIR}"

# 4. add every artifact, then verify each through the fail-closed client.
for f in "${ARTIFACTS[@]}"; do
  name="$(basename "$f")"
  log "postern-tuf add-target ${name}"
  cargo run --quiet --manifest-path "${CRATE_DIR}/Cargo.toml" --bin postern-tuf -- \
    add-target "${REPO_DIR}" "$f"
  log "postern-tuf verify ${name}"
  verify_out="$(cargo run --quiet --manifest-path "${CRATE_DIR}/Cargo.toml" --bin postern-tuf -- \
    verify "${REPO_DIR}" "${name}")"
  printf '%s\n' "${verify_out}"
  # Cross-check the TUF-verified hash against SHA256SUMS.
  tuf_hash="$(printf '%s\n' "${verify_out}" | awk 'NR==1{print $1}')"
  sums_hash="$(awk -v n="${name}" '$2==n || $2=="*"n {print $1}' "${OUT_DIR}/SHA256SUMS")"
  [ -n "${sums_hash}" ] || die "artifact ${name} missing from SHA256SUMS"
  [ "${tuf_hash}" = "${sums_hash}" ] || \
    die "hash mismatch for ${name}: TUF=${tuf_hash} SHA256SUMS=${sums_hash}"
  log "hash cross-check OK for ${name}"
done

if [ ${SELF_TEST} -eq 1 ]; then
  # Fail-closed proof: flip one byte of the dummy artifact AFTER build+sign;
  # `verify`'s re-hash of the bundle dir must now HARD-FAIL (exit nonzero).
  # This runs last so the TUF steps above saw the untampered bundle.
  log "--self-test: tampering with the artifact to prove verify fails closed"
  printf 'X' | dd of="${BUNDLE_DIR}/postern-app-0.0.0-dev.bin" \
    bs=1 seek=0 count=1 conv=notrunc 2>/dev/null
  if release_manifest verify "${BUNDLE_DIR}" "${MANIFEST}" "${MANIFEST_KEY_PREFIX}" \
      >/dev/null 2>&1; then
    die "self-test: verify SUCCEEDED on a tampered bundle — fail-closed re-check is broken"
  fi
  log "--self-test: tampered-bundle verify failed as required (fail closed)"
fi

log "DONE (dev-only). Local TUF repo: ${REPO_DIR}"
log "Signed manifest: ${MANIFEST} (+ .pqsig; dev keys in ${MANIFEST_KEYS_DIR})"
log "REMINDER: dev keys, unaudited, LOCAL metadata only — no update server is"
log "live and desktop createUpdaterArtifacts stays false until the channel is real."
if [ ${SELF_TEST} -eq 1 ]; then
  log "self-test artifacts were created under mktemp and are cleaned up on exit."
fi
