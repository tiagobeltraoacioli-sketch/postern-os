#!/usr/bin/env bash
# mobile/ci/check-stream.sh
#
# One-command lightweight consistency gate for the "Postern OS mobile/aarch64
# image + pmOS overlay + mobile app shells" workstream.
#
# What this is: a fast, source-level sanity check (lint + syntax/parse +
# honesty-marker grep). What this is NOT: a build. It never invokes `nix
# build`, `cargo build`/`cargo test`, `pmbootstrap`, or the QEMU boot harness
# — those are heavy, environment-dependent operations that belong to a real
# CI/build pipeline, not a pre-commit-speed gate.
#
# Each check prints exactly one "PASS: ...", "SKIP: ..." or "FAIL: ..." line.
# The script exits 0 only if every check PASSed (SKIP is allowed only for the
# nix-instantiate parse check, and only when nix-instantiate is genuinely
# absent from PATH — it is never used to paper over a real failure).
set -euo pipefail

# Repo root = two levels up from this script (mobile/ci/ -> repo root).
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

overall_status=0

pass() { printf 'PASS: %s\n' "$1"; }
skip() { printf 'SKIP: %s\n' "$1"; }
fail() { printf 'FAIL: %s\n' "$1"; overall_status=1; }

# --------------------------------------------------------------------------
# 1) shellcheck -S warning across the workstream's shell scripts.
# --------------------------------------------------------------------------
check_shellcheck() {
  local label="shellcheck -S warning (pmos-overlay + mobile + os/boot-harness shell scripts)"

  if ! command -v shellcheck >/dev/null 2>&1; then
    fail "$label — shellcheck not found on PATH"
    return
  fi

  local -a scripts=()
  local -a globs=(
    "pmos-overlay"/*.sh
    "pmos-overlay/build"/*.sh
    "pmos-overlay/keys"/*.sh
    "pmos-overlay/flavor/first-run"/*.sh
    "mobile/build-android.sh"
    "mobile/build-ios.sh"
    "mobile/ci"/*.sh
    "os/boot-harness"/*.sh
  )
  local g
  for g in "${globs[@]}"; do
    if [ -e "$g" ]; then
      scripts+=("$g")
    fi
  done

  if [ "${#scripts[@]}" -eq 0 ]; then
    fail "$label — no scripts matched the expected globs"
    return
  fi

  if shellcheck -S warning "${scripts[@]}"; then
    pass "$label (${#scripts[@]} scripts)"
  else
    fail "$label"
  fi
}

# --------------------------------------------------------------------------
# 2) bash -n on the Alpine APKBUILD files (they're sourced as shell by
#    abuild/pmbootstrap, so a syntax error there breaks the real build).
# --------------------------------------------------------------------------
check_apkbuild_syntax() {
  local label="bash -n on pmos-overlay APKBUILDs"
  local -a apkbuilds=(
    "pmos-overlay/postern/APKBUILD"
    "pmos-overlay/postern-wallet/APKBUILD"
    "pmos-overlay/postern-apps/APKBUILD"
    "pmos-overlay/flavor/postern-flavor/APKBUILD"
  )
  local f ok=1
  for f in "${apkbuilds[@]}"; do
    if [ ! -f "$f" ]; then
      fail "$label — missing $f"
      ok=0
      continue
    fi
    if ! bash -n "$f" 2>&1; then
      fail "$label — syntax error in $f"
      ok=0
    fi
  done
  if [ "$ok" -eq 1 ]; then
    pass "$label (${#apkbuilds[@]} files)"
  fi
}

# --------------------------------------------------------------------------
# 3) npm run check in mobile/signer-app (node --check over bridge/server.js,
#    bridge/signer-bridge.js, web/app.js — no install, no server start).
# --------------------------------------------------------------------------
check_signer_app_syntax() {
  local label="npm run check (mobile/signer-app: node --check on bridge + web JS)"

  if ! command -v npm >/dev/null 2>&1; then
    fail "$label — npm not found on PATH"
    return
  fi
  if [ ! -f "mobile/signer-app/package.json" ]; then
    fail "$label — mobile/signer-app/package.json missing"
    return
  fi

  local logf
  logf="$(mktemp)"
  if (cd mobile/signer-app && npm run check --silent) >"$logf" 2>&1; then
    pass "$label"
  else
    fail "$label — see output below"
    cat "$logf" >&2
  fi
  rm -f "$logf"
}

# --------------------------------------------------------------------------
# 4) python3 -m py_compile on the R2 upload helper.
# --------------------------------------------------------------------------
check_r2_upload_py() {
  local label="python3 -m py_compile pmos-overlay/build/r2_upload.py"

  if ! command -v python3 >/dev/null 2>&1; then
    fail "$label — python3 not found on PATH"
    return
  fi
  if [ ! -f "pmos-overlay/build/r2_upload.py" ]; then
    fail "$label — file missing"
    return
  fi

  if python3 -m py_compile pmos-overlay/build/r2_upload.py; then
    pass "$label"
    # Note: py_compile regenerates pmos-overlay/build/__pycache__/*.pyc as a
    # side effect. That cache file is tracked in this repo (not gitignored),
    # so a run of this check can leave it touched in `git status` — that is
    # expected byproduct of the mandated check, not a bug in this script.
  else
    fail "$label"
  fi
}

# --------------------------------------------------------------------------
# 5) The single-UniFFI-scaffolding gate (Dev-F1 convergence check).
# --------------------------------------------------------------------------
check_setup_scaffolding() {
  local label="mobile/ci/check-one-setup-scaffolding.sh"
  local script="mobile/ci/check-one-setup-scaffolding.sh"

  if [ ! -x "$script" ]; then
    fail "$label — missing or not executable: $script"
    return
  fi

  local logf
  logf="$(mktemp)"
  if "$script" >"$logf" 2>&1; then
    pass "$label"
  else
    fail "$label — see output below"
    cat "$logf" >&2
  fi
  rm -f "$logf"
}

# --------------------------------------------------------------------------
# 6) nix-instantiate --parse on os/mobile.nix and os/telephony.nix, ONLY if
#    nix-instantiate is on PATH. Honest SKIP (not a silent PASS) otherwise.
# --------------------------------------------------------------------------
check_nix_parse() {
  local label="nix-instantiate --parse (os/mobile.nix, os/telephony.nix)"

  if ! command -v nix-instantiate >/dev/null 2>&1; then
    skip "$label — no nix on this host — parse not run"
    return
  fi

  local -a nixfiles=("os/mobile.nix" "os/telephony.nix")
  local f ok=1
  for f in "${nixfiles[@]}"; do
    if [ ! -f "$f" ]; then
      fail "$label — missing $f"
      ok=0
      continue
    fi
    if ! nix-instantiate --parse "$f" >/dev/null 2>&1; then
      fail "$label — parse error in $f"
      ok=0
    fi
  done
  if [ "$ok" -eq 1 ]; then
    pass "$label"
  fi
}

# --------------------------------------------------------------------------
# 7) Caveat guard: FAIL if any required honesty marker has disappeared.
#    This is the check that keeps "unbooted / unaudited / zero-security /
#    wallet-only / no mining on phones" true in the tree, not just in memory.
# --------------------------------------------------------------------------
check_caveats() {
  local label="caveat guard (honesty markers)"
  local ok=1

  _require() {
    local file="$1" needle="$2"
    if [ ! -f "$file" ]; then
      fail "$label — missing file: $file"
      ok=0
      return
    fi
    if ! grep -qF -- "$needle" "$file"; then
      fail "$label — missing marker '$needle' in $file"
      ok=0
    fi
  }

  _require "os/MOBILE.md" "wallet only"
  _require "os/MOBILE.md" "zero-security"
  _require "mobile/signer/Cargo.toml" "UNBOOTED"
  _require "mobile/signer/Cargo.toml" "UNAUDITED"
  _require "mobile/signer-app/package.json" "UNBOOTED"
  _require "pmos-overlay/README.md" "Nothing here has been built"

  # No-mining-on-phones: services.bloch.enable must be forced off in the
  # phone profile.
  local mobnix="os/mobile.nix"
  if [ ! -f "$mobnix" ]; then
    fail "$label — missing file: $mobnix"
    ok=0
  elif ! grep -qE 'services\.bloch\.enable[[:space:]]*=[[:space:]]*lib\.mkForce[[:space:]]+false' "$mobnix"; then
    fail "$label — services.bloch.enable is not forced to false (no-mining-on-phones) in $mobnix"
    ok=0
  fi

  if [ "$ok" -eq 1 ]; then
    pass "$label (7 markers across 5 files)"
  fi
}

# --------------------------------------------------------------------------
# Run all checks.
# --------------------------------------------------------------------------
check_shellcheck
check_apkbuild_syntax
check_signer_app_syntax
check_r2_upload_py
check_setup_scaffolding
check_nix_parse
check_caveats

exit "$overall_status"
