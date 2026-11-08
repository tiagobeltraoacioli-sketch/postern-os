#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# build-all-image-targets-userdata-snippet.sh — a snippet to APPEND to whatever
# build user-data/script on the x86_64 Nix build instance already runs
# `nix build .#iso`. It attempts every OTHER x86_64-linux image target
# (`.#desktop-iso`, `.#attested-image`, `.#seal-gate`, `.#cloud-image`) and
# stages each successful result to the build-artifact S3 bucket
# `os/publish-iso.sh` already knows how to pull from (its default SRC_BUCKET:
# postern-os-build-1783966602) — see docs/bucketA/IMAGE-TARGETS.md for the
# full read-through this was written from.
#
# STATUS: STAGED, NOT RUN. This is prep — no build described here has
# happened. It is not a standalone script (no shebang-driven entrypoint logic
# beyond what's below); it assumes it runs in the SAME shell/session as the
# existing `.#iso` step, after Nix is already installed and the repo already
# checked out at $FLAKE_DIR. Fill in the TODOs before use.
#
# What it deliberately does NOT do:
#   - does not attempt `.#mobile-image` (aarch64-linux ONLY — see the
#     aarch64/Graviton block at the bottom, run on a DIFFERENT host);
#   - does not publish anything to R2 / the public downloads page — that
#     stays the separate, explicit `os/publish-iso.sh` step, which enforces
#     the boot-status honesty gate this build step cannot answer;
#   - does not treat a `.#cloud-image` failure as fatal to the sweep — it is
#     EXPECTED to fail until `os/seal-gate.nix`'s 5 `lib.fakeHash` sentinels
#     are filled on this Nix host (os/seal-gate/fill-outputhashes.sh).
#
# ---- TODO: fill these in before use -----------------------------------------
BUILD_S3_BUCKET="${BUILD_S3_BUCKET:-postern-os-build-1783966602}"
BUILD_S3_PREFIX="${BUILD_S3_PREFIX:-builds/$(date -u +%Y-%m-%d)}"
FLAKE_DIR="${FLAKE_DIR:-/opt/postern}"          # same checkout the .#iso step used
# ------------------------------------------------------------------------------

BUILD_LOG_DIR="${BUILD_LOG_DIR:-/var/log/postern-image-builds}"
mkdir -p "$BUILD_LOG_DIR"

stage_result() {
	# $1 = nix attr, $2 = local glob under ./result to upload, $3 = dest filename
	attr="$1"; glob="$2"; dest_name="$3"
	echo "=== nix build .#${attr} ==="
	if nix build ".#${attr}" --print-out-paths \
			> "$BUILD_LOG_DIR/${attr}.outpath" 2> "$BUILD_LOG_DIR/${attr}.log"; then
		src=""
		# shellcheck disable=SC2086
		for cand in ${glob}; do
			if [ -e "$cand" ]; then src="$cand"; break; fi
		done
		if [ -n "$src" ]; then
			aws s3 cp "$src" "s3://${BUILD_S3_BUCKET}/${BUILD_S3_PREFIX}/${dest_name}" \
				&& echo "staged: s3://${BUILD_S3_BUCKET}/${BUILD_S3_PREFIX}/${dest_name}"
		else
			echo "WARN: .#${attr} build reported success but no artifact matched '${glob}'" >&2
		fi
	else
		echo "WARN: .#${attr} build FAILED — see $BUILD_LOG_DIR/${attr}.log" >&2
		echo "      (EXPECTED on first run for .#cloud-image / .#seal-gate until" >&2
		echo "      os/seal-gate.nix's 5 fakeHash sentinels are filled — see" >&2
		echo "      os/seal-gate/fill-outputhashes.sh and os/seal-gate/README.md)" >&2
	fi
}

cd "$FLAKE_DIR" || { echo "FATAL: FLAKE_DIR '$FLAKE_DIR' not found" >&2; exit 1; }

echo "=== image-target build sweep starting: $(date -u +%FT%TZ) ==="

# ── Same x86_64-linux instance as `.#iso` — no new host, no emulation ────────
stage_result "desktop-iso"    "./result/iso/*.iso"            "postern-os-desktop-x86_64.iso"
stage_result "attested-image" "./result/*.raw ./result/*.img" "postern-os-attested-x86_64.raw"
# Unblocks .#cloud-image; a failure here is designed, not a bug in this script.
stage_result "seal-gate"      "./result/bin/postern-seal-gate" "postern-seal-gate-x86_64"
stage_result "cloud-image"    "./result/*.raw ./result/*.img" "postern-cloud-x86_64.raw"

echo "=== image-target build sweep complete: $(date -u +%FT%TZ) ==="
echo "Nothing above was published to R2 / the downloads page. For anything"
echo "that actually succeeded, run os/publish-iso.sh with an honest"
echo "--boot-status (UNBOOTED at minimum; QEMU-PASS/HARDWARE-BOOTED require"
echo "-e/--boot-evidence from the boot-verify harness) as a separate step."

# ─────────────────────────────────────────────────────────────────────────────
# .#mobile-image is aarch64-linux ONLY (flake.nix: optionalAttrs (system ==
# "aarch64-linux")) — it cannot run in the block above. Run the equivalent on
# a DIFFERENT, aarch64 build host (reuse the existing Graviton box already used
# for the aarch64/pmOS pipeline if one is provisioned for this project; native
# aarch64 is strongly preferred over x86_64 + binfmt/qemu-user emulation —
# emulating a Rust/rocksdb/openssl compile is slow and untested here):
#
#   nix build .#mobile-image --print-out-paths
#   aws s3 cp <result-path> \
#     "s3://${BUILD_S3_BUCKET}/${BUILD_S3_PREFIX}/postern-os-mobile-pinephone-aarch64.img"
#
# Also unpinned/at-risk on that host: `mobile-nixos` is a `flake = false`
# source import and flake.lock is currently the empty seed
# (docs/plan/FLAKE-REPRO.md §1) — until scripts/flake-lock.sh freezes a rev,
# `.#mobile-image` re-resolves mobile-nixos HEAD on every eval, and the
# `mobilePinephone.outputs.default` selector in flake.nix may need adjusting
# for whatever rev that resolves to (flake.nix's own header flags this).
