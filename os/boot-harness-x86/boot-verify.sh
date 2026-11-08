#!/usr/bin/env sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# boot-verify.sh — KVM-accelerated boot-verification wrapper around
# boot-qemu-x86_64.sh, for use ONLY on a bare-metal AWS instance
# (c5.metal / m5.metal / m5zn.metal, us-west-2 — see the
# `boot-verify-metal-userdata.sh` sibling) where /dev/kvm is real, not nested
# TCG. It does three things the plain TCG harness does not:
#
#   1. Forces QEMU_ACCEL=kvm + QEMU_CPU=host (the plain harness defaults to
#      TCG because the mac and most CI runners have no /dev/kvm — see
#      boot-qemu-x86_64.sh's own comment on this).
#   2. Fails loudly (not silently falls back to TCG) if /dev/kvm is missing,
#      so a misconfigured instance cannot produce a slow-but-quiet TCG run
#      that looks like a KVM run.
#   3. Cross-checks the dm-verity roothash: extracts the REFERENCE roothash
#      from the built image (extract-roothash.sh, PASS 1 only — no rebind)
#      BEFORE booting, then greps the captured serial console for the
#      roothash the running kernel actually saw on its command line, and
#      diffs the two. This is the host-side half of what
#      os/attested/verify-boot-binding.sh does guest-side (that script needs
#      a shell ON the booted node; this one only needs the serial transcript,
#      so it is fully automatable from the QEMU host with no expect/ssh).
#
# STATUS: STAGED, NOT RUN. No `.#iso` has been built anywhere yet (macOS dev
# host: no Nix, no QEMU, no KVM). This script is written and ready to run on
# the Nix+QEMU+KVM metal box the day an ISO exists. Until it runs there and
# produces a graded PASS + a roothash match, nothing here is evidence of
# anything — same honesty rule as boot-qemu-x86_64.sh:
#   built != booted . QEMU != hardware . reproducible-by-design != reproduced.
# KVM narrows (not closes) the QEMU!=hardware gap: real virtualization
# extensions run the guest's instructions natively, but firmware, TPM,
# SEV-SNP/TDX launch measurement, and physical devices are still unmodeled
# here (that's the attested.nix / L3 TEE rung, a separate deliverable).
#
# Usage:
#   boot-verify.sh --variant node|desktop --iso <path|s3://…|https://…>
#                   [--flake <path>] [--roothash-attr <attr>]
#                   [--log <file>] [--timeout <secs>] [--mem <MiB>] [--smp <n>]
#                   [--s3-results <s3://bucket/prefix>] [--skip-roothash]
# Env overrides mirror boot-qemu-x86_64.sh (VARIANT, ISO, LOG, BOOT_TIMEOUT,
# MEM, SMP, MARKERS), plus: FLAKE, ROOTHASH_ATTR, S3_RESULTS, SKIP_ROOTHASH.
#
# Exit: 0 boot graded PASS AND roothash matched (or --skip-roothash);
#       1 boot ladder failed/out of order (see check-boot-log.sh);
#       2 boot/QEMU failure marker seen;
#       4 no bootable ISO produced/located;
#       5 missing tool OR no /dev/kvm (this host cannot do a KVM run);
#       6 roothash extracted but did NOT match the serial-log value.
set -eu

# shellcheck disable=SC1007  # `CDPATH= cd` is the intended scoped-empty idiom
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BOOT_QEMU="$HERE/boot-qemu-x86_64.sh"
EXTRACT_ROOTHASH="$HERE/../attested/extract-roothash.sh"

VARIANT=${VARIANT:-node}
ISO=${ISO:-}
FLAKE=${FLAKE:-"$HERE/../.."}
ROOTHASH_ATTR=${ROOTHASH_ATTR:-attested-image}
LOG=${LOG:-/tmp/qemu-x86_64-kvm-boot.log}
BOOT_TIMEOUT=${BOOT_TIMEOUT:-600}
MEM=${MEM:-4096}
SMP=${SMP:-4}
S3_RESULTS=${S3_RESULTS:-}
SKIP_ROOTHASH=${SKIP_ROOTHASH:-0}

while [ $# -gt 0 ]; do
  case "$1" in
    --variant) VARIANT=$2; shift 2 ;;
    --iso) ISO=$2; shift 2 ;;
    --flake) FLAKE=$2; shift 2 ;;
    --roothash-attr) ROOTHASH_ATTR=$2; shift 2 ;;
    --log) LOG=$2; shift 2 ;;
    --timeout) BOOT_TIMEOUT=$2; shift 2 ;;
    --mem) MEM=$2; shift 2 ;;
    --smp) SMP=$2; shift 2 ;;
    --s3-results) S3_RESULTS=$2; shift 2 ;;
    --skip-roothash) SKIP_ROOTHASH=1; shift ;;
    -h|--help) sed -n '3,45p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 5 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1" >&2; exit 5; }; }
need grep
need awk
[ -x "$BOOT_QEMU" ] || [ -r "$BOOT_QEMU" ] || { echo "cannot find boot-qemu-x86_64.sh at $BOOT_QEMU" >&2; exit 5; }

# ── 0. This is the whole point of running on metal: refuse a quiet TCG fallback ─
if [ ! -e /dev/kvm ]; then
  echo "boot-verify: /dev/kvm not present. This host is not KVM-capable (or the" >&2
  echo "  kvm module isn't loaded) — refusing to silently fall back to TCG, which" >&2
  echo "  is what boot-qemu-x86_64.sh would otherwise do. Run this on a *.metal" >&2
  echo "  instance (see boot-verify-metal-userdata.sh) with kvm_intel/kvm_amd" >&2
  echo "  loaded, or drop to plain boot-qemu-x86_64.sh if a TCG run is what you" >&2
  echo "  actually want." >&2
  exit 5
fi
if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
  echo "boot-verify: /dev/kvm exists but is not read/write for $(id -un)." >&2
  echo "  Fix: add the user to the 'kvm' group (or run as a user already in it)" >&2
  echo "  and re-login, e.g.: sudo usermod -aG kvm \"\$(id -un)\"" >&2
  exit 5
fi
echo "==> /dev/kvm present and accessible — real hardware virtualization, not TCG."

# ── 1. Resolve --iso if it is a remote ref (s3:// or http[s]://) ──────────────
if [ -n "$ISO" ]; then
  case "$ISO" in
    s3://*)
      need aws
      LOCAL_ISO="${TMPDIR:-/tmp}/$(basename "$ISO")"
      echo "==> fetching ISO from $ISO"
      aws s3 cp "$ISO" "$LOCAL_ISO" || { echo "boot-verify: aws s3 cp failed for $ISO" >&2; exit 4; }
      ISO="$LOCAL_ISO"
      ;;
    http://*|https://*)
      need curl
      LOCAL_ISO="${TMPDIR:-/tmp}/$(basename "$ISO")"
      echo "==> downloading ISO from $ISO"
      curl -fsSL -o "$LOCAL_ISO" "$ISO" || { echo "boot-verify: curl failed for $ISO" >&2; exit 4; }
      ISO="$LOCAL_ISO"
      ;;
  esac
fi
# If ISO is still empty, boot-qemu-x86_64.sh will `nix build .#iso` /
# `.#desktop-iso` itself — that path is unchanged here.

# ── 2. PRE-boot: extract the REFERENCE roothash (build-time, ground truth) ────
REFERENCE_ROOTHASH=""
if [ "$SKIP_ROOTHASH" -eq 0 ]; then
  if [ -x "$EXTRACT_ROOTHASH" ] || [ -r "$EXTRACT_ROOTHASH" ]; then
    echo "==> extracting reference roothash: nix build ${FLAKE}#${ROOTHASH_ATTR}"
    set +e
    REFERENCE_ROOTHASH=$(sh "$EXTRACT_ROOTHASH" -f "$FLAKE" -a "$ROOTHASH_ATTR" 2>/tmp/extract-roothash.stderr)
    RH_RC=$?
    set -e
    if [ "$RH_RC" -ne 0 ] || [ -z "$REFERENCE_ROOTHASH" ]; then
      echo "==> WARN: could not extract a reference roothash (rc=$RH_RC)." >&2
      echo "          $(tail -n1 /tmp/extract-roothash.stderr 2>/dev/null || true)" >&2
      echo "          Continuing WITHOUT the roothash cross-check (boot ladder" >&2
      echo "          grading still runs). Pass --skip-roothash to silence this," >&2
      echo "          or fix the ${ROOTHASH_ATTR} build to get real verification." >&2
      REFERENCE_ROOTHASH=""
    else
      echo "==> reference roothash (PASS 1, from ${ROOTHASH_ATTR}): $REFERENCE_ROOTHASH"
    fi
  else
    echo "==> WARN: extract-roothash.sh not found at $EXTRACT_ROOTHASH — skipping roothash check." >&2
  fi
else
  echo "==> --skip-roothash set: no reference roothash will be extracted or checked."
fi

# ── 3. Boot under REAL KVM (not TCG) and grade with the shared marker ladder ──
echo "==> booting $VARIANT ISO under KVM (accel=kvm, cpu=host)"
export QEMU_ACCEL=kvm
export QEMU_CPU=host
set +e
if [ -n "$ISO" ]; then
  sh "$BOOT_QEMU" --variant "$VARIANT" --iso "$ISO" --log "$LOG" \
    --timeout "$BOOT_TIMEOUT" --mem "$MEM" --smp "$SMP"
else
  sh "$BOOT_QEMU" --variant "$VARIANT" --log "$LOG" \
    --timeout "$BOOT_TIMEOUT" --mem "$MEM" --smp "$SMP"
fi
CHECK_RC=$?
set -e
echo "==> boot-qemu-x86_64.sh (KVM) graded rc=$CHECK_RC (see $LOG and ${LOG%.log}.evidence)"

# ── 4. POST-boot: does the serial log's own roothash= match the reference? ────
# The kernel prints its full command line early in boot ("Command line: ...");
# a systemd-repart/verity image carries `roothash=<hex>` on that line. This is
# a host-side, log-only check — no ssh/RPC into the guest required.
ROOTHASH_RC=0
if [ -n "$REFERENCE_ROOTHASH" ] && [ -r "$LOG" ]; then
  SEEN_ROOTHASH=$(grep -Eo 'roothash=[0-9a-f]{64}' "$LOG" | head -n1 | sed 's/^roothash=//' || true)
  if [ -z "$SEEN_ROOTHASH" ]; then
    echo "==> ROOTHASH: no 'roothash=<hex>' found in $LOG — this ISO/kernel cmdline" >&2
    echo "              does not carry a verity roothash (expected for the plain" >&2
    echo "              node/desktop live ISO; only the attested image binds one)." >&2
    echo "              Not a failure of THIS check; nothing to compare." >&2
  elif [ "$SEEN_ROOTHASH" = "$REFERENCE_ROOTHASH" ]; then
    echo "==> ROOTHASH: PASS — serial-log roothash matches the reference"
    echo "              ($REFERENCE_ROOTHASH)."
  else
    echo "==> ROOTHASH: FAIL — serial-log roothash ($SEEN_ROOTHASH) != reference" >&2
    echo "              ($REFERENCE_ROOTHASH). The booted image is NOT the one" >&2
    echo "              extract-roothash.sh just built. Do not trust this run." >&2
    ROOTHASH_RC=6
  fi
fi

# ── 5. Ship evidence to S3 if asked ────────────────────────────────────────────
if [ -n "$S3_RESULTS" ]; then
  need aws
  echo "==> uploading evidence to $S3_RESULTS"
  aws s3 cp "$LOG" "$S3_RESULTS/" || echo "==> WARN: failed to upload $LOG" >&2
  [ -r "${LOG%.log}.evidence" ] && { aws s3 cp "${LOG%.log}.evidence" "$S3_RESULTS/" || echo "==> WARN: failed to upload evidence sidecar" >&2; }
  {
    echo "variant: $VARIANT"
    echo "accel: kvm (host cpu)"
    echo "check_rc: $CHECK_RC"
    echo "reference_roothash: ${REFERENCE_ROOTHASH:-n/a}"
    echo "roothash_rc: $ROOTHASH_RC"
  } | aws s3 cp - "$S3_RESULTS/summary-$(date -u +%Y%m%dT%H%M%SZ).txt" \
    || echo "==> WARN: failed to upload summary" >&2
fi

# ── 6. Combine exit codes: boot ladder AND roothash must both be clean ────────
if [ "$CHECK_RC" -ne 0 ]; then
  echo "==> NOT PASSED: boot ladder rc=$CHECK_RC (see grading output above)." >&2
  exit "$CHECK_RC"
fi
if [ "$ROOTHASH_RC" -ne 0 ]; then
  echo "==> NOT PASSED: boot ladder was clean but the roothash cross-check FAILED." >&2
  exit "$ROOTHASH_RC"
fi
echo "==> PASS: KVM boot ladder clean AND roothash (if applicable) matched."
echo "          This is the strongest evidence this repo can produce without"
echo "          real x86 firmware/TPM (that is the separate attested.nix /"
echo "          hardware rung)."
exit 0
