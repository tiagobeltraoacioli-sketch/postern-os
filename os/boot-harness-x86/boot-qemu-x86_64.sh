#!/usr/bin/env sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# boot-qemu-x86_64.sh — the x86_64 analogue of
# os/boot-harness/boot-qemu-aarch64.sh. Boots a Postern OS NixOS live ISO under
# qemu-system-x86_64 (TCG, no KVM), captures the serial console as boot
# evidence, and grades it with Dev O4's SHARED grader. Proves the x86_64
# SOFTWARE boot chain only.
#
# THE OVERCLAIM THIS EXISTS TO FIX: the site says the node + desktop ISOs are
# "boot-validated on QEMU x86_64", but NO x86 boot harness and NO committed x86
# boot evidence existed in-repo. This is that harness. Until it actually runs on
# the Nix+QEMU box and produces a graded PASS log, the site claim remains
# UNSUBSTANTIATED — do not represent a green expectation here as a boot.
#
#   built != booted     — a green `nix build` is not this.
#   QEMU != hardware    — TCG emulation says nothing about any real x86 machine,
#                         its firmware, TPM, or measured boot.
#   reproducible-by-design != reproduced.
#   UNAUDITED / SCAFFOLD reference prototype; the coin is worthless by design.
#
# This harness has NEVER been run on the dev workstation (macOS: no Nix, no KVM,
# no qemu-system). It is written to run on a Linux host with Nix + flakes +
# qemu-system-x86_64 — the same host that can `nix build .#iso` / `.#desktop-iso`.
#
# Usage:
#   boot-qemu-x86_64.sh [--variant node|desktop] [--iso <store-path|file>]
#                       [--log <file>] [--timeout <secs>] [--mem <MiB>]
#                       [--smp <n>] [--markers <file>]
# Env overrides: VARIANT, ISO, LOG, BOOT_TIMEOUT, MEM, SMP, MARKERS,
#                QEMU_CPU, QEMU_MACHINE, QEMU_ACCEL.
#
# Definition of done (mirrors the aarch64 Rung 1):
#   1. The captured serial log shows kernel -> NixOS stage-1 -> systemd ->
#      getty (node) OR GDM greeter (desktop) with NO panic / emergency-mode
#      (graded by ../boot-harness/check-boot-log.sh against the x86 markers).
#   2. Functional check (INTERACTIVE / CI-expect follow-up, not done here):
#      node   -> `bloch-wallet --help` on the console;
#      desktop-> a GDM greeter is drawn (needs a graphical run — see README).
#   3. The log is kept as evidence with the ISO store path + sha256 recorded in
#      a `<log>.evidence` sidecar.
#   4. It runs unattended in CI (exit codes below). Wiring the CI job is a
#      separate deliverable — this script is what that job calls.
#
# Exit: 0 boot passed the marker ladder; 1 markers failed; 2 boot/QEMU failure
#       marker; 4 could not produce/locate a bootable ISO; 5 missing tools.
set -eu

# shellcheck disable=SC1007  # `CDPATH= cd` is the intended scoped-empty idiom
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# Dev O4's shared grader lives one directory over; consumed READ-ONLY.
GRADER="$HERE/../boot-harness/check-boot-log.sh"

VARIANT=${VARIANT:-node}
ISO=${ISO:-}
LOG=${LOG:-/tmp/qemu-x86_64-boot.log}
BOOT_TIMEOUT=${BOOT_TIMEOUT:-600}
MEM=${MEM:-2048}
SMP=${SMP:-2}
MARKERS=${MARKERS:-}
QEMU_CPU=${QEMU_CPU:-max}
QEMU_MACHINE=${QEMU_MACHINE:-q35}
# TCG by design: the mac has no KVM, and CI Linux runners are often nested VMs
# without /dev/kvm. Override with QEMU_ACCEL=kvm on a bare-metal Linux host.
QEMU_ACCEL=${QEMU_ACCEL:-tcg}

while [ $# -gt 0 ]; do
  case "$1" in
    --variant) VARIANT=$2; shift 2 ;;
    --iso) ISO=$2; shift 2 ;;
    --log) LOG=$2; shift 2 ;;
    --timeout) BOOT_TIMEOUT=$2; shift 2 ;;
    --mem) MEM=$2; shift 2 ;;
    --smp) SMP=$2; shift 2 ;;
    --markers) MARKERS=$2; shift 2 ;;
    -h|--help) sed -n '3,55p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 5 ;;
  esac
done

# Pick the flake attribute + default markers file for the variant.
case "$VARIANT" in
  node)
    ISO_ATTR=".#iso"
    [ -n "$MARKERS" ] || MARKERS="$HERE/success-markers-x86.txt"
    ;;
  desktop)
    ISO_ATTR=".#desktop-iso"
    [ -n "$MARKERS" ] || MARKERS="$HERE/success-markers-x86-desktop.txt"
    ;;
  *)
    echo "unknown --variant: $VARIANT (want: node|desktop)" >&2; exit 5 ;;
esac

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1" >&2; exit 5; }; }
need qemu-system-x86_64
need grep
need awk
[ -r "$GRADER" ] || { echo "shared grader not readable: $GRADER" >&2; exit 5; }
[ -r "$MARKERS" ] || { echo "markers file not readable: $MARKERS" >&2; exit 5; }

# ── 1. Produce or locate the ISO ──────────────────────────────────────────────
if [ -z "$ISO" ]; then
  need nix
  echo "==> nix build $ISO_ATTR (first build compiles the node; can take a while)"
  OUT=$(nix build "$ISO_ATTR" --no-link --print-out-paths 2>&1 | tail -n1) || {
    echo "nix build $ISO_ATTR failed — nothing to boot." >&2
    exit 4
  }
  ISO="$OUT"
fi
# The isoImage output is a directory containing iso/*.iso; accept either a
# direct .iso file or a store dir and resolve to the .iso inside.
if [ -d "$ISO" ]; then
  FOUND=$(find "$ISO" -maxdepth 3 -type f -name '*.iso' 2>/dev/null | head -n1 || true)
  [ -n "$FOUND" ] && ISO="$FOUND"
fi
if [ ! -f "$ISO" ] || ! printf '%s' "$ISO" | grep -q '\.iso$'; then
  echo "could not locate a bootable *.iso (got: '$ISO')" >&2
  echo "pass one with --iso <file.iso>, or check the $ISO_ATTR output layout." >&2
  exit 4
fi
echo "==> ISO: $ISO"

# ── 2. Record boot-evidence provenance BEFORE booting ─────────────────────────
EVIDENCE="${LOG%.log}.evidence"
{
  echo "# Postern OS — QEMU-x86_64 boot evidence ($VARIANT ISO)"
  echo "# UNAUDITED / SCAFFOLD. built!=booted; QEMU!=hardware; repro-by-design!=reproduced."
  echo "# Site claim 'boot-validated on QEMU x86_64' is backed ONLY once check_rc below is 0."
  echo "variant     : $VARIANT ($ISO_ATTR)"
  echo "timestamp   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host        : $(uname -srm 2>/dev/null || echo unknown)"
  echo "qemu        : $(qemu-system-x86_64 --version 2>/dev/null | head -n1)"
  echo "machine     : -machine $QEMU_MACHINE,accel=$QEMU_ACCEL -cpu $QEMU_CPU -m $MEM -smp $SMP"
  echo "iso_path    : $ISO"
  if command -v nix >/dev/null 2>&1; then
    echo "iso_nixhash : $(nix hash path "$ISO" 2>/dev/null || echo 'n/a')"
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    echo "iso_sha256  : $(sha256sum "$ISO" | awk '{print $1}')"
  fi
  echo "markers     : $MARKERS"
  echo "grader      : $GRADER (Dev O4, read-only)"
  echo "log         : $LOG"
} > "$EVIDENCE"
echo "==> evidence sidecar: $EVIDENCE"

# ── 3. Extract kernel+initrd+boot-params from the ISO so we can FORCE a serial
#      console (console=ttyS0). A live NixOS ISO does not reliably enable ttyS0
#      on its own, and headless serial capture is what the grader reads. If we
#      cannot extract, fall back to a plain -cdrom boot (serial only if the ISO
#      happens to configure it). ─────────────────────────────────────────────
WORK=$(mktemp -d "${TMPDIR:-/tmp}/postern-x86-boot.XXXXXX")
# shellcheck disable=SC2329  # invoked indirectly via the trap below
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

EXTRACTOR=""
for e in xorriso bsdtar 7z 7za osirrox; do
  if command -v "$e" >/dev/null 2>&1; then EXTRACTOR="$e"; break; fi
done

KERNEL=""; INITRD=""; APPEND=""
extract_boot_bits() {
  [ -n "$EXTRACTOR" ] || return 1
  case "$EXTRACTOR" in
    xorriso|osirrox)
      xorriso -osirrox on -indev "$ISO" -extract / "$WORK" >/dev/null 2>&1 || return 1
      ;;
    bsdtar)
      bsdtar -x -f "$ISO" -C "$WORK" >/dev/null 2>&1 || return 1
      ;;
    7z|7za)
      "$EXTRACTOR" x -y -o"$WORK" "$ISO" >/dev/null 2>&1 || return 1
      ;;
  esac
  # NixOS ISOs stage the kernel as /boot/bzImage and initrd as /boot/initrd.
  for k in boot/bzImage boot/kernel boot/vmlinuz; do
    [ -f "$WORK/$k" ] && KERNEL="$WORK/$k" && break
  done
  for i in boot/initrd boot/initrd.img boot/initramfs; do
    [ -f "$WORK/$i" ] && INITRD="$WORK/$i" && break
  done
  # FOUND ON THE FIRST REAL RUN (postern-os-build, 2026-07-14): the 25.05 node
  # ISO does NOT use those legacy paths — it stages the pair under
  # /boot/nix/store/…-linux-*/bzImage and …-initrd-*/initrd (matching the
  # isolinux.cfg KERNEL/INITRD lines). Glob for them before giving up, else
  # this silently degrades to the cdrom fallback and the serial log stalls at
  # the bootloader (no console=ttyS0 on the ISO's own cmdline).
  [ -n "$KERNEL" ] || KERNEL=$(find "$WORK/boot" -type f -name 'bzImage' 2>/dev/null | head -n1)
  [ -n "$INITRD" ] || INITRD=$(find "$WORK/boot" -type f -name 'initrd*' 2>/dev/null | head -n1)
  [ -n "$KERNEL" ] && [ -n "$INITRD" ] || return 1
  # Reuse the ISO's own kernel command line (it carries the exact
  # init=/nix/store/...-init path the live root needs), then force serial.
  CFG=""
  for c in boot/grub/grub.cfg EFI/BOOT/grub.cfg isolinux/isolinux.cfg \
           boot/isolinux/isolinux.cfg boot/syslinux/syslinux.cfg; do
    [ -f "$WORK/$c" ] && CFG="$WORK/$c" && break
  done
  if [ -n "$CFG" ]; then
    # Grab the params from the first kernel/APPEND line, drop the leading
    # kernel-path token and any pre-existing console=, then add ttyS0.
    APPEND=$(awk '
      /^[[:space:]]*(linux|APPEND|append)[[:space:]]/ {
        line=$0
        sub(/^[[:space:]]*(linux|APPEND|append)[[:space:]]+/, "", line)
        # for grub the first token is the kernel path; drop it.
        if ($1 == "linux") sub(/^[^[:space:]]+[[:space:]]+/, "", line)
        print line; exit
      }' "$CFG")
  fi
  # Strip any console= the ISO set, then pin the serial console last.
  # ALSO strip the ISO's quiet-ish loglevel (the 25.05 node ISO ships
  # loglevel=4, which hides the KERN_NOTICE "Linux version …" banner the
  # marker ladder requires) and force a verbose console — this changes
  # console VERBOSITY only, not boot behavior.
  APPEND=$(printf '%s' "$APPEND" | sed 's/console=[^ ]*//g; s/loglevel=[^ ]*//g')
  APPEND="$APPEND loglevel=7 console=ttyS0,115200"
  return 0
}

if extract_boot_bits; then
  BOOT_MODE="kernel+initrd (serial forced)"
else
  BOOT_MODE="cdrom (serial only if the ISO enables ttyS0)"
  echo "==> WARN: could not extract kernel/initrd from the ISO" >&2
  echo "==>       (no xorriso/bsdtar/7z, or unexpected ISO layout);" >&2
  echo "==>       falling back to a plain -cdrom boot. If the serial log is" >&2
  echo "==>       empty the grader will FAIL — install xorriso and re-run." >&2
fi
echo "==> boot mode: $BOOT_MODE"

# Bound a hung boot so unattended CI cannot wedge forever (124 = timed out).
TIMEOUT_PREFIX=""
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_PREFIX="timeout --foreground $BOOT_TIMEOUT"
fi

boot() {
  if [ -n "$KERNEL" ] && [ -n "$INITRD" ]; then
    echo "==> booting: qemu-system-x86_64 -kernel (serial on ttyS0)"
    # ISO is attached as a CD so stage-1 finds the live squashfs by label.
    # shellcheck disable=SC2086
    $TIMEOUT_PREFIX qemu-system-x86_64 \
      -machine "$QEMU_MACHINE",accel="$QEMU_ACCEL" -cpu "$QEMU_CPU" \
      -m "$MEM" -smp "$SMP" \
      -kernel "$KERNEL" -initrd "$INITRD" -append "$APPEND" \
      -drive file="$ISO",format=raw,if=ide,media=cdrom,readonly=on \
      -nographic -serial mon:stdio -no-reboot
    return
  fi
  echo "==> booting: qemu-system-x86_64 -cdrom (fallback)"
  # shellcheck disable=SC2086
  $TIMEOUT_PREFIX qemu-system-x86_64 \
    -machine "$QEMU_MACHINE",accel="$QEMU_ACCEL" -cpu "$QEMU_CPU" \
    -m "$MEM" -smp "$SMP" \
    -cdrom "$ISO" -boot d \
    -nographic -serial mon:stdio -no-reboot
}

echo "==> capturing serial console to $LOG (timeout ${BOOT_TIMEOUT}s)"
set +e
# BOOT_RC is tee's status (POSIX sh has no PIPESTATUS); the marker grading in
# check-boot-log.sh is the real gate. A `timeout` kill still lands in the log.
boot 2>&1 | tee "$LOG"
BOOT_RC=$?
set -e

# ── 4. Grade the captured log against the shared marker contract ──────────────
echo "==> grading $LOG against $MARKERS (via O4 grader)"
set +e
sh "$GRADER" "$LOG" "$MARKERS"
CHECK_RC=$?
set -e

{
  echo "boot_mode   : $BOOT_MODE"
  echo "boot_rc     : ${BOOT_RC:-n/a}"
  echo "check_rc    : $CHECK_RC"
} >> "$EVIDENCE"

echo "==> evidence: $EVIDENCE"
if [ "$CHECK_RC" -eq 0 ]; then
  echo "==> PASS: this log is the first real x86_64 QEMU boot evidence for the"
  echo "         $VARIANT ISO. Commit LOG + EVIDENCE to back the site claim."
else
  echo "==> NOT PASSED (check_rc=$CHECK_RC): the site's 'boot-validated on QEMU"
  echo "         x86_64' claim stays UNSUBSTANTIATED until this grades PASS." >&2
fi
echo "==> NEXT (functional / interactive follow-up):"
if [ "$VARIANT" = "desktop" ]; then
  echo "        run WITHOUT -nographic to eyeball the GDM greeter (see README)"
else
  echo "        bloch-wallet --help        # wallet engine loaded"
  echo "        systemctl is-system-running"
fi
exit "$CHECK_RC"
