#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# extract-roothash.sh — PRODUCE the real dm-verity roothash of the attested image.
#
# This is the pipeline that turns `os_roothash` from a design-reference
# PLACEHOLDER into a measured value. It CANNOT run on macOS — it needs a Linux
# host with Nix (flakes) because the roothash only exists once systemd-repart has
# built the erofs rootfs + verity hash tree. On the mac this script is
# statically checked (shellcheck) and reviewed; it produces nothing on the mac —
# only a Nix host makes it emit a value.
#
# What it does on a Nix host:
#   PASS 1  nix build <flake>#<attr>   → builds the immutable image; systemd-repart
#           emits every partition's metadata to `<result>/repart-output.json`,
#           and the `root-verity` partition object carries the real "roothash".
#           We read it with jq. THAT hex string is the real os_roothash.
#   PASS 2  (optional, --bind) rebuild the image with that roothash injected onto
#           the UKI cmdline (module option `bloch.attested.osRoothash`), so it is
#           covered by measured boot. Then re-read repart-output.json to confirm
#           the roothash is stable across the rebuild (it must be — verity is
#           deterministic) and print the cmdline that now carries `roothash=R`.
#
# Usage:
#   extract-roothash.sh [-f FLAKE] [-a ATTR] [-o OUTFILE] [--bind]
#     -f FLAKE    flake ref (default: the repo root two dirs up, ".")
#     -a ATTR     package attr to build (default: attested-image)
#     -o OUTFILE  write the bare roothash hex to this file (default: stdout only)
#     --bind      run PASS 2: rebind roothash into the measured UKI cmdline
#
# Exit: 0 roothash extracted; 1 build/parse failure; 2 usage; 3 not on a Nix host.
set -euo pipefail

FLAKE="."
ATTR="attested-image"
OUTFILE=""
BIND=0

die()   { echo "extract-roothash: $*" >&2; exit 1; }
usage() { echo "usage: extract-roothash.sh [-f FLAKE] [-a ATTR] [-o OUTFILE] [--bind]" >&2; exit 2; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    -f) FLAKE="${2:?-f needs a value}"; shift 2 ;;
    -a) ATTR="${2:?-a needs a value}"; shift 2 ;;
    -o) OUTFILE="${2:?-o needs a value}"; shift 2 ;;
    --bind) BIND=1; shift ;;
    -h|--help) usage ;;
    *) echo "extract-roothash: unknown arg: $1" >&2; usage ;;
  esac
done

# Fail loudly (not silently) if the required toolchain is absent — this is the
# guardrail that keeps a macOS run from ever fabricating a value.
command -v nix >/dev/null 2>&1 || { echo "extract-roothash: no 'nix' — this is a Nix-host-only step (VM-gated). Nothing produced." >&2; exit 3; }
command -v jq  >/dev/null 2>&1 || die "no 'jq' on PATH (needed to parse repart-output.json)"

# --- Read the roothash out of a built image's repart-output.json ---------------
# systemd-repart writes one JSON object per partition. The verity *hash* partition
# is the one that carries "roothash"; we also match by our Label as a fallback.
read_roothash() {
  local result="$1" json
  json="${result}/repart-output.json"
  [ -r "$json" ] || die "no repart-output.json under '$result' (did the attested image build with image.repart?)"
  local rh
  rh="$(jq -r '
      ( map(select(.roothash != null)) )
      | ( map(select((.type // "") | test("root-verity"))) + . )
      | .[0].roothash // empty
    ' "$json")"
  [ -n "$rh" ] || die "no roothash field in $json — the verity partition may not have built"
  # dm-verity sha256 roothash is 64 lowercase hex chars.
  printf '%s' "$rh" | grep -Eq '^[0-9a-f]{64}$' \
    || die "roothash '$rh' is not 64 lowercase hex chars — refusing to treat it as measured"
  printf '%s\n' "$rh"
}

echo "extract-roothash: PASS 1 — nix build ${FLAKE}#${ATTR}" >&2
RESULT="$(mktemp -d)/result"
nix build "${FLAKE}#${ATTR}" --out-link "$RESULT" --print-build-logs \
  || die "pass-1 build failed"
ROOTHASH="$(read_roothash "$RESULT")"
echo "extract-roothash: PASS 1 roothash = ${ROOTHASH}" >&2

if [ "$BIND" -eq 1 ]; then
  echo "extract-roothash: PASS 2 — rebinding roothash into the measured UKI cmdline" >&2
  # Rebuild the SAME nixosConfiguration with the module option set, without
  # editing flake.nix (O2 owns it). We evaluate an override expression that
  # imports the flake by absolute path and layers a one-line module setting
  # bloch.attested.osRoothash onto the postern-attested config via extendModules.
  # The preferred path is O2's `.#attested-roothash` app, which wraps exactly
  # this; this inline --expr keeps the script self-contained if that app is absent.
  FLAKE_ABS="$FLAKE"
  case "$FLAKE_ABS" in
    .|./*|../*|/*) FLAKE_ABS="$(cd "$(dirname -- "${FLAKE_ABS%/}/.")" >/dev/null 2>&1 && pwd)" ;;
    *) die "--bind needs a local flake path (got flakeref '$FLAKE'); use O2's .#attested-roothash app instead" ;;
  esac
  RESULT2="$(mktemp -d)/result"
  nix build --impure --print-build-logs --out-link "$RESULT2" --expr "
    let
      flake = builtins.getFlake \"${FLAKE_ABS}\";
      base  = flake.nixosConfigurations.postern-attested;
      bound = base.extendModules {
        modules = [ { bloch.attested.osRoothash = \"${ROOTHASH}\"; } ];
      };
    in bound.config.system.build.image
  " || die "pass-2 rebind build failed"
  ROOTHASH2="$(read_roothash "$RESULT2")"
  [ "$ROOTHASH" = "$ROOTHASH2" ] \
    || die "roothash changed across rebind ($ROOTHASH → $ROOTHASH2) — verity should be deterministic; investigate before trusting either"
  echo "extract-roothash: PASS 2 roothash stable = ${ROOTHASH2} (now bound as roothash= on the measured cmdline)" >&2
fi

# Emit the bare value on stdout (for capture) and optionally to a file.
printf '%s\n' "$ROOTHASH"
if [ -n "$OUTFILE" ]; then
  printf '%s\n' "$ROOTHASH" > "$OUTFILE"
  echo "extract-roothash: wrote roothash to ${OUTFILE}" >&2
fi

echo "extract-roothash: DONE. This is a REAL roothash ONLY because it came from a Nix-host build." >&2
echo "                  Pin it as Expected.os_roothash, then prove it reached the running node" >&2
echo "                  with verify-boot-binding.sh (software chain) + a TPM2 PCR read (hardware)." >&2
