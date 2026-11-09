#!/usr/bin/env bash
# Run this inside nix develop, or provide python3 and qemu-system-x86_64.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
exec python3 "$script_dir/postern-verify.py" "$@"
