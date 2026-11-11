#!/usr/bin/env bash
# Lightweight local/CI checks. No Nix builds, dependency downloads or deployment.
set -euo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$repo_dir"
cache_dir=$(mktemp -d "${TMPDIR:-/tmp}/postern-core-test.XXXXXX")
trap 'rm -rf -- "$cache_dir"' EXIT
export PYTHONPYCACHEPREFIX="$cache_dir"

python3 --version
for script in scripts/postern-*.sh; do
  bash -n "$script"
done
python3 -m py_compile \
  scripts/postern-verify.py \
  scripts/postern-demo.py \
  tools/parallel-data/postern_data.py \
  tools/parallel-data/benchmark.py \
  tools/parallel-data/tests/test_parallel_data.py \
  tools/postern-status/postern_status.py \
  tools/postern-status/tests/test_postern_status.py
python3 -m unittest discover -s tools/parallel-data/tests -v
python3 -m unittest discover -s tools/postern-status/tests -v
