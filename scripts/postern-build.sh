#!/usr/bin/env bash
# Build reviewed Postern outputs without updating their locked inputs.
set -euo pipefail
umask 077

usage() {
  cat <<'EOF'
Usage: postern-build.sh [checks|compute|desktop|mobile|all|compute-vm|desktop-vm]

"all" runs the checks and builds the compute, desktop and mobile live ISOs. The VM modes build a qcow2
development disk and are never part of "all".

Run inside the repository's Linux Nix development shell. Output is written to
a new private directory below POSTERN_ARTIFACT_DIR (default: ../postern-artifacts).
POSTERN_NIX_BIN may select a Nix executable. POSTERN_BUILD_JOBS and
POSTERN_BUILD_CORES default to 2 each; their product may not exceed
POSTERN_BUILD_CPU_BUDGET (default 4, maximum 8). These are build hints; an outer
cgroup must enforce the host's CPU/memory budget.
EOF
}

mode=${1:-all}
case "$mode" in
  -h|--help) usage; exit 0 ;;
  checks|compute|desktop|mobile|all|compute-vm|desktop-vm) ;;
  *) usage >&2; exit 2 ;;
esac
if [[ $# -gt 1 ]]; then usage >&2; exit 2; fi
if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo 'Build on an x86_64 Linux host; no implicit cross compilation.' >&2
  exit 2
fi

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
nix_bin=${POSTERN_NIX_BIN:-nix}
jobs=${POSTERN_BUILD_JOBS:-2}
cores=${POSTERN_BUILD_CORES:-2}
cpu_budget=${POSTERN_BUILD_CPU_BUDGET:-4}
for value in "$jobs" "$cores" "$cpu_budget"; do
  if [[ ! $value =~ ^[1-8]$ ]]; then
    echo 'CPU settings must be integers from 1 to 8.' >&2
    exit 2
  fi
done
if (( jobs * cores > cpu_budget )); then
  echo 'POSTERN_BUILD_JOBS × POSTERN_BUILD_CORES exceeds the CPU budget.' >&2
  exit 2
fi
for command in "$nix_bin" python3 sha256sum realpath; do
  command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 2; }
done

# A seed/placeholder lock must never be called a pinned build.
python3 - "$repo_dir/flake.lock" <<'PY'
import json, sys
lock=json.load(open(sys.argv[1]))
inputs=lock['nodes'][lock['root']].get('inputs',{})
node=inputs.get('nixpkgs')
if not isinstance(node,str):
    raise SystemExit('flake.lock has no direct pinned nixpkgs input')
pin=lock['nodes'][node].get('locked',{})
if not pin.get('rev') or not pin.get('narHash'):
    raise SystemExit('flake.lock lacks a real nixpkgs revision/hash')
PY

artifact_root=$(realpath -m -- "${POSTERN_ARTIFACT_DIR:-$repo_dir/../postern-artifacts}")
case "$artifact_root/" in
  "$repo_dir/"*) echo 'Artifacts must live outside the source checkout.' >&2; exit 2 ;;
esac
mkdir -p -- "$artifact_root"
artifact_dir="$artifact_root/$(date -u +%Y%m%dT%H%M%SZ)-$mode-$$"
mkdir -m 700 -- "$artifact_dir"
printf 'running\n' > "$artifact_dir/STATUS"
trap 'rc=$?; if (( rc != 0 )); then printf "failed:%s\n" "$rc" > "$artifact_dir/STATUS"; fi' EXIT
printf 'Artifacts: %s\n' "$artifact_dir"

python3 - "$repo_dir" "$artifact_dir" <<'PY'
import hashlib,json,pathlib,sys
repo,out=map(pathlib.Path,sys.argv[1:3])
files={repo/'flake.nix',repo/'flake.lock'}
for directory in ('nix','os/profiles','os/tests','os/modules'):
    files.update(p for p in (repo/directory).rglob('*') if p.is_file())
files.update(p for tool in ('parallel-data','postern-status','postern-vault')
             for p in (repo/'tools'/tool).rglob('*')
             if p.is_file() and p.suffix in ('.py','.md','.json','.sh','.svg') and '__pycache__' not in p.parts)
files.update(p for p in (repo/'os'/'assets').rglob('*') if p.is_file())
files.update(p for p in (repo/'scripts').glob('postern*') if p.is_file())
manifest={str(p.relative_to(repo)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}
(out/'input-files-sha256.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
PY
"$nix_bin" --extra-experimental-features 'nix-command flakes' flake metadata --no-update-lock-file --json "$repo_dir" > "$artifact_dir/flake-metadata.json"

build_phase() {
  local phase=$1
  shift
  local refs=()
  for attribute in "$@"; do refs+=("$repo_dir#$attribute"); done
  printf 'Building %s (%s jobs, %s cores per job)\n' "$phase" "$jobs" "$cores"
  if ! "$nix_bin" --extra-experimental-features 'nix-command flakes' build --no-update-lock-file --no-link --json \
       --max-jobs "$jobs" --cores "$cores" --option keep-going false \
       "${refs[@]}" > "$artifact_dir/$phase-build.json" 2> "$artifact_dir/$phase-build.log"; then
    tail -n 80 "$artifact_dir/$phase-build.log" >&2
    echo "Build failed; full log: $artifact_dir/$phase-build.log" >&2
    return 1
  fi
}

copy_iso() {
  local phase=$1
  local output
  output=$(python3 - "$artifact_dir/$phase-build.json" <<'PY'
import json,sys
data=json.load(open(sys.argv[1]))
if len(data)!=1 or 'out' not in data[0].get('outputs',{}):
    raise SystemExit('Expected one ISO build output')
print(data[0]['outputs']['out'])
PY
)
  if [[ ! -d "$output/iso" ]]; then
    echo 'ISO store path is unavailable; run this script inside nix develop.' >&2
    return 1
  fi
  local images=()
  shopt -s nullglob
  images=("$output"/iso/*.iso)
  shopt -u nullglob
  if (( ${#images[@]} != 1 )); then
    echo "Expected exactly one ISO in $output/iso" >&2
    return 1
  fi
  cp --reflink=auto --sparse=always -- "${images[0]}" "$artifact_dir/postern-$phase-x86_64.iso"
  (cd -- "$artifact_dir" && sha256sum "postern-$phase-x86_64.iso" >> SHA256SUMS)
}

copy_vm_image() {
  local phase=$1
  local output
  output=$(python3 - "$artifact_dir/$phase-build.json" <<'PY'
import json,sys
data=json.load(open(sys.argv[1]))
if len(data)!=1 or 'out' not in data[0].get('outputs',{}):
    raise SystemExit('Expected one disk-image build output')
print(data[0]['outputs']['out'])
PY
)
  local images=()
  shopt -s nullglob
  images=("$output"/*.qcow2)
  shopt -u nullglob
  if (( ${#images[@]} != 1 )); then
    echo "Expected exactly one qcow2 image in $output" >&2
    return 1
  fi
  cp --reflink=auto --sparse=always -- "${images[0]}" "$artifact_dir/postern-$phase-x86_64.qcow2"
  chmod 600 -- "$artifact_dir/postern-$phase-x86_64.qcow2"
  (cd -- "$artifact_dir" && sha256sum "postern-$phase-x86_64.qcow2" >> SHA256SUMS)
}

if [[ $mode == checks || $mode == all ]]; then
  build_phase checks checks.x86_64-linux.parallel-data checks.x86_64-linux.postern-status checks.x86_64-linux.postern-vault checks.x86_64-linux.image-policy checks.x86_64-linux.privacy
fi
if [[ $mode == compute-vm || $mode == desktop-vm ]]; then
  build_phase "$mode" "packages.x86_64-linux.$mode-image"
  copy_vm_image "$mode"
fi
if [[ $mode == compute || $mode == all ]]; then
  build_phase compute packages.x86_64-linux.compute-iso
  copy_iso compute
fi
if [[ $mode == desktop || $mode == all ]]; then
  build_phase desktop packages.x86_64-linux.desktop-iso
  copy_iso desktop
fi
if [[ $mode == mobile || $mode == all ]]; then
  build_phase mobile packages.x86_64-linux.mobile-iso
  copy_iso mobile
fi

python3 - "$repo_dir" "$artifact_dir" "$mode" "$jobs" "$cores" <<'PY'
import datetime,hashlib,json,pathlib,subprocess,sys
repo,out=map(pathlib.Path,sys.argv[1:3])
def git(*args):
    p=subprocess.run(['git','-C',str(repo),*args],capture_output=True,text=True)
    return p.stdout.strip() if p.returncode==0 else None
source_status=git('status','--porcelain')
record={
 'completed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'mode':sys.argv[3], 'source_revision':git('rev-parse','HEAD'),
 'source_dirty':None if source_status is None else bool(source_status),
 'flake_lock_sha256':hashlib.sha256((repo/'flake.lock').read_bytes()).hexdigest(),
 'input_files_sha256':json.loads((out/'input-files-sha256.json').read_text()),
 'max_jobs':int(sys.argv[4]), 'cores_per_job':int(sys.argv[5]),
 'images':[p.name for p in sorted([*out.glob('*.iso'),*out.glob('*.qcow2')])],
 'verification':'Build output only; booting an image is a separate step (postern-verify.sh for ISOs).'}
(out/'build-summary.json').write_text(json.dumps(record,indent=2)+'\n')
PY
printf 'complete\n' > "$artifact_dir/STATUS"
printf 'Build complete: %s\n' "$artifact_dir"
