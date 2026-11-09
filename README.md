# Postern OS

Private source repository for Postern OS. The **0.2.0-dev** development line adds
two NixOS 26.05 live-image definitions for **x86_64 Linux**, an offline parallel
file-integrity tool, and a shared privacy baseline. Historical desktop, mobile,
wallet and attestation sources remain available separately.

| Image | Flake package | Intended use |
| --- | --- | --- |
| Compute | `.#compute-iso` (also `.#iso`) | Local console, offline data processing and diagnostics |
| Desktop | `.#desktop-iso` | GNOME/Wayland, Firefox, KeePassXC and the same data tools |

These are development live sessions. Both use local `nixos` autologin with sudo;
root and user passwords are locked, and network login is disabled. The desktop
screen lock is disabled for this passwordless live session. Physical access gives
control of the session. Persistent installation, encrypted storage and an
authenticated installed-user setup are separate work.

## Validation status

| Check | Recorded result |
| --- | --- |
| Python integrity-tool tests | 16 passed locally on macOS/Python 3.9.6 after the directory-race fixes; Bash/Python syntax checks also passed |
| Measured parallel hashing after audit fixes | 512 MiB, three repetitions per variant: 1 worker 1.335 s; 2 workers 0.850 s; 4 workers 0.565 s; all nine manifests identical |
| Nix input lock | NixOS 26.05 pinned at `c56a87d8e41ce69bd2af57eb35dcc117a9dfca33`, with its verified NAR hash in `flake.lock` |
| Linux package and privacy VM tests | In validation; no passing result recorded here yet |
| Compute and desktop ISO builds/boots | In validation; no completed image or boot claim recorded here yet |
| Physical hardware, persistent installation and Bloch interoperability | Not validated by this development step |

The measured 2.36× result with four workers applies to one synthetic hashing
workload on one Mac. It does not establish Linux, general OS or blockchain
performance. The [tool documentation and raw measurements](tools/parallel-data/README.md#measure-do-not-assume)
record the run order, effective workers and page-cache limitation. The earlier
measurement is preserved and labeled as evidence from before the audit fixes.

Run `bash scripts/postern-test-core.sh` from a checkout to check the Postern Bash
and Python syntax and execute the integrity-tool unit tests with the installed
Python 3. The wrapper downloads no dependencies and can be reused in CI; no
automatic GitHub workflow is configured. It does not build Nix outputs or boot
an ISO, and a local pass does not establish a Linux CI result.

## Build and boot verification

Use a separate **x86_64 Linux** build environment with Nix flakes enabled. The
scripts do not cross-compile implicitly or reconfigure the host. Fetching Nix
inputs and missing build dependencies requires network access; the data CLI and
ISO boot harness operate offline. Keep the source checkout and artifact
directory separate, and enforce CPU/memory limits on the build environment.

The committed lock records the reviewed NixOS input. To deliberately update
dependencies in a separate maintenance change, generate and review a new lock:

```sh
nix flake update nixpkgs
git diff -- flake.lock
```

Nix uses tracked files from a Git checkout; untracked profiles and tools must be
added before evaluating the flake. Subsequent builds use the reviewed lock
without updating it. From the repository root:

```sh
# Package tests, evaluated image policy and booted privacy-module tests.
nix develop --no-update-lock-file --command bash scripts/postern-build.sh checks

# The same checks plus both ISO builds, with private artifact directories.
nix develop --no-update-lock-file --command bash scripts/postern-build.sh all
```

`compute` or `desktop` builds only that image and does not run the separate check
set. Defaults are two Nix jobs and two cores per job. `POSTERN_BUILD_JOBS`,
`POSTERN_BUILD_CORES` and `POSTERN_BUILD_CPU_BUDGET` can reduce this budget; the
script rejects a jobs × cores product above the budget, whose maximum is eight.
These are scheduling hints. An outer cgroup must enforce host CPU and memory
containment, including for the development-shell setup.

Artifacts go to a new timestamped directory under `../postern-artifacts`, or
`POSTERN_ARTIFACT_DIR` outside the checkout. It contains build logs, JSON results,
source/lock metadata, `STATUS`, and `SHA256SUMS` for any built images. A completed
build is not a boot verdict. Use the exact printed directory for the next step:

```sh
POSTERN_BUILD_DIR=/absolute/path/to/completed-all-build
nix develop --no-update-lock-file --command bash scripts/postern-verify.sh \
  "$POSTERN_BUILD_DIR/postern-compute-x86_64.iso" --profile compute \
  --output "$POSTERN_BUILD_DIR/boot-compute"
nix develop --no-update-lock-file --command bash scripts/postern-verify.sh \
  "$POSTERN_BUILD_DIR/postern-desktop-x86_64.iso" --profile desktop \
  --output "$POSTERN_BUILD_DIR/boot-desktop"
```

Each verification output directory must be new. The harness boots the actual ISO
in QEMU with **no network adapter**, software emulation, at most two vCPUs and
2 GiB RAM. The default deadline is 900 seconds; `--timeout` accepts 60–1800.
It checks console startup, selected privacy settings, sequential/parallel
manifest equality, private manifest permissions and detection of changed data.
The desktop additionally requires an active Wayland session. Evidence includes
the ISO digest, serial log, executed guest script and `result.json`; a screenshot
is supporting evidence, not the pass criterion. This does not replace tests on
physical hardware or establish that every application is confined.

## Offline data processing

Both image definitions include `postern-data`; the standalone package is
`.#parallel-data`. It hashes regular files with SHA-256, validates a saved
inventory and provides a separate measured benchmark. No daemon, telemetry or
automatic background scan is installed.

```sh
mkdir -m 700 -p /tmp/postern-input /tmp/postern-manifests
printf 'example\n' > /tmp/postern-input/example.txt
postern-data scan /tmp/postern-input \
  --output /tmp/postern-manifests/input.jsonl --workers 2
postern-data verify /tmp/postern-input /tmp/postern-manifests/input.jsonl
```

The manifest must be outside the input tree. It is written atomically with mode
`0600`, contains relative names and hashes, and remains sensitive metadata.
Workers are bounded by CPU affinity, cgroup-v2 quotas and available memory;
automatic selection caps at eight. Symlink targets are excluded, and results are
deterministic across worker counts. The tool detects some concurrent changes but
does not create a filesystem snapshot or authenticate a baseline. See the
[CLI reference](tools/parallel-data/README.md) for resource limits, exit codes,
benchmarking and integrity boundaries.

## Privacy and performance profiles

The shared [privacy module](os/profiles/privacy.nix) disables SSH, automatic
discovery, GNOME sharing/online accounts, location services, connectivity probes
and Firefox telemetry/studies. It enables inbound filtering and AppArmor,
discards core dumps, limits the volatile journal, and sets private login-file
permissions. The desktop applies additional browser policies and randomized
Wi-Fi MAC addresses. CPU security mitigations remain enabled.

The [performance module](os/profiles/performance.nix) uses zstd zram, includes
diagnostic tools and limits nested OpenMP/BLAS thread defaults so parallel jobs
do not multiply their worker counts. These settings do not claim a universal
speedup. AppArmor confinement depends on loaded application profiles; normal
outbound DNS, DHCP, time synchronization and application traffic remain possible.
The profile does not make the whole OS anonymous or configure disk encryption.
Volatile system logs do not erase application files, caches or remote records.

## Optional Bloch integration

`nixosModules.bloch-pos` exposes [services.blochPos](os/modules/bloch-pos.nix) for
explicit integration with a separately approved `bloch-pos` package. It is
**not enabled or imported by either live image**. No validator, miner, key or
chain data is bundled or started automatically.

An operator must supply a package containing `bin/bloch-pos`, the intended
genesis, transport/peers, protected keystore credentials and network allowances.
The service uses a dedicated user, systemd credentials and resource limits;
RPC is loopback-only and metrics are disabled by default. Its configuration and
the selected binary must be tested together before production use. The present
OS checks do not validate consensus or compatibility with a live chain.

| Change | Required artifact |
| --- | --- |
| OS packaging, service or external RPC client | New OS image/package; no inherent consensus change |
| Architecture or runtime compatibility | Possibly a rebuild of the same node revision |
| Functionality inside the node executable | New node binary for nodes using that functionality |
| Block-validation, admission or reward rules | Coordinated protocol change and validator upgrade |

## Preserved source and layout

The original [Postern product repository on GitLab](https://gitlab.com/bloch-sis-group/bloch-sis-project)
was imported at commit
[`257ab0703ffc63a7faddb5bf646791e52b3dee3f`](https://gitlab.com/bloch-sis-group/bloch-sis-project/-/tree/257ab0703ffc63a7faddb5bf646791e52b3dee3f).
Its overview is retained in [UPSTREAM-README.md](UPSTREAM-README.md). The original
flake and lock are preserved as `flake.legacy.nix` and `flake.legacy.lock`;
historical `os/configuration.nix` and `os/bloch-node.nix` still describe the PoW
configuration and are not part of the new image definitions. Legacy mobile,
cloud, product-app and hardware-attestation components are not certified by
the new live-image tests.

| Path | Contents |
| --- | --- |
| `flake.nix`, `flake.lock` | New development outputs and their input lock |
| `os/profiles/`, `os/tests/` | Live-image profiles, privacy/performance baseline and VM tests |
| `os/modules/bloch-pos.nix` | Optional node service; no node package or credentials |
| `tools/parallel-data/`, `nix/parallel-data.nix` | Offline integrity CLI, tests, measured evidence and package |
| `scripts/postern-build.sh`, `scripts/postern-verify.*` | Bounded build orchestration and offline ISO boot evidence |
| `crates/`, `desktop/`, `mobile/`, `apps/`, `integration/`, `android-*` | Retained product and shared components |
| `UPSTREAM.json`, `SOURCE-MANIFEST.json` | Original import provenance and per-file hashes, not a manifest of subsequent development |

`data/` contains upstream Rust source packages, not an operator database. The
original GitLab CI configuration remains historical source; it is not a GitHub
Actions workflow and does not deploy this repository.

## Licenses and credentials

Preserve [LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE),
[ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md) and the component-specific notices.
Their terms continue to apply to the imported code and third-party assets.

Do not commit access tokens, validator keys, wallet seeds or operator credentials.
Public certificate chains and explicitly documented development/test fixtures
remain part of the upstream source.
