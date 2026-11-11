# Postern OS

Private source repository for Postern OS. The **0.4.0-dev** development line
defines three NixOS 26.05 live images for **x86_64 Linux**, virtual-machine
development disks, an offline parallel file-integrity tool, encrypted container
files, a read-only privacy and hardening status report, and a shared privacy
and kernel-hardening baseline. Historical desktop, mobile,
wallet and attestation sources remain available separately.

| Image | Flake package | Intended use |
| --- | --- | --- |
| Compute | `.#compute-iso` (also `.#iso`) | Local console, offline data processing and diagnostics |
| Desktop | `.#desktop-iso` | GNOME/Wayland, Firefox, Tor Browser, KeePassXC, Metadata Cleaner and the same data tools |
| Mobile | `.#mobile-iso` | Phone interface (Phosh) on a portrait display, for a virtual machine or x86 tablet; not a handset image |
| Compute VM disk | `.#compute-vm-image` | qcow2 development disk for a virtual machine; console only |
| Desktop VM disk | `.#desktop-vm-image` | qcow2 development disk for a virtual machine; GNOME desktop |

These are development live sessions. All use local `nixos` autologin with sudo;
root and user passwords are locked, and network login is disabled. The desktop
screen lock is disabled for this passwordless live session. Physical access gives
control of the session. Persistent installation, encrypted storage and an
authenticated installed-user setup are separate work.

The VM disks keep data across restarts on an **unencrypted** virtual disk, with
the same password-locked local autologin. They exist for development inside a
virtual machine. Do not write one to a physical machine or keep private data in
it; they are not an installer and configure neither disk encryption nor a real
user account.

## What 0.4.0-dev adds

Security

- Kernel hardening on every image (`os/profiles/hardening.nix`): memory is
  wiped when allocated and when freed, the allocator and kernel stack are
  hardened, kexec, hibernation, SysRq, the legacy vsyscall page and debugfs are
  off, unprivileged userfaultfd and line-discipline autoloading are disabled,
  ICMP redirects and source routing are ignored, and unused network protocol
  modules (SCTP, DCCP, RDS, TIPC and others) and FireWire cannot be loaded.
  This raises the cost of exploiting a bug. It is not a sandbox, removes no
  bug, and wiping memory costs some speed.
- Network identity: NetworkManager now runs on every image, including the
  console image (`nmtui`, `nmcli`). Each connection, wired or wireless, uses a
  random hardware address and the host name is not sent in DHCP requests. A
  network that admits devices by hardware address needs that changed for its
  connection.
- `postern-vault`: encrypted container files (LUKS2, AES-256-XTS, Argon2id)
  that can live on removable media, so a live session can keep private files
  across restarts. See [its documentation and limits](tools/postern-vault/README.md);
  a lost passphrase cannot be recovered.
- `postern-status` reports two more observations, kernel hardening and network
  identity, on the command line and in the Postern Status application.
- Desktop: Tor Browser and Metadata Cleaner are included. Tor Browser starts
  only when opened and protects only its own traffic; no system-wide Tor daemon
  runs.

Function and speed

- Compressed swap in memory now covers up to half of RAM, with kernel settings
  suited to it; the session stops a runaway group of processes under memory
  pressure instead of freezing (systemd-oomd); BBR congestion control with fair
  queueing; interrupt balancing.
- More tools on every image: `age`, `gnupg`, `git`, `tmux`, `rsync`, `zstd`,
  `pv`, `parallel`, `fd`, `smartmontools`, `nvme-cli`, `wireguard-tools`,
  hardware listing tools.
- Mobile: Calendar, Contacts, Weather, image and document viewers, an audio
  player, Secrets (a KeePass-format password manager with a phone layout) and
  the phone shell's settings application.

Look

- One icon family (Tela) and one pointer (Bibata) on desktop and mobile, an
  original Postern Status application icon, window controls at the left of the
  title bar, and the existing dock, blur, wallpaper and fonts.
- Mobile: in a virtual machine the phone shell's compositor uses its pixman
  renderer. Its OpenGL path on a software rasterizer left stale black squares
  on screen in 0.3.1-dev; a side-by-side run in QEMU showed pixman drawing the
  same screens correctly. Real hardware keeps the GPU renderer. Firefox, Files
  and Postern Status are listed in the phone shell's grid and search.
- `scripts/postern-demo.py` now composes the walkthrough video: the captured
  screen, unmodified, inside a drawn device frame, with captions set beside it,
  an opening card and a closing card listing the checks recorded during the
  session. Playback is faster than real time, idle waits are shortened and the
  boot of the graphical images is not shown; the opening card and `result.json`
  say so. On the mobile image applications are opened from the phone shell's
  search with keyboard events, with a recorded fallback to the serial console.

## What 0.3.1-dev added

- Desktop look: an original wallpaper (`os/assets/wallpaper.svg`), a fixed
  translucent dock, blurred top bar and overview (Dash to Dock and Blur my
  Shell), Inter and JetBrains Mono, a themed terminal, window minimize and
  maximize buttons, and the desktop shown at login instead of the overview.
  These are defaults; the user can change each one in Settings.
- Postern Status is now a desktop application (GTK 4, libadwaita) that adapts
  to a phone-width window. It renders the same report as the command-line tool.
- Firefox starts on a quiet page: no onboarding, import prompt or promotions.
- Mobile image: the Phosh phone shell with the same privacy baseline, wallpaper,
  fonts, Firefox policy and tools. It starts unlocked because the live account
  has no password; an installed phone must set a PIN and keep the lock. It has
  no handset port, modem, telephony or battery management, and none is tested.
- A graphical boot splash (Plymouth) was tried and removed: after autologin it
  left the display on the login greeter.

## What 0.3.0-dev added

- `postern-status`: a read-only report of the observable privacy baseline
  (firewall, listeners, remote-login services, AppArmor, CPU mitigations, core
  dumps, swap, temporary storage, journal, account passwords), as a table or
  JSON. A check that cannot read its source reports `unknown`, never `ok`. See
  [its documentation and limits](tools/postern-status/README.md).
- Desktop: a "Postern Status" launcher, a fixed dock (Firefox, Files, Terminal,
  KeePassXC, Postern Status, Settings), dark style, and GNOME defaults that keep
  no recent-file history, disable location services and usage reporting, and
  expire trash and temporary files after one day.
- VM development disks (`compute-vm`, `desktop-vm`) bootable under BIOS and UEFI.
- `scripts/postern-demo.py`: records a scripted walkthrough of a real ISO booted
  offline in QEMU, driven by keyboard events, as an MP4 with captions.

## Validation status

### 0.4.0-dev

| Check | Recorded result |
| --- | --- |
| Core tests (`scripts/postern-test-core.sh`) | Passed on macOS: 16 integrity-tool tests and 22 status-report tests, plus Bash/Python syntax checks including `postern-vault` |
| Nix checks (`postern-build.sh checks`) | Passed on the final source tree on an x86_64 Linux builder: the three tool packages with their tests, the evaluated image policy for all five image configurations, and the booted test, which now also checks the kernel hardening on a running system, that an unused protocol module cannot be loaded, and an encrypted vault round trip (contents not readable in the closed file, wrong passphrase rejected, read-only reopen, key file) |
| ISO builds | Completed on an x86_64 Linux builder: desktop SHA-256 `39546a1e…0d1e8c056f`, mobile `735ddf06…03300ab02b`, compute `2309e6be…d741149d45` |
| Actual ISO boots (`postern-verify.sh`) | All three passed offline under software emulation with 2 vCPUs and 2 GiB RAM: compute in 155 s, desktop (active Wayland session) in 200 s, mobile (phone shell running) in 219 s. The check requires a status report with no failed and no undetermined item |
| Recorded walkthroughs (`postern-demo.py`) | Completed for all three ISOs under software emulation; every recorded check passed (19 desktop, 12 mobile, 6 compute). Desktop: all eight applications opened from the Activities search. Mobile: five applications opened from the phone shell's search with keyboard events; Files and Settings did not start within the wait and were started from the serial console, as `result.json` records |
| Mobile rendering | The stale black squares of 0.3.1-dev were reproduced in QEMU with the compositor's OpenGL renderer and did not appear with pixman in the same session, nor in the final recording. Not tested on physical hardware |
| VM disks | Defined and evaluated; not rebuilt or booted for 0.4.0-dev |
| KVM, physical hardware, Wi-Fi/DHCP behaviour on a real network, persistent installation, Tor Browser connectivity and Bloch interoperability | Not validated. The recordings run with no network adapter, so the network-identity settings are checked as configuration, not as observed packets |

The builder had no KVM and ran Nix inside a container with the Nix build sandbox
disabled; these are development builds, not reproducibility or release claims.
One earlier recording attempt of the desktop failed a timing check and two of
the mobile stopped at the Console step (a search for "console" opened a
terminal program while every installed entry was listed); the recorder now
polls instead of waiting a fixed time and the phone grid is curated. Result
files are kept in [docs/evidence/postern-0.4.0-dev](docs/evidence/postern-0.4.0-dev).

### 0.3.0-dev

| Check | Recorded result |
| --- | --- |
| Core tests (`scripts/postern-test-core.sh`) | Passed on macOS/Python 3.9.6: 16 integrity-tool tests and 18 status-report tests, plus Bash/Python syntax checks |
| Nix checks (`postern-build.sh all`) | Passed on an x86_64 Linux builder: both tool packages with their unit tests, the evaluated image policy for all four images, and the booted privacy test including the status-report subtest |
| Compute and desktop ISO builds | Completed; SHA-256 `eb443dd6…7ae8c758` (compute, 1.55 GB) and `2020d4da…ea4980d6` (desktop, 3.1 GB) |
| Actual ISO boots (`postern-verify.sh`) | Both passed offline under software emulation with 2 vCPUs and 2 GiB RAM: compute in 124 s, desktop (active Wayland session) in 152 s |
| Compute VM disk | Built (qcow2, 2.0 GB, SHA-256 `ca9aa00d…e8c9b00d`); one offline BIOS boot under software emulation reached the console and `postern-status` reported 11 ok, 1 warning, 0 failed. UEFI boot not tested |
| Desktop VM disk | Defined and evaluated; not built or booted |
| Recorded walkthroughs (`postern-demo.py`) | Completed for both ISOs under software emulation, played back at 3×; all recorded checks passed (5 compute, 11 desktop) |
| KVM, physical hardware, persistent installation and Bloch interoperability | Not validated |

The builder had no KVM and ran Nix inside a container with the Nix build sandbox
disabled; these are development builds, not reproducibility or release claims.
The one warning in `postern-status` is the emulated CPU reporting no
`spec_store_bypass` mitigation. Result files are kept in
[docs/evidence/postern-0.3.0-dev](docs/evidence/postern-0.3.0-dev).

### Earlier results, recorded for 0.2.0-dev

These predate the 0.3.0-dev changes and are not results for the current images.

| Check | Recorded result |
| --- | --- |
| Python integrity-tool tests | 16 passed on macOS/Python 3.9.6 and in the Nix Linux package after the directory-race fixes; Bash/Python syntax checks also passed |
| Measured parallel hashing after audit fixes | 512 MiB, three repetitions per variant: 1 worker 1.335 s; 2 workers 0.850 s; 4 workers 0.565 s; all nine manifests identical |
| Measured parallel hashing on Linux | Same 512 MiB workload under a four-CPU limit: 1 worker 1.551 s; 2 workers 0.934 s; 4 workers 0.579 s (2.68×); all nine manifests identical |
| Nix input lock | NixOS 26.05 pinned at `c56a87d8e41ce69bd2af57eb35dcc117a9dfca33`, with its verified NAR hash in `flake.lock` |
| Nix Linux package and evaluated image policy | Passed; package tests completed in 0.604 s on the Linux builder |
| Privacy VM tests | Passed, including real inbound filtering with a positive control, private permissions, discarded core dumps, AppArmor, a new boot ID, preserved disk data and cleared temporary storage |
| Compute and desktop ISO builds | Completed; final media boot verification is in progress |
| Actual ISO boots | In validation; no passing boot verdict recorded here yet |
| Physical hardware, persistent installation and Bloch interoperability | Not validated by this development step |

The measured 2.36× result with four workers applies to one synthetic hashing
workload on one Mac. It does not establish Linux, general OS or blockchain
performance. The [tool documentation and raw measurements](tools/parallel-data/README.md#measure-do-not-assume)
record the run order, effective workers and page-cache limitation. The earlier
measurement is preserved and labeled as evidence from before the audit fixes.
The [Linux measurements](docs/evidence/postern-0.2.0-dev/linux-benchmark.json)
used Python 3.13.17 and the same file-hashing workload under a four-CPU limit.
Their 2.68× ratio is a within-host comparison; page caches were not reset.

Run `bash scripts/postern-test-core.sh` from a checkout to check the Postern Bash
and Python syntax and execute the integrity-tool and status-report unit tests
with the installed Python 3. The wrapper downloads no dependencies and can be reused in CI; no
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

### VM disks and recorded walkthrough

```sh
# qcow2 development disks; never part of "all".
nix develop --no-update-lock-file --command bash scripts/postern-build.sh compute-vm
nix develop --no-update-lock-file --command bash scripts/postern-build.sh desktop-vm

# Scripted, captioned recording of a real ISO (new output directory each time).
nix develop --no-update-lock-file --command python3 scripts/postern-demo.py \
  "$POSTERN_BUILD_DIR/postern-desktop-x86_64.iso" --profile desktop \
  --output "$POSTERN_BUILD_DIR/walkthrough-desktop"
```

The recorder boots the ISO with **no network adapter**, opens applications
through the shell's search with keyboard events, types the commands shown, and
captures the display through QMP. It uses KVM when `/dev/kvm` is usable and
software emulation otherwise. The video shows the captured screen unmodified
inside a drawn frame; it is played back faster than recorded under emulation,
runs of identical frames (the guest is waiting) are shortened, and the boot of
the graphical images is left out. The opening card and `result.json` state all
of this. The serial console is used to detect readiness and to record checks
(for example, that an opened application is running); on the mobile image it
is also the fallback when the phone shell's search does not start an
application, and `result.json` records how each one was opened. The output
holds the MP4, an `.srt` caption file, raw stills, composed previews, the
serial log and `result.json`. A recording shows one scripted session in a
virtual machine; it is neither the boot verification above nor a hardware test.

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
permissions. Where NetworkManager manages the network it randomizes hardware
addresses and withholds the host name from DHCP. The graphical images apply
additional browser policies. CPU security mitigations remain enabled.

The [hardening module](os/profiles/hardening.nix) sets the kernel command line,
sysctl values and module restrictions listed under "What 0.4.0-dev adds". The
booted test in `os/tests/privacy.nix` checks them on a running system.

The [performance module](os/profiles/performance.nix) uses zstd zram for up to
half of memory, systemd-oomd, BBR with fair queueing, includes diagnostic tools
and limits nested OpenMP/BLAS thread defaults so parallel jobs do not multiply
their worker counts. These settings do not claim a universal speedup, and the
memory wiping in the hardening module costs some throughput. AppArmor confinement depends on loaded application profiles; normal
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
