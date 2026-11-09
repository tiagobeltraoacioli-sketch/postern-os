# Postern parallel data

An offline command-line tool for integrity inventories of regular files. It uses
only the Python standard library and does not transmit data, contact a service,
or copy file contents into its output.

```sh
postern-data scan /path/to/input --output /private/manifests/input.jsonl
postern-data verify /path/to/input /private/manifests/input.jsonl
postern-data scan /path/to/input --output /private/manifests/sequential.jsonl --workers 1
```

The output directory must exist **outside** the scanned root. Existing outputs
are refused unless `scan --force` is explicitly requested. Manifests and temporary
outputs are created with mode `0600` and published atomically. Standard output
contains aggregate counts and the effective worker count, not filenames or the
absolute root. The manifest itself contains relative filenames, sizes and hashes;
these are sensitive metadata, so protect it like the underlying files.

## Parallelism and limits

`--workers 0` (the default) chooses at most eight workers. An explicit value from
1 to 32 is clamped to detected CPU affinity, ancestor cgroup-v2 CPU quotas and
available memory. Fractional CPU quotas are rounded down, with a minimum of one
worker. Each worker reads in 4-MiB blocks by default; `--chunk-mib` accepts 1–64.
There are at most twice the worker count queued. Directory entries are sorted
deterministically; memory for traversal scales with directories on the active
walk stack, not the contents of files. The memory estimate is a scheduling guard,
not a hard memory sandbox; use the OS service limits for strict containment.

Sequential and parallel modes write byte-identical JSON Lines manifests. The
first line identifies `postern-data/v1`; subsequent lines describe files or
explicitly skipped entries. Paths are ordered by their components. Performance
depends on storage bandwidth, cache, CPU and file size: small datasets or slow
disks can make more processes slower.

## Integrity boundaries

- Symbolic links, including directory links, are recorded as excluded; their
  targets are never hashed. Special files such as FIFOs are also skipped.
- Every directory component is opened relative to an anchored directory
  descriptor with `O_NOFOLLOW`. File identity, size and timestamps are compared
  before and after reading; detected changes become errors, not trusted hashes.
- Verification rejects absolute/traversing paths, duplicate/unordered entries,
  invalid digests and incomplete manifests. It reports added, missing, modified
  and unreadable files separately.
- This is not a filesystem snapshot. Freeze the dataset or use a filesystem
  snapshot for a point-in-time guarantee while other processes may write.
- Keep the input root, output directory and their ancestors stable during a
  run, and use an output directory that other users cannot modify. Operations
  are anchored to directory descriptors and identity changes detected before
  publication abort the write. The tool cannot lock an entire directory tree
  against hostile concurrent renames; those require external isolation.
- A digest does not establish authorship. An attacker able to replace both data
  and manifest can replace both hashes. Keep the baseline separately protected;
  signing and encryption are separate controls.
- Excluded link targets and empty directories are not covered by integrity
  verification. Relative names and hashes in a manifest can reveal information
  even though the original contents are not stored there.

Exit codes: `0` means the scan completed without errors or verification matched;
`1` means scan errors or an integrity mismatch; `2` means invalid input or a fatal
operational error. A scan with exit code `1` retains explicit error records and
must not be treated as a complete trusted baseline.

## Measure, do not assume

```sh
postern-data-benchmark --files 32 --size-mib 16 --workers 1,2,4 \
  --repeats 3 --output /private/reports/data-benchmark.json
```

The benchmark generates temporary synthetic data, rotates run order and measures
whole CLI wall time, including process startup, traversal, hashing and output
fsync. Data generation is recorded separately. Every run must produce an identical
manifest, otherwise no performance result is accepted. Cache state is not reset;
the report explicitly retains slowdowns and identifies the host platform without
recording a hostname or absolute data paths. Temporary input is removed afterward.
The JSON report is mode `0600` and does not replace an existing report.

After the directory-race fixes, a local macOS/x86-64 run (Python 3.9.6,
32 files × 16 MiB, three repetitions, 512 MiB of equal input work per scan)
measured the following medians:

| Workers | Whole-command wall time | Relative to sequential |
| --- | --- | --- |
| 1 | 1.335 s | 1.00× |
| 2 | 0.850 s | 1.57× |
| 4 | 0.565 s | 2.36× |

All nine manifests were byte-identical. The raw observations, order, effective
worker counts and cache caveat are in
[`evidence/macos-2026-11-09.json`](evidence/macos-2026-11-09.json).
These are measurements of this file-hashing workload on one Mac, not Linux boot,
general OS, blockchain or hardware-attestation performance results.

The earlier [`evidence/macos-2026-11-08.json`](evidence/macos-2026-11-08.json)
is preserved unchanged as **pre-audit evidence**. It measured 1.350/0.868/0.585 s
for one/two/four workers. Different timings across these runs are not evidence
that the race fixes improve speed: cache and host load were not controlled.

The post-audit validation passed **16 unit tests** locally on macOS/Python 3.9.6,
including directory replacement and worker-initialization error cases. The
repository wrapper also passed Bash and Python syntax checks:

```sh
bash scripts/postern-test-core.sh
```

This local result does not establish a Linux package or ISO boot result.

To run from source:

```sh
python3 tools/parallel-data/postern_data.py scan INPUT --output OUTPUT.jsonl
python3 -m unittest discover -s tools/parallel-data/tests -v
python3 tools/parallel-data/benchmark.py --files 8 --size-mib 4 --repeats 2 \
  --output /tmp/postern-data-benchmark.json
```

The Nix derivation is `nix/parallel-data.nix`; it runs the correctness tests as
part of the package build. The tool requires Linux or a compatible POSIX host
with descriptor-relative opens and `O_NOFOLLOW`. No network daemon or automatic
background scan is installed.
