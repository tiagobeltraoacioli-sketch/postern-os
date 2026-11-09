#!/usr/bin/env python3
"""Measure equal-work sequential/parallel inventories; retain slow results too."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import statistics
import subprocess
import sys
import tempfile
import time

import postern_data as data


def publish_report(path, record):
    target = Path(path).expanduser()
    parent = target.parent.resolve(strict=True)
    target = parent/target.name
    fd, temp = tempfile.mkstemp(prefix='.postern-benchmark-',suffix='.tmp',dir=parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            json.dump(record, output, sort_keys=True, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.link(temp, target)
    finally:
        os.unlink(temp)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--files', type=int, default=32)
    parser.add_argument('--size-mib', type=int, default=8, help='size of each synthetic file')
    parser.add_argument('--workers', default='1,2,4', help='comma-separated requested worker counts; must include 1')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--output', required=True, help='new mode-0600 JSON report')
    parser.add_argument('--workspace', help='optional existing directory for temporary synthetic data')
    args = parser.parse_args(argv)
    try:
        counts = sorted(set(int(item) for item in args.workers.split(',')))
        if not counts or counts[0] != 1 or counts[-1] > data.MAX_WORKERS:
            raise ValueError('workers must include 1 and be between 1 and 32')
        if not (1 <= args.files <= 4096 and 1 <= args.size_mib <= 1024 and 1 <= args.repeats <= 20):
            raise ValueError('benchmark size or repeat count outside allowed range')
        if args.files * args.size_mib > 16384:
            raise ValueError('synthetic data is limited to 16 GiB per run')
        if os.path.lexists(args.output):
            raise ValueError('the report already exists')
        runs = []
        baseline_hash = None
        start = time.perf_counter()
        with tempfile.TemporaryDirectory(prefix='postern-benchmark-',dir=args.workspace) as temporary:
            temporary = Path(temporary)
            root = temporary/'input'
            root.mkdir()
            for index in range(args.files):
                block = random.Random(index).randbytes(1024*1024)
                with (root/('file-%05d.bin' % index)).open('wb') as stream:
                    for _ in range(args.size_mib):
                        stream.write(block)
            setup_seconds = time.perf_counter()-start
            for repeat in range(args.repeats):
                # Rotate the order to expose, rather than hide, order/cache effects.
                offset = repeat % len(counts)
                for count in counts[offset:]+counts[:offset]:
                    output = temporary/('run-%d-%d.jsonl' % (repeat,count))
                    started = time.perf_counter()
                    process = subprocess.run([sys.executable,str(Path(data.__file__).resolve()),
                        'scan',str(root),'--output',str(output),'--workers',str(count)],
                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    elapsed = time.perf_counter()-started
                    if process.returncode != 0:
                        raise RuntimeError('benchmark scan failed; no performance result accepted')
                    result = json.loads(process.stdout)
                    manifest_hash = hashlib.sha256(output.read_bytes()).hexdigest()
                    if baseline_hash is None:
                        baseline_hash = manifest_hash
                    if baseline_hash != manifest_hash:
                        raise RuntimeError('non-equivalent manifests; no performance result accepted')
                    runs.append({'repeat':repeat+1,'requested_workers':count,'effective_workers':result['workers'],
                                 'wall_seconds':elapsed,'files':result['files'],'bytes':result['bytes'],
                                 'manifest_sha256':manifest_hash})
        medians = {count:statistics.median(r['wall_seconds'] for r in runs if r['requested_workers']==count) for count in counts}
        record = {
            'format':'postern-data-benchmark/v1','platform':sys.platform,'architecture':platform.machine(),
            'python':platform.python_version(),'effective_cpu_limit':data.resource_limits()[0],
            'files':args.files,'bytes_per_file':args.size_mib*1024**2,'repeats':args.repeats,
            'setup_seconds_excluded':setup_seconds,'cache_state':'OS page cache was not reset; successive scans can be cached.',
            'timing_includes':['CLI startup','worker startup','traversal','reads','SHA-256','manifest encoding','manifest fsync'],
            'input':'Deterministic synthetic bytes; one seeded 1-MiB block repeated per file.',
            'equivalent_manifests':True,'runs':runs,
            'comparison':[{'requested_workers':count,'median_seconds':medians[count],
                           'speedup_vs_sequential':medians[1]/medians[count]} for count in counts],
            'interpretation':'Host-, dataset- and cache-specific observations. Ratios below 1 are slowdowns. No consensus or cryptographic acceleration is implied.',
        }
        publish_report(args.output, record)
        print(json.dumps({'ok':True,'equivalent_manifests':True,'comparison':record['comparison']},sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        # The report and stdout omit machine names and absolute source paths.
        message = str(error) if isinstance(error,(ValueError,RuntimeError)) else type(error).__name__
        print(json.dumps({'ok':False,'error':message}),file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
