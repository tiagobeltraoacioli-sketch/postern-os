import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import postern_data as data


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'private-root'
        self.root.mkdir()

    def records(self, workers=1):
        root, fd = data.open_root(self.root)
        try:
            return list(data.scan_records(root, fd, workers, 1024))
        finally:
            os.close(fd)

    def write(self, name, content=b'content'):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def test_sequential_parallel_and_jsonl_are_identical(self):
        self.write('a/child', b'abc')
        self.write('a.txt', b'')
        self.write('z/data', bytes(range(256)) * 500)
        self.write('área/秘密', b'non-public-file-content')
        (self.root / 'outside-link').symlink_to(self.base / 'not-readable-by-scan')
        sequential = self.records(1)
        parallel = self.records(2)
        self.assertEqual(sequential, parallel)
        a, b = self.base / 'one.jsonl', self.base / 'two.jsonl'
        summary = data.write_manifest(a, self.root, iter(sequential))
        data.write_manifest(b, self.root, iter(parallel))
        self.assertEqual(a.read_bytes(), b.read_bytes())
        self.assertEqual(list(data.manifest_records(a)), sequential)
        self.assertEqual(summary, {'files':4, 'bytes':128026, 'skipped':1, 'errors':0})
        self.assertEqual(sequential[0]['sha256'], hashlib.sha256(b'abc').hexdigest())
        self.assertNotIn(str(self.root), a.read_text())
        self.assertNotIn('non-public-file-content', a.read_text())

    def test_output_is_private_outside_root_and_no_clobber(self):
        self.write('one')
        output = self.base / 'manifest.jsonl'
        data.write_manifest(output, self.root, iter(self.records()))
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        original = output.read_bytes()
        with self.assertRaises(ValueError):
            data.write_manifest(output, self.root, iter([]))
        self.assertEqual(output.read_bytes(), original)
        with self.assertRaises(ValueError):
            data.write_manifest(self.root/'manifest.jsonl', self.root, iter([]))
        self.assertFalse((self.root/'manifest.jsonl').exists())
        data.write_manifest(output, self.root, iter([]), force=True)
        self.assertEqual(output.read_text(), data.encode(data.HEADER))
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(list(self.base.glob('.postern-data-*.tmp')), [])

    def test_output_symlink_cannot_write_into_root(self):
        target = self.write('protected', b'leave-intact')
        output = self.base/'out.jsonl'
        output.symlink_to(target)
        with self.assertRaises(ValueError):
            data.write_manifest(output, self.root, iter([]), force=True)
        self.assertEqual(target.read_bytes(), b'leave-intact')

    def test_failed_scan_does_not_publish_partial_output(self):
        def failing_records():
            yield {'path':'one', 'kind':'file', 'status':'ok', 'size':0, 'sha256':'0'*64}
            raise RuntimeError('interrupted')
        output = self.base/'out.jsonl'
        with self.assertRaises(RuntimeError):
            data.write_manifest(output, self.root, failing_records())
        self.assertFalse(output.exists())
        self.assertEqual(list(self.base.glob('.postern-data-*.tmp')), [])

    def test_links_and_fifo_are_not_opened(self):
        outside = self.base/'outside-secret'
        outside.write_bytes(b'never-follow-this')
        (self.root/'file-link').symlink_to(outside)
        (self.root/'dir-link').symlink_to(self.base)
        os.mkfifo(self.root/'fifo')
        records = self.records()
        self.assertEqual([r['status'] for r in records], ['skipped']*3)
        self.assertEqual([r['kind'] for r in records], ['symlink','special','symlink'])
        link_root = self.base/'root-link'
        link_root.symlink_to(self.root)
        with self.assertRaises(ValueError):
            data.open_root(link_root)

    def test_directory_swap_cannot_escape_root(self):
        self.write('inner/data', b'expected')
        outside = self.base/'outside'
        outside.mkdir()
        (outside/'data').write_bytes(b'secret-outside')
        root, fd = data.open_root(self.root)
        try:
            job = list(data.discover(fd))[0]
            (self.root/'inner').rename(self.root/'moved')
            (self.root/'inner').symlink_to(outside)
            result = data.hash_file(job, 1024, fd)
            self.assertEqual(result['status'], 'error')
            self.assertEqual(result['code'], 'path_changed')
            self.assertNotIn('sha256', result)
        finally:
            os.close(fd)

    def test_root_replaced_by_symlink_during_resolution_is_rejected(self):
        self.write('inside', b'expected')
        outside = self.base/'outside'
        outside.mkdir()
        (outside/'private-outside-file').write_bytes(b'never-hash-this')
        real_resolve = Path.resolve
        swapped = False
        def swap_then_resolve(path, *args, **kwargs):
            nonlocal swapped
            if path == self.root and not swapped:
                swapped = True
                self.root.rename(self.base/'original-root')
                self.root.symlink_to(outside, target_is_directory=True)
            return real_resolve(path, *args, **kwargs)
        with mock.patch.object(Path, 'resolve', swap_then_resolve):
            with self.assertRaisesRegex(ValueError, 'root_changed'):
                data.open_root(self.root)

    def test_output_directory_moved_into_root_is_not_published(self):
        output_dir = self.base/'output'
        output_dir.mkdir()
        relocated = self.root/'moved-output'
        def moving_records():
            output_dir.rename(relocated)
            output_dir.symlink_to(relocated, target_is_directory=True)
            yield {'path':'one', 'kind':'file', 'status':'ok', 'size':0, 'sha256':'0'*64}
        with self.assertRaisesRegex(ValueError, 'output_directory_changed'):
            data.write_manifest(output_dir/'manifest.jsonl', self.root, moving_records())
        self.assertFalse((relocated/'manifest.jsonl').exists())
        self.assertEqual(list(relocated.glob('.postern-data-*.tmp')), [])

    def test_output_directory_replacement_does_not_touch_decoy(self):
        output_dir = self.base/'output'
        output_dir.mkdir()
        original_dir = self.base/'original-output'
        decoys = []
        def replacing_records():
            temporary_name = next(output_dir.glob('.postern-data-*.tmp')).name
            output_dir.rename(original_dir)
            output_dir.mkdir()
            decoy = output_dir/temporary_name
            decoy.write_bytes(b'leave-this-unrelated-file-alone')
            decoys.append(decoy)
            yield {'path':'one', 'kind':'file', 'status':'ok', 'size':0, 'sha256':'0'*64}
        with self.assertRaisesRegex(ValueError, 'output_directory_changed'):
            data.write_manifest(output_dir/'manifest.jsonl', self.root, replacing_records(), force=True)
        self.assertFalse((output_dir/'manifest.jsonl').exists())
        self.assertFalse((original_dir/'manifest.jsonl').exists())
        self.assertEqual(decoys[0].read_bytes(), b'leave-this-unrelated-file-alone')
        self.assertEqual(list(original_dir.glob('.postern-data-*.tmp')), [])

    def test_root_replacement_does_not_replace_existing_manifest(self):
        output = self.base/'manifest.jsonl'
        output.write_bytes(b'keep-previous-baseline')
        def replacing_records():
            self.root.rename(self.base/'original-root')
            self.root.mkdir()
            yield {'path':'one', 'kind':'file', 'status':'ok', 'size':0, 'sha256':'0'*64}
        with self.assertRaisesRegex(ValueError, 'root_changed'):
            data.write_manifest(output, self.root, replacing_records(), force=True)
        self.assertEqual(output.read_bytes(), b'keep-previous-baseline')
        self.assertEqual(list(self.base.glob('.postern-data-*.tmp')), [])

    def test_worker_initialization_failure_does_not_log_private_paths(self):
        self.write('private-file', b'private-content')
        # Move the root only when the generator is consumed: the CLI has
        # already opened its root and output anchors before worker startup.
        script = '''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import postern_data as data
original_scan = data.scan_records
def moving_scan(root, root_fd, workers, chunk):
    root.rename(root.with_name('moved-private-root'))
    yield from original_scan(root, root_fd, workers, chunk)
data.scan_records = moving_scan
data.choose_workers = lambda requested, chunk: 2
raise SystemExit(data.main(['scan', sys.argv[2], '--output', sys.argv[3], '--workers', '2']))
'''
        output = self.base/'manifest.jsonl'
        process = subprocess.run([sys.executable, '-c', script,
                                  str(Path(data.__file__).parent), str(self.root), str(output)],
                                 capture_output=True, text=True)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(json.loads(process.stderr), {'ok':False, 'error':'root_changed'})
        for private in (str(self.base), 'private-root', 'private-file', 'private-content', 'Traceback'):
            self.assertNotIn(private, process.stdout+process.stderr)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.base.glob('.postern-data-*.tmp')), [])

    def test_file_change_while_hashing_is_reported(self):
        path = self.write('changing', b'a'*4096)
        root, fd = data.open_root(self.root)
        real_read = os.read
        changed = False
        def change_after_read(file_fd, size):
            nonlocal changed
            block = real_read(file_fd, size)
            if not changed:
                changed = True
                with path.open('ab') as out:
                    out.write(b'changed')
            return block
        try:
            job = list(data.discover(fd))[0]
            with mock.patch.object(data.os, 'read', side_effect=change_after_read):
                result = data.hash_file(job, 1024, fd)
            self.assertEqual(result['code'], 'changed_during_scan')
        finally:
            os.close(fd)

    def test_verify_detects_added_removed_and_modified(self):
        self.write('keep', b'a')
        self.write('change', b'b')
        self.write('remove', b'c')
        expected = self.records()
        self.write('change', b'd')
        (self.root/'remove').unlink()
        self.write('add', b'e')
        result = data.verify_records(iter(expected), iter(self.records()))
        self.assertEqual(result, {'verified':1,'changed':1,'missing':1,'added':1,'errors':0,'skipped':0})

    def test_manifest_rejects_escapes_duplicates_and_bad_digests(self):
        valid = {'path':'ok','kind':'file','status':'ok','size':1,'sha256':'0'*64}
        cases = [[{**valid,'path':'../private'}], [{**valid,'path':'/etc/passwd'}],
                 [{**valid,'path':'a//b'}], [valid,valid],
                 [{**valid,'sha256':'NOT-A-DIGEST'}],
                 [{'path':'bad','kind':'file','status':'error','code':'io_error'}]]
        for entries in cases:
            with self.subTest(entries=entries):
                manifest = self.base/'bad.jsonl'
                manifest.write_text(data.encode(data.HEADER)+''.join(data.encode(r) for r in entries))
                with self.assertRaises(data.ManifestError):
                    list(data.manifest_records(manifest))

    def test_cli_does_not_log_root_paths_or_content(self):
        self.write('private-name', b'private-content-for-qa')
        output = self.base/'manifest.jsonl'
        process = subprocess.run([sys.executable, data.__file__, 'scan', str(self.root),
                                  '--output',str(output),'--workers','1'], capture_output=True,text=True)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertTrue(json.loads(process.stdout)['ok'])
        self.assertNotIn(str(self.root), process.stdout+process.stderr)
        self.assertNotIn('private-name', process.stdout+process.stderr)
        self.assertNotIn('private-content-for-qa', process.stdout+process.stderr)
        process = subprocess.run([sys.executable,data.__file__,'verify',str(self.root),str(output),
                                  '--workers','1'],capture_output=True,text=True)
        self.assertEqual(process.returncode, 0, process.stderr)
        (self.root/'private-name').write_bytes(b'changed')
        process = subprocess.run([sys.executable,data.__file__,'verify',str(self.root),str(output),
                                  '--workers','1'],capture_output=True,text=True)
        self.assertEqual(process.returncode, 1)
        self.assertEqual(json.loads(process.stdout)['changed'], 1)
        process = subprocess.run([sys.executable,data.__file__,'scan',str(self.root/'secret-absent'),
                                  '--output',str(output)],capture_output=True,text=True)
        self.assertEqual(process.returncode, 2)
        self.assertNotIn('secret-absent', process.stderr)

    def test_ancestor_cgroup_limits_are_respected(self):
        proc, cgroup = self.base/'proc', self.base/'cgroup'
        (proc/'self').mkdir(parents=True)
        (cgroup/'parent/child').mkdir(parents=True)
        (proc/'self/cgroup').write_text('0::/parent/child\n')
        (proc/'meminfo').write_text('MemAvailable: 4000000 kB\n')
        (cgroup/'cpu.max').write_text('max 100000')
        (cgroup/'parent/cpu.max').write_text('150000 100000')
        (cgroup/'parent/child/cpu.max').write_text('400000 100000')
        (cgroup/'parent/memory.max').write_text(str(512*1024**2))
        (cgroup/'parent/memory.current').write_text(str(128*1024**2))
        with mock.patch.object(data.os, 'cpu_count', return_value=8):
            cpus, memory = data.resource_limits(cgroup, proc)
        self.assertEqual(cpus, 1)
        self.assertEqual(memory, 384*1024**2)
        with mock.patch.object(data, 'resource_limits', return_value=(16,384*1024**2)):
            self.assertEqual(data.choose_workers(0,4*1024**2), 2)
            self.assertEqual(data.choose_workers(32,4*1024**2), 2)
        with mock.patch.object(data, 'resource_limits', return_value=(64,None)):
            self.assertEqual(data.choose_workers(0,4*1024**2), 8)
            self.assertEqual(data.choose_workers(32,4*1024**2), 32)
        with self.assertRaises(ValueError):
            data.choose_workers(33,4*1024**2)
        with mock.patch.object(data, 'resource_limits', return_value=(2,32*1024**2)):
            with self.assertRaises(ValueError):
                data.choose_workers(0,4*1024**2)


if __name__ == '__main__':
    unittest.main()
