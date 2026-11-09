#!/usr/bin/env python3
"""Offline, deterministic file-integrity manifests with bounded parallel work."""
import argparse
from collections import deque
from concurrent.futures import ProcessPoolExecutor
import errno
import hashlib
import json
import multiprocessing
import os
from pathlib import Path, PurePosixPath
import secrets
import stat
import sys

HEADER = {"format": "postern-data/v1", "digest": "sha256", "symlinks": "excluded"}
MAX_WORKERS = 32
AUTO_WORKERS = 8
MAX_LINE = 1024 * 1024
WORKER_ROOT = None
WORKER_ERROR = None


class ManifestError(ValueError):
    pass


def _read_text(path):
    try:
        return Path(path).read_text().strip()
    except (OSError, UnicodeError):
        return None


def resource_limits(cgroup_root=Path('/sys/fs/cgroup'), proc_root=Path('/proc')):
    """Conservatively honor affinity, ancestor cgroup-v2 quotas and memory."""
    cpus = os.cpu_count() or 1
    if hasattr(os, 'sched_getaffinity'):
        try:
            cpus = min(cpus, len(os.sched_getaffinity(0)))
        except OSError:
            pass
    memory = None
    meminfo = _read_text(proc_root / 'meminfo') or ''
    for line in meminfo.splitlines():
        if line.startswith('MemAvailable:'):
            try:
                memory = int(line.split()[1]) * 1024
            except (ValueError, IndexError):
                pass
    # In a cgroup namespace the process path may not exist relative to this
    # mount. Its mounted root still provides a useful upper bound.
    paths = {cgroup_root}
    for line in (_read_text(proc_root / 'self/cgroup') or '').splitlines():
        if line.startswith('0::'):
            relative = PurePosixPath(line[3:].lstrip('/'))
            if '..' not in relative.parts:
                current = cgroup_root.joinpath(*relative.parts)
                if current.is_dir():
                    while True:
                        paths.add(current)
                        if current == cgroup_root:
                            break
                        current = current.parent
    for directory in paths:
        quota = (_read_text(directory / 'cpu.max') or '').split()
        if len(quota) == 2 and quota[0] != 'max':
            try:
                cpus = min(cpus, max(1, int(quota[0]) // int(quota[1])))
            except (ValueError, ZeroDivisionError):
                pass
        limit = _read_text(directory / 'memory.max')
        used = _read_text(directory / 'memory.current')
        if limit and limit != 'max':
            try:
                remaining = max(0, int(limit) - int(used or 0))
                memory = remaining if memory is None else min(memory, remaining)
            except ValueError:
                pass
    return max(1, cpus), memory


def choose_workers(requested, chunk_bytes):
    if not 0 <= requested <= MAX_WORKERS:
        raise ValueError('workers must be between 0 and 32')
    cpus, memory = resource_limits()
    # This is a conservative scheduling estimate, not a hard memory sandbox.
    per_worker = 128 * 1024**2 + 2 * chunk_bytes
    if memory is not None and memory < per_worker:
        raise ValueError('insufficient available memory for a bounded worker')
    memory_cap = MAX_WORKERS if memory is None else memory // per_worker
    cap = min(MAX_WORKERS, cpus, memory_cap)
    return max(1, min(requested or AUTO_WORKERS, cap))


def _flags(directory=False):
    if not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'O_DIRECTORY'):
        raise ValueError('this tool requires Linux or a compatible POSIX host')
    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0) | (os.O_DIRECTORY if directory else os.O_NONBLOCK)


def open_root(value):
    supplied = Path(value).expanduser()
    try:
        # Open the supplied final component before resolving its display path.
        # A separate is_symlink()/resolve()/open() sequence can follow a link
        # substituted between the check and the open.
        fd = os.open(supplied, _flags(directory=True))
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            raise ValueError('the root must be a directory, not a symbolic link') from None
        raise
    try:
        root = _directory_path(supplied, fd, 'root_changed')
        return root, fd
    except BaseException:
        os.close(fd)
        raise


def _identity(info):
    return info.st_dev, info.st_ino


def _directory_path(path, fd, code):
    """Check a pathname against its anchor; do not use it for later writes."""
    try:
        resolved = Path(path).resolve(strict=True)
        probe = os.open(path, _flags(directory=True))
        try:
            identity = _identity(os.fstat(fd))
            if (_identity(os.fstat(probe)) != identity or
                    _identity(os.stat(resolved, follow_symlinks=False)) != identity):
                raise ValueError(code)
        finally:
            os.close(probe)
    except (OSError, RuntimeError):
        raise ValueError(code) from None
    return resolved


def _init_worker(root, identity):
    global WORKER_ROOT, WORKER_ERROR
    WORKER_ROOT, WORKER_ERROR = None, None
    fd = None
    try:
        fd = os.open(root, _flags(directory=True))
        if _identity(os.fstat(fd)) != tuple(identity):
            WORKER_ERROR = 'root_changed'
        else:
            WORKER_ROOT, fd = fd, None
    except OSError as error:
        # ProcessPoolExecutor prints initializer exceptions (including paths)
        # directly to stderr. Return sanitized job failures instead.
        WORKER_ERROR = _error_code(error)
    finally:
        if fd is not None:
            os.close(fd)


def _failure(path, kind, code):
    return {"path": path, "kind": kind, "status": "error", "code": code}


def _error_code(error):
    if error.errno in (errno.EACCES, errno.EPERM):
        return 'access_denied'
    if error.errno in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP):
        return 'path_changed'
    return 'io_error'


def discover(directory_fd, prefix=''):
    """Deterministic component-wise order; memory scales with one directory."""
    try:
        with os.scandir(directory_fd) as entries:
            names = sorted(entry.name for entry in entries)
    except OSError as error:
        yield _failure(prefix or '.', 'directory', _error_code(error))
        return
    for name in names:
        relative = prefix + '/' + name if prefix else name
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                yield {"path": relative, "kind": "symlink", "status": "skipped"}
            elif stat.S_ISDIR(info.st_mode):
                child = os.open(name, _flags(directory=True), dir_fd=directory_fd)
                try:
                    if _identity(os.fstat(child)) != _identity(info):
                        yield _failure(relative, 'directory', 'path_changed')
                    else:
                        yield from discover(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                yield (relative, (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))
            else:
                yield {"path": relative, "kind": "special", "status": "skipped"}
        except OSError as error:
            yield _failure(relative, 'entry', _error_code(error))


def _open_file(root_fd, relative):
    parts = PurePosixPath(relative).parts
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, _flags(directory=True), dir_fd=current)
            os.close(current)
            current = child
        return os.open(parts[-1], _flags(), dir_fd=current)
    finally:
        os.close(current)


def hash_file(job, chunk_bytes, root_fd=None):
    relative, expected = job
    if root_fd is None and WORKER_ROOT is None:
        return _failure(relative, 'file', WORKER_ERROR or 'root_unavailable')
    fd = None
    try:
        fd = _open_file(WORKER_ROOT if root_fd is None else root_fd, relative)
        before = os.fstat(fd)
        signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if not stat.S_ISREG(before.st_mode) or signature(before) != tuple(expected):
            return _failure(relative, 'file', 'changed_during_scan')
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(fd, chunk_bytes)
            if not block:
                break
            digest.update(block)
            total += len(block)
        if signature(os.fstat(fd)) != signature(before) or total != before.st_size:
            return _failure(relative, 'file', 'changed_during_scan')
        return {"path": relative, "kind": "file", "status": "ok", "size": total, "sha256": digest.hexdigest()}
    except OSError as error:
        return _failure(relative, 'file', _error_code(error))
    finally:
        if fd is not None:
            os.close(fd)


def scan_records(root, root_fd, workers, chunk_bytes):
    jobs = discover(root_fd)
    if workers == 1:
        for job in jobs:
            yield job if isinstance(job, dict) else hash_file(job, chunk_bytes, root_fd)
        return
    context = multiprocessing.get_context('spawn')
    with ProcessPoolExecutor(max_workers=workers, mp_context=context,
                             initializer=_init_worker,
                             initargs=(str(root), _identity(os.fstat(root_fd)))) as pool:
        pending = deque()
        for job in jobs:
            pending.append(job if isinstance(job, dict) else pool.submit(hash_file, job, chunk_bytes))
            if len(pending) >= 2 * workers:
                first = pending.popleft()
                yield first if isinstance(first, dict) else first.result()
        while pending:
            first = pending.popleft()
            yield first if isinstance(first, dict) else first.result()


def encode(record):
    return json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(',', ':')) + '\n'


def _inside(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def write_manifest(destination, root, records, force=False, root_fd=None):
    owned_root_fd = None
    parent_fd = None
    fd = None
    temporary = None
    output = Path(destination).expanduser()
    summary = {"files": 0, "bytes": 0, "skipped": 0, "errors": 0}
    try:
        if root_fd is None:
            root, owned_root_fd = open_root(root)
            root_fd = owned_root_fd
        root = _directory_path(root, root_fd, 'root_changed')
        parent = output.parent.resolve(strict=True)
        parent_fd = os.open(parent, _flags(directory=True))
        parent = _directory_path(parent, parent_fd, 'output_directory_changed')
        output = parent / output.name
        if _inside(output.resolve(strict=False), root):
            raise ValueError('the manifest must be outside the scanned root')
        try:
            os.stat(output.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if not force:
                raise ValueError('the output already exists; use --force to replace it')
        # Use directory-relative operations throughout. Resolving a parent once
        # does not prevent a later rename/symlink substitution of that path.
        while fd is None:
            candidate = '.postern-data-' + secrets.token_hex(16) + '.tmp'
            try:
                fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0),
                             0o600, dir_fd=parent_fd)
                temporary = candidate
            except FileExistsError:
                continue
        with os.fdopen(fd, 'w', encoding='ascii', newline='\n') as stream:
            fd = None
            stream.write(encode(HEADER))
            for record in records:
                stream.write(encode(record))
                if record['status'] == 'ok':
                    summary['files'] += 1
                    summary['bytes'] += record['size']
                elif record['status'] == 'skipped':
                    summary['skipped'] += 1
                else:
                    summary['errors'] += 1
            stream.flush()
            os.fsync(stream.fileno())
        # Fail before publication if a caller moved either directory during
        # traversal. This is not a filesystem snapshot: ancestors must remain
        # stable, and hostile concurrent renames cannot be locked by this API.
        root = _directory_path(root, root_fd, 'root_changed')
        current_parent = _directory_path(parent, parent_fd, 'output_directory_changed')
        if _inside(current_parent / output.name, root):
            raise ValueError('the manifest must be outside the scanned root')
        if force:
            os.replace(temporary, output.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        else:
            # Atomic no-clobber publication even if another process creates
            # the destination after the existence check above.
            os.link(temporary, output.name, src_dir_fd=parent_fd,
                    dst_dir_fd=parent_fd, follow_symlinks=False)
            os.unlink(temporary, dir_fd=parent_fd)
        temporary = None
        os.fsync(parent_fd)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
        finally:
            if parent_fd is not None:
                os.close(parent_fd)
            if owned_root_fd is not None:
                os.close(owned_root_fd)
    return summary


def manifest_records(filename):
    fd = os.open(filename, _flags())
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ManifestError('manifest_not_regular')
    with os.fdopen(fd, 'r', encoding='ascii') as stream:
        header = stream.readline(MAX_LINE + 1)
        if len(header) > MAX_LINE or json.loads(header) != HEADER:
            raise ManifestError('invalid_manifest_header')
        previous = None
        while True:
            line = stream.readline(MAX_LINE + 1)
            if not line:
                break
            if len(line) > MAX_LINE:
                raise ManifestError('manifest_line_too_long')
            record = json.loads(line)
            path = record.get('path') if isinstance(record, dict) else None
            if not isinstance(path, str) or not path or '\x00' in path:
                raise ManifestError('invalid_manifest_path')
            parsed = PurePosixPath(path)
            if parsed.is_absolute() or '..' in parsed.parts or str(parsed) != path or path == '.':
                raise ManifestError('invalid_manifest_path')
            key = parsed.parts
            if previous is not None and key <= previous:
                raise ManifestError('manifest_paths_not_unique_and_ordered')
            previous = key
            if record.get('kind') == 'file' and record.get('status') == 'ok':
                size = record.get('size')
                digest = record.get('sha256')
                if (set(record) != {'path','kind','status','size','sha256'} or
                    not isinstance(size, int) or isinstance(size, bool) or size < 0 or
                    not isinstance(digest, str) or len(digest) != 64 or
                    any(c not in '0123456789abcdef' for c in digest)):
                    raise ManifestError('invalid_manifest_file')
            elif record.get('kind') in ('symlink','special') and record.get('status') == 'skipped':
                if set(record) != {'path','kind','status'}:
                    raise ManifestError('invalid_manifest_skipped_entry')
            else:
                raise ManifestError('manifest_contains_errors_or_unknown_entries')
            yield record


def verify_records(expected, actual):
    summary = {"verified": 0, "changed": 0, "missing": 0, "added": 0, "errors": 0, "skipped": 0}
    a, b = next(expected, None), next(actual, None)
    while a is not None or b is not None:
        if b is None or (a is not None and PurePosixPath(a['path']).parts < PurePosixPath(b['path']).parts):
            summary['missing'] += 1
            a = next(expected, None)
        elif a is None or PurePosixPath(b['path']).parts < PurePosixPath(a['path']).parts:
            summary['added'] += 1
            if b['status'] == 'error':
                summary['errors'] += 1
            b = next(actual, None)
        else:
            if b['status'] == 'error':
                summary['errors'] += 1
            elif a != b:
                summary['changed'] += 1
            elif b['status'] == 'ok':
                summary['verified'] += 1
            else:
                summary['skipped'] += 1
            a, b = next(expected, None), next(actual, None)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for command in ('scan', 'verify'):
        child = commands.add_parser(command)
        child.add_argument('root', help='directory whose regular files are checked')
        child.add_argument('--workers', type=int, default=0, help='0=automatic, 1=sequential, up to 32; clamped to resource limits')
        child.add_argument('--chunk-mib', type=int, default=4, help='read buffer per worker, 1 to 64 MiB')
        if command == 'scan':
            child.add_argument('--output', required=True, help='private JSONL manifest outside the scanned root')
            child.add_argument('--force', action='store_true', help='replace an existing manifest atomically')
        else:
            child.add_argument('manifest', help='previous JSONL manifest')
    args = parser.parse_args(argv)
    root_fd = None
    records = None
    try:
        if not 1 <= args.chunk_mib <= 64:
            raise ValueError('chunk-mib must be between 1 and 64')
        chunk = args.chunk_mib * 1024**2
        workers = choose_workers(args.workers, chunk)
        root, root_fd = open_root(args.root)
        records = scan_records(root, root_fd, workers, chunk)
        if args.command == 'scan':
            summary = write_manifest(args.output, root, records, args.force, root_fd=root_fd)
            success = summary['errors'] == 0
        else:
            if _inside(Path(args.manifest).expanduser().resolve(strict=True), root):
                raise ValueError('the manifest must be outside the scanned root')
            summary = verify_records(manifest_records(args.manifest), records)
            success = not any(summary[key] for key in ('changed','missing','added','errors'))
        print(json.dumps({"command": args.command, "ok": success, "workers": workers, **summary}, sort_keys=True))
        return 0 if success else 1
    except (ValueError, OSError, RuntimeError) as error:
        # No traceback, absolute filename or file contents in terminal logs.
        code = str(error) if isinstance(error, (ValueError, ManifestError)) else type(error).__name__
        if isinstance(error, json.JSONDecodeError):
            code = 'invalid_manifest_json'
        print(json.dumps({"ok": False, "error": code}), file=sys.stderr)
        return 2
    finally:
        if records is not None:
            records.close()
        if root_fd is not None:
            os.close(root_fd)


if __name__ == '__main__':
    raise SystemExit(main())
