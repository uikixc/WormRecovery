"""Publish an already signed local release; never accepts remote writes."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import shutil
import uuid

from collector_updates import checked_path, read_manifest
from update_security import verify_file, version_tuple


def atomic_write(path, data):
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex + '.partial')
    try:
        with temporary.open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def publication_lock(root):
    lock = root / '.publish.lock'
    # Exclusive creation serializes local publishers. An interrupted publisher
    # leaves an explicit lock to inspect instead of silently racing another.
    with lock.open('xb') as stream:
        stream.write(str(os.getpid()).encode('ascii'))
    try:
        yield
    finally:
        lock.unlink(missing_ok=True)


def publish(source, destination):
    source = Path(source).resolve()
    root = Path(destination).resolve()
    raw, document, payload = read_manifest(source / 'update-manifest.json')
    executable = source / 'WormRecovery.exe'
    verify_file(executable, payload)
    root.mkdir(parents=True, exist_ok=True)
    releases = root / 'releases'
    stable = root / 'stable'
    releases.mkdir(exist_ok=True)
    stable.mkdir(exist_ok=True)
    checked_path(root, 'releases')
    checked_path(root, 'stable')
    version = payload['version']
    target = releases / ('v' + version)
    with publication_lock(root):
        active = stable / 'update-manifest.json'
        if active.exists():
            checked_path(root, 'stable', 'update-manifest.json')
            _, _, previous = read_manifest(active)
            if version_tuple(version) < version_tuple(previous['version']):
                raise ValueError('Publishing an older stable version is refused.')
        if target.exists():
            current = checked_path(root, 'releases', 'v' + version, 'update-manifest.json')
            _, existing, _ = read_manifest(current)
            if existing != document:
                raise ValueError('An immutable release version already has different contents.')
            verify_file(checked_path(root, 'releases', 'v' + version, 'WormRecovery.exe'), payload)
        else:
            temporary = releases / ('.v' + version + '.' + uuid.uuid4().hex + '.partial')
            temporary.mkdir()
            try:
                with executable.open('rb') as incoming, (temporary / 'WormRecovery.exe').open('xb') as outgoing:
                    shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
                    outgoing.flush()
                    os.fsync(outgoing.fileno())
                verify_file(temporary / 'WormRecovery.exe', payload)
                atomic_write(temporary / 'update-manifest.json', raw)
                os.rename(temporary, target)
            finally:
                if temporary.exists():
                    # Only this freshly created staging directory is removed.
                    for name in ('WormRecovery.exe', 'update-manifest.json'):
                        (temporary / name).unlink(missing_ok=True)
                    temporary.rmdir()
        # Readers never see a manifest before the complete immutable release.
        atomic_write(active, raw)
    return {'version': version, 'bytes': payload['bytes'], 'sha256': payload['sha256'],
            'directory': str(target), 'manifest': str(active)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--destination', required=True)
    args = parser.parse_args()
    print(json.dumps(publish(args.source, args.destination)))
