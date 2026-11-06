"""Read-only signed release delivery alongside the diagnostic receiver."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import threading

from update_security import verify_manifest, version_tuple

MAX_MANIFEST = 256 * 1024
STABLE_PATH = '/updates/stable/update-manifest.json'
RELEASE_PATH = re.compile(r'/updates/releases/v((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))/WormRecovery\.exe')


def read_manifest(path):
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_MANIFEST + 1)
    if len(data) > MAX_MANIFEST:
        raise ValueError('Release manifest exceeds its size limit.')
    document = json.loads(data.decode('utf-8-sig'))
    payload = verify_manifest(document)
    if payload['version'] != '.'.join(map(str, version_tuple(payload['version']))):
        raise ValueError('Release version must use its canonical form.')
    return data, document, payload


def file_identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def checked_path(root, *parts):
    """Reject links and traversal even for an otherwise signed release path."""
    path = root
    for part in parts:
        path = path / part
        info = path.lstat()
        if path.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Release paths cannot contain reparse points.')
    path.resolve().relative_to(root)
    return path


class UpdateStore:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.lock = threading.Lock()
        self.download_slots = threading.BoundedSemaphore(2)
        self.verified = {}

    @contextmanager
    def resource(self, request_path):
        # This exact allowlist is the whole public file surface. There is no
        # upload/publish endpoint, arbitrary path mapping or directory listing.
        match = RELEASE_PATH.fullmatch(request_path)
        if request_path != STABLE_PATH and not match:
            raise FileNotFoundError('Unknown update resource.')
        stream = None
        try:
            with self.lock:
                if request_path == STABLE_PATH:
                    active_path = checked_path(self.directory, 'stable', 'update-manifest.json')
                    raw, active, payload = read_manifest(active_path)
                    version = payload['version']
                else:
                    version = match.group(1)
                    active = None
                release_manifest = checked_path(self.directory, 'releases', 'v' + version, 'update-manifest.json')
                release_raw, document, payload = read_manifest(release_manifest)
                if payload['version'] != version or (active is not None and document != active):
                    raise ValueError('Stable and versioned release metadata disagree.')
                asset = checked_path(self.directory, 'releases', 'v' + version, 'WormRecovery.exe')
                stream = asset.open('rb')
                before = file_identity(os.fstat(stream.fileno()))
                key = (version, payload['sha256'])
                if before[2] != payload['bytes']:
                    raise ValueError('Release asset size does not match its signature.')
                # This cache saves a large rehash per request. It is not a trust
                # boundary: every client verifies the signed full-file digest.
                if self.verified.get(key) != before:
                    if stream.read(2) != b'MZ':
                        raise ValueError('Release asset is not a PE carrier.')
                    stream.seek(0)
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                    if digest != payload['sha256'] or file_identity(os.fstat(stream.fileno())) != before:
                        raise ValueError('Release asset digest changed or is invalid.')
                    if len(self.verified) >= 32:
                        self.verified.clear()
                    self.verified[key] = before
                stream.seek(0)
                if active is not None:
                    stream.close()
                    stream = None
                    resource = {'data': raw, 'stream': None, 'bytes': len(raw),
                                'sha256': hashlib.sha256(raw).hexdigest(), 'content_type': 'application/json'}
                else:
                    resource = {'data': None, 'stream': stream, 'bytes': payload['bytes'],
                                'sha256': payload['sha256'], 'content_type': 'application/octet-stream'}
            yield resource
        finally:
            if stream is not None:
                stream.close()


def byte_range(value, size):
    """Parse one RFC byte range, including suffix and open-ended forms."""
    match = re.fullmatch(r'bytes=([0-9]*)-([0-9]*)', value)
    if not match or not any(match.groups()):
        raise ValueError('Invalid byte range.')
    left, right = match.groups()
    # Limit decimal input before converting attacker-controlled large integers.
    if len(left) > 20 or len(right) > 20:
        raise ValueError('Invalid byte range.')
    if not left:
        suffix = int(right)
        if suffix <= 0:
            raise ValueError('Invalid byte range.')
        return max(0, size - suffix), size - 1
    start = int(left)
    end = min(int(right), size - 1) if right else size - 1
    if start >= size or start > end:
        raise ValueError('Unsatisfiable byte range.')
    return start, end


def serve_update(handler):
    """Handle only /updates requests; leave the receiver's API untouched."""
    if not handler.path.startswith('/updates/'):
        return False
    store = handler.server.updates
    download = handler.command == 'GET' and RELEASE_PATH.fullmatch(handler.path) is not None
    if download and not store.download_slots.acquire(blocking=False):
        handler.respond(503, {'error': 'update_download_busy'})
        return True
    headers_sent = False
    try:
        with store.resource(handler.path) as resource:
            size = resource['bytes']
            etag = '"' + resource['sha256'] + '"'
            selected = handler.headers.get('Range')
            if handler.headers.get('If-Range') not in (None, etag):
                selected = None
            try:
                start, end = byte_range(selected, size) if selected else (0, size - 1)
            except ValueError:
                handler.send_response(416)
                handler.send_header('Content-Range', 'bytes */' + str(size))
                handler.send_header('Content-Length', '0')
                handler.end_headers()
                return True
            handler.send_response(206 if selected else 200)
            handler.send_header('Content-Type', resource['content_type'])
            handler.send_header('Content-Length', str(end - start + 1))
            handler.send_header('Accept-Ranges', 'bytes')
            handler.send_header('ETag', etag)
            handler.send_header('Cache-Control', 'no-store' if resource['data'] is not None else 'public, max-age=31536000, immutable')
            if selected:
                handler.send_header('Content-Range', f'bytes {start}-{end}/{size}')
            handler.end_headers()
            headers_sent = True
            if handler.command == 'HEAD':
                return True
            if resource['data'] is not None:
                handler.wfile.write(resource['data'][start:end + 1])
            else:
                resource['stream'].seek(start)
                remaining = end - start + 1
                while remaining:
                    chunk = resource['stream'].read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise OSError('Release file was truncated during delivery.')
                    handler.wfile.write(chunk)
                    remaining -= len(chunk)
    except FileNotFoundError:
        if not headers_sent:
            handler.respond(404, {'error': 'update_not_published'})
    except (OSError, ValueError, TypeError, KeyError):
        if not headers_sent:
            handler.respond(503, {'error': 'update_unavailable'})
        else:
            handler.close_connection = True
    finally:
        if download:
            store.download_slots.release()
    return True
