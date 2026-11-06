"""Signed inert carriers served over loopback; no executable is launched."""
import base64
import gzip
import hashlib
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import collector_server
from collector_updates import byte_range
import publish_collector_update as publisher
from update_security import canonical, REPOSITORY


class CollectorUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.key = Ed25519PrivateKey.generate()
        public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.trust = patch('update_trust.UPDATE_PUBLIC_KEY', base64.b64encode(public).decode())
        self.trust.start()
        self.data = self.root / 'collector'
        collector_server.initialize(self.data)
        self.config = json.loads((self.data / 'collector-server.json').read_text())
        self.updates = self.data / 'updates'
        self.server = collector_server.Collector(('127.0.0.1', 0), self.config)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)
        self.trust.stop()
        self.temporary.cleanup()

    def release(self, version='1.8.2', marker=b'inert release fixture'):
        source = self.root / ('source-' + uuid.uuid4().hex)
        source.mkdir()
        data = b'MZ' + marker + b'\0' * 2048
        (source / 'WormRecovery.exe').write_bytes(data)
        payload = {'schema': 1, 'repository': REPOSITORY, 'version': version,
                   'platform': 'windows-x64', 'asset': 'WormRecovery.exe',
                   'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
                   'published_at': '2026-11-06T00:00:00Z'}
        document = {'payload': payload, 'signature': base64.b64encode(self.key.sign(canonical(payload))).decode()}
        (source / 'update-manifest.json').write_text(json.dumps(document), encoding='utf-8')
        return source, data, document

    def request(self, path, method='GET', headers=None, body=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        try:
            connection.request(method, path, headers=headers or {}, body=body)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_complete_signed_release_and_resume_bytes(self):
        source, data, document = self.release()
        publisher.publish(source, self.updates)
        status, headers, body = self.request('/updates/stable/update-manifest.json')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), document)
        path = '/updates/releases/v1.8.2/WormRecovery.exe'
        status, headers, body = self.request(path, method='HEAD')
        self.assertEqual(status, 200)
        self.assertEqual(int(headers['Content-Length']), len(data))
        self.assertEqual(body, b'')
        for value, expected in [('bytes=0-1', data[:2]), ('bytes=100-', data[100:]), ('bytes=-10', data[-10:])]:
            status, headers, body = self.request(path, headers={'Range': value})
            self.assertEqual(status, 206)
            self.assertEqual(body, expected)
            self.assertEqual(int(headers['Content-Length']), len(expected))
        status, _, body = self.request(path)
        self.assertEqual(status, 200)
        self.assertEqual(body, data)

    def test_invalid_ranges_and_changed_if_range(self):
        source, data, _ = self.release()
        publisher.publish(source, self.updates)
        path = '/updates/releases/v1.8.2/WormRecovery.exe'
        for value in ('bytes=999999-', 'bytes=2-1', 'bytes=0-1,4-8', 'bytes=-0', 'bytes=--', 'bytes=' + '9' * 100 + '-'):
            status, headers, body = self.request(path, headers={'Range': value})
            self.assertEqual(status, 416)
            self.assertEqual(headers['Content-Range'], 'bytes */' + str(len(data)))
            self.assertEqual(body, b'')
        status, _, body = self.request(path, headers={'Range': 'bytes=2-', 'If-Range': 'old-digest'})
        self.assertEqual(status, 200)
        self.assertEqual(body, data)

    def test_unsigned_or_damaged_release_cannot_replace_stable(self):
        source, _, document = self.release()
        publisher.publish(source, self.updates)
        active = (self.updates / 'stable/update-manifest.json').read_bytes()
        bad_source, _, bad_document = self.release('1.8.3')
        bad_document['payload']['bytes'] += 1
        (bad_source / 'update-manifest.json').write_text(json.dumps(bad_document))
        with self.assertRaises(ValueError):
            publisher.publish(bad_source, self.updates)
        self.assertEqual((self.updates / 'stable/update-manifest.json').read_bytes(), active)
        bad_source, _, _ = self.release('1.8.3')
        (bad_source / 'WormRecovery.exe').write_bytes(b'MZ' + b'changed' * 400)
        with self.assertRaises(ValueError):
            publisher.publish(bad_source, self.updates)
        self.assertFalse((self.updates / 'releases/v1.8.3').exists())
        (self.updates / 'stable/update-manifest.json').write_text('{}')
        self.assertEqual(self.request('/updates/stable/update-manifest.json')[0], 503)

    def test_versioned_release_is_immutable_and_downgrade_refused(self):
        source, _, _ = self.release()
        publisher.publish(source, self.updates)
        publisher.publish(source, self.updates)
        conflict, _, _ = self.release(marker=b'different signed bytes')
        with self.assertRaisesRegex(ValueError, 'immutable'):
            publisher.publish(conflict, self.updates)
        older, _, _ = self.release('1.8.1')
        with self.assertRaisesRegex(ValueError, 'older'):
            publisher.publish(older, self.updates)
        status, _, body = self.request('/updates/stable/update-manifest.json')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['payload']['version'], '1.8.2')

    def test_tampered_asset_is_not_advertised_after_cached_request(self):
        source, data, _ = self.release()
        publisher.publish(source, self.updates)
        self.assertEqual(self.request('/updates/stable/update-manifest.json')[0], 200)
        asset = self.updates / 'releases/v1.8.2/WormRecovery.exe'
        changed = bytearray(data)
        changed[-1] = 1
        asset.write_bytes(changed)
        self.assertEqual(self.request('/updates/stable/update-manifest.json')[0], 503)
        self.assertEqual(self.request('/updates/releases/v1.8.2/WormRecovery.exe')[0], 503)

    def test_update_allowlist_does_not_expose_local_files_or_accept_publish(self):
        source, _, _ = self.release()
        publisher.publish(source, self.updates)
        for path in ('/updates/', '/updates/../collector-server.json', '/updates/%2e%2e/collector-server.json',
                     '/updates/stable/update-manifest.json?token=x', '/updates/releases/v1.8.2/update-manifest.json',
                     '/updates/releases/v01.8.2/WormRecovery.exe', '/updates/releases/v1.8.2/WormRecovery.exe/extra'):
            self.assertEqual(self.request(path)[0], 404, path)
        self.assertEqual(self.request('/updates/stable/update-manifest.json', method='POST', body=b'{}')[0], 404)
        self.assertEqual(self.request('/v1/status')[0], 401)

    def test_download_slots_leave_health_and_diagnostic_upload_available(self):
        source, _, _ = self.release()
        publisher.publish(source, self.updates)
        for _ in range(2):
            self.server.updates.download_slots.acquire()
        try:
            self.assertEqual(self.request('/updates/releases/v1.8.2/WormRecovery.exe')[0], 503)
            self.assertEqual(self.request('/updates/stable/update-manifest.json')[0], 200)
            self.assertEqual(self.request('/updates/releases/v1.8.2/WormRecovery.exe', method='HEAD')[0], 200)
            self.assertEqual(self.request('/health')[0], 200)
            record = {'schema': 1, 'bundle_id': str(uuid.uuid4()), 'device_id': str(uuid.uuid4()),
                      'report': {'findings': []}, 'journal': []}
            wire = gzip.compress(json.dumps(record).encode())
            status, _, body = self.request('/v1/diagnostics', method='POST', body=wire,
                                          headers={'X-Content-SHA256': hashlib.sha256(wire).hexdigest()})
            self.assertEqual(status, 201)
            self.assertEqual(json.loads(body)['receipt'], record['bundle_id'])
            self.assertEqual(len(list(Path(self.config['directory']).glob('*.json'))), 1)
        finally:
            for _ in range(2):
                self.server.updates.download_slots.release()

    def test_incomplete_copy_never_promotes_stable(self):
        source, _, _ = self.release('1.8.1')
        publisher.publish(source, self.updates)
        before = (self.updates / 'stable/update-manifest.json').read_bytes()
        new_source, _, _ = self.release()
        with patch.object(publisher.shutil, 'copyfileobj', side_effect=OSError('inert disk failure')):
            with self.assertRaises(OSError):
                publisher.publish(new_source, self.updates)
        self.assertEqual((self.updates / 'stable/update-manifest.json').read_bytes(), before)
        self.assertFalse((self.updates / 'releases/v1.8.2').exists())
        self.assertFalse((self.updates / '.publish.lock').exists())


class ByteRangeTests(unittest.TestCase):
    def test_bounded_suffix_and_long_end(self):
        self.assertEqual(byte_range('bytes=-100', 10), (0, 9))
        self.assertEqual(byte_range('bytes=2-99999', 10), (2, 9))


if __name__ == '__main__':
    unittest.main()
