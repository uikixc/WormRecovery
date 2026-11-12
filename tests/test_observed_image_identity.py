"""Metadata tolerance and code ownership using inert, non-runnable fixtures."""
import hashlib
import io
from pathlib import Path
import random
import struct
import tempfile
import unittest
from unittest.mock import patch

import deployment_review
import family_analysis as family
import png_tail_analysis as tail
import worm_recovery as recovery
from test_png_tail_analysis import carrier, dll
from test_family_analysis import inert_pe


class NormalizedImageTests(unittest.TestCase):
    def setUp(self):
        self.data = dll(b'INERT mapped content, never loaded' + bytes(1024))
        normalized = bytearray(self.data)
        offset = struct.unpack_from('<I', normalized, 60)[0]
        normalized[offset + 8:offset + 12] = bytes(4)
        normalized[offset + 88:offset + 92] = bytes(4)
        self.digest = hashlib.sha256(normalized).hexdigest()
        self.spec = {'mapped_bytes': len(self.data), 'confirmed': True,
                     'reference_sha256': hashlib.sha256(self.data).hexdigest(),
                     'signature': 'WR_INERT_Normalized', 'family': 'INERT'}
        patches = [patch.object(tail, 'NORMALIZED_IMAGES', {self.digest: self.spec}),
                   patch.object(tail, 'KNOWN_PAYLOADS', {})]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def changed_metadata(self):
        data = bytearray(self.data)
        struct.pack_into('<I', data, 136, 123456789)
        struct.pack_into('<I', data, 216, 987654321)
        return bytes(data)

    def test_timestamp_checksum_and_overlay_tolerated_with_explicit_scope(self):
        for suffix in (b'', b'INERT appended data'):
            result = family.inspect(self.changed_metadata() + suffix)
            self.assertEqual(result['status'], 'detected')
            hit = result['detections'][0]
            self.assertEqual(hit['normalized_sha256'], self.digest)
            self.assertEqual(hit['excluded_overlay_bytes'], len(suffix))
            self.assertEqual(hit['normalized_fields'], ['coff_timestamp', 'optional_header_checksum'])
            self.assertFalse(result['target_execution'])

    def test_mapped_code_data_entry_and_directory_changes_cannot_inherit_identity(self):
        for offset in (168, 248, 412, 520, len(self.data) - 1):
            changed = bytearray(self.data)
            changed[offset] ^= 1
            with self.subTest(offset=offset):
                result = family.inspect(bytes(changed))
                self.assertFalse(result['detections'])
                self.assertFalse(result.get('identifications'))

    def test_x64_or_exe_is_not_a_normalized_dll_match(self):
        for offset in (132, 150):
            changed = bytearray(self.data)
            struct.pack_into('<H', changed, offset, 0x8664 if offset == 132 else 0)
            self.assertFalse(family.inspect(bytes(changed))['detections'])

    def test_png_metadata_seed_and_renamed_carrier_use_normalized_identity(self):
        with tempfile.TemporaryDirectory() as directory, patch('subprocess.Popen', side_effect=AssertionError('no execution')):
            path = Path(directory) / 'unrelated.pdf'
            path.write_bytes(carrier(self.changed_metadata(), seed=203))
            original = path.read_bytes()
            result = recovery.inspect_file_content(path, path.stat())
            self.assertEqual(result['findings'][0]['kind'], 'malware_component')
            self.assertEqual(path.read_bytes(), original)

    def test_packed_companion_remains_review_only(self):
        with patch.object(tail, 'NORMALIZED_IMAGES', {self.digest: {**self.spec, 'confirmed': False}}):
            result = family.inspect(self.changed_metadata())
            self.assertEqual(result['status'], 'identified')
            self.assertFalse(result['detections'])

    def test_parent_with_nested_matching_dll_does_not_inherit_identity(self):
        for data in (inert_pe(b'INERT host') + self.data, inert_pe(b'INERT resource' + self.data)):
            result = family.inspect(data)
            self.assertFalse(result['detections'])
            self.assertFalse(result.get('identifications'))

    def test_memoryview_input_releases_temporary_view(self):
        data = bytearray(self.changed_metadata())
        pe = family.PE(data)
        self.assertIsNotNone(tail.normalized_image(data, pe))
        data.extend(b'INERT still resizable')


class LoaderCombinationTests(unittest.TestCase):
    def setUp(self):
        # Four fragments in a synthetic section; this is not a runnable image.
        self.anchors = ((4096, b'INERT ENTRY'), (4128, b'INERT A'),
                        (4160, b'INERT B'), (4192, b'INERT C'))
        body = bytearray(256)
        for rva, fragment in self.anchors:
            body[rva - 4096:rva - 4096 + len(fragment)] = fragment
        self.data = dll(bytes(body))
        patches = [patch.object(tail, 'LOADER_ENTRY_RVA', 4096),
                   patch.object(tail, 'LOADER_CODE_ANCHORS', self.anchors),
                   patch.object(tail, 'NORMALIZED_IMAGES', {}),
                   patch.object(tail, 'KNOWN_PAYLOADS', {})]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def test_all_four_active_code_fragments_identify_only_for_review(self):
        changed = bytearray(self.data)
        changed[-1] = 42
        result = family.inspect(bytes(changed))
        self.assertEqual(result['status'], 'identified')
        self.assertFalse(result['detections'])
        hit = result['identifications'][0]
        self.assertEqual(hit['signature'], 'WR_PNG_Tail_Loader_Code_Combination')
        self.assertEqual(len(hit['pattern_hits']), 4)
        self.assertFalse(hit['automatic_cleanup'])
        self.assertFalse(hit['consumer_chain_proven'])

    def test_missing_anchor_moved_entry_or_nonexecutable_section_rejects(self):
        for offset in (512, 544, 576, 608, 168, 415):
            changed = bytearray(self.data)
            changed[offset] ^= 0x20 if offset == 415 else 1
            result = family.inspect(bytes(changed))
            self.assertFalse(result['detections'])
            self.assertFalse(result.get('identifications'))

    def test_nested_code_does_not_identify_parent(self):
        self.assertEqual(family.inspect(inert_pe(b'INERT wrapper' + self.data))['status'], 'no_known_match')

    def test_combination_never_enters_exact_deployment_approval_group(self):
        analysis = family.inspect(self.data)
        findings = [{'path': 'C:/inert/loader.dll', 'sha256': analysis['source_sha256'], 'family_analysis': analysis}]
        findings.append({'path': 'C:/inert/image.png', 'sha256': 'a' * 64, 'family_analysis': {
            'identifications': [{'signature': 'WR_PNG_Tail_Packed_Companion'}],
            'decodings': [{'method': 'png_iend_incrementing_xor'}]}})
        self.assertEqual(deployment_review.correlate(findings, []), [])


class XorLaneTests(unittest.TestCase):
    def test_fast_path_matches_literal_algorithm_across_period_and_index(self):
        randomizer = random.Random(1812)
        for size in (0, 81, 1023, 1024, 1025, 4097, 65539):
            data = randomizer.randbytes(size)
            for seed, index in ((0, 0), (69, 0), (166, 60), (255, 511)):
                expected = bytes(value ^ ((seed + index + n) & 255) for n, value in enumerate(data))
                self.assertEqual(tail._xor(data, seed, index), expected)


if __name__ == '__main__':
    unittest.main()
