"""Inert containers only; no real executable payload is shipped in tests."""
import hashlib
import io
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import zlib

import family_analysis as family
import png_tail_analysis as tail
import worm_recovery as recovery
from test_family_analysis import inert_pe


def dll(body=b'INERT fixture data, never executable'):
    data=bytearray(inert_pe(body))
    struct.pack_into('<H',data,150,0x2000)
    return bytes(data)


def chunk(kind,body):
    return struct.pack('>I',len(body))+kind+body+struct.pack('>I',zlib.crc32(kind+body)&0xffffffff)


def carrier(payload,seed=69,metadata=b'INERT metadata'):
    png=tail.PNG_MAGIC+chunk(b'IHDR',struct.pack('>IIBBBBB',1,1,8,2,0,0,0))
    png+=chunk(b'tEXt',metadata)+chunk(b'IEND',b'')
    start=(len(png)+15)//16*16
    return png+bytes(start-len(png))+tail._xor(payload,seed)+struct.pack('<IB',start,seed)


class PngTailTests(unittest.TestCase):
    def setUp(self):
        self.payload=dll()
        self.digest=hashlib.sha256(self.payload).hexdigest()
        self.spec={'bytes':len(self.payload),'confirmed':True,'signature':'WR_INERT_Test',
                   'family':'INERT-Test','basis':'inert_test_fingerprint'}
        p=patch.object(tail,'KNOWN_PAYLOADS',{self.digest:self.spec});p.start();self.addCleanup(p.stop)

    def test_decoded_identity_ignores_png_metadata_and_encoding_seed(self):
        for seed in (0,69,166,255):
            for metadata in (b'first image',b'other metadata of a different length'):
                result=family.inspect(carrier(self.payload,seed,metadata))
                self.assertEqual(result['status'],'detected')
                self.assertEqual(result['detections'][0]['sha256'],self.digest)
                self.assertFalse(result['target_execution']);self.assertFalse(result['name_used_for_verdict'])

    def test_renamed_carrier_reaches_primary_detector_without_process_execution(self):
        data=carrier(self.payload)
        with tempfile.TemporaryDirectory() as directory,patch('subprocess.Popen',side_effect=AssertionError('execution forbidden')):
            for name in ('thumbs.db','renamed.odd','document.pdf','image.png','normal.exe'):
                path=Path(directory)/name;path.write_bytes(data)
                result=recovery.inspect_file_content(path,path.stat())
                self.assertEqual(result['findings'][0]['kind'],'malware_component')
                self.assertEqual(path.read_bytes(),data)

    def test_payload_over_old_four_mib_limit_is_inspected(self):
        payload=dll(b'INERT'+bytes(4*1024*1024))
        spec={**self.spec,'bytes':len(payload)}
        with patch.object(tail,'KNOWN_PAYLOADS',{hashlib.sha256(payload).hexdigest():spec}),tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'large.cache';path.write_bytes(carrier(payload))
            result=recovery.inspect_file_content(path,path.stat())
            self.assertEqual(result['findings'][0]['kind'],'malware_component')

    def test_changed_decoded_content_stays_review_instead_of_confirmation(self):
        payload=self.payload[:-1]+b'!'
        result=family.inspect(carrier(payload))
        self.assertEqual(result['status'],'incomplete');self.assertFalse(result['detections'])
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'unknown.bin';path.write_bytes(carrier(payload))
            rows=recovery.inspect_file_content(path,path.stat())['findings']
            self.assertEqual(rows[0]['kind'],'review_binary');self.assertFalse(recovery.is_confirmed(rows[0]))

    def test_known_packed_companion_is_identified_without_cleanup_authority(self):
        with patch.object(tail,'KNOWN_PAYLOADS',{self.digest:{**self.spec,'confirmed':False}}):
            result=family.inspect(carrier(self.payload))
            self.assertEqual(result['status'],'identified');self.assertFalse(result['detections'])
            self.assertNotIn('TSCO',result['reason'])
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'renamed.cache';path.write_bytes(carrier(self.payload))
                row=recovery.inspect_file_content(path,path.stat())['findings'][0]
                self.assertEqual(row['kind'],'review_binary');self.assertFalse(recovery.is_confirmed(row))

    def test_direct_decoded_dll_has_same_identity(self):
        self.assertEqual(family.inspect(self.payload)['status'],'detected')

    def test_parent_image_does_not_inherit_child_identity(self):
        for parent in (inert_pe(b'INERT host')+self.payload,inert_pe(b'INERT host'+self.payload)):
            result=family.inspect(parent)
            self.assertFalse(result['detections']);self.assertFalse(result.get('identifications'))

    def test_ordinary_png_names_and_generic_api_strings_are_not_hits(self):
        ordinary=tail.PNG_MAGIC+chunk(b'IHDR',struct.pack('>IIBBBBB',1,1,8,2,0,0,0))+chunk(b'IEND',b'')
        for data in (ordinary,ordinary+bytes(1024),b'thumbs.db image.png XPSPLOG.dll fHy4DF',
                     dll(b'VirtualAllocEx WriteProcessMemory CreateRemoteThread ClearEventLogA')):
            self.assertEqual(family.inspect(data)['status'],'no_known_match')

    def test_same_named_inert_file_is_not_malware(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ('image.png','thumbs.db','XPSPLOG.dll'):
                path=Path(directory)/name;path.write_bytes(dll(b'INERT normal content'))
                self.assertEqual(recovery.inspect_file_content(path,path.stat())['findings'],[])

    def test_probe_is_bounded_and_restores_position(self):
        class Counting(io.BytesIO):
            read_bytes=0
            def read(self,n=-1):
                self.assert_bounded(n)
                data=super().read(n);self.read_bytes+=len(data);return data
            @staticmethod
            def assert_bounded(n):
                if not 0<=n<=64:raise AssertionError('unbounded preview read')
        stream=Counting(carrier(self.payload));stream.seek(128)
        self.assertTrue(tail.probe(stream,len(stream.getbuffer())))
        self.assertEqual(stream.tell(),128);self.assertLessEqual(stream.read_bytes,81)

    def test_invalid_trailer_and_truncation_never_confirm(self):
        data=carrier(self.payload)
        variants=(data[:-1],data[:-5]+struct.pack('<IB',0xffffffff,69),
                  data[:-5]+struct.pack('<IB',33,69),data[:-5]+struct.pack('<IB',32,0))
        for value in variants:
            result=family.inspect(value)
            self.assertFalse(result['detections']);self.assertFalse(result.get('identifications'))

    def test_invalid_png_chunk_bounds_are_review_only(self):
        data=bytearray(carrier(self.payload));struct.pack_into('>I',data,8,0x7fffffff)
        result=family.inspect(bytes(data))
        self.assertEqual(result['status'],'incomplete');self.assertFalse(result['detections'])

    def test_truncated_pe_is_review_only(self):
        result=family.inspect(carrier(self.payload[:-10]))
        self.assertEqual(result['status'],'incomplete');self.assertFalse(result['detections'])

    def test_carrier_over_budget_is_not_read_in_full(self):
        data=carrier(self.payload)
        with patch.object(tail,'MAX_PNG_CARRIER',len(data)-1):
            self.assertEqual(family.inspect(data)['status'],'incomplete')
        with patch.object(family,'MAX_PNG_CARRIER',len(data)-1),tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'oversize.cache';path.write_bytes(data)
            with patch.object(family,'inspect',side_effect=AssertionError('full read forbidden')):
                rows=recovery.inspect_file_content(path,path.stat())['findings']
            self.assertEqual(rows[0]['kind'],'review_binary')

    def test_exact_loader_identity_tolerates_only_four_trailer_bytes(self):
        data=dll(b'INERT observed loader'+bytes(16))
        with patch.object(tail,'LOADER_BYTES',len(data)),patch.object(tail,'LOADER_PREFIX_SHA256',hashlib.sha256(data[:-4]).hexdigest()):
            for trailer in (b'ABCD',b'WXYZ'):
                self.assertEqual(family.inspect(data[:-4]+trailer)['status'],'identified')
            changed=bytearray(data);changed[-5]^=1
            self.assertEqual(family.inspect(bytes(changed))['status'],'no_known_match')


if __name__=='__main__':unittest.main()
