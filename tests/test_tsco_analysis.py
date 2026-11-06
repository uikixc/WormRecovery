"""Inert TSCO-shaped containers, no real payloads or specimen execution."""
import copy
import hashlib
import lzma
import mmap
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import family_analysis as family
import tsco_analysis as tsco
import worm_recovery as recovery
from test_family_analysis import inert_pe


def fixture():
    children=[];blobs=[];encoded=bytearray()
    for index,machine in enumerate((0x8664,0x14c,0x8664,0x14c)):
        child=bytearray(inert_pe(b'INERT child identity '+bytes([index])*100,machine))
        struct.pack_into('<H',child,150,0x2000)
        child=bytes(child);children.append(child)
        plain=b'inert-prefix'+child;wire=bytes((x+1)&255 for x in plain)
        blobs.append({'source_data_offset':len(encoded),'length':len(wire),
                      'encoded_slice_sha256':tsco.digest(wire),'decoded_slice_sha256':tsco.digest(plain),
                      'inner_pe_offset':12,'inner_pe_length':len(child),
                      'inner_pe_sha256':tsco.digest(child),'machine':machine})
        encoded.extend(wire)
    props={'rva':0x1080,'hex':'5d00000001','dict_size':16777216,'lc':3,'lp':0,'pb':2}
    filters=[{'id':lzma.FILTER_LZMA1,**{k:props[k] for k in ('dict_size','lc','lp','pb')}}]
    outputs=[b'INERT text'*10,b'INERT constants'*10,bytes(encoded),b'INERT resource'*10]
    body=bytearray(8192);anchor=b'INERT ENTRY, NOT EXECUTABLE';descriptor=b'INERT FOUR STREAM TABLE'
    body[:len(anchor)]=anchor;body[64:64+len(descriptor)]=descriptor
    body[128:133]=bytes.fromhex(props['hex']);cursor=256;streams=[]
    for index,output in enumerate(outputs):
        wire=lzma.compress(output,format=lzma.FORMAT_RAW,filters=filters)
        streams.append({'source_rva':0x1000+cursor,'compressed_bytes':len(wire),
                        'compressed_sha256':tsco.digest(wire),'dest_rva':0x1000*(index+1),
                        'decoded_bytes':len(output),'decoded_sha256':tsco.digest(output)})
        body[cursor:cursor+len(wire)]=wire;cursor+=len(wire)+16
    data=inert_pe(bytes(body))
    features={'sample_bytes':len(data),'entry_anchor':{'rva':0x1000,'length':len(anchor),'hex':anchor.hex()},
              'descriptor':{'rva':0x1040,'length':len(descriptor),'hex':descriptor.hex()},
              'props':props,'streams':streams,'blobs':blobs}
    return data,features,sum(map(len,outputs)),children


class TscoContentTests(unittest.TestCase):
    def setUp(self):
        self.data,self.features,self.budget,self.children=fixture()
        for name,value in (('FEATURES',self.features),('MAX_OUTPUT',self.budget)):
            p=patch.object(tsco,name,value);p.start();self.addCleanup(p.stop)

    def test_four_eos_streams_and_children_identify_current_root(self):
        result=family.inspect(self.data)
        self.assertEqual(result['status'],'identified')
        root=result['identifications'][0]
        self.assertEqual(len(root['streams']),4);self.assertEqual(len(root['children']),4)
        self.assertEqual(result['detections'],[])
        self.assertFalse(result['target_execution']);self.assertFalse(result['name_used_for_verdict'])

    def test_renamed_unknown_extension_reaches_content_engine_without_cleanup_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in ('renamed.odd','document.pdf','program.exe'):
                path=Path(directory)/name;path.write_bytes(self.data)
                rows=recovery.inspect_file_content(path,path.stat())['findings']
                self.assertEqual(len(rows),1);self.assertEqual(rows[0]['kind'],'review_binary')
                self.assertEqual(rows[0]['assessment'],'known_payload_content')
                self.assertFalse(recovery.is_confirmed(rows[0]))

    def test_unrelated_pe_metadata_change_does_not_break_content_identity(self):
        changed=bytearray(self.data);struct.pack_into('<I',changed,136,12345678)
        self.assertEqual(family.inspect(bytes(changed))['status'],'identified')

    def test_entry_fragment_at_wrong_entry_is_not_root_identity(self):
        changed=bytearray(self.data);struct.pack_into('<I',changed,168,0x1200)
        self.assertFalse(family.inspect(bytes(changed)).get('identifications'))

    def test_entry_in_zero_raw_or_ambiguous_rva_cannot_identify(self):
        changed=bytearray(self.data);struct.pack_into('<I',changed,152+224+16,0)
        self.assertFalse(family.inspect(bytes(changed)).get('identifications'))

    def test_descriptor_props_and_compressed_changes_fail_closed(self):
        for rva in (0x1040,0x1080,self.features['streams'][0]['source_rva']):
            changed=bytearray(self.data);changed[512+rva-0x1000]^=1
            result=family.inspect(bytes(changed))
            self.assertEqual(result['status'],'incomplete');self.assertFalse(result['identifications'])

    def test_truncated_stream_with_matching_compressed_hash_still_requires_eos(self):
        spec=self.features['streams'][0];spec['compressed_bytes']-=1
        start=512+spec['source_rva']-0x1000
        spec['compressed_sha256']=tsco.digest(self.data[start:start+spec['compressed_bytes']])
        result=family.inspect(self.data)
        self.assertEqual(result['status'],'incomplete');self.assertFalse(result['identifications'])

    def test_trailing_stream_bytes_are_not_accepted(self):
        spec=self.features['streams'][0];spec['compressed_bytes']+=1
        start=512+spec['source_rva']-0x1000
        spec['compressed_sha256']=tsco.digest(self.data[start:start+spec['compressed_bytes']])
        self.assertEqual(family.inspect(self.data)['status'],'incomplete')

    def test_output_limit_and_child_hash_mismatch_are_not_identified(self):
        with patch.object(tsco,'MAX_OUTPUT',self.budget-1):
            self.assertEqual(family.inspect(self.data)['status'],'incomplete')
        self.features['blobs'][0]['inner_pe_sha256']='0'*64
        self.assertEqual(family.inspect(self.data)['status'],'incomplete')

    def test_complete_child_requires_machine_and_dll_identity(self):
        for child in self.children:
            self.assertEqual(family.inspect(child)['status'],'identified')
            changed=bytearray(child);struct.pack_into('<H',changed,150,0)
            self.assertFalse(family.inspect(bytes(changed)).get('identifications'))

    def test_enclosing_pe_never_inherits_root_identity(self):
        carrier=inert_pe(b'INERT legitimate parent'+self.data)
        result=family.inspect(carrier)
        self.assertFalse(result['identifications']);self.assertEqual(result['detections'],[])
        self.assertEqual(len(result['contained_payloads']),1)
        self.assertEqual(result['contained_payloads'][0]['scope'],'contained_pe_only')

    def test_independent_malicious_code_evidence_keeps_detection_priority(self):
        hit={'signature':'WR_independent_code','family':'test','basis':'inert_mock'}
        with patch.object(family,'_hits',return_value=[hit]):
            result=family.inspect(self.data)
        self.assertEqual(result['status'],'detected')
        self.assertEqual(result['detections'],[hit])
        self.assertEqual(len(result['identifications']),1)

    def test_generic_crypto_protector_api_strings_are_not_identity(self):
        data=inert_pe(b'AutoIt UPX LZMA ChaCha20 wxspy.dll StartWorker StopWorker VirtualAlloc wcprobe.dll')
        self.assertEqual(family.inspect(data)['status'],'no_known_match')

    def test_read_only_mapping_releases_nested_views_for_all_outcomes(self):
        changed=bytearray(self.data)
        changed[512+self.features['descriptor']['rva']-0x1000]^=1
        for payload in (self.data,bytes(changed)):
            for data in (payload,inert_pe(b'INERT parent'+payload)):
                with tempfile.TemporaryDirectory() as directory:
                    path=Path(directory)/'inert.bin';path.write_bytes(data)
                    with path.open('rb') as stream:
                        with mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as mapped:
                            result=family.inspect_mapped_pe(mapped,{'matches':[]})
                    self.assertNotEqual(result.get('error_type'),'BufferError')
                    path.unlink()

    def test_large_root_and_contained_payload_reach_review_without_mapping_leaks(self):
        for data,scope in ((self.data,'root'),(inert_pe(b'INERT parent'+self.data),'contained')):
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'large-renamed.odd'
                with path.open('wb') as stream:
                    stream.write(data);stream.seek(family.MAX_INPUT+512);stream.write(b'\0')
                rows=recovery.inspect_file_content(path,path.stat())['findings']
                self.assertEqual(len(rows),1);row=rows[0]
                self.assertEqual(row['kind'],'review_binary');self.assertFalse(recovery.is_confirmed(row))
                analysis=row['family_analysis']
                self.assertEqual(analysis['status'],'identified')
                self.assertEqual(analysis['coverage']['source_identity'],'stable')
                self.assertEqual(len(analysis['identifications']),int(scope=='root'))
                self.assertEqual(len(analysis['contained_payloads']),int(scope=='contained'))
                path.unlink()

    def test_large_source_change_invalidates_content_identity(self):
        import large_pe_analysis as large
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'inert.bin';path.write_bytes(self.data)
            verify=large.verify_identity;calls=[]
            def change_after_analysis(*args,**kwargs):
                calls.append(True)
                if len(calls)==3:raise large.SourceChanged('inert test change')
                return verify(*args,**kwargs)
            with patch.object(large,'verify_identity',side_effect=change_after_analysis):
                result=family.inspect_large_file(path)
            self.assertEqual(result['status'],'incomplete')
            self.assertEqual(result['coverage']['source_identity'],'changed')
            self.assertNotIn('source_sha256',result)
            self.assertFalse(result.get('identifications'))
            self.assertFalse(result.get('contained_payloads'))

    def test_child_in_parent_is_contained_and_candidate_limit_is_explicit(self):
        carrier=inert_pe(b'INERT parent'+self.children[0])
        result=family.inspect(carrier)
        self.assertEqual(result['identifications'],[])
        self.assertEqual(len(result['contained_payloads']),1)
        limited=inert_pe(b'MZ'*33+self.data)
        result=family.inspect(limited)
        self.assertEqual(result['status'],'incomplete')
        self.assertIn('32',result['reason'])
        self.assertEqual(result['detections'],[])


if __name__=='__main__':unittest.main()
