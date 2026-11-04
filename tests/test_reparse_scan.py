import json
import os
from pathlib import Path
import shutil
import struct
import unittest
import uuid
from unittest.mock import patch
import worm_recovery as w
import reparse_scan as rs

def link_data(target,tag=0xa0000003,relative=False):
    payload=target.encode('utf-16le')
    head=struct.pack('<HHHH',0,len(payload),0,0)
    if tag==0xa000000c:head+=struct.pack('<I',int(relative))
    body=head+payload
    return struct.pack('<IHH',tag,len(body),0)+body

class ReparseTests(unittest.TestCase):
    def test_junction_target_is_decoded(self):
        self.assertEqual(rs.decode_reparse(link_data('\\??\\C:\\Users'),'C:/old')['target'],'C:\\Users')
    def test_relative_symlink_is_resolved(self):
        result=rs.decode_reparse(link_data('..\\actual',0xa000000c,True),'C:\\root\\links\\alias')
        self.assertEqual(result['target'],'C:\\root\\actual')
    def test_app_alias_target_is_identified(self):
        payload=struct.pack('<I',3)+'package\0id\0C:\\Apps\\tool.exe\0'.encode('utf-16le')
        data=struct.pack('<IHH',0x8000001b,len(payload),0)+payload
        self.assertEqual(rs.decode_reparse(data,'C:/alias')['target'],'C:\\Apps\\tool.exe')
    def test_remote_target_is_not_followed(self):
        with self.assertRaises(rs.CoverageLimit):rs.decode_reparse(link_data('\\??\\UNC\\server\\share'),'C:/link')
    def test_invalid_offsets_are_rejected(self):
        data=bytearray(link_data('C:\\safe'));struct.pack_into('<H',data,8,65534)
        with self.assertRaises(ValueError):rs.decode_reparse(data,'C:/link')
    def test_unknown_tag_is_unverified(self):
        with self.assertRaises(rs.CoverageLimit):rs.decode_reparse(struct.pack('<IHH',0x80001234,0,0),'C:/link')
    def test_out_of_scope_target_is_rejected_before_filesystem_access(self):
        with patch.object(rs.os,'lstat',side_effect=AssertionError('must not access volume')):
            with self.assertRaises(rs.CoverageLimit):rs.resolve_target('D:/research',lambda p:False)
    def test_cycle_does_not_recurse_forever(self):
        fake=type('Stat',(),{'st_file_attributes':0x400})()
        with patch.object(rs.os,'lstat',return_value=fake),patch.object(rs,'inspect_reparse',return_value={'kind':'symbolic_link','target':'C:\\loop'}):
            with self.assertRaisesRegex(rs.CoverageLimit,'link_cycle'):rs.resolve_target('C:/loop',lambda p:True)
    def test_real_links_scan_target_once_and_preserve_specimen(self):
        base=Path('C:/ProgramData/WormRecoveryReparseTests')/uuid.uuid4().hex
        actual=base/'actual';actual.mkdir(parents=True)
        import hashlib
        infected=actual/'fixture.a3x';infected.write_bytes(b'Inert scanner regression fixture; never executed.')
        fixture_hash=hashlib.sha256(infected.read_bytes()).hexdigest()
        fingerprint_patch=patch.object(w,'AUTOIT_A3X_SHA256',fixture_hash)
        fingerprint_patch.start()
        os.symlink(actual,base/'alias',target_is_directory=True)
        os.symlink(base,actual/'parent_loop',target_is_directory=True)
        os.symlink(infected,base/'file_alias.a3x')
        c=w.Cleaner(emit=lambda s:None)
        try:
            c.scan([str(base)])
            self.assertEqual(len([x for x in c.findings if x['kind']=='worm_script']),1)
            self.assertLessEqual(c.dircount,2)
            self.assertEqual(len(c.reparse_points),3)
            self.assertTrue(all(x['status'] in ('target_visited','target_checked','target_already_checked') for x in c.reparse_points))
            self.assertEqual(c.errors,[])
            self.assertEqual(w.digest_file(infected),fixture_hash)
        finally:
            fingerprint_patch.stop()
            for link in (base/'alias',actual/'parent_loop',base/'file_alias.a3x'):
                if link.is_symlink():link.unlink()
            shutil.rmtree(base)

if __name__=='__main__':
    unittest.main(verbosity=2)
