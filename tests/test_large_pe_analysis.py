"""Large inert PE fixtures only; no target loading or operating system mutation."""
import hashlib
import mmap
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import family_analysis as family
import large_pe_analysis as large
import local_rules
import worm_recovery as recovery
from test_family_analysis import inert_controller,inert_pe


class LargeFileTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def pe(self,name='ordinary.exe',size=32*1024*1024+513,body=b'',overlay=False):
        path=self.root/name;header=bytearray(inert_pe(b'INERT ONLY')[:512]);section=152+224
        code_size=1024 if overlay else size-512
        struct.pack_into('<IIII',header,section+8,code_size,4096,code_size,512)
        struct.pack_into('<I',header,section+36,0x60000020)
        with path.open('wb') as stream:
            stream.write(header);stream.seek(size-1);stream.write(b'\0')
            if body:stream.seek(size-len(body));stream.write(body)
        return path

    def test_large_valid_pe_finishes_full_rules_without_unknown_finding(self):
        path=self.pe();before=path.stat();seen=[];original=family.inspect_mapped_pe
        def mapped(data,rules):
            self.assertIsInstance(data,mmap.mmap);seen.append(len(data));return original(data,rules)
        with patch.object(family,'inspect_mapped_pe',side_effect=mapped),             patch.object(family,'scan_bytes',side_effect=AssertionError('whole-file bytes scan forbidden')):
            result=recovery.inspect_file_content(path,before)
        self.assertEqual(seen,[before.st_size]);self.assertEqual(result['findings'],[])
        self.assertEqual(result['streamed_bytes'],before.st_size)
        self.assertEqual(result['large_file_coverage']['source_identity'],'stable')
        self.assertNotIn('family_size_limited',result['engine_checks'])
        self.assertEqual(large.identity(before),large.identity(path.stat()))
        self.assertGreater(result['large_file_coverage']['timeout_seconds'],3)
        path.unlink();self.assertFalse(path.exists())

    def test_real_directory_entry_queue_uses_only_available_identity_fields(self):
        path=self.pe()
        with os.scandir(self.root) as entries:
            queued=next(entry for entry in entries if entry.name==path.name).stat(follow_symlinks=False)
        result=recovery.inspect_file_content(path,queued)
        self.assertEqual(result['findings'],[])
        self.assertEqual(result['large_file_coverage']['source_identity'],'stable')

    def test_large_extracted_original_is_fully_checked_before_restore(self):
        from test_cleanup_audit import inert_cleaner
        original=self.pe();wrapper=self.root/'wrapper.exe';wrapper.write_bytes(b'inert wrapper')
        c=inert_cleaner()
        class Resource:
            def __init__(self,path):self.path=Path(path);self.size=self.path.stat().st_size
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def resource(self,name):return (0,original.stat().st_size)
            def extract_resource(self,resource,destination):
                import shutil
                shutil.copyfile(original,destination)
        def replace(destination,stage,expected=None):
            import shutil
            shutil.copyfile(stage,destination)
        c.replace.side_effect=replace
        with patch.object(recovery,'is_stub',side_effect=lambda p:Path(p)==wrapper and wrapper.stat().st_size<64),\
                patch.object(recovery,'PEView',Resource):
            c.restore_executable(wrapper)
        self.assertEqual(wrapper.stat().st_size,original.stat().st_size)
        self.assertEqual(wrapper.read_bytes()[:512],original.read_bytes()[:512])
        c.replace.assert_called_once()

    def test_code_beyond_old_limit_is_detected_with_full_hash(self):
        body=inert_controller()[512:];path=self.pe(body=body)
        result=recovery.inspect_file_content(path,path.stat());row=result['findings'][0]
        self.assertEqual(row['kind'],'malware_component')
        h=hashlib.sha256()
        with path.open('rb') as stream:
            for data in iter(lambda:stream.read(1024*1024),b''):h.update(data)
        self.assertEqual(row['sha256'],h.hexdigest())
        positions=row['family_analysis']['detections'][0]['code_locations']
        self.assertTrue(all(match['offset']>family.MAX_INPUT for match in positions))

    def test_same_signature_in_large_overlay_is_review_and_never_quarantine_authority(self):
        path=self.pe(body=inert_controller(),overlay=True)
        result=recovery.inspect_file_content(path,path.stat())
        self.assertEqual([row['kind'] for row in result['findings']],['review_binary'])
        self.assertTrue(result['findings'][0]['content_rules']['matches'])

    def test_timeout_and_mapping_failure_remain_uncompleted(self):
        path=self.pe()
        with patch.object(local_rules,'scan_file',side_effect=TimeoutError('inert timeout')):
            result=recovery.inspect_file_content(path,path.stat())
        self.assertEqual(result['findings'][0]['kind'],'review_binary')
        self.assertEqual(result['engine_checks']['family_streamed_failed'],1)
        self.assertNotIn('family_streamed_pe',result['engine_checks'])
        self.assertEqual(result['large_file_coverage']['rule_scan_bytes'],0)
        with patch.object(large.mmap,'mmap',side_effect=OSError('inert mapping refusal')):
            result=family.inspect_large_file(path)
        self.assertEqual(result['status'],'incomplete')

    def test_source_identity_changes_in_queue_or_during_scan_fail_closed(self):
        path=self.pe();before=path.stat()
        os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns+1000000000))
        result=family.inspect_large_file(path,expected_stat=before)
        self.assertEqual(result['status'],'incomplete');self.assertEqual(result['coverage']['source_identity'],'changed')
        original=local_rules.scan_file
        def changed(filename,**kwargs):
            result=original(filename,**kwargs);current=path.stat()
            with path.open('r+b') as stream:stream.seek(1024);stream.write(b'changed inert bytes')
            os.utime(path,ns=(current.st_atime_ns,current.st_mtime_ns+1000000000));return result
        with patch.object(local_rules,'scan_file',side_effect=changed):result=family.inspect_large_file(path)
        self.assertEqual(result['status'],'incomplete');self.assertEqual(result['coverage']['source_identity'],'changed')
        self.assertNotIn('source_sha256',result);self.assertEqual(result['detections'],[])

    def test_source_write_with_restored_mtime_stays_uncompleted(self):
        path=self.pe();before=path.stat();original=local_rules.scan_file
        def changed(filename,**kwargs):
            result=original(filename,**kwargs)
            with path.open('r+b') as stream:
                stream.seek(1024);stream.write(b'CHANGED')
            os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns))
            return result
        with patch.object(local_rules,'scan_file',side_effect=changed):
            result=family.inspect_large_file(path)
        self.assertEqual(path.stat().st_mtime_ns,before.st_mtime_ns)
        self.assertEqual(result['status'],'incomplete')
        self.assertEqual(result['coverage']['source_identity'],'changed')
        self.assertEqual(result['detections'],[])

    def test_large_content_confirmation_uses_full_current_code(self):
        from test_cleanup_audit import inert_cleaner
        c=inert_cleaner();ordinary=self.pe();malicious=self.pe(name='other.exe',body=inert_controller()[512:])
        self.assertFalse(c.content_confirmed_path(ordinary))
        self.assertTrue(c.content_confirmed_path(malicious))
        with malicious.open('r+b') as stream:
            stream.seek(malicious.stat().st_size-len(inert_controller()[512:]));stream.write(b'X'*len(inert_controller()[512:]))
        self.assertFalse(c.content_confirmed_path(malicious))

    def test_known_packer_with_oversize_compressed_range_stays_review(self):
        path=self.pe(size=32*1024*1024+513)
        # Inert modified-packer prefix only; it contains no compressed program.
        header=bytearray(inert_pe(b'INERT',machine=0x8664)[:512]);section=152+240
        struct.pack_into('<IIII',header,section+8,path.stat().st_size-512,4096,path.stat().st_size-512,512)
        struct.pack_into('<I',header,section+36,0x60000020)
        prefix=family.PACKED_PREFIX+struct.pack('<i',64-14)+family.PACKED_XOR
        with path.open('r+b') as stream:stream.write(header);stream.seek(512);stream.write(prefix)
        result=family.inspect_large_file(path)
        self.assertEqual(result['status'],'incomplete')
        self.assertIn('解包',result['reason'])

    def test_large_script_entire_content_is_scanned_and_hits_remain_review(self):
        path=self.root/'ordinary.ps1'
        with path.open('wb') as stream:stream.write(b'# inert fixture\n');stream.seek(5*1024*1024);stream.write(b'\n')
        result=recovery.inspect_file_content(path,path.stat());self.assertEqual(result['findings'],[])
        self.assertEqual(result['streamed_bytes'],path.stat().st_size)
        with path.open('ab') as stream:stream.write(b'# AutoIt3ExecuteScript GoogleChrome.a3x MozillaFirefox cmd.exe')
        result=recovery.inspect_file_content(path,path.stat())
        self.assertEqual([row['kind'] for row in result['findings']],['review_script'])
        self.assertEqual(result['streamed_bytes'],path.stat().st_size)

    def test_file_rule_scan_releases_source_before_mutation(self):
        path=self.pe()
        rules=local_rules.scan_file(path,timeout_seconds=6)
        self.assertEqual(rules['matches'],[])
        moved=path.with_suffix('.checked')
        path.rename(moved);moved.unlink()
        self.assertFalse(moved.exists())

    def test_rule_timeout_is_reset_and_last_input_scanner_is_released(self):
        from unittest.mock import MagicMock,call
        fake=MagicMock();fake.scan_file.return_value=SimpleNamespace(matching_rules=[])
        previous=getattr(local_rules._local,'scanner',None)
        local_rules._local.scanner=fake
        try:
            with patch.object(local_rules,'_scanner',return_value=fake):
                local_rules.scan_file('inert-fixture',timeout_seconds=10)
            self.assertEqual(fake.set_timeout.call_args_list,[call(10),call(3)])
            self.assertIsNot(getattr(local_rules._local,'scanner',None),fake)
        finally:
            if previous is not None:local_rules._local.scanner=previous

    def test_admission_limit_is_explicit_before_mapping_or_scanning(self):
        path=self.pe();before=path.stat()
        oversized=SimpleNamespace(st_dev=before.st_dev,st_ino=before.st_ino,st_size=large.MAX_FILE_BYTES+1,
            st_mode=before.st_mode,st_mtime_ns=before.st_mtime_ns,st_ctime_ns=before.st_ctime_ns,
            st_birthtime_ns=getattr(before,'st_birthtime_ns',None))
        with patch.object(large.os,'fstat',return_value=oversized),patch.object(large.mmap,'mmap') as mapping,\
                patch.object(local_rules,'scan_file') as scanning:
            result=family.inspect_large_file(path)
        self.assertEqual(result['status'],'incomplete')
        self.assertIn('2 GiB',result['reason']);mapping.assert_not_called();scanning.assert_not_called()

    def test_larger_files_receive_a_bounded_io_budget(self):
        path=self.pe();seen=[];original=local_rules.scan_file
        def scan(filename,**kwargs):
            seen.append(kwargs['timeout_seconds']);return original(filename,**kwargs)
        with patch.object(local_rules,'scan_file',side_effect=scan):
            result=family.inspect_large_file(path)
        self.assertEqual(result['status'],'no_known_match')
        self.assertGreater(seen[0],3);self.assertLessEqual(seen[0],180)


if __name__=='__main__':unittest.main()
