"""No-backup repair regressions use inert bytes only."""
import ctypes
import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock,patch
import repair_storage
import worm_recovery as recovery


def cleaner(root):
    c=recovery.Cleaner.__new__(recovery.Cleaner)
    c.run=root/'session';c.run.mkdir()
    c.policy=SimpleNamespace(mutation=MagicMock())
    c.protected=[];c.events=[];c.findings=[];c.close_locks=MagicMock()
    c.log=lambda kind,**data:c.events.append({'kind':kind,**data})
    return c


def security_text(path):
    from ctypes import wintypes as W
    api=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    api.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes=[ctypes.c_void_p,W.DWORD,W.DWORD,ctypes.POINTER(W.LPWSTR),ctypes.c_void_p]
    api.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype=W.BOOL;kernel.LocalFree.argtypes=[ctypes.c_void_p]
    descriptor=ctypes.create_string_buffer(repair_storage.file_security(path));text=W.LPWSTR()
    if not api.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor,1,5,ctypes.byref(text),None):raise ctypes.WinError(ctypes.get_last_error())
    try:
        owner,dacl=text.value.split('D:',1)
        control,separator,entries=dacl.partition('(')
        # ReplaceFileW may set AUTO_INHERITED without changing protection or ACEs.
        return owner,control.replace('AI',''),separator+entries
    finally:kernel.LocalFree(ctypes.cast(text,ctypes.c_void_p))


class RepairStorageTests(unittest.TestCase):
    def test_legacy_private_directory_validation_remains(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);trusted=root/'private'
            repair_storage.private_directory(trusted)
            repair_storage.private_directory(trusted,create=False)
            untrusted=root/'inherited';untrusted.mkdir()
            with self.assertRaises(PermissionError):repair_storage.private_directory(untrusted,create=False)

    def test_successful_replacement_does_not_create_or_move_backup(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'inert.exe';source.write_bytes(b'old')
            stage=root/'stage.tmp';stage.write_bytes(b'new')
            repair_storage.private_file(source);security=security_text(source)
            replace=recovery.kernel.ReplaceFileW;arguments=[]
            def commit(*args):arguments.append(args);return replace(*args)
            with patch.object(recovery.kernel,'ReplaceFileW',side_effect=commit),patch.object(recovery.shutil,'copy2',side_effect=AssertionError('No backup copy')):
                c.replace(source,stage)
            self.assertEqual(source.read_bytes(),b'new');self.assertFalse(stage.exists())
            self.assertIsNone(arguments[0][2]);self.assertFalse(c.events[-1]['backup_created'])
            self.assertEqual(security_text(source),security)
            self.assertEqual({p.name for p in root.iterdir()},{'session','inert.exe'})
            self.assertFalse(any(e['kind'] in ('backup','quarantined','original_move_pending') for e in c.events))

    def test_hash_mismatch_preserves_source_and_does_not_release_locks(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'inert.bin';source.write_bytes(b'keep')
            with self.assertRaises(RuntimeError):c.remove_confirmed_file(source,'fixture',expected='wrong')
            c.close_locks.assert_not_called();self.assertEqual(source.read_bytes(),b'keep')

    def test_replacement_hash_mismatch_preserves_both(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'inert.exe';source.write_bytes(b'old')
            stage=root/'stage.tmp';stage.write_bytes(b'new')
            with self.assertRaises(RuntimeError):c.replace(source,stage,expected='wrong')
            self.assertEqual(source.read_bytes(),b'old');self.assertEqual(stage.read_bytes(),b'new')
            c.close_locks.assert_not_called()

    def test_failed_replace_reports_no_success_and_preserves_stage(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'inert.exe';source.write_bytes(b'original')
            stage=root/'stage.tmp';stage.write_bytes(b'repaired')
            with patch.object(recovery.kernel,'ReplaceFileW',return_value=False),self.assertRaises(OSError):c.replace(source,stage)
            self.assertEqual(source.read_bytes(),b'original');self.assertEqual(stage.read_bytes(),b'repaired')
            self.assertFalse(any(e['kind']=='restored' for e in c.events))

    def test_delete_has_no_backup_or_quarantine_copy(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'inert.bin';source.write_bytes(b'inert deletion fixture')
            expected=recovery.digest_file(source)
            with patch.object(recovery.shutil,'copy2',side_effect=AssertionError('No backup copy')),patch.object(recovery.os,'rename',side_effect=AssertionError('No quarantine move')):
                c.remove_confirmed_file(source,'inert fixture',expected=expected)
            self.assertFalse(source.exists());self.assertEqual({p.name for p in root.iterdir()},{'session'})
            self.assertEqual(c.events[-1]['kind'],'removed');self.assertFalse(c.events[-1]['backup_created'])

    def test_failed_delete_keeps_source_and_reports_no_success(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'inert.bin';source.write_bytes(b'keep')
            with patch.object(recovery.os,'unlink',side_effect=PermissionError('fixture locked')),self.assertRaises(PermissionError):
                c.remove_confirmed_file(source,'fixture')
            self.assertEqual(source.read_bytes(),b'keep');self.assertFalse(any(e['kind']=='removed' for e in c.events))

    def test_20_gib_sparse_delete_creates_no_backup(self):
        import msvcrt
        from ctypes import wintypes as W
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'inert.bin'
            api=ctypes.WinDLL('kernel32',use_last_error=True)
            api.DeviceIoControl.argtypes=[W.HANDLE,W.DWORD,ctypes.c_void_p,W.DWORD,ctypes.c_void_p,W.DWORD,ctypes.POINTER(W.DWORD),ctypes.c_void_p]
            api.DeviceIoControl.restype=W.BOOL
            with source.open('wb') as stream:
                count=W.DWORD()
                if not api.DeviceIoControl(msvcrt.get_osfhandle(stream.fileno()),0x900c4,None,0,None,0,ctypes.byref(count),None):self.skipTest('Sparse unsupported')
                stream.write(b'inert fixture');stream.truncate(20*1024**3)
            with patch.object(recovery,'digest_file',return_value='f'*64),patch.object(recovery.shutil,'copy2',side_effect=AssertionError('No copy')):
                c.remove_confirmed_file(source,'fixture',expected='f'*64)
            self.assertFalse(source.exists());self.assertEqual(c.events[-1]['size'],20*1024**3)
            self.assertEqual({p.name for p in root.iterdir()},{'session'})

    def test_hardlinked_source_is_preserved(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'inert.bin';source.write_bytes(b'original')
            alias=root/'alias.bin';os.link(source,alias)
            with self.assertRaises(PermissionError):c.remove_confirmed_file(source,'fixture')
            c.close_locks.assert_not_called();self.assertEqual(alias.read_bytes(),b'original')

    def test_existing_destination_is_not_replaced(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);dest=root/'inert.xlsx';dest.write_bytes(b'occupant')
            stage=root/'stage.tmp';stage.write_bytes(b'repaired')
            with self.assertRaises(FileExistsError):c.replace(dest,stage,require_absent=True)
            self.assertEqual(dest.read_bytes(),b'occupant');self.assertEqual(stage.read_bytes(),b'repaired')

    def test_missing_expected_source_does_not_commit(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'missing.exe'
            stage=root/'stage.tmp';stage.write_bytes(b'repaired')
            with self.assertRaises(FileNotFoundError):c.replace(source,stage,expected='f'*64)
            self.assertFalse(source.exists());self.assertEqual(stage.read_bytes(),b'repaired')

    def test_related_deletion_keeps_only_hash_and_analysis_metadata(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'peer.dat';source.write_bytes(b'inert peer')
            sha=recovery.digest_file(source);c.findings=[{'kind':'malware_deployment','path':str(root/'runtime.exe'),'related_evidence':[{'path':str(source),'sha256':sha}]}]
            analysis={'status':'detected','detections':[{'signature':'inert_fixture'}]}
            with patch('family_analysis.inspect',return_value=analysis):c.remove_confirmed_file(source,'fixture',expected=sha)
            evidence=c.removed_evidence(source,sha);self.assertEqual(evidence['family_analysis'],analysis)
            self.assertNotIn('backup',evidence);self.assertFalse(source.exists())

    def test_office_restore_keeps_only_repaired_document(self):
        from tests.test_office_package import OfficePackageTests
        import zipfile
        for same_extension in (False,True):
            with self.subTest(same_extension=same_extension):
                fixture=OfficePackageTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
                source=fixture.source
                if same_extension:
                    source=source.with_suffix('.xlsx');fixture.source.rename(source)
                c=cleaner(fixture.root)
                with patch.object(recovery,'BAD_VBA_HASHES',{hashlib.sha256(fixture.macro).hexdigest()}),patch.object(c,'historical_original',return_value=None):
                    c.restore_office(source,expected=recovery.digest_file(source))
                dest=source.with_suffix('.xlsx')
                with zipfile.ZipFile(dest) as package:self.assertEqual(package.read('xl/worksheets/sheet1.xml'),fixture.parts['xl/worksheets/sheet1.xml'])
                self.assertEqual({p.name for p in fixture.root.iterdir()},{'session',dest.name})
                self.assertFalse(any(e['kind']=='backup' for e in c.events))

    def test_office_destination_appearing_during_repair_preserves_both(self):
        from tests.test_office_package import OfficePackageTests
        fixture=OfficePackageTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        source=fixture.source;original=source.read_bytes();dest=source.with_suffix('.xlsx')
        c=cleaner(fixture.root);sanitize=recovery.sanitized_xlsx
        def create_occupant(path,stage):
            result=sanitize(path,stage);dest.write_bytes(b'new occupant');return result
        with (patch.object(recovery,'BAD_VBA_HASHES',{hashlib.sha256(fixture.macro).hexdigest()}),
              patch.object(c,'historical_original',return_value=None),patch.object(recovery,'sanitized_xlsx',side_effect=create_occupant),self.assertRaises(FileExistsError)):
            c.restore_office(source)
        self.assertEqual(source.read_bytes(),original);self.assertEqual(dest.read_bytes(),b'new occupant')

if __name__=='__main__':unittest.main()
