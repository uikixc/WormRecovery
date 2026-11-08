"""Original-retention tests use inert bytes only, without host cleanup."""
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
    c.protected=[];c.events=[];c.close_locks=MagicMock()
    c.log=lambda kind,**data:c.events.append({'kind':kind,**data})
    return c


def security_text(path):
    from ctypes import wintypes as W
    api=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    api.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes=[ctypes.c_void_p,W.DWORD,W.DWORD,ctypes.POINTER(W.LPWSTR),ctypes.c_void_p]
    api.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype=W.BOOL
    kernel.LocalFree.argtypes=[ctypes.c_void_p]
    descriptor=ctypes.create_string_buffer(repair_storage.file_security(path));text=W.LPWSTR()
    if not api.ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor,1,5,ctypes.byref(text),None):raise ctypes.WinError(ctypes.get_last_error())
    try:return text.value
    finally:kernel.LocalFree(ctypes.cast(text,ctypes.c_void_p))


class RepairStorageTests(unittest.TestCase):
    def test_private_directory_rejects_existing_inherited_permissions(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);trusted=root/'private'
            repair_storage.private_directory(trusted)
            repair_storage.private_directory(trusted,create=False)
            untrusted=root/'inherited';untrusted.mkdir()
            with self.assertRaises(PermissionError):repair_storage.private_directory(untrusted,create=False)

    def test_original_is_moved_without_copying_and_keeps_file_identity(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'inert.exe';source.write_bytes(b'inert original')
            before=source.stat();expected=hashlib.sha256(source.read_bytes()).hexdigest()
            with patch.object(recovery,'volume',return_value=str(root)),patch.object(recovery.shutil,'copy2',side_effect=AssertionError('No full copy')):
                sha,retained,st=c.backup(source,expected=expected)
            self.assertFalse(source.exists());self.assertEqual(retained.read_bytes(),b'inert original')
            self.assertEqual(retained.stat().st_ino,before.st_ino);self.assertEqual(sha,expected)
            self.assertEqual(c.events[-1]['method'],'same_volume_move');self.assertEqual(c.events[-1]['copied_bytes'],0)
            self.assertTrue(c.protected_path(retained));c.close_locks.assert_called_once_with(source)
            repair_storage._validate_private_security(retained)

    def test_20_gib_sparse_original_moves_without_copy_or_new_allocation(self):
        import msvcrt
        from ctypes import wintypes as W
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'inert.exe'
            api=ctypes.WinDLL('kernel32',use_last_error=True)
            api.DeviceIoControl.argtypes=[W.HANDLE,W.DWORD,ctypes.c_void_p,W.DWORD,ctypes.c_void_p,W.DWORD,ctypes.POINTER(W.DWORD),ctypes.c_void_p]
            api.DeviceIoControl.restype=W.BOOL
            with source.open('wb') as stream:
                count=W.DWORD()
                if not api.DeviceIoControl(msvcrt.get_osfhandle(stream.fileno()),0x900c4,None,0,None,0,ctypes.byref(count),None):
                    self.skipTest('Fixture volume does not support sparse files')
                stream.write(b'inert size fixture');stream.truncate(20*1024**3)
            before=source.stat()
            with (patch.object(recovery,'volume',return_value=str(root)),
                 patch.object(recovery,'digest_file',return_value='f'*64),
                 patch.object(recovery.shutil,'copy2',side_effect=AssertionError('No full copy'))):
                _,retained,_=c.backup(source,expected='f'*64)
            with retained.open('rb') as stream:self.assertEqual(stream.read(18),b'inert size fixture')
            self.assertEqual(retained.stat().st_ino,before.st_ino);self.assertFalse(source.exists())
            self.assertEqual(retained.stat().st_size,20*1024**3)
            self.assertEqual(c.events[-1]['size'],20*1024**3);self.assertEqual(c.events[-1]['copied_bytes'],0)

    def test_hash_mismatch_does_not_release_locks_or_move_source(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'inert.bin';source.write_bytes(b'keep')
            with self.assertRaises(RuntimeError):c.backup(source,expected='wrong')
            c.close_locks.assert_not_called();self.assertEqual(source.read_bytes(),b'keep')

    def test_rename_failure_never_falls_back_to_copy(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'inert.bin';source.write_bytes(b'keep')
            original_security=security_text(source)
            with (patch.object(recovery,'volume',return_value=str(root)),
                 patch.object(recovery.os,'rename',side_effect=OSError(17,'different volume')),
                 patch.object(recovery.shutil,'copy2',side_effect=AssertionError('No full copy')),self.assertRaises(OSError)):
                c.backup(source)
            self.assertEqual(source.read_bytes(),b'keep')
            self.assertEqual(security_text(source),original_security)
            self.assertFalse(any(e['kind']=='backup' for e in c.events))

    def test_failed_commit_restores_original_and_preserves_stage(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'inert.exe';source.write_bytes(b'original')
            original_security=security_text(source)
            stage=root/'inert.tmp';stage.write_bytes(b'repaired')
            with patch.object(recovery,'volume',return_value=str(root)),patch.object(recovery.kernel,'ReplaceFileW',return_value=False),self.assertRaises(OSError):
                c.replace(source,stage)
            self.assertEqual(source.read_bytes(),b'original');self.assertEqual(stage.read_bytes(),b'repaired')
            self.assertEqual(security_text(source),original_security)
            self.assertFalse(any(e['kind']=='backup' for e in c.events))

    def test_partial_replace_failure_restores_moved_original(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'inert.exe';source.write_bytes(b'original')
            stage=root/'inert.tmp';stage.write_bytes(b'repaired')
            def fail(path,replacement,backup,*unused):
                os.rename(path,backup);ctypes.set_last_error(1177);return False
            with patch.object(recovery,'volume',return_value=str(root)),patch.object(recovery.kernel,'ReplaceFileW',side_effect=fail),self.assertRaises(OSError):
                c.replace(source,stage)
            self.assertEqual(source.read_bytes(),b'original');self.assertEqual(stage.read_bytes(),b'repaired')
            self.assertEqual(c.events[-1]['kind'],'original_move_rolled_back')

    def test_existing_destination_is_not_overwritten_on_rollback(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'inert.exe';source.write_bytes(b'new occupant')
            back=root/'retained.bin';back.write_bytes(b'original')
            c.rollback_original(source,back)
            self.assertEqual(source.read_bytes(),b'new occupant');self.assertEqual(back.read_bytes(),b'original')

    def test_successful_replacement_retains_old_bytes_without_copying(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'inert.exe';source.write_bytes(b'old')
            original_security=security_text(source)
            before=source.stat();stage=root/'inert.tmp';stage.write_bytes(b'new')
            with patch.object(recovery,'volume',return_value=str(root)),patch.object(recovery.shutil,'copy2',side_effect=AssertionError('No full copy')):
                c.replace(source,stage)
            self.assertEqual(source.read_bytes(),b'new');self.assertFalse(stage.exists())
            event=next(e for e in c.events if e['kind']=='backup');back=Path(event['backup'])
            self.assertEqual(back.read_bytes(),b'old');self.assertEqual(back.stat().st_ino,before.st_ino)
            repair_storage._validate_private_security(back)
            self.assertEqual(security_text(source),original_security)

    def test_security_roundtrip_does_not_copy_file_content(self):
        with TemporaryDirectory() as directory:
            source=Path(directory)/'inert.bin';source.write_bytes(b'original')
            descriptor=repair_storage.file_security(source);original=security_text(source)
            repair_storage.private_file(source);repair_storage._validate_private_security(source)
            repair_storage.restore_security(source,descriptor)
            self.assertEqual(security_text(source),original);self.assertEqual(source.read_bytes(),b'original')

    def test_hardlinked_source_is_preserved(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);source=root/'inert.bin';source.write_bytes(b'original')
            alias=root/'alias.bin';os.link(source,alias)
            with patch.object(recovery,'volume',return_value=str(root)),self.assertRaises(PermissionError):c.backup(source)
            self.assertEqual(source.read_bytes(),b'original');self.assertEqual(alias.read_bytes(),b'original')

    def test_new_office_destination_is_never_replaced(self):
        with TemporaryDirectory() as directory:
            root=Path(directory);c=cleaner(root);dest=root/'inert.xlsx';dest.write_bytes(b'new occupant')
            stage=root/'stage.tmp';stage.write_bytes(b'repaired')
            with self.assertRaises(FileExistsError):c.replace(dest,stage,require_absent=True)
            self.assertEqual(dest.read_bytes(),b'new occupant');self.assertEqual(stage.read_bytes(),b'repaired')

    def test_office_restore_keeps_one_original_for_both_extensions(self):
        from tests.test_office_package import OfficePackageTests
        import zipfile
        for same_extension in (False,True):
            with self.subTest(same_extension=same_extension):
                fixture=OfficePackageTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
                source=fixture.source
                if same_extension:
                    source=source.with_suffix('.xlsx');fixture.source.rename(source)
                original=source.read_bytes();original_security=security_text(source);c=cleaner(fixture.root)
                with (patch.object(recovery,'volume',return_value=str(fixture.root)),
                      patch.object(recovery,'BAD_VBA_HASHES',{hashlib.sha256(fixture.macro).hexdigest()}),
                      patch.object(c,'historical_original',return_value=None)):
                    c.restore_office(source,expected=hashlib.sha256(original).hexdigest())
                dest=source.with_suffix('.xlsx')
                with zipfile.ZipFile(dest) as package:self.assertEqual(package.read('xl/worksheets/sheet1.xml'),fixture.parts['xl/worksheets/sheet1.xml'])
                events=[e for e in c.events if e['kind']=='backup'];self.assertEqual(len(events),1)
                retained=Path(events[0]['backup']);self.assertEqual(retained.read_bytes(),original)
                repair_storage._validate_private_security(retained);self.assertTrue(c.retained_original(retained))
                if same_extension:self.assertEqual(security_text(dest),original_security)
                else:self.assertFalse(source.exists())

    def test_office_destination_appearing_during_repair_preserves_both(self):
        from tests.test_office_package import OfficePackageTests
        fixture=OfficePackageTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        source=fixture.source;original=source.read_bytes();original_security=security_text(source)
        dest=source.with_suffix('.xlsx');c=cleaner(fixture.root);sanitize=recovery.sanitized_xlsx
        def create_occupant(path,stage):
            result=sanitize(path,stage);dest.write_bytes(b'new occupant');return result
        with (patch.object(recovery,'volume',return_value=str(fixture.root)),
              patch.object(recovery,'BAD_VBA_HASHES',{hashlib.sha256(fixture.macro).hexdigest()}),
              patch.object(c,'historical_original',return_value=None),
              patch.object(recovery,'sanitized_xlsx',side_effect=create_occupant),self.assertRaises(FileExistsError)):
            c.restore_office(source)
        self.assertEqual(source.read_bytes(),original);self.assertEqual(security_text(source),original_security)
        self.assertEqual(dest.read_bytes(),b'new occupant')


if __name__=='__main__':unittest.main()
