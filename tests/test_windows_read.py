"""Read failures and path handling; inert fixtures only, no system ACL changes."""
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import windows_read
import worm_recovery as recovery


class WindowsReadTests(unittest.TestCase):
    def test_short_path_remains_unchanged(self):
        self.assertEqual(windows_read.extended_path('C:/fixture.txt'),'C:/fixture.txt')

    def test_long_drive_path_gets_explicit_prefix_once(self):
        path='C:/'+('a'*90+'/')*3+'fixture.dll'
        explicit=windows_read.extended_path(path)
        self.assertTrue(explicit.startswith('\\\\?\\C:\\'))
        self.assertEqual(windows_read.extended_path(explicit),explicit)

    def test_long_unc_path_keeps_server_and_share(self):
        path='//server/share/'+('a'*90+'/')*3+'fixture.dll'
        self.assertTrue(windows_read.extended_path(path).startswith('\\\\?\\UNC\\server\\share\\'))

    def test_permission_denial_retries_read_only_and_propagates_failure(self):
        with patch.object(windows_read.builtins,'open',side_effect=PermissionError('denied')),patch.object(windows_read,'backup_read',return_value=io.BytesIO(b'inert')) as backup:
            with windows_read.open_read('C:/fixture.dll') as stream:self.assertEqual(stream.read(),b'inert')
            backup.assert_called_once_with('C:/fixture.dll')
        with patch.object(windows_read.builtins,'open',side_effect=PermissionError('denied')),patch.object(windows_read,'backup_read',side_effect=OSError('still unavailable')):
            with self.assertRaisesRegex(OSError,'still unavailable'):windows_read.open_read('C:/fixture.dll')

    def test_missing_file_does_not_attempt_privilege_fallback(self):
        with patch.object(windows_read.builtins,'open',side_effect=FileNotFoundError('missing')),patch.object(windows_read,'backup_read') as backup:
            with self.assertRaises(FileNotFoundError):windows_read.open_read('C:/missing.dll')
            backup.assert_not_called()

    def test_write_modes_are_rejected(self):
        for mode in ('wb','r+b','ab'):
            with self.subTest(mode=mode),self.assertRaises(ValueError):windows_read.open_read('C:/fixture',mode)

    def test_backup_reader_reads_without_changing_fixture(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'fixture';path.write_bytes(b'inert bytes')
            before=path.stat().st_mtime_ns
            with windows_read.backup_read(path) as stream:self.assertEqual(stream.read(),b'inert bytes')
            self.assertEqual(path.read_bytes(),b'inert bytes');self.assertEqual(path.stat().st_mtime_ns,before)

    def test_long_path_reaches_detector_and_second_pass_snapshot(self):
        import threading
        from secondary_analysis import snapshot_file
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp);created=[]
            for name in ('a'*90,'b'*90,'c'*90):
                directory/=name;os.mkdir(windows_read.extended_path(directory));created.append(directory)
            path=directory/'fixture.dll';data=b'inert fixture content'
            try:
                with open(windows_read.extended_path(path),'wb') as stream:stream.write(data)
                result=recovery.inspect_file_content(str(path),os.stat(windows_read.extended_path(path)))
                self.assertEqual(result['findings'],[])
                snapshot=Path(temp)/'copy.dll';snapshot_file(path,snapshot,threading.Event())
                self.assertEqual(snapshot.read_bytes(),data)
                cleaner=recovery.Cleaner(report_dir=Path(temp)/'reports',emit=lambda _:None)
                with patch('secondary_analysis.enrich_reviews'):
                    cleaner.scan([str(created[0])],workers=1)
                self.assertEqual(cleaner.errors,[])
                self.assertEqual(cleaner.count,1)
                self.assertEqual(cleaner.findings,[])
            finally:
                os.unlink(windows_read.extended_path(path))
                for directory in reversed(created):os.rmdir(windows_read.extended_path(directory))


if __name__=='__main__':unittest.main()
