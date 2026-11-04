"""Containment and residue authorization regressions; never run malware."""
from pathlib import Path
from types import SimpleNamespace
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import worm_recovery as w
import worm_residue as residue


class ResidueTests(unittest.TestCase):
    def cleaner(self):
        c=w.Cleaner.__new__(w.Cleaner)
        c.events=[];c.errors=[];c.findings=[];c.protected=[]
        c.policy=SimpleNamespace(check=lambda p:True,mutation=lambda p:True)
        c.log=lambda kind,**data:c.events.append({'kind':kind,**data})
        return c

    def test_payload_root_does_not_match_legitimate_installation(self):
        self.assertEqual(residue.payload_root('C:/GoogleChrome/data'),'C:\\GoogleChrome')
        self.assertIsNone(residue.payload_root('C:/Program Files/Google/Chrome/Application/chrome.exe'))
        self.assertIsNone(residue.payload_root('//server/GoogleChrome/GoogleChrome.exe'))

    def test_exact_startup_command_requires_same_root(self):
        self.assertEqual(residue.exact_startup_root('C:/GoogleChrome/GoogleChrome.exe /AutoIt3ExecuteScript C:/GoogleChrome/GoogleChrome.a3x'),'C:\\GoogleChrome')
        self.assertIsNone(residue.exact_startup_root('C:/Other/GoogleChrome.exe /AutoIt3ExecuteScript C:/GoogleChrome/GoogleChrome.a3x'))
        self.assertIsNone(residue.exact_startup_root('C:/GoogleChrome/GoogleChrome.exe /AutoIt3ExecuteScript C:/GoogleChrome/GoogleChrome.a3x & calc.exe'))

    def test_missing_startup_target_requires_local_content_evidence(self):
        c=self.cleaner()
        command='C:/GoogleChrome/GoogleChrome.exe /AutoIt3ExecuteScript C:/GoogleChrome/GoogleChrome.a3x'
        with patch.object(w.os.path,'isfile',return_value=False),patch.object(c,'root_residue_evidence',return_value=False):
            self.assertFalse(c.confirmed_command(command))
        with patch.object(w.os.path,'isfile',return_value=False),patch.object(c,'root_residue_evidence',return_value=True):
            self.assertTrue(c.confirmed_command(command))

    def test_external_runtime_is_contained_without_mutating_sample(self):
        c=self.cleaner();c.policy=SimpleNamespace(check=MagicMock(side_effect=PermissionError('preserved device')))
        p=SimpleNamespace(pid=123456,info={'name':'fixture.exe','exe':'E:/._cache_GoogleChrome.exe','cmdline':['E:/._cache_GoogleChrome.exe','/AutoIt3ExecuteScript','C:/GoogleChrome/GoogleChrome.a3x']})
        c.stop_pid=MagicMock();c.quarantine_file=MagicMock()
        with patch.object(w.psutil,'process_iter',return_value=[p]),patch.object(w,'is_stub',return_value=False),patch.object(w.os.path,'isfile',return_value=True),patch.object(w.os.path,'getsize',return_value=750320),patch.object(w,'digest_file',side_effect=lambda path:w.AUTOIT_EXE_SHA256 if str(path).endswith('.exe') else w.AUTOIT_A3X_SHA256):
            self.assertEqual(len(c.contain(True)),1)
        c.stop_pid.assert_called_once();c.quarantine_file.assert_not_called();c.policy.check.assert_not_called()

    def test_runtime_name_alone_does_not_authorize_termination(self):
        c=self.cleaner();c.stop_pid=MagicMock()
        p=SimpleNamespace(pid=123456,info={'name':'._cache_GoogleChrome.exe','exe':'E:/._cache_GoogleChrome.exe','cmdline':['E:/._cache_GoogleChrome.exe','/AutoIt3ExecuteScript','C:/GoogleChrome/GoogleChrome.a3x']})
        with patch.object(w.psutil,'process_iter',return_value=[p]),patch.object(w,'is_stub',return_value=False),patch.object(w.os.path,'isfile',return_value=True),patch.object(w.os.path,'getsize',return_value=750320),patch.object(w,'digest_file',return_value='unrecognized'):
            self.assertEqual(c.contain(True),[])
        c.stop_pid.assert_not_called()

    def test_nonempty_payload_directory_is_not_removed(self):
        c=self.cleaner()
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'GoogleChrome';root.mkdir();document=root/'user.txt';document.write_text('keep')
            with patch.object(w,'payload_root',return_value=str(root)):
                c.cleanup_empty_payload_roots([root])
            self.assertEqual(document.read_text(),'keep')

    def test_empty_confirmed_root_is_removed_without_recursive_delete(self):
        c=self.cleaner()
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'GoogleChrome';root.mkdir()
            with patch.object(w,'payload_root',return_value=str(root)):
                c.cleanup_empty_payload_roots([root])
            self.assertFalse(root.exists())

    def test_startup_state_backup_precedes_exact_value_removal(self):
        c=self.cleaner();key=MagicMock();key.__enter__.return_value=key
        state=b'fixture state'
        with patch.object(w.winreg,'OpenKey',return_value=key),patch.object(w.winreg,'QueryValueEx',return_value=(state,w.winreg.REG_BINARY)),patch.object(w.winreg,'DeleteValue') as delete:
            c.startup_approved(w.winreg.HKEY_CURRENT_USER,'','Fixture',('Run',),'confirmed fixture command')
        self.assertEqual(delete.call_count,2)
        self.assertEqual(c.events[0]['kind'],'startup_approved_backup')
        self.assertTrue(all(call.args[1]=='Fixture' for call in delete.call_args_list))


if __name__=='__main__':
    unittest.main(verbosity=2)
