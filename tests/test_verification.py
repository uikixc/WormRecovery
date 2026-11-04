import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import worm_recovery as w

class VerificationTests(unittest.TestCase):
    def cleaner(self):
        c=w.Cleaner.__new__(w.Cleaner)
        c.scan_roots=['C:/test'];c.errors=[];c.findings=[];c.skipped=[];c.inspection_failed=False
        import threading
        c.cancel=threading.Event();c.contain=lambda apply:[];c.registry=lambda apply:[];c.firewall=lambda apply:[]
        c.scan=lambda roots:[];c.log=lambda *a,**kw:None;c.save=lambda:None
        c.system_persistence=lambda apply:{'tasks':[],'services':[],'wmi':[]}
        return c
    def test_prior_error_blocks_clean_result(self):
        c=self.cleaner();c.errors=[{'path':'C:/locked.exe','error':'access denied'}]
        self.assertFalse(c.verify()['known_family_clear'])
    def test_verification_preserves_selected_worker_count(self):
        c=self.cleaner();c.scan_workers=2;calls=[]
        c.scan=lambda roots,**kwargs:calls.append(kwargs) or []
        c.verify()
        self.assertEqual(calls,[{'workers':2}])
    def test_persistence_failure_cannot_report_clean(self):
        c=self.cleaner();c.inspection_failed=True
        self.assertFalse(c.verify()['known_family_clear'])
    def test_disabled_task_xml_with_namespace_and_whitespace(self):
        c=self.cleaner()
        c.system_persistence=lambda apply:{'tasks':[{'xml':'<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Settings><Enabled> false </Enabled></Settings></Task>'}],'services':[],'wmi':[]}
        self.assertEqual(c.verify()['active_tasks'],[])
    def test_malformed_task_remains_unresolved(self):
        c=self.cleaner();c.system_persistence=lambda apply:{'tasks':[{'xml':'invalid'}],'services':[],'wmi':[]}
        self.assertFalse(c.verify()['known_family_clear'])
    def test_active_process_blocks_completion(self):
        c=self.cleaner();c.contain=lambda apply:[{'pid':123,'family':'test'}]
        self.assertFalse(c.verify()['known_family_clear'])
    def test_stop_does_not_report_clean(self):
        c=self.cleaner();c.cancel.set()
        self.assertFalse(c.verify()['known_family_clear'])
    def test_unresolved_link_blocks_completion(self):
        c=self.cleaner();c.reparse_points=[{'path':'C:/link','status':'unverified'}]
        self.assertFalse(c.verify()['known_family_clear'])
    def test_command_name_alone_cannot_authorize_mutation(self):
        c=self.cleaner();c.protected_path=lambda p:False
        c.policy=type('Policy',(),{'check':lambda *a:True})()
        with patch.object(w.os.path,'isfile',return_value=False):
            self.assertFalse(c.confirmed_command('C:/GoogleChrome/GoogleChrome.a3x'))
    def test_quoted_service_path_and_arguments_are_parsed(self):
        c=self.cleaner();c.protected_path=lambda p:False
        c.policy=type('Policy',(),{'check':lambda *a:True})()
        with patch.object(w.os.path,'isfile',return_value=True),patch.object(w,'is_stub',return_value=True) as fingerprint:
            self.assertTrue(c.confirmed_command('"C:/Program Files/Synaptics/Synaptics.exe" /service'))
            self.assertEqual(fingerprint.call_args.args[0],'C:/Program Files/Synaptics/Synaptics.exe')

if __name__=='__main__':
    unittest.main(verbosity=2)
