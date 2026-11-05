import json
from pathlib import Path
import threading
import types
import unittest
from unittest.mock import patch,Mock
import worm_recovery as w

class CLIStatusTests(unittest.TestCase):
    def test_scan_never_enters_repair_or_applying_inspection(self):
        cleaner=types.SimpleNamespace(run=Path('C:/test/report'),count=1,findings=[],errors=[],skipped=[],cancel=threading.Event(),inspection_failed=False,verification={})
        for name in ('contain','registry','system_persistence','scan','repair','verify'):setattr(cleaner,name,Mock())
        with patch.object(w.sys,'argv',['tool','--scan']),patch.object(w,'resolve_scan_scope',return_value={'roots':['C:/test'],'external_volumes':{},'excluded_roots':[]}),patch.object(w,'Cleaner',return_value=cleaner),patch('diagnostic_client.retry'):
            self.assertEqual(w.cli_main(),0)
        for name in ('contain','registry','system_persistence'):getattr(cleaner,name).assert_called_once_with(False)
        cleaner.repair.assert_not_called();cleaner.verify.assert_not_called()
    def run_case(self,errors=(),findings=(),clean=False):
        c=types.SimpleNamespace(run=Path('C:/test/report'),count=1,findings=list(findings),errors=list(errors),skipped=[],cancel=threading.Event(),inspection_failed=False,verification={'known_family_clear':not errors})
        c.contain=c.registry=c.system_persistence=lambda *args:None
        c.scan=c.repair=c.verify=lambda *args:None
        args=['tool','--clean' if clean else '--scan']
        with patch.object(w.sys,'argv',args),patch.object(w,'resolve_scan_scope',return_value={'roots':['C:/test'],'external_volumes':{},'excluded_roots':[]}),patch.object(w,'Cleaner',return_value=c):
            return w.cli_main()
    def test_incomplete_scan_returns_failure(self):self.assertEqual(self.run_case(errors=[{'error':'access denied'}]),1)
    def test_detected_threat_returns_attention_code(self):self.assertEqual(self.run_case(findings=[{'kind':'worm_payload'}]),2)
    def test_completed_scan_returns_zero(self):self.assertEqual(self.run_case(),0)
    def test_informational_components_are_not_reported_as_infection(self):self.assertEqual(self.run_case(findings=[{'kind':'info_office'}]),0)
    def test_unknown_macros_return_distinct_review_status(self):self.assertEqual(self.run_case(findings=[{'kind':'review_office'}]),3)

if __name__=='__main__':
    unittest.main(verbosity=2)
