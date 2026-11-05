import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from pathlib import Path
import tempfile
import zipfile

from engine_audit import build_audit,dispatch_message
from secondary_analysis import enrich_reviews


class EngineAuditTests(unittest.TestCase):
    def test_installed_assets_do_not_count_as_execution(self):
        audit=build_audit({'yara_x':123,'vba_source':3,'vba_pcode':3},{'status':'not_needed','candidates':0},[])
        self.assertEqual(audit['engine_usage']['rea']['status'],'not_invoked')
        self.assertEqual(audit['engine_usage']['yara_x']['first_pass_files'],123)
        self.assertEqual(audit['engine_usage']['vba_pcode']['status'],'executed')
        self.assertIn('未调用',dispatch_message(audit['dispatch']))

    def test_failure_and_completed_evidence_remain_distinct(self):
        rows=[{'secondary_analysis':{'rea':{'status':'analyzed'},'capa':{'status':'incomplete'},'clamav':{'status':'no_match'}}}]
        engines=build_audit({}, {'status':'dispatched','candidates':1},rows)['engine_usage']
        self.assertEqual(engines['rea']['status'],'executed')
        self.assertEqual(engines['capa']['status'],'not_finished')
        self.assertEqual(engines['clamav']['second_pass_results'],{'no_match':1})

    def test_zero_candidates_are_logged_without_starting_engines(self):
        records=[];cleaner=SimpleNamespace(findings=[{'kind':'infected_office'}],cancel=threading.Event(),log=lambda kind,**fields:records.append((kind,fields)))
        with patch('secondary_analysis.clam_batch',side_effect=AssertionError('must not start')):
            enrich_reviews(cleaner)
        self.assertEqual(cleaner.secondary_dispatch['status'],'not_needed')
        self.assertEqual(records[0][0],'secondary_dispatch')
        self.assertEqual(records[0][1]['candidates'],0)

    def test_confirmed_macro_does_not_keep_unconfirmed_reason(self):
        import worm_recovery as recovery
        analysis={'family_modules':['ThisWorkbook'],'other_modules':[],
                  'pcode_family_match':True,'pcode_status':'instructions_read'}
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'fixture.xlsm'
            with zipfile.ZipFile(path,'w') as archive:
                archive.writestr('xl/workbook.xml','<workbook/>')
                archive.writestr('xl/vbaProject.bin',b'inert macro placeholder')
            with patch('office_analysis.analyze_project',return_value=analysis):
                result=recovery._office_check(path)
            self.assertEqual(result['status'],'infected')
            self.assertIn('已确认感染',result['reason'])
            self.assertNotIn('尚未确认',result['reason'])


if __name__=='__main__':unittest.main()
