"""Inert evidence only: reuse, changed content, explicit limits and PE alias boundaries."""
import copy
from pathlib import Path
import struct
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import secondary_analysis as engines
import family_analysis as family
import worm_recovery as recovery
from test_family_analysis import inert_pe
REAL_PE_SECOND_OPINION=engines.pe_second_opinion


class ReviewEfficiencyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.source=self.root/'inert.exe'
        self.source.write_bytes(inert_pe(b'INERT DATA ONLY'*90))
        self.cleaner=SimpleNamespace(findings=[],cancel=threading.Event(),run=self.root,
            policy=SimpleNamespace(check=lambda _:None),protected_path=lambda _:False,
            emit=lambda _:None,log=lambda *a,**kw:None,error=lambda *a:None,inspection_failed=False)
        self.clam=patch.object(engines,'clam_batch',side_effect=lambda paths,*a,**kw:(
            {str(p):{'status':'no_match'} for p in paths},{'version':'fixture'})).start()
        self.pe=patch.object(engines,'pe_second_opinion',return_value={
            'capa':{'status':'not_requested'},'rea':{'status':'analyzed'}}).start()
        self.addCleanup(patch.stopall)

    def run_review(self,paths=None):
        self.cleaner.findings=[{'kind':'review_binary','path':str(p),'reason':'unknown'} for p in (paths or [self.source])]
        engines.enrich_reviews(self.cleaner)
        return self.cleaner.findings

    def test_duplicate_and_rescan_rehash_but_execute_once(self):
        duplicate=self.root/'renamed.data';duplicate.write_bytes(self.source.read_bytes())
        with patch.object(engines,'snapshot_file',wraps=engines.snapshot_file) as snapshot:
            rows=self.run_review([self.source,duplicate]);self.run_review()
        self.assertEqual(snapshot.call_count,3)
        self.assertEqual(self.pe.call_count,1);self.assertEqual(self.clam.call_count,1)
        self.assertEqual(rows[1]['secondary_analysis']['reuse']['status'],'reused')
        self.assertTrue(rows[1]['secondary_analysis']['reuse']['source_rehashed'])
        self.assertEqual(self.cleaner.findings[0]['kind'],'review_binary')

    def test_same_size_changed_bytes_invalidate_cache(self):
        self.run_review();data=self.source.read_bytes()
        self.source.write_bytes(data[:-1]+b'X');self.run_review()
        self.assertEqual(self.pe.call_count,2);self.assertEqual(self.clam.call_count,2)

    def test_rules_assets_and_mode_each_invalidate_cache(self):
        self.run_review()
        with patch('local_rules.RULESET_VERSION','fixture-rules'):self.run_review()
        with patch.object(engines,'manifest',return_value={'versions':{'clamav':'changed'}}):self.run_review()
        self.cleaner.deep_analysis=True;self.run_review()
        self.assertEqual(self.pe.call_count,4)
        self.assertTrue(self.pe.call_args.kwargs['include_capabilities'])

    def test_incomplete_and_cancelled_results_never_reused(self):
        self.pe.return_value={'rea':{'status':'incomplete','reason':'fixture timeout'}}
        self.run_review();self.run_review()
        self.assertEqual(self.pe.call_count,2);self.assertTrue(self.cleaner.inspection_failed)
        self.assertEqual(self.cleaner._secondary_cache,{})
        self.cleaner.cancel.set();self.run_review()
        self.assertEqual(self.pe.call_count,2)

    def test_cached_negative_never_clears_current_office_parser_failure(self):
        self.source.write_bytes(b'INERT OFFICE')
        self.cleaner.findings=[{'kind':'review_office','path':str(self.source),'reason':'unknown'}]
        engines.enrich_reviews(self.cleaner)
        self.cleaner.findings=[{'kind':'review_office','path':str(self.source),'reason':'parser failed','analysis_error':True}]
        engines.enrich_reviews(self.cleaner)
        self.assertTrue(self.cleaner.inspection_failed)
        self.assertEqual(self.cleaner.findings[0]['secondary_analysis']['status'],'incomplete')

    def test_optional_capa_does_not_start_or_claim_execution(self):
        with patch.object(engines,'_tool',side_effect=lambda name:Path(name)) as tool, \
             patch.object(engines,'_json_command',return_value={'normalized_result':{'imports':[],'coverage':{'status':'complete'}}}) as command:
            result=REAL_PE_SECOND_OPINION(self.source,include_capabilities=False)
        self.assertEqual(result['capa']['status'],'not_requested')
        self.assertEqual(result['rea']['status'],'analyzed')
        self.assertEqual(command.call_count,1)
        self.assertFalse(any('capa' in call.args[0] for call in tool.call_args_list))


class AliasBoundaryTests(unittest.TestCase):
    def fixture(self,second_flags=0x42000040,first_flags=0x40000040,second_start=1200):
        data=bytearray(inert_pe(b'INERT'*350));struct.pack_into('<H',data,134,3)
        first=376;second=416;third=456
        struct.pack_into('<IIII',data,first+8,128,4096,128,512)
        struct.pack_into('<IIII',data,second+8,700,8192,700,700)
        struct.pack_into('<I',data,second+36,first_flags)
        struct.pack_into('<IIII',data,third+8,200,12288,200,second_start)
        struct.pack_into('<I',data,third+36,second_flags)
        return bytes(data)

    def test_only_readonly_nonexecutable_alias_is_accepted(self):
        result=family.inspect(self.fixture())
        self.assertEqual(result['status'],'no_known_match')
        self.assertEqual(len(result['readonly_section_aliases']),1)
        for flags in (0x60000040,0xC0000040,0x40000020):
            with self.subTest(flags=flags),self.assertRaises(ValueError):family.PE(self.fixture(second_flags=flags))

    def test_code_alias_with_enclosing_data_is_rejected(self):
        with self.assertRaises(ValueError):family.PE(self.fixture(second_flags=0x60000020,second_start=600))

    def test_restore_checks_alias_original_and_commits_once(self):
        import shutil
        from test_cleanup_audit import inert_cleaner
        for rejected in (False,True):
            with self.subTest(rejected=rejected),tempfile.TemporaryDirectory() as temp:
                root=Path(temp);wrapper=root/'inert-wrapper.exe';wrapper.write_bytes(b'INERT WRAPPER ONLY')
                original=root/'inert-original.bin';original.write_bytes(self.fixture(second_flags=0x60000040 if rejected else 0x42000040))
                c=inert_cleaner();events=[];c.log=lambda kind,**fields:events.append((kind,fields))
                class Resource:
                    def __init__(self,path):self.size=Path(path).stat().st_size
                    def __enter__(self):return self
                    def __exit__(self,*args):pass
                    def resource(self,name):return (0,original.stat().st_size)
                    def extract_resource(self,resource,destination):shutil.copyfile(original,destination)
                c.replace.side_effect=lambda destination,stage,expected=None:shutil.copyfile(stage,destination)
                with patch.object(recovery,'PEView',Resource),patch.object(recovery,'is_stub',side_effect=lambda p:Path(p)==wrapper and wrapper.stat().st_size<64):
                    if rejected:
                        with self.assertRaisesRegex(ValueError,'incomplete'):c.restore_executable(wrapper)
                        c.replace.assert_not_called();self.assertEqual(wrapper.read_bytes(),b'INERT WRAPPER ONLY')
                        self.assertTrue(any(kind=='executable_recovery_blocked' for kind,_ in events))
                    else:
                        c.restore_executable(wrapper);c.replace.assert_called_once()
                        self.assertEqual(wrapper.read_bytes(),original.read_bytes())
                self.assertEqual(list(root.glob('.wormrepair-*')),[])


class ErrorAggregationTests(unittest.TestCase):
    def test_duplicate_keeps_stage_counts_and_repair_failure_separate(self):
        c=recovery.Cleaner.__new__(recovery.Cleaner);c.errors=[];events=[]
        c.log=lambda kind,**row:events.append(copy.deepcopy(row))
        c.error('C:/inert','fixture unavailable')
        c._error_stage='verification';c.error('c:/INERT','fixture unavailable')
        self.assertEqual(len(c.errors),1);self.assertEqual(c.errors[0]['occurrences'],2)
        self.assertEqual(c.errors[0]['stages'],{'scan':1,'verification':1})
        c._error_stage='repair';c.error('C:/inert','fixture unavailable')
        self.assertEqual(len(c.errors),2);self.assertEqual(c.errors[1]['scope'],'repair_failed')
        self.assertEqual(len(events),3);self.assertEqual(events[0]['occurrences'],1)


if __name__=='__main__':unittest.main()
