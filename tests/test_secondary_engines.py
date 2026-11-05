"""Offline-engine regressions using inert documents and fabricated engine output."""
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
import builtins
from unittest.mock import patch
import zipfile

import local_rules
import secondary_analysis as engines
import worm_recovery as recovery


def write_xlm_fixture(path):
    parts = {
        '[Content_Types].xml': '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/><Override PartName="/xl/macrosheets/sheet1.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/></Types>',
        'xl/workbook.xml': '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Macro1" sheetId="1" r:id="rId1"/></sheets><definedNames><definedName name="_xlnm.Auto_Open">Macro1!$A$1</definedName></definedNames></workbook>',
        'xl/_rels/workbook.xml.rels': '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet" Target="macrosheets/sheet1.xml"/></Relationships>',
        'xl/macrosheets/sheet1.xml': '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1"><f>HALT()</f><v>0</v></c></row></sheetData></worksheet>',
    }
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, value in parts.items():
            archive.writestr(name, value)


class ContentRuleTests(unittest.TestCase):
    def test_binary_detector_reads_exact_size_once_and_preserves_match(self):
        content=b'Harmless fixture Synaptics ~$cache1 RegKeySave Workbook_Open'
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'fixture.exe';path.write_bytes(content)
            with patch('builtins.open',wraps=builtins.open) as opening:
                result=recovery.inspect_file_content(str(path),path.stat())
            self.assertEqual(opening.call_count,1)
            self.assertEqual(result['findings'][0]['kind'],'review_binary')
            self.assertEqual(path.read_bytes(),content)

    def test_binary_size_change_cannot_return_clean(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'changed.exe';path.write_bytes(b'inert')
            fake=SimpleNamespace(st_size=2)
            with self.assertRaisesRegex(ValueError,'文件大小发生变化'):
                recovery.inspect_file_content(str(path),fake)

    def test_file_scan_does_not_perform_extra_empty_content_scan(self):
        with patch.object(local_rules,'scan_bytes',side_effect=AssertionError('redundant scan')):
            with tempfile.TemporaryDirectory() as temp:
                path=Path(temp)/'inert.txt';path.write_bytes(b'inert text')
                self.assertEqual(local_rules.scan_file(path)['matches'],[])

    def test_name_alone_never_matches_family_rule(self):
        self.assertEqual(local_rules.scan_bytes(b'GoogleChrome MozillaFirefox Synaptics')['matches'], [])

    def test_ascii_and_wide_family_combinations(self):
        content = 'Synaptics ~$cache1 RegKeySave Workbook_Open'
        for encoding in ('ascii', 'utf-16-le'):
            with self.subTest(encoding=encoding):
                self.assertIn('WR_Synaptics_Excel_Replication', local_rules.scan_bytes(content.encode(encoding))['matches'])

    def test_native_file_scan_matches_byte_scan(self):
        content = b'AutoIt3ExecuteScript GoogleChrome.a3x cmd.exe'
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'Chinese-name-fixture.txt'
            path.write_bytes(content)
            self.assertEqual(local_rules.scan_file(path)['matches'], local_rules.scan_bytes(content)['matches'])


class EngineResultTests(unittest.TestCase):
    def test_pe_cancellation_does_not_start_following_engine(self):
        cancel=threading.Event();stages=[]
        def stop(*args,**kwargs):
            self.assertIs(kwargs['cancel'],cancel);cancel.set();raise InterruptedError('stopped')
        with patch.object(engines,'_tool',return_value=Path('fixture')),patch.object(engines,'_json_command',side_effect=stop) as command:
            with self.assertRaises(InterruptedError):
                engines.pe_second_opinion(Path('fixture.exe'),cancel=cancel,progress=stages.append)
        self.assertEqual(command.call_count,1);self.assertEqual(len(stages),1)

    def test_snapshot_cancelled_before_copy_does_not_read_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'source';target=root/'copy';source.write_bytes(b'inert')
            cancel=threading.Event();cancel.set()
            with self.assertRaises(InterruptedError):engines.snapshot_file(source,target,cancel)
            self.assertEqual(source.read_bytes(),b'inert');self.assertEqual(target.read_bytes(),b'')

    def test_review_progress_reports_batch_and_completed_candidates(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);source=root/'inert.txt';source.write_bytes(b'inert content')
            phases=[];row={'kind':'review_script','path':str(source)}
            cleaner=SimpleNamespace(findings=[row],cancel=threading.Event(),run=root,
                policy=SimpleNamespace(check=lambda _:None),protected_path=lambda _:False,
                emit=lambda _:None,log=lambda kind,**data:phases.append(data) if kind=='scan_phase' else None,
                error=lambda *args:None,inspection_failed=False)
            def scan(paths,work,**kwargs):return {str(p):{'status':'no_match'} for p in paths},{}
            with patch.object(engines,'clam_batch',side_effect=scan):engines.enrich_reviews(cleaner)
            self.assertTrue(any(p['timeout']==180 for p in phases))
            self.assertEqual(phases[-1]['completed'],1);self.assertEqual(phases[-1]['total'],1)

    def test_cancelled_batch_marks_every_unprocessed_candidate_incomplete(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);paths=[root/'a.txt',root/'b.txt']
            for path in paths:path.write_bytes(b'inert')
            rows=[{'kind':'review_script','path':str(path)} for path in paths]
            cleaner=SimpleNamespace(findings=rows,cancel=threading.Event(),run=root,
                policy=SimpleNamespace(check=lambda _:None),protected_path=lambda _:False,
                emit=lambda _:None,log=lambda *a,**kw:None,error=lambda *a:None,inspection_failed=False)
            def stop(*args,**kwargs):cleaner.cancel.set();raise InterruptedError('stopped')
            with patch.object(engines,'clam_batch',side_effect=stop):engines.enrich_reviews(cleaner)
            self.assertTrue(cleaner.inspection_failed)
            self.assertTrue(all(row['secondary_analysis']['status']=='incomplete' for row in rows))

    def clam_result(self, message, code=0):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            database = root / 'clamdb'
            database.mkdir()
            for name in ('main.cvd', 'daily.cvd', 'bytecode.cvd'):
                (database / name).write_bytes(b'ClamAV-VDB:03 Nov 2026 08-00 +0000:1:123:90:fixture')
            sample = root / 'fixture with spaces.txt'
            sample.write_text('inert')
            def run(command, **kwargs):
                kwargs['stdout'].write((str(sample) + ': ' + message + '\n').encode())
                return SimpleNamespace(returncode=code)
            with patch.object(engines, '_tool', return_value=root / 'clamscan.exe'), patch.object(engines, 'engine_root', return_value=root), patch.object(engines, 'run_engine', side_effect=run):
                rows, databases = engines.clam_batch([sample], root)
            return rows[str(sample)]

    def test_clam_no_match_is_not_infection(self):
        self.assertEqual(self.clam_result('OK')['status'], 'no_match')

    def test_clam_detection_is_preserved(self):
        result = self.clam_result('Synthetic.Test.Identifier FOUND', 1)
        self.assertEqual(result['status'], 'detected')
        self.assertEqual(result['detections'], ['Synthetic.Test.Identifier'])

    def test_clam_limit_cannot_be_reported_as_completed(self):
        self.assertEqual(self.clam_result('Heuristics.Limits.Exceeded.MaxFileSize FOUND', 1)['status'], 'incomplete')

    def test_clam_failed_exit_cannot_be_reported_clean(self):
        with self.assertRaisesRegex(ValueError, '退出码'):
            self.clam_result('engine failed ERROR', 2)

    def test_capa_timeout_is_explicit_and_does_not_suppress_rea(self):
        rea = {'normalized_result': {'coverage': {'status': 'complete'}, 'imports': []}}
        with patch.object(engines, '_tool', side_effect=lambda x: Path(x)), patch.object(engines, '_json_command', side_effect=[subprocess.TimeoutExpired('capa', 25), rea]):
            result = engines.pe_second_opinion(Path('fixture.exe'))
        self.assertEqual(result['capa']['status'], 'incomplete')
        self.assertIn('timed out', result['capa']['reason'])
        self.assertEqual(result['rea']['status'], 'analyzed')

    def test_missing_component_is_explicit_failure(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(engines, 'engine_root', return_value=Path(temp)), patch.object(engines, 'manifest', return_value={}):
            with self.assertRaises(FileNotFoundError):
                engines._tool('capa/capa.exe')

    def test_modified_component_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'fixture.exe').write_bytes(b'inert modified component')
            with patch.object(engines, 'engine_root', return_value=root), patch.object(engines, 'manifest', return_value={'files': {'fixture.exe': {'sha256': '0' * 64}}}):
                with self.assertRaisesRegex(ValueError, '完整性'):
                    engines._tool('fixture.exe')

    def test_real_xlm_parser_reads_halt_without_modifying_document(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'inert-xlm.xlsm'
            write_xlm_fixture(path)
            before = path.read_bytes()
            result = engines.parser_request('xlm', path)
            self.assertEqual(result['status'], 'analyzed', result)
            self.assertGreater(result['extracted_records'], 0)
            self.assertGreater(result['emulated_records'], 0)
            self.assertIn('HALT(', result['actions'])
            self.assertEqual(path.read_bytes(), before)

    def test_unknown_macro_survives_second_opinion_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document = root / 'inert-macro.xlsm'
            document.write_bytes(b'not executable; inert unknown content')
            row = {'kind': 'review_office', 'path': str(document), 'reason': 'Unknown macro'}
            cleaner = SimpleNamespace(findings=[row], cancel=threading.Event(), run=root,
                policy=SimpleNamespace(check=lambda _: None), protected_path=lambda _: False,
                emit=lambda _: None, log=lambda *a, **kw: None, error=lambda *a: None,
                inspection_failed=False)
            original = document.read_bytes()
            def scan(paths, work, **kwargs):
                return {str(p): {'status': 'no_match', 'detections': []} for p in paths}, {}
            with patch.object(engines, 'clam_batch', side_effect=scan):
                engines.enrich_reviews(cleaner)
            self.assertEqual(row['kind'], 'review_office')
            self.assertTrue(row['kind'].startswith('review_'))
            self.assertEqual(row['secondary_analysis']['status'], 'no_known_match')
            self.assertEqual(document.read_bytes(), original)
            self.assertFalse(any(root.glob('engine-review-*')))

    def test_clam_no_match_does_not_hide_office_parser_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document = root / 'inert-invalid.xlsm'
            document.write_bytes(b'inert malformed document')
            row = {'kind': 'review_office', 'path': str(document), 'reason': 'parser failure', 'analysis_error': True}
            cleaner = SimpleNamespace(findings=[row], cancel=threading.Event(), run=root,
                policy=SimpleNamespace(check=lambda _: None), protected_path=lambda _: False,
                emit=lambda _: None, log=lambda *a, **kw: None, error=lambda *a: None,
                inspection_failed=False)
            def scan(paths, work, **kwargs):
                return {str(p): {'status': 'no_match', 'detections': []} for p in paths}, {}
            with patch.object(engines, 'clam_batch', side_effect=scan):
                engines.enrich_reviews(cleaner)
            self.assertEqual(row['secondary_analysis']['status'], 'incomplete')
            self.assertIn('office_parser', row['analysis_incomplete_engines'])
            self.assertTrue(cleaner.inspection_failed)


if __name__ == '__main__':
    unittest.main()
