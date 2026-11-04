"""Exercise the real parser import in a fresh process without console streams."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import worm_recovery as w


class WindowlessTests(unittest.TestCase):
    def test_real_parser_import_with_missing_console_streams(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'result.json'
            script = r'''
import json, pathlib, sys
output = pathlib.Path(sys.argv[1])
sys.stdout = None
sys.stderr = None
import worm_recovery as w
from oletools.olevba import VBA_Parser
sys.stdout.flush()
sys.stderr.flush()
output.write_text(json.dumps({'windowless': w.WINDOWLESS, 'parser': VBA_Parser.__name__}), encoding='utf-8')
'''
            result = subprocess.run([sys.executable, '-c', script, str(output)], cwd=Path(w.__file__).parent, capture_output=True, timeout=45)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertEqual(json.loads(output.read_text(encoding='utf-8')), {'windowless': True, 'parser': 'VBA_Parser'})

    def test_parser_failure_is_explicit_review(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'fixture.xlsm'
            with zipfile.ZipFile(path, 'w') as package:
                package.writestr('xl/workbook.xml', '<workbook/>')
                package.writestr('xl/vbaProject.bin', b'Inert invalid parser fixture')
            with patch('office_analysis.analyze_project', side_effect=RuntimeError('fixture parser failure')):
                result = w.office_check(path)
            self.assertEqual(result['status'], 'review')
            self.assertTrue(result['analysis_error'])
            self.assertIn('fixture parser failure', result['reason'])

    def test_scan_records_parser_failure_and_blocks_completion(self):
        cleaner=w.Cleaner.__new__(w.Cleaner)
        cleaner.count=0
        cleaner.scanned_office=0
        cleaner.inspection_failed=False
        cleaner.findings=[]
        cleaner.errors=[]
        cleaner.add=lambda kind,path,**info:cleaner.findings.append({'kind':kind,'path':path,**info})
        cleaner.error=lambda path,error:cleaner.errors.append({'path':path,'error':error})
        with patch.object(w,'office_check',return_value={'status':'review','analysis_error':True,'reason':'fixture failure'}):
            cleaner.scan_file('C:/fixture.xlsm',None)
        self.assertTrue(cleaner.inspection_failed)
        self.assertEqual(cleaner.findings[0]['kind'],'review_office')
        self.assertEqual(len(cleaner.errors),1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
