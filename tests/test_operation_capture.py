import copy
import json
from pathlib import Path
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

from operation_capture import execute
import diagnostic_bundle


class OperationCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.cleaner=types.SimpleNamespace(run=self.root,cancel=threading.Event(),errors=[],inspection_failed=False,findings=[],events=[])
        def log(kind,**fields):
            event={'kind':kind,**fields};self.cleaner.events.append(copy.deepcopy(event))
            with (self.root/'journal.jsonl').open('a',encoding='utf-8') as stream:stream.write(json.dumps(event)+'\n')
        def save():
            record={'version':'test','operation':self.cleaner.operation,'findings':self.cleaner.findings,'events':self.cleaner.events,'errors':self.cleaner.errors}
            (self.root/'report.json').write_text(json.dumps(record),encoding='utf-8')
        self.cleaner.log=log;self.cleaner.save=save
    def tearDown(self):self.temp.cleanup()
    def test_scan_and_repair_snapshots_queued_separately_before_overwrite(self):
        received=[]
        def collect(path,**kwargs):
            received.append((json.loads(Path(path).read_text()),Path(path).with_name('journal.jsonl').read_text()))
        with patch('diagnostic_client.collect',side_effect=collect),patch('diagnostic_client.schedule'):
            execute(self.cleaner,'scan',lambda:self.cleaner.findings.append({'kind':'review_office','path':'C:/inert.xlsm'}))
            execute(self.cleaner,'repair',lambda:self.cleaner.findings.clear())
        scan,repair=[item[0] for item in received]
        self.assertEqual(scan['operation']['type'],'scan');self.assertFalse(scan['operation']['mutations_allowed'])
        self.assertEqual(repair['operation']['type'],'repair');self.assertTrue(repair['operation']['mutations_allowed'])
        self.assertEqual(scan['operation']['session_id'],repair['operation']['session_id'])
        self.assertNotEqual(scan['operation']['id'],repair['operation']['id'])
        self.assertEqual(len(scan['findings']),1);self.assertEqual(repair['findings'],[])
        self.assertEqual(len(list((self.root/'operations').glob('*/report.json'))),2)
        self.assertIn('operation_finished',received[0][1])
    def test_failed_scan_still_has_report_and_journal(self):
        def fail():raise ValueError('inert parser failure')
        with patch('diagnostic_client.collect') as collect,patch('diagnostic_client.schedule'),self.assertRaises(ValueError):
            execute(self.cleaner,'scan',fail)
        path=Path(collect.call_args.args[0]);record=json.loads(path.read_text())
        self.assertEqual(record['operation']['status'],'failed');self.assertEqual(record['operation']['error_type'],'ValueError')
        self.assertIn('inert parser failure',path.with_name('journal.jsonl').read_text())
    def test_cancelled_operation_is_distinct_from_success(self):
        with patch('diagnostic_client.collect') as collect,patch('diagnostic_client.schedule'):
            execute(self.cleaner,'scan',lambda:self.cleaner.cancel.set())
        record=json.loads(Path(collect.call_args.args[0]).read_text());self.assertEqual(record['operation']['status'],'cancelled')
    def test_capture_failure_does_not_change_completed_scan_result(self):
        with patch('diagnostic_client.collect',side_effect=OSError('inert queue failure')):
            self.assertEqual(execute(self.cleaner,'scan',lambda:42),42)
        self.assertTrue(any(x['kind']=='diagnostic_capture_error' for x in self.cleaner.events))
    def test_operation_identity_reaches_upload_bundle(self):
        with patch('diagnostic_client.collect'),patch('diagnostic_client.schedule'):
            execute(self.cleaner,'scan',lambda:None)
        path=next((self.root/'operations').glob('*/report.json'))
        bundle,_=diagnostic_bundle.build_bundle(path,state=self.root/'state')
        self.assertEqual(bundle['operation']['type'],'scan');self.assertEqual(bundle['operation']['status'],'completed')


if __name__=='__main__':unittest.main(verbosity=2)
