import os
import subprocess
import sys
import time
import unittest
from unittest.mock import patch,Mock

from engine_process import start
from office_worker_transport import OfficeWorker


class WorkerTransportTests(unittest.TestCase):
    def worker(self,code):
        worker=OfficeWorker([sys.executable,'-u','-c',code],os.environ.copy())
        self.addCleanup(worker.close)
        return worker

    def test_multiple_requests_reuse_process_and_keep_frames_separate(self):
        worker=self.worker('import sys,json\nfor line in sys.stdin.buffer:\n print(json.dumps({"ok":True,"result":json.loads(line)}),flush=True)')
        first,one=worker.request({'fixture':'one'},5)
        second,two=worker.request({'fixture':'two'},5)
        self.assertIn(b'one',first);self.assertIn(b'two',second)
        self.assertEqual(one['process_id'],two['process_id'])
        self.assertEqual(two['request_number'],2)

    def test_timeout_terminates_owned_worker_with_bounded_wait(self):
        worker=self.worker('import sys,time\nfor line in sys.stdin.buffer:time.sleep(30)')
        tick=time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):worker.request({'fixture':'timeout'},0.2)
        self.assertLess(time.monotonic()-tick,4)
        self.assertIsNone(worker.process)

    def test_output_limit_is_an_explicit_failure(self):
        worker=self.worker('import sys\nfor line in sys.stdin.buffer:print("x"*(1024*1024+2),flush=True)')
        with self.assertRaisesRegex(RuntimeError,'资源上限'):worker.request({'fixture':'limit'},5)
        self.assertIsNone(worker.process)

    def test_exited_process_is_replaced_for_next_request(self):
        worker=self.worker('import sys,json\nline=sys.stdin.buffer.readline()\nprint(json.dumps({"ok":True,"result":{}}),flush=True)')
        _,first=worker.request({'fixture':'one'},5)
        worker.process.wait(timeout=3)
        _,second=worker.request({'fixture':'two'},5)
        self.assertNotEqual(first['process_id'],second['process_id'])

    def test_retry_is_limited_to_process_creation_denials(self):
        error=PermissionError('inert creation denial');error.winerror=5
        process=Mock()
        with patch('engine_process.subprocess.Popen',side_effect=[error,process]) as launch,patch('engine_process.time.sleep'):
            self.assertIs(start(['inert']),process)
            self.assertEqual(launch.call_count,2)
        with patch('engine_process.subprocess.Popen',side_effect=error) as launch,patch('engine_process.time.sleep'):
            with self.assertRaises(PermissionError):start(['inert'])
            self.assertEqual(launch.call_count,4)
        missing=FileNotFoundError('inert missing executable');missing.winerror=2
        with patch('engine_process.subprocess.Popen',side_effect=missing) as launch:
            with self.assertRaises(FileNotFoundError):start(['inert'])
            self.assertEqual(launch.call_count,1)


if __name__=='__main__':unittest.main()
