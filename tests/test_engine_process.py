import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock,patch

import psutil
from engine_process import run


class EngineProcessTests(unittest.TestCase):
    def test_cleanup_pipe_wait_is_bounded_and_does_not_close_live_reader(self):
        process=Mock();process.poll.return_value=0
        process._stdout_thread.is_alive.return_value=True
        process._stderr_thread.is_alive.return_value=False
        process.communicate.side_effect=[(b'ok',b''),subprocess.TimeoutExpired('fixture',2)]
        with patch('engine_process.subprocess.Popen',return_value=process),patch('engine_process._job',return_value=(None,None)):
            result=run(['inert fixture'],timeout=5)
        self.assertEqual(result.stdout,b'ok')
        self.assertEqual(process.communicate.call_args.kwargs['timeout'],2)
        process.stdout.close.assert_not_called()
        process.stderr.close.assert_called_once()

    def test_json_transport_and_stdin(self):
        result = run([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(sys.stdin.buffer.read().upper())'], input=b'inert transport', timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b'INERT TRANSPORT')

    def test_cancelled_request_stops_worker(self):
        cancelled = threading.Event()
        cancelled.set()
        with self.assertRaises(InterruptedError):
            run([sys.executable, '-c', 'import time; time.sleep(10)'], timeout=5, cancel=cancelled)

    @unittest.skipUnless(os.name == 'nt', 'Windows job-object lifecycle')
    def test_timeout_closes_grandchild_process(self):
        with tempfile.TemporaryDirectory() as temp:
            pidfile = Path(temp) / 'child.pid'
            code = 'import subprocess,sys,time; from pathlib import Path; child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"]); Path(sys.argv[1]).write_text(str(child.pid)); time.sleep(30)'
            with self.assertRaises(subprocess.TimeoutExpired):
                run([sys.executable, '-c', code, str(pidfile)], timeout=1)
            self.assertTrue(pidfile.exists())
            pid = int(pidfile.read_text())
            if psutil.pid_exists(pid):
                try:
                    psutil.Process(pid).wait(timeout=3)
                except psutil.NoSuchProcess:
                    pass
            self.assertFalse(psutil.pid_exists(pid))


if __name__ == '__main__':
    unittest.main()
