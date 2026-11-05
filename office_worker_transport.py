"""Bounded, reusable Office parser transport. Document bytes never execute."""
import atexit
import json
import queue
import subprocess
import threading
import time

from engine_process import start, _job

MAX_RESPONSE = 1024 * 1024


class OfficeWorker:
    def __init__(self, command, environment):
        self.command, self.environment = command, environment
        self.process = self.kernel = self.handle = None
        self.responses = queue.Queue(maxsize=2)
        self.errors = bytearray()
        self.count = 0
        self.lock = threading.Lock()

    def launch(self):
        process = start(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, env=self.environment,
                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        self.process = process
        try:
            self.kernel, self.handle = _job(process)
        except Exception:
            self.close()
            raise
        responses, errors = self.responses, self.errors

        def read_output():
            try:
                while True:
                    line = process.stdout.readline(MAX_RESPONSE + 2)
                    if not line:
                        responses.put(('error', '分析工作进程已退出。'))
                        return
                    if len(line) > MAX_RESPONSE or not line.endswith(b'\n'):
                        responses.put(('error', '分析结果超过资源上限或传输不完整。'))
                        return
                    responses.put(('response', line))
            except (OSError, ValueError) as error:
                try:responses.put_nowait(('error', str(error)))
                except queue.Full:pass

        def read_errors():
            try:
                while block := process.stderr.read(4096):
                    errors.extend(block)
                    if len(errors) > 65536:del errors[:-65536]
            except (OSError, ValueError):pass

        threading.Thread(target=read_output, daemon=True, name='Office-Output').start()
        threading.Thread(target=read_errors, daemon=True, name='Office-Diagnostics').start()

    def request(self, document, timeout):
        with self.lock:
            if self.process is None or self.process.poll() is not None or self.count >= 64:
                self.close()
                self.responses = queue.Queue(maxsize=2)
                self.errors = bytearray()
                self.count = 0
                self.launch()
            process, responses = self.process, self.responses
            payload = json.dumps(document, ensure_ascii=True, separators=(',', ':')).encode('ascii') + b'\n'
            started = time.monotonic()

            def write_request():
                try:
                    process.stdin.write(payload)
                    process.stdin.flush()
                except (OSError, ValueError) as error:
                    try:responses.put_nowait(('error', str(error)))
                    except queue.Full:pass

            threading.Thread(target=write_request, daemon=True, name='Office-Input').start()
            try:
                kind, value = responses.get(timeout=max(0.001, timeout - (time.monotonic() - started)))
                if kind != 'response':
                    detail = bytes(self.errors).decode('utf-8', 'replace')[-700:]
                    raise RuntimeError(value + (' ' + detail if detail else ''))
                self.count += 1
                return value, {'transport': 'persistent_bytes', 'process_id': process.pid,
                               'request_number': self.count}
            except queue.Empty:
                self.close()
                raise subprocess.TimeoutExpired(self.command, timeout) from None
            except BaseException:
                self.close()
                raise

    def close(self):
        process, handle = self.process, self.handle
        self.process = self.handle = None
        if handle:
            self.kernel.CloseHandle(handle)
        if process:
            if process.poll() is None:
                try:process.kill()
                except OSError:pass
            try:process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):pass
            # Do not synchronously close handles still owned by blocked readers.
            for stream in (process.stdin,):
                if stream and process.poll() is not None:
                    try:stream.close()
                    except (OSError, ValueError):pass


_worker = None
_configuration = None
_lock = threading.Lock()


def request(command, environment, document, timeout):
    global _worker, _configuration
    configuration = (tuple(command), environment.get('WORMRECOVERY_ENGINE_ROOT'),
                     environment.get('WORMRECOVERY_WORK_ROOT'))
    with _lock:
        if _worker is None or _configuration != configuration:
            if _worker:_worker.close()
            _worker = OfficeWorker(command, environment)
            _configuration = configuration
        return _worker.request(document, timeout)


def close():
    global _worker, _configuration
    with _lock:
        if _worker:_worker.close()
        _worker = _configuration = None


atexit.register(close)
