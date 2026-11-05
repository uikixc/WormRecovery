"""Bound native analysis worker lifetimes, including their child processes."""
import ctypes
from ctypes import wintypes as W
import os
import subprocess
import time


def _job(process):
    if os.name != 'nt':
        return None, None
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    class Basic(ctypes.Structure):
        _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
            ('flags', W.DWORD), ('min_working', ctypes.c_size_t), ('max_working', ctypes.c_size_t),
            ('active_processes', W.DWORD), ('affinity', ctypes.c_size_t),
            ('priority', W.DWORD), ('scheduling', W.DWORD)]
    class Counters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in ('read_ops', 'write_ops', 'other_ops', 'read_bytes', 'write_bytes', 'other_bytes')]
    class Extended(ctypes.Structure):
        _fields_ = [('basic', Basic), ('io', Counters), ('process_memory', ctypes.c_size_t),
            ('job_memory', ctypes.c_size_t), ('peak_process', ctypes.c_size_t), ('peak_job', ctypes.c_size_t)]
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, W.LPCWSTR]
    kernel.CreateJobObjectW.restype = W.HANDLE
    kernel.SetInformationJobObject.argtypes = [W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [W.HANDLE, W.HANDLE]
    kernel.CloseHandle.argtypes = [W.HANDLE]
    handle = kernel.CreateJobObjectW(None, None)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    limits = Extended()
    limits.basic.flags = 0x2000 | 0x200  # Kill all children when closed; total memory cap.
    limits.job_memory = 2 * 1024 * 1024 * 1024
    if not kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)) or not kernel.AssignProcessToJobObject(handle, W.HANDLE(int(process._handle))):
        error = ctypes.get_last_error()
        kernel.CloseHandle(handle)
        raise ctypes.WinError(error)
    return kernel, handle


def run(command, *, timeout, input=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=None, cancel=None):
    process = subprocess.Popen(command, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
        stdout=stdout, stderr=stderr, env=env, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    kernel = handle = None
    started = time.monotonic()
    try:
        kernel, handle = _job(process)
        payload = input
        while True:
            if cancel is not None and cancel.is_set():
                raise InterruptedError('离线分析已停止。')
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, timeout)
            try:
                output, errors = process.communicate(input=payload, timeout=min(0.25, remaining))
                return subprocess.CompletedProcess(command, process.returncode, output, errors)
            except subprocess.TimeoutExpired:
                payload = None
    finally:
        if handle:
            kernel.CloseHandle(handle)
        if process.poll() is None:
            process.kill()
        try:process.communicate(timeout=2)
        except (subprocess.TimeoutExpired,OSError):
            # Never let inherited pipe handles turn cleanup into an endless wait.
            for stream in (process.stdin,process.stdout,process.stderr):
                if stream:
                    reader=getattr(process,'_stdout_thread',None) if stream is process.stdout else getattr(process,'_stderr_thread',None) if stream is process.stderr else None
                    if reader is not None and reader.is_alive():continue
                    try:stream.close()
                    except OSError:pass
