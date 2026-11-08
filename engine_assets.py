"""Locate version-pinned offline engines shipped inside the single EXE."""
from pathlib import Path
import json
import functools
import os
import sys
import tempfile
import atexit
import shutil
import threading

_optional_root=None
_optional_guard=threading.Lock()


def engine_root():
    if _optional_root is not None:return _optional_root
    if getattr(sys, '_MEIPASS', None):
        candidate = Path(sys._MEIPASS) / 'engines'
        if (candidate / 'manifest.json').is_file():
            return candidate
    inherited = os.environ.get('WORMRECOVERY_ENGINE_ROOT')
    if inherited and (Path(inherited) / 'manifest.json').is_file():
        return Path(inherited)
    return Path(__file__).parent / 'build/engine-assets/engines'


def prepare_optional_engines():
    """Ask the authenticated outer launcher to verify and hold optional files."""
    global _optional_root
    if not getattr(sys,'frozen',False) or not os.environ.get('WORMRECOVERY_ENGINE_PIPE'):return engine_root()
    with _optional_guard:
        if _optional_root is not None:return _optional_root
        import ctypes,re
        from ctypes import wintypes as W
        from runtime_identity import application_path
        if application_path()==Path(sys.executable).resolve():raise ValueError('无法验证离线组件启动器身份。')
        name=os.environ['WORMRECOVERY_ENGINE_PIPE']
        if not re.fullmatch(r'WormRecovery-[0-9a-f]{32}',name):raise ValueError('离线组件通道无效。')
        kernel=ctypes.WinDLL('kernel32',use_last_error=True)
        kernel.WaitNamedPipeW.argtypes=[W.LPCWSTR,W.DWORD];kernel.WaitNamedPipeW.restype=W.BOOL
        kernel.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,ctypes.c_void_p,W.DWORD,W.DWORD,W.HANDLE];kernel.CreateFileW.restype=W.HANDLE
        kernel.CloseHandle.argtypes=[W.HANDLE]
        kernel.GetNamedPipeServerProcessId.argtypes=[W.HANDLE,ctypes.POINTER(W.ULONG)];kernel.GetNamedPipeServerProcessId.restype=W.BOOL
        kernel.ReadFile.argtypes=[W.HANDLE,ctypes.c_void_p,W.DWORD,ctypes.POINTER(W.DWORD),ctypes.c_void_p];kernel.ReadFile.restype=W.BOOL
        pipe='\\\\.\\pipe\\'+name
        if not kernel.WaitNamedPipeW(pipe,30000):raise ctypes.WinError(ctypes.get_last_error())
        handle=kernel.CreateFileW(pipe,0xC0000000,0,None,3,0,None)
        if handle==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
        try:
            pid=W.ULONG()
            if not kernel.GetNamedPipeServerProcessId(handle,ctypes.byref(pid)) or pid.value!=int(os.environ['WORMRECOVERY_LAUNCHER_PID']):
                raise ValueError('离线组件通道不属于当前启动器。')
            response=bytearray();buffer=ctypes.create_string_buffer(4096);count=W.DWORD()
            while b'\n' not in response:
                if not kernel.ReadFile(handle,buffer,len(buffer),ctypes.byref(count),None):raise ctypes.WinError(ctypes.get_last_error())
                if not count.value or len(response)+count.value>65536:raise ValueError('离线组件启动器响应无效。')
                response.extend(buffer.raw[:count.value])
            message=response.decode('utf-8').strip()
            if not message.startswith('OK\t'):raise RuntimeError(message.partition('\t')[2] or '离线组件准备失败。')
            root=Path(message[3:]).resolve();cache=Path(os.environ['WORMRECOVERY_RUNTIME_ROOT']).resolve().parent
            if root.parts[-2:]!=('_internal','engines') or root.parents[2]!=cache or not re.fullmatch('[0-9a-f]{64}',root.parents[1].name):
                raise ValueError('离线组件目录无效。')
            _optional_root=root
            return root
        finally:kernel.CloseHandle(handle)


@functools.lru_cache(maxsize=4)
def _manifest(root):
    path = Path(root) / 'manifest.json'
    return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else {}


def manifest():
    return _manifest(str(engine_root()))


@functools.lru_cache(maxsize=1)
def _cached_runtime_work():
    root=tempfile.mkdtemp(prefix='WormRecovery-worker-')
    atexit.register(shutil.rmtree,root,ignore_errors=True)
    return root


def subprocess_environment(independent=False):
    environment = os.environ.copy()
    if independent:
        # A different packaged program must not inherit another bootloader's
        # private process level, archive or DLL extraction state.
        for name in list(environment):
            if name.startswith('_PYI_') or name=='_MEIPASS2':environment.pop(name,None)
        environment['PYINSTALLER_RESET_ENVIRONMENT']='1'
    environment['WORMRECOVERY_ENGINE_ROOT'] = str(engine_root())
    environment['PYTHONIOENCODING'] = 'utf-8'
    work_root = environment.get('WORMRECOVERY_WORK_ROOT')
    if not work_root and getattr(sys, '_MEIPASS', None):
        work_root = _cached_runtime_work() if environment.get('WORMRECOVERY_RUNTIME_ROOT') else str(Path(sys._MEIPASS) / 'worker-temp')
    if work_root:
        Path(work_root).mkdir(parents=True, exist_ok=True)
        environment['WORMRECOVERY_WORK_ROOT'] = work_root
        environment['TEMP'] = work_root
        environment['TMP'] = work_root
    return environment
