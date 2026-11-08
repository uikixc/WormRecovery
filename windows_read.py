"""Read-only Win32 fallback for long paths and backup-privilege file access."""
import builtins
import ctypes
from ctypes import wintypes as W
import ntpath
import os


def extended_path(path):
    path=os.fspath(path)
    if os.name!='nt' or path.startswith('\\\\?\\'):return path
    absolute=ntpath.abspath(path)
    if len(absolute)<248:return path
    if absolute.startswith('\\\\'):return '\\\\?\\UNC\\'+absolute[2:]
    return '\\\\?\\'+absolute


def backup_read(path):
    import msvcrt
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,ctypes.c_void_p,W.DWORD,W.DWORD,W.HANDLE]
    kernel.CreateFileW.restype=W.HANDLE
    kernel.CloseHandle.argtypes=[W.HANDLE];kernel.CloseHandle.restype=W.BOOL
    # GENERIC_READ, share read/write/delete, OPEN_EXISTING; no write access.
    handle=kernel.CreateFileW(extended_path(path),0x80000000,7,None,3,0x02000000|0x08000000|0x00200000,None)
    if handle==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
    try:descriptor=msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY)
    except BaseException:kernel.CloseHandle(handle);raise
    try:return os.fdopen(descriptor,'rb')
    except BaseException:os.close(descriptor);raise


def open_read(path,mode='rb'):
    if mode!='rb':raise ValueError('只读检测接口仅支持 rb 模式。')
    try:return builtins.open(extended_path(path),'rb')
    except PermissionError:
        if os.name!='nt':raise
        return backup_read(path)


def locked_read(path):
    """Read lease that denies replacement/writes; callers may safely reuse bytes."""
    import msvcrt
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,ctypes.c_void_p,W.DWORD,W.DWORD,W.HANDLE]
    kernel.CreateFileW.restype=W.HANDLE
    kernel.CloseHandle.argtypes=[W.HANDLE];kernel.CloseHandle.restype=W.BOOL
    handle=kernel.CreateFileW(extended_path(path),0x80000000,1,None,3,0x02000000,None)
    if handle==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
    try:descriptor=msvcrt.open_osfhandle(handle,os.O_RDONLY|os.O_BINARY)
    except BaseException:kernel.CloseHandle(handle);raise
    try:return os.fdopen(descriptor,'rb')
    except BaseException:os.close(descriptor);raise
