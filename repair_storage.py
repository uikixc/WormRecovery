"""Private, same-volume storage for original bytes; never copy file payloads."""
import ctypes
from ctypes import wintypes as W
import os
from pathlib import Path

from windows_read import extended_path


QUARANTINE_NAME='WormRecoveryQuarantine'
PRIVATE_FILE_SDDL='O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)'


def file_security(path):
    api=ctypes.WinDLL('advapi32',use_last_error=True)
    api.GetFileSecurityW.argtypes=[W.LPCWSTR,W.DWORD,ctypes.c_void_p,W.DWORD,ctypes.POINTER(W.DWORD)]
    api.GetFileSecurityW.restype=W.BOOL
    needed=W.DWORD();api.GetFileSecurityW(extended_path(path),5,None,0,ctypes.byref(needed))
    if not needed.value:raise ctypes.WinError(ctypes.get_last_error())
    result=ctypes.create_string_buffer(needed.value)
    if not api.GetFileSecurityW(extended_path(path),5,result,len(result),ctypes.byref(needed)):raise ctypes.WinError(ctypes.get_last_error())
    return result.raw


def restore_security(path,descriptor):
    api=ctypes.WinDLL('advapi32',use_last_error=True)
    api.GetSecurityDescriptorControl.argtypes=[ctypes.c_void_p,ctypes.POINTER(W.WORD),ctypes.POINTER(W.DWORD)]
    api.GetSecurityDescriptorControl.restype=W.BOOL
    control=W.WORD();revision=W.DWORD();buffer=ctypes.create_string_buffer(descriptor)
    if not api.GetSecurityDescriptorControl(buffer,ctypes.byref(control),ctypes.byref(revision)):raise ctypes.WinError(ctypes.get_last_error())
    api.SetFileSecurityW.argtypes=[W.LPCWSTR,W.DWORD,ctypes.c_void_p];api.SetFileSecurityW.restype=W.BOOL
    flags=5|(0x80000000 if control.value&0x1000 else 0x20000000)
    if not api.SetFileSecurityW(extended_path(path),flags,buffer):raise ctypes.WinError(ctypes.get_last_error())


def private_file(path):
    api=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    api.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[W.LPCWSTR,W.DWORD,ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p]
    api.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype=W.BOOL
    api.SetFileSecurityW.argtypes=[W.LPCWSTR,W.DWORD,ctypes.c_void_p];api.SetFileSecurityW.restype=W.BOOL
    kernel.LocalFree.argtypes=[ctypes.c_void_p]
    descriptor=ctypes.c_void_p()
    if not api.ConvertStringSecurityDescriptorToSecurityDescriptorW(PRIVATE_FILE_SDDL,1,ctypes.byref(descriptor),None):raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not api.SetFileSecurityW(extended_path(path),0x80000005,descriptor):raise ctypes.WinError(ctypes.get_last_error())
    finally:kernel.LocalFree(descriptor)
    _validate_private_security(path)


def private_directory(path,*,create=True):
    """Create or validate an administrator/SYSTEM-only ordinary directory."""
    path=Path(path)
    for parent in path.parents:
        st=os.stat(extended_path(parent),follow_symlinks=False)
        if getattr(st,'st_file_attributes',0)&0x400:raise PermissionError('隔离目录路径包含重解析点。')
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    security=ctypes.WinDLL('advapi32',use_last_error=True)
    class Attributes(ctypes.Structure):
        _fields_=[('length',W.DWORD),('descriptor',ctypes.c_void_p),('inherit',W.BOOL)]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[W.LPCWSTR,W.DWORD,ctypes.POINTER(ctypes.c_void_p),ctypes.c_void_p]
    security.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype=W.BOOL
    kernel.CreateDirectoryW.argtypes=[W.LPCWSTR,ctypes.POINTER(Attributes)];kernel.CreateDirectoryW.restype=W.BOOL
    kernel.LocalFree.argtypes=[ctypes.c_void_p]
    descriptor=ctypes.c_void_p()
    if not security.ConvertStringSecurityDescriptorToSecurityDescriptorW('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)',1,ctypes.byref(descriptor),None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        attributes=Attributes(ctypes.sizeof(Attributes),descriptor,False)
        if create and not kernel.CreateDirectoryW(extended_path(path),ctypes.byref(attributes)) and ctypes.get_last_error()!=183:
            raise ctypes.WinError(ctypes.get_last_error())
    finally:kernel.LocalFree(descriptor)
    for parent in (path,*path.parents):
        st=os.stat(extended_path(parent),follow_symlinks=False)
        if getattr(st,'st_file_attributes',0)&0x400:raise PermissionError('隔离目录路径包含重解析点。')
    if not path.is_dir():raise NotADirectoryError(str(path))
    _validate_private_security(path)
    return path


def _validate_private_security(path):
    security=ctypes.WinDLL('advapi32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.LocalFree.argtypes=[ctypes.c_void_p]
    class AclInfo(ctypes.Structure):
        _fields_=[('count',W.DWORD),('used',W.DWORD),('free',W.DWORD)]
    security.GetFileSecurityW.argtypes=[W.LPCWSTR,W.DWORD,ctypes.c_void_p,W.DWORD,ctypes.POINTER(W.DWORD)]
    security.GetFileSecurityW.restype=W.BOOL
    needed=W.DWORD();security.GetFileSecurityW(extended_path(path),5,None,0,ctypes.byref(needed))
    if not needed.value:raise ctypes.WinError(ctypes.get_last_error())
    buffer=ctypes.create_string_buffer(needed.value)
    if not security.GetFileSecurityW(extended_path(path),5,buffer,len(buffer),ctypes.byref(needed)):raise ctypes.WinError(ctypes.get_last_error())
    security.ConvertSidToStringSidW.argtypes=[ctypes.c_void_p,ctypes.POINTER(W.LPWSTR)];security.ConvertSidToStringSidW.restype=W.BOOL
    def sid_text(sid):
        text=W.LPWSTR()
        if not security.ConvertSidToStringSidW(sid,ctypes.byref(text)):raise ctypes.WinError(ctypes.get_last_error())
        try:return text.value
        finally:kernel.LocalFree(ctypes.cast(text,ctypes.c_void_p))
    trusted={'S-1-5-18','S-1-5-32-544'}
    owner=ctypes.c_void_p();defaulted=W.BOOL()
    security.GetSecurityDescriptorOwner.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(W.BOOL)]
    security.GetSecurityDescriptorOwner.restype=W.BOOL
    if not security.GetSecurityDescriptorOwner(buffer,ctypes.byref(owner),ctypes.byref(defaulted)) or sid_text(owner) not in trusted:
        raise PermissionError('隔离目录所有者不可信。')
    control=W.WORD();revision=W.DWORD()
    security.GetSecurityDescriptorControl.argtypes=[ctypes.c_void_p,ctypes.POINTER(W.WORD),ctypes.POINTER(W.DWORD)]
    security.GetSecurityDescriptorControl.restype=W.BOOL
    if not security.GetSecurityDescriptorControl(buffer,ctypes.byref(control),ctypes.byref(revision)) or not control.value&0x1000:
        raise PermissionError('隔离目录权限继承未隔离。')
    present=W.BOOL();acl=ctypes.c_void_p()
    security.GetSecurityDescriptorDacl.argtypes=[ctypes.c_void_p,ctypes.POINTER(W.BOOL),ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(W.BOOL)]
    security.GetSecurityDescriptorDacl.restype=W.BOOL
    if not security.GetSecurityDescriptorDacl(buffer,ctypes.byref(present),ctypes.byref(acl),ctypes.byref(defaulted)) or not present.value or not acl.value:
        raise PermissionError('隔离目录缺少访问控制。')
    info=AclInfo();security.GetAclInformation.argtypes=[ctypes.c_void_p,ctypes.c_void_p,W.DWORD,W.DWORD];security.GetAclInformation.restype=W.BOOL
    if not security.GetAclInformation(acl,ctypes.byref(info),ctypes.sizeof(info),2):raise ctypes.WinError(ctypes.get_last_error())
    security.GetAce.argtypes=[ctypes.c_void_p,W.DWORD,ctypes.POINTER(ctypes.c_void_p)];security.GetAce.restype=W.BOOL
    admin=False
    for index in range(info.count):
        ace=ctypes.c_void_p()
        if not security.GetAce(acl,index,ctypes.byref(ace)):raise ctypes.WinError(ctypes.get_last_error())
        kind,flags=ctypes.string_at(ace,2)
        if kind==1:continue
        if kind!=0 or sid_text(ace.value+8) not in trusted:raise PermissionError('隔离目录允许非管理员访问。')
        mask=W.DWORD.from_address(ace.value+4).value
        if sid_text(ace.value+8)=='S-1-5-32-544' and mask&0x1f01ff==0x1f01ff and not flags&8:admin=True
    if not admin:raise PermissionError('隔离目录缺少管理员完整访问权限。')
    return path
