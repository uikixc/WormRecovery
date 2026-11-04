"""Bounded, read-only reparse inspection; no execution or out-of-scope traversal."""
import ctypes
from ctypes import wintypes as W
import ntpath
import os
import struct

k=ctypes.WinDLL('kernel32',use_last_error=True)
k.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,ctypes.c_void_p,W.DWORD,W.DWORD,W.HANDLE]
k.CreateFileW.restype=W.HANDLE
k.DeviceIoControl.argtypes=[W.HANDLE,W.DWORD,ctypes.c_void_p,W.DWORD,ctypes.c_void_p,W.DWORD,ctypes.POINTER(W.DWORD),ctypes.c_void_p]
k.DeviceIoControl.restype=W.BOOL
k.CloseHandle.argtypes=[W.HANDLE]

class CoverageLimit(Exception):
    def __init__(self,reason,target=None):
        super().__init__(reason);self.reason=reason;self.target=target

def local_path(path):
    if path.startswith('\\??\\'):path=path[4:]
    if path.startswith('\\\\?\\') and len(path)>6 and path[5]==':':path=path[4:]
    drive,tail=ntpath.splitdrive(path)
    if len(drive)!=2 or drive[1]!=':' or not tail.startswith(('\\','/')):
        raise CoverageLimit('non_drive_or_remote_target',path)
    return ntpath.normpath(path)

def decode_reparse(data,path):
    if len(data)<8:raise ValueError('重解析数据头不完整。')
    tag,length=struct.unpack_from('<IH',data)
    if length+8>len(data):raise ValueError('重解析数据长度不完整。')
    data=data[:length+8]
    result={'tag':hex(tag)}
    if tag in (0xa0000003,0xa000000c):
        start=16 if tag==0xa0000003 else 20
        if len(data)<start:raise ValueError('链接数据头不完整。')
        offset,size=struct.unpack_from('<HH',data,8)
        if size%2 or offset%2 or start+offset+size>len(data):raise ValueError('链接目标数据无效。')
        target=data[start+offset:start+offset+size].decode('utf-16le')
        if '\0' in target:raise ValueError('链接目标包含无效字符。')
        if tag==0xa000000c and struct.unpack_from('<I',data,16)[0]&1:
            target=ntpath.join(ntpath.dirname(path),target)
        result.update(kind='junction' if tag==0xa0000003 else 'symbolic_link',target=local_path(target))
    elif tag==0x8000001b:
        if len(data)<12:raise ValueError('应用别名数据不完整。')
        strings=[s for s in data[12:].decode('utf-16le').split('\0') if s]
        targets=[s for s in strings if len(ntpath.splitdrive(s)[0])==2 and ntpath.isabs(s)]
        if len(set(targets))!=1:raise CoverageLimit('ambiguous_app_alias_target')
        result.update(kind='app_execution_alias',target=local_path(targets[0]))
    elif tag==0x80000017:
        result.update(kind='wof_file_data',target=local_path(path))
    else:raise CoverageLimit('unsupported_reparse_tag:'+hex(tag))
    return result

def inspect_reparse(path):
    handle=k.CreateFileW(str(path),0,7,None,3,0x02200000,None)
    if handle==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
    try:
        buffer=ctypes.create_string_buffer(16384);size=W.DWORD()
        if not k.DeviceIoControl(handle,0x900a8,None,0,buffer,len(buffer),ctypes.byref(size),None):raise ctypes.WinError(ctypes.get_last_error())
        return decode_reparse(buffer.raw[:size.value],str(path))
    finally:k.CloseHandle(handle)

def resolve_target(path,approved,max_hops=63):
    """Validate each new destination before following any ancestor reparse point."""
    candidate=local_path(str(path));seen=set();chain=[]
    for _ in range(max_hops):
        if not approved(candidate):raise CoverageLimit('target_outside_scan_scope',candidate)
        key=ntpath.normcase(candidate)
        if key in seen:raise CoverageLimit('link_cycle',candidate)
        seen.add(key)
        drive,tail=ntpath.splitdrive(candidate)
        parts=[p for p in tail.split('\\') if p]
        partial=drive+'\\';redirected=False
        for index,part in enumerate(parts):
            partial=ntpath.join(partial,part)
            st=os.lstat(partial)
            if getattr(st,'st_file_attributes',0)&0x400:
                info=inspect_reparse(partial)
                chain.append({'path':partial,**info})
                if info['kind']=='wof_file_data':
                    if index!=len(parts)-1:raise CoverageLimit('unsupported_directory_filter',partial)
                    continue
                candidate=ntpath.join(info['target'],*parts[index+1:])
                candidate=local_path(candidate)
                redirected=True;break
        if not redirected:return {'target':candidate,'chain':chain}
    raise CoverageLimit('link_resolution_limit',candidate)
