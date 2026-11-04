"""Explain read limitations without suppressing errors or certifying content."""
import ctypes
from ctypes import wintypes as W
import ntpath
import os


def active_pagefiles():
    class Information(ctypes.Structure):
        _fields_=[('size',W.DWORD),('reserved',W.DWORD),('total',ctypes.c_size_t),
                  ('used',ctypes.c_size_t),('peak',ctypes.c_size_t)]
    callback_type=ctypes.WINFUNCTYPE(W.BOOL,ctypes.c_void_p,ctypes.POINTER(Information),W.LPCWSTR)
    paths=[]
    @callback_type
    def collect(context,information,path):
        paths.append(ntpath.normcase(ntpath.normpath(path)))
        return True
    api=ctypes.WinDLL('psapi',use_last_error=True)
    api.EnumPageFilesW.argtypes=[callback_type,ctypes.c_void_p]
    api.EnumPageFilesW.restype=W.BOOL
    if not api.EnumPageFilesW(collect,None):
        raise ctypes.WinError(ctypes.get_last_error())
    return set(paths)


def describe_read_error(path,error,paging_files=()):
    normalized=ntpath.normcase(ntpath.abspath(str(path)))
    paging_files={ntpath.normcase(ntpath.abspath(str(p))) for p in paging_files}
    text=str(error)
    permission=isinstance(error,PermissionError) or 'permission denied' in text.casefold() or 'winerror 32' in text.casefold()
    if not permission:return {}
    if normalized in paging_files:
        return {'category':'active_pagefile_unreadable','reason':'Windows 已登记的活动分页文件，在线文件读取被系统拒绝。',
                'identity_basis':'EnumPageFilesW','content_inspected':False,
                'action':'这是读取范围限制，不是病毒检出；保留系统内存管理设置。需要检查该内容时，应在可信离线环境中处理。'}
    system_drive=ntpath.splitdrive(os.environ.get('SystemRoot','C:/Windows'))[0]
    swap=ntpath.normcase(ntpath.join(system_drive+'/', 'swapfile.sys'))
    if normalized==swap and any(ntpath.splitdrive(p)[0]==system_drive.casefold() for p in paging_files):
        return {'category':'system_swap_path_unreadable','reason':'系统卷根目录的交换文件位置，在线文件读取被拒绝。',
                'identity_basis':'Exact system-volume path plus enumerated active pagefile; file content not verified',
                'content_inspected':False,
                'action':'该位置与 Windows 交换文件一致，但内容未读取，不据此认证安全。无需为了消除提示禁用虚拟内存或关闭系统关键进程。'}
    return {}
