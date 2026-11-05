"""Read mounted-volume metadata through read-only Win32 requests."""
import ctypes
from ctypes import wintypes as W
import struct

BUS_NAMES={1:'SCSI',2:'ATAPI',3:'ATA',4:'1394',5:'SSA',6:'Fibre',7:'USB',8:'RAID',
           9:'iSCSI',10:'SAS',11:'SATA',12:'SD',13:'MMC',14:'Virtual',
           15:'File Backed Virtual',16:'Storage Spaces',17:'NVMe',18:'SCM',19:'UFS'}


def decode_extents(data):
    # DISK_EXTENT has 8-byte alignment, including in the 32-bit Windows ABI.
    if len(data)<8:raise ValueError('卷磁盘映射返回数据不完整。')
    count=struct.unpack_from('<I',data)[0]
    if not 1<=count<=256 or len(data)<8+24*count:
        raise ValueError('卷磁盘映射数量或长度无效。')
    return sorted({struct.unpack_from('<I',data,8+24*i)[0] for i in range(count)})


def mounted_volumes():
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GetLogicalDrives.restype=W.DWORD
    kernel.GetDriveTypeW.argtypes=[W.LPCWSTR];kernel.GetDriveTypeW.restype=W.UINT
    kernel.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,ctypes.c_void_p,W.DWORD,W.DWORD,W.HANDLE]
    kernel.CreateFileW.restype=W.HANDLE
    kernel.DeviceIoControl.argtypes=[W.HANDLE,W.DWORD,ctypes.c_void_p,W.DWORD,ctypes.c_void_p,W.DWORD,ctypes.POINTER(W.DWORD),ctypes.c_void_p]
    kernel.DeviceIoControl.restype=W.BOOL
    kernel.CloseHandle.argtypes=[W.HANDLE]
    kernel.GetVolumeNameForVolumeMountPointW.argtypes=[W.LPCWSTR,W.LPWSTR,W.DWORD]
    kernel.GetVolumeNameForVolumeMountPointW.restype=W.BOOL
    mask=kernel.GetLogicalDrives()
    if not mask:raise ctypes.WinError(ctypes.get_last_error())
    result=[]
    for i in range(26):
        if not mask & (1<<i):continue
        root=chr(65+i)+':\\';kind=kernel.GetDriveTypeW(root)
        if kind not in (2,3):continue
        item={'letter':root[0],'drive_type':kind,'disks':[],'bus':None,'removable':None,'volume':'','issues':[]}
        name=ctypes.create_unicode_buffer(1024)
        if kernel.GetVolumeNameForVolumeMountPointW(root,name,len(name)):item['volume']=name.value
        else:item['issues'].append({'category':'volume_identity_failed','winerror':ctypes.get_last_error()})
        handle=kernel.CreateFileW('\\\\.\\'+root[:2],0,7,None,3,0,None)
        if handle==ctypes.c_void_p(-1).value:
            item['issues'].append({'category':'volume_open_failed','winerror':ctypes.get_last_error()})
        else:
            try:
                data=ctypes.create_string_buffer(8+24*256);received=W.DWORD()
                if kernel.DeviceIoControl(handle,0x00560000,None,0,data,len(data),ctypes.byref(received),None):
                    try:item['disks']=decode_extents(data.raw[:received.value])
                    except ValueError as ex:item['issues'].append({'category':'volume_extents_invalid','message':str(ex)})
                else:item['issues'].append({'category':'volume_extents_unavailable','winerror':ctypes.get_last_error()})
                query=ctypes.create_string_buffer(12);data=ctypes.create_string_buffer(4096)
                if kernel.DeviceIoControl(handle,0x2d1400,query,len(query),data,len(data),ctypes.byref(received),None) and received.value>=36:
                    item['bus']=BUS_NAMES.get(struct.unpack_from('<I',data.raw,28)[0])
                    item['removable']=bool(data.raw[10])
            finally:kernel.CloseHandle(handle)
        result.append(item)
    return result
