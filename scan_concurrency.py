"""Bounded read-only work queue with per-physical-device I/O limits."""
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import ctypes
from ctypes import wintypes as W
import os
import struct
import threading


def storage_profile(root):
    """Read device number and seek penalty; unknown media use one reader."""
    result={'device':os.path.normcase(root),'seek_penalty':None,'readers':1}
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    k.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,ctypes.c_void_p,W.DWORD,W.DWORD,W.HANDLE]
    k.CreateFileW.restype=W.HANDLE
    k.DeviceIoControl.argtypes=[W.HANDLE,W.DWORD,ctypes.c_void_p,W.DWORD,ctypes.c_void_p,W.DWORD,ctypes.POINTER(W.DWORD),ctypes.c_void_p]
    k.DeviceIoControl.restype=W.BOOL;k.CloseHandle.argtypes=[W.HANDLE]
    handle=k.CreateFileW('\\\\.\\'+str(root)[:2],0,3,None,3,0,None)
    if handle==ctypes.c_void_p(-1).value:return result
    try:
        answer=ctypes.create_string_buffer(32);returned=W.DWORD()
        if k.DeviceIoControl(handle,0x2d1080,None,0,answer,len(answer),ctypes.byref(returned),None) and returned.value>=12:
            device_type,number,_=struct.unpack_from('<III',answer.raw)
            result['device']='device:%s:%s'%(device_type,number)
        query=ctypes.create_string_buffer(struct.pack('<III',7,0,0));answer=ctypes.create_string_buffer(32)
        if k.DeviceIoControl(handle,0x2d1400,query,len(query),answer,len(answer),ctypes.byref(returned),None) and returned.value>=9:
            result['seek_penalty']=bool(answer.raw[8])
            if not result['seek_penalty']:result['readers']=4
        return result
    finally:k.CloseHandle(handle)


class FileScanner:
    """Workers return results; only the caller mutates reports and counters."""
    def __init__(self,inspect,accept,cancel,profiles,workers=None,validate=None,batch_size=32):
        if workers is not None and (not isinstance(workers,int) or not 1<=workers<=8):
            raise ValueError('扫描线程数必须为 1 到 8。')
        self.inspect=inspect;self.accept=accept;self.cancel=cancel;self.validate=validate
        self.profiles=profiles;self.batch_size=batch_size;self.buffers={};self.pending=set()
        devices={}
        for profile in profiles.values():
            key=profile['device'];devices[key]=min(devices.get(key,8),profile['readers'])
        self.workers=workers or max(1,min(8,sum(devices.values())))
        self.limits={key:threading.BoundedSemaphore(value) for key,value in devices.items()}
        self.queue_limit=self.workers*2;self.peak_pending=0;self.pool=None
        self.active={};self.lock=threading.Lock()
    def __enter__(self):
        if self.workers>1:self.pool=ThreadPoolExecutor(max_workers=self.workers,thread_name_prefix='WormScan')
        return self
    def __exit__(self,*exc):
        if exc[0] is not None:self.cancel.set()
        try:self.finish()
        finally:
            if self.pool:self.pool.shutdown(wait=True,cancel_futures=True)
    def submit(self,path,stat,root):
        if self.cancel.is_set():return
        if not self.pool:
            self._accept(self._batch([(path,stat)],root));return
        self.poll()
        batch=self.buffers.setdefault(root,[])
        batch.append((path,stat))
        if len(batch)>=self.batch_size:self._flush(root)
    def _flush(self,root):
        batch=self.buffers.pop(root,[])
        if not batch or self.cancel.is_set():return
        while len(self.pending)>=self.queue_limit:self.poll(block=True)
        self.pending.add(self.pool.submit(self._batch,batch,root))
        self.peak_pending=max(self.peak_pending,len(self.pending))
    def _batch(self,batch,root):
        output=[];gate=self.limits[self.profiles[root]['device']]
        while not self.cancel.is_set():
            if gate.acquire(timeout=.1):break
        else:return output
        try:
            if self.cancel.is_set():return output
            try:
                if self.validate:self.validate(root)
            except Exception as ex:return [(path,None,str(ex)) for path,_ in batch]
            for path,stat in batch:
                if self.cancel.is_set():break
                with self.lock:self.active[threading.get_ident()]=path
                try:output.append((path,self.inspect(path,stat),None))
                except Exception as ex:output.append((path,None,str(ex)))
            return output
        finally:
            with self.lock:self.active.pop(threading.get_ident(),None)
            gate.release()
    def _accept(self,rows):
        for path,result,error in rows:self.accept(path,result,error)
    def poll(self,block=False):
        if not self.pending:return
        done,_=wait(self.pending,timeout=.1,return_when=FIRST_COMPLETED) if block else ({future for future in self.pending if future.done()},None)
        for future in done:
            self.pending.remove(future);self._accept(future.result())
    def finish(self):
        if self.pool:
            for root in list(self.buffers):self._flush(root)
        self.buffers.clear()
        while self.pending:self.poll(block=True)
    def current(self):
        with self.lock:return next(iter(self.active.values()),'')
