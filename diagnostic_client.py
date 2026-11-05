"""Automatic diagnostic delivery with a bounded persistent upload queue."""
import ctypes
from ctypes import wintypes as W
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import threading
import uuid

from diagnostic_bundle import build_bundle,MAX_REPORT,scrub,read_bounded
from diagnostic_transport import send,probe
from diagnostic_routes import DEFAULT_ENDPOINTS,current_endpoints

LOCK=threading.Lock()
UPLOAD_LOCK=threading.Lock()
QUEUE_CHANGED=threading.Event()
MAX_QUEUE=20
BACKGROUND_LOCK=threading.Lock()
BACKGROUND_STOP=threading.Event()
BACKGROUND_THREAD=None


def state_root():
    root=Path(os.environ.get('LOCALAPPDATA',str(Path.home()/'AppData/Local')))/'WormRecovery/diagnostics'
    root.mkdir(parents=True,exist_ok=True);return root


def protect(data,decrypt=False):
    class Blob(ctypes.Structure):_fields_=[('size',W.DWORD),('data',ctypes.POINTER(ctypes.c_ubyte))]
    api=ctypes.WinDLL('crypt32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    buffer=ctypes.create_string_buffer(data);source=Blob(len(data),ctypes.cast(buffer,ctypes.POINTER(ctypes.c_ubyte)));target=Blob()
    if decrypt:
        function=api.CryptUnprotectData
        function.argtypes=[ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,W.DWORD,ctypes.POINTER(Blob)]
        args=(ctypes.byref(source),None,None,None,None,1,ctypes.byref(target))
    else:
        function=api.CryptProtectData
        function.argtypes=[ctypes.POINTER(Blob),W.LPCWSTR,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,W.DWORD,ctypes.POINTER(Blob)]
        args=(ctypes.byref(source),'WormRecovery diagnostics',None,None,None,1,ctypes.byref(target))
    function.restype=W.BOOL;kernel.LocalFree.argtypes=[ctypes.c_void_p]
    if not function(*args):raise ctypes.WinError(ctypes.get_last_error())
    try:return ctypes.string_at(target.data,target.size)
    finally:kernel.LocalFree(target.data)


def validate_config(config):
    from urllib.parse import urlsplit
    if config.get('schema')!=2:raise ValueError('采集配置版本无效。')
    endpoints=config.get('endpoints')
    if not isinstance(endpoints,list) or not 1<=len(endpoints)<=4:raise ValueError('采集服务地址无效。')
    for endpoint in endpoints:
        url=urlsplit(endpoint)
        if url.scheme!='http' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('','/'):
            raise ValueError('采集服务必须使用 HTTP 根地址。')
    if not re.fullmatch('[A-Za-z0-9_-]{32,160}',str(config.get('upload_token',''))):raise ValueError('设备上传授权无效。')
    return dict(config,endpoints=current_endpoints(endpoints))


def enroll(path):
    path=Path(path)
    if path.stat().st_size>16384:raise ValueError('采集配置超过大小上限。')
    config=validate_config(json.loads(path.read_text(encoding='utf-8-sig')))
    destination=state_root()/'collector.dpapi';temporary=destination.with_suffix('.new')
    temporary.write_bytes(protect(json.dumps(config).encode('utf-8')));os.replace(temporary,destination)
    (state_root()/'paused').unlink(missing_ok=True)
    return {'enabled':True,'endpoints':config['endpoints']}


def configuration():
    if (state_root()/'paused').is_file():return None
    path=state_root()/'collector.dpapi'
    if not path.is_file():return {'schema':2,'endpoints':list(DEFAULT_ENDPOINTS),'upload_token':'','automatic':True}
    try:
        if path.stat().st_size>32768:raise ValueError('采集授权文件异常。')
        return validate_config(json.loads(protect(path.read_bytes(),decrypt=True)))
    except (OSError,ValueError):
        return {'schema':2,'endpoints':list(DEFAULT_ENDPOINTS),'upload_token':'','automatic':True}


def disable():
    (state_root()/'collector.dpapi').unlink(missing_ok=True)
    (state_root()/'paused').write_text('paused',encoding='ascii')


def record_event(kind,**fields):
    try:
        root=state_root();path=root/'application.jsonl'
        if path.exists() and path.stat().st_size>512*1024:path.replace(path.with_suffix('.previous'))
        record=scrub({'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'kind':kind,**fields})
        with path.open('a',encoding='utf-8') as stream:stream.write(json.dumps(record,ensure_ascii=True)+'\n')
    except OSError:pass


def read_status():
    root=state_root();path=root/'status.json'
    try:record=json.loads(path.read_text(encoding='utf-8')) if path.is_file() else {}
    except (ValueError,OSError):record={}
    record.update(enabled=not (root/'paused').is_file(),pending=len(list((root/'queue').glob('*.wrdiag'))))
    return record


def status(message,**fields):
    record={'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'message':message,**fields}
    path=state_root()/'status.json';temporary=path.with_suffix('.'+uuid.uuid4().hex+'.new')
    temporary.write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8');os.replace(temporary,path)
    return record


def check_connection():
    """Probe configured routes without queue changes or diagnostic uploads."""
    from concurrent.futures import ThreadPoolExecutor
    from urllib.parse import urlsplit
    import ipaddress,time
    config=configuration();endpoints=config['endpoints'] if config else list(DEFAULT_ENDPOINTS)
    token=config.get('upload_token') if config else None
    def check(endpoint):
        host=urlsplit(endpoint).hostname
        try:route='内网' if ipaddress.ip_address(host).is_private else '外网'
        except ValueError:route='指定地址'
        started=time.monotonic();row={'endpoint':endpoint,'route':route}
        try:row.update(probe(endpoint,token=token,timeout=3))
        except Exception as ex:row.update(reachable=False,error_type=type(ex).__name__,reason=scrub(str(ex))[:250])
        row['elapsed_ms']=round((time.monotonic()-started)*1000);return row
    with ThreadPoolExecutor(max_workers=min(4,len(endpoints))) as pool:rows=list(pool.map(check,endpoints))
    selected=next((row for row in rows if row.get('reachable') and row.get('authorization')=='accepted'),None)
    reachable=next((row for row in rows if row.get('reachable')),None)
    if selected:message='日志服务器已连接 · '+selected['route']+' · 自动提交可用。'
    elif reachable:message='日志服务器可连接 · '+reachable['route']+' · '+('自动提交已暂停。' if not config else '接收服务尚未允许提交。')
    else:message='日志服务器未连接：内网、外网检测均未成功。'
    result={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'configured':bool(config),
            'connected':bool(reachable),'upload_ready':bool(selected),'selected_route':selected['route'] if selected else reachable['route'] if reachable else None,
            'message':message,'routes':rows}
    root=state_root();path=root/'connection.json';temporary=path.with_suffix('.'+uuid.uuid4().hex+'.new')
    temporary.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');os.replace(temporary,path)
    return result


def flush_queue(config):
    root=state_root()/'queue';root.mkdir(exist_ok=True);sent=0;last_receipt=None;last_endpoint=None
    for path in sorted(root.glob('*.wrdiag'))[:MAX_QUEUE]:
        if (state_root()/'paused').is_file():return status('自动提交已暂停。',pending=len(list(root.glob('*.wrdiag'))),sent=sent)
        if path.stat().st_size>12*1024*1024:return status('队列文件超过传输上限。',pending=len(list(root.glob('*.wrdiag'))),sent=sent)
        payload=path.read_bytes();receipt=None;transport_errors=[]
        for endpoint in config['endpoints']:
            try:
                candidate=send(endpoint,payload,config['upload_token'])
                if candidate['receipt']!=path.stem:raise ValueError('接收凭据与诊断包不匹配。')
                receipt=candidate;last_endpoint=endpoint;break
            except Exception as ex:
                transport_errors.append({'endpoint':endpoint,'error_type':type(ex).__name__,'message':scrub(str(ex))[:300]})
                record_event('diagnostic_transport_error',endpoint=endpoint,error_type=type(ex).__name__,message=str(ex)[:500])
                continue
        if receipt is None:
            return status('上传未完成：采集服务未返回有效接收凭据，诊断包仍保存在本机队列。',pending=len(list(root.glob('*.wrdiag'))),sent=sent,delivery='pending',transport_errors=transport_errors,
                          last_receipt=last_receipt,last_endpoint=last_endpoint)
        received=state_root()/'receipts.jsonl'
        if received.exists() and received.stat().st_size>1024*1024:
            received.replace(received.with_suffix('.previous'))
        with received.open('a',encoding='utf-8') as stream:stream.write(json.dumps(receipt,ensure_ascii=True)+'\n')
        path.unlink();sent+=1;last_receipt=receipt
    if not sent:
        previous=read_status();last_receipt=previous.get('last_receipt');last_endpoint=previous.get('last_endpoint')
        if not last_receipt:
            journal=state_root()/'receipts.jsonl'
            try:
                with journal.open('rb') as stream:
                    stream.seek(max(0,journal.stat().st_size-8192));lines=stream.read().splitlines()
                last_receipt=json.loads(lines[-1]) if lines else None
            except (OSError,ValueError):pass
        if last_receipt:
            return status('诊断资料已同步，服务器接收凭据已保留。',pending=0,sent=0,delivery='acknowledged',last_receipt=last_receipt,last_endpoint=last_endpoint)
        return status('当前没有待提交资料；本次未发送报告，不代表当前扫描已上传。',pending=0,sent=0,delivery='no_pending_reports')
    return status('已提交 %s 份诊断资料，服务器已确认接收。'%sent,pending=len(list(root.glob('*.wrdiag'))),sent=sent,delivery='acknowledged',last_receipt=last_receipt,last_endpoint=last_endpoint)


def collect(report,manual=False,upload=True):
    LOCK.acquire()
    try:
        config=configuration()
        if config is None:return {'message':'自动提交已暂停。','enabled':False}
        report=Path(report)
        if report.stat().st_size>MAX_REPORT:raise ValueError('诊断报告超过采集上限。')
        fingerprint=hashlib.sha256(read_bounded(report)).hexdigest()
        root=state_root();queue=root/'queue';queue.mkdir(exist_ok=True)
        marker=root/'last-report.txt';index_path=root/'report-index.json'
        try:index=json.loads(index_path.read_text(encoding='utf-8')) if index_path.is_file() else {}
        except (ValueError,OSError):index={}
        if manual or fingerprint not in index and (not marker.exists() or marker.read_text(encoding='ascii')!=fingerprint):
            if len(list(queue.glob('*.wrdiag')))>=MAX_QUEUE:
                return status('采集队列已满，未覆盖已有诊断包；联网后重试。',pending=MAX_QUEUE)
            bundle,compressed=build_bundle(report,state=root)
            payload=compressed
            path=queue/(bundle['bundle_id']+'.wrdiag');temporary=path.with_suffix('.partial')
            temporary.write_bytes(payload);os.replace(temporary,path)
            QUEUE_CHANGED.set()
            marker.write_text(fingerprint,encoding='ascii')
            index[fingerprint]=bundle['bundle_id']
            if len(index)>4096:index=dict(list(index.items())[-4096:])
            temporary=index_path.with_suffix('.new');temporary.write_text(json.dumps(index),encoding='utf-8');os.replace(temporary,index_path)
        previous=read_status()
        result=status('诊断包已压缩保存，等待提交。',pending=len(list(queue.glob('*.wrdiag'))),
                      last_receipt=previous.get('last_receipt'),last_endpoint=previous.get('last_endpoint'))
    except Exception as ex:
        # Do not include config values, authorization headers or document content.
        return status('诊断任务未完成。',error_type=type(ex).__name__)
    finally:LOCK.release()
    return retry() if upload else result


def report_candidates():
    """Inspect only the application's own report directories, never whole disks."""
    roots=[Path(os.environ.get('PROGRAMDATA','C:/ProgramData'))/'WormRecovery',state_root()/'failures']
    candidates=[]
    def normal_directory(path):
        try:return path.is_dir() and not path.stat().st_file_attributes & 0x400
        except OSError:return False
    for root in roots:
        if not normal_directory(root):continue
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    if len(candidates)>=2000:break
                    try:
                        if not entry.is_dir(follow_symlinks=False) or entry.stat(follow_symlinks=False).st_file_attributes & 0x400:continue
                        folder=Path(entry.path);operations=folder/'operations';paths=[]
                        if normal_directory(operations):
                            with os.scandir(operations) as children:
                                for child in children:
                                    if len(paths)>=MAX_QUEUE:break
                                    if child.is_dir(follow_symlinks=False) and not child.stat(follow_symlinks=False).st_file_attributes & 0x400:
                                        paths.append(Path(child.path)/'report.json')
                        paths=paths or [folder/'report.json']
                        for path in paths:
                            if path.is_file() and not path.stat().st_file_attributes & 0x400 and path.stat().st_size<=MAX_REPORT:candidates.append((path.stat().st_mtime,path))
                    except OSError:continue
        except OSError:continue
    return [p for _,p in sorted(candidates,key=lambda x:x[0],reverse=True)]


def backfill_reports():
    count=0;read_bytes=0;root=state_root();index_path=root/'report-index.json';cache_path=root/'backfill-index.json'
    try:index=json.loads(index_path.read_text(encoding='utf-8')) if index_path.is_file() else {}
    except (OSError,ValueError):index={}
    try:cache=json.loads(cache_path.read_text(encoding='utf-8')) if cache_path.is_file() else {}
    except (OSError,ValueError):cache={}
    for path in report_candidates():
        if (root/'paused').exists():break
        if len(list((root/'queue').glob('*.wrdiag')))>=MAX_QUEUE:break
        try:
            stat=path.stat();key=str(path.resolve());metadata=[stat.st_size,stat.st_mtime_ns]
            cached=cache.get(key,{})
            if cached.get('metadata')==metadata and cached.get('fingerprint') in index:continue
            if read_bytes+stat.st_size>64*1024*1024:break
            raw=read_bounded(path);read_bytes+=len(raw);fingerprint=hashlib.sha256(raw).hexdigest()
            if fingerprint in index:
                cache[key]={'metadata':metadata,'fingerprint':fingerprint};continue
            # Only completed operation snapshots and legacy application reports.
            document=json.loads(raw.decode('utf-8-sig'))
            operation=document.get('operation') or {}
            if operation.get('status')=='running' or not document.get('version') or not isinstance(document.get('findings'),list):continue
            result=collect(path,upload=False)
            if result.get('error_type'):record_event('backfill_error',error_type=result['error_type'])
            elif (root/'report-index.json').is_file() and fingerprint in json.loads((root/'report-index.json').read_text(encoding='utf-8')):
                index[fingerprint]=True;cache[key]={'metadata':metadata,'fingerprint':fingerprint};count+=1
        except (OSError,ValueError,TypeError):continue
    if len(cache)>4096:cache=dict(list(cache.items())[-4096:])
    temporary=cache_path.with_suffix('.new');temporary.write_text(json.dumps(cache),encoding='utf-8');os.replace(temporary,cache_path)
    return count


def retry(wait=False,backfill=False):
    acquired=UPLOAD_LOCK.acquire(timeout=10) if wait else UPLOAD_LOCK.acquire(blocking=False)
    if not acquired:
        QUEUE_CHANGED.set()
        return {'message':'后台提交正在执行，新诊断已保留在队列。'}
    try:
        config=configuration()
        if not config:
            QUEUE_CHANGED.clear()
            return {'message':'自动提交已暂停。','enabled':False}
        if backfill:backfill_reports()
        while True:
            QUEUE_CHANGED.clear();result=flush_queue(config)
            if not QUEUE_CHANGED.is_set() or result.get('pending') and not result.get('sent'):return result
    except Exception as ex:return status('诊断任务未完成。',error_type=type(ex).__name__)
    finally:
        UPLOAD_LOCK.release()
        if QUEUE_CHANGED.is_set():schedule()


def schedule(report=None):
    def worker():collect(report) if report else retry(backfill=True)
    threading.Thread(target=worker,daemon=True,name='WormRecovery-Diagnostics').start()


def start_background(callback=None,interval=30):
    """Retry and backfill while the application is open, including after outages."""
    global BACKGROUND_THREAD
    with BACKGROUND_LOCK:
        if BACKGROUND_THREAD and BACKGROUND_THREAD.is_alive():return
        BACKGROUND_STOP.clear()
        def worker():
            previous=None
            while not BACKGROUND_STOP.is_set():
                result=retry(backfill=True)
                signature=(result.get('message'),result.get('pending'),result.get('delivery'),str(result.get('last_receipt')))
                if callback and signature!=previous:
                    try:callback(result)
                    except Exception:pass
                previous=signature
                BACKGROUND_STOP.wait(interval)
        BACKGROUND_THREAD=threading.Thread(target=worker,daemon=True,name='WormRecovery-Diagnostics-Auto')
        BACKGROUND_THREAD.start()


def stop_background():
    BACKGROUND_STOP.set()
