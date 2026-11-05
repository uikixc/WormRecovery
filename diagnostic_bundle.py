"""Bounded diagnostic evidence only; never reads document originals or credentials."""
import collections
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import uuid

MAX_REPORT=16*1024*1024
MAX_PLAIN=20*1024*1024
SECRET_KEYS={'token','access_token','refresh_token','authorization','password','secret','cookie',
             'private_key','credential','environment','env','upload_token','admin_token',
             'computer','hostname','source_code','document_text','document_content','vba_source'}


def scrub(value):
    if isinstance(value,dict):return {str(k):scrub(v) for k,v in value.items() if str(k).casefold() not in SECRET_KEYS}
    if isinstance(value,list):return [scrub(x) for x in value]
    if isinstance(value,str):
        value=re.sub(r'github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]{20,}|(?i:Bearer)\s+[A-Za-z0-9._~+/=-]+','[REDACTED]',value)
        value=re.sub(r'(?i)([?&](?:token|key|password|sig|signature|auth|access_token)=)[^&\s]+',r'\1[REDACTED]',value)
        value=re.sub(r'(?i)((?:password|passwd|access_token|upload_token|secret)\s*[=:]\s*)[^\s,;]+',r'\1[REDACTED]',value)
        # Keep file identity and hierarchy while removing local account names.
        value=re.sub(r'(?i)([A-Z]:[\\/]Users[\\/])[^\\/\r\n]+',r'\1[USER]',value)
        return value
    return value


def device_id(state):
    path=Path(state)/'device-id.txt';path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():return path.read_text(encoding='ascii').strip()
    value=str(uuid.uuid4());path.write_text(value,encoding='ascii');return value


def read_bounded(path,limit=MAX_REPORT):
    with Path(path).open('rb') as stream:data=stream.read(limit+1)
    if len(data)>limit:raise ValueError('诊断数据超过读取上限。')
    return data


def build_bundle(report,journal=None,state=None):
    report=Path(report)
    if report.stat().st_size>MAX_REPORT:raise ValueError('诊断报告超过采集上限。')
    raw=read_bounded(report);document=json.loads(raw.decode('utf-8-sig'))
    if len(raw)>MAX_REPORT or not isinstance(document,dict):raise ValueError('诊断报告格式或大小无效。')
    findings=document.get('findings',[])
    local_state=Path(state or Path(os.environ.get('LOCALAPPDATA',Path.home()))/'WormRecovery/diagnostics')
    device=device_id(local_state)
    document=dict(document);document.pop('computer',None)
    # Host names are not needed to group a device; a generated random ID is used.
    for event in document.get('events',[]):
        if isinstance(event,dict):event.pop('computer',None)
    journal=Path(journal) if journal else report.with_name('journal.jsonl')
    events=[]
    if journal.is_file():
        if journal.stat().st_size>MAX_REPORT:raise ValueError('诊断日志超过采集上限。')
        for line in read_bounded(journal).decode('utf-8-sig').splitlines():
            if line.strip():events.append(json.loads(line))
    try:
        import psutil
        memory=psutil.virtual_memory()
        runtime={'cpu_logical':psutil.cpu_count(),'memory_total':memory.total,'memory_available':memory.available}
    except Exception:runtime={}
    bundle={'schema':1,'bundle_id':str(uuid.uuid4()),'device_id':device,
            'created_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'application_version':document.get('version'),'report_sha256':hashlib.sha256(raw).hexdigest(),
            'system':{'os':platform.system(),'release':platform.release(),'version':platform.version(),
                      'architecture':platform.machine(),**runtime},
            'summary':{'files':document.get('files'),'scan_seconds':document.get('scan_seconds'),
                       'finding_counts':dict(collections.Counter(x.get('kind','unknown') for x in findings)),
                       'review_count':sum(x.get('kind','').startswith('review_') for x in findings),
                       'errors':len(document.get('errors',[]))},
            'report':document,'journal':events,
            'collection_scope':'扫描报告、待核证据、解析与引擎输出、设备范围、故障及性能信息；不含文档正文、原件、隔离文件、令牌、密码、浏览记录或环境变量。'}
    runtime_events=local_state/'application.jsonl'
    if runtime_events.is_file() and runtime_events.stat().st_size<=1024*1024:
        bundle['application_events']=[json.loads(line) for line in read_bounded(runtime_events,1024*1024).decode('utf-8').splitlines() if line.strip()]
    bundle=scrub(bundle)
    encoded=json.dumps(bundle,ensure_ascii=True,separators=(',',':')).encode('ascii')
    if len(encoded)>MAX_PLAIN:raise ValueError('诊断数据超过总大小上限。')
    return bundle,gzip.compress(encoded,compresslevel=6,mtime=0)
