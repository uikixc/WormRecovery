"""Capture scan and repair independently before a later operation changes results."""
import datetime
import json
import os
from pathlib import Path
import shutil
import uuid


def capture_preflight_failure(error,version,mode,manual=None):
    """Retain discovery failures that occur before a Cleaner can be created."""
    operation_id=str(uuid.uuid4());now=datetime.datetime.now(datetime.timezone.utc).isoformat()
    operation={'id':operation_id,'session_id':str(uuid.uuid4()),'type':'scan','status':'failed',
               'stage':'storage_discovery','started_at':now,'finished_at':now,
               'mutations_allowed':False,'error_type':type(error).__name__}
    detail={'stage':'storage_discovery','error_type':type(error).__name__,'message':str(error)[:2000],
            'details':getattr(error,'details',{})}
    report={'version':version,'operation':operation,'files':0,'directories':0,'findings':[],
            'errors':[detail],'inspection_failed':True,'scan_roots':[],
            'scope_summary':{'mode':mode,'requested_paths':manual or []},
            'events':[{'kind':'operation_failed','operation':operation,**detail}]}
    root=Path(os.environ.get('LOCALAPPDATA',Path.home()))/'WormRecovery/diagnostics/failures'/operation_id
    root.mkdir(parents=True,exist_ok=False)
    path=root/'report.json';path.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    (root/'journal.jsonl').write_text(json.dumps(report['events'][0],ensure_ascii=False)+'\n',encoding='utf-8')
    from diagnostic_client import collect,schedule
    collect(path,upload=False);schedule()
    return path


def execute(cleaner,kind,action):
    if kind not in ('scan','repair'):raise ValueError('操作类型无效。')
    cleaner.session_id=getattr(cleaner,'session_id',str(uuid.uuid4()))
    cleaner.operation={'id':str(uuid.uuid4()),'session_id':cleaner.session_id,'type':kind,
        'status':'running','started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'mutations_allowed':kind=='repair'}
    logger=getattr(cleaner,'log',None)
    if callable(logger):logger('operation_started',operation=dict(cleaner.operation))
    try:
        result=action()
    except BaseException as ex:
        cleaner.operation.update(status='failed',error_type=type(ex).__name__)
        if callable(logger):logger('operation_failed',operation=dict(cleaner.operation),error_type=type(ex).__name__,message=str(ex)[:700])
        capture(cleaner)
        raise
    cleaner.operation['status']='cancelled' if cleaner.cancel.is_set() else 'completed_with_errors' if cleaner.errors or getattr(cleaner,'inspection_failed',False) else 'completed'
    capture(cleaner)
    return result


def capture(cleaner):
    cleaner.operation['finished_at']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    logger=getattr(cleaner,'log',None)
    if callable(logger):logger('operation_finished',operation=dict(cleaner.operation))
    saver=getattr(cleaner,'save',None)
    if not callable(saver):return
    try:
        saver()
        source=Path(cleaner.run)/'report.json'
        if not source.is_file():return
        destination=Path(cleaner.run)/'operations'/cleaner.operation['id']
        destination.mkdir(parents=True,exist_ok=False)
        shutil.copy2(source,destination/'report.json')
        journal=Path(cleaner.run)/'journal.jsonl'
        if journal.is_file():shutil.copy2(journal,destination/'journal.jsonl')
        from diagnostic_client import collect,schedule
        # Queue the exact snapshot before another operation can overwrite it.
        collect(destination/'report.json',upload=False)
        schedule()
    except Exception as ex:
        if callable(logger):logger('diagnostic_capture_error',error_type=type(ex).__name__,message=str(ex)[:500])
