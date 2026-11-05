"""Capture scan and repair independently before a later operation changes results."""
import datetime
from pathlib import Path
import shutil
import uuid


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
