"""Retain independent ClamAV verdicts across a bounded batch interruption."""
import copy
import hashlib
from pathlib import Path
import subprocess
import time

MAX_OUTPUT=8*1024*1024
STARTUP_SECONDS=180
FILE_SECONDS=20
STALL_SECONDS=45


def batch_deadline(count):
    # --max-scantime is per input, not a budget for the complete file list.
    return STARTUP_SECONDS+(FILE_SECONDS+10)*count


class OutputMonitor:
    def __init__(self,path,inputs,progress):
        self.path=path;self.inputs={str(p) for p in inputs};self.progress=progress
        self.messages={};self.offset=0;self.pending=b'';self.started=time.monotonic()
        self.last_activity=self.started;self.current=None;self.have_progress=False

    def poll(self,final=False):
        with self.path.open('rb') as source:
            source.seek(self.offset);data=source.read(MAX_OUTPUT-self.offset+1)
        self.offset+=len(data)
        if self.offset>MAX_OUTPUT:raise ValueError('ClamAV 输出超过资源上限。')
        self.pending+=data
        lines=self.pending.split(b'\n');self.pending=lines.pop()
        if final and self.pending:lines.append(self.pending);self.pending=b''
        if len(self.pending)>65536:raise ValueError('ClamAV 输出行超过资源上限。')
        for raw in lines:
            line=raw.decode('utf-8','replace').strip('\r')
            scanning=line.removeprefix('Scanning ')
            if line.startswith('Scanning ') and scanning in self.inputs:
                self.current=scanning;self._activity('scanning',scanning)
            path,separator,message=line.rpartition(': ')
            if separator and path in self.inputs:
                self.messages.setdefault(path,[]).append(message)
                if message=='OK' or message.endswith((' FOUND',' ERROR')) or message=='Empty file':
                    self._activity('result',path)
        if not final:
            idle=time.monotonic()-self.last_activity
            allowance=STALL_SECONDS if self.have_progress else STARTUP_SECONDS
            if idle>allowance:
                error=subprocess.TimeoutExpired('ClamAV file progress',allowance)
                error.reason='文件检查长时间没有进展。' if self.have_progress else '病毒库加载或首次检查超时。'
                raise error

    def _activity(self,phase,path):
        self.have_progress=True;self.last_activity=time.monotonic()
        self.progress({'stage':phase,'path':path,'completed':sum(terminal(values) for values in self.messages.values()),
                       'total':len(self.inputs)})


def terminal(messages):
    return any(value=='OK' or value.endswith((' FOUND',' ERROR')) or value=='Empty file' for value in messages)


def verdict(messages,complete,reason):
    detections=[value[:-6] for value in messages if value.endswith(' FOUND') and 'Heuristics.Limits.Exceeded' not in value]
    failures=[value for value in messages if 'ERROR' in value or 'Heuristics.Limits.Exceeded' in value]
    if detections:
        return {'status':'detected','detections':detections,'content_inspected':not failures,
                **({'reason':'; '.join(failures)} if failures else {})}
    if not failures and 'OK' in messages:return {'status':'no_match','detections':[]}
    return {'status':'incomplete','detections':[],
            'reason':'; '.join(failures) or (reason if not complete else '; '.join(messages) or '引擎未返回该文件的独立结果。')}


def scan(paths,work,tool,root,run_engine,environment,timeout=None,cancel=None,progress=lambda value:None):
    paths=[Path(path) for path in paths];work=Path(work);groups={};rows={}
    for path in paths:
        if cancel is not None and cancel.is_set():raise InterruptedError('离线分析已停止。')
        with path.open('rb') as source:digest=hashlib.file_digest(source,'sha256').hexdigest()
        if path.stat().st_size==0:
            rows[str(path)]={'status':'no_content','detections':[],'engine_invoked':False,
                            'reason':'校验副本为零字节，没有可供病毒库检查的内容。'}
        else:groups.setdefault((digest,path.suffix.casefold()),[]).append(path)
    if not groups:return rows,{}
    exe=tool('clamav/clamscan.exe');database=root/'clamdb'
    dbinfo={}
    for name in ('main.cvd','daily.cvd','bytecode.cvd'):
        tool('clamdb/'+name)
        with (database/name).open('rb') as source:fields=source.read(512).decode('ascii','replace').strip().split(':')
        dbinfo[name]={'build':fields[1] if len(fields)>1 else '', 'version':fields[2] if len(fields)>2 else '',
                      'signatures':fields[3] if len(fields)>3 else ''}
    todo=[items[0] for items in groups.values()];all_results={};attempts=[]
    for attempt in range(2):
        if not todo:break
        if cancel is not None and cancel.is_set():raise InterruptedError('离线分析已停止。')
        filelist=work/('clam-files-%s.txt'%attempt);output=work/('clam-output-%s.txt'%attempt)
        filelist.write_text(''.join(str(path)+'\n' for path in todo),encoding='utf-8')
        existing=len(all_results)
        def attempt_progress(event):progress({**event,'completed':existing+event['completed'],'total':len(groups)})
        monitor=OutputMonitor(output,todo,attempt_progress)
        deadline=timeout if timeout is not None else batch_deadline(len(todo))
        command=[str(exe),'--database='+str(database),'--file-list='+str(filelist),
                 '--verbose','--stdout','--no-summary','--alert-exceeds-max=yes',
                 '--max-scantime='+str(FILE_SECONDS*1000),'--max-filesize=128M','--max-scansize=256M',
                 '--max-recursion=12','--bytecode-timeout=5000','--tempdir='+str(work)]
        started=time.monotonic();failure=None;code=None
        progress({'stage':'loading','path':'','completed':len(all_results),'total':len(groups)})
        with output.open('wb') as sink:
            try:
                completed=run_engine(command,stdout=sink,stderr=subprocess.STDOUT,timeout=deadline,
                                     env=environment,cancel=cancel,on_poll=monitor.poll)
                code=completed.returncode
            except (subprocess.TimeoutExpired,OSError,ValueError) as error:
                failure=getattr(error,'reason',None) or str(error)
        try:monitor.poll(final=True)
        except (OSError,ValueError) as error:failure=str(error)
        complete=code in (0,1) and failure is None
        failure=failure or ('ClamAV 未完成，退出码 '+str(code) if not complete else None)
        state={'attempt':attempt+1,'inputs':len(todo),'results':sum(terminal(value) for value in monitor.messages.values()),
               'exit_code':code,'status':'completed' if complete else 'incomplete','deadline_seconds':deadline,
               'elapsed_seconds':round(time.monotonic()-started,3),'reason':failure}
        attempts.append(state)
        pending=[]
        for path in todo:
            messages=monitor.messages.get(str(path),[])
            if terminal(messages):all_results[str(path)]=verdict(messages,complete,failure)
            else:pending.append(path)
        # One retry of unfinished inputs after real progress. Never rescan a
        # completed file or repeatedly reload a database that cannot start.
        if not complete and pending and all_results and attempt==0:
            pending.sort(key=lambda path:str(path)==monitor.current)
            todo=pending;continue
        for path in pending:all_results[str(path)]=verdict(monitor.messages.get(str(path),[]),complete,failure)
        break
    for (digest,_),items in groups.items():
        original=items[0];result=all_results.get(str(original),{'status':'incomplete','reason':'病毒引擎未完成该文件检查。'})
        for path in items:
            rows[str(path)]={**copy.deepcopy(result),'engine_invoked':True,'sha256':digest,
                            'identical_inputs':len(items),'execution':{'unique_inputs':len(groups),'attempts':attempts}}
    return rows,dbinfo
