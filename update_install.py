"""Verified same-path application replacement after the current GUI exits."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

import psutil
from update_security import verify_manifest,verify_file


def file_hash(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def check_plain_path(path):
    path=Path(path)
    if not path.is_absolute() or path.suffix.casefold()!='.exe':raise ValueError('更新目标路径无效。')
    for item in (path,*path.parents):
        if item.exists() and getattr(item.lstat(),'st_file_attributes',0)&0x400:
            raise ValueError('更新目标包含重解析点，不能原位替换。')
    return path


def wait_for_processes(identities,timeout=90):
    deadline=time.monotonic()+timeout
    while True:
        active=False
        for identity in identities:
            try:
                process=psutil.Process(identity['pid'])
                if abs(process.create_time()-identity['created'])<.01 and process.is_running():active=True
            except psutil.NoSuchProcess:pass
        if not active:return
        if time.monotonic()>deadline:raise TimeoutError('原程序尚未退出，更新未替换任何文件。')
        time.sleep(.2)


def replace_verified(source,target,signed,old_hash):
    source=check_plain_path(source);target=check_plain_path(target)
    payload=verify_manifest(signed);verify_file(source,payload)
    if not target.is_file() or file_hash(target)!=old_hash:raise ValueError('原程序已变化，更新已停止。')
    stage=target.with_name(target.name+'.update-new');backup=target.with_name(target.name+'.backup-'+old_hash[:12])
    if stage.exists() or backup.exists():raise ValueError('存在上次更新备份，请先检查更新日志，未覆盖现有备份。')
    shutil.copyfile(source,stage)
    try:
        verify_file(stage,payload)
        os.replace(target,backup)
        try:
            os.replace(stage,target)
            verify_file(target,payload)
        except Exception:
            target.unlink(missing_ok=True)
            os.replace(backup,target)
            raise
    finally:stage.unlink(missing_ok=True)
    return backup


def run_job(job_path):
    job_path=Path(job_path);record={'success':False}
    try:
        if job_path.stat().st_size>65536:raise ValueError('更新任务超过大小限制。')
        job=json.loads(job_path.read_text(encoding='utf-8'))
        payload=verify_manifest(job['manifest'])
        if Path(job['source']).resolve().parent!=job_path.resolve().parent:raise ValueError('更新文件不在任务工作目录中。')
        wait_for_processes(job['parents'])
        backup=replace_verified(Path(job['source']),Path(job['target']),job['manifest'],job['old_sha256'])
        try:
            if job.get('relaunch',True):
                environment=os.environ.copy();environment['PYINSTALLER_RESET_ENVIRONMENT']='1'
                for key in ('WORMRECOVERY_ENGINE_ROOT','WORMRECOVERY_WORK_ROOT'):environment.pop(key,None)
                subprocess.Popen([job['target']],cwd=str(Path(job['target']).parent),env=environment,
                    creationflags=getattr(subprocess,'CREATE_NEW_PROCESS_GROUP',0)|getattr(subprocess,'CREATE_NO_WINDOW',0))
        except Exception:
            Path(job['target']).unlink(missing_ok=True)
            os.replace(backup,job['target'])
            raise
        record={'success':True,'version':payload['version'],'target':job['target'],'backup':str(backup)}
    except Exception as ex:record={'success':False,'error':str(ex)[:700]}
    job_path.with_name('install-result.json').write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf-8')
    return 0 if record['success'] else 1


def start_install(downloaded,manifest,target=None):
    if not getattr(sys,'frozen',False):raise ValueError('源码运行模式不替换 Python，请使用发行版安装更新。')
    from bundled_components import component_path
    downloaded=Path(downloaded).resolve();target=check_plain_path(Path(target or sys.executable).resolve())
    payload=verify_manifest(manifest);verify_file(downloaded,payload)
    identities=[]
    for process in (psutil.Process(),psutil.Process().parent()):
        if process and os.path.normcase(process.exe())==os.path.normcase(str(target)):
            identities.append({'pid':process.pid,'created':process.create_time()})
    helper=downloaded.parent/'WormRecovery-Updater.exe'
    shutil.copy2(component_path('WormRecovery-CLI.exe'),helper)
    job_path=downloaded.parent/'install-job.json'
    job={'source':str(downloaded),'target':str(target),'old_sha256':file_hash(target),
         'manifest':manifest,'parents':identities,'relaunch':True}
    job_path.write_text(json.dumps(job,ensure_ascii=True),encoding='utf-8')
    environment=os.environ.copy();environment['PYINSTALLER_RESET_ENVIRONMENT']='1'
    for key in ('WORMRECOVERY_ENGINE_ROOT','WORMRECOVERY_WORK_ROOT'):environment.pop(key,None)
    subprocess.Popen([str(helper),'--apply-update',str(job_path)],cwd=str(downloaded.parent),env=environment,
        stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)|getattr(subprocess,'CREATE_NEW_PROCESS_GROUP',0))
    return job_path
