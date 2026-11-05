"""Validate built receiver and embedded client using only local inert reports."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import psutil

import diagnostic_transport


def validate(receiver,client,output):
    started=time.monotonic();checks={};process=None
    with tempfile.TemporaryDirectory(prefix='WormRecovery-Diagnostics-') as temporary:
        root=Path(temporary);data=root/'collector-data';state=root/'userdata';state.mkdir()
        env=os.environ.copy();env['LOCALAPPDATA']=str(state)
        def run(exe,*args):
            result=subprocess.run([str(Path(exe).resolve()),*map(str,args)],env=env,capture_output=True,timeout=45,
                                  creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            if result.returncode:raise RuntimeError('Fixture command failed: '+result.stdout.decode('utf-8','replace')[-700:]+' '+result.stderr.decode('utf-8','replace')[-700:])
            return result
        run(receiver,'init','--directory',data)
        config=json.loads((data/'collector-server.json').read_text())
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
        config.update(bind='127.0.0.1',port=port)
        configpath=data/'collector-server.json';configpath.write_text(json.dumps(config))
        enrollment=json.loads((data/'devices.enroll').read_text());enrollment['endpoints']=['http://127.0.0.1:'+str(port)]
        enrollmentpath=data/'devices.enroll';enrollmentpath.write_text(json.dumps(enrollment))
        report=root/'report.json';report.write_text(json.dumps({'version':'1.7.0','files':3,'errors':[],
            'findings':[{'kind':'review_office','path':'C:/Users/FixtureUser/inert.xlsm','analysis_sha256':'a'*64,
                         'reason':'Inert evidence','password':'fixture-secret'}]}))
        before=hashlib.sha256(report.read_bytes()).hexdigest()
        try:
            process=subprocess.Popen([str(receiver),'serve','--config',str(configpath)],stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            deadline=time.monotonic()+25
            while time.monotonic()<deadline:
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.3):break
                except OSError:time.sleep(.1)
            run(client,'--enroll-diagnostics',enrollmentpath)
            run(client,'--submit-diagnostics',report)
            received=list((data/'received').glob('*.json'));checks['built_client_and_receiver_deliver']=len(received)==1
            if received:
                text=received[0].read_text();record=json.loads(text)
                checks['private_fields_removed']='fixture-secret' not in text and 'FixtureUser' not in text
                checks['review_evidence_retained']=record['report']['findings'][0]['analysis_sha256']=='a'*64
                checks['receipt_persisted']=(state/'WormRecovery/diagnostics/receipts.jsonl').is_file()
            checks['original_report_unchanged']=hashlib.sha256(report.read_bytes()).hexdigest()==before
            protected=state/'WormRecovery/diagnostics/collector.dpapi'
            checks['authorization_protected']=protected.is_file() and enrollment['upload_token'].encode() not in protected.read_bytes()
            run(client,'--disable-diagnostics')
            checks['pause_removes_enrollment']=not protected.exists()
            summary=json.loads(run(receiver,'summary','--directory',data/'received').stdout)
            checks['built_receiver_groups_reviews']=summary['reports']==1 and summary['review_groups'][0]['sha256']=='a'*64
        finally:
            if process and process.poll() is None:
                owned=psutil.Process(process.pid);children=owned.children(recursive=True)
                for child in reversed(children):
                    try:child.terminate()
                    except psutil.NoSuchProcess:pass
                process.terminate();process.wait(timeout=10);psutil.wait_procs(children,timeout=5)
    result={'passed':all(checks.values()),'checks':checks,'elapsed_seconds':round(time.monotonic()-started,3),
            'scope':'Loopback HTTP and inert report only; no external upload or document execution'}
    Path(output).write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))
    return 0 if result['passed'] else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for name in ('receiver','client','output'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args();raise SystemExit(validate(args.receiver,args.client,args.output))
