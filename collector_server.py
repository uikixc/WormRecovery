"""Authorized gzip-over-HTTP diagnostics receiver. No specimen execution or remote commands."""
import argparse
import collections
import datetime
import gzip
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import secrets
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer

from diagnostic_transport import MAX_WIRE
from diagnostic_routes import DEFAULT_ENDPOINTS
from collector_updates import UpdateStore, serve_update


def initialize(directory,endpoints=None):
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    config_path=directory/'collector-server.json'
    if config_path.exists():raise ValueError('服务配置已存在，拒绝覆盖现有授权。')
    token=secrets.token_urlsafe(40);admin=secrets.token_urlsafe(40)
    config={'schema':2,'bind':'0.0.0.0','port':10888,'directory':str(directory.resolve()/'received'),'allow_anonymous_upload':True,
            'upload_token_hash':hashlib.sha256(token.encode()).hexdigest(),
            'admin_token_hash':hashlib.sha256(admin.encode()).hexdigest(),
            'max_storage_bytes':10*1024*1024*1024,'retention_days':90}
    enrollment={'schema':2,'endpoints':endpoints or list(DEFAULT_ENDPOINTS),'upload_token':token}
    files={'collector-server.json':json.dumps(config,indent=2).encode(),
           'devices.enroll':json.dumps(enrollment,indent=2).encode(),'admin-access.txt':admin.encode()}
    for filename,data in files.items():
        path=directory/filename
        with path.open('xb') as stream:stream.write(data)
        if os.name!='nt':path.chmod(0o600)
    if os.name!='nt':directory.chmod(0o700)
    return {'config':str(config_path),'enrollment':str(directory/'devices.enroll'),'port':10888,'transport':'http-gzip'}


def migrate_http(directory):
    directory=Path(directory);config_path=directory/'collector-server.json';device_path=directory/'devices.enroll'
    config=json.loads(config_path.read_text(encoding='utf-8'));device=json.loads(device_path.read_text(encoding='utf-8'))
    if config.get('schema')==2:return {'transport':'http-gzip','changed':False}
    if config.get('schema')!=1 or device.get('schema')!=1:raise ValueError('现有服务配置版本无效。')
    for path in (config_path,device_path):
        backup=path.with_name(path.name+'.v1-backup')
        if not backup.exists():backup.write_bytes(path.read_bytes())
    config={key:value for key,value in config.items() if key not in ('certificate','tls_key','encryption_private_key')}
    config['schema']=2
    device={key:value for key,value in device.items() if key not in ('certificate_sha256','encryption_public_key')}
    device.update(schema=2,endpoints=[value.replace('https://','http://',1) for value in device['endpoints']])
    for path,value in ((config_path,config),(device_path,device)):
        temporary=path.with_suffix('.new');temporary.write_text(json.dumps(value,indent=2),encoding='utf-8');os.replace(temporary,path)
    return {'transport':'http-gzip','changed':True,'enrollment':str(device_path)}


def validate_bundle(data):
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as source:raw=source.read(20*1024*1024+1)
    if len(raw)>20*1024*1024:raise ValueError('诊断解压数据超过上限。')
    record=json.loads(raw)
    if record.get('schema')!=1:raise ValueError('诊断格式无效。')
    for name in ('bundle_id','device_id'):uuid.UUID(record[name])
    if str(uuid.UUID(record['bundle_id']))!=record['bundle_id']:raise ValueError('诊断编号必须为标准 UUID。')
    if not isinstance(record.get('report'),dict) or not isinstance(record.get('journal'),list):raise ValueError('诊断内容无效。')
    findings=record['report'].get('findings',[])
    if not isinstance(findings,list) or not all(isinstance(x,dict) for x in findings):raise ValueError('检测项目格式无效。')
    return record,raw


class Collector(ThreadingHTTPServer):
    daemon_threads=True
    def __init__(self,address,config):
        self.config=config;self.storage_lock=threading.Lock();self.request_lock=threading.Lock();self.slots=threading.BoundedSemaphore(8)
        self.rate={};self.rate_lock=threading.Lock()
        if config.get('schema')!=2:raise ValueError('服务需要先迁移至 HTTP 配置。')
        self.directory=Path(config['directory']);self.directory.mkdir(parents=True,exist_ok=True)
        self.updates=UpdateStore(config.get('updates_directory',self.directory.parent/'updates'))
        if os.name!='nt':self.directory.chmod(0o700)
        self.bytes_used=sum(p.stat().st_size for p in self.directory.glob('*.json'))
        self.next_cleanup=0;self.cleanup()
        super().__init__(address,Handler)
    def record_request(self,record):
        # No payload, Authorization header, user-agent, or query string is retained.
        path=self.directory.parent/'receiver-requests.jsonl'
        with self.request_lock:
            if path.exists() and path.stat().st_size>2*1024*1024:
                os.replace(path,path.with_suffix('.previous'))
            with path.open('a',encoding='utf-8') as stream:
                stream.write(json.dumps(record,ensure_ascii=True)+'\n')
    def cleanup(self):
        with self.storage_lock:
            if time.monotonic()<self.next_cleanup:return
            cutoff=time.time()-max(1,int(self.config.get('retention_days',90)))*86400
            for path in self.directory.glob('*.json'):
                try:
                    if path.stat().st_mtime<cutoff:
                        size=path.stat().st_size;path.unlink();self.bytes_used-=size
                except OSError:continue
            self.next_cleanup=time.monotonic()+3600
    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):request.close();return
        try:super().process_request(request,address)
        except Exception:self.slots.release();raise
    def process_request_thread(self,request,address):
        try:
            request.settimeout(10)
            super().process_request_thread(request,address)
        except OSError:request.close()
        finally:self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version='WormRecoveryCollector/1'
    def setup(self):super().setup();self.connection.settimeout(20)
    def log_message(self,*args):pass
    def respond(self,status,body):
        if self.command=='POST':
            record={'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'remote_address':self.client_address[0],'status':status,'method':'POST',
                    'endpoint':'diagnostics' if self.path=='/v1/diagnostics' else 'other'}
            if body.get('receipt'):record['receipt']=body['receipt']
            if body.get('error'):record['error']=body['error']
            try:self.server.record_request(record)
            except OSError:pass
        data=json.dumps(body,separators=(',',':')).encode()
        self.send_response(status);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(data)));self.send_header('Cache-Control','no-store');self.end_headers()
        if self.command!='HEAD':self.wfile.write(data)
    def do_HEAD(self):self.do_GET()
    def do_GET(self):
        if serve_update(self):return
        if self.path=='/health':self.respond(200,{'status':'ready','protocol':1})
        elif self.path=='/v1/upload-check':
            if not self.authorized('upload_token_hash'):self.respond(401,{'error':'unauthorized'});return
            self.respond(200,{'status':'ready','protocol':1,'authorized':True})
        elif self.path=='/v1/status':
            if not self.authorized('admin_token_hash'):self.respond(401,{'error':'unauthorized'});return
            self.respond(200,{'status':'ready','stored_bytes':self.server.bytes_used,
                              'reports':len(list(self.server.directory.glob('*.json'))),
                              'retention_days':self.server.config.get('retention_days',90)})
        else:self.respond(404,{'error':'not_found'})
    def authorized(self,role):
        auth=self.headers.get('Authorization','')
        if role=='upload_token_hash' and not auth and self.server.config.get('allow_anonymous_upload') is True:return True
        if not auth.startswith('Bearer '):return False
        token=auth[7:]
        return len(token)<=200 and hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(),self.server.config[role])
    def do_POST(self):
        if self.path!='/v1/diagnostics':self.respond(404,{'error':'not_found'});return
        if not self.authorized('upload_token_hash'):
            self.close_connection=True;self.respond(401,{'error':'unauthorized'});return
        with self.server.rate_lock:
            now=time.monotonic();key=self.client_address[0];entries=[t for t in self.server.rate.get(key,[]) if now-t<60]
            if len(self.server.rate)>4096:
                self.server.rate={k:v for k,v in self.server.rate.items() if v and now-v[-1]<60}
                if len(self.server.rate)>4096:self.server.rate.clear()
            if len(entries)>=30:self.close_connection=True;self.respond(429,{'error':'rate_limited'});return
            self.server.rate[key]=entries+[now]
        try:
            length=int(self.headers.get('Content-Length','0'))
            if self.headers.get('Transfer-Encoding') or not 0<length<=MAX_WIRE:raise ValueError('size')
            payload=self.rfile.read(length)
            if len(payload)!=length:raise ValueError('truncated')
            expected=self.headers.get('X-Content-SHA256','')
            if not hmac.compare_digest(hashlib.sha256(payload).hexdigest(),expected):raise ValueError('digest')
            record,raw=validate_bundle(payload)
            receipt=record['bundle_id'];path=self.server.directory/(receipt+'.json')
            self.server.cleanup()
            with self.server.storage_lock:
                if path.exists():
                    if hashlib.sha256(path.read_bytes()).digest()!=hashlib.sha256(raw).digest():
                        self.respond(409,{'error':'receipt_conflict'});return
                else:
                    if self.server.bytes_used+len(raw)>self.server.config.get('max_storage_bytes',10*1024**3):
                        self.respond(507,{'error':'storage_full'});return
                    temporary=path.with_suffix('.partial')
                    try:
                        with temporary.open('xb') as stream:stream.write(raw)
                        if os.name!='nt':temporary.chmod(0o600)
                        os.replace(temporary,path)
                    finally:temporary.unlink(missing_ok=True)
                    self.server.bytes_used+=len(raw)
            self.respond(201,{'accepted':True,'receipt':receipt,'received_at':datetime.datetime.now(datetime.timezone.utc).isoformat()})
        except Exception:
            self.close_connection=True;self.respond(400,{'error':'invalid_diagnostic_envelope'})


def summarize(directory,limit=1000):
    versions=collections.Counter();groups=collections.Counter();operations=collections.Counter();devices=set();reports=0
    paths=sorted(Path(directory).glob('*.json'),key=lambda p:p.stat().st_mtime,reverse=True)
    for path in paths[:limit]:
        if path.stat().st_size>20*1024**2:continue
        try:
            record=json.loads(path.read_text(encoding='utf-8'));reports+=1;devices.add(record['device_id']);versions[record.get('application_version','unknown')]+=1
            operations[record.get('operation',{}).get('type','legacy_unclassified')]+=1
            for row in record.get('report',{}).get('findings',[]):
                if row.get('kind','').startswith('review_'):
                    key=(row.get('analysis_sha256') or row.get('sha256') or row.get('vba_hash') or 'no_hash',
                         str(row.get('assessment') or row.get('reason','unknown')))
                    groups[key]+=1
        except (ValueError,KeyError,OSError,TypeError,AttributeError):continue
    return {'reports':reports,'devices':len(devices),'versions':dict(versions),'operations':dict(operations),'report_limit':limit,'total_stored':len(paths),
            'review_groups':[{'sha256':key[0],'assessment':key[1],'occurrences':n} for key,n in groups.most_common(200)]}


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    init=sub.add_parser('init');init.add_argument('--directory',required=True)
    serve=sub.add_parser('serve');serve.add_argument('--config',required=True)
    migrate=sub.add_parser('migrate-http');migrate.add_argument('--directory',required=True)
    summary=sub.add_parser('summary');summary.add_argument('--directory',required=True)
    args=parser.parse_args()
    if args.command=='init':print(json.dumps(initialize(args.directory)));return
    if args.command=='migrate-http':print(json.dumps(migrate_http(args.directory)));return
    if args.command=='summary':print(json.dumps(summarize(args.directory),ensure_ascii=False,indent=2));return
    config=json.loads(Path(args.config).read_text(encoding='utf-8'))
    server=Collector((config.get('bind','0.0.0.0'),config.get('port',10888)),config)
    print('WormRecovery diagnostics receiver listening on port '+str(server.server_port),flush=True)
    try:server.serve_forever(poll_interval=.5)
    finally:server.server_close()


if __name__=='__main__':main()
