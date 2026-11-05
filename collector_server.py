"""Authenticated, encrypted diagnostics receiver. No specimen execution or remote commands."""
import argparse
import base64
import collections
import datetime
import gzip
import hashlib
import hmac
import ipaddress
import io
import json
import os
from pathlib import Path
import secrets
import ssl
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer

from diagnostic_transport import decrypt,MAX_WIRE


def initialize(directory,endpoints=None):
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec,x25519
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.x509.oid import NameOID
    directory=Path(directory);directory.mkdir(parents=True,exist_ok=True)
    config_path=directory/'collector-server.json'
    if config_path.exists():raise ValueError('服务配置已存在，拒绝覆盖现有密钥。')
    key=ec.generate_private_key(ec.SECP256R1());now=datetime.datetime.now(datetime.timezone.utc)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'WormRecovery Diagnostics')])
    certificate=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(now+datetime.timedelta(days=730)).add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(x)) for x in ('8.134.112.170','10.205.103.120','127.0.0.1')]),critical=False).sign(key,hashes.SHA256())
    private=x25519.X25519PrivateKey.generate()
    token=secrets.token_urlsafe(40);admin=secrets.token_urlsafe(40)
    upload_hash=hashlib.sha256(token.encode()).hexdigest()
    config={'schema':1,'bind':'0.0.0.0','port':10888,'directory':str(directory.resolve()/'received'),
            'certificate':str(directory.resolve()/'collector-cert.pem'),'tls_key':str(directory.resolve()/'collector-key.pem'),
            'encryption_private_key':base64.b64encode(private.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())).decode(),
            'upload_token_hash':upload_hash,'admin_token_hash':hashlib.sha256(admin.encode()).hexdigest(),
            'max_storage_bytes':10*1024*1024*1024,'retention_days':90}
    enrollment={'schema':1,'endpoints':endpoints or ['https://10.205.103.120:10888','https://8.134.112.170:10888'],
                'certificate_sha256':certificate.fingerprint(hashes.SHA256()).hex(),
                'encryption_public_key':base64.b64encode(private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode(),
                'upload_token':token}
    files={'collector-server.json':json.dumps(config,indent=2).encode(),
           'collector-cert.pem':certificate.public_bytes(serialization.Encoding.PEM),
           'collector-key.pem':key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),
           'devices.enroll':json.dumps(enrollment,indent=2).encode(),
           'admin-access.txt':admin.encode()}
    for filename,data in files.items():
        path=directory/filename
        with path.open('xb') as stream:stream.write(data)
        if os.name!='nt':path.chmod(0o600)
    if os.name!='nt':directory.chmod(0o700)
    return {'config':str(config_path),'enrollment':str(directory/'devices.enroll'),'port':10888}


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
        self.config=config;self.storage_lock=threading.Lock();self.slots=threading.BoundedSemaphore(8)
        self.rate={};self.rate_lock=threading.Lock()
        self.tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);self.tls.minimum_version=ssl.TLSVersion.TLSv1_2
        self.tls.load_cert_chain(config['certificate'],config['tls_key'])
        self.directory=Path(config['directory']);self.directory.mkdir(parents=True,exist_ok=True)
        if os.name!='nt':self.directory.chmod(0o700)
        self.bytes_used=sum(p.stat().st_size for p in self.directory.glob('*.json'))
        self.next_cleanup=0;self.cleanup()
        super().__init__(address,Handler)
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
            secure=self.tls.wrap_socket(request,server_side=True)
            super().process_request_thread(secure,address)
        except (OSError,ssl.SSLError):request.close()
        finally:self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version='WormRecoveryCollector/1'
    def setup(self):super().setup();self.connection.settimeout(20)
    def log_message(self,*args):pass
    def respond(self,status,body):
        data=json.dumps(body,separators=(',',':')).encode()
        self.send_response(status);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(data)));self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(data)
    def do_GET(self):
        if self.path=='/health':self.respond(200,{'status':'ready','protocol':1})
        elif self.path=='/v1/status':
            if not self.authorized('admin_token_hash'):self.respond(401,{'error':'unauthorized'});return
            self.respond(200,{'status':'ready','stored_bytes':self.server.bytes_used,
                              'reports':len(list(self.server.directory.glob('*.json'))),
                              'retention_days':self.server.config.get('retention_days',90)})
        else:self.respond(404,{'error':'not_found'})
    def authorized(self,role):
        auth=self.headers.get('Authorization','')
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
            encrypted=self.rfile.read(length)
            if len(encrypted)!=length:raise ValueError('truncated')
            record,raw=validate_bundle(decrypt(encrypted,self.server.config['encryption_private_key']))
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
    versions=collections.Counter();groups=collections.Counter();devices=set();reports=0
    paths=sorted(Path(directory).glob('*.json'),key=lambda p:p.stat().st_mtime,reverse=True)
    for path in paths[:limit]:
        if path.stat().st_size>20*1024**2:continue
        try:
            record=json.loads(path.read_text(encoding='utf-8'));reports+=1;devices.add(record['device_id']);versions[record.get('application_version','unknown')]+=1
            for row in record.get('report',{}).get('findings',[]):
                if row.get('kind','').startswith('review_'):
                    key=(row.get('analysis_sha256') or row.get('sha256') or row.get('vba_hash') or 'no_hash',
                         str(row.get('assessment') or row.get('reason','unknown')))
                    groups[key]+=1
        except (ValueError,KeyError,OSError,TypeError,AttributeError):continue
    return {'reports':reports,'devices':len(devices),'versions':dict(versions),'report_limit':limit,'total_stored':len(paths),
            'review_groups':[{'sha256':key[0],'assessment':key[1],'occurrences':n} for key,n in groups.most_common(200)]}


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    init=sub.add_parser('init');init.add_argument('--directory',required=True)
    serve=sub.add_parser('serve');serve.add_argument('--config',required=True)
    summary=sub.add_parser('summary');summary.add_argument('--directory',required=True)
    args=parser.parse_args()
    if args.command=='init':print(json.dumps(initialize(args.directory)));return
    if args.command=='summary':print(json.dumps(summarize(args.directory),ensure_ascii=False,indent=2));return
    config=json.loads(Path(args.config).read_text(encoding='utf-8'))
    server=Collector((config.get('bind','0.0.0.0'),config.get('port',10888)),config)
    print('WormRecovery diagnostics receiver listening on port '+str(server.server_port),flush=True)
    try:server.serve_forever(poll_interval=.5)
    finally:server.server_close()


if __name__=='__main__':main()
