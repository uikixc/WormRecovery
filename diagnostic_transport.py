"""Small gzip-over-HTTP diagnostic transport with upload authorization."""
import hashlib
import http.client
import json
from urllib.parse import urlsplit

MAX_WIRE=12*1024*1024

def probe(endpoint,token=None,timeout=3):
    """Read-only service and upload-authorization check; sends no report."""
    url=urlsplit(endpoint)
    if url.scheme!='http' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('','/'):
        raise ValueError('诊断地址必须为 HTTP 服务根地址。')
    def request(path,headers=None):
        connection=http.client.HTTPConnection(url.hostname,url.port or 80,timeout=timeout)
        try:
            connection.request('GET',path,headers=headers or {})
            response=connection.getresponse();raw=response.read(4097)
            if len(raw)>4096:raise ValueError('连接检测返回内容超过上限。')
            try:body=json.loads(raw)
            except (ValueError,UnicodeError):body={}
            return response.status,body
        finally:connection.close()
    status,body=request('/health')
    if status!=200 or body.get('status')!='ready' or body.get('protocol')!=1:
        raise ValueError('目标未返回有效的日志服务状态，HTTP '+str(status))
    result={'reachable':True,'service':'ready','authorization':'not_verified'}
    status,body=request('/v1/upload-check',{'Authorization':'Bearer '+token} if token else {})
    if status==200 and body.get('authorized') is True:result['authorization']='accepted'
    elif status==401:result['authorization']='rejected'
    elif status==404:result['authorization']='check_unavailable'
    else:raise ValueError('授权检测响应无效，HTTP '+str(status))
    return result


def send(endpoint,payload,token,timeout=4):
    url=urlsplit(endpoint)
    if url.scheme!='http' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('','/'):
        raise ValueError('诊断地址必须为 HTTP 服务根地址。')
    if not 0<len(payload)<=MAX_WIRE:raise ValueError('诊断数据超过传输上限。')
    connection=http.client.HTTPConnection(url.hostname,url.port or 80,timeout=timeout)
    try:
        connection.request('POST','/v1/diagnostics',body=payload,headers={
            **({'Authorization':'Bearer '+token} if token else {}),'Content-Type':'application/gzip',
            'Content-Length':str(len(payload)),'X-Content-SHA256':hashlib.sha256(payload).hexdigest()})
        response=connection.getresponse();data=response.read(4097)
        if len(data)>4096 or response.status not in (200,201):raise ValueError('诊断服务拒绝接收，HTTP '+str(response.status))
        result=json.loads(data)
        if not result.get('accepted') or not result.get('receipt'):raise ValueError('诊断服务未返回有效接收凭据。')
        return result
    finally:connection.close()
