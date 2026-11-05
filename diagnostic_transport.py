"""Small gzip-over-HTTP diagnostic transport with upload authorization."""
import hashlib
import http.client
import json
from urllib.parse import urlsplit

MAX_WIRE=12*1024*1024

def send(endpoint,payload,token,timeout=4):
    url=urlsplit(endpoint)
    if url.scheme!='http' or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ('','/'):
        raise ValueError('诊断地址必须为 HTTP 服务根地址。')
    if not 0<len(payload)<=MAX_WIRE:raise ValueError('诊断数据超过传输上限。')
    connection=http.client.HTTPConnection(url.hostname,url.port or 80,timeout=timeout)
    try:
        connection.request('POST','/v1/diagnostics',body=payload,headers={
            'Authorization':'Bearer '+token,'Content-Type':'application/gzip',
            'Content-Length':str(len(payload)),'X-Content-SHA256':hashlib.sha256(payload).hexdigest()})
        response=connection.getresponse();data=response.read(4097)
        if len(data)>4096 or response.status not in (200,201):raise ValueError('诊断服务拒绝接收，HTTP '+str(response.status))
        result=json.loads(data)
        if not result.get('accepted') or not result.get('receipt'):raise ValueError('诊断服务未返回有效接收凭据。')
        return result
    finally:connection.close()
