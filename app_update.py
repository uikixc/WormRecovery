"""GitHub release checks, authenticated private downloads and public mirrors."""
from concurrent.futures import ThreadPoolExecutor,as_completed
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import socket
import ssl

from update_security import REPOSITORY,load_token,verify_manifest,verify_file,version_tuple

API='https://api.github.com/repos/'+REPOSITORY
PUBLIC_MIRRORS=(('GitHub 直连',''),('GH-Proxy','https://gh-proxy.com/'),
                ('GHFast','https://ghfast.top/'),('GHProxy.net','https://ghproxy.net/'))
MIRROR_HOSTS={'gh-proxy.com','gh-proxy.org','ghfast.top','ghproxy.net'}
MAX_METADATA=256*1024


class UpdateError(Exception):pass


def trusted_github_host(host):
    return host in ('github.com','api.github.com','uploads.github.com') or host.endswith('.githubusercontent.com')


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,message,headers,newurl):
        target=urllib.parse.urlsplit(newurl)
        if target.scheme!='https' or target.username or target.password or not (trusted_github_host(target.hostname or '') or target.hostname in MIRROR_HOSTS):
            raise UpdateError('更新下载跳转到未允许的地址。')
        redirected=super().redirect_request(request,fp,code,message,headers,newurl)
        if redirected and urllib.parse.urlsplit(request.full_url).hostname!=target.hostname:
            redirected.remove_header('Authorization')
        return redirected


def open_url(url,token=None,accept='application/vnd.github+json',extra_headers=None,timeout=10):
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme!='https' or parsed.username or parsed.password:raise UpdateError('更新地址无效。')
    headers={'User-Agent':'WormRecovery-Updater','Accept':accept}
    if token:
        if parsed.hostname!='api.github.com':raise UpdateError('私有凭据只能发送给 GitHub API。')
        headers['Authorization']='Bearer '+token
    headers.update(extra_headers or {})
    request=urllib.request.Request(url,headers=headers)
    return urllib.request.build_opener(SafeRedirect()).open(request,timeout=timeout)


def read_json(url,token=None,asset=False):
    try:
        with open_url(url,token,accept='application/octet-stream' if asset else 'application/vnd.github+json') as response:
            data=response.read(MAX_METADATA+1)
        if len(data)>MAX_METADATA:raise UpdateError('更新元数据超过限制。')
        document=json.loads(data.decode('utf-8-sig'))
        if not isinstance(document,dict):raise ValueError('metadata object expected')
        return document
    except urllib.error.HTTPError as ex:
        if ex.code in (401,403):raise UpdateError('GitHub 授权无效、权限不足或访问频率受限，请检查更新设置。') from None
        if ex.code==404:raise UpdateError('尚无正式 Release，或当前设备无权读取此私有仓库。') from None
        raise UpdateError('GitHub 请求失败：HTTP '+str(ex.code)) from None
    except (OSError,ValueError) as ex:
        cause=getattr(ex,'reason',ex)
        if isinstance(cause,(TimeoutError,socket.timeout)):reason='连接超时'
        elif isinstance(cause,socket.gaierror):reason='DNS 名称解析失败'
        elif isinstance(cause,ssl.SSLCertVerificationError):reason='HTTPS 证书验证失败'
        elif isinstance(cause,ssl.SSLError):reason='TLS 连接失败'
        elif isinstance(ex,ValueError):reason='服务返回的版本清单格式无效'
        else:reason='网络连接失败'
        raise UpdateError(reason+'；离线检测和恢复仍可使用。') from None


def validate_asset_url(url,tag):
    parsed=urllib.parse.urlsplit(url)
    prefix='/'+REPOSITORY+'/releases/download/'+tag+'/'
    if parsed.scheme!='https' or parsed.hostname!='github.com' or parsed.query or parsed.fragment or not parsed.path.startswith(prefix):
        raise UpdateError('Release 附件地址与当前仓库不一致。')
    return url


def _api_check(current_version,token=None):
    repository=read_json(API,token)
    private=repository.get('private')
    if type(private) is not bool:raise UpdateError('无法确认仓库可见性。')
    try:release=read_json(API+'/releases/latest',token)
    except UpdateError as ex:
        ex.private=private;raise
    if release.get('draft') or release.get('prerelease'):raise UpdateError('更新版本不是正式发布。')
    latest=version_tuple(release.get('tag_name'))
    if latest<=version_tuple(current_version):return {'available':False,'version':release['tag_name'].lstrip('v'),'private':private}
    assets={x.get('name'):x for x in release.get('assets',[]) if x.get('state')=='uploaded'}
    if not all(name in assets for name in ('update-manifest.json','WormRecovery.exe')):raise UpdateError('此 Release 缺少完整更新附件。')
    for item in assets.values():
        if type(item.get('id')) is not int:raise UpdateError('Release 附件标识无效。')
    try:signed=read_json(API+'/releases/assets/'+str(assets['update-manifest.json']['id']),token,asset=True)
    except UpdateError as ex:
        ex.private=private;raise
    payload=verify_manifest(signed)
    if version_tuple(payload['version'])!=latest or assets['WormRecovery.exe'].get('size')!=payload['bytes']:
        raise UpdateError('签名清单与 Release 附件不一致。')
    validate_asset_url(assets['WormRecovery.exe']['browser_download_url'],release['tag_name'])
    return {'available':True,'version':payload['version'],'private':private,'manifest':signed,
        'asset_id':assets['WormRecovery.exe']['id'],'public_url':assets['WormRecovery.exe']['browser_download_url'],
        'notes':str(release.get('body',''))[:12000]}


def public_manifest_check(current_version,api_error):
    """Public channel fallback independent of API availability; always verify signature."""
    url='https://github.com/'+REPOSITORY+'/releases/latest/download/update-manifest.json'
    routes=[(name,prefix+url) for name,prefix in PUBLIC_MIRRORS]
    successes=[];failures=[]
    def fetch(route):
        name,target=route
        try:
            signed=read_json(target,token='',asset=True)
            payload=verify_manifest(signed)
            return name,signed,payload,None
        except Exception as ex:
            return name,None,None,str(ex) if isinstance(ex,UpdateError) else '发布签名或清单校验失败'
    with ThreadPoolExecutor(max_workers=4) as executor:
        for future in as_completed([executor.submit(fetch,route) for route in routes]):
            name,signed,payload,error=future.result()
            if payload:successes.append((version_tuple(payload['version']),name,signed,payload))
            else:failures.append(name+'：'+error)
    if not successes:
        raise UpdateError('版本检查未完成。GitHub API：'+str(api_error)+'；备用线路：'+'；'.join(failures))
    latest,name,signed,payload=max(successes,key=lambda item:item[0])
    available=latest>version_tuple(current_version)
    return {'available':available,'version':payload['version'],'private':False,'manifest':signed,
            'asset_id':None,'public_url':'https://github.com/'+REPOSITORY+'/releases/download/v'+payload['version']+'/WormRecovery.exe',
            'notes':'','metadata_route':name,'metadata_fallback':True,
            'diagnostics':'GitHub API 未完成，已通过备用线路获取并验证发布清单。'}


def check_update(current_version,token=None):
    if token is None:
        try:token=load_token()
        except OSError:token=''
    try:return _api_check(current_version,token)
    except UpdateError as ex:
        if getattr(ex,'private',False):raise
        return public_manifest_check(current_version,ex)


def routes_for(info):
    # Never disclose private URLs, signed redirects or tokens to public mirrors.
    if info['private']:return [('GitHub 私有直连',API+'/releases/assets/'+str(info['asset_id']))]
    return [(name,prefix+info['public_url']) for name,prefix in PUBLIC_MIRRORS]


def probe_route(route,size):
    name,url=route;started=time.monotonic()
    try:
        amount=min(512*1024,size)
        with open_url(url,accept='application/octet-stream',extra_headers={'Range':'bytes=0-'+str(amount-1)},timeout=6) as response:
            data=response.read(amount)
            if response.status not in (200,206) or len(data)!=amount or not data.startswith(b'MZ'):raise ValueError('invalid response')
        return {'name':name,'url':url,'seconds':time.monotonic()-started,'bytes':len(data)}
    except Exception:return None


def cache_root():
    root=Path(os.environ.get('LOCALAPPDATA',str(Path.home()/'AppData/Local')))/'WormRecovery/updates'
    root.mkdir(parents=True,exist_ok=True)
    return root


def download_update(info,progress=lambda value:None,cancel=None,token=None):
    payload=verify_manifest(info['manifest']);token=load_token() if token is None else token
    root=cache_root()/('v'+payload['version']);root.mkdir(parents=True,exist_ok=True)
    destination=root/'WormRecovery.exe'
    if destination.is_file():
        try:verify_file(destination,payload);return destination
        except ValueError:destination.unlink()
    routes=routes_for(info)
    if not info['private']:
        progress({'phase':'routes','message':'正在测试下载线路'})
        with ThreadPoolExecutor(max_workers=4) as executor:
            probes=list(executor.map(lambda route:probe_route(route,payload['bytes']),routes))
        ranked=sorted((p for p in probes if p),key=lambda p:p['seconds'])
        routes=[(p['name'],p['url']) for p in ranked]+[r for r in routes if r[1] not in {p['url'] for p in ranked}]
    failures=[]
    for name,url in routes:
        partial=root/'WormRecovery.exe.partial'
        try:
            if cancel is not None and cancel.is_set():raise InterruptedError('更新下载已停止。')
            digest=hashlib.sha256();written=0;started=time.monotonic();last=0
            with open_url(url,token if info['private'] else None,accept='application/octet-stream',timeout=12) as response, partial.open('wb') as output:
                while True:
                    if cancel is not None and cancel.is_set():raise InterruptedError('更新下载已停止。')
                    if time.monotonic()-started>900:raise TimeoutError('download deadline')
                    chunk=response.read(1024*1024)
                    if not chunk:break
                    written+=len(chunk)
                    if written>payload['bytes']:raise ValueError('更新大小超过签名清单。')
                    digest.update(chunk);output.write(chunk)
                    if time.monotonic()-last>=.3:
                        last=time.monotonic();progress({'phase':'download','route':name,'received':written,'total':payload['bytes']})
                output.flush();os.fsync(output.fileno())
            if written!=payload['bytes'] or digest.hexdigest()!=payload['sha256']:raise ValueError('更新校验失败。')
            verify_file(partial,payload);os.replace(partial,destination)
            (root/'update-manifest.json').write_text(json.dumps(info['manifest'],ensure_ascii=True),encoding='utf-8')
            progress({'phase':'ready','route':name,'received':written,'total':payload['bytes']})
            return destination
        except InterruptedError:
            partial.unlink(missing_ok=True);raise
        except Exception:
            partial.unlink(missing_ok=True);failures.append(name)
    raise UpdateError('更新下载未完成，原程序保持不变。已尝试：'+'、'.join(failures))
