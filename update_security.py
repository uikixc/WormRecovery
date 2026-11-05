"""Signed release metadata and Windows-protected local credentials."""
import base64
import ctypes
from ctypes import wintypes as W
import hashlib
import json
import re

REPOSITORY='uikixc/WormRecovery'
CREDENTIAL_TARGET='WormRecovery/GitHub/'+REPOSITORY


def version_tuple(value):
    match=re.fullmatch(r'v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)',str(value))
    if not match:raise ValueError('版本号格式无效。')
    return tuple(map(int,match.groups()))


def canonical(payload):
    return json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')


def verify_manifest(document,public_key=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from update_trust import UPDATE_PUBLIC_KEY
    if not isinstance(document,dict) or set(document)!={'payload','signature'}:raise ValueError('更新清单结构无效。')
    payload=document['payload']
    try:
        key=base64.b64decode(public_key or UPDATE_PUBLIC_KEY,validate=True)
        Ed25519PublicKey.from_public_bytes(key).verify(base64.b64decode(document['signature'],validate=True),canonical(payload))
    except Exception as ex:raise ValueError('更新发布签名无效，已拒绝更新。') from ex
    if payload.get('schema')!=1 or payload.get('repository')!=REPOSITORY:raise ValueError('更新来源不匹配。')
    version_tuple(payload.get('version'))
    if payload.get('platform')!='windows-x64' or payload.get('asset')!='WormRecovery.exe':raise ValueError('更新包平台或文件名无效。')
    if not re.fullmatch('[0-9a-f]{64}',str(payload.get('sha256'))):raise ValueError('更新哈希无效。')
    if type(payload.get('bytes')) is not int or not 1024<=payload['bytes']<=2*1024*1024*1024:raise ValueError('更新文件大小无效。')
    return payload


def verify_file(path,payload):
    with open(path,'rb') as stream:
        if stream.read(2)!=b'MZ':raise ValueError('更新文件不是 Windows 程序。')
        stream.seek(0)
        digest=hashlib.file_digest(stream,'sha256').hexdigest()
    if path.stat().st_size!=payload['bytes'] or digest!=payload['sha256']:raise ValueError('更新文件校验失败，已拒绝安装。')


class Credential(ctypes.Structure):
    _fields_=[('Flags',W.DWORD),('Type',W.DWORD),('TargetName',W.LPWSTR),('Comment',W.LPWSTR),
        ('LastWritten',W.FILETIME),('CredentialBlobSize',W.DWORD),('CredentialBlob',ctypes.POINTER(ctypes.c_ubyte)),
        ('Persist',W.DWORD),('AttributeCount',W.DWORD),('Attributes',ctypes.c_void_p),
        ('TargetAlias',W.LPWSTR),('UserName',W.LPWSTR)]


def credential_api():
    api=ctypes.WinDLL('advapi32',use_last_error=True)
    api.CredReadW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,ctypes.POINTER(ctypes.POINTER(Credential))]
    api.CredReadW.restype=W.BOOL
    api.CredWriteW.argtypes=[ctypes.POINTER(Credential),W.DWORD];api.CredWriteW.restype=W.BOOL
    api.CredDeleteW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD];api.CredDeleteW.restype=W.BOOL
    api.CredFree.argtypes=[ctypes.c_void_p]
    return api


def load_token():
    api=credential_api();pointer=ctypes.POINTER(Credential)()
    if not api.CredReadW(CREDENTIAL_TARGET,1,0,ctypes.byref(pointer)):
        if ctypes.get_last_error()==1168:return None
        raise ctypes.WinError(ctypes.get_last_error())
    try:return ctypes.string_at(pointer.contents.CredentialBlob,pointer.contents.CredentialBlobSize).decode('utf-8')
    finally:api.CredFree(pointer)


def save_token(token):
    token=token.strip()
    if not re.fullmatch(r'[A-Za-z0-9_]{20,255}',token):raise ValueError('访问令牌格式无效。')
    data=token.encode('utf-8');buffer=ctypes.create_string_buffer(data)
    record=Credential();record.Type=1;record.TargetName=CREDENTIAL_TARGET;record.Persist=2
    record.UserName='GitHub';record.CredentialBlobSize=len(data);record.CredentialBlob=ctypes.cast(buffer,ctypes.POINTER(ctypes.c_ubyte))
    if not credential_api().CredWriteW(ctypes.byref(record),0):raise ctypes.WinError(ctypes.get_last_error())


def delete_token():
    api=credential_api()
    if not api.CredDeleteW(CREDENTIAL_TARGET,1,0) and ctypes.get_last_error()!=1168:raise ctypes.WinError(ctypes.get_last_error())
