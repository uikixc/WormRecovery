"""Create signed release attachments; private signing material stays local."""
import argparse
import base64
import ctypes
from ctypes import wintypes as W
import datetime
import hashlib
import json
from pathlib import Path
import shutil

from update_security import REPOSITORY,canonical,version_tuple,verify_manifest


def signing_key(path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    class Blob(ctypes.Structure):_fields_=[('size',W.DWORD),('data',ctypes.POINTER(ctypes.c_ubyte))]
    data=Path(path).read_bytes();buffer=ctypes.create_string_buffer(data)
    source=Blob(len(data),ctypes.cast(buffer,ctypes.POINTER(ctypes.c_ubyte)));target=Blob()
    api=ctypes.WinDLL('crypt32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    api.CryptUnprotectData.argtypes=[ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,W.DWORD,ctypes.POINTER(Blob)]
    api.CryptUnprotectData.restype=W.BOOL;kernel.LocalFree.argtypes=[ctypes.c_void_p]
    if not api.CryptUnprotectData(ctypes.byref(source),None,None,None,None,1,ctypes.byref(target)):raise ctypes.WinError(ctypes.get_last_error())
    try:return Ed25519PrivateKey.from_private_bytes(ctypes.string_at(target.data,target.size))
    finally:kernel.LocalFree(target.data)


def prepare(executable,version,destination,key_path):
    version_tuple(version);executable=Path(executable);destination=Path(destination)
    destination.mkdir(parents=True,exist_ok=True)
    with executable.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    payload={'schema':1,'repository':REPOSITORY,'version':version,'platform':'windows-x64',
             'asset':'WormRecovery.exe','bytes':executable.stat().st_size,'sha256':digest,
             'published_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    key=signing_key(key_path)
    document={'payload':payload,'signature':base64.b64encode(key.sign(canonical(payload))).decode('ascii')}
    verify_manifest(document)
    if executable.resolve()!=(destination/'WormRecovery.exe').resolve():shutil.copy2(executable,destination/'WormRecovery.exe')
    (destination/'update-manifest.json').write_text(json.dumps(document,ensure_ascii=True,indent=2),encoding='utf-8')
    (destination/'SHA256SUMS.txt').write_text(digest+'  WormRecovery.exe\n',encoding='ascii')
    print(json.dumps({'version':version,'bytes':payload['bytes'],'sha256':digest,'directory':str(destination)}))


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    for name in ('exe','version','destination','key'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args();prepare(args.exe,args.version,args.destination,args.key)
