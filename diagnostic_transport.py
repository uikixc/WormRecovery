"""Pinned TLS and end-to-end encrypted diagnostic transfer, no remote execution."""
import base64
import hashlib
import http.client
import json
import ssl
from urllib.parse import urlsplit

MAX_WIRE=12*1024*1024
CONTEXT=b'WormRecovery-Diagnostics-v1'


def encrypt(data,public_key):
    import os
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ephemeral=X25519PrivateKey.generate();public=ephemeral.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    peer=X25519PublicKey.from_public_bytes(base64.b64decode(public_key,validate=True))
    key=HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=CONTEXT).derive(ephemeral.exchange(peer))
    nonce=os.urandom(12);ciphertext=AESGCM(key).encrypt(nonce,data,CONTEXT+public)
    envelope={'schema':1,'ephemeral':base64.b64encode(public).decode(),'nonce':base64.b64encode(nonce).decode(),
              'ciphertext':base64.b64encode(ciphertext).decode()}
    encoded=json.dumps(envelope,separators=(',',':')).encode('ascii')
    if len(encoded)>MAX_WIRE:raise ValueError('加密诊断数据超过传输上限。')
    return encoded


def decrypt(data,private_key):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(data)>MAX_WIRE:raise ValueError('请求过大。')
    envelope=json.loads(data)
    if envelope.get('schema')!=1:raise ValueError('不支持的诊断协议。')
    private=X25519PrivateKey.from_private_bytes(base64.b64decode(private_key,validate=True))
    public=base64.b64decode(envelope['ephemeral'],validate=True)
    key=HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=CONTEXT).derive(private.exchange(X25519PublicKey.from_public_bytes(public)))
    return AESGCM(key).decrypt(base64.b64decode(envelope['nonce'],validate=True),
                             base64.b64decode(envelope['ciphertext'],validate=True),CONTEXT+public)


def send(endpoint,payload,token,certificate_sha256,timeout=8):
    url=urlsplit(endpoint)
    if url.scheme!='https' or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError('诊断地址必须为 HTTPS 服务地址。')
    # A self-signed certificate is accepted only after exact pin verification,
    # before any authorization header or report bytes are sent.
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    connection=http.client.HTTPSConnection(url.hostname,url.port or 443,context=context,timeout=timeout)
    try:
        connection.connect()
        actual=hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
        if actual!=certificate_sha256:raise ValueError('诊断服务证书指纹不匹配，未发送数据。')
        connection.request('POST',(url.path.rstrip('/') or '')+'/v1/diagnostics',body=payload,
                           headers={'Authorization':'Bearer '+token,'Content-Type':'application/json','Content-Length':str(len(payload))})
        response=connection.getresponse();data=response.read(4097)
        if len(data)>4096 or response.status not in (200,201):raise ValueError('诊断服务拒绝接收，HTTP '+str(response.status))
        result=json.loads(data)
        if not result.get('accepted') or not result.get('receipt'):raise ValueError('诊断服务未返回有效接收凭据。')
        return result
    finally:connection.close()
