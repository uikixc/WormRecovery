"""Bounded nonexecuting format probes for documents with misleading extensions."""
from pathlib import Path
import re
import hashlib
from windows_read import open_read

MAX_RTF_BYTES=32*1024*1024
MAX_TEXT_BYTES=4*1024*1024


def inspect_plain_document(path):
    """Recognize a complete passive text .doc, never HTML/XML/RTF by extension."""
    path=Path(path)
    if path.suffix.casefold()!='.doc' or not 0<path.stat().st_size<=MAX_TEXT_BYTES:return None
    with open_read(path) as source:data=source.read(MAX_TEXT_BYTES+1)
    if len(data)>MAX_TEXT_BYTES:return None
    try:
        encoding='utf-16' if data.startswith((b'\xff\xfe',b'\xfe\xff')) else 'utf-8-sig'
        text=data.decode(encoding)
    except UnicodeError:return None
    if not text.strip() or any((ord(char)<32 and char not in '\t\r\n\f') or 127<=ord(char)<=159 for char in text):return None
    # A format masquerading as text must retain its dedicated inspection path.
    placeholders={'<stdin>','<string>','<module>','<lambda>','<listcomp>','<unknown>'}
    masked=re.sub(r'<[^<>\r\n]+>',lambda match:'' if match[0].casefold() in placeholders else match[0],text)
    if re.search(r'<[!?/\s]*[A-Za-z!?/]',masked) or re.search(r'\{\\rtf|^\s*(?:MIME-Version:|ID;)',text,re.I|re.M):return None
    return {'status':'review','macro':False,'document_format':'plain_text','passive_text_verified':True,
            'format_sha256':hashlib.sha256(data).hexdigest(),'text_encoding':encoding,
            'reason':'文件实际为纯文本文档，正在完成内容规则及病毒库检查。'}


def inspect_rtf(path):
    path=Path(path)
    if path.stat().st_size>MAX_RTF_BYTES:
        return {'status':'review','analysis_error':True,'document_format':'rtf','reason':'RTF 超过静态解析上限，未完成内容检查。'}
    with open_read(path) as source:data=source.read(MAX_RTF_BYTES+1)
    if len(data)>MAX_RTF_BYTES:raise ValueError('RTF 超过静态解析上限。')
    # RTF controls may be represented with escaped hex bytes or line wrapping.
    compact=re.sub(rb'\\\r?\n',b'',data)
    def escape(match):
        try:return bytes([int(match.group(1),16)])
        except ValueError:return match[0]
    compact=re.sub(rb"\\'([0-9a-fA-F]{2})",escape,compact)
    object_controls=sorted(set(x.decode('ascii') for x in re.findall(rb'\\(object|objdata|objupdate|objautlink|objlink|bin)\b',compact,re.I)))
    dde=bool(re.search(rb'\bDDE(?:AUTO)?\b',compact,re.I))
    if object_controls or dde:
        return {'status':'review','macro':False,'document_format':'rtf','active_content_unresolved':True,
                'structural_evidence':[{'kind':'rtf_active_content','member':'RTF body','controls':object_controls,'dde':dde}],
                'reason':'RTF 包含对象、二进制片段或 DDE，继续按活动内容复核。'}
    # Obfuscated control-word concatenation or malformed structure is not cleared.
    if not data.lstrip().startswith(b'{\\rtf') or data.count(b'{')!=data.count(b'}'):
        return {'status':'review','analysis_error':True,'document_format':'rtf','reason':'RTF 结构异常，未完成内容检查。'}
    return {'status':'review','macro':False,'document_format':'rtf','rtf_controls_checked':True,
            'reason':'文件实际为 RTF 文本，正在完成病毒和活动内容检查。'}
