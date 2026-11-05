"""Bounded nonexecuting format probes for documents with misleading extensions."""
from pathlib import Path
import re

MAX_RTF_BYTES=32*1024*1024


def inspect_rtf(path):
    path=Path(path)
    if path.stat().st_size>MAX_RTF_BYTES:
        return {'status':'review','analysis_error':True,'document_format':'rtf','reason':'RTF 超过静态解析上限，未完成内容检查。'}
    data=path.read_bytes()
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
