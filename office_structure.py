"""Read-only OOXML active-content inventory; never starts Office or follows links."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from defusedxml import ElementTree as SafeET

MAX_XML_BYTES = 8 * 1024 * 1024
MAX_TOTAL_XML_BYTES = 32 * 1024 * 1024
MAX_STREAM_XML_BYTES = 128 * 1024 * 1024


def structure_nodes(package,item):
    """Read large Word bodies incrementally rather than failing at 8 MiB."""
    if item.file_size>MAX_STREAM_XML_BYTES:raise ValueError('文档 XML 超过流式检查上限：'+item.filename)
    with package.open(item) as stream:
        stack=[]
        for event,node in SafeET.iterparse(stream,events=('start','end'),forbid_dtd=True,forbid_entities=True,forbid_external=True):
            if event=='start':
                stack.append(node)
                if len(stack)>256:raise ValueError('文档 XML 嵌套超过检查上限。')
                continue
            yield node
            if len(stack)>1:stack[-2].remove(node)
            node.clear();stack.pop()


def inspect_package(package):
    """Return structural evidence, not an automatic malware verdict."""
    evidence = []
    total = 0
    seen = set()

    def add(kind, member, **detail):
        key = (kind, member, detail.get('relationship_type', ''), detail.get('target',''))
        if key not in seen:
            seen.add(key)
            evidence.append({'kind': kind, 'member': member, **detail})

    for item in package.infolist():
        name = item.filename
        low = name.casefold()
        parts = low.replace('\\', '/').split('/')
        if name.startswith(('/', '\\')) or '\\' in name or '..' in parts or '\x00' in name:
            raise ValueError('文档包含非规范成员路径：' + name)
        if item.flag_bits & 1:
            raise ValueError('文档包含加密成员，无法完成内容检查：' + name)
        if re.search(r'(^|/)macrosheets/', low):
            add('xlm_macro_sheet', name)
        if re.search(r'(^|/)embeddings/', low):
            add('embedded_object', name)
        if re.search(r'(^|/)activex/', low):
            add('activex', name)
        if re.search(r'(^|/)externallinks/', low):
            add('external_data', name)

        selected = (low == '[content_types].xml' or low.endswith('.rels')
                    or low in ('xl/workbook.xml', 'word/document.xml', 'word/settings.xml')
                    or low.startswith('xl/externallinks/') and low.endswith('.xml'))
        if not selected:
            continue
        streaming=low=='word/document.xml'
        if not streaming and (item.file_size > MAX_XML_BYTES or total + item.file_size > MAX_TOTAL_XML_BYTES):
            raise ValueError('文档结构 XML 超过检查资源上限：' + name)
        if streaming:nodes=structure_nodes(package,item)
        else:
            data = package.read(item)
            total += len(data)
            if re.search(br'<!\s*(?:DOCTYPE|ENTITY)\b', data.replace(b'\x00', b''), re.I):
                raise ValueError('文档结构包含不支持的 XML 声明：' + name)
            nodes=ET.fromstring(data).iter()
        for node in nodes:
            tag = node.tag.rsplit('}', 1)[-1]
            if tag in ('ddeLink','oleLink'):add('external_executable_link',name,link_type=tag)
            if tag=='externalBook':add('external_book_link',name)
            if tag == 'Override' and 'macrosheet' in node.attrib.get('ContentType', '').casefold():
                add('xlm_macro_sheet', node.attrib.get('PartName', name))
            if tag == 'Relationship':
                reltype = node.attrib.get('Type', '').rsplit('/', 1)[-1].casefold()
                if reltype in ('xlmacrosheet', 'xlintlmacrosheet'):
                    add('xlm_macro_sheet', name, relationship_type=reltype)
                if node.attrib.get('TargetMode', '').casefold() == 'external':
                    if reltype == 'hyperlink':
                        continue  # An ordinary link alone is not active content.
                    add('external_relationship', name, relationship_type=reltype,
                        target=node.attrib.get('Target', '')[:1024],
                        target_truncated=len(node.attrib.get('Target',''))>1024)
            if tag == 'definedName' and node.attrib.get('name', '').casefold().removeprefix('_xlnm.') in ('auto_open', 'auto_close'):
                add('auto_macro_name', name)
            if tag in ('instrText', 'fldSimple'):
                text = ' '.join(node.itertext()) + ' ' + ' '.join(node.attrib.values())
                if re.search(r'\bDDE(?:AUTO)?\b', text, re.I):
                    add('dde_field', name)
    return evidence


def attach_evidence(result, evidence):
    if not evidence:
        return result
    result = dict(result)
    result['structural_evidence'] = evidence
    result['active_content_unresolved'] = True
    if result.get('status') == 'infected':
        result['has_family_macro'] = True
    result['status'] = 'review'
    result['reason'] = '文档包含需要独立检查的活动内容，不能仅移除 VBA 后判定恢复完成。'
    return result
