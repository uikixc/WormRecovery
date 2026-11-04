"""Read-only OOXML active-content inventory; never starts Office or follows links."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

MAX_XML_BYTES = 8 * 1024 * 1024
MAX_TOTAL_XML_BYTES = 32 * 1024 * 1024


def inspect_package(package):
    """Return structural evidence, not an automatic malware verdict."""
    evidence = []
    total = 0
    seen = set()

    def add(kind, member, **detail):
        key = (kind, member, detail.get('relationship_type', ''))
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
                    or low in ('xl/workbook.xml', 'word/document.xml', 'word/settings.xml'))
        if not selected:
            continue
        if item.file_size > MAX_XML_BYTES or total + item.file_size > MAX_TOTAL_XML_BYTES:
            raise ValueError('文档结构 XML 超过检查资源上限：' + name)
        data = package.read(item)
        total += len(data)
        # Reject declarations before ElementTree can expand internal entities.
        if re.search(br'<!\s*(?:DOCTYPE|ENTITY)\b', data.replace(b'\x00', b''), re.I):
            raise ValueError('文档结构包含不支持的 XML 声明：' + name)
        root = ET.fromstring(data)
        for node in root.iter():
            tag = node.tag.rsplit('}', 1)[-1]
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
                        target=node.attrib.get('Target', '')[:1024])
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
