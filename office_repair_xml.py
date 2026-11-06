"""Structural OOXML edits and package relationship checks; never starts Office."""
from __future__ import annotations
import io
import posixpath
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET
from defusedxml import ElementTree as SafeET

CONTENT='http://schemas.openxmlformats.org/package/2006/content-types'
RELATIONSHIPS='http://schemas.openxmlformats.org/package/2006/relationships'
SHEET={'http://schemas.openxmlformats.org/spreadsheetml/2006/main','http://purl.oclc.org/ooxml/spreadsheetml/main'}
VBA_RELATIONS={'http://schemas.microsoft.com/office/2006/relationships/'+name for name in ('vbaProject','vbaProjectSignature','vbaData')}


def parse(data):
    return SafeET.fromstring(data,forbid_dtd=True,forbid_entities=True,forbid_external=True)


def target_part(rels_name,target):
    if not target or '\\' in target:raise ValueError('文档关系目标无效。')
    uri=urlsplit(target)
    if uri.scheme or uri.netloc:raise ValueError('内部关系包含外部地址。')
    path=unquote(uri.path)
    if '\\' in path or '\x00' in path:raise ValueError('文档关系路径无效。')
    if rels_name=='_rels/.rels':base=''
    else:
        folder,basename=posixpath.split(rels_name)
        if posixpath.basename(folder)!='_rels' or not basename.endswith('.rels'):
            raise ValueError('文档关系成员路径无效。')
        base=posixpath.dirname(folder)
    normalized=posixpath.normpath(path.lstrip('/') if path.startswith('/') else posixpath.join(base,path))
    if normalized in ('.','..') or normalized.startswith('../'):raise ValueError('文档关系超出包范围。')
    return normalized


def rewrite(name,data,removed):
    # minidom preserves original namespace declarations used by QName-valued
    # attributes (for example mc:Ignorable), comments and processing instructions.
    # SafeET first rejects DTD/entities before the structural editor sees bytes.
    parse(data)
    from xml.dom import minidom,Node
    document=minidom.parseString(data);root=document.documentElement;changed=False
    children=lambda parent:[node for node in parent.childNodes if node.nodeType==Node.ELEMENT_NODE]
    if name=='[Content_Types].xml':
        if (root.namespaceURI,root.localName)!=(CONTENT,'Types'):raise ValueError('文档内容类型命名空间无效。')
        for node in children(root):
            if (node.namespaceURI,node.localName)!=(CONTENT,'Override'):continue
            part=unquote(node.getAttribute('PartName')).lstrip('/')
            if part in removed:root.removeChild(node);changed=True
            elif part=='xl/workbook.xml' and node.getAttribute('ContentType')=='application/vnd.ms-excel.sheet.macroEnabled.main+xml':
                node.setAttribute('ContentType','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml');changed=True
    elif name.endswith('.rels'):
        if (root.namespaceURI,root.localName)!=(RELATIONSHIPS,'Relationships'):raise ValueError('文档关系命名空间无效。')
        for node in children(root):
            if (node.namespaceURI,node.localName)==(RELATIONSHIPS,'Relationship') and node.getAttribute('Type') in VBA_RELATIONS:
                if node.getAttribute('TargetMode').casefold()=='external' or target_part(name,node.getAttribute('Target')) not in removed:
                    raise ValueError('宏关系没有指向已确认移除的宏成员。')
                root.removeChild(node);changed=True
    elif name=='xl/workbook.xml':
        for node in document.getElementsByTagName('*'):
            if node.namespaceURI not in SHEET:continue
            if node.localName=='sheet' and node.getAttribute('state') in ('hidden','veryHidden'):
                node.removeAttribute('state');changed=True
            if node.localName=='workbookView':
                for key in ('activeTab','firstSheet'):
                    if node.hasAttribute(key) and node.getAttribute(key)!='0':node.setAttribute(key,'0');changed=True
    return document.toxml(encoding='utf-8') if changed else data


def validate_relationships(package):
    names=set(package.namelist())
    for name in names:
        if name.endswith('.rels'):
            root=parse(package.read(name));seen=set()
            if root.tag!='{'+RELATIONSHIPS+'}Relationships':raise ValueError('文档关系命名空间无效。')
            for node in root:
                if node.tag!='{'+RELATIONSHIPS+'}Relationship':raise ValueError('文档关系包含未知节点。')
                identity=node.get('Id')
                if not identity or identity in seen:raise ValueError('文档关系标识为空或重复。')
                seen.add(identity)
                if node.get('Type') in VBA_RELATIONS:raise ValueError('修复文档仍含宏关系。')
                if node.get('TargetMode','').casefold()=='external':continue
                if target_part(name,node.get('Target','')) not in names:raise ValueError('修复文档存在缺失的关系目标：'+name)
        elif name=='[Content_Types].xml':
            root=parse(package.read(name))
            if root.tag!='{'+CONTENT+'}Types':raise ValueError('文档内容类型命名空间无效。')
            for node in root:
                if node.tag=='{'+CONTENT+'}Override' and unquote(node.get('PartName','')).lstrip('/') not in names:
                    raise ValueError('修复文档内容类型指向缺失成员。')
