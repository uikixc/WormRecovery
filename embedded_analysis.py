"""Bounded static inventory of embedded Office documents and OLE packages."""
import hashlib
import io
from pathlib import PurePosixPath
import struct
import zipfile

from office_structure import inspect_package

MAX_OBJECTS=64
MAX_BYTES=64*1024*1024
MAX_OBJECT_BYTES=32*1024*1024
MAX_DEPTH=4
CFB=bytes.fromhex('d0cf11e0a1b11ae1')


class Budget:
    def __init__(self):self.objects=0;self.bytes=0
    def consume(self,length,depth):
        self.objects+=1;self.bytes+=length
        if self.objects>MAX_OBJECTS or self.bytes>MAX_BYTES or length>MAX_OBJECT_BYTES or depth>MAX_DEPTH:
            raise ValueError('嵌入对象超过数量、大小或嵌套检查上限。')


def inspect(data):
    budget=Budget();rows=[]
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as package:
            rows=objects(package,budget,1)
        return {'status':'analyzed','container_sha256':hashlib.sha256(data).hexdigest(),'objects':rows,
                'all_passive':bool(rows) and all(row['classification']=='passive_office' for row in rows),
                'objects_checked':budget.objects,'decoded_bytes':budget.bytes,
                'scope':'只读对象结构与内容规则检查；不启动 Office、不执行对象、不打开对象记录的路径。'}
    except Exception as error:
        return {'status':'incomplete','container_sha256':hashlib.sha256(data).hexdigest(),'objects':rows,
                'all_passive':False,'reason':str(error)[:700],'objects_checked':budget.objects,'decoded_bytes':budget.bytes}


def objects(package,budget,depth):
    rows=[]
    for entry in package.infolist():
        if '/embeddings/' not in ('/'+entry.filename.casefold()) or entry.is_dir():continue
        if entry.file_size>MAX_OBJECT_BYTES or entry.flag_bits&1:raise ValueError('嵌入对象超过大小上限或已加密。')
        with package.open(entry) as source:data=source.read(MAX_OBJECT_BYTES+1)
        if len(data)!=entry.file_size:raise ValueError('嵌入对象字节数与目录不一致。')
        budget.consume(len(data),depth)
        row=content(data,budget,depth);row.update(member=entry.filename,bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
        rows.append(row)
    return rows


def content(data,budget,depth):
    from local_rules import scan_bytes
    rules=scan_bytes(data)
    if rules.get('matches'):return {'format':'content_rule_match','classification':'suspicious','rules':rules}
    if data.startswith(b'MZ'):return {'format':'windows_program','classification':'executable','reason':'嵌入 Windows 程序字节，不能按普通文档对象归类。'}
    if data.startswith(CFB):return ole(data,budget,depth)
    if not zipfile.is_zipfile(io.BytesIO(data)):
        return {'format':'unknown_binary','classification':'unresolved','reason':'对象不是支持的 OOXML 或 OLE 文档结构。'}
    with zipfile.ZipFile(io.BytesIO(data)) as package:
        entries=package.infolist();names=[entry.filename for entry in entries]
        if len(entries)>20000 or len(names)!=len(set(names)) or sum(entry.file_size for entry in entries)>MAX_BYTES:
            raise ValueError('嵌入文档目录重复或超过检查上限。')
        family=next((kind for root,kind in (('xl/workbook.xml','excel'),('word/document.xml','word'),
                    ('ppt/presentation.xml','powerpoint'),('visio/document.xml','visio')) if root in names),None)
        if '[Content_Types].xml' not in names or not family:
            return {'format':'zip','classification':'unresolved','reason':'压缩对象缺少可识别的 Office 主部件。'}
        structure=inspect_package(package)
        macros=[name for name in names if name.casefold().endswith('vbaproject.bin')]
        programs=[name for name in names if PurePosixPath(name).suffix.casefold() in ('.exe','.dll','.com','.scr','.a3x','.vbs','.js','.ps1','.bat','.cmd','.wsf')]
        children=objects(package,budget,depth+1)
        other=[row for row in structure if row['kind']!='embedded_object']
        passive=not macros and not programs and not other and all(row['classification']=='passive_office' for row in children)
        return {'format':'ooxml_'+family,'classification':'passive_office' if passive else 'unresolved',
                'macro_parts':macros,'program_parts':programs,'structural_evidence':structure,'children':children,
                'reason':'已检查的嵌入文档无宏、外部活动关系或未分类对象。' if passive else '对象中存在宏、外部关系或需要独立检查的内容。'}


def ole(data,budget,depth):
    import olefile
    with olefile.OleFileIO(data) as container:
        if container.parsing_issues:raise ValueError('嵌入 OLE 容器结构异常。')
        streams=['/'.join(parts) for parts in container.listdir()]
        if len(streams)>512:raise ValueError('嵌入 OLE 流数量超过检查上限。')
        if any('/vba/' in ('/'+path.casefold()) or path.casefold().endswith('vbaproject') for path in streams):
            return {'format':'ole_macro_project','classification':'unresolved','streams':streams,'reason':'嵌入 OLE 文档含 VBA 项目，需独立宏检查。'}
        native=[path for path in streams if path.casefold()=='\x01ole10native']
        allowed={'\x01ole10native','\x01compobj','\x01ole','\x05summaryinformation','\x05documentsummaryinformation'}
        if len(native)==1 and all(path.casefold() in allowed for path in streams):
            from oletools.oleobj import OleNativeStream
            raw=container.openstream(native[0]).read(MAX_OBJECT_BYTES+1)
            source=io.BytesIO(raw);parsed=OleNativeStream(source)
            if parsed.is_link:return {'format':'ole_link','classification':'unresolved','reason':'OLE 对象只保存外部路径，未打开目标。'}
            if parsed.native_data_size!=len(raw)-4 or not 0<parsed.actual_size<=MAX_OBJECT_BYTES:
                raise ValueError('OLE 包装大小与声明不一致。')
            body=source.read(parsed.actual_size)
            if len(body)!=parsed.actual_size or any(source.read()):raise ValueError('OLE 包装内容不完整或尾部存在未分类字节。')
            budget.consume(len(body),depth+1);child=content(body,budget,depth+1)
            child.update(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
            return {'format':'ole_package','classification':'passive_office' if child['classification']=='passive_office' else 'unresolved',
                    'children':[child],'reason':'已解析 OLE 包装内容，记录中的文件路径未被打开。'}
        from vba_inventory import inspect_legacy_workbook
        workbook=inspect_legacy_workbook(container)
        if workbook.get('status')=='complete' and workbook.get('active_or_unclassified_features')==[]:
            return {'format':'biff8_workbook','classification':'passive_office','structure':workbook}
        kind='equation_object' if any(path.casefold()=='equation native' for path in streams) else 'ole_document'
        return {'format':kind,'classification':'unresolved','streams':streams,
                'reason':'已识别公式对象，尚未完整解析公式二进制记录。' if kind=='equation_object' else '已识别 OLE 容器，仍含未分类流或活动记录。'}
