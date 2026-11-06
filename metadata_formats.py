"""Parse metadata containers by bytes; never follow their recorded paths."""
import hashlib
import ntpath
from pathlib import Path
import re
import struct

from windows_read import open_read

MAX_BYTES=2*1024*1024


def inspect_metadata(path,prefix):
    path=Path(path)
    recycle=bool(re.fullmatch(r'\$I[^\\/]{6}(?:\.[^\\/]+)?',path.name,re.I)
                 and re.search(r'(?i)(?:^|[\\/])\$Recycle\.Bin[\\/]S-1-[0-9-]+[\\/]',str(path)))
    apple=prefix.startswith(b'\x00\x05\x16\x07')
    if not apple and not recycle:return None
    with open_read(path) as stream:data=stream.read(MAX_BYTES+1)
    kind='appledouble' if apple else 'recycle_index'
    try:
        if len(data)>MAX_BYTES:raise ValueError('元数据容器超过检查上限。')
        details=appledouble(data) if apple else recycle_index(data)
        passive=details.pop('passive')
        result={'status':'review','macro':False,'document_format':kind,'format_sha256':hashlib.sha256(data).hexdigest(),
                'metadata_structure':details,'passive_metadata_verified':passive,
                'reason':'文件实际为 macOS 元数据附属文件，正文位于独立文件。' if apple else '文件实际为回收站索引，索引记录的路径不作为可执行命令。'}
        if not passive:
            result.update(active_content_unresolved=True,structural_evidence=[{'kind':'metadata_resource_fork','member':'AppleDouble resource fork'}],
                          reason='文件为 macOS 元数据容器，包含非空资源叉或未分类记录，需要进一步检查。')
        return result
    except (ValueError,struct.error,UnicodeError) as error:
        return {'status':'review','analysis_error':True,'macro':False,'document_format':kind,
                'reason':'元数据容器结构未通过检查：'+str(error)}


def appledouble(data):
    if len(data)<26:raise ValueError('AppleDouble 头不完整。')
    magic,version=struct.unpack_from('>II',data)
    if magic!=0x51607 or version!=0x20000:raise ValueError('AppleDouble 版本不支持。')
    count=struct.unpack_from('>H',data,24)[0];end=26+count*12
    if not 0<count<=64 or end>len(data):raise ValueError('AppleDouble 项目录无效。')
    rows=[];ids=set();regions=[];passive=True
    for index in range(count):
        identity,offset,length=struct.unpack_from('>III',data,26+index*12)
        if identity in ids or offset<end or offset+length>len(data):raise ValueError('AppleDouble 项重复或越界。')
        ids.add(identity);rows.append({'id':identity,'offset':offset,'bytes':length})
        if length:regions.append((offset,offset+length))
        if identity==1:raise ValueError('AppleDouble 不应包含正文数据叉。')
        if identity not in (2,3,4,8,9,10,11,12,13,14,15) or identity==2 and length:passive=False
        if identity==8 and length!=16:raise ValueError('日期记录长度异常。')
        if identity==9 and length<32:raise ValueError('Finder 元数据长度异常。')
    cursor=end
    for start,finish in sorted(regions):
        if start<cursor:raise ValueError('AppleDouble 项数据重叠。')
        if any(data[cursor:start]):raise ValueError('AppleDouble 间隙包含未分类数据。')
        cursor=finish
    if any(data[cursor:]):raise ValueError('AppleDouble 尾部包含未分类数据。')
    return {'status':'complete','version':version,'entries':rows,'passive':passive,
            'scope':'记录结构与资源叉范围检查；独立正文文件不在此容器内。'}


def recycle_index(data):
    if len(data)<28:raise ValueError('回收站索引头不完整。')
    version,size,timestamp=struct.unpack_from('<QQQ',data)
    if version==1:
        if len(data)!=544:raise ValueError('回收站 v1 索引长度异常。')
        encoded=data[24:]
        text=encoded.decode('utf-16-le');parts=text.split('\0',1)
        if len(parts)!=2 or parts[1].strip('\0'):raise ValueError('回收站索引路径未正确结束。')
        target=parts[0]
    elif version==2:
        count=struct.unpack_from('<I',data,24)[0]
        if not 1<=count<=32768 or 28+2*count!=len(data):raise ValueError('回收站 v2 路径长度异常。')
        text=data[28:].decode('utf-16-le')
        if not text.endswith('\0') or '\0' in text[:-1]:raise ValueError('回收站索引路径未正确结束。')
        target=text[:-1]
    else:raise ValueError('回收站索引版本不支持。')
    drive,tail=ntpath.splitdrive(target)
    if not drive or not tail.startswith('\\') or any(ord(c)<32 for c in target):raise ValueError('回收站索引不是绝对路径记录。')
    if timestamp<=0 or timestamp>=2650467744000000000:raise ValueError('回收站删除时间无效。')
    return {'status':'complete','version':version,'original_bytes':size,'deleted_filetime':timestamp,
            'original_extension':ntpath.splitext(target)[1].casefold(),'passive':True,
            'scope':'索引仅保存已删除文件的位置、大小与时间；不读取该路径。对应 $R 文件单独检查。'}
