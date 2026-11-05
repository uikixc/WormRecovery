"""Positive VBA module inventory; absent source operations are not a cache verdict.

MS-OVBA MODULEOFFSET defines the exact module performance-cache length. Unknown
cache layouts and undeclared streams remain explicit; no macro is executed.
"""
import hashlib
import re
import struct


def source_inventory(code):
    depth=None;procedures=0;operations=0
    for original in code.splitlines():
        line='';masked='';quoted=False;index=0
        while index<len(original):
            char=original[index]
            if char=='"':
                if quoted and index+1<len(original) and original[index+1]=='"':
                    line+='""';masked+='  ';index+=2;continue
                quoted=not quoted
            elif char=="'" and not quoted:break
            line+=char;masked+=(' ' if quoted or char=='"' else char);index+=1
        line=line.strip();masked=masked.strip()
        if not line or re.match(r'^Rem(?:\s|$)',line,re.I):continue
        if quoted or '\ufffd' in line or ':' in masked:operations+=1;continue
        if re.fullmatch(r'Attribute\s+[A-Za-z_][\w.]*\s*=\s*(?:"(?:[^"]|"")*"|True|False|-?\d+)',line,re.I):continue
        if re.fullmatch(r'Option\s+(?:Explicit|Private\s+Module|Base\s+[01]|Compare\s+(?:Binary|Text|Database))',line,re.I):continue
        header=re.fullmatch(r'(?:(?:Public|Private|Friend|Static)\s+)*(Sub|Function|Property\s+(?:Get|Let|Set))\s+[A-Za-z_]\w*\s*\([^:]*\)(?:\s+As\s+[\w.]+)?',masked,re.I)
        if header and depth is None and '=' not in masked and not re.search(r'\b(?:Declare|New|Lib|Alias)\b',masked,re.I):
            depth=header[1].split()[0].casefold();procedures+=1;continue
        end=re.fullmatch(r'End\s+(Sub|Function|Property)',masked,re.I)
        if end and depth==end[1].casefold():depth=None;continue
        operations+=1
    return {'procedure_count':procedures,'executable_or_unsupported_lines':operations,
            'empty_bodies_verified':operations==0 and depth is None}


def inspect_inventory(parser, extracted):
    """Require strict declarations to cover all extracted modules and streams."""
    from oletools.olevba import VBA_Project
    class InventoryProject(VBA_Project):
        def check_value(self,name,expected,value):
            super().check_value(name,expected,value)
            if name=='PROJECTCONSTANTS_Reserved':
                # Pinned olevba 0.60.2 reads the Unicode constants length next,
                # then the reference records, ending at PROJECTMODULES_Id.
                position=self.dir_stream.tell();raw=self.dir_stream.getvalue()
                size=struct.unpack_from('<I',raw,position)[0]
                self.reference_start=position+4+size
                if self.reference_start>len(raw):raise ValueError('项目引用清单边界异常。')
    rows=[];unknown=[];cache_streams=[];roots=[];containers=[];references=[]
    try:
        expected={str(row['stream']).casefold():row for row in extracted}
        if len(expected)!=len(extracted):raise ValueError('重复的模块流标识。')
        for root,project_path,dir_path in parser.find_vba_projects():
            roots.append(root)
            project=InventoryProject(parser.ole_file,root,project_path,dir_path,relaxed=False)
            reference_end=project.dir_stream.tell()-2
            reference_start=getattr(project,'reference_start',None)
            if reference_start is None or not 0<=reference_start<=reference_end:raise ValueError('无法核对完整项目引用清单。')
            references.append({'project':project_path,'record_bytes':reference_end-reference_start,
                               'status':'absent' if reference_end==reference_start else 'dependencies_not_verified'})
            project.parse_project_stream();list(project.parse_modules())
            if len(project.modules)!=project.modules_count:raise ValueError('模块声明数量不一致。')
            if project.dir_stream.read()!=b'\x10\x00\x00\x00\x00\x00':raise ValueError('项目结束记录缺失或存在未分类记录。')
            for module in project.modules:
                if not isinstance(module.code_str,str):raise ValueError('模块源码未完整读取。')
                stream=module.code_path;raw=parser.ole_file.openstream(stream).read()
                if module.type not in (0x21,0x22) or module.name!=module._name_unicode or module.streamname!=module._streamname_unicode:
                    raise ValueError('模块类型或双份名称未严格对应。')
                if stream.casefold()!=(root+'VBA/'+module.streamname).casefold():raise ValueError('模块流使用了回退路径。')
                offset=module.textoffset
                if type(offset) is not int or not 0<=offset<len(raw):raise ValueError('模块源码偏移无效。')
                previous=expected.get(stream.casefold())
                if previous is None or previous['source_sha256']!=hashlib.sha256(module.code_str.encode('utf-8')).hexdigest():
                    raise ValueError('模块声明与提取结果不一致。')
                rows.append({'stream':stream,'name':module.name,'source_offset':offset,'stream_bytes':len(raw),
                             'cache_bytes':offset,'source':source_inventory(module.code_str)})
        if getattr(parser.ole_file,'parsing_issues',[]):raise ValueError('OLE 容器存在结构解析警告。')
        declared={row['stream'].casefold() for row in rows}
        if not rows or declared!=set(expected):raise ValueError('存在未覆盖的模块或孤立源码。')
        for parts in parser.ole_file.listdir(streams=True,storages=False):
            path='/'.join(parts);low=path.casefold();owner=next((root for root in roots if low.startswith((root+'VBA/').casefold())),None)
            if low in declared:continue
            if owner is not None:
                tail=path[len(owner+'VBA/'):]
                if tail.casefold()=='dir':continue
                if tail.casefold()=='_vba_project':
                    data=parser.ole_file.openstream(path).read()
                    if len(data)<7 or data[:2]!=b'\xcc\x61':raise ValueError('项目版本流无效。')
                    cache_streams.append({'stream':path,'bytes':max(0,len(data)-7),'version':int.from_bytes(data[2:4],'little')});continue
                if re.fullmatch(r'__SRP_[0-9A-F]{1,25}',tail,re.I):
                    cache_streams.append({'stream':path,'bytes':parser.ole_file.get_size(path)});continue
                unknown.append(path)
            elif any(low in ((root+'PROJECT').casefold(),(root+'PROJECTwm').casefold()) for root in roots):continue
            elif low in ('workbook','book'):containers.append(path)
            elif low in ('\x05summaryinformation','\x05documentsummaryinformation','\x01compobj'):continue
            else:unknown.append(path)
        if len(declared)!=len(rows):raise ValueError('模块声明重复引用同一源码流。')
        absent=all(row['cache_bytes']==0 for row in rows) and not any(row['bytes'] for row in cache_streams)
        return {'status':'complete','modules':rows,'module_count':len(rows),'project_caches':cache_streams,
                'unclassified_streams':unknown,'compiled_cache_absent':absent,
                'container_streams':containers,
                'project_references':references,
                'empty_project_verified':absent and not unknown and not any(row['record_bytes'] for row in references) and all(row['source']['empty_bodies_verified'] for row in rows),
                'basis':'Strict MS-OVBA module declarations, exact source offsets, complete source coverage, and cache inventory'}
    except Exception as error:
        return {'status':'partial','modules':rows,'unclassified_streams':unknown,
                'empty_project_verified':False,'reason':str(error)[:500]}


def inspect_legacy_workbook(ole):
    """Bound BIFF8 structure before applying an empty-VBA assessment to XLS."""
    import struct
    streams=['/'.join(parts) for parts in ole.listdir(streams=True,storages=False)]
    books=[path for path in streams if path.casefold() in ('workbook','book')]
    if len(books)!=1:return {'status':'unavailable','reason':'仅对可识别的 BIFF8 工作簿使用此规则。'}
    raw=ole.openstream(books[0]).read()
    if len(raw)<12 or raw[:2]!=b'\x09\x08' or raw[4:8]!=b'\x00\x06\x05\x00':
        return {'status':'unavailable','reason':'不是支持的 BIFF8 全局记录。'}
    # A positive decision is limited to ordinary data and formatting records.
    # Formula, object, drawing, name, external-reference and unknown records
    # explicitly block it, including records not understood by this reader.
    data_records={0x0809,0x000A,0x0085,0x0042,0x008C,0x0022,0x0031,0x041E,
                  0x00E0,0x0293,0x0092,0x00FC,0x003C,0x00FF,0x005C,0x003D,
                  0x0200,0x0208,0x020B,0x00D7,0x0201,0x0203,0x0204,0x0205,
                  0x00FD,0x027E,0x00BD,0x00BE,0x007D,0x0055,0x0225,0x023E,
                  0x0081,0x00E5,0x0041,0x00A0,0x0099,0x0026,0x0027,0x0028,
                  0x0029,0x002A,0x002B,0x0083,0x0084}
    position=0;records=0;features=set();opened=False;bofs={};sheets=[];current_type=None
    try:
        while position<len(raw):
            if raw[position:position+4]==b'\0\0\0\0':
                if any(raw[position:]):raise ValueError('BIFF 填充区含未分类数据。')
                break
            if position+4>len(raw):raise ValueError('BIFF 记录头不完整。')
            kind,size=struct.unpack_from('<HH',raw,position);position+=4
            if position+size>len(raw):raise ValueError('BIFF 记录越界。')
            data=raw[position:position+size];position+=size;records+=1
            if records>200000:raise ValueError('BIFF 记录超过上限。')
            if kind not in data_records:features.add('unclassified_record_0x%04X'%kind)
            if kind==0x0809:
                if opened or len(data)!=16 or data[:2]!=b'\x00\x06':raise ValueError('BIFF 子流起始记录无效。')
                current_type=int.from_bytes(data[2:4],'little');bofs[position-size-4]=current_type;opened=True
                if current_type not in (0x0005,0x0010):features.add('macro_or_unsupported_substream')
            elif not opened:raise ValueError('BIFF 记录位于子流之外。')
            if kind==0x0085:
                if current_type!=5 or len(data)<8:raise ValueError('工作表类型记录不完整或位置异常。')
                sheets.append(int.from_bytes(data[:4],'little'))
                if data[5]!=0:features.add('macro_or_unsupported_sheet')
            if kind==0x000A:
                if size:raise ValueError('BIFF 结束记录长度异常。')
                opened=False
        if opened or not sheets or len(sheets)!=len(set(sheets)) or any(bofs.get(offset)!=0x10 for offset in sheets) or set(bofs)!={0,*sheets}:
            raise ValueError('BIFF 工作表目录与完整子流未对应。')
        for path in streams:
            low=path.casefold()
            if low in ('workbook','book','\x05summaryinformation','\x05documentsummaryinformation','\x01compobj','project','projectwm'):continue
            if low.startswith('vba/') or low.startswith('_vba_project_cur/'):continue
            features.add('unclassified_ole_stream')
        return {'status':'complete','records':records,'active_or_unclassified_features':sorted(features)}
    except Exception as error:return {'status':'partial','reason':str(error)[:400]}
