"""Content-based worm/miner signatures and bounded static carrier decoding.

Recovered REA code facts are compiled into local detectors. REA/Ghidra itself
does not run for each file. Names, extensions, a valid publisher signature,
general mining strings and a packer alone never confirm maliciousness.
"""
from __future__ import annotations
import hashlib
import io
import os
import re
import struct
import zipfile

from local_rules import CONFIRMED_CODE_RULES, RULESET_VERSION, scan_bytes

MAX_INPUT=16*1024*1024
MAX_CARRIER=4*1024*1024
SYNAPTICS_CODE='9251b16208e38d5de48130230d5f51036c979843ac33bc52cd31c298dd9cb105'
KNOWN_RUNTIME='c49da0039e1a10d9c9ab686744a169c1308326c1a26ce631f89c8a29ea6eb8c7'
# Observed runtime/archive and shellcode constants, not a user credential.
PROJECT_PASSWORD=b'99B2328D3FDF4E9E98559B4414F7ACB9'
PNG_KEY=bytes.fromhex('504073737730336400de9cabfeccd012')
PACKED_PREFIX=bytes.fromhex('53565755505152488d0d')
PACKED_XOR=bytes.fromhex('4889ca48c7c6100000008a02343c880248ffc28a0234e8880248ffc248ffce75e9')


class PE:
    """Validated byte ranges only; never asks Windows to load an image."""
    def __init__(self,data):
        self.data=data
        if len(data)<64 or data[:2]!=b'MZ':raise ValueError('不是 PE 映像。')
        offset=struct.unpack_from('<I',data,60)[0]
        if not 64<=offset<=min(len(data)-24,1024*1024) or data[offset:offset+4]!=b'PE\0\0':
            raise ValueError('PE 头无效。')
        self.machine,count=struct.unpack_from('<HH',data,offset+4)
        optlen=struct.unpack_from('<H',data,offset+20)[0];opt=offset+24
        if not 1<=count<=256 or not 96<=optlen<=4096 or opt+optlen+count*40>len(data):
            raise ValueError('PE 节目录不完整。')
        magic=struct.unpack_from('<H',data,opt)[0]
        if magic not in (0x10b,0x20b):raise ValueError('PE 可选头无效。')
        self.entry=struct.unpack_from('<I',data,opt+16)[0]
        self.headers=struct.unpack_from('<I',data,opt+60)[0]
        self.sections=[]
        self.code_ranges=[]
        for i in range(count):
            p=opt+optlen+i*40;vs,va,size,raw=struct.unpack_from('<IIII',data,p+8)
            if size and (raw<opt+optlen+count*40 or raw+size>len(data)):
                raise ValueError('PE 节字节范围无效。')
            self.sections.append((va,size,raw,vs))
            flags=struct.unpack_from('<I',data,p+36)[0]
            if flags&0x20000000 and size:self.code_ranges.append((raw,raw+size))
        # Overlapping raw sections cannot establish unique image ownership.
        ranges=sorted((raw,raw+size) for _,size,raw,_ in self.sections if size)
        if any(end>right for (_,end),(right,_) in zip(ranges,ranges[1:])):
            raise ValueError('PE 节范围重叠，无法确认代码归属。')

    def rva(self,value,length=1):
        if 0<=value and value+length<=min(self.headers,len(self.data)):return value
        matches=[raw+value-va for va,size,raw,_ in self.sections if va<=value and value+length<=va+size]
        if len(matches)!=1:raise ValueError('PE 地址没有唯一文件映射。')
        return matches[0]


def rc4(data,key):
    state=list(range(256));j=0
    for i in range(256):
        j=(j+state[i]+key[i%len(key)])&255;state[i],state[j]=state[j],state[i]
    i=j=0;output=bytearray(len(data))
    for n,value in enumerate(data):
        i=(i+1)&255;j=(j+state[i])&255;state[i],state[j]=state[j],state[i]
        output[n]=value^state[(state[i]+state[j])&255]
    return bytes(output)


def _hits(data,rules=None,*,raw_kind=None):
    result=rules if rules is not None else scan_bytes(data)
    names=[name for name in result.get('matches',[]) if name in CONFIRMED_CODE_RULES]
    if names and not result.get('pattern_hits'):
        if not isinstance(data,bytes):return []
        result=scan_bytes(data)
    pe=None
    if raw_kind is None:
        try:pe=PE(data)
        except (ValueError,struct.error):return []
    output=[]
    for name in names:
        # Raw loader and unpacked code have a caller-verified container scope.
        # A match in an arbitrary file/resource never inherits that authority.
        if raw_kind=='loader' and name!='WR_PNG_Memory_Loader_Code':continue
        if raw_kind=='miner_image' and name!='WR_Coinminer_Perfr_Code':continue
        required={'WR_Coinminer_Perfr_Code':('$pool','$update'),
                  'WR_Miner_Controller_Code':('$names','$uac','$deploy'),
                  'WR_PNG_Memory_Loader_Code':('$k1','$png','$map')}[name]
        patterns=result.get('pattern_hits',{}).get(name,{})
        code=[]
        for identifier in required:
            candidates=patterns.get(identifier,{}).get('matches',[])
            owned=[hit for hit in candidates if raw_kind is not None or any(
                start<=hit['offset'] and hit['offset']+hit['length']<=end for start,end in pe.code_ranges)]
            if not owned:break
            code.append({'pattern':identifier,**owned[0]})
        if len(code)!=len(required):continue
        # Nested complete PE bytes inside a resource or overlay have their own
        # image identity. Do not classify the enclosing legitimate executable as
        # a standalone component based on the embedded program's code fragments.
        if pe is not None:
            nested=False
            cursor=data.find(b'MZ',64)
            examined=0
            while cursor>=0 and examined<256:
                examined+=1
                try:
                    child=PE(memoryview(data)[cursor:])
                    if any(any(cursor+start<=hit['offset'] and hit['offset']+hit['length']<=cursor+end
                               for start,end in child.code_ranges) for hit in code):
                        nested=True;break
                except (ValueError,struct.error):pass
                cursor=data.find(b'MZ',cursor+2)
            if nested or (cursor>=0 and examined>=256):continue
        output.append({'signature':name,'family':CONFIRMED_CODE_RULES[name],
                       'basis':'recovered_code_combination','code_locations':code,
                       'code_scope':raw_kind or 'outer_pe_executable_sections'})
    return output


def _project(data):
    """Read fixed embedded project members only, never extract archive paths."""
    if len(data)>MAX_CARRIER:return None
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members=archive.infolist()
        if len(members)>16:return None
        projects=[m for m in members if m.filename=='_TUProj.dat' and m.flag_bits&1]
        if len(projects)!=1:return None
        member=projects[0]
        if member.file_size>1024*1024 or member.compress_size>MAX_CARRIER:
            raise ValueError('加密项目超过静态检查上限。')
        try:
            with archive.open(member,pwd=PROJECT_PASSWORD) as stream:project=stream.read(1024*1024+1)
        except RuntimeError:
            # Other TrueUpdate archives/passwords are not this observed chain.
            return None
        if len(project)!=member.file_size:raise ValueError('加密项目字节数与目录不符。')
        arrays=re.finditer(rb'\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*\{([0-9,\s]{100,30000})\}',project)
        for match in arrays:
            values=match[1].split(b',')
            if not 100<=len(values)<=8192:continue
            try:code=bytes(int(value.strip()) for value in values)
            except (ValueError,OverflowError):continue
            hits=_hits(code,raw_kind='loader')
            api=all(token in project for token in (b'DLL.CallFunction',b'VirtualAlloc',b'RtlFillMemory',b'CreateThread'))
            if api and hits:
                return {'signature':'WR_Encrypted_Project_Loader','family':'TrueUpdate-PNG-Loader',
                        'basis':'encrypted_project_crc_and_embedded_loader_code',
                        'project_sha256':hashlib.sha256(project).hexdigest(),
                        'loader_sha256':hashlib.sha256(code).hexdigest(),'code_matches':hits}
    return None


def _packed(data,pe):
    if pe.machine!=0x8664:return None
    try:entry=pe.rva(pe.entry,47)
    except ValueError:return None
    if not any(start<=entry and entry+47<=end for start,end in pe.code_ranges):return None
    head=data[entry:entry+47]
    if not (head.startswith(PACKED_PREFIX) and head[14:47]==PACKED_XOR):return None
    displacement=struct.unpack_from('<i',head,10)[0]
    compressed_rva=pe.entry+14+displacement;offset=pe.rva(compressed_rva,32)
    section=next(s for s in pe.sections if s[0]<=compressed_rva< s[0]+s[1])
    end=section[2]+section[1]
    if not 32<=end-offset<=8*1024*1024:raise ValueError('压缩区超过静态解包范围。')
    source=bytearray(data[offset:end])
    for i in range(32):source[i]^=(0x3c,0xe8)[i%2]
    from packed_content import decode_nrv2e
    decoded,consumed=decode_nrv2e(source)
    return decoded,{'method':'observed_xor32_nrv2e','compressed_offset':offset,
                    'compressed_bytes_consumed':consumed,'decoded_bytes':len(decoded),
                    'decoded_sha256':hashlib.sha256(decoded).hexdigest(),
                    'representation':'image bytes before relative branch inversion; not a runnable restoration'}


def _inspect(data,rules=None,*,mapped_pe=False):
    """Return positive code evidence or explicit limits, never a clean verdict."""
    result={'engine':'WormRecovery static family analysis','ruleset_version':RULESET_VERSION,
            'status':'no_known_match','detections':[],'decodings':[],
            'target_execution':False,'name_used_for_verdict':False}
    if len(data)>MAX_INPUT and not mapped_pe:
        result.update(status='incomplete',reason='文件超过家族静态分析大小上限。');return result
    pe=None
    if data[:2]==b'MZ':
        try:pe=PE(data)
        except (ValueError,struct.error):pass
    observed_rules=rules if rules is not None else scan_bytes(data)
    result['detections']=_hits(data,observed_rules)
    if pe:
        from tsco_analysis import identify
        tsco=identify(data,pe)
        result.update(tsco)
        for _,size,offset,_ in pe.sections:
            if size==629760 and hashlib.sha256(data[offset:offset+size]).hexdigest()==SYNAPTICS_CODE:
                result['detections'].append({'signature':'WR_Synaptics_Code_Section','family':'Synaptics',
                    'basis':'exact_infection_code_section','section_offset':offset,'section_bytes':size,'section_sha256':SYNAPTICS_CODE})
                break
        try:
            unpacked=_packed(data,pe)
            if unpacked:
                decoded,details=unpacked;details['code_matches']=_hits(decoded,raw_kind='miner_image');result['decodings'].append(details)
                result['detections'].extend(details['code_matches'])
                if not details['code_matches']:
                    result.update(status='incomplete',reason='已解开匹配的压缩层，但未确认内部恶意代码。')
        except (ValueError,struct.error,StopIteration) as error:
            result.update(status='incomplete',reason=str(error))
    elif data.startswith(b'PK\x03\x04') and b'_TUProj.dat' in data:
        try:
            hit=_project(data)
            if hit:result['detections'].append(hit)
        except (ValueError,zipfile.BadZipFile,NotImplementedError,EOFError) as error:
            result.update(status='incomplete',reason='加密项目解析未完成：'+str(error)[:300])
    elif data.startswith(b'\x89PNG\r\n\x1a\n') and len(data)>128:
        # 64-byte prefix and RC4 key are recovered from the loader instructions.
        # Reject ordinary images after 64 decoded bytes; do not decrypt all PNGs.
        preview=rc4(data[64:128],PNG_KEY)
        if preview.startswith(b'MZ') and 64<=struct.unpack_from('<I',preview,60)[0]<=1024*1024:
            if len(data)>MAX_CARRIER:
                result.update(status='incomplete',reason='疑似加密 PE 载体超过静态解密大小上限。')
            else:
                decoded=rc4(data[64:],PNG_KEY)
                try:
                    PE(decoded);hits=_hits(decoded)
                    result['decodings'].append({'method':'png_prefix64_rc4','decoded_sha256':hashlib.sha256(decoded).hexdigest(),
                                                'decoded_bytes':len(decoded),'code_matches':hits})
                    result['detections'].extend(hits)
                    if not hits:result.update(status='incomplete',reason='载体解密为 PE，但未匹配已确认恶意代码。')
                except (ValueError,struct.error) as error:
                    result.update(status='incomplete',reason='载体内部 PE 结构未完成检查：'+str(error))
    if not result['detections'] and any(name in CONFIRMED_CODE_RULES for name in observed_rules.get('matches',[])):
        result.update(status='incomplete',reason='发现代码特征组合，但无法确认其属于外层程序的执行代码；可能位于嵌入资源，已保留原文件。')
    if result['detections']:
        result.update(status='detected',source_sha256=hashlib.sha256(data).hexdigest())
    if not result['detections'] and (result.get('identifications') or result.get('contained_payloads')):
        # Content identification does not establish a miner/worm classification
        # or authorize quarantine of a carrier containing a research sample.
        result.update(status='identified',source_sha256=hashlib.sha256(data).hexdigest(),
                      reason='已识别 TSCO 已知载荷内容；挖矿或文档蠕虫归属未证实，保留原件待核。')
    elif result.get('diagnostics') and not result['detections']:
        result.update(status='incomplete',reason='；'.join(result['diagnostics']))
    if len(data)==486832 and hashlib.sha256(data).hexdigest()==KNOWN_RUNTIME:
        result['role']='observed_trueupdate_runtime';result['source_sha256']=KNOWN_RUNTIME
    return result


def inspect(data,rules=None):
    """Inspect an already bounded byte string without loading target code."""
    return _inspect(data,rules)


def inspect_mapped_pe(mapping,rules):
    """Apply code ownership to a validated read-only mapped PE and full scan.

    The caller retains the source handle, bounds mapping admission, performs
    the complete file rule scan, and checks file identity before/after. This
    function makes no whole-file bytes copy; digesting a positive buffer uses
    the buffer protocol directly. Known carrier unpack limits still apply.
    """
    PE(mapping)
    return _inspect(mapping,rules,mapped_pe=True)


def inspect_large_file(path,expected_stat=None):
    from large_pe_analysis import inspect_large_file as inspect_streamed
    return inspect_streamed(path,expected_stat=expected_stat)


def inspect_large_script(path,expected_stat=None):
    from large_pe_analysis import inspect_large_script as inspect_streamed
    return inspect_streamed(path,expected_stat=expected_stat)


def correlate(findings,observations):
    """Code proof plus the runtime's actual companion lookup relationship.

    Basename/path equality models what this runtime reads; it is never malware
    evidence on its own. Unrelated malicious neighbours cannot condemn a
    legitimate updater merely because they share a directory.
    """
    groups={}
    for row in findings:
        analysis=row.get('family_analysis',{})
        if analysis.get('status')!='detected':continue
        groups.setdefault(os.path.normcase(os.path.dirname(row['path'])),[]).append(row)
    output=[]
    for runtime in observations:
        if runtime.get('role')!='observed_trueupdate_runtime' or runtime.get('sha256')!=KNOWN_RUNTIME:continue
        peers=groups.get(os.path.normcase(os.path.dirname(runtime['path'])),[])
        stem=os.path.splitext(runtime['path'])[0];selected=[]
        for suffix,required in (('.dat','WR_Encrypted_Project_Loader'),('.png','WR_Miner_Controller_Code')):
            expected=os.path.normcase(stem+suffix)
            peer=next((p for p in peers if os.path.normcase(p['path'])==expected and any(
                hit['signature']==required for hit in p['family_analysis']['detections'])),None)
            if peer is None:break
            if suffix=='.png' and not any(d.get('method')=='png_prefix64_rc4' for d in peer['family_analysis'].get('decodings',[])):break
            selected.append(peer)
        if len(selected)!=2:continue
        output.append({'kind':'malware_deployment','path':runtime['path'],'sha256':KNOWN_RUNTIME,
            'family':'TrueUpdate-Miner-Controller','assessment':'confirmed_content_and_companions',
            'reason':'运行时实际读取的配套项目与图片载荷均已解密并确认恶意代码，形成完整加载链。',
            'action':'处理时重新核对本文件及关联内容；签名或文件名不单独作为处理依据。',
            'related_evidence':[{'path':peer['path'],'sha256':peer['sha256'],
                                'signatures':[h['signature'] for h in peer['family_analysis']['detections']]} for peer in selected]})
    return output
