"""Evidence-based local repair for the observed AutoIt/Synaptics outbreak.

Never executes specimens or contacts their endpoints. Selected device volumes
are validated before changes; Office repair never starts Office applications.
"""
from __future__ import annotations
import argparse, base64, collections, copy, ctypes, datetime, hashlib, io, json
import os, pathlib, re, shutil, struct, subprocess, sys, tempfile, threading
import time, uuid, winreg, zipfile, xml.etree.ElementTree as ET
from ctypes import wintypes as W
import psutil
from windows_read import open_read,extended_path
from office_triage import assess_office,is_confirmed
from office_structure import inspect_package, attach_evidence
from persistence_inventory import (INVENTORY_SCRIPT, select_confirmed, registry_paths,
    disable_task_script, disable_service_script, reconcile_snapshot)
from worm_residue import QUARANTINE_LINK_HASHES, payload_root, exact_script_root, exact_startup_root

VERSION = '1.8.4'
WINDOWLESS = sys.stdout is None

def ensure_standard_streams():
    """Provide file-like streams before libraries initialize console support."""
    for name in ('stdout', 'stderr'):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, 'w', encoding='utf-8', errors='replace'))
        elif hasattr(getattr(sys,name),'reconfigure'):
            getattr(sys,name).reconfigure(encoding='utf-8',errors='replace')

ensure_standard_streams()
STUB_CODE_SHA256 = '9251b16208e38d5de48130230d5f51036c979843ac33bc52cd31c298dd9cb105'
AUTOIT_A3X_SHA256 = '6cb8bd1ec21353f2a48f0f37c4125ebd04023153f70a00ceaf9787dd035868fa'
AUTOIT_EXE_SHA256 = 'fb73a819b37523126c7708a1d06f3b8825fa60c926154ab2d511ba668f49dc4b'
HOOK_SHA256 = 'b9eae90f8e942cc4586d31dc484f29079651ad64c49f90d99f86932630c66af2'
BAD_VBA_HASHES = {
    '177b0f70870d9a5874044ea4eb7985c4ece470be5bb5e4680c58d4fb329ef732',
    '4fef3df248f7d18a419883b4999f9d592df705460e7559c0168847de72ff43d7'}
EXE_EXTS = {'.exe', '.dll', '.scr', '.cpl', '.com', '.ocx', '.sys'}
OFFICE_EXTS = {'.xlsx','.xlsm','.xlam','.xlsb','.xltm','.docx','.docm','.dotm','.pptx','.pptm','.ppam','.xls','.doc','.ppt'}
CRITICAL_PROCESSES = {'system','registry','smss.exe','csrss.exe','wininit.exe','winlogon.exe',
    'services.exe','lsass.exe','svchost.exe','msmpeng.exe','mssense.exe','codex.exe','openai.exe'}
from runtime_identity import application_path
HERE = (application_path() if getattr(sys,'frozen',False) else pathlib.Path(__file__).resolve()).parent
kernel = ctypes.WinDLL('kernel32', use_last_error=True)
kernel.GetCurrentProcess.argtypes=[];kernel.GetCurrentProcess.restype=W.HANDLE
kernel.GetFileAttributesW.argtypes=[W.LPCWSTR];kernel.GetFileAttributesW.restype=W.DWORD
kernel.SetFileAttributesW.argtypes=[W.LPCWSTR,W.DWORD];kernel.SetFileAttributesW.restype=W.BOOL
kernel.GetDriveTypeW.argtypes=[W.LPCWSTR];kernel.GetDriveTypeW.restype=W.UINT
kernel.GetVolumePathNameW.argtypes=[W.LPCWSTR,W.LPWSTR,W.DWORD];kernel.GetVolumePathNameW.restype=W.BOOL
kernel.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,ctypes.c_void_p,W.DWORD,W.DWORD,W.HANDLE]
kernel.CreateFileW.restype=W.HANDLE
kernel.DeviceIoControl.argtypes=[W.HANDLE,W.DWORD,ctypes.c_void_p,W.DWORD,ctypes.c_void_p,W.DWORD,ctypes.POINTER(W.DWORD),ctypes.c_void_p]
kernel.DeviceIoControl.restype=W.BOOL
kernel.CloseHandle.argtypes=[W.HANDLE]
kernel.GetVolumeNameForVolumeMountPointW.argtypes=[W.LPCWSTR,W.LPWSTR,W.DWORD]
kernel.GetVolumeNameForVolumeMountPointW.restype=W.BOOL
kernel.ReplaceFileW.argtypes=[W.LPCWSTR,W.LPCWSTR,W.LPCWSTR,W.DWORD,ctypes.c_void_p,ctypes.c_void_p]
kernel.ReplaceFileW.restype=W.BOOL

def digest_file(path):
    h=hashlib.sha256()
    with open_read(path) as f:
        while b:=f.read(4*1024*1024):h.update(b)
    return h.hexdigest()

def json_save(path,value):
    pathlib.Path(path).write_text(json.dumps(value,ensure_ascii=False,indent=2),encoding='utf-8')

def norm(path):return os.path.normcase(os.path.abspath(path)).rstrip('\\/')
def beneath(path,root):return norm(path)==norm(root) or norm(path).startswith(norm(root)+os.sep)

def file_attributes(path):
    a=kernel.GetFileAttributesW(extended_path(path))
    if a==0xffffffff:raise ctypes.WinError(ctypes.get_last_error())
    return a

def volume(path):
    buf=ctypes.create_unicode_buffer(32768)
    if not kernel.GetVolumePathNameW(os.path.abspath(path),buf,len(buf)):
        raise ctypes.WinError(ctypes.get_last_error())
    return buf.value

def storage_info(root):
    """Reject fixed-type USB enclosures as well as DRIVE_REMOVABLE sticks."""
    device='\\\\.\\'+root[:2]
    h=kernel.CreateFileW(device,0,3,None,3,0,None)
    if h==ctypes.c_void_p(-1).value:return {'bus':None,'removable':None}
    try:
        query=ctypes.create_string_buffer(12);answer=ctypes.create_string_buffer(4096);n=W.DWORD()
        if kernel.DeviceIoControl(h,0x2d1400,query,len(query),answer,len(answer),ctypes.byref(n),None) and n.value>=36:
            return {'bus':struct.unpack_from('<I',answer.raw,28)[0], 'removable':bool(answer.raw[10])}
        return {'bus':None,'removable':None}
    finally:kernel.CloseHandle(h)

def volume_identity(root):
    buf=ctypes.create_unicode_buffer(1024)
    if not kernel.GetVolumeNameForVolumeMountPointW(root,buf,len(buf)):raise ctypes.WinError(ctypes.get_last_error())
    return buf.value.casefold()

class VolumePolicy:
    def __init__(self,external_volumes=None,excluded_roots=()):
        self.cache={}
        self.external_volumes={norm(k):v.casefold() for k,v in (external_volumes or {}).items()}
        self.excluded_roots={norm(k) for k in excluded_roots}
    def check(self,path):
        return self.check_volume(volume(path))
    def check_volume(self,root):
        if norm(root) in self.excluded_roots:raise PermissionError('该卷已列入本机排除列表。')
        if root not in self.cache:
            kind=kernel.GetDriveTypeW(root); info=storage_info(root) if kind in (2,3) else {'bus':None,'removable':None}
            # Unknown buses are permitted only for a fixed system volume.
            allowed=kind==3 and info['bus'] not in (7,12,13) and info['removable'] is not True
            if info['bus'] is None and root[:2].lower()!=os.environ.get('SystemDrive','C:').lower():allowed=False
            if norm(root) in self.external_volumes:
                allowed=kind in (2,3) and volume_identity(root)==self.external_volumes[norm(root)]
            self.cache[root]={'root':root,'drive_type':kind,**info,'allowed':allowed}
        if norm(root) in self.external_volumes and volume_identity(root)!=self.external_volumes[norm(root)]:
            raise PermissionError('设备连接状态已变化。请重新扫描。')
        if not self.cache[root]['allowed']:raise PermissionError('该卷不在本次可处理范围内：'+root)
        return self.cache[root]
    def fixed_roots(self):
        result=[]
        for i in range(26):
            root=chr(65+i)+':\\'
            if kernel.GetDriveTypeW(root)==3:
                try:self.check(root);result.append(root)
                except OSError:pass
        return result
    def mutation(self,path):
        self.check(path)
        p=pathlib.Path(os.path.abspath(path))
        for part in [p,*p.parents]:
            if part.exists() and file_attributes(part)&0x400:
                raise PermissionError('拒绝通过重解析点改动文件: '+str(part))

class PEView:
    """Small read-only PE header/resource reader; streams large original payloads."""
    def __init__(self,path):
        self.path=pathlib.Path(path); self.f=open_read(path);self.size=os.fstat(self.f.fileno()).st_size
        try:
            h=self.read(0,64)
            if h[:2]!=b'MZ':raise ValueError('not PE')
            peoff=struct.unpack_from('<I',h,60)[0]
            if peoff<64 or peoff>1024*1024:raise ValueError('invalid PE offset')
            h=self.read(peoff,24)
            if h[:4]!=bytes.fromhex('50450000'):raise ValueError('not PE')
            self.machine,self.n=struct.unpack_from('<HH',h,4);optlen=struct.unpack_from('<H',h,20)[0]
            if not 1<=self.n<=96 or not 96<=optlen<=4096:raise ValueError('invalid PE headers')
            opt=self.read(peoff+24,optlen);self.magic=struct.unpack_from('<H',opt)[0]
            self.entry=struct.unpack_from('<I',opt,16)[0]
            self.headers_size=struct.unpack_from('<I',opt,60)[0]
            diroff=96 if self.magic==0x10b else 112 if self.magic==0x20b else -1
            if diroff<0:raise ValueError('unknown optional header')
            self.res_rva,self.res_size=struct.unpack_from('<II',opt,diroff+16)
            sec=self.read(peoff+24+optlen,40*self.n);self.sections=[]
            for i in range(self.n):
                s=sec[i*40:i*40+40];vs,va,rs,rp=struct.unpack_from('<IIII',s,8)
                if rs and rp+rs>self.size:raise ValueError('truncated PE section')
                self.sections.append((s[:8].rstrip(bytes([0])),vs,va,rs,rp))
        except BaseException:self.f.close();raise
    def __enter__(self):return self
    def __exit__(self,*args):self.f.close()
    def read(self,offset,n):
        if offset<0 or n<0 or offset+n>self.size:raise ValueError('PE read outside file')
        self.f.seek(offset);b=self.f.read(n)
        if len(b)!=n:raise ValueError('short PE read')
        return b
    def rva(self,rva,n=1):
        if rva<self.headers_size and rva+n<=self.headers_size:return rva
        for name,vs,va,rs,rp in self.sections:
            if va<=rva and rva+n<=va+rs:return rp+rva-va
        raise ValueError('unmapped PE RVA')
    def known_stub(self):
        return self.machine==0x14c and any(s[3]==629760 and
            hashlib.sha256(self.read(s[4],s[3])).hexdigest()==STUB_CODE_SHA256 for s in self.sections)
    def resource(self,wanted):
        if not self.res_rva or not self.res_size:return None
        base=self.rva(self.res_rva);found=[];budget=[0]
        def rd(off,n):
            if off<0 or off+n>self.res_size:raise ValueError('resource outside directory')
            return self.read(base+off,n)
        def walk(off,parts):
            budget[0]+=1
            if budget[0]>4096 or len(parts)>3:raise ValueError('resource tree budget exceeded')
            h=rd(off,16);a,b=struct.unpack_from('<HH',h,12);entries=rd(off+16,(a+b)*8)
            for i in range(a+b):
                key,child=struct.unpack_from('<II',entries,i*8)
                if key&0x80000000:
                    z=key&0x7fffffff;length=struct.unpack('<H',rd(z,2))[0]
                    if length>256:raise ValueError('resource name too long')
                    name=rd(z+2,length*2).decode('utf-16le')
                else:name=str(key)
                seq=parts+[name]
                if child&0x80000000:walk(child&0x7fffffff,seq)
                else:
                    addr,size,cp,res=struct.unpack('<IIII',rd(child,16));fo=self.rva(addr,size)
                    if wanted in seq:found.append((fo,size,seq))
        walk(0,[])
        if len(found)>1:raise ValueError('ambiguous original resource')
        return found[0] if found else None
    def extract_resource(self,res,dest):
        offset,size,_=res;self.f.seek(offset);remaining=size
        with open(dest,'xb') as out:
            while remaining:
                b=self.f.read(min(4*1024*1024,remaining))
                if not b:raise ValueError('truncated embedded original')
                out.write(b);remaining-=len(b)
            out.flush();os.fsync(out.fileno())

def is_stub(path,strict=False,data=None):
    try:
        with (io.BytesIO(data) if data is not None else open_read(path)) as f:
            h=f.read(4096)
            if len(h)<64 or h[:2]!=b'MZ':return False
            off=struct.unpack_from('<I',h,60)[0]
            if off>1024*1024:return False
            f.seek(off);h=f.read(512)
            if h[:4]!=bytes.fromhex('50450000') or len(h)<256:return False
            if struct.unpack_from('<H',h,4)[0]!=0x14c:return False
        with PEView(path) as pe:return pe.known_stub()
    except OSError:
        if strict:raise
        return False
    except (ValueError,struct.error):return False

def shortcut(path):
    with open_read(path) as stream:b=stream.read()
    if len(b)<76 or b[:4]!=bytes.fromhex('4c000000') or b[4:20]!=bytes.fromhex('0114020000000000c000000000000046'):return None
    flags=struct.unpack_from('<I',b,20)[0];pos=76;strings={}
    if flags&1:
        n=struct.unpack_from('<H',b,pos)[0];pos+=n+2
    if flags&2:
        n=struct.unpack_from('<I',b,pos)[0]
        if n<28 or pos+n>len(b):raise ValueError('invalid shell link info')
        strings['link_info']=b[pos:pos+n].decode('utf-16le','ignore')+' '+b[pos:pos+n].decode('latin1','ignore');pos+=n
    for bit,name in [(4,'name'),(8,'relative'),(16,'working_dir'),(32,'arguments'),(64,'icon')]:
        if flags&bit:
            n=struct.unpack_from('<H',b,pos)[0];pos+=2;size=n*(2 if flags&128 else 1)
            if pos+size>len(b):raise ValueError('truncated shell link')
            strings[name]=b[pos:pos+size].decode('utf-16le' if flags&128 else 'mbcs','replace');pos+=size
    text=' '.join(strings.values()).casefold()
    if 'qmquarantine' in text or '/openquarantine?' in text:return {'malicious':False,'av_placeholder':True,**strings}
    return {'malicious':('googlechrome.a3x' in text and ('autoit3executescript' in text or 'googlechrome.exe' in text)),**strings}

_OFFICE_PARSE_LOCK=threading.Lock()

def office_check(path):
    # oletools/pyparsing initialization and parser state are not shared concurrently.
    with _OFFICE_PARSE_LOCK:return assess_office(path,_office_check(path))

def _office_check(path):
    p=pathlib.Path(path)
    stage='read_header';source_read=False
    def failed(error):
        details={'phase':getattr(error,'operation_phase',stage),'exception_type':type(error).__name__,
                 'winerror':getattr(error,'winerror',None),'source_bytes_read':source_read}
        details.update(getattr(error,'analysis_details',{}))
        labels={'macro_worker':'宏分析进程','legacy_worker':'旧版文档分析进程','package_structure':'文档结构解析'}
        return {'status':'review','reason':('文件读取未完成：' if stage.startswith('read_') else '文档分析未完成（'+labels.get(stage,stage)+'）：')+str(error),
                'analysis_error':True,'error_details':details}
    try:
        with open_read(p) as header:prefix=header.read(16)
        if not prefix:return {'status':'review','macro':False,'reason':'文件内容为空，原有正文缺失；没有可供宏分析的字节，需要另行恢复内容。','document_format':'empty','data_integrity_issue':'empty_document'}
        from metadata_formats import inspect_metadata
        metadata=inspect_metadata(p,prefix)
        if metadata is not None:return metadata
        stage='read_container'
        with open_read(p) as package,zipfile.ZipFile(package) as z:
            stage='package_structure'
            entries=z.infolist()
            if len(entries)>20000 or sum(x.file_size for x in entries)>1024*1024*1024:return {'status':'review','reason':'文档超过检查资源上限，需进一步核查。'}
            names=[x.filename for x in entries]
            if len(set(names))!=len(names):return {'status':'review','reason':'文档包含重复压缩成员，需进一步核查。'}
            structure=inspect_package(z)
            macro=[x for x in entries if x.filename.casefold().endswith('vbaproject.bin')]
            if not macro:return attach_evidence({'status':'clean','macro':False},structure)
            if len(macro)!=1 or macro[0].file_size>16*1024*1024:return {'status':'review','reason':'宏项目结构异常，需进一步核查。'}
            stage='read_macro_bytes';data=z.read(macro[0]);source_read=True;h=hashlib.sha256(data).hexdigest()
            if h in BAD_VBA_HASHES:
                if macro[0].filename!='xl/vbaProject.bin' or 'xl/workbook.xml' not in names:return {'status':'review','reason':'已知宏位于非预期文档结构中，需人工核查。'}
                return attach_evidence({'status':'infected','family':'Synaptics-Excel','vba_hash':h,'vba_part':macro[0].filename},structure)
            from office_analysis import analyze_project
            stage='macro_worker'
            analysis=analyze_project(data)
            matches=analysis['family_modules'];others=analysis['other_modules']
            result={'status':'review','macro':True,'document_format':'ooxml','package_structure_checked':True,'reason':'宏项目已进行源码和可用编译指令检查，判定范围以各项结果为准。','has_family_macro':bool(matches),'other_modules':others,'vba_hash':h,'macro_analysis':analysis}
            if matches and not others and analysis.get('pcode_family_match') and macro[0].filename=='xl/vbaProject.bin':
                result.update(status='infected',family='Synaptics-Excel',vba_part=macro[0].filename,
                              reason='宏源码与编译指令均匹配 Synaptics-Excel 感染特征，已确认感染。')
            return attach_evidence(result,structure)
    except zipfile.BadZipFile:
        if p.name.startswith('~$'):return {'status':'lock_file'}
        if prefix.lstrip().startswith(b'{\\rtf'):
            from document_formats import inspect_rtf
            return inspect_rtf(p)
        if not prefix.startswith(bytes.fromhex('d0cf11e0a1b11ae1')):
            from document_formats import inspect_plain_document
            passive=inspect_plain_document(p)
            if passive:return passive
            return {'status':'review','analysis_error':True,'document_format':'unrecognized',
                    'reason':'文件内容不是可识别的 Office 容器或 RTF，可能为扩展名不符、损坏或其他格式；未判为病毒。'}
        try:
            stage='read_legacy_bytes'
            with open_read(p) as source:data=source.read(128*1024*1024+1)
            if len(data)>128*1024*1024:raise ValueError('旧版 Office 文件超过静态解析上限。')
            source_read=True;stage='legacy_worker'
            from office_analysis import analyze_legacy_document
            return analyze_legacy_document(data)
        except Exception as ex:return failed(ex)
    except Exception as ex:
        return failed(ex)

def sanitized_xlsx(source,dest):
    """Copy original parts verbatim except VBA relationships/types and visibility."""
    with zipfile.ZipFile(source) as src:
        if inspect_package(src):raise ValueError('文档存在额外活动内容，不能仅移除 VBA 后自动恢复。')
        names=src.namelist();removed={n for n in names if re.search(r'(?i)(^|/)vba(project(signature)?\.bin|data\.xml)$',n)}
        removed.update(n for n in names if re.search(r'(?i)(^|/)_rels/vba(project(signature)?\.bin|data\.xml)\.rels$',n))
        changes={};before={}
        for name in names:
            if name in removed:continue
            b=src.read(name)
            if name=='[Content_Types].xml' or name.endswith('.rels') or name=='xl/workbook.xml':
                from office_repair_xml import rewrite
                b=rewrite(name,b,removed)
            changes[name]=b
            if b==src.read(name):before[name]=hashlib.sha256(b).hexdigest()
        with zipfile.ZipFile(dest,'x',compression=zipfile.ZIP_DEFLATED) as out:
            for item in src.infolist():
                if item.filename not in removed:out.writestr(copy.copy(item),changes[item.filename])
        with zipfile.ZipFile(dest) as check:
            if check.testzip():raise ValueError('修复文档的完整性校验失败。')
            if any('vbaproject' in x.casefold() for x in check.namelist()):raise ValueError('修复文档中仍存在宏项目。')
            for name,h in before.items():
                if hashlib.sha256(check.read(name)).hexdigest()!=h:raise ValueError('非目标工作簿成员发生变化：'+name)
            for name in check.namelist():
                if name.endswith(('.xml','.rels')):ET.fromstring(check.read(name))
            from office_repair_xml import validate_relationships
            validate_relationships(check)
            for name in names:
                if name.startswith('xl/worksheets/') and name.endswith('.xml') and check.read(name)!=src.read(name):raise ValueError('工作表内容校验不一致。')
    return {'unchanged_parts':len(before),'removed_parts':sorted(removed),'worksheet_bytes_preserved':True}

def powershell(script,timeout=60):
    exe=os.path.join(os.environ.get('WINDIR','C:\\Windows'),'System32','WindowsPowerShell','v1.0','powershell.exe')
    prefix="[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
    encoded=base64.b64encode((prefix+script).encode('utf-16le')).decode('ascii')
    from engine_process import run
    r=run([exe,'-NoProfile','-NonInteractive','-EncodedCommand',encoded],timeout=timeout)
    if r.returncode:
        from powershell_output import error_text
        raise RuntimeError(error_text(r.stderr)[-2000:])
    s=r.stdout.decode('utf-8-sig','replace').strip()
    return json.loads(s) if s else None

def psquote(s):return "'"+str(s).replace("'","''")+"'"

def enable_privileges():
    adv=ctypes.WinDLL('advapi32',use_last_error=True)
    class LUID(ctypes.Structure):_fields_=[('LowPart',W.DWORD),('HighPart',W.LONG)]
    class TOKEN_PRIVILEGES(ctypes.Structure):_fields_=[('count',W.DWORD),('luid',LUID),('attr',W.DWORD)]
    adv.OpenProcessToken.argtypes=[W.HANDLE,W.DWORD,ctypes.POINTER(W.HANDLE)];adv.LookupPrivilegeValueW.argtypes=[W.LPCWSTR,W.LPCWSTR,ctypes.POINTER(LUID)]
    adv.AdjustTokenPrivileges.argtypes=[W.HANDLE,W.BOOL,ctypes.POINTER(TOKEN_PRIVILEGES),W.DWORD,ctypes.c_void_p,ctypes.c_void_p]
    token=W.HANDLE();result={}
    if adv.OpenProcessToken(kernel.GetCurrentProcess(),0x28,ctypes.byref(token)):
        try:
            for name in ('SeDebugPrivilege','SeBackupPrivilege','SeRestorePrivilege'):
                t=TOKEN_PRIVILEGES();t.count=1;t.attr=2
                if adv.LookupPrivilegeValueW(None,name,ctypes.byref(t.luid)):
                    ctypes.set_last_error(0);adv.AdjustTokenPrivileges(token,False,ctypes.byref(t),0,None,None);result[name]=ctypes.get_last_error()==0
        finally:kernel.CloseHandle(token)
    return result

def lock_holders(path):
    rm=ctypes.WinDLL('rstrtmgr');session=W.DWORD();key=ctypes.create_unicode_buffer(33)
    class UNIQUE(ctypes.Structure):_fields_=[('pid',W.DWORD),('start',W.FILETIME)]
    class INFO(ctypes.Structure):_fields_=[('process',UNIQUE),('app',W.WCHAR*256),('service',W.WCHAR*64),('type',W.UINT),('status',W.ULONG),('ts',W.DWORD),('restart',W.BOOL)]
    rm.RmStartSession.argtypes=[ctypes.POINTER(W.DWORD),W.DWORD,W.LPWSTR];rm.RmStartSession.restype=W.DWORD
    rm.RmRegisterResources.argtypes=[W.DWORD,W.UINT,ctypes.POINTER(W.LPCWSTR),W.UINT,ctypes.POINTER(UNIQUE),W.UINT,ctypes.POINTER(W.LPCWSTR)];rm.RmRegisterResources.restype=W.DWORD
    rm.RmGetList.argtypes=[W.DWORD,ctypes.POINTER(W.UINT),ctypes.POINTER(W.UINT),ctypes.POINTER(INFO),ctypes.POINTER(W.DWORD)];rm.RmGetList.restype=W.DWORD
    rm.RmEndSession.argtypes=[W.DWORD];rm.RmEndSession.restype=W.DWORD
    if rm.RmStartSession(ctypes.byref(session),0,key):return []
    try:
        names=(W.LPCWSTR*1)(str(path))
        if rm.RmRegisterResources(session,1,names,0,None,0,None):return []
        needed=W.UINT();count=W.UINT();reasons=W.DWORD()
        result=rm.RmGetList(session,ctypes.byref(needed),ctypes.byref(count),None,ctypes.byref(reasons))
        if result!=234 or not 0<needed.value<1024:return []
        rows=(INFO*needed.value)();count.value=needed.value
        if rm.RmGetList(session,ctypes.byref(needed),ctypes.byref(count),rows,ctypes.byref(reasons)):return []
        return [{'pid':x.process.pid,'created':((x.process.start.dwHighDateTime<<32)|x.process.start.dwLowDateTime)/10000000-11644473600}
                for x in rows[:count.value]]
    finally:rm.RmEndSession(session)

def autoit_companion_path(path):
    p=pathlib.Path(path);stem=p.stem
    if stem.casefold().startswith('._cache_'):stem=stem[len('._cache_'):]
    return p.with_name(stem+'.a3x')


def autoit_companion(path):
    """An interpreter hash is not malicious; require its exact paired script."""
    candidate=autoit_companion_path(path)
    try:
        if candidate.is_file() and not file_attributes(candidate)&0x400 and digest_file(candidate)==AUTOIT_A3X_SHA256:
            return {'path':str(candidate),'sha256':AUTOIT_A3X_SHA256}
    except OSError:pass
    return None

def inspect_file_content(path,st):
    """Read-only detector; return data without mutating Cleaner or UI state."""
    result={'office':0,'findings':[]}
    def add(kind,path,**detail):result['findings'].append({'kind':kind,'path':str(path),'size':getattr(st,'st_size',None),**detail})
    name=os.path.basename(path).casefold();ext=os.path.splitext(name)[1]
    # Every selected file reaches a bounded header probe, even with a misleading
    # extension. Do not follow a name/extension allowlist before reading magic.
    from family_analysis import MAX_INPUT,MAX_CARRIER,inspect as inspect_family
    data=None
    with open_read(path) as stream:
        prefix=stream.read(min(128,st.st_size+1))
        packed_zip=prefix.startswith(b'PK\x03\x04');png=prefix.startswith(b'\x89PNG\r\n\x1a\n')
        office_container=False;encrypted_project=False
        archive_probe=None
        if packed_zip:
            from carrier_probe import zip_directory
            archive_probe=zip_directory(stream,st.st_size)
            office_container=archive_probe.get('office',False)
            encrypted_project=archive_probe.get('encrypted_project',False)
            stream.seek(len(prefix))
        from carrier_probe import png_candidate
        program=prefix.startswith(b'MZ') or (ext in EXE_EXTS or name.startswith(('~$cache','._cache_'))) and not (packed_zip or png)
        carrier=png and png_candidate(prefix) or encrypted_project
        script=ext in ('.au3','.vbs','.js','.ps1','.cmd','.bat','.wsf','.lua')
        if program and st.st_size<=MAX_INPUT or (carrier or script) and st.st_size<=MAX_CARRIER:
            data=prefix+stream.read(max(0,st.st_size+1-len(prefix)))
            if len(data)!=st.st_size:raise ValueError('检查时文件大小发生变化，请重新扫描。')
    result['engine_checks']={'file_header':1}
    if archive_probe and archive_probe['status']!='complete':
        result['engine_checks']['archive_directory_limited']=1
    def family(data=None,rules=None,analysis=None):
        analysis=inspect_family(data,rules) if analysis is None else analysis
        result['engine_checks']['family_static']=1
        if analysis.get('role'):
            result['family_observations']=[{'path':str(path),'role':analysis['role'],'sha256':analysis['source_sha256']}]
        if analysis['status']=='identified':
            add('review_binary',path,sha256=analysis['source_sha256'],family_analysis=analysis,
                assessment='known_payload_content',reason=analysis['reason'],
                action='仅识别内容；嵌入载荷不赋予父文件恶意身份，不自动清理或隔离。')
            return True
        if analysis['status']=='detected':
            names=sorted({hit['family'] for hit in analysis['detections']})
            # Infection code in an unusual PE layout still requires the
            # original-program recovery path. Never quarantine its entire host
            # as an independent miner merely because the wrapper parser failed.
            if any(h['signature']=='WR_Synaptics_Code_Section' for h in analysis['detections']):
                add('infected_executable',path,family='Synaptics',family_analysis=analysis,
                    reason='已确认感染代码；文件布局需在恢复前重新核对原程序资源。',
                    action='使用程序恢复流程；结构无法验证时保留整份原文件。')
                return True
            add('malware_component',path,sha256=analysis['source_sha256'],family=' / '.join(names),
                assessment='confirmed_malicious_code',family_analysis=analysis,
                reason='已确认恶意代码特征：'+'、'.join(hit['signature'] for hit in analysis['detections']),
                action='处理时复核内容指纹并保留隔离副本；不按名称删除目录。')
            return True
        if analysis['status']=='incomplete':
            add('review_binary',path,family_analysis=analysis,reason=analysis['reason'],
                content_rules=analysis.get('content_rules'),
                action='保留原件；静态解码未完成不等于已确认感染。')
            return True
        return False
    def large_checks(analysis):
        coverage=analysis.get('coverage',{})
        result['large_file_coverage']=coverage
        if coverage.get('rule_scan')=='complete':
            result['engine_checks']['yara_x']=1
            result['engine_checks']['family_streamed_pe' if program else 'family_streamed_script']=1
            result['streamed_bytes']=coverage.get('rule_scan_bytes',0)
        if analysis['status']=='incomplete':result['engine_checks']['family_streamed_failed']=1
    if program:
        if st.st_size>MAX_INPUT:
            from family_analysis import inspect_large_file
            analysis=inspect_large_file(path,expected_stat=st);large_checks(analysis)
            rules=analysis.get('content_rules',{})
            if not family(analysis=analysis) and rules.get('matches'):
                add('review_binary',path,family_analysis=analysis,content_rules=rules,
                    reason='完整文件规则命中，但尚未确立独立恶意程序的代码归属。')
        elif is_stub(path,strict=True,data=data):
            with PEView(path) as pe:original=pe.resource('EXERESX')
            result['engine_checks']['family_static']=1
            add('infected_executable' if original else 'worm_payload',path,size=st.st_size,embedded_original_bytes=original[1] if original else None,
                family='Synaptics',reason='感染代码节完整指纹与已确认的蠕虫感染器一致。',
                family_analysis={'engine':'WormRecovery static family analysis','status':'detected',
                    'ruleset_version':__import__('local_rules').RULESET_VERSION,'name_used_for_verdict':False,'target_execution':False,
                    'detections':[{'signature':'WR_Synaptics_Code_Section','family':'Synaptics',
                                   'basis':'exact_infection_code_section','section_sha256':STUB_CODE_SHA256}]})
        elif st.st_size==15360 and (hashlib.sha256(data).hexdigest() if data is not None else digest_file(path))==HOOK_SHA256:add('worm_hook',path,sha256=HOOK_SHA256)
        elif st.st_size==750320 and (hashlib.sha256(data).hexdigest() if data is not None else digest_file(path))==AUTOIT_EXE_SHA256:
            companion=autoit_companion(path)
            if companion:add('worm_runtime',path,sha256=AUTOIT_EXE_SHA256,related_evidence=[companion],
                reason='解释器内容指纹与其实际配套脚本内容共同确认已知恶意部署。')
            else:result['engine_checks']['recognized_autoit_runtime_without_malicious_companion']=1
        elif data is not None:
            from local_rules import scan_bytes
            rules=scan_bytes(data);result['engine_checks']['yara_x']=1
            if not family(data,rules) and rules['matches']:add('review_binary',path,reason='程序内容命中家族组合规则，正在执行离线复核。',content_rules=rules)
        else:
            result['engine_checks']['family_size_limited']=1
            add('review_binary',path,reason='程序超过静态家族检查大小上限，完整内容未检查。')
    elif carrier:
        if data is not None:family(data)
        else:
            result['engine_checks']['family_size_limited']=1
            add('review_binary',path,reason='载体超过静态家族检查大小上限，完整内容未检查。')
    elif ext=='.a3x':
        if digest_file(path)==AUTOIT_A3X_SHA256:add('worm_script',path,sha256=AUTOIT_A3X_SHA256)
        else:add('review_autoit',path,reason='未识别脚本已保留，需进一步核查。')
    elif script and data is not None:
        from local_rules import scan_bytes
        rules=scan_bytes(data);result['engine_checks']['yara_x']=1
        if not family(data,rules) and rules['matches']:add('review_script',path,reason='本地组合规则命中，正在执行离线复核。',content_rules=rules)
    elif script:
        from large_pe_analysis import inspect_large_script
        analysis=inspect_large_script(path,expected_stat=st);large_checks(analysis)
        if analysis['status']=='incomplete':
            add('review_script',path,family_analysis=analysis,content_rules=analysis.get('content_rules'),reason=analysis['reason'])
    elif ext=='.lnk' and st.st_size<1024*1024:
        link=shortcut(path)
        if link and link.get('malicious'):add('malicious_shortcut',path,shortcut=link)
        elif link and link.get('av_placeholder') and payload_root(path) and norm(os.path.dirname(path))==norm(payload_root(path)):
            fingerprint=digest_file(path)
            if fingerprint in QUARANTINE_LINK_HASHES:add('worm_residue',path,sha256=fingerprint,reason='已确认家族目录内的已知隔离提示快捷方式。')
    elif ext in OFFICE_EXTS or office_container:
        result['office']=1;info=office_check(path)
        analysis=info.get('macro_analysis',{});checks={}
        if analysis.get('source_sha256'):checks['vba_source_analysis']=1
        if analysis.get('pcode_status')=='instructions_read':checks['vba_pcode']=1
        if analysis.get('content_rules'):checks['yara_x']=1
        if checks:result['engine_checks'].update(checks)
        if info['status']=='infected':add('infected_office',path,**info)
        elif info['status']=='info':add('info_office',path,**info)
        elif info['status']=='review':
            add('review_office',path,**info)
            if info.get('analysis_error'):
                result['error']=info['reason']
                result['error_details']=info.get('error_details',{})
    return result

class Cleaner:
    def __init__(self,report_dir=None,emit=print,force_close=True,protected=(),restore_history=True,external_volumes=None,excluded_roots=()):
        from device_scope import protection_path
        profile=protection_path()
        local=json.loads(profile.read_text(encoding='utf-8-sig')) if profile.exists() else {}
        protected=[*protected,*local.get('excluded_paths',[])]
        self.policy=VolumePolicy(external_volumes,excluded_roots);self.emit=emit;self.force_close=force_close;self.restore_history=restore_history;self.shadow_cache=None
        default=pathlib.Path(os.environ.get('PROGRAMDATA','C:/ProgramData'))/'WormRecovery'
        self.run=pathlib.Path(report_dir or default)/datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
        self.policy.mutation(self.run.parent);self.run.mkdir(parents=True,exist_ok=False)
        self.quarantine=self.run/'quarantine';self.quarantine.mkdir();self.events=[];self.findings=[];self.errors=[]
        tool_scope=pathlib.Path(sys.executable) if getattr(sys,'frozen',False) else HERE
        self.protected=[tool_scope,self.run.parent,*map(pathlib.Path,protected)]
        if getattr(sys,'frozen',False):self.protected.append(application_path())
        if getattr(sys,'_MEIPASS',None):self.protected.append(pathlib.Path(sys._MEIPASS))
        if os.environ.get('WORMRECOVERY_WORK_ROOT'):self.protected.append(pathlib.Path(os.environ['WORMRECOVERY_WORK_ROOT']))
        from engine_assets import engine_root
        self.protected.append(engine_root())
        self.cancel=threading.Event();self.count=0;self.dircount=0;self.scanned_office=0;self.started=time.monotonic()
        self.scan_roots=[];self.initial_findings=None;self.verification=None
        self.skipped=[];self.reparse_points=[];self.inspection_failed=False
        self.progress={'phase':'idle','stage':'准备就绪','path':'','started':time.monotonic(),'completed':0,'total':0}
        self.log('session',version=VERSION,volume_policy='Explicit physical-device scope; local exclusions enforced',privileges=enable_privileges())
    def log(self,kind,**data):
        rec={'time':datetime.datetime.now().isoformat(timespec='seconds'),'kind':kind,**data};self.events.append(rec)
        with (self.run/'journal.jsonl').open('a',encoding='utf-8') as f:f.write(json.dumps(rec,ensure_ascii=False)+'\n');f.flush();os.fsync(f.fileno())
    def protected_path(self,p):return any(beneath(p,r) for r in self.protected)
    def set_progress(self,phase,stage,path='',completed=0,total=0,timeout=None):
        self.progress={'phase':phase,'stage':stage,'path':str(path),'started':time.monotonic(),
                       'completed':completed,'total':total,'timeout':timeout}
        self.log('scan_phase',**self.progress)
        self.emit(stage+('：'+str(path) if path else ''))
    def root_residue_evidence(self,root):
        root=pathlib.Path(root)
        if norm(payload_root(root) or '')!=norm(root) or self.protected_path(root):return False
        try:
            self.policy.mutation(root)
            for name in ('GoogleChrome.a3x','GoogleChrome.exe','WindowsUpdate.lnk','GoogleUpdate.lnk'):
                p=root/name
                if not p.is_file() or file_attributes(p)&0x400:continue
                if name.endswith('.a3x') and digest_file(p)==AUTOIT_A3X_SHA256:return True
                if name.endswith('.exe') and is_stub(p):return True
                if name.endswith('.lnk') and (shortcut(p) or {}).get('malicious'):return True
            if root.is_dir():
                for p in root.iterdir():
                    if p.suffix.casefold()=='.lnk' and p.is_file() and not file_attributes(p)&0x400 and digest_file(p) in QUARANTINE_LINK_HASHES:return True
        except OSError:return False
        return False
    def confirmed_command(self,command):
        text=os.path.expandvars(str(command))
        pattern=r'"([^"]+)"|((?:[A-Za-z]:[\\/])[^"\r\n]*?\.(?:exe|com|scr|lnk|a3x))(?=\s|$|\")'
        for quoted,bare in re.findall(pattern,text,re.I):
            path=quoted or bare
            if not os.path.isabs(path) or self.protected_path(path):continue
            try:
                self.policy.check(path)
                if not os.path.isfile(path):continue
                extension=os.path.splitext(path)[1].casefold()
                if extension=='.a3x' and digest_file(path)==AUTOIT_A3X_SHA256:return True
                if extension=='.lnk' and (shortcut(path) or {}).get('malicious'):return True
                if extension in ('.exe','.com','.scr') and is_stub(path):return True
                if extension in ('.exe','.com','.scr') and self.content_confirmed_path(path):return True
            except (OSError,ValueError,struct.error):continue
        root=exact_startup_root(text)
        if root and self.root_residue_evidence(root):return True
        return False
    def content_confirmed_path(self,path):
        if self.protected_path(path):return False
        self.policy.check(path)
        if not os.path.isfile(path) or file_attributes(path)&0x400:return False
        from family_analysis import MAX_INPUT,inspect as inspect_family
        if os.path.getsize(path)>MAX_INPUT:
            from family_analysis import inspect_large_file
            return inspect_large_file(path)['status']=='detected'
        with open_read(path) as stream:data=stream.read(MAX_INPUT+1)
        if inspect_family(data)['status']=='detected':return True
        return any(row.get('kind')=='malware_deployment' and norm(row['path'])==norm(path)
                   and self.confirmed_deployment(row) for row in [*getattr(self,'findings',[]),*(getattr(self,'initial_findings',None) or [])])
    def confirmed_deployment(self,record):
        from family_analysis import KNOWN_RUNTIME,MAX_INPUT,inspect as inspect_family
        target=record['path']
        if record.get('sha256')!=KNOWN_RUNTIME or digest_file(target)!=KNOWN_RUNTIME:return False
        verified=[]
        for peer in record.get('related_evidence',[]):
            source=peer['path']
            if norm(os.path.dirname(source))!=norm(os.path.dirname(target)) or norm(source)==norm(target):return False
            self.policy.check(source)
            if self.protected_path(source):return False
            if os.path.isfile(source):
                if file_attributes(source)&0x400:return False
            else:
                backup=next((event.get('backup') for event in reversed(self.events)
                    if event.get('kind')=='quarantined' and norm(event['path'])==norm(source)
                    and event.get('sha256')==peer['sha256']),None)
                if not backup or not beneath(backup,self.quarantine):return False
                source=backup
            if os.path.getsize(source)>MAX_INPUT:return False
            with open_read(source) as stream:data=stream.read(MAX_INPUT+1)
            if hashlib.sha256(data).hexdigest()!=peer['sha256']:return False
            result=inspect_family(data)
            if result['status']!='detected':return False
            verified.append({'path':peer['path'],'sha256':peer['sha256'],'family_analysis':result})
        from family_analysis import correlate
        return bool(correlate(verified,[{'path':target,'sha256':KNOWN_RUNTIME,'role':'observed_trueupdate_runtime'}]))
    def recheck_deployment_observations(self):
        """Use verified quarantine evidence if an exact runtime is regenerated."""
        observed={(norm(row['path']),row.get('sha256')) for row in getattr(self,'family_observations',[])
                  if row.get('role')=='observed_trueupdate_runtime'}
        present={norm(row['path']) for row in self.findings if row.get('kind')=='malware_deployment'}
        for original in (getattr(self,'initial_findings',None) or []):
            if original.get('kind')!='malware_deployment' or norm(original['path']) in present:continue
            if (norm(original['path']),original.get('sha256')) not in observed:continue
            try:
                if not self.confirmed_deployment(original):
                    self.add('review_binary',original['path'],reason='原已确认部署运行时再次出现，但关联证据无法重新验证，原文件已保留。')
                    continue
                record=copy.deepcopy(original);kind=record.pop('kind');path=record.pop('path')
                record['confirmation_basis']='current_runtime_and_verified_pre_repair_companions'
                self.add(kind,path,**record);present.add(norm(path))
            except (OSError,ValueError,KeyError) as ex:self.error(original['path'],ex)
    def startup_approved(self,base,prefix,name,branches,source):
        for branch in branches:
            sub=(prefix+'\\' if prefix else '')+r'Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'+'\\'+branch
            for view in (winreg.KEY_WOW64_64KEY,winreg.KEY_WOW64_32KEY):
                try:
                    with winreg.OpenKey(base,sub,0,winreg.KEY_READ|winreg.KEY_SET_VALUE|view) as key:
                        try:value,typ=winreg.QueryValueEx(key,name)
                        except FileNotFoundError:continue
                        self.log('startup_approved_backup',key=sub,name=name,type=typ,view=view,value=base64.b64encode(value).decode('ascii') if isinstance(value,bytes) else value,source=source)
                        if winreg.QueryValueEx(key,name)!=(value,typ):raise RuntimeError('启动项状态已改变，请重新检测。')
                        winreg.DeleteValue(key,name);self.log('startup_approved_removed',key=sub,name=name,source=source)
                except FileNotFoundError:pass
    def shortcut_startup_approved(self,path):
        p=pathlib.Path(path)
        common=pathlib.Path(os.environ.get('PROGRAMDATA','C:/ProgramData'))/'Microsoft/Windows/Start Menu/Programs/Startup'
        user=pathlib.Path(os.environ.get('APPDATA',str(pathlib.Path.home()/'AppData/Roaming')))/'Microsoft/Windows/Start Menu/Programs/Startup'
        if norm(p.parent)==norm(common):base=winreg.HKEY_LOCAL_MACHINE
        elif norm(p.parent)==norm(user):base=winreg.HKEY_CURRENT_USER
        else:return
        self.startup_approved(base,'',p.name,('StartupFolder',),str(p))
    def error(self,path,ex,details=None):
        record={'path':str(path),'error':str(ex)}
        details=details or {'phase':getattr(ex,'operation_phase',None),'winerror':getattr(ex,'winerror',None)}
        if details.get('phase'):record['error_details']=details
        if details.get('phase')=='reparse_target':
            record.update(category='reparse_target_missing',content_inspected=False,
                          reason='链接目标在当前扫描环境中不存在：'+str(details.get('target') or ''),
                          action='保留链接及目标路径记录；目标不存在与读取权限被拒绝分别报告。')
        if details.get('source_bytes_read'):
            record.update(category='document_analysis_failed',source_bytes_read=True,content_inspected=False,
                          reason='文件字节已经读取，后续文档解析未完成。',action='保留原文件，查看具体分析步骤及自动重试结果。')
        elif details.get('phase')=='process_start':
            record.update(category='inspection_process_start_failed',reason='内部检查进程未能启动。',
                          action='文件访问权限与进程启动限制分别记录，不能将该错误解释为文件内容不可读。')
        from coverage_errors import active_pagefiles,describe_read_error
        if not record.get('category') and ('permission denied' in str(ex).casefold() or 'winerror 32' in str(ex).casefold() or getattr(ex,'winerror',None) in (5,32) or isinstance(ex,PermissionError)):
            if not hasattr(self,'_active_pagefiles'):
                try:self._active_pagefiles=active_pagefiles()
                except OSError:self._active_pagefiles=set()
            record.update(describe_read_error(path,ex,self._active_pagefiles))
        self.errors.append(record);self.log('error',**record)
    def add(self,kind,path,**detail):
        record={'kind':kind,'path':str(path),**detail};self.findings.append(record)
        labels={'infected_office':'受感染文档','infected_executable':'受感染程序','worm_payload':'恶意载荷','worm_hook':'恶意组件','worm_runtime':'恶意缓存','worm_script':'恶意脚本','malicious_shortcut':'恶意快捷方式','worm_residue':'已确认家族残留','review_office':'待核查文档','review_autoit':'待核查脚本'}
        if kind=='info_office':self.emit('已核对 Office 组件：'+str(path))
        else:self.emit('检测到'+labels.get(kind,'风险项目')+'：'+str(path))
        return record
    def backup(self,path):
        self.policy.mutation(path);p=pathlib.Path(path)
        if self.protected_path(p):raise PermissionError('所选路径已列入排除范围。')
        before=p.stat();h=digest_file(p);dest=self.quarantine/(h+'-'+uuid.uuid4().hex[:8]+'.quarantined')
        shutil.copy2(p,dest)
        if digest_file(dest)!=h or p.stat().st_size!=before.st_size or p.stat().st_mtime_ns!=before.st_mtime_ns:raise RuntimeError('备份期间源文件发生变化，操作已中止。')
        self.log('backup',path=str(p),backup=str(dest),sha256=h,attributes=file_attributes(p),mtime_ns=before.st_mtime_ns,size=before.st_size)
        return h,dest,before
    def stop_pid(self,pid,reason,*,process=None,expected_created=None,expected_exe=None):
        if pid in (0,4,os.getpid()):raise PermissionError('不能终止关键系统进程或当前程序。')
        if process is None or process.pid!=pid or expected_created is None or not expected_exe:
            raise PermissionError('进程身份不完整，已停止终止操作。')
        p=process
        if not p.is_running():raise psutil.NoSuchProcess(pid)
        if abs(p.create_time()-expected_created)>0.00001 or norm(p.exe())!=norm(expected_exe):
            raise PermissionError('进程身份已改变，已停止终止操作。')
        if p.name().casefold() in CRITICAL_PROCESSES or self.protected_path(expected_exe):
            raise PermissionError('受保护进程不能自动终止：'+p.name())
        self.log('terminate_process',pid=pid,name=p.name(),path=expected_exe,created=expected_created,reason=reason)
        p.kill();p.wait(10)
    def close_locks(self,path):
        if not self.force_close:return
        for holder in lock_holders(path):
            try:
                process=psutil.Process(holder['pid'])
                self.stop_pid(holder['pid'],'User-authorized release of confirmed infected file '+str(path),
                    process=process,expected_created=holder['created'],expected_exe=process.exe())
            except psutil.NoSuchProcess:pass
    def quarantine_file(self,path,reason,expected=None):
        self.policy.mutation(path);p=pathlib.Path(path)
        if not p.exists():return
        h,dest,st=self.backup(p)
        if expected and h!=expected:raise RuntimeError('文件在复核后发生变化，未终止占用进程。')
        self.close_locks(p)
        if digest_file(p)!=h:raise RuntimeError('隔离前源文件发生变化，操作已中止。')
        attrs=file_attributes(p);kernel.SetFileAttributesW(str(p),attrs&~1)
        p.unlink();self.log('quarantined',path=str(p),backup=str(dest),sha256=h,reason=reason)
    def replace(self,path,stage,expected=None):
        self.policy.mutation(path);self.policy.mutation(stage);p=pathlib.Path(path);t=pathlib.Path(stage)
        if p.exists():
            h,back,st=self.backup(p)
            if expected and h!=expected:raise RuntimeError('源文件与检测记录不一致，操作已中止。')
            self.close_locks(p)
            if digest_file(p)!=h:raise RuntimeError('提交修复前源文件发生变化，操作已中止。')
            oldattrs=file_attributes(p);kernel.SetFileAttributesW(str(p),oldattrs&~1)
            if not kernel.ReplaceFileW(str(p),str(t),None,1,None,None):
                error=ctypes.get_last_error()
                if error in (1,50) and t.exists() and digest_file(p)==h:
                    try:os.replace(t,p)
                    except OSError:kernel.SetFileAttributesW(str(p),oldattrs);raise
                else:kernel.SetFileAttributesW(str(p),oldattrs);raise ctypes.WinError(error)
            kernel.SetFileAttributesW(str(p),(oldattrs&~7) or 0x80);os.utime(p,ns=(st.st_atime_ns,st.st_mtime_ns))
        else:
            # rename on Windows fails if destination appeared; never overwrite it.
            os.rename(t,p)
        self.log('restored',path=str(p),sha256=digest_file(p))
    def contain(self,apply=False):
        hits=[]
        for p in psutil.process_iter(['pid','name','exe','cmdline','create_time']):
            try:
                if p.pid==os.getpid() or (p.info['name'] or '').casefold() in CRITICAL_PROCESSES:continue
                exe=p.info['exe'];args=p.info['cmdline'] or [];cmd=' '.join(args)
                if not exe:continue
                # Process containment is independent from file mutation scope.
                # Reading a live external process image never removes USB samples.
                bad=bool(is_stub(exe))
                autoit=False
                if os.path.isfile(exe) and os.path.getsize(exe)==750320 and digest_file(exe)==AUTOIT_EXE_SHA256 and any(str(a).casefold()=='/autoit3executescript' for a in args[1:]):
                    for arg in args[1:]:
                        script=arg.strip('"')
                        if os.path.isabs(script) and script.casefold().endswith('.a3x') and os.path.isfile(script) and digest_file(script)==AUTOIT_A3X_SHA256:
                            autoit=True;break
                        root=exact_script_root(script)
                        if root and self.root_residue_evidence(root):autoit=True;break
                content=not bad and not autoit and self.content_confirmed_path(exe)
                if bad or autoit or content:
                    rec={'pid':p.pid,'exe':exe,'cmdline':cmd,'family':'Synaptics' if bad else 'AutoIt' if autoit else 'Confirmed worm/miner code'};hits.append(rec)
                    if apply:self.stop_pid(p.pid,'Confirmed worm process',process=p,expected_created=p.info.get('create_time'),expected_exe=exe)
            except (psutil.Error,OSError,ValueError) as ex:self.error('process:'+str(p.pid),ex)
        self.log('process_inspection',apply=apply,processes=hits);return hits
    def registry(self,apply=False):
        hits=[];hives=[('HKLM',winreg.HKEY_LOCAL_MACHINE)]
        # Inspect loaded user hives without mounting or writing offline hives.
        i=0
        while True:
            try:sid=winreg.EnumKey(winreg.HKEY_USERS,i);i+=1
            except OSError:break
            if sid.startswith('S-1-5-') and not sid.endswith('_Classes'):
                hives.append(('HKU\\'+sid,(winreg.HKEY_USERS,sid)))
        paths=registry_paths()
        for label,hive in hives:
            for view in (winreg.KEY_WOW64_64KEY,winreg.KEY_WOW64_32KEY):
                for sub in paths:
                    base,prefix=hive if isinstance(hive,tuple) else (hive,'')
                    keypath=(prefix+'\\' if prefix else '')+sub
                    try:
                        with winreg.OpenKey(base,keypath,0,winreg.KEY_READ|(winreg.KEY_SET_VALUE if apply else 0)|view) as key:
                            values=[];i=0
                            while True:
                                try:values.append(winreg.EnumValue(key,i));i+=1
                                except OSError:break
                            for name,value,typ in values:
                                text=str(value).casefold()
                                prior=next((r for r in (getattr(self,'registry_snapshot',None) or [])
                                    if r.get('confirmed') and (r['hive'].casefold(),r['key'].casefold(),r['view'],r['name'].casefold())==(label.casefold(),sub.casefold(),view,name.casefold())),None)
                                snapshot_match=bool(prior and prior['value']==value and prior['type']==typ)
                                confirmed=self.confirmed_command(value) or snapshot_match
                                bad=bool(prior) or confirmed or ('googlechrome.a3x' in text or exact_startup_root(value) is not None)
                                if 'synaptics' in text:
                                    target=str(value).strip('"').split('"')[0]
                                    bad=bad or (os.path.isfile(target) and is_stub(target))
                                if bad:
                                    rec={'hive':label,'key':sub,'view':view,'name':name,'value':value,'type':typ};hits.append(rec)
                                    rec['confirmed']=confirmed
                                    if prior:rec['snapshot_status']='exact' if snapshot_match else 'changed_requires_review'
                                    if apply and rec['confirmed']:
                                        self.log('registry_backup',**rec)
                                        if winreg.QueryValueEx(key,name)!=(value,typ):raise RuntimeError('启动项已改变，请重新检测。')
                                        if sub in paths[:3]:
                                            winreg.DeleteValue(key,name);self.log('registry_removed',**rec)
                                            self.startup_approved(base,prefix,name,('Run','Run32'),value)
                                        else:
                                            # Shared Shell/Userinit/AppInit values can contain legitimate commands.
                                            self.inspection_failed=True
                                            self.log('registry_manual_repair_required',**rec)
                    except FileNotFoundError:pass
                    except OSError as ex:self.error(label+'\\'+sub,ex)
        self.log('registry_inspection',apply=apply,hits=hits);return hits
    def system_persistence(self,apply=False):
        try:
            inventory=powershell(INVENTORY_SCRIPT)
            d=select_confirmed(inventory,self.confirmed_command)
            if not apply:d=reconcile_snapshot(inventory,d,getattr(self,'persistence_snapshot',{}))
            self.last_persistence=copy.deepcopy(d)
            self.log('persistence_inventory',counts=d['inventory_counts'],filters=inventory.get('filters',[]),bindings=inventory.get('bindings',[]))
            self.log('system_persistence',apply=apply,result=d)
            if apply:
                for t in d.get('tasks',[]):
                    if self.confirmed_command('"'+str(t.get('execute','')).strip('"')+'" '+str(t.get('arguments',''))):
                        self.log('task_disable_backup',task=t)
                        powershell(disable_task_script(t));self.log('task_disabled',task=t)
                for s in d.get('services',[]):
                    # Require the real engine fingerprint before changing a service.
                    if self.confirmed_command(s['PathName']):
                        self.log('service_disable_backup',service=s)
                        powershell(disable_service_script(s));self.log('service_disabled',service=s)
                for x in d.get('wmi',[]):
                    self.log('wmi_subscription_backup',consumer=x,filters=inventory.get('filters',[]),bindings=inventory.get('bindings',[]))
                    from persistence_inventory import remove_consumer_script
                    powershell(remove_consumer_script(x));self.log('wmi_consumer_removed',consumer=x)
            return d
        except Exception as ex:self.inspection_failed=True;self.error('system_persistence',ex);return {}
    def firewall(self,apply=False):
        # The exact abused cache name, never a generic Chrome browser rule.
        script=r"""
        $out=@();foreach($r in (Get-NetFirewallRule -DisplayName 'GoogleChrome.exe' -ErrorAction SilentlyContinue)){
          foreach($f in ($r|Get-NetFirewallApplicationFilter)){
            if($f.Program.Replace([char]92,[char]47).EndsWith('/._cache_GoogleChrome.exe',[StringComparison]::OrdinalIgnoreCase)){
              $out+=@{name=$r.Name;display=$r.DisplayName;enabled=[string]$r.Enabled;program=$f.Program;direction=[string]$r.Direction;action=[string]$r.Action}
            }
          }
        };ConvertTo-Json -InputObject @($out) -Compress
        """
        try:
            rows=powershell(script) or [];rows=[rows] if isinstance(rows,dict) else rows
            self.log('firewall_inspection',rules=rows,apply=apply)
            if apply:
                for r in rows:
                    if r['enabled']=='True':
                        self.log('firewall_backup',rule=r)
                        powershell('Disable-NetFirewallRule -Name '+psquote(r['name'])+' | Out-Null')
                        self.log('firewall_disabled',rule=r)
            return rows
        except Exception as ex:self.inspection_failed=True;self.error('firewall',ex);return []
    def historical_original(self,path,infected_mtime):
        """Optional, exact-path snapshot recovery; the current bytes stay backed up."""
        if not self.restore_history:return None
        if self.shadow_cache is None:
            script=r"@(Get-CimInstance Win32_ShadowCopy | ForEach-Object {@{device=$_.DeviceObject;volume=$_.VolumeName;created=$_.InstallDate.ToUniversalTime().ToString('o')}}) | ConvertTo-Json -Compress"
            rows=powershell(script) or [];self.shadow_cache=[rows] if isinstance(rows,dict) else rows
        p=pathlib.Path(path).with_suffix('.xlsx')
        source_volume=volume_identity(volume(p))
        for s in sorted(self.shadow_cache,key=lambda x:x['created'],reverse=True):
            if str(s.get('volume','')).casefold()!=source_volume:continue
            created=datetime.datetime.fromisoformat(s['created'].replace('Z','+00:00')).timestamp()
            if created>=infected_mtime:continue
            source=s['device']+chr(92)+str(p)[3:]
            try:
                st=os.stat(source)
                if st.st_mtime>infected_mtime or st.st_size>1024*1024*1024:continue
                if office_check(source).get('macro') is not False:continue
                with zipfile.ZipFile(source) as z:
                    if z.testzip():continue
                    if 'xl/workbook.xml' not in z.namelist():continue
                    if any(any(t in n.casefold() for t in ('vbaproject','activex','embeddings/','externallinks/')) for n in z.namelist()):continue
                self.log('historical_original_selected',path=str(p),source=source,sha256=digest_file(source),snapshot=s,warning='Explicit historical recovery can discard edits after this snapshot; pre-repair bytes are retained in quarantine.')
                return {'source':source,'sha256':digest_file(source),'mtime_ns':st.st_mtime_ns,'snapshot':s}
            except FileNotFoundError:continue
            except OSError as ex:self.log('snapshot_unavailable',source=source,error=str(ex))
        return None
    def record_file_result(self,path,result):
        self.count+=1;self.scanned_office+=result.get('office',0)
        self.streamed_bytes=getattr(self,'streamed_bytes',0)+result.get('streamed_bytes',0)
        if not hasattr(self,'engine_checks'):self.engine_checks={}
        for engine,count in result.get('engine_checks',{}).items():
            self.engine_checks[engine]=self.engine_checks.get(engine,0)+count
        for row in result.get('findings',[]):
            row=dict(row);kind=row.pop('kind');target=row.pop('path')
            self.add(kind,target,**row)
        if result.get('family_observations'):
            if not hasattr(self,'family_observations'):self.family_observations=[]
            self.family_observations.extend(result['family_observations'])
        if result.get('error'):
            self.inspection_failed=True;self.error(path,result['error'],result.get('error_details'))
    def scan_file(self,path,st):
        self.record_file_result(path,inspect_file_content(path,st))
    def scan(self,roots=None,workers=None):
        from scan_concurrency import FileScanner,storage_profile
        from reparse_scan import inspect_reparse,resolve_target,CoverageLimit
        roots=self.policy.fixed_roots() if roots is None else roots
        if not roots:raise ValueError('未指定有效扫描范围。')
        self.findings=[];self.count=0;self.dircount=0;self.scanned_office=0;self.skipped=[];self.reparse_points=[];start=time.monotonic()
        self.engine_checks={};self.streamed_bytes=0;self.secondary_dispatch={'status':'not_started','candidates':0};self.family_observations=[]
        self.scan_roots=list(map(os.path.abspath,roots))
        self.scan_active=True;self.scan_started=start;self.current_path='';self.last_progress=start;self.last_completed=start
        self.set_progress('files','正在遍历并检查文件')
        self.emit('正在检查所选扫描范围。');stack=[];visited=set();files_seen=set();failed_directories=set();directory_volumes={}
        def approved(path):
            if self.protected_path(path) or not any(beneath(path,r) for r in self.scan_roots):return False
            try:self.policy.check(path);return True
            except OSError:return False
        def directory_id(path,st=None):
            st=st or os.stat(extended_path(path))
            return ('id',st.st_dev,st.st_ino) if st.st_ino else ('path',norm(path))
        failed_files=set()
        def accept_file(path,result,error):
            if error:
                failed_files.add(norm(path));self.count+=1;self.error(path,error)
            else:self.record_file_result(path,result)
            self.last_completed=time.monotonic()
        profiles={};root_infos={}
        for selected in roots:
            info=self.policy.check(selected);root=info['root'];root_infos[norm(selected)]=info
            if root not in profiles:profiles[root]=storage_profile(root)
        def validate_volume(root):
            if norm(root) in self.policy.external_volumes and volume_identity(root)!=self.policy.external_volumes[norm(root)]:
                raise PermissionError('设备连接状态已变化。请重新扫描。')
        scanner=FileScanner(inspect_file_content,accept_file,self.cancel,profiles,workers,validate_volume)
        self.file_scanner=scanner;self.scan_workers=scanner.workers
        self.log('scan_concurrency',workers=scanner.workers,devices=list(profiles.values()),queue_limit=scanner.queue_limit)
        def inspect_file(path,st):
            key=norm(path)
            if key in files_seen:return 'target_already_checked'
            files_seen.add(key);self.current_path=path
            root=directory_volumes.get(norm(os.path.dirname(path)))
            if root is None:root=self.policy.check(path)['root']
            if root not in profiles:
                # A reparse target on a newly encountered volume is checked serially.
                try:accept_file(path,inspect_file_content(path,st),None)
                except Exception as ex:accept_file(path,None,str(ex))
            else:scanner.submit(path,st,root)
            return 'target_checked'
        def inspect_link(path):
            record={'path':path,'status':'pending'};self.reparse_points.append(record)
            try:
                if self.protected_path(path):raise CoverageLimit('excluded_path',path)
                info=inspect_reparse(path);record.update(info)
                resolved=resolve_target(info['target'],approved)
                target=resolved['target'];record['resolved_target']=target;record['chain']=resolved['chain']
                st=os.stat(target)
                if os.path.isdir(target):
                    record['directory_id']=directory_id(target,st)
                    directory_volumes[norm(target)]=self.policy.check(target)['root'];stack.append(target)
                else:record['status']=inspect_file(target,st)
            except CoverageLimit as ex:
                record['status']='unverified';record['reason']=ex.reason
                if ex.target:record['target']=ex.target
                self.skipped.append({'path':path,'reason':ex.reason,'target':ex.target})
            except FileNotFoundError as ex:
                record['status']='error';record['error']=str(ex)
                details={'phase':'reparse_target','source_bytes_read':False,'target':record.get('target'),
                         'exception_type':type(ex).__name__,'winerror':getattr(ex,'winerror',None)}
                self.error(path,ex,details)
            except Exception as ex:
                record['status']='error';record['error']=str(ex);self.error(path,ex)
        try:
            with scanner:
                for root in roots:
                    info=root_infos[norm(root)]
                    removed={norm(e['path']) for e in self.events if e['kind']=='empty_payload_directory_removed'}
                    if norm(root) in removed and not os.path.exists(root):
                        self.log('verified_removed_scan_root',path=str(root));continue
                    if not os.path.isdir(extended_path(root)):raise ValueError('扫描位置不存在或不是目录：'+str(root))
                    if self.protected_path(root):raise ValueError('所选位置已列入排除范围。')
                    if file_attributes(root)&0x400:inspect_link(os.path.abspath(root))
                    else:
                        directory_volumes[norm(root)]=info['root'];stack.append(os.path.abspath(root))
                while stack and not self.cancel.is_set():
                    scanner.poll()
                    directory=stack.pop()
                    if self.protected_path(directory):
                        self.skipped.append({'path':directory,'reason':'excluded_path'});continue
                    try:
                        # Reparse targets are resolved separately; ordinary entries
                        # inherit the verified parent volume without a Win32 query.
                        root=directory_volumes[norm(directory)]
                        self.policy.check_volume(root);self.current_path=directory
                        identity=directory_id(directory)
                        if identity in visited:continue
                        with os.scandir(extended_path(directory)) as entries:
                            visited.add(identity)
                            self.dircount+=1
                            for e in entries:
                                if self.cancel.is_set():break
                                path=os.path.join(directory,e.name)
                                try:
                                    st=e.stat(follow_symlinks=False)
                                    if st.st_file_attributes&0x400:
                                        inspect_link(path);continue
                                    if e.is_dir(follow_symlinks=False):
                                        directory_volumes[norm(path)]=root;stack.append(path);continue
                                    inspect_file(path,st)
                                except Exception as ex:self.error(path,ex)
                        self.last_completed=time.monotonic()
                        if self.last_completed-self.last_progress>=1:
                            self.last_progress=self.last_completed
                            self.emit('已扫描 %s 文件 / %s 目录；平均 %s 文件/秒'%(self.count,self.dircount,int(self.count/max(.001,self.last_completed-start))))
                    except OSError as ex:failed_directories.add(norm(directory));self.error(directory,ex)
        finally:
            self.scan_active=False;self.file_scanner=None
        for record in self.reparse_points:
            if record.get('resolved_target') and norm(record['resolved_target']) in failed_files:
                record['status']='error';record['error']='链接目标读取失败，详见异常记录。'
            identity=record.pop('directory_id',None)
            if identity is not None:
                target=record['resolved_target']
                record['status']='target_visited' if identity in visited and norm(target) not in failed_directories else 'unverified'
                if record['status']=='unverified':
                    record['reason']='scan_cancelled_or_target_unavailable';self.skipped.append({'path':record['path'],'target':target,'reason':record['reason']})
        self.scan_seconds=time.monotonic()-start;self.scan_active=False
        self.file_scan_seconds=self.scan_seconds
        if not self.cancel.is_set():
            from family_analysis import correlate
            for row in correlate(self.findings,self.family_observations):
                kind=row.pop('kind');path=row.pop('path');self.add(kind,path,**row)
            self.recheck_deployment_observations()
            from secondary_analysis import enrich_reviews
            enrich_reviews(self)
        self.scan_seconds=time.monotonic()-start
        self.review_seconds=max(0,self.scan_seconds-self.file_scan_seconds)
        self.set_progress('save','正在保存检测报告')
        self.log('scan_complete',files=self.count,directories=self.dircount,seconds=self.scan_seconds,cancelled=self.cancel.is_set(),findings=len(self.findings),skipped_count=len(self.skipped))
        self.save()
        self.progress=dict(self.progress,phase='stopped' if self.cancel.is_set() else 'complete',stage='已停止' if self.cancel.is_set() else '检测完成')
        return self.findings
    def payload_path(self,path):
        p=pathlib.Path(path);parts=[x.casefold() for x in p.parts]
        root_payload=len(parts)>1 and parts[1] in ('googlechrome','mozillafirefox')
        return root_payload or p.name.casefold().startswith(('~$cache','._cache_')) or ('synaptics' in parts and p.name.casefold()=='synaptics.exe')
    def cleanup_empty_payload_roots(self,roots):
        for raw in roots:
            root=pathlib.Path(raw)
            if not root.exists():continue
            self.policy.mutation(root)
            if self.protected_path(root) or norm(payload_root(root) or '')!=norm(root):continue
            if any(root.iterdir()):
                self.log('payload_directory_retained',path=str(root),reason='Contains unclassified files; no recursive deletion')
                continue
            attrs=file_attributes(root);self.log('empty_payload_directory_backup',path=str(root),attributes=attrs)
            if not kernel.SetFileAttributesW(str(root),attrs&~7 or 16):raise ctypes.WinError(ctypes.get_last_error())
            try:root.rmdir()
            except OSError:
                if root.exists():kernel.SetFileAttributesW(str(root),attrs)
                raise
            self.log('empty_payload_directory_removed',path=str(root))
    def restore_executable(self,path,expected=None):
        p=pathlib.Path(path);self.policy.mutation(p);source_hash=digest_file(p);created=[]
        if expected and source_hash!=expected:raise ValueError('程序在复核后发生变化，原文件已保留。')
        try:
            current=p;layers=0
            while is_stub(current):
                if layers>=8:raise ValueError('嵌套感染层数超过处理上限。')
                nextstage=p.with_name('.wormrepair-'+uuid.uuid4().hex+'.tmp');created.append(nextstage)
                with PEView(current) as pe:
                    res=pe.resource('EXERESX')
                    if not res:raise ValueError('文件中未发现可验证原件，无法自动恢复。')
                    pe.extract_resource(res,nextstage)
                current=nextstage;layers+=1
            if not layers:raise ValueError('感染层结构未验证，原文件已保留。')
            from family_analysis import MAX_INPUT,inspect as inspect_family
            if current.stat().st_size>MAX_INPUT:
                from family_analysis import inspect_large_file
                original_analysis=inspect_large_file(current,expected_stat=current.stat())
            else:
                with open_read(current) as stream:original_analysis=inspect_family(stream.read(MAX_INPUT+1))
            if original_analysis['status']!='no_known_match':raise ValueError('嵌入原件仍包含已知恶意代码或未完成解析，原文件已保留。')
            with PEView(current) as clean:
                if clean.size<1024:raise ValueError('嵌入原件结构无效，无法自动恢复。')
            if digest_file(p)!=source_hash:raise RuntimeError('提取期间源文件发生变化，操作已中止。')
            restored_hash=digest_file(current);self.replace(p,current,expected=source_hash)
            if digest_file(p)!=restored_hash or is_stub(p):raise RuntimeError('程序修复后校验失败。')
            self.log('executable_recovered',path=str(p),layers=layers,original_sha256=restored_hash,original_bytes=p.stat().st_size,scope='observed Synaptics wrapper only; unrelated threats not certified')
        finally:
            for t in created:
                if t.exists():t.unlink()
    def restore_office(self,path,expected=None):
        p=pathlib.Path(path);self.policy.mutation(p);check=office_check(p)
        if check['status']!='infected':raise ValueError('文档不再匹配检测指纹，请重新检测。')
        h=digest_file(p)
        if expected and h!=expected:raise ValueError('文档在复核后发生变化，原文件已保留。')
        source_stat=p.stat();source_attrs=file_attributes(p);dest=p.with_suffix('.xlsx')
        if dest!=p and dest.exists():raise FileExistsError('目标文件已存在，双方均已保留，需人工核查：'+str(dest))
        stage=p.with_name('.wormrepair-'+uuid.uuid4().hex+'.xlsx.tmp')
        try:
            history=self.historical_original(p,source_stat.st_mtime)
            if history:
                shutil.copyfile(history['source'],stage)
                if digest_file(stage)!=history['sha256']:raise RuntimeError('历史原件复制后的哈希校验失败。')
                validation={'historical_original':history,'worksheet_bytes_preserved':False}
            else:validation=sanitized_xlsx(p,stage)
            if digest_file(p)!=h:raise RuntimeError('修复期间文档发生变化，操作已中止。')
            result_hash=digest_file(stage);backup_hash,_,_=self.backup(p)
            if backup_hash!=h:raise RuntimeError('备份前文档发生变化，未终止占用进程。')
            self.close_locks(p)
            if digest_file(p)!=h:raise RuntimeError('提交修复前文档发生变化，操作已中止。')
            if dest==p:self.replace(p,stage,expected=h)
            else:
                self.replace(dest,stage)
                if digest_file(dest)!=result_hash:raise RuntimeError('文档修复后校验失败。')
                os.utime(dest,ns=(source_stat.st_atime_ns,source_stat.st_mtime_ns))
                if not kernel.SetFileAttributesW(str(dest),(source_attrs&~7) or 0x80):raise ctypes.WinError(ctypes.get_last_error())
                kernel.SetFileAttributesW(str(p),file_attributes(p)&~1);p.unlink()
            if history:os.utime(dest,ns=(source_stat.st_atime_ns,history['mtime_ns']))
            self.log('office_recovered',path=str(p),restored_path=str(dest),source_sha256=h,sha256=result_hash,validation=validation,content_provenance='exact-path macro-free snapshot original' if history else 'preserved current worksheet bytes; no claim of missing historical data restoration')
        finally:
            if stage.exists():stage.unlink()
    def security_settings(self):
        changes=[]
        # Only repair the exact weakened macro setting observed in the malware.
        for version in ('12.0','14.0','15.0','16.0'):
            for app in ('Excel','Word'):
                sub='Software\\Microsoft\\Office\\'+version+'\\'+app+'\\Security'
                try:
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER,sub,0,winreg.KEY_READ|winreg.KEY_SET_VALUE) as k:
                        old,typ=winreg.QueryValueEx(k,'VBAWarnings')
                        if old==1:self.log('security_setting_backup',key=sub,name='VBAWarnings',value=old,type=typ);winreg.SetValueEx(k,'VBAWarnings',0,winreg.REG_DWORD,2);changes.append(sub)
                except FileNotFoundError:pass
        sub=r'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER,sub) as k:
            for name,new in [('Hidden',1),('ShowSuperHidden',1)]:
                try:old,typ=winreg.QueryValueEx(k,name)
                except FileNotFoundError:old,typ=None,winreg.REG_DWORD
                self.log('security_setting_backup',key=sub,name=name,value=old,type=typ);winreg.SetValueEx(k,name,0,winreg.REG_DWORD,new)
        self.log('security_settings_repaired',macro_keys=changes)
    def confirmed_autoit_runtime(self,record):
        if digest_file(record['path'])!=AUTOIT_EXE_SHA256:return False
        companion=str(autoit_companion_path(record['path']))
        peers=record.get('related_evidence',[])
        if len(peers)!=1 or norm(peers[0]['path'])!=norm(companion) or peers[0].get('sha256')!=AUTOIT_A3X_SHA256:return False
        if self.protected_path(companion):return False
        self.policy.check(companion)
        if os.path.isfile(companion):
            return not file_attributes(companion)&0x400 and digest_file(companion)==AUTOIT_A3X_SHA256
        backup=next((event.get('backup') for event in reversed(self.events)
            if event.get('kind')=='quarantined' and norm(event['path'])==norm(companion)
            and event.get('sha256')==AUTOIT_A3X_SHA256),None)
        return bool(backup and beneath(backup,self.quarantine) and digest_file(backup)==AUTOIT_A3X_SHA256)
    def revalidate_finding(self,record,path):
        """Require current byte evidence before any application lock release."""
        before=digest_file(path)
        if record.get('sha256') and before!=record['sha256']:
            raise ValueError('检测后文件已改变，未终止占用进程，原文件已保留。')
        if record['kind']=='malware_deployment':
            valid=self.confirmed_deployment(record)
        elif record['kind']=='worm_runtime':
            valid=self.confirmed_autoit_runtime(record)
        else:
            fresh=inspect_file_content(path,path.stat())
            valid=any(row['kind']==record['kind'] and is_confirmed(row) for row in fresh['findings'])
        if not valid or digest_file(path)!=before:
            raise ValueError('内容复核未通过，未终止占用进程，原文件已保留。')
        return before
    def repair(self):
        self.initial_findings=copy.deepcopy(self.findings)
        self.registry_snapshot=copy.deepcopy(self.registry(False))
        self.persistence_snapshot=copy.deepcopy(self.system_persistence(False))
        self.registry(True);self.system_persistence(True);self.firewall(True);self.contain(True)
        self.log('containment_scope',reason='Persistence disabled before process containment; subsequent process checks reduce but cannot atomically prevent regeneration.')
        residue_roots=set()
        for rec in list(self.findings):
            if self.cancel.is_set():break
            kind,p=rec['kind'],pathlib.Path(rec['path'])
            if not is_confirmed(rec):continue
            try:
                if not p.exists():continue
                self.policy.mutation(p)
                expected=self.revalidate_finding(rec,p)
                self.contain(True)
                self.emit('正在修复：'+str(p))
                if kind=='infected_office':self.restore_office(p,expected=expected)
                elif kind=='infected_executable':self.restore_executable(p,expected=expected)
                elif kind=='malicious_shortcut':
                    if not shortcut(p).get('malicious'):raise ValueError('快捷方式已发生变化，请重新检测。')
                    self.shortcut_startup_approved(p)
                    self.quarantine_file(p,'confirmed AutoIt shortcut',expected=expected)
                    candidate=p.with_suffix('')
                    if candidate.is_dir() and not self.payload_path(candidate) and not beneath(candidate,os.environ.get('WINDIR','C:/Windows')):
                        self.policy.mutation(candidate);a=file_attributes(candidate)
                        if a&6:self.log('attributes_backup',path=str(candidate),attributes=a);kernel.SetFileAttributesW(str(candidate),(a&~6) or 16)
                elif kind=='worm_payload':
                    if not is_stub(p):raise ValueError('载荷指纹已发生变化，请重新检测。')
                    self.quarantine_file(p,kind,expected=expected)
                elif kind=='worm_script':
                    if digest_file(p)!=AUTOIT_A3X_SHA256:raise ValueError('脚本已发生变化，请重新检测。')
                    self.quarantine_file(p,kind,expected=expected)
                elif kind in ('worm_runtime','worm_hook'):
                    expected=AUTOIT_EXE_SHA256 if kind=='worm_runtime' else HOOK_SHA256
                    if digest_file(p)!=expected:raise ValueError('组件指纹已发生变化，请重新检测。')
                    if kind=='worm_runtime' and not self.confirmed_autoit_runtime(rec):raise ValueError('恶意配套脚本证据发生变化，解释器已保留。')
                    self.quarantine_file(p,kind,expected=expected)
                elif kind=='worm_residue':
                    if digest_file(p) not in QUARANTINE_LINK_HASHES:raise ValueError('残留文件指纹已改变，请重新检测。')
                    self.quarantine_file(p,'confirmed family quarantine-link residue',expected=expected)
                elif kind=='malware_component':
                    if digest_file(p)!=rec['sha256']:raise ValueError('恶意组件内容已改变，请重新检测。')
                    fresh=inspect_file_content(p,p.stat())
                    if not any(r['kind']=='malware_component' and r['sha256']==rec['sha256'] for r in fresh['findings']):
                        raise ValueError('恶意代码特征复核未通过，原文件已保留。')
                    self.quarantine_file(p,'confirmed malicious code component',expected=expected)
                elif kind=='malware_deployment':
                    # A legitimate signed runtime is not deletion authority on
                    # its own. Recheck all peer hashes before processing starts;
                    # peers already quarantined retain their exact backup proof.
                    if not self.confirmed_deployment(rec):raise ValueError('关联加载链已改变，运行时已保留。')
                    self.quarantine_file(p,'content-proven malicious deployment runtime',expected=expected)
                root=payload_root(p)
                if root:residue_roots.add(root)
            except Exception as ex:self.error(p,ex)
        for root in residue_roots:
            try:self.cleanup_empty_payload_roots([root])
            except Exception as ex:self.error(root,ex)
        try:self.security_settings();self.registry(True)
        except Exception as ex:self.error('security_settings',ex)
        self.save()
    def verify(self):
        before_errors=len(self.errors);roots=list(self.scan_roots)
        workers=getattr(self,'scan_workers',None)
        remaining=self.scan(roots,workers=workers) if workers is not None else self.scan(roots)
        processes=self.contain(False);registry=self.registry(False);system=self.system_persistence(False);firewall=[x for x in self.firewall(False) if x['enabled']=='True']
        active_tasks=[]
        for x in system.get('tasks',[]):
            try:
                enabled=ET.fromstring(x.get('xml','')).find('.//{*}Settings/{*}Enabled')
                if enabled is None or (enabled.text or '').strip().casefold()!='false':active_tasks.append(x)
            except ET.ParseError:active_tasks.append(x)
        active_services=[x for x in system.get('services',[]) if x.get('StartMode')!='Disabled' or x.get('State')!='Stopped']
        confirmed=[x for x in remaining if is_confirmed(x)]
        self.verification={'roots':roots,'remaining_confirmed':confirmed,'review_count':sum(x['kind'].startswith('review_') for x in remaining),'processes':processes,'registry':registry,'active_tasks':active_tasks,'active_services':active_services,'wmi':system.get('wmi',[]),'enabled_worm_firewall_rules':firewall,'new_errors':len(self.errors)-before_errors,'known_family_clear':not (confirmed or processes or registry or active_tasks or active_services or system.get('wmi',[]) or firewall or len(self.errors)>before_errors or self.cancel.is_set()),'coverage':'USB, research paths, and inaccessible locations excluded; no universal clean certification'}
        self.verification['disabled_tasks']=[x for x in system.get('tasks',[]) if x not in active_tasks]
        self.verification['disabled_services']=[x for x in system.get('services',[]) if x not in active_services]
        self.verification['persistence_changes']=system.get('snapshot_changes',[])
        self.verification['size_limited_files']=getattr(self,'engine_checks',{}).get('family_size_limited',0)
        self.verification['large_file_incomplete']=getattr(self,'engine_checks',{}).get('family_streamed_failed',0)
        self.verification['known_family_clear']=self.verification['known_family_clear'] and not self.errors and not self.inspection_failed and not self.verification['persistence_changes'] and not self.verification['size_limited_files'] and not self.verification['large_file_incomplete']
        self.verification['unverified_links']=[r for r in getattr(self,'reparse_points',[]) if r.get('status') in ('unverified','error','pending')]
        self.verification['known_family_clear']=self.verification['known_family_clear'] and not self.verification['unverified_links']
        self.verification['coverage']='Selected mounted volumes only; exclusions, reparse points, archives, offline hives and other malware families are not certified.'
        self.verification['skipped_count']=len(self.skipped)
        self.verification['informational_count']=sum(x['kind'].startswith('info_') for x in remaining)
        self.verification['unresolved_review_count']=self.verification['review_count']
        self.verification['known_family_clear']=self.verification['known_family_clear'] and not self.verification['review_count']
        self.verification['assessment']='未检出已知威胁，检测覆盖范围存在限制。' if self.verification['known_family_clear'] else '存在未解决项目或未完成检查，不能判定清理完成。'
        self.verification['unverified_areas']=['压缩档内部文件','离线用户配置单元','未分配盘符或未挂载的卷','排除目录与未解析或范围外的链接目标','未识别的恶意软件家族']
        self.log('verification_complete',result=self.verification);self.save();return self.verification
    def save(self):
        summary={'version':VERSION,'computer':os.environ.get('COMPUTERNAME'),'files':self.count,'directories':self.dircount,'scan_seconds':getattr(self,'scan_seconds',None),'file_scan_seconds':getattr(self,'file_scan_seconds',None),'review_seconds':getattr(self,'review_seconds',None),'scan_workers':getattr(self,'scan_workers',1),'office_examined':self.scanned_office,'findings':self.findings,'errors':self.errors,'events':self.events,'volume_policy':self.policy.cache,'cancelled':self.cancel.is_set(),'limitation':'Sample-specific repair; encrypted/corrupt/unknown malware and inaccessible areas remain explicitly unverified.'}
        summary.update(registry_snapshot=getattr(self,'registry_snapshot',None),persistence_snapshot=getattr(self,'persistence_snapshot',None),scan_roots=self.scan_roots,initial_findings=self.initial_findings,verification=self.verification,skipped=self.skipped,reparse_points=getattr(self,'reparse_points',[]),inspection_failed=self.inspection_failed,scope_summary=getattr(self,'scope_summary',None))
        summary['operation']=dict(getattr(self,'operation',{'type':'legacy_unclassified'}))
        summary['scan_timing']={'file_scan_seconds':getattr(self,'file_scan_seconds',None),'secondary_analysis_seconds':getattr(self,'review_seconds',None)}
        summary['scan_progress']=dict(self.progress)
        from engine_assets import manifest
        from local_rules import RULESET_VERSION
        assets=manifest()
        from engine_audit import build_audit
        summary['offline_analysis']={'versions':assets.get('versions',{}),'ruleset_version':RULESET_VERSION,'assets_available':bool(assets),'scope':'Content screening plus second-opinion analysis of unresolved candidates; no universal safety verdict',
            **build_audit(getattr(self,'engine_checks',{}),getattr(self,'secondary_dispatch',{'status':'not_started','candidates':0}),self.findings)}
        summary['offline_analysis']['family_detection']={'source':'REA-reviewed code combinations compiled into offline rules',
            'methods':['infection_code_section','xor32_nrv2e','encrypted_project_crc_and_loader_code','png_rc4_and_controller_code','content_proven_companion_correlation'],
            'target_execution':False,'filename_used_as_verdict':False,'maximum_input_bytes':16*1024*1024,
            'large_pe_method':'Full-file YARA-X plus read-only mapped PE structure and code ownership; source identity checked before and after',
            'streamed_bytes':getattr(self,'streamed_bytes',0),
            'streamed_pe_files':getattr(self,'engine_checks',{}).get('family_streamed_pe',0),
            'streamed_script_files':getattr(self,'engine_checks',{}).get('family_streamed_script',0),
            'large_file_incomplete':getattr(self,'engine_checks',{}).get('family_streamed_failed',0),
            'maximum_carrier_bytes':4*1024*1024,'size_limited_files':getattr(self,'engine_checks',{}).get('family_size_limited',0),
            'scope':'Known observed families; bounded decoding is not universal unpacking or a clean certification.'}
        json_save(self.run/'report.json',summary);return summary

def resolve_scan_scope(mode='internal',manual=None):
    from device_scope import resolve_scope
    try:return resolve_scope(powershell,mode,manual)
    except Exception as ex:
        try:
            from operation_capture import capture_preflight_failure
            capture_preflight_failure(ex,VERSION,mode,manual)
        except Exception:pass  # Reporting failure must not replace the discovery error.
        raise

def cli_main():
    if sys.argv[1:]==['--check-update']:
        from app_update import check_update
        print(json.dumps(check_update(VERSION),ensure_ascii=False));return 0
    if sys.argv[1:2] in (['--enroll-diagnostics'],['--submit-diagnostics'],['--diagnostics-status'],['--disable-diagnostics'],['--retry-diagnostics'],['--check-diagnostics-connection']):
        import diagnostic_client as diagnostics
        option=sys.argv[1]
        if option in ('--enroll-diagnostics','--submit-diagnostics'):
            if len(sys.argv)!=3:raise ValueError('请提供配置文件或扫描报告的完整路径。')
            result=diagnostics.enroll(sys.argv[2]) if option=='--enroll-diagnostics' else diagnostics.collect(sys.argv[2],manual=True)
        elif option=='--disable-diagnostics':
            diagnostics.disable();result={'enabled':False,'message':'自动提交已暂停，已有待提交队列保留。'}
        elif option=='--retry-diagnostics':result=diagnostics.retry(backfill=True)
        elif option=='--check-diagnostics-connection':result=diagnostics.check_connection()
        else:result=diagnostics.read_status()
        print(json.dumps(result,ensure_ascii=False));return 1 if result.get('error_type') or result.get('pending') else 0
    if len(sys.argv)==3 and sys.argv[1]=='--apply-update':
        from update_install import run_job
        return run_job(sys.argv[2])
    if sys.argv[1:]==['--office-analysis-worker']:
        from office_analysis import worker_main
        return worker_main()
    if getattr(sys,'frozen',False) and WINDOWLESS and sys.argv[1:]:
        from bundled_components import component_path
        result=subprocess.run([str(component_path('WormRecovery-CLI.exe')),*sys.argv[1:]],
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                              creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0),
                              env=__import__('engine_assets').subprocess_environment())
        for stream,data in ((sys.stdout,result.stdout),(sys.stderr,result.stderr)):
            if data:stream.write(data.decode('utf-8','replace'));stream.flush()
        return result.returncode
    parser=argparse.ArgumentParser(description='WormRecovery 文件安全检测与原位恢复')
    parser.add_argument('--scan',action='store_true',help='只扫描，不修复')
    parser.add_argument('--clean',action='store_true',help='扫描并修复确认感染项')
    parser.add_argument('--root',action='append',help='手动指定扫描位置；选择外接设备中的位置时包含同设备全部盘符')
    parser.add_argument('--scope',choices=['internal','removable'],default='internal',help='internal：本机全盘；removable：可移动设备')
    parser.add_argument('--workers',type=int,choices=range(1,9),metavar='1-8',help='只读文件扫描线程数；默认按物理磁盘自动选择')
    parser.add_argument('--report-dir',help='固定磁盘上的报告/隔离根目录')
    parser.add_argument('--force-close',action='store_true',default=True,help=argparse.SUPPRESS)
    parser.add_argument('--restore-history',action='store_true',default=True,help=argparse.SUPPRESS)
    parser.add_argument('--exclude',action='append',default=[],help='额外保护目录')
    args=parser.parse_args()
    if not args.scan and not args.clean:return gui_main()
    if args.clean and not ctypes.windll.shell32.IsUserAnAdmin():raise PermissionError('修复需要以管理员身份运行')
    scope=resolve_scan_scope(args.scope,args.root)
    cleaner=Cleaner(args.report_dir,force_close=True,protected=args.exclude,restore_history=True,external_volumes=scope['external_volumes'],excluded_roots=scope['excluded_roots'])
    cleaner.scope_summary=scope
    from operation_capture import execute
    def inspect_only():
        cleaner.contain(False);cleaner.registry(False);cleaner.system_persistence(False)
        if args.workers is None:cleaner.scan(scope['roots'])
        else:cleaner.scan(scope['roots'],workers=args.workers)
    execute(cleaner,'scan',inspect_only)
    if args.clean:
        def repair_and_verify():cleaner.repair();cleaner.verify()
        execute(cleaner,'repair',repair_and_verify)
    from diagnostic_client import retry
    retry(wait=True)
    failed=bool(cleaner.errors or cleaner.cancel.is_set() or cleaner.inspection_failed or any(x.get('status') in ('unverified','error','pending') for x in getattr(cleaner,'reparse_points',[])) or args.clean and not (cleaner.verification or {}).get('known_family_clear'))
    status=1 if failed else 2 if any(is_confirmed(x) for x in cleaner.findings) else 3 if any(x['kind'].startswith('review_') for x in cleaner.findings) else 0
    print(json.dumps({'report':str(cleaner.run/'report.json'),'files':cleaner.count,'findings':dict(collections.Counter(x['kind'] for x in cleaner.findings)),'errors':len(cleaner.errors),'skipped':len(cleaner.skipped),'exit_code':status},ensure_ascii=False))
    return status

def gui_main():
    from modern_ui import run
    run(sys.modules[__name__])

if __name__=='__main__':
    try:raise SystemExit(cli_main())
    except Exception as ex:
        if getattr(sys,'frozen',False) and WINDOWLESS:
            ctypes.windll.user32.MessageBoxW(None,str(ex),'蠕虫恢复工具：未完成',0x10)
        else:raise
