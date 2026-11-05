"""Bounded offline VBA source and P-code analysis in a separate process."""
from __future__ import annotations

import base64
import copy
import contextlib
import hashlib
import io
import json
import pathlib
import re
import subprocess
import sys
from types import SimpleNamespace

MAX_PROJECT_BYTES = 16 * 1024 * 1024
MAX_SOURCE_CHARS = 8 * 1024 * 1024
MAX_PCODE_CHARS = 4 * 1024 * 1024
ANALYSIS_TIMEOUT = 25
MAX_DOCUMENT_BYTES = 128 * 1024 * 1024
_CACHE = {}


class LimitedText(io.StringIO):
    def __init__(self, limit):
        super().__init__()
        self.limit = limit
        self.used = 0

    def write(self, value):
        self.used += len(value)
        if self.used > self.limit:
            raise ValueError('编译代码分析输出超过资源上限。')
        return super().write(value)


def inspect_project(data, full_document=False):
    """Worker only. Extract code without executing Office or macro instructions."""
    if len(data) > (MAX_DOCUMENT_BYTES if full_document else MAX_PROJECT_BYTES):
        raise ValueError('宏项目超过分析资源上限。')
    from oletools.olevba import VBA_Parser
    from oletools.mraptor import MacroRaptor
    from pcodedmp import pcodedmp

    parser = VBA_Parser('vbaProject.bin', data=data, disable_pcode=True)
    errors = LimitedText(65536)
    output = LimitedText(MAX_PCODE_CHARS)
    try:
        if parser.ole_file is None:
            raise ValueError('宏项目不是有效的 OLE 容器。')
        modules = []
        sources = []
        matches = []
        others = []
        count = 0
        # Some parsers catch exceptions and only log them; absent source or
        # diagnostics below must never become a successful empty analysis.
        with contextlib.redirect_stderr(errors):
            for _, stream, name, code in parser.extract_macros():
                count += len(code)
                if count > MAX_SOURCE_CHARS or len(modules) >= 512:
                    raise ValueError('宏源码超过分析资源上限。')
                modules.append({'name': name, 'stream': stream,'source_sha256':hashlib.sha256(code.encode('utf-8')).hexdigest()})
                sources.append(code)
                low = code.casefold()
                if all(token in low for token in ('synaptics', '~$cache1', 'regkeysave', 'workbook_open')):
                    matches.append(name)
                elif any(line.strip() and not line.strip().casefold().startswith(
                        ('attribute ', 'option ', 'private sub', 'end sub', "'")) for line in code.splitlines()):
                    others.append(name)
            from vba_inventory import inspect_inventory
            with contextlib.redirect_stderr(LimitedText(8192)):
                inventory=inspect_inventory(parser,modules)
            module_cache_absent=inventory.get('status')=='complete' and all(row['cache_bytes']==0 for row in inventory['modules'])
            if not module_cache_absent:
                pcodedmp.processProject(parser, SimpleNamespace(disasmOnly=True, verbose=False), output_file=output)
        if errors.getvalue().strip():
            raise ValueError('宏编译代码解析未完成：' + errors.getvalue().strip()[:700])
        if not modules:
            raise ValueError('未能提取宏模块，不能将空结果判为安全。')
        source = '\n'.join(sources)
        pcode = output.getvalue()
        from local_rules import scan_bytes
        rule_source = scan_bytes(source.encode('utf-8'))
        rule_pcode = scan_bytes(pcode.encode('utf-8'))
        mr = MacroRaptor(source)
        mr.scan()
        from macro_verdict import inspect_behavior
        behavior=inspect_behavior(source,pcode)
        indicators = []
        for keyword in ('Shell', 'CreateObject', 'RegWrite', 'RegKeySave', 'VBProject',
                        'VBComponents', 'SaveAs', 'Workbook_Open', 'Document_Open',
                        'URLDownloadToFile', 'AutoIt3ExecuteScript'):
            if re.search(r'\b' + re.escape(keyword) + r'\b', pcode, re.I):
                indicators.append(keyword)
        return {'modules': modules, 'family_modules': matches, 'other_modules': others,
                'pcode_status': 'cache_absent' if inventory.get('compiled_cache_absent') else 'no_module_cache' if module_cache_absent else 'instructions_read' if 'Line #' in pcode else 'no_instructions_returned',
                'module_inventory':inventory,
                'pcode_family_match': all(token in pcode.casefold() for token in
                                         ('synaptics', '~$cache1', 'regkeysave', 'workbook_open')),
                'source_sha256': hashlib.sha256(source.encode('utf-8')).hexdigest(),
                'pcode_sha256': hashlib.sha256(pcode.encode('utf-8')).hexdigest(),
                'pcode_indicators': indicators, 'source_behavior_flags': mr.get_flags(),
                'content_rules': {'source': rule_source, 'pcode': rule_pcode},
                'source_behavior_suspicious': bool(mr.suspicious),
                'behavior_analysis':behavior,
                'analysis_method': 'olevba + MacroRaptor + pcodedmp; offline static analysis',
                'analysis_limit': '源码与返回的编译指令仅作静态证据；未返回指令时不授权自动清理，未证明完整运行行为或所有威胁不存在。'}
    finally:
        parser.close()


def analyze_project(data, timeout=ANALYSIS_TIMEOUT):
    return _analyze_bytes(data, 'vba', timeout)


def analyze_legacy_document(data, timeout=ANALYSIS_TIMEOUT):
    return _analyze_bytes(data, 'legacy', timeout)


def _analyze_bytes(data, mode, timeout):
    if len(data) > (MAX_DOCUMENT_BYTES if mode == 'legacy' else MAX_PROJECT_BYTES):
        raise ValueError('宏项目超过分析资源上限。')
    fingerprint = (mode, hashlib.sha256(data).hexdigest())
    if fingerprint in _CACHE:
        return copy.deepcopy(_CACHE[fingerprint])
    entry = pathlib.Path(__file__).with_name('analysis_entry.py')
    frozen = getattr(sys, 'frozen', False)
    executable = pathlib.Path(sys.executable)
    if frozen:
        from bundled_components import component_path
        executable = component_path('WormRecovery-Analysis.exe')
    command = [str(executable)] if frozen else [sys.executable, str(entry)]
    command.append('--office-worker-server')
    from office_worker_transport import request, close
    raw, runtime = request(command, __import__('engine_assets').subprocess_environment(independent=frozen),
                           {'mode': mode, 'data': base64.b64encode(data).decode('ascii')}, timeout)
    try:
        response=decode_worker_result(SimpleNamespace(returncode=0,stdout=raw,stderr=b''),'宏分析',1024*1024)
    except Exception:
        close()
        raise
    response['result']['worker_runtime'] = runtime
    if len(_CACHE) >= 128:
        _CACHE.pop(next(iter(_CACHE)))
    _CACHE[fingerprint] = copy.deepcopy(response['result'])
    return response['result']


def decode_worker_result(result,label='离线解析',limit=16*1024*1024):
    """Check process completion before decoding JSON, retaining actual failures."""
    from powershell_output import error_text
    if result.returncode:
        detail=error_text(result.stderr or b'').strip()
        raise ValueError(label+'进程启动或执行失败，退出码 '+str(result.returncode)+'：'+(detail[:700] or '未返回错误说明。'))
    if len(result.stdout)>limit:raise ValueError(label+'结果超过资源上限。')
    if not result.stdout.strip():raise ValueError(label+'进程未返回结果：'+error_text(result.stderr or b'')[:500])
    try:response=json.loads(result.stdout.decode('utf-8-sig'))
    except (ValueError,UnicodeError) as ex:raise ValueError(label+'进程返回无效结果：'+error_text(result.stderr or b'')[:500]) from ex
    if not isinstance(response,dict) or not isinstance(response.get('ok'),bool):raise ValueError(label+'进程返回的数据结构无效。')
    if not response['ok']:
        error=ValueError(response.get('error') or label+'失败。')
        error.analysis_details=response.get('error_details',{})
        raise error
    if not isinstance(response.get('result'),dict):raise ValueError(label+'进程缺少分析结果。')
    return response


def _legacy_bytes(data):
    from oletools.olevba import VBA_Parser
    parser=VBA_Parser('legacy-document.ole',data=data,disable_pcode=True)
    try:
        has=parser.detect_vba_macros()
        from vba_inventory import inspect_legacy_workbook
        structure=inspect_legacy_workbook(parser.ole_file) if parser.ole_file else {'status':'unavailable'}
    finally:parser.close()
    if not has:return {'status':'clean','macro':False,'document_format':'ole'}
    analysis=inspect_project(data,full_document=True)
    return {'status':'review','macro':True,'document_format':'ole','macro_analysis':analysis,'legacy_structure':structure,
            'has_family_macro':bool(analysis.get('family_modules')),
            'other_modules':analysis.get('other_modules',[]),
            'reason':'旧版 Office 宏已完成源码、编译指令和内容特征检查。'}


def worker_server():
    """One bounded JSON line per request; parse bytes, never reopen an original."""
    import socket
    import traceback
    def denied(*args,**kwargs):raise PermissionError('离线文档分析禁止联网或启动外部程序。')
    class OfflineSocket(socket.socket):connect=denied;connect_ex=denied
    socket.socket=OfflineSocket;socket.create_connection=denied
    def audit(event,args):
        if event.startswith(('subprocess.','os.exec','os.spawn')) or event in ('os.system','socket.connect','socket.bind'):
            denied()
    sys.addaudithook(audit)
    maximum=MAX_DOCUMENT_BYTES*4//3+4096
    for _ in range(64):
        line=sys.stdin.buffer.readline(maximum+1)
        if not line:return 0
        if len(line)>maximum or not line.endswith(b'\n'):return 2
        diagnostics=LimitedText(65536)
        mode=None
        try:
            with contextlib.redirect_stdout(diagnostics),contextlib.redirect_stderr(diagnostics):
                request=json.loads(line)
                mode=request.get('mode')
                if mode not in ('vba','legacy'):raise ValueError('未知 Office 字节分析任务。')
                data=base64.b64decode(request['data'],validate=True)
                if len(data)>(MAX_DOCUMENT_BYTES if mode=='legacy' else MAX_PROJECT_BYTES):raise ValueError('文档超过分析上限。')
                result=_legacy_bytes(data) if mode=='legacy' else inspect_project(data)
                response={'ok':True,'result':result}
        except Exception as error:
            response={'ok':False,'error':str(error)[:1200],
                      'error_details':{'phase':'legacy_parser' if mode=='legacy' else 'vba_parser',
                        'exception_type':type(error).__name__,'winerror':getattr(error,'winerror',None),
                        'frames':[{'module':pathlib.Path(frame.filename).name,'function':frame.name,'line':frame.lineno}
                                  for frame in traceback.extract_tb(error.__traceback__)[-5:]]}}
        if diagnostics.getvalue():response['parser_diagnostics']=diagnostics.getvalue()[:4096]
        encoded=json.dumps(response,ensure_ascii=True).encode('ascii')
        if len(encoded)>1024*1024:encoded=b'{"ok":false,"error":"Office analysis result exceeds resource limit"}'
        sys.stdout.buffer.write(encoded+b'\n');sys.stdout.buffer.flush()
    return 0


def worker_main():
    """Private transport for VBA bytes or a selected static-parser task."""
    diagnostics = LimitedText(65536)
    try:
        encoded = sys.stdin.buffer.read((MAX_PROJECT_BYTES * 4 // 3) + 8)
        # Optional parsers print import notices. Keep stdout JSON-only for all
        # imports and parsing, including the VBA path that loads XLM support.
        with contextlib.redirect_stdout(diagnostics), contextlib.redirect_stderr(diagnostics):
            if encoded.startswith(b'{'):
                from secondary_analysis import worker_request
                response = {'ok': True, 'result': worker_request(json.loads(encoded.decode('utf-8')))}
            else:
                data = base64.b64decode(encoded, validate=True)
                response = {'ok': True, 'result': inspect_project(data)}
    except Exception as ex:
        response = {'ok': False, 'error': str(ex)[:1200]}
    if diagnostics.getvalue():
        response['parser_diagnostics'] = diagnostics.getvalue()[:4096]
    sys.stdout.buffer.write(json.dumps(response, ensure_ascii=False).encode('utf-8'))
    sys.stdout.buffer.flush()
    return 0
