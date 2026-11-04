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


def inspect_project(data):
    """Worker only. Extract code without executing Office or macro instructions."""
    if len(data) > MAX_PROJECT_BYTES:
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
                modules.append({'name': name, 'stream': stream})
                sources.append(code)
                low = code.casefold()
                if all(token in low for token in ('synaptics', '~$cache1', 'regkeysave', 'workbook_open')):
                    matches.append(name)
                elif any(line.strip() and not line.strip().casefold().startswith(
                        ('attribute ', 'option ', 'private sub', 'end sub', "'")) for line in code.splitlines()):
                    others.append(name)
            pcodedmp.processProject(parser, SimpleNamespace(disasmOnly=True, verbose=False), output_file=output)
        if errors.getvalue().strip():
            raise ValueError('宏编译代码解析未完成：' + errors.getvalue().strip()[:700])
        if not modules:
            raise ValueError('未能提取宏模块，不能将空结果判为安全。')
        source = '\n'.join(sources)
        pcode = output.getvalue()
        mr = MacroRaptor(source)
        mr.scan()
        indicators = []
        for keyword in ('Shell', 'CreateObject', 'RegWrite', 'RegKeySave', 'VBProject',
                        'VBComponents', 'SaveAs', 'Workbook_Open', 'Document_Open',
                        'URLDownloadToFile', 'AutoIt3ExecuteScript'):
            if re.search(r'\b' + re.escape(keyword) + r'\b', pcode, re.I):
                indicators.append(keyword)
        return {'modules': modules, 'family_modules': matches, 'other_modules': others,
                'pcode_status': 'instructions_read' if 'Line #' in pcode else 'no_instructions_returned',
                'pcode_family_match': all(token in pcode.casefold() for token in
                                         ('synaptics', '~$cache1', 'regkeysave', 'workbook_open')),
                'source_sha256': hashlib.sha256(source.encode('utf-8')).hexdigest(),
                'pcode_sha256': hashlib.sha256(pcode.encode('utf-8')).hexdigest(),
                'pcode_indicators': indicators, 'source_behavior_flags': mr.get_flags(),
                'source_behavior_suspicious': bool(mr.suspicious),
                'analysis_method': 'olevba + MacroRaptor + pcodedmp; offline static analysis',
                'analysis_limit': '源码与返回的编译指令仅作静态证据；未返回指令时不授权自动清理，未证明完整运行行为或所有威胁不存在。'}
    finally:
        parser.close()


def analyze_project(data, timeout=ANALYSIS_TIMEOUT):
    if len(data) > MAX_PROJECT_BYTES:
        raise ValueError('宏项目超过分析资源上限。')
    fingerprint = hashlib.sha256(data).hexdigest()
    if fingerprint in _CACHE:
        return copy.deepcopy(_CACHE[fingerprint])
    entry = pathlib.Path(__file__).with_name('worm_recovery.py')
    frozen = getattr(sys, 'frozen', False)
    executable = pathlib.Path(sys.executable)
    if frozen and not executable.name.casefold().endswith('-cli.exe'):
        candidate = executable.with_name('WormRecovery-Analysis.exe')
        if not candidate.is_file():
            raise ValueError('缺少离线宏分析组件 WormRecovery-Analysis.exe，请保留完整分发目录。')
        executable = candidate
    command = [str(executable)] if frozen else [sys.executable, str(entry)]
    command.append('--office-analysis-worker')
    if frozen and executable.name.casefold().endswith('-analysis.exe'):
        command = [str(executable)]
    result = subprocess.run(command, input=base64.b64encode(data), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode or len(result.stdout) > 1024 * 1024:
        raise ValueError('宏分析进程未正常完成：' + result.stderr.decode('utf-8', 'replace')[:350])
    try:
        response = json.loads(result.stdout.decode('utf-8'))
    except (ValueError, UnicodeError) as ex:
        raise ValueError('宏分析进程返回无效结果。') from ex
    if not response.get('ok'):
        raise ValueError(response.get('error', '宏分析失败。'))
    if len(_CACHE) >= 128:
        _CACHE.pop(next(iter(_CACHE)))
    _CACHE[fingerprint] = copy.deepcopy(response['result'])
    return response['result']


def worker_main():
    """Private stdin transport; no file path, command or executable is accepted."""
    try:
        encoded = sys.stdin.buffer.read((MAX_PROJECT_BYTES * 4 // 3) + 8)
        data = base64.b64decode(encoded, validate=True)
        response = {'ok': True, 'result': inspect_project(data)}
    except Exception as ex:
        response = {'ok': False, 'error': str(ex)[:1200]}
    sys.stdout.buffer.write(json.dumps(response, ensure_ascii=False).encode('utf-8'))
    sys.stdout.buffer.flush()
    return 0
