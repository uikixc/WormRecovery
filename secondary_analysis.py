"""Offline second-opinion engines for unresolved files; no cleanup authority."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from engine_assets import engine_root, manifest, subprocess_environment
from engine_process import run as run_engine

MAX_INPUT = 128 * 1024 * 1024
_verified_tools = {}


def _tool(relative):
    root = engine_root()
    path = root / relative
    record = manifest().get('files', {}).get(relative)
    if not path.is_file() or not record:
        raise FileNotFoundError('缺少已固定版本的离线分析组件：' + relative)
    stat = path.stat()
    identity = (str(path), stat.st_size, stat.st_mtime_ns, record['sha256'])
    if identity in _verified_tools:
        return path
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if digest != record['sha256']:
        raise ValueError('离线分析组件完整性校验失败：' + relative)
    _verified_tools[identity] = True
    return path


def _json_command(command, timeout=45):
    result = run_engine([str(x) for x in command], timeout=timeout, env=subprocess_environment())
    if result.returncode or len(result.stdout) > 16 * 1024 * 1024:
        raise ValueError('分析引擎未完成：' + result.stderr.decode('utf-8', 'replace')[-700:])
    return json.loads(result.stdout.decode('utf-8-sig'))


def clam_batch(paths, work, timeout=180, cancel=None):
    """One database load for the whole batch, on private immutable snapshots."""
    exe = _tool('clamav/clamscan.exe')
    database = engine_root() / 'clamdb'
    if not all((database / name).is_file() for name in ('main.cvd', 'daily.cvd', 'bytecode.cvd')):
        raise FileNotFoundError('离线病毒库不完整，不能完成通用病毒检查。')
    for name in ('main.cvd', 'daily.cvd', 'bytecode.cvd'):
        _tool('clamdb/' + name)
    filelist = work / 'clam-file-list.txt'
    filelist.write_text(''.join(str(p) + '\n' for p in paths), encoding='utf-8')
    output = work / 'clam-output.txt'
    command = [str(exe), '--database=' + str(database), '--file-list=' + str(filelist),
        '--stdout', '--no-summary', '--alert-exceeds-max=yes', '--max-scantime=20000',
        '--max-filesize=128M', '--max-scansize=256M', '--max-recursion=12',
        '--bytecode-timeout=5000', '--tempdir=' + str(work)]
    with output.open('wb') as stream:
        result = run_engine(command, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout, cancel=cancel)
    if result.returncode not in (0, 1):
        raise ValueError('ClamAV 未完成，退出码 ' + str(result.returncode) + '：' + output.read_text(encoding='utf-8', errors='replace')[-900:])
    if output.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('ClamAV 输出超过资源上限。')
    text = output.read_text(encoding='utf-8', errors='replace')
    rows = {}
    for path in paths:
        prefix = str(path) + ': '
        messages = [line[len(prefix):] for line in text.splitlines() if line.startswith(prefix)]
        detections = [line[:-6] for line in messages if line.endswith(' FOUND')]
        incomplete = [line for line in messages if 'ERROR' in line or 'Heuristics.Limits.Exceeded' in line]
        if incomplete or not messages:
            rows[str(path)] = {'status': 'incomplete', 'detections': detections,
                'reason': '; '.join(incomplete) or '引擎未返回该文件的独立结果。'}
        elif detections:
            rows[str(path)] = {'status': 'detected', 'detections': detections}
        elif 'OK' in messages:
            rows[str(path)] = {'status': 'no_match', 'detections': []}
        else:
            rows[str(path)] = {'status': 'incomplete', 'reason': '; '.join(messages)}
    dbinfo = {}
    for name in ('main.cvd', 'daily.cvd', 'bytecode.cvd'):
        with (database / name).open('rb') as stream:
            header = stream.read(512).decode('ascii', 'replace').strip()
        fields = header.split(':')
        dbinfo[name] = {'build': fields[1] if len(fields) > 1 else '',
                        'version': fields[2] if len(fields) > 2 else '',
                        'signatures': fields[3] if len(fields) > 3 else ''}
    return rows, dbinfo


def worker_request(request):
    """Selected parsers only; no specimen is launched or sent to a server."""
    mode = request.get('mode')
    if mode not in ('autoit', 'xlm'):
        raise ValueError('未知离线分析任务。')
    path = Path(request['path'])
    if not path.is_file() or path.stat().st_size > MAX_INPUT:
        raise ValueError('分析副本缺失或超过大小限制。')
    from local_rules import scan_bytes
    # These parsers require no network. Refuse accidental networking in worker.
    def deny_network(*args, **kwargs):
        raise PermissionError('离线分析进程禁止网络访问。')
    class OfflineSocket(socket.socket):
        connect = deny_network
        connect_ex = deny_network
    socket.socket = OfflineSocket
    socket.create_connection = deny_network
    def parser_audit(event, arguments):
        if event.startswith(('subprocess.', 'os.exec', 'os.spawn')) or event in ('os.system', 'socket.connect', 'socket.bind'):
            raise PermissionError('离线解析任务禁止启动外部程序或建立网络连接。')
    sys.addaudithook(parser_audit)
    if mode == 'autoit':
        from autoit_ripper import extract
        extracted = extract(path.read_bytes())
        if not extracted:
            return {'status': 'unsupported', 'reason': '当前 AutoIt 提取器未识别此脚本格式。'}
        if len(extracted) > 1000 or sum(len(data) for _, data in extracted) > 32 * 1024 * 1024:
            raise ValueError('AutoIt 提取结果超过资源上限。')
        return {'status': 'analyzed', 'engine': 'AutoIt-Ripper', 'members': [
            {'name': name[:300], 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
             'rules': scan_bytes(data)} for name, data in extracted]}
    # Suppress third-party import banners on the private JSON transport.
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        from XLMMacroDeobfuscator.deobfuscator import process_file
        extracted = process_file(file=str(path), noninteractive=True, extract_only=True,
            return_deobfuscated=True, with_ms_excel=False, start_with_shell=False,
            silent=True, timeout=8)
        # Extraction feeds the rules even if emulation later cannot cover a path.
        deobfuscated = process_file(file=str(path), noninteractive=True, extract_only=False,
            return_deobfuscated=True, with_ms_excel=False, start_with_shell=False,
            silent=True, timeout=8)
    text = '\n'.join(map(str, extracted or []))
    interpreted = '\n'.join(map(str, deobfuscated or []))
    if len(text) + len(interpreted) > 4 * 1024 * 1024:
        raise ValueError('XLM 分析输出超过资源上限。')
    actions = sorted(set(re.findall(r'\b(?:EXEC|CALL|REGISTER|RUN|FOPEN|FWRITE|FORMULA|HALT|RETURN)\s*\(', text + '\n' + interpreted, re.I)))
    complete = bool(extracted) and bool(deobfuscated) and not re.search(r'NOT.?IMPLEMENTED|PARTIAL|ERROR|UNKNOWN', interpreted, re.I)
    return {'status': 'analyzed' if complete else 'incomplete', 'engine': 'XLMMacroDeobfuscator',
            'extracted_records': len(extracted or []), 'emulated_records': len(deobfuscated or []),
            'actions': actions, 'rules': scan_bytes((text + '\n' + interpreted).encode('utf-8')),
            'reason': None if complete else '部分路径未模拟完成、缺少入口或包含未解析指令。',
            'coverage': 'bounded emulation; unsupported paths and unknown values are not proven safe'}


def parser_request(mode, path, timeout=25):
    frozen = getattr(sys, 'frozen', False)
    if frozen:
        from bundled_components import component_path
        command = [str(component_path('WormRecovery-Analysis.exe'))]
    else:
        command = [sys.executable, str(Path(__file__).with_name('analysis_entry.py'))]
    result = run_engine(command, input=json.dumps({'mode': mode, 'path': str(path)}).encode('utf-8'),
        timeout=timeout, env=subprocess_environment())
    response = json.loads(result.stdout.decode('utf-8'))
    if result.returncode or not response.get('ok'):
        raise ValueError(response.get('error', '离线解析进程未完成。'))
    return response['result']


def pe_second_opinion(path):
    """Capabilities and declarations are evidence, not maliciousness verdicts."""
    output = {}
    try:
        executable = _tool('capa/capa.exe')
        document = _json_command([executable, '-j', str(path)], timeout=25)
        coverage = {'backend': 'auto', 'function_analysis': True}
        output['capa'] = {'status': 'analyzed', 'capabilities': list(document.get('rules', {}))[:120], 'coverage': coverage}
    except Exception as ex:
        output['capa'] = {'status': 'incomplete', 'reason': str(ex)[:700]}
    try:
        node = _tool('rea/node.exe')
        entry = _tool('rea/package/scripts/rea.mjs')
        document = _json_command([node, entry, 'inspect-pe-imports', path, '--format', 'json'], timeout=25)
        result = document.get('normalized_result', {})
        output['rea'] = {'status': 'analyzed', 'evidence_id': document.get('evidence_id'),
            'coverage': result.get('coverage'), 'imphash': result.get('imphash'),
            'imports': [{'dll': row.get('name'), 'functions': [x.get('name') for x in row.get('functions', [])][:150]}
                        for row in result.get('imports', [])],
            'scope': 'REA static PE import analysis; Ghidra decompilation is not bundled'}
    except Exception as ex:
        output['rea'] = {'status': 'incomplete', 'reason': str(ex)[:700]}
    return output


def enrich_reviews(cleaner):
    candidates = [row for row in cleaner.findings if row.get('kind', '').startswith('review_')]
    if not candidates or cleaner.cancel.is_set():
        return
    cleaner.emit('正在执行离线多引擎复核：' + str(len(candidates)) + ' 项。')
    with tempfile.TemporaryDirectory(prefix='engine-review-', dir=cleaner.run) as temp:
        work = Path(temp)
        pairs = []
        for index, row in enumerate(candidates):
            if cleaner.cancel.is_set():
                break
            path = Path(row['path'])
            try:
                cleaner.policy.check(path)
                if cleaner.protected_path(path):
                    raise PermissionError('该位置受保护，不进入外部分析引擎。')
                if path.stat().st_size > MAX_INPUT:
                    raise ValueError('文件超过多引擎复核大小上限。')
                before = path.stat()
                snapshot = work / ('item-%06d' % index + path.suffix)
                shutil.copyfile(path, snapshot)
                digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
                with path.open('rb') as stream:
                    original_digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                if digest != original_digest or path.stat().st_mtime_ns != before.st_mtime_ns:
                    raise ValueError('准备分析时文件发生变化。')
                row['analysis_sha256'] = digest
                pairs.append((row, snapshot))
            except Exception as ex:
                row['secondary_analysis'] = {'status': 'incomplete', 'reason': str(ex)}
                cleaner.inspection_failed = True
                cleaner.error(path, ex)
        if not pairs:
            return
        try:
            clam, database = clam_batch([snapshot for _, snapshot in pairs], work, cancel=cleaner.cancel)
        except Exception as ex:
            clam, database = {}, {}
            cleaner.inspection_failed = True
            cleaner.error('ClamAV', ex)
        for row, snapshot in pairs:
            if cleaner.cancel.is_set():
                break
            cleaner.emit('正在复核：' + str(row['path']))
            evidence = {'clamav': clam.get(str(snapshot), {'status': 'incomplete'}), 'database': database}
            try:
                evidence['yara_x'] = __import__('local_rules').scan_bytes(snapshot.read_bytes())
            except Exception as ex:
                evidence['yara_x'] = {'status': 'incomplete', 'reason': str(ex)[:700]}
            if row.get('kind') == 'review_autoit':
                try:
                    evidence['autoit'] = parser_request('autoit', snapshot)
                except Exception as ex:
                    evidence['autoit'] = {'status': 'incomplete', 'reason': str(ex)[:700]}
            kinds = {x['kind'] for x in row.get('structural_evidence', [])}
            if kinds & {'xlm_macro_sheet', 'auto_macro_name'}:
                try:
                    evidence['xlm'] = parser_request('xlm', snapshot)
                except Exception as ex:
                    evidence['xlm'] = {'status': 'incomplete', 'reason': str(ex)[:700]}
            with snapshot.open('rb') as stream:
                is_pe = stream.read(2) == b'MZ'
            if is_pe:
                evidence.update(pe_second_opinion(snapshot))
            detected = evidence['clamav'].get('status') == 'detected'
            rule_hits = evidence['yara_x'].get('matches', [])
            failures = [name for name, value in evidence.items() if isinstance(value, dict) and value.get('status') in ('incomplete', 'unsupported')]
            evidence['status'] = 'detected' if detected else 'incomplete' if failures else 'suspicious' if rule_hits else 'no_known_match'
            row['secondary_analysis'] = evidence
            if detected:
                row['assessment'] = 'engine_detected_requires_recovery'
                row['reason'] = '离线 ClamAV 检出：' + '、'.join(evidence['clamav'].get('detections', []))
                row['action'] = '已确认有引擎检出，需要结合感染结构恢复；当前文件保留原件，不以整份删除代替内容恢复。'
            elif rule_hits:
                row['reason'] = '离线内容规则命中：' + '、'.join(rule_hits) + '；需结合代码及文件关联判断。'
            else:
                row['reason'] = row.get('reason', '检测到尚未认证的活动内容。') + '；已完成的离线引擎未匹配已知威胁，未知内容的用途仍未认证。'
            if failures:
                row['analysis_incomplete_engines'] = failures
                cleaner.inspection_failed = True
            cleaner.log('secondary_analysis', path=row['path'], sha256=row['analysis_sha256'], result=evidence)
