"""Full file rule scanning with read-only mapped PE ownership and identity checks.

Mappings supply bounded structural reads. No target is loaded or executed, no
permissions change, and Python never copies a complete large file into bytes.
"""
from __future__ import annotations
import hashlib
import mmap
import os
import stat

from windows_read import open_read, extended_path

MAX_FILE_BYTES=2*1024*1024*1024

class SourceChanged(ValueError):pass


def identity(info):
    # On Python/Windows, stat ctime can mean creation time while fstat ctime
    # means change time. Birth time is consistent across both interfaces.
    extra=getattr(info,'st_birthtime_ns',None) if os.name=='nt' else info.st_ctime_ns
    return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,extra)


def queued_identity_matches(queued,current):
    # Windows DirEntry.stat intentionally reports st_dev/st_ino as zero. The
    # opened handle and fresh path stat still require full identity equality;
    # the queue can bind only the fields it actually observed.
    queued_id=identity(queued);current_id=identity(current)
    return (queued_id[2:]==current_id[2:] and
            all(not queued_id[index] or queued_id[index]==current_id[index] for index in (0,1)))


def verify_identity(path,stream,expected,change_times=None):
    handle_stat=os.fstat(stream.fileno());path_stat=os.stat(extended_path(path))
    if identity(handle_stat)!=expected or identity(path_stat)!=expected:
        raise SourceChanged('检查期间文件身份或内容时间戳发生变化，请重新扫描。')
    observed=(handle_stat.st_ctime_ns,path_stat.st_ctime_ns)
    # Compare ctime only against the same interface's baseline, never across
    # stat/fstat on Windows. This also detects writes that restore mtime.
    if change_times is not None and change_times!=observed:
        raise SourceChanged('检查期间文件变更时间发生变化，请重新扫描。')
    return observed


def _base(kind):
    from local_rules import RULESET_VERSION
    return {'engine':'WormRecovery static family analysis','ruleset_version':RULESET_VERSION,
            'status':'incomplete','detections':[],'decodings':[],
            'target_execution':False,'name_used_for_verdict':False,
            'coverage':{'method':kind,'rule_scan':'not_started','mapped_pe':'not_applicable',
                        'source_identity':'unverified','file_bytes':None,'rule_scan_bytes':0}}


def _rules(path,timeout_seconds):
    from local_rules import scan_file
    result=scan_file(extended_path(path),timeout_seconds=timeout_seconds)
    if not isinstance(result,dict) or not isinstance(result.get('matches'),list):
        raise ValueError('完整文件规则扫描未返回有效完成结果。')
    return result


def _hash_mapping(mapping):
    digest=hashlib.sha256()
    # Only positive findings need a whole-file content pin. Views avoid one
    # Python bytes allocation proportional to a potentially multi-GB program.
    with memoryview(mapping) as view:
        for offset in range(0,len(view),1024*1024):
            with view[offset:offset+1024*1024] as chunk:digest.update(chunk)
    return digest.hexdigest()


def inspect_large_file(path,expected_stat=None):
    from family_analysis import PE,inspect_mapped_pe
    result=_base('whole_file_rules_and_read_only_mapped_pe');coverage=result['coverage']
    try:
        with open_read(path) as stream:
            before=os.fstat(stream.fileno());expected=identity(before)
            if not stat.S_ISREG(before.st_mode) or before.st_size<64:raise ValueError('大型程序不是有效的普通PE文件。')
            coverage.update(file_bytes=before.st_size,maximum_file_bytes=MAX_FILE_BYTES)
            if before.st_size>MAX_FILE_BYTES:raise ValueError('程序超过 2 GiB 完整规则检查上限。')
            if expected_stat is not None and not queued_identity_matches(expected_stat,before):
                raise SourceChanged('文件与扫描队列中的身份不一致，请重新扫描。')
            coverage['file_bytes']=before.st_size;change_times=verify_identity(path,stream,expected)
            with mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ) as mapping:
                coverage['mapped_pe']='incomplete'
                PE(mapping);coverage['mapped_pe']='complete'
                coverage['timeout_seconds']=min(180,3+(before.st_size+16*1024*1024-1)//(16*1024*1024))
                coverage['rule_scan']='incomplete'
                rules=_rules(path,coverage['timeout_seconds']);result['content_rules']=rules
                coverage.update(rule_scan='complete',rule_scan_bytes=before.st_size)
                verify_identity(path,stream,expected,change_times)
                analysis=inspect_mapped_pe(mapping,rules)
                if not isinstance(analysis,dict) or analysis.get('status') not in ('detected','incomplete','no_known_match'):
                    raise ValueError('映射程序家族检查未返回有效结果。')
                result.update(analysis);result['content_rules']=rules;result['coverage']=coverage
                if result['status']=='detected' and not result.get('source_sha256'):result['source_sha256']=_hash_mapping(mapping)
                verify_identity(path,stream,expected,change_times)
            verify_identity(path,stream,expected,change_times);coverage['source_identity']='stable'
    except Exception as error:
        result.pop('source_sha256',None);result['detections']=[];result['status']='incomplete'
        result['reason']='大型程序完整检查未完成：'+str(error)[:400]
        coverage['source_identity']='changed' if isinstance(error,SourceChanged) else 'unverified'
        result['error_type']=type(error).__name__
    return result


def inspect_large_script(path,expected_stat=None):
    result=_base('whole_file_script_rules');coverage=result['coverage']
    try:
        with open_read(path) as stream:
            before=os.fstat(stream.fileno());expected=identity(before)
            if not stat.S_ISREG(before.st_mode):raise ValueError('脚本不是普通文件。')
            coverage.update(file_bytes=before.st_size,maximum_file_bytes=MAX_FILE_BYTES)
            if before.st_size>MAX_FILE_BYTES:raise ValueError('脚本超过 2 GiB 完整规则检查上限。')
            if expected_stat is not None and not queued_identity_matches(expected_stat,before):
                raise SourceChanged('文件与扫描队列中的身份不一致，请重新扫描。')
            coverage['file_bytes']=before.st_size;change_times=verify_identity(path,stream,expected)
            coverage['timeout_seconds']=min(180,3+(before.st_size+16*1024*1024-1)//(16*1024*1024))
            coverage['rule_scan']='incomplete'
            rules=_rules(path,coverage['timeout_seconds']);result['content_rules']=rules
            coverage.update(rule_scan='complete',rule_scan_bytes=before.st_size)
            verify_identity(path,stream,expected,change_times);coverage['source_identity']='stable'
            if rules['matches']:
                result.update(status='incomplete',reason='脚本完整内容命中家族组合规则；代码归属和执行语义仍需独立核查。')
            else:result['status']='no_known_match'
    except Exception as error:
        result['status']='incomplete';result['reason']='大型脚本完整检查未完成：'+str(error)[:400]
        coverage['source_identity']='changed' if isinstance(error,SourceChanged) else 'unverified'
        result['error_type']=type(error).__name__
    return result
