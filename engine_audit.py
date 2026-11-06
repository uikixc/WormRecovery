"""Report actual per-file engine evidence separately from installed assets."""
def build_audit(first_pass,dispatch,findings):
    engines={name:{'first_pass_files':int(first_pass.get(name,0)),
                   'second_pass_results':{},'reused_results':0,'status':'not_invoked'}
             for name in ('file_header','family_static','family_size_limited','family_streamed_pe','family_streamed_script','family_streamed_failed','yara_x','vba_source_analysis','vba_pcode','clamav','capa','rea','autoit','xlm')}
    for row in findings:
        evidence=row.get('secondary_analysis',{})
        for name,engine in engines.items():
            result=evidence.get(name)
            if isinstance(result,dict):
                status=result.get('status','rules_checked' if name=='yara_x' else 'unknown')
                counts=engine['second_pass_results'];counts[status]=counts.get(status,0)+1
                if evidence.get('reuse',{}).get('status')=='reused':engine['reused_results']+=1
    for engine in engines.values():
        counts=engine['second_pass_results']
        if counts.get('incomplete') or counts.get('unsupported') or counts.get('unknown'):
            engine['status']='not_finished'
        elif engine['first_pass_files'] or counts:
            engine['status']='not_requested' if set(counts)=={'not_requested'} else 'not_needed' if set(counts)=={'no_content'} and not engine['first_pass_files'] else 'executed'
    return {'dispatch':dict(dispatch),'engine_usage':engines,
            'count_basis':'Files checked or with retained results; cached identical VBA projects may reuse analysis. Installed versions do not prove execution.',
            'rea_scope':'Static PE import inspection; Ghidra decompilation and runtime execution are not bundled.'}


def dispatch_message(dispatch):
    status=dispatch.get('status')
    if status=='not_needed':return '二次引擎未调用：本次没有未决候选文件。'
    if status=='dispatched':return '二次引擎已调度：%s 个候选文件，具体结果请查看文件详情。'%dispatch.get('candidates',0)
    if status=='cancelled':return '二次引擎未完成：用户已停止。'
    return '二次引擎尚未调度。'
