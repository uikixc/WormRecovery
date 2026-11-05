"""Deterministic offline document decisions; unknowns never become safe by default."""
import ntpath
import re
from urllib.parse import unquote, urlsplit

VERSION='2026.11.05.2'


def local_reference(target,extensions):
    value=str(target)
    for _ in range(3):
        decoded=unquote(value)
        if decoded==value:break
        value=decoded
    if any(ord(c)<32 for c in value):return False
    if value.casefold().startswith('file:'):
        uri=urlsplit(value)
        if uri.netloc or uri.query or uri.fragment:return False
        value=uri.path.lstrip('/')
    value=value.replace('/','\\')
    if not re.match(r'^[A-Za-z]:\\',value) or ':' in value[2:] or value.startswith('\\'):return False
    if any(part=='..' for part in value.split('\\')):return False
    return ntpath.splitext(value)[1].casefold() in extensions


def assess_document(row):
    def result(classification,rule,reason,basis):
        return {'engine':'WormRecovery offline decision','version':VERSION,'classification':classification,
                'rule':rule,'reason':reason,'basis':basis,
                'scope':'仅判断当前文件与已检查活动内容的风险；外部目标未读取时不认证目标文件安全。'}
    if not row.get('kind','').startswith('review_'):
        return result('unchanged','preserve_existing_verdict','保留原检测结论。','不是未解决候选文件')
    evidence=row.get('secondary_analysis',{})
    if evidence.get('clamav',{}).get('status')=='detected':
        return result('detected','antivirus_detection','病毒引擎已检出，保留检出与恢复要求。','ClamAV detection')
    if row.get('analysis_error') or evidence.get('status')=='incomplete':
        return result('incomplete','analysis_incomplete','文件分析未完成，不能判定无威胁。','解析错误或引擎未完成')
    if row.get('kind')!='review_office':
        return result('unresolved','executable_candidate','脚本或程序候选保留其引擎判定，不使用文档资源规则。','仅对 Office 文档使用文档分类规则')
    if row.get('has_family_macro') or row.get('macro_analysis',{}).get('family_modules'):
        return result('suspicious','family_macro_evidence','存在家族宏证据，保留处置要求。','VBA 家族特征')
    behavior=row.get('macro_analysis',{}).get('behavior_analysis',{})
    if behavior.get('classification')=='suspicious':
        return result('suspicious','macro_behavior_combination','宏命中高风险行为组合：'+'、'.join(behavior.get('rules',[]))+'。',
                      '源码及可读编译指令中的行为组合；保留原件，禁止据此删除全部宏')
    rules=evidence.get('yara_x',{})
    if evidence.get('clamav',{}).get('status')!='no_match' or rules.get('matches')!=[]:
        return result('unresolved','insufficient_engine_evidence','现有证据不足以自动降级。','缺少完成的病毒检查或内容规则命中')
    from office_triage import installation_component, REVIEWED_COMPONENTS
    known=REVIEWED_COMPONENTS.get(row.get('analysis_sha256'))
    if known and installation_component(row['path']) and ntpath.basename(row['path']).casefold()==known[0].casefold() and not row.get('active_content_unresolved'):
        return result('informational','reviewed_office_component',known[1]+'：完整文件与已核对组件一致，未检出已知威胁。',
                      '安装目录结构、文件名、完整 SHA-256、当前病毒检查及内容规则同时匹配')
    if row.get('parser_recovery',{}).get('status')=='completed' and row.get('status')=='clean' and row.get('macro') is False and not row.get('structural_evidence') and evidence.get('office_parser',{}).get('status')=='analyzed':
        return result('informational','recovered_document_analysis','文档重试分析完成，未发现宏或已检查类型的活动内容，当前病毒库与内容规则未检出威胁。',
                      '完整哈希校验的只读副本、文档解析成功、当前病毒检查及内容规则均完成')
    structures=row.get('structural_evidence',[])
    if row.get('macro') is not False or row.get('macro_analysis') or row.get('other_modules') or not structures or evidence.get('office_parser',{}).get('status')!='analyzed':
        return result('unresolved','unresolved_executable_content','宏或文档结构尚无足够证据，保留风险状态。','不使用文件名或杀毒未命中作为单独白名单')
    ordinary=[]
    for item in structures:
        kind=item.get('kind');relation=item.get('relationship_type','').casefold()
        if item.get('target_truncated'):
            return result('unresolved','truncated_target','目标地址超过记录上限，不能自动归类。','地址记录不完整')
        if kind=='external_relationship' and relation=='image' and local_reference(item.get('target'),{'.png','.jpg','.jpeg','.gif','.bmp','.tif','.tiff','.webp'}):
            ordinary.append('本地图片引用')
        elif kind=='external_relationship' and relation in ('externallinkpath','xlpathmissing') and local_reference(item.get('target'),{'.xls','.xlsx'}):
            ordinary.append('本地工作簿数据链接')
        elif kind in ('external_data','external_book_link'):
            member=item.get('member','')
            owner=member.replace('/_rels/','/')[:-5] if member.endswith('.rels') else member
            if not any(s.get('kind')=='external_book_link' and s.get('member')==owner for s in structures):
                return result('unresolved','external_data_needs_typed_analysis','需要检查外部数据连接的具体类型。','缺少 externalBook / DDE / OLE 分类')
        else:
            return result('unresolved','active_content_needs_analysis','存在需独立检查的宏、对象、模板、远程目标或异常连接。','活动内容不属于可自动归类的本地资源引用')
    if not ordinary:return result('unresolved','missing_resource_evidence','资源引用证据不完整。','未确认完整关系类型')
    return result('informational','ordinary_local_resource_links',
                  '、'.join(dict.fromkeys(ordinary))+'；当前文档未检出已知威胁，无需清理这些引用。',
                  '无宏、Office 结构解析完成、目标为受限的本地资源路径、病毒检查完成且无内容规则命中')
