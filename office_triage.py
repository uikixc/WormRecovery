"""Content-pinned Office component assessments and explicit user actions."""
import hashlib
import ntpath
import os

# Exact local files reviewed through extracted VBA and available compiled P-code.
# These are assessment pins, not Microsoft signature or universal trust claims.
REVIEWED_COMPONENTS={
    'fe86c45ec48b3e84b273da869de229a6bad65a44750e77a727c68d91cac2ed6b':('EUROTOOL.XLAM','欧元转换加载项安装缓存'),
    'f45117f0990e71bc2dd8de70e5e9c8d1dcc5d250197770c25b84dbf9821db74b':('SOLVSAMP.XLS','规划求解示例工作簿'),
    '5d224a37b3aba8c8b8cb84b5f2e7d150b330e07e5a07fe8bc4d53b9c28b97969':('EUROTOOL.XLAM','欧元转换加载项'),
    'e036ae99fb40457b5c02b51151f3e9baf68688892a84c036572a30af0b0ac420':('SOLVER.XLAM','规划求解加载项'),
    '50df8d0ab675e21193cc9b79ea30c141f3621c7c889f01d5bb248da55de15ca8':('ATPVBACS.XLAM','分析工具库中文宏接口'),
    'ab00ef62a15be0f6aba0e2eb77c4702f1056391019c4ab419e4c30b6b3b3643f':('ATPVBAEN.XLAM','分析工具库英文宏接口'),
    'e0192690cb368c75e961ab85a322ac0f96881b0245e1fa93161657e3af38f298':('FUNCRES.XLAM','分析工具库函数资源'),
    'c7d1c345f51acd2ecc5c9b7fad7497586768cb003e49918b5bf7e7a4e2f57ebc':('PROCDB.XLAM','分析工具库过程资源'),
}

def is_confirmed(record):
    return not record['kind'].startswith(('review_','info_'))

def installation_component(path):
    path=ntpath.normcase(ntpath.abspath(str(path)))
    for env,default in (('ProgramFiles','C:/Program Files'),('ProgramFiles(x86)','C:/Program Files (x86)')):
        root=ntpath.normcase(ntpath.join(os.environ.get(env,default),'Microsoft Office'))
        if path.startswith(root+'\\'):
            tail=path[len(root)+1:].split('\\')
            if tail and tail[0]=='root':tail=tail[1:]
            if len(tail)>=3 and tail[0].startswith('office') and tail[1] in ('library','samples'):return True
    cache=ntpath.normcase(ntpath.join(os.environ.get('WINDIR','C:/Windows'),'Installer','$PatchCache$','Managed'))
    return path.startswith(cache+'\\')

def content_hash(path):
    digest=hashlib.sha256()
    with open(path,'rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
    return digest.hexdigest()

def assess_office(path,result):
    result=dict(result)
    if result.get('status')!='review':return result
    if not result.get('analysis_error') and not result.get('has_family_macro') and not result.get('active_content_unresolved') and installation_component(path):
        digest=content_hash(path);known=REVIEWED_COMPONENTS.get(digest)
        if known and ntpath.basename(str(path)).casefold()==known[0].casefold():
            result.update(status='info',component=known[1],file_sha256=digest,assessment='reviewed_office_component',
                reason='已核对的 Office 组件；未发现本次蠕虫特征。',
                action='保留，无需删除、转换格式或移除宏。',
                assessment_basis='文件完整 SHA-256 与已静态核对的组件一致；已检查 VBA 源码和可读编译代码。',
                assessment_limit='仅针对本次蠕虫静态核对，不代表 Microsoft 签名认证或对所有威胁的安全保证。')
            return result
    if result.get('analysis_error'):
        result.update(assessment='analysis_incomplete',action='暂勿打开或启用宏；保留原件，查看解析错误并使用已更新的安全软件检查。')
    elif result.get('active_content_unresolved'):
        names={'xlm_macro_sheet':'Excel 4.0 宏表','auto_macro_name':'自动运行宏名称','embedded_object':'嵌入对象','activex':'ActiveX 控件','external_data':'外部数据连接','external_relationship':'外部内容关系','dde_field':'DDE 字段'}
        types=list(dict.fromkeys(names.get(row['kind'],row['kind']) for row in result.get('structural_evidence',[])))
        result.update(assessment='active_content_unresolved',reason='检测到'+ '、'.join(types)+'；存在此类内容不等于已感染，但当前检查不能证明其安全。',action='保留原件，暂勿启用宏、外部内容或嵌入对象；需要针对列出的活动内容进一步检查，不自动删除或转换格式。')
    elif result.get('has_family_macro'):
        result.update(assessment='mixed_family_macro',action='发现家族宏与其他内容混合，暂勿打开或启用宏；保留原件并交由技术人员分析，不能直接删除全部宏。')
    else:
        result.update(assessment='unrecognized_macro',action='未确认感染，保留文件并保持宏禁用；不要直接删除或批量转换。可使用已更新的安全软件复核。')
        if result.get('other_modules') is not None:
            result['reason']='含宏项目，未匹配本次蠕虫；文件来源与宏用途尚未验证。'
    return result
