"""Exact observed companions, separately approved from confirmed malware.

Co-observation is not proof of execution or of a loader-to-carrier code edge.
Only the known host's imported DLL lookup uses a name. Nothing is loaded.
"""
import hashlib
import json
import os


def group_id(members):
    pins=sorted((os.path.normcase(os.path.abspath(row['path'])),row['sha256']) for row in members)
    return hashlib.sha256(json.dumps(pins,separators=(',',':')).encode()).hexdigest()


def correlate(findings,observations):
    groups={}
    for row in findings:
        analysis=row.get('family_analysis') or {}
        signatures={hit.get('signature') for hit in analysis.get('identifications',[])}
        role=('observed_loader' if 'WR_PNG_Tail_Observed_Loader' in signatures else
              'packed_carrier' if 'WR_PNG_Tail_Packed_Companion' in signatures and any(
                  d.get('method')=='png_iend_incrementing_xor' for d in analysis.get('decodings',[])) else None)
        if role and row.get('sha256'):
            groups.setdefault(os.path.normcase(os.path.dirname(row['path'])),[]).append({
                'path':row['path'],'sha256':row['sha256'],'role':role})
    output=[]
    for directory,members in groups.items():
        if {row['role'] for row in members}!={'observed_loader','packed_carrier'}:continue
        # A signed host is included only beside the exact DLL it imports.
        from png_tail_analysis import HOST_SHA256
        if any(os.path.basename(row['path']).casefold()=='xpsplog.dll' for row in members if row['role']=='observed_loader'):
            members += [{'path':row['path'],'sha256':row['sha256'],'role':'signed_host'} for row in observations
                        if row.get('role')=='observed_png_tail_host' and row.get('sha256')==HOST_SHA256
                        and os.path.normcase(os.path.dirname(row['path']))==directory]
        unique={os.path.normcase(row['path']):row for row in members}
        members=sorted(unique.values(),key=lambda row:os.path.normcase(row['path']))
        identity=group_id(members)
        for member in members:
            output.append({'kind':'review_deployment','path':member['path'],'sha256':member['sha256'],
                'assessment':'observed_deployment_requires_explicit_approval','deployment_group':identity,
                'deployment_role':member['role'],'deployment_members':members,
                'reason':'已知图片载荷与已知打包DLL组成原观察部署；宿主按精确内容及实际DLL导入关系列入。组件独立恶意行为及运行状态未全部证实。',
                'action':'整组风险未解除；在处理确认框逐项列出，只有明确选择处理关联部署后才删除这些精确内容文件。无关文件不处理。',
                'target_execution':False,'automatic_cleanup':False})
    return output


def groups(findings):
    return {row['deployment_group']:row['deployment_members'] for row in findings
            if row.get('kind')=='review_deployment' and row.get('deployment_group')}
