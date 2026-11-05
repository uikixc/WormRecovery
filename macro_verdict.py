"""Conservative static VBA behavior combinations, with no macro execution."""
import ast
import operator
import re

OPERATORS={ast.Add:operator.add,ast.Sub:operator.sub,ast.BitXor:operator.xor}


def constant_integer(text):
    if len(text)>80:raise ValueError('constant too long')
    tree=ast.parse(text,mode='eval')
    def number(node,depth=0):
        if depth>8:raise ValueError('expression too deep')
        if isinstance(node,ast.Constant) and type(node.value) is int and abs(node.value)<1000000:return node.value
        if isinstance(node,ast.BinOp) and type(node.op) in OPERATORS:
            value=OPERATORS[type(node.op)](number(node.left,depth+1),number(node.right,depth+1))
            if abs(value)<1000000:return value
        raise ValueError('unsupported constant')
    return number(tree.body)


def inspect_behavior(source,pcode=''):
    text=source[:8*1024*1024]
    def character(match):
        try:return '"'+chr(constant_integer(match.group(1))%65536)+'"'
        except (ValueError,SyntaxError,OverflowError):return match[0]
    text=re.sub(r'\bChrW?\s*\(([^()]{1,80})\)',character,text,flags=re.I)
    # Join literal fragments only; this does not evaluate identifiers or calls.
    for _ in range(5):
        joined=re.sub(r'"([^"\r\n]*)"\s*&\s*"([^"\r\n]*)"',lambda m:'"'+m[1]+m[2]+'"',text)
        if joined==text:break
        text=joined
    low=(text+'\n'+pcode[:4*1024*1024]).casefold()
    tests={
        'automatic_entry':r'\b(?:workbook_open|document_open|auto_open|autoopen|documentopen)\b',
        'download':r'\b(?:urldownloadtofile|xmlhttp|winhttp|downloadfile|downloadstring)\b',
        'execute':r'\b(?:shell|shellexecute|wscript\.shell|powershell|cmd\.exe)\b',
        'vba_project_modification':r'\b(?:vbproject|vbcomponents|codemodule)\b',
        'code_insertion':r'\b(?:addfromstring|addfromfile|insertlines|deletelines|import)\b',
        'document_write':r'\b(?:saveas|savecopyas)\b',
        'persistence':r'currentversion\\run|startup|xlstart|\bregwrite\b',
        'encoded_command':r'(?:powershell|pwsh)[^\r\n]{0,180}-(?:enc(?:odedcommand)?|e)\s+[a-z0-9+/=]{24,}',
    }
    signals=[name for name,pattern in tests.items() if re.search(pattern,low,re.I)]
    present=set(signals);rules=[]
    if {'automatic_entry','download','execute'}<=present:rules.append('autorun_download_execute')
    if {'automatic_entry','vba_project_modification','code_insertion','document_write'}<=present:rules.append('autorun_vba_replication')
    if {'execute','persistence'}<=present:rules.append('execution_with_persistence')
    if 'encoded_command' in present:rules.append('encoded_powershell_command')
    return {'engine':'WormRecovery VBA behavior','version':'2026.11.05.1','signals':signals,'rules':rules,
            'classification':'suspicious' if rules else 'no_high_risk_combination',
            'scope':'静态代码组合证据；不执行宏、不把未命中视为安全、不授权删除整份文档。'}
