"""Enumerate persistence before selecting content-confirmed worm targets."""
from __future__ import annotations

import base64
import json

INVENTORY_SCRIPT = r'''
$ErrorActionPreference='Stop';
function Get-ConsumerReference($item){
  if($null -eq $item){return ''};
  if($item -is [string]){return $item};
  return ([string]$item.CimClass.CimClassName)+'.Name="'+$item.Name.Replace('\','\\').Replace('"','\"')+'"'
};
$tasks=@(foreach($t in Get-ScheduledTask){foreach($a in $t.Actions){
  if($a.Execute){@{name=$t.TaskName;path=$t.TaskPath;execute=$a.Execute;arguments=$a.Arguments;working_directory=$a.WorkingDirectory;xml=(Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath)}}
}});
$services=@(Get-CimInstance Win32_Service | Select-Object Name,PathName,State,StartMode,StartName,ServiceType);
$commands=@(Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | ForEach-Object {
  @{class='CommandLineEventConsumer';Name=$_.Name;command=($_.ExecutablePath+' '+$_.CommandLineTemplate);object_path=(Get-ConsumerReference $_)}
});
$scripts=@(Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer | ForEach-Object {
  @{class='ActiveScriptEventConsumer';Name=$_.Name;command=$_.ScriptFileName;script_text=$_.ScriptText;object_path=(Get-ConsumerReference $_)}
});
$filters=@(Get-CimInstance -Namespace root/subscription -ClassName __EventFilter | Select-Object Name,Query,EventNamespace);
$bindings=@(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | ForEach-Object {
  @{consumer=(Get-ConsumerReference $_.Consumer);filter=(Get-ConsumerReference $_.Filter)}
});
@{tasks=$tasks;services=$services;wmi=@($commands)+@($scripts);filters=$filters;bindings=$bindings}|ConvertTo-Json -Depth 8 -Compress
'''


def rows(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def select_confirmed(inventory, confirm):
    """Names do not authorize mutation; the target must pass content checks."""
    if not isinstance(inventory, dict):
        raise ValueError('持久化枚举结果无效。')
    selected = {'tasks': [], 'services': [], 'wmi': [],
                'inventory_counts': {key: len(rows(inventory.get(key)))
                                     for key in ('tasks', 'services', 'wmi', 'filters', 'bindings')}}
    selected_tasks={}
    for task in rows(inventory.get('tasks')):
        command = '"' + str(task.get('execute', '')).strip('"') + '" ' + str(task.get('arguments', ''))
        if confirm(command):
            identity=(str(task.get('path','')).casefold(),str(task.get('name','')).casefold())
            previous=selected_tasks.get(identity)
            if previous is not None:
                if previous.get('xml')!=task.get('xml'):
                    raise ValueError('同一任务在枚举期间发生变化，请重新扫描。')
                continue
            selected_tasks[identity]=task
            selected['tasks'].append({**task, 'confirmed': True})
    for service in rows(inventory.get('services')):
        if confirm(service.get('PathName', '')):
            selected['services'].append({**service, 'confirmed': True})
    for consumer in rows(inventory.get('wmi')):
        command = str(consumer.get('command', ''))
        script = str(consumer.get('script_text', '') or '')
        if confirm(command) or script and confirm(script):
            selected['wmi'].append({**consumer, 'confirmed': True})
    return selected


def registry_paths():
    return (
        r'Software\Microsoft\Windows\CurrentVersion\Run',
        r'Software\Microsoft\Windows\CurrentVersion\RunOnce',
        r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        r'Software\Microsoft\Windows NT\CurrentVersion\Windows',
        r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
        r'Software\Microsoft\Command Processor',
    )


def remove_consumer_script(consumer):
    """Recheck consumer identity and content; leave shared filters intact."""
    if consumer.get('class') not in ('CommandLineEventConsumer', 'ActiveScriptEventConsumer') or not consumer.get('object_path'):
        raise ValueError('WMI 消费者身份不完整，已停止修改。')
    payload = base64.b64encode(json.dumps(consumer, ensure_ascii=False).encode('utf-8')).decode('ascii')
    return "$expected=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + payload + r"""'))|ConvertFrom-Json;
$ErrorActionPreference='Stop';
$items=@(Get-CimInstance -Namespace root/subscription -ClassName $expected.class | Where-Object {$_.Name -ceq $expected.Name});
if($items.Count -ne 1){throw 'WMI consumer identity changed'};
$item=$items[0];
$reference=([string]$item.CimClass.CimClassName)+'.Name="'+$item.Name.Replace('\','\\').Replace('"','\"')+'"';
if($reference -cne $expected.object_path){throw 'WMI consumer path changed'};
if($expected.class -eq 'CommandLineEventConsumer'){
  if(($item.ExecutablePath+' '+$item.CommandLineTemplate) -cne $expected.command){throw 'WMI command changed'}
}else{
  if([string]$item.ScriptFileName -cne [string]$expected.command -or [string]$item.ScriptText -cne [string]$expected.script_text){throw 'WMI script changed'}
};
$bindings=@(Get-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding | Where-Object {
  $consumer=$_.Consumer;
  $target=if($consumer -is [string]){$consumer}else{([string]$consumer.CimClass.CimClassName)+'.Name="'+$consumer.Name.Replace('\','\\').Replace('"','\"')+'"'};
  $target -ceq $reference
});
foreach($binding in $bindings){Remove-CimInstance -InputObject $binding -ErrorAction Stop};
Remove-CimInstance -InputObject $item -ErrorAction Stop
"""


def _expected_script(record, required):
    if any(not isinstance(record.get(key),str) or not record[key] for key in required):
        raise ValueError('持久化身份或内容证据不完整，已停止修改。')
    payload=base64.b64encode(json.dumps(record,ensure_ascii=False).encode('utf-8')).decode('ascii')
    return "$ErrorActionPreference='Stop';$expected=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+payload+"'))|ConvertFrom-Json;\n"


def disable_task_script(task):
    """Bind disabling to the task identity and exact exported definition."""
    return _expected_script(task,('name','path','xml'))+r"""
$items=@(Get-ScheduledTask | Where-Object {$_.TaskName -ceq $expected.name -and $_.TaskPath -ceq $expected.path});
if($items.Count -ne 1){throw 'Scheduled task identity changed'};
$item=$items[0];
$xml=Export-ScheduledTask -InputObject $item;
if($xml -cne $expected.xml){throw 'Scheduled task definition changed'};
Disable-ScheduledTask -InputObject $item -ErrorAction Stop | Out-Null
"""


def disable_service_script(service):
    """Recheck the observed service configuration and disable before stopping."""
    return _expected_script(service,('Name','PathName','StartName','ServiceType'))+r"""
function Confirm-ServiceSnapshot {
  $items=@(Get-CimInstance Win32_Service | Where-Object {$_.Name -ceq $expected.Name});
  if($items.Count -ne 1){throw 'Service identity changed'};
  $item=$items[0];
  if($item.PathName -cne $expected.PathName -or $item.StartName -cne $expected.StartName -or $item.ServiceType -cne $expected.ServiceType){throw 'Service configuration changed'};
  return $item
};
$item=Confirm-ServiceSnapshot;
$changed=Invoke-CimMethod -InputObject $item -MethodName Change -Arguments @{StartMode='Disabled'} -ErrorAction Stop;
if($changed.ReturnValue -ne 0){throw ('Service disable failed: '+$changed.ReturnValue)};
$item=Confirm-ServiceSnapshot;
$stopped=Invoke-CimMethod -InputObject $item -MethodName StopService -ErrorAction Stop;
if($stopped.ReturnValue -notin @(0,6)){throw ('Service stop failed: '+$stopped.ReturnValue)}
"""


def _task_definition(xml):
    """Compare every definition field except the expected Enabled transition."""
    from xml.etree import ElementTree as ET
    root=ET.fromstring(xml)
    for settings in root.findall('./{*}Settings'):
        for enabled in settings.findall('./{*}Enabled'):
            settings.remove(enabled)
    def tree(element):
        return (element.tag,tuple(sorted(element.attrib.items())),(element.text or '').strip(),
                tuple(tree(child) for child in element))
    return tree(root)


def reconcile_snapshot(inventory,selected,snapshot):
    """Keep exact previously proven entries visible after their payload is gone.

    An identity whose definition changed is unresolved, never automatically
    authorized from its old content. Absence is only concluded from a successful
    complete inventory supplied by the caller.
    """
    snapshot=snapshot or {}
    selected={**selected,**{key:list(selected.get(key,[])) for key in ('tasks','services','wmi')},'snapshot_changes':[]}
    identities={'tasks':('path','name'),'services':('Name',),'wmi':('class','Name')}
    fields={'tasks':('execute','arguments','working_directory'),
            'services':('PathName','StartName','ServiceType'),'wmi':('object_path','command','script_text')}
    for kind,keys in identities.items():
        identity=lambda row:tuple(str(row.get(key,'')) for key in keys)
        for old in rows(snapshot.get(kind)):
            if not old.get('confirmed'):continue
            candidates=[row for row in rows(inventory.get(kind)) if tuple(v.casefold() for v in identity(row))==tuple(v.casefold() for v in identity(old))]
            if not candidates:continue
            # Tasks expose one row per action; compare the full XML as well.
            matches=[]
            for current in candidates:
                valid=identity(current)==identity(old) and all(str(current.get(key,'') or '')==str(old.get(key,'') or '') for key in fields[kind])
                if valid and kind=='tasks':
                    try:valid=_task_definition(current.get('xml',''))==_task_definition(old.get('xml',''))
                    except (ValueError,TypeError):valid=False
                if valid:matches.append(current)
            if not matches or kind!='tasks' and len(candidates)!=1:
                selected['snapshot_changes'].append({'kind':kind,'identity':dict(zip(keys,identity(old))),
                    'reason':'Previously confirmed persistence changed; current definition requires review.'})
                continue
            if not any(identity(row)==identity(old) for row in selected[kind]):
                selected[kind].append({**matches[0],'confirmed':True,'confirmation_basis':'exact_pre_repair_snapshot'})
    return selected
