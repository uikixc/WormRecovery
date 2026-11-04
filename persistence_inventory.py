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
$services=@(Get-CimInstance Win32_Service | Select-Object Name,PathName,State,StartMode);
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
    for task in rows(inventory.get('tasks')):
        command = '"' + str(task.get('execute', '')).strip('"') + '" ' + str(task.get('arguments', ''))
        if confirm(command):
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
