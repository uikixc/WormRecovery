"""Read-only physical-device discovery and partition-aware scan selection."""
import hashlib
import json
import os
from pathlib import Path

INVENTORY_SCRIPT=r"""
$out=@();$legacy=@(Get-CimInstance Win32_DiskDrive);
foreach($d in @(Get-Disk)){
 $old=$legacy|Where-Object {$_.Index -eq $d.Number}|Select-Object -First 1;
 $parts=@();foreach($p in @(Get-Partition -DiskNumber $d.Number)){
  $vol=$p|Get-Volume -ErrorAction SilentlyContinue;
  $parts+=@{partition=[int]$p.PartitionNumber;letter=[string]$p.DriveLetter;access=@($p.AccessPaths);volume=[string]$vol.UniqueId;label=[string]$vol.FileSystemLabel;filesystem=[string]$vol.FileSystem;size=[double]$p.Size}
 };
 $out+=@{number=[int]$d.Number;model=[string]$d.FriendlyName;serial=([string]$d.SerialNumber).Trim();unique=[string]$d.UniqueId;pnp=[string]$old.PNPDeviceID;bus=[string]$d.BusType;readonly=[bool]$d.IsReadOnly;offline=[bool]$d.IsOffline;size=[double]$d.Size;partitions=@($parts)}
};ConvertTo-Json -InputObject @($out) -Depth 7 -Compress
"""

def root_key(path):
    return os.path.normcase(os.path.abspath(path)).rstrip('\\/')+os.sep

def identifiers(device):
    values=[]
    for field in ('unique','pnp'):
        value=str(device.get(field,'')).strip().casefold()
        if value:values.append(field+':'+hashlib.sha256(value.encode()).hexdigest())
    serial=str(device.get('serial','')).strip().casefold()
    if serial:values.append('serial:'+hashlib.sha256((str(device.get('model','')).casefold()+'|'+serial).encode()).hexdigest())
    return values

def protection_path():
    return Path(os.environ.get('PROGRAMDATA','C:/ProgramData'))/'WormRecovery/device-protection.json'

class DeviceCatalog:
    def __init__(self,rows,protection=None):
        if isinstance(rows,dict):rows=[rows]
        self.devices=[]
        protected_ids=set((protection or {}).get('identifiers',[]))
        protected_volumes={str(x).casefold() for x in (protection or {}).get('volumes',[])}
        for row in rows or []:
            d=dict(row)
            d['identifiers']=identifiers(d)
            d['key']=d['identifiers'][0] if d['identifiers'] else 'unidentified:'+str(d['number'])
            d['external']=str(d.get('bus','')).casefold() in ('usb','sd','mmc','1394')
            parts=d.get('partitions') or []
            if isinstance(parts,dict):parts=[parts]
            for p in parts:
                if not str(p.get('letter','')).isalpha():p['letter']=''
            d['partitions']=parts
            d['roots']=sorted({str(p['letter']).upper()+':'+os.sep for p in parts if len(str(p.get('letter','')))==1 and str(p['letter']).isalpha()})
            d['protected']=bool(protected_ids.intersection(d['identifiers']) or protected_volumes.intersection(str(p.get('volume','')).casefold() for p in parts))
            self.devices.append(d)
    @classmethod
    def discover(cls,powershell):
        path=protection_path()
        protection=json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else {}
        return cls(powershell(INVENTORY_SCRIPT),protection)
    def device_for_root(self,root):
        key=root_key(root)
        return next((d for d in self.devices if any(root_key(r)==key for r in d['roots'])),None)
    def select(self,mode='internal',manual=None,device_key=None):
        selected=[];skipped=[]
        if manual:
            for path in manual:
                absolute=os.path.abspath(path)
                drive=os.path.splitdrive(absolute)[0]+os.sep
                d=self.device_for_root(drive)
                if d and d['protected']:raise PermissionError('所选设备已在本机排除列表中。')
                if d and d['external']:selected.extend(d['roots'])
                else:selected.append(absolute)
        else:
            for d in self.devices:
                if device_key and d['key']!=device_key:continue
                if mode=='internal' and d['external'] or mode=='removable' and not d['external']:continue
                if d['protected'] or d.get('offline'):skipped.append(d['key']);continue
                selected.extend(d['roots'])
        roots=[]
        for path in selected:
            if not any(root_key(path)==root_key(p) or root_key(path).startswith(root_key(p)) for p in roots):roots.append(path)
        external={}
        for r in roots:
            d=self.device_for_root(os.path.splitdrive(r)[0]+os.sep)
            if d and d['external']:
                part=next(p for p in d['partitions'] if str(p.get('letter','')).casefold()==r[:1].casefold())
                external[r]=part.get('volume','')
        return {'roots':roots,'external_volumes':external,'skipped':skipped,
                'excluded_roots':[r for d in self.devices if d['protected'] for r in d['roots']],
                'devices':[{'key':d['key'],'model':d.get('model'),'roots':d['roots'],'protected':d['protected'],'external':d['external'],'partitions_without_letters':sum(not p.get('letter') for p in d['partitions'])} for d in self.devices]}

def resolve_scope(powershell,mode='internal',manual=None,device_key=None):
    result=DeviceCatalog.discover(powershell).select(mode,manual,device_key)
    if not result['roots']:raise ValueError('当前扫描范围内没有可用卷。请连接设备或调整扫描范围。')
    if any(not guid for guid in result['external_volumes'].values()):raise ValueError('无法确认设备卷标识，未开始扫描。')
    return result
